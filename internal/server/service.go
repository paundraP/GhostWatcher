package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	ghostwatcherv1 "ghostwatcher/internal/gen/ghostwatcherv1"
	"ghostwatcher/internal/macos"
	"ghostwatcher/internal/threatintel"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type MacInfo struct {
	AgentID             string
	Hostname            string
	OSVersion           string
	SerialNumber        string
	GatekeeperEnabled   bool
	SIPEnabled          bool
	SecurityPosture     uint32
	AuthToken           string
	TotalStreamedEvents uint64
	AlertEvents         uint64
	LastSeen            time.Time
	Connected           bool
}

type Service struct {
	ghostwatcherv1.UnimplementedMacEnrollmentServiceServer
	ghostwatcherv1.UnimplementedMachOIngestorServiceServer
	ghostwatcherv1.UnimplementedXProtectLookupServiceServer

	mu         sync.RWMutex
	onlineMacs map[string]MacInfo
	xprotectDB map[string]string
	store      DataStore
	vtClient   threatintel.LookupClient
	hub        *EventHub
}

type threatVerdict struct {
	Hash       string
	Malicious  bool
	ThreatName string
	Detail     string
	Source     string
}

func NewService(store DataStore, vtClient threatintel.LookupClient) *Service {
	if store == nil {
		store = NewNoopStore()
	}
	if isNilLookupClient(vtClient) {
		vtClient = nil
	}

	svc := &Service{
		onlineMacs: make(map[string]MacInfo),
		xprotectDB: threatintel.DefaultHashes(),
		store:      store,
		vtClient:   vtClient,
	}

	for hash, threat := range svc.xprotectDB {
		if err := svc.store.UpsertThreat(context.Background(), ThreatCache{
			Hash:       hash,
			Malicious:  true,
			ThreatName: threat,
			Source:     "seeded_xprotect",
			Detail:     "seeded local threat intel from project defaults",
		}); err != nil {
			log.Printf("[WARN] failed to seed threat cache for %s: %v", hash, err)
		}
	}

	return svc
}

func isNilLookupClient(client threatintel.LookupClient) bool {
	if client == nil {
		return true
	}
	value := reflect.ValueOf(client)
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func:
		return value.IsNil()
	default:
		return false
	}
}

func (s *Service) EnrollMac(_ context.Context, req *ghostwatcherv1.EnrollMacRequest) (*ghostwatcherv1.EnrollMacResponse, error) {
	if strings.TrimSpace(req.GetHostname()) == "" {
		return nil, status.Error(codes.InvalidArgument, "hostname is required")
	}

	agentID := "mac-" + mustToken(4)
	token := mustToken(16)
	score := postureScore(req.GetGatekeeperEnabled(), req.GetSipEnabled())

	info := MacInfo{
		AgentID:           agentID,
		Hostname:          req.GetHostname(),
		OSVersion:         req.GetOsVersion(),
		SerialNumber:      req.GetSerialNumber(),
		GatekeeperEnabled: req.GetGatekeeperEnabled(),
		SIPEnabled:        req.GetSipEnabled(),
		SecurityPosture:   score,
		AuthToken:         token,
		Connected:         true,
		LastSeen:          time.Now(),
	}

	s.mu.Lock()
	s.onlineMacs[agentID] = info
	s.mu.Unlock()

	if err := s.store.UpsertMac(context.Background(), info); err != nil {
		log.Printf("[WARN] failed to persist enrollment for %s: %v", agentID, err)
	}

	log.Printf("[INFO] Enrolled %s (%s) - posture=%d gatekeeper=%t sip=%t", info.Hostname, agentID, score, info.GatekeeperEnabled, info.SIPEnabled)

	s.publishEvent(DashboardEvent{
		Type:      "agent_enrolled",
		AgentID:   info.AgentID,
		Hostname:  info.Hostname,
		Severity:  "info",
		Message:   "Agent enrolled successfully",
		Timestamp: info.LastSeen,
		Data: map[string]any{
			"os_version":             info.OSVersion,
			"serial_number":          info.SerialNumber,
			"security_posture_score": info.SecurityPosture,
			"gatekeeper_enabled":     info.GatekeeperEnabled,
			"sip_enabled":            info.SIPEnabled,
		},
	})

	return &ghostwatcherv1.EnrollMacResponse{
		AgentId:              agentID,
		AuthToken:            token,
		SecurityPostureScore: score,
		Message:              "Enrollment successful",
	}, nil
}

func (s *Service) StreamProcessEvents(stream grpc.ClientStreamingServer[ghostwatcherv1.StreamProcessEventRequest, ghostwatcherv1.StreamProcessEventsResponse]) error {
	var (
		agentID string
		host    string
		total   uint64
		alerts  uint64
	)

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		event := req.GetEvent()
		if event == nil {
			continue
		}

		agent, authErr := s.authorize(req.GetAgentId(), req.GetAuthToken())
		if authErr != nil {
			return authErr
		}

		agentID = agent.AgentID
		host = agent.Hostname
		total++

		log.Printf(
			"[EVENT] host=%s pid=%d path=%s signer=%s team=%s sha256=%s sandboxed=%t",
			host,
			event.GetPid(),
			event.GetPath(),
			emptyFallback(event.GetSigningIdentifier(), "unknown"),
			emptyFallback(event.GetTeamId(), "-"),
			emptyFallback(event.GetSha256(), "-"),
			event.GetIsSandboxed(),
		)

		unsigned := !looksSigned(event)
		eventAlert := false
		s.publishEvent(DashboardEvent{
			Type:      "process_event",
			AgentID:   agentID,
			Hostname:  host,
			Severity:  "info",
			Message:   fmt.Sprintf("Process observed: %s", event.GetPath()),
			Timestamp: time.Unix(event.GetObservedUnix(), 0),
			Data: map[string]any{
				"pid":                event.GetPid(),
				"path":               event.GetPath(),
				"bundle_id":          event.GetBundleId(),
				"signing_identifier": emptyFallback(event.GetSigningIdentifier(), "unknown"),
				"team_id":            emptyFallback(event.GetTeamId(), "-"),
				"sha256":             emptyFallback(event.GetSha256(), "-"),
				"is_sandboxed":       event.GetIsSandboxed(),
				"is_alert":           false,
				"observed_unix":      event.GetObservedUnix(),
			},
		})
		if unsigned {
			alerts++
			eventAlert = true
			log.Printf("[ALERT] Unsigned process detected on %s: %s", host, event.GetPath())
			s.publishEvent(DashboardEvent{
				Type:      "security_alert",
				AgentID:   agentID,
				Hostname:  host,
				Severity:  "high",
				Message:   "Unsigned process detected",
				Timestamp: time.Unix(event.GetObservedUnix(), 0),
				Data: map[string]any{
					"kind":               "unsigned_process",
					"pid":                event.GetPid(),
					"path":               event.GetPath(),
					"signing_identifier": emptyFallback(event.GetSigningIdentifier(), "unknown"),
					"sha256":             emptyFallback(event.GetSha256(), "-"),
				},
			})
		}

		threatVerdict, lookupErr := s.lookupThreat(stream.Context(), event.GetSha256())
		if lookupErr != nil {
			log.Printf("[WARN] threat lookup failed for hash %s: %v", event.GetSha256(), lookupErr)
		}

		if threatVerdict.Malicious {
			alerts++
			eventAlert = true
			log.Printf("[ALERT] Threat Intel match (%s) on %s: %s", threatVerdict.ThreatName, host, event.GetPath())
			s.publishEvent(DashboardEvent{
				Type:      "security_alert",
				AgentID:   agentID,
				Hostname:  host,
				Severity:  "critical",
				Message:   fmt.Sprintf("Threat intel match: %s", threatVerdict.ThreatName),
				Timestamp: time.Unix(event.GetObservedUnix(), 0),
				Data: map[string]any{
					"kind":        "threat_match",
					"pid":         event.GetPid(),
					"path":        event.GetPath(),
					"sha256":      emptyFallback(event.GetSha256(), "-"),
					"threat_name": threatVerdict.ThreatName,
					"detail":      threatVerdict.Detail,
					"source":      threatVerdict.Source,
				},
			})
		}

		if err := s.store.InsertProcessEvent(stream.Context(), agentID, event, eventAlert, threatVerdict.ThreatName); err != nil {
			log.Printf("[WARN] failed to persist process event for %s: %v", agentID, err)
		}

		s.recordEvent(stream.Context(), agentID, eventAlert)
	}

	if agentID == "" {
		return status.Error(codes.InvalidArgument, "stream contained no events")
	}

	s.setConnected(context.Background(), agentID, false)
	log.Printf("[INFO] Streaming %d logs from %s...", total, host)
	s.publishEvent(DashboardEvent{
		Type:      "agent_disconnected",
		AgentID:   agentID,
		Hostname:  host,
		Severity:  "warning",
		Message:   "Telemetry stream closed",
		Timestamp: time.Now(),
		Data: map[string]any{
			"total_events": total,
			"alert_events": alerts,
		},
	})

	return stream.SendAndClose(&ghostwatcherv1.StreamProcessEventsResponse{
		AgentId:     agentID,
		TotalEvents: total,
		AlertEvents: alerts,
		Status:      "stream closed",
	})
}

func (s *Service) CheckSignStatus(_ context.Context, req *ghostwatcherv1.CheckSignStatusRequest) (*ghostwatcherv1.CheckSignStatusResponse, error) {
	if strings.TrimSpace(req.GetPath()) == "" {
		return nil, status.Error(codes.InvalidArgument, "path is required")
	}

	if _, err := s.authorize(req.GetAgentId(), req.GetAuthToken()); err != nil {
		return nil, err
	}

	if _, err := os.Stat(req.GetPath()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid path: %v", err)
	}

	sig := macos.AnalyzeSignature(req.GetPath())
	return &ghostwatcherv1.CheckSignStatusResponse{
		Signed:            sig.Signed,
		AppleSigned:       sig.AppleSigned,
		SigningIdentifier: sig.SigningIdentifier,
		TeamId:            sig.TeamID,
		Detail:            sig.Detail,
	}, nil
}

func (s *Service) LookupHash(_ context.Context, req *ghostwatcherv1.XProtectLookupRequest) (*ghostwatcherv1.XProtectLookupResponse, error) {
	hash := strings.TrimSpace(req.GetHash())
	if hash == "" {
		return nil, status.Error(codes.InvalidArgument, "hash is required")
	}

	verdict, err := s.lookupThreat(context.Background(), hash)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "threat lookup failed: %v", err)
	}

	if verdict.Malicious {
		return &ghostwatcherv1.XProtectLookupResponse{
			Verdict:    ghostwatcherv1.XProtectLookupResponse_MALICIOUS,
			ThreatName: verdict.ThreatName,
			Detail:     verdict.Detail,
		}, nil
	}

	return &ghostwatcherv1.XProtectLookupResponse{
		Verdict:    ghostwatcherv1.XProtectLookupResponse_SAFE,
		ThreatName: "",
		Detail:     verdict.Detail,
	}, nil
}

func emptyFallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func (s *Service) authorize(agentID, token string) (MacInfo, error) {
	s.mu.RLock()
	mac, ok := s.onlineMacs[agentID]
	s.mu.RUnlock()

	if !ok {
		return MacInfo{}, status.Errorf(codes.NotFound, "agent ID %q is not registered", agentID)
	}

	if token != mac.AuthToken {
		return MacInfo{}, status.Error(codes.PermissionDenied, "invalid telemetry token")
	}

	return mac, nil
}

func (s *Service) recordEvent(ctx context.Context, agentID string, isAlert bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	mac, ok := s.onlineMacs[agentID]
	if !ok {
		return
	}

	mac.TotalStreamedEvents++
	if isAlert {
		mac.AlertEvents++
	}
	mac.LastSeen = time.Now()
	mac.Connected = true
	s.onlineMacs[agentID] = mac

	alertDelta := uint64(0)
	if isAlert {
		alertDelta = 1
	}
	if err := s.store.UpdateMacRuntime(ctx, agentID, true, mac.LastSeen, 1, alertDelta); err != nil {
		log.Printf("[WARN] failed to update mac runtime for %s: %v", agentID, err)
	}
}

func (s *Service) setConnected(ctx context.Context, agentID string, connected bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if mac, ok := s.onlineMacs[agentID]; ok {
		mac.Connected = connected
		mac.LastSeen = time.Now()
		s.onlineMacs[agentID] = mac
		if err := s.store.UpdateMacRuntime(ctx, agentID, connected, mac.LastSeen, 0, 0); err != nil {
			log.Printf("[WARN] failed to update mac connectivity for %s: %v", agentID, err)
		}
	}
}

func (s *Service) lookupThreat(ctx context.Context, hash string) (threatVerdict, error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if hash == "" {
		return threatVerdict{Detail: "empty hash, treated as safe"}, nil
	}

	if threatName, found := s.xprotectDB[hash]; found {
		return threatVerdict{
			Hash:       hash,
			Malicious:  true,
			ThreatName: threatName,
			Detail:     "hash found in seeded local threat intel",
			Source:     "seeded_xprotect",
		}, nil
	}

	if s.vtClient != nil {
		result, err := s.vtClient.LookupHash(ctx, hash)
		if err != nil {
			if !errors.Is(err, threatintel.ErrNotConfigured) {
				if cached, found, cacheErr := s.store.GetThreat(ctx, hash); cacheErr != nil {
					log.Printf("[WARN] threat cache lookup failed for %s after VT error: %v", hash, cacheErr)
				} else if found {
					log.Printf("[WARN] using cached threat intel for %s after VT lookup error: %v", hash, err)
					return threatVerdict{
						Hash:       cached.Hash,
						Malicious:  cached.Malicious,
						ThreatName: cached.ThreatName,
						Detail:     cached.Detail,
						Source:     cached.Source,
					}, nil
				}
				return threatVerdict{}, err
			}
		} else {
			cacheRecord := ThreatCache{
				Hash:        hash,
				Malicious:   result.Malicious,
				ThreatName:  result.ThreatName,
				Source:      result.Source,
				Detail:      result.Detail,
				LastChecked: time.Now().UTC(),
			}
			if cacheErr := s.store.UpsertThreat(ctx, cacheRecord); cacheErr != nil {
				log.Printf("[WARN] failed to persist threat cache for %s: %v", hash, cacheErr)
			}
			return threatVerdict{
				Hash:       hash,
				Malicious:  result.Malicious,
				ThreatName: result.ThreatName,
				Detail:     result.Detail,
				Source:     result.Source,
			}, nil
		}
	}

	if cached, found, err := s.store.GetThreat(ctx, hash); err != nil {
		log.Printf("[WARN] threat cache lookup failed for %s: %v", hash, err)
	} else if found {
		return threatVerdict{
			Hash:       cached.Hash,
			Malicious:  cached.Malicious,
			ThreatName: cached.ThreatName,
			Detail:     cached.Detail,
			Source:     cached.Source,
		}, nil
	}

	return threatVerdict{
		Hash:      hash,
		Malicious: false,
		Detail:    "hash not found in local cache and external intel unavailable",
		Source:    "unknown",
	}, nil
}

func postureScore(gatekeeperEnabled, sipEnabled bool) uint32 {
	score := uint32(40)
	if gatekeeperEnabled {
		score += 30
	}
	if sipEnabled {
		score += 30
	}
	return score
}

func looksSigned(event *ghostwatcherv1.ProcessEvent) bool {
	id := strings.TrimSpace(event.GetSigningIdentifier())
	if id == "" || strings.EqualFold(id, "unsigned") || strings.EqualFold(id, "unknown") {
		return false
	}
	return true
}

func mustToken(size int) string {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("unable to generate secure token: %v", err))
	}
	return hex.EncodeToString(buf)
}
