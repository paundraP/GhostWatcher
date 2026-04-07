package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	ghostwatcherv1 "ghostwatcher/internal/gen/ghostwatcherv1"
	"ghostwatcher/internal/macos"
	"ghostwatcher/internal/threatintel"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type config struct {
	serverAddr string
	events     int
	interval   time.Duration
	checkPath  string
	lookupHash string
	live       bool
	demo       bool
	noStream   bool
	continuous bool
}

func main() {
	cfg := parseFlags()

	conn, err := grpc.NewClient(cfg.serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("unable to connect to server: %v", err)
	}
	defer conn.Close()

	enrollClient := ghostwatcherv1.NewMacEnrollmentServiceClient(conn)
	ingestorClient := ghostwatcherv1.NewMachOIngestorServiceClient(conn)
	xprotectClient := ghostwatcherv1.NewXProtectLookupServiceClient(conn)

	profile := macos.CollectSystemProfile()
	enrollCtx, enrollCancel := context.WithTimeout(context.Background(), 8*time.Second)
	enrollResp, err := enrollClient.EnrollMac(enrollCtx, &ghostwatcherv1.EnrollMacRequest{
		Hostname:          profile.Hostname,
		OsVersion:         profile.OSVersion,
		SerialNumber:      profile.SerialNumber,
		GatekeeperEnabled: profile.GatekeeperEnabled,
		SipEnabled:        profile.SIPEnabled,
		AgentVersion:      "ghostwatcher-agent/1.0.0",
	})
	enrollCancel()
	if err != nil {
		log.Fatalf("enrollment failed: %v", err)
	}

	fmt.Printf("[ENROLLED] agent_id=%s posture=%d\n", enrollResp.GetAgentId(), enrollResp.GetSecurityPostureScore())

	if cfg.checkPath != "" {
		if err := runSignCheck(ingestorClient, enrollResp.GetAgentId(), enrollResp.GetAuthToken(), cfg.checkPath); err != nil {
			log.Fatalf("CheckSignStatus failed: %v", err)
		}
	}

	if cfg.lookupHash != "" {
		if err := runXProtectLookup(xprotectClient, cfg.lookupHash); err != nil {
			log.Fatalf("LookupHash failed: %v", err)
		}
	}

	if cfg.noStream {
		return
	}

	if cfg.continuous {
		if err := runContinuousStream(ingestorClient, enrollResp.GetAgentId(), enrollResp.GetAuthToken(), cfg); err != nil {
			log.Fatalf("continuous stream failed: %v", err)
		}
		return
	}

	if err := runBoundedStream(ingestorClient, enrollResp.GetAgentId(), enrollResp.GetAuthToken(), cfg); err != nil {
		log.Fatalf("streaming failed: %v", err)
	}
}

func runBoundedStream(client ghostwatcherv1.MachOIngestorServiceClient, agentID, authToken string, cfg config) error {
	events, err := buildEvents(cfg.events, cfg.live)
	if err != nil {
		return fmt.Errorf("cannot prepare process events: %w", err)
	}

	streamCtx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.events+10)*cfg.interval)
	defer cancel()

	stream, err := client.StreamProcessEvents(streamCtx)
	if err != nil {
		return fmt.Errorf("unable to open stream: %w", err)
	}

	for idx, event := range events {
		err := stream.Send(&ghostwatcherv1.StreamProcessEventRequest{
			AgentId:   agentID,
			AuthToken: authToken,
			Event:     event,
		})
		if err != nil {
			return fmt.Errorf("stream send failed at event %d: %w", idx+1, err)
		}

		if idx < len(events)-1 {
			time.Sleep(cfg.interval)
		}
	}

	summary, err := stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("stream close failed: %w", err)
	}

	fmt.Printf("[STREAM] agent=%s total=%d alerts=%d status=%s\n", summary.GetAgentId(), summary.GetTotalEvents(), summary.GetAlertEvents(), summary.GetStatus())
	return nil
}

func runContinuousStream(client ghostwatcherv1.MachOIngestorServiceClient, agentID, authToken string, cfg config) error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	stream, err := client.StreamProcessEvents(context.Background())
	if err != nil {
		return fmt.Errorf("unable to open stream: %w", err)
	}

	fmt.Printf("[STREAM] Continuous mode started (interval=%s). Press Ctrl+C to stop.\n", cfg.interval)
	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()

	sent := 0
	for {
		select {
		case <-signals:
			summary, err := stream.CloseAndRecv()
			if err != nil {
				return fmt.Errorf("stream close failed: %w", err)
			}
			fmt.Printf("[STREAM] agent=%s total=%d alerts=%d status=%s\n", summary.GetAgentId(), summary.GetTotalEvents(), summary.GetAlertEvents(), summary.GetStatus())
			return nil
		case <-ticker.C:
			event, err := buildNextEvent(sent, cfg.live)
			if err != nil {
				return fmt.Errorf("cannot build continuous event: %w", err)
			}

			err = stream.Send(&ghostwatcherv1.StreamProcessEventRequest{
				AgentId:   agentID,
				AuthToken: authToken,
				Event:     event,
			})
			if err != nil {
				return fmt.Errorf("stream send failed at event %d: %w", sent+1, err)
			}
			sent++

			if sent%50 == 0 {
				fmt.Printf("[STREAM] sent=%d\n", sent)
			}
		}
	}
}

func parseFlags() config {
	cfg := config{
		live: true,
	}
	flag.StringVar(&cfg.serverAddr, "server", "localhost:50051", "GhostWatcher server address")
	flag.IntVar(&cfg.events, "events", 45, "Number of process events to send")
	flag.DurationVar(&cfg.interval, "interval", 250*time.Millisecond, "Delay between streamed events")
	flag.StringVar(&cfg.checkPath, "check-path", "", "Path to verify with CheckSignStatus(path)")
	flag.StringVar(&cfg.lookupHash, "lookup-hash", threatintel.ShlayerHash, "Hash to lookup in XProtect service (set empty to skip)")
	flag.BoolVar(&cfg.live, "live", true, "Collect real process list from host")
	flag.BoolVar(&cfg.demo, "demo", false, "Use deterministic demo events instead of real process data")
	flag.BoolVar(&cfg.noStream, "no-stream", false, "Skip telemetry streaming")
	flag.BoolVar(&cfg.continuous, "continuous", false, "Run continuous streaming until interrupted (Ctrl+C)")
	flag.Parse()

	if cfg.events < 1 {
		cfg.events = 1
	}
	if cfg.interval <= 0 {
		cfg.interval = 250 * time.Millisecond
	}
	if cfg.demo {
		cfg.live = false
	}
	return cfg
}

func runSignCheck(client ghostwatcherv1.MachOIngestorServiceClient, agentID, token, path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	resp, err := client.CheckSignStatus(ctx, &ghostwatcherv1.CheckSignStatusRequest{
		AgentId:   agentID,
		AuthToken: token,
		Path:      path,
	})
	if err != nil {
		return err
	}

	fmt.Printf("[SIGN] path=%s signed=%t apple_signed=%t identifier=%s team_id=%s detail=%s\n",
		path,
		resp.GetSigned(),
		resp.GetAppleSigned(),
		resp.GetSigningIdentifier(),
		resp.GetTeamId(),
		resp.GetDetail(),
	)
	return nil
}

func runXProtectLookup(client ghostwatcherv1.XProtectLookupServiceClient, hash string) error {
	hash = strings.TrimSpace(hash)
	if hash == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.LookupHash(ctx, &ghostwatcherv1.XProtectLookupRequest{Hash: hash})
	if err != nil {
		return err
	}

	fmt.Printf("[XPROTECT] hash=%s verdict=%s threat=%s\n", hash, resp.GetVerdict().String(), resp.GetThreatName())
	return nil
}

func buildEvents(count int, live bool) ([]*ghostwatcherv1.ProcessEvent, error) {
	if live {
		if events, err := buildLiveEvents(count); err == nil && len(events) > 0 {
			return events, nil
		}
	}
	return buildDemoEvents(count), nil
}

func buildNextEvent(index int, live bool) (*ghostwatcherv1.ProcessEvent, error) {
	if live {
		procs, err := macos.ListProcesses(100)
		if err == nil && len(procs) > 0 {
			proc := procs[index%len(procs)]
			return buildEvent(proc.PID, proc.Path, false), nil
		}
	}

	path := demoPaths[index%len(demoPaths)]
	malicious := strings.Contains(path, "hidden_malware")
	return buildEvent(4200+index, path, malicious), nil
}

func buildLiveEvents(count int) ([]*ghostwatcherv1.ProcessEvent, error) {
	procs, err := macos.ListProcesses(count)
	if err != nil {
		return nil, err
	}
	if len(procs) == 0 {
		return nil, errors.New("no process found from ps")
	}

	events := make([]*ghostwatcherv1.ProcessEvent, 0, len(procs))
	for _, proc := range procs {
		events = append(events, buildEvent(proc.PID, proc.Path, false))
	}
	return events, nil
}

func buildDemoEvents(count int) []*ghostwatcherv1.ProcessEvent {
	events := make([]*ghostwatcherv1.ProcessEvent, 0, count)
	for i := 0; i < count; i++ {
		path := demoPaths[i%len(demoPaths)]
		malicious := strings.Contains(path, "hidden_malware")
		events = append(events, buildEvent(4200+i, path, malicious))
	}
	return events
}

var demoPaths = []string{
	"/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
	"/Applications/Safari.app/Contents/MacOS/Safari",
	"/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
	"/tmp/hidden_malware",
}

func buildEvent(pid int, path string, forceMalicious bool) *ghostwatcherv1.ProcessEvent {
	sig := macos.AnalyzeSignature(path)
	bundleID := macos.BundleID(path)
	sha := macos.FileSHA256(path)
	if sha == "" {
		sha = hashString(path)
	}

	signingID := sig.SigningIdentifier
	if !sig.Signed {
		signingID = "unsigned"
	}
	if signingID == "" {
		signingID = "unknown"
	}

	if forceMalicious {
		sha = threatintel.ShlayerHash
		signingID = "unsigned"
	}

	return &ghostwatcherv1.ProcessEvent{
		Pid:               int32(pid),
		Path:              path,
		BundleId:          bundleID,
		SigningIdentifier: signingID,
		IsSandboxed:       macos.IsSandboxedPath(path),
		CdHash:            sig.CDHash,
		TeamId:            sig.TeamID,
		Sha256:            sha,
		ObservedUnix:      time.Now().Unix(),
	}
}

func hashString(input string) string {
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])
}
