package server

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	ghostwatcherv1 "ghostwatcher/internal/gen/ghostwatcherv1"
)

type DashboardEvent struct {
	Type      string         `json:"type"`
	Timestamp time.Time      `json:"timestamp"`
	AgentID   string         `json:"agent_id,omitempty"`
	Hostname  string         `json:"hostname,omitempty"`
	Severity  string         `json:"severity,omitempty"`
	Message   string         `json:"message"`
	Data      map[string]any `json:"data,omitempty"`
}

type DashboardStats struct {
	TotalAgents     int    `json:"total_agents"`
	ConnectedAgents int    `json:"connected_agents"`
	TotalEvents     uint64 `json:"total_events"`
	AlertEvents     uint64 `json:"alert_events"`
}

type DashboardAgent struct {
	AgentID              string    `json:"agent_id"`
	Hostname             string    `json:"hostname"`
	OSVersion            string    `json:"os_version"`
	GatekeeperEnabled    bool      `json:"gatekeeper_enabled"`
	SIPEnabled           bool      `json:"sip_enabled"`
	SecurityPostureScore uint32    `json:"security_posture_score"`
	TotalStreamedEvents  uint64    `json:"total_streamed_events"`
	AlertEvents          uint64    `json:"alert_events"`
	Connected            bool      `json:"connected"`
	LastSeen             time.Time `json:"last_seen"`
}

type DashboardSnapshot struct {
	GeneratedAt time.Time        `json:"generated_at"`
	Stats       DashboardStats   `json:"stats"`
	Agents      []DashboardAgent `json:"agents"`
	Events      []DashboardEvent `json:"events"`
}

type DashboardMessage struct {
	Type     string             `json:"type"`
	Action   string             `json:"action,omitempty"`
	Snapshot *DashboardSnapshot `json:"snapshot,omitempty"`
	Event    *DashboardEvent    `json:"event,omitempty"`
	Payload  any                `json:"payload,omitempty"`
	Error    string             `json:"error,omitempty"`
}

type EventHub struct {
	mu         sync.RWMutex
	clients    map[chan DashboardMessage]struct{}
	history    []DashboardEvent
	maxHistory int
}

func NewEventHub(maxHistory int) *EventHub {
	if maxHistory < 1 {
		maxHistory = 100
	}
	return &EventHub{
		clients:    make(map[chan DashboardMessage]struct{}),
		maxHistory: maxHistory,
	}
}

func (h *EventHub) Subscribe() (<-chan DashboardMessage, func()) {
	ch := make(chan DashboardMessage, 32)

	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()

	cancel := func() {
		h.mu.Lock()
		if _, ok := h.clients[ch]; ok {
			delete(h.clients, ch)
			close(ch)
		}
		h.mu.Unlock()
	}

	return ch, cancel
}

func (h *EventHub) Publish(event DashboardEvent) {
	if h == nil {
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	h.mu.Lock()
	h.history = append(h.history, event)
	if len(h.history) > h.maxHistory {
		h.history = append([]DashboardEvent(nil), h.history[len(h.history)-h.maxHistory:]...)
	}
	clients := make([]chan DashboardMessage, 0, len(h.clients))
	for ch := range h.clients {
		clients = append(clients, ch)
	}
	h.mu.Unlock()

	message := DashboardMessage{Type: "event", Event: &event}
	for _, ch := range clients {
		select {
		case ch <- message:
		default:
		}
	}
}

func (h *EventHub) History() []DashboardEvent {
	if h == nil {
		return nil
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	out := make([]DashboardEvent, len(h.history))
	copy(out, h.history)
	return out
}

func (s *Service) SetEventHub(hub *EventHub) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hub = hub
}

func (s *Service) Snapshot() DashboardSnapshot {
	s.mu.RLock()
	agents := make([]DashboardAgent, 0, len(s.onlineMacs))
	stats := DashboardStats{TotalAgents: len(s.onlineMacs)}
	for _, mac := range s.onlineMacs {
		agents = append(agents, DashboardAgent{
			AgentID:              mac.AgentID,
			Hostname:             mac.Hostname,
			OSVersion:            mac.OSVersion,
			GatekeeperEnabled:    mac.GatekeeperEnabled,
			SIPEnabled:           mac.SIPEnabled,
			SecurityPostureScore: mac.SecurityPosture,
			TotalStreamedEvents:  mac.TotalStreamedEvents,
			AlertEvents:          mac.AlertEvents,
			Connected:            mac.Connected,
			LastSeen:             mac.LastSeen,
		})
		if mac.Connected {
			stats.ConnectedAgents++
		}
		stats.TotalEvents += mac.TotalStreamedEvents
		stats.AlertEvents += mac.AlertEvents
	}
	hub := s.hub
	s.mu.RUnlock()

	sort.Slice(agents, func(i, j int) bool {
		if agents[i].Connected != agents[j].Connected {
			return agents[i].Connected
		}
		return strings.ToLower(agents[i].Hostname) < strings.ToLower(agents[j].Hostname)
	})

	return DashboardSnapshot{
		GeneratedAt: time.Now().UTC(),
		Stats:       stats,
		Agents:      agents,
		Events:      hub.History(),
	}
}

func (s *Service) LookupHashForDashboard(hash string) (*ghostwatcherv1.XProtectLookupResponse, error) {
	return s.LookupHash(context.Background(), &ghostwatcherv1.XProtectLookupRequest{Hash: hash})
}

func (s *Service) CheckSignStatusForDashboard(agentID, path string) (*ghostwatcherv1.CheckSignStatusResponse, error) {
	token, err := s.dashboardAuthToken(agentID)
	if err != nil {
		return nil, err
	}
	return s.CheckSignStatus(context.Background(), &ghostwatcherv1.CheckSignStatusRequest{
		AgentId:   agentID,
		AuthToken: token,
		Path:      path,
	})
}

func (s *Service) dashboardAuthToken(agentID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	mac, ok := s.onlineMacs[agentID]
	if !ok {
		return "", fmt.Errorf("agent %q is not registered", agentID)
	}
	return mac.AuthToken, nil
}

func (s *Service) publishEvent(event DashboardEvent) {
	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()
	if hub != nil {
		hub.Publish(event)
	}
}

func BuildSignCheckPayload(resp *ghostwatcherv1.CheckSignStatusResponse, path string) map[string]any {
	return map[string]any{
		"path":               path,
		"signed":             resp.GetSigned(),
		"apple_signed":       resp.GetAppleSigned(),
		"signing_identifier": resp.GetSigningIdentifier(),
		"team_id":            resp.GetTeamId(),
		"detail":             resp.GetDetail(),
	}
}

func BuildLookupPayload(resp *ghostwatcherv1.XProtectLookupResponse, hash string) map[string]any {
	return map[string]any{
		"hash":        strings.TrimSpace(hash),
		"verdict":     resp.GetVerdict().String(),
		"threat_name": resp.GetThreatName(),
		"detail":      resp.GetDetail(),
	}
}
