package web

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strings"

	"ghostwatcher/internal/server"
	"golang.org/x/net/websocket"
)

//go:embed static/*
var staticFiles embed.FS

type Server struct {
	service *server.Service
	hub     *server.EventHub
	assets  fs.FS
}

type commandRequest struct {
	Action  string                 `json:"action"`
	Payload map[string]interface{} `json:"payload"`
}

func New(service *server.Service, hub *server.EventHub) (*Server, error) {
	assets, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return nil, fmt.Errorf("prepare embedded assets: %w", err)
	}
	return &Server{service: service, hub: hub, assets: assets}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/ws", websocket.Handler(s.handleWS))
	mux.Handle("/", http.FileServer(http.FS(s.assets)))
	return mux
}

func (s *Server) handleWS(conn *websocket.Conn) {
	defer conn.Close()

	hubMessages, unsubscribe := s.hub.Subscribe()
	defer unsubscribe()

	outbound := make(chan server.DashboardMessage, 64)
	done := make(chan struct{})
	defer close(done)

	go func() {
		for {
			select {
			case msg, ok := <-hubMessages:
				if !ok {
					return
				}
				select {
				case outbound <- msg:
				case <-done:
					return
				}
			case <-done:
				return
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		for {
			select {
			case <-done:
				return
			case msg := <-outbound:
				if err := websocket.JSON.Send(conn, msg); err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	outbound <- server.DashboardMessage{
		Type:     "snapshot",
		Snapshot: ptrSnapshot(s.service.Snapshot()),
	}

	for {
		select {
		case err := <-errCh:
			if err != nil {
				log.Printf("[WARN] websocket client disconnected: %v", err)
			}
			return
		default:
		}

		var req commandRequest
		if err := websocket.JSON.Receive(conn, &req); err != nil {
			return
		}

		response := s.executeCommand(req)
		select {
		case outbound <- response:
		case err := <-errCh:
			if err != nil {
				log.Printf("[WARN] websocket client disconnected: %v", err)
			}
			return
		}
	}
}

func (s *Server) executeCommand(req commandRequest) server.DashboardMessage {
	action := strings.TrimSpace(req.Action)
	switch action {
	case "lookup_hash":
		hash := stringPayload(req.Payload, "hash")
		resp, err := s.service.LookupHashForDashboard(hash)
		if err != nil {
			return server.DashboardMessage{Type: "command_error", Action: action, Error: err.Error()}
		}
		return server.DashboardMessage{Type: "command_result", Action: action, Payload: server.BuildLookupPayload(resp, hash)}
	case "check_sign_status":
		agentID := stringPayload(req.Payload, "agent_id")
		path := stringPayload(req.Payload, "path")
		resp, err := s.service.CheckSignStatusForDashboard(agentID, path)
		if err != nil {
			return server.DashboardMessage{Type: "command_error", Action: action, Error: err.Error()}
		}
		return server.DashboardMessage{Type: "command_result", Action: action, Payload: server.BuildSignCheckPayload(resp, path)}
	case "get_agent_snapshot":
		return server.DashboardMessage{Type: "snapshot", Action: action, Snapshot: ptrSnapshot(s.service.Snapshot())}
	default:
		return server.DashboardMessage{Type: "command_error", Action: action, Error: "unknown action"}
	}
}

func stringPayload(payload map[string]interface{}, key string) string {
	if payload == nil {
		return ""
	}
	value, ok := payload[key]
	if !ok || value == nil {
		return ""
	}
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func ptrSnapshot(snapshot server.DashboardSnapshot) *server.DashboardSnapshot {
	return &snapshot
}
