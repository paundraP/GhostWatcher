package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	ghostwatcherv1 "ghostwatcher/internal/gen/ghostwatcherv1"
	"ghostwatcher/internal/server"
	"ghostwatcher/internal/threatintel"
	"ghostwatcher/internal/web"

	"google.golang.org/grpc"
)

func main() {
	if err := loadDotEnv(".env"); err != nil {
		log.Printf("failed to load .env: %v", err)
	}

	listenAddr := flag.String("listen", ":50051", "gRPC listen address")
	httpListenAddr := flag.String("http-listen", ":8080", "HTTP/WebSocket dashboard listen address")
	dbPath := flag.String("db-path", "./ghostwatcher.db", "SQLite database path")
	vtAPIKey := flag.String("virustotal-api-key", os.Getenv("VT_API_KEY"), "VirusTotal API key (or set VT_API_KEY)")
	flag.Parse()

	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", *listenAddr, err)
	}

	grpcServer := grpc.NewServer()
	store, err := server.NewSQLiteStore(*dbPath)
	if err != nil {
		log.Fatalf("failed to initialize sqlite store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			log.Printf("failed to close sqlite store: %v", err)
		}
	}()

	var vtClient threatintel.LookupClient
	if *vtAPIKey != "" {
		vtClient = threatintel.NewVirusTotalClient(*vtAPIKey)
		log.Print("VirusTotal integration enabled")
	} else {
		log.Print("VirusTotal integration disabled (set VT_API_KEY to enable)")
	}

	svc := server.NewService(store, vtClient)
	hub := server.NewEventHub(200)
	svc.SetEventHub(hub)

	ghostwatcherv1.RegisterMacEnrollmentServiceServer(grpcServer, svc)
	ghostwatcherv1.RegisterMachOIngestorServiceServer(grpcServer, svc)
	ghostwatcherv1.RegisterXProtectLookupServiceServer(grpcServer, svc)

	webServer, err := web.New(svc, hub)
	if err != nil {
		log.Fatalf("failed to initialize web dashboard: %v", err)
	}

	httpSrv := &http.Server{
		Addr:              *httpListenAddr,
		Handler:           webServer.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("GhostWatcher gRPC server listening on %s (db: %s)", *listenAddr, *dbPath)
	log.Printf("GhostWatcher web dashboard listening on http://localhost%s", *httpListenAddr)

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("gRPC server failed: %v", err)
		}
	}()

	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	<-shutdown
	log.Print("Shutting down server...")
	grpcServer.GracefulStop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Printf("HTTP server shutdown failed: %v", err)
	}
}

func loadDotEnv(path string) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, found := strings.Cut(line, "=")
		if !found {
			return fmt.Errorf("invalid .env entry at line %d", lineNumber)
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		if key == "" {
			return fmt.Errorf("empty key in .env at line %d", lineNumber)
		}

		if _, exists := os.LookupEnv(key); !exists {
			if err := os.Setenv(key, value); err != nil {
				return fmt.Errorf("set env %s: %w", key, err)
			}
		}
	}

	return scanner.Err()
}
