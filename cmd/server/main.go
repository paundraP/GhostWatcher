package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	ghostwatcherv1 "ghostwatcher/internal/gen/ghostwatcherv1"
	"ghostwatcher/internal/server"
	"ghostwatcher/internal/threatintel"

	"google.golang.org/grpc"
)

func main() {
	listenAddr := flag.String("listen", ":50051", "gRPC listen address")
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

	ghostwatcherv1.RegisterMacEnrollmentServiceServer(grpcServer, svc)
	ghostwatcherv1.RegisterMachOIngestorServiceServer(grpcServer, svc)
	ghostwatcherv1.RegisterXProtectLookupServiceServer(grpcServer, svc)

	log.Printf("GhostWatcher server listening on %s (db: %s)", *listenAddr, *dbPath)

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("gRPC server failed: %v", err)
		}
	}()

	<-shutdown
	log.Print("Shutting down server...")
	grpcServer.GracefulStop()
}
