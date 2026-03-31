# GhostWatcher EDR

GhostWatcher is a simple Endpoint Detection and Response (EDR) simulation for macOS.
It was built for an Integration System course project to show how a security team can monitor Mac devices in near real-time.
In the current chapter, our Integration System course material is gRPC, and this project is my implementation of that material by building a simple EDR.

## What This Project Does

- Registers Mac devices to a central server
- Monitors running process activity from each device
- Detects suspicious indicators such as unsigned executables
- Checks malware hash intelligence from open-source data (VirusTotal)
- Stores monitoring data in a database for reporting and review

## Why It Matters

In real organizations, security teams need visibility across many laptops and desktops.
GhostWatcher demonstrates that idea in a clean, understandable, classroom-friendly implementation.

## High-Level Workflow

1. A Mac agent starts and connects to the server
2. The device is registered automatically
3. Process activity is streamed continuously (or in bounded mode)
4. Server analyzes activity, raises alerts, and stores results in database

## Quick Demo

### 1) Start the server

```bash
go run ./cmd/server -listen :50051 -db-path ./ghostwatcher.db
```

If you want open-source threat intelligence lookup enabled:

```bash
export VT_API_KEY="your_api_key_here"
go run ./cmd/server -listen :50051 -db-path ./ghostwatcher.db
```

### 2) Start agent from a Mac client

Bounded demo mode:

```bash
go run ./cmd/agent -server localhost:50051 -events 45 -interval 200ms
```

Continuous mode (recommended for live presentation):

```bash
go run ./cmd/agent -server localhost:50051 -continuous -interval 500ms
```

Stop continuous mode with `Ctrl + C`.
