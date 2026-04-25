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
- Streams monitoring events into a realtime Web dashboard through WebSocket
- Accepts browser commands that trigger backend security checks

## Why It Matters

In real organizations, security teams need visibility across many laptops and desktops.
GhostWatcher demonstrates that idea in a clean, understandable, classroom-friendly implementation.

## High-Level Workflow

1. A Mac agent starts and connects to the gRPC server.
2. The device is registered automatically through `EnrollMac`.
3. Process activity is streamed continuously (or in bounded mode) through `StreamProcessEvents`.
4. The server analyzes activity, raises alerts, stores results in SQLite, and broadcasts events to WebSocket clients.
5. The browser dashboard updates live and can trigger `LookupHash` or `CheckSignStatus` through the command bridge.

## Main Components

- `cmd/server`: gRPC server plus HTTP/WebSocket dashboard server
- `cmd/agent`: macOS agent simulator / telemetry sender
- `internal/server`: core business logic, SQLite persistence, in-memory agent state, dashboard event hub
- `internal/web`: embedded dashboard assets and WebSocket gateway
- `proto/ghostwatcher.proto`: gRPC contract

## Realtime Dashboard

The new dashboard exposes a browser-based monitoring UI with three main realtime areas:
- **Security Summary**: total agents, connected agents, total events, and total alerts
- **Agent Status Panel**: online/offline agents, posture score, and last seen
- **Live Activity + Alert Feed**: process events and server-initiated alert messages

The dashboard also includes a **Command Bridge**:
- `lookup_hash`: checks a hash using the existing `LookupHash` logic
- `check_sign_status`: checks code-signing status for a selected agent and executable path
- `get_agent_snapshot`: refreshes dashboard state from the server

## Quick Demo

### 1) Start the server

```bash
go run ./cmd/server -listen :50051 -http-listen :8080 -db-path ./ghostwatcher.db
```

If you want open-source threat intelligence lookup enabled:

```bash
export VT_API_KEY="your_api_key_here"
go run ./cmd/server -listen :50051 -http-listen :8080 -db-path ./ghostwatcher.db
```

Open the dashboard in a browser:

```text
http://localhost:8080
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

### 3) Demo the command bridge from browser

From the dashboard:
- use the pre-filled seeded hash to trigger a malicious lookup result
- select an agent and try `Check Sign Status`
- click `Refresh Snapshot` to request fresh state from the server

## Suggested Demo Script

1. Start the server and open `http://localhost:8080`.
2. Run one agent in bounded or continuous mode.
3. Watch agent enrollment appear in the dashboard automatically.
4. Observe process events and alert feed update without refreshing the page.
5. Run `lookup_hash` from the browser to show WebSocket -> backend -> response flow.
6. Run `check_sign_status` from the browser to show WebSocket -> backend -> local inspection flow.

## Notes

- The dashboard is embedded into the server binary, so no separate frontend build step is required.
- SQLite remains the persistent store for device and process data.
- The realtime UI uses WebSocket while the backend telemetry path still uses gRPC.
