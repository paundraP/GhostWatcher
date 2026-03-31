package server

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	ghostwatcherv1 "ghostwatcher/internal/gen/ghostwatcherv1"

	_ "modernc.org/sqlite"
)

type ThreatCache struct {
	Hash        string
	Malicious   bool
	ThreatName  string
	Source      string
	Detail      string
	LastChecked time.Time
}

type DataStore interface {
	UpsertMac(ctx context.Context, info MacInfo) error
	UpdateMacRuntime(ctx context.Context, agentID string, connected bool, lastSeen time.Time, totalDelta uint64, alertDelta uint64) error
	InsertProcessEvent(ctx context.Context, agentID string, event *ghostwatcherv1.ProcessEvent, isAlert bool, threatName string) error
	GetThreat(ctx context.Context, hash string) (ThreatCache, bool, error)
	UpsertThreat(ctx context.Context, record ThreatCache) error
	Close() error
}

type NoopStore struct{}

func NewNoopStore() *NoopStore {
	return &NoopStore{}
}

func (n *NoopStore) UpsertMac(context.Context, MacInfo) error {
	return nil
}

func (n *NoopStore) UpdateMacRuntime(context.Context, string, bool, time.Time, uint64, uint64) error {
	return nil
}

func (n *NoopStore) InsertProcessEvent(context.Context, string, *ghostwatcherv1.ProcessEvent, bool, string) error {
	return nil
}

func (n *NoopStore) GetThreat(context.Context, string) (ThreatCache, bool, error) {
	return ThreatCache{}, false, nil
}

func (n *NoopStore) UpsertThreat(context.Context, ThreatCache) error {
	return nil
}

func (n *NoopStore) Close() error {
	return nil
}

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	trimmed := strings.TrimSpace(dbPath)
	if trimmed == "" {
		return nil, fmt.Errorf("empty database path")
	}

	if trimmed != ":memory:" {
		dir := filepath.Dir(trimmed)
		if dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, fmt.Errorf("create db directory: %w", err)
			}
		}
	}

	db, err := sql.Open("sqlite", trimmed)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	db.SetMaxOpenConns(1)

	store := &SQLiteStore{db: db}
	if err := store.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) migrate(ctx context.Context) error {
	statements := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA busy_timeout=5000;`,
		`PRAGMA foreign_keys=ON;`,
		`CREATE TABLE IF NOT EXISTS macs (
			agent_id TEXT PRIMARY KEY,
			hostname TEXT NOT NULL,
			os_version TEXT,
			serial_number TEXT,
			gatekeeper_enabled INTEGER NOT NULL,
			sip_enabled INTEGER NOT NULL,
			security_posture INTEGER NOT NULL,
			auth_token TEXT NOT NULL,
			total_streamed_events INTEGER NOT NULL DEFAULT 0,
			alert_events INTEGER NOT NULL DEFAULT 0,
			last_seen TIMESTAMP NOT NULL,
			connected INTEGER NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS process_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			agent_id TEXT NOT NULL,
			pid INTEGER NOT NULL,
			path TEXT NOT NULL,
			bundle_id TEXT,
			signing_identifier TEXT,
			is_sandboxed INTEGER NOT NULL,
			cd_hash TEXT,
			team_id TEXT,
			sha256 TEXT,
			observed_unix INTEGER NOT NULL,
			is_alert INTEGER NOT NULL,
			threat_name TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(agent_id) REFERENCES macs(agent_id)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_process_events_agent_id ON process_events(agent_id);`,
		`CREATE INDEX IF NOT EXISTS idx_process_events_sha256 ON process_events(sha256);`,
		`CREATE TABLE IF NOT EXISTS threat_cache (
			hash TEXT PRIMARY KEY,
			malicious INTEGER NOT NULL,
			threat_name TEXT,
			source TEXT NOT NULL,
			detail TEXT,
			last_checked TIMESTAMP NOT NULL
		);`,
	}

	for _, stmt := range statements {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate sqlite schema: %w", err)
		}
	}
	return nil
}

func (s *SQLiteStore) UpsertMac(ctx context.Context, info MacInfo) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO macs (
			agent_id, hostname, os_version, serial_number,
			gatekeeper_enabled, sip_enabled, security_posture, auth_token,
			total_streamed_events, alert_events, last_seen, connected
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(agent_id) DO UPDATE SET
			hostname=excluded.hostname,
			os_version=excluded.os_version,
			serial_number=excluded.serial_number,
			gatekeeper_enabled=excluded.gatekeeper_enabled,
			sip_enabled=excluded.sip_enabled,
			security_posture=excluded.security_posture,
			auth_token=excluded.auth_token,
			last_seen=excluded.last_seen,
			connected=excluded.connected,
			updated_at=CURRENT_TIMESTAMP;
	`,
		info.AgentID,
		info.Hostname,
		info.OSVersion,
		info.SerialNumber,
		boolToInt(info.GatekeeperEnabled),
		boolToInt(info.SIPEnabled),
		info.SecurityPosture,
		info.AuthToken,
		info.TotalStreamedEvents,
		info.AlertEvents,
		info.LastSeen.UTC(),
		boolToInt(info.Connected),
	)
	if err != nil {
		return fmt.Errorf("upsert mac: %w", err)
	}
	return nil
}

func (s *SQLiteStore) UpdateMacRuntime(ctx context.Context, agentID string, connected bool, lastSeen time.Time, totalDelta uint64, alertDelta uint64) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE macs
		SET
			total_streamed_events = total_streamed_events + ?,
			alert_events = alert_events + ?,
			connected = ?,
			last_seen = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE agent_id = ?;
	`, totalDelta, alertDelta, boolToInt(connected), lastSeen.UTC(), agentID)
	if err != nil {
		return fmt.Errorf("update mac runtime: %w", err)
	}
	return nil
}

func (s *SQLiteStore) InsertProcessEvent(ctx context.Context, agentID string, event *ghostwatcherv1.ProcessEvent, isAlert bool, threatName string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO process_events (
			agent_id, pid, path, bundle_id, signing_identifier,
			is_sandboxed, cd_hash, team_id, sha256, observed_unix,
			is_alert, threat_name
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`,
		agentID,
		event.GetPid(),
		event.GetPath(),
		event.GetBundleId(),
		event.GetSigningIdentifier(),
		boolToInt(event.GetIsSandboxed()),
		event.GetCdHash(),
		event.GetTeamId(),
		strings.ToLower(strings.TrimSpace(event.GetSha256())),
		event.GetObservedUnix(),
		boolToInt(isAlert),
		threatName,
	)
	if err != nil {
		return fmt.Errorf("insert process event: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetThreat(ctx context.Context, hash string) (ThreatCache, bool, error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if hash == "" {
		return ThreatCache{}, false, nil
	}

	row := s.db.QueryRowContext(ctx, `
		SELECT hash, malicious, threat_name, source, detail, last_checked
		FROM threat_cache
		WHERE hash = ?;
	`, hash)

	var (
		record    ThreatCache
		malicious int
	)
	if err := row.Scan(&record.Hash, &malicious, &record.ThreatName, &record.Source, &record.Detail, &record.LastChecked); err != nil {
		if err == sql.ErrNoRows {
			return ThreatCache{}, false, nil
		}
		return ThreatCache{}, false, fmt.Errorf("get threat cache: %w", err)
	}

	record.Malicious = malicious == 1
	return record, true, nil
}

func (s *SQLiteStore) UpsertThreat(ctx context.Context, record ThreatCache) error {
	record.Hash = strings.ToLower(strings.TrimSpace(record.Hash))
	if record.Hash == "" {
		return nil
	}
	if record.LastChecked.IsZero() {
		record.LastChecked = time.Now().UTC()
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO threat_cache (hash, malicious, threat_name, source, detail, last_checked)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(hash) DO UPDATE SET
			malicious = excluded.malicious,
			threat_name = excluded.threat_name,
			source = excluded.source,
			detail = excluded.detail,
			last_checked = excluded.last_checked;
	`, record.Hash, boolToInt(record.Malicious), record.ThreatName, record.Source, record.Detail, record.LastChecked.UTC())
	if err != nil {
		return fmt.Errorf("upsert threat cache: %w", err)
	}
	return nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
