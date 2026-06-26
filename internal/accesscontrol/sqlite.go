package accesscontrol

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const schemaSQL = `
CREATE TABLE IF NOT EXISTS model_policies (
	model TEXT PRIMARY KEY,
	action TEXT NOT NULL DEFAULT 'allow',
	route_to TEXT NOT NULL DEFAULT '',
	channel_to TEXT NOT NULL DEFAULT '',
	reason TEXT NOT NULL DEFAULT '',
	max_rpm INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ip_records (
	ip TEXT PRIMARY KEY,
	status TEXT NOT NULL DEFAULT 'normal',
	reason TEXT NOT NULL DEFAULT '',
	expires_at TEXT,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auto_policies (
	type TEXT PRIMARY KEY,
	threshold INTEGER NOT NULL DEFAULT 50,
	window_seconds INTEGER NOT NULL DEFAULT 300,
	action TEXT NOT NULL DEFAULT 'none',
	duration_seconds INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS client_whitelist (
	client_id TEXT PRIMARY KEY,
	label TEXT NOT NULL DEFAULT '',
	note TEXT NOT NULL DEFAULT '',
	enabled INTEGER NOT NULL DEFAULT 1,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS client_whitelist_meta (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL DEFAULT ''
);
`

const migrateSQL = `
ALTER TABLE model_policies ADD COLUMN max_rpm INTEGER NOT NULL DEFAULT 0;
`

type store struct {
	db *sql.DB
}

func openStore(dbPath string) (*store, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, fmt.Errorf("access control: create directory: %w", err)
	}
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("access control: open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("access control: create schema: %w", err)
	}
	// Best-effort migration: add max_rpm column if missing (existing DBs).
	_, _ = db.Exec(migrateSQL)
	return &store{db: db}, nil
}

func (s *store) close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// --- model policies ---

func (s *store) loadModelPolicies() ([]ModelPolicy, error) {
	rows, err := s.db.Query(`SELECT model, action, route_to, channel_to, reason, max_rpm, created_at FROM model_policies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ModelPolicy
	for rows.Next() {
		var p ModelPolicy
		var createdStr string
		if err = rows.Scan(&p.Model, &p.Action, &p.RouteTo, &p.ChannelTo, &p.Reason, &p.MaxRPM, &createdStr); err != nil {
			return nil, err
		}
		p.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *store) upsertModelPolicy(p ModelPolicy) error {
	_, err := s.db.Exec(`
		INSERT INTO model_policies (model, action, route_to, channel_to, reason, max_rpm, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(model) DO UPDATE SET action=excluded.action, route_to=excluded.route_to,
			channel_to=excluded.channel_to, reason=excluded.reason, max_rpm=excluded.max_rpm, created_at=excluded.created_at
	`, p.Model, p.Action, p.RouteTo, p.ChannelTo, p.Reason, p.MaxRPM, p.CreatedAt.UTC().Format(time.RFC3339))
	return err
}

func (s *store) deleteModelPolicy(model string) error {
	_, err := s.db.Exec(`DELETE FROM model_policies WHERE model = ?`, model)
	return err
}

// --- ip records ---

func (s *store) loadIPRecords() ([]IPRecord, error) {
	rows, err := s.db.Query(`SELECT ip, status, reason, expires_at, created_at FROM ip_records`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IPRecord
	for rows.Next() {
		var r IPRecord
		var expiresStr sql.NullString
		var createdStr string
		if err = rows.Scan(&r.IP, &r.Status, &r.Reason, &expiresStr, &createdStr); err != nil {
			return nil, err
		}
		r.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
		if expiresStr.Valid && expiresStr.String != "" {
			t, errP := time.Parse(time.RFC3339, expiresStr.String)
			if errP == nil {
				r.ExpiresAt = &t
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *store) upsertIPRecord(r IPRecord) error {
	var expiresStr *string
	if r.ExpiresAt != nil {
		s := r.ExpiresAt.UTC().Format(time.RFC3339)
		expiresStr = &s
	}
	_, err := s.db.Exec(`
		INSERT INTO ip_records (ip, status, reason, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET status=excluded.status, reason=excluded.reason,
			expires_at=excluded.expires_at, created_at=excluded.created_at
	`, r.IP, r.Status, r.Reason, expiresStr, r.CreatedAt.UTC().Format(time.RFC3339))
	return err
}

func (s *store) deleteIPRecord(ip string) error {
	_, err := s.db.Exec(`DELETE FROM ip_records WHERE ip = ?`, ip)
	return err
}

// --- auto policies ---

func (s *store) loadAutoPolicies() ([]AutoPolicy, error) {
	rows, err := s.db.Query(`SELECT type, threshold, window_seconds, action, duration_seconds FROM auto_policies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AutoPolicy
	for rows.Next() {
		var a AutoPolicy
		if err = rows.Scan(&a.Type, &a.Threshold, &a.Window, &a.Action, &a.Duration); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *store) upsertAutoPolicy(a AutoPolicy) error {
	_, err := s.db.Exec(`
		INSERT INTO auto_policies (type, threshold, window_seconds, action, duration_seconds)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(type) DO UPDATE SET threshold=excluded.threshold, window_seconds=excluded.window_seconds,
			action=excluded.action, duration_seconds=excluded.duration_seconds
	`, a.Type, a.Threshold, a.Window, a.Action, a.Duration)
	return err
}

// --- client whitelist ---

func (s *store) loadClientWhitelist() (ClientWhitelistState, error) {
	var state ClientWhitelistState
	// Load active flag from meta table.
	var activeVal string
	err := s.db.QueryRow(`SELECT value FROM client_whitelist_meta WHERE key = 'active'`).Scan(&activeVal)
	if err == nil {
		state.Active = activeVal == "1"
	}
	// Load entries.
	rows, errQ := s.db.Query(`SELECT client_id, label, note, enabled, created_at FROM client_whitelist`)
	if errQ != nil {
		return state, errQ
	}
	defer rows.Close()
	for rows.Next() {
		var e ClientEntry
		var createdStr string
		var enabled int
		if err = rows.Scan(&e.ClientID, &e.Label, &e.Note, &enabled, &createdStr); err != nil {
			return state, err
		}
		e.Enabled = enabled != 0
		e.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
		state.Entries = append(state.Entries, e)
	}
	return state, rows.Err()
}

func (s *store) saveClientWhitelist(state ClientWhitelistState) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	activeVal := "0"
	if state.Active {
		activeVal = "1"
	}
	if _, err = tx.Exec(`INSERT INTO client_whitelist_meta (key, value) VALUES ('active', ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, activeVal); err != nil {
		return err
	}

	// Rebuild entries: delete all then re-insert.
	if _, err = tx.Exec(`DELETE FROM client_whitelist`); err != nil {
		return err
	}
	for _, e := range state.Entries {
		enabled := 0
		if e.Enabled {
			enabled = 1
		}
		if e.CreatedAt.IsZero() {
			e.CreatedAt = time.Now()
		}
		if _, err = tx.Exec(`INSERT INTO client_whitelist (client_id, label, note, enabled, created_at)
			VALUES (?, ?, ?, ?, ?)`,
			e.ClientID, e.Label, e.Note, enabled, e.CreatedAt.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	return tx.Commit()
}
