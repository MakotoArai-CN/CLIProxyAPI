package usage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	coreusage "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
	log "github.com/sirupsen/logrus"
	_ "modernc.org/sqlite"
)

const createTableSQL = `
CREATE TABLE IF NOT EXISTS usage_records (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	api_key TEXT NOT NULL,
	model TEXT NOT NULL,
	provider TEXT NOT NULL DEFAULT '',
	source TEXT NOT NULL DEFAULT '',
	auth_index TEXT NOT NULL DEFAULT '',
	requested_at TEXT NOT NULL,
	latency_ms INTEGER NOT NULL DEFAULT 0,
	failed INTEGER NOT NULL DEFAULT 0,
	input_tokens INTEGER NOT NULL DEFAULT 0,
	output_tokens INTEGER NOT NULL DEFAULT 0,
	reasoning_tokens INTEGER NOT NULL DEFAULT 0,
	cached_tokens INTEGER NOT NULL DEFAULT 0,
	total_tokens INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_usage_api_key ON usage_records(api_key);
CREATE INDEX IF NOT EXISTS idx_usage_requested_at ON usage_records(requested_at);
`

// SQLitePlugin persists usage records to a SQLite database file.
// It implements coreusage.Plugin.
type SQLitePlugin struct {
	db   *sql.DB
	mu   sync.Mutex
	stmt *sql.Stmt
}

// NewSQLitePlugin opens (or creates) the SQLite database at dbPath and returns a plugin
// ready to receive usage records. The caller should call Close when done.
func NewSQLitePlugin(dbPath string) (*SQLitePlugin, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, fmt.Errorf("sqlite usage: create directory: %w", err)
	}
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("sqlite usage: open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(createTableSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite usage: create schema: %w", err)
	}
	stmt, err := db.Prepare(`
		INSERT INTO usage_records
			(api_key, model, provider, source, auth_index, requested_at, latency_ms, failed,
			 input_tokens, output_tokens, reasoning_tokens, cached_tokens, total_tokens)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite usage: prepare insert: %w", err)
	}
	return &SQLitePlugin{db: db, stmt: stmt}, nil
}

// HandleUsage implements coreusage.Plugin.
func (p *SQLitePlugin) HandleUsage(_ context.Context, record coreusage.Record) {
	if p == nil || p.db == nil {
		return
	}
	timestamp := record.RequestedAt
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	detail := normaliseDetail(record.Detail)
	model := record.Model
	if model == "" {
		model = "unknown"
	}
	apiKey := record.APIKey
	if apiKey == "" {
		apiKey = record.Provider
	}
	failed := 0
	if record.Failed {
		failed = 1
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := p.stmt.Exec(
		apiKey,
		model,
		record.Provider,
		record.Source,
		record.AuthIndex,
		timestamp.UTC().Format(time.RFC3339Nano),
		normaliseLatency(record.Latency),
		failed,
		detail.InputTokens,
		detail.OutputTokens,
		detail.ReasoningTokens,
		detail.CachedTokens,
		detail.TotalTokens,
	); err != nil {
		log.WithError(err).Error("sqlite usage: insert record failed")
	}
}

// RestoreInto loads all persisted records into the given RequestStatistics store.
func (p *SQLitePlugin) RestoreInto(stats *RequestStatistics) error {
	if p == nil || p.db == nil || stats == nil {
		return nil
	}
	rows, err := p.db.Query(`
		SELECT api_key, model, provider, source, auth_index, requested_at, latency_ms, failed,
		       input_tokens, output_tokens, reasoning_tokens, cached_tokens, total_tokens
		FROM usage_records ORDER BY id
	`)
	if err != nil {
		return fmt.Errorf("sqlite usage: query records: %w", err)
	}
	defer rows.Close()

	snapshot := StatisticsSnapshot{
		APIs: make(map[string]APISnapshot),
	}
	for rows.Next() {
		var (
			apiKey          string
			model           string
			provider        string
			source          string
			authIndex       string
			requestedAtStr  string
			latencyMs       int64
			failed          int
			inputTokens     int64
			outputTokens    int64
			reasoningTokens int64
			cachedTokens    int64
			totalTokens     int64
		)
		if err = rows.Scan(&apiKey, &model, &provider, &source, &authIndex, &requestedAtStr,
			&latencyMs, &failed, &inputTokens, &outputTokens, &reasoningTokens, &cachedTokens, &totalTokens); err != nil {
			return fmt.Errorf("sqlite usage: scan row: %w", err)
		}
		requestedAt, errParse := time.Parse(time.RFC3339Nano, requestedAtStr)
		if errParse != nil {
			requestedAt = time.Now()
		}
		detail := RequestDetail{
			Timestamp: requestedAt,
			LatencyMs: latencyMs,
			Source:    source,
			AuthIndex: authIndex,
			Tokens: TokenStats{
				InputTokens:     inputTokens,
				OutputTokens:    outputTokens,
				ReasoningTokens: reasoningTokens,
				CachedTokens:    cachedTokens,
				TotalTokens:     totalTokens,
			},
			Failed: failed != 0,
		}
		apiSnap, ok := snapshot.APIs[apiKey]
		if !ok {
			apiSnap = APISnapshot{Models: make(map[string]ModelSnapshot)}
		}
		modelSnap := apiSnap.Models[model]
		modelSnap.TotalRequests++
		modelSnap.TotalTokens += totalTokens
		modelSnap.Details = append(modelSnap.Details, detail)
		apiSnap.Models[model] = modelSnap
		apiSnap.TotalRequests++
		apiSnap.TotalTokens += totalTokens
		snapshot.APIs[apiKey] = apiSnap
	}
	if err = rows.Err(); err != nil {
		return fmt.Errorf("sqlite usage: iterate rows: %w", err)
	}
	if len(snapshot.APIs) > 0 {
		result := stats.MergeSnapshot(snapshot)
		log.Infof("sqlite usage: restored %d records (%d skipped) from database", result.Added, result.Skipped)
	}
	return nil
}

// Close releases the database resources.
func (p *SQLitePlugin) Close() error {
	if p == nil || p.db == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stmt != nil {
		_ = p.stmt.Close()
	}
	return p.db.Close()
}

// RegisterSQLitePlugin registers the given SQLite plugin on the default usage manager.
func RegisterSQLitePlugin(plugin *SQLitePlugin) {
	coreusage.RegisterPlugin(plugin)
}
