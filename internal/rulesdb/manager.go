// Package rulesdb is the storage layer for build-time generated SQL rules.
//
// The DB lives at outputs/rules.duckdb and is independent of cases.duckdb —
// see CLAUDE.md "重要な制約 10". Rationale: cases.duckdb holds per-case events
// (high churn, large), rules.duckdb holds the static rule SQL cache (low
// churn, small). Keeping them separate makes backup/restore and CI seeding
// straightforward.
//
// Schema:
//   rule_sql_cache (rule_id, rule_source, rule_sha256, schema_version,
//                   model_id, sql, state, generated_at, prefilter_artifacts,
//                   rule_meta)
//     PRIMARY KEY (rule_id, rule_source)
//     state: 'pending' | 'built' | 'failed'
//
// Cache invalidation:
//   The combination (rule_sha256, schema_version, model_id) is the validity
//   signature. If any of the three drift from the values stored on a row,
//   the row is considered stale and the build pipeline will reset it to
//   'pending' before re-generating.
package rulesdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/marcboeker/go-duckdb"
)

// Mode mirrors casedb.Mode — only ReadWrite is currently used for builds.
type Mode int

const (
	ReadWrite Mode = iota
	ReadOnly
)

// Manager wraps the rules.duckdb connection.
type Manager struct {
	db   *sql.DB
	mode Mode
	path string
}

// Open returns a Manager. ReadWrite creates the DB if missing; ReadOnly fails.
func Open(path string, mode Mode) (*Manager, error) {
	if path == "" {
		return nil, errors.New("rulesdb.Open: path is required")
	}
	if _, err := os.Stat(path); err != nil && os.IsNotExist(err) {
		if mode == ReadOnly {
			return nil, fmt.Errorf("rulesdb at %q does not exist (read-only)", path)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("mkdir for rulesdb: %w", err)
		}
	}
	dsn := path
	if mode == ReadOnly {
		dsn = path + "?access_mode=read_only"
	}
	db, err := sql.Open("duckdb", dsn)
	if err != nil {
		return nil, fmt.Errorf("open duckdb: %w", err)
	}
	db.SetMaxOpenConns(4)
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping duckdb: %w", err)
	}
	m := &Manager{db: db, mode: mode, path: path}
	if mode == ReadWrite {
		if err := m.ensureSchema(context.Background()); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return m, nil
}

// Close releases the connection.
func (m *Manager) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

// DB exposes the underlying *sql.DB for callers that need to ATTACH or
// run raw SQL (e.g. the build worker's progress accounting).
func (m *Manager) DB() *sql.DB { return m.db }

func (m *Manager) ensureSchema(ctx context.Context) error {
	stmts := []string{
		// prefilter_artifacts is a comma-separated TEXT (DuckDB TEXT[] needs
		// special driver support that go-duckdb doesn't expose cleanly).
		// Empty string = "no artifact prefilter, applies to all".
		`CREATE TABLE IF NOT EXISTS rule_sql_cache (
			rule_id              VARCHAR NOT NULL,
			rule_source          VARCHAR NOT NULL,
			rule_sha256          VARCHAR NOT NULL,
			schema_version       VARCHAR NOT NULL,
			model_id             VARCHAR NOT NULL,
			sql                  VARCHAR,
			state                VARCHAR NOT NULL DEFAULT 'pending',
			generated_at         TIMESTAMP,
			prefilter_artifacts  VARCHAR DEFAULT '',
			rule_meta            VARCHAR,
			error_message        VARCHAR,
			PRIMARY KEY (rule_id, rule_source)
		)`,
		// No secondary index: DuckDB disallows ON CONFLICT DO UPDATE on
		// indexed columns, and we update `state` via the UPSERT. At a few
		// thousand rows the full scan is sub-millisecond, so we don't need
		// the index for query speed either.
	}
	for _, s := range stmts {
		if _, err := m.db.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("ddl %q: %w", strings.SplitN(s, "\n", 2)[0], err)
		}
	}
	return nil
}

// CacheState is the per-rule build status.
type CacheState string

const (
	StatePending CacheState = "pending"
	StateBuilt   CacheState = "built"
	StateFailed  CacheState = "failed"
)

// CacheRow is the in-memory shape of a rule_sql_cache row.
type CacheRow struct {
	RuleID              string
	RuleSource          string
	RuleSHA256          string
	SchemaVersion       string
	ModelID             string
	SQL                 string
	State               CacheState
	GeneratedAt         *time.Time
	PrefilterArtifacts  string // comma-separated, may be empty
	RuleMeta            string // JSON-encoded
	ErrorMessage        string
}

// UpsertPending inserts or updates a row to 'pending' state, used by the
// build pipeline to mark rules that need (re)generation. It does NOT
// overwrite a 'built' row whose validity signature still matches.
func (m *Manager) UpsertPending(ctx context.Context, r CacheRow) error {
	if m.mode == ReadOnly {
		return errors.New("rulesdb opened read-only")
	}
	_, err := m.db.ExecContext(ctx, `
		INSERT INTO rule_sql_cache
		    (rule_id, rule_source, rule_sha256, schema_version, model_id,
		     sql, state, generated_at, prefilter_artifacts, rule_meta, error_message)
		VALUES (?, ?, ?, ?, ?, NULL, 'pending', NULL, '', ?, NULL)
		ON CONFLICT (rule_id, rule_source) DO UPDATE SET
		    rule_sha256    = excluded.rule_sha256,
		    schema_version = excluded.schema_version,
		    model_id       = excluded.model_id,
		    rule_meta      = excluded.rule_meta,
		    state          = CASE
		        WHEN rule_sql_cache.rule_sha256    = excluded.rule_sha256
		         AND rule_sql_cache.schema_version = excluded.schema_version
		         AND rule_sql_cache.model_id       = excluded.model_id
		         AND rule_sql_cache.state          = 'built'
		        THEN 'built'
		        ELSE 'pending'
		    END,
		    sql = CASE
		        WHEN rule_sql_cache.rule_sha256    = excluded.rule_sha256
		         AND rule_sql_cache.schema_version = excluded.schema_version
		         AND rule_sql_cache.model_id       = excluded.model_id
		         AND rule_sql_cache.state          = 'built'
		        THEN rule_sql_cache.sql
		        ELSE NULL
		    END,
		    error_message = NULL`,
		r.RuleID, r.RuleSource, r.RuleSHA256, r.SchemaVersion, r.ModelID, r.RuleMeta)
	return err
}

// MarkBuilt records a successful SQL generation.
func (m *Manager) MarkBuilt(ctx context.Context, ruleID, ruleSource, sqlText, prefilterArtifacts string) error {
	if m.mode == ReadOnly {
		return errors.New("rulesdb opened read-only")
	}
	_, err := m.db.ExecContext(ctx, `
		UPDATE rule_sql_cache
		   SET sql = ?, state = 'built', generated_at = ?,
		       prefilter_artifacts = ?, error_message = NULL
		 WHERE rule_id = ? AND rule_source = ?`,
		sqlText, time.Now().UTC(), prefilterArtifacts, ruleID, ruleSource)
	return err
}

// MarkFailed records a build failure (the rule will be retried on next build).
func (m *Manager) MarkFailed(ctx context.Context, ruleID, ruleSource, errMsg string) error {
	if m.mode == ReadOnly {
		return errors.New("rulesdb opened read-only")
	}
	_, err := m.db.ExecContext(ctx, `
		UPDATE rule_sql_cache
		   SET state = 'failed', generated_at = ?, error_message = ?
		 WHERE rule_id = ? AND rule_source = ?`,
		time.Now().UTC(), errMsg, ruleID, ruleSource)
	return err
}

// Delete removes one cache row by (rule_id, rule_source). Used when the
// loader newly classifies a rule as Skip — we no longer want a stale
// failed/pending row to clutter status views or trigger retries.
func (m *Manager) Delete(ctx context.Context, ruleID, ruleSource string) (bool, error) {
	if m.mode == ReadOnly {
		return false, errors.New("rulesdb opened read-only")
	}
	res, err := m.db.ExecContext(ctx,
		`DELETE FROM rule_sql_cache WHERE rule_id = ? AND rule_source = ?`,
		ruleID, ruleSource)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListPending returns all rows in 'pending' or 'failed' state that need
// building (or rebuilding after a failure). Optional source filter.
func (m *Manager) ListPending(ctx context.Context, sourceFilter string) ([]CacheRow, error) {
	q := `SELECT rule_id, rule_source, rule_sha256, schema_version, model_id,
	             COALESCE(sql, ''), state, generated_at,
	             COALESCE(prefilter_artifacts, ''), COALESCE(rule_meta, ''),
	             COALESCE(error_message, '')
	        FROM rule_sql_cache
	       WHERE state IN ('pending', 'failed')`
	args := []any{}
	if sourceFilter != "" {
		q += ` AND rule_source = ?`
		args = append(args, sourceFilter)
	}
	q += ` ORDER BY rule_source, rule_id`
	rows, err := m.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCacheRows(rows)
}

// CountByState returns counts grouped by state. Convenient for the build
// summary line and the Web UI Rule Library view.
func (m *Manager) CountByState(ctx context.Context) (map[CacheState]int, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT state, COUNT(*) FROM rule_sql_cache GROUP BY state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[CacheState]int{}
	for rows.Next() {
		var s string
		var c int
		if err := rows.Scan(&s, &c); err != nil {
			return nil, err
		}
		out[CacheState(s)] = c
	}
	return out, rows.Err()
}

// ListAll returns all rows, optionally filtered by source and/or state.
// Used by `tlvb rules list` and the Web UI.
func (m *Manager) ListAll(ctx context.Context, sourceFilter string, stateFilter CacheState) ([]CacheRow, error) {
	q := `SELECT rule_id, rule_source, rule_sha256, schema_version, model_id,
	             COALESCE(sql, ''), state, generated_at,
	             COALESCE(prefilter_artifacts, ''), COALESCE(rule_meta, ''),
	             COALESCE(error_message, '')
	        FROM rule_sql_cache
	       WHERE 1=1`
	args := []any{}
	if sourceFilter != "" {
		q += ` AND rule_source = ?`
		args = append(args, sourceFilter)
	}
	if stateFilter != "" {
		q += ` AND state = ?`
		args = append(args, string(stateFilter))
	}
	q += ` ORDER BY rule_source, rule_id`
	rows, err := m.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCacheRows(rows)
}

// GetBuiltSQL returns the cached SQL for a rule, or "" if not built.
// Used by Tier 1A runtime — when this returns "" the rule is skipped.
func (m *Manager) GetBuiltSQL(ctx context.Context, ruleID, ruleSource string) (string, error) {
	var sqlText string
	var state string
	err := m.db.QueryRowContext(ctx,
		`SELECT COALESCE(sql, ''), state
		   FROM rule_sql_cache WHERE rule_id = ? AND rule_source = ?`,
		ruleID, ruleSource).Scan(&sqlText, &state)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if state != string(StateBuilt) {
		return "", nil
	}
	return sqlText, nil
}

func scanCacheRows(rows *sql.Rows) ([]CacheRow, error) {
	var out []CacheRow
	for rows.Next() {
		var r CacheRow
		var gen sql.NullTime
		var state string
		if err := rows.Scan(&r.RuleID, &r.RuleSource, &r.RuleSHA256,
			&r.SchemaVersion, &r.ModelID, &r.SQL, &state,
			&gen, &r.PrefilterArtifacts, &r.RuleMeta, &r.ErrorMessage); err != nil {
			return nil, err
		}
		r.State = CacheState(state)
		if gen.Valid {
			t := gen.Time
			r.GeneratedAt = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
