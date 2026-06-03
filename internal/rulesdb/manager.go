// Package rulesdb is the storage layer for build-time generated SQL rules.
//
// The DB lives at outputs/rules.duckdb and is independent of cases.duckdb —
// see CLAUDE.md "重要な制約 10". Rationale: cases.duckdb holds per-case events
// (high churn, large), rules.duckdb holds the static rule SQL cache (low
// churn, small). Keeping them separate makes backup/restore and CI seeding
// straightforward.
//
// Schema:
//
//	rule_sql_cache (rule_id, rule_source, rule_sha256, schema_version,
//	                model_id, sql, state, generated_at, prefilter_artifacts,
//	                rule_meta)
//	  PRIMARY KEY (rule_id, rule_source)
//	  state: 'pending' | 'built' | 'failed'
//
//	skill_sql_cache (skill, sql_sha256, sql, intent, state, origin_case,
//	                 generated_at, hit_count, last_used_case,
//	                 schema_version, model_id)               -- Tier 1B v0.2
//	  PRIMARY KEY (skill, sql_sha256)
//	  state: 'candidate' (LLM-proposed, unproven)
//	       | 'canonical'  (produced a real finding in >=1 case)
//	The two tables share the DB but NOT lifecycle/PK — see the Tier 1B
//	hybrid-cache design memo. rule_sql_cache is build-time prebake; skill
//	queries grow at runtime as the anomaly agent learns reusable lenses.
//
// Cache invalidation:
//
//	The combination (rule_sha256, schema_version, model_id) is the validity
//	signature. If any of the three drift from the values stored on a row,
//	the row is considered stale and the build pipeline will reset it to
//	'pending' before re-generating. For skill_sql_cache the signature is
//	(schema_version, model_id): rows are loaded only when both match the
//	current runtime values, so stale learned SQL is silently ignored.
package rulesdb

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
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
		`CREATE TABLE IF NOT EXISTS skill_sql_cache (
			skill           VARCHAR NOT NULL,
			sql_sha256      VARCHAR NOT NULL,
			sql             VARCHAR NOT NULL,
			intent          VARCHAR,
			state           VARCHAR NOT NULL DEFAULT 'candidate',
			origin_case     VARCHAR,
			generated_at    TIMESTAMP,
			hit_count       INTEGER NOT NULL DEFAULT 0,
			last_used_case  VARCHAR,
			schema_version  VARCHAR NOT NULL,
			model_id        VARCHAR NOT NULL,
			PRIMARY KEY (skill, sql_sha256)
		)`,
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
	RuleID             string
	RuleSource         string
	RuleSHA256         string
	SchemaVersion      string
	ModelID            string
	SQL                string
	State              CacheState
	GeneratedAt        *time.Time
	PrefilterArtifacts string // comma-separated, may be empty
	RuleMeta           string // JSON-encoded
	ErrorMessage       string
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

// SeedBuilt materialises a row in the 'built' state from an external snapshot —
// the JSONL produced by `rules export` and vendored in git. It carries the full
// validity signature (rule_sha256 / schema_version / model_id) verbatim, so a
// later `rules build` against a drifted corpus or model still resets the row to
// 'pending' correctly.
//
// overwrite=false (the default for `rules import`) NEVER modifies a row that
// already exists, in any state — so rules already in outputs/rules.duckdb can
// not be degraded by an import; only genuinely-missing rules are inserted.
// overwrite=true replaces the existing row with the snapshot.
//
// Returns the action taken: "inserted" | "updated" | "skipped".
func (m *Manager) SeedBuilt(ctx context.Context, r CacheRow, overwrite bool) (string, error) {
	if m.mode == ReadOnly {
		return "", errors.New("rulesdb opened read-only")
	}
	exists := false
	switch scanErr := m.db.QueryRowContext(ctx,
		`SELECT 1 FROM rule_sql_cache WHERE rule_id = ? AND rule_source = ?`,
		r.RuleID, r.RuleSource).Scan(new(int)); scanErr {
	case nil:
		exists = true
	case sql.ErrNoRows:
		exists = false
	default:
		return "", scanErr
	}
	if exists && !overwrite {
		return "skipped", nil
	}
	var meta any
	if r.RuleMeta != "" {
		meta = r.RuleMeta
	}
	if _, err := m.db.ExecContext(ctx, `
		INSERT INTO rule_sql_cache
		    (rule_id, rule_source, rule_sha256, schema_version, model_id,
		     sql, state, generated_at, prefilter_artifacts, rule_meta, error_message)
		VALUES (?, ?, ?, ?, ?, ?, 'built', ?, ?, ?, NULL)
		ON CONFLICT (rule_id, rule_source) DO UPDATE SET
		    rule_sha256         = excluded.rule_sha256,
		    schema_version      = excluded.schema_version,
		    model_id            = excluded.model_id,
		    sql                 = excluded.sql,
		    state               = 'built',
		    generated_at        = excluded.generated_at,
		    prefilter_artifacts = excluded.prefilter_artifacts,
		    rule_meta           = excluded.rule_meta,
		    error_message       = NULL`,
		r.RuleID, r.RuleSource, r.RuleSHA256, r.SchemaVersion, r.ModelID,
		r.SQL, time.Now().UTC(), r.PrefilterArtifacts, meta); err != nil {
		return "", err
	}
	if exists {
		return "updated", nil
	}
	return "inserted", nil
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

// ----------------------------------------------------------------------------
// skill_sql_cache — Tier 1B v0.2 learned-lens storage
// ----------------------------------------------------------------------------

// SkillState is the proof status of a learned skill query.
type SkillState string

const (
	// SkillCandidate is an LLM-proposed query that has not yet produced a
	// finding. It is executed on a trial basis but may be pruned by a
	// signature change.
	SkillCandidate SkillState = "candidate"
	// SkillCanonical is a query that produced a real finding in at least
	// one case. It runs unconditionally with zero LLM cost thereafter.
	SkillCanonical SkillState = "canonical"
)

// SkillSQLRow is the in-memory shape of a skill_sql_cache row.
type SkillSQLRow struct {
	Skill         string
	SQLSHA256     string // hash of the normalized SQL; auto-filled on upsert if empty
	SQL           string
	Intent        string
	State         SkillState
	OriginCase    string
	GeneratedAt   *time.Time
	HitCount      int
	LastUsedCase  string
	SchemaVersion string
	ModelID       string
}

// NormalizeSkillSQL canonicalises SQL for dedup hashing: lowercase, collapse
// whitespace runs to a single space, trim, and drop a trailing ';'. Two
// queries that differ only in formatting or literal whitespace hash equal.
func NormalizeSkillSQL(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(strings.TrimSpace(s), ";")
	return strings.Join(strings.Fields(s), " ")
}

// SkillSQLHash returns the sha256 hex of the normalized SQL — the dedup key.
func SkillSQLHash(s string) string {
	h := sha256.Sum256([]byte(NormalizeSkillSQL(s)))
	return hex.EncodeToString(h[:])
}

// UpsertSkillCandidate stores a newly LLM-proposed query as a 'candidate'.
// Returns inserted=true only when (skill, sql_sha256) was new. Existing rows
// (candidate or canonical) are left untouched so we never demote a proven
// query or reset its hit_count — dedup by normalized-SQL hash absorbs
// literal-only variation across runs.
func (m *Manager) UpsertSkillCandidate(ctx context.Context, r SkillSQLRow) (bool, error) {
	if m.mode == ReadOnly {
		return false, errors.New("rulesdb opened read-only")
	}
	if r.SQLSHA256 == "" {
		r.SQLSHA256 = SkillSQLHash(r.SQL)
	}
	var one int
	err := m.db.QueryRowContext(ctx,
		`SELECT 1 FROM skill_sql_cache WHERE skill = ? AND sql_sha256 = ?`,
		r.Skill, r.SQLSHA256).Scan(&one)
	if err == nil {
		return false, nil // already present
	}
	if err != sql.ErrNoRows {
		return false, err
	}
	_, err = m.db.ExecContext(ctx, `
		INSERT INTO skill_sql_cache
		    (skill, sql_sha256, sql, intent, state, origin_case, generated_at,
		     hit_count, last_used_case, schema_version, model_id)
		VALUES (?, ?, ?, ?, 'candidate', ?, ?, 0, NULL, ?, ?)`,
		r.Skill, r.SQLSHA256, r.SQL, r.Intent, r.OriginCase,
		time.Now().UTC(), r.SchemaVersion, r.ModelID)
	if err != nil {
		return false, err
	}
	return true, nil
}

// PromoteSkillSQL marks a query as proven: state -> 'canonical', hit_count++,
// last_used_case set. It is safe to call on an already-canonical row (just
// bumps the counter), so the runner can call it for every cited query
// regardless of current state.
func (m *Manager) PromoteSkillSQL(ctx context.Context, skill, sqlSHA256, usedCase string) error {
	if m.mode == ReadOnly {
		return errors.New("rulesdb opened read-only")
	}
	_, err := m.db.ExecContext(ctx, `
		UPDATE skill_sql_cache
		   SET state = 'canonical', hit_count = hit_count + 1, last_used_case = ?
		 WHERE skill = ? AND sql_sha256 = ?`,
		usedCase, skill, sqlSHA256)
	return err
}

// ListSkillSQL returns the queries for a skill whose validity signature
// (schema_version, model_id) matches the current runtime values. Stale rows
// (built under a different schema/model) are silently excluded — that is the
// invalidation mechanism. Ordered canonical-first, then by hit_count desc.
func (m *Manager) ListSkillSQL(ctx context.Context, skill, schemaVersion, modelID string) ([]SkillSQLRow, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT skill, sql_sha256, sql, COALESCE(intent, ''), state,
		       COALESCE(origin_case, ''), generated_at, hit_count,
		       COALESCE(last_used_case, ''), schema_version, model_id
		  FROM skill_sql_cache
		 WHERE skill = ? AND schema_version = ? AND model_id = ?
		 ORDER BY CASE state WHEN 'canonical' THEN 0 ELSE 1 END,
		          hit_count DESC, sql_sha256`,
		skill, schemaVersion, modelID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSkillRows(rows)
}

// SourceStateCount is one (rule_source, state) bucket count, used by the
// Web UI Rule Library to render the build-coverage matrix.
type SourceStateCount struct {
	Source string
	State  CacheState
	Count  int
}

// CountRulesBySourceState aggregates rule_sql_cache into (source, state)
// buckets without loading SQL text — cheap enough to call per page view.
func (m *Manager) CountRulesBySourceState(ctx context.Context) ([]SourceStateCount, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT rule_source, state, COUNT(*)
		   FROM rule_sql_cache GROUP BY rule_source, state
		  ORDER BY rule_source, state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SourceStateCount
	for rows.Next() {
		var c SourceStateCount
		var st string
		if err := rows.Scan(&c.Source, &st, &c.Count); err != nil {
			return nil, err
		}
		c.State = CacheState(st)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListAllSkillSQL returns every skill_sql_cache row regardless of validity
// signature, ordered canonical-first then by hit_count. Used by the Web UI
// Rule Library to expose the Tier 1B learned-lens cache for inspection.
func (m *Manager) ListAllSkillSQL(ctx context.Context) ([]SkillSQLRow, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT skill, sql_sha256, sql, COALESCE(intent, ''), state,
		       COALESCE(origin_case, ''), generated_at, hit_count,
		       COALESCE(last_used_case, ''), schema_version, model_id
		  FROM skill_sql_cache
		 ORDER BY CASE state WHEN 'canonical' THEN 0 ELSE 1 END,
		          hit_count DESC, skill, sql_sha256`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSkillRows(rows)
}

// ListPrunableSkillCandidates returns 'candidate' rows that were never
// promoted (hit_count = 0) and generated before olderThan — dead weight that
// was proposed across one or more cases but never cited in a finding.
// Canonical rows are always excluded.
func (m *Manager) ListPrunableSkillCandidates(ctx context.Context, olderThan time.Time) ([]SkillSQLRow, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT skill, sql_sha256, sql, COALESCE(intent, ''), state,
		       COALESCE(origin_case, ''), generated_at, hit_count,
		       COALESCE(last_used_case, ''), schema_version, model_id
		  FROM skill_sql_cache
		 WHERE state = 'candidate' AND hit_count = 0 AND generated_at < ?
		 ORDER BY generated_at`, olderThan.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSkillRows(rows)
}

// PruneSkillCandidates deletes the rows ListPrunableSkillCandidates would
// return and reports how many were removed. Canonical rows are never touched,
// so a query that has proven itself in any case is permanent.
func (m *Manager) PruneSkillCandidates(ctx context.Context, olderThan time.Time) (int, error) {
	if m.mode == ReadOnly {
		return 0, errors.New("rulesdb opened read-only")
	}
	res, err := m.db.ExecContext(ctx, `
		DELETE FROM skill_sql_cache
		 WHERE state = 'candidate' AND hit_count = 0 AND generated_at < ?`,
		olderThan.UTC())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// CountSkillByState returns counts grouped by state across all skills.
func (m *Manager) CountSkillByState(ctx context.Context) (map[SkillState]int, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT state, COUNT(*) FROM skill_sql_cache GROUP BY state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[SkillState]int{}
	for rows.Next() {
		var s string
		var c int
		if err := rows.Scan(&s, &c); err != nil {
			return nil, err
		}
		out[SkillState(s)] = c
	}
	return out, rows.Err()
}

func scanSkillRows(rows *sql.Rows) ([]SkillSQLRow, error) {
	var out []SkillSQLRow
	for rows.Next() {
		var r SkillSQLRow
		var gen sql.NullTime
		var state string
		if err := rows.Scan(&r.Skill, &r.SQLSHA256, &r.SQL, &r.Intent, &state,
			&r.OriginCase, &gen, &r.HitCount, &r.LastUsedCase,
			&r.SchemaVersion, &r.ModelID); err != nil {
			return nil, err
		}
		r.State = SkillState(state)
		if gen.Valid {
			t := gen.Time
			r.GeneratedAt = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
