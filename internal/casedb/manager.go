// Package casedb is the read-mostly access layer for case state.
//
// Schema (DuckDB):
//
//	cases            (case_id PK, name, examiner, timezone, created_at, status)
//	evidence         (evidence_id PK, case_id FK, path, sha256, size_bytes,
//	                  registered_at, source_host, evidence_type)
//	parse_results    (case_id, artifact_id PK, started_at, finished_at,
//	                  command, exit_code, stdout_tail, stderr_tail,
//	                  output_csv, row_count)
//	unified_events   (case_id, evidence_id, artifact_id, audit_id, ts_utc,
//	                  event_type, computer, payload_json)  -- main fact table
//
// All public methods on *Manager are read-only when opened with ReadOnly.
// Mutating helpers (RegisterCase, RegisterEvidence, RecordParseResult,
// AppendUnifiedEvents) are used by the orchestrator/CLI, not by the MCP server.
package casedb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "github.com/marcboeker/go-duckdb" // registers "duckdb" driver
)

// Mode controls connection access.
type Mode int

const (
	ReadWrite Mode = iota
	ReadOnly
)

// Manager wraps a DuckDB connection plus convenience helpers.
type Manager struct {
	db   *sql.DB
	mode Mode
	path string
}

// Open returns a Manager. If the database file does not exist and mode is
// ReadWrite, the schema is initialised. ReadOnly callers fail if the file
// is missing — that is intentional, the MCP server should never auto-create.
func Open(path string, mode Mode) (*Manager, error) {
	if path == "" {
		return nil, errors.New("casedb.Open: path is required")
	}

	if _, err := os.Stat(path); err != nil && os.IsNotExist(err) {
		if mode == ReadOnly {
			return nil, fmt.Errorf("casedb at %q does not exist (read-only)", path)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("mkdir for casedb: %w", err)
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
		ctx := context.Background()
		if err := m.ensureSchema(ctx); err != nil {
			_ = db.Close()
			return nil, err
		}
		// Wave 16: upgrade evidence PK in place if this DB was created
		// before the (case_id, evidence_id) composite key.
		if err := m.migrateEvidencePK(ctx); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("migrate evidence PK: %w", err)
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

// Ping is used by the health endpoint.
func (m *Manager) Ping(ctx context.Context) error { return m.db.PingContext(ctx) }

// DB returns the underlying *sql.DB so callers that need to run custom
// SQL (e.g. Wave 20f `case vacuum` which ATTACHes a second DB) can do so
// without going through the typed wrappers. Returns nil if Manager has
// been closed. Use with care — the typed methods enforce schema
// invariants this raw handle does not.
func (m *Manager) DB() *sql.DB { return m.db }

// ensureSchema runs the DDL idempotently. DuckDB supports IF NOT EXISTS.
func (m *Manager) ensureSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS cases (
			case_id      VARCHAR PRIMARY KEY,
			name         VARCHAR NOT NULL,
			examiner     VARCHAR NOT NULL,
			timezone     VARCHAR NOT NULL DEFAULT 'UTC',
			created_at   TIMESTAMP NOT NULL,
			status       VARCHAR NOT NULL DEFAULT 'active'
		)`,
		// Wave 16: evidence PK is the (case_id, evidence_id) pair — one
		// triage zip parsed under multiple case_ids will get separate
		// rows. Earlier versions used `evidence_id PRIMARY KEY` alone,
		// which silently dropped the second case's INSERT and produced
		// the "has no registered evidence" Analyze error. See
		// migrateEvidencePK() for the in-place upgrade path.
		`CREATE TABLE IF NOT EXISTS evidence (
			evidence_id     VARCHAR NOT NULL,
			case_id         VARCHAR NOT NULL,
			path            VARCHAR NOT NULL,
			sha256          VARCHAR NOT NULL,
			size_bytes      BIGINT  NOT NULL,
			registered_at   TIMESTAMP NOT NULL,
			source_host     VARCHAR,
			evidence_type   VARCHAR,
			timezone        VARCHAR,
			PRIMARY KEY (case_id, evidence_id)
		)`,
		// Per-evidence display timezone (IANA name). NULL means "inherit the
		// case timezone". Stored events stay canonical UTC; this drives only
		// the display-time conversion (Web UI + Tier 3 reports) and is the
		// source zone used to canonicalise naive-local artifacts at parse
		// time (IIS native, web error logs). ADD COLUMN IF NOT EXISTS makes
		// this idempotent for DBs created before the column existed.
		`ALTER TABLE evidence ADD COLUMN IF NOT EXISTS timezone VARCHAR`,
		`CREATE TABLE IF NOT EXISTS parse_results (
			case_id      VARCHAR NOT NULL,
			artifact_id  VARCHAR NOT NULL,
			started_at   TIMESTAMP NOT NULL,
			finished_at  TIMESTAMP,
			command      VARCHAR NOT NULL,
			exit_code    INTEGER,
			stdout_tail  VARCHAR,
			stderr_tail  VARCHAR,
			output_csv   VARCHAR,
			row_count    BIGINT,
			PRIMARY KEY (case_id, artifact_id)
		)`,
		UnifiedEventsDDL,
		`CREATE INDEX IF NOT EXISTS idx_unified_events_lookup
			ON unified_events(case_id, artifact_id, ts_utc)`,
	}
	for _, s := range stmts {
		if _, err := m.db.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("ddl %q: %w", strings.SplitN(s, "\n", 2)[0], err)
		}
	}
	return nil
}

// migrateEvidencePK upgrades a v0 evidence schema (PRIMARY KEY on
// evidence_id alone) to the Wave 16 composite key (case_id, evidence_id).
// Without the composite key, parsing the same triage bundle under a
// second case silently drops the new evidence row (PK conflict), which
// later surfaces as "case has no registered evidence" during Analyze.
//
// Strategy: rename the existing table aside, recreate with the new PK,
// COPY all rows back, drop the old. Existing rows can never violate the
// new PK because the old PK was already strictly stronger (evidence_id
// alone implies (case_id, evidence_id) uniqueness), so the COPY always
// succeeds. The whole transition runs inside one statement batch so a
// crash mid-migration leaves the DB recoverable on next start.
func (m *Manager) migrateEvidencePK(ctx context.Context) error {
	// Inspect the current PK columns. DuckDB exposes PK membership via
	// PRAGMA table_info("evidence") — the 6th column ("pk") is a bool
	// flag (true if the column participates in the primary key). Note
	// it does NOT report the position within a composite key, so we
	// rely on column-name presence to decide which schema we're on.
	rows, err := m.db.QueryContext(ctx, `PRAGMA table_info('evidence')`)
	if err != nil {
		return fmt.Errorf("inspect evidence schema: %w", err)
	}
	var pkCols []string
	for rows.Next() {
		var (
			cid     int
			name    string
			typ     string
			notnull bool
			dflt    sql.NullString
			pk      bool
		)
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan table_info: %w", err)
		}
		if pk {
			pkCols = append(pkCols, name)
		}
	}
	_ = rows.Close()

	// Normalise ordering so the membership check is positional-stable.
	sort.Strings(pkCols)

	// Already on the new (Wave 16) schema: composite key on case_id +
	// evidence_id. Nothing to do.
	if len(pkCols) == 2 && pkCols[0] == "case_id" && pkCols[1] == "evidence_id" {
		return nil
	}
	// Old (v0) schema: PK on evidence_id alone. Migration needed.
	if !(len(pkCols) == 1 && pkCols[0] == "evidence_id") {
		// Empty PK or some other unexpected shape — bail rather than
		// silently reshape a schema we don't recognise.
		return fmt.Errorf("unexpected evidence PK shape: %+v", pkCols)
	}

	// Old schema confirmed. Rebuild in a single batch.
	const migrationSQL = `
ALTER TABLE evidence RENAME TO evidence_v0;
CREATE TABLE evidence (
    evidence_id     VARCHAR NOT NULL,
    case_id         VARCHAR NOT NULL,
    path            VARCHAR NOT NULL,
    sha256          VARCHAR NOT NULL,
    size_bytes      BIGINT  NOT NULL,
    registered_at   TIMESTAMP NOT NULL,
    source_host     VARCHAR,
    evidence_type   VARCHAR,
    timezone        VARCHAR,
    PRIMARY KEY (case_id, evidence_id)
);
INSERT INTO evidence
    SELECT evidence_id, case_id, path, sha256, size_bytes,
           registered_at, source_host, evidence_type, timezone
    FROM evidence_v0;
DROP TABLE evidence_v0;`
	if _, err := m.db.ExecContext(ctx, migrationSQL); err != nil {
		return fmt.Errorf("rebuild evidence table: %w", err)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Read API (used by the MCP server)
// ----------------------------------------------------------------------------

type CaseRow struct {
	CaseID    string    `json:"case_id"`
	Name      string    `json:"name"`
	Examiner  string    `json:"examiner"`
	Timezone  string    `json:"timezone"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"`
}

func (m *Manager) ListCases(ctx context.Context) ([]CaseRow, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT case_id, name, examiner, timezone, created_at, status
		   FROM cases ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CaseRow
	for rows.Next() {
		var c CaseRow
		if err := rows.Scan(&c.CaseID, &c.Name, &c.Examiner, &c.Timezone, &c.CreatedAt, &c.Status); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// EventCountsByCase returns per-case ingested-event counts for the Dashboard
// listing, derived from the tiny parse_results table (SUM of the parser-
// reported row_count) rather than by scanning the multi-GB unified_events
// table.
//
// Why not COUNT(unified_events): the listing must enrich *every* case at once,
// and a grouped COUNT over unified_events makes the go-duckdb driver hang for
// minutes on some large DBs (the same payload block where it asserts on heavy
// queries — Python duckdb runs the identical COUNT in ~10ms, so it is a driver
// issue, not the query). parse_results carries one row per (case, artifact)
// with the row_count recorded at ingest, so SUM(row_count) is the same total
// without ever touching the fact table. Cases with no parse rows are absent
// from the map (callers default to 0).
func (m *Manager) EventCountsByCase(ctx context.Context) (map[string]int64, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT case_id, CAST(COALESCE(SUM(row_count), 0) AS BIGINT)
		   FROM parse_results GROUP BY case_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int64)
	for rows.Next() {
		var id string
		var n int64
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// CountEvidenceByCase returns evidence counts for every case in a single
// GROUP BY scan (same rationale as CountUnifiedEventsByCase).
func (m *Manager) CountEvidenceByCase(ctx context.Context) (map[string]int, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT case_id, COUNT(*) FROM evidence GROUP BY case_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int)
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

type CaseStatus struct {
	Case          CaseRow          `json:"case"`
	EvidenceCount int              `json:"evidence_count"`
	ParseResults  []ParseResultRow `json:"parse_results"`
	// UnifiedRowCount is the total ingested-event count for the case, derived
	// scan-free from SUM(parse_results.row_count) — it is NOT a live COUNT(*)
	// over unified_events. See GetCaseStatus for the rationale. The JSON field
	// name is kept as "unified_event_rows" for wire compatibility.
	UnifiedRowCount int64 `json:"unified_event_rows"`
}

func (m *Manager) GetCaseStatus(ctx context.Context, caseID string) (*CaseStatus, error) {
	var c CaseRow
	err := m.db.QueryRowContext(ctx,
		`SELECT case_id, name, examiner, timezone, created_at, status
		   FROM cases WHERE case_id = ?`, caseID).
		Scan(&c.CaseID, &c.Name, &c.Examiner, &c.Timezone, &c.CreatedAt, &c.Status)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("case %q not found", caseID)
	}
	if err != nil {
		return nil, err
	}
	out := &CaseStatus{Case: c}

	if err := m.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM evidence WHERE case_id = ?`, caseID).
		Scan(&out.EvidenceCount); err != nil {
		return nil, err
	}
	// UnifiedRowCount is the SUM of the parser-reported row_count in
	// parse_results, NOT a COUNT(*) over unified_events. Same rationale as
	// EventCountsByCase (used by the Dashboard listing): a COUNT over the
	// multi-GB fact table makes the go-duckdb driver hang for minutes on
	// large DBs / un-checkpointed WALs, which froze the case-detail view.
	// parse_results carries one row per (case, artifact) with the row_count
	// recorded at ingest, so the SUM is the same total without ever touching
	// unified_events. COALESCE handles a case with no parse rows (→ 0).
	if err := m.db.QueryRowContext(ctx,
		`SELECT CAST(COALESCE(SUM(row_count), 0) AS BIGINT)
		   FROM parse_results WHERE case_id = ?`, caseID).
		Scan(&out.UnifiedRowCount); err != nil {
		return nil, err
	}

	prs, err := m.listParseResultsForCase(ctx, caseID)
	if err != nil {
		return nil, err
	}
	out.ParseResults = prs
	return out, nil
}

type EvidenceRow struct {
	EvidenceID   string    `json:"evidence_id"`
	CaseID       string    `json:"case_id"`
	Path         string    `json:"path"`
	SHA256       string    `json:"sha256"`
	SizeBytes    int64     `json:"size_bytes"`
	RegisteredAt time.Time `json:"registered_at"`
	SourceHost   string    `json:"source_host,omitempty"`
	EvidenceType string    `json:"evidence_type,omitempty"`
	// Timezone is the per-evidence display timezone (IANA name). Empty means
	// "inherit the case timezone". Events are stored in UTC regardless; this
	// only drives display-time conversion and naive-local parse canonicalisation.
	Timezone string `json:"timezone,omitempty"`
}

// columnExists reports whether table.column is present in the current schema.
// Used to stay compatible with a cases.duckdb written by an older binary that
// the read-only query path can't migrate in place — ensureSchema (and its
// ADD COLUMN migrations) only runs on a ReadWrite open. Cheap catalog lookup,
// safe on a read-only connection.
func (m *Manager) columnExists(ctx context.Context, table, column string) bool {
	var n int
	if err := m.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM information_schema.columns
		   WHERE table_name = ? AND column_name = ?`, table, column).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

func (m *Manager) ListEvidence(ctx context.Context, caseID string) ([]EvidenceRow, error) {
	// evidence.timezone (per-evidence display TZ) was added after the initial
	// schema. A DB last written by an older binary and only ever opened
	// read-only afterwards (the web server's query path) never had the
	// ADD COLUMN migration applied, so selecting the column errors and blanks
	// the entire evidence list — which silently disabled the Events-tab
	// evidence filter and the per-evidence Status view. Degrade to an empty
	// timezone (= inherit the case timezone) when the column is absent; the
	// next ReadWrite open re-runs ensureSchema and adds it for real.
	tzExpr := "COALESCE(timezone, '')"
	if !m.columnExists(ctx, "evidence", "timezone") {
		tzExpr = "'' AS timezone"
	}
	rows, err := m.db.QueryContext(ctx,
		`SELECT evidence_id, case_id, path, sha256, size_bytes,
		        registered_at, COALESCE(source_host, ''), COALESCE(evidence_type, ''),
		        `+tzExpr+`
		   FROM evidence WHERE case_id = ? ORDER BY registered_at`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EvidenceRow
	for rows.Next() {
		var e EvidenceRow
		if err := rows.Scan(&e.EvidenceID, &e.CaseID, &e.Path, &e.SHA256, &e.SizeBytes,
			&e.RegisteredAt, &e.SourceHost, &e.EvidenceType, &e.Timezone); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type ParseResultRow struct {
	CaseID     string     `json:"case_id"`
	ArtifactID string     `json:"artifact_id"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Command    string     `json:"command"`
	ExitCode   *int       `json:"exit_code,omitempty"`
	StdoutTail string     `json:"stdout_tail,omitempty"`
	StderrTail string     `json:"stderr_tail,omitempty"`
	OutputCSV  string     `json:"output_csv,omitempty"`
	RowCount   *int64     `json:"row_count,omitempty"`
}

func (m *Manager) GetParseResult(ctx context.Context, caseID, artifactID string) (*ParseResultRow, error) {
	var p ParseResultRow
	var fin sql.NullTime
	var exit sql.NullInt64
	var rc sql.NullInt64
	err := m.db.QueryRowContext(ctx,
		`SELECT case_id, artifact_id, started_at, finished_at, command,
		        exit_code, COALESCE(stdout_tail,''), COALESCE(stderr_tail,''),
		        COALESCE(output_csv,''), row_count
		   FROM parse_results WHERE case_id = ? AND artifact_id = ?`,
		caseID, artifactID).
		Scan(&p.CaseID, &p.ArtifactID, &p.StartedAt, &fin, &p.Command,
			&exit, &p.StdoutTail, &p.StderrTail, &p.OutputCSV, &rc)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no parse result for case=%s artifact=%s", caseID, artifactID)
	}
	if err != nil {
		return nil, err
	}
	if fin.Valid {
		t := fin.Time
		p.FinishedAt = &t
	}
	if exit.Valid {
		v := int(exit.Int64)
		p.ExitCode = &v
	}
	if rc.Valid {
		p.RowCount = &rc.Int64
	}
	return &p, nil
}

func (m *Manager) listParseResultsForCase(ctx context.Context, caseID string) ([]ParseResultRow, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT case_id, artifact_id, started_at, finished_at, command,
		        exit_code, COALESCE(stdout_tail,''), COALESCE(stderr_tail,''),
		        COALESCE(output_csv,''), row_count
		   FROM parse_results WHERE case_id = ? ORDER BY artifact_id`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ParseResultRow
	for rows.Next() {
		var p ParseResultRow
		var fin sql.NullTime
		var exit sql.NullInt64
		var rc sql.NullInt64
		if err := rows.Scan(&p.CaseID, &p.ArtifactID, &p.StartedAt, &fin, &p.Command,
			&exit, &p.StdoutTail, &p.StderrTail, &p.OutputCSV, &rc); err != nil {
			return nil, err
		}
		if fin.Valid {
			t := fin.Time
			p.FinishedAt = &t
		}
		if exit.Valid {
			v := int(exit.Int64)
			p.ExitCode = &v
		}
		if rc.Valid {
			p.RowCount = &rc.Int64
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UnifiedEventQuery captures filter parameters from the MCP tool call.
type UnifiedEventQuery struct {
	CaseID     string
	ArtifactID string
	EvidenceID string // exact evidence_id match — scope events to one source evidence
	AuditID    string // exact audit_id match — Issue #20 (Evidence row drill-down)
	StartTime  string // ISO8601 UTC, optional
	EndTime    string
	Computer   string
	Contains   string
	Limit      int
	Offset     int
}

type UnifiedEventRow struct {
	CaseID      string    `json:"case_id"`
	EvidenceID  string    `json:"evidence_id,omitempty"`
	ArtifactID  string    `json:"artifact_id"`
	AuditID     string    `json:"audit_id"`
	TsUTC       time.Time `json:"ts_utc"`
	EventType   string    `json:"event_type"`
	Computer    string    `json:"computer,omitempty"`
	PayloadJSON string    `json:"payload_json"` // raw JSON string; client parses if needed
}

func (m *Manager) QueryUnifiedEvents(ctx context.Context, q UnifiedEventQuery) ([]UnifiedEventRow, error) {
	if q.CaseID == "" {
		return nil, errors.New("case_id is required")
	}
	if q.Limit <= 0 {
		q.Limit = 100
	}

	var sb strings.Builder
	args := []any{q.CaseID}
	sb.WriteString(`SELECT case_id, COALESCE(evidence_id, ''), artifact_id, audit_id,
	        ts_utc, event_type, COALESCE(computer, ''), payload_json
	    FROM unified_events
	   WHERE case_id = ?`)

	if q.ArtifactID != "" {
		sb.WriteString(` AND artifact_id = ?`)
		args = append(args, q.ArtifactID)
	}
	if q.EvidenceID != "" {
		sb.WriteString(` AND evidence_id = ?`)
		args = append(args, q.EvidenceID)
	}
	if q.AuditID != "" {
		sb.WriteString(` AND audit_id = ?`)
		args = append(args, q.AuditID)
	}
	// CAST: the driver binds these as VARCHAR and DuckDB refuses an implicit
	// TIMESTAMP vs VARCHAR comparison. CAST accepts both "2026-06-08 09:17:46"
	// and ISO "2026-06-08T09:17:46Z" (ts_utc is stored as naive UTC).
	if q.StartTime != "" {
		sb.WriteString(` AND ts_utc >= CAST(? AS TIMESTAMP)`)
		args = append(args, q.StartTime)
	}
	if q.EndTime != "" {
		sb.WriteString(` AND ts_utc < CAST(? AS TIMESTAMP)`)
		args = append(args, q.EndTime)
	}
	if q.Computer != "" {
		sb.WriteString(` AND computer = ?`)
		args = append(args, q.Computer)
	}
	if q.Contains != "" {
		sb.WriteString(` AND payload_json LIKE ?`)
		args = append(args, "%"+q.Contains+"%")
	}
	sb.WriteString(` ORDER BY ts_utc LIMIT ? OFFSET ?`)
	args = append(args, q.Limit, q.Offset)

	rows, err := m.db.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UnifiedEventRow
	for rows.Next() {
		var (
			u  UnifiedEventRow
			ts sql.NullTime
		)
		// Wave 47: ts_utc CAN be NULL for artifacts that don't carry
		// a per-event timestamp (shimcache is the classic case — the
		// SHIM CACHE in the registry only records the file's
		// LastModified, not when it was actually run). Scanning a
		// NULL TIMESTAMP into *time.Time crashes the driver with
		// "unsupported Scan, storing driver.Value type <nil> into
		// type *time.Time" and used to make `case export` abort,
		// which in turn made `case import` impossible because no
		// .fcz could be produced. Use sql.NullTime to absorb the
		// NULL, then map Valid → u.TsUTC, !Valid → zero time.
		if err := rows.Scan(&u.CaseID, &u.EvidenceID, &u.ArtifactID, &u.AuditID,
			&ts, &u.EventType, &u.Computer, &u.PayloadJSON); err != nil {
			return nil, err
		}
		if ts.Valid {
			u.TsUTC = ts.Time
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ----------------------------------------------------------------------------
// Write API (used by orchestrator/CLI; NOT exposed via MCP)
// ----------------------------------------------------------------------------

// RegisterCase inserts a new case row. Idempotent on case_id.
func (m *Manager) RegisterCase(ctx context.Context, c CaseRow) error {
	if m.mode == ReadOnly {
		return errors.New("casedb opened read-only")
	}
	if c.Timezone == "" {
		c.Timezone = "UTC"
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	if c.Status == "" {
		c.Status = "active"
	}
	_, err := m.db.ExecContext(ctx, `
		INSERT INTO cases (case_id, name, examiner, timezone, created_at, status)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (case_id) DO UPDATE SET
		  name=excluded.name, examiner=excluded.examiner,
		  timezone=excluded.timezone, status=excluded.status`,
		c.CaseID, c.Name, c.Examiner, c.Timezone, c.CreatedAt, c.Status)
	return err
}

// DeleteCase removes the case row plus all dependent rows (evidence,
// parse_results, unified_events). Intended for the Web UI's "Delete case"
// action — DuckDB has no FK cascade so we delete each table explicitly.
//
// Note on chain-of-custody: this does NOT remove the on-disk evidence
// files (the original images live outside outputs/). It only removes the
// indexed metadata. The Web layer is responsible for removing the case
// workspace dir.
func (m *Manager) DeleteCase(ctx context.Context, caseID string) error {
	if m.mode == ReadOnly {
		return errors.New("casedb opened read-only")
	}
	stmts := []struct {
		sql  string
		name string
	}{
		{`DELETE FROM unified_events WHERE case_id = ?`, "unified_events"},
		{`DELETE FROM parse_results WHERE case_id = ?`, "parse_results"},
		{`DELETE FROM evidence WHERE case_id = ?`, "evidence"},
		{`DELETE FROM cases WHERE case_id = ?`, "cases"},
	}
	for _, s := range stmts {
		if _, err := m.db.ExecContext(ctx, s.sql, caseID); err != nil {
			return fmt.Errorf("delete %s for case %q: %w", s.name, caseID, err)
		}
	}
	return nil
}

// Checkpoint flushes the write-ahead log into the main database file. A large
// delete (e.g. dropping a case's hundreds of thousands of unified_events rows)
// can leave megabytes in the WAL; until it is checkpointed, go-duckdb stalls
// replaying that WAL on every subsequent read-only open, which makes the
// Dashboard listing and case detail hang. Callers run this right after a big
// mutation so the WAL never lingers.
func (m *Manager) Checkpoint(ctx context.Context) error {
	if m.mode == ReadOnly {
		return errors.New("casedb opened read-only")
	}
	_, err := m.db.ExecContext(ctx, `CHECKPOINT`)
	return err
}

// RegisterEvidence inserts an evidence row.
func (m *Manager) RegisterEvidence(ctx context.Context, e EvidenceRow) error {
	if m.mode == ReadOnly {
		return errors.New("casedb opened read-only")
	}
	if e.RegisteredAt.IsZero() {
		e.RegisteredAt = time.Now().UTC()
	}
	_, err := m.db.ExecContext(ctx, `
		INSERT INTO evidence (evidence_id, case_id, path, sha256, size_bytes,
		                     registered_at, source_host, evidence_type, timezone)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.EvidenceID, e.CaseID, e.Path, e.SHA256, e.SizeBytes,
		e.RegisteredAt, nullableString(e.SourceHost), nullableString(e.EvidenceType),
		nullableString(e.Timezone))
	return err
}

// UpdateEvidenceTimezone sets the per-evidence display timezone (IANA name).
// An empty tz clears the override so the evidence falls back to the case
// timezone. Events are never rewritten — only display/parse interpretation
// changes — so this is safe to call at any time.
func (m *Manager) UpdateEvidenceTimezone(ctx context.Context, caseID, evidenceID, tz string) error {
	if m.mode == ReadOnly {
		return errors.New("casedb opened read-only")
	}
	res, err := m.db.ExecContext(ctx,
		`UPDATE evidence SET timezone = ? WHERE case_id = ? AND evidence_id = ?`,
		nullableString(tz), caseID, evidenceID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("no evidence %q in case %q", evidenceID, caseID)
	}
	return nil
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
