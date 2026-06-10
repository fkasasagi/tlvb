package casedb

import (
	"context"
	"database/sql"
	"path/filepath"
	"sort"
	"testing"
	"time"

	_ "github.com/marcboeker/go-duckdb"
)

// Wave 16: the evidence table moved from "PRIMARY KEY (evidence_id)" to
// "PRIMARY KEY (case_id, evidence_id)" so the same triage bundle can be
// parsed under multiple cases without the second registration silently
// failing. These tests cover the on-disk migration path (existing
// single-PK DBs) and the new cross-case INSERT behaviour.

// createV0EvidenceDB writes a DuckDB file with the *old* (single-PK)
// evidence schema and seeds it with `rows` (evidence_id, case_id) tuples.
// All non-key columns are filled in with stub values.
func createV0EvidenceDB(t *testing.T, path string, rows [][2]string) {
	t.Helper()
	db, err := sql.Open("duckdb", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	_, err = db.Exec(`
CREATE TABLE evidence (
    evidence_id     VARCHAR PRIMARY KEY,
    case_id         VARCHAR NOT NULL,
    path            VARCHAR NOT NULL,
    sha256          VARCHAR NOT NULL,
    size_bytes      BIGINT  NOT NULL,
    registered_at   TIMESTAMP NOT NULL,
    source_host     VARCHAR,
    evidence_type   VARCHAR
);
CREATE TABLE cases (
    case_id    VARCHAR PRIMARY KEY,
    name       VARCHAR NOT NULL,
    examiner   VARCHAR NOT NULL,
    timezone   VARCHAR NOT NULL DEFAULT 'UTC',
    created_at TIMESTAMP NOT NULL,
    status     VARCHAR NOT NULL DEFAULT 'active'
);
CREATE TABLE parse_results (
    case_id     VARCHAR NOT NULL,
    artifact_id VARCHAR NOT NULL,
    started_at  TIMESTAMP NOT NULL,
    finished_at TIMESTAMP,
    command     VARCHAR NOT NULL,
    exit_code   INTEGER,
    stdout_tail VARCHAR,
    stderr_tail VARCHAR,
    output_csv  VARCHAR,
    row_count   BIGINT,
    PRIMARY KEY (case_id, artifact_id)
);
CREATE TABLE unified_events (
    case_id      VARCHAR NOT NULL,
    evidence_id  VARCHAR,
    artifact_id  VARCHAR NOT NULL,
    audit_id     VARCHAR NOT NULL,
    ts_utc       TIMESTAMP,
    event_type   VARCHAR NOT NULL,
    computer     VARCHAR,
    payload_json VARCHAR NOT NULL
);
`)
	if err != nil {
		t.Fatalf("create v0 schema: %v", err)
	}
	for _, r := range rows {
		_, err = db.Exec(
			`INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			r[0], r[1], "/tmp/"+r[0], "sha", int64(0), time.Now().UTC(), nil, "auto",
		)
		if err != nil {
			t.Fatalf("seed evidence (%s, %s): %v", r[0], r[1], err)
		}
	}
}

// pkColumns returns the column names that form the PRIMARY KEY of the
// evidence table, sorted alphabetically (for stable test assertions).
func pkColumns(t *testing.T, m *Manager) []string {
	t.Helper()
	rows, err := m.db.Query(`PRAGMA table_info('evidence')`)
	if err != nil {
		t.Fatalf("pragma: %v", err)
	}
	defer rows.Close()
	var out []string
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
			t.Fatalf("scan: %v", err)
		}
		if pk {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// TestMigrateEvidencePK_FromV0 verifies that opening an old DB (single
// PK on evidence_id) triggers the migration, ends up with the composite
// PK, and preserves all existing rows.
func TestMigrateEvidencePK_FromV0(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v0.duckdb")
	createV0EvidenceDB(t, path, [][2]string{
		{"EV-A", "case_1"},
		{"EV-B", "case_1"},
		{"EV-C", "case_2"},
	})

	m, err := Open(path, ReadWrite)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer m.Close()

	pk := pkColumns(t, m)
	if len(pk) != 2 || pk[0] != "case_id" || pk[1] != "evidence_id" {
		t.Fatalf("expected composite PK (case_id, evidence_id), got %v", pk)
	}

	// All seeded rows survived the migration.
	row := m.db.QueryRow(`SELECT COUNT(*) FROM evidence`)
	var n int
	if err := row.Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 rows preserved, got %d", n)
	}

	// And the temporary evidence_v0 table was dropped.
	row = m.db.QueryRow(
		`SELECT COUNT(*) FROM information_schema.tables WHERE table_name='evidence_v0'`)
	if err := row.Scan(&n); err != nil {
		t.Fatalf("v0 check: %v", err)
	}
	if n != 0 {
		t.Fatalf("evidence_v0 should be dropped after migration, found %d rows", n)
	}
}

// TestListEvidence_MissingTimezoneColumn covers the read-only compatibility
// path: a DB written before evidence.timezone existed, opened read-only (so
// ensureSchema's ADD COLUMN migration can't run). ListEvidence must still
// return the rows — with an empty timezone (= inherit case TZ) — rather than
// erroring out, which previously blanked detail.evidence and silently
// disabled the Events-tab evidence filter and per-evidence Status view.
func TestListEvidence_MissingTimezoneColumn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.duckdb")
	// createV0EvidenceDB writes an evidence table with NO timezone column.
	createV0EvidenceDB(t, path, [][2]string{
		{"EV-A", "case_1"},
		{"EV-B", "case_1"},
		{"EV-C", "case_2"},
	})

	// Open read-only — ensureSchema (and ADD COLUMN timezone) is skipped, so
	// the column stays absent, exactly like the web server's query path.
	ro, err := Open(path, ReadOnly)
	if err != nil {
		t.Fatalf("Open read-only: %v", err)
	}
	defer ro.Close()

	ctx := context.Background()
	if ro.columnExists(ctx, "evidence", "timezone") {
		t.Fatal("precondition failed: v0 evidence table must not have a timezone column")
	}

	evs, err := ro.ListEvidence(ctx, "case_1")
	if err != nil {
		t.Fatalf("ListEvidence on a pre-timezone DB must not error, got: %v", err)
	}
	if len(evs) != 2 {
		t.Fatalf("expected 2 evidence rows for case_1, got %d", len(evs))
	}
	for _, e := range evs {
		if e.Timezone != "" {
			t.Errorf("evidence %s: want empty timezone (inherit case TZ), got %q",
				e.EvidenceID, e.Timezone)
		}
		if e.EvidenceType != "auto" {
			t.Errorf("evidence %s: non-timezone columns must still populate, got evidence_type=%q",
				e.EvidenceID, e.EvidenceType)
		}
	}
}

// TestMigrateEvidencePK_AlreadyMigrated verifies that a DB already on
// the new schema is a no-op (idempotent).
func TestMigrateEvidencePK_AlreadyMigrated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fresh.duckdb")
	m, err := Open(path, ReadWrite) // creates new DB with composite PK
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	pk := pkColumns(t, m)
	if len(pk) != 2 {
		m.Close()
		t.Fatalf("fresh DB should already have composite PK, got %v", pk)
	}
	m.Close()

	// Re-open: migration runs again and must be a no-op.
	m, err = Open(path, ReadWrite)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	defer m.Close()
	pk = pkColumns(t, m)
	if len(pk) != 2 || pk[0] != "case_id" || pk[1] != "evidence_id" {
		t.Fatalf("composite PK should remain stable on re-open, got %v", pk)
	}
}

// TestCrossCaseRegistration is the regression test for the Wave 16
// "case has no registered evidence" bug: the same evidence_id must be
// insertable under two different case_ids.
func TestCrossCaseRegistration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fresh.duckdb")
	m, err := Open(path, ReadWrite)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer m.Close()

	ctx := context.Background()
	// Seed two cases the evidence rows can reference.
	for _, cid := range []string{"case_A", "case_B"} {
		if _, err := m.db.ExecContext(ctx,
			`INSERT INTO cases (case_id, name, examiner, timezone, created_at, status)
			   VALUES (?, ?, 'test', 'UTC', NOW(), 'active')`, cid, cid); err != nil {
			t.Fatalf("seed case %s: %v", cid, err)
		}
	}

	// Same evidence_id, two different case_ids — both should succeed.
	row := EvidenceRow{
		EvidenceID:   "EV-shared",
		Path:         "/tmp/triage.zip",
		SHA256:       "stub",
		SizeBytes:    0,
		EvidenceType: "auto",
		RegisteredAt: time.Now().UTC(),
	}
	row.CaseID = "case_A"
	if err := m.RegisterEvidence(ctx, row); err != nil {
		t.Fatalf("register under case_A: %v", err)
	}
	row.CaseID = "case_B"
	if err := m.RegisterEvidence(ctx, row); err != nil {
		t.Fatalf("register under case_B (regression — Wave 16): %v", err)
	}

	// ListEvidence should return one row for each case.
	for _, cid := range []string{"case_A", "case_B"} {
		ev, err := m.ListEvidence(ctx, cid)
		if err != nil {
			t.Fatalf("list %s: %v", cid, err)
		}
		if len(ev) != 1 || ev[0].EvidenceID != "EV-shared" {
			t.Fatalf("case %s: expected one EV-shared row, got %+v", cid, ev)
		}
	}
}

// TestRegisterEvidence_RejectsDuplicateWithinCase keeps the inverse
// guarantee: the same (case_id, evidence_id) pair cannot be inserted
// twice.
func TestRegisterEvidence_RejectsDuplicateWithinCase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fresh.duckdb")
	m, err := Open(path, ReadWrite)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer m.Close()

	ctx := context.Background()
	if _, err := m.db.ExecContext(ctx,
		`INSERT INTO cases (case_id, name, examiner, timezone, created_at, status)
		   VALUES ('case_X', 'X', 'test', 'UTC', NOW(), 'active')`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	row := EvidenceRow{
		EvidenceID:   "EV-dup",
		CaseID:       "case_X",
		Path:         "/tmp/x",
		SHA256:       "stub",
		SizeBytes:    0,
		EvidenceType: "auto",
		RegisteredAt: time.Now().UTC(),
	}
	if err := m.RegisterEvidence(ctx, row); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := m.RegisterEvidence(ctx, row); err == nil {
		t.Fatalf("second register with same (case_X, EV-dup) should fail")
	}
}

// TestEvidenceTimezone covers the per-evidence display-timezone column:
// register defaults to inherit (empty), UpdateEvidenceTimezone sets/clears it,
// the value round-trips through ListEvidence, and updating an unknown evidence
// errors. Events themselves are never touched by this — it is metadata only.
func TestEvidenceTimezone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fresh.duckdb")
	m, err := Open(path, ReadWrite)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer m.Close()

	ctx := context.Background()
	if _, err := m.db.ExecContext(ctx,
		`INSERT INTO cases (case_id, name, examiner, timezone, created_at, status)
		   VALUES ('case_TZ', 'TZ', 'test', 'UTC', NOW(), 'active')`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Register with an explicit timezone — it must round-trip.
	if err := m.RegisterEvidence(ctx, EvidenceRow{
		EvidenceID: "EV-1", CaseID: "case_TZ", Path: "/tmp/a", SHA256: "s",
		Timezone: "Asia/Tokyo", RegisteredAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("register EV-1: %v", err)
	}
	// Register without one — defaults to empty (inherit case).
	if err := m.RegisterEvidence(ctx, EvidenceRow{
		EvidenceID: "EV-2", CaseID: "case_TZ", Path: "/tmp/b", SHA256: "s",
		RegisteredAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("register EV-2: %v", err)
	}

	tzOf := func(id string) string {
		evs, err := m.ListEvidence(ctx, "case_TZ")
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, e := range evs {
			if e.EvidenceID == id {
				return e.Timezone
			}
		}
		t.Fatalf("evidence %s not listed", id)
		return ""
	}

	if got := tzOf("EV-1"); got != "Asia/Tokyo" {
		t.Fatalf("EV-1 timezone: want Asia/Tokyo, got %q", got)
	}
	if got := tzOf("EV-2"); got != "" {
		t.Fatalf("EV-2 timezone: want empty (inherit), got %q", got)
	}

	// Override EV-2, then clear it back to inherit.
	if err := m.UpdateEvidenceTimezone(ctx, "case_TZ", "EV-2", "America/New_York"); err != nil {
		t.Fatalf("set EV-2 tz: %v", err)
	}
	if got := tzOf("EV-2"); got != "America/New_York" {
		t.Fatalf("EV-2 after set: want America/New_York, got %q", got)
	}
	if err := m.UpdateEvidenceTimezone(ctx, "case_TZ", "EV-2", ""); err != nil {
		t.Fatalf("clear EV-2 tz: %v", err)
	}
	if got := tzOf("EV-2"); got != "" {
		t.Fatalf("EV-2 after clear: want empty, got %q", got)
	}

	// Updating a non-existent evidence must error (no silent no-op).
	if err := m.UpdateEvidenceTimezone(ctx, "case_TZ", "EV-nope", "UTC"); err == nil {
		t.Fatalf("expected error updating unknown evidence")
	}
}
