package casedb

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/marcboeker/go-duckdb"
)

// parse_results moved from PRIMARY KEY (case_id, artifact_id) to the
// per-evidence key (case_id, evidence_id, artifact_id) so a multi-evidence
// case keeps every evidence's parse outcome instead of the last orchestrator
// run overwriting the previous evidence's rows. These tests cover the
// on-disk migration (including the single-evidence backfill), the new
// multi-row behaviour, and the read-only old-DB compatibility path.

// seedV0ParseResults inserts rows into an old-shape parse_results table
// (no evidence_id column) as written by a pre-migration binary.
func seedV0ParseResults(t *testing.T, path string, rows [][2]string) {
	t.Helper()
	db, err := sql.Open("duckdb", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	for _, r := range rows {
		if _, err := db.Exec(
			`INSERT INTO parse_results (case_id, artifact_id, started_at, command, exit_code, row_count)
			   VALUES (?, ?, ?, 'cmd', 0, 5)`, r[0], r[1], time.Now().UTC()); err != nil {
			t.Fatalf("seed parse_result (%s, %s): %v", r[0], r[1], err)
		}
	}
}

// TestMigrateParseResultsPK_FromV0 verifies that opening an old DB triggers
// the rebuild, the evidence_id backfill attributes rows to the evidence when
// the case has exactly one, and leaves "" when attribution is ambiguous.
func TestMigrateParseResultsPK_FromV0(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v0.duckdb")
	// case_1 has two evidence (ambiguous), case_2 has exactly one.
	createV0EvidenceDB(t, path, [][2]string{
		{"EV-A", "case_1"},
		{"EV-B", "case_1"},
		{"EV-C", "case_2"},
	})
	seedV0ParseResults(t, path, [][2]string{
		{"case_1", "evtx"},
		{"case_1", "mft"},
		{"case_2", "evtx"},
	})

	m, err := Open(path, ReadWrite)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer m.Close()
	ctx := context.Background()

	if !m.columnExists(ctx, "parse_results", "evidence_id") {
		t.Fatal("evidence_id column missing after migration")
	}

	// Backfill: multi-evidence case stays "", single-evidence case gets its id.
	wantEv := map[string]string{"case_1": "", "case_2": "EV-C"}
	for caseID, want := range wantEv {
		prs, err := m.GetParseResults(ctx, caseID, "evtx")
		if err != nil {
			t.Fatalf("GetParseResults(%s, evtx): %v", caseID, err)
		}
		if len(prs) != 1 {
			t.Fatalf("case %s: want 1 row, got %d", caseID, len(prs))
		}
		if prs[0].EvidenceID != want {
			t.Errorf("case %s: want evidence_id %q, got %q", caseID, want, prs[0].EvidenceID)
		}
		if prs[0].RowCount == nil || *prs[0].RowCount != 5 {
			t.Errorf("case %s: non-key columns must survive migration, got %+v", caseID, prs[0])
		}
	}

	// The temporary table was dropped.
	var n int
	if err := m.db.QueryRow(
		`SELECT COUNT(*) FROM information_schema.tables WHERE table_name='parse_results_v0'`).
		Scan(&n); err != nil {
		t.Fatalf("v0 check: %v", err)
	}
	if n != 0 {
		t.Fatalf("parse_results_v0 should be dropped after migration")
	}

	// Idempotent on re-open.
	m.Close()
	m2, err := Open(path, ReadWrite)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	defer m2.Close()
}

// TestParseResults_PerEvidenceRows is the regression test for the original
// bug: the same artifact parsed from two evidence must keep BOTH rows
// (previously the second run overwrote the first).
func TestParseResults_PerEvidenceRows(t *testing.T) {
	dir := t.TempDir()
	m, err := Open(filepath.Join(dir, "fresh.duckdb"), ReadWrite)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer m.Close()
	ctx := context.Background()

	now := time.Now().UTC()
	rc1, rc2 := int64(10), int64(0)
	if err := m.BulkInsertParseResults(ctx, []ParseResultRow{
		{CaseID: "c1", EvidenceID: "EV-1", ArtifactID: "evtx", StartedAt: now, Command: "run1", RowCount: &rc1},
		{CaseID: "c1", EvidenceID: "EV-2", ArtifactID: "evtx", StartedAt: now, Command: "(not present in input)", RowCount: &rc2},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	prs, err := m.GetParseResults(ctx, "c1", "evtx")
	if err != nil {
		t.Fatalf("GetParseResults: %v", err)
	}
	if len(prs) != 2 {
		t.Fatalf("want 2 rows (one per evidence), got %d", len(prs))
	}
	if prs[0].EvidenceID != "EV-1" || prs[1].EvidenceID != "EV-2" {
		t.Fatalf("rows not keyed per evidence: %+v", prs)
	}
	if prs[0].Command != "run1" || prs[1].Command != "(not present in input)" {
		t.Fatalf("per-evidence outcomes not preserved: %+v", prs)
	}

	// Re-insert for one evidence only — upsert must not touch the other.
	if err := m.BulkInsertParseResults(ctx, []ParseResultRow{
		{CaseID: "c1", EvidenceID: "EV-2", ArtifactID: "evtx", StartedAt: now, Command: "run2", RowCount: &rc1},
	}); err != nil {
		t.Fatalf("re-insert: %v", err)
	}
	prs, err = m.GetParseResults(ctx, "c1", "evtx")
	if err != nil {
		t.Fatalf("GetParseResults after upsert: %v", err)
	}
	if len(prs) != 2 || prs[0].Command != "run1" || prs[1].Command != "run2" {
		t.Fatalf("upsert must replace only its own (evidence, artifact) row: %+v", prs)
	}
}

// TestListParseResults_MissingEvidenceColumn covers the read-only
// compatibility path: a DB written before parse_results.evidence_id existed,
// opened read-only (so migrateParseResultsPK can't run). Reads must degrade
// to an empty evidence_id rather than erroring out.
func TestListParseResults_MissingEvidenceColumn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.duckdb")
	createV0EvidenceDB(t, path, [][2]string{{"EV-A", "case_1"}})
	seedV0ParseResults(t, path, [][2]string{{"case_1", "evtx"}})
	{
		db, err := sql.Open("duckdb", path)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if _, err := db.Exec(
			`INSERT INTO cases (case_id, name, examiner, created_at)
			   VALUES ('case_1', 'c', 'test', ?)`, time.Now().UTC()); err != nil {
			t.Fatalf("seed case: %v", err)
		}
		db.Close()
	}

	ro, err := Open(path, ReadOnly)
	if err != nil {
		t.Fatalf("Open read-only: %v", err)
	}
	defer ro.Close()
	ctx := context.Background()

	if ro.columnExists(ctx, "parse_results", "evidence_id") {
		t.Fatal("precondition failed: v0 parse_results must not have evidence_id")
	}

	prs, err := ro.GetParseResults(ctx, "case_1", "evtx")
	if err != nil {
		t.Fatalf("GetParseResults on a pre-evidence_id DB must not error, got: %v", err)
	}
	if len(prs) != 1 || prs[0].EvidenceID != "" {
		t.Fatalf("want one row with empty evidence_id, got %+v", prs)
	}

	st, err := ro.GetCaseStatus(ctx, "case_1")
	if err != nil {
		t.Fatalf("GetCaseStatus: %v", err)
	}
	if len(st.ParseResults) != 1 {
		t.Fatalf("listParseResultsForCase must still return rows, got %d", len(st.ParseResults))
	}
}
