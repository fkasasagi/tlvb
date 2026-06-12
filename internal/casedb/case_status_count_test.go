package casedb

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// TestGetCaseStatusCountFromParseResults proves the case-detail event count
// (CaseStatus.UnifiedRowCount, surfaced by the Web UI's case-detail view and
// the CLI `status` command) is derived scan-free from SUM(parse_results
// .row_count) — NOT a live COUNT(*) over the multi-GB unified_events fact
// table. The old COUNT(*) made the go-duckdb driver hang on large DBs / an
// un-checkpointed WAL, freezing the case detail view.
//
// To make the source unambiguous we seed parse_results with a known total and
// leave unified_events deliberately EMPTY: a COUNT(*) over unified_events would
// return 0, so an assertion of the parse_results SUM can only pass if the count
// comes from parse_results.
func TestGetCaseStatusCountFromParseResults(t *testing.T) {
	m, err := Open(filepath.Join(t.TempDir(), "cases.duckdb"), ReadWrite)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer m.Close()
	ctx := context.Background()
	now := time.Now().UTC()

	if err := m.RegisterCase(ctx, CaseRow{CaseID: "A", Name: "A", Examiner: "t"}); err != nil {
		t.Fatalf("register case: %v", err)
	}
	if err := m.BulkInsertEvidence(ctx, []EvidenceRow{
		{EvidenceID: "e1", CaseID: "A", Path: "/a1", SHA256: "x", SizeBytes: 1, RegisteredAt: now},
	}); err != nil {
		t.Fatalf("insert evidence: %v", err)
	}
	// parse_results sums to 30; unified_events stays empty on purpose.
	if err := m.BulkInsertParseResults(ctx, []ParseResultRow{
		{CaseID: "A", ArtifactID: "evtx", StartedAt: now, Command: "c", RowCount: i64(20)},
		{CaseID: "A", ArtifactID: "amcache", StartedAt: now, Command: "c", RowCount: i64(10)},
	}); err != nil {
		t.Fatalf("insert parse_results: %v", err)
	}

	// Sanity: unified_events really is empty, so the old COUNT(*) path would
	// have reported 0 here.
	var ueRows int64
	if err := m.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM unified_events WHERE case_id = 'A'`).Scan(&ueRows); err != nil {
		t.Fatalf("count unified_events: %v", err)
	}
	if ueRows != 0 {
		t.Fatalf("precondition: unified_events should be empty, got %d", ueRows)
	}

	st, err := m.GetCaseStatus(ctx, "A")
	if err != nil {
		t.Fatalf("GetCaseStatus: %v", err)
	}
	if st.UnifiedRowCount != 30 {
		t.Fatalf("UnifiedRowCount = %d, want 30 (SUM of parse_results.row_count, not unified_events COUNT)",
			st.UnifiedRowCount)
	}
	if st.EvidenceCount != 1 {
		t.Fatalf("EvidenceCount = %d, want 1", st.EvidenceCount)
	}
	if len(st.ParseResults) != 2 {
		t.Fatalf("ParseResults len = %d, want 2", len(st.ParseResults))
	}
}

// TestGetCaseStatusCountNoParseRows confirms a case with no parse_results
// reports a 0 event count rather than erroring (COALESCE(SUM(...), 0)).
func TestGetCaseStatusCountNoParseRows(t *testing.T) {
	m, err := Open(filepath.Join(t.TempDir(), "cases.duckdb"), ReadWrite)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer m.Close()
	ctx := context.Background()

	if err := m.RegisterCase(ctx, CaseRow{CaseID: "Z", Name: "Z", Examiner: "t"}); err != nil {
		t.Fatalf("register case: %v", err)
	}
	st, err := m.GetCaseStatus(ctx, "Z")
	if err != nil {
		t.Fatalf("GetCaseStatus: %v", err)
	}
	if st.UnifiedRowCount != 0 {
		t.Fatalf("UnifiedRowCount = %d, want 0 for a case with no parse rows", st.UnifiedRowCount)
	}
}
