package web

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/tlvb/tlvb/internal/casedb"
)

// TestGetCaseDetailCountFromParseResults locks in the scan-free case-detail
// event count: GET /api/cases/{id} reports case.unified_event_rows from
// SUM(parse_results.row_count), NOT a COUNT(*) over unified_events (which used
// to hang the go-duckdb driver on large DBs / an un-checkpointed WAL and froze
// the case detail view).
//
// unified_events is left EMPTY on purpose: the old COUNT(*) path would report
// 0, so an assertion of the parse_results SUM can only pass via parse_results.
func TestGetCaseDetailCountFromParseResults(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cases.duckdb")
	m, err := casedb.Open(dbPath, casedb.ReadWrite)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	if err := m.RegisterCase(ctx, casedb.CaseRow{CaseID: "CASE-D", Name: "CASE-D", Examiner: "t"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := m.BulkInsertEvidence(ctx, []casedb.EvidenceRow{
		{EvidenceID: "e1", CaseID: "CASE-D", Path: "/a", SHA256: "x", SizeBytes: 1, RegisteredAt: now},
	}); err != nil {
		t.Fatalf("evidence: %v", err)
	}
	rc1, rc2 := int64(20), int64(10) // SUM = 30
	if err := m.BulkInsertParseResults(ctx, []casedb.ParseResultRow{
		{CaseID: "CASE-D", ArtifactID: "evtx", StartedAt: now, Command: "c", RowCount: &rc1},
		{CaseID: "CASE-D", ArtifactID: "amcache", StartedAt: now, Command: "c", RowCount: &rc2},
	}); err != nil {
		t.Fatalf("parse_results: %v", err)
	}
	m.Close()

	s, err := New(Config{DBPath: dbPath})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/cases/CASE-D", nil))
	if rec.Code != 200 {
		t.Fatalf("GET /api/cases/CASE-D = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Case struct {
			UnifiedRowCount int64 `json:"unified_event_rows"`
			EvidenceCount   int   `json:"evidence_count"`
		} `json:"case"`
		ParseResults []json.RawMessage `json:"parse_results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Case.UnifiedRowCount != 30 {
		t.Fatalf("case.unified_event_rows = %d, want 30 (SUM of parse_results.row_count)",
			resp.Case.UnifiedRowCount)
	}
	if resp.Case.EvidenceCount != 1 {
		t.Fatalf("case.evidence_count = %d, want 1", resp.Case.EvidenceCount)
	}
	if len(resp.ParseResults) != 2 {
		t.Fatalf("parse_results len = %d, want 2", len(resp.ParseResults))
	}
}
