package web

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tlvb/tlvb/internal/casedb"
)

// seedTwoCaseDB builds an on-disk cases.duckdb with two cases carrying
// different event/evidence counts and returns its path.
func seedTwoCaseDB(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "cases.duckdb")
	m, err := casedb.Open(dbPath, casedb.ReadWrite)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer m.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	for _, id := range []string{"CASE-A", "CASE-B"} {
		if err := m.RegisterCase(ctx, casedb.CaseRow{CaseID: id, Name: id, Examiner: "t"}); err != nil {
			t.Fatalf("register %s: %v", id, err)
		}
	}
	if err := m.BulkInsertEvidence(ctx, []casedb.EvidenceRow{
		{EvidenceID: "e1", CaseID: "CASE-A", Path: "/a", SHA256: "x", SizeBytes: 1, RegisteredAt: now},
	}); err != nil {
		t.Fatalf("evidence: %v", err)
	}
	// Event count is derived from parse_results.row_count (scan-free), so seed
	// that rather than unified_events. CASE-A → 2 events, CASE-B → 0.
	rc := int64(2)
	if err := m.BulkInsertParseResults(ctx, []casedb.ParseResultRow{
		{CaseID: "CASE-A", ArtifactID: "evtx", StartedAt: now, Command: "c", RowCount: &rc},
	}); err != nil {
		t.Fatalf("parse_results: %v", err)
	}
	return dbPath
}

// TestListCasesBatchedCounts asserts the listing returns correct per-case
// counts in one request (the batched GROUP BY path), including a 0-event case.
func TestListCasesBatchedCounts(t *testing.T) {
	s, err := New(Config{DBPath: seedTwoCaseDB(t)})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/cases", nil))
	if rec.Code != 200 {
		t.Fatalf("GET /api/cases = %d: %s", rec.Code, rec.Body.String())
	}
	var got []caseSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	counts := map[string]int64{}
	evid := map[string]int{}
	for _, c := range got {
		counts[c.CaseID] = c.UnifiedRowCount
		evid[c.CaseID] = c.EvidenceCount
	}
	if counts["CASE-A"] != 2 {
		t.Errorf("CASE-A unified_event_rows = %d, want 2", counts["CASE-A"])
	}
	if counts["CASE-B"] != 0 {
		t.Errorf("CASE-B unified_event_rows = %d, want 0", counts["CASE-B"])
	}
	if evid["CASE-A"] != 1 {
		t.Errorf("CASE-A evidence_count = %d, want 1", evid["CASE-A"])
	}
	if evid["CASE-B"] != 0 {
		t.Errorf("CASE-B evidence_count = %d, want 0", evid["CASE-B"])
	}
}

// TestStaticAssetRouting locks in the fallback hardening: real assets live
// under /static/, an asset-looking path without that prefix 404s (instead of
// being served index.html and executed as JS), and the shell is uncacheable.
func TestStaticAssetRouting(t *testing.T) {
	s, err := New(Config{DBPath: filepath.Join(t.TempDir(), "cases.duckdb")})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	h := s.Handler()

	do := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}

	// Real asset: served as JS.
	if rec := do("/static/app.js"); rec.Code != 200 {
		t.Errorf("GET /static/app.js = %d, want 200", rec.Code)
	} else if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("/static/app.js Content-Type = %q, want javascript", ct)
	}

	// Stale/foreign asset path (no /static/): must 404, NOT serve HTML.
	if rec := do("/app.js"); rec.Code != 404 {
		t.Errorf("GET /app.js = %d, want 404 (got body: %.40q)", rec.Code, rec.Body.String())
	}
	if rec := do("/style.css"); rec.Code != 404 {
		t.Errorf("GET /style.css = %d, want 404", rec.Code)
	}

	// SPA shell: 200 text/html, never cached.
	rec := do("/")
	if rec.Code != 200 {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("/ Content-Type = %q, want text/html", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("/ Cache-Control = %q, want no-store", cc)
	}
}
