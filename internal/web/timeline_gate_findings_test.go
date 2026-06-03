package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Review Gate 2's audit_id set is derived from the findings-based timeline
// (the tier2 synthesis.json no longer stores a raw timeline). Regression:
// before this, the gate read synthesis.json::timeline (empty under tier2) so
// every approve/reject 404'd and the review table showed 0 of the timeline's
// entries.
func TestTimelineGateUsesFindingsTimeline(t *testing.T) {
	root := t.TempDir()
	caseID := "CASE-TL"
	caseDir := filepath.Join(root, "cases", caseID)
	byRule := filepath.Join(caseDir, "findings", "by-rule", "sigma")
	if err := os.MkdirAll(byRule, 0o755); err != nil {
		t.Fatal(err)
	}
	// Gate 2 is a no-op until synthesis.json exists; create a minimal one.
	if err := os.WriteFile(filepath.Join(caseDir, "synthesis.json"),
		[]byte(`{"case_id":"CASE-TL","clusters":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	finding := `{
	  "rule_id":"r1","rule_source":"sigma",
	  "rule_meta":{"title":"LSASS dump","level":"high",
	    "mitre_tactics":["credential-access"],"mitre_techniques":["T1003.001"]},
	  "evidence":[{"audit_id":"AUD-1","ts_utc":"2026-05-19T13:50:28Z",
	    "artifact_id":"evtx","event_type":"process_creation","extra":{}}]
	}`
	if err := os.WriteFile(filepath.Join(byRule, "r1.json"), []byte(finding), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Server{cfg: Config{OutputsRoot: filepath.Join(root, "cases")}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/cases/{id}/timeline-review", s.handleGetTimelineReview)
	mux.HandleFunc("POST /api/cases/{id}/timeline-review/{audit_id}/approve", s.handleApproveTimelineEntry)

	// GET — the findings-derived audit_id should appear as a pending entry.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/cases/"+caseID+"/timeline-review", nil))
	if rec.Code != 200 {
		t.Fatalf("GET status = %d, want 200", rec.Code)
	}
	var got struct {
		Total   int                       `json:"total"`
		Reviews map[string]map[string]any `json:"reviews"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Total != 1 || got.Reviews["AUD-1"] == nil {
		t.Fatalf("want 1 review row keyed AUD-1, got total=%d reviews=%v", got.Total, got.Reviews)
	}

	// Approve the known audit_id → 200 (previously 404 because the known set
	// was empty).
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST",
		"/api/cases/"+caseID+"/timeline-review/AUD-1/approve", nil))
	if rec.Code != 200 {
		t.Fatalf("approve known audit_id status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	// An audit_id not in the timeline must still be rejected with 404.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST",
		"/api/cases/"+caseID+"/timeline-review/NOPE/approve", nil))
	if rec.Code != 404 {
		t.Fatalf("approve unknown audit_id status = %d, want 404", rec.Code)
	}
}
