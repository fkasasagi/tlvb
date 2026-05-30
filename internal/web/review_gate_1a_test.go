package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tlvb/tlvb/internal/tier1a"
	"github.com/tlvb/tlvb/internal/tier1b"
)

// fixtureServer builds a Server pointed at a temp outputs dir that already
// contains a synthetic findings/ tree:
//
//	by-rule/sigma/critical-rule.json  (severity=critical → pending)
//	by-rule/hayabusa/medium-rule.json (severity=medium  → auto-approved)
//	by-skill/anomaly_hunter.json      (two findings: high + low)
//
// Returns the Server, its HTTP handler, the case ID, and the temp root so
// individual tests can inspect on-disk state after mutations.
func fixtureServer(t *testing.T) (*Server, http.Handler, string, string) {
	t.Helper()
	root := t.TempDir()
	caseID := "case-rev-1a"

	findingsRoot := filepath.Join(root, "cases", caseID, "findings")
	mustWrite := func(path string, v any) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		body, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	now := time.Date(2026, 5, 29, 13, 50, 0, 0, time.UTC)

	mustWrite(filepath.Join(findingsRoot, "by-rule", "sigma", "critical-rule.json"),
		tier1a.Finding{
			FindingID:   "F-CRITICAL-1",
			CaseID:      caseID,
			RuleID:      "00000000-0000-0000-0000-aaaaaaaaaaaa",
			RuleSource:  "sigma",
			RuleMeta:    tier1a.RuleMeta{Title: "LSASS dump", Level: "critical", MITRETechniques: []string{"T1003.001"}, MITRETactics: []string{"credential-access"}},
			Evidence:    []tier1a.EvidenceRef{{AuditID: "AUD-1", ArtifactID: "evtx", EventType: "process_creation"}},
			MatchCount:  1,
			Approved:    false, // critical → pending per AutoApproveByLevel
			GeneratedAt: now,
			SQL:         "SELECT * FROM unified_events WHERE case_id = ?",
		})

	mustWrite(filepath.Join(findingsRoot, "by-rule", "hayabusa", "medium-rule.json"),
		tier1a.Finding{
			FindingID:   "F-MEDIUM-1",
			CaseID:      caseID,
			RuleID:      "00000000-0000-0000-0000-bbbbbbbbbbbb",
			RuleSource:  "hayabusa",
			RuleMeta:    tier1a.RuleMeta{Title: "Suspicious Path", Level: "medium", MITRETactics: []string{"execution"}},
			Evidence:    []tier1a.EvidenceRef{{AuditID: "AUD-2", ArtifactID: "amcache", EventType: "process"}},
			MatchCount:  2,
			Approved:    true, // medium → auto-approved
			ApprovedBy:  "auto:severity-rule",
			GeneratedAt: now,
			SQL:         "SELECT * FROM unified_events WHERE case_id = ?",
		})

	mustWrite(filepath.Join(findingsRoot, "by-skill", "anomaly_hunter.json"),
		tier1b.AnomalyReport{
			CaseID:      caseID,
			Skill:       "anomaly_hunter",
			SkillSHA256: "deadbeef",
			GeneratedAt: now,
			Findings: []tier1b.AnomalyFinding{
				{
					FindingID: "F-ANOM-HIGH", Lens: "A2", Summary: "LSASS-like dump path",
					Severity: "high", AuditIDs: []string{"AUD-3"}, TechniqueID: "T1003",
					Tactic: "credential-access", GeneratedAt: now,
					Approved: false, // high → pending
				},
				{
					FindingID: "F-ANOM-LOW", Lens: "A5", Summary: "Off-hours boot",
					Severity: "low", AuditIDs: []string{"AUD-4"}, GeneratedAt: now,
					Approved: true, ApprovedBy: "auto:severity-rule",
				},
			},
		})

	s := &Server{
		cfg: Config{
			OutputsRoot: filepath.Join(root, "cases"),
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/cases/{id}/findings", s.handleListReviewFindings)
	mux.HandleFunc("POST /api/cases/{id}/findings/{fid}/approve", s.handleApproveReviewFinding)
	mux.HandleFunc("POST /api/cases/{id}/findings/{fid}/reject", s.handleRejectReviewFinding)
	mux.HandleFunc("POST /api/cases/{id}/findings/{fid}/reset", s.handleResetReviewFinding)
	mux.HandleFunc("POST /api/cases/{id}/findings/bulk", s.handleBulkReviewFindings)
	return s, mux, caseID, findingsRoot
}

func TestListReviewFindings_SortAndFlatten(t *testing.T) {
	_, mux, caseID, _ := fixtureServer(t)
	req := httptest.NewRequest("GET", "/api/cases/"+caseID+"/findings", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status: got %d, body=%s", rec.Code, rec.Body.String())
	}
	var got []ReviewFinding
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rec.Body.String())
	}
	if len(got) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(got))
	}
	// Severity desc: critical, high, medium, low
	want := []string{"critical", "high", "medium", "low"}
	for i, sev := range want {
		if got[i].Severity != sev {
			t.Errorf("[%d] severity got=%s want=%s (fid=%s)", i, got[i].Severity, sev, got[i].FindingID)
		}
	}
	// Auto-approved propagates
	for _, rf := range got {
		switch rf.FindingID {
		case "F-MEDIUM-1", "F-ANOM-LOW":
			if !rf.AutoApproved {
				t.Errorf("%s expected AutoApproved=true", rf.FindingID)
			}
		case "F-CRITICAL-1", "F-ANOM-HIGH":
			if rf.AutoApproved {
				t.Errorf("%s expected AutoApproved=false", rf.FindingID)
			}
		}
	}
}

func TestApproveTier1A(t *testing.T) {
	_, mux, caseID, findingsRoot := fixtureServer(t)
	req := httptest.NewRequest("POST", "/api/cases/"+caseID+"/findings/F-CRITICAL-1/approve", nil)
	req.Header.Set("X-Examiner", "alice")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
	}
	// Inspect on-disk file
	body, err := os.ReadFile(filepath.Join(findingsRoot, "by-rule", "sigma", "critical-rule.json"))
	if err != nil {
		t.Fatalf("read after approve: %v", err)
	}
	var f tier1a.Finding
	if err := json.Unmarshal(body, &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !f.Approved || f.Rejected {
		t.Errorf("expected approved=true rejected=false, got approved=%v rejected=%v", f.Approved, f.Rejected)
	}
	if f.ApprovedBy != "alice" || f.ReviewedBy != "alice" {
		t.Errorf("examiner not persisted: approvedBy=%q reviewedBy=%q", f.ApprovedBy, f.ReviewedBy)
	}
	if f.ReviewedAt.IsZero() {
		t.Error("ReviewedAt should be set")
	}
}

func TestRejectTier1BWithReason(t *testing.T) {
	_, mux, caseID, findingsRoot := fixtureServer(t)
	body := bytes.NewBufferString(`{"reason":"false positive: known admin task"}`)
	req := httptest.NewRequest("POST",
		"/api/cases/"+caseID+"/findings/F-ANOM-HIGH/reject", body)
	req.Header.Set("X-Examiner", "bob")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
	}
	raw, err := os.ReadFile(filepath.Join(findingsRoot, "by-skill", "anomaly_hunter.json"))
	if err != nil {
		t.Fatalf("read after reject: %v", err)
	}
	var rep tier1b.AnomalyReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var target *tier1b.AnomalyFinding
	for i := range rep.Findings {
		if rep.Findings[i].FindingID == "F-ANOM-HIGH" {
			target = &rep.Findings[i]
			break
		}
	}
	if target == nil {
		t.Fatal("target finding missing")
	}
	if target.Approved || !target.Rejected {
		t.Errorf("expected approved=false rejected=true, got %+v", target)
	}
	if target.RejectReason != "false positive: known admin task" {
		t.Errorf("reject reason not persisted: %q", target.RejectReason)
	}
	if target.ReviewedBy != "bob" {
		t.Errorf("examiner not persisted: %q", target.ReviewedBy)
	}
	// Other finding in the same file must be untouched.
	for _, f := range rep.Findings {
		if f.FindingID == "F-ANOM-LOW" && (f.Rejected || f.RejectReason != "") {
			t.Errorf("F-ANOM-LOW touched accidentally: %+v", f)
		}
	}
}

func TestResetRestoresSeverityDefault(t *testing.T) {
	_, mux, caseID, findingsRoot := fixtureServer(t)

	// First reject the auto-approved medium finding.
	body := bytes.NewBufferString(`{"reason":"benign"}`)
	req := httptest.NewRequest("POST",
		"/api/cases/"+caseID+"/findings/F-MEDIUM-1/reject", body)
	req.Header.Set("X-Examiner", "carol")
	mux.ServeHTTP(httptest.NewRecorder(), req)

	// Then reset and expect it to go back to auto-approved (medium default).
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST",
		"/api/cases/"+caseID+"/findings/F-MEDIUM-1/reset", nil))
	if rec.Code != 200 {
		t.Fatalf("reset status: %d body=%s", rec.Code, rec.Body.String())
	}
	raw, err := os.ReadFile(filepath.Join(findingsRoot, "by-rule", "hayabusa", "medium-rule.json"))
	if err != nil {
		t.Fatalf("read after reset: %v", err)
	}
	var f tier1a.Finding
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !f.Approved || f.Rejected || f.RejectReason != "" {
		t.Errorf("reset did not restore severity default: %+v", f)
	}
	if f.ApprovedBy != "auto:severity-rule" {
		t.Errorf("approvedBy not restored to auto: %q", f.ApprovedBy)
	}
}

func TestBulkApproveAcrossSources(t *testing.T) {
	_, mux, caseID, findingsRoot := fixtureServer(t)
	body := bytes.NewBufferString(`{"finding_ids":["F-CRITICAL-1","F-ANOM-HIGH","F-NONEXISTENT"],"action":"approve"}`)
	req := httptest.NewRequest("POST", "/api/cases/"+caseID+"/findings/bulk", body)
	req.Header.Set("X-Examiner", "dave")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
	}
	var resp reviewMutationResult
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rec.Body.String())
	}
	if resp.Updated != 2 {
		t.Errorf("updated: got %d want 2", resp.Updated)
	}
	if len(resp.NotFound) != 1 || resp.NotFound[0] != "F-NONEXISTENT" {
		t.Errorf("not_found: %+v", resp.NotFound)
	}
	// Verify on-disk
	raw, err := os.ReadFile(filepath.Join(findingsRoot, "by-rule", "sigma", "critical-rule.json"))
	if err != nil {
		t.Fatalf("read critical: %v", err)
	}
	var f tier1a.Finding
	_ = json.Unmarshal(raw, &f)
	if !f.Approved || f.ReviewedBy != "dave" {
		t.Errorf("F-CRITICAL-1 not approved after bulk: %+v", f)
	}
}

func TestApproveNonexistentReturns404(t *testing.T) {
	_, mux, caseID, _ := fixtureServer(t)
	req := httptest.NewRequest("POST",
		"/api/cases/"+caseID+"/findings/F-DOES-NOT-EXIST/approve", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Errorf("expected 404, got %d body=%s", rec.Code, rec.Body.String())
	}
}
