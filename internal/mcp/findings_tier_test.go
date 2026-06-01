package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tlvb/tlvb/internal/tier1a"
	"github.com/tlvb/tlvb/internal/tier1b"
)

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCollectTierFindings(t *testing.T) {
	root := t.TempDir()
	caseID := "C1"
	findings := filepath.Join(root, caseID, "findings")
	now := time.Date(2026, 6, 1, 13, 50, 0, 0, time.UTC)

	// Tier 1A — critical sigma rule, pending (not approved).
	writeJSONFile(t, filepath.Join(findings, "by-rule", "sigma", "crit.json"),
		tier1a.Finding{
			FindingID: "F-CRIT", CaseID: caseID,
			RuleID: "rule-crit", RuleSource: "sigma",
			RuleMeta: tier1a.RuleMeta{
				Title: "LSASS Dump", Level: "critical",
				MITRETechniques: []string{"T1003.001"}, MITRETactics: []string{"credential-access"},
			},
			Evidence:    []tier1a.EvidenceRef{{AuditID: "A1"}, {AuditID: "A2"}},
			MatchCount:  2,
			GeneratedAt: now,
		})
	// Tier 1A — medium hayabusa rule, auto-approved.
	writeJSONFile(t, filepath.Join(findings, "by-rule", "hayabusa", "med.json"),
		tier1a.Finding{
			FindingID: "F-MED", CaseID: caseID,
			RuleID: "rule-med", RuleSource: "hayabusa",
			RuleMeta:   tier1a.RuleMeta{Title: "Suspicious Path", Level: "medium"},
			Evidence:   []tier1a.EvidenceRef{{AuditID: "A3"}},
			MatchCount: 1,
			Approved:   true, ApprovedBy: "auto:severity-rule",
			GeneratedAt: now,
		})
	// Tier 1B — high anomaly, pending.
	writeJSONFile(t, filepath.Join(findings, "by-skill", "anomaly_hunter.json"),
		tier1b.AnomalyReport{
			CaseID: caseID, Skill: "anomaly_hunter",
			Findings: []tier1b.AnomalyFinding{{
				FindingID: "F-ANOM", Lens: "A5", Summary: "Prefetch burst",
				Severity: "high", AuditIDs: []string{"A4", "A5"},
				TechniqueID: "T1059.001", GeneratedAt: now,
			}},
		})

	s := &Server{outputsRoot: root}
	got, err := s.collectTierFindings(caseID)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(got))
	}
	// Severity-desc order: critical, high, medium.
	wantSev := []string{"critical", "high", "medium"}
	for i, sev := range wantSev {
		if got[i].Severity != sev {
			t.Errorf("[%d] severity got=%s want=%s", i, got[i].Severity, sev)
		}
	}
	byID := map[string]tierFindingDTO{}
	for _, f := range got {
		byID[f.FindingID] = f
	}
	if f := byID["F-CRIT"]; f.Source != "tier1a" || f.RuleSource != "sigma" ||
		f.ReviewState != "pending" || f.EvidenceCount != 2 || len(f.AuditIDs) != 2 ||
		f.Tactic != "credential-access" || len(f.Techniques) != 1 {
		t.Errorf("F-CRIT mapped wrong: %+v", f)
	}
	if f := byID["F-MED"]; f.ReviewState != "auto_approved" || f.RuleSource != "hayabusa" {
		t.Errorf("F-MED review_state/source wrong: %+v", f)
	}
	if f := byID["F-ANOM"]; f.Source != "tier1b" || f.Skill != "anomaly_hunter" ||
		f.Lens != "A5" || f.Title != "Prefetch burst" || f.ReviewState != "pending" ||
		f.EvidenceCount != 2 || len(f.Techniques) != 1 || f.Techniques[0] != "T1059.001" {
		t.Errorf("F-ANOM mapped wrong: %+v", f)
	}
}

func TestCollectTierFindingsEmpty(t *testing.T) {
	// No findings dir at all → empty slice, no error (graceful).
	s := &Server{outputsRoot: t.TempDir()}
	got, err := s.collectTierFindings("nonexistent")
	if err != nil {
		t.Fatalf("expected nil error for missing case, got %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
}

func TestReviewState(t *testing.T) {
	cases := []struct {
		approved, rejected bool
		by, want           string
	}{
		{false, false, "", "pending"},
		{true, false, "auto:severity-rule", "auto_approved"},
		{true, false, "examiner-jane", "approved"},
		{false, true, "", "rejected"},
	}
	for _, c := range cases {
		if got := reviewState(c.approved, c.rejected, c.by); got != c.want {
			t.Errorf("reviewState(%v,%v,%q)=%s want %s", c.approved, c.rejected, c.by, got, c.want)
		}
	}
}
