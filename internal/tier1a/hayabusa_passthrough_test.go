package tier1a

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tlvb/tlvb/internal/casedb"
)

// insertHayabusa inserts one unified_events row whose payload is the
// Hayabusa JSON the parser writes.
func insertHayabusa(t *testing.T, db *casedb.Manager, caseID, ruleID, title, level string, ts time.Time, channel, eventID, details string) {
	t.Helper()
	payload := map[string]any{
		"RuleID":         ruleID,
		"RuleTitle":      title,
		"Level":          level,
		"Channel":        channel,
		"EventID":        eventID,
		"Computer":       "WS01",
		"Details":        details,
		"ExtraFieldInfo": "",
		"Timestamp":      ts.Format(time.RFC3339Nano),
	}
	body, _ := json.Marshal(payload)
	audit := ruleID + "-" + ts.Format("150405.000")
	if _, err := db.DB().Exec(
		`INSERT INTO unified_events (case_id, evidence_id, artifact_id, audit_id, ts_utc, event_type, computer, payload_json)
		 VALUES (?, ?, 'hayabusa', ?, ?, 'hayabusa', 'WS01', ?)`,
		caseID, "EV1", audit, ts, string(body)); err != nil {
		t.Fatalf("insert hayabusa: %v", err)
	}
}

func TestHayabusaPassthroughGroupsAndFilters(t *testing.T) {
	cdb, _, cleanup := setupCase(t)
	defer cleanup()

	// 3 high-level hits across 2 rules + 2 info-level hits (should be filtered)
	t0 := mustTime("2026-05-20T08:00:00Z")
	insertHayabusa(t, cdb, "C1", "rule-A", "Important Log File Cleared", "high",
		t0, "Sys", "104", "Log: System")
	insertHayabusa(t, cdb, "C1", "rule-A", "Important Log File Cleared", "high",
		t0.Add(5*time.Second), "Sys", "104", "Log: Application")
	insertHayabusa(t, cdb, "C1", "rule-B", "Suspicious Eventlog Clearing", "high",
		t0.Add(10*time.Second), "Sec", "1102", "User: taro")
	insertHayabusa(t, cdb, "C1", "rule-noise-1", "Proc Exec", "info",
		t0.Add(20*time.Second), "Sec", "4688", "noise")
	insertHayabusa(t, cdb, "C1", "rule-noise-2", "Net Conn", "low",
		t0.Add(25*time.Second), "Sec", "5156", "noise")

	outDir := t.TempDir()
	cfg := Config{
		CaseID: "C1", CaseDB: cdb, FindingsDir: outDir,
	}
	rep, err := RunHayabusaPassthrough(context.Background(), cfg,
		HayabusaPassthroughOptions{IncludeInfoLevel: false})
	if err != nil {
		t.Fatalf("RunHayabusaPassthrough: %v", err)
	}

	// 2 unique high-level rules emitted; info/low filtered out.
	if rep.TotalRules != 2 {
		t.Errorf("TotalRules: got %d, want 2", rep.TotalRules)
	}
	if rep.Matched != 2 {
		t.Errorf("Matched: got %d, want 2", rep.Matched)
	}
	if len(rep.Findings) != 2 {
		t.Fatalf("Findings: got %d, want 2", len(rep.Findings))
	}

	// rule-A finding should bundle the 2 evidence rows.
	var ruleA *FindingSummary
	for i := range rep.Findings {
		if rep.Findings[i].RuleID == "rule-A" {
			ruleA = &rep.Findings[i]
		}
	}
	if ruleA == nil {
		t.Fatal("rule-A finding missing")
	}
	if ruleA.MatchCount != 2 {
		t.Errorf("rule-A MatchCount: got %d, want 2", ruleA.MatchCount)
	}
	if ruleA.RuleSource != "hayabusa" {
		t.Errorf("rule_source: got %q, want hayabusa", ruleA.RuleSource)
	}

	// Inspect on-disk finding.
	body, err := os.ReadFile(ruleA.OutputPath)
	if err != nil {
		t.Fatalf("read finding: %v", err)
	}
	var f Finding
	if err := json.Unmarshal(body, &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if f.RuleMeta.Level != "high" {
		t.Errorf("level not propagated: %q", f.RuleMeta.Level)
	}
	if f.Approved {
		t.Errorf("high-level finding should NOT be auto-approved")
	}
	if len(f.Evidence) != 2 {
		t.Errorf("Evidence: got %d, want 2", len(f.Evidence))
	}
	if ch, _ := f.Evidence[0].Extra["channel"].(string); ch == "" {
		t.Errorf("channel extra missing: %v", f.Evidence[0].Extra)
	}
}

func TestHayabusaPassthroughIncludesInfoWhenFlag(t *testing.T) {
	cdb, _, cleanup := setupCase(t)
	defer cleanup()
	t0 := mustTime("2026-05-20T08:00:00Z")
	insertHayabusa(t, cdb, "C1", "rule-X", "high rule", "high", t0,
		"Sec", "4688", "x")
	insertHayabusa(t, cdb, "C1", "rule-Y", "info rule", "info", t0.Add(1*time.Second),
		"Sec", "4688", "y")

	outDir := t.TempDir()
	rep, err := RunHayabusaPassthrough(context.Background(), Config{
		CaseID: "C1", CaseDB: cdb, FindingsDir: outDir,
	}, HayabusaPassthroughOptions{IncludeInfoLevel: true})
	if err != nil {
		t.Fatalf("RunHayabusaPassthrough: %v", err)
	}
	if rep.Matched != 2 {
		t.Errorf("with IncludeInfoLevel=true, expected 2 matches, got %d", rep.Matched)
	}

	// info-level finding should be auto-approved.
	for _, fs := range rep.Findings {
		if fs.RuleID == "rule-Y" {
			body, _ := os.ReadFile(fs.OutputPath)
			var f Finding
			_ = json.Unmarshal(body, &f)
			if !f.Approved {
				t.Errorf("informational finding should be auto-approved: %+v", f)
			}
			if f.ApprovedBy != "auto:severity-rule" {
				t.Errorf("ApprovedBy: got %q", f.ApprovedBy)
			}
		}
	}
}

func TestHayabusaPassthroughLevelNormalisation(t *testing.T) {
	cases := []struct{ in, want string }{
		{"info", "informational"},
		{"med", "medium"},
		{"high", "high"},
		{"low", "low"},
		{"critical", "critical"},
		{" HIGH ", "high"},
	}
	for _, c := range cases {
		got := normaliseLevel(c.in)
		if got != c.want {
			t.Errorf("normaliseLevel(%q): got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHayabusaPassthroughEmptyCaseProducesNoFindings(t *testing.T) {
	cdb, _, cleanup := setupCase(t)
	defer cleanup()
	outDir := t.TempDir()
	rep, err := RunHayabusaPassthrough(context.Background(), Config{
		CaseID: "C1", CaseDB: cdb, FindingsDir: outDir,
	}, HayabusaPassthroughOptions{})
	if err != nil {
		t.Fatalf("RunHayabusaPassthrough: %v", err)
	}
	if rep.Matched != 0 {
		t.Errorf("empty case: got %d matches, want 0", rep.Matched)
	}
	// Out dir should not have any files written.
	files, _ := filepath.Glob(filepath.Join(outDir, "hayabusa", "*.json"))
	if len(files) != 0 {
		t.Errorf("empty case wrote %d findings", len(files))
	}
}
