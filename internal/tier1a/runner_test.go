package tier1a

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tlvb/tlvb/internal/casedb"
	"github.com/tlvb/tlvb/internal/rulesdb"
)

func setupCase(t *testing.T) (*casedb.Manager, string, func()) {
	t.Helper()
	dir := t.TempDir()
	dbpath := filepath.Join(dir, "cases.duckdb")
	db, err := casedb.Open(dbpath, casedb.ReadWrite)
	if err != nil {
		t.Fatalf("casedb open: %v", err)
	}
	ctx := context.Background()
	if err := db.RegisterCase(ctx, casedb.CaseRow{
		CaseID: "C1", Name: "test", Examiner: "tester",
	}); err != nil {
		t.Fatalf("register case: %v", err)
	}
	if err := db.RegisterEvidence(ctx, casedb.EvidenceRow{
		EvidenceID: "EV1", CaseID: "C1", Path: "/tmp/fake",
		SHA256: "deadbeef", SizeBytes: 1,
	}); err != nil {
		t.Fatalf("register evidence: %v", err)
	}

	// Seed unified_events with two evtx rows that match a fake rule and
	// one shellbags row that should not match anything we test.
	insertEvent(t, db, "C1", "EV1", "evtx", "aud-1",
		mustTime("2026-05-20T08:00:00Z"), "process_creation", "WS01",
		`{"Image":"C:\\Windows\\System32\\powershell.exe","CommandLine":"powershell -enc AAAA"}`)
	insertEvent(t, db, "C1", "EV1", "evtx", "aud-2",
		mustTime("2026-05-20T08:05:00Z"), "process_creation", "WS01",
		`{"Image":"C:\\Windows\\System32\\powershell.exe","CommandLine":"powershell -nop -enc BBBB"}`)
	insertEvent(t, db, "C1", "EV1", "shellbags", "aud-3",
		mustTime("2026-05-20T08:10:00Z"), "registry_entry", "WS01",
		`{"Path":"C:\\\\Users\\\\foo"}`)

	cleanup := func() { _ = db.Close() }
	return db, dbpath, cleanup
}

func insertEvent(t *testing.T, db *casedb.Manager, caseID, evID, artifact, audit string, ts time.Time, etype, computer, payload string) {
	t.Helper()
	_, err := db.DB().Exec(
		`INSERT INTO unified_events (case_id, evidence_id, artifact_id, audit_id, ts_utc, event_type, computer, payload_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		caseID, evID, artifact, audit, ts, etype, computer, payload)
	if err != nil {
		t.Fatalf("insert event: %v", err)
	}
}

func mustTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func setupRules(t *testing.T) *rulesdb.Manager {
	t.Helper()
	dir := t.TempDir()
	dbpath := filepath.Join(dir, "rules.duckdb")
	rdb, err := rulesdb.Open(dbpath, rulesdb.ReadWrite)
	if err != nil {
		t.Fatalf("rulesdb open: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

func seedBuiltRule(t *testing.T, rdb *rulesdb.Manager, ruleID, source, sqlText, prefilter, meta string) {
	t.Helper()
	ctx := context.Background()
	if err := rdb.UpsertPending(ctx, rulesdb.CacheRow{
		RuleID: ruleID, RuleSource: source, RuleSHA256: "sha-" + ruleID,
		SchemaVersion: "uev-test", ModelID: "test",
		RuleMeta: meta,
	}); err != nil {
		t.Fatalf("upsert pending: %v", err)
	}
	if err := rdb.MarkBuilt(ctx, ruleID, source, sqlText, prefilter); err != nil {
		t.Fatalf("mark built: %v", err)
	}
}

func TestRunMatchesAndWritesFinding(t *testing.T) {
	cdb, _, cleanup := setupCase(t)
	defer cleanup()
	rdb := setupRules(t)

	seedBuiltRule(t, rdb,
		"sigma-1", "sigma",
		`SELECT audit_id, ts_utc, artifact_id, event_type,
		        json_extract_string(payload_json, '$.CommandLine') AS cmdline
		   FROM unified_events
		  WHERE case_id = ?
		    AND artifact_id = 'evtx'
		    AND json_extract_string(payload_json, '$.CommandLine') ILIKE '%-enc%'`,
		"evtx",
		`{"title":"Encoded PowerShell","level":"high","mitre_techniques":["T1059.001"]}`)

	outDir := t.TempDir()
	rep, err := Run(context.Background(), Config{
		CaseID: "C1", RulesDB: rdb, CaseDB: cdb,
		FindingsDir: outDir,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.TotalRules != 1 {
		t.Errorf("TotalRules: got %d, want 1", rep.TotalRules)
	}
	if rep.Matched != 1 {
		t.Errorf("Matched: got %d, want 1", rep.Matched)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("Findings: got %d, want 1", len(rep.Findings))
	}
	fs := rep.Findings[0]
	if fs.MatchCount != 2 {
		t.Errorf("MatchCount: got %d, want 2", fs.MatchCount)
	}

	// Inspect the on-disk finding.
	body, err := os.ReadFile(fs.OutputPath)
	if err != nil {
		t.Fatalf("read finding: %v", err)
	}
	var f Finding
	if err := json.Unmarshal(body, &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if f.RuleID != "sigma-1" || f.RuleSource != "sigma" {
		t.Errorf("rule_id/source: got %s/%s", f.RuleID, f.RuleSource)
	}
	if f.RuleMeta.Level != "high" {
		t.Errorf("level: got %q", f.RuleMeta.Level)
	}
	// High severity → NOT auto-approved.
	if f.Approved {
		t.Errorf("high-severity finding should NOT be auto-approved")
	}
	if f.ApprovedBy != "" {
		t.Errorf("ApprovedBy should be empty for high-severity, got %q", f.ApprovedBy)
	}
	if len(f.Evidence) != 2 {
		t.Fatalf("Evidence count: got %d, want 2", len(f.Evidence))
	}
	if cmd, _ := f.Evidence[0].Extra["cmdline"].(string); cmd == "" {
		t.Errorf("Extra cmdline column missing or empty: %v", f.Evidence[0].Extra)
	}
}

func TestRunSkipsRuleForMissingArtifact(t *testing.T) {
	cdb, _, cleanup := setupCase(t)
	defer cleanup()
	rdb := setupRules(t)

	// Rule targets registry (not parsed for case C1).
	seedBuiltRule(t, rdb,
		"sigma-r1", "sigma",
		`SELECT audit_id, ts_utc, artifact_id, event_type FROM unified_events WHERE case_id = ? AND artifact_id = 'registry'`,
		"registry",
		`{"title":"Registry-only rule","level":"low"}`)

	outDir := t.TempDir()
	rep, err := Run(context.Background(), Config{
		CaseID: "C1", RulesDB: rdb, CaseDB: cdb, FindingsDir: outDir,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.SkippedArtifact != 1 {
		t.Errorf("SkippedArtifact: got %d, want 1", rep.SkippedArtifact)
	}
	if rep.Matched != 0 {
		t.Errorf("Matched: got %d, want 0", rep.Matched)
	}
}

func TestRunAutoApprovesLowSeverity(t *testing.T) {
	cdb, _, cleanup := setupCase(t)
	defer cleanup()
	rdb := setupRules(t)

	seedBuiltRule(t, rdb,
		"sigma-low-1", "sigma",
		`SELECT audit_id, ts_utc, artifact_id, event_type FROM unified_events WHERE case_id = ? AND artifact_id = 'evtx'`,
		"evtx",
		`{"title":"Low sig","level":"low"}`)
	seedBuiltRule(t, rdb,
		"sigma-info-1", "sigma",
		`SELECT audit_id, ts_utc, artifact_id, event_type FROM unified_events WHERE case_id = ? AND artifact_id = 'evtx'`,
		"evtx",
		`{"title":"Info sig","level":"informational"}`)

	outDir := t.TempDir()
	rep, err := Run(context.Background(), Config{
		CaseID: "C1", RulesDB: rdb, CaseDB: cdb, FindingsDir: outDir,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Matched != 2 {
		t.Fatalf("Matched: got %d, want 2", rep.Matched)
	}
	for _, fs := range rep.Findings {
		body, _ := os.ReadFile(fs.OutputPath)
		var f Finding
		_ = json.Unmarshal(body, &f)
		if !f.Approved {
			t.Errorf("%s/%s (level=%s) should be auto-approved, got Approved=%v",
				f.RuleSource, f.RuleID, f.RuleMeta.Level, f.Approved)
		}
		if f.ApprovedBy != "auto:severity-rule" {
			t.Errorf("auto-approve ApprovedBy: got %q", f.ApprovedBy)
		}
	}
}

func TestRunRespectsRuleIDFilter(t *testing.T) {
	cdb, _, cleanup := setupCase(t)
	defer cleanup()
	rdb := setupRules(t)
	seedBuiltRule(t, rdb, "want", "sigma",
		`SELECT audit_id, ts_utc, artifact_id, event_type FROM unified_events WHERE case_id = ? AND artifact_id = 'evtx'`,
		"evtx", `{"level":"low"}`)
	seedBuiltRule(t, rdb, "other", "sigma",
		`SELECT audit_id, ts_utc, artifact_id, event_type FROM unified_events WHERE case_id = ? AND artifact_id = 'evtx'`,
		"evtx", `{"level":"low"}`)

	outDir := t.TempDir()
	rep, err := Run(context.Background(), Config{
		CaseID: "C1", RulesDB: rdb, CaseDB: cdb, FindingsDir: outDir,
		RuleIDFilter: "want",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.SkippedFilter != 1 {
		t.Errorf("SkippedFilter: got %d, want 1", rep.SkippedFilter)
	}
	if rep.Matched != 1 {
		t.Errorf("Matched: got %d, want 1", rep.Matched)
	}
}

func TestRunHandlesBadSQLAsErrorNotAbort(t *testing.T) {
	cdb, _, cleanup := setupCase(t)
	defer cleanup()
	rdb := setupRules(t)

	// SQL references non-existent column → driver returns error.
	seedBuiltRule(t, rdb, "bad", "sigma",
		`SELECT does_not_exist FROM unified_events WHERE case_id = ?`,
		"evtx", `{"level":"low"}`)
	// Good rule runs after, should still produce a finding.
	seedBuiltRule(t, rdb, "good", "sigma",
		`SELECT audit_id, ts_utc, artifact_id, event_type FROM unified_events WHERE case_id = ? AND artifact_id = 'evtx'`,
		"evtx", `{"level":"low"}`)

	outDir := t.TempDir()
	rep, err := Run(context.Background(), Config{
		CaseID: "C1", RulesDB: rdb, CaseDB: cdb, FindingsDir: outDir,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Errors != 1 {
		t.Errorf("Errors: got %d, want 1", rep.Errors)
	}
	if rep.Matched != 1 {
		t.Errorf("Matched: got %d, want 1 (good rule should still run after bad)", rep.Matched)
	}
}

func TestAutoApproveByLevel(t *testing.T) {
	cases := []struct {
		level    string
		wantApproved bool
	}{
		{"critical", false},
		{"high", false},
		{"medium", true},
		{"low", true},
		{"informational", true},
		{"", true},
		{"unknown", true}, // default to auto-approve
	}
	for _, c := range cases {
		ok, _ := AutoApproveByLevel(c.level)
		if ok != c.wantApproved {
			t.Errorf("level=%q: got Approved=%v, want %v", c.level, ok, c.wantApproved)
		}
	}
}
