package tier2

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(v)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadFindingsFromBothSources(t *testing.T) {
	dir := t.TempDir()
	// Tier 1A finding under by-rule/sigma/
	t1a := map[string]any{
		"finding_id": "f-1a-1",
		"case_id":    "C1",
		"rule_id":    "sigma-1",
		"rule_source": "sigma",
		"rule_meta": map[string]any{
			"title":            "Encoded PowerShell",
			"level":            "high",
			"mitre_techniques": []string{"T1059.001"},
			"mitre_tactics":    []string{"execution"},
		},
		"evidence": []map[string]any{
			{"audit_id": "aud-1", "ts_utc": "2026-05-19T13:50:28Z",
				"artifact_id": "evtx", "event_type": "evtx"},
		},
	}
	writeJSON(t, filepath.Join(dir, "by-rule", "sigma", "sigma-1.json"), t1a)

	// Tier 1A Hayabusa pass-through under by-rule/hayabusa/
	t1aHaya := map[string]any{
		"finding_id": "f-1a-2",
		"case_id":    "C1",
		"rule_id":    "haya-1",
		"rule_source": "hayabusa",
		"rule_meta": map[string]any{
			"title": "Mimikatz Execution",
			"level": "high",
		},
		"evidence": []map[string]any{
			{"audit_id": "aud-2", "ts_utc": "2026-05-19T13:56:27Z",
				"artifact_id": "hayabusa", "event_type": "hayabusa_detection"},
		},
	}
	writeJSON(t, filepath.Join(dir, "by-rule", "hayabusa", "haya-1.json"), t1aHaya)

	// Tier 1B AnomalyReport under by-skill/
	t1b := map[string]any{
		"case_id": "C1",
		"skill":   "anomaly_hunter",
		"findings": []map[string]any{
			{
				"finding_id":   "f-1b-1",
				"lens":         "A5",
				"summary":      "Prefetch execution burst",
				"description":  "9 prefetch entries within ±30 min of finding ts",
				"severity":     "medium",
				"audit_ids":    []string{"pf-aud-1", "pf-aud-2"},
				"technique_id": "T1059",
				"tactic":       "execution",
			},
		},
	}
	writeJSON(t, filepath.Join(dir, "by-skill", "anomaly_hunter.json"), t1b)

	got, err := LoadFindings(dir)
	if err != nil {
		t.Fatalf("LoadFindings: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(got))
	}
	var t1aFinding, hayaFinding, t1bFinding *Finding
	for i := range got {
		switch got[i].Source {
		case "sigma":
			t1aFinding = &got[i]
		case "hayabusa":
			hayaFinding = &got[i]
		case "anomaly_hunter":
			t1bFinding = &got[i]
		}
	}
	if t1aFinding == nil {
		t.Fatal("sigma source finding missing")
	}
	if t1aFinding.Title != "Encoded PowerShell" {
		t.Errorf("title: %q", t1aFinding.Title)
	}
	if t1aFinding.MITRETactic != "execution" {
		t.Errorf("tactic: %q", t1aFinding.MITRETactic)
	}

	if hayaFinding == nil {
		t.Fatal("hayabusa source finding missing")
	}
	if hayaFinding.RuleID != "haya-1" {
		t.Errorf("haya rule_id: %q", hayaFinding.RuleID)
	}

	if t1bFinding == nil {
		t.Fatal("anomaly_hunter source finding missing")
	}
	if t1bFinding.Description == "" {
		t.Errorf("Tier 1B description not propagated")
	}
	if len(t1bFinding.Evidence) != 2 {
		t.Errorf("Tier 1B evidence count: got %d, want 2", len(t1bFinding.Evidence))
	}
}

func TestLoadFindingsToleratesMissingDirs(t *testing.T) {
	dir := t.TempDir()
	got, err := LoadFindings(dir)
	if err != nil {
		t.Fatalf("expected nil error with missing subdirs, got: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 findings, got %d", len(got))
	}
}

func TestFirstTimestamp(t *testing.T) {
	earlier := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	later := time.Date(2026, 5, 19, 14, 0, 0, 0, time.UTC)
	f := Finding{
		Evidence: []FindingEvidence{
			{TsUTC: later, HasTS: true},
			{TsUTC: earlier, HasTS: true},
			{HasTS: false},
		},
	}
	if got := f.FirstTimestamp(); !got.Equal(earlier) {
		t.Errorf("got %v, want %v", got, earlier)
	}
	if got := (Finding{}).FirstTimestamp(); !got.IsZero() {
		t.Errorf("empty finding should return zero time, got %v", got)
	}
}
