package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeJSONFile(t *testing.T, p string, v any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(v)
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestWalkFindings(t *testing.T) {
	dir := t.TempDir()
	// Two Tier 1A findings (sigma + hayabusa) with different levels.
	writeJSONFile(t, filepath.Join(dir, "by-rule", "sigma", "r1.json"), map[string]any{
		"rule_source": "sigma",
		"rule_meta":   map[string]any{"level": "high"},
	})
	writeJSONFile(t, filepath.Join(dir, "by-rule", "hayabusa", "h1.json"), map[string]any{
		"rule_source": "hayabusa",
		"rule_meta":   map[string]any{"level": "medium"},
	})
	writeJSONFile(t, filepath.Join(dir, "by-rule", "hayabusa", "h2.json"), map[string]any{
		"rule_source": "hayabusa",
		"rule_meta":   map[string]any{"level": "high"},
	})
	// One Tier 1B AnomalyReport with 2 findings.
	writeJSONFile(t, filepath.Join(dir, "by-skill", "anomaly_hunter.json"), map[string]any{
		"skill": "anomaly_hunter",
		"findings": []map[string]any{
			{"severity": "critical"},
			{"severity": "low"},
		},
	})

	s := walkFindings(dir)
	if s.totalByRule != 3 {
		t.Errorf("totalByRule: got %d, want 3", s.totalByRule)
	}
	if s.totalBySkill != 2 {
		t.Errorf("totalBySkill: got %d, want 2", s.totalBySkill)
	}
	if s.bySource["sigma"] != 1 {
		t.Errorf("sigma count: got %d, want 1", s.bySource["sigma"])
	}
	if s.bySource["hayabusa"] != 2 {
		t.Errorf("hayabusa count: got %d, want 2", s.bySource["hayabusa"])
	}
	if s.bySource["anomaly_hunter"] != 2 {
		t.Errorf("anomaly_hunter count: got %d, want 2", s.bySource["anomaly_hunter"])
	}
	if s.bySeverity["high"] != 2 {
		t.Errorf("high: got %d, want 2", s.bySeverity["high"])
	}
	if s.bySeverity["medium"] != 1 {
		t.Errorf("medium: got %d, want 1", s.bySeverity["medium"])
	}
	if s.bySeverity["critical"] != 1 {
		t.Errorf("critical: got %d, want 1", s.bySeverity["critical"])
	}
	if s.bySeverity["low"] != 1 {
		t.Errorf("low: got %d, want 1", s.bySeverity["low"])
	}
}

func TestWalkFindingsEmptyDir(t *testing.T) {
	dir := t.TempDir()
	s := walkFindings(dir)
	if s.totalByRule != 0 || s.totalBySkill != 0 {
		t.Errorf("expected zero counts, got rule=%d skill=%d",
			s.totalByRule, s.totalBySkill)
	}
}

func TestReadSynthesisSummary(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "synthesis.json")
	writeJSONFile(t, p, map[string]any{
		"total_findings": 39,
		"cluster_count":  2,
		"overall_story":  "Some overall narrative.",
		"mitre_mapping": []map[string]any{
			{"technique": "T1059"}, {"technique": "T1003"}, {"technique": "T1486"},
		},
		"audit": map[string]any{
			"active_sql_attempted": 6,
			"active_sql_succeeded": 6,
		},
	})
	sum, err := readSynthesisSummary(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if sum.TotalFindings != 39 {
		t.Errorf("TotalFindings: got %d", sum.TotalFindings)
	}
	if sum.ClusterCount != 2 {
		t.Errorf("ClusterCount: got %d", sum.ClusterCount)
	}
	if sum.MITRECount != 3 {
		t.Errorf("MITRECount: got %d", sum.MITRECount)
	}
	if !sum.HasOverallStory {
		t.Error("HasOverallStory should be true")
	}
	if sum.OverallStoryLen != len("Some overall narrative.") {
		t.Errorf("OverallStoryLen: got %d", sum.OverallStoryLen)
	}
	if sum.ActiveSearchSucceeded != 6 || sum.ActiveSearchAttempted != 6 {
		t.Errorf("active search: got %d/%d", sum.ActiveSearchSucceeded, sum.ActiveSearchAttempted)
	}
}

func TestReadSynthesisSummaryEmptyOverall(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "synthesis.json")
	writeJSONFile(t, p, map[string]any{
		"total_findings": 5,
		"cluster_count":  1,
		"overall_story":  "   ", // whitespace-only counts as empty
	})
	sum, _ := readSynthesisSummary(p)
	if sum.HasOverallStory {
		t.Error("whitespace-only overall_story should NOT count as present")
	}
}

func TestCommaInt64(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0"},
		{42, "42"},
		{1000, "1,000"},
		{470372, "470,372"},
		{1234567890, "1,234,567,890"},
	}
	for _, c := range cases {
		if got := commaInt64(c.in); got != c.want {
			t.Errorf("commaInt64(%d): got %q, want %q", c.in, got, c.want)
		}
	}
}
