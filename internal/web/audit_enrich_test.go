package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tlvb/tlvb/internal/tier1a"
	"github.com/tlvb/tlvb/internal/tier1b"
	"github.com/tlvb/tlvb/internal/tier2"
)

func mustWriteJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestAuditEnricher checks that each agent audit-row kind is joined back to the
// human "what / why" context stored in findings/**/*.json and synthesis.json.
func TestAuditEnricher(t *testing.T) {
	root := t.TempDir()
	caseID := "C1"
	caseDir := filepath.Join(root, caseID)

	mustWriteJSONFile(t, filepath.Join(caseDir, "findings", "by-rule", "sigma", "rule-1.json"),
		tier1a.Finding{
			RuleID: "rule-1", RuleSource: "sigma",
			RuleMeta: tier1a.RuleMeta{
				Title: "Webshell Strings", Description: "Detects webshell markers",
				MITRETechniques: []string{"T1505.003"}, MITRETactics: []string{"persistence"},
				SourcePath: "rules/sigma/x.yml",
			},
			SQL: "SELECT * FROM unified_events WHERE 1=1",
		})

	mustWriteJSONFile(t, filepath.Join(caseDir, "findings", "by-skill", "anomaly_hunter.json"),
		tier1b.AnomalyReport{
			Skill: "anomaly_hunter", EventsScanned: 1234, PriorFindings: 7,
			Findings: []tier1b.AnomalyFinding{{
				Summary: "Recovery inhibition cluster", Description: "vssadmin+wbadmin first-run",
				Severity: "high", TechniqueID: "T1490",
			}},
		})

	mustWriteJSONFile(t, filepath.Join(caseDir, "synthesis.json"),
		tier2.CaseSynthesis{
			OverallStory: "Whole-case story",
			Clusters: []tier2.SynthCluster{{
				ID: 3, AttackPhase: "impact", Narrative: "Cluster narrative here",
				OpenQuestions: []string{"Which files were encrypted?"},
				ActiveSearch: []tier2.ActiveSearchResult{{
					Question: "Which files were affected?",
					SQL:      "SELECT a FROM unified_events WHERE x = 1",
					Answer:   "101 tiny .locked files",
					Attempts: []tier2.SQLAttempt{
						{N: 1, SQL: "SELECT bad", Outcome: "execute_error"},
						{N: 2, SQL: "SELECT a FROM unified_events WHERE x = 1", Outcome: "ok"},
					},
				}},
			}},
		})

	enr := newAuditEnricher(root, caseID)

	// Tier 1A rule_sql → rule intent + SQL + MITRE (tactics before techniques).
	ex := enr.explain(map[string]any{"actor": "tier1a", "kind": "rule_sql", "rule_id": "rule-1", "rule_source": "sigma"})
	if ex == nil || ex.RuleTitle != "Webshell Strings" || ex.SQL == "" || ex.SourcePath != "rules/sigma/x.yml" {
		t.Fatalf("1A explain = %+v", ex)
	}
	if len(ex.MITRE) != 2 || ex.MITRE[0] != "persistence" || ex.MITRE[1] != "T1505.003" {
		t.Errorf("1A MITRE = %v", ex.MITRE)
	}

	// Tier 1B llm_call → anomaly findings + scan scope.
	ex = enr.explain(map[string]any{"actor": "tier1b", "kind": "llm_call", "detail": "anomaly_hunter"})
	if ex == nil || ex.EventsScanned != 1234 || ex.PriorFindings != 7 ||
		len(ex.Findings) != 1 || ex.Findings[0].Technique != "T1490" {
		t.Fatalf("1B explain = %+v", ex)
	}

	// Tier 2 cluster_analysis → narrative (cluster_id arrives as JSON float64).
	ex = enr.explain(map[string]any{"actor": "tier2", "kind": "llm_call", "detail": "cluster_analysis", "cluster_id": float64(3)})
	if ex == nil || ex.Narrative != "Cluster narrative here" || ex.AttackPhase != "impact" {
		t.Fatalf("2 cluster explain = %+v", ex)
	}

	// Tier 2 overall_synthesis → overall story.
	ex = enr.explain(map[string]any{"actor": "tier2", "kind": "llm_call", "detail": "overall_synthesis", "cluster_id": float64(0)})
	if ex == nil || ex.Narrative != "Whole-case story" {
		t.Fatalf("2 overall explain = %+v", ex)
	}

	// Tier 2 active_sql → question+answer, matched on the corrected (attempt-2)
	// SQL even with incidental whitespace differences.
	ex = enr.explain(map[string]any{"actor": "tier2", "kind": "active_sql", "cluster_id": float64(3),
		"command": "SELECT   a FROM unified_events\nWHERE x = 1"})
	if ex == nil || ex.Question != "Which files were affected?" || ex.Answer != "101 tiny .locked files" {
		t.Fatalf("2 active_sql explain = %+v", ex)
	}

	// The failed first-attempt SQL maps to the same question (audit logs every attempt).
	ex = enr.explain(map[string]any{"actor": "tier2", "kind": "active_sql", "cluster_id": float64(3), "command": "SELECT bad"})
	if ex == nil || ex.Question != "Which files were affected?" {
		t.Fatalf("2 active_sql attempt1 explain = %+v", ex)
	}

	// Tier 0 / unknown rows carry no explain.
	if got := enr.explain(map[string]any{"actor": "tier0-orchestrator", "kind": "parse"}); got != nil {
		t.Errorf("tier0 explain = %+v, want nil", got)
	}

	// A rule_sql whose finding file is absent (e.g. a failed rule) → nil, no panic.
	if got := enr.explain(map[string]any{"actor": "tier1a", "kind": "rule_sql", "rule_id": "absent", "rule_source": "sigma"}); got != nil {
		t.Errorf("absent rule explain = %+v, want nil", got)
	}
}

func TestNormalizeSQL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"  SELECT a\n FROM t  ", "SELECT a FROM t"},
		{"SELECT\t1", "SELECT 1"},
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeSQL(c.in); got != c.want {
			t.Errorf("normalizeSQL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
