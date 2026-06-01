package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/tlvb/tlvb/internal/rulesdb"
)

// seedRulesDB writes a temp rules.duckdb with one built rule, one pending
// rule, and one skill candidate, then returns a Server pointed at it plus a
// mux with the Rule Library routes registered.
func ruleLibFixture(t *testing.T, rulesDBPath string) (http.Handler, error) {
	t.Helper()
	if rulesDBPath != "" {
		m, err := rulesdb.Open(rulesDBPath, rulesdb.ReadWrite)
		if err != nil {
			return nil, err
		}
		ctx := context.Background()
		// Built sigma rule with rich meta.
		_ = m.UpsertPending(ctx, rulesdb.CacheRow{
			RuleID: "rule-a", RuleSource: "sigma",
			RuleSHA256: "sha-a", SchemaVersion: "v1", ModelID: "model-1",
			RuleMeta: `{"level":"high","title":"LSASS Dump Keyword","mitre_techniques":["T1003.001"]}`,
		})
		_ = m.MarkBuilt(ctx, "rule-a", "sigma",
			"SELECT audit_id, ts_utc, artifact_id FROM unified_events WHERE case_id = ? AND artifact_id='evtx'",
			"evtx")
		// Pending sigma rule.
		_ = m.UpsertPending(ctx, rulesdb.CacheRow{
			RuleID: "rule-b", RuleSource: "sigma",
			RuleSHA256: "sha-b", SchemaVersion: "v1", ModelID: "model-1",
			RuleMeta: `{"level":"low","title":"Registry Query Discovery"}`,
		})
		// Skill candidate (Tier 1B v0.2 cache).
		_, _ = m.UpsertSkillCandidate(ctx, rulesdb.SkillSQLRow{
			Skill:  "anomaly_hunter",
			SQL:    "SELECT audit_id, ts_utc, artifact_id FROM unified_events WHERE case_id = ? LIMIT 50",
			Intent: "rare service install off-hours", OriginCase: "case-x",
			SchemaVersion: "v1", ModelID: "model-1",
		})
		m.Close()
	}

	s := &Server{cfg: Config{RulesDBPath: rulesDBPath}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/rules/summary", s.handleGetRulesSummary)
	mux.HandleFunc("GET /api/rules/skills", s.handleListSkillSQL)
	mux.HandleFunc("GET /api/rules", s.handleListRules)
	return mux, nil
}

func getJSON(t *testing.T, mux http.Handler, url string, dst any) int {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", url, nil))
	if rec.Code == 200 && dst != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
			t.Fatalf("unmarshal %s: %v body=%s", url, err, rec.Body.String())
		}
	}
	return rec.Code
}

func TestRuleLibrarySummary(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rules.duckdb")
	mux, err := ruleLibFixture(t, dbPath)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var sum RulesSummary
	if code := getJSON(t, mux, "/api/rules/summary", &sum); code != 200 {
		t.Fatalf("summary status %d", code)
	}
	if !sum.Available {
		t.Fatal("expected available=true")
	}
	if sum.Rules.Total != 2 || sum.Rules.ByState["built"] != 1 || sum.Rules.ByState["pending"] != 1 {
		t.Fatalf("rule counts wrong: %+v", sum.Rules)
	}
	if len(sum.Rules.BySource) != 1 || sum.Rules.BySource[0].Source != "sigma" ||
		sum.Rules.BySource[0].Built != 1 || sum.Rules.BySource[0].Pending != 1 {
		t.Fatalf("by_source wrong: %+v", sum.Rules.BySource)
	}
	if sum.Skills.Candidate != 1 || sum.Skills.Total != 1 {
		t.Fatalf("skill counts wrong: %+v", sum.Skills)
	}
}

func TestRuleLibraryListAndFilter(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rules.duckdb")
	mux, err := ruleLibFixture(t, dbPath)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}

	// No filter → both rules, meta parsed.
	var all RuleListResponse
	getJSON(t, mux, "/api/rules", &all)
	if all.Total != 2 {
		t.Fatalf("expected 2 rules, got %d", all.Total)
	}
	var builtRow *RuleRow
	for i := range all.Rows {
		if all.Rows[i].RuleID == "rule-a" {
			builtRow = &all.Rows[i]
		}
	}
	if builtRow == nil || builtRow.Level != "high" || builtRow.Title != "LSASS Dump Keyword" ||
		len(builtRow.MitreTechniques) != 1 || builtRow.SQL == "" {
		t.Fatalf("built rule meta not parsed: %+v", builtRow)
	}

	// state=built → only rule-a.
	var built RuleListResponse
	getJSON(t, mux, "/api/rules?state=built", &built)
	if built.Total != 1 || built.Rows[0].RuleID != "rule-a" {
		t.Fatalf("state filter wrong: %+v", built)
	}

	// q=registry → matches rule-b's title (case-insensitive).
	var q RuleListResponse
	getJSON(t, mux, "/api/rules?q=registry", &q)
	if q.Total != 1 || q.Rows[0].RuleID != "rule-b" {
		t.Fatalf("q filter wrong: %+v", q)
	}
}

func TestRuleLibrarySkills(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rules.duckdb")
	mux, err := ruleLibFixture(t, dbPath)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var resp struct {
		Rows []SkillRow `json:"rows"`
	}
	getJSON(t, mux, "/api/rules/skills", &resp)
	if len(resp.Rows) != 1 || resp.Rows[0].Intent != "rare service install off-hours" ||
		resp.Rows[0].State != "candidate" || resp.Rows[0].SQL == "" {
		t.Fatalf("skill row wrong: %+v", resp.Rows)
	}
}

func TestRuleLibraryMissingDBGraceful(t *testing.T) {
	// Point at a path that does not exist → handlers answer empty, not 500.
	missing := filepath.Join(t.TempDir(), "nope.duckdb")
	s := &Server{cfg: Config{RulesDBPath: missing}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/rules/summary", s.handleGetRulesSummary)
	mux.HandleFunc("GET /api/rules", s.handleListRules)

	var sum RulesSummary
	if code := getJSON(t, mux, "/api/rules/summary", &sum); code != 200 {
		t.Fatalf("missing-db summary status %d (want 200)", code)
	}
	if sum.Available {
		t.Fatal("expected available=false for missing rules.duckdb")
	}
	var list RuleListResponse
	if code := getJSON(t, mux, "/api/rules", &list); code != 200 || list.Total != 0 {
		t.Fatalf("missing-db list: code=%d total=%d (want 200/0)", code, list.Total)
	}
}
