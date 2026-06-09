package tier1b

import (
	"reflect"
	"sort"
	"testing"
)

func TestValidateSkillSQL(t *testing.T) {
	good := "SELECT audit_id, ts_utc, artifact_id FROM unified_events WHERE case_id = ? AND artifact_id = 'lnk' LIMIT 100"
	if err := validateSkillSQL(good); err != nil {
		t.Fatalf("valid SQL rejected: %v", err)
	}
	cases := map[string]string{
		"not a select":       "EXPLAIN SELECT 1 WHERE case_id = ?",
		"ddl keyword":        "SELECT audit_id FROM unified_events WHERE case_id = ?; DROP TABLE x",
		"missing case_id":    "SELECT audit_id FROM unified_events WHERE artifact_id = ?",
		"two placeholders":   "SELECT audit_id FROM unified_events WHERE case_id = ? AND artifact_id = ?",
		"trailing semicolon": "SELECT audit_id FROM unified_events WHERE case_id = ?;",
		"empty":              "   ",
	}
	for name, sqlText := range cases {
		if err := validateSkillSQL(sqlText); err == nil {
			t.Errorf("%s: expected rejection, got nil", name)
		}
	}
	// A literal containing 'create' must not trip the keyword guard.
	lit := "SELECT audit_id, ts_utc, artifact_id FROM unified_events WHERE case_id = ? AND payload_json LIKE '%create remote thread%' LIMIT 10"
	if err := validateSkillSQL(lit); err != nil {
		t.Fatalf("keyword inside string literal should pass: %v", err)
	}
}

func TestPromotableHashes(t *testing.T) {
	auditToSQL := map[string][]string{
		"a1": {"sha-A"},
		"a2": {"sha-A", "sha-B"},
		"a3": {"sha-C"}, // produced by C but never cited
	}
	findings := []AnomalyFinding{
		{Summary: "f1", AuditIDs: []string{"a1"}},
		{Summary: "f2", AuditIDs: []string{"a2", "zz-not-from-cache"}},
	}
	got := promotableHashes(findings, auditToSQL)
	sort.Strings(got)
	want := []string{"sha-A", "sha-B"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("promotable = %v, want %v", got, want)
	}
}

func TestParseAnomalyOutput_Object(t *testing.T) {
	raw := "```json\n" + `{
	  "findings": [
	    {"lens":"A2","summary":"temp exec","severity":"High","audit_ids":["x1"]},
	    {"lens":"A1","summary":"","audit_ids":["x2"]},
	    {"lens":"A4","summary":"no evidence","severity":"low","audit_ids":[]}
	  ],
	  "proposed_queries": [
	    {"intent":"rare service install","rationale":"recurs","sql":"SELECT audit_id, ts_utc, artifact_id FROM unified_events WHERE case_id = ? LIMIT 50"}
	  ]
	}` + "\n```"
	findings, plans, _, err := parseAnomalyOutput(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 valid finding (empty-summary and no-evidence dropped), got %d", len(findings))
	}
	if findings[0].Severity != "high" {
		t.Fatalf("severity should be lowercased, got %q", findings[0].Severity)
	}
	if len(plans) != 1 || plans[0].Intent != "rare service install" {
		t.Fatalf("expected 1 proposed query, got %+v", plans)
	}
}

func TestParseAnomalyOutput_ArrayBackCompat(t *testing.T) {
	raw := `[{"lens":"A2","summary":"temp exec","severity":"high","audit_ids":["x1"]}]`
	findings, plans, _, err := parseAnomalyOutput(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if plans != nil {
		t.Fatalf("array shape carries no proposed_queries, got %+v", plans)
	}
}

func TestMergeCacheCandidates(t *testing.T) {
	heur := []candidate{
		{AuditID: "h1", Lenses: []string{"A1"}},
		{AuditID: "shared", Lenses: []string{"A2"}},
	}
	cache := []candidate{
		{AuditID: "c1", Lenses: []string{"S0"}},
		{AuditID: "shared", Lenses: []string{"S0"}},
	}
	out := mergeCacheCandidates(heur, cache, 10)
	// cache first, dedup 'shared', heuristic h1 last.
	if len(out) != 3 {
		t.Fatalf("expected 3 deduped, got %d (%+v)", len(out), out)
	}
	if out[0].AuditID != "c1" || out[1].AuditID != "shared" {
		t.Fatalf("cache candidates should lead: %+v", out)
	}
	// 'shared' should carry both lenses (S0 from cache + A2 from heuristic).
	if len(out[1].Lenses) != 2 {
		t.Fatalf("shared candidate should union lenses, got %v", out[1].Lenses)
	}
	// Cap is enforced.
	capped := mergeCacheCandidates(heur, cache, 1)
	if len(capped) != 1 || capped[0].AuditID != "c1" {
		t.Fatalf("cap not enforced / priority wrong: %+v", capped)
	}
}

func TestDedupStrings(t *testing.T) {
	got := dedupStrings([]string{"a", "", "b", "a", "c"}, 0)
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dedup = %v, want %v", got, want)
	}
	if limited := dedupStrings([]string{"a", "b", "c", "d"}, 2); len(limited) != 2 {
		t.Fatalf("limit not applied: %v", limited)
	}
}

func TestDistinctIntents(t *testing.T) {
	rows := []skillCacheEntry{
		{Intent: "rare service", State: "canonical", HitCount: 3},
		{Intent: "Rare Service", State: "candidate"}, // case-insensitive dup
		{Intent: "off-hours logon", State: "candidate"},
		{Intent: "", State: "candidate"}, // blank dropped
	}
	got := distinctIntents(rows)
	if len(got) != 2 {
		t.Fatalf("expected 2 distinct intents, got %d (%+v)", len(got), got)
	}
	if got[0].Intent != "rare service" || got[0].HitCount != 3 {
		t.Fatalf("first intent metadata wrong: %+v", got[0])
	}
}
