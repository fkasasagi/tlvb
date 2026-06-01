package rulesdb

import (
	"context"
	"path/filepath"
	"testing"
)

func TestRulesDBLifecycle(t *testing.T) {
	dir := t.TempDir()
	dbpath := filepath.Join(dir, "rules.duckdb")
	m, err := Open(dbpath, ReadWrite)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer m.Close()
	ctx := context.Background()

	// 1. UpsertPending creates a new row in 'pending' state.
	row := CacheRow{
		RuleID:        "abc-1",
		RuleSource:    "sigma",
		RuleSHA256:    "sha256-v1",
		SchemaVersion: "uev-aaaa",
		ModelID:       "claude-sonnet-4-6",
		RuleMeta:      `{"level":"high"}`,
	}
	if err := m.UpsertPending(ctx, row); err != nil {
		t.Fatalf("upsert pending: %v", err)
	}
	counts, _ := m.CountByState(ctx)
	if counts[StatePending] != 1 {
		t.Fatalf("expected 1 pending, got %v", counts)
	}

	// 2. MarkBuilt → state moves to 'built', SQL is stored.
	if err := m.MarkBuilt(ctx, "abc-1", "sigma",
		"SELECT audit_id FROM unified_events WHERE case_id = ? AND artifact_id = 'evtx'",
		"evtx"); err != nil {
		t.Fatalf("mark built: %v", err)
	}
	sqlText, err := m.GetBuiltSQL(ctx, "abc-1", "sigma")
	if err != nil {
		t.Fatalf("get built sql: %v", err)
	}
	if sqlText == "" {
		t.Fatal("expected built SQL, got empty")
	}

	// 3. Re-upserting with the SAME signature leaves the 'built' row alone.
	if err := m.UpsertPending(ctx, row); err != nil {
		t.Fatalf("re-upsert (same sig): %v", err)
	}
	counts, _ = m.CountByState(ctx)
	if counts[StateBuilt] != 1 || counts[StatePending] != 0 {
		t.Fatalf("same-sig re-upsert disturbed built row: %v", counts)
	}
	sqlText2, _ := m.GetBuiltSQL(ctx, "abc-1", "sigma")
	if sqlText2 != sqlText {
		t.Fatal("same-sig re-upsert lost SQL text")
	}

	// 4. Re-upserting with a CHANGED rule_sha256 invalidates the cache.
	row.RuleSHA256 = "sha256-v2"
	if err := m.UpsertPending(ctx, row); err != nil {
		t.Fatalf("re-upsert (new sig): %v", err)
	}
	counts, _ = m.CountByState(ctx)
	if counts[StatePending] != 1 || counts[StateBuilt] != 0 {
		t.Fatalf("new-sig re-upsert did not invalidate cache: %v", counts)
	}
	if got, _ := m.GetBuiltSQL(ctx, "abc-1", "sigma"); got != "" {
		t.Fatal("new-sig re-upsert should clear cached SQL")
	}

	// 5. MarkFailed records the error and moves to 'failed'.
	if err := m.MarkFailed(ctx, "abc-1", "sigma", "LLM returned invalid SQL"); err != nil {
		t.Fatalf("mark failed: %v", err)
	}
	counts, _ = m.CountByState(ctx)
	if counts[StateFailed] != 1 {
		t.Fatalf("expected 1 failed, got %v", counts)
	}

	// 6. ListPending includes failed rows (so retries happen).
	pending, err := m.ListPending(ctx, "")
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending+failed, got %d", len(pending))
	}
	if pending[0].ErrorMessage != "LLM returned invalid SQL" {
		t.Fatalf("error message not propagated: %q", pending[0].ErrorMessage)
	}

	// 7. Source filter narrows the list.
	pending, _ = m.ListPending(ctx, "hayabusa")
	if len(pending) != 0 {
		t.Fatalf("source filter for hayabusa should be empty, got %d", len(pending))
	}
}

func TestSkillSQLCacheLifecycle(t *testing.T) {
	dir := t.TempDir()
	m, err := Open(filepath.Join(dir, "rules.duckdb"), ReadWrite)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer m.Close()
	ctx := context.Background()

	const skill = "anomaly_hunter"
	sig := func(r SkillSQLRow) SkillSQLRow {
		r.Skill = skill
		r.SchemaVersion = "uev-aaaa"
		r.ModelID = "claude-opus-4-8"
		return r
	}

	// 1. First candidate insert reports inserted=true.
	q1 := "SELECT audit_id, ts_utc, artifact_id FROM unified_events WHERE case_id = ? AND artifact_id = 'lnk' LIMIT 100"
	ins, err := m.UpsertSkillCandidate(ctx, sig(SkillSQLRow{
		SQL: q1, Intent: "lnk targets in temp", OriginCase: "CASE-1",
	}))
	if err != nil || !ins {
		t.Fatalf("first insert: ins=%v err=%v", ins, err)
	}

	// 2. Re-inserting the same SQL with only whitespace/case differences is
	//    deduped by the normalized hash → inserted=false.
	q1variant := "select  audit_id, ts_utc, artifact_id  FROM unified_events WHERE case_id = ?   AND artifact_id = 'lnk' LIMIT 100 ;"
	ins, err = m.UpsertSkillCandidate(ctx, sig(SkillSQLRow{SQL: q1variant, Intent: "dup"}))
	if err != nil {
		t.Fatalf("dup insert err: %v", err)
	}
	if ins {
		t.Fatal("whitespace/case-variant SQL should dedup to the existing row")
	}

	// 3. A genuinely different query inserts as a second candidate.
	q2 := "SELECT audit_id, ts_utc, artifact_id FROM unified_events WHERE case_id = ? AND artifact_id = 'registry' LIMIT 50"
	if ins, _ := m.UpsertSkillCandidate(ctx, sig(SkillSQLRow{SQL: q2, Intent: "run keys"})); !ins {
		t.Fatal("distinct SQL should insert")
	}

	counts, _ := m.CountSkillByState(ctx)
	if counts[SkillCandidate] != 2 {
		t.Fatalf("expected 2 candidates, got %v", counts)
	}

	// 4. ListSkillSQL returns both for the matching signature.
	rows, err := m.ListSkillSQL(ctx, skill, "uev-aaaa", "claude-opus-4-8")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}

	// 5. Promotion flips state to canonical, bumps hit_count, sets last_used.
	h1 := SkillSQLHash(q1)
	if err := m.PromoteSkillSQL(ctx, skill, h1, "CASE-2"); err != nil {
		t.Fatalf("promote: %v", err)
	}
	counts, _ = m.CountSkillByState(ctx)
	if counts[SkillCanonical] != 1 || counts[SkillCandidate] != 1 {
		t.Fatalf("after promote expected 1/1, got %v", counts)
	}
	// Promoting again (canonical re-hit) bumps hit_count without demoting.
	if err := m.PromoteSkillSQL(ctx, skill, h1, "CASE-3"); err != nil {
		t.Fatalf("re-promote: %v", err)
	}
	rows, _ = m.ListSkillSQL(ctx, skill, "uev-aaaa", "claude-opus-4-8")
	if rows[0].State != SkillCanonical { // canonical ordered first
		t.Fatalf("expected canonical first, got %q", rows[0].State)
	}
	if rows[0].HitCount != 2 || rows[0].LastUsedCase != "CASE-3" {
		t.Fatalf("hit_count/last_used not updated: %+v", rows[0])
	}

	// 6. Signature drift (different model_id) hides the rows → invalidation.
	stale, _ := m.ListSkillSQL(ctx, skill, "uev-aaaa", "claude-sonnet-4-6")
	if len(stale) != 0 {
		t.Fatalf("rows under a different model signature must be excluded, got %d", len(stale))
	}
}
