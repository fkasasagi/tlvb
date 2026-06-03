package rulesdb

import (
	"context"
	"path/filepath"
	"testing"
	"time"
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

func TestSeedBuilt(t *testing.T) {
	dir := t.TempDir()
	m, err := Open(filepath.Join(dir, "rules.duckdb"), ReadWrite)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer m.Close()
	ctx := context.Background()

	snap := CacheRow{
		RuleID: "seed-1", RuleSource: "sigma", RuleSHA256: "sha-v1",
		SchemaVersion: "uev-aaaa", ModelID: "claude-sonnet-4-6",
		SQL:                "SELECT audit_id FROM unified_events WHERE case_id = ?",
		PrefilterArtifacts: "evtx", RuleMeta: `{"level":"high"}`,
	}

	// 1. Into an empty cache the snapshot is inserted as 'built'.
	if act, err := m.SeedBuilt(ctx, snap, false); err != nil || act != "inserted" {
		t.Fatalf("first seed: act=%q err=%v", act, err)
	}
	if got, _ := m.GetBuiltSQL(ctx, "seed-1", "sigma"); got != snap.SQL {
		t.Fatalf("seeded SQL mismatch: %q", got)
	}

	// 2. Degrade-guard: a row already present is preserved untouched in the
	//    default (overwrite=false) mode, even when the snapshot differs.
	changed := snap
	changed.SQL = "SELECT 1 -- snapshot would clobber this"
	changed.ModelID = "claude-opus-4-8"
	if act, err := m.SeedBuilt(ctx, changed, false); err != nil || act != "skipped" {
		t.Fatalf("expected existing row skipped, got act=%q err=%v", act, err)
	}
	if got, _ := m.GetBuiltSQL(ctx, "seed-1", "sigma"); got != snap.SQL {
		t.Fatalf("default seed degraded an existing row: %q", got)
	}

	// 3. A locally-built row (via the normal build path) is likewise preserved.
	other := CacheRow{
		RuleID: "seed-2", RuleSource: "sigma", RuleSHA256: "sha-local",
		SchemaVersion: "uev-aaaa", ModelID: "local",
	}
	if err := m.UpsertPending(ctx, other); err != nil {
		t.Fatalf("upsert pending: %v", err)
	}
	if err := m.MarkBuilt(ctx, "seed-2", "sigma", "SELECT audit_id FROM unified_events WHERE case_id = ? AND artifact_id='amcache'", "amcache"); err != nil {
		t.Fatalf("mark built: %v", err)
	}
	snap2 := snap
	snap2.RuleID = "seed-2"
	snap2.SQL = "SELECT 0 -- snapshot"
	if act, _ := m.SeedBuilt(ctx, snap2, false); act != "skipped" {
		t.Fatalf("locally-built row must be preserved, got %q", act)
	}
	if got, _ := m.GetBuiltSQL(ctx, "seed-2", "sigma"); got == snap2.SQL {
		t.Fatal("default seed overwrote a locally-built row")
	}

	// 4. --overwrite replaces the existing row with the snapshot.
	if act, err := m.SeedBuilt(ctx, changed, true); err != nil || act != "updated" {
		t.Fatalf("overwrite seed: act=%q err=%v", act, err)
	}
	if got, _ := m.GetBuiltSQL(ctx, "seed-1", "sigma"); got != changed.SQL {
		t.Fatalf("overwrite did not apply snapshot SQL: %q", got)
	}

	// 5. ReadOnly handle refuses to seed.
	ro, err := Open(filepath.Join(dir, "rules.duckdb"), ReadOnly)
	if err != nil {
		t.Fatalf("open ro: %v", err)
	}
	defer ro.Close()
	if _, err := ro.SeedBuilt(ctx, snap, true); err == nil {
		t.Fatal("read-only SeedBuilt should error")
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

func TestPruneSkillCandidates(t *testing.T) {
	dir := t.TempDir()
	m, err := Open(filepath.Join(dir, "rules.duckdb"), ReadWrite)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer m.Close()
	ctx := context.Background()

	mk := func(sqlText, intent string) SkillSQLRow {
		return SkillSQLRow{
			Skill: "anomaly_hunter", SQL: sqlText, Intent: intent,
			OriginCase: "C1", SchemaVersion: "v1", ModelID: "m1",
		}
	}
	c1 := "SELECT audit_id, ts_utc, artifact_id FROM unified_events WHERE case_id = ? AND artifact_id = 'lnk' LIMIT 10"
	c2 := "SELECT audit_id, ts_utc, artifact_id FROM unified_events WHERE case_id = ? AND artifact_id = 'registry' LIMIT 10"
	if _, err := m.UpsertSkillCandidate(ctx, mk(c1, "lnk")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpsertSkillCandidate(ctx, mk(c2, "registry")); err != nil {
		t.Fatal(err)
	}
	// Promote one → canonical (hit_count=1); it must survive pruning forever.
	if err := m.PromoteSkillSQL(ctx, "anomaly_hunter", SkillSQLHash(c1), "C2"); err != nil {
		t.Fatal(err)
	}

	// A past cutoff prunes nothing — both rows were generated "now".
	past := time.Now().Add(-1 * time.Hour)
	if victims, _ := m.ListPrunableSkillCandidates(ctx, past); len(victims) != 0 {
		t.Fatalf("past cutoff should prune nothing, got %d", len(victims))
	}

	// A future cutoff makes the lone candidate (c2) prunable; the canonical
	// (c1) is excluded.
	future := time.Now().Add(1 * time.Hour)
	victims, err := m.ListPrunableSkillCandidates(ctx, future)
	if err != nil {
		t.Fatalf("list prunable: %v", err)
	}
	if len(victims) != 1 || victims[0].Intent != "registry" {
		t.Fatalf("expected only the unpromoted candidate prunable, got %+v", victims)
	}

	n, err := m.PruneSkillCandidates(ctx, future)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 pruned, got %d", n)
	}
	counts, _ := m.CountSkillByState(ctx)
	if counts[SkillCanonical] != 1 || counts[SkillCandidate] != 0 {
		t.Fatalf("after prune expected 1 canonical / 0 candidate, got %v", counts)
	}
}
