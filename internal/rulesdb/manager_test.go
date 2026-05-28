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
