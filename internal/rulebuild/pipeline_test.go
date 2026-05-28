package rulebuild

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/tlvb/tlvb/internal/casedb"
	"github.com/tlvb/tlvb/internal/rulesdb"
	"github.com/tlvb/tlvb/internal/rulesrepo"
)

// mockBuilder satisfies Builder without making real LLM calls.
type mockBuilder struct {
	model     string
	calls     int
	failEvery int    // fail every Nth call (0 = never)
	failWith  error
	emptyEvery int    // return empty SQL every Nth call (0 = never)
}

func (m *mockBuilder) ModelID() string { return m.model }

func (m *mockBuilder) BuildSQL(ctx context.Context, rule rulesrepo.RawRule, schemaDoc string) (*BuiltSQL, error) {
	m.calls++
	if m.failEvery > 0 && m.calls%m.failEvery == 0 {
		err := m.failWith
		if err == nil {
			err = errors.New("mock failure")
		}
		return nil, err
	}
	if m.emptyEvery > 0 && m.calls%m.emptyEvery == 0 {
		return &BuiltSQL{
			SQL:                "",
			PrefilterArtifacts: []string{},
			Notes:              "mock: not expressible",
			ModelID:            m.model,
			InputTokens:        100,
			OutputTokens:       20,
		}, nil
	}
	return &BuiltSQL{
		SQL:                fmt.Sprintf("SELECT audit_id FROM unified_events WHERE case_id = ? -- %s", rule.RuleID),
		PrefilterArtifacts: []string{"evtx"},
		Notes:              "mock",
		ModelID:            m.model,
		InputTokens:        1000,
		OutputTokens:       400,
		CacheReadTokens:    900, // simulate cache hit on system prompt
	}, nil
}

// fixtureLoader returns a fixed list of rules. Implements rulesrepo.Loader.
type fixtureLoader struct {
	src   string
	rules []rulesrepo.RawRule
}

func (f *fixtureLoader) Source() string                                  { return f.src }
func (f *fixtureLoader) LoadAll(ctx context.Context) ([]rulesrepo.RawRule, error) { return f.rules, nil }

func mkRule(id, source string, skip bool) rulesrepo.RawRule {
	r := rulesrepo.RawRule{
		RuleID:             id,
		RuleSource:         source,
		RuleSHA256:         "sha256-" + id,
		PrefilterArtifacts: []string{"evtx"},
		Title:              "test-" + id,
		Level:              "high",
		RawContent:         "title: test\nid: " + id,
	}
	if skip {
		r.Skip = true
		r.SkipReason = "Sysmon-only logsource"
		r.RequiresSysmon = true
	}
	return r
}

func setupPipeline(t *testing.T, builder Builder, rules ...rulesrepo.RawRule) (*Pipeline, *rulesdb.Manager, func()) {
	t.Helper()
	dir := t.TempDir()
	dbpath := filepath.Join(dir, "rules.duckdb")
	db, err := rulesdb.Open(dbpath, rulesdb.ReadWrite)
	if err != nil {
		t.Fatalf("rulesdb open: %v", err)
	}
	loader := &fixtureLoader{src: "sigma", rules: rules}
	p := &Pipeline{
		Loaders:   []rulesrepo.Loader{loader},
		Builder:   builder,
		RulesDB:   db,
		SchemaDoc: casedb.SchemaDoc(),
		SchemaVer: casedb.SchemaVersion(),
		Rates:     DefaultRatesSonnet46(),
	}
	cleanup := func() { _ = db.Close() }
	return p, db, cleanup
}

func TestPipelinePlan(t *testing.T) {
	mb := &mockBuilder{model: "mock-1"}
	p, db, cleanup := setupPipeline(t, mb,
		mkRule("r1", "sigma", false),
		mkRule("r2", "sigma", false),
		mkRule("r3-sysmon", "sigma", true),
	)
	defer cleanup()
	_ = db

	rep, err := p.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if rep.TotalRules != 3 {
		t.Errorf("TotalRules: got %d, want 3", rep.TotalRules)
	}
	if rep.ToBuild != 2 {
		t.Errorf("ToBuild: got %d, want 2", rep.ToBuild)
	}
	if rep.SkippedByLoader != 1 {
		t.Errorf("SkippedByLoader: got %d, want 1", rep.SkippedByLoader)
	}
	if rep.SkippedReasons["sysmon"] != 1 {
		t.Errorf("sysmon bucket: got %d, want 1", rep.SkippedReasons["sysmon"])
	}
	if rep.EstInputTokens == 0 || rep.EstOutputTokens == 0 {
		t.Errorf("estimates not populated: in=%d out=%d", rep.EstInputTokens, rep.EstOutputTokens)
	}
	if rep.EstCostYen <= 0 {
		t.Errorf("EstCostYen not populated: %f", rep.EstCostYen)
	}
	if mb.calls != 0 {
		t.Errorf("Plan must not call Builder, got %d calls", mb.calls)
	}
}

func TestPipelineBuildAndResume(t *testing.T) {
	mb := &mockBuilder{model: "mock-1"}
	p, db, cleanup := setupPipeline(t, mb,
		mkRule("r1", "sigma", false),
		mkRule("r2", "sigma", false),
		mkRule("r3-sysmon", "sigma", true),
	)
	defer cleanup()

	// First build: 2 LLM calls, 1 skip.
	rep, err := p.Build(context.Background())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if rep.Built != 2 {
		t.Errorf("Built: got %d, want 2", rep.Built)
	}
	if rep.SkippedLoader != 1 {
		t.Errorf("SkippedLoader: got %d, want 1", rep.SkippedLoader)
	}
	if mb.calls != 2 {
		t.Errorf("Builder calls: got %d, want 2", mb.calls)
	}
	if rep.ActualCostYen <= 0 {
		t.Errorf("ActualCostYen not populated: %f", rep.ActualCostYen)
	}

	// Verify SQL is actually stored.
	sqlText, err := db.GetBuiltSQL(context.Background(), "r1", "sigma")
	if err != nil || sqlText == "" {
		t.Fatalf("r1 SQL not stored: %v, %q", err, sqlText)
	}

	// Second build: nothing to do (all cached). 0 LLM calls.
	mbBefore := mb.calls
	rep2, err := p.Build(context.Background())
	if err != nil {
		t.Fatalf("Build (resume): %v", err)
	}
	if rep2.Built != 0 {
		t.Errorf("resume Built: got %d, want 0", rep2.Built)
	}
	if rep2.SkippedCached != 2 {
		t.Errorf("resume SkippedCached: got %d, want 2", rep2.SkippedCached)
	}
	if mb.calls != mbBefore {
		t.Errorf("resume should not call Builder: before=%d after=%d", mbBefore, mb.calls)
	}
}

func TestPipelineBudgetGuard(t *testing.T) {
	mb := &mockBuilder{model: "mock-1"}
	rules := []rulesrepo.RawRule{
		mkRule("r1", "sigma", false),
		mkRule("r2", "sigma", false),
		mkRule("r3", "sigma", false),
		mkRule("r4", "sigma", false),
		mkRule("r5", "sigma", false),
	}
	p, _, cleanup := setupPipeline(t, mb, rules...)
	defer cleanup()
	p.BudgetYen = 0.5 // tiny budget — should stop after 1-2 calls

	rep, err := p.Build(context.Background())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if rep.StoppedReason != "budget" {
		t.Errorf("StoppedReason: got %q, want budget", rep.StoppedReason)
	}
	if rep.Built >= 5 {
		t.Errorf("budget should stop early, got Built=%d", rep.Built)
	}
}

func TestPipelineMaxRules(t *testing.T) {
	mb := &mockBuilder{model: "mock-1"}
	p, _, cleanup := setupPipeline(t, mb,
		mkRule("r1", "sigma", false),
		mkRule("r2", "sigma", false),
		mkRule("r3", "sigma", false),
	)
	defer cleanup()
	p.MaxRules = 2

	rep, err := p.Build(context.Background())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if rep.StoppedReason != "max_rules" {
		t.Errorf("StoppedReason: got %q, want max_rules", rep.StoppedReason)
	}
	if rep.Built != 2 {
		t.Errorf("Built: got %d, want 2", rep.Built)
	}
}

func TestPipelineFailureRetried(t *testing.T) {
	mb := &mockBuilder{model: "mock-1", failEvery: 1, failWith: errors.New("simulated LLM error")}
	p, db, cleanup := setupPipeline(t, mb,
		mkRule("r1", "sigma", false),
	)
	defer cleanup()

	rep, err := p.Build(context.Background())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if rep.Failed != 1 || rep.Built != 0 {
		t.Errorf("expected 1 failed, got built=%d failed=%d", rep.Built, rep.Failed)
	}

	// Failed row should be retried on next run.
	mb.failEvery = 0 // succeed this time
	mbBefore := mb.calls
	rep2, _ := p.Build(context.Background())
	if rep2.Built != 1 {
		t.Errorf("retry Built: got %d, want 1", rep2.Built)
	}
	if mb.calls <= mbBefore {
		t.Errorf("retry should have called Builder again: before=%d after=%d", mbBefore, mb.calls)
	}
	if sql, _ := db.GetBuiltSQL(context.Background(), "r1", "sigma"); sql == "" {
		t.Error("r1 SQL should now be stored after retry")
	}
}

func TestPipelineEmptySQLTreatedAsFailure(t *testing.T) {
	mb := &mockBuilder{model: "mock-1", emptyEvery: 1}
	p, _, cleanup := setupPipeline(t, mb, mkRule("r1", "sigma", false))
	defer cleanup()

	rep, err := p.Build(context.Background())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if rep.Failed != 1 || rep.Built != 0 {
		t.Errorf("empty SQL should count as failure: built=%d failed=%d", rep.Built, rep.Failed)
	}
}

// Ensure casedb.SchemaDoc() is usable without an open DB (the constant doesn't
// touch the database).
func TestSchemaDocDoesNotRequireDB(t *testing.T) {
	if os.Getenv("CI") == "yes" {
		t.Skip()
	}
	doc := casedb.SchemaDoc()
	if doc == "" {
		t.Fatal("SchemaDoc is empty")
	}
	if casedb.SchemaVersion() == "" {
		t.Fatal("SchemaVersion is empty")
	}
}
