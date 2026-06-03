package rulebuild

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tlvb/tlvb/internal/rulesdb"
	"github.com/tlvb/tlvb/internal/rulesrepo"
)

// Rates is the cost table used by Plan / Build to compute running yen totals.
// Defaults assume Claude Sonnet 4.6 at the 2026-Q2 list price ($3 / $15 / $0.30
// per million tokens for input / output / cache-read) converted at 150 yen/USD.
// Override from the CLI when prices change.
type Rates struct {
	YenPerMInputTokens     float64
	YenPerMOutputTokens    float64
	YenPerMCacheReadTokens float64
}

// DefaultRatesSonnet46 reflects 2026-Q2 list prices for claude-sonnet-4-6,
// converted at 150 yen/USD. Override via CLI when prices change.
func DefaultRatesSonnet46() Rates {
	return Rates{
		YenPerMInputTokens:     450.0,  // $3 × 150
		YenPerMOutputTokens:    2250.0, // $15 × 150
		YenPerMCacheReadTokens: 45.0,   // $0.30 × 150
	}
}

// Pipeline orchestrates the rule → SQL build over all loaders.
type Pipeline struct {
	Loaders   []rulesrepo.Loader
	Builder   Builder
	RulesDB   *rulesdb.Manager
	SchemaDoc string
	SchemaVer string
	Rates     Rates

	// Compiler (optional) runtime-validates generated SQL against an empty
	// unified_events before it is cached as "built". nil disables the gate.
	Compiler *SQLCompiler

	// Budget guards. 0 = no limit.
	MaxRules  int
	BudgetYen float64

	// Optional source filter (e.g. only "sigma"). Empty = all.
	SourceFilter string

	// Optional rule_id allowlist. Non-nil + non-empty narrows the build to
	// the specified IDs only. Used for targeted rebuild / debugging.
	RuleIDsFilter []string

	// Force re-build even if cache signature matches.
	Force bool

	// Optional progress callback (called per-rule).
	Progress func(BuildEvent)
}

// BuildEvent is delivered to Pipeline.Progress for each rule processed.
type BuildEvent struct {
	Phase      string // "loading" | "planning" | "building" | "done"
	RuleID     string
	RuleSource string
	State      string // "built" | "failed" | "skipped_cached" | "skipped_loader" | "skipped_budget"
	Index      int
	Total      int
	CostYen    float64 // running cost so far
	Error      string
}

// DryRunReport summarises what a real Build would do.
type DryRunReport struct {
	TotalRules      int
	ToBuild         int // not skipped by loader, not already cached
	AlreadyCached   int
	SkippedByLoader int // sysmon / non-windows / parse-error / etc.
	SkippedReasons  map[string]int

	// Token / cost projections (chars/4 estimate; cache-read counted at 1x
	// input for safety since cache hits depend on call order).
	EstInputTokens  int
	EstOutputTokens int
	EstCostYen      float64
}

// BuildReport is returned by Build.
type BuildReport struct {
	TotalRules    int
	Built         int
	Failed        int
	SkippedCached int
	SkippedLoader int
	StoppedReason string // "budget" | "max_rules" | "context" | "complete"
	ActualCostYen float64
}

// Plan walks all loaders, classifies each rule, and returns projected counts
// + token / cost estimates. No LLM calls.
func (p *Pipeline) Plan(ctx context.Context) (*DryRunReport, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	rep := &DryRunReport{SkippedReasons: map[string]int{}}

	rules, err := p.loadAll(ctx)
	if err != nil {
		return nil, err
	}
	rep.TotalRules = len(rules)

	// Avg LLM output for a SQL row: empirically 300-500 tokens. Use 400.
	const avgOutputTokens = 400

	for _, r := range rules {
		if r.Skip {
			rep.SkippedByLoader++
			reasonKey := skipReasonBucket(r.SkipReason)
			rep.SkippedReasons[reasonKey]++
			continue
		}
		if !p.Force && p.isAlreadyCached(ctx, r) {
			rep.AlreadyCached++
			continue
		}
		rep.ToBuild++
		rep.EstInputTokens += EstimateTokens(p.SchemaDoc) + EstimateTokens(SystemPrompt) + EstimateTokens(BuildUserMessage(r))
		rep.EstOutputTokens += avgOutputTokens
	}
	rep.EstCostYen = float64(rep.EstInputTokens)*p.Rates.YenPerMInputTokens/1_000_000 +
		float64(rep.EstOutputTokens)*p.Rates.YenPerMOutputTokens/1_000_000
	return rep, nil
}

// Build executes the actual LLM-driven rule → SQL conversion. Resumable:
// re-running picks up where the previous run left off (cached rows skipped,
// failed rows retried).
func (p *Pipeline) Build(ctx context.Context) (*BuildReport, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	rep := &BuildReport{}

	rules, err := p.loadAll(ctx)
	if err != nil {
		return nil, err
	}
	rep.TotalRules = len(rules)

	processed := 0
	for i, r := range rules {
		if ctx.Err() != nil {
			rep.StoppedReason = "context"
			return rep, ctx.Err()
		}
		if r.Skip {
			// Newly-classified-as-skip rule: if it has a stale cache row from
			// a previous loader version (e.g. when the new build run added a
			// proxy/firewall/database/webserver category to the skip set),
			// drop it so status views aren't littered with failed retries
			// for rules we'll never attempt again.
			if deleted, _ := p.RulesDB.Delete(ctx, r.RuleID, r.RuleSource); deleted {
				p.emit(BuildEvent{Phase: "building", RuleID: r.RuleID, RuleSource: r.RuleSource,
					State: "skipped_loader_purged", Index: i + 1, Total: len(rules), CostYen: rep.ActualCostYen})
			}
			rep.SkippedLoader++
			p.emit(BuildEvent{Phase: "building", RuleID: r.RuleID, RuleSource: r.RuleSource,
				State: "skipped_loader", Index: i + 1, Total: len(rules), CostYen: rep.ActualCostYen})
			continue
		}

		// Cache check via UpsertPending: same signature + state=built leaves
		// the row alone; mismatched signature resets to pending.
		meta, _ := json.Marshal(map[string]any{
			"title":            r.Title,
			"level":            r.Level,
			"mitre_techniques": r.MITRETechniques,
			"mitre_tactics":    r.MITRETactics,
			"source_path":      r.SourcePath,
		})
		row := rulesdb.CacheRow{
			RuleID:        r.RuleID,
			RuleSource:    r.RuleSource,
			RuleSHA256:    r.RuleSHA256,
			SchemaVersion: p.SchemaVer,
			ModelID:       p.Builder.ModelID(),
			RuleMeta:      string(meta),
		}
		if err := p.RulesDB.UpsertPending(ctx, row); err != nil {
			return rep, fmt.Errorf("upsert pending: %w", err)
		}

		// If still 'built' after upsert (signature matched), skip the LLM call.
		if !p.Force {
			if existing, err := p.RulesDB.GetBuiltSQL(ctx, r.RuleID, r.RuleSource); err == nil && existing != "" {
				rep.SkippedCached++
				p.emit(BuildEvent{Phase: "building", RuleID: r.RuleID, RuleSource: r.RuleSource,
					State: "skipped_cached", Index: i + 1, Total: len(rules), CostYen: rep.ActualCostYen})
				continue
			}
		}

		// Budget / count guards check BEFORE the call (so the running cost
		// includes the previous call's actuals).
		if p.BudgetYen > 0 && rep.ActualCostYen >= p.BudgetYen {
			rep.StoppedReason = "budget"
			break
		}
		if p.MaxRules > 0 && processed >= p.MaxRules {
			rep.StoppedReason = "max_rules"
			break
		}

		// Real LLM call.
		built, err := p.Builder.BuildSQL(ctx, r, p.SchemaDoc)
		if err != nil {
			_ = p.RulesDB.MarkFailed(ctx, r.RuleID, r.RuleSource, err.Error())
			rep.Failed++
			p.emit(BuildEvent{Phase: "building", RuleID: r.RuleID, RuleSource: r.RuleSource,
				State: "failed", Index: i + 1, Total: len(rules), CostYen: rep.ActualCostYen, Error: err.Error()})
			processed++
			continue
		}

		// Even with no error, the LLM may have returned empty SQL ("not
		// expressible") — treat as a clean failure that won't be retried.
		if built.SQL == "" {
			_ = p.RulesDB.MarkFailed(ctx, r.RuleID, r.RuleSource,
				"LLM returned empty SQL: "+built.Notes)
			rep.Failed++
			p.addCost(rep, built)
			p.emit(BuildEvent{Phase: "building", RuleID: r.RuleID, RuleSource: r.RuleSource,
				State: "failed", Index: i + 1, Total: len(rules), CostYen: rep.ActualCostYen,
				Error: "empty SQL"})
			processed++
			continue
		}

		// Runtime compile-check: reject SQL that parses but won't execute
		// against unified_events (unknown function / bad regex / etc.) so it
		// never gets cached as "built" then skipped at Tier 1A runtime (#6).
		if cerr := p.Compiler.Check(built.SQL); cerr != nil {
			_ = p.RulesDB.MarkFailed(ctx, r.RuleID, r.RuleSource, "SQL compile-check: "+cerr.Error())
			rep.Failed++
			p.addCost(rep, built)
			p.emit(BuildEvent{Phase: "building", RuleID: r.RuleID, RuleSource: r.RuleSource,
				State: "failed", Index: i + 1, Total: len(rules), CostYen: rep.ActualCostYen,
				Error: "compile-check: " + truncate(cerr.Error(), 80)})
			processed++
			continue
		}

		// Success.
		prefilter := joinArtifacts(built.PrefilterArtifacts, r.PrefilterArtifacts)
		if err := p.RulesDB.MarkBuilt(ctx, r.RuleID, r.RuleSource, built.SQL, prefilter); err != nil {
			return rep, fmt.Errorf("mark built: %w", err)
		}
		rep.Built++
		p.addCost(rep, built)
		p.emit(BuildEvent{Phase: "building", RuleID: r.RuleID, RuleSource: r.RuleSource,
			State: "built", Index: i + 1, Total: len(rules), CostYen: rep.ActualCostYen})
		processed++
	}

	if rep.StoppedReason == "" {
		rep.StoppedReason = "complete"
	}
	p.emit(BuildEvent{Phase: "done", Total: rep.TotalRules, CostYen: rep.ActualCostYen})
	return rep, nil
}

func (p *Pipeline) validate() error {
	if len(p.Loaders) == 0 {
		return fmt.Errorf("pipeline: no loaders configured")
	}
	if p.RulesDB == nil {
		return fmt.Errorf("pipeline: RulesDB is nil")
	}
	if p.Builder == nil {
		return fmt.Errorf("pipeline: Builder is nil")
	}
	if p.SchemaVer == "" {
		return fmt.Errorf("pipeline: SchemaVer is empty")
	}
	return nil
}

func (p *Pipeline) loadAll(ctx context.Context) ([]rulesrepo.RawRule, error) {
	var all []rulesrepo.RawRule
	for _, l := range p.Loaders {
		if p.SourceFilter != "" && l.Source() != p.SourceFilter {
			continue
		}
		rules, err := l.LoadAll(ctx)
		if err != nil {
			return nil, fmt.Errorf("loader %s: %w", l.Source(), err)
		}
		all = append(all, rules...)
	}
	if len(p.RuleIDsFilter) > 0 {
		allow := map[string]bool{}
		for _, id := range p.RuleIDsFilter {
			allow[id] = true
		}
		filtered := make([]rulesrepo.RawRule, 0, len(p.RuleIDsFilter))
		for _, r := range all {
			if allow[r.RuleID] {
				filtered = append(filtered, r)
			}
		}
		all = filtered
	}
	return all, nil
}

func (p *Pipeline) isAlreadyCached(ctx context.Context, r rulesrepo.RawRule) bool {
	rows, err := p.RulesDB.ListAll(ctx, r.RuleSource, rulesdb.StateBuilt)
	if err != nil {
		return false
	}
	for _, row := range rows {
		if row.RuleID == r.RuleID &&
			row.RuleSHA256 == r.RuleSHA256 &&
			row.SchemaVersion == p.SchemaVer &&
			row.ModelID == p.Builder.ModelID() {
			return true
		}
	}
	return false
}

func (p *Pipeline) addCost(rep *BuildReport, built *BuiltSQL) {
	// Anthropic Usage already separates the three token buckets:
	//   input_tokens             — uncached input (full rate)
	//   cache_read_input_tokens  — cache hit  (discounted rate)
	//   output_tokens            — completion (output rate)
	// Earlier we double-subtracted CacheReadTokens from InputTokens, which
	// pushed running cost negative on cache-heavy runs and disabled the
	// budget guard.
	in := float64(built.InputTokens) / 1_000_000 * p.Rates.YenPerMInputTokens
	cache := float64(built.CacheReadTokens) / 1_000_000 * p.Rates.YenPerMCacheReadTokens
	out := float64(built.OutputTokens) / 1_000_000 * p.Rates.YenPerMOutputTokens
	rep.ActualCostYen += in + cache + out
}

func (p *Pipeline) emit(ev BuildEvent) {
	if p.Progress != nil {
		p.Progress(ev)
	}
}

// joinArtifacts merges the LLM-narrowed prefilter list with the loader's
// default. If the LLM provided a non-empty list, prefer it; else fall back to
// the loader's. Stored as comma-separated TEXT in rule_sql_cache.
func joinArtifacts(llmList, loaderList []string) string {
	pick := llmList
	if len(pick) == 0 {
		pick = loaderList
	}
	return strings.Join(pick, ",")
}

// skipReasonBucket categorises SkipReason strings into broad buckets for the
// Plan report (so the operator sees "Sysmon: 1857" instead of 1857 unique
// reason strings).
func skipReasonBucket(reason string) string {
	r := strings.ToLower(reason)
	switch {
	case strings.Contains(r, "sysmon"):
		return "sysmon"
	case strings.Contains(r, "non-windows"),
		strings.Contains(r, "not a windows"):
		return "non_windows"
	case strings.Contains(r, "revoked"):
		return "revoked"
	case strings.Contains(r, "deprecated"):
		return "deprecated"
	case strings.Contains(r, "parse error"):
		return "parse_error"
	default:
		return "other"
	}
}
