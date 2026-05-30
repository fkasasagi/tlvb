package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/tlvb/tlvb/internal/casedb"
	"github.com/tlvb/tlvb/internal/rulebuild"
	"github.com/tlvb/tlvb/internal/rulesdb"
	"github.com/tlvb/tlvb/internal/rulesrepo"
)

// runRules dispatches `tlvb rules ...` subcommands.
func runRules(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: tlvb rules build|list ...")
	}
	switch args[0] {
	case "build":
		return runRulesBuild(args[1:])
	case "list":
		return runRulesList(args[1:])
	default:
		return fmt.Errorf("unknown rules subcommand %q (want build|list)", args[0])
	}
}

func runRulesBuild(args []string) error {
	fs := flag.NewFlagSet("rules build", flag.ContinueOnError)
	rulesRoot := fs.String("rules-root", "rules",
		"top-level rules dir (submodules live under here)")
	rulesDBPath := fs.String("rules-db", "outputs/rules.duckdb",
		"path to the rule SQL cache DB")
	source := fs.String("source", "",
		"restrict to one loader: sigma | hayabusa | stix (default: all)")
	dryRun := fs.Bool("dry-run", false,
		"do not call the LLM; just plan + cost estimate")
	maxRules := fs.Int("max-rules", 0,
		"stop after N successfully-attempted rules (0 = no limit)")
	budgetYen := fs.Float64("budget-yen", 0,
		"stop when running cost exceeds this many yen (0 = no limit)")
	force := fs.Bool("force", false,
		"rebuild rules even when cache signature matches")
	ruleIDsCSV := fs.String("rule-ids", "",
		"comma-separated rule_ids to build (debugging / targeted rebuild). "+
			"Other rules are filtered out entirely.")
	model := fs.String("model", "claude-sonnet-4-6",
		"model id used for SQL generation (engine-specific)")
	engine := fs.String("engine", "claude-code",
		"build engine: claude-code (uses local `claude` CLI, no API key needed) | anthropic-api")
	rateIn := fs.Float64("rate-yen-per-m-input", 450.0,
		"cost rate: yen per 1M input tokens (Sonnet 4.6 list price default)")
	rateOut := fs.Float64("rate-yen-per-m-output", 2250.0,
		"cost rate: yen per 1M output tokens")
	rateCache := fs.Float64("rate-yen-per-m-cache-read", 45.0,
		"cost rate: yen per 1M cache-read tokens")
	if err := fs.Parse(args); err != nil {
		return err
	}

	loaders, err := buildLoaders(*rulesRoot, *source)
	if err != nil {
		return err
	}
	if len(loaders) == 0 {
		return fmt.Errorf("no loaders available under %s (did you check out the submodules?)", *rulesRoot)
	}

	db, err := rulesdb.Open(*rulesDBPath, rulesdb.ReadWrite)
	if err != nil {
		return fmt.Errorf("open rules db: %w", err)
	}
	defer db.Close()

	var builder rulebuild.Builder
	switch *engine {
	case "anthropic-api":
		apiKey := os.Getenv("ANTHROPIC_API_KEY")
		if !*dryRun && apiKey == "" {
			return fmt.Errorf("--engine anthropic-api requires ANTHROPIC_API_KEY (use --dry-run to plan, or --engine claude-code)")
		}
		builder = rulebuild.NewAnthropicBuilder(apiKey, *model, casedb.SchemaDoc())
	case "claude-code":
		if !*dryRun {
			if _, err := exec.LookPath("claude"); err != nil {
				return fmt.Errorf("--engine claude-code requires the `claude` binary on PATH (install Claude Code CLI, or use --engine anthropic-api)")
			}
		}
		builder = rulebuild.NewClaudeCodeBuilder(*model, casedb.SchemaDoc())
	default:
		return fmt.Errorf("unknown --engine %q (want claude-code | anthropic-api)", *engine)
	}
	pipeline := &rulebuild.Pipeline{
		Loaders:   loaders,
		Builder:   builder,
		RulesDB:   db,
		SchemaDoc: casedb.SchemaDoc(),
		SchemaVer: casedb.SchemaVersion(),
		Rates: rulebuild.Rates{
			YenPerMInputTokens:     *rateIn,
			YenPerMOutputTokens:    *rateOut,
			YenPerMCacheReadTokens: *rateCache,
		},
		MaxRules:     *maxRules,
		BudgetYen:    *budgetYen,
		SourceFilter: *source,
		Force:        *force,
		Progress:     progressPrinter(),
		RuleIDsFilter: splitCSV(*ruleIDsCSV),
	}

	ctx := context.Background()

	if *dryRun {
		rep, err := pipeline.Plan(ctx)
		if err != nil {
			return err
		}
		printDryRun(rep, *model, casedb.SchemaVersion())
		return nil
	}

	fmt.Fprintf(os.Stderr, "tlvb rules build — model=%s schema_version=%s\n",
		*model, casedb.SchemaVersion())
	rep, err := pipeline.Build(ctx)
	if err != nil {
		return err
	}
	printBuildReport(rep)
	return nil
}

func runRulesList(args []string) error {
	fs := flag.NewFlagSet("rules list", flag.ContinueOnError)
	rulesDBPath := fs.String("rules-db", "outputs/rules.duckdb",
		"path to the rule SQL cache DB")
	source := fs.String("source", "",
		"restrict to one source: sigma | hayabusa | stix (default: all)")
	state := fs.String("state", "",
		"filter by state: pending | built | failed (default: all)")
	showSQL := fs.Bool("show-sql", false,
		"print the cached SQL body for each row (long output)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	db, err := rulesdb.Open(*rulesDBPath, rulesdb.ReadOnly)
	if err != nil {
		return fmt.Errorf("open rules db (read-only): %w", err)
	}
	defer db.Close()

	ctx := context.Background()
	rows, err := db.ListAll(ctx, *source, rulesdb.CacheState(*state))
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}

	counts, _ := db.CountByState(ctx)
	fmt.Printf("Rule SQL cache  (sigma=%d hayabusa=%d stix=%d custom=%d)\n",
		countBySource(rows, "sigma"), countBySource(rows, "hayabusa"),
		countBySource(rows, "stix"), countBySource(rows, "custom"))
	fmt.Printf("States: built=%d pending=%d failed=%d\n\n",
		counts[rulesdb.StateBuilt], counts[rulesdb.StatePending], counts[rulesdb.StateFailed])

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SOURCE\tRULE_ID\tSTATE\tMODEL\tGENERATED\tPREFILTER\tERROR")
	for _, r := range rows {
		ts := "-"
		if r.GeneratedAt != nil {
			ts = r.GeneratedAt.UTC().Format(time.RFC3339)
		}
		errMsg := truncateStr(r.ErrorMessage, 60)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.RuleSource, truncateStr(r.RuleID, 40), r.State, r.ModelID, ts,
			r.PrefilterArtifacts, errMsg)
	}
	w.Flush()

	if *showSQL {
		fmt.Println()
		for _, r := range rows {
			if r.SQL == "" {
				continue
			}
			fmt.Printf("# %s/%s\n%s\n\n", r.RuleSource, r.RuleID, r.SQL)
		}
	}
	return nil
}

// buildLoaders constructs the standard Sigma + Hayabusa + STIX loader set,
// optionally narrowed by --source.
func buildLoaders(rulesRoot, sourceFilter string) ([]rulesrepo.Loader, error) {
	var out []rulesrepo.Loader

	addIfExists := func(path string, mk func(p string) rulesrepo.Loader, name string) {
		if sourceFilter != "" && sourceFilter != name {
			return
		}
		if _, err := os.Stat(path); err == nil {
			out = append(out, mk(path))
		}
	}

	addIfExists(filepath.Join(rulesRoot, "sigma", "upstream", "rules"),
		func(p string) rulesrepo.Loader { return rulesrepo.NewSigmaLoader(p) }, "sigma")
	addIfExists(filepath.Join(rulesRoot, "hayabusa", "upstream", "hayabusa"),
		func(p string) rulesrepo.Loader { return rulesrepo.NewHayabusaLoader(p) }, "hayabusa")
	addIfExists(filepath.Join(rulesRoot, "stix", "mitre-attack", "enterprise-attack", "attack-pattern"),
		func(p string) rulesrepo.Loader { return rulesrepo.NewSTIXLoader(p) }, "stix")
	return out, nil
}

func progressPrinter() func(rulebuild.BuildEvent) {
	lastIdx := 0
	return func(ev rulebuild.BuildEvent) {
		switch ev.Phase {
		case "done":
			fmt.Fprintf(os.Stderr, "\n[done] processed=%d total_cost=%.2f yen\n",
				ev.Total, ev.CostYen)
			return
		case "building":
			// Print every 25 to keep stderr readable; always surface signals
			// that an examiner cares about (failed + purged stale rows).
			isAlwaysOn := ev.State == "failed" || ev.State == "skipped_loader_purged"
			if ev.Index-lastIdx < 25 && !isAlwaysOn {
				return
			}
			if !isAlwaysOn {
				lastIdx = ev.Index
			}
			fmt.Fprintf(os.Stderr, "[build %d/%d] %s/%s -> %s  (cost so far: %.2f yen)",
				ev.Index, ev.Total, ev.RuleSource, ev.RuleID, ev.State, ev.CostYen)
			if ev.Error != "" {
				fmt.Fprintf(os.Stderr, "  err=%s", truncateStr(ev.Error, 80))
			}
			fmt.Fprintln(os.Stderr)
		}
	}
}

func printDryRun(rep *rulebuild.DryRunReport, model, schemaVer string) {
	fmt.Printf("Dry-run report\n")
	fmt.Printf("  model:           %s\n", model)
	fmt.Printf("  schema_version:  %s\n", schemaVer)
	fmt.Printf("  total rules:     %d\n", rep.TotalRules)
	fmt.Printf("  to build:        %d\n", rep.ToBuild)
	fmt.Printf("  already cached:  %d\n", rep.AlreadyCached)
	fmt.Printf("  skipped (loader): %d\n", rep.SkippedByLoader)
	if len(rep.SkippedReasons) > 0 {
		keys := make([]string, 0, len(rep.SkippedReasons))
		for k := range rep.SkippedReasons {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Printf("    breakdown:\n")
		for _, k := range keys {
			fmt.Printf("      %-12s %d\n", k+":", rep.SkippedReasons[k])
		}
	}
	fmt.Printf("\nProjected cost (worst case, ignores prompt-cache savings):\n")
	fmt.Printf("  est input tokens:  %s\n", commaInt(rep.EstInputTokens))
	fmt.Printf("  est output tokens: %s\n", commaInt(rep.EstOutputTokens))
	fmt.Printf("  est cost:          %.2f yen\n", rep.EstCostYen)
	fmt.Printf("\nReal cost is typically 30-60%% of the above thanks to prompt-cache hits.\n")
}

func printBuildReport(rep *rulebuild.BuildReport) {
	fmt.Printf("\nBuild summary\n")
	fmt.Printf("  stopped_reason:  %s\n", rep.StoppedReason)
	fmt.Printf("  total rules:     %d\n", rep.TotalRules)
	fmt.Printf("  built:           %d\n", rep.Built)
	fmt.Printf("  failed:          %d\n", rep.Failed)
	fmt.Printf("  skipped cached:  %d\n", rep.SkippedCached)
	fmt.Printf("  skipped loader:  %d\n", rep.SkippedLoader)
	fmt.Printf("  actual cost:     %.2f yen\n", rep.ActualCostYen)
	if rep.StoppedReason == "budget" || rep.StoppedReason == "max_rules" {
		fmt.Printf("\nNote: build did not finish.  Re-run the same command to continue.\n")
	}
}

func countBySource(rows []rulesdb.CacheRow, src string) int {
	n := 0
	for _, r := range rows {
		if r.RuleSource == src {
			n++
		}
	}
	return n
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// splitCSV trims and splits a comma-separated list. Empty input returns nil.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// commaInt formats an integer with comma thousands separators (no extra deps).
func commaInt(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	for i, ch := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(ch)
	}
	return b.String()
}
