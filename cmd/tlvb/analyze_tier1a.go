package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tlvb/tlvb/internal/casedb"
	"github.com/tlvb/tlvb/internal/rulesdb"
	"github.com/tlvb/tlvb/internal/tier1a"
)

// runAnalyzeTier1A is the CLI entry point for `tlvb analyze CASE_ID --tier 1a`.
// Executes the cached SQL in rules.duckdb against unified_events for the
// given case and writes findings to findings/by-rule/<source>/<rule_id>.json.
func runAnalyzeTier1A(caseID string, args []string) error {
	fs := flag.NewFlagSet("analyze --tier 1a", flag.ContinueOnError)
	dbPath := fs.String("db", "outputs/cases.duckdb", "case DuckDB path")
	rulesDBPath := fs.String("rules-db", "outputs/rules.duckdb", "rule SQL cache DB path")
	outDir := fs.String("out-dir", "",
		"findings output dir (default: outputs/cases/<id>/findings/by-rule)")
	source := fs.String("source", "",
		"restrict to one source: sigma | hayabusa | stix (default: all)")
	ruleID := fs.String("rule", "",
		"run exactly one rule by rule_id (debugging)")
	maxEvidence := fs.Int("max-evidence", 100,
		"cap evidence rows retained per finding (matches beyond this still count toward MatchCount)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cdb, err := casedb.Open(*dbPath, casedb.ReadOnly)
	if err != nil {
		return fmt.Errorf("open case db: %w", err)
	}
	defer cdb.Close()
	rdb, err := rulesdb.Open(*rulesDBPath, rulesdb.ReadOnly)
	if err != nil {
		return fmt.Errorf("open rules db: %w", err)
	}
	defer rdb.Close()

	if *outDir == "" {
		*outDir = filepath.Join("outputs", "cases", caseID, "findings", "by-rule")
	}

	cfg := tier1a.Config{
		CaseID:       caseID,
		RulesDB:      rdb,
		CaseDB:       cdb,
		FindingsDir:  *outDir,
		SourceFilter: *source,
		RuleIDFilter: *ruleID,
		MaxEvidence:  *maxEvidence,
		ProgressFn:   tier1aProgress(),
	}
	fmt.Fprintf(os.Stderr, "tier 1A — case=%s rules_db=%s out=%s\n",
		caseID, *rulesDBPath, *outDir)
	rep, err := tier1a.Run(context.Background(), cfg)
	if err != nil {
		return err
	}
	printTier1AReport(rep)
	return nil
}

func tier1aProgress() func(tier1a.Event) {
	last := 0
	return func(ev tier1a.Event) {
		switch ev.State {
		case "matched":
			// always print matches — they're rare and interesting
			fmt.Fprintf(os.Stderr, "[%d/%d] %s/%s -> MATCH (%d evidence rows)\n",
				ev.Index, ev.Total, ev.RuleSource, ev.RuleID, ev.MatchCount)
		case "error":
			fmt.Fprintf(os.Stderr, "[%d/%d] %s/%s -> ERROR: %s\n",
				ev.Index, ev.Total, ev.RuleSource, ev.RuleID,
				truncateStr(ev.Error, 200))
		default:
			// progress ticker every 50 rules
			if ev.Index-last >= 50 {
				last = ev.Index
				fmt.Fprintf(os.Stderr, "[%d/%d] ...\n", ev.Index, ev.Total)
			}
		}
	}
}

func printTier1AReport(rep *tier1a.Report) {
	fmt.Printf("\nTier 1A summary — case=%s\n", rep.CaseID)
	fmt.Printf("  total rules:        %d\n", rep.TotalRules)
	fmt.Printf("  matched:            %d  (findings written)\n", rep.Matched)
	fmt.Printf("  no match:           %d\n", rep.NoMatch)
	fmt.Printf("  skipped (artifact): %d\n", rep.SkippedArtifact)
	if rep.SkippedFilter > 0 {
		fmt.Printf("  skipped (filter):   %d\n", rep.SkippedFilter)
	}
	fmt.Printf("  errors:             %d\n", rep.Errors)
	fmt.Printf("  duration:           %.2fs\n", rep.DurationS)

	if len(rep.Findings) == 0 {
		return
	}
	fmt.Printf("\nFindings:\n")
	for _, f := range rep.Findings {
		mark := ""
		if f.Truncated {
			mark = " (evidence truncated)"
		}
		fmt.Printf("  [%s] %s/%s  %d evidence%s\n",
			f.Level, f.RuleSource, truncateStr(f.RuleID, 40), f.MatchCount, mark)
		if f.Title != "" {
			fmt.Printf("       %s\n", truncateStr(f.Title, 100))
		}
	}
}

