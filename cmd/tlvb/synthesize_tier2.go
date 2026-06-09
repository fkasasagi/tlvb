package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tlvb/tlvb/internal/tier2"
)

func runSynthesizeTier2(caseID string, args []string) error {
	fs := flag.NewFlagSet("synthesize --tier 2", flag.ContinueOnError)
	dbPath := fs.String("db", "outputs/cases.duckdb", "case DuckDB path")
	findingsBase := fs.String("findings-dir", "",
		"findings base dir (default: outputs/cases/<id>/findings)")
	outPath := fs.String("out", "",
		"synthesis.json output path (default: outputs/cases/<id>/synthesis.json)")
	skillName := fs.String("skill", "timeline_review",
		"skill markdown basename under skills/")
	skillsDir := fs.String("skills-dir", "skills", "skill markdown root")
	model := fs.String("model", "", "model id (empty = let claude CLI default)")
	language := fs.String("language", "ja", "output language for narratives / summary: ja | en")
	gapMinutes := fs.Int("cluster-gap-minutes", 30, "cluster gap threshold")
	windowMinutes := fs.Int("timeline-window-minutes", 5,
		"±N min raw timeline window around each cluster")
	maxRowsPerCluster := fs.Int("max-rows-per-cluster", 300,
		"raw timeline rows per cluster (stratified across artifacts)")
	timeoutMinutes := fs.Int("timeout-minutes", 5, "per-LLM-call timeout in minutes")
	activeSearch := fs.Bool("active-search", false,
		"enable hypothesis-driven SQL pass per cluster (LLM proposes SQL to answer open_questions, executes against unified_events, then writes an addendum to the narrative)")
	maxSelfCorrect := fs.Int("max-self-correct", 2,
		"active-search SQL self-correction rounds when a proposed query fails or returns all-NULL (0 = disable; the agent feeds the failure back to the LLM and re-runs the revised SQL)")
	demoInjectFault := fs.Bool("demo-inject-sql-fault", false,
		"DEMO ONLY: deliberately corrupt the first active-search SQL per cluster (references a non-existent column) so the self-correction loop visibly fires; the agent detects the DB error and recovers")
	dryRun := fs.Bool("dry-run", false, "skip LLM calls")
	overallOnly := fs.Bool("overall-only", false,
		"regenerate ONLY the case-wide executive summary (overall_story) in an existing synthesis.json and write it back in place — cheap refresh after a prompt/timeout change, no re-clustering / per-cluster / active-search")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *findingsBase == "" {
		*findingsBase = filepath.Join("outputs", "cases", caseID, "findings")
	}
	if *outPath == "" {
		*outPath = filepath.Join("outputs", "cases", caseID, "synthesis.json")
	}

	// CLI semantics: 0 (or less) disables self-correction. tier2 treats a zero
	// value as "use default" and a negative value as "disabled", so map here.
	msc := *maxSelfCorrect
	if msc <= 0 {
		msc = -1
	}

	cfg := tier2.Config{
		CaseID:             caseID,
		FindingsBaseDir:    *findingsBase,
		OutputPath:         *outPath,
		DBPath:             *dbPath,
		SkillsDir:          *skillsDir,
		SkillName:          *skillName,
		Model:              *model,
		Language:           *language,
		ClusterGap:         time.Duration(*gapMinutes) * time.Minute,
		TimelineWindow:     time.Duration(*windowMinutes) * time.Minute,
		MaxRowsPerCluster:  *maxRowsPerCluster,
		PerClusterTimeout:  time.Duration(*timeoutMinutes) * time.Minute,
		ActiveSearch:       *activeSearch,
		MaxSelfCorrect:     msc,
		DemoInjectSQLFault: *demoInjectFault,
		DryRun:             *dryRun,
		ProgressFn: func(ev tier2.Event) {
			fmt.Fprintf(os.Stderr, "[%s] %s\n", ev.Phase, ev.Message)
		},
	}
	if *overallOnly {
		fmt.Fprintf(os.Stderr, "tier 2 (overall-only) — case=%s out=%s\n", caseID, *outPath)
		r, err := tier2.RegenerateOverall(context.Background(), cfg)
		if err != nil {
			return err
		}
		fmt.Printf("\nTier 2 overall regenerated — case=%s\n", caseID)
		fmt.Printf("  output:            %s\n", r.OutputPath)
		fmt.Printf("  summary:           %d chars / %d paragraphs\n", r.Chars, r.Paragraphs)
		fmt.Printf("  llm calls:         %d  (%.1fs)\n", r.LLMCalls, r.Duration)
		if r.Fallback {
			fmt.Printf("  ⚠ fallback:        LLM failed; deterministic stitch written (re-run recommended)\n")
		}
		return nil
	}

	fmt.Fprintf(os.Stderr, "tier 2 (Timeline Analysis) — case=%s findings=%s out=%s\n",
		caseID, *findingsBase, *outPath)
	rep, err := tier2.Run(context.Background(), cfg)
	if err != nil {
		return err
	}
	fmt.Printf("\nTier 2 summary — case=%s\n", rep.CaseID)
	fmt.Printf("  total findings:    %d\n", rep.TotalFindings)
	fmt.Printf("  clusters:          %d\n", rep.ClusterCount)
	fmt.Printf("  clusters analysed: %d\n", rep.ClustersAnalyzed)
	fmt.Printf("  duration:          %.1fs\n", rep.Duration)
	fmt.Printf("  llm calls:         %d\n", rep.LLMCalls)
	fmt.Printf("  tokens:            in %d / cache_read %d / out %d  (cost $%.4f)\n",
		rep.InputTokens, rep.CacheReadTokens, rep.OutputTokens, rep.TotalCostUSD)
	if *activeSearch {
		fmt.Printf("  active-search:     %d attempted / %d ok / %d self-corrected (%d correction rounds)\n",
			rep.ActiveSQLAttempted, rep.ActiveSQLSucceeded,
			rep.ActiveSQLSelfCorrected, rep.ActiveSQLCorrectionRounds)
	}
	if rep.OutputPath != "" {
		fmt.Printf("  output:            %s\n", rep.OutputPath)
	}
	return nil
}
