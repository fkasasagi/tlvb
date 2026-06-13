package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tlvb/tlvb/internal/common"
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
	activeSearch := fs.Bool("active-search", true,
		"hypothesis-driven SQL pass per cluster (LLM proposes SQL to answer open_questions, executes against unified_events, self-corrects/re-sequences, then writes an addendum). ON by default — Tier 2 is already LLM-driven; pass --active-search=false to disable for a cheaper/faster run")
	maxSelfCorrect := fs.Int("max-self-correct", 2,
		"active-search SQL self-correction rounds when a proposed query fails or returns all-NULL (0 = disable; the agent feeds the failure back to the LLM and re-runs the revised SQL)")
	maxReframe := fs.Int("max-reframe", 1,
		"active-search investigative-pivot rounds when a query runs cleanly but returns 0 rows (0 = disable; the agent judges true-negative vs wrong-angle and re-issues from a different artifact/field/hypothesis)")
	reproduceLLMFault := fs.Bool("reproduce-llm-fault", false,
		"FILMING AID (never default): rewrite the first active-search SQL per cluster to reproduce the most common real LLM mistake — treating an EventData field (TargetUserName) as a top-level column — so the natural error→self-correction arc is guaranteed to appear once on camera. Indistinguishable from a genuine miss in the audit log; disclosed in docs/DEMO_SCRIPT.md")
	dryRun := fs.Bool("dry-run", false, "skip LLM calls")
	overallOnly := fs.Bool("overall-only", false,
		"regenerate ONLY the case-wide executive summary (overall_story) in an existing synthesis.json and write it back in place — cheap refresh after a prompt/timeout change, no re-clustering / per-cluster / active-search")
	evidenceFetch := fs.Bool("evidence-fetch", true,
		"let the agent pull & read files from the disk image on demand while analysing a cluster "+
			"(requested_files → bounded follow-up pass with the file contents)")
	maxEvidenceRounds := fs.Int("max-evidence-rounds", 1,
		"max fetch+reanalyse rounds per cluster when --evidence-fetch is on")
	maxEvidenceFiles := fs.Int("max-evidence-files", 8,
		"max files extracted per evidence round")
	pythonBin := fs.String("python", "",
		"python interpreter for on-demand extraction (default: $TLVB_PYTHON, then ./.venv/bin/python3, then python3)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pyBin := *pythonBin
	if pyBin == "" {
		pyBin = common.ResolvePython()
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
	// Same mapping for the reframe (investigative-pivot) budget.
	mrf := *maxReframe
	if mrf <= 0 {
		mrf = -1
	}

	cfg := tier2.Config{
		CaseID:            caseID,
		FindingsBaseDir:   *findingsBase,
		OutputPath:        *outPath,
		DBPath:            *dbPath,
		SkillsDir:         *skillsDir,
		SkillName:         *skillName,
		Model:             *model,
		Language:          *language,
		ClusterGap:        time.Duration(*gapMinutes) * time.Minute,
		TimelineWindow:    time.Duration(*windowMinutes) * time.Minute,
		MaxRowsPerCluster: *maxRowsPerCluster,
		PerClusterTimeout: time.Duration(*timeoutMinutes) * time.Minute,
		ActiveSearch:      *activeSearch,
		MaxSelfCorrect:    msc,
		MaxReframe:        mrf,
		ReproduceLLMFault: *reproduceLLMFault,
		DryRun:            *dryRun,
		EvidenceFetch:     *evidenceFetch,
		MaxEvidenceRounds: *maxEvidenceRounds,
		MaxEvidenceFiles:  *maxEvidenceFiles,
		PythonBin:         pyBin,
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
		fmt.Printf("  reframe (pivots):  %d re-sequenced / %d honest-negative (0-row)\n",
			rep.ActiveSQLReframed, rep.ActiveSQLNoEvidence)
	}
	if rep.FilesRequested > 0 {
		fmt.Printf("  evidence fetch:    %d requested / %d extracted (%d round(s))\n",
			rep.FilesRequested, rep.FilesExtracted, rep.EvidenceRounds)
	}
	if rep.OutputPath != "" {
		fmt.Printf("  output:            %s\n", rep.OutputPath)
	}
	return nil
}
