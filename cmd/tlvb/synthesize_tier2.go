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
	gapMinutes := fs.Int("cluster-gap-minutes", 30, "cluster gap threshold")
	windowMinutes := fs.Int("timeline-window-minutes", 5,
		"±N min raw timeline window around each cluster")
	maxRowsPerCluster := fs.Int("max-rows-per-cluster", 300,
		"raw timeline rows per cluster (stratified across artifacts)")
	timeoutMinutes := fs.Int("timeout-minutes", 5, "per-LLM-call timeout in minutes")
	dryRun := fs.Bool("dry-run", false, "skip LLM calls")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *findingsBase == "" {
		*findingsBase = filepath.Join("outputs", "cases", caseID, "findings")
	}
	if *outPath == "" {
		*outPath = filepath.Join("outputs", "cases", caseID, "synthesis.json")
	}

	cfg := tier2.Config{
		CaseID:            caseID,
		FindingsBaseDir:   *findingsBase,
		OutputPath:        *outPath,
		DBPath:            *dbPath,
		SkillsDir:         *skillsDir,
		SkillName:         *skillName,
		Model:             *model,
		ClusterGap:        time.Duration(*gapMinutes) * time.Minute,
		TimelineWindow:    time.Duration(*windowMinutes) * time.Minute,
		MaxRowsPerCluster: *maxRowsPerCluster,
		PerClusterTimeout: time.Duration(*timeoutMinutes) * time.Minute,
		DryRun:            *dryRun,
		ProgressFn: func(ev tier2.Event) {
			fmt.Fprintf(os.Stderr, "[%s] %s\n", ev.Phase, ev.Message)
		},
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
	if rep.OutputPath != "" {
		fmt.Printf("  output:            %s\n", rep.OutputPath)
	}
	return nil
}
