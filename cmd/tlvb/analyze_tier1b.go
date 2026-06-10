package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tlvb/tlvb/internal/casedb"
	"github.com/tlvb/tlvb/internal/common"
	"github.com/tlvb/tlvb/internal/tier1b"
)

// runAnalyzeTier1B is the CLI entry point for `tlvb analyze CASE_ID --tier 1b`.
// Reads prior Tier 1A findings + raw timeline, runs the skill-driven
// anomaly hunter via claude CLI, writes findings/by-skill/anomaly_hunter.json.
func runAnalyzeTier1B(caseID string, args []string) error {
	fs := flag.NewFlagSet("analyze --tier 1b", flag.ContinueOnError)
	dbPath := fs.String("db", "outputs/cases.duckdb", "case DuckDB path")
	skillsDir := fs.String("skills-dir", "skills", "skill markdown root")
	outDir := fs.String("out-dir", "",
		"findings base dir (default: outputs/cases/<id>/findings; tier1b writes to <base>/by-skill/)")
	maxEvents := fs.Int("max-events", 200, "anomaly candidate cap shown to LLM")
	model := fs.String("model", "",
		"model id (empty = let claude CLI default)")
	timeoutMin := fs.Int("timeout-minutes", 5, "per-LLM-call timeout in minutes")
	dryRun := fs.Bool("dry-run", false, "build prompt and stats, skip the LLM call")
	rulesDB := fs.String("rules-db", "outputs/rules.duckdb",
		"rules DuckDB path (skill_sql_cache for Tier 1B v0.2 learned lenses)")
	noSkillCache := fs.Bool("no-skill-cache", false,
		"disable the skill SQL cache (v0.1 heuristic-only behaviour)")
	skill := fs.String("skill", "anomaly_hunter",
		"skill to run (skills/<skill>.md); the .md is the system prompt")
	skillsCSV := fs.String("skills", "",
		"comma-separated skills to run in sequence (overrides --skill). e.g. "+
			"anomaly_hunter,persistence,credential_access — each gets its own "+
			"skill_sql_cache namespace and findings/by-skill/<skill>.json")
	evidenceFetch := fs.Bool("evidence-fetch", true,
		"let the agent pull & read files from the disk image on demand "+
			"(requested_files → bounded follow-up pass with the file contents)")
	maxEvidenceRounds := fs.Int("max-evidence-rounds", 1,
		"max fetch+reanalyse rounds when --evidence-fetch is on")
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

	if *outDir == "" {
		*outDir = filepath.Join("outputs", "cases", caseID, "findings")
	}

	modelID := *model
	if modelID == "" {
		modelID = "claude-code-default"
	}

	skills := splitCSV(*skillsCSV)
	if len(skills) == 0 {
		skills = []string{*skill}
	}

	var totalNew int
	for _, sk := range skills {
		cfg := tier1b.Config{
			CaseID:          caseID,
			Skill:           sk,
			SkillsDir:       *skillsDir,
			FindingsBaseDir: *outDir,
			DBPath:          *dbPath,
			MaxEvents:       *maxEvents,
			Model:           *model,
			Timeout:         time.Duration(*timeoutMin) * time.Minute,
			DryRun:          *dryRun,
			ProgressFn:      tier1bProgress(),
			RulesDBPath:     *rulesDB,
			NoSkillCache:    *noSkillCache,
			SchemaVersion:   casedb.SchemaVersion(),
			ModelID:         modelID,

			EvidenceFetch:     *evidenceFetch,
			MaxEvidenceRounds: *maxEvidenceRounds,
			MaxEvidenceFiles:  *maxEvidenceFiles,
			PythonBin:         pyBin,
		}
		fmt.Fprintf(os.Stderr, "tier 1B (Skills-driven Anomaly) — case=%s skill=%s findings_base=%s\n",
			caseID, sk, *outDir)
		rep, err := tier1b.Run(context.Background(), cfg)
		if err != nil {
			if len(skills) == 1 {
				return err
			}
			// graceful: one skill failing doesn't abort the rest (CLAUDE.md #4).
			fmt.Fprintf(os.Stderr, "skill %s failed (continuing): %v\n", sk, err)
			continue
		}
		printTier1BReport(rep, sk, *dryRun)
		totalNew += len(rep.NewFindings)
	}
	if len(skills) > 1 {
		fmt.Printf("\nTier 1B multi-skill total — %d skill(s) run, %d new findings\n",
			len(skills), totalNew)
	}
	return nil
}

func tier1bProgress() func(tier1b.Event) {
	return func(ev tier1b.Event) {
		fmt.Fprintf(os.Stderr, "[%s] %s\n", ev.Phase, ev.Message)
	}
}

func printTier1BReport(rep *tier1b.Report, skill string, dryRun bool) {
	fmt.Printf("\nTier 1B summary — case=%s skill=%s\n", rep.CaseID, skill)
	fmt.Printf("  prior findings consumed:  %d\n", rep.PriorFindings)
	fmt.Printf("  events scanned:           %d\n", rep.EventsScanned)
	fmt.Printf("  candidates (in window):   %d  (truncated=%v)\n",
		rep.EventsInWindow, rep.Truncated)
	if rep.CacheEnabled {
		fmt.Printf("  skill cache:              %d available / %d executed / %d hits\n",
			rep.SkillSQLAvailable, rep.SkillSQLExecuted, rep.SkillSQLHits)
	}
	if dryRun {
		fmt.Printf("\n  (dry-run: LLM call skipped)\n")
		return
	}
	if rep.CacheEnabled {
		fmt.Printf("  cache growth:             %d proposed / %d appended / %d promoted\n",
			rep.CandidatesProposed, rep.CandidatesAppended, rep.Promoted)
	}
	fmt.Printf("  LLM call duration:        %.1fs\n", rep.LLMCallDurationS)
	fmt.Printf("  tokens:                   in %d / cache_read %d / out %d  (cost $%.4f)\n",
		rep.InputTokens, rep.CacheReadTokens, rep.OutputTokens, rep.TotalCostUSD)
	fmt.Printf("  new findings:             %d\n", len(rep.NewFindings))
	if rep.FilesRequested > 0 {
		fmt.Printf("  evidence fetch:           %d requested / %d extracted (%d round(s))\n",
			rep.FilesRequested, rep.FilesExtracted, rep.EvidenceRounds)
	}
	if rep.OutputPath != "" {
		fmt.Printf("  output:                   %s\n", rep.OutputPath)
	}
	if len(rep.NewFindings) > 0 {
		fmt.Printf("\nFindings:\n")
		for _, f := range rep.NewFindings {
			fmt.Printf("  [%s/%s] %d evidence  — %s\n",
				f.Severity, f.Lens, f.AuditCount, truncateStr(f.Summary, 110))
		}
	}
}
