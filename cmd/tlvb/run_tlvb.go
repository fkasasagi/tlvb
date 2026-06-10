package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// runPipelineTLVB is the v0.1 TLVB one-shot orchestrator:
//
//	tlvb run CASE_ID --tier all [--evidence PATH] [--evidence-id EV-001]
//	   [--skip-parse] [--skip-1a] [--skip-1b] [--skip-2] [--skip-report]
//	   [--active-search] [--max-self-correct N] [--format html,csv,json] [--language ja|en]
//	   [--include-info-level]
//
// It chains the existing TLVB CLI sub-flows in order:
//  1. case init (idempotent)
//  2. parse (Tier 0) — unless --skip-parse
//  3. analyze --tier 1a — cached SQL + Hayabusa pass-through
//  4. analyze --tier 1b — Skills-driven Anomaly
//  5. synthesize --tier 2 — Timeline Analysis (optionally with --active-search)
//  6. report --tier 3 — HTML / CSV / JSON
//
// Failure policy:
//   - Parse failure aborts (downstream needs data).
//   - 1A / 1B / 2 / 3 failures are surfaced but the pipeline continues so
//     the operator can inspect partial results.
func runPipelineTLVB(caseID string, rawArgs []string) error {
	// Manually parse our flags then forward residual args to nothing
	// (we call each TLVB stage with the args it needs).
	var (
		evPath           string
		evID             = "EV-001"
		caseName         = "TLVB pipeline " + caseID
		examiner         = ""
		dbPath           = "outputs/cases.duckdb"
		skipParse        bool
		skip1A           bool
		skip1B           bool
		skip2            bool
		skipReport       bool
		activeSearch     bool
		maxSelfCorrect   string // forwarded verbatim to synthesize; "" = synthesize default
		demoInjectFault  bool
		noEvidenceFetch  bool // disable on-demand file extraction in Tier 1B/2
		includeInfoLevel bool
		format           = "html,csv,json"
		language         = "ja"
		model            string
		timezone         = "UTC"
	)
	args := rawArgs
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, bool) {
			if i+1 >= len(args) {
				return "", false
			}
			i++
			return args[i], true
		}
		switch {
		case a == "--evidence":
			if v, ok := next(); ok {
				evPath = v
			}
		case strings.HasPrefix(a, "--evidence="):
			evPath = strings.TrimPrefix(a, "--evidence=")
		case a == "--evidence-id":
			if v, ok := next(); ok {
				evID = v
			}
		case strings.HasPrefix(a, "--evidence-id="):
			evID = strings.TrimPrefix(a, "--evidence-id=")
		case a == "--name":
			if v, ok := next(); ok {
				caseName = v
			}
		case strings.HasPrefix(a, "--name="):
			caseName = strings.TrimPrefix(a, "--name=")
		case a == "--examiner":
			if v, ok := next(); ok {
				examiner = v
			}
		case strings.HasPrefix(a, "--examiner="):
			examiner = strings.TrimPrefix(a, "--examiner=")
		case a == "--db":
			if v, ok := next(); ok {
				dbPath = v
			}
		case strings.HasPrefix(a, "--db="):
			dbPath = strings.TrimPrefix(a, "--db=")
		case a == "--timezone":
			if v, ok := next(); ok {
				timezone = v
			}
		case strings.HasPrefix(a, "--timezone="):
			timezone = strings.TrimPrefix(a, "--timezone=")
		case a == "--format":
			if v, ok := next(); ok {
				format = v
			}
		case strings.HasPrefix(a, "--format="):
			format = strings.TrimPrefix(a, "--format=")
		case a == "--language":
			if v, ok := next(); ok {
				language = v
			}
		case strings.HasPrefix(a, "--language="):
			language = strings.TrimPrefix(a, "--language=")
		case a == "--model":
			if v, ok := next(); ok {
				model = v
			}
		case strings.HasPrefix(a, "--model="):
			model = strings.TrimPrefix(a, "--model=")
		case a == "--skip-parse":
			skipParse = true
		case a == "--skip-1a":
			skip1A = true
		case a == "--skip-1b":
			skip1B = true
		case a == "--skip-2":
			skip2 = true
		case a == "--skip-report":
			skipReport = true
		case a == "--active-search":
			activeSearch = true
		case a == "--max-self-correct":
			if v, ok := next(); ok {
				maxSelfCorrect = v
			}
		case strings.HasPrefix(a, "--max-self-correct="):
			maxSelfCorrect = strings.TrimPrefix(a, "--max-self-correct=")
		case a == "--demo-inject-sql-fault":
			demoInjectFault = true
		case a == "--no-evidence-fetch":
			noEvidenceFetch = true
		case a == "--include-info-level":
			includeInfoLevel = true
		default:
			return fmt.Errorf("unknown flag %q for `tlvb run --tier all`", a)
		}
	}
	if examiner == "" {
		examiner = "tlvb-pipeline"
	}

	start := time.Now()
	banner := func(msg string) {
		fmt.Fprintf(os.Stderr, "\n────────── %s\n", msg)
	}

	// Step 1 — case init (idempotent).
	banner(fmt.Sprintf("Step 1/6  case init  (case_id=%s)", caseID))
	if err := runCaseInit([]string{
		"--case-id", caseID,
		"--name", caseName,
		"--examiner", examiner,
		"--timezone", timezone,
		"--db", dbPath,
	}); err != nil {
		// Idempotent: ignore "already exists" errors; abort on others.
		if !strings.Contains(err.Error(), "already") {
			fmt.Fprintf(os.Stderr, "case init warning: %v (continuing)\n", err)
		}
	}

	// Step 2 — parse (Tier 0).
	if skipParse {
		fmt.Fprintln(os.Stderr, "Step 2/6  parse  SKIPPED (--skip-parse)")
	} else if evPath == "" {
		fmt.Fprintln(os.Stderr,
			"Step 2/6  parse  SKIPPED (no --evidence given — assuming case is already parsed)")
	} else {
		banner("Step 2/6  parse  (Tier 0)")
		if err := runParse([]string{
			"--case-id", caseID,
			"--evidence-id", evID,
			"--input", evPath,
			"--db", dbPath,
		}); err != nil {
			return fmt.Errorf("parse failed (pipeline aborted): %w", err)
		}
	}

	// Step 3 — Tier 1A.
	if skip1A {
		fmt.Fprintln(os.Stderr, "Step 3/6  Tier 1A  SKIPPED (--skip-1a)")
	} else {
		banner("Step 3/6  analyze --tier 1a  (cached SQL + Hayabusa pass-through)")
		args1A := []string{caseID, "--tier", "1a", "--db", dbPath}
		if includeInfoLevel {
			args1A = append(args1A, "--include-info-level")
		}
		if err := runAnalyze(args1A); err != nil {
			fmt.Fprintf(os.Stderr, "Tier 1A error (continuing): %v\n", err)
		}
	}

	// Step 4 — Tier 1B.
	if skip1B {
		fmt.Fprintln(os.Stderr, "Step 4/6  Tier 1B  SKIPPED (--skip-1b)")
	} else {
		banner("Step 4/6  analyze --tier 1b  (Skills-driven Anomaly)")
		args1B := []string{caseID, "--tier", "1b", "--db", dbPath}
		if model != "" {
			args1B = append(args1B, "--model", model)
		}
		if noEvidenceFetch {
			args1B = append(args1B, "--evidence-fetch=false")
		}
		if err := runAnalyze(args1B); err != nil {
			fmt.Fprintf(os.Stderr, "Tier 1B error (continuing): %v\n", err)
		}
	}

	// Step 5 — Tier 2.
	if skip2 {
		fmt.Fprintln(os.Stderr, "Step 5/6  Tier 2  SKIPPED (--skip-2)")
	} else {
		banner("Step 5/6  synthesize --tier 2  (Timeline Analysis)")
		args2 := []string{caseID, "--tier", "2", "--db", dbPath}
		if activeSearch {
			args2 = append(args2, "--active-search")
		}
		if maxSelfCorrect != "" {
			args2 = append(args2, "--max-self-correct", maxSelfCorrect)
		}
		if demoInjectFault {
			args2 = append(args2, "--demo-inject-sql-fault")
		}
		if model != "" {
			args2 = append(args2, "--model", model)
		}
		if noEvidenceFetch {
			args2 = append(args2, "--evidence-fetch=false")
		}
		if err := runSynthesize(args2); err != nil {
			fmt.Fprintf(os.Stderr, "Tier 2 error (continuing): %v\n", err)
		}
	}

	// Step 6 — Tier 3 report.
	if skipReport {
		fmt.Fprintln(os.Stderr, "Step 6/6  Tier 3 report  SKIPPED (--skip-report)")
	} else {
		banner("Step 6/6  report --tier 3  (HTML / CSV / JSON)")
		args3 := []string{caseID, "--tier", "3", "--format", format, "--language", language}
		if err := runReport(args3); err != nil {
			fmt.Fprintf(os.Stderr, "Tier 3 report error (continuing): %v\n", err)
		}
	}

	dur := time.Since(start)
	banner(fmt.Sprintf("Pipeline DONE  total=%s", dur.Truncate(time.Second)))
	reportPath := filepath.Join("outputs", "cases", caseID, "reports", "report.html")
	if _, err := os.Stat(reportPath); err == nil {
		fmt.Fprintf(os.Stderr, "  HTML report: %s\n", reportPath)
	}
	return nil
}
