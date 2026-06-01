// Command tlvb is the TLVB CLI / MCP server entry point.
//
// Subcommands (Phase 1 — only mcp-serve is functional):
//   tlvb mcp-serve     run the Tier 0 MCP server over stdio
//   tlvb case init     (TODO Phase 2.x)
//   tlvb parse <id>    (TODO Phase 2.x)
//   tlvb version       print build info
package main

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/agents"
	"github.com/tlvb/tlvb/internal/casedb"
	"github.com/tlvb/tlvb/internal/common"
	"github.com/tlvb/tlvb/internal/exporter"
	mcpsrv "github.com/tlvb/tlvb/internal/mcp"
	"github.com/tlvb/tlvb/internal/reporter"
	"github.com/tlvb/tlvb/internal/review"
	"github.com/tlvb/tlvb/internal/synthesizer"
	"github.com/tlvb/tlvb/internal/web"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "version":
		fmt.Printf("tlvb %s\n", version)
	case "mcp-serve":
		if err := runMCPServe(args); err != nil {
			fmt.Fprintf(os.Stderr, "mcp-serve: %v\n", err)
			os.Exit(1)
		}
	case "case":
		if err := runCase(args); err != nil {
			fmt.Fprintf(os.Stderr, "case: %v\n", err)
			os.Exit(1)
		}
	case "parse":
		if err := runParse(args); err != nil {
			fmt.Fprintf(os.Stderr, "parse: %v\n", err)
			os.Exit(1)
		}
	case "analyze":
		if err := runAnalyze(args); err != nil {
			fmt.Fprintf(os.Stderr, "analyze: %v\n", err)
			os.Exit(1)
		}
	case "synthesize":
		if err := runSynthesize(args); err != nil {
			fmt.Fprintf(os.Stderr, "synthesize: %v\n", err)
			os.Exit(1)
		}
	case "report":
		if err := runReport(args); err != nil {
			fmt.Fprintf(os.Stderr, "report: %v\n", err)
			os.Exit(1)
		}
	case "review":
		if err := runReview(args); err != nil {
			fmt.Fprintf(os.Stderr, "review: %v\n", err)
			os.Exit(1)
		}
	case "run":
		if err := runFullPipeline(args); err != nil {
			fmt.Fprintf(os.Stderr, "run: %v\n", err)
			os.Exit(1)
		}
	case "serve":
		if err := runServe(args); err != nil {
			fmt.Fprintf(os.Stderr, "serve: %v\n", err)
			os.Exit(1)
		}
	case "calibrate":
		// Wave 20e: read findings/**/*.json and fit per_event_sec
		// from real (InputEvents, DurationSec, PromptSizeChars) data.
		if err := runCalibrate(args); err != nil {
			fmt.Fprintf(os.Stderr, "calibrate: %v\n", err)
			os.Exit(1)
		}
	case "rules":
		// TLVB Tier 1A — build / list the rule SQL cache.
		if err := runRules(args); err != nil {
			fmt.Fprintf(os.Stderr, "rules: %v\n", err)
			os.Exit(1)
		}
	case "status":
		// One-shot per-case state inspector.
		if err := runStatus(args); err != nil {
			fmt.Fprintf(os.Stderr, "status: %v\n", err)
			os.Exit(1)
		}
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `tlvb %s — TLVB orchestrator + MCP server

Usage:
  tlvb mcp-serve [--config PATH] [--db PATH]
  tlvb case init --case-id ID --name NAME --examiner NAME [--timezone TZ]
  tlvb parse --case-id ID --evidence-id ID --input PATH [--workspace DIR]
  tlvb parse --case-id ID --inputs PATH1,PATH2,... [--evidence-ids EV1,EV2,...]   ★ multi-evidence
  tlvb analyze CASE_ID --tactic NAME [--engine claude-code|anthropic-api]    # legacy tactic-based
  tlvb analyze CASE_ID --tier 1a [--source S] [--rule R] [--max-evidence N]   # Tier 1A signature SQL runtime
  tlvb synthesize CASE_ID [--correct] [--findings-dir DIR] [--out PATH]
  tlvb report CASE_ID [--format html,csv,json] [--language ja|en] [--only-approved]
  tlvb review CASE_ID [--gate 1] [--examiner NAME]
  tlvb run CASE_ID --evidence PATH [--engine claude-code]                   # legacy tactic-based pipeline
  tlvb run CASE_ID --tier all --evidence PATH [--active-search]              # TLVB v0.1 one-shot pipeline
       [--skip-parse|--skip-1a|--skip-1b|--skip-2|--skip-report]
       [--format html,csv,json] [--language ja|en]
  tlvb serve [--port 8080] [--db PATH] [--outputs DIR]
  tlvb rules build [--dry-run] [--budget-yen N] [--max-rules N] [--source sigma|hayabusa|stix] [--force]
  tlvb rules list  [--source sigma|hayabusa|stix] [--state pending|built|failed] [--show-sql]
  tlvb status CASE_ID [-v]                                                   # case state inspector
  tlvb version

Run 'tlvb <subcommand> -h' for subcommand options.
`, version)
}

func runMCPServe(args []string) error {
	fs := flag.NewFlagSet("mcp-serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "config/artifacts.yaml", "artifact catalog YAML")
	dbPath := fs.String("db", "outputs/cases.duckdb", "case DuckDB path")
	outputs := fs.String("outputs", filepath.Join("outputs", "cases"),
		"case workspaces root (used for findings/*.json read by list_findings/get_finding)")
	logLevel := fs.String("log-level", "info", "debug|info|warn|error")
	if err := fs.Parse(args); err != nil {
		return err
	}

	level := slog.LevelInfo
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	logger := common.NewStderrLogger(level)

	srv, err := mcpsrv.New(mcpsrv.Config{
		Name:          "tlvb-tier0",
		Version:       version,
		ArtifactsYAML: *cfgPath,
		CaseDBPath:    *dbPath,
		OutputsRoot:   *outputs,
	}, logger)
	if err != nil {
		return err
	}
	defer srv.Close()

	logger.Info("TLVB Tier 0 MCP server starting (stdio)",
		"config", *cfgPath, "db", *dbPath)
	return srv.ServeStdio(context.Background())
}

func runCase(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: tlvb case init|export|import|vacuum ...")
	}
	switch args[0] {
	case "init":
		return runCaseInit(args[1:])
	case "export":
		return runCaseExport(args[1:])
	case "import":
		return runCaseImport(args[1:])
	case "vacuum":
		// Wave 20f: rebuild cases.duckdb keeping only specified cases (or
		// auto-detect cases with on-disk dirs in outputs/cases/).
		return runCaseVacuum(args[1:])
	default:
		return fmt.Errorf("unknown case subcommand %q", args[0])
	}
}

func runCaseInit(args []string) error {
	fs := flag.NewFlagSet("case init", flag.ContinueOnError)
	caseID := fs.String("case-id", "", "required")
	name := fs.String("name", "", "required")
	examiner := fs.String("examiner", "", "required")
	tz := fs.String("timezone", "UTC", "case timezone")
	dbPath := fs.String("db", "outputs/cases.duckdb", "case DuckDB path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caseID == "" || *name == "" || *examiner == "" {
		return fmt.Errorf("--case-id, --name, --examiner are required")
	}

	mgr, err := casedb.Open(*dbPath, casedb.ReadWrite)
	if err != nil {
		return err
	}
	defer mgr.Close()

	if err := mgr.RegisterCase(context.Background(), casedb.CaseRow{
		CaseID:    *caseID,
		Name:      *name,
		Examiner:  *examiner,
		Timezone:  *tz,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		return err
	}
	fmt.Printf("case registered: %s (%s)\n", *caseID, *name)
	return nil
}

// runCaseExport packs a case into a .fcz tarball (Issue #16 / REQ-2).
func runCaseExport(args []string) error {
	fs := flag.NewFlagSet("case export", flag.ContinueOnError)
	caseID := fs.String("case-id", "", "required")
	out := fs.String("out", "", "output .fcz path (default: <case-id>.fcz)")
	dbPath := fs.String("db", "outputs/cases.duckdb", "case DuckDB path")
	outputs := fs.String("outputs", "outputs/cases", "case workspaces root")
	includeEv := fs.Bool("include-evidence", false,
		"also bundle outputs/cases/<id>/extractions/ (can be many GiB)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caseID == "" {
		return fmt.Errorf("--case-id is required")
	}
	if *out == "" {
		*out = *caseID + ".fcz"
	}
	mgr, err := casedb.Open(*dbPath, casedb.ReadOnly)
	if err != nil {
		return err
	}
	defer mgr.Close()
	m, err := exporter.Export(context.Background(), mgr, exporter.ExportOptions{
		CaseID:          *caseID,
		OutputsRoot:     *outputs,
		DBPath:          *dbPath,
		OutputPath:      *out,
		IncludeEvidence: *includeEv,
		TLVBVersion: version,
	})
	if err != nil {
		return err
	}
	fmt.Printf("exported case %s → %s\n", m.CaseID, *out)
	fmt.Printf("  rows: case=%d evidence=%d parse_results=%d unified_events=%d\n",
		m.RowCounts["case"], m.RowCounts["evidence"],
		m.RowCounts["parse_results"], m.RowCounts["unified_events"])
	fmt.Printf("  workspace files: %d  include_evidence=%v\n",
		m.WorkspaceFiles, m.IncludeEvidence)
	fmt.Printf("  files hashed: %d\n", len(m.Files))
	return nil
}

// runCaseImport unpacks a .fcz, verifies SHA-256, loads rows + workspace.
func runCaseImport(args []string) error {
	fs := flag.NewFlagSet("case import", flag.ContinueOnError)
	in := fs.String("in", "", "input .fcz path (required)")
	dbPath := fs.String("db", "outputs/cases.duckdb", "case DuckDB path")
	outputs := fs.String("outputs", "outputs/cases", "case workspaces root")
	overwrite := fs.Bool("overwrite", false,
		"replace existing case with same case_id")
	force := fs.Bool("force", false,
		"continue even if a payload SHA-256 doesn't match the manifest")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("--in is required")
	}
	mgr, err := casedb.Open(*dbPath, casedb.ReadWrite)
	if err != nil {
		return err
	}
	defer mgr.Close()
	rep, err := exporter.Import(context.Background(), mgr, exporter.ImportOptions{
		InputPath:   *in,
		OutputsRoot: *outputs,
		DBPath:      *dbPath,
		Overwrite:   *overwrite,
		Force:       *force,
	})
	if err != nil {
		return err
	}
	fmt.Printf("imported case %s (schema=%s)\n", rep.CaseID, rep.Schema)
	fmt.Printf("  rows: %v\n", rep.RowCounts)
	fmt.Printf("  workspace files: %d\n", rep.WorkspaceFiles)
	fmt.Printf("  sha256: verified=%d mismatched=%d  overwritten=%v\n",
		rep.Verified, rep.Mismatched, rep.Overwritten)
	return nil
}

// runParse dispatches to the Python orchestrator (parsers.orchestrator).
//
// Why subprocess: parsers/ is Python (CLAUDE.md §開発言語). Go invokes the
// orchestrator with structured args, captures stdout (a JSON OrchestratorReport),
// registers the evidence row in DuckDB, and prints a summary. The orchestrator
// itself writes parse_results / unified_events into the same DuckDB.
//
// Multi-evidence (★v0.3 #1): pass --inputs path1,path2,... to parse N
// evidences in one invocation. Each gets its own evidence_id (auto-
// generated if --evidence-ids is omitted or short). Failures in one
// evidence don't abort the rest — same graceful-degradation policy as
// the Web UI handler.
func runParse(args []string) error {
	fs := flag.NewFlagSet("parse", flag.ContinueOnError)
	caseID := fs.String("case-id", "", "required — must already be `case init`-ed")
	evID := fs.String("evidence-id", "",
		"single-evidence mode — unique within the case (use --evidence-ids for multi)")
	evIDs := fs.String("evidence-ids", "",
		"comma-separated list of evidence_ids; pairs with --inputs in order. "+
			"Missing entries are auto-generated as EV-<ts>-<n>")
	input := fs.String("input", "", "single-evidence input — .zip or directory")
	inputs := fs.String("inputs", "",
		"comma-separated list of evidence inputs (.zip or directory). "+
			"Each is processed sequentially; one failure doesn't abort the rest. "+
			"★v0.3 #1 multi-evidence mode")
	dbPath := fs.String("db", "outputs/cases.duckdb", "case DuckDB path")
	workspace := fs.String("workspace", "",
		"working dir (default: outputs/cases/<case-id>)")
	timeout := fs.Int("timeout-seconds", 600, "per-parser timeout")
	tz := fs.String("timezone", "UTC", "evidence timezone")
	only := fs.String("only", "",
		"comma-separated artifact_ids to restrict (e.g. evtx,registry)")
	pythonBin := fs.String("python", "",
		"python interpreter (default: $TLVB_PYTHON, then ./.venv/bin/python3, then python3)")
	// Issue #23: optional input-shape flags (match the Web Parse modal).
	inputMode := fs.String("input-mode", "auto",
		"auto|image|cdir|washizukami — input shape hint (Issue #23)")
	imageFormat := fs.String("image-format", "auto",
		"auto|ewf|raw|vmdk|vhd|vhdx — force a disk-image format (only with --input-mode=image)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caseID == "" {
		return fmt.Errorf("--case-id is required")
	}

	// Build the (path, evidence_id) list. --inputs takes precedence; else
	// fall back to single --input. Auto-generate evidence_ids where blank.
	pathList := []string{}
	if *inputs != "" {
		for _, p := range strings.Split(*inputs, ",") {
			if p = strings.TrimSpace(p); p != "" {
				pathList = append(pathList, p)
			}
		}
	} else if *input != "" {
		pathList = []string{*input}
	} else {
		return fmt.Errorf("--input or --inputs is required")
	}

	idList := []string{}
	if *evIDs != "" {
		for _, s := range strings.Split(*evIDs, ",") {
			idList = append(idList, strings.TrimSpace(s))
		}
	} else if *evID != "" {
		idList = []string{*evID}
	}
	now := time.Now().UTC().Format("20060102-150405")
	for i := range pathList {
		if i >= len(idList) || idList == nil || idList[i] == "" {
			autoID := fmt.Sprintf("EV-%s-%d", now, i+1)
			if i >= len(idList) {
				idList = append(idList, autoID)
			} else {
				idList[i] = autoID
			}
		}
	}
	if len(pathList) != len(idList) {
		return fmt.Errorf("mismatched count: --inputs=%d --evidence-ids=%d",
			len(pathList), len(idList))
	}

	pyBin := *pythonBin
	if pyBin == "" {
		pyBin = common.ResolvePython()
	}

	if *workspace == "" {
		*workspace = filepath.Join("outputs", "cases", *caseID)
	}
	if err := os.MkdirAll(*workspace, 0o755); err != nil {
		return err
	}

	// Per-evidence sequential loop.
	ok, failed := []string{}, []string{}
	for i, p := range pathList {
		evIDLocal := idList[i]
		fmt.Fprintf(os.Stderr, "\n[parse %d/%d] case=%s evidence=%s input=%s\n",
			i+1, len(pathList), *caseID, evIDLocal, p)
		err := runParseOneEvidence(*caseID, evIDLocal, p, *dbPath, *workspace,
			*timeout, *tz, *only, pyBin, *inputMode, *imageFormat)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[parse %d/%d] FAIL: %v\n", i+1, len(pathList), err)
			failed = append(failed, fmt.Sprintf("%s: %v", evIDLocal, err))
			continue
		}
		ok = append(ok, evIDLocal)
	}

	fmt.Printf("\nMulti-evidence parse summary — case=%s  ok=%d  failed=%d\n",
		*caseID, len(ok), len(failed))
	for _, id := range ok {
		fmt.Printf("  [OK  ] %s\n", id)
	}
	for _, msg := range failed {
		fmt.Printf("  [FAIL] %s\n", msg)
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d evidence(s) failed", len(failed))
	}
	return nil
}

// runParseOneEvidence does the per-evidence work that was previously
// inlined in runParse: register evidence row in DuckDB, then invoke the
// Python orchestrator. Used by both runParse (single + multi) and the
// internal pipeline runner.
func runParseOneEvidence(
	caseID, evID, input, dbPath, workspace string,
	timeout int, tz, only, pyBin string,
	inputMode, imageFormat string,
) error {
	inputAbs, err := filepath.Abs(input)
	if err != nil {
		return fmt.Errorf("resolve input: %w", err)
	}
	if _, err := os.Stat(inputAbs); err != nil {
		return fmt.Errorf("input not accessible: %w", err)
	}

	// Register evidence row first — chain of custody record exists even
	// if parsing fails. SHA-256 the file (or use "dir:..." tag for dirs).
	mgr, err := casedb.Open(dbPath, casedb.ReadWrite)
	if err != nil {
		return err
	}
	sha, sizeBytes, err := evidenceFingerprint(inputAbs)
	if err != nil {
		_ = mgr.Close()
		return fmt.Errorf("hash evidence: %w", err)
	}
	if err := mgr.RegisterEvidence(context.Background(), casedb.EvidenceRow{
		EvidenceID:   evID,
		CaseID:       caseID,
		Path:         inputAbs,
		SHA256:       sha,
		SizeBytes:    sizeBytes,
		EvidenceType: detectEvidenceType(inputAbs),
		RegisteredAt: time.Now().UTC(),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: register evidence: %v\n", err)
	}
	if err := mgr.Close(); err != nil {
		return err
	}

	argv := []string{
		"-m", "parsers.orchestrator",
		"--case-id", caseID,
		"--evidence-id", evID,
		"--input", inputAbs,
		"--db", dbPath,
		"--workspace", workspace,
		"--timeout-seconds", fmt.Sprintf("%d", timeout),
		"--timezone", tz,
		"--report-json", "-",
	}
	if only != "" {
		argv = append(argv, "--only")
		for _, a := range strings.Split(only, ",") {
			if a = strings.TrimSpace(a); a != "" {
				argv = append(argv, a)
			}
		}
	}
	if inputMode != "" && inputMode != "auto" {
		argv = append(argv, "--input-mode", inputMode)
	}
	if imageFormat != "" && imageFormat != "auto" {
		argv = append(argv, "--image-format", imageFormat)
	}
	cmd := exec.Command(pyBin, argv...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	report := strings.TrimSpace(string(out))
	if report != "" {
		printParseSummary(report)
	}
	if err != nil {
		return fmt.Errorf("orchestrator: %w", err)
	}
	return nil
}

// evidenceFingerprint returns sha256 + size for files. Directories return
// a synthetic fingerprint over their relative file list — enough to detect
// re-runs against an unchanged tree without walking gigabytes of content.
func evidenceFingerprint(path string) (string, int64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", 0, err
	}
	if !fi.IsDir() {
		f, err := os.Open(path)
		if err != nil {
			return "", 0, err
		}
		defer f.Close()
		h := sha256.New()
		n, err := io.Copy(h, f)
		if err != nil {
			return "", 0, err
		}
		return hex.EncodeToString(h.Sum(nil)), n, nil
	}
	// Directory: hash a stable list of (relpath, size, mtime).
	h := sha256.New()
	var total int64
	err = filepath.Walk(path, func(p string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(path, p)
		fmt.Fprintf(h, "%s\x00%d\x00%d\n", rel, info.Size(), info.ModTime().UnixNano())
		total += info.Size()
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	return "dir:" + hex.EncodeToString(h.Sum(nil)), total, nil
}

func detectEvidenceType(path string) string {
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		return "directory"
	}
	if strings.HasSuffix(strings.ToLower(path), ".zip") {
		return "zip"
	}
	return "file"
}

func printParseSummary(reportJSON string) {
	var r struct {
		CaseID       string `json:"case_id"`
		EvidenceID   string `json:"evidence_id"`
		Detections   int    `json:"detections"`
		Succeeded    int    `json:"succeeded"`
		Failed       int    `json:"failed"`
		ParseResults []struct {
			ArtifactID      string  `json:"artifact_id"`
			Success         bool    `json:"success"`
			ExitCode        *int    `json:"exit_code"`
			RowCount        *int64  `json:"row_count"`
			DurationSeconds float64 `json:"duration_seconds"`
			Error           string  `json:"error,omitempty"`
		} `json:"parse_results"`
	}
	if err := json.Unmarshal([]byte(reportJSON), &r); err != nil {
		fmt.Fprintf(os.Stderr, "warning: report parse: %v\nraw: %s\n", err, reportJSON)
		return
	}
	fmt.Printf("\nParse summary — case=%s evidence=%s\n", r.CaseID, r.EvidenceID)
	fmt.Printf("  detections=%d  succeeded=%d  failed=%d\n",
		r.Detections, r.Succeeded, r.Failed)
	for _, pr := range r.ParseResults {
		ok := "OK "
		if !pr.Success {
			ok = "FAIL"
		}
		rows := int64(0)
		if pr.RowCount != nil {
			rows = *pr.RowCount
		}
		fmt.Printf("  [%s] %-16s rows=%-7d  dur=%.2fs",
			ok, pr.ArtifactID, rows, pr.DurationSeconds)
		if pr.Error != "" {
			fmt.Printf("  err=%s", truncate(pr.Error, 80))
		}
		fmt.Println()
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// runAnalyze runs one Tactic Agent against a case. The first positional
// arg is the case_id (required). The agent's TacticReport is written as
// DRAFT to outputs/cases/<case_id>/findings/<tactic>.json and a summary is
// printed to stdout.
func runAnalyze(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: tlvb analyze CASE_ID --tactic persistence [...]")
	}
	caseID := args[0]
	rest := args[1:]
	if strings.HasPrefix(caseID, "-") {
		return fmt.Errorf("first argument must be CASE_ID, got %q", caseID)
	}

	// TLVB v0.1: `tlvb analyze CASE_ID --tier 1a` routes to the cached-SQL
	// signature runner instead of the legacy tactic-based agent flow.
	// Detected with a sloppy pre-scan because the existing analyze flag set
	// is large and we don't want to thread a --tier flag through 300 lines.
	for i, a := range rest {
		if a == "--tier" && i+1 < len(rest) {
			switch strings.ToLower(rest[i+1]) {
			case "1a":
				inner := append([]string{}, rest[:i]...)
				inner = append(inner, rest[i+2:]...)
				return runAnalyzeTier1A(caseID, inner)
			case "1b":
				inner := append([]string{}, rest[:i]...)
				inner = append(inner, rest[i+2:]...)
				return runAnalyzeTier1B(caseID, inner)
			case "2":
				return fmt.Errorf("--tier 2 not implemented yet")
			}
		}
		if strings.HasPrefix(a, "--tier=") {
			val := strings.ToLower(strings.TrimPrefix(a, "--tier="))
			switch val {
			case "1a":
				inner := append([]string{}, rest[:i]...)
				inner = append(inner, rest[i+1:]...)
				return runAnalyzeTier1A(caseID, inner)
			case "1b":
				inner := append([]string{}, rest[:i]...)
				inner = append(inner, rest[i+1:]...)
				return runAnalyzeTier1B(caseID, inner)
			case "2":
				return fmt.Errorf("--tier 2 not implemented yet")
			}
		}
	}

	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	tactic := fs.String("tactic", "persistence", "tactic name (skill file basename)")
	evID := fs.String("evidence-id", "", "evidence_id (default: first evidence in case)")
	dbPath := fs.String("db", "outputs/cases.duckdb", "case DuckDB path")
	engine := fs.String("engine", "claude-code",
		"execution engine: claude-code (default, uses local `claude` CLI session) | anthropic-api")
	model := fs.String("model", "",
		"model id (default: empty for claude-code → CLI default; "+
			"claude-sonnet-4-6 for anthropic-api)")
	// Wave 19 → Wave 20a:
	//   - MaxEvents stays at 400 (prefilter cap).
	//   - timeout-seconds default 0 → auto-compute via
	//     agents.ComputeTimeout(tactic, max_events). Operator can still
	//     pass a positive value to force a fixed budget. Env-var overrides
	//     (TLVB_LLM_TIMEOUT_*) apply when --timeout-seconds=0.
	maxEvents := fs.Int("max-events", 400, "cap on events shown to the LLM")
	maxIters := fs.Int("max-iters", 3, "JSON-validation retry budget")
	timeoutSec := fs.Int("timeout-seconds", 0,
		"wall-clock cap in seconds; 0 → auto-compute from --max-events + tactic via "+
			"agents.ComputeTimeout (overridable with TLVB_LLM_TIMEOUT_* env vars)")
	outDir := fs.String("out-dir", "",
		"directory for findings JSON (default: outputs/cases/<case-id>/findings)")
	dryRun := fs.Bool("dry-run", false,
		"build prompt and report sizes; skip the engine call")
	// Wave 20h: --artifact-scope narrows the SQL prefilter to events from
	// one artifact_id. Useful for focused deep-dives (e.g. "look only at
	// what amcache says") and for verifying the scope wiring via --dry-run.
	artifactScope := fs.String("artifact-scope", "",
		"narrow SQL prefilter to a single artifact_id (e.g. amcache). "+
			"Empty = full cross-artifact run. Scoped findings go under "+
			"findings/by-artifact/<id>/ instead of findings/.")
	// Wave 22 (introduced) + Wave 42 (default flipped on):
	// --sliding-window enables chunked Tactic Agent execution for cases
	// where the matched event set exceeds --max-events. Without it, the
	// runner truncates to the first MaxEvents rows ordered by ts_utc
	// ASC — so late-stage attack signals (Persistence Run keys written
	// at the end, Impact stage, etc.) get cut off on big cases (B1
	// indictment, Mandiant 7-day dwell time). Wave 42 makes this the
	// default; pass `--sliding-window=false` to restore the old single-
	// window truncation behaviour.
	slidingWindow := fs.Bool("sliding-window", true,
		"chunk Tactic Agent runs into overlapping windows when match set "+
			"> --max-events (Wave 22 / DESIGN v0.3 #3; default on as of Wave 42 — "+
			"pass --sliding-window=false to disable)")
	windowOverlap := fs.Float64("window-overlap", 0.2,
		"overlap fraction (0.0-0.5) between adjacent windows; only used with --sliding-window")
	if err := fs.Parse(rest); err != nil {
		return err
	}

	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if *engine == "anthropic-api" && apiKey == "" && !*dryRun {
		return fmt.Errorf("engine=anthropic-api requires ANTHROPIC_API_KEY " +
			"(use --engine claude-code or --dry-run)")
	}

	// Resolve all evidence_ids from DB; primary is the explicit --evidence-id
	// or the first registered evidence. Full list is stamped on the report
	// for cross-evidence correlation (★v0.3 #7).
	allEvIDs := []string{}
	{
		mgr, err := casedb.Open(*dbPath, casedb.ReadOnly)
		if err != nil {
			return fmt.Errorf("open db: %w", err)
		}
		ctx := context.Background()
		evList, err := mgr.ListEvidence(ctx, caseID)
		_ = mgr.Close()
		if err != nil {
			return fmt.Errorf("list evidence: %w", err)
		}
		if len(evList) == 0 {
			return fmt.Errorf("case %q has no registered evidence", caseID)
		}
		for _, e := range evList {
			allEvIDs = append(allEvIDs, e.EvidenceID)
		}
		if *evID == "" {
			*evID = allEvIDs[0]
		}
	}

	// Wave 20a: timeoutSec=0 → dynamic compute. Else honour the flag verbatim.
	timeout := time.Duration(*timeoutSec) * time.Second
	if *timeoutSec == 0 {
		timeout = agents.ComputeTimeout(*tactic, *maxEvents)
	}
	cfg := agents.Config{
		Tactic:      *tactic,
		Engine:      *engine,
		APIKey:        apiKey,
		Model:         *model,
		MaxEvents:     *maxEvents,
		MaxIters:      *maxIters,
		Timeout:       timeout,
		DBPath:        *dbPath,
		DryRun:        *dryRun,
		EvidenceIDs:   allEvIDs,
		ArtifactScope: *artifactScope, // Wave 20h
		SlidingWindow: *slidingWindow, // Wave 22
		WindowOverlap: *windowOverlap, // Wave 22
	}
	runner, err := agents.New(cfg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	if *dryRun {
		// Wave 20c: anomaly_hunter is not in TacticRegistry (Tier 1.5 has
		// its own harness), so Runner.DryRun would fail with "unknown
		// tactic". Branch to AnomalyHunter.DryRun which builds the
		// equivalent prompt + candidate window.
		if *tactic == "anomaly_hunter" {
			findingsDir := *outDir
			if findingsDir == "" {
				findingsDir = filepath.Join("outputs", "cases", caseID, "findings")
			}
			ah, err := agents.NewAnomalyHunter(agents.AnomalyConfig{
				CaseID: caseID, EvidenceID: *evID, EvidenceIDs: allEvIDs,
				FindingsDir: findingsDir, DBPath: *dbPath,
				Engine: *engine, APIKey: apiKey, Model: *model,
				MaxEvents: *maxEvents, MaxIters: *maxIters, Timeout: cfg.Timeout,
			})
			if err != nil {
				return err
			}
			info, err := ah.DryRun(ctx)
			if err != nil {
				return err
			}
			fmt.Printf("DRY RUN — no API call made (anomaly_hunter / Tier 1.5)\n")
			fmt.Printf("  tactic=anomaly_hunter case=%s evidence=%s model=%s\n",
				caseID, *evID, *model)
			fmt.Printf("  events_total_scanned=%d  events_in_window=%d  truncated=%v\n",
				info.EventsScanned, info.EventsInWindow, info.Truncated)
			fmt.Printf("  lenses_applied: %d (%s)\n",
				len(info.Lenses), strings.Join(info.Lenses, ", "))
			fmt.Printf("  system_prompt: %d chars (~%d tokens)\n",
				len(info.SystemPrompt), len(info.SystemPrompt)/4)
			fmt.Printf("  user_message:  %d chars (~%d tokens)\n",
				len(info.UserMessage), len(info.UserMessage)/4)
			budget := cfg.Timeout
			budgetSrc := "auto-compute"
			if *timeoutSec != 0 {
				budgetSrc = "explicit --timeout-seconds"
			}
			fmt.Printf("  wall_clock_budget: %v  (%s; max_events=%d)\n",
				budget, budgetSrc, *maxEvents)
			return nil
		}

		sys, user, w, total, err := runner.DryRun(ctx, caseID, *evID)
		if err != nil {
			return err
		}
		fmt.Printf("DRY RUN — no API call made\n")
		fmt.Printf("  tactic=%s case=%s evidence=%s model=%s\n",
			*tactic, caseID, *evID, *model)
		if *artifactScope != "" {
			fmt.Printf("  artifact_scope=%s (SQL prefilter narrowed)\n", *artifactScope)
		}
		fmt.Printf("  events_total_match=%d  events_in_window=%d  truncated=%v\n",
			total, w.Total, w.Truncated)
		fmt.Printf("  counts_by_artifact: %v\n", w.Counts)
		fmt.Printf("  system_prompt: %d chars (~%d tokens)\n", len(sys), len(sys)/4)
		fmt.Printf("  user_message:  %d chars (~%d tokens)\n", len(user), len(user)/4)
		// Wave 25: sliding window cost estimate. When --sliding-window is on
		// AND total > MaxEvents, real Run() will execute multiple LLM calls.
		// Show the projected window count + total token estimate so the
		// operator can spot a runaway plan before paying.
		if *slidingWindow && total > *maxEvents {
			overlap := *windowOverlap
			if overlap <= 0 || overlap > 0.5 {
				overlap = 0.2
			}
			stride := int(float64(*maxEvents) * (1.0 - overlap))
			if stride < 1 {
				stride = 1
			}
			windowCount := 1 + (total-*maxEvents+stride-1)/stride
			estTokensPerWin := (len(sys) + len(user)) / 4
			estTotalTokens := windowCount * estTokensPerWin
			fmt.Printf("  sliding_window: %d windows (stride=%d, overlap=%.0f%%)\n",
				windowCount, stride, overlap*100)
			fmt.Printf("  est_total_input_tokens: ~%d (= %d windows × ~%d tokens/window)\n",
				estTotalTokens, windowCount, estTokensPerWin)
		} else if *slidingWindow {
			fmt.Printf("  sliding_window: 1 window (fallback, total %d ≤ max %d)\n",
				total, *maxEvents)
		}
		// Wave 20a: surface the computed wall-clock budget so operators
		// can verify ComputeTimeout / env-var overrides without running
		// a real LLM call.
		budget := cfg.Timeout
		budgetSrc := "auto-compute"
		if *timeoutSec != 0 {
			budgetSrc = "explicit --timeout-seconds"
		}
		fmt.Printf("  wall_clock_budget: %v  (%s; max_events=%d)\n",
			budget, budgetSrc, *maxEvents)
		return nil
	}

	modelDisplay := *model
	if modelDisplay == "" {
		modelDisplay = "<engine default>"
	}
	fmt.Fprintf(os.Stderr,
		"running %s agent on case=%s evidence=%s (engine=%s, model=%s)...\n",
		*tactic, caseID, *evID, *engine, modelDisplay)

	var report *agents.TacticReport
	var runErr error
	if *tactic == "anomaly_hunter" {
		// Tier 1.5 — different harness, but writes to the same findings
		// dir using the same TacticReport schema.
		findingsDir := *outDir
		if findingsDir == "" {
			findingsDir = filepath.Join("outputs", "cases", caseID, "findings")
		}
		ah, ahErr := agents.NewAnomalyHunter(agents.AnomalyConfig{
			CaseID:      caseID,
			EvidenceID:  *evID,
			EvidenceIDs: allEvIDs, // ★v0.3 #7
			FindingsDir: findingsDir,
			DBPath:      *dbPath,
			Engine:      *engine,
			APIKey:      apiKey,
			Model:       *model,
			MaxEvents:   *maxEvents,
			MaxIters:    *maxIters,
			Timeout:     timeout, // Wave 20a: shared with the regular runner
			DryRun:      *dryRun,
		})
		if ahErr != nil {
			return ahErr
		}
		report, runErr = ah.Run(ctx)
	} else {
		report, runErr = runner.Run(ctx, caseID, *evID)
	}

	// Persist whatever we got — even partial / failed reports help debugging.
	// Wave 20h: when --artifact-scope is set and --out-dir wasn't explicit,
	// nest under findings/by-artifact/<scope>/ to mirror the web handler
	// (runOneTacticScoped) layout. Keeps full-case findings/<tactic>.json
	// untouched so the synthesizer / review UI continue to read the
	// canonical case-wide view.
	target := *outDir
	if target == "" {
		if *artifactScope != "" {
			target = filepath.Join("outputs", "cases", caseID,
				"findings", "by-artifact", *artifactScope)
		} else {
			target = filepath.Join("outputs", "cases", caseID, "findings")
		}
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return fmt.Errorf("mkdir out: %w", err)
	}
	outPath := filepath.Join(target, *tactic+".json")
	if report != nil {
		body, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal report: %w", err)
		}
		if err := os.WriteFile(outPath, body, 0o644); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
	}

	if report != nil {
		printAnalyzeSummary(outPath, report)
	}
	if runErr != nil {
		return runErr
	}
	return nil
}

// runReport renders a CaseSynthesis into HTML / CSV / JSON. Reads from
// outputs/cases/<id>/synthesis.json, writes to outputs/cases/<id>/reports/.
func runReport(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: tlvb report CASE_ID [--format html,csv,json] [...]")
	}
	caseID := args[0]
	rest := args[1:]
	if strings.HasPrefix(caseID, "-") {
		return fmt.Errorf("first argument must be CASE_ID, got %q", caseID)
	}

	// TLVB v0.1: `tlvb report CASE_ID --tier 3` renders Tier 2's
	// CaseSynthesis (TLVB schema) instead of the legacy findevil
	// reporter (TacticReport schema).
	for i, a := range rest {
		if a == "--tier" && i+1 < len(rest) && rest[i+1] == "3" {
			inner := append([]string{}, rest[:i]...)
			inner = append(inner, rest[i+2:]...)
			return runReportTier3(caseID, inner)
		}
		if strings.ToLower(a) == "--tier=3" {
			inner := append([]string{}, rest[:i]...)
			inner = append(inner, rest[i+1:]...)
			return runReportTier3(caseID, inner)
		}
	}

	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	formatStr := fs.String("format", "html,csv,json",
		"comma-separated subset of html,csv,json")
	lang := fs.String("language", "ja", "report language: ja | en")
	synthPath := fs.String("synthesis", "",
		"input synthesis.json path (default: outputs/cases/<id>/synthesis.json)")
	outDir := fs.String("out-dir", "",
		"output dir (default: outputs/cases/<id>/reports)")
	onlyApproved := fs.Bool("only-approved", false,
		"only render findings where Approved=true (post Review Gate 1)")
	if err := fs.Parse(rest); err != nil {
		return err
	}

	if *synthPath == "" {
		*synthPath = filepath.Join("outputs", "cases", caseID, "synthesis.json")
	}
	if *outDir == "" {
		*outDir = filepath.Join("outputs", "cases", caseID, "reports")
	}

	formats := []string{}
	for _, f := range strings.Split(*formatStr, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			formats = append(formats, f)
		}
	}

	cfg := reporter.Config{
		CaseID:        caseID,
		SynthesisPath: *synthPath,
		OutDir:        *outDir,
		Formats:       formats,
		Language:      *lang,
		OnlyApproved:  *onlyApproved,
	}
	res, err := reporter.Render(cfg)
	if err != nil {
		return err
	}
	printReportSummary(res)
	return nil
}

func printReportSummary(res *reporter.Result) {
	fmt.Printf("\nReport written to %s\n", res.OutDir)
	fmt.Printf("  case=%s  generated_at=%s\n",
		res.CaseID, res.GeneratedAt.UTC().Format(time.RFC3339))
	if res.Sections > 0 {
		fmt.Printf("  html_sections=%d\n", res.Sections)
	}
	for _, f := range res.Files {
		fmt.Printf("  [%-13s] %-60s  %d bytes\n", f.Format, f.Path, f.SizeBytes)
	}
}

// runSynthesize aggregates Tactic Reports for a case, runs consistency
// checks (R1–R4), builds a chronological timeline, and emits a
// CaseSynthesis JSON document. Deterministic — no LLM call required.
func runSynthesize(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: tlvb synthesize CASE_ID [...]")
	}
	caseID := args[0]
	rest := args[1:]
	if strings.HasPrefix(caseID, "-") {
		return fmt.Errorf("first argument must be CASE_ID, got %q", caseID)
	}

	// TLVB v0.1: `tlvb synthesize CASE_ID --tier 2` routes to the new
	// Tier 2 Timeline Analysis Agent. Without --tier, the legacy
	// findevil synthesizer runs (still works for TacticReport-format
	// findings). Same prescan pattern as analyze --tier 1a|1b.
	for i, a := range rest {
		if a == "--tier" && i+1 < len(rest) && rest[i+1] == "2" {
			inner := append([]string{}, rest[:i]...)
			inner = append(inner, rest[i+2:]...)
			return runSynthesizeTier2(caseID, inner)
		}
		if strings.ToLower(a) == "--tier=2" {
			inner := append([]string{}, rest[:i]...)
			inner = append(inner, rest[i+1:]...)
			return runSynthesizeTier2(caseID, inner)
		}
	}

	fs := flag.NewFlagSet("synthesize", flag.ContinueOnError)
	findingsDir := fs.String("findings-dir", "",
		"directory containing TacticReport JSONs "+
			"(default: outputs/cases/<case-id>/findings)")
	dbPath := fs.String("db", "outputs/cases.duckdb", "case DuckDB path")
	evID := fs.String("evidence-id", "",
		"evidence_id to record in the synthesis (default: first evidence)")
	tz := fs.String("timezone", "UTC", "display timezone for the synthesis")
	out := fs.String("out", "",
		"output JSON path (default: outputs/cases/<case-id>/synthesis.json)")
	correct := fs.Bool("correct", false,
		"run Tier 2 Corrector loop after the initial consistency check "+
			"(re-runs Tactic Agents whose inconsistency rules fired)")
	correctEngine := fs.String("correct-engine", "claude-code",
		"Tactic Agent engine for correction re-runs")
	correctModel := fs.String("correct-model", "",
		"model override for correction re-runs (engine default if empty)")
	reviewTimeline := fs.Bool("review-timeline", false,
		"run the Tier 2 TimelineReviewer LLM pass after consistency / "+
			"correction. Applies the 12 forensic perspectives in "+
			"skills/timeline_review.md. Graceful on LLM unavailability.")
	tlEngine := fs.String("review-engine", "claude-code",
		"engine for the TimelineReviewer pass (claude-code | anthropic-api)")
	tlModel := fs.String("review-model", "",
		"model override for the TimelineReviewer pass (engine default if empty)")
	tlLanguage := fs.String("review-language", "ja",
		"output language for TimelineReviewer prose (ja | en)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *findingsDir == "" {
		*findingsDir = filepath.Join("outputs", "cases", caseID, "findings")
	}
	if *out == "" {
		*out = filepath.Join("outputs", "cases", caseID, "synthesis.json")
	}

	// Resolve every evidence_id in the case (★v0.3 #7). Primary evidence is
	// the explicit --evidence-id or the first registered.
	allEvIDs := []string{}
	if mgr, err := casedb.Open(*dbPath, casedb.ReadOnly); err == nil {
		ctx := context.Background()
		if evList, _ := mgr.ListEvidence(ctx, caseID); len(evList) > 0 {
			for _, e := range evList {
				allEvIDs = append(allEvIDs, e.EvidenceID)
			}
			if *evID == "" {
				*evID = allEvIDs[0]
			}
		}
		_ = mgr.Close()
	}

	cfg := synthesizer.Config{
		CaseID:      caseID,
		EvidenceID:  *evID,
		EvidenceIDs: allEvIDs, // ★v0.3 #7
		Timezone:    *tz,
		FindingsDir: *findingsDir,
		DBPath:      *dbPath,
		Correct:     *correct,
		Language:    *tlLanguage, // Wave 26 — drives Recommendations ja/en
	}
	if *correct {
		// Wave 20a: corrector も動的 timeout に揃える。
		const correctorMaxEvents = 100
		cfg.CorrectorCfg = synthesizer.CorrectionConfig{
			Engine:       *correctEngine,
			APIKey:       os.Getenv("ANTHROPIC_API_KEY"),
			Model:        *correctModel,
			MaxRounds:    1,
			AgentTimeout: agents.ComputeTimeout("", correctorMaxEvents),
			MaxEvents:    correctorMaxEvents,
			MaxIters:     3,
		}
	}
	if *reviewTimeline {
		// Timeline review consumes the timeline + findings rather than
		// raw events; size with a representative event count (= 100).
		cfg.ReviewTimeline = true
		cfg.TimelineReviewCfg = synthesizer.TimelineReviewConfig{
			Language:    *tlLanguage,
			Engine:      *tlEngine,
			APIKey:      os.Getenv("ANTHROPIC_API_KEY"),
			Model:       *tlModel,
			MaxTokens:   50000,
			Timeout:     agents.ComputeTimeout("", 100),
			SkillsDir:   "skills",
			MaxExcerpt:  200,
			MaxFindings: 50,
		}
	}
	// Wave 20a: parent budget = ceiling × safety margin so individual
	// corrector / timeline-review steps don't get pre-emptively SIGKILLed.
	overallTimeout := 30 * time.Minute
	if *correct {
		overallTimeout = 90 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), overallTimeout)
	defer cancel()

	cs, err := synthesizer.Synthesize(ctx, cfg)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(cs, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, body, 0o644); err != nil {
		return err
	}

	printSynthesisSummary(*out, cs)
	return nil
}

func printSynthesisSummary(outPath string, cs *synthesizer.CaseSynthesis) {
	fmt.Printf("\nCaseSynthesis written to %s\n", outPath)
	fmt.Printf("  case=%s evidence=%s tz=%s reports=%d\n",
		cs.CaseID, cs.EvidenceID, cs.Timezone, cs.Audit.ReportsAggregated)
	fmt.Printf("  total_findings=%d  clusters=%d  merged=%d  unique_evidence=%d\n",
		cs.Stats.TotalFindings, cs.Stats.ClusterCount,
		cs.Stats.MergedFindings, cs.Stats.UniqueEvidenceIDs)
	fmt.Printf("  timeline_rows=%d  unresolved_audit_ids=%d  exec_seconds=%.2f\n",
		len(cs.Timeline), cs.Audit.UnresolvedRefCount,
		cs.Audit.ExecutionTimeSeconds)

	if len(cs.IntrusionPath) > 0 {
		fmt.Printf("\n  intrusion_path:\n")
		for _, s := range cs.IntrusionPath {
			fmt.Printf("    %d. %s (%s) %s — %s\n",
				s.Step, s.Tactic, s.TacticName,
				s.Timestamp.UTC().Format(time.RFC3339),
				truncate(s.Description, 80))
		}
	}

	if len(cs.Inconsistencies) > 0 {
		fmt.Printf("\n  inconsistencies:\n")
		for _, i := range cs.Inconsistencies {
			fmt.Printf("    [%s/%s] %s\n",
				i.Rule, i.Severity, truncate(i.Description, 100))
		}
	}

	if cs.CorrectionReport != nil {
		cr := cs.CorrectionReport
		fmt.Printf("\n  corrector:\n")
		fmt.Printf("    rounds_run=%d  agents_retried=%v\n",
			cr.RoundsRun, cr.AgentsRetried)
		fmt.Printf("    new_findings_added=%v\n", cr.NewFindingsAdded)
		fmt.Printf("    resolved=%v  unresolved=%v\n",
			cr.ResolvedRules, cr.UnresolvedRules)
		for _, d := range cr.Diagnostics {
			fmt.Printf("    [%s/%s] status=%s new=%d  dur=%.1fs\n",
				d.Rule, d.Tactic, d.Status, d.NewCount, d.DurationS)
		}
	}

	if len(cs.MITREMapping) > 0 {
		fmt.Printf("\n  mitre_mapping (%d entries):\n", len(cs.MITREMapping))
		shown := cs.MITREMapping
		if len(shown) > 8 {
			shown = shown[:8]
		}
		for _, m := range shown {
			fmt.Printf("    %s/%s  findings=%d  evidence=%d  conf=%s\n",
				m.Tactic, m.Technique, m.FindingCount,
				m.EvidenceCount, m.Confidence)
		}
		if len(cs.MITREMapping) > 8 {
			fmt.Printf("    ... +%d more\n", len(cs.MITREMapping)-8)
		}
	}

	fmt.Printf("\n  executive_summary: %s\n",
		truncate(cs.ExecutiveSummary, 240))

	if cs.TimelineReview != nil {
		tr := cs.TimelineReview
		fmt.Printf("\n  timeline_review (%s):\n", tr.Schema)
		if tr.Audit.SkippedReason != "" {
			fmt.Printf("    SKIPPED: %s\n", tr.Audit.SkippedReason)
		} else {
			s := tr.SummaryStats
			fmt.Printf("    obs=%d (info=%d warn=%d crit=%d) dwell=%.1fh hosts=%d tactics=%d\n",
				len(tr.Observations),
				s.ObservationsBySeverity["info"],
				s.ObservationsBySeverity["warning"],
				s.ObservationsBySeverity["critical"],
				s.DwellTimeHours, s.HostCount, s.TacticsObservedCount)
			if tr.Audit.PhantomIDsDropped > 0 {
				fmt.Printf("    phantom_audit_ids_dropped=%d\n", tr.Audit.PhantomIDsDropped)
			}
			for _, o := range tr.Observations {
				fmt.Printf("    [%s/%s] %s — %s\n",
					o.Perspective, o.Severity, o.ObservationID,
					truncate(o.Summary, 80))
			}
			if tr.Narrative != "" {
				fmt.Printf("    narrative: %s\n", truncate(tr.Narrative, 200))
			}
		}
	}
}

func printAnalyzeSummary(outPath string, r *agents.TacticReport) {
	fmt.Printf("\nTacticReport written to %s\n", outPath)
	fmt.Printf("  tactic=%s case=%s evidence=%s\n",
		r.TacticID, r.CaseID, r.EvidenceID)
	fmt.Printf("  status=%s findings=%d negatives=%d open_questions=%d\n",
		r.Status, len(r.Findings), len(r.NegativeFindings), len(r.OpenQuestions))
	fmt.Printf("  model=%s iters=%d input_events=%d tok_in=%d tok_out=%d cache_read=%d duration=%.1fs\n",
		r.Audit.ModelID, r.Audit.Iterations, r.Audit.InputEvents,
		r.Audit.TokensInput, r.Audit.TokensOutput, r.Audit.CacheHitTok,
		r.Audit.DurationSec)
	if !r.Audit.ValidationOK {
		fmt.Printf("  validation_err: %s\n", truncate(r.Audit.ValidationErr, 200))
	}
	for _, f := range r.Findings {
		fmt.Printf("  - %s [%s] conf=%s evidence=%d  %s\n",
			f.FindingID, f.TechniqueID, f.Confidence,
			len(f.Evidence), truncate(f.Summary, 80))
	}
}

// runReview opens an interactive Gate 1 session for a case. The Examiner
// can a/r/s/q each finding; results are persisted to the TacticReport
// JSON files in-place.
func runReview(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: tlvb review CASE_ID [--gate 1] [--examiner NAME]")
	}
	caseID := args[0]
	rest := args[1:]
	if strings.HasPrefix(caseID, "-") {
		return fmt.Errorf("first argument must be CASE_ID, got %q", caseID)
	}

	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	gate := fs.Int("gate", 1, "review gate id (1 = findings; 0/2 reserved)")
	examiner := fs.String("examiner", "examiner-cli", "name recorded in ReviewedBy")
	findingsDir := fs.String("findings-dir", "",
		"override findings dir (default: outputs/cases/<id>/findings)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *findingsDir == "" {
		*findingsDir = filepath.Join("outputs", "cases", caseID, "findings")
	}
	if *gate != 1 {
		return fmt.Errorf("only --gate 1 is implemented in this build")
	}

	res, err := review.RunGate1(review.Config{
		CaseID:      caseID,
		FindingsDir: *findingsDir,
		Examiner:    *examiner,
	})
	if err != nil {
		return err
	}

	fmt.Printf("\nReview session — case=%s gate=%d examiner=%s\n",
		caseID, *gate, *examiner)
	fmt.Printf("  approved=%d  rejected=%d  skipped=%d  quit=%v\n",
		res.Approved, res.Rejected, res.Skipped, res.Quit)
	fmt.Printf("  files updated: %d\n", len(res.Touched))
	for _, p := range res.Touched {
		fmt.Printf("    %s\n", p)
	}
	return nil
}

// runFullPipeline implements `tlvb run` — Tier 0 → Tier 1 (×10) →
// Tier 1.5 → Tier 2 (with Corrector) → Tier 3, in sequence, with timing
// and graceful degradation per the CLAUDE.md "1 agent failure ≠ case
// abort" rule.
func runFullPipeline(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: tlvb run CASE_ID --evidence PATH [...]")
	}
	caseID := args[0]
	rest := args[1:]
	if strings.HasPrefix(caseID, "-") {
		return fmt.Errorf("first argument must be CASE_ID, got %q", caseID)
	}

	// TLVB v0.1: `tlvb run CASE_ID --tier all --evidence PATH` runs the
	// new TLVB pipeline (parse → analyze 1a → analyze 1b → synthesize 2
	// → report 3). Without --tier, the legacy findevil tactic-based
	// pipeline runs. Same prescan pattern as analyze / synthesize / report.
	for i, a := range rest {
		if a == "--tier" && i+1 < len(rest) && strings.ToLower(rest[i+1]) == "all" {
			inner := append([]string{}, rest[:i]...)
			inner = append(inner, rest[i+2:]...)
			return runPipelineTLVB(caseID, inner)
		}
		if strings.ToLower(a) == "--tier=all" {
			inner := append([]string{}, rest[:i]...)
			inner = append(inner, rest[i+1:]...)
			return runPipelineTLVB(caseID, inner)
		}
	}

	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	evID := fs.String("evidence-id", "EV-001", "evidence id to register")
	evPath := fs.String("evidence", "",
		"path to .zip or directory of evidence (required if not yet registered)")
	dbPath := fs.String("db", "outputs/cases.duckdb", "case DuckDB path")
	engine := fs.String("engine", "claude-code", "Tactic Agent engine")
	model := fs.String("model", "", "model override")
	caseName := fs.String("name", "", "case name (required if case not yet inited)")
	examiner := fs.String("examiner", "examiner-cli",
		"examiner name (used for case init only; Review is separate)")
	skipParse := fs.Bool("skip-parse", false,
		"skip Tier 0 (use when evidence already parsed in this DB)")
	skipAnalyze := fs.Bool("skip-analyze", false,
		"skip Tier 1 (use when 10 TacticReports already exist)")
	skipAnomaly := fs.Bool("skip-anomaly", false, "skip Tier 1.5 Anomaly Hunter")
	skipCorrect := fs.Bool("skip-correct", false, "skip Tier 2 Corrector loop")
	tactics := fs.String("tactics",
		"initial_access,execution,persistence,privilege_escalation,"+
			"defense_evasion,credential_access,discovery,lateral_movement,"+
			"collection,impact",
		"comma-separated tactic slugs to run in Tier 1")
	if err := fs.Parse(rest); err != nil {
		return err
	}

	pipelineStarted := time.Now().UTC()
	fmt.Printf("[run] case=%s started %s\n", caseID, pipelineStarted.Format(time.RFC3339))

	// --- Tier 0a — case init (idempotent) ----------------------------------
	mgr, err := casedb.Open(*dbPath, casedb.ReadWrite)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	cases, err := mgr.ListCases(context.Background())
	if err != nil {
		_ = mgr.Close()
		return fmt.Errorf("list cases: %w", err)
	}
	caseExists := false
	for _, c := range cases {
		if c.CaseID == caseID {
			caseExists = true
			break
		}
	}
	if !caseExists {
		if *caseName == "" {
			_ = mgr.Close()
			return fmt.Errorf("case %q does not exist; pass --name to create it", caseID)
		}
		if err := mgr.RegisterCase(context.Background(), casedb.CaseRow{
			CaseID:    caseID,
			Name:      *caseName,
			Examiner:  *examiner,
			Timezone:  "UTC",
			CreatedAt: time.Now().UTC(),
		}); err != nil {
			_ = mgr.Close()
			return fmt.Errorf("register case: %w", err)
		}
		fmt.Printf("[run] case-init  ok  (new case)\n")
	} else {
		fmt.Printf("[run] case-init  ok  (existing)\n")
	}
	_ = mgr.Close()

	// --- Tier 0b — parse ---------------------------------------------------
	if !*skipParse {
		if *evPath == "" {
			return fmt.Errorf("--evidence is required unless --skip-parse")
		}
		t0 := time.Now()
		if err := runParseInternal(caseID, *evID, *evPath, *dbPath); err != nil {
			return fmt.Errorf("tier0 parse: %w", err)
		}
		fmt.Printf("[run] tier0      ok  in %.1fs\n", time.Since(t0).Seconds())
	} else {
		fmt.Printf("[run] tier0      skip\n")
	}

	// --- Tier 1 — Tactic Agents ×N ----------------------------------------
	if !*skipAnalyze {
		t1 := time.Now()
		tacticList := []string{}
		for _, t := range strings.Split(*tactics, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tacticList = append(tacticList, t)
			}
		}
		var failed []string
		total := len(tacticList)
		for i, tac := range tacticList {
			// Wave 28: per-tactic visual progress. Prints a one-line
			// progress bar before kicking off, then overwrites with
			// the result. Stderr-bound so it doesn't pollute stdout
			// pipelines.
			printRunProgress("tier1", i, total, tac, "running")
			ts := time.Now()
			err := runAnalyzeInternal(caseID, *evID, tac, *engine, *model, *dbPath)
			elapsed := time.Since(ts).Seconds()
			if err != nil {
				fmt.Printf("[run] tier1.%s  FAIL %.1fs: %v\n", tac, elapsed, err)
				failed = append(failed, tac)
				continue
			}
			fmt.Printf("[run] tier1.%s  ok %.1fs\n", tac, elapsed)
		}
		printRunProgress("tier1", total, total, "done", "complete")
		fmt.Printf("[run] tier1      ok  in %.1fs (%d/%d completed)\n",
			time.Since(t1).Seconds(), total-len(failed), total)
	} else {
		fmt.Printf("[run] tier1      skip\n")
	}

	// --- Tier 1.5 — Anomaly Hunter ----------------------------------------
	if !*skipAnomaly {
		t15 := time.Now()
		err := runAnalyzeInternal(caseID, *evID, "anomaly_hunter", *engine, *model, *dbPath)
		elapsed := time.Since(t15).Seconds()
		if err != nil {
			fmt.Printf("[run] tier1.5    FAIL %.1fs: %v\n", elapsed, err)
		} else {
			fmt.Printf("[run] tier1.5    ok  in %.1fs\n", elapsed)
		}
	} else {
		fmt.Printf("[run] tier1.5    skip\n")
	}

	// --- Tier 2 — Synthesizer (with Corrector) ----------------------------
	t2 := time.Now()
	// Pull all evidence_ids for the case (★v0.3 #7).
	pipelineEvIDs := []string{*evID}
	if mgr, err := casedb.Open(*dbPath, casedb.ReadOnly); err == nil {
		ctx := context.Background()
		if evList, _ := mgr.ListEvidence(ctx, caseID); len(evList) > 0 {
			pipelineEvIDs = pipelineEvIDs[:0]
			for _, e := range evList {
				pipelineEvIDs = append(pipelineEvIDs, e.EvidenceID)
			}
		}
		_ = mgr.Close()
	}
	syntCfg := synthesizer.Config{
		CaseID:      caseID,
		EvidenceID:  *evID,
		EvidenceIDs: pipelineEvIDs,
		Timezone:    "UTC",
		FindingsDir: filepath.Join("outputs", "cases", caseID, "findings"),
		DBPath:      *dbPath,
		Correct:     !*skipCorrect,
		Language:    "ja", // Wave 26 default for `tlvb run` pipeline
	}
	if !*skipCorrect {
		syntCfg.CorrectorCfg = synthesizer.CorrectionConfig{
			Engine:       *engine,
			APIKey:       os.Getenv("ANTHROPIC_API_KEY"),
			Model:        *model,
			MaxRounds:    1,
			AgentTimeout: 10 * time.Minute,
			MaxEvents:    200,
			MaxIters:     3,
		}
	}
	syntTimeout := 5 * time.Minute
	if !*skipCorrect {
		syntTimeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), syntTimeout)
	cs, err := synthesizer.Synthesize(ctx, syntCfg)
	cancel()
	if err != nil {
		return fmt.Errorf("tier2 synthesize: %w", err)
	}
	synthOut := filepath.Join("outputs", "cases", caseID, "synthesis.json")
	body, err := json.MarshalIndent(cs, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(synthOut, body, 0o644); err != nil {
		return err
	}
	fmt.Printf("[run] tier2      ok  in %.1fs (findings=%d clusters=%d inconsistencies=%d)\n",
		time.Since(t2).Seconds(),
		cs.Stats.TotalFindings, cs.Stats.ClusterCount, len(cs.Inconsistencies))

	// --- Tier 3 — Reporter ------------------------------------------------
	t3 := time.Now()
	rcfg := reporter.Config{
		CaseID:        caseID,
		SynthesisPath: synthOut,
		OutDir:        filepath.Join("outputs", "cases", caseID, "reports"),
		Formats:       []string{"html", "csv", "json"},
		Language:      "ja",
	}
	res, err := reporter.Render(rcfg)
	if err != nil {
		return fmt.Errorf("tier3 report: %w", err)
	}
	fmt.Printf("[run] tier3      ok  in %.1fs (%d files)\n",
		time.Since(t3).Seconds(), len(res.Files))
	for _, f := range res.Files {
		fmt.Printf("              %-13s %s  %d bytes\n", f.Format, f.Path, f.SizeBytes)
	}

	fmt.Printf("\n[run] DONE  case=%s  total=%.1fs\n",
		caseID, time.Since(pipelineStarted).Seconds())
	return nil
}

// runParseInternal calls the Python orchestrator the same way `runParse`
// does, but with parameters injected programmatically.
func runParseInternal(caseID, evID, input, dbPath string) error {
	abs, err := filepath.Abs(input)
	if err != nil {
		return err
	}
	workspace := filepath.Join("outputs", "cases", caseID)
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		return err
	}

	// SHA-256 fingerprint + evidence registration (mirrors runParse).
	mgr, err := casedb.Open(dbPath, casedb.ReadWrite)
	if err != nil {
		return err
	}
	sha, size, err := evidenceFingerprint(abs)
	if err != nil {
		_ = mgr.Close()
		return err
	}
	_ = mgr.RegisterEvidence(context.Background(), casedb.EvidenceRow{
		EvidenceID:   evID,
		CaseID:       caseID,
		Path:         abs,
		SHA256:       sha,
		SizeBytes:    size,
		EvidenceType: detectEvidenceType(abs),
		RegisteredAt: time.Now().UTC(),
	})
	_ = mgr.Close()

	cmd := exec.Command(common.ResolvePython(), "-m", "parsers.orchestrator",
		"--case-id", caseID, "--evidence-id", evID,
		"--input", abs, "--db", dbPath, "--workspace", workspace,
		"--report-json", "/dev/null")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runAnalyzeInternal mirrors runAnalyze for one tactic, used by `run`.
func runAnalyzeInternal(caseID, evID, tactic, engine, model, dbPath string) error {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if engine == "anthropic-api" && apiKey == "" {
		return fmt.Errorf("engine=anthropic-api requires ANTHROPIC_API_KEY")
	}

	// Pull all evidence_ids so the report stamps the full case scope (★v0.3 #7).
	allEvIDs := []string{evID}
	if mgr, err := casedb.Open(dbPath, casedb.ReadOnly); err == nil {
		ctx := context.Background()
		if evList, _ := mgr.ListEvidence(ctx, caseID); len(evList) > 0 {
			allEvIDs = allEvIDs[:0]
			for _, e := range evList {
				allEvIDs = append(allEvIDs, e.EvidenceID)
			}
		}
		_ = mgr.Close()
	}

	cfg := agents.Config{
		Tactic:      tactic,
		Engine:      engine,
		APIKey:      apiKey,
		Model:       model,
		MaxEvents:   200,
		MaxIters:    3,
		Timeout:     10 * time.Minute,
		DBPath:      dbPath,
		EvidenceIDs: allEvIDs,
	}
	if tactic != "anomaly_hunter" {
		runner, err := agents.New(cfg)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
		defer cancel()
		report, err := runner.Run(ctx, caseID, evID)
		if err != nil {
			return err
		}
		return persistTacticReport(caseID, tactic, report)
	}

	findingsDir := filepath.Join("outputs", "cases", caseID, "findings")
	ah, err := agents.NewAnomalyHunter(agents.AnomalyConfig{
		CaseID:      caseID,
		EvidenceID:  evID,
		EvidenceIDs: allEvIDs,
		FindingsDir: findingsDir,
		DBPath:      dbPath,
		Engine:      engine,
		APIKey:      apiKey,
		Model:       model,
		MaxEvents:   200,
		MaxIters:    3,
		Timeout:     cfg.Timeout,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	report, err := ah.Run(ctx)
	if err != nil {
		return err
	}
	return persistTacticReport(caseID, "anomaly_hunter", report)
}

func persistTacticReport(caseID, tactic string, report *agents.TacticReport) error {
	if report == nil {
		return fmt.Errorf("nil report")
	}
	dir := filepath.Join("outputs", "cases", caseID, "findings")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, tactic+".json"), body, 0o644)
}

// runServe boots the TLVB web UI + REST API. The UI assets are
// embedded into the binary via internal/web (uiassets.go at the repo root).
//
// Long-running pipeline steps (parse / analyze / synthesize / report)
// execute in goroutines tracked by an in-memory JobsManager; the UI
// polls /api/cases/<id>/<step>/status for progress.
func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	port := fs.Int("port", 8080, "HTTP listen port")
	addr := fs.String("addr", "", "explicit listen addr (overrides --port; e.g. 127.0.0.1:8080)")
	dbPath := fs.String("db", "outputs/cases.duckdb", "case DuckDB path")
	rulesDB := fs.String("rules-db", "outputs/rules.duckdb", "rules DuckDB path (Rule Library view)")
	outputs := fs.String("outputs", filepath.Join("outputs", "cases"), "case workspaces root")
	logLevel := fs.String("log-level", "info", "debug|info|warn|error")
	envFile := fs.String("env-file", ".env.local",
		"path to a KEY=VALUE file loaded into env (existing env vars win); "+
			"missing file is silently ignored")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Load .env.local before constructing the server so ANTHROPIC_API_KEY
	// (and any other persistent dev defaults) are visible to handlers.
	// Shell-set env still wins — see internal/common/dotenv.go.
	if n, err := common.LoadDotEnv(*envFile); err != nil {
		fmt.Fprintf(os.Stderr, "warning: load %s: %v\n", *envFile, err)
	} else if n > 0 {
		fmt.Fprintf(os.Stderr, "loaded %d env vars from %s\n", n, *envFile)
	}

	level := slog.LevelInfo
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	// web.Config takes a *slog.Logger directly — common.Logger is a wrapper
	// for the MCP server use case, but here we want slog's structured methods.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	listenAddr := *addr
	if listenAddr == "" {
		listenAddr = fmt.Sprintf(":%d", *port)
	}

	srv, err := web.New(web.Config{
		Addr:        listenAddr,
		DBPath:      *dbPath,
		RulesDBPath: *rulesDB,
		OutputsRoot: *outputs,
		Logger:      logger,
	})
	if err != nil {
		return err
	}
	return srv.Start(context.Background())
}

// runCaseVacuum (Wave 20f) rebuilds the DuckDB by copying retained cases to
// a fresh DB and atomically swapping it in. Used to reclaim disk space
// when many cases were deleted from outputs/cases/<id>/ but their rows
// are still in cases.duckdb (DELETE in DuckDB doesn't shrink the file).
//
// Default behavior: keep cases that have an on-disk directory under
// --outputs (= "the user clearly still wants this case"). Override with
// --keep-cases or --drop-cases.
//
// Operation:
//   1. Read existing cases + filter to keep set
//   2. CREATE TABLE new_<table> with same schema, ATTACH '<dbpath>.new'
//   3. INSERT INTO new_cases SELECT * FROM cases WHERE case_id IN (...)
//      (same for evidence / parse_results / unified_events)
//   4. Verify row counts match expected
//   5. Move current → backup, new → current
//
// Safety:
//   - Refuses to run if the DB is locked (running server / parse)
//   - --dry-run shows what would be kept/dropped without touching disk
//   - The backup is NOT auto-deleted; operator should rm manually after
//     confirming the new DB works
func runCaseVacuum(args []string) error {
	fs := flag.NewFlagSet("case vacuum", flag.ContinueOnError)
	dbPath := fs.String("db", "outputs/cases.duckdb", "case DuckDB path")
	outputsDir := fs.String("outputs", "outputs/cases",
		"case root — cases with an on-disk dir here are kept by default")
	keepCSV := fs.String("keep-cases", "",
		"comma-separated case_ids to keep (overrides --outputs auto-detect)")
	dropCSV := fs.String("drop-cases", "",
		"comma-separated case_ids to drop (after the keep set is decided)")
	dryRun := fs.Bool("dry-run", false,
		"show what would happen without touching the DB")
	if err := fs.Parse(args); err != nil {
		return err
	}

	mgr, err := casedb.Open(*dbPath, casedb.ReadOnly)
	if err != nil {
		return fmt.Errorf("open db (lock?): %w", err)
	}
	cases, err := mgr.ListCases(context.Background())
	if err != nil {
		mgr.Close()
		return err
	}
	mgr.Close()
	if len(cases) == 0 {
		fmt.Println("no cases in DB; nothing to vacuum")
		return nil
	}

	// Decide keep set.
	keep := map[string]bool{}
	if *keepCSV != "" {
		for _, id := range strings.Split(*keepCSV, ",") {
			id = strings.TrimSpace(id)
			if id != "" {
				keep[id] = true
			}
		}
	} else {
		// Auto-detect from on-disk dirs.
		entries, err := os.ReadDir(*outputsDir)
		if err != nil {
			return fmt.Errorf("read outputs dir: %w", err)
		}
		for _, e := range entries {
			if e.IsDir() {
				keep[e.Name()] = true
			}
		}
	}
	for _, id := range strings.Split(*dropCSV, ",") {
		id = strings.TrimSpace(id)
		if id != "" {
			delete(keep, id)
		}
	}

	var keepIDs, dropIDs []string
	for _, c := range cases {
		if keep[c.CaseID] {
			keepIDs = append(keepIDs, c.CaseID)
		} else {
			dropIDs = append(dropIDs, c.CaseID)
		}
	}
	sort.Strings(keepIDs)
	sort.Strings(dropIDs)

	fmt.Printf("=== Wave 20f vacuum plan ===\n")
	fmt.Printf("DB: %s\n", *dbPath)
	fmt.Printf("keep: %d cases\n", len(keepIDs))
	for _, id := range keepIDs {
		fmt.Printf("  ✓ %s\n", id)
	}
	fmt.Printf("drop: %d cases (orphan rows)\n", len(dropIDs))
	for _, id := range dropIDs {
		fmt.Printf("  ✗ %s\n", id)
	}
	fmt.Println()

	if *dryRun {
		fmt.Println("--dry-run: not modifying DB")
		return nil
	}
	if len(dropIDs) == 0 {
		fmt.Println("nothing to drop; DB already minimal")
		return nil
	}

	// Build new DB next to current. DuckDB can't rename DB files atomically
	// while open, so we operate on plain files.
	newPath := *dbPath + ".new"
	_ = os.Remove(newPath) // remove stale aborted attempt if any

	// Re-open source read-write so we can ATTACH the new DB.
	src, err := casedb.Open(*dbPath, casedb.ReadWrite)
	if err != nil {
		return fmt.Errorf("reopen db rw: %w", err)
	}
	defer src.Close()
	sqlDB := src.DB()

	// ATTACH new DB, ensure schema, COPY filtered rows.
	if _, err := sqlDB.Exec(fmt.Sprintf("ATTACH '%s' AS newdb", newPath)); err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	defer func() {
		_, _ = sqlDB.Exec("DETACH newdb")
	}()

	// Run schema DDL on the attached DB using the same statements as
	// casedb.ensureSchema. The simplest portable way is to ask DuckDB
	// to copy the schema via CREATE OR REPLACE TABLE ... AS SELECT
	// (... LIMIT 0) which preserves column types but loses constraints.
	// For vacuum the constraints don't matter (we only insert from the
	// source DB which already validates them), but we ALSO want primary
	// key behaviour preserved so the new DB is a drop-in replacement.
	// Approach: read the DuckDB-system schema via PRAGMA, regenerate
	// CREATE statements with `CREATE TABLE newdb.X (cols, pk)`.
	tables := []string{"cases", "evidence", "parse_results", "unified_events"}
	for _, tbl := range tables {
		// CREATE TABLE newdb.<tbl> AS SELECT * FROM <tbl> WHERE case_id IN (...)
		// LIMIT 0 wouldn't preserve PK; we copy structure via DuckDB's
		// CREATE TABLE ... AS SELECT then create indexes if needed.
		// For now, structure-only via LIMIT 0:
		if _, err := sqlDB.Exec(fmt.Sprintf(
			"CREATE TABLE newdb.%s AS SELECT * FROM main.%s LIMIT 0", tbl, tbl),
		); err != nil {
			return fmt.Errorf("create newdb.%s: %w", tbl, err)
		}
	}

	// Build IN-list once.
	if len(keepIDs) == 0 {
		return fmt.Errorf("refusing to vacuum to ZERO cases — pass --keep-cases explicitly to confirm")
	}
	placeholders := make([]string, len(keepIDs))
	args2 := make([]interface{}, len(keepIDs))
	for i, id := range keepIDs {
		placeholders[i] = "?"
		args2[i] = id
	}
	inList := strings.Join(placeholders, ",")

	for _, tbl := range tables {
		q := fmt.Sprintf("INSERT INTO newdb.%s SELECT * FROM main.%s WHERE case_id IN (%s)",
			tbl, tbl, inList)
		res, err := sqlDB.Exec(q, args2...)
		if err != nil {
			return fmt.Errorf("copy %s: %w", tbl, err)
		}
		n, _ := res.RowsAffected()
		fmt.Printf("  copied %s: %d rows\n", tbl, n)
	}

	// Detach + swap.
	if _, err := sqlDB.Exec("DETACH newdb"); err != nil {
		return fmt.Errorf("detach: %w", err)
	}
	src.Close()

	backup := *dbPath + ".bak." + time.Now().UTC().Format("20060102T150405")
	if err := os.Rename(*dbPath, backup); err != nil {
		return fmt.Errorf("rename old → backup: %w", err)
	}
	if err := os.Rename(newPath, *dbPath); err != nil {
		// Restore.
		_ = os.Rename(backup, *dbPath)
		return fmt.Errorf("rename new → current: %w", err)
	}
	fmt.Printf("\n✓ vacuum complete. Backup: %s\n", backup)
	fmt.Println("  Verify the new DB works, then `rm` the backup to reclaim its space.")
	return nil
}

// runCalibrate (Wave 20e) walks every findings.json under outputs/cases/**
// and emits a per_event_sec regression report. The current Wave 20a default
// is 5 s/event; this tool produces the data-driven estimate to swap in.
//
// Output (per tactic + global):
//   tactic        runs  ev_min  ev_max  dur_min  dur_max  per_event_sec  R²
//
// Usage:
//   tlvb calibrate [--outputs DIR] [--tactic NAME] [--csv PATH]
func runCalibrate(args []string) error {
	fs := flag.NewFlagSet("calibrate", flag.ContinueOnError)
	outputsDir := fs.String("outputs", "outputs/cases",
		"root containing case dirs with findings/*.json")
	onlyTactic := fs.String("tactic", "",
		"only consider this tactic (default: all)")
	csvPath := fs.String("csv", "",
		"write samples + per-tactic fit to this CSV (optional)")
	minSamples := fs.Int("min-samples", 3,
		"refuse to fit if a tactic has fewer than this many runs")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Sample collection. Each sample = one TacticReport's Audit block.
	type sample struct {
		Case        string
		Tactic      string
		ArtifactScope string
		Events      int  // Audit.InputEvents
		MaxEvents   int  // Audit.MaxEvents (Wave 20b)
		PromptChars int  // Audit.PromptSizeChars (Wave 20b)
		DurationSec float64
		Iterations  int
		ModelID     string
	}
	var samples []sample

	root, err := os.Stat(*outputsDir)
	if err != nil || !root.IsDir() {
		return fmt.Errorf("--outputs %q: not a directory", *outputsDir)
	}

	caseDirs, err := os.ReadDir(*outputsDir)
	if err != nil {
		return err
	}
	for _, cd := range caseDirs {
		if !cd.IsDir() {
			continue
		}
		findingsRoot := filepath.Join(*outputsDir, cd.Name(), "findings")
		_ = filepath.Walk(findingsRoot, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(p, ".json") {
				return nil
			}
			body, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			var rep agents.TacticReport
			if err := json.Unmarshal(body, &rep); err != nil {
				return nil
			}
			if rep.TacticID == "" && rep.TacticName == "" {
				return nil // not a TacticReport
			}
			tac := rep.TacticName
			if tac == "" {
				tac = rep.TacticID
			}
			if *onlyTactic != "" && tac != *onlyTactic && rep.TacticID != *onlyTactic {
				return nil
			}
			samples = append(samples, sample{
				Case:          rep.CaseID,
				Tactic:        tac,
				ArtifactScope: rep.ArtifactScope,
				Events:        rep.Audit.InputEvents,
				MaxEvents:     rep.Audit.MaxEvents,
				PromptChars:   rep.Audit.PromptSizeChars,
				DurationSec:   rep.Audit.DurationSec,
				Iterations:    rep.Audit.Iterations,
				ModelID:       rep.Audit.ModelID,
			})
			return nil
		})
	}

	if len(samples) == 0 {
		fmt.Println("no findings.json samples found under " + *outputsDir)
		fmt.Println("(run Tier 1 analyze on some cases first; Wave 20b stamps PromptSizeChars + DurationSec into Audit)")
		return nil
	}

	// Group by tactic, fit y = a*x + b via least squares where x = InputEvents.
	byTactic := map[string][]sample{}
	for _, s := range samples {
		byTactic[s.Tactic] = append(byTactic[s.Tactic], s)
	}
	tactics := make([]string, 0, len(byTactic))
	for t := range byTactic {
		tactics = append(tactics, t)
	}
	sort.Strings(tactics)

	fmt.Printf("=== Wave 20e per_event_sec calibration ===\n")
	fmt.Printf("samples: %d total / %d tactics\n\n", len(samples), len(tactics))
	fmt.Printf("%-22s %5s %8s %8s %10s %10s %16s %6s\n",
		"tactic", "runs", "ev_min", "ev_max", "dur_min", "dur_max",
		"per_event_sec", "R²")
	fmt.Println(strings.Repeat("-", 90))

	for _, t := range tactics {
		ss := byTactic[t]
		if len(ss) < *minSamples {
			fmt.Printf("%-22s %5d %8s\n", t, len(ss),
				fmt.Sprintf("(need ≥%d samples)", *minSamples))
			continue
		}
		var (
			evMin, evMax   = 1 << 30, 0
			durMin, durMax = 1e9, 0.0
			sx, sy, sxy, sxx float64
		)
		n := float64(len(ss))
		for _, s := range ss {
			x := float64(s.Events)
			y := s.DurationSec
			sx += x; sy += y
			sxy += x * y; sxx += x * x
			if s.Events < evMin {
				evMin = s.Events
			}
			if s.Events > evMax {
				evMax = s.Events
			}
			if y < durMin {
				durMin = y
			}
			if y > durMax {
				durMax = y
			}
		}
		denom := n*sxx - sx*sx
		var slope, intercept, r2 float64
		if denom > 0 {
			slope = (n*sxy - sx*sy) / denom
			intercept = (sy - slope*sx) / n
			// R² = 1 - SS_res / SS_tot
			yMean := sy / n
			var ssRes, ssTot float64
			for _, s := range ss {
				y := s.DurationSec
				yPred := slope*float64(s.Events) + intercept
				ssRes += (y - yPred) * (y - yPred)
				ssTot += (y - yMean) * (y - yMean)
			}
			if ssTot > 0 {
				r2 = 1.0 - ssRes/ssTot
			}
		}
		fmt.Printf("%-22s %5d %8d %8d %10.2f %10.2f %16.3f %6.2f\n",
			t, len(ss), evMin, evMax, durMin, durMax, slope, r2)
	}

	fmt.Println()
	fmt.Println("Interpretation:")
	fmt.Println("  per_event_sec is the slope of DurationSec ~ InputEvents (seconds per event).")
	fmt.Println("  Compare to Wave 20a default = 5.0 s/event. Set TLVB_LLM_TIMEOUT_PER_EVENT_SEC")
	fmt.Println("  to a calibrated value (e.g. max(slope) × 1.2 safety margin) to right-size timeouts.")
	fmt.Println("  Low R² (<0.5) means events count alone is a poor predictor — also inspect")
	fmt.Println("  PromptSizeChars + CacheHitTok before adopting the slope.")

	if *csvPath != "" {
		f, err := os.Create(*csvPath)
		if err != nil {
			return fmt.Errorf("open csv: %w", err)
		}
		defer f.Close()
		w := csv.NewWriter(f)
		defer w.Flush()
		_ = w.Write([]string{
			"case_id", "tactic", "artifact_scope", "input_events",
			"max_events", "prompt_chars", "duration_sec", "iterations", "model",
		})
		for _, s := range samples {
			_ = w.Write([]string{
				s.Case, s.Tactic, s.ArtifactScope,
				fmt.Sprint(s.Events), fmt.Sprint(s.MaxEvents),
				fmt.Sprint(s.PromptChars), fmt.Sprintf("%.3f", s.DurationSec),
				fmt.Sprint(s.Iterations), s.ModelID,
			})
		}
		fmt.Printf("\nCSV samples written: %s (%d rows)\n", *csvPath, len(samples))
	}
	return nil
}

// printRunProgress (Wave 28) emits a one-line visual progress bar for the
// `tlvb run` per-stage loop. Stderr-bound so stdout pipelines aren't
// polluted. Uses \r so successive calls overwrite the previous line —
// matching the convention examiners are used to from curl / pip / etc.
//
// Format:
//   tier1  [█████████░░░░░░░░░░░░░]  4/10 (40%)  current=persistence running
//
// done=true emits a final line with newline so the next println starts clean.
func printRunProgress(stage string, completed, total int, current, state string) {
	if total <= 0 {
		return
	}
	const barWidth = 20
	pct := completed * 100 / total
	filled := (completed * barWidth) / total
	if filled > barWidth {
		filled = barWidth
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	terminator := "\r"
	if completed >= total {
		terminator = "\n"
	}
	fmt.Fprintf(os.Stderr, "%s  [%s]  %d/%d (%d%%)  current=%s %s%s",
		stage, bar, completed, total, pct, current, state, terminator)
}
