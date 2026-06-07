package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tlvb/tlvb/internal/casedb"
	"github.com/tlvb/tlvb/internal/completeness"
)

// runCompleteness reports which detection-relevant collection inputs are
// present or absent for a case, so an examiner can distinguish a detection
// MISS from a DATA GAP (e.g. "C2 undetected" vs "DNS-Client log not collected").
func runCompleteness(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("usage: tlvb completeness CASE_ID [--db PATH] [--out PATH]")
	}
	caseID := args[0]
	fs := flag.NewFlagSet("completeness", flag.ContinueOnError)
	dbPath := fs.String("db", "outputs/cases.duckdb", "case DuckDB path")
	caseRoot := fs.String("case-root", "", "case workspace root (default: outputs/cases/<id>)")
	outPath := fs.String("out", "", "JSON output path (default: <case-root>/collection_gaps.json)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *caseRoot == "" {
		*caseRoot = filepath.Join("outputs", "cases", caseID)
	}
	if *outPath == "" {
		*outPath = filepath.Join(*caseRoot, "collection_gaps.json")
	}

	mgr, err := casedb.Open(*dbPath, casedb.ReadOnly)
	if err != nil {
		return fmt.Errorf("open case db (read-only): %w", err)
	}
	defer mgr.Close()
	ctx := context.Background()

	results, channels, err := completeness.EvaluateCase(ctx, mgr.DB(), caseID)
	if err != nil {
		return err
	}
	missing := completeness.Missing(results)

	printCompletenessReport(caseID, channels, results, missing)

	if err := writeGapsJSON(*outPath, caseID, channels, results); err != nil {
		return fmt.Errorf("write %s: %w", *outPath, err)
	}
	fmt.Printf("\nwrote %s\n", *outPath)
	return nil
}

func printCompletenessReport(caseID string, channels []string, results, missing []completeness.Result) {
	fmt.Printf("Detection-input completeness — case %s\n", caseID)
	if len(channels) > 0 {
		fmt.Printf("  EVTX channels collected: %s\n", strings.Join(channels, ", "))
	} else {
		fmt.Printf("  EVTX channels collected: (none)\n")
	}
	fmt.Println()
	for _, r := range results {
		mark := "MISSING"
		if r.Present {
			mark = "ok"
		}
		fmt.Printf("  [%-7s] %-9s %-44s %s\n", mark, r.Importance, r.Label, r.Capability)
	}
	if len(missing) == 0 {
		fmt.Printf("\nAll catalogued detection inputs present.\n")
		return
	}
	fmt.Printf("\nDATA GAPS — %d detection input(s) absent. The following are NOT\n", len(missing))
	fmt.Printf("detection failures; they could not be evaluated because the input\n")
	fmt.Printf("was not collected:\n")
	for _, r := range missing {
		fmt.Printf("  - %s (%s) → %s\n", r.Label, r.Importance, r.Capability)
	}
}

type gapsReport struct {
	CaseID          string                `json:"case_id"`
	EVTXChannels    []string              `json:"evtx_channels_collected"`
	Inputs          []completeness.Result `json:"inputs"`
	MissingCount    int                   `json:"missing_count"`
	MissingCritical int                   `json:"missing_critical"`
}

func writeGapsJSON(path, caseID string, channels []string, results []completeness.Result) error {
	rep := gapsReport{CaseID: caseID, EVTXChannels: channels, Inputs: results}
	rep.MissingCount, rep.MissingCritical = completeness.CountMissing(results)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
