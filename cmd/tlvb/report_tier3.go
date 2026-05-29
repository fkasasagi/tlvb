package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/tlvb/tlvb/internal/tier3"
)

func runReportTier3(caseID string, args []string) error {
	fs := flag.NewFlagSet("report --tier 3", flag.ContinueOnError)
	synthPath := fs.String("synthesis", "",
		"input synthesis.json (default: outputs/cases/<id>/synthesis.json)")
	outDir := fs.String("out-dir", "",
		"output dir (default: outputs/cases/<id>/reports)")
	formatStr := fs.String("format", "html,csv,json",
		"comma-separated subset of html,csv,json")
	lang := fs.String("language", "ja", "report UI language: ja | en")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *synthPath == "" {
		*synthPath = filepath.Join("outputs", "cases", caseID, "synthesis.json")
	}
	if *outDir == "" {
		*outDir = filepath.Join("outputs", "cases", caseID, "reports")
	}
	var formats []string
	for _, f := range strings.Split(*formatStr, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			formats = append(formats, f)
		}
	}
	rep, err := tier3.Render(tier3.Config{
		CaseID:        caseID,
		SynthesisPath: *synthPath,
		OutDir:        *outDir,
		Formats:       formats,
		Language:      *lang,
	})
	if err != nil {
		return err
	}
	fmt.Printf("\nTier 3 report — case=%s\n", rep.CaseID)
	fmt.Printf("  output dir:        %s\n", rep.OutDir)
	fmt.Printf("  generated_at:      %s\n", rep.GeneratedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("  cluster sections:  %d\n", rep.Sections)
	for _, f := range rep.Files {
		fmt.Printf("  [%-13s] %-60s  %d bytes\n", f.Format, f.Path, f.SizeBytes)
	}
	return nil
}
