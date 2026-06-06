package main

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/tlvb/tlvb/internal/casedb"
	"github.com/tlvb/tlvb/internal/completeness"
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
	findingsDir := fs.String("findings-dir", "",
		"findings root for evidence/IOC/timeline enrichment (default: outputs/cases/<id>/findings)")
	dbPath := fs.String("db", filepath.Join("outputs", "cases.duckdb"),
		"case DB for evidence / chain-of-custody metadata")
	examiner := fs.String("examiner", "", "examiner name (overrides the case DB value)")
	org := fs.String("org", "", "examiner organization shown on the report")
	classification := fs.String("classification", "",
		"handling classification banner (default: CONFIDENTIAL)")
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

	// Forensic case metadata is best-effort: a missing/locked DB just omits
	// the evidence & chain-of-custody section rather than failing the report.
	meta, dbExaminer := loadReportCaseMeta(*dbPath, caseID)
	if *examiner == "" {
		*examiner = dbExaminer
	}

	rep, err := tier3.Render(tier3.Config{
		CaseID:         caseID,
		SynthesisPath:  *synthPath,
		OutDir:         *outDir,
		Formats:        formats,
		Language:       *lang,
		FindingsDir:    *findingsDir,
		CaseMeta:       meta,
		Examiner:       *examiner,
		Organization:   *org,
		Classification: *classification,
		ToolVersion:    "TLVB " + version,
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

// loadReportCaseMeta pulls evidence + case identity from the case DB.
// Returns (nil, "") on any error so the caller can render without it.
func loadReportCaseMeta(dbPath, caseID string) (*tier3.CaseMeta, string) {
	mgr, err := casedb.Open(dbPath, casedb.ReadOnly)
	if err != nil {
		return nil, ""
	}
	defer mgr.Close()
	ctx := context.Background()

	meta := &tier3.CaseMeta{}
	examiner := ""

	if cases, err := mgr.ListCases(ctx); err == nil {
		for _, c := range cases {
			if c.CaseID == caseID {
				meta.DisplayName = c.Name
				meta.Status = c.Status
				meta.CreatedAt = c.CreatedAt
				examiner = c.Examiner
				break
			}
		}
	}

	if evs, err := mgr.ListEvidence(ctx, caseID); err == nil {
		for _, e := range evs {
			meta.Evidence = append(meta.Evidence, tier3.EvidenceItem{
				EvidenceID:   e.EvidenceID,
				SourcePath:   filepath.Base(e.Path),
				SHA256:       e.SHA256,
				SizeBytes:    e.SizeBytes,
				RegisteredAt: e.RegisteredAt,
				SourceHost:   e.SourceHost,
				EvidenceType: e.EvidenceType,
			})
		}
	}

	// Per-artifact event counts (Tier 0 coverage) — raw query, best-effort.
	rows, err := mgr.DB().Query(
		`SELECT artifact_id, COUNT(*) AS n
		 FROM unified_events WHERE case_id = ?
		 GROUP BY artifact_id ORDER BY n DESC`, caseID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var a string
			var n int
			if rows.Scan(&a, &n) == nil {
				meta.ArtifactCounts = append(meta.ArtifactCounts,
					tier3.ArtifactCount{ArtifactID: a, EventCount: n})
				meta.TotalEvents += n
			}
		}
	}

	// Detection-input completeness (data gap vs detection miss). Best-effort;
	// skipped silently if the case has no events.
	if results, _, err := completeness.EvaluateCase(ctx, mgr.DB(), caseID); err == nil {
		meta.CollectionGaps = results
	}

	if meta.DisplayName == "" && len(meta.Evidence) == 0 && len(meta.ArtifactCounts) == 0 {
		return nil, examiner
	}
	return meta, examiner
}
