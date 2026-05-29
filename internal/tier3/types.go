// Package tier3 renders Tier 2's CaseSynthesis into human / machine-friendly
// reports (HTML / CSV / JSON).
//
// v0.1 MVP scope:
//   - HTML: single self-contained file with inline CSS, no external deps
//   - CSV: three files — findings.csv / mitre.csv / clusters.csv
//   - JSON: pretty-printed copy of synthesis.json
//   - i18n: ja / en label dictionaries (narratives stay verbatim from LLM)
//
// Out of scope for MVP:
//   - PDF rendering
//   - Multi-page HTML / pagination
//   - Interactive timeline visualisation
package tier3

import (
	"time"
)

// Config drives Render.
type Config struct {
	CaseID        string
	SynthesisPath string // outputs/cases/<id>/synthesis.json
	OutDir        string // outputs/cases/<id>/reports
	Formats       []string // subset of {"html","csv","json"}; default ["html","csv","json"]
	Language      string   // "ja" | "en" — UI labels, NOT LLM-narratives
	OnlyApproved  bool     // (future) filter to Review Gate 1A approved findings
}

// Report describes what was rendered.
type Report struct {
	CaseID       string
	OutDir       string
	GeneratedAt  time.Time
	Files        []OutputFile
	Sections     int // for HTML, number of cluster sections
}

// OutputFile is one rendered file.
type OutputFile struct {
	Format    string // "html" | "csv-findings" | "csv-mitre" | "csv-clusters" | "json"
	Path      string
	SizeBytes int64
}
