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

	"github.com/tlvb/tlvb/internal/completeness"
)

// Config drives Render.
type Config struct {
	CaseID        string
	SynthesisPath string   // outputs/cases/<id>/synthesis.json
	OutDir        string   // outputs/cases/<id>/reports
	Formats       []string // subset of {"html","csv","json"}; default ["html","csv","json"]
	Language      string   // "ja" | "en" — UI labels; LLM-narratives translated only when TranslateNarratives is set
	OnlyApproved  bool     // (future) filter to Review Gate 1A approved findings

	// TranslateNarratives opts into the report-time LLM translation pass: when the
	// synthesis was written in a different language than Language, the verbatim
	// LLM prose (executive summary, cluster narratives, open questions, timeline
	// notes, active-search answers) is translated into Language so the whole
	// report reads in one language — not just the static UI labels. Off by default
	// (it costs one LLM call and is non-deterministic); the CLI / web report path
	// turn it on. Best-effort: no transport or a failed call leaves the narratives
	// untranslated and logs a warning rather than failing the report. Tier 1A
	// stays LLM-free — this is a Tier 3 concern only.
	TranslateNarratives bool

	// Timezone is the IANA zone the report's timestamps are displayed in
	// (e.g. "Asia/Tokyo"). Events are stored in UTC; this only changes the
	// rendered time. Empty / unloadable → UTC. The CLI fills this from the
	// case timezone.
	Timezone string

	// FindingsDir is the per-case findings root used to enrich the report with
	// per-finding evidence, IOCs and a key-event timeline. Defaults to
	// outputs/cases/<id>/findings. Missing dir → enrichment is simply skipped.
	FindingsDir string

	// Forensic case metadata (chain of custody / examiner identity). Optional;
	// the CLI fills CaseMeta from the case DB. nil → the section is omitted.
	CaseMeta *CaseMeta

	// Report-level identity fields. Sensible placeholders are substituted when
	// empty so the report still reads as a forensic document.
	Examiner       string
	Organization   string
	Classification string // e.g. "CONFIDENTIAL" / "社外秘"
	ToolVersion    string // TLVB build identifier

	// CaseBackground is examiner-supplied UNVERIFIED case context, passed to the
	// advisory LLM consistency reviewer as NON-authoritative context (the
	// findings remain ground truth). The CLI / web layer fills it from the case
	// DB. Empty → nothing is injected.
	CaseBackground string

	// ConsistencyLLM opts into the advisory LLM consistency reviewer that reads
	// the assembled report against the findings and flags FREE-TEXT internal
	// contradictions the deterministic gate cannot pattern-match. Off by default
	// (it costs tokens and is non-deterministic). Its findings are advisory only
	// — they never block the report or auto-edit it, only surface for Review
	// Gate 2. Empty transport / binary → the pass is skipped and noted.
	ConsistencyLLM bool
	// Model is the LLM id for the consistency reviewer (default claude-opus-4-8);
	// a "[1m]" routing suffix is stripped for the raw API. ClaudeBinary is the
	// CLI fallback used only when no API/Vertex transport is configured.
	Model        string
	ClaudeBinary string
}

// CaseMeta is the forensic case context the renderer pulls from the case DB.
type CaseMeta struct {
	DisplayName    string
	Status         string
	CreatedAt      time.Time
	Notes          string
	Evidence       []EvidenceItem
	ArtifactCounts []ArtifactCount
	TotalEvents    int

	// CollectionGaps is the per-input completeness analysis (detection-relevant
	// artefacts / EVTX channels present vs missing). Lets the report distinguish
	// a DATA GAP from a detection MISS. nil → the subsection is omitted.
	CollectionGaps []completeness.Result
}

// EvidenceItem is one acquired exhibit (chain-of-custody row).
type EvidenceItem struct {
	EvidenceID   string
	SourcePath   string
	SHA256       string
	SizeBytes    int64
	RegisteredAt time.Time
	SourceHost   string
	EvidenceType string
}

// ArtifactCount is per-artifact event volume (Tier 0 parse coverage).
type ArtifactCount struct {
	ArtifactID string
	EventCount int
}

// Report describes what was rendered.
type Report struct {
	CaseID      string
	OutDir      string
	GeneratedAt time.Time
	Files       []OutputFile
	Sections    int // for HTML, number of cluster sections
	// ConsistencyIssues are the internal contradictions the post-render gate
	// found (empty when the report is internally consistent). Callers surface
	// blockers before treating the report as done.
	ConsistencyIssues []ConsistencyIssue
}

// OutputFile is one rendered file.
type OutputFile struct {
	Format    string // "html" | "csv-findings" | "csv-mitre" | "csv-clusters" | "json"
	Path      string
	SizeBytes int64
}
