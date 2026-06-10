// Package tier1b is the runtime executor for the Skills-driven Anomaly
// Agent (Tier 1B). Unlike Tier 1A which executes cached SQL with zero LLM
// at runtime, Tier 1B drives the LLM at runtime to surface abstract
// patterns that signature rules cannot catch.
//
// v0.1 MVP scope:
//   - One skill (anomaly_hunter.md) consumed
//   - Prior Tier 1A findings read for context (existing audit_ids + timestamps)
//   - Heuristic candidate selection (off-hours / suspicious path / adjacency)
//   - LLM call via claude CLI (or anthropic API — interface ready)
//   - Output: outputs/cases/<id>/findings/by-skill/<skill>.json
//
// v0.2 (Hybrid Cache — implemented, see skillcache.go):
//   - skill_sql_cache (rules.duckdb): canonical SQL runs zero-LLM and
//     augments the heuristic prefilter; candidate SQL runs on a trial basis
//   - The LLM self-judges coverage against existing_skill_intents and may
//     propose new reusable queries (stored as candidates)
//   - A cached query whose rows the LLM cites in a finding is promoted to
//     canonical → cost decreases as proven lenses accumulate across cases
//
// v0.2+ (multi-skill): Run() builds one skill at a time (cfg.Skill, default
// anomaly_hunter); the CLI loops it over --skills to run several. The skill
// .md is the system prompt (its detection lenses/knowledge); the Tier 1B
// user message is the AUTHORITATIVE output contract ({findings,
// proposed_queries}) regardless of any output format the .md describes.
package tier1b

import (
	"time"

	"github.com/tlvb/tlvb/internal/evidencex"
)

// Config drives Run().
type Config struct {
	CaseID           string
	Skill            string // skill name (skills/<Skill>.md); default "anomaly_hunter"
	SkillsDir        string // default "skills"
	FindingsBaseDir  string // outputs/cases/<id>/findings
	DBPath           string // outputs/cases.duckdb (read-only opened by Run)
	ClaudeBinary     string // default "claude"
	Model            string // empty = let Claude Code default
	MaxEvents        int    // default 200
	Timeout          time.Duration
	IncludeInfoLevel bool // include info/low-level Hayabusa findings in prior context
	DryRun           bool // build prompt + sizes, skip LLM call
	ProgressFn       func(Event)

	// --- Tier 1B v0.2 skill SQL cache (Hybrid Cache) ---
	// RulesDBPath points at outputs/rules.duckdb; canonical/candidate skill
	// queries live there in skill_sql_cache (separate from rule_sql_cache).
	// Empty path or NoSkillCache disables the cache entirely → v0.1 behaviour.
	RulesDBPath   string
	NoSkillCache  bool
	SchemaVersion string // cache validity signature; defaults to "unknown" if empty
	ModelID       string // cache validity signature; defaults to Model or "claude-code-default"

	// --- On-demand evidence extraction (agent-driven file fetch) ---
	// When enabled the LLM may list files in `requested_files`; the runner
	// extracts them read-only from the case's disk image and runs a bounded
	// follow-up pass with their contents so the agent can inspect a file
	// directly (not just its normalized event). Requires mountable image
	// evidence + SIFT mount tools; degrades to a single pass when unavailable.
	EvidenceFetch     bool          // master switch (default off; CLI defaults it on)
	MaxEvidenceRounds int           // fetch+reanalyse rounds (default 1)
	MaxEvidenceFiles  int           // files fetched per round (default 8)
	EvidenceTimeout   time.Duration // per-fetch wall-clock budget (default 10m)
	PythonBin         string        // interpreter for parsers.evidence_fetch
	RepoDir           string        // module root for the import (default: cwd)
}

// Event is the progress hook callback.
type Event struct {
	Phase   string // "loading" | "prefilter" | "llm" | "writing" | "done"
	Message string
	Count   int
}

// Report is returned by Run().
type Report struct {
	CaseID           string
	PriorFindings    int // count of Tier 1A findings consumed as context
	EventsScanned    int
	EventsInWindow   int
	Truncated        bool
	LLMCallDurationS float64
	NewFindings      []FindingSummary
	OutputPath       string // findings/by-skill/anomaly_hunter.json
	SkillSHA256      string // for cache invalidation tracking

	// Token / cost of the LLM call (mirrors AnomalyReport.Audit; surfaced for
	// the CLI summary). InputTokens excludes cache; CacheReadTokens is the
	// cached portion (the bulk of the prompt). TotalCostUSD is the CLI figure.
	InputTokens     int
	CacheReadTokens int
	OutputTokens    int
	TotalCostUSD    float64

	// --- Tier 1B v0.2 skill SQL cache accounting ---
	CacheEnabled       bool // skill_sql_cache was consulted this run
	SkillSQLAvailable  int  // cached queries matching the current signature
	SkillSQLExecuted   int  // queries that ran without error
	SkillSQLHits       int  // total rows returned by cached queries
	CandidatesProposed int  // new queries the LLM proposed this run
	CandidatesAppended int  // newly stored (deduped) candidates
	Promoted           int  // candidate→canonical promotions + canonical re-hits

	// --- On-demand evidence extraction accounting ---
	EvidenceRounds int // fetch+reanalyse rounds actually performed
	FilesRequested int // files the LLM asked to inspect (across rounds)
	FilesExtracted int // files successfully pulled from the image
}

// FindingSummary mirrors tier1a.FindingSummary so the CLI report printer
// can be reused. Note this is for display — actual finding JSON shape is
// AnomalyFinding below.
type FindingSummary struct {
	Lens       string
	Severity   string
	Summary    string
	AuditCount int
}

// AnomalyFinding is the LLM-emitted shape for one anomaly. The skill
// prompt instructs Claude to produce JSON conforming to this.
//
// The Review Gate 1A state (Approved/Rejected/…) is filled in by the
// runner using tier1a.AutoApproveByLevel(severity) so Tier 1B findings
// flow through the same review pipeline as cached-SQL findings.
type AnomalyFinding struct {
	FindingID   string    `json:"finding_id"`             // server-assigned UUID
	Lens        string    `json:"lens"`                   // "A1"|"A2"|"A4"|"A5"|"A6"|"A7"
	Summary     string    `json:"summary"`                // 1-line title
	Description string    `json:"description"`            // free-text rationale
	Severity    string    `json:"severity"`               // info|low|medium|high|critical
	AuditIDs    []string  `json:"audit_ids"`              // evidence references
	TechniqueID string    `json:"technique_id,omitempty"` // optional MITRE T-number
	Tactic      string    `json:"tactic,omitempty"`       // optional kill-chain phase
	GeneratedAt time.Time `json:"generated_at"`

	// Review Gate 1A state (mirror of tier1a.Finding).
	Approved     bool      `json:"approved"`
	Rejected     bool      `json:"rejected,omitempty"`
	ApprovedBy   string    `json:"approved_by,omitempty"`
	RejectReason string    `json:"reject_reason,omitempty"`
	ReviewedAt   time.Time `json:"reviewed_at,omitempty"`
	ReviewedBy   string    `json:"reviewed_by,omitempty"`
}

// AnomalyReport is the wrapper written to disk
// (findings/by-skill/anomaly_hunter.json).
type AnomalyReport struct {
	CaseID         string           `json:"case_id"`
	Skill          string           `json:"skill"`
	SkillSHA256    string           `json:"skill_sha256"`
	GeneratedAt    time.Time        `json:"generated_at"`
	ModelID        string           `json:"model_id,omitempty"`
	EventsScanned  int              `json:"events_scanned"`
	EventsInWindow int              `json:"events_in_window"`
	PriorFindings  int              `json:"prior_findings"`
	Findings       []AnomalyFinding `json:"findings"`
	Audit          AnomalyAudit     `json:"audit"`

	// EvidenceFetches records every file the agent pulled from the disk image
	// during this run (the audit trail for Review Gate 1B / the Web Audit tab).
	EvidenceFetches []evidencex.FetchSummary `json:"evidence_fetches,omitempty"`
}

type AnomalyAudit struct {
	LLMCallDurationS float64 `json:"llm_call_duration_s"`
	// Token accounting. InputTokens is the non-cached (newly billed) input;
	// the bulk of a Tier 1B prompt is usually served from prompt cache, so
	// CacheReadTokens/CacheCreationTokens are recorded separately for accurate
	// per-run cost. TotalCostUSD is the claude CLI's own cost figure.
	InputTokens         int     `json:"input_tokens,omitempty"`
	CacheReadTokens     int     `json:"cache_read_tokens,omitempty"`
	CacheCreationTokens int     `json:"cache_creation_tokens,omitempty"`
	OutputTokens        int     `json:"output_tokens,omitempty"`
	TotalCostUSD        float64 `json:"total_cost_usd,omitempty"`
	StopReason          string  `json:"stop_reason,omitempty"`
	SessionID           string  `json:"session_id,omitempty"`
	EvidenceRounds      int     `json:"evidence_rounds,omitempty"`
}
