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
// Out of scope for MVP (deferred to v0.2):
//   - Skill-specific build-time canonical SQL cache
//   - Runtime LLM-driven new SQL generation + cache growth
//   - Multi-skill orchestration
package tier1b

import "time"

// Config drives Run().
type Config struct {
	CaseID            string
	SkillsDir         string // default "skills"
	FindingsBaseDir   string // outputs/cases/<id>/findings
	DBPath            string // outputs/cases.duckdb (read-only opened by Run)
	ClaudeBinary      string // default "claude"
	Model             string // empty = let Claude Code default
	MaxEvents         int    // default 200
	Timeout           time.Duration
	IncludeInfoLevel  bool   // include info/low-level Hayabusa findings in prior context
	DryRun            bool   // build prompt + sizes, skip LLM call
	ProgressFn        func(Event)
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
	PriorFindings    int     // count of Tier 1A findings consumed as context
	EventsScanned    int
	EventsInWindow   int
	Truncated        bool
	LLMCallDurationS float64
	NewFindings      []FindingSummary
	OutputPath       string // findings/by-skill/anomaly_hunter.json
	SkillSHA256      string // for cache invalidation tracking
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
	FindingID   string    `json:"finding_id"`            // server-assigned UUID
	Lens        string    `json:"lens"`                  // "A1"|"A2"|"A4"|"A5"|"A6"|"A7"
	Summary     string    `json:"summary"`               // 1-line title
	Description string    `json:"description"`           // free-text rationale
	Severity    string    `json:"severity"`              // info|low|medium|high|critical
	AuditIDs    []string  `json:"audit_ids"`             // evidence references
	TechniqueID string    `json:"technique_id,omitempty"`// optional MITRE T-number
	Tactic      string    `json:"tactic,omitempty"`      // optional kill-chain phase
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
}

type AnomalyAudit struct {
	LLMCallDurationS float64 `json:"llm_call_duration_s"`
	InputTokens      int     `json:"input_tokens,omitempty"`
	OutputTokens     int     `json:"output_tokens,omitempty"`
	StopReason       string  `json:"stop_reason,omitempty"`
	SessionID        string  `json:"session_id,omitempty"`
}
