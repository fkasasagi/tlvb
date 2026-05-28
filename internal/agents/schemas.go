// Package agents implements Tier 1 Tactic Agents.
//
// Each agent is one MITRE ATT&CK Tactic (e.g. TA0003 Persistence). Agents
// run independently, consume pre-filtered UnifiedEvent rows, and emit a
// TacticReport. Reports stage as DRAFT (Valhuntir-pattern); Review Gate 1
// is responsible for promoting them to APPROVED.
//
// The schemas in this file mirror docs/DESIGN.md §5.4. JSON tags are the
// canonical wire format — the LLM emits this shape and Go validates it.
package agents

import "time"

// TacticReport is what one Tactic Agent run produces. Always status="draft"
// at this layer; promotion to APPROVED happens at Review Gate 1.
type TacticReport struct {
	TacticID    string `json:"tactic_id"`         // e.g. "TA0003"
	TacticName  string `json:"tactic_name"`       // e.g. "Persistence"
	CaseID      string `json:"case_id"`
	// EvidenceID is the *primary* evidence the report was anchored on
	// (back-compat with v0.2 reports). For multi-evidence cases this is
	// typically the first registered evidence; the full set is in
	// EvidenceIDs below.
	EvidenceID string `json:"evidence_id"`
	// EvidenceIDs lists every evidence the agent actually saw. The Tier 1
	// SQL prefilter pools events by case_id (not evidence_id), so a single
	// agent run already spans all evidences of the case — this field
	// records that scope honestly so cross-evidence Tier 2 correlation
	// (★v0.3 #7) can reason about it. May be empty for legacy reports.
	EvidenceIDs      []string          `json:"evidence_ids,omitempty"`
	StartedAt        time.Time         `json:"started_at"`
	FinishedAt       time.Time         `json:"finished_at"`
	Status           string            `json:"status"` // completed | partial | failed
	Findings         []Finding         `json:"findings"`
	NegativeFindings []NegativeFinding `json:"negative_findings"`
	OpenQuestions    []OpenQuestion    `json:"open_questions,omitempty"`
	Summary          string            `json:"summary,omitempty"`
	Audit            Audit             `json:"audit"`

	// ArtifactScope (Wave 20h) records which single artifact_id this run
	// was filtered to, if any. Empty means a full cross-artifact run
	// (the v0.6 default). Set when the examiner triggered the per-
	// artifact analyze path so downstream consumers (review UI,
	// synthesizer, report) can present scope honestly and not double-
	// count findings from overlapping runs.
	ArtifactScope string `json:"artifact_scope,omitempty"`
}

// Finding asserts that a sub-technique is supported by evidence.
type Finding struct {
	FindingID     string     `json:"finding_id"`
	TechniqueID   string     `json:"technique_id"`
	TechniqueName string     `json:"technique_name"`
	Summary       string     `json:"summary"`
	Confidence    string     `json:"confidence"` // high | medium | low
	Evidence      []Evidence `json:"evidence"`
	Reasoning     string     `json:"reasoning"`

	// Review-gate fields. Default zero-values mean "unreviewed". The
	// fields are mutually exclusive — Approved and Rejected can't both
	// be true. Set by `tlvb review` (CLI) or the future Examiner Portal.
	Approved     bool      `json:"approved,omitempty"`
	Rejected     bool      `json:"rejected,omitempty"`
	RejectReason string    `json:"reject_reason,omitempty"`
	ReviewedAt   time.Time `json:"reviewed_at,omitempty"`
	ReviewedBy   string    `json:"reviewed_by,omitempty"`
}

// Evidence cites one row from unified_events. AuditID must exist in the
// case DB; the runner validates this before persisting the report.
type Evidence struct {
	SourceArtifact string `json:"source_artifact"`
	AuditID        string `json:"audit_id"`
	Excerpt        string `json:"excerpt"`
}

// NegativeFinding records a technique that was checked and ruled out.
// Tier 2's ConsistencyChecker uses these to detect blind spots.
type NegativeFinding struct {
	TechniqueID string   `json:"technique_id"`
	CheckedVia  []string `json:"checked_via"`
	Rationale   string   `json:"rationale"`
}

// OpenQuestion is an unresolved tension — evidence is suggestive but not
// conclusive. Forensic discipline: never close these by guessing.
type OpenQuestion struct {
	TechniqueID string `json:"technique_id"`
	Question    string `json:"question"`
	NextStep    string `json:"next_step"`
}

// Audit captures observability data for the run. Mirrors Valhuntir's
// approach of attaching provenance to every staged item.
type Audit struct {
	Iterations    int        `json:"iterations"`
	InputEvents   int        `json:"input_events"`
	ModelID       string     `json:"model_id"`
	StopReason    string     `json:"stop_reason"`
	TokensInput   int        `json:"tokens_input"`
	TokensOutput  int        `json:"tokens_output"`
	CacheHitTok   int        `json:"cache_read_input_tokens"`
	DurationSec   float64    `json:"duration_seconds"`
	ToolCalls     []ToolCall `json:"tool_calls,omitempty"`
	SkillFile     string     `json:"skill_file"`
	SkillSHA256   string     `json:"skill_sha256"`
	ValidationOK  bool       `json:"validation_ok"`
	ValidationErr string     `json:"validation_err,omitempty"`

	// Wave 20b: observability metrics for data-driven per_event_sec
	// calibration of Wave 20a's dynamic LLM timeout. PromptSizeChars is
	// computed before the engine call (skill + user message + correction
	// context + feedback), MaxEvents is the configured prefilter cap
	// (InputEvents above is the actual window size after filtering and
	// may be smaller). DurationAPIMS isolates the LLM server-side
	// component (claude-code reports it separately from total wall
	// clock, useful for diagnosing cache-hit vs cache-miss latency).
	PromptSizeChars int `json:"prompt_size_chars,omitempty"`
	MaxEvents       int `json:"max_events,omitempty"`
	DurationAPIMS   int `json:"duration_api_ms,omitempty"`

	// Wave 22 sliding-window: when SlidingWindow is enabled, the tactic
	// agent loops over the full match set in WindowsTotal calls. These
	// fields record what the loop actually did so the calibrator
	// (Wave 20e) can distinguish 1-shot vs windowed runs.
	WindowsTotal  int `json:"windows_total,omitempty"`
	WindowSize    int `json:"window_size,omitempty"`
	WindowOverlap float64 `json:"window_overlap,omitempty"`

	// TraceID (Wave 29) links the TacticReport back to the engine call
	// that produced it. claude-code provides session_id which the
	// examiner can grep in `claude --resume` logs. Anthropic SDK leaves
	// this empty for now. Last call's TraceID wins in sliding-window
	// runs (the merged report doesn't carry per-window traces today).
	TraceID string `json:"trace_id,omitempty"`
}

// ToolCall is reserved for the future agentic loop. Single-shot MVP doesn't
// use tools yet — the LLM only sees a pre-built event window.
type ToolCall struct {
	Tool    string         `json:"tool"`
	Args    map[string]any `json:"args,omitempty"`
	TS      time.Time      `json:"ts"`
	TraceID string         `json:"trace_id"`
}

// EventWindow is what the runner serialises into the user-message. Field
// names are short to keep the prompt token-efficient — the LLM doesn't see
// these Go field names, only the JSON output.
type EventWindow struct {
	CaseID    string         `json:"case_id"`
	Tactic    string         `json:"tactic"`
	WindowMin time.Time      `json:"window_min"`
	WindowMax time.Time      `json:"window_max"`
	Total     int            `json:"total_in_window"`
	Truncated bool           `json:"truncated"`
	Events    []EventForLLM  `json:"events"`
	Counts    map[string]int `json:"counts_by_artifact"`
}

// EventForLLM is the trimmed view we hand to the model. We strip
// payload.raw and other noisy fields to keep tokens reasonable.
type EventForLLM struct {
	AuditID    string         `json:"audit_id"`
	TS         string         `json:"ts"`
	Artifact   string         `json:"artifact"`
	Computer   string         `json:"computer,omitempty"`
	Excerpt    map[string]any `json:"excerpt"`
}
