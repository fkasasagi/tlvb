// Package auditlog appends structured action records to a case's
// outputs/cases/<id>/actions.jsonl — the unified, timestamped execution log the
// Web UI Audit tab streams.
//
// Tier 0 (the Python parser orchestrator) already writes parse / skip /
// nested_extract records here. This Go writer lets the agentic tiers (1A / 1B /
// 2) append their tool executions, LLM calls, and self-correction attempts to
// the SAME file, so a case's whole investigation — from parsing through the
// agent's reasoning and its runtime error-recovery — is auditable end to end in
// one ordered log (hackathon deliverable: agent execution log; judging: audit
// trail quality).
//
// The envelope (ts / case_id / actor / kind) matches the Tier 0 schema and what
// the Audit tab renders; the optional fields carry agent-specific detail.
package auditlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Action is one row in actions.jsonl. Optional fields use omitempty so a record
// only carries what is relevant to its kind.
type Action struct {
	TS              string  `json:"ts"`
	CaseID          string  `json:"case_id"`
	Actor           string  `json:"actor"` // "tier1a" | "tier1b" | "tier2"
	Kind            string  `json:"kind"`  // "llm_call" | "active_sql" | "rule_sql" | ...
	Success         *bool   `json:"success,omitempty"`
	DurationSeconds float64 `json:"duration_seconds,omitempty"`
	RowCount        *int    `json:"row_count,omitempty"`
	Command         string  `json:"command,omitempty"` // SQL text or a call descriptor
	Error           string  `json:"error,omitempty"`
	// Agent-specific detail.
	Model           string  `json:"model,omitempty"`
	InputTokens     int     `json:"input_tokens,omitempty"`
	OutputTokens    int     `json:"output_tokens,omitempty"`
	CacheReadTokens int     `json:"cache_read_tokens,omitempty"`
	CostUSD         float64 `json:"cost_usd,omitempty"`
	RuleID          string  `json:"rule_id,omitempty"`
	RuleSource      string  `json:"rule_source,omitempty"` // sigma | hayabusa | custom | stix
	ClusterID       int     `json:"cluster_id,omitempty"`
	Attempt         int     `json:"attempt,omitempty"`
	Outcome         string  `json:"outcome,omitempty"` // ok | execute_error | null_result | ...
	Detail          string  `json:"detail,omitempty"`  // sub-kind, e.g. "cluster_analysis"
}

// Logger appends actions to one case's actions.jsonl. Safe for concurrent use.
// A nil *Logger is a no-op, so callers can hold one unconditionally.
type Logger struct {
	mu     sync.Mutex
	path   string
	caseID string
}

// New returns a Logger that appends to actionsPath. caseID backfills records
// that don't set their own.
func New(actionsPath, caseID string) *Logger {
	return &Logger{path: actionsPath, caseID: caseID}
}

// Append writes one record as a JSON line. ts and case_id are filled when empty.
// Best-effort: any I/O error is swallowed — an unwritable audit log must never
// abort the analysis it is recording.
func (l *Logger) Append(a Action) {
	if l == nil {
		return
	}
	if a.TS == "" {
		a.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if a.CaseID == "" {
		a.CaseID = l.caseID
	}
	b, err := json.Marshal(a)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

// BoolPtr is a small helper for the Success field.
func BoolPtr(b bool) *bool { return &b }

// IntPtr is a small helper for the RowCount field.
func IntPtr(n int) *int { return &n }
