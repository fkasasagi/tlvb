// Package rulebuild generates SQL for the Tier 1A signature cache.
//
// Flow:
//   1. internal/rulesrepo loads RawRule from the upstream submodules.
//   2. rulebuild.Builder consumes one RawRule and returns BuiltSQL via LLM.
//   3. The pipeline (pipeline.go, task #7) accumulates BuiltSQL into rulesdb
//      with cost / budget accounting.
//
// The LLM is the heaviest cost in TLVB; it runs once per rule per (rule_sha256,
// schema_version, model_id) signature change and the result is cached forever
// otherwise — see CLAUDE.md "★ TLVB 設計の確定事項 → Tier 1A は runtime LLM ゼロ".
package rulebuild

import (
	"context"

	"github.com/tlvb/tlvb/internal/rulesrepo"
)

// BuiltSQL is the result of one rule → SQL conversion.
type BuiltSQL struct {
	SQL                string   // DuckDB-compatible SELECT
	PrefilterArtifacts []string // refined artifact list (overrides RawRule's default if LLM narrows)
	Notes              string   // free-text rationale or warnings from the LLM
	ModelID            string   // model that produced this SQL
	InputTokens        int      // for cost accounting
	OutputTokens       int
	CacheReadTokens    int      // counts toward 10% cost
}

// Builder converts one RawRule into a BuiltSQL via LLM.
//
// Implementations must:
//   - Include "WHERE case_id = ?" as the first predicate (mandatory)
//   - Use DuckDB JSON extraction (json_extract / json_extract_string)
//   - Return SELECT columns starting with audit_id, ts_utc, artifact_id, event_type
//   - Reject SQL containing INSERT/UPDATE/DELETE/ATTACH/DROP/CREATE/PRAGMA
//     (defensive — the LLM shouldn't generate them but a guardrail is cheap)
type Builder interface {
	BuildSQL(ctx context.Context, rule rulesrepo.RawRule, schemaDoc string) (*BuiltSQL, error)
	ModelID() string
}
