// Package rulesrepo loads upstream rule corpora (Sigma / Hayabusa / STIX)
// from their respective git submodules under rules/, normalises them into
// RawRule, and feeds them to the Tier 1A build pipeline.
//
// Each loader walks its own subdirectory and produces RawRule slices with
// rule_sha256 computed over the source file content. The build pipeline
// uses rule_sha256 as one of the three cache invalidation keys (with
// schema_version and model_id — see internal/rulesdb/manager.go).
//
// Skip semantics: when a rule cannot or should not be built (non-Windows,
// Sysmon-only when --include-sysmon is off, malformed YAML, etc.) the
// loader returns the RawRule with Skip=true + a SkipReason. The build
// pipeline filters these out instead of treating them as errors.
package rulesrepo

import "context"

// RawRule is the normalised representation of one upstream rule.
type RawRule struct {
	RuleID              string   // upstream-original id (Sigma UUID, STIX T-number, etc.)
	RuleSource          string   // "sigma" | "hayabusa" | "stix" | "custom"
	RuleSHA256          string   // hex SHA-256 of the source file content
	SourcePath          string   // relative path under rules/ for debugging
	PrefilterArtifacts  []string // unified_events.artifact_id values this rule targets ("" = all)

	// Well-known metadata extracted from upstream
	Title           string
	Description     string
	Level           string   // "critical" | "high" | "medium" | "low" | "informational"
	MITRETechniques []string // e.g. ["T1003.001", "T1059.001"]
	MITRETactics    []string // e.g. ["credential-access", "execution"]

	// TLVB-specific flags
	RequiresSysmon bool   // logsource implies Sysmon EVTX — excluded by default
	Skip           bool   // build pipeline should not generate SQL for this row
	SkipReason     string // why Skip is true (audit / debugging)

	// Raw upstream content, passed to the LLM verbatim so it can read
	// detection / selection / condition blocks. For STIX this is the
	// pretty-printed JSON.
	RawContent string
}

// Loader walks a single corpus root and yields its rules.
type Loader interface {
	Source() string                              // "sigma" | "hayabusa" | "stix"
	LoadAll(ctx context.Context) ([]RawRule, error)
}
