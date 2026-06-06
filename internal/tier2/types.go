// Package tier2 is the Timeline Analysis Agent — Tier 2 of TLVB.
//
// Input: outputs/cases/<id>/findings/by-rule/**.json (Tier 1A)
//
//	outputs/cases/<id>/findings/by-skill/*.json  (Tier 1B)
//
// Output: outputs/cases/<id>/synthesis.json
//
// Tier 2 (v0.1 MVP scope):
//   - Load both finding sources, normalise to a unified Finding type
//   - Cluster findings temporally (within 30 min → same cluster)
//   - For each cluster, query unified_events for ±N min raw timeline
//     (artifact-stratified, noise EIDs excluded)
//   - LLM (claude CLI) reads cluster findings + raw timeline →
//     produces attack-chain narrative + MITRE mapping + open questions
//   - Write CaseSynthesis to synthesis.json
//
// Deferred to v0.2:
//   - Active wide-range SQL generation (hypothesis-driven exploration)
//   - Consistency rules R1-R4 (findevil-style)
//   - Cross-evidence correlation across multiple evidences in one case
package tier2

import "time"

// Finding is the unified shape Tier 2 reasons about. Sources:
//   - Tier 1A "cached SQL hit" — by-rule/<source>/<id>.json (one Finding per file)
//   - Tier 1A Hayabusa pass-through — by-rule/hayabusa/<id>.json (same shape)
//   - Tier 1B anomaly_hunter — by-skill/anomaly_hunter.json (wrapped array)
type Finding struct {
	FindingID       string
	Source          string // "sigma" | "hayabusa" | "stix" | "custom" | "anomaly_hunter"
	RuleID          string // upstream id (Sigma UUID, Hayabusa UUID, T-number, or skill lens id)
	Title           string
	Description     string // populated for Tier 1B; empty for Tier 1A signature hits
	Severity        string // critical | high | medium | low | informational
	MITRETechniques []string
	MITRETactic     string
	Evidence        []FindingEvidence
	OriginPath      string // file path the finding came from (for audit)
}

// FindingEvidence is one unified_events row that supports a Finding.
type FindingEvidence struct {
	AuditID    string
	TsUTC      time.Time
	HasTS      bool
	ArtifactID string
	EventType  string
	// Extra is opaque artifact-specific projection (Tier 1A SQL output columns,
	// or selected payload fields for pass-through).
	Extra map[string]any
}

// FirstTimestamp returns the earliest evidence ts for the finding, or zero
// time if none. Used for temporal clustering.
func (f Finding) FirstTimestamp() time.Time {
	var earliest time.Time
	for _, e := range f.Evidence {
		if !e.HasTS {
			continue
		}
		if earliest.IsZero() || e.TsUTC.Before(earliest) {
			earliest = e.TsUTC
		}
	}
	return earliest
}

// Cluster is a temporal grouping of findings whose evidence falls within
// a configurable max gap (default 30 min) of each other.
type Cluster struct {
	ID       int
	StartTS  time.Time
	EndTS    time.Time
	Findings []Finding
	// Narrative is filled in by the LLM pass.
	Narrative          string
	MITRETechniques    []string // union of finding-level + LLM-added
	OpenQuestions      []string
	AttackPhase        string          // e.g. "initial-access", "execution", "impact"
	RawTimelineExcerpt []TimelineEvent // ±N min around the cluster (raw events)
	// ActiveSearch holds wide-range hypothesis-driven query results.
	// Populated only when --active-search is enabled. Each entry pairs an
	// open question with the SQL that tried to answer it.
	ActiveSearch []ActiveSearchResult
}

// ActiveSearchResult is one "open question → SQL → answer" round-trip.
type ActiveSearchResult struct {
	Question string          // the open_question being investigated
	SQL      string          // the SELECT that finally ran (last attempt)
	Hits     int             // total matching rows (may exceed len(Evidence))
	Evidence []TimelineEvent // up to MaxEvidenceActive rows from the SQL
	Answer   string          // LLM's interpretation written after seeing the evidence
	Error    string          // populated when SQL validation / execution failed
	// Attempts is the self-correction trail: attempt 1 is the LLM's original
	// SQL; each later entry is a revision the agent made after feeding the prior
	// failure back to the LLM. len(Attempts) > 1 means the agent corrected its
	// own query at runtime — the hackathon "self-correction" requirement made
	// auditable.
	Attempts []SQLAttempt `json:"attempts,omitempty"`
	// Corrected is true when the query failed on attempt 1 but a self-correction
	// round produced a working query.
	Corrected bool `json:"corrected,omitempty"`
}

// SQLAttempt records one execution attempt of an active-search query, including
// self-correction retries. The ordered sequence makes the agent's error
// detection and recovery visible (and feeds the per-case execution log).
type SQLAttempt struct {
	N       int    `json:"n"`               // 1-based attempt number
	SQL     string `json:"sql"`             // the SQL executed this attempt
	Outcome string `json:"outcome"`         // ok | validation_error | execute_error | null_result
	Error   string `json:"error,omitempty"` // failure detail (empty when ok)
	Hits    int    `json:"hits"`            // rows returned this attempt
}

// TimelineEvent is one raw unified_events row used as context for the LLM.
type TimelineEvent struct {
	AuditID    string
	TsUTC      time.Time
	ArtifactID string
	EventType  string
	Excerpt    map[string]any // shrunken payload (artifact-aware)
}

// CaseSynthesis is the final Tier 2 output. Serialised to synthesis.json.
type CaseSynthesis struct {
	CaseID        string         `json:"case_id"`
	GeneratedAt   time.Time      `json:"generated_at"`
	ModelID       string         `json:"model_id,omitempty"`
	TotalFindings int            `json:"total_findings"`
	ClusterCount  int            `json:"cluster_count"`
	Clusters      []SynthCluster `json:"clusters"`
	OverallStory  string         `json:"overall_story"`
	MITREMapping  []MITREEntry   `json:"mitre_mapping"`
	OpenQuestions []string       `json:"open_questions,omitempty"`
	Audit         SynthAudit     `json:"audit"`
}

// SynthCluster is the cluster shape in synthesis.json. Drops the heavy
// fields (raw timeline excerpt) — those stay only as Tier 2 input.
type SynthCluster struct {
	ID              int                  `json:"id"`
	StartTS         time.Time            `json:"start_ts"`
	EndTS           time.Time            `json:"end_ts"`
	AttackPhase     string               `json:"attack_phase,omitempty"`
	Narrative       string               `json:"narrative"`
	FindingRefs     []FindingRef         `json:"finding_refs"`
	MITRETechniques []string             `json:"mitre_techniques,omitempty"`
	OpenQuestions   []string             `json:"open_questions,omitempty"`
	ActiveSearch    []ActiveSearchResult `json:"active_search,omitempty"`
}

// FindingRef is a compact reference to a Tier 1 finding inside a cluster.
type FindingRef struct {
	Source   string `json:"source"`
	RuleID   string `json:"rule_id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	// Provenance / Confidence record HOW the finding was derived, so the report
	// and Review UI can separate machine-confirmed evidence from AI inference.
	// signature → a deterministic Tier 1A rule matched real events (confirmed);
	// anomaly-llm → a Tier 1B LLM judged the pattern anomalous (inferred).
	Provenance string `json:"provenance,omitempty"` // signature | anomaly-llm
	Confidence string `json:"confidence,omitempty"` // confirmed | inferred
}

// ProvenanceForSource maps a finding's source engine to its provenance and
// confidence. Tier 1A signature rules (sigma/hayabusa/stix/custom) matched real
// logged events deterministically (confirmed); the Tier 1B anomaly_hunter lens
// is an LLM judgement (inferred). Confidence describes the derivation method,
// not certainty of malice — both still require Examiner validation.
func ProvenanceForSource(source string) (provenance, confidence string) {
	switch source {
	case "anomaly_hunter", "tier1b":
		return "anomaly-llm", "inferred"
	default: // sigma | hayabusa | stix | custom
		return "signature", "confirmed"
	}
}

// MITREEntry is one (tactic, technique, evidence_count) row in the
// case-wide MITRE mapping.
type MITREEntry struct {
	Tactic       string `json:"tactic,omitempty"`
	Technique    string `json:"technique"`
	FindingCount int    `json:"finding_count"`
	ClusterIDs   []int  `json:"cluster_ids"`
}

// SynthAudit captures provenance for the synthesis.
type SynthAudit struct {
	LLMCallsTotal int     `json:"llm_calls_total"`
	LLMDurationS  float64 `json:"llm_duration_s"`
	// Token accounting across all Tier 2 LLM calls. InputTokensTotal is the
	// non-cached (newly billed) input; CacheRead/CacheCreation are tracked
	// separately because prompt caching serves most of the input.
	InputTokensTotal         int     `json:"input_tokens_total,omitempty"`
	CacheReadTokensTotal     int     `json:"cache_read_tokens_total,omitempty"`
	CacheCreationTokensTotal int     `json:"cache_creation_tokens_total,omitempty"`
	OutputTokensTotal        int     `json:"output_tokens_total,omitempty"`
	TotalCostUSD             float64 `json:"total_cost_usd,omitempty"`
	ClustersAnalysed         int     `json:"clusters_analysed"`
	ClustersSkippedNoLLM     int     `json:"clusters_skipped_no_llm,omitempty"`
	ActiveSearchEnabled      bool    `json:"active_search_enabled,omitempty"`
	ActiveSQLAttempted       int     `json:"active_sql_attempted,omitempty"`
	ActiveSQLSucceeded       int     `json:"active_sql_succeeded,omitempty"`
	// ActiveSQLNullResult counts queries that executed and returned rows but
	// whose projected columns were all NULL — executed-but-useless (usually a
	// wrong JSON path). Tracked separately so ActiveSQLSucceeded means "useful".
	ActiveSQLNullResult int `json:"active_sql_null_result,omitempty"`
	// ActiveSQLSelfCorrected counts queries that FAILED on their first attempt
	// but became useful after >=1 LLM self-correction round — the headline metric
	// for autonomous runtime error-recovery.
	ActiveSQLSelfCorrected int `json:"active_sql_self_corrected,omitempty"`
	// ActiveSQLCorrectionRounds is the total number of self-correction LLM calls
	// made across all queries (the cost side of self-correction).
	ActiveSQLCorrectionRounds int    `json:"active_sql_correction_rounds,omitempty"`
	SkillSHA256               string `json:"skill_sha256,omitempty"`
}

// addUsage folds one claudeOutput's token + cost figures into the audit.
// Centralises the accumulation so every call site (per-cluster, overall,
// active-search) records cache_read / cache_creation / cost consistently.
func (a *SynthAudit) addUsage(out *claudeOutput) {
	a.InputTokensTotal += out.Usage.InputTokens
	a.CacheReadTokensTotal += out.Usage.CacheReadInputTokens
	a.CacheCreationTokensTotal += out.Usage.CacheCreationInputTokens
	a.OutputTokensTotal += out.Usage.OutputTokens
	a.TotalCostUSD += out.TotalCostUSD
}
