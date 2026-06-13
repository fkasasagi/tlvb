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
//   - Consistency rules R1-R4 (moai-style)
//   - Cross-evidence correlation across multiple evidences in one case
package tier2

import (
	"time"

	"github.com/tlvb/tlvb/internal/evidencex"
)

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
	// EvidenceFetches records files the agent pulled from the disk image while
	// analysing this cluster (on-demand evidence extraction). Empty unless the
	// agent requested a file and --evidence-fetch is enabled.
	EvidenceFetches []evidencex.FetchSummary
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
	// Reframed is true when a query that ran cleanly but returned 0 rows was
	// re-issued from a different angle (artifact/field/hypothesis) — an
	// investigative pivot, distinct from fixing a broken query (Corrected).
	Reframed bool `json:"reframed,omitempty"`
}

// SQLAttempt records one execution attempt of an active-search query, including
// self-correction retries. The ordered sequence makes the agent's error
// detection and recovery visible (and feeds the per-case execution log).
type SQLAttempt struct {
	N       int    `json:"n"`               // 1-based attempt number
	SQL     string `json:"sql"`             // the SQL executed this attempt
	Outcome string `json:"outcome"`         // ok | no_evidence | validation_error | execute_error | null_result
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
	// OverallStory is the case-wide executive summary. For backward
	// compatibility it always holds the technical layer (== TechSummary), so
	// older readers and the Web UI keep working unchanged.
	OverallStory string `json:"overall_story"`
	// ExecBrief is the non-technical "key findings" layer of the executive
	// summary (Layer 1) — short bullet points for a decision-maker, no process
	// names / registry paths / EventIDs. Empty when the LLM produced no
	// `---EXEC---` section or the deterministic fallback was used.
	ExecBrief string `json:"exec_brief,omitempty"`
	// TechSummary is the DFIR-analyst layer of the executive summary (Layer 2)
	// — the existing 4-5 paragraph technical prose. Equal to OverallStory.
	TechSummary string `json:"tech_summary,omitempty"`
	// OverallStoryFallback is true when OverallStory is the deterministic
	// per-cluster stitch used because the LLM overall synthesis failed.
	// Tier 3 renders its warning banner from this flag; the banner-prefix
	// sniff remains only for synthesis.json written before this field.
	OverallStoryFallback bool         `json:"overall_story_fallback,omitempty"`
	MITREMapping         []MITREEntry `json:"mitre_mapping"`
	// MITREUnconfirmed holds techniques that are NOT asserted as confirmed: either
	// the Tier 2 cluster LLM proposed them with no finding backing, or a
	// finding-derived technique was demoted because the case lacks the
	// corroboration a high-impact, FP-prone tag needs (web shell with no web
	// server, Pass-the-Hash explained by a brute-force burst, timestomp on an
	// unreliable clock). Kept separate so the authoritative matrix is not inflated
	// by misleading signature tags (issue #82, tasks 2-4).
	MITREUnconfirmed []MITREEntry `json:"mitre_unconfirmed,omitempty"`
	// MITREDemotionNotes explains, in human-readable form, why finding-derived
	// techniques were demoted to MITREUnconfirmed. Empty when nothing was demoted.
	MITREDemotionNotes []string `json:"mitre_demotion_notes,omitempty"`
	// TimelineReliability is "reliable" or "unreliable". "unreliable" means a
	// deterministic check found the case timeline is internally inconsistent
	// (clusters separated by clock jumps / years-apart provisioning activity), so
	// any "attacker rewound the clock / re-intrusion" reading must be treated as a
	// re-anchoring problem first, not as an anti-forensic attack (issue #82, task 1).
	TimelineReliability string `json:"timeline_reliability,omitempty"`
	// TimelineNotes carries the human-readable reasons behind TimelineReliability.
	TimelineNotes []string `json:"timeline_notes,omitempty"`
	// UngroundedMentions lists named offensive tools / techniques that appear in
	// the executive/technical summary prose without any supporting finding. The
	// report renders them as "unconfirmed" rather than asserting them (issue #82,
	// task 2).
	UngroundedMentions []string `json:"ungrounded_mentions,omitempty"`
	// OpenQuestions is the flat, deduplicated union of every cluster's open
	// questions (kept for backward compatibility and as the fallback view).
	OpenQuestions []string `json:"open_questions,omitempty"`
	// OpenQuestionsSynth is the LLM-consolidated, prioritised view of the open
	// questions (critical / needs-collection / supplementary). Empty when the
	// consolidation LLM was skipped or failed — the report then falls back to
	// the flat OpenQuestions list.
	OpenQuestionsSynth OpenQuestionsSynthesis `json:"open_questions_synthesis,omitempty"`
	Audit              SynthAudit             `json:"audit"`
}

// OpenQuestionsSynthesis is the prioritised, deduplicated consolidation of the
// per-cluster open questions, produced by a dedicated Tier 2 LLM pass
// (skills/open_questions_synthesis.md). Splitting ~50 raw bullet points into
// three actionable tiers was a common reviewer ask (report improvement Vol.2).
type OpenQuestionsSynthesis struct {
	// Critical: questions whose answers would change the conclusions about root
	// cause, initial access, or scope of compromise (max ~5).
	Critical []string `json:"critical,omitempty"`
	// NeedsCollection: questions resolvable by obtaining a specific additional
	// artifact (the artifact is named in each item).
	NeedsCollection []string `json:"needs_collection,omitempty"`
	// Supplementary: everything else, lower priority.
	Supplementary []string `json:"supplementary,omitempty"`
}

// IsEmpty reports whether the synthesis carries no questions in any tier — the
// signal the report uses to fall back to the flat OpenQuestions list.
func (o OpenQuestionsSynthesis) IsEmpty() bool {
	return len(o.Critical) == 0 && len(o.NeedsCollection) == 0 && len(o.Supplementary) == 0
}

// SynthCluster is the cluster shape in synthesis.json. Drops the heavy
// fields (raw timeline excerpt) — those stay only as Tier 2 input.
type SynthCluster struct {
	ID          int          `json:"id"`
	StartTS     time.Time    `json:"start_ts"`
	EndTS       time.Time    `json:"end_ts"`
	AttackPhase string       `json:"attack_phase,omitempty"`
	Narrative   string       `json:"narrative"`
	FindingRefs []FindingRef `json:"finding_refs"`
	// MITRETechniques is the finding-derived (confirmed) technique set for the
	// cluster. MITREUnconfirmed holds techniques the cluster LLM narrative added
	// that no finding backs — kept separate so the report can label them as
	// inference rather than confirmed detection (issue #82, task 2).
	MITRETechniques  []string             `json:"mitre_techniques,omitempty"`
	MITREUnconfirmed []string             `json:"mitre_unconfirmed,omitempty"`
	OpenQuestions    []string             `json:"open_questions,omitempty"`
	ActiveSearch     []ActiveSearchResult `json:"active_search,omitempty"`
	// EvidenceFetches surfaces, per cluster, which files the agent read from the
	// disk image to reach its narrative (audit trail for Review Gate 2 / Web).
	EvidenceFetches []evidencex.FetchSummary `json:"evidence_fetches,omitempty"`
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
	case "heuristic":
		// Tier 2 deterministic heuristic over real logged events (e.g. the 4625
		// brute-force burst detector). Not an LLM judgement — confirmed.
		return "heuristic", "confirmed"
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
	ActiveSQLCorrectionRounds int `json:"active_sql_correction_rounds,omitempty"`
	// ActiveSQLReframed counts queries that executed cleanly, returned 0 rows,
	// and were re-issued from a different artifact/field/hypothesis (an
	// investigative pivot). The headline metric for "recognised the result did
	// not answer the question and changed approach mid-run".
	ActiveSQLReframed int `json:"active_sql_reframed,omitempty"`
	// ActiveSQLNoEvidence counts 0-row queries the agent judged a TRUE negative
	// (the honest answer is "nothing here") — either no pivot was taken or the
	// pivot also found nothing. An honest-negative signal, not a failure.
	ActiveSQLNoEvidence int    `json:"active_sql_no_evidence,omitempty"`
	SkillSHA256         string `json:"skill_sha256,omitempty"`

	// On-demand evidence extraction accounting (across all clusters).
	EvidenceRounds       int `json:"evidence_rounds,omitempty"`
	EvidenceFilesRequest int `json:"evidence_files_requested,omitempty"`
	EvidenceFilesGot     int `json:"evidence_files_extracted,omitempty"`
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
