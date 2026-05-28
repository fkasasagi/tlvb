package synthesizer

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	_ "github.com/marcboeker/go-duckdb"

	"github.com/tlvb/tlvb/internal/agents"
)

// CaseSynthesis matches docs/DESIGN.md §6.6.
//
// Fields the deterministic Synthesizer fills today:
//   - case_id, evidence_id, timezone
//   - intrusion_path (from inferAttackSteps)
//   - affected_scope.compromised_hosts (distinct Computers from evidence)
//   - timeline (resolved from unified_events)
//   - findings_by_tactic
//   - inconsistencies (R1–R4)
//   - mitre_mapping (aggregated)
//   - audit
//
// Fields LLM-driven Tier-2-prose features will fill later:
//   - executive_summary
//   - recommendations.*
//   - affected_scope.compromised_accounts / data_at_risk
type CaseSynthesis struct {
	CaseID           string                       `json:"case_id"`
	EvidenceID       string                       `json:"evidence_id"`
	// EvidenceIDs lists every evidence the case has registered at synth
	// time (★v0.3 #7). Empty means the case is single-evidence (legacy)
	// or the synthesis was generated before this field existed.
	EvidenceIDs      []string                     `json:"evidence_ids,omitempty"`
	Timezone         string                       `json:"timezone"`
	GeneratedAt      time.Time                    `json:"generated_at"`
	ExecutiveSummary string                       `json:"executive_summary"`
	IntrusionPath    []AttackStep                 `json:"intrusion_path"`
	AffectedScope    AffectedScope                `json:"affected_scope"`
	Timeline         []TimelineEntry              `json:"timeline"`
	FindingsByTactic map[string][]agents.Finding  `json:"findings_by_tactic"`
	FindingClusters  []FindingCluster             `json:"finding_clusters"`
	Inconsistencies  []Inconsistency              `json:"inconsistencies"`
	Recommendations  Recommendations              `json:"recommendations"`
	MITREMapping     []MITREMappingEntry          `json:"mitre_mapping"`
	UnresolvedRefs   []string                     `json:"unresolved_audit_ids,omitempty"`
	Stats            Stats                        `json:"stats"`
	Audit            CaseAudit                    `json:"audit"`
	CorrectionReport *CorrectionReport            `json:"correction_report,omitempty"`
	// TimelineReview holds the optional Tier 2 LLM-driven review of the
	// aggregate temporal picture (DESIGN §6.7). Nil when disabled via
	// Config.ReviewTimeline=false. Non-nil but with
	// Audit.SkippedReason set when the LLM was attempted and failed
	// gracefully.
	TimelineReview *TimelineReview `json:"timeline_review,omitempty"`
	// FailedArtifacts lists artifacts the orchestrator attempted to parse
	// but couldn't complete — exit_code != 0 or the parser raised an
	// exception before persisting events. Issue #26: surfaced in the
	// report so examiners know which evidence categories were NOT covered.
	FailedArtifacts []FailedArtifact `json:"failed_artifacts,omitempty"`

	// CrossEvidenceCorrelations (Wave 24, DESIGN v0.3 #7) records when the
	// same MITRE technique was observed across multiple evidence_ids in
	// the case. Useful for multi-host engagements — single-evidence cases
	// emit nothing here. omitempty so legacy reports remain comparable.
	CrossEvidenceCorrelations []CrossEvidenceCorrelation `json:"cross_evidence_correlations,omitempty"`
}

// FailedArtifact records one parse_results row whose run did not succeed.
// Stage is "parse" today; the field exists so a future image-extract
// pre-step (Issue #23) can report its own failures uniformly.
type FailedArtifact struct {
	ArtifactID string `json:"artifact_id"`
	Stage      string `json:"stage"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	Reason     string `json:"reason"`
	Command    string `json:"command,omitempty"`
}

type AffectedScope struct {
	CompromisedHosts    []string `json:"compromised_hosts"`
	CompromisedAccounts []string `json:"compromised_accounts"` // populated by LLM step
	DataAtRisk          []string `json:"data_at_risk"`         // populated by LLM step
}

type Recommendations struct {
	Containment []string `json:"containment"`
	Eradication []string `json:"eradication"`
	Recovery    []string `json:"recovery"`
	// NextSteps lists "we couldn't investigate this — recommend you do
	// next" items derived from observable gaps in the case data.
	// Examples: unresolved audit_ids hint at LLM hallucinations worth
	// re-running; lateral-movement findings without a registered source-
	// host evidence suggest collecting that host. ★v0.3 #10.
	NextSteps   []string `json:"next_steps,omitempty"`
}

type MITREMappingEntry struct {
	Tactic        string `json:"tactic"`
	TacticName    string `json:"tactic_name"`
	Technique     string `json:"technique"`
	TechniqueName string `json:"technique_name"`
	EvidenceCount int    `json:"evidence_count"`
	FindingCount  int    `json:"finding_count"`
	Confidence    string `json:"confidence"` // max across findings
}

type CaseAudit struct {
	TotalTokens             int     `json:"total_tokens"`
	TotalIterations         int     `json:"total_iterations"`
	CorrectionRounds        int     `json:"correction_rounds"`
	ExecutionTimeSeconds    float64 `json:"execution_time_seconds"`
	ReportsAggregated       int     `json:"reports_aggregated"`
	UnresolvedRefCount      int     `json:"unresolved_ref_count"`
	SynthesizerVersion      string  `json:"synthesizer_version"`
}

const synthesizerVersion = "synthesizer/0.1.0-deterministic"

// Config controls one Synthesize call.
type Config struct {
	CaseID       string
	EvidenceID   string // optional; used in CaseSynthesis output only
	// EvidenceIDs is the full set of evidences in scope (★v0.3 #7).
	// Stamped onto the resulting CaseSynthesis.
	EvidenceIDs  []string
	Timezone     string // case display TZ; defaults to UTC
	FindingsDir  string
	DBPath       string

	// Language (Wave 26) picks the locale of the deterministically-generated
	// Recommendations bullets. "ja" → Japanese, "en" → English. Defaults to
	// "en" for back-compat (the strings were English-only pre-Wave-26).
	// The Tier 3 renderer's dict (containment/eradication/recovery labels)
	// is separately controlled by reporter.Config.Language — both should
	// match for a coherent report.
	Language     string

	// Correct enables the Corrector. When true, after the initial
	// consistency check, every warning-severity rule whose rule->tactic
	// mapping is non-empty triggers a Tactic Agent re-run. Findings are
	// merged back, then synthesis runs a second time over the augmented
	// findings.
	Correct       bool
	CorrectorCfg  CorrectionConfig // engine + caps for the re-run agents

	// ReviewTimeline enables the Tier 2 TimelineReviewer (DESIGN §6.7).
	// When true, after Correct() resolves (or doesn't), the LLM is given
	// a compact view of the timeline + R1-R4 + top findings and asked to
	// apply the 12 forensic perspectives in skills/timeline_review.md.
	// The result is attached to CaseSynthesis.TimelineReview. Graceful:
	// on any LLM unavailability, the review is recorded with
	// Audit.SkippedReason and synthesis still succeeds.
	ReviewTimeline   bool
	TimelineReviewCfg TimelineReviewConfig
}

// Synthesize runs Aggregator + ConsistencyChecker + TimelineBuilder and
// returns a CaseSynthesis. Caller persists it (e.g. as JSON).
func Synthesize(ctx context.Context, cfg Config) (*CaseSynthesis, error) {
	startedAt := time.Now().UTC()
	if cfg.CaseID == "" {
		return nil, fmt.Errorf("case_id is required")
	}
	if cfg.FindingsDir == "" {
		return nil, fmt.Errorf("findings_dir is required")
	}
	if cfg.DBPath == "" {
		return nil, fmt.Errorf("db_path is required")
	}
	tz := cfg.Timezone
	if tz == "" {
		tz = "UTC"
	}

	// Step 1 — Aggregate findings.
	agg, err := Aggregate(cfg.CaseID, cfg.FindingsDir)
	if err != nil {
		return nil, fmt.Errorf("aggregate: %w", err)
	}

	// Step 2 — Open the case DB read-only for consistency + timeline.
	db, err := sql.Open("duckdb", cfg.DBPath+"?access_mode=read_only")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	// Step 3 — Consistency check.
	inconsistencies, err := CheckConsistency(ctx, db, cfg.CaseID, agg)
	if err != nil {
		return nil, fmt.Errorf("consistency: %w", err)
	}
	SortInconsistencies(inconsistencies)

	// Step 3b (Wave 24) — Cross-evidence correlation. Multi-host engagements
	// only; single-evidence cases get nil back and the field stays omitempty.
	crossEvidence, err := DetectCrossEvidence(ctx, db, cfg.CaseID, agg)
	if err != nil {
		// Don't fail the whole synthesis if cross-evidence detection has
		// trouble — it's an enrichment, not a critical step. Log instead.
		fmt.Fprintf(os.Stderr, "synthesizer: cross_evidence skipped: %v\n", err)
		crossEvidence = nil
	}

	// Step 4 — Timeline + intrusion path.
	timeline, steps, unresolved, err := BuildTimeline(ctx, db, cfg.CaseID, agg)
	if err != nil {
		return nil, fmt.Errorf("timeline: %w", err)
	}

	// Step 5 — Affected scope (compromised hosts) from timeline rows.
	hosts := map[string]struct{}{}
	for _, t := range timeline {
		if t.Computer != "" {
			hosts[t.Computer] = struct{}{}
		}
	}
	hostList := sortedKeys(hosts)

	// Step 6 — MITRE mapping.
	mapping := buildMITREMapping(agg)

	// Step 7 — findings_by_tactic.
	findingsByTactic := map[string][]agents.Finding{}
	for _, rep := range agg.Reports {
		findingsByTactic[rep.TacticID] = append(
			findingsByTactic[rep.TacticID], rep.Findings...)
	}

	// Step 8 — audit aggregation across reports.
	totalTokens := 0
	totalIters := 0
	for _, rep := range agg.Reports {
		totalTokens += rep.Audit.TokensInput + rep.Audit.TokensOutput
		totalIters += rep.Audit.Iterations
	}

	// Optional: run Corrector loop if enabled and any warning fired.
	var correctionReport *CorrectionReport
	if cfg.Correct && hasActionableWarning(inconsistencies) {
		cc := cfg.CorrectorCfg
		// Inherit case-level fields from the parent config.
		cc.CaseID = cfg.CaseID
		cc.EvidenceID = cfg.EvidenceID
		cc.FindingsDir = cfg.FindingsDir
		cc.DBPath = cfg.DBPath

		cr, _, cerr := Correct(ctx, cc, agg, inconsistencies)
		if cerr != nil {
			return nil, fmt.Errorf("corrector: %w", cerr)
		}
		correctionReport = cr

		// Re-aggregate (file mutation) and re-check if anything got merged.
		if cr != nil && len(cr.AgentsRetried) > 0 {
			db.Close() // release read-only handle before reopening
			db, err = sql.Open("duckdb", cfg.DBPath+"?access_mode=read_only")
			if err != nil {
				return nil, fmt.Errorf("reopen db: %w", err)
			}
			defer db.Close()

			agg, err = Aggregate(cfg.CaseID, cfg.FindingsDir)
			if err != nil {
				return nil, fmt.Errorf("re-aggregate: %w", err)
			}
			inconsistencies, err = CheckConsistency(ctx, db, cfg.CaseID, agg)
			if err != nil {
				return nil, fmt.Errorf("re-consistency: %w", err)
			}
			SortInconsistencies(inconsistencies)
			timeline, steps, unresolved, err = BuildTimeline(ctx, db, cfg.CaseID, agg)
			if err != nil {
				return nil, fmt.Errorf("re-timeline: %w", err)
			}
			hosts = map[string]struct{}{}
			for _, t := range timeline {
				if t.Computer != "" {
					hosts[t.Computer] = struct{}{}
				}
			}
			hostList = sortedKeys(hosts)
			mapping = buildMITREMapping(agg)
			findingsByTactic = map[string][]agents.Finding{}
			for _, rep := range agg.Reports {
				findingsByTactic[rep.TacticID] = append(
					findingsByTactic[rep.TacticID], rep.Findings...)
			}

			// After re-check, distinguish resolved vs still-firing.
			stillFiring := map[string]struct{}{}
			for _, inc := range inconsistencies {
				if inc.Severity == "warning" {
					stillFiring[inc.Rule] = struct{}{}
				}
			}
			var resolved, unresolvedRules []string
			for _, rule := range cr.UnresolvedRules {
				if _, still := stillFiring[rule]; still {
					unresolvedRules = append(unresolvedRules, rule)
				} else {
					resolved = append(resolved, rule)
				}
			}
			cr.ResolvedRules = resolved
			cr.UnresolvedRules = unresolvedRules
		}
	}

	exec := generateExecutiveSummary(agg, inconsistencies, hostList, steps)

	finishedAt := time.Now().UTC()
	cs := &CaseSynthesis{
		CaseID:           cfg.CaseID,
		EvidenceID:       cfg.EvidenceID,
		EvidenceIDs:      append([]string(nil), cfg.EvidenceIDs...),
		Timezone:         tz,
		GeneratedAt:      finishedAt,
		ExecutiveSummary: exec,
		IntrusionPath:    steps,
		AffectedScope: AffectedScope{
			CompromisedHosts:    hostList,
			CompromisedAccounts: nil, // LLM step
			DataAtRisk:          nil, // LLM step
		},
		Timeline:         timeline,
		FindingsByTactic: findingsByTactic,
		FindingClusters:  agg.Clusters,
		Inconsistencies:  inconsistencies,
		Recommendations:  generateRecommendations(agg, inconsistencies, unresolved, hostList, cfg.Language),
		MITREMapping:     mapping,
		UnresolvedRefs:   unresolved,
		Stats:            agg.Stats,
		Audit: CaseAudit{
			TotalTokens:          totalTokens,
			TotalIterations:      totalIters,
			CorrectionRounds:     correctionRoundsRun(correctionReport),
			ExecutionTimeSeconds: finishedAt.Sub(startedAt).Seconds(),
			ReportsAggregated:    len(agg.Reports),
			UnresolvedRefCount:   len(unresolved),
			SynthesizerVersion:   synthesizerVersion,
		},
		CorrectionReport:          correctionReport,
		FailedArtifacts:           collectFailedArtifacts(ctx, db),
		CrossEvidenceCorrelations: crossEvidence, // Wave 24 (DESIGN v0.3 #7)
	}

	// Recompute audit token/iter aggregations after Correct (the merged
	// reports now have updated audit fields).
	totalTokens = 0
	totalIters = 0
	for _, rep := range agg.Reports {
		totalTokens += rep.Audit.TokensInput + rep.Audit.TokensOutput
		totalIters += rep.Audit.Iterations
	}
	cs.Audit.TotalTokens = totalTokens
	cs.Audit.TotalIterations = totalIters

	// Optional Tier 2 TimelineReviewer (DESIGN §6.7). Graceful by design:
	// the result is attached unconditionally, with Audit.SkippedReason set
	// when the LLM was unavailable so examiners can see "we tried, X
	// happened" rather than silent absence.
	if cfg.ReviewTimeline {
		trCfg := cfg.TimelineReviewCfg
		trCfg.CaseID = cfg.CaseID
		trCfg.EvidenceIDs = cfg.EvidenceIDs
		tr, _ := ReviewTimeline(ctx, trCfg, timeline, steps, inconsistencies, agg)
		cs.TimelineReview = tr
		if tr != nil {
			cs.Audit.TotalTokens += tr.Audit.InputTokens + tr.Audit.OutputTokens
		}
	}

	return cs, nil
}

// collectFailedArtifacts pulls parse_results rows whose exit_code indicates
// the parser run did not succeed. The DB schema doesn't store the
// ParseResult.error string explicitly, so we synthesise a reason from the
// stderr tail (first non-empty line) and fall back to a generic message.
// Issue #26.
func collectFailedArtifacts(ctx context.Context, db *sql.DB) []FailedArtifact {
	rows, err := db.QueryContext(ctx,
		`SELECT artifact_id, exit_code, COALESCE(stderr_tail,''), COALESCE(command,'')
		   FROM parse_results
		  WHERE exit_code IS NULL OR exit_code <> 0
		  ORDER BY artifact_id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []FailedArtifact
	for rows.Next() {
		var (
			artifactID string
			exit       sql.NullInt64
			stderr     string
			cmd        string
		)
		if err := rows.Scan(&artifactID, &exit, &stderr, &cmd); err != nil {
			continue
		}
		fa := FailedArtifact{
			ArtifactID: artifactID,
			Stage:      "parse",
			Reason:     firstNonEmptyLine(stderr),
			Command:    cmd,
		}
		if exit.Valid {
			v := int(exit.Int64)
			fa.ExitCode = &v
		}
		if fa.Reason == "" {
			fa.Reason = "parser exited with non-zero status (no stderr captured)"
		}
		out = append(out, fa)
	}
	return out
}

func firstNonEmptyLine(s string) string {
	if s == "" {
		return ""
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			if len(line) > 400 {
				return line[:400] + "…"
			}
			return line
		}
	}
	return ""
}

func correctionRoundsRun(cr *CorrectionReport) int {
	if cr == nil {
		return 0
	}
	return cr.RoundsRun
}

// hasActionableWarning returns true if any inconsistency is severity=warning
// AND the rule has a non-empty tactic mapping. Both conditions must hold —
// info-severity rules and rules without tactic owners (R3 single-host)
// don't trigger correction.
func hasActionableWarning(inc []Inconsistency) bool {
	for _, i := range inc {
		if i.Severity != "warning" {
			continue
		}
		if len(affectedTacticsForRule(i.Rule)) == 0 {
			continue
		}
		return true
	}
	return false
}

// buildMITREMapping aggregates (tactic, technique) over all findings.
func buildMITREMapping(agg *AggregateResult) []MITREMappingEntry {
	type key struct{ Tactic, Technique string }
	type accum struct {
		TacticName    string
		TechniqueName string
		Findings      int
		Evidence      int
		MaxConfidence string
	}
	confRank := map[string]int{"low": 1, "medium": 2, "high": 3}
	m := map[key]*accum{}
	for _, fws := range agg.AllFindings {
		k := key{fws.TacticID, fws.Finding.TechniqueID}
		a, ok := m[k]
		if !ok {
			a = &accum{
				TacticName:    fws.TacticName,
				TechniqueName: fws.Finding.TechniqueName,
			}
			m[k] = a
		}
		a.Findings++
		a.Evidence += len(fws.Finding.Evidence)
		c := normaliseConfidence(fws.Finding.Confidence)
		if confRank[c] > confRank[a.MaxConfidence] {
			a.MaxConfidence = c
		}
	}

	out := make([]MITREMappingEntry, 0, len(m))
	for k, v := range m {
		out = append(out, MITREMappingEntry{
			Tactic:        k.Tactic,
			TacticName:    v.TacticName,
			Technique:     k.Technique,
			TechniqueName: v.TechniqueName,
			EvidenceCount: v.Evidence,
			FindingCount:  v.Findings,
			Confidence:    v.MaxConfidence,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Tactic != out[j].Tactic {
			return out[i].Tactic < out[j].Tactic
		}
		return out[i].Technique < out[j].Technique
	})
	return out
}

// generateExecutiveSummary is a deterministic 2–3-sentence template.
// LLM-driven prose generation will replace this — but a templated summary
// is better than an empty field for now, and stays grounded in the data.
func generateExecutiveSummary(
	agg *AggregateResult,
	inc []Inconsistency,
	hosts []string,
	steps []AttackStep,
) string {
	tactics := agg.Stats.TacticsRun
	if len(tactics) == 0 {
		return "No tactic agent reports were aggregated for this case."
	}
	hostStr := "(unknown host)"
	if len(hosts) == 1 {
		hostStr = hosts[0]
	} else if len(hosts) > 1 {
		hostStr = fmt.Sprintf("%d hosts", len(hosts))
	}
	first := ""
	if len(steps) > 0 {
		first = fmt.Sprintf(" Earliest attributed activity is %s (%s) at %s.",
			steps[0].Tactic, steps[0].TacticName,
			steps[0].Timestamp.UTC().Format(time.RFC3339))
	}
	warningCount := 0
	for _, i := range inc {
		if i.Severity == "warning" {
			warningCount++
		}
	}
	return fmt.Sprintf(
		"Aggregated %d tactic reports producing %d findings (%d clusters after dedup) "+
			"on %s.%s %d consistency warnings flagged for examiner review.",
		len(agg.Reports), agg.Stats.TotalFindings,
		agg.Stats.ClusterCount, hostStr, first, warningCount)
}

// recsLocale (Wave 26) maps a recommendation key to its ja/en pair.
// Keys are stable so the localization can be extended later (e.g. with
// zh/ko) by adding more language fields.
type recsLocaleEntry struct {
	JA string
	EN string
}

var recsLocale = map[string]recsLocaleEntry{
	"impact_containment": {
		JA: "影響範囲が確定するまで、影響を受けたホストをネットワークから隔離してください。",
		EN: "Isolate affected hosts from the network until impact actions are scoped.",
	},
	"impact_recovery": {
		JA: "バックアップが TA0040 (Impact) の最古証跡より前のものであることを確認し、オフライン保管のコピーから復元してください。",
		EN: "Verify backups predate the earliest TA0040 evidence and restore from offline copies.",
	},
	"cred_containment": {
		JA: "案件期間中に影響ホストで認証した全アカウントのパスワードを強制リセットしてください。",
		EN: "Force password reset for all accounts that authenticated on affected hosts during the case window.",
	},
	"cred_eradication": {
		JA: "認証情報窃取が確認された場合、Kerberos krbtgt を 2 回ローテーションしてください。",
		EN: "Rotate Kerberos krbtgt twice if credential theft is confirmed.",
	},
	"persistence_eradication": {
		JA: "特定された永続化アーティファクト (Registry Run キー / サービス / スケジュールタスク) を削除してください。",
		EN: "Remove identified persistence artifacts (registry Run keys, services, scheduled tasks).",
	},
	"lateral_containment": {
		JA: "影響ホスト上のラテラルムーブメント経路 (RDP / SMB / WinRM) を見直し、必要に応じて制限してください。",
		EN: "Review and tighten lateral-movement vectors (RDP, SMB, WinRM) on affected hosts.",
	},
	"r1_log_clear": {
		JA: "R1 フォローアップ: EVTX ログクリアが検出されたため ETW / Sysmon の補完収集を実施し、ラテラルムーブメント / 認証情報アクセスの計上漏れを前提に再評価してください。",
		EN: "R1 follow-up: collect ETW / sysmon backfill since EVTX log clearing was detected — assume Lateral Movement and Credential Access activity may be undercounted.",
	},
}

// rec picks the ja/en variant for a recommendation key. Falls back to EN
// for unknown lang values (the most conservative default).
func rec(lang, key string) string {
	e, ok := recsLocale[key]
	if !ok {
		return key
	}
	if lang == "ja" {
		return e.JA
	}
	return e.EN
}

// generateRecommendations is a thin deterministic pass — produces generic
// containment/eradication/recovery action items based on which tactics
// fired and which inconsistencies surfaced. The full LLM-prose version
// belongs in Tier 3. Wave 26: emits ja or en bullets per the lang arg.
func generateRecommendations(
	agg *AggregateResult, inc []Inconsistency,
	unresolvedRefs []string, compromisedHosts []string,
	lang string,
) Recommendations {
	r := Recommendations{}

	if agg.Stats.FindingsByTactic["TA0040"] > 0 {
		r.Containment = append(r.Containment, rec(lang, "impact_containment"))
		r.Recovery = append(r.Recovery, rec(lang, "impact_recovery"))
	}
	if agg.Stats.FindingsByTactic["TA0006"] > 0 {
		r.Containment = append(r.Containment, rec(lang, "cred_containment"))
		r.Eradication = append(r.Eradication, rec(lang, "cred_eradication"))
	}
	if agg.Stats.FindingsByTactic["TA0003"] > 0 {
		r.Eradication = append(r.Eradication, rec(lang, "persistence_eradication"))
	}
	if agg.Stats.FindingsByTactic["TA0008"] > 0 {
		r.Containment = append(r.Containment, rec(lang, "lateral_containment"))
	}
	for _, i := range inc {
		if i.Rule == "R1" && i.Severity == "warning" {
			r.Eradication = append(r.Eradication, rec(lang, "r1_log_clear"))
		}
	}

	r.NextSteps = generateNextSteps(agg, inc, unresolvedRefs, compromisedHosts)
	return r
}

// generateNextSteps produces "couldn't investigate, do this next"
// recommendations grounded in observable case-data gaps. Deterministic
// and conservative — never speculates beyond what the data shows.
//
// Trigger sources:
//   - Unresolved audit_ids → likely LLM-hallucinated evidence refs;
//     suggest re-running the affected Tactic or examining the report.
//   - TA0008 (Lateral Movement) findings without a corresponding source
//     host in CompromisedHosts → likely missing evidence collection.
//   - Findings citing file_paths but no hash → suggest VirusTotal /
//     sandbox lookup of the binary.
//   - Tier 0 parse_results gaps (artifact_ids the case lacks) →
//     suggest re-collection or a different parser.
//
// ★v0.3 #10
func generateNextSteps(
	agg *AggregateResult, inc []Inconsistency,
	unresolvedRefs []string, compromisedHosts []string,
) []string {
	steps := []string{}

	if len(unresolvedRefs) > 0 {
		preview := unresolvedRefs
		if len(preview) > 3 {
			preview = preview[:3]
		}
		steps = append(steps, fmt.Sprintf(
			"%d 件の audit_id が unified_events に解決されません(LLM ハルシネーション疑い)。"+
				"先頭例: %s。該当 finding を持つ Tactic Agent を再実行(`tlvb analyze CASE_ID --tactic <slug>`)してください",
			len(unresolvedRefs), strings.Join(preview, ", ")))
	}

	// Lateral Movement detected but only 1 host in CompromisedHosts —
	// the source-side host's evidence is probably uncollected.
	if agg.Stats.FindingsByTactic["TA0008"] > 0 && len(compromisedHosts) <= 1 {
		steps = append(steps, "TA0008 Lateral Movement の finding がありますが、影響ホストが "+
			"1 件以下しか登録されていません。流入元 / 流入先 ホストの evidence 追加収集を推奨します")
	}

	// Hash-poor findings (heuristic: count file_path mentions vs sha256
	// mentions across all reasoning + summary text — but we don't pre-
	// compute that here). Fall back to a generic prompt when there are
	// many findings.
	if agg.Stats.TotalFindings >= 10 {
		steps = append(steps, "Finding 中に登場する不審ファイルパス(`C:\\Users\\...\\*.exe` 等)について、"+
			"VirusTotal / サンドボックスで実ファイル解析を実施し、ハッシュベースの IOC 化を推奨")
	}

	// Persistence findings → consider memory image
	if agg.Stats.FindingsByTactic["TA0003"] > 0 {
		steps = append(steps, "TA0003 Persistence の finding があるため、攻撃者プロセスの常駐 "+
			"検証として **メモリダンプ + Volatility 3** (`vol -f <dump> windows.pslist` 等) "+
			"を取得することを推奨します(Tier 0 の memory パーサは未実装、別途取得)")
	}

	// Inconsistency rules that we don't already cover above
	for _, i := range inc {
		switch i.Rule {
		case "R2":
			if i.Severity == "warning" {
				steps = append(steps, "R2: Persistence finding はあるが Execution の痕跡(Prefetch/Amcache)が"+
					"乏しい — Prefetch が無効化されている可能性。SRUM / EvtxECmd の追加スコープを確認")
			}
		case "R3":
			if i.Severity == "warning" {
				steps = append(steps, "R3: マルチホスト時の流入元ホスト側に Lateral Movement finding がない "+
					"— 流入元ホストの evidence (EVTX + 認証ログ) を追加収集してください")
			}
		case "R4":
			if i.Severity == "warning" {
				steps = append(steps, "R4: Initial Access より時系列が前にある Execution finding を確認 — "+
					"真の侵入起点が現在の Kill Chain 先頭より前にある可能性。タイムライン伸長 (前 7 日) を推奨")
			}
		}
	}

	// If we have nothing, leave it empty (omitempty)
	return steps
}
