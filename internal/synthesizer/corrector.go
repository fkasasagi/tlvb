package synthesizer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/agents"
)

// Corrector implements DESIGN.md §6.5.
//
// Given a synthesis result with inconsistencies, the Corrector identifies
// which Tactic Agents are implicated by each rule, re-runs them with
// extra context describing the inconsistency, and merges any new findings
// back into the original TacticReport file. After at most MaxRounds
// (default 1), it returns a CorrectionReport describing what was retried
// and which rules were resolved.
//
// Hard rules (mirrors DESIGN.md):
//   - We only re-run Tier 1 (Tactic Agents). Tier 0 parsers are deterministic
//     and would produce the same output.
//   - We only react to severity="warning". info-severity inconsistencies are
//     observations, not actionable signals — re-running an agent for an
//     info note would burn tokens for no payoff.
//   - We never overwrite findings — we merge by finding_id. If the
//     re-run produces a duplicate finding_id, it is dropped (the original
//     finding is preserved for chain-of-custody continuity).

// CorrectionConfig controls one Correct() call.
type CorrectionConfig struct {
	CaseID       string
	EvidenceID   string
	FindingsDir  string
	DBPath       string
	Engine       string        // "claude-code" | "anthropic-api"
	APIKey       string        // required when Engine == "anthropic-api"
	Model        string        // optional model override
	MaxRounds    int           // default 1
	AgentTimeout time.Duration // default 5 min
	MaxEvents    int           // default 200
	MaxIters     int           // default 3
}

// CorrectionReport summarises what the Corrector did. The synthesizer
// embeds this into CaseSynthesis.audit so the final report can show
// "Round 1 retried initial_access + execution; R4 still unresolved".
type CorrectionReport struct {
	RoundsRun       int                  `json:"rounds_run"`
	AgentsRetried   []string             `json:"agents_retried"`
	NewFindingsAdded map[string]int      `json:"new_findings_added"` // tactic → count
	ResolvedRules   []string             `json:"resolved_rules"`
	UnresolvedRules []string             `json:"unresolved_rules"`
	Errors          []string             `json:"errors,omitempty"`
	Diagnostics     []CorrectorDiagnostic `json:"diagnostics"`
}

// CorrectorDiagnostic is one retry's audit trail (what was tried, was the
// inconsistency resolved). Examiner can read this in CaseSynthesis.
type CorrectorDiagnostic struct {
	Round      int           `json:"round"`
	Rule       string        `json:"rule"`
	Tactic     string        `json:"tactic"`
	Hint       string        `json:"hint"`
	Status     string        `json:"status"` // "retried_ok" | "retried_no_change" | "agent_failed"
	NewCount   int           `json:"new_findings_count"`
	DurationS  float64       `json:"duration_seconds"`
	Error      string        `json:"error,omitempty"`
}

// affectedTacticsForRule maps a consistency rule to the Tactic Agent slugs
// whose re-run might resolve it. Stays in sync with consistency.go.
//
// Empty map result = rule has no actionable Tier 1 owner. The Corrector
// will mark it unresolved-by-design.
func affectedTacticsForRule(rule string) []string {
	switch rule {
	case "R1":
		// Logs cleared; LM/CredAccess findings may be undercounted because
		// of Defense Evasion. Re-running won't generate more events but the
		// agent can mark T1070.001 as a confidence multiplier and emit
		// negative_findings explicitly.
		return []string{"lateral_movement", "credential_access"}
	case "R2":
		// Persistence cited no Prefetch/Amcache. Either the rows don't
		// exist (info, skipped) or the agent missed them — re-run prompts
		// the agent to look harder.
		return []string{"persistence"}
	case "R3":
		// Multi-host without LM source-host attribution.
		return []string{"lateral_movement"}
	case "R4":
		// Execution earlier than Initial Access. Re-run both: IA agent
		// looks for earlier evidence, Execution agent re-evaluates whether
		// the early process is actually pre-intrusion benign.
		return []string{"initial_access", "execution"}
	default:
		return nil
	}
}

// hintForRule returns the Japanese-language correction context the Agent
// will see appended to its user message. Speaks directly to the Agent.
func hintForRule(rule string, inc Inconsistency) string {
	switch rule {
	case "R1":
		return "前回の解析で Defense Evasion Agent が T1070.001 (Event Log Clear) "+
			"を検出しました。あなたの Tactic では finding 数が極端に少なく、"+
			"消されたログに該当痕跡が含まれていた可能性があります。今回の再走では、"+
			"(1) 残存している間接的シグナル (アカウント変更、サービス起動など) "+
			"を `negative_findings` ではなく低 confidence の finding として記録、"+
			"(2) 「ログクリアにより一次証拠が失われた」旨を summary に明示、"+
			"してください。\n\n発火した不整合: " + inc.Description
	case "R2":
		return "前回の解析であなたの Persistence finding が " +
			"Prefetch / Amcache を corroboration として引いていませんでした。"+
			"今回の再走では、`amcache` / `prefetch` artifact_id の events を "+
			"明示的に検索してから finding を立てるようにしてください。"+
			"これらが本当にケースに存在しない場合は negative_finding にその旨を"+
			"明記してください。\n\n発火した不整合: " + inc.Description
	case "R3":
		return "前回の解析でこのケースが複数ホスト構成と判明しましたが、"+
			"Lateral Movement findings が流入元ホストとの突き合わせ無しで記録されています。"+
			"今回は `Computer` フィールドの distinct 値を明示的に確認し、"+
			"flow direction (どのホストから/どのホストへ) を summary に含めてください。"+
			"\n\n発火した不整合: " + inc.Description
	case "R4":
		return "前回の解析で時系列矛盾が検出されました: あなたの所属する Tactic と "+
			"Initial Access の最古 finding 時刻が逆転しています。今回の再走では、"+
			"(Initial Access の場合) より早い 4624 type 10 / 1149 / 4625 burst 等を探索、"+
			"(Execution の場合) 最古 finding が侵入前から存在する OS 由来プロセス "+
			"(Windows Update / TrustedInstaller / 既存スケジュールタスク) "+
			"でないか再評価し、必要なら confidence を下げるか negative_finding に降格させてください。"+
			"\n\n発火した不整合: " + inc.Description
	default:
		return "未指定の整合性ルール" + rule + "が発火しました: " + inc.Description
	}
}

// Correct runs at most cfg.MaxRounds correction rounds. Returns the
// CorrectionReport plus the path of every TacticReport file that was
// actually rewritten (so the caller can re-run Aggregate to refresh
// CaseSynthesis).
func Correct(
	ctx context.Context, cfg CorrectionConfig, agg *AggregateResult,
	inconsistencies []Inconsistency,
) (*CorrectionReport, []string, error) {
	if cfg.CaseID == "" {
		return nil, nil, fmt.Errorf("case_id is required")
	}
	if cfg.MaxRounds <= 0 {
		cfg.MaxRounds = 1
	}
	if cfg.AgentTimeout <= 0 {
		cfg.AgentTimeout = 5 * time.Minute
	}
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = 200
	}
	if cfg.MaxIters <= 0 {
		cfg.MaxIters = 3
	}
	if cfg.Engine == "" {
		cfg.Engine = "claude-code"
	}

	report := &CorrectionReport{
		NewFindingsAdded: map[string]int{},
	}
	rewritten := map[string]struct{}{}

	// Build the work list: one (rule, tactic_slug) entry per actionable
	// inconsistency.
	type work struct {
		rule   string
		tactic string
		inc    Inconsistency
	}
	var workList []work
	seen := map[string]struct{}{} // dedup (rule,tactic) pairs
	for _, inc := range inconsistencies {
		if inc.Severity != "warning" {
			continue
		}
		for _, t := range affectedTacticsForRule(inc.Rule) {
			key := inc.Rule + "|" + t
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			workList = append(workList, work{rule: inc.Rule, tactic: t, inc: inc})
		}
	}

	if len(workList) == 0 {
		// No actionable warnings — leave any info-level rules as-is.
		for _, inc := range inconsistencies {
			report.UnresolvedRules = append(report.UnresolvedRules, inc.Rule)
		}
		report.UnresolvedRules = uniqStrings(report.UnresolvedRules)
		return report, nil, nil
	}

	// Single round only by spec; the loop is here for forward-compatibility
	// when MaxRounds > 1 in the future.
	for round := 1; round <= cfg.MaxRounds; round++ {
		report.RoundsRun = round
		for _, w := range workList {
			diag := CorrectorDiagnostic{
				Round:  round,
				Rule:   w.rule,
				Tactic: w.tactic,
				Hint:   hintForRule(w.rule, w.inc),
			}
			startedAt := time.Now()

			// Re-run the agent with correction context.
			runner, err := agents.New(agents.Config{
				Tactic:            w.tactic,
				Engine:            cfg.Engine,
				APIKey:            cfg.APIKey,
				Model:             cfg.Model,
				MaxEvents:         cfg.MaxEvents,
				MaxIters:          cfg.MaxIters,
				Timeout:           cfg.AgentTimeout,
				DBPath:            cfg.DBPath,
				CorrectionContext: diag.Hint,
			})
			if err != nil {
				diag.Status = "agent_failed"
				diag.Error = err.Error()
				report.Errors = append(report.Errors, fmt.Sprintf(
					"%s/%s: %v", w.rule, w.tactic, err))
				report.Diagnostics = append(report.Diagnostics, diag)
				continue
			}

			retryCtx, cancel := context.WithTimeout(ctx, cfg.AgentTimeout)
			newReport, runErr := runner.Run(retryCtx, cfg.CaseID, cfg.EvidenceID)
			cancel()
			diag.DurationS = time.Since(startedAt).Seconds()

			if runErr != nil || newReport == nil {
				diag.Status = "agent_failed"
				if runErr != nil {
					diag.Error = runErr.Error()
				} else {
					diag.Error = "nil report from agent"
				}
				report.Errors = append(report.Errors, fmt.Sprintf(
					"%s/%s: %s", w.rule, w.tactic, diag.Error))
				report.Diagnostics = append(report.Diagnostics, diag)
				continue
			}

			// Merge new findings into the existing TacticReport file.
			path := filepath.Join(cfg.FindingsDir, w.tactic+".json")
			added, mergeErr := mergeFindings(path, newReport, w.rule, diag.Hint)
			if mergeErr != nil {
				diag.Status = "agent_failed"
				diag.Error = mergeErr.Error()
				report.Errors = append(report.Errors, fmt.Sprintf(
					"%s/%s merge: %v", w.rule, w.tactic, mergeErr))
				report.Diagnostics = append(report.Diagnostics, diag)
				continue
			}

			diag.NewCount = added
			if added > 0 {
				diag.Status = "retried_ok"
				rewritten[path] = struct{}{}
				report.NewFindingsAdded[w.tactic] += added
				if !contains(report.AgentsRetried, w.tactic) {
					report.AgentsRetried = append(report.AgentsRetried, w.tactic)
				}
			} else {
				diag.Status = "retried_no_change"
			}
			report.Diagnostics = append(report.Diagnostics, diag)
		}
	}

	sort.Strings(report.AgentsRetried)

	// Re-evaluate which rules now look resolved by re-aggregating and
	// re-running consistency. Caller does this; we just record what
	// changed.
	if len(rewritten) > 0 {
		// Marker for caller — see synthesizer.go reuse.
	}

	// At this point we don't yet know which rules are still firing —
	// caller re-runs CheckConsistency after re-aggregating. We populate
	// UnresolvedRules optimistically with all warning rules; caller
	// overrides.
	for _, inc := range inconsistencies {
		if inc.Severity == "warning" {
			report.UnresolvedRules = append(report.UnresolvedRules, inc.Rule)
		}
	}
	report.UnresolvedRules = uniqStrings(report.UnresolvedRules)

	out := make([]string, 0, len(rewritten))
	for k := range rewritten {
		out = append(out, k)
	}
	sort.Strings(out)
	return report, out, nil
}

// mergeFindings reads the existing TacticReport at path, adds any new
// findings from newReport that don't share a finding_id, appends any new
// negative_findings / open_questions, and writes the file back. Returns
// the count of newly-added findings.
//
// We never delete or overwrite an existing finding — the original is
// "DRAFT received from first run" and is preserved for chain-of-custody.
// Newly-added findings are tagged in `reasoning` with "[Corrector round X
// — rule RULE]" so an examiner sees their provenance.
func mergeFindings(path string, newReport *agents.TacticReport, rule, hint string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read %q: %w", path, err)
	}
	var existing agents.TacticReport
	if err := json.Unmarshal(raw, &existing); err != nil {
		return 0, fmt.Errorf("parse %q: %w", path, err)
	}

	knownIDs := map[string]struct{}{}
	for _, f := range existing.Findings {
		knownIDs[f.FindingID] = struct{}{}
	}

	added := 0
	tag := fmt.Sprintf("[Corrector — %s]", rule)
	for _, f := range newReport.Findings {
		if _, dup := knownIDs[f.FindingID]; dup {
			continue
		}
		// Tag the reasoning so the Examiner sees this came from a retry.
		if f.Reasoning != "" && !strings.Contains(f.Reasoning, tag) {
			f.Reasoning = tag + " " + f.Reasoning
		} else if f.Reasoning == "" {
			f.Reasoning = tag
		}
		existing.Findings = append(existing.Findings, f)
		knownIDs[f.FindingID] = struct{}{}
		added++
	}

	// Append (don't replace) negative_findings + open_questions — the
	// Agent may have new ones to share.
	existing.NegativeFindings = append(existing.NegativeFindings,
		newReport.NegativeFindings...)
	existing.OpenQuestions = append(existing.OpenQuestions,
		newReport.OpenQuestions...)

	// Audit accumulation: preserve original audit, record corrector run.
	existing.Audit.Iterations += newReport.Audit.Iterations
	existing.Audit.TokensInput += newReport.Audit.TokensInput
	existing.Audit.TokensOutput += newReport.Audit.TokensOutput
	existing.Audit.CacheHitTok += newReport.Audit.CacheHitTok
	existing.Audit.DurationSec += newReport.Audit.DurationSec
	if newReport.Status == "failed" && existing.Status == "completed" {
		existing.Status = "partial" // a follow-up failed — degrade
	}

	body, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return 0, fmt.Errorf("write %q: %w", path, err)
	}
	return added, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func uniqStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
