package tier3

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/tlvb/tlvb/internal/tier2"
)

// consistency.go is the report self-check gate. After Tier 3 derives its
// plain-language sections from the Tier 2 synthesis, this pass re-reads the
// assembled report against the synthesis (and the techniques the case actually
// confirmed) and flags internal contradictions — a claim in one section that
// another section or the evidence refutes. The goal is that a finished report
// never says two opposite things: the WinRM-spray case said "entry point
// unknown" in the intrusion-path step while the conclusion described a
// brute-force entry from WS01.
//
// Design: the derivations are grounded at the source (deriveIntrusionPath now
// honours an entry-equivalent vector), so in the happy path this gate finds
// nothing. It stays as (a) an independent verifier that the assembled report is
// consistent before it is called "done", and (b) a regression guard that fails
// loudly if a future change re-introduces a divergence. Like synthesis_guard.go,
// every check is pure and case-agnostic — no host names, thresholds, or threat
// names from any specific case are baked in.

// ConsistencyIssue is one detected internal contradiction in the report.
type ConsistencyIssue struct {
	Code     string `json:"code"`
	Severity string `json:"severity"` // "blocker" | "warning" | "advisory"
	Detail   string `json:"detail"`
	// Resolution is the 裏取り / reconciliation that resolves a deterministic
	// issue. For LLM advisory items it holds the recommended next step.
	Resolution string `json:"resolution"`
	// Source is "deterministic" (the rule-based gate) or "llm" (the advisory
	// free-text reviewer). LLM items are advisory only — they never block.
	Source string `json:"source,omitempty"`
	// ConflictsWith / Grounding are populated by the LLM reviewer to locate the
	// opposing statement and the finding/evidence that corroborates the call.
	ConflictsWith string `json:"conflicts_with,omitempty"`
	Grounding     string `json:"grounding,omitempty"`
}

// ConsistencyReport is the persisted record of the gate — written to
// reports/report_consistency.json so a reviewer can see the report was checked
// and what (if anything) was found.
type ConsistencyReport struct {
	CaseID   string             `json:"case_id"`
	Status   string             `json:"status"` // "clean" | "unresolved" | "advisory"
	Blockers int                `json:"blockers"`
	Warnings int                `json:"warnings"`
	Advisory int                `json:"advisory"`
	Checks   []string           `json:"checks_run"`
	Issues   []ConsistencyIssue `json:"issues,omitempty"`
	// LLMReview records whether the advisory LLM pass ran, and why not when it
	// was requested but skipped (no transport, error). Nil when not requested.
	LLMReview *LLMReviewMeta `json:"llm_review,omitempty"`
}

// LLMReviewMeta is the audit of the advisory LLM consistency pass.
type LLMReviewMeta struct {
	Requested    bool    `json:"requested"`
	Ran          bool    `json:"ran"`
	Transport    string  `json:"transport,omitempty"`
	Model        string  `json:"model,omitempty"`
	InputTokens  int     `json:"input_tokens,omitempty"`
	OutputTokens int     `json:"output_tokens,omitempty"`
	CostUSD      float64 `json:"cost_usd,omitempty"`
	Error        string  `json:"error,omitempty"`
}

// consistencyChecks names every check this gate runs, for the persisted record.
var consistencyChecks = []string{
	"intrusion-path-contradicts-entry-vector",
	"earliest-claim-on-unreliable-timeline",
	"technique-confirmed-and-unconfirmed",
	"demoted-technique-asserted-in-prose",
	"ungrounded-mention-in-exec-brief",
	"noise-ioc-in-affected-scope",
}

// checkReportConsistency runs every consistency check over the synthesis (and
// the findings enrichment, for scope checks) plus the intrusion-path text Tier 3
// derives from it, returning the issues found. en may be nil (scope checks are
// then skipped).
func checkReportConsistency(cs tier2.CaseSynthesis, en *enrichment, lang string) []ConsistencyIssue {
	ja := lang != "en"
	var issues []ConsistencyIssue
	intrusion := deriveIntrusionPath(cs, lang, nil)

	// C1: the intrusion-path step disclaims any known entry while the case
	// actually confirms an entry vector (initial-access, or a brute-force /
	// valid-account / external-remote-service the narrative treats as the way
	// in). These two statements must never coexist in one report.
	if intrusionDisclaimsEntry(intrusion) {
		if vec := confirmedEntryVector(cs); vec != "" {
			issues = append(issues, ConsistencyIssue{
				Code:     "intrusion-path-contradicts-entry-vector",
				Severity: "blocker",
				Detail: pickLang(ja,
					"侵入経路の節は「侵入の入り口を特定できない」と述べているが、確定した侵入手口("+vec+")が存在する。",
					"The intrusion-path section says the entry point is unknown, but the case confirms an entry vector ("+vec+")."),
				Resolution: pickLang(ja,
					"侵入経路を確定済みの侵入手口("+vec+")から再生成し、結論の記述と一致させる。",
					"Re-derive the intrusion path from the confirmed entry vector ("+vec+") so it matches the conclusion."),
			})
		}
	}

	// C2: the intrusion-path step asserts a timestamp-order "earliest" while the
	// timeline is flagged unreliable — a clock rollback makes record order and
	// timestamps diverge, so "earliest" by time cannot be claimed.
	if strings.EqualFold(cs.TimelineReliability, "unreliable") && intrusionAssertsEarliest(intrusion) {
		issues = append(issues, ConsistencyIssue{
			Code:     "earliest-claim-on-unreliable-timeline",
			Severity: "warning",
			Detail: pickLang(ja,
				"タイムラインが unreliable（時刻巻き戻し検出）であるのに、侵入経路の節が「最も早く確認できた活動」と時刻順を断定している。",
				"The timeline is unreliable (clock rollback) yet the intrusion-path section asserts a timestamp-order 'earliest activity'."),
			Resolution: pickLang(ja,
				"時刻順に依拠した断定表現を外し、発生順は不確実であることを明記する。",
				"Drop the timestamp-order assertion and state the order of events is uncertain."),
		})
	}

	// C3: a technique appears as BOTH confirmed and unconfirmed — the matrix
	// would assert and retract the same technique.
	confirmed := map[string]bool{}
	for _, m := range cs.MITREMapping {
		confirmed[m.Technique] = true
	}
	seen := map[string]bool{}
	for _, m := range cs.MITREUnconfirmed {
		if confirmed[m.Technique] && !seen[m.Technique] {
			seen[m.Technique] = true
			issues = append(issues, ConsistencyIssue{
				Code:     "technique-confirmed-and-unconfirmed",
				Severity: "warning",
				Detail: pickLang(ja,
					"テクニック "+m.Technique+" が confirmed と unconfirmed の両方のマトリクスに存在する。",
					"Technique "+m.Technique+" appears in both the confirmed and unconfirmed matrices."),
				Resolution: pickLang(ja,
					"確定側を優先し、unconfirmed 側から除外する。",
					"Keep the confirmed entry and drop it from the unconfirmed matrix."),
			})
		}
	}

	// C4: the technical summary asserts a named technique the MITRE matrix
	// DEMOTED (it lives in mitre_unconfirmed). A good report mentions such a
	// technique only to REFUTE it ("no hash-theft evidence, so NOT Pass-the-Hash")
	// — so we skip the whole field when it hedges, and only flag a bare,
	// unqualified assertion. This avoids firing on the very prose that correctly
	// rules the technique out.
	tech := cs.TechSummary
	if tech == "" {
		tech = cs.OverallStory
	}
	if tech != "" && !proseHedged(tech) {
		unconf := map[string]bool{}
		for _, m := range cs.MITREUnconfirmed {
			unconf[m.Technique] = true
		}
		lowTech := strings.ToLower(tech)
		for _, claim := range reportedClaims {
			if len(claim.techniques) == 0 || !anyIn(unconf, claim.techniques) {
				continue
			}
			if containsAny(lowTech, claim.aliases) {
				issues = append(issues, ConsistencyIssue{
					Code:     "demoted-technique-asserted-in-prose",
					Severity: "warning",
					Detail: pickLang(ja,
						"技術サマリが「"+claim.label+"」を断定的に記述しているが、MITRE マトリクスでは未確認に降格されている（"+strings.Join(claim.techniques, "/")+"）。",
						"The technical summary asserts \""+claim.label+"\" but the MITRE matrix demoted it to unconfirmed ("+strings.Join(claim.techniques, "/")+")."),
					Resolution: pickLang(ja,
						"本文を降格事由に合わせて留保付き表現に直すか、裏付けがあるなら確定マトリクスへ昇格する。",
						"Hedge the prose to match the demotion reason, or promote it to the confirmed matrix if it is actually corroborated."),
				})
			}
		}
	}

	// C5: the EXECUTIVE brief (the decision-maker layer) states a claim the case
	// flagged as ungrounded/unconfirmed. The exec brief is short and high-stakes,
	// so an unhedged ungrounded mention there is a real problem. Skipped when the
	// brief hedges.
	if exec := cs.ExecBrief; exec != "" && len(cs.UngroundedMentions) > 0 && !proseHedged(exec) {
		lowExec := strings.ToLower(exec)
		seenLabel := map[string]bool{}
		for _, label := range cs.UngroundedMentions {
			if seenLabel[label] {
				continue
			}
			if containsAny(lowExec, aliasesForLabel(label)) {
				seenLabel[label] = true
				issues = append(issues, ConsistencyIssue{
					Code:     "ungrounded-mention-in-exec-brief",
					Severity: "warning",
					Detail: pickLang(ja,
						"経営層向けサマリが、裏付けの無い主張「"+label+"」を事実として記述している。",
						"The executive brief states the ungrounded claim \""+label+"\" as fact."),
					Resolution: pickLang(ja,
						"経営層サマリから「"+label+"」を削除するか、未確認である旨を明記する。",
						"Remove \""+label+"\" from the executive brief or mark it explicitly as unconfirmed."),
				})
			}
		}
	}

	// C6: a noise-confidence IOC (a parser artifact, e.g. "LogonType 3") leaked
	// into the affected-scope hosts/accounts. deriveAffectedScope already filters
	// these, so this is a regression guard — it should normally never fire.
	if en != nil {
		noise := map[string]bool{}
		for _, ioc := range en.IOCs {
			if ioc.Confidence == "noise" {
				noise[strings.ToLower(strings.TrimSpace(ioc.Value))] = true
			}
		}
		if len(noise) > 0 {
			if sv := deriveAffectedScope(cs, en, lang); sv != nil {
				for _, v := range append(append([]string{}, sv.Hosts...), sv.Accounts...) {
					if noise[strings.ToLower(strings.TrimSpace(v))] {
						issues = append(issues, ConsistencyIssue{
							Code:     "noise-ioc-in-affected-scope",
							Severity: "warning",
							Detail: pickLang(ja,
								"影響範囲に、ノイズ（パーサ由来アーティファクト）と判定された IOC「"+v+"」が混入している。",
								"The affected scope includes \""+v+"\", an IOC classified as noise (a parser artifact)."),
							Resolution: pickLang(ja,
								"ノイズ IOC を影響範囲から除外する（deriveAffectedScope のフィルタを確認）。",
								"Drop the noise IOC from the affected scope (check the deriveAffectedScope filter)."),
						})
						break
					}
				}
			}
		}
	}

	return issues
}

// reportedClaim is a high-signal named attack claim the deterministic gate looks
// for in the report's own prose. It mirrors a small subset of tier2's
// namedAttackClaims — duplicated rather than imported to keep tier3 independent
// of tier2 internals; keep the labels/aliases in sync.
type reportedClaim struct {
	label      string
	aliases    []string // lowercase phrases that count as a mention
	techniques []string // techniques whose demotion makes a bare assertion a contradiction
}

var reportedClaims = []reportedClaim{
	{label: "Mimikatz", aliases: []string{"mimikatz"}},
	{label: "Cobalt Strike", aliases: []string{"cobalt strike", "cobaltstrike", "beacon"}},
	{label: "Pass-the-Hash", aliases: []string{"pass-the-hash", "pass the hash", "passthehash", "パス・ザ・ハッシュ", "パスザハッシュ"}, techniques: []string{"T1550.002"}},
	{label: "Web shell", aliases: []string{"web shell", "webshell", "ウェブシェル", "web シェル"}, techniques: []string{"T1505.003", "T1190"}},
}

// aliasesForLabel returns the lowercase aliases for an ungrounded-mention label,
// falling back to the lowercased label itself (tool names match verbatim).
func aliasesForLabel(label string) []string {
	for _, c := range reportedClaims {
		if c.label == label {
			return c.aliases
		}
	}
	return []string{strings.ToLower(label)}
}

// hedgeMarkers are negation / uncertainty phrases. Their presence anywhere in a
// prose field means the field qualifies its claims, so the field is exempt from
// the "bare assertion" checks (C4/C5) — better to miss a hedged contradiction
// than to false-alarm on prose that correctly rules a technique out.
var hedgeMarkers = []string{
	// ja
	"ではなく", "ではない", "ではありません", "では無く", "証拠が無い", "証拠がない", "証拠は無い",
	"誤検知", "断定でき", "可能性", "未確認", "とは限らない", "確証", "裏付けられ", "示していません", "不明",
	// en
	"no evidence", "false positive", "cannot confirm", "could not confirm",
	"unconfirmed", "rather than", "not confirmed", "is not ", "was not ",
}

func proseHedged(s string) bool {
	low := strings.ToLower(s)
	for _, m := range hedgeMarkers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

// containsAny reports whether low contains any of subs.
func containsAny(low string, subs []string) bool {
	for _, s := range subs {
		if strings.Contains(low, s) {
			return true
		}
	}
	return false
}

// anyIn reports whether set contains any of keys.
func anyIn(set map[string]bool, keys []string) bool {
	for _, k := range keys {
		if set[k] {
			return true
		}
	}
	return false
}

// confirmedEntryVector returns a short technique-id label for the entry vector
// the case confirmed (initial-access first, then entry-equivalent), or "" when
// the case truly confirms no way in.
func confirmedEntryVector(cs tier2.CaseSynthesis) string {
	if t := intrusionTechniques(cs); len(t) > 0 {
		return strings.Join(t, ", ")
	}
	if t := entryEquivalentTechniques(cs); len(t) > 0 {
		return strings.Join(t, ", ")
	}
	return ""
}

// intrusionDisclaimsEntry reports whether the intrusion-path text says the entry
// point could not be determined (either disclaimer phrasing, JA or EN).
func intrusionDisclaimsEntry(text string) bool {
	for _, s := range []string{
		"特定できませんでした",
		"特定できる手がかりは得られませんでした",
		"could not be determined",
		"not enough evidence to determine",
		"the order of events cannot establish the entry path",
		"発生順から侵入経路を断定することはできません",
	} {
		if strings.Contains(text, s) {
			return true
		}
	}
	return false
}

// intrusionAssertsEarliest reports whether the intrusion-path text makes a
// timestamp-order "earliest activity" claim.
func intrusionAssertsEarliest(text string) bool {
	return strings.Contains(text, "最も早く確認できた") ||
		strings.Contains(text, "earliest suspicious activity")
}

// pickLang returns j when ja, else e.
func pickLang(ja bool, j, e string) string {
	if ja {
		return j
	}
	return e
}

// runConsistencyGate runs the deterministic checks (the hard gate), then — when
// cfg.ConsistencyLLM is set — the advisory LLM free-text reviewer, writes the
// merged reports/report_consistency.json, and returns the issues so the caller
// (CLI / pipeline) can warn before declaring the report done. The LLM pass is
// best-effort: any failure is recorded and never blocks rendering.
func runConsistencyGate(ctx context.Context, cfg Config, cs tier2.CaseSynthesis, en *enrichment) []ConsistencyIssue {
	issues := checkReportConsistency(cs, en, cfg.Language)
	for i := range issues {
		issues[i].Source = "deterministic"
	}

	rep := ConsistencyReport{
		CaseID: cfg.CaseID,
		Status: "clean",
		Checks: consistencyChecks,
	}

	if cfg.ConsistencyLLM {
		llmIssues, meta := llmConsistencyReview(ctx, cfg, cs, en)
		rep.LLMReview = meta
		issues = append(issues, llmIssues...)
	}

	rep.Issues = issues
	for _, is := range issues {
		switch is.Severity {
		case "blocker":
			rep.Blockers++
		case "advisory":
			rep.Advisory++
		default:
			rep.Warnings++
		}
	}
	switch {
	case rep.Blockers > 0:
		rep.Status = "unresolved"
	case rep.Advisory > 0 && rep.Warnings == 0:
		rep.Status = "advisory"
	}
	if body, err := json.MarshalIndent(rep, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(cfg.OutDir, "report_consistency.json"), body, 0o644)
	}
	return issues
}
