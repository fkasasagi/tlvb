package tier3

import (
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
	Code       string `json:"code"`
	Severity   string `json:"severity"` // "blocker" | "warning"
	Detail     string `json:"detail"`
	Resolution string `json:"resolution"` // the 裏取り / reconciliation that resolves it
}

// ConsistencyReport is the persisted record of the gate — written to
// reports/report_consistency.json so a reviewer can see the report was checked
// and what (if anything) was found.
type ConsistencyReport struct {
	CaseID   string             `json:"case_id"`
	Status   string             `json:"status"` // "clean" | "unresolved"
	Blockers int                `json:"blockers"`
	Warnings int                `json:"warnings"`
	Checks   []string           `json:"checks_run"`
	Issues   []ConsistencyIssue `json:"issues,omitempty"`
}

// consistencyChecks names every check this gate runs, for the persisted record.
var consistencyChecks = []string{
	"intrusion-path-contradicts-entry-vector",
	"earliest-claim-on-unreliable-timeline",
	"technique-confirmed-and-unconfirmed",
}

// checkReportConsistency runs every consistency check over the synthesis and the
// intrusion-path text Tier 3 derives from it, returning the issues found.
func checkReportConsistency(cs tier2.CaseSynthesis, lang string) []ConsistencyIssue {
	ja := lang != "en"
	var issues []ConsistencyIssue
	intrusion := deriveIntrusionPath(cs, lang)

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

	return issues
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

// runConsistencyGate runs the checks, writes reports/report_consistency.json,
// and returns the issues so the caller (CLI / pipeline) can warn or block before
// declaring the report done. Writing the record is best-effort: a write failure
// never blocks rendering.
func runConsistencyGate(outDir, caseID, lang string, cs tier2.CaseSynthesis) []ConsistencyIssue {
	issues := checkReportConsistency(cs, lang)
	rep := ConsistencyReport{
		CaseID: caseID,
		Status: "clean",
		Checks: consistencyChecks,
		Issues: issues,
	}
	for _, is := range issues {
		if is.Severity == "blocker" {
			rep.Blockers++
		} else {
			rep.Warnings++
		}
	}
	if rep.Blockers > 0 {
		rep.Status = "unresolved"
	}
	if body, err := json.MarshalIndent(rep, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(outDir, "report_consistency.json"), body, 0o644)
	}
	return issues
}
