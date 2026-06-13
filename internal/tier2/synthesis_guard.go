package tier2

import (
	"regexp"
	"sort"
	"strings"
)

// synthesis_guard.go holds the deterministic guardrails that keep the Tier 2
// synthesis honest, independent of what the LLM narrative claims. They were
// added for issue #82, where an evaluation case showed four general failure
// modes:
//
//   - clock non-monotonicity (lab Set-Date correction) read as an attacker
//     timestomp + a fabricated "re-intrusion" phase;
//   - techniques/tools with no finding backing (web shell, Pass-the-Hash,
//     Mimikatz) asserted in the conclusion and the MITRE matrix;
//   - a single-account 4625 password-spray missed / a successful NTLM logon
//     labelled Pass-the-Hash without any hash-theft evidence;
//   - benign provisioning clusters double-counted as attacker activity.
//
// Every function here is pure and case-agnostic — no host names, thresholds in
// hours, or threat names from the evaluation case are baked in.

// standardTechniqueID matches a canonical MITRE ATT&CK technique id: a capital
// T, four digits, and an optional three-digit sub-technique. Anything else
// (free-text "techniques" the LLM invents, tactic names, non-standard ids) is
// rejected so it can never reach the authoritative MITRE matrix.
var standardTechniqueID = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

func isStandardTechniqueID(s string) bool {
	return standardTechniqueID.MatchString(strings.TrimSpace(s))
}

// findingTechniqueUnion returns the deterministic, finding-derived technique
// set for a cluster: the union of every finding's rule→technique tags, filtered
// to standard ids. This is the ONLY source the case-wide MITRE matrix is built
// from — the cluster LLM's free-form mitre_techniques are deliberately excluded
// (they flow to MITREUnconfirmed instead).
func findingTechniqueUnion(c Cluster) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range c.Findings {
		for _, t := range f.MITRETechniques {
			t = strings.TrimSpace(t)
			if !isStandardTechniqueID(t) || seen[t] {
				continue
			}
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// clusterUnconfirmedTechniques returns the standard-id techniques the cluster
// LLM narrative proposed (c.MITRETechniques) that NO finding in the cluster
// backs. These are "参考 / unconfirmed" — never promoted to the final matrix.
func clusterUnconfirmedTechniques(c Cluster) []string {
	confirmed := map[string]bool{}
	for _, t := range findingTechniqueUnion(c) {
		confirmed[t] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, t := range c.MITRETechniques {
		t = strings.TrimSpace(t)
		if !isStandardTechniqueID(t) || confirmed[t] || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// timeChangeSubjectBenign reports whether the Subject of a Security 4616
// (system time change) is a normal Windows time-keeping principal rather than
// an interactive/attacker context. A 4616 raised by LOCAL SERVICE / SYSTEM or
// the W32Time service is the OS correcting its own clock — exactly the lab
// `Set-Date` / W32Time activity that must NOT be attributed to an attacker
// timestomp (issue #82, task 1). Matching is on well-known SIDs and service
// names only, so it is case-agnostic.
func timeChangeSubjectBenign(subjectSID, subjectUser string) bool {
	sid := strings.ToUpper(strings.TrimSpace(subjectSID))
	switch sid {
	case "S-1-5-19", // LOCAL SERVICE
		"S-1-5-18", // LOCAL SYSTEM
		"S-1-5-20": // NETWORK SERVICE
		return true
	}
	u := strings.ToLower(strings.TrimSpace(subjectUser))
	for _, kw := range []string{
		"local service", "ローカル サービス", "ローカルサービス",
		"local system", "システム", "network service",
		"w32time", "time service",
	} {
		if u != "" && strings.Contains(u, kw) {
			return true
		}
	}
	return false
}

// detectTimelineReliability returns ("unreliable", notes) when the case
// timeline is internally inconsistent and any "attacker manipulated the clock /
// re-entered later" reading should be treated as a re-anchoring problem first.
//
// The deterministic signal is a cluster whose time window sits more than a year
// from the median cluster (temporalOutlierClusters) — the fingerprint of
// provisioning / VM-creation activity or a Set-Date correction bundled into the
// same case as the real incident, where record order and timestamp order
// diverge. No threshold from the evaluation case is hard-coded.
func detectTimelineReliability(clusters []Cluster, lang string) (string, []string) {
	outliers := temporalOutlierClusters(clusters)
	any := false
	for _, o := range outliers {
		if o {
			any = true
			break
		}
	}
	if !any {
		return "reliable", nil
	}
	ja := strings.ToLower(lang) != "en"
	var notes []string
	if ja {
		notes = append(notes,
			"イベントの記録順とタイムスタンプが乖離するクラスタ(他クラスタから1年以上離れた時刻)を検出しました。タイムラインは再アンカーが必要です。",
			"この時刻不整合は、プロビジョニング/OSセットアップや時刻補正(例: Set-Date)に起因する可能性を第一仮説とすべきで、攻撃者によるタイムスタンプ改変(T1070.006)や再侵入と断定してはなりません。裏付け(攻撃者文脈のプロセスが時刻変更APIを呼んだ等)がある場合にのみ攻撃帰属します。")
	} else {
		notes = append(notes,
			"Detected cluster(s) where record order and timestamps diverge (more than a year from the other clusters). The timeline needs re-anchoring.",
			"Treat this inconsistency as provisioning / OS-setup or clock correction (e.g. Set-Date) FIRST; do not conclude an attacker timestomp (T1070.006) or a re-intrusion without corroboration (e.g. a time-change API called from an attacker-context process).")
	}
	return "unreliable", notes
}

// groundedTool pairs a named offensive tool / technique phrase with the MITRE
// technique ids that would corroborate it. A mention in the summary prose is
// "ungrounded" when an alias appears in the prose but neither the alias text
// nor any corroborating technique appears in the findings.
type groundedTool struct {
	label      string   // canonical name reported when ungrounded
	aliases    []string // lowercase phrases that count as a mention in prose
	techniques []string // finding technique ids that ground the mention
}

// namedAttackClaims is the small, case-agnostic catalogue of high-signal claims
// the conclusion must not assert without finding backing. These are tool names
// and technique phrases, NOT values from the evaluation case.
var namedAttackClaims = []groundedTool{
	// Specific tool NAMES are grounded only by being named in a finding — a
	// related technique tag is NOT enough (a comsvcs.dll LOLBin dump carries
	// T1003.001 but does not mean Mimikatz was used; that conflation is exactly
	// the evaluation-case hallucination).
	{label: "Mimikatz", aliases: []string{"mimikatz"}},
	{label: "Cobalt Strike", aliases: []string{"cobalt strike", "cobaltstrike", "beacon"}},
	{label: "Metasploit/Meterpreter", aliases: []string{"metasploit", "meterpreter"}},
	{label: "Rubeus", aliases: []string{"rubeus"}},
	{label: "BloodHound", aliases: []string{"bloodhound", "sharphound"}},
	{label: "Impacket secretsdump", aliases: []string{"secretsdump", "impacket"}},
	{label: "LaZagne", aliases: []string{"lazagne"}},
	{label: "CrackMapExec", aliases: []string{"crackmapexec"}},
	{label: "PowerSploit", aliases: []string{"powersploit", "mimikittenz"}},
	// Conceptual technique phrases MAY be grounded by their corroborating
	// technique id (the behaviour, not a brand, is what is asserted).
	{label: "Web shell", aliases: []string{"web shell", "webshell", "ウェブシェル", "web シェル"}, techniques: []string{"T1505.003", "T1190"}},
	{label: "Pass-the-Hash", aliases: []string{"pass-the-hash", "pass the hash", "passthehash", "パスザハッシュ", "パス・ザ・ハッシュ"}, techniques: []string{"T1550.002"}},
}

// findUngroundedMentions scans the conclusion prose for named attack claims and
// returns the labels of those that no finding corroborates. The report surfaces
// these as "unconfirmed" so an LLM hallucination (e.g. naming Mimikatz when the
// dump used a comsvcs.dll LOLBin) is flagged rather than asserted as fact.
func findUngroundedMentions(prose string, findings []Finding) []string {
	if strings.TrimSpace(prose) == "" {
		return nil
	}
	lowProse := strings.ToLower(prose)
	corpus := findingGroundingText(findings)
	tagged := findingTechniqueSet(findings)

	var out []string
	seen := map[string]bool{}
	for _, t := range namedAttackClaims {
		mentioned := false
		for _, a := range t.aliases {
			if strings.Contains(lowProse, a) {
				mentioned = true
				break
			}
		}
		if !mentioned {
			continue
		}
		grounded := false
		for _, a := range t.aliases {
			if strings.Contains(corpus, a) {
				grounded = true
				break
			}
		}
		if !grounded {
			for _, tech := range t.techniques {
				if tagged[tech] {
					grounded = true
					break
				}
			}
		}
		if !grounded && !seen[t.label] {
			seen[t.label] = true
			out = append(out, t.label)
		}
	}
	return out
}

// findingGroundingText concatenates the searchable text of every finding
// (title, description, rule id, source, and evidence projection values) into one
// lowercased blob used to decide whether a prose claim is corroborated.
func findingGroundingText(findings []Finding) string {
	var sb strings.Builder
	for _, f := range findings {
		sb.WriteString(f.Title)
		sb.WriteByte(' ')
		sb.WriteString(f.Description)
		sb.WriteByte(' ')
		sb.WriteString(f.RuleID)
		sb.WriteByte(' ')
		sb.WriteString(f.Source)
		sb.WriteByte(' ')
		for _, e := range f.Evidence {
			for _, v := range e.Extra {
				if s, ok := v.(string); ok {
					sb.WriteString(s)
					sb.WriteByte(' ')
				}
			}
		}
	}
	return strings.ToLower(sb.String())
}

// findingTechniqueSet is the set of standard technique ids carried by findings.
func findingTechniqueSet(findings []Finding) map[string]bool {
	set := map[string]bool{}
	for _, f := range findings {
		for _, t := range f.MITRETechniques {
			t = strings.TrimSpace(t)
			if isStandardTechniqueID(t) {
				set[t] = true
			}
		}
	}
	return set
}
