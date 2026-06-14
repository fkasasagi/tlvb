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
// Two deterministic signals, either of which makes the timeline unreliable:
//   - a cluster whose time window sits more than a year from the median cluster
//     (temporalOutlierClusters) — provisioning / VM-creation bundled into the
//     same case, where record order and timestamp order diverge; and
//   - a clock reversal (a Security 4616 whose time was stepped backward beyond a
//     threshold — clockReversed, computed from the raw events). This catches the
//     same-day "16 hours back" lab Set-Date that the year-apart heuristic misses.
//
// No threshold from the evaluation case is hard-coded.
func detectTimelineReliability(clusters []Cluster, clockReversed bool, lang string) (string, []string) {
	outliers := temporalOutlierClusters(clusters)
	hasOutlier := false
	for _, o := range outliers {
		if o {
			hasOutlier = true
			break
		}
	}
	if !hasOutlier && !clockReversed {
		return "reliable", nil
	}
	ja := strings.ToLower(lang) != "en"
	var notes []string
	// First note names the actual signal(s) found, so the report does not claim
	// a "year-apart cluster" when the real trigger was a same-day clock reversal.
	if clockReversed {
		if ja {
			notes = append(notes, "システム時刻の後方ジャンプ(Security 4616 でクロックが大きく巻き戻された)を検出しました。記録順とタイムスタンプが乖離するため、タイムラインは再アンカーが必要です。")
		} else {
			notes = append(notes, "Detected a backward clock step (a Security 4616 stepped the system time far back). Record order and timestamps diverge, so the timeline needs re-anchoring.")
		}
	}
	if hasOutlier {
		if ja {
			notes = append(notes, "他クラスタから1年以上離れた時刻のクラスタ(プロビジョニング/OSセットアップの可能性)を検出しました。タイムラインは再アンカーが必要です。")
		} else {
			notes = append(notes, "Detected a cluster more than a year from the others (likely provisioning / OS setup). The timeline needs re-anchoring.")
		}
	}
	// Second note is the shared attribution caveat.
	if ja {
		notes = append(notes, "この時刻不整合は、プロビジョニング/OSセットアップや時刻補正(例: Set-Date)に起因する可能性を第一仮説とすべきで、攻撃者によるタイムスタンプ改変(T1070.006)や再侵入と断定してはなりません。裏付け(攻撃者文脈のプロセスが時刻変更APIを呼んだ等)がある場合にのみ攻撃帰属します。")
	} else {
		notes = append(notes, "Treat this inconsistency as provisioning / OS-setup or clock correction (e.g. Set-Date) FIRST; do not conclude an attacker timestomp (T1070.006) or a re-intrusion without corroboration (e.g. a time-change API called from an attacker-context process).")
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
// returns the labels of those the case does not corroborate. The report surfaces
// these as "unconfirmed" so an LLM hallucination is flagged rather than asserted.
//
// Grounding differs by claim kind:
//   - a TECHNIQUE PHRASE (web shell, Pass-the-Hash — has linked techniques) is
//     grounded only when one of its techniques is in `confirmed`, the
//     POST-corroboration matrix. A finding merely TAGGED or NAMED after it
//     ("Pass the Hash Activity 2") does NOT ground it — that is exactly the
//     misleading-signature case the corroboration layer demotes;
//   - a TOOL NAME (Mimikatz — no linked techniques) is grounded only when the
//     name itself appears in the finding text.
func findUngroundedMentions(prose string, findings []Finding, confirmed map[string]bool) []string {
	if strings.TrimSpace(prose) == "" {
		return nil
	}
	lowProse := strings.ToLower(prose)
	corpus := findingGroundingText(findings)

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
		if len(t.techniques) > 0 {
			// Technique phrase: ground ONLY on a confirmed technique.
			for _, tech := range t.techniques {
				if confirmed[tech] {
					grounded = true
					break
				}
			}
		} else {
			// Tool name: ground on the name appearing in the finding text.
			for _, a := range t.aliases {
				if strings.Contains(corpus, a) {
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

// groundingContext carries the case-level facts the corroboration layer needs.
// Computed once per run from the events/findings, never from a specific case's
// values.
type groundingContext struct {
	// HasWebArtifact is true when the case contains any web-server artifact
	// (IIS/Apache/nginx/Tomcat) OR a web-server document root / live config on
	// disk (MFT shows inetpub\wwwroot, htdocs, webapps, or a live
	// applicationHost.config). A web shell / public-facing-app exploit cannot be
	// confirmed without one. The on-disk signal is independent of whether web
	// *logs* were parsed, so the corroboration holds even when no web-log parser
	// ran (the distrib_winrm_spray case had neither web logs nor a web root —
	// the "web shell" was a LIKE-wildcard FP on an unrelated PnP event).
	HasWebArtifact bool
	// BruteForcedAccounts is the set of accounts (lowercased, domain-stripped)
	// for which a 4625 burst was detected — i.e. whose successful logon is
	// explained by password guessing, not Pass-the-Hash.
	BruteForcedAccounts map[string]bool
	// ClockReversed is true when a Security 4616 stepped the clock backward
	// beyond the reversal threshold — the timeline is non-monotonic.
	ClockReversed bool
}

// webServerArtifacts are the artifact_ids that evidence a web server in the case.
var webServerArtifacts = map[string]bool{
	"w3c_iis": true, "iis_module": true,
	"apache_access": true, "apache_error": true,
	"nginx": true, "nginx_access": true, "nginx_error": true,
	"tomcat": true,
}

func containsWebArtifact(arts []string) bool {
	for _, a := range arts {
		if webServerArtifacts[strings.ToLower(strings.TrimSpace(a))] {
			return true
		}
	}
	return false
}

// webRootMarkers are case-insensitive ParentPath substrings that mark a genuine
// web-server document root on disk (MFT). They are matched only after the OS
// component store is excluded (see pathIndicatesWebServer), so a dormant
// framework skeleton never counts.
// Matched with strings.Contains, so no trailing separator — the marker must hit
// whether the directory is the path's last segment (a file sitting directly in
// it) or an intermediate one.
var webRootMarkers = []string{
	`\inetpub\wwwroot`, // IIS default site root
	`\htdocs`,          // Apache document root
	`\webapps`,         // Tomcat web applications
	`\nginx\html`,      // nginx default root
}

// osComponentStoreMarkers are ParentPath fragments under which Windows ships a
// DORMANT ASP.NET / IIS skeleton (the .NET Framework's ASP.NETWebAdminFiles, the
// WinSxS component store, servicing packages, catalog signatures). Files here are
// never a served web site, so a path under any of them is rejected before the
// web-root / config tests. This is what lets the MFT signal reject the .aspx /
// applicationHost.config template noise present on every Windows Server.
var osComponentStoreMarkers = []string{
	`\winsxs\`,
	`\servicing\`,
	`\catroot`,
	`\microsoft.net\`,
	`\assembly\`,
}

// pathIndicatesWebServer reports whether an MFT (ParentPath, FileName) pair
// evidences a live web server: a document root, or a live IIS site config
// (applicationHost.config outside the component store). Pure + case-agnostic so
// it is unit-tested directly.
func pathIndicatesWebServer(parentPath, fileName string) bool {
	pp := strings.ToLower(parentPath)
	// OS component store / servicing — never a live web root or config.
	for _, m := range osComponentStoreMarkers {
		if strings.Contains(pp, m) {
			return false
		}
	}
	// A live IIS site config lives at \Windows\System32\inetsrv\config, so it is
	// matched BEFORE the \Windows exclusion below. The WinSxS template was already
	// rejected by the component-store check.
	if strings.EqualFold(strings.TrimSpace(fileName), "applicationHost.config") {
		return true
	}
	// A genuine web-server document root is never under C:\Windows — that is OS
	// territory. Windows itself ships web-shaped folders there (e.g. the
	// CloudExperienceHost's \Windows\SystemApps\...\webapps UI), which must NOT be
	// read as a served site. Real roots live at C:\inetpub, C:\Apache24, etc.
	if strings.Contains(pp, `\windows\`) {
		return false
	}
	for _, m := range webRootMarkers {
		if strings.Contains(pp, m) {
			return true
		}
	}
	return false
}

// techniqueDemotionReason decides whether a finding-derived technique should be
// demoted from the confirmed matrix because the case lacks the corroboration the
// technique needs. These are general DFIR principles, NOT case-specific values:
//
//   - T1190 / T1505.003 (public-facing exploit / web shell) require a web server
//     in the case — you cannot have a web shell with no web server (the
//     evaluation case's "Antivirus Web Shell Detection" hit actually matched an
//     unrelated PnP driver event);
//   - T1550.002 (Pass-the-Hash) is demoted when the same environment shows a
//     brute-force burst — the NTLM success is then password authentication, and
//     PtH needs separate hash-theft/use evidence (issue #82, task 3);
//   - T1070.006 (timestomp / clock change) is demoted when the timeline carries a
//     clock reversal — the change is explained by provisioning / Set-Date and
//     cannot be confirmed as an attacker anti-forensic act (issue #82, task 1).
//
// Returns (reason, true) to demote, ("", false) to keep confirmed.
func techniqueDemotionReason(tech string, ctx groundingContext, ja bool) (string, bool) {
	switch tech {
	case "T1190", "T1505.003":
		if !ctx.HasWebArtifact {
			if ja {
				return tech + ": Web サーバ由来アーティファクト (IIS/Apache/nginx 等) がケースに存在せず、Web シェル/公開アプリ侵害を裏付けられないため未確認に降格。", true
			}
			return tech + ": no web-server artifact (IIS/Apache/nginx) in the case to corroborate a web shell / public-facing-app exploit — demoted to unconfirmed.", true
		}
	case "T1550.002":
		if len(ctx.BruteForcedAccounts) > 0 {
			if ja {
				return tech + ": 同一環境でパスワード推測 (4625 バースト→成功) を検出。NTLM 成功はパスワード認証で説明可能で、ハッシュ窃取/利用の具体証跡が無いため Pass-the-Hash を未確認に降格。", true
			}
			return tech + ": password guessing (4625 burst→success) was detected; the NTLM logon is password authentication, and no hash-theft/use evidence confirms Pass-the-Hash — demoted to unconfirmed.", true
		}
	case "T1070.006":
		if ctx.ClockReversed {
			if ja {
				return tech + ": タイムラインに時刻巻き戻し (4616 後方ジャンプ) があり、プロビジョニング/時刻補正で説明可能。攻撃者の timestomp と断定できないため未確認に降格。", true
			}
			return tech + ": the timeline has a clock reversal (4616 backward jump) explainable by provisioning / time correction — not confirmable as an attacker timestomp, demoted to unconfirmed.", true
		}
	}
	return "", false
}

// splitCorroboratedMITRE partitions the finding-derived matrix into the entries
// that stay confirmed and the entries demoted to unconfirmed for lack of
// corroboration, returning the demotion reasons for the report.
func splitCorroboratedMITRE(entries []MITREEntry, ctx groundingContext, lang string) (keep, demoted []MITREEntry, notes []string) {
	ja := strings.ToLower(lang) != "en"
	for _, e := range entries {
		if reason, demote := techniqueDemotionReason(e.Technique, ctx, ja); demote {
			demoted = append(demoted, e)
			notes = append(notes, reason)
			continue
		}
		keep = append(keep, e)
	}
	return keep, demoted, notes
}

// bruteForcedAccountsOf collects the accounts a brute-force heuristic finding
// attributed a burst to (from the synthetic finding's evidence).
func bruteForcedAccountsOf(findings []Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range findings {
		if f.RuleID != "TLVB-BRUTEFORCE-4625" {
			continue
		}
		for _, e := range f.Evidence {
			if u, ok := e.Extra["TargetUserName"].(string); ok {
				if n := normUser(u); n != "" {
					out[n] = true
				}
			}
		}
	}
	return out
}

// ----------------------------------------------------------------------------
// Closing the corroboration loop: once the deterministic layer judges an
// FP-prone claim uncorroborated, that verdict must reach the human-facing parts
// of the report — the narrative and the open questions — not just the MITRE
// metadata. Otherwise the prose still asserts a "web shell detection" and an open
// question still asks an analyst to hunt for its hash, exactly the gap the
// distrib_winrm_spray report showed. These functions feed the verdict back.
// ----------------------------------------------------------------------------

// corroborationGatedClaim links an FP-prone claim to the techniques whose
// demotion means the case does not corroborate it, plus the prose aliases that
// signal the claim is being asserted or asked about. The technique→demotion
// predicate is techniqueDemotionReason (single source of truth); this table only
// adds the prose vocabulary needed to reach the narrative / open questions.
type corroborationGatedClaim struct {
	label      string
	techniques []string
	aliases    []string // lowercase phrases, ja + en
}

var corroborationGatedClaims = []corroborationGatedClaim{
	{
		label:      "Web shell",
		techniques: []string{"T1190", "T1505.003"},
		aliases:    []string{"web shell", "webshell", "ウェブシェル", "web シェル", "webシェル"},
	},
	{
		label:      "Pass-the-Hash",
		techniques: []string{"T1550.002"},
		aliases:    []string{"pass-the-hash", "pass the hash", "passthehash", "パスザハッシュ", "パス・ザ・ハッシュ"},
	},
	{
		label:      "attacker timestomp",
		techniques: []string{"T1070.006"},
		aliases:    []string{"timestomp", "タイムスタンプ改ざん", "タイムスタンプの改ざん", "時刻改ざん", "タイムスタンプ改変"},
	},
}

// uncorroboratedClaimAliases returns, for the live run, the aliases of every
// corroboration-gated claim the case does NOT corroborate (per groundingContext).
// Keyed by label. An empty result means nothing to reframe.
func uncorroboratedClaimAliases(ctx groundingContext) map[string][]string {
	out := map[string][]string{}
	for _, c := range corroborationGatedClaims {
		for _, t := range c.techniques {
			if _, demote := techniqueDemotionReason(t, ctx, false); demote {
				out[c.label] = c.aliases
				break
			}
		}
	}
	return out
}

// uncorroboratedClaimAliasesFromTechniques is the regenerate-path counterpart: it
// derives the same map from an already-demoted technique set (cs.MITREUnconfirmed),
// since RegenerateOverall reads a stored synthesis instead of recomputing
// groundingContext.
func uncorroboratedClaimAliasesFromTechniques(unconfirmed []MITREEntry) map[string][]string {
	set := map[string]bool{}
	for _, e := range unconfirmed {
		set[strings.TrimSpace(e.Technique)] = true
	}
	out := map[string][]string{}
	for _, c := range corroborationGatedClaims {
		for _, t := range c.techniques {
			if set[t] {
				out[c.label] = c.aliases
				break
			}
		}
	}
	return out
}

// matchUncorroboratedClaim returns the label of the (single) uncorroborated claim
// a question mentions, or "" if none. First match wins.
func matchUncorroboratedClaim(question string, aliases map[string][]string) string {
	low := strings.ToLower(question)
	for _, c := range corroborationGatedClaims { // deterministic order
		al, ok := aliases[c.label]
		if !ok {
			continue
		}
		for _, a := range al {
			if strings.Contains(low, a) {
				return c.label
			}
		}
	}
	return ""
}

// resolvedClaimStatement is the deterministic note that REPLACES an open question
// asking to confirm/locate an uncorroborated claim. It states the verdict and why,
// so an analyst is not sent hunting for an artifact the case shows is absent.
// Case-agnostic: no host names, threat names, or thresholds.
func resolvedClaimStatement(label string, ja bool) string {
	if ja {
		switch label {
		case "Web shell":
			return "【自動裏取り済】本ケースには Web サーバ由来アーティファクト (IIS/Apache/nginx 等) もディスク上の Web ルート (inetpub\\wwwroot 等) も存在しないため、Web シェルは裏付けられない。Web シェル検知に見えた痕跡は誤検知の可能性が高く、Web シェルを起点とする初期アクセスは確定しない (実在前提の追加収集は不要)。"
		case "Pass-the-Hash":
			return "【自動裏取り済】同一環境でパスワード推測 (4625 バースト→成功) を検出しており、NTLM 成功はパスワード認証で説明できる。ハッシュ窃取/利用の証跡が無いため Pass-the-Hash は裏付けられない。"
		case "attacker timestomp":
			return "【自動裏取り済】タイムラインに時刻巻き戻し (4616 後方ジャンプ) があり、プロビジョニング/時刻補正で説明できる。攻撃者によるタイムスタンプ改変は裏付けられず、タイムラインは再アンカー前提で扱う。"
		}
		return "【自動裏取り済】" + label + " は本ケースでは裏付けられない (誤検知の可能性)。"
	}
	switch label {
	case "Web shell":
		return "[auto-corroborated] The case has no web-server artifact (IIS/Apache/nginx) and no web document root on disk (inetpub\\wwwroot etc.), so a web shell is not corroborated. The apparent \"web shell detection\" is most likely a false positive; a web-shell initial-access vector is not established (no collection of a nonexistent file is needed)."
	case "Pass-the-Hash":
		return "[auto-corroborated] Password guessing (4625 burst→success) was detected in the same environment, so the NTLM logon is explained by password authentication. With no hash-theft/use evidence, Pass-the-Hash is not corroborated."
	case "attacker timestomp":
		return "[auto-corroborated] The timeline has a backward clock step (4616), explainable by provisioning / time correction. An attacker timestomp is not corroborated; treat the timeline as needing re-anchoring."
	}
	return "[auto-corroborated] " + label + " is not corroborated in this case (likely a false positive)."
}

// reframeResolvedOpenQuestions rewrites the flat open-questions list: any question
// that asks to confirm/locate an uncorroborated claim is dropped and replaced by a
// single resolved statement per claim (deduped). Questions about corroborated or
// unrelated matters pass through unchanged, order preserved.
func reframeResolvedOpenQuestions(questions []string, aliases map[string][]string, ja bool) []string {
	if len(aliases) == 0 {
		return questions
	}
	out := make([]string, 0, len(questions))
	emitted := map[string]bool{}
	for _, q := range questions {
		if label := matchUncorroboratedClaim(q, aliases); label != "" {
			if !emitted[label] {
				emitted[label] = true
				out = append(out, resolvedClaimStatement(label, ja))
			}
			continue
		}
		out = append(out, q)
	}
	return out
}

// reframeOpenQuestionsSynth applies the same reframe to the prioritised three-tier
// view: items about an uncorroborated claim are removed from critical /
// needs_collection / supplementary (they are not open actions), and one resolved
// note per claim is appended to supplementary (informational, lowest priority).
func reframeOpenQuestionsSynth(s OpenQuestionsSynthesis, aliases map[string][]string, ja bool) OpenQuestionsSynthesis {
	if len(aliases) == 0 {
		return s
	}
	resolved := map[string]bool{}
	strip := func(in []string) []string {
		out := make([]string, 0, len(in))
		for _, q := range in {
			if label := matchUncorroboratedClaim(q, aliases); label != "" {
				resolved[label] = true
				continue
			}
			out = append(out, q)
		}
		return out
	}
	s.Critical = strip(s.Critical)
	s.NeedsCollection = strip(s.NeedsCollection)
	s.Supplementary = strip(s.Supplementary)
	// Append resolved notes in the table's deterministic order.
	for _, c := range corroborationGatedClaims {
		if resolved[c.label] {
			s.Supplementary = append(s.Supplementary, resolvedClaimStatement(c.label, ja))
		}
	}
	return s
}

// uncorroboratedClaimDirectives returns LLM steering lines for the overall-synthesis
// prompt that FORBID asserting an uncorroborated claim even when a finding is tagged
// with it — the override the existing generic GROUNDING RULES lacked (a finding
// titled "Antivirus Web Shell Detection" was treated as "a finding supports it").
// `aliases` keys (claim labels) drive which lines are emitted.
func uncorroboratedClaimDirectives(aliases map[string][]string, ja bool) []string {
	var out []string
	for _, c := range corroborationGatedClaims {
		if _, ok := aliases[c.label]; !ok {
			continue
		}
		switch c.label {
		case "Web shell":
			if ja {
				out = append(out, "- 裏取り結果: Web シェルは本ケースで未裏付け (Web サーバ由来アーティファクトもディスク上の Web ルートも無い)。たとえ署名 finding が Web シェルとタグ付けしていても、事実として断定せず、誤検知/未確認として扱うか省略すること。Web シェル起点の初期アクセスを攻撃ストーリーの前提にしないこと。")
			} else {
				out = append(out, "- Corroboration: a web shell is UNCORROBORATED in this case (no web-server artifact and no web document root on disk). Even if a signature finding is tagged as a web shell, do NOT assert it as fact — treat it as a false positive / unconfirmed or omit it, and do not build the attack story on a web-shell initial access.")
			}
		case "Pass-the-Hash":
			if ja {
				out = append(out, "- 裏取り結果: Pass-the-Hash は本ケースで未裏付け (同一環境のパスワード推測成功で NTLM 成功を説明可能、ハッシュ窃取/利用の証跡無し)。署名 finding がタグ付けしていても断定しないこと。")
			} else {
				out = append(out, "- Corroboration: Pass-the-Hash is UNCORROBORATED here (a password-guessing success explains the NTLM logon; no hash-theft/use evidence). Do NOT assert it even if a finding is tagged with it.")
			}
		}
	}
	return out
}
