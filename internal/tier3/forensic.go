package tier3

import (
	"strings"

	"github.com/tlvb/tlvb/internal/tier2"
)

// forensic.go derives the three incident-response narrative sections that a
// DFIR report needs but synthesis.json (v0.1) does not yet carry explicitly:
//
//   - Intrusion path (how the attacker got in)
//   - Affected scope (hosts / accounts / data at risk)
//   - Recommendations (containment / eradication / recovery)
//
// All three are best-effort, RULE-BASED derivations from the detected findings,
// MITRE techniques and IOCs — they are NOT LLM output. The report marks them as
// auto-derived and requiring human review. When a future Tier 2 fills these in
// explicitly, switch the renderer to prefer the synthesis values.

type scopeView struct {
	Hosts      []string
	Accounts   []string
	DataAtRisk []string
}

type recoView struct {
	Containment []string
	Eradication []string
	Recovery    []string
}

// collectTactics gathers the set of MITRE tactics present in the case, from
// both the case-wide mapping and the per-cluster attack phases.
func collectTactics(cs tier2.CaseSynthesis) map[string]bool {
	t := map[string]bool{}
	for _, m := range cs.MITREMapping {
		if m.Tactic != "" {
			t[strings.ToLower(m.Tactic)] = true
		}
	}
	for _, c := range cs.Clusters {
		if c.AttackPhase != "" {
			t[strings.ToLower(c.AttackPhase)] = true
		}
	}
	return t
}

// deriveIntrusionPath produces a best-effort initial-access narrative. Returns
// "" only when there is nothing at all to say (no clusters, no mapping).
func deriveIntrusionPath(cs tier2.CaseSynthesis, lang string) string {
	ja := lang != "en"

	var iaTechs []string
	for _, m := range cs.MITREMapping {
		if strings.ToLower(m.Tactic) == "initial-access" {
			iaTechs = appendUniq(iaTechs, m.Technique)
		}
	}

	var firstPhase, firstNarr string
	if len(cs.Clusters) > 0 { // clusters are time-ordered by the Tier 2 runner
		firstPhase = cs.Clusters[0].AttackPhase
		firstNarr = cs.Clusters[0].Narrative
	}

	if len(iaTechs) > 0 {
		if ja {
			return "初期侵入に関連する MITRE technique " + strings.Join(iaTechs, ", ") +
				" (initial-access) が検出された。詳細は該当クラスタおよびイベントタイムラインを参照のこと。"
		}
		return "MITRE technique(s) " + strings.Join(iaTechs, ", ") +
			" (initial-access) were detected. See the relevant cluster and the event timeline for detail."
	}

	if firstPhase == "initial-access" && firstNarr != "" {
		return firstNarr
	}

	if firstPhase == "" {
		if ja {
			return "侵入経路を判断できる finding が得られなかった。"
		}
		return "No findings were available from which to determine the intrusion path."
	}

	if ja {
		return "初期侵入経路は本ケースの証拠群からは特定できなかった。最も早く観測された活動は「" +
			phaseLabelJA(firstPhase) + "」フェーズであり、それ以前の侵入手段は収集対象外のデータソースに痕跡が残っている可能性がある。"
	}
	return "The initial access vector could not be determined from the available evidence. The earliest observed activity was the \"" +
		firstPhase + "\" phase; the entry method may reside in data sources that were not collected."
}

// deriveAffectedScope pulls hosts / accounts from the IOC set and infers
// data-at-risk categories from the detected tactics. Returns nil when nothing
// can be said.
func deriveAffectedScope(cs tier2.CaseSynthesis, en *enrichment, lang string) *scopeView {
	ja := lang != "en"
	sv := &scopeView{}
	for _, ioc := range en.IOCs {
		switch ioc.Type {
		case "host":
			sv.Hosts = appendUniq(sv.Hosts, ioc.Value)
		case "account":
			sv.Accounts = appendUniq(sv.Accounts, ioc.Value)
		}
	}

	t := collectTactics(cs)
	add := func(j, e string) {
		if ja {
			sv.DataAtRisk = append(sv.DataAtRisk, j)
		} else {
			sv.DataAtRisk = append(sv.DataAtRisk, e)
		}
	}
	if t["credential-access"] {
		add("アカウント認証情報 (LSASS メモリ / レジストリハイブ)", "Account credentials (LSASS memory / registry hives)")
	}
	if t["collection"] {
		add("収集対象とされたユーザーデータ", "User data targeted for collection")
	}
	if t["exfiltration"] {
		add("外部へ持ち出された可能性のあるデータ", "Data potentially exfiltrated")
	}
	if t["impact"] {
		add("システムの可用性 (シャドウコピー / バックアップ)", "System availability (shadow copies / backups)")
	}

	if len(sv.Hosts) == 0 && len(sv.Accounts) == 0 && len(sv.DataAtRisk) == 0 {
		return nil
	}
	return sv
}

// deriveRecommendations maps the detected tactics to containment / eradication
// / recovery actions, plus a couple of generic ones. Returns nil only if there
// are no tactics at all (the generic items still make it non-nil normally).
func deriveRecommendations(cs tier2.CaseSynthesis, lang string) *recoView {
	ja := lang != "en"
	t := collectTactics(cs)
	r := &recoView{}
	addC := func(j, e string) {
		if ja {
			r.Containment = append(r.Containment, j)
		} else {
			r.Containment = append(r.Containment, e)
		}
	}
	addE := func(j, e string) {
		if ja {
			r.Eradication = append(r.Eradication, j)
		} else {
			r.Eradication = append(r.Eradication, e)
		}
	}
	addR := func(j, e string) {
		if ja {
			r.Recovery = append(r.Recovery, j)
		} else {
			r.Recovery = append(r.Recovery, e)
		}
	}

	if t["credential-access"] {
		addC("窃取された可能性のあるアカウントのパスワードを強制リセットし、既存セッションを失効させる", "Force-reset passwords for potentially compromised accounts and revoke active sessions")
		addE("KRBTGT アカウントを二段階でリセットし、窃取資格情報の悪用を監視する", "Double-reset the KRBTGT account and monitor for abuse of stolen credentials")
		addR("特権アカウントへ多要素認証 (MFA) を導入する", "Enforce multi-factor authentication for privileged accounts")
	}
	if t["defense-evasion"] {
		addC("イベントログの集中転送 (WEF/SIEM) を有効化し、以後の改ざんに備える", "Enable centralized event-log forwarding (WEF/SIEM) to resist further tampering")
		addR("監査ポリシーを強化し、ログ消去イベント (EID 1102/104) のアラートを設定する", "Harden the audit policy and alert on log-clear events (EID 1102/104)")
	}
	if t["execution"] {
		addC("確認された不審プロセスを停止し、関連する実行ファイルを隔離する", "Terminate the identified suspicious processes and quarantine the associated binaries")
		addE("ドロップされた実行ファイル (例: C:\\Users\\Public 配下) を除去する", "Remove dropped binaries (e.g. under C:\\Users\\Public)")
		addR("アプリケーション許可リスト (WDAC/AppLocker) の導入を検討する", "Consider application allow-listing (WDAC/AppLocker)")
	}
	if t["persistence"] {
		addE("不正なスケジュールタスク・サービス・自動起動エントリを除去する", "Remove malicious scheduled tasks, services and autorun entries")
	}
	if t["lateral-movement"] {
		addC("RDP・管理共有・WMI を制限し、影響ホストをネットワーク分離する", "Restrict RDP, admin shares and WMI; isolate affected hosts on the network")
		addE("横展開先の候補ホストを特定し追加調査する", "Identify and investigate candidate lateral-movement destination hosts")
	}
	if t["initial-access"] {
		addC("侵害された可能性のあるアカウントを無効化し、外部公開された RDP を遮断する", "Disable potentially compromised accounts and block internet-exposed RDP")
	}
	if t["command-and-control"] {
		addC("特定された C2 への通信を遮断し、関連ホストを隔離する", "Block communication to the identified C2 and isolate related hosts")
	}
	if t["impact"] {
		addC("影響を受けたホストを隔離し、さらなる破壊行為を防ぐ", "Isolate affected hosts to prevent further destructive actions")
		addE("削除されたシャドウコピー / バックアップの状態を確認する", "Verify the status of deleted shadow copies / backups")
		addR("オフライン・改ざん耐性のあるバックアップからの復旧手順を検証する", "Validate recovery from offline, tamper-resistant backups")
	}

	// Generic, always-applicable items.
	addE("本レポートの全 finding を人手で精査し、未解決の論点を解消する", "Manually review every finding in this report and resolve the open questions")
	addR("影響範囲の確定後、侵害ホストのクリーン再構築を検討する", "After scoping is complete, consider clean rebuilds of compromised hosts")

	if len(r.Containment) == 0 && len(r.Eradication) == 0 && len(r.Recovery) == 0 {
		return nil
	}
	return r
}

// appendUniq appends v to s if non-empty and not already present, capping the
// slice at 25 entries so a noisy IOC set cannot blow up the report.
func appendUniq(s []string, v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return s
	}
	for _, x := range s {
		if x == v {
			return s
		}
	}
	if len(s) >= 25 {
		return s
	}
	return append(s, v)
}
