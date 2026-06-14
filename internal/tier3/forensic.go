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

// intrusionTechniques returns the initial-access MITRE technique IDs detected in
// the case (from the confirmed mapping). These render as chips on the intrusion
// step of the attack-story timeline. Empty when none were detected.
func intrusionTechniques(cs tier2.CaseSynthesis) []string {
	var out []string
	for _, m := range cs.MITREMapping {
		if strings.ToLower(m.Tactic) == "initial-access" {
			out = appendUniq(out, m.Technique)
		}
	}
	return out
}

// baseTechnique strips a sub-technique suffix ("T1059.001" → "T1059") so the
// plain-language lookups can be keyed by the parent technique.
func baseTechnique(id string) string {
	if i := strings.IndexByte(id, '.'); i > 0 {
		return id[:i]
	}
	return strings.TrimSpace(id)
}

// mitrePlain maps a base MITRE technique ID to a short, plain-language label a
// non-specialist can understand. Used for the intrusion path and the
// attack-story step chips — i.e. everything OUTSIDE the analyst sections, which
// keep the raw technique IDs. {ja, en}. Unmapped IDs fall back to the raw ID.
var mitrePlain = map[string][2]string{
	// initial access
	"T1190": {"公開アプリ/サーバの脆弱性を悪用", "Exploit public-facing app"},
	"T1133": {"外部リモートサービス経由の侵入", "External remote services"},
	"T1078": {"正規アカウントの不正利用", "Valid accounts (stolen logins)"},
	"T1566": {"フィッシング(不正メール等)", "Phishing"},
	"T1189": {"改ざんサイト閲覧による侵入", "Drive-by compromise"},
	"T1199": {"取引先など信頼関係の悪用", "Trusted relationship abuse"},
	"T1195": {"サプライチェーン経由の侵入", "Supply-chain compromise"},
	"T1091": {"USB等メディア経由の侵入", "Removable-media spread"},
	"T1200": {"不正ハードウェア接続", "Hardware additions"},
	// execution
	"T1059": {"コマンド/スクリプト実行", "Command & scripting"},
	"T1204": {"利用者をだましての実行", "User execution"},
	"T1106": {"OS機能を使った実行", "Native API execution"},
	"T1047": {"WMIによる遠隔実行", "WMI execution"},
	// persistence / priv-esc
	"T1053": {"タスクスケジューラへの常駐", "Scheduled task"},
	"T1547": {"自動起動への登録", "Autostart entry"},
	"T1543": {"サービス化による常駐", "System service"},
	"T1546": {"イベント連動の常駐", "Event-triggered persistence"},
	"T1505": {"サーバへの裏口設置(Webシェル等)", "Server component (web shell)"},
	"T1098": {"アカウント設定の改ざん", "Account manipulation"},
	"T1136": {"不正アカウントの作成", "Create account"},
	"T1574": {"正規プログラムの読込先乗っ取り", "Hijack execution flow"},
	"T1055": {"他プロセスへのコード注入", "Process injection"},
	"T1548": {"権限昇格の悪用", "Abuse elevation control"},
	"T1134": {"アクセストークンの操作", "Access-token manipulation"},
	// defense evasion
	"T1070": {"証跡(ログ)の消去", "Log/indicator removal"},
	"T1562": {"セキュリティ機能の無効化", "Impair defenses"},
	"T1027": {"難読化・隠蔽", "Obfuscation"},
	"T1036": {"正規ファイルへの偽装", "Masquerading"},
	"T1202": {"コマンドの間接実行", "Indirect command execution"},
	"T1620": {"メモリ内実行(ファイルレス)", "In-memory (fileless) execution"},
	"T1112": {"レジストリの改ざん", "Modify registry"},
	"T1218": {"正規ツールを悪用した実行", "Living-off-the-land binary"},
	// credential access
	"T1003": {"認証情報の窃取(ダンプ)", "Credential dumping"},
	"T1552": {"設定等に残る認証情報の窃取", "Unsecured credentials"},
	"T1558": {"Kerberosチケットの窃取", "Steal Kerberos tickets"},
	"T1550": {"窃取した認証情報での認証", "Use stolen auth material"},
	"T1110": {"パスワード総当たり攻撃", "Brute force"},
	"T1056": {"キー入力等の盗聴", "Input capture"},
	// discovery
	"T1016": {"ネットワーク構成の調査", "Network config discovery"},
	"T1018": {"他ホストの探索", "Remote host discovery"},
	"T1082": {"システム情報の調査", "System info discovery"},
	"T1087": {"アカウントの調査", "Account discovery"},
	"T1482": {"ドメイン信頼関係の調査", "Domain trust discovery"},
	"T1083": {"ファイル/フォルダの探索", "File & directory discovery"},
	"T1057": {"実行中プロセスの調査", "Process discovery"},
	"T1069": {"権限グループの調査", "Permission-group discovery"},
	"T1033": {"ログインユーザーの調査", "User discovery"},
	"T1518": {"導入ソフトの調査", "Software discovery"},
	"T1012": {"レジストリの調査", "Query registry"},
	"T1007": {"サービスの調査", "Service discovery"},
	"T1049": {"ネットワーク接続の調査", "Network connection discovery"},
	"T1135": {"ネットワーク共有の調査", "Network share discovery"},
	"T1201": {"パスワードポリシーの調査", "Password-policy discovery"},
	"T1614": {"システムの地域設定の調査", "System location discovery"},
	"T1588": {"攻撃ツール/証明書の入手", "Obtain capabilities"},
	// lateral movement / collection / c2 / exfil / impact
	"T1021": {"リモート接続での横展開", "Remote-service lateral move"},
	"T1570": {"横方向へのツール転送", "Lateral tool transfer"},
	"T1005": {"端末内データの収集", "Local data collection"},
	"T1074": {"持ち出し用データの集約", "Data staging"},
	"T1560": {"データの圧縮/暗号化(持ち出し準備)", "Archive collected data"},
	"T1071": {"通常通信を装ったC2", "App-layer C2"},
	"T1105": {"外部からのツール持ち込み", "Ingress tool transfer"},
	"T1041": {"C2経由のデータ持ち出し", "Exfiltration over C2"},
	"T1567": {"Webサービス経由の持ち出し", "Exfil over web service"},
	"T1486": {"データ暗号化(ランサム)", "Data encrypted (ransomware)"},
	"T1490": {"復旧手段の妨害(シャドウコピー削除等)", "Inhibit system recovery"},
	"T1489": {"サービスの停止", "Service stop"},
	"T1531": {"アカウント締め出し", "Account access removal"},
}

// intrusionExplain gives a fuller, plain-language sentence fragment for the
// initial-access techniques shown in the intrusion-path step. {ja, en}.
var intrusionExplain = map[string][2]string{
	"T1190": {"外部に公開されたアプリやサーバの弱点(脆弱性)を突いて侵入する手口", "exploiting a vulnerability in an internet-facing app or server"},
	"T1133": {"VPN やリモートデスクトップなど外部公開サービス経由で侵入する手口", "entering through external remote services such as VPN or RDP"},
	"T1078": {"盗まれた正規の ID とパスワードでログインして侵入する手口", "logging in with stolen but otherwise legitimate credentials"},
	"T1566": {"不正なメールやリンク(フィッシング)で利用者をだまして侵入する手口", "tricking a user with a phishing email or link"},
	"T1189": {"改ざんされた Web サイトを閲覧しただけで侵入される手口(ドライブバイ)", "a drive-by compromise from visiting a booby-trapped website"},
	"T1199": {"取引先や委託先など、信頼関係を悪用して侵入する手口", "abusing a trusted third-party relationship"},
	"T1195": {"ソフトウェアの供給網(サプライチェーン)を経由した侵入", "compromise through the software supply chain"},
	"T1091": {"USB などリムーバブルメディア経由で持ち込まれる侵入", "spreading in via removable media such as USB"},
	"T1098": {"アカウントの権限や認証設定を改ざんして侵入の足場を作る手口", "manipulating account privileges or authentication settings"},
	"T1200": {"不正なハードウェアを接続して侵入する手口", "adding malicious hardware to gain entry"},
}

// mitrePlainLabel returns the short plain-language label for a technique ID, or
// the raw ID when there is no mapping.
func mitrePlainLabel(id, lang string) string {
	if v, ok := mitrePlain[baseTechnique(id)]; ok {
		if lang == "en" {
			return v[1]
		}
		return v[0]
	}
	return strings.TrimSpace(id)
}

// intrusionPhrase renders one initial-access technique as a plain-language
// phrase with the ID kept in parentheses for reference.
func intrusionPhrase(id, lang string) string {
	if v, ok := intrusionExplain[baseTechnique(id)]; ok {
		if lang == "en" {
			return v[1] + " (" + id + ")"
		}
		return v[0] + "（" + id + "）"
	}
	if lbl := mitrePlainLabel(id, lang); lbl != strings.TrimSpace(id) {
		if lang == "en" {
			return lbl + " (" + id + ")"
		}
		return lbl + "（" + id + "）"
	}
	if lang == "en" {
		return "an initial-access technique (" + id + ")"
	}
	return "初期侵入の手口（" + id + "）"
}

// deriveIntrusionPath produces a best-effort initial-access narrative. Returns
// "" only when there is nothing at all to say (no clusters, no mapping).
func deriveIntrusionPath(cs tier2.CaseSynthesis, lang string) string {
	ja := lang != "en"

	iaTechs := intrusionTechniques(cs)

	var firstPhase, firstNarr string
	if len(cs.Clusters) > 0 { // clusters are time-ordered by the Tier 2 runner
		firstPhase = cs.Clusters[0].AttackPhase
		firstNarr = cs.Clusters[0].Narrative
	}

	if len(iaTechs) > 0 {
		var phrases []string
		for _, t := range iaTechs {
			phrases = append(phrases, intrusionPhrase(t, lang))
		}
		if ja {
			return "攻撃の入り口（侵入経路）として、" + strings.Join(phrases, "、また") +
				" が検出されました。これが最初の侵入手段になったと推定されます。"
		}
		return "The likely entry point was " + strings.Join(phrases, ", and ") +
			". This is how the attacker most likely first got in."
	}

	if firstPhase == "initial-access" && firstNarr != "" {
		return firstNarr
	}

	if firstPhase == "" {
		if ja {
			return "侵入の起点を特定できる手がかりは得られませんでした。"
		}
		return "There was not enough evidence to determine how the attacker first got in."
	}

	if ja {
		return "侵入の入り口（最初の侵入手段）は、今回集めた証拠からは特定できませんでした。" +
			"最も早く確認できた不審な活動は「" + phaseLabelJA(firstPhase) +
			"」で、それより前の侵入手段は、今回収集していないデータ（例: 通信ログ等）に痕跡が残っている可能性があります。"
	}
	return "The way the attacker first got in could not be determined from the evidence collected. " +
		"The earliest suspicious activity seen was \"" + phaseLabelEN(firstPhase) +
		"\"; the entry method may live in data that was not collected (e.g. network logs)."
}

// deriveAffectedScope pulls hosts / accounts from the IOC set and infers
// data-at-risk categories from the detected tactics. Returns nil when nothing
// can be said.
func deriveAffectedScope(cs tier2.CaseSynthesis, en *enrichment, lang string) *scopeView {
	ja := lang != "en"
	sv := &scopeView{}
	for _, ioc := range en.IOCs {
		if ioc.Confidence == "noise" {
			continue // a parser artifact (e.g. "LogonType 3") is not an affected host/account
		}
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
