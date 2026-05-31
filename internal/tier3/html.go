package tier3

import (
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/tier2"
)

// renderHTML writes a single self-contained HTML report structured as a
// digital-forensics analysis report.
//
// Sections (forensic-report convention — SANS DFIR / NIST SP 800-86 / ISO
// 27042):
//  0. Classification banner + report metadata (examiner / org / generated)
//  1. Case Information + Executive Summary + Severity Summary
//  2. Intrusion Path (rule-derived)
//  3. Affected Scope (rule-derived)
//  4. Evidence & Chain of Custody (exhibits, SHA-256, parse coverage)
//  5. Methodology & Limitations (pipeline, reproducibility, AI disclaimer)
//  6. Event Timeline (key-event chronology)
//  7. Findings (per attack cluster, with evidence detail + active search)
//     - MITRE ATT&CK Mapping
//  8. Indicators of Compromise
//  9. Recommendations (rule-derived: containment / eradication / recovery)
//  10. Open Questions (case-wide)
//     - Appendix: Audit / Provenance
//
// All CSS is inline; no JS, no external assets — the file is fully portable.
func renderHTML(path string, cs tier2.CaseSynthesis, cfg Config, en *enrichment) error {
	d := selectDict(cfg.Language)
	view := buildView(cs, cfg, en, d)

	tpl, err := template.New("report").Funcs(template.FuncMap{
		"fmtTS":      formatTS,
		"join":       func(s []string) string { return strings.Join(s, ", ") },
		"sevClass":   severityClass,
		"sevLabel":   d.sevLabel,
		"para":       splitParagraphs,
		"truncate":   truncateForTooltip,
		"phaseLabel": d.phaseLabel,
		"humanBytes": humanBytes,
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return tpl.Execute(f, view)
}

// reportView is the full view model handed to the template.
type reportView struct {
	Case           tier2.CaseSynthesis
	Dict           labelDict
	Lang           string
	GeneratedAt    string
	Examiner       string
	Organization   string
	Classification string
	ToolVersion    string
	Meta           *CaseMeta
	Severity       []sevCount
	Timeline       []timelineRow
	IOCs           []iocRow
	Clusters       []clusterView

	// Rule-derived IR narrative (best-effort, not LLM).
	IntrusionPath string
	Scope         *scopeView
	Reco          *recoView
}

type clusterView struct {
	ID              int
	AttackPhase     string
	StartTS         time.Time
	EndTS           time.Time
	Narrative       string
	MITRETechniques []string
	OpenQuestions   []string
	ActiveSearch    []tier2.ActiveSearchResult
	Findings        []findingRow
}

type findingRow struct {
	Severity      string
	Source        string
	RuleID        string
	Title         string
	FirstSeen     time.Time
	HasTS         bool
	Artifacts     []string
	EvidenceCount int
}

func buildView(cs tier2.CaseSynthesis, cfg Config, en *enrichment, d labelDict) reportView {
	v := reportView{
		Case:           cs,
		Dict:           d,
		Lang:           cfg.Language,
		GeneratedAt:    time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Examiner:       orStr(cfg.Examiner, d.UnknownExaminer),
		Organization:   cfg.Organization,
		Classification: orStr(cfg.Classification, d.DefaultClassification),
		ToolVersion:    orStr(cfg.ToolVersion, "TLVB"),
		Meta:           cfg.CaseMeta,
		Severity:       en.SeverityCounts,
		Timeline:       en.Timeline,
		IOCs:           en.IOCs,
		IntrusionPath:  deriveIntrusionPath(cs, cfg.Language),
		Scope:          deriveAffectedScope(cs, en, cfg.Language),
		Reco:           deriveRecommendations(cs, cfg.Language),
	}
	for _, c := range cs.Clusters {
		cv := clusterView{
			ID:              c.ID,
			AttackPhase:     c.AttackPhase,
			StartTS:         c.StartTS,
			EndTS:           c.EndTS,
			Narrative:       c.Narrative,
			MITRETechniques: c.MITRETechniques,
			OpenQuestions:   c.OpenQuestions,
			ActiveSearch:    c.ActiveSearch,
		}
		for _, fr := range c.FindingRefs {
			row := findingRow{
				Severity: normSeverity(fr.Severity),
				Source:   fr.Source,
				RuleID:   fr.RuleID,
				Title:    fr.Title,
			}
			if det := en.lookupDetail(fr.Source, fr.RuleID, fr.Title); det != nil {
				row.FirstSeen = det.FirstSeen
				row.HasTS = det.HasTS
				row.Artifacts = det.Artifacts
				row.EvidenceCount = det.EvidenceCount
			}
			cv.Findings = append(cv.Findings, row)
		}
		v.Clusters = append(v.Clusters, cv)
	}
	return v
}

func (en *enrichment) lookupDetail(source, ruleID, title string) *findingDetail {
	if d, ok := en.detailByKey[detailKey(source, ruleID)]; ok {
		return d
	}
	if d, ok := en.detailByTitle[strings.ToLower(strings.TrimSpace(title))]; ok {
		return d
	}
	return nil
}

func humanBytes(n int64) string {
	if n <= 0 {
		return "-"
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// labelDict holds the UI strings. LLM-generated narrative / open questions
// stay verbatim — we only translate frame labels.
type labelDict struct {
	ReportTitle      string
	Case             string
	Generated        string
	Model            string
	TotalFindings    string
	ClusterCount     string
	ExecutiveSummary string
	MITREMapping     string
	Technique        string
	Tactic           string
	FindingCount     string
	ClusterIDs       string
	Cluster          string
	Window           string
	AttackPhase      string
	Narrative        string
	Findings         string
	Source           string
	RuleID           string
	Title            string
	Severity         string
	OpenQuestions    string
	Audit            string
	LLMCalls         string
	LLMDuration      string
	InputTokens      string
	OutputTokens     string
	SkillSHA         string

	// forensic additions
	DefaultClassification string
	Examiner              string
	UnknownExaminer       string
	Organization          string
	CaseInformation       string
	DisplayName           string
	Status                string
	AnalysisDate          string
	ToolVersion           string
	Notes                 string
	Scope                 string
	ScopeBody             string
	SeveritySummary       string
	EvidenceChain         string
	EvidenceID            string
	SourcePath            string
	SHA256                string
	Size                  string
	CollectedAt           string
	EvidenceTypeCol       string
	Host                  string
	IntegrityNote         string
	ArtifactCoverage      string
	ArtifactName          string
	EventCount            string
	TotalEvents           string
	Methodology           string
	MethodologyBody       string
	Limitations           string
	AIDisclaimer          string
	FirstSeen             string
	Artifacts             string
	EvidenceCountCol      string
	TimelineSection       string
	TimeCol               string
	EventTypeCol          string
	IOCSection            string
	IOCType               string
	IOCValue              string
	IOCCount              string
	NoIOC                 string
	ActiveSearch          string
	Question              string
	AnswerCol             string
	HitsCol               string
	CaseOpenQuestions     string
	None                  string

	// intrusion path / affected scope / recommendations
	IntrusionPathSec   string
	AffectedScopeSec   string
	ScopeHosts         string
	ScopeAccounts      string
	ScopeData          string
	RecommendationsSec string
	RecContainment     string
	RecEradication     string
	RecRecovery        string
	DerivedNote        string

	phaseLabel func(string) string
	sevLabel   func(string) string
}

var dictJA = labelDict{
	ReportTitle:      "TLVB フォレンジック解析レポート",
	Case:             "ケース ID",
	Generated:        "生成日時",
	Model:            "解析モデル",
	TotalFindings:    "Finding 総数",
	ClusterCount:     "クラスタ数",
	ExecutiveSummary: "エグゼクティブサマリ",
	MITREMapping:     "MITRE ATT&CK マッピング",
	Technique:        "Technique",
	Tactic:           "Tactic",
	FindingCount:     "件数",
	ClusterIDs:       "クラスタ ID",
	Cluster:          "Finding 詳細 (攻撃クラスタ別)",
	Window:           "時刻範囲",
	AttackPhase:      "攻撃フェーズ",
	Narrative:        "シナリオ",
	Findings:         "Finding 一覧",
	Source:           "ソース",
	RuleID:           "ルール ID",
	Title:            "タイトル",
	Severity:         "重要度",
	OpenQuestions:    "未解決の論点",
	Audit:            "付録: 監査・来歴情報",
	LLMCalls:         "LLM 呼び出し回数",
	LLMDuration:      "LLM 累計時間 (秒)",
	InputTokens:      "Input tokens",
	OutputTokens:     "Output tokens",
	SkillSHA:         "Skill SHA-256",

	DefaultClassification: "社外秘 / CONFIDENTIAL",
	Examiner:              "解析担当 (Examiner)",
	UnknownExaminer:       "(未記入)",
	Organization:          "所属組織",
	CaseInformation:       "1. ケース情報",
	DisplayName:           "ケース名",
	Status:                "ステータス",
	AnalysisDate:          "解析実施日時",
	ToolVersion:           "使用ツール",
	Notes:                 "備考",
	Scope:                 "解析スコープ",
	ScopeBody:             "本レポートは、提供された Windows フォレンジック・アーティファクトに対する自動解析の結果である。対象は下記「証拠インベントリ」に列挙した証拠に限定される。ネットワークログ・メモリダンプ等、収集対象外のデータソースは解析範囲に含まれない。",
	SeveritySummary:       "重要度サマリ",
	EvidenceChain:         "4. 証拠インベントリと完全性 (Chain of Custody)",
	EvidenceID:            "証拠 ID",
	SourcePath:            "取得元",
	SHA256:                "SHA-256",
	Size:                  "サイズ",
	CollectedAt:           "登録日時",
	EvidenceTypeCol:       "種別",
	Host:                  "ホスト",
	IntegrityNote:         "各証拠は取得時に SHA-256 ハッシュを記録しており、上記値で原本との同一性を検証できる。解析は読み取り専用で行われ、原本は変更されていない。",
	ArtifactCoverage:      "アーティファクト別イベント数 (Tier 0 解析範囲)",
	ArtifactName:          "アーティファクト",
	EventCount:            "イベント数",
	TotalEvents:           "総イベント数",
	Methodology:           "5. 解析手法と限界",
	MethodologyBody:       "本解析は TLVB 自律 IR エージェントによる以下のパイプラインで実施した。Tier 0 (パーサ群が各アーティファクトを正規化イベントに変換)、Tier 1A (Sigma / Hayabusa / MITRE ATT&CK 由来のシグネチャを事前生成 SQL として実行し、ヒットを finding 化)、Tier 1B (skill ベースの異常検知を LLM 推論で補完)、Tier 2 (finding を時間クラスタ化し、周辺の生イベントから攻撃シナリオを再構成)、Tier 3 (本レポート生成)。各 finding は event_id・source_artifact・タイムスタンプで裏付けられる。",
	Limitations:           "限界・前提: (1) タイムスタンプは原則 UTC。アーティファクト由来のタイムゾーン誤差は補正していない。(2) シグネチャ未知の攻撃や、収集対象外のアーティファクトに痕跡が残る攻撃は検知できない。(3) 自動再構成された攻撃シナリオは仮説であり、確証には人手レビューを要する。未解決事項は各「未解決の論点」に明示した。",
	AIDisclaimer:          "AI 利用に関する開示: シナリオ記述・MITRE マッピング・未解決論点は大規模言語モデル (上記「解析モデル」) が生成した。シグネチャ検知部 (Tier 1A) は LLM を実行時に呼び出さず、事前検証済み SQL のみを実行する。最終的な判断は資格を持つ解析担当者によるレビューを前提とする。",
	FirstSeen:             "初出時刻",
	Artifacts:             "アーティファクト",
	EvidenceCountCol:      "証拠数",
	TimelineSection:       "6. イベントタイムライン (主要事象)",
	TimeCol:               "時刻 (UTC)",
	EventTypeCol:          "イベント種別",
	IOCSection:            "8. 侵害指標 (Indicators of Compromise)",
	IOCType:               "種別",
	IOCValue:              "値",
	IOCCount:              "出現回数",
	NoIOC:                 "抽出可能な侵害指標はなかった。",
	ActiveSearch:          "能動探索 (仮説駆動クエリ)",
	Question:              "論点 / 仮説",
	AnswerCol:             "解釈",
	HitsCol:               "ヒット数",
	CaseOpenQuestions:     "10. 未解決の論点 (ケース全体)",
	None:                  "該当なし",

	IntrusionPathSec:   "2. 侵入経路 (Intrusion Path)",
	AffectedScopeSec:   "3. 影響範囲 (Affected Scope)",
	ScopeHosts:         "影響を受けたホスト",
	ScopeAccounts:      "影響を受けたアカウント",
	ScopeData:          "リスクに晒されたデータ",
	RecommendationsSec: "9. 今後の推奨事項 (Recommendations)",
	RecContainment:     "封じ込め (Containment)",
	RecEradication:     "根絶 (Eradication)",
	RecRecovery:        "復旧 (Recovery)",
	DerivedNote:        "※ 本セクションは検出された finding・MITRE technique・IOC からルールベースで自動導出した参考情報であり、LLM 生成ではない。確証と優先順位付けには人手レビューを要する。",

	phaseLabel: phaseLabelJA,
	sevLabel:   sevLabelJA,
}

var dictEN = labelDict{
	ReportTitle:      "TLVB Forensic Analysis Report",
	Case:             "Case ID",
	Generated:        "Generated",
	Model:            "Analysis model",
	TotalFindings:    "Total findings",
	ClusterCount:     "Cluster count",
	ExecutiveSummary: "Executive Summary",
	MITREMapping:     "MITRE ATT&CK Mapping",
	Technique:        "Technique",
	Tactic:           "Tactic",
	FindingCount:     "Count",
	ClusterIDs:       "Cluster IDs",
	Cluster:          "Findings (by attack cluster)",
	Window:           "Window",
	AttackPhase:      "Attack phase",
	Narrative:        "Narrative",
	Findings:         "Findings",
	Source:           "Source",
	RuleID:           "Rule ID",
	Title:            "Title",
	Severity:         "Severity",
	OpenQuestions:    "Open questions",
	Audit:            "Appendix: Audit & Provenance",
	LLMCalls:         "LLM calls",
	LLMDuration:      "LLM duration (s)",
	InputTokens:      "Input tokens",
	OutputTokens:     "Output tokens",
	SkillSHA:         "Skill SHA-256",

	DefaultClassification: "CONFIDENTIAL",
	Examiner:              "Examiner",
	UnknownExaminer:       "(not recorded)",
	Organization:          "Organization",
	CaseInformation:       "1. Case Information",
	DisplayName:           "Case name",
	Status:                "Status",
	AnalysisDate:          "Analysis date",
	ToolVersion:           "Tooling",
	Notes:                 "Notes",
	Scope:                 "Scope",
	ScopeBody:             "This report presents the result of automated analysis of the provided Windows forensic artifacts. Its scope is limited to the evidence listed under \"Evidence Inventory\" below. Data sources that were not collected (e.g. network logs, memory dumps) are out of scope.",
	SeveritySummary:       "Severity Summary",
	EvidenceChain:         "4. Evidence Inventory & Integrity (Chain of Custody)",
	EvidenceID:            "Evidence ID",
	SourcePath:            "Source",
	SHA256:                "SHA-256",
	Size:                  "Size",
	CollectedAt:           "Registered at",
	EvidenceTypeCol:       "Type",
	Host:                  "Host",
	IntegrityNote:         "A SHA-256 hash was recorded for each exhibit at acquisition; the values above let an examiner verify integrity against the original. Analysis was read-only and the originals were not modified.",
	ArtifactCoverage:      "Events per Artifact (Tier 0 coverage)",
	ArtifactName:          "Artifact",
	EventCount:            "Events",
	TotalEvents:           "Total events",
	Methodology:           "5. Methodology & Limitations",
	MethodologyBody:       "Analysis was performed by the TLVB autonomous IR agent through the following pipeline: Tier 0 (parsers normalise each artifact into unified events), Tier 1A (Sigma / Hayabusa / MITRE ATT&CK signatures compiled to pre-baked SQL, matches become findings), Tier 1B (skill-based anomaly detection augmented by LLM reasoning), Tier 2 (findings are clustered temporally and the surrounding raw events are reconstructed into an attack narrative), Tier 3 (this report). Every finding is backed by event_id, source_artifact and a timestamp.",
	Limitations:           "Limitations & assumptions: (1) Timestamps are UTC; artifact-specific timezone skew is not corrected. (2) Attacks with no known signature, or whose traces live in uncollected artifacts, cannot be detected. (3) The reconstructed attack narrative is a hypothesis and requires human review to confirm; unresolved items are listed under \"Open questions\".",
	AIDisclaimer:          "AI disclosure: narratives, MITRE mappings and open questions were generated by a large language model (see \"Analysis model\"). The signature-detection tier (Tier 1A) invokes no LLM at runtime — it executes only pre-validated SQL. Final determinations are expected to be reviewed by a qualified examiner.",
	FirstSeen:             "First seen",
	Artifacts:             "Artifacts",
	EvidenceCountCol:      "Evidence",
	TimelineSection:       "6. Event Timeline (key events)",
	TimeCol:               "Time (UTC)",
	EventTypeCol:          "Event type",
	IOCSection:            "8. Indicators of Compromise",
	IOCType:               "Type",
	IOCValue:              "Value",
	IOCCount:              "Occurrences",
	NoIOC:                 "No indicators of compromise could be extracted.",
	ActiveSearch:          "Active search (hypothesis-driven queries)",
	Question:              "Question / hypothesis",
	AnswerCol:             "Interpretation",
	HitsCol:               "Hits",
	CaseOpenQuestions:     "10. Open Questions (case-wide)",
	None:                  "None",

	IntrusionPathSec:   "2. Intrusion Path",
	AffectedScopeSec:   "3. Affected Scope",
	ScopeHosts:         "Affected hosts",
	ScopeAccounts:      "Affected accounts",
	ScopeData:          "Data at risk",
	RecommendationsSec: "9. Recommendations",
	RecContainment:     "Containment",
	RecEradication:     "Eradication",
	RecRecovery:        "Recovery",
	DerivedNote:        "Note: this section is auto-derived (rule-based, not LLM) from the detected findings, MITRE techniques and IOCs. It requires human review for confirmation and prioritisation.",

	phaseLabel: phaseLabelEN,
	sevLabel:   sevLabelEN,
}

func selectDict(lang string) labelDict {
	if strings.ToLower(lang) == "en" {
		return dictEN
	}
	return dictJA
}

func phaseLabelJA(p string) string {
	m := map[string]string{
		"initial-access":       "初期侵入",
		"execution":            "実行",
		"persistence":          "永続化",
		"privilege-escalation": "権限昇格",
		"defense-evasion":      "防御回避",
		"credential-access":    "認証情報窃取",
		"discovery":            "ディスカバリ",
		"lateral-movement":     "横展開",
		"collection":           "収集",
		"command-and-control":  "C2",
		"exfiltration":         "持ち出し",
		"impact":               "影響",
		"reconnaissance":       "偵察",
	}
	if v, ok := m[p]; ok {
		return v + " (" + p + ")"
	}
	return p
}

func phaseLabelEN(p string) string { return p }

func sevLabelJA(s string) string {
	m := map[string]string{
		"critical":      "緊急",
		"high":          "高",
		"medium":        "中",
		"low":           "低",
		"informational": "情報",
		"unknown":       "不明",
	}
	if v, ok := m[normSeverity(s)]; ok {
		return v
	}
	return s
}

func sevLabelEN(s string) string {
	s = normSeverity(s)
	if s == "" {
		return "unknown"
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// severityClass maps a finding's severity to a CSS class for the badge.
func severityClass(s string) string {
	switch normSeverity(s) {
	case "critical":
		return "sev-critical"
	case "high":
		return "sev-high"
	case "medium":
		return "sev-medium"
	case "low":
		return "sev-low"
	case "informational":
		return "sev-info"
	default:
		return "sev-unknown"
	}
}

// splitParagraphs converts narratives to []string of paragraph chunks
// (split on blank line).
func splitParagraphs(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, "\n\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func truncateForTooltip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="{{.Lang}}">
<head>
<meta charset="UTF-8">
<title>{{.Dict.ReportTitle}} — {{.Case.CaseID}}</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Yu Gothic UI", Roboto, "Hiragino Sans", sans-serif;
         max-width: 1100px; margin: 0 auto; padding: 1.5rem 1.5rem 3rem;
         line-height: 1.55; color: #1f2329; background: #fafbfc; }
  h1, h2, h3, h4 { color: #0d1117; margin-top: 1.8rem; }
  h1 { border-bottom: 3px solid #0969da; padding-bottom: 0.4rem; margin-top: 0.6rem; }
  h2 { border-bottom: 1px solid #d0d7de; padding-bottom: 0.3rem; }
  h3 { border-left: 4px solid #0969da; padding-left: 0.6rem; }
  .classbanner { background: #cf222e; color: #fff; text-align: center; font-weight: 700;
                 letter-spacing: 0.08em; padding: 0.35rem; border-radius: 4px; margin-bottom: 0.6rem; }
  header.meta, dl.info { background: #fff; border: 1px solid #d0d7de; border-radius: 6px;
                padding: 0.8rem 1rem; margin-bottom: 1.2rem;
                display: grid; grid-template-columns: max-content 1fr; gap: 0.3rem 1rem; }
  header.meta dt, dl.info dt { font-weight: 600; color: #57606a; }
  header.meta dd, dl.info dd { margin: 0; }
  table { border-collapse: collapse; width: 100%; margin: 0.5rem 0 1rem;
          background: #fff; border: 1px solid #d0d7de; border-radius: 4px; overflow: hidden; }
  th, td { border-bottom: 1px solid #d0d7de; padding: 0.45rem 0.7rem; text-align: left;
           vertical-align: top; font-size: 0.9rem; }
  th { background: #f6f8fa; font-weight: 600; }
  tr:last-child td { border-bottom: none; }
  code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.85rem; word-break: break-all; }
  .badge { display: inline-block; padding: 0.15rem 0.55rem; border-radius: 999px;
           font-size: 0.78rem; font-weight: 600; white-space: nowrap; }
  .sev-critical { background: #cf222e; color: #fff; }
  .sev-high     { background: #fb8500; color: #fff; }
  .sev-medium   { background: #d4a72c; color: #1f2329; }
  .sev-low      { background: #2da44e; color: #fff; }
  .sev-info     { background: #6e7781; color: #fff; }
  .sev-unknown  { background: #c1c4c8; color: #1f2329; }
  .sevgrid { display: flex; flex-wrap: wrap; gap: 0.6rem; margin: 0.6rem 0 1rem; }
  .sevcard { border: 1px solid #d0d7de; border-radius: 6px; background: #fff;
             padding: 0.5rem 0.9rem; min-width: 5.5rem; text-align: center; }
  .sevcard .n { font-size: 1.2rem; font-weight: 700; display: block; line-height: 1.4; }
  .sevcard .l { font-size: 0.78rem; color: #57606a; text-transform: uppercase; letter-spacing: 0.04em; }
  article.cluster { background: #fff; border: 1px solid #d0d7de; border-radius: 6px;
                    padding: 1rem 1.3rem; margin: 1rem 0; }
  article.cluster header { display: flex; gap: 1rem; flex-wrap: wrap; align-items: baseline;
                            margin-bottom: 0.5rem; color: #57606a; font-size: 0.9rem; }
  .narrative p { margin: 0 0 0.7rem; }
  ul.open-q li, ul.reco li { margin-bottom: 0.3rem; }
  dl.scope { display: grid; grid-template-columns: max-content 1fr; gap: 0.3rem 1rem; margin: 0.6rem 0; }
  dl.scope dt { font-weight: 600; color: #57606a; }
  dl.scope dd { margin: 0; }
  .note { background: #ddf4ff; border: 1px solid #54aeff; border-radius: 6px;
          padding: 0.6rem 0.9rem; margin: 0.6rem 0; font-size: 0.9rem; }
  .disclaimer { background: #fff8c5; border: 1px solid #d4a72c; border-radius: 6px;
                padding: 0.6rem 0.9rem; margin: 0.6rem 0; font-size: 0.9rem; }
  .active { background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 6px;
            padding: 0.5rem 0.8rem; margin: 0.5rem 0; font-size: 0.88rem; }
  .active .q { font-weight: 600; }
  .active pre { background: #0d111720; padding: 0.4rem 0.6rem; border-radius: 4px;
                overflow-x: auto; margin: 0.3rem 0; }
  .empty, .muted { color: #57606a; font-style: italic; }
  footer.audit { background: #fff; border: 1px solid #d0d7de; border-radius: 6px;
                 padding: 0.8rem 1rem; margin-top: 1rem;
                 display: grid; grid-template-columns: max-content 1fr; gap: 0.2rem 1rem;
                 font-size: 0.88rem; color: #57606a; }
  footer.audit dt { font-weight: 600; }
  footer.audit dd { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  @media (prefers-color-scheme: dark) {
    body { background: #0d1117; color: #c9d1d9; }
    h1, h2, h3, h4 { color: #f0f6fc; }
    header.meta, dl.info, table, article.cluster, footer.audit, .sevcard, .active { background: #161b22; border-color: #30363d; }
    th { background: #21262d; }
    th, td, tr:last-child td { border-color: #30363d; }
    h1 { border-bottom-color: #58a6ff; }
    h3 { border-left-color: #58a6ff; }
    .note { background: #0c2d4a; border-color: #1f6feb; }
    .disclaimer { background: #3a2d00; border-color: #9e6a03; }
  }
</style>
</head>
<body>

<div class="classbanner">{{.Classification}}</div>
<h1>{{.Dict.ReportTitle}}</h1>

<header class="meta">
  <dt>{{.Dict.Case}}</dt>          <dd>{{.Case.CaseID}}</dd>
  <dt>{{.Dict.Generated}}</dt>     <dd>{{.GeneratedAt}}</dd>
  <dt>{{.Dict.Examiner}}</dt>      <dd>{{.Examiner}}</dd>
  {{if .Organization}}<dt>{{.Dict.Organization}}</dt><dd>{{.Organization}}</dd>{{end}}
  <dt>{{.Dict.ToolVersion}}</dt>   <dd>{{.ToolVersion}}</dd>
  {{if .Case.ModelID}}<dt>{{.Dict.Model}}</dt><dd>{{.Case.ModelID}}</dd>{{end}}
</header>

<!-- 1. Case Information -->
<section>
  <h2>{{.Dict.CaseInformation}}</h2>
  <dl class="info">
    <dt>{{.Dict.Case}}</dt>            <dd>{{.Case.CaseID}}</dd>
    {{if .Meta}}{{if .Meta.DisplayName}}<dt>{{.Dict.DisplayName}}</dt><dd>{{.Meta.DisplayName}}</dd>{{end}}
    {{if .Meta.Status}}<dt>{{.Dict.Status}}</dt><dd>{{.Meta.Status}}</dd>{{end}}{{end}}
    <dt>{{.Dict.AnalysisDate}}</dt>    <dd>{{.GeneratedAt}}</dd>
    <dt>{{.Dict.TotalFindings}}</dt>   <dd>{{.Case.TotalFindings}}</dd>
    <dt>{{.Dict.ClusterCount}}</dt>    <dd>{{.Case.ClusterCount}}</dd>
    {{if .Meta}}{{if .Meta.Notes}}<dt>{{.Dict.Notes}}</dt><dd>{{.Meta.Notes}}</dd>{{end}}{{end}}
  </dl>
  <h3>{{.Dict.Scope}}</h3>
  <p>{{.Dict.ScopeBody}}</p>
</section>

{{if .Case.OverallStory}}
<!-- Executive Summary -->
<section>
  <h2>{{.Dict.ExecutiveSummary}}</h2>
  <div class="narrative">
    {{range para .Case.OverallStory}}<p>{{.}}</p>{{end}}
  </div>
</section>
{{end}}

{{if .Severity}}
<section>
  <h3>{{.Dict.SeveritySummary}}</h3>
  <div class="sevgrid">
    {{range .Severity}}
    <div class="sevcard">
      <span class="n">{{.Count}}</span>
      <span class="l"><span class="badge {{sevClass .Severity}}">{{sevLabel .Severity}}</span></span>
    </div>
    {{end}}
  </div>
</section>
{{end}}

<!-- 2. Intrusion Path -->
{{if .IntrusionPath}}
<section>
  <h2>{{.Dict.IntrusionPathSec}}</h2>
  <p>{{.IntrusionPath}}</p>
  <div class="note">{{.Dict.DerivedNote}}</div>
</section>
{{end}}

<!-- 3. Affected Scope -->
{{if .Scope}}
<section>
  <h2>{{.Dict.AffectedScopeSec}}</h2>
  <dl class="scope">
    <dt>{{.Dict.ScopeHosts}}</dt>
    <dd>{{if .Scope.Hosts}}{{join .Scope.Hosts}}{{else}}<span class="muted">—</span>{{end}}</dd>
    <dt>{{.Dict.ScopeAccounts}}</dt>
    <dd>{{if .Scope.Accounts}}{{join .Scope.Accounts}}{{else}}<span class="muted">—</span>{{end}}</dd>
    <dt>{{.Dict.ScopeData}}</dt>
    <dd>{{if .Scope.DataAtRisk}}{{join .Scope.DataAtRisk}}{{else}}<span class="muted">—</span>{{end}}</dd>
  </dl>
  <div class="note">{{.Dict.DerivedNote}}</div>
</section>
{{end}}

<!-- 4. Evidence & Chain of Custody -->
{{if .Meta}}
<section>
  <h2>{{.Dict.EvidenceChain}}</h2>
  {{if .Meta.Evidence}}
  <table>
    <thead>
      <tr><th>{{.Dict.EvidenceID}}</th><th>{{.Dict.SourcePath}}</th><th>{{.Dict.SHA256}}</th>
          <th>{{.Dict.Size}}</th><th>{{.Dict.CollectedAt}}</th><th>{{.Dict.EvidenceTypeCol}}</th><th>{{.Dict.Host}}</th></tr>
    </thead>
    <tbody>
      {{range .Meta.Evidence}}
      <tr>
        <td>{{.EvidenceID}}</td>
        <td class="mono">{{.SourcePath}}</td>
        <td><code>{{if .SHA256}}{{.SHA256}}{{else}}—{{end}}</code></td>
        <td>{{humanBytes .SizeBytes}}</td>
        <td>{{if .RegisteredAt.IsZero}}—{{else}}{{fmtTS .RegisteredAt}}{{end}}</td>
        <td>{{if .EvidenceType}}{{.EvidenceType}}{{else}}—{{end}}</td>
        <td>{{if .SourceHost}}{{.SourceHost}}{{else}}—{{end}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  <div class="note">{{.Dict.IntegrityNote}}</div>
  {{else}}<p class="empty">{{.Dict.None}}</p>{{end}}

  {{if .Meta.ArtifactCounts}}
  <h3>{{.Dict.ArtifactCoverage}}</h3>
  <table>
    <thead><tr><th>{{.Dict.ArtifactName}}</th><th>{{.Dict.EventCount}}</th></tr></thead>
    <tbody>
      {{range .Meta.ArtifactCounts}}<tr><td>{{.ArtifactID}}</td><td>{{.EventCount}}</td></tr>{{end}}
      <tr><th>{{.Dict.TotalEvents}}</th><th>{{.Meta.TotalEvents}}</th></tr>
    </tbody>
  </table>
  {{end}}
</section>
{{end}}

<!-- 5. Methodology & Limitations -->
<section>
  <h2>{{.Dict.Methodology}}</h2>
  <p>{{.Dict.MethodologyBody}}</p>
  <p>{{.Dict.Limitations}}</p>
  <div class="disclaimer">{{.Dict.AIDisclaimer}}</div>
</section>

<!-- 6. Event Timeline -->
{{if .Timeline}}
<section>
  <h2>{{.Dict.TimelineSection}}</h2>
  <table>
    <thead>
      <tr><th>{{.Dict.TimeCol}}</th><th>{{.Dict.Severity}}</th><th>{{.Dict.ArtifactName}}</th>
          <th>{{.Dict.EventTypeCol}}</th><th>{{.Dict.Source}}</th><th>{{.Dict.Title}}</th></tr>
    </thead>
    <tbody>
      {{range .Timeline}}
      <tr>
        <td class="mono">{{fmtTS .TS}}</td>
        <td><span class="badge {{sevClass .Severity}}">{{sevLabel .Severity}}</span></td>
        <td>{{.Artifact}}</td>
        <td>{{.EventType}}</td>
        <td>{{.Source}}</td>
        <td>{{.Title}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
</section>
{{end}}

<!-- 7. Findings by cluster -->
<section>
  <h2>7. {{.Dict.Cluster}}</h2>
  {{if not .Clusters}}<p class="empty">{{.Dict.None}}</p>{{end}}
  {{range .Clusters}}
  <article class="cluster" id="cluster-{{.ID}}">
    <h3>#{{.ID}} — {{phaseLabel .AttackPhase}}</h3>
    <header>
      <span><strong>{{$.Dict.Window}}:</strong> {{fmtTS .StartTS}} ~ {{fmtTS .EndTS}}</span>
      <span>{{$.Dict.FindingCount}}: {{len .Findings}}</span>
      {{if .MITRETechniques}}<span>MITRE: {{join .MITRETechniques}}</span>{{end}}
    </header>

    {{if .Narrative}}
    <h4>{{$.Dict.Narrative}}</h4>
    <div class="narrative">
      {{range para .Narrative}}<p>{{.}}</p>{{end}}
    </div>
    {{end}}

    {{if .Findings}}
    <h4>{{$.Dict.Findings}}</h4>
    <table>
      <thead>
        <tr><th>{{$.Dict.Severity}}</th><th>{{$.Dict.Source}}</th><th>{{$.Dict.RuleID}}</th>
            <th>{{$.Dict.Title}}</th><th>{{$.Dict.FirstSeen}}</th>
            <th>{{$.Dict.Artifacts}}</th><th>{{$.Dict.EvidenceCountCol}}</th></tr>
      </thead>
      <tbody>
        {{range .Findings}}
        <tr>
          <td><span class="badge {{sevClass .Severity}}">{{sevLabel .Severity}}</span></td>
          <td>{{.Source}}</td>
          <td><code>{{.RuleID}}</code></td>
          <td>{{.Title}}</td>
          <td>{{if .HasTS}}{{fmtTS .FirstSeen}}{{else}}<span class="muted">—</span>{{end}}</td>
          <td>{{if .Artifacts}}{{join .Artifacts}}{{else}}<span class="muted">—</span>{{end}}</td>
          <td>{{if .EvidenceCount}}{{.EvidenceCount}}{{else}}<span class="muted">—</span>{{end}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
    {{end}}

    {{if .ActiveSearch}}
    <h4>{{$.Dict.ActiveSearch}}</h4>
    {{range .ActiveSearch}}
    <div class="active">
      <div class="q">{{.Question}}</div>
      {{if .SQL}}<pre><code>{{.SQL}}</code></pre>{{end}}
      <div><strong>{{$.Dict.HitsCol}}:</strong> {{.Hits}}</div>
      {{if .Answer}}<div><strong>{{$.Dict.AnswerCol}}:</strong> {{.Answer}}</div>{{end}}
      {{if .Error}}<div class="muted">{{.Error}}</div>{{end}}
    </div>
    {{end}}
    {{end}}

    {{if .OpenQuestions}}
    <h4>{{$.Dict.OpenQuestions}}</h4>
    <ul class="open-q">
      {{range .OpenQuestions}}<li>{{.}}</li>{{end}}
    </ul>
    {{end}}
  </article>
  {{end}}
</section>

{{if .Case.MITREMapping}}
<section>
  <h2>{{.Dict.MITREMapping}}</h2>
  <table>
    <thead>
      <tr><th>{{.Dict.Technique}}</th><th>{{.Dict.Tactic}}</th>
          <th>{{.Dict.FindingCount}}</th><th>{{.Dict.ClusterIDs}}</th></tr>
    </thead>
    <tbody>
      {{range .Case.MITREMapping}}
      <tr>
        <td><a href="https://attack.mitre.org/techniques/{{.Technique}}/" target="_blank" rel="noopener">{{.Technique}}</a></td>
        <td>{{.Tactic}}</td>
        <td>{{.FindingCount}}</td>
        <td>{{range $i, $cid := .ClusterIDs}}{{if $i}}, {{end}}#{{$cid}}{{end}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
</section>
{{end}}

<!-- 8. Indicators of Compromise -->
<section>
  <h2>{{.Dict.IOCSection}}</h2>
  {{if .IOCs}}
  <table>
    <thead><tr><th>{{.Dict.IOCType}}</th><th>{{.Dict.IOCValue}}</th><th>{{.Dict.ArtifactName}}</th><th>{{.Dict.IOCCount}}</th></tr></thead>
    <tbody>
      {{range .IOCs}}<tr><td>{{.Type}}</td><td class="mono">{{.Value}}</td><td>{{.Artifact}}</td><td>{{.Count}}</td></tr>{{end}}
    </tbody>
  </table>
  {{else}}<p class="empty">{{.Dict.NoIOC}}</p>{{end}}
</section>

<!-- 9. Recommendations -->
{{if .Reco}}
<section>
  <h2>{{.Dict.RecommendationsSec}}</h2>
  {{if .Reco.Containment}}
  <h3>{{.Dict.RecContainment}}</h3>
  <ul class="reco">{{range .Reco.Containment}}<li>{{.}}</li>{{end}}</ul>
  {{end}}
  {{if .Reco.Eradication}}
  <h3>{{.Dict.RecEradication}}</h3>
  <ul class="reco">{{range .Reco.Eradication}}<li>{{.}}</li>{{end}}</ul>
  {{end}}
  {{if .Reco.Recovery}}
  <h3>{{.Dict.RecRecovery}}</h3>
  <ul class="reco">{{range .Reco.Recovery}}<li>{{.}}</li>{{end}}</ul>
  {{end}}
  <div class="note">{{.Dict.DerivedNote}}</div>
</section>
{{end}}

{{if .Case.OpenQuestions}}
<!-- 10. Case-wide open questions -->
<section>
  <h2>{{.Dict.CaseOpenQuestions}}</h2>
  <ul class="open-q">
    {{range .Case.OpenQuestions}}<li>{{.}}</li>{{end}}
  </ul>
</section>
{{end}}

<footer class="audit">
  <dt>{{.Dict.LLMCalls}}</dt>       <dd>{{.Case.Audit.LLMCallsTotal}}</dd>
  <dt>{{.Dict.LLMDuration}}</dt>    <dd>{{printf "%.1f" .Case.Audit.LLMDurationS}}</dd>
  {{if gt .Case.Audit.InputTokensTotal 0}}
  <dt>{{.Dict.InputTokens}}</dt>    <dd>{{.Case.Audit.InputTokensTotal}}</dd>
  {{end}}
  {{if gt .Case.Audit.OutputTokensTotal 0}}
  <dt>{{.Dict.OutputTokens}}</dt>   <dd>{{.Case.Audit.OutputTokensTotal}}</dd>
  {{end}}
  {{if .Case.Audit.SkillSHA256}}
  <dt>{{.Dict.SkillSHA}}</dt>       <dd>{{truncate .Case.Audit.SkillSHA256 16}}...</dd>
  {{end}}
</footer>

</body>
</html>
`
