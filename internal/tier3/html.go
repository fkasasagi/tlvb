package tier3

import (
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/tier2"
)

// renderHTML writes a single self-contained HTML report.
//
// Schema:
//   - Header (case_id, generated_at, model, totals)
//   - Executive Summary (overall_story)
//   - MITRE ATT&CK Mapping (table)
//   - Cluster Sections (per-cluster narrative + finding refs + open questions)
//   - Audit footer
//
// All CSS is inline; no JS, no external assets — the file is fully
// portable (zip + send by email works).
func renderHTML(path string, cs tier2.CaseSynthesis, lang string) error {
	d := selectDict(lang)
	data := htmlData{
		Case:        cs,
		Dict:        d,
		Lang:        lang,
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
	}
	tpl, err := template.New("report").Funcs(template.FuncMap{
		"fmtTS":      formatTS,
		"join":       func(s []string) string { return strings.Join(s, ", ") },
		"sevClass":   severityClass,
		"para":       splitParagraphs,
		"truncate":   truncateForTooltip,
		"phaseLabel": d.phaseLabel,
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return tpl.Execute(f, data)
}

type htmlData struct {
	Case        tier2.CaseSynthesis
	Dict        labelDict
	Lang        string
	GeneratedAt string
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

	phaseLabel func(string) string
}

var dictJA = labelDict{
	ReportTitle:      "TLVB 解析レポート",
	Case:             "ケース",
	Generated:        "生成日時",
	Model:            "モデル",
	TotalFindings:    "Finding 総数",
	ClusterCount:     "クラスタ数",
	ExecutiveSummary: "全体ストーリー",
	MITREMapping:     "MITRE ATT&CK マッピング",
	Technique:        "Technique",
	Tactic:           "Tactic",
	FindingCount:     "件数",
	ClusterIDs:       "クラスタ ID",
	Cluster:          "クラスタ",
	Window:           "時刻範囲",
	AttackPhase:      "攻撃フェーズ",
	Narrative:        "シナリオ",
	Findings:         "Finding 一覧",
	Source:           "ソース",
	RuleID:           "ルール ID",
	Title:            "タイトル",
	Severity:         "重要度",
	OpenQuestions:    "未解決の論点",
	Audit:            "監査情報",
	LLMCalls:         "LLM 呼び出し回数",
	LLMDuration:      "LLM 累計時間 (秒)",
	InputTokens:      "Input tokens",
	OutputTokens:     "Output tokens",
	SkillSHA:         "Skill SHA-256",
	phaseLabel:       phaseLabelJA,
}

var dictEN = labelDict{
	ReportTitle:      "TLVB Analysis Report",
	Case:             "Case",
	Generated:        "Generated",
	Model:            "Model",
	TotalFindings:    "Total findings",
	ClusterCount:     "Cluster count",
	ExecutiveSummary: "Executive Summary",
	MITREMapping:     "MITRE ATT&CK Mapping",
	Technique:        "Technique",
	Tactic:           "Tactic",
	FindingCount:     "Count",
	ClusterIDs:       "Cluster IDs",
	Cluster:          "Cluster",
	Window:           "Window",
	AttackPhase:      "Attack phase",
	Narrative:        "Narrative",
	Findings:         "Findings",
	Source:           "Source",
	RuleID:           "Rule ID",
	Title:            "Title",
	Severity:         "Severity",
	OpenQuestions:    "Open questions",
	Audit:            "Audit",
	LLMCalls:         "LLM calls",
	LLMDuration:      "LLM duration (s)",
	InputTokens:      "Input tokens",
	OutputTokens:     "Output tokens",
	SkillSHA:         "Skill SHA-256",
	phaseLabel:       phaseLabelEN,
}

func selectDict(lang string) labelDict {
	if strings.ToLower(lang) == "en" {
		return dictEN
	}
	return dictJA
}

func phaseLabelJA(p string) string {
	m := map[string]string{
		"initial-access":      "初期侵入",
		"execution":           "実行",
		"persistence":         "永続化",
		"privilege-escalation": "権限昇格",
		"defense-evasion":     "防御回避",
		"credential-access":   "認証情報窃取",
		"discovery":           "ディスカバリ",
		"lateral-movement":    "横展開",
		"collection":          "収集",
		"command-and-control": "C2",
		"exfiltration":        "持ち出し",
		"impact":              "影響",
		"reconnaissance":      "偵察",
	}
	if v, ok := m[p]; ok {
		return v + " (" + p + ")"
	}
	return p
}

func phaseLabelEN(p string) string { return p }

// severityClass maps a finding's severity to a CSS class for the badge.
func severityClass(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "sev-critical"
	case "high":
		return "sev-high"
	case "medium":
		return "sev-medium"
	case "low":
		return "sev-low"
	case "informational", "info":
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
  h1 { border-bottom: 3px solid #0969da; padding-bottom: 0.4rem; }
  h2 { border-bottom: 1px solid #d0d7de; padding-bottom: 0.3rem; }
  h3 { border-left: 4px solid #0969da; padding-left: 0.6rem; }
  header.meta { background: #fff; border: 1px solid #d0d7de; border-radius: 6px;
                padding: 0.8rem 1rem; margin-bottom: 1.5rem;
                display: grid; grid-template-columns: max-content 1fr; gap: 0.3rem 1rem; }
  header.meta dt { font-weight: 600; color: #57606a; }
  header.meta dd { margin: 0; }
  table { border-collapse: collapse; width: 100%; margin: 0.5rem 0 1rem;
          background: #fff; border: 1px solid #d0d7de; border-radius: 4px; overflow: hidden; }
  th, td { border-bottom: 1px solid #d0d7de; padding: 0.45rem 0.7rem; text-align: left;
           vertical-align: top; font-size: 0.92rem; }
  th { background: #f6f8fa; font-weight: 600; }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-block; padding: 0.15rem 0.55rem; border-radius: 999px;
           font-size: 0.78rem; font-weight: 600; }
  .sev-critical { background: #cf222e; color: #fff; }
  .sev-high     { background: #fb8500; color: #fff; }
  .sev-medium   { background: #d4a72c; color: #1f2329; }
  .sev-low      { background: #2da44e; color: #fff; }
  .sev-info     { background: #6e7781; color: #fff; }
  .sev-unknown  { background: #c1c4c8; color: #1f2329; }
  article.cluster { background: #fff; border: 1px solid #d0d7de; border-radius: 6px;
                    padding: 1rem 1.3rem; margin: 1rem 0; }
  article.cluster header { display: flex; gap: 1rem; flex-wrap: wrap; align-items: baseline;
                            margin-bottom: 0.5rem; color: #57606a; font-size: 0.9rem; }
  .narrative p { margin: 0 0 0.7rem; }
  ul.open-q li { margin-bottom: 0.3rem; }
  footer.audit { background: #fff; border: 1px solid #d0d7de; border-radius: 6px;
                 padding: 0.8rem 1rem; margin-top: 2rem;
                 display: grid; grid-template-columns: max-content 1fr; gap: 0.2rem 1rem;
                 font-size: 0.88rem; color: #57606a; }
  footer.audit dt { font-weight: 600; }
  footer.audit dd { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .empty { color: #57606a; font-style: italic; }
  @media (prefers-color-scheme: dark) {
    body { background: #0d1117; color: #c9d1d9; }
    h1, h2, h3 { color: #f0f6fc; }
    header.meta, table, article.cluster, footer.audit { background: #161b22; border-color: #30363d; }
    th { background: #21262d; }
    th, td, tr:last-child td { border-color: #30363d; }
    h1 { border-bottom-color: #58a6ff; }
    h3 { border-left-color: #58a6ff; }
  }
</style>
</head>
<body>
<h1>{{.Dict.ReportTitle}}</h1>

<header class="meta">
  <dt>{{.Dict.Case}}</dt>             <dd>{{.Case.CaseID}}</dd>
  <dt>{{.Dict.Generated}}</dt>        <dd>{{.GeneratedAt}}</dd>
  {{if .Case.ModelID}}<dt>{{.Dict.Model}}</dt><dd>{{.Case.ModelID}}</dd>{{end}}
  <dt>{{.Dict.TotalFindings}}</dt>    <dd>{{.Case.TotalFindings}}</dd>
  <dt>{{.Dict.ClusterCount}}</dt>     <dd>{{.Case.ClusterCount}}</dd>
</header>

{{if .Case.OverallStory}}
<section>
  <h2>{{.Dict.ExecutiveSummary}}</h2>
  <div class="narrative">
    {{range para .Case.OverallStory}}<p>{{.}}</p>{{end}}
  </div>
</section>
{{end}}

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

<section>
  <h2>{{.Dict.Cluster}}</h2>
  {{range .Case.Clusters}}
  <article class="cluster" id="cluster-{{.ID}}">
    <h3>#{{.ID}} — {{phaseLabel .AttackPhase}}</h3>
    <header>
      <span><strong>{{$.Dict.Window}}:</strong> {{fmtTS .StartTS}} ~ {{fmtTS .EndTS}}</span>
      <span>{{$.Dict.FindingCount}}: {{len .FindingRefs}}</span>
      {{if .MITRETechniques}}<span>MITRE: {{join .MITRETechniques}}</span>{{end}}
    </header>

    {{if .Narrative}}
    <h4>{{$.Dict.Narrative}}</h4>
    <div class="narrative">
      {{range para .Narrative}}<p>{{.}}</p>{{end}}
    </div>
    {{end}}

    {{if .FindingRefs}}
    <h4>{{$.Dict.Findings}}</h4>
    <table>
      <thead>
        <tr><th>{{$.Dict.Severity}}</th><th>{{$.Dict.Source}}</th>
            <th>{{$.Dict.RuleID}}</th><th>{{$.Dict.Title}}</th></tr>
      </thead>
      <tbody>
        {{range .FindingRefs}}
        <tr>
          <td><span class="badge {{sevClass .Severity}}">{{.Severity}}</span></td>
          <td>{{.Source}}</td>
          <td><code>{{.RuleID}}</code></td>
          <td>{{.Title}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
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
