package reporter

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/agents"
	"github.com/tlvb/tlvb/internal/synthesizer"
)

// htmlSectionCount is exported via writeHTML's return so the CLI summary
// can show "11/11 sections rendered" — useful for catching template
// regressions early.
const htmlSectionCount = 11

// writeHTML renders a single self-contained .html file with embedded CSS.
// No JS, no external assets — the report is openable from a USB stick and
// printable as-is.
func writeHTML(cs *synthesizer.CaseSynthesis, cfg Config) (string, int, error) {
	d := dict(cfg.Language)
	iocs := ExtractIOCs(cs)

	view := htmlView{
		Dict:        d,
		Lang:        cfg.Language,
		Synthesis:   cs,
		IOCs:        iocs,
		GeneratedAt: time.Now().UTC(),
		FindingsByTacticOrdered: orderFindingsByTactic(cs),
		AllEvidence: collectAllEvidence(cs),
	}

	tmpl, err := template.New("report").Funcs(htmlFuncs).Parse(htmlTemplate)
	if err != nil {
		return "", 0, fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, view); err != nil {
		return "", 0, fmt.Errorf("render: %w", err)
	}

	out := filepath.Join(cfg.OutDir, "report.html")
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
		return "", 0, fmt.Errorf("write %q: %w", out, err)
	}
	return out, htmlSectionCount, nil
}

// htmlView is the data the template sees.
type htmlView struct {
	Dict                    map[string]string
	Lang                    string
	Synthesis               *synthesizer.CaseSynthesis
	IOCs                    []IOCExtraction
	GeneratedAt             time.Time
	FindingsByTacticOrdered []findingsByTacticEntry
	AllEvidence             []evidenceRow
}

type findingsByTacticEntry struct {
	TacticID   string
	TacticName string
	Findings   []agents.Finding
}

type evidenceRow struct {
	FindingID  string
	TacticID   string
	Evidence   agents.Evidence
}

// orderFindingsByTactic stabilises the §5 section: tactics in Kill Chain
// order, findings inside each block sorted by confidence (high first).
func orderFindingsByTactic(cs *synthesizer.CaseSynthesis) []findingsByTacticEntry {
	confRank := map[string]int{"high": 3, "medium": 2, "low": 1}

	// Kill Chain order — re-declared here to keep reporter independent of
	// synthesizer's package-private ordering. Keep in sync.
	order := []string{
		"TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004",
		"TA0005", "TA0006", "TA0007", "TA0008", "TA0009", "TA0011",
		"TA0010", "TA0040",
	}
	rank := map[string]int{}
	for i, t := range order {
		rank[t] = i
	}

	keys := make([]string, 0, len(cs.FindingsByTactic))
	for k := range cs.FindingsByTactic {
		keys = append(keys, k)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		ri, ok1 := rank[keys[i]]
		rj, ok2 := rank[keys[j]]
		if !ok1 {
			ri = 999
		}
		if !ok2 {
			rj = 999
		}
		if ri != rj {
			return ri < rj
		}
		return keys[i] < keys[j]
	})

	out := make([]findingsByTacticEntry, 0, len(keys))
	for _, k := range keys {
		flist := append([]agents.Finding(nil), cs.FindingsByTactic[k]...)
		sort.SliceStable(flist, func(i, j int) bool {
			return confRank[strings.ToLower(flist[i].Confidence)] >
				confRank[strings.ToLower(flist[j].Confidence)]
		})
		out = append(out, findingsByTacticEntry{
			TacticID:   k,
			TacticName: lookupTacticName(cs, k),
			Findings:   flist,
		})
	}
	return out
}

// collectAllEvidence is the data backing §11 Appendix. We duplicate
// per-finding evidence rows here so the appendix can be a flat reference
// table indexed by finding_id; the timeline section already shows the
// chronological view.
func collectAllEvidence(cs *synthesizer.CaseSynthesis) []evidenceRow {
	var out []evidenceRow
	for tid, list := range cs.FindingsByTactic {
		for _, f := range list {
			for _, ev := range f.Evidence {
				out = append(out, evidenceRow{
					FindingID: f.FindingID,
					TacticID:  tid,
					Evidence:  ev,
				})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].FindingID != out[j].FindingID {
			return out[i].FindingID < out[j].FindingID
		}
		return out[i].Evidence.AuditID < out[j].Evidence.AuditID
	})
	return out
}

// htmlFuncs — small helpers used inside the template. Kept here, not in
// renderer.go, because they're only meaningful in the HTML context.
var htmlFuncs = template.FuncMap{
	"fmtTime": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format("2006-01-02 15:04:05 UTC")
	},
	"fmtTimeShort": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format("01-02 15:04:05")
	},
	"fmtSeconds": func(s float64) string {
		return fmt.Sprintf("%.2fs", s)
	},
	"fmtInt": func(n int) string {
		return fmt.Sprintf("%d", n)
	},
	"truncate": func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		return s[:n] + "…"
	},
	"join": func(sep string, list []string) string {
		return strings.Join(list, sep)
	},
	"lower":   strings.ToLower,
	"toJSON":  toJSONForTemplate,
	"hasItem": func(list []agents.Finding) bool { return len(list) > 0 },
}

func toJSONForTemplate(v any) string {
	b, err := bytesToString(v)
	if err != nil {
		return ""
	}
	return b
}

func bytesToString(v any) (string, error) {
	type marshaler interface{ MarshalJSON() ([]byte, error) }
	if m, ok := v.(marshaler); ok {
		b, err := m.MarshalJSON()
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	return fmt.Sprintf("%v", v), nil
}

// htmlTemplate — embedded text/template; html/template auto-escapes content.
//
// CSS lives inline in <style>. No external dependencies. Light + print
// rules; dark mode left to follow-up because monitor-print parity matters
// more for examiner reports than aesthetics.
const htmlTemplate = `<!DOCTYPE html>
<html lang="{{.Lang}}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{index .Dict "report_title"}} — {{.Synthesis.CaseID}}</title>
<style>
:root {
  --bg: #fdfdfa;
  --fg: #1f2933;
  --muted: #6b7280;
  --border: #d6d3c5;
  --accent: #1e40af;
  --accent-soft: #e0e7ff;
  --warn-bg: #fff4e5;
  --warn-fg: #92400e;
  --info-bg: #eff6ff;
  --info-fg: #1e40af;
  --high-bg: #fee2e2;
  --high-fg: #991b1b;
  --med-bg: #fef3c7;
  --med-fg: #92400e;
  --low-bg: #ecfdf5;
  --low-fg: #065f46;
  --code-bg: #f3f4ec;
}
* { box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Hiragino Sans", "Yu Gothic UI",
    "Meiryo", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  line-height: 1.5;
}
.container {
  max-width: 1100px;
  margin: 0 auto;
  padding: 32px 28px;
}
h1 {
  margin: 0 0 6px 0;
  font-size: 28px;
  letter-spacing: -0.01em;
}
h2 {
  margin: 36px 0 12px 0;
  font-size: 21px;
  border-bottom: 2px solid var(--border);
  padding-bottom: 6px;
}
h3 { margin: 22px 0 8px 0; font-size: 16px; }
p, li { font-size: 14px; }
.meta {
  color: var(--muted);
  font-size: 13px;
  margin-bottom: 24px;
}
.meta strong { color: var(--fg); }
nav.toc {
  background: var(--accent-soft);
  border-left: 4px solid var(--accent);
  padding: 12px 16px;
  margin-bottom: 28px;
  font-size: 13px;
}
nav.toc ol { margin: 0; padding-left: 24px; }
nav.toc a { color: var(--accent); text-decoration: none; }
nav.toc a:hover { text-decoration: underline; }
table {
  width: 100%;
  border-collapse: collapse;
  margin: 12px 0;
  font-size: 13px;
}
th, td {
  padding: 7px 10px;
  border: 1px solid var(--border);
  text-align: left;
  vertical-align: top;
}
th {
  background: var(--code-bg);
  font-weight: 600;
}
td.mono, code {
  font-family: ui-monospace, SFMono-Regular, "Menlo", "Consolas", monospace;
  font-size: 12px;
  word-break: break-all;
}
.badge {
  display: inline-block;
  padding: 1px 8px;
  border-radius: 3px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.02em;
  text-transform: uppercase;
}
.badge-high   { background: var(--high-bg); color: var(--high-fg); }
.badge-medium { background: var(--med-bg);  color: var(--med-fg); }
.badge-low    { background: var(--low-bg);  color: var(--low-fg); }
.badge-warn   { background: var(--warn-bg); color: var(--warn-fg); }
.badge-info   { background: var(--info-bg); color: var(--info-fg); }
.kill-chain {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  margin: 8px 0 18px;
}
.kill-chain .step {
  border: 1px solid var(--accent);
  border-radius: 4px;
  padding: 6px 10px;
  background: var(--accent-soft);
  font-size: 12px;
}
.kill-chain .step .num { font-weight: 700; color: var(--accent); }
.kill-chain .arrow { align-self: center; color: var(--muted); }
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 8px;
  margin: 12px 0 20px 0;
}
.summary-grid .item {
  background: var(--code-bg);
  padding: 8px 12px;
  border-radius: 4px;
}
.summary-grid .item .label {
  font-size: 11px;
  color: var(--muted);
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.summary-grid .item .value {
  font-size: 18px;
  font-weight: 700;
}
.empty {
  color: var(--muted);
  font-style: italic;
  padding: 8px 0;
}
ul.recs { padding-left: 22px; }
ul.recs li { margin: 4px 0; }
details {
  border: 1px solid var(--border);
  border-radius: 4px;
  margin: 6px 0;
  background: var(--bg);
}
summary {
  padding: 6px 10px;
  cursor: pointer;
  font-size: 13px;
  font-weight: 600;
}
details > div { padding: 0 12px 10px 12px; font-size: 13px; }
.finding {
  border: 1px solid var(--border);
  border-left-width: 4px;
  padding: 10px 14px;
  margin: 8px 0;
  background: #fff;
  border-radius: 4px;
}
.finding.high { border-left-color: var(--high-fg); }
.finding.medium { border-left-color: var(--med-fg); }
.finding.low { border-left-color: var(--low-fg); }
.finding h4 {
  margin: 0 0 4px 0;
  font-size: 14px;
}
.finding .meta-line {
  font-size: 12px;
  color: var(--muted);
  margin-bottom: 6px;
}
.finding p { margin: 4px 0; }
footer {
  margin-top: 48px;
  padding-top: 16px;
  border-top: 1px solid var(--border);
  font-size: 11px;
  color: var(--muted);
}
@media print {
  body { background: white; }
  nav.toc { background: white; }
  table, .finding, .kill-chain .step { break-inside: avoid; }
  details { border: none; }
  details[open] summary { display: none; }
  details[open] > div { padding: 0; }
}
</style>
</head>
<body>
<div class="container">

<h1>{{index .Dict "report_title"}}</h1>
<p class="meta">
  <strong>{{index .Dict "case"}}:</strong> {{.Synthesis.CaseID}}
  &nbsp;·&nbsp;
  <strong>{{index .Dict "evidence"}}:</strong> {{.Synthesis.EvidenceID}}
  &nbsp;·&nbsp;
  <strong>{{index .Dict "timezone"}}:</strong> {{.Synthesis.Timezone}}
  &nbsp;·&nbsp;
  <strong>{{index .Dict "generated"}}:</strong> {{fmtTime .GeneratedAt}}
</p>

<nav class="toc">
  <strong>{{index .Dict "toc"}}</strong>
  <ol>
    <li><a href="#sec1">{{index .Dict "sec1_executive"}}</a></li>
    <li><a href="#sec2">{{index .Dict "sec2_scope"}}</a></li>
    <li><a href="#sec3">{{index .Dict "sec3_intrusion_path"}}</a></li>
    <li><a href="#sec4">{{index .Dict "sec4_timeline"}}</a></li>
    <li><a href="#sec5">{{index .Dict "sec5_findings"}}</a></li>
    <li><a href="#sec6">{{index .Dict "sec6_inconsistencies"}}</a></li>
    <li><a href="#sec7">{{index .Dict "sec7_recommendations"}}</a></li>
    <li><a href="#sec8">{{index .Dict "sec8_iocs"}}</a></li>
    <li><a href="#sec9">{{index .Dict "sec9_mitre"}}</a></li>
    <li><a href="#sec10">{{index .Dict "sec10_audit"}}</a></li>
    <li><a href="#sec11">{{index .Dict "sec11_appendix"}}</a></li>
  </ol>
</nav>

<!-- §1 Executive Summary -->
<h2 id="sec1">{{index .Dict "sec1_executive"}}</h2>
<p>{{.Synthesis.ExecutiveSummary}}</p>
<div class="summary-grid">
  <div class="item"><div class="label">{{index .Dict "reports_aggregated"}}</div>
    <div class="value">{{.Synthesis.Audit.ReportsAggregated}}</div></div>
  <div class="item"><div class="label">{{index .Dict "total_findings"}}</div>
    <div class="value">{{.Synthesis.Stats.TotalFindings}}</div></div>
  <div class="item"><div class="label">{{index .Dict "clusters"}}</div>
    <div class="value">{{.Synthesis.Stats.ClusterCount}}</div></div>
  <div class="item"><div class="label">{{index .Dict "merged"}}</div>
    <div class="value">{{.Synthesis.Stats.MergedFindings}}</div></div>
  <div class="item"><div class="label">{{index .Dict "unique_evidence"}}</div>
    <div class="value">{{.Synthesis.Stats.UniqueEvidenceIDs}}</div></div>
  <div class="item"><div class="label">{{index .Dict "timeline_rows"}}</div>
    <div class="value">{{len .Synthesis.Timeline}}</div></div>
</div>

<!-- §2 Affected Scope -->
<h2 id="sec2">{{index .Dict "sec2_scope"}}</h2>
<table>
  <tr><th style="width:30%">{{index .Dict "compromised_hosts"}}</th>
      <td>{{if .Synthesis.AffectedScope.CompromisedHosts}}{{join ", " .Synthesis.AffectedScope.CompromisedHosts}}{{else}}<span class="empty">{{index .Dict "none"}}</span>{{end}}</td></tr>
  <tr><th>{{index .Dict "compromised_accounts"}}</th>
      <td>{{if .Synthesis.AffectedScope.CompromisedAccounts}}{{join ", " .Synthesis.AffectedScope.CompromisedAccounts}}{{else}}<span class="empty">{{index .Dict "none"}}</span>{{end}}</td></tr>
  <tr><th>{{index .Dict "data_at_risk"}}</th>
      <td>{{if .Synthesis.AffectedScope.DataAtRisk}}{{join ", " .Synthesis.AffectedScope.DataAtRisk}}{{else}}<span class="empty">{{index .Dict "none"}}</span>{{end}}</td></tr>
</table>

<!-- §3 Intrusion Path -->
<h2 id="sec3">{{index .Dict "sec3_intrusion_path"}}</h2>
{{if .Synthesis.IntrusionPath}}
<div class="kill-chain">
  {{range $i, $s := .Synthesis.IntrusionPath}}
    {{if $i}}<span class="arrow">→</span>{{end}}
    <div class="step">
      <span class="num">{{$s.Step}}.</span>
      <strong>{{$s.Tactic}}</strong> {{$s.TacticName}}<br>
      <code>{{$s.Technique}}</code>
      <div style="font-size:11px;color:var(--muted)">{{fmtTime $s.Timestamp}}</div>
    </div>
  {{end}}
</div>
<table>
  <tr><th>{{index .Dict "step"}}</th><th>{{index .Dict "tactic"}}</th>
      <th>{{index .Dict "technique"}}</th><th>{{index .Dict "timestamp"}}</th>
      <th>{{index .Dict "description"}}</th></tr>
  {{range .Synthesis.IntrusionPath}}
  <tr><td>{{.Step}}</td>
      <td>{{.Tactic}} <small>{{.TacticName}}</small></td>
      <td><code>{{.Technique}}</code></td>
      <td class="mono">{{fmtTime .Timestamp}}</td>
      <td>{{.Description}}</td></tr>
  {{end}}
</table>
{{else}}
<p class="empty">{{index .Dict "intrusion_path_empty"}}</p>
{{end}}

<!-- §4 Timeline -->
<h2 id="sec4">{{index .Dict "sec4_timeline"}}</h2>
{{if .Synthesis.Timeline}}
<table>
  <tr>
    <th style="width:155px">{{index .Dict "timestamp"}}</th>
    <th>{{index .Dict "tactic"}}</th>
    <th>{{index .Dict "technique"}}</th>
    <th>{{index .Dict "artifact"}}</th>
    <th>{{index .Dict "computer"}}</th>
    <th>{{index .Dict "summary"}}</th>
    <th>{{index .Dict "confidence"}}</th>
  </tr>
  {{range .Synthesis.Timeline}}
  <tr>
    <td class="mono">{{fmtTime .Timestamp}}</td>
    <td>{{.Tactic}}</td>
    <td><code>{{.Technique}}</code></td>
    <td>{{.ArtifactID}}</td>
    <td class="mono">{{.Computer}}</td>
    <td>{{.Summary}}</td>
    <td>{{if .Confidence}}<span class="badge badge-{{lower .Confidence}}">{{.Confidence}}</span>{{end}}</td>
  </tr>
  {{end}}
</table>
{{else}}
<p class="empty">{{index .Dict "timeline_empty"}}</p>
{{end}}

<!-- §5 Findings by Tactic -->
<h2 id="sec5">{{index .Dict "sec5_findings"}}</h2>
{{range .FindingsByTacticOrdered}}
<h3>{{.TacticID}} {{.TacticName}} <small style="color:var(--muted)">({{len .Findings}})</small></h3>
{{range .Findings}}
<div class="finding {{lower .Confidence}}">
  <h4><code>{{.FindingID}}</code> · <code>{{.TechniqueID}}</code> {{.TechniqueName}}
    <span class="badge badge-{{lower .Confidence}}">{{.Confidence}}</span></h4>
  <div class="meta-line">{{len .Evidence}} {{index $.Dict "evidence_rows_n"}}</div>
  <p><strong>{{index $.Dict "summary"}}:</strong> {{.Summary}}</p>
  <p><strong>{{index $.Dict "reasoning"}}:</strong> {{.Reasoning}}</p>
  <details>
    <summary>{{index $.Dict "evidence"}} ({{len .Evidence}})</summary>
    <div>
      <table>
        <tr><th>{{index $.Dict "audit_id"}}</th>
            <th>{{index $.Dict "artifact"}}</th>
            <th>{{index $.Dict "excerpt"}}</th></tr>
        {{range .Evidence}}
        <tr><td class="mono">{{.AuditID}}</td>
            <td>{{.SourceArtifact}}</td>
            <td>{{.Excerpt}}</td></tr>
        {{end}}
      </table>
    </div>
  </details>
</div>
{{end}}
{{end}}

<!-- §6 Inconsistencies & Open Questions -->
<h2 id="sec6">{{index .Dict "sec6_inconsistencies"}}</h2>
{{if .Synthesis.Inconsistencies}}
<table>
  <tr><th>{{index .Dict "rule"}}</th>
      <th>{{index .Dict "severity"}}</th>
      <th>{{index .Dict "description"}}</th>
      <th>{{index .Dict "resolved"}}</th></tr>
  {{range .Synthesis.Inconsistencies}}
  <tr>
    <td><strong>{{.Rule}}</strong></td>
    <td><span class="badge badge-{{.Severity}}">{{.Severity}}</span></td>
    <td>{{.Description}}{{if .Resolution}}<br><em>→ {{.Resolution}}</em>{{end}}</td>
    <td>{{if .Resolved}}{{index $.Dict "yes"}}{{else}}{{index $.Dict "no"}}{{end}}</td>
  </tr>
  {{end}}
</table>
{{else}}
<p class="empty">{{index .Dict "inconsistencies_empty"}}</p>
{{end}}

{{if .Synthesis.UnresolvedRefs}}
<h3>{{index .Dict "unresolved_refs"}}</h3>
<table>
  <tr><th>{{index .Dict "audit_id"}}</th></tr>
  {{range .Synthesis.UnresolvedRefs}}
  <tr><td class="mono">{{.}}</td></tr>
  {{end}}
</table>
{{end}}

<!-- §7 Recommendations -->
<h2 id="sec7">{{index .Dict "sec7_recommendations"}}</h2>
{{if or .Synthesis.Recommendations.Containment .Synthesis.Recommendations.Eradication .Synthesis.Recommendations.Recovery .Synthesis.Recommendations.NextSteps}}
<h3>{{index .Dict "containment"}}</h3>
{{if .Synthesis.Recommendations.Containment}}
<ul class="recs">{{range .Synthesis.Recommendations.Containment}}<li>{{.}}</li>{{end}}</ul>
{{else}}<p class="empty">{{index .Dict "none"}}</p>{{end}}

<h3>{{index .Dict "eradication"}}</h3>
{{if .Synthesis.Recommendations.Eradication}}
<ul class="recs">{{range .Synthesis.Recommendations.Eradication}}<li>{{.}}</li>{{end}}</ul>
{{else}}<p class="empty">{{index .Dict "none"}}</p>{{end}}

<h3>{{index .Dict "recovery"}}</h3>
{{if .Synthesis.Recommendations.Recovery}}
<ul class="recs">{{range .Synthesis.Recommendations.Recovery}}<li>{{.}}</li>{{end}}</ul>
{{else}}<p class="empty">{{index .Dict "none"}}</p>{{end}}

<!-- ★v0.3 #10 — Next steps (couldn't-investigate gaps) -->
<h3>{{index .Dict "next_steps"}}</h3>
{{if .Synthesis.Recommendations.NextSteps}}
<ul class="recs next-steps">{{range .Synthesis.Recommendations.NextSteps}}<li>{{.}}</li>{{end}}</ul>
{{else}}<p class="empty">{{index .Dict "next_steps_empty"}}</p>{{end}}
{{else}}
<p class="empty">{{index .Dict "recommendations_empty"}}</p>
{{end}}

<!-- §8 IOC Summary -->
<h2 id="sec8">{{index .Dict "sec8_iocs"}}</h2>
{{if .IOCs}}
<table>
  <tr>
    <th>{{index .Dict "ioc_type"}}</th>
    <th>{{index .Dict "ioc_value"}}</th>
    <th>{{index .Dict "ioc_count"}}</th>
    <th>{{index .Dict "ioc_sources"}}</th>
  </tr>
  {{range .IOCs}}
  <tr>
    <td><code>{{.Type}}</code></td>
    <td class="mono">{{.Value}}</td>
    <td>{{len .Findings}}</td>
    <td class="mono">{{range $i, $k := .Findings}}{{if $i}}, {{end}}{{$k}}{{end}}</td>
  </tr>
  {{end}}
</table>
{{else}}
<p class="empty">{{index .Dict "iocs_empty"}}</p>
{{end}}

<!-- §9 MITRE ATT&CK Mapping -->
<h2 id="sec9">{{index .Dict "sec9_mitre"}}</h2>
{{if .Synthesis.MITREMapping}}
<table>
  <tr>
    <th>{{index .Dict "tactic"}}</th>
    <th>{{index .Dict "technique"}}</th>
    <th>{{index .Dict "evidence_count"}}</th>
    <th>{{index .Dict "findings_col"}}</th>
    <th>{{index .Dict "confidence"}}</th>
  </tr>
  {{range .Synthesis.MITREMapping}}
  <tr>
    <td><strong>{{.Tactic}}</strong> {{.TacticName}}</td>
    <td><code>{{.Technique}}</code> {{.TechniqueName}}</td>
    <td>{{.EvidenceCount}}</td>
    <td>{{.FindingCount}}</td>
    <td>{{if .Confidence}}<span class="badge badge-{{lower .Confidence}}">{{.Confidence}}</span>{{end}}</td>
  </tr>
  {{end}}
</table>
{{else}}
<p class="empty">{{index .Dict "none"}}</p>
{{end}}

<!-- §10 Audit Trail -->
<h2 id="sec10">{{index .Dict "sec10_audit"}}</h2>
<table>
  <tr><th>{{index .Dict "total_tokens"}}</th>
      <td>{{.Synthesis.Audit.TotalTokens}}</td></tr>
  <tr><th>{{index .Dict "total_iterations"}}</th>
      <td>{{.Synthesis.Audit.TotalIterations}}</td></tr>
  <tr><th>{{index .Dict "correction_rounds"}}</th>
      <td>{{.Synthesis.Audit.CorrectionRounds}}</td></tr>
  <tr><th>{{index .Dict "exec_seconds"}}</th>
      <td>{{fmtSeconds .Synthesis.Audit.ExecutionTimeSeconds}}</td></tr>
  <tr><th>{{index .Dict "reports_aggregated"}}</th>
      <td>{{.Synthesis.Audit.ReportsAggregated}}</td></tr>
  <tr><th>{{index .Dict "unresolved_count"}}</th>
      <td>{{.Synthesis.Audit.UnresolvedRefCount}}</td></tr>
  <tr><th>{{index .Dict "synthesizer_version"}}</th>
      <td><code>{{.Synthesis.Audit.SynthesizerVersion}}</code></td></tr>
</table>

<!-- §10b Failed Artifacts (Issue #26) -->
<h2>{{index .Dict "failed_artifacts"}}</h2>
{{if .Synthesis.FailedArtifacts}}
<table>
  <tr>
    <th>{{index .Dict "artifact"}}</th>
    <th>{{index .Dict "failed_stage"}}</th>
    <th>exit_code</th>
    <th>{{index .Dict "failed_reason"}}</th>
  </tr>
  {{range .Synthesis.FailedArtifacts}}
  <tr>
    <td><code>{{.ArtifactID}}</code></td>
    <td>{{.Stage}}</td>
    <td class="mono">{{if .ExitCode}}{{.ExitCode}}{{else}}—{{end}}</td>
    <td>{{.Reason}}</td>
  </tr>
  {{end}}
</table>
{{else}}
<p class="empty">{{index .Dict "failed_artifacts_empty"}}</p>
{{end}}

<!-- §11 Appendix: Evidence -->
<h2 id="sec11">{{index .Dict "sec11_appendix"}}</h2>
{{if .AllEvidence}}
<table>
  <tr><th>{{index .Dict "finding_id"}}</th>
      <th>{{index .Dict "tactic"}}</th>
      <th>{{index .Dict "audit_id"}}</th>
      <th>{{index .Dict "artifact"}}</th>
      <th>{{index .Dict "excerpt"}}</th></tr>
  {{range .AllEvidence}}
  <tr>
    <td><code>{{.FindingID}}</code></td>
    <td>{{.TacticID}}</td>
    <td class="mono">{{.Evidence.AuditID}}</td>
    <td>{{.Evidence.SourceArtifact}}</td>
    <td>{{.Evidence.Excerpt}}</td>
  </tr>
  {{end}}
</table>
{{else}}
<p class="empty">{{index .Dict "none"}}</p>
{{end}}

<footer>{{index .Dict "footer"}}</footer>

</div>
</body>
</html>
`
