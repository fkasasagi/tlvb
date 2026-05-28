// Package reporter implements Tier 3 — DESIGN.md §7.
//
// Input: outputs/cases/<case_id>/synthesis.json
// Output: HTML, CSV (3 files), and pretty-printed JSON, written under
//         outputs/cases/<case_id>/reports/
//
// Why a separate package: the synthesizer's job ends when CaseSynthesis is
// persisted. Reporting is read-only over that snapshot, so this package
// has no DuckDB / no LLM / no MCP dependency — it's deterministic
// rendering you can run again at any time.
package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/synthesizer"
)

const reporterVersion = "reporter/0.1.0"

// Config controls one report generation run.
type Config struct {
	CaseID       string
	SynthesisPath string // absolute path to synthesis.json
	OutDir       string // output directory (default: outputs/cases/<case>/reports)
	Formats      []string // subset of {"html","csv","json"}; empty = all
	Language     string   // "ja" (default) | "en"

	// OnlyApproved drops findings whose Approved!=true. When false, all
	// findings (including unreviewed and rejected) are rendered. The
	// `tlvb run` pipeline sets this true automatically; manual
	// `tlvb report` keeps it false to preserve the DRAFT view.
	OnlyApproved bool
}

// Result lists what was actually written, plus per-format file sizes.
type Result struct {
	CaseID    string            `json:"case_id"`
	OutDir    string            `json:"out_dir"`
	Files     []OutputFile      `json:"files"`
	Sections  int               `json:"html_section_count"` // for caller-side reporting
	GeneratedAt time.Time       `json:"generated_at"`
}

type OutputFile struct {
	Format    string `json:"format"`     // "html" | "csv-findings" | "csv-timeline" | "csv-iocs" | "json"
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
}

// Render reads CaseSynthesis from disk and writes every requested format.
func Render(cfg Config) (*Result, error) {
	if cfg.CaseID == "" {
		return nil, fmt.Errorf("case_id is required")
	}
	if cfg.SynthesisPath == "" {
		return nil, fmt.Errorf("synthesis_path is required")
	}
	if cfg.Language == "" {
		cfg.Language = "ja"
	}
	if len(cfg.Formats) == 0 {
		cfg.Formats = []string{"html", "csv", "json"}
	}

	cs, err := loadSynthesis(cfg.SynthesisPath)
	if err != nil {
		return nil, err
	}
	if cs.CaseID != cfg.CaseID {
		return nil, fmt.Errorf(
			"synthesis case_id %q does not match requested %q",
			cs.CaseID, cfg.CaseID)
	}

	if cfg.OnlyApproved {
		filterToApproved(cs)
	}

	if cfg.OutDir == "" {
		cfg.OutDir = filepath.Join("outputs", "cases", cfg.CaseID, "reports")
	}
	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir reports: %w", err)
	}

	res := &Result{
		CaseID:      cfg.CaseID,
		OutDir:      cfg.OutDir,
		GeneratedAt: time.Now().UTC(),
	}

	want := map[string]bool{}
	for _, f := range cfg.Formats {
		want[strings.ToLower(strings.TrimSpace(f))] = true
	}

	if want["json"] {
		path, err := writeJSON(cs, cfg)
		if err != nil {
			return res, fmt.Errorf("json: %w", err)
		}
		res.Files = append(res.Files, statFile("json", path))
	}
	if want["csv"] {
		paths, err := writeCSVs(cs, cfg)
		if err != nil {
			return res, fmt.Errorf("csv: %w", err)
		}
		for k, p := range paths {
			res.Files = append(res.Files, statFile("csv-"+k, p))
		}
	}
	if want["html"] {
		path, sections, err := writeHTML(cs, cfg)
		if err != nil {
			return res, fmt.Errorf("html: %w", err)
		}
		res.Files = append(res.Files, statFile("html", path))
		res.Sections = sections
	}

	sort.SliceStable(res.Files, func(i, j int) bool {
		return res.Files[i].Format < res.Files[j].Format
	})
	return res, nil
}

// filterToApproved walks the CaseSynthesis and drops findings whose
// Approved field is false. We keep the originals immutable on disk —
// this in-memory filter only affects what the Reporter renders.
//
// Stats / mitre_mapping / clusters / timeline / IOCs are NOT recomputed
// here — those came from the Synthesizer's view of all findings. Caller
// must re-run synthesize after the review session if they want approved-
// only stats. Reporter at this layer just hides the rejected/unreviewed
// findings from the §5 "Findings by Tactic" section.
func filterToApproved(cs *synthesizer.CaseSynthesis) {
	for tid, list := range cs.FindingsByTactic {
		filtered := list[:0]
		for _, f := range list {
			if f.Approved {
				filtered = append(filtered, f)
			}
		}
		cs.FindingsByTactic[tid] = filtered
	}
}

func loadSynthesis(path string) (*synthesizer.CaseSynthesis, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read synthesis %q: %w", path, err)
	}
	var cs synthesizer.CaseSynthesis
	if err := json.Unmarshal(raw, &cs); err != nil {
		return nil, fmt.Errorf("parse synthesis %q: %w", path, err)
	}
	return &cs, nil
}

func statFile(format, path string) OutputFile {
	of := OutputFile{Format: format, Path: path}
	if fi, err := os.Stat(path); err == nil {
		of.SizeBytes = fi.Size()
	}
	return of
}

// ---- Localisation -----------------------------------------------------------
//
// A flat JP/EN dictionary keeps all examiner-facing labels in one place.
// HTML templates reference dict() entries, so adding English is a config
// switch later, not a template fork.

func dict(lang string) map[string]string {
	if lang == "en" {
		return dictEN
	}
	return dictJA
}

var dictJA = map[string]string{
	"report_title":         "TLVB インシデントレスポンス報告書",
	"sec1_executive":       "1. エグゼクティブサマリ",
	"sec2_scope":           "2. 影響範囲",
	"sec3_intrusion_path":  "3. 侵入経路 (Kill Chain)",
	"sec4_timeline":        "4. 攻撃タイムライン",
	"sec5_findings":        "5. Tactic 別 Finding 一覧",
	"sec6_inconsistencies": "6. 未解決事項・整合性チェック",
	"sec7_recommendations": "7. 推奨対応",
	"sec8_iocs":            "8. IOC サマリ",
	"sec9_mitre":           "9. MITRE ATT&CK マッピング",
	"sec10_audit":          "10. 監査トレイル",
	"sec11_appendix":       "11. 付録: Evidence 詳細",
	"toc":                  "目次",
	"case":                 "ケース",
	"evidence":             "証拠",
	"timezone":             "タイムゾーン",
	"generated":            "生成日時",
	"step":                 "ステップ",
	"tactic":               "Tactic",
	"technique":            "Technique",
	"timestamp":            "タイムスタンプ",
	"summary":              "概要",
	"confidence":           "信頼度",
	"evidence_count":       "証拠件数",
	"finding_id":           "Finding ID",
	"reasoning":            "判断根拠",
	"audit_id":             "Audit ID",
	"artifact":             "アーティファクト",
	"computer":             "ホスト",
	"rule":                 "ルール",
	"severity":             "重要度",
	"description":          "内容",
	"resolved":             "解消",
	"containment":          "封じ込め",
	"next_steps":           "Next Steps(できなかった調査)",
	"next_steps_empty":     "（追加調査の推奨はありません）",
	"eradication":          "根絶",
	"recovery":             "復旧",
	"compromised_hosts":    "侵害ホスト",
	"compromised_accounts": "侵害アカウント",
	"data_at_risk":         "リスクのあるデータ",
	"none":                 "（該当なし）",
	"yes":                  "はい",
	"no":                   "いいえ",
	"warning":              "警告",
	"info":                 "情報",
	"high":                 "高",
	"medium":               "中",
	"low":                  "低",
	"ioc_type":             "種別",
	"ioc_value":            "値",
	"ioc_count":            "件数",
	"ioc_sources":          "ソース Finding",
	"open_questions":       "未解決の問い",
	"negative_findings":    "ネガティブ調査結果",
	"footer":               "TLVB v0.1 — 本レポートは Tactic Agent 出力 + 決定論的 Synthesizer により生成。Tactic Report は DRAFT 段階の可能性があり、Examiner レビューを経て確定します。",
	"unresolved_refs":      "未解決の audit_id (Tactic Agent が架空 ID を返した可能性)",
	"intrusion_path_empty": "侵入経路は推定できません (関連 finding がありません)。",
	"timeline_empty":       "タイムライン項目はありません。",
	"recommendations_empty": "決定論的に生成可能な推奨は該当ありません。LLM 連携で詳細化されます。",
	"iocs_empty":           "Finding 内から抽出可能な IOC は検出されませんでした。",
	"inconsistencies_empty": "整合性チェックでヒットしたルールはありません。",
	"reports_aggregated":   "集約レポート数",
	"total_findings":       "Finding 総数",
	"clusters":             "クラスタ数",
	"merged":               "マージされた重複",
	"unique_evidence":      "ユニーク Evidence 数",
	"timeline_rows":        "タイムライン行数",
	"unresolved_count":     "未解決 audit_id 数",
	"total_tokens":         "総トークン",
	"total_iterations":     "総 iter 数",
	"correction_rounds":    "Corrector 周回数",
	"exec_seconds":         "実行秒数",
	"synthesizer_version":  "Synthesizer バージョン",
	// Issue #22: missing labels
	"excerpt":              "抜粋",
	"findings_col":         "Finding 件数",
	"evidence_rows_n":      "件の Evidence",
	"failed_artifacts":     "パース失敗アーティファクト",
	"failed_artifacts_empty": "全アーティファクトのパースに成功しました。",
	"failed_reason":        "理由",
	"failed_stage":         "段階",
}

var dictEN = map[string]string{
	"report_title":         "TLVB Incident Response Report",
	"sec1_executive":       "1. Executive Summary",
	"sec2_scope":           "2. Affected Scope",
	"sec3_intrusion_path":  "3. Intrusion Path (Kill Chain)",
	"sec4_timeline":        "4. Attack Timeline",
	"sec5_findings":        "5. Findings by Tactic",
	"sec6_inconsistencies": "6. Inconsistencies & Open Questions",
	"sec7_recommendations": "7. Recommendations",
	"sec8_iocs":            "8. IOC Summary",
	"sec9_mitre":           "9. MITRE ATT&CK Mapping",
	"sec10_audit":          "10. Audit Trail",
	"sec11_appendix":       "11. Appendix: Evidence Detail",
	"toc":                  "Contents",
	"case":                 "Case",
	"evidence":             "Evidence",
	"timezone":             "Timezone",
	"generated":            "Generated",
	"step":                 "Step",
	"tactic":               "Tactic",
	"technique":            "Technique",
	"timestamp":            "Timestamp",
	"summary":              "Summary",
	"confidence":           "Confidence",
	"evidence_count":       "Evidence Count",
	"finding_id":           "Finding ID",
	"reasoning":            "Reasoning",
	"audit_id":             "Audit ID",
	"artifact":             "Artifact",
	"computer":             "Host",
	"rule":                 "Rule",
	"severity":             "Severity",
	"description":          "Description",
	"resolved":             "Resolved",
	"containment":          "Containment",
	"next_steps":           "Next Steps (couldn't-investigate gaps)",
	"next_steps_empty":     "(no follow-up actions recommended)",
	"eradication":          "Eradication",
	"recovery":             "Recovery",
	"compromised_hosts":    "Compromised Hosts",
	"compromised_accounts": "Compromised Accounts",
	"data_at_risk":         "Data at Risk",
	"none":                 "(none)",
	"yes":                  "Yes",
	"no":                   "No",
	"warning":              "Warning",
	"info":                 "Info",
	"high":                 "High",
	"medium":               "Medium",
	"low":                  "Low",
	"ioc_type":             "Type",
	"ioc_value":            "Value",
	"ioc_count":            "Count",
	"ioc_sources":          "Source Findings",
	"open_questions":       "Open Questions",
	"negative_findings":    "Negative Findings",
	"footer":               "TLVB v0.1 — Generated from Tactic Agent output + deterministic Synthesizer. Tactic Reports may still be DRAFT; examiner approval required for finalisation.",
	"unresolved_refs":      "Unresolved audit_ids (possible LLM hallucinations)",
	"intrusion_path_empty": "Intrusion path could not be inferred (no associated findings).",
	"timeline_empty":       "Timeline is empty.",
	"recommendations_empty": "No deterministic recommendations apply. Will be enriched by LLM step.",
	"iocs_empty":           "No IOCs were extractable from findings.",
	"inconsistencies_empty": "No consistency rules fired.",
	"reports_aggregated":   "Reports aggregated",
	"total_findings":       "Total findings",
	"clusters":             "Clusters",
	"merged":               "Merged duplicates",
	"unique_evidence":      "Unique evidence",
	"timeline_rows":        "Timeline rows",
	"unresolved_count":     "Unresolved audit_ids",
	"total_tokens":         "Total tokens",
	"total_iterations":     "Total iterations",
	"correction_rounds":    "Correction rounds",
	"exec_seconds":         "Execution seconds",
	"synthesizer_version":  "Synthesizer version",
	// Issue #22 / #26: additional report labels
	"excerpt":              "Excerpt",
	"findings_col":         "Findings",
	"evidence_rows_n":      "evidence row(s)",
	"failed_artifacts":     "Failed Artifacts",
	"failed_artifacts_empty": "All targeted artifacts parsed successfully.",
	"failed_reason":        "Reason",
	"failed_stage":         "Stage",
}
