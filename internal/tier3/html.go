package tier3

import (
	"fmt"
	"html/template"
	"os"
	"sort"
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
// All CSS is inline; the only JS is a tiny inline severity-summary navigation
// helper (no external assets) — the file stays fully portable.
func renderHTML(path string, cs tier2.CaseSynthesis, cfg Config, en *enrichment, loc *time.Location) error {
	d := selectDict(cfg.Language)
	view := buildView(cs, cfg, en, d, loc)

	tpl, err := template.New("report").Funcs(template.FuncMap{
		"fmtTS":      func(t time.Time) string { return formatTSIn(t, loc) },
		"join":       func(s []string) string { return strings.Join(s, ", ") },
		"sevClass":   severityClass,
		"sevLabel":   d.sevLabel,
		"para":       splitParagraphs,
		"bullets":    splitBullets,
		"truncate":   truncateForTooltip,
		"phaseLabel": d.phaseLabel,
		"humanBytes": humanBytes,
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	// Render to a temp file and rename so a template error mid-execute can
	// never leave a truncated, unopenable report.html behind.
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := tpl.Execute(f, view); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// reportView is the full view model handed to the template.
type reportView struct {
	Case           tier2.CaseSynthesis
	Dict           labelDict
	Lang           string
	GeneratedAt    string
	Timezone       string
	Examiner       string
	Organization   string
	Classification string
	ToolVersion    string
	Meta           *CaseMeta
	Severity       []sevCount
	Timeline       []timelineRow

	// Executive summary, two layers. ExecBrief is the non-technical "key
	// findings" box (Layer 1); TechSummary is the analyst prose (Layer 2),
	// falling back to OverallStory for synthesis.json predating the split.
	ExecBrief   string
	TechSummary string

	// IOCs split into the three report tiers (report improvement Vol.2).
	ConfirmedIOCs []iocRow
	SuspectedIOCs []iocRow
	NoiseIOCs     []iocRow

	// Clusters split into genuine attack activity (rendered open) and likely
	// noise (rendered collapsed at the end of the findings section).
	AttackClusters []clusterArticleCtx
	NoiseClusters  []clusterArticleCtx

	// Rule-derived IR narrative (best-effort, not LLM).
	IntrusionPath string
	// IntrusionChips are the initial-access technique(s) behind the intrusion-path
	// statement as plain-language chips on the intrusion timeline step (so it
	// reads like the cluster steps). Empty when none were detected.
	IntrusionChips []techChip
	Scope          *scopeView
	Reco           *recoView

	// Verdict is the at-a-glance judgement box at the top of the report
	// (auto-derived from the findings, deliberately conservative). nil when there
	// is nothing to judge (no findings).
	Verdict *verdictView
	// Story is the attack narrative rendered as an ordered vertical timeline —
	// the genuine attack clusters in time order, with a gap marker between
	// clusters separated by a long quiet window. Mirrors the case's AttackClusters
	// in a digestible "what happened" form; the full per-cluster tables stay in
	// the findings section.
	Story []storyStepView
	// StoryReordered is true when the attack steps were ordered by attack logic
	// (entry first) rather than recorded time, because the timeline is unreliable.
	StoryReordered bool

	// IsExecutiveSummaryFallback is true when the overall_story was produced
	// by tier2's deterministic fallback (LLM overall synthesis failed) rather
	// than the LLM. Drives a warning banner in the Executive Summary.
	IsExecutiveSummaryFallback bool
}

// clusterArticleCtx wraps one clusterView with the label dict so the shared
// {{define "clusterArticle"}} template can render both the attack and noise
// cluster lists. (A named template's $ is its own argument, not the page root,
// so the dict has to travel with the cluster.)
type clusterArticleCtx struct {
	Dict labelDict
	C    clusterView
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
	// IsLikelyNoise is true when tier2's heuristic flags this cluster as
	// pre-existing system activity / false positive rather than attacker
	// action. Drives a "noise candidate" badge and dimmed styling.
	IsLikelyNoise bool
	// WorstSeverity is the strongest finding severity in the cluster, used for
	// the per-cluster severity badge in the attack-story timeline.
	WorstSeverity string
	// StepNo is the cluster's 1-based position in the (possibly reordered) attack
	// story, shown as "#N" in the story step and the cluster heading so the
	// numbering reflects the attack sequence rather than the raw Tier 2 cluster
	// id. 0 for noise clusters (they fall back to the cluster id).
	StepNo int
}

// verdictView is the conservative, auto-derived at-a-glance judgement box.
type verdictView struct {
	State       string   // localized headline
	StateClass  string   // alert | warn | ok — drives banner colour
	Pills       []string // short status pills (severity / auto-derived note)
	Earliest    string   // formatted earliest observed attack activity, or "—"
	Dwell       string   // localized activity span, or "—"
	Hosts       string   // localized affected-host count, or "—"
	Containment string   // localized containment status (conservative)
}

// storyStepView is one step of the attack-story vertical timeline (one attack
// cluster, in time order).
type storyStepView struct {
	ID          int
	AttackPhase string
	StartTS     time.Time
	EndTS       time.Time
	HasTS       bool
	Desc        string     // first paragraph of the cluster narrative
	Chips       []techChip // plain-language technique chips (deduped)
	WorstSev    string
	// GapBefore, when non-empty, is a localized "N-long quiet window" marker
	// rendered as a dashed break above this step.
	GapBefore string
}

// techChip is one plain-language technique chip for the attack-story timeline.
// Label is the human label; Title carries the underlying MITRE ID(s) for the
// hover tooltip (so analysts can still recover the exact technique).
type techChip struct {
	Label string
	Title string
}

// plainChips maps a technique-ID list to deduped plain-language chips. Sub-
// techniques that share a parent (T1059.001/.003/...) collapse to a single
// chip ("コマンド/スクリプト実行"); the merged IDs all go in the tooltip.
func plainChips(ids []string, lang string) []techChip {
	at := map[string]int{}
	var out []techChip
	for _, id := range ids {
		lbl := mitrePlainLabel(id, lang)
		if i, ok := at[lbl]; ok {
			out[i].Title += ", " + id
			continue
		}
		at[lbl] = len(out)
		out = append(out, techChip{Label: lbl, Title: id})
	}
	return out
}

type findingRow struct {
	Severity        string
	Source          string
	RuleID          string
	Title           string
	FirstSeen       time.Time
	HasTS           bool
	Artifacts       []string
	EvidenceCount   int
	Confidence      string // confirmed | inferred (raw → CSS class)
	ConfidenceLabel string // localized label
}

func buildView(cs tier2.CaseSynthesis, cfg Config, en *enrichment, d labelDict, loc *time.Location) reportView {
	v := reportView{
		Case:           cs,
		Dict:           d,
		Lang:           cfg.Language,
		GeneratedAt:    time.Now().In(loc).Format("2006-01-02 15:04:05 MST"),
		Timezone:       loc.String(),
		Examiner:       orStr(cfg.Examiner, d.UnknownExaminer),
		Organization:   cfg.Organization,
		Classification: orStr(cfg.Classification, d.DefaultClassification),
		ToolVersion:    orStr(cfg.ToolVersion, "TLVB"),
		Meta:           cfg.CaseMeta,
		Severity:       en.SeverityCounts,
		Timeline:       en.Timeline,
		IntrusionPath:  deriveIntrusionPath(cs, cfg.Language, loc),
		Scope:          deriveAffectedScope(cs, en, cfg.Language),
		Reco:           deriveRecommendations(cs, cfg.Language),
	}

	// Executive summary layers. TechSummary falls back to OverallStory for
	// synthesis.json written before the two-layer split.
	v.ExecBrief = cs.ExecBrief
	v.TechSummary = cs.TechSummary
	if v.TechSummary == "" {
		v.TechSummary = cs.OverallStory
	}

	// IOC three-tier split: confirmed (signature) / suspected (anomaly) / noise
	// (parser artifact, hidden by default).
	for _, ioc := range en.IOCs {
		switch ioc.Confidence {
		case "noise":
			v.NoiseIOCs = append(v.NoiseIOCs, ioc)
		case "inferred":
			v.SuspectedIOCs = append(v.SuspectedIOCs, ioc)
		default: // confirmed or unset
			v.ConfirmedIOCs = append(v.ConfirmedIOCs, ioc)
		}
	}

	// tier2 flags a fallback executive summary explicitly; the banner-prefix
	// sniff remains only for synthesis.json written before that field existed.
	v.IsExecutiveSummaryFallback = cs.OverallStoryFallback ||
		strings.HasPrefix(cs.OverallStory, "[NOTE:") ||
		strings.HasPrefix(cs.OverallStory, "【注意:")
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
			IsLikelyNoise:   tier2.IsNoiseCluster(c.AttackPhase, c.Narrative),
		}
		for _, fr := range c.FindingRefs {
			conf := fr.Confidence
			if conf == "" { // synthesis.json predating the provenance field
				_, conf = tier2.ProvenanceForSource(fr.Source)
			}
			row := findingRow{
				Severity:        normSeverity(fr.Severity),
				Source:          fr.Source,
				RuleID:          fr.RuleID,
				Title:           fr.Title,
				Confidence:      conf,
				ConfidenceLabel: d.confLabel(conf),
			}
			if det := en.lookupDetail(fr.Source, fr.RuleID, fr.Title); det != nil {
				row.FirstSeen = det.FirstSeen
				row.HasTS = det.HasTS
				row.Artifacts = det.Artifacts
				row.EvidenceCount = det.EvidenceCount
			}
			cv.Findings = append(cv.Findings, row)
		}
		cv.WorstSeverity = worstSeverity(cv.Findings)
		ctx := clusterArticleCtx{Dict: d, C: cv}
		if cv.IsLikelyNoise {
			v.NoiseClusters = append(v.NoiseClusters, ctx)
		} else {
			v.AttackClusters = append(v.AttackClusters, ctx)
		}
	}

	ja := cfg.Language != "en"
	// Attack-story ordering: timestamps are the source of truth WHEN the timeline
	// is reliable. When it is unreliable (a clock rollback), record order and
	// timestamps diverge — presenting post-compromise activity (defense evasion)
	// before the way-in (the brute-force entry) just because its rolled-back
	// timestamp is earlier is misleading. In that case order the steps by attack
	// logic: the confirmed entry cluster first, then by kill-chain phase. Either
	// way, number the steps sequentially in display order so the entry is #1.
	v.StoryReordered = orderAttackClusters(v.AttackClusters, cs)
	for i := range v.AttackClusters {
		v.AttackClusters[i].C.StepNo = i + 1
	}
	v.Story = buildStory(v.AttackClusters, cfg.Language)
	v.Verdict = buildVerdict(v.AttackClusters, v.Scope, loc, ja)
	v.IntrusionChips = plainChips(intrusionTechniques(cs), cfg.Language)
	return v
}

// orderAttackClusters sorts the attack clusters in place. With a reliable
// timeline it keeps timestamp order (the Tier 2 order). With an unreliable
// timeline it sorts by attack logic — the confirmed entry cluster(s) first, then
// kill-chain phase, ties broken by timestamp — and returns true so the report
// can note the steps are in reconstructed (not recorded-time) order.
func orderAttackClusters(clusters []clusterArticleCtx, cs tier2.CaseSynthesis) bool {
	if !strings.EqualFold(cs.TimelineReliability, "unreliable") {
		return false
	}
	entry := entryClusterIDs(cs)
	rank := func(ctx clusterArticleCtx) int {
		if entry[ctx.C.ID] {
			return -1 // the way in always leads
		}
		return phaseRank(ctx.C.AttackPhase)
	}
	sort.SliceStable(clusters, func(i, j int) bool {
		ri, rj := rank(clusters[i]), rank(clusters[j])
		if ri != rj {
			return ri < rj
		}
		return clusters[i].C.StartTS.Before(clusters[j].C.StartTS)
	})
	return true
}

// worstSeverity returns the strongest severity across a cluster's findings.
func worstSeverity(rows []findingRow) string {
	w := ""
	for _, r := range rows {
		if severityRank(r.Severity) > severityRank(w) {
			w = normSeverity(r.Severity)
		}
	}
	return w
}

// buildStory turns the time-ordered attack clusters into a vertical-timeline
// step list, inserting a "quiet window" gap marker between clusters separated by
// more than 30 minutes of silence.
func buildStory(clusters []clusterArticleCtx, lang string) []storyStepView {
	ja := lang != "en"
	var steps []storyStepView
	var prevEnd time.Time
	for _, ctx := range clusters {
		c := ctx.C
		stepID := c.StepNo
		if stepID == 0 {
			stepID = c.ID
		}
		step := storyStepView{
			ID:          stepID,
			AttackPhase: c.AttackPhase,
			StartTS:     c.StartTS,
			EndTS:       c.EndTS,
			HasTS:       !c.StartTS.IsZero(),
			Desc:        firstParagraph(c.Narrative),
			Chips:       plainChips(c.MITRETechniques, lang),
			WorstSev:    c.WorstSeverity,
		}
		if step.HasTS && !prevEnd.IsZero() {
			if gap := c.StartTS.Sub(prevEnd); gap >= 30*time.Minute {
				step.GapBefore = humanizeGap(gap, ja)
			}
		}
		steps = append(steps, step)
		if !c.EndTS.IsZero() {
			prevEnd = c.EndTS
		}
	}
	return steps
}

// buildVerdict derives the conservative at-a-glance judgement box. Deliberately
// understated: it reports what was detected (confirmed signatures vs anomalies),
// never asserts a containment state it cannot know.
func buildVerdict(clusters []clusterArticleCtx, scope *scopeView, loc *time.Location, ja bool) *verdictView {
	var total, confirmed int
	worst := ""
	var earliest, latest time.Time
	for _, ctx := range clusters {
		for _, f := range ctx.C.Findings {
			total++
			if f.Confidence == "confirmed" {
				confirmed++
			}
			if severityRank(f.Severity) > severityRank(worst) {
				worst = normSeverity(f.Severity)
			}
		}
		if !ctx.C.StartTS.IsZero() && (earliest.IsZero() || ctx.C.StartTS.Before(earliest)) {
			earliest = ctx.C.StartTS
		}
		if !ctx.C.EndTS.IsZero() && (latest.IsZero() || ctx.C.EndTS.After(latest)) {
			latest = ctx.C.EndTS
		}
	}
	if total == 0 {
		return nil
	}

	v := &verdictView{Earliest: "—", Dwell: "—", Hosts: "—"}
	switch {
	case confirmed > 0:
		v.StateClass = "alert"
		if ja {
			v.State = "確定シグネチャを検出 — 侵害の痕跡あり"
			v.Containment = "要確認 (自動判定の対象外)"
		} else {
			v.State = "Confirmed signatures detected — evidence of compromise"
			v.Containment = "To be confirmed (out of auto-scope)"
		}
	case total > 0:
		v.StateClass = "warn"
		if ja {
			v.State = "要精査の異常を検出"
			v.Containment = "要確認 (自動判定の対象外)"
		} else {
			v.State = "Anomalies detected — review required"
			v.Containment = "To be confirmed (out of auto-scope)"
		}
	}

	if !earliest.IsZero() {
		v.Earliest = formatTSIn(earliest, loc)
	}
	if !earliest.IsZero() && !latest.IsZero() && latest.After(earliest) {
		v.Dwell = humanizeDuration(latest.Sub(earliest), ja)
	}
	if scope != nil && len(scope.Hosts) > 0 {
		if ja {
			v.Hosts = fmt.Sprintf("%d 台", len(scope.Hosts))
		} else if len(scope.Hosts) == 1 {
			v.Hosts = "1 host"
		} else {
			v.Hosts = fmt.Sprintf("%d hosts", len(scope.Hosts))
		}
	}

	// Conservative status pills: worst severity + an explicit auto-derived flag.
	if worst != "" {
		if ja {
			v.Pills = append(v.Pills, "最大重要度: "+sevLabelJA(worst))
		} else {
			v.Pills = append(v.Pills, "Max severity: "+sevLabelEN(worst))
		}
	}
	if ja {
		v.Pills = append(v.Pills, "自動判定 (要レビュー)")
	} else {
		v.Pills = append(v.Pills, "Auto-derived (review required)")
	}
	return v
}

// firstParagraph returns the first blank-line-delimited paragraph of s, trimmed.
func firstParagraph(s string) string {
	ps := splitParagraphs(s)
	if len(ps) == 0 {
		return ""
	}
	return ps[0]
}

// humanizeDuration renders a duration as a coarse, human phrase
// ("約 16 時間" / "~16 hours"). Used for the verdict's activity span.
func humanizeDuration(d time.Duration, ja bool) string {
	switch {
	case d >= 48*time.Hour:
		n := int(d.Hours() / 24)
		if ja {
			return fmt.Sprintf("約 %d 日間", n)
		}
		return fmt.Sprintf("~%d days", n)
	case d >= 90*time.Minute:
		n := int(d.Hours() + 0.5)
		if ja {
			return fmt.Sprintf("約 %d 時間", n)
		}
		return fmt.Sprintf("~%d hours", n)
	default:
		n := int(d.Minutes() + 0.5)
		if ja {
			return fmt.Sprintf("約 %d 分", n)
		}
		return fmt.Sprintf("~%d minutes", n)
	}
}

// humanizeGap wraps humanizeDuration with the "quiet window" suffix used by the
// attack-story timeline's gap markers ("約 16 時間の空白 — 観測されたアクティビティなし").
func humanizeGap(d time.Duration, ja bool) string {
	if ja {
		return humanizeDuration(d, ja) + "の空白 — 観測されたアクティビティなし"
	}
	return humanizeDuration(d, ja) + " quiet window — no observed activity"
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
	ReportTitle                string
	Case                       string
	Generated                  string
	Timezone                   string
	Model                      string
	TotalFindings              string
	ClusterCount               string
	ExecutiveSummary           string
	ExecSummaryFallbackWarning string
	TimelineUnreliableHeading  string
	UngroundedHeading          string
	MITREUnconfirmedHeading    string
	MITREUnconfirmedNote       string
	NoiseBadge                 string
	MITREMapping               string
	Technique                  string
	Tactic                     string
	FindingCount               string
	ClusterIDs                 string
	Cluster                    string
	Window                     string
	AttackPhase                string
	Narrative                  string
	Findings                   string
	Source                     string
	RuleID                     string
	Title                      string
	Severity                   string
	OpenQuestions              string
	Audit                      string
	LLMCalls                   string
	LLMDuration                string
	InputTokens                string
	OutputTokens               string
	SkillSHA                   string

	// forensic additions
	DefaultClassification  string
	Examiner               string
	UnknownExaminer        string
	Organization           string
	CaseInformation        string
	DisplayName            string
	Status                 string
	AnalysisDate           string
	ToolVersion            string
	Notes                  string
	Scope                  string
	ScopeBody              string
	SeveritySummary        string
	SevJumpHint            string
	EvidenceChain          string
	EvidenceID             string
	SourcePath             string
	SHA256                 string
	Size                   string
	CollectedAt            string
	EvidenceTypeCol        string
	Host                   string
	IntegrityNote          string
	ArtifactCoverage       string
	ArtifactName           string
	EventCount             string
	TotalEvents            string
	Methodology            string
	MethodologyBody        string
	Limitations            string
	AIDisclaimer           string
	CompletenessSec        string
	CompletenessBody       string
	CompletenessInput      string
	CompletenessCapability string
	CompletenessStatus     string
	CompletenessPresent    string
	CompletenessMissing    string
	FirstSeen              string
	Artifacts              string
	EvidenceCountCol       string
	ConfidenceCol          string
	ConfirmedLabel         string
	InferredLabel          string
	TimelineSection        string
	TimeCol                string
	EventTypeCol           string
	IOCSection             string
	IOCType                string
	IOCValue               string
	IOCCount               string
	NoIOC                  string
	ActiveSearch           string
	Question               string
	AnswerCol              string
	HitsCol                string
	CaseOpenQuestions      string
	None                   string

	// executive summary two-layer (report improvement Vol.2)
	ExecBriefHeading  string
	TechDetailHeading string
	// findings section: noise-cluster grouping
	AttackActivity       string
	NoiseClustersSummary string
	// open questions three-tier
	OQCritical        string
	OQNeedsCollection string
	OQSupplementary   string
	// IOC three-tier
	IOCConfirmed   string
	IOCSuspected   string
	IOCNoiseHidden string

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

	// redesign: verdict box / attack story / side-nav / inline intrusion evidence
	BrandSub              string
	Subtitle              string
	NavExec               string
	NavIR                 string
	NavDetails            string
	NavAnalyst            string
	NavVerdict            string
	NavStory              string
	NavSummary            string
	NavScope              string
	NavIntrusion          string
	NavReco               string
	NavOpen               string
	NavClusters           string
	NavMitre              string
	NavIOC                string
	NavEvidence           string
	VerdictSec            string
	VEarliest             string
	VDwell                string
	VHosts                string
	VContainment          string
	ActionsHeading        string
	AttackStorySec        string
	StoryLogicalOrderNote string
	IntrusionEvidence     string
	EarliestEvents        string

	phaseLabel func(string) string
	sevLabel   func(string) string
}

var dictJA = labelDict{
	ReportTitle:                "TLVB フォレンジック解析レポート",
	Case:                       "ケース ID",
	Generated:                  "生成日時",
	Timezone:                   "表示タイムゾーン",
	Model:                      "解析モデル",
	TotalFindings:              "Finding 総数",
	ClusterCount:               "クラスタ数",
	ExecutiveSummary:           "エグゼクティブサマリ",
	ExecSummaryFallbackWarning: "⚠️ LLM による全体合成が失敗したため、このサマリは攻撃クラスタ要約の自動連結で代替されています。攻撃チェーンとしての論理構成は行われていません。人手でのレビューおよび Tier 2 の再実行を推奨します。",
	TimelineUnreliableHeading:  "⚠️ タイムライン信頼性: 要再アンカー",
	UngroundedHeading:          "⚠️ 結論中に finding の裏付けが無いツール/手法名が含まれます (未確認・要検証):",
	MITREUnconfirmedHeading:    "未確認の technique (参考)",
	MITREUnconfirmedNote:       "※ 以下は LLM が叙述で言及したが finding(rule→technique)の裏付けが無い technique です。確定したマッピングではなく、要検証の仮説として扱ってください。",
	NoiseBadge:                 "ノイズ候補",
	MITREMapping:               "MITRE ATT&CK マッピング",
	Technique:                  "Technique",
	Tactic:                     "Tactic",
	FindingCount:               "件数",
	ClusterIDs:                 "クラスタ ID",
	Cluster:                    "Finding 詳細 (攻撃クラスタ別)",
	Window:                     "時刻範囲",
	AttackPhase:                "攻撃フェーズ",
	Narrative:                  "シナリオ",
	Findings:                   "Finding 一覧",
	Source:                     "ソース",
	RuleID:                     "ルール ID",
	Title:                      "タイトル",
	Severity:                   "重要度",
	OpenQuestions:              "未解決の論点",
	Audit:                      "付録: 監査・来歴情報",
	LLMCalls:                   "LLM 呼び出し回数",
	LLMDuration:                "LLM 累計時間 (秒)",
	InputTokens:                "Input tokens",
	OutputTokens:               "Output tokens",
	SkillSHA:                   "Skill SHA-256",

	DefaultClassification:  "社外秘 / CONFIDENTIAL",
	Examiner:               "解析担当 (Examiner)",
	UnknownExaminer:        "(未記入)",
	Organization:           "所属組織",
	CaseInformation:        "ケース情報",
	DisplayName:            "ケース名",
	Status:                 "ステータス",
	AnalysisDate:           "解析実施日時",
	ToolVersion:            "使用ツール",
	Notes:                  "備考",
	Scope:                  "解析スコープ",
	ScopeBody:              "本レポートは、提供された Windows フォレンジック・アーティファクトに対する自動解析の結果である。対象は下記「証拠インベントリ」に列挙した証拠に限定される。ネットワークログ・メモリダンプ等、収集対象外のデータソースは解析範囲に含まれない。",
	SeveritySummary:        "重要度サマリ",
	SevJumpHint:            "クリックでこの重要度の検出に移動・ハイライト",
	EvidenceChain:          "証拠インベントリと完全性 (Chain of Custody)",
	EvidenceID:             "証拠 ID",
	SourcePath:             "取得元",
	SHA256:                 "SHA-256",
	Size:                   "サイズ",
	CollectedAt:            "登録日時",
	EvidenceTypeCol:        "種別",
	Host:                   "ホスト",
	IntegrityNote:          "各証拠は取得時に SHA-256 ハッシュを記録しており、上記値で原本との同一性を検証できる。解析は読み取り専用で行われ、原本は変更されていない。",
	ArtifactCoverage:       "アーティファクト別イベント数 (Tier 0 解析範囲)",
	ArtifactName:           "アーティファクト",
	EventCount:             "イベント数",
	TotalEvents:            "総イベント数",
	Methodology:            "解析手法と限界",
	MethodologyBody:        "本解析は TLVB 自律 IR エージェントによる以下のパイプラインで実施した。Tier 0 (パーサ群が各アーティファクトを正規化イベントに変換)、Tier 1A (Sigma / Hayabusa / MITRE ATT&CK 由来のシグネチャを事前生成 SQL として実行し、ヒットを finding 化)、Tier 1B (skill ベースの異常検知を LLM 推論で補完)、Tier 2 (finding を時間クラスタ化し、周辺の生イベントから攻撃シナリオを再構成)、Tier 3 (本レポート生成)。各 finding は event_id・source_artifact・タイムスタンプで裏付けられる。各 finding の「確度」列は導出方法を示す: 確認 = Tier 1A の決定的シグネチャが実際の記録イベントに一致したもの (照合自体は事実)、推論 = Tier 1B の LLM が異常と判断したもの。いずれも悪性の確証ではなく、最終判断は解析担当者のレビューを要する。",
	Limitations:            "限界・前提: (1) タイムスタンプは UTC で正規化保存し、本レポートでは表示タイムゾーンに変換して表示している（各時刻は RFC3339 のオフセット付き）。アーティファクト由来のタイムゾーン誤差は補正していない。(2) シグネチャ未知の攻撃や、収集対象外のアーティファクトに痕跡が残る攻撃は検知できない。(3) 自動再構成された攻撃シナリオは仮説であり、確証には人手レビューを要する。未解決事項は各「未解決の論点」に明示した。",
	AIDisclaimer:           "AI 利用に関する開示: シナリオ記述・MITRE マッピング・未解決論点は大規模言語モデル (上記「解析モデル」) が生成した。シグネチャ検知部 (Tier 1A) は LLM を実行時に呼び出さず、事前検証済み SQL のみを実行する。最終的な判断は資格を持つ解析担当者によるレビューを前提とする。",
	CompletenessSec:        "収集完全性 — データ欠落と検知失敗の区別",
	CompletenessBody:       "以下は検知に関連する収集入力 (EVTX チャネル / Tier 0 アーティファクト) の在否である。「未収集」の項目は検知が失敗したのではなく、調査対象がそもそも収集されていなかったことを意味する (沈黙の不在を「調べて何も無かった」と誤読しないための明示)。",
	CompletenessInput:      "検知入力",
	CompletenessCapability: "解禁される検知",
	CompletenessStatus:     "状態",
	CompletenessPresent:    "収集済",
	CompletenessMissing:    "未収集",
	FirstSeen:              "初出時刻",
	Artifacts:              "アーティファクト",
	EvidenceCountCol:       "証拠数",
	ConfidenceCol:          "確度",
	ConfirmedLabel:         "確認",
	InferredLabel:          "推論",
	TimelineSection:        "イベントタイムライン (主要事象)",
	TimeCol:                "時刻",
	EventTypeCol:           "イベント種別",
	IOCSection:             "侵害指標 (Indicators of Compromise)",
	IOCType:                "種別",
	IOCValue:               "値",
	IOCCount:               "出現回数",
	NoIOC:                  "抽出可能な侵害指標はなかった。",
	ActiveSearch:           "能動探索 (仮説駆動クエリ)",
	Question:               "論点 / 仮説",
	AnswerCol:              "解釈",
	HitsCol:                "ヒット数",
	CaseOpenQuestions:      "未解決の論点 (ケース全体)",
	None:                   "該当なし",

	ExecBriefHeading:     "要点 (意思決定者向け)",
	TechDetailHeading:    "技術的詳細 (アナリスト向け)",
	AttackActivity:       "検出された攻撃活動 (攻撃クラスタ別)",
	NoiseClustersSummary: "ノイズ候補 / 誤検知判定済みクラスタ",
	OQCritical:           "🔴 根本原因に直結するクリティカル論点",
	OQNeedsCollection:    "🟡 追加アーティファクト収集で解決可能",
	OQSupplementary:      "🟢 補足確認事項",
	IOCConfirmed:         "確定 IOC (シグネチャ由来)",
	IOCSuspected:         "要精査 IOC (異常検知・推論由来)",
	IOCNoiseHidden:       "パーサノイズ / 除外済み",

	IntrusionPathSec:   "侵入経路 (Intrusion Path)",
	AffectedScopeSec:   "影響範囲 (Affected Scope)",
	ScopeHosts:         "影響を受けたホスト",
	ScopeAccounts:      "影響を受けたアカウント",
	ScopeData:          "リスクに晒されたデータ",
	RecommendationsSec: "今後の推奨事項 (Recommendations)",
	RecContainment:     "封じ込め (Containment)",
	RecEradication:     "根絶 (Eradication)",
	RecRecovery:        "復旧 (Recovery)",
	DerivedNote:        "※ 本セクションは検出された finding・MITRE technique・IOC からルールベースで自動導出した参考情報であり、LLM 生成ではない。確証と優先順位付けには人手レビューを要する。",

	BrandSub:              "Forensic Report",
	Subtitle:              "Windows フォレンジック・アーティファクト自動解析レポート",
	NavExec:               "総論",
	NavDetails:            "各論詳細",
	NavIR:                 "IR 対応者向け",
	NavAnalyst:            "アナリスト向け",
	NavVerdict:            "判定と推奨対応",
	NavStory:              "攻撃の経緯",
	NavSummary:            "エグゼクティブサマリ",
	NavScope:              "影響範囲",
	NavIntrusion:          "侵入経路",
	NavReco:               "推奨対応",
	NavOpen:               "未解決の論点",
	NavClusters:           "攻撃クラスタ詳細",
	NavMitre:              "MITRE ATT&CK",
	NavIOC:                "侵害指標 (IOC)",
	NavEvidence:           "証拠・手法・付録",
	VerdictSec:            "判定と推奨対応",
	VEarliest:             "最古の確認活動",
	VDwell:                "活動期間 (滞留)",
	VHosts:                "影響ホスト",
	VContainment:          "封じ込め状態",
	ActionsHeading:        "今すぐやること (推奨初動)",
	AttackStorySec:        "攻撃の経緯",
	StoryLogicalOrderNote: "※ 本ケースは時刻が信頼できない（巻き戻し検出）ため、各ステップは記録時刻順ではなく攻撃の論理的順序（侵入を起点）で並べ替えて番号付けしています。",
	IntrusionEvidence:     "侵入経路の根拠 (該当クラスタをインライン表示)",
	EarliestEvents:        "最初期の主要イベント",

	phaseLabel: phaseLabelJA,
	sevLabel:   sevLabelJA,
}

var dictEN = labelDict{
	ReportTitle:                "TLVB Forensic Analysis Report",
	Case:                       "Case ID",
	Generated:                  "Generated",
	Timezone:                   "Display timezone",
	Model:                      "Analysis model",
	TotalFindings:              "Total findings",
	ClusterCount:               "Cluster count",
	ExecutiveSummary:           "Executive Summary",
	ExecSummaryFallbackWarning: "⚠️ The LLM overall synthesis failed, so this summary is an auto-stitch of the attack-cluster narratives — it has NOT been composed into a coherent attack chain. Manual review and a Tier 2 re-run are recommended.",
	TimelineUnreliableHeading:  "⚠️ Timeline reliability: re-anchoring required",
	UngroundedHeading:          "⚠️ The summary names tools/techniques with no supporting finding (unconfirmed — verify):",
	MITREUnconfirmedHeading:    "Unconfirmed techniques (for reference)",
	MITREUnconfirmedNote:       "Note: the following techniques were mentioned in LLM narrative but are NOT backed by any finding (rule→technique). Treat them as hypotheses to verify, not as a confirmed mapping.",
	NoiseBadge:                 "Likely noise",
	MITREMapping:               "MITRE ATT&CK Mapping",
	Technique:                  "Technique",
	Tactic:                     "Tactic",
	FindingCount:               "Count",
	ClusterIDs:                 "Cluster IDs",
	Cluster:                    "Findings (by attack cluster)",
	Window:                     "Window",
	AttackPhase:                "Attack phase",
	Narrative:                  "Narrative",
	Findings:                   "Findings",
	Source:                     "Source",
	RuleID:                     "Rule ID",
	Title:                      "Title",
	Severity:                   "Severity",
	OpenQuestions:              "Open questions",
	Audit:                      "Appendix: Audit & Provenance",
	LLMCalls:                   "LLM calls",
	LLMDuration:                "LLM duration (s)",
	InputTokens:                "Input tokens",
	OutputTokens:               "Output tokens",
	SkillSHA:                   "Skill SHA-256",

	DefaultClassification:  "CONFIDENTIAL",
	Examiner:               "Examiner",
	UnknownExaminer:        "(not recorded)",
	Organization:           "Organization",
	CaseInformation:        "Case Information",
	DisplayName:            "Case name",
	Status:                 "Status",
	AnalysisDate:           "Analysis date",
	ToolVersion:            "Tooling",
	Notes:                  "Notes",
	Scope:                  "Scope",
	ScopeBody:              "This report presents the result of automated analysis of the provided Windows forensic artifacts. Its scope is limited to the evidence listed under \"Evidence Inventory\" below. Data sources that were not collected (e.g. network logs, memory dumps) are out of scope.",
	SeveritySummary:        "Severity Summary",
	SevJumpHint:            "Click to jump to and highlight findings of this severity",
	EvidenceChain:          "Evidence Inventory & Integrity (Chain of Custody)",
	EvidenceID:             "Evidence ID",
	SourcePath:             "Source",
	SHA256:                 "SHA-256",
	Size:                   "Size",
	CollectedAt:            "Registered at",
	EvidenceTypeCol:        "Type",
	Host:                   "Host",
	IntegrityNote:          "A SHA-256 hash was recorded for each exhibit at acquisition; the values above let an examiner verify integrity against the original. Analysis was read-only and the originals were not modified.",
	ArtifactCoverage:       "Events per Artifact (Tier 0 coverage)",
	ArtifactName:           "Artifact",
	EventCount:             "Events",
	TotalEvents:            "Total events",
	Methodology:            "Methodology & Limitations",
	MethodologyBody:        "Analysis was performed by the TLVB autonomous IR agent through the following pipeline: Tier 0 (parsers normalise each artifact into unified events), Tier 1A (Sigma / Hayabusa / MITRE ATT&CK signatures compiled to pre-baked SQL, matches become findings), Tier 1B (skill-based anomaly detection augmented by LLM reasoning), Tier 2 (findings are clustered temporally and the surrounding raw events are reconstructed into an attack narrative), Tier 3 (this report). Every finding is backed by event_id, source_artifact and a timestamp. The \"Confidence\" column records how each finding was derived: Confirmed = a deterministic Tier 1A signature matched real logged events (the match itself is factual); Inferred = a Tier 1B LLM judged the pattern anomalous. Neither asserts malice — final adjudication requires analyst review.",
	Limitations:            "Limitations & assumptions: (1) Timestamps are normalised and stored in UTC and rendered in the report display timezone (each value carries its RFC3339 offset); artifact-specific timezone skew is not corrected. (2) Attacks with no known signature, or whose traces live in uncollected artifacts, cannot be detected. (3) The reconstructed attack narrative is a hypothesis and requires human review to confirm; unresolved items are listed under \"Open questions\".",
	AIDisclaimer:           "AI disclosure: narratives, MITRE mappings and open questions were generated by a large language model (see \"Analysis model\"). The signature-detection tier (Tier 1A) invokes no LLM at runtime — it executes only pre-validated SQL. Final determinations are expected to be reviewed by a qualified examiner.",
	CompletenessSec:        "Collection completeness - data gap vs detection miss",
	CompletenessBody:       "The table below lists detection-relevant collection inputs (EVTX channels and Tier 0 artefacts) and whether each was present. A NOT-collected row means the input was never acquired, so a related miss is a DATA GAP rather than a detection failure; absence here must not be read as looked-and-found-nothing.",
	CompletenessInput:      "Detection input",
	CompletenessCapability: "Detection enabled",
	CompletenessStatus:     "Status",
	CompletenessPresent:    "collected",
	CompletenessMissing:    "NOT collected",
	FirstSeen:              "First seen",
	Artifacts:              "Artifacts",
	EvidenceCountCol:       "Evidence",
	ConfidenceCol:          "Confidence",
	ConfirmedLabel:         "Confirmed",
	InferredLabel:          "Inferred",
	TimelineSection:        "Event Timeline (key events)",
	TimeCol:                "Time",
	EventTypeCol:           "Event type",
	IOCSection:             "Indicators of Compromise",
	IOCType:                "Type",
	IOCValue:               "Value",
	IOCCount:               "Occurrences",
	NoIOC:                  "No indicators of compromise could be extracted.",
	ActiveSearch:           "Active search (hypothesis-driven queries)",
	Question:               "Question / hypothesis",
	AnswerCol:              "Interpretation",
	HitsCol:                "Hits",
	CaseOpenQuestions:      "Open Questions (case-wide)",
	None:                   "None",

	ExecBriefHeading:     "Key Findings (for decision-makers)",
	TechDetailHeading:    "Technical Detail (for analysts)",
	AttackActivity:       "Detected Attack Activity (by cluster)",
	NoiseClustersSummary: "Noise candidates / false-positive clusters",
	OQCritical:           "🔴 Critical — directly affects root cause",
	OQNeedsCollection:    "🟡 Resolvable by collecting more artifacts",
	OQSupplementary:      "🟢 Supplementary",
	IOCConfirmed:         "Confirmed IOC (signature-derived)",
	IOCSuspected:         "Suspected IOC (anomaly / inferred)",
	IOCNoiseHidden:       "Parser noise / excluded",

	IntrusionPathSec:   "Intrusion Path",
	AffectedScopeSec:   "Affected Scope",
	ScopeHosts:         "Affected hosts",
	ScopeAccounts:      "Affected accounts",
	ScopeData:          "Data at risk",
	RecommendationsSec: "Recommendations",
	RecContainment:     "Containment",
	RecEradication:     "Eradication",
	RecRecovery:        "Recovery",
	DerivedNote:        "Note: this section is auto-derived (rule-based, not LLM) from the detected findings, MITRE techniques and IOCs. It requires human review for confirmation and prioritisation.",

	BrandSub:              "Forensic Report",
	Subtitle:              "Automated analysis of Windows forensic artifacts",
	NavExec:               "Overview",
	NavDetails:            "Details",
	NavIR:                 "For IR responders",
	NavAnalyst:            "For analysts",
	NavVerdict:            "Verdict & actions",
	NavStory:              "Attack story",
	NavSummary:            "Executive summary",
	NavScope:              "Affected scope",
	NavIntrusion:          "Intrusion path",
	NavReco:               "Recommendations",
	NavOpen:               "Open questions",
	NavClusters:           "Attack clusters",
	NavMitre:              "MITRE ATT&CK",
	NavIOC:                "Indicators (IOC)",
	NavEvidence:           "Evidence & method",
	VerdictSec:            "Verdict & Recommended Actions",
	VEarliest:             "Earliest observed activity",
	VDwell:                "Activity span (dwell)",
	VHosts:                "Affected hosts",
	VContainment:          "Containment status",
	ActionsHeading:        "Immediate actions (recommended)",
	AttackStorySec:        "Attack Story",
	StoryLogicalOrderNote: "Note: this case has an unreliable clock (rollback detected), so the steps are ordered and numbered by attack logic (entry first), not by recorded time.",
	IntrusionEvidence:     "Intrusion evidence (relevant cluster, inlined)",
	EarliestEvents:        "Earliest key events",

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
		return v
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
// confLabel localises a confirmed/inferred confidence value.
func (d labelDict) confLabel(conf string) string {
	switch conf {
	case "confirmed":
		return d.ConfirmedLabel
	case "inferred":
		return d.InferredLabel
	default:
		return conf
	}
}

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

// splitBullets turns the Executive Brief (one bullet per line, each starting
// with "- "/"•"/"*"/"・") into a clean []string for an <ul>. Blank lines and
// leading bullet glyphs are stripped; a single-paragraph brief degrades to one
// item per non-blank line.
func splitBullets(s string) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		ln = strings.TrimLeft(ln, "-*•・ \t")
		if ln = strings.TrimSpace(ln); ln != "" {
			out = append(out, ln)
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
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{.Dict.ReportTitle}} — {{.Case.CaseID}}</title>
<style>
  :root {
    --ink:#11161f; --paper:#f7f8fa; --card:#ffffff; --tx:#1f2733; --tx2:#57606a; --tx3:#8b95a3;
    --line:#e2e6ec; --line2:#cdd3dc; --indigo:#3b5bdb; --indigo-soft:#edf0fd;
    --alert:#e03131; --alert-soft:#fff0f0; --warn:#f08c00; --warn-soft:#fff7e8; --amber:#c08a00;
    --verify:#2f9e44; --verify-soft:#ebfaef; --muted:#868e96; --muted-soft:#f0f2f5;
    --mono:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;
    --sans:"IBM Plex Sans JP","Yu Gothic UI","Hiragino Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
    --maxw:780px; color-scheme: light dark;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --paper:#0f1419; --card:#18202c; --tx:#e6e8eb; --tx2:#9aa3b2; --tx3:#6b7585;
      --line:#2a3342; --line2:#3a4456; --indigo:#8ea4ff; --indigo-soft:#1a2236;
      --alert:#ff6b6b; --alert-soft:#2a1518; --warn:#ffa94d; --warn-soft:#2a1f12;
      --amber:#ffd43b; --verify:#69db7c; --verify-soft:#14271a; --muted:#868e96; --muted-soft:#1d2530;
    }
  }
  * { box-sizing: border-box; }
  html { scroll-behavior: smooth; }
  body { margin:0; background:var(--paper); color:var(--tx); font-family:var(--sans);
         font-size:15px; line-height:1.7; -webkit-font-smoothing:antialiased; }
  .layout { display:grid; grid-template-columns:210px 1fr; max-width:1140px; margin:0 auto; }
  nav.toc { position:sticky; top:0; align-self:start; height:100vh; overflow-y:auto;
            padding:28px 18px; font-size:12px; border-right:1px solid var(--line); }
  nav.toc .brand { font-weight:700; font-size:14px; letter-spacing:.02em; }
  nav.toc .brand small { display:block; font-weight:400; color:var(--tx3); font-size:10px; font-family:var(--mono); margin-top:2px; }
  nav.toc .layer-label { font-size:9px; text-transform:uppercase; letter-spacing:.1em; color:var(--tx3); margin:18px 0 6px; font-family:var(--mono); }
  nav.toc a { display:block; color:var(--tx2); text-decoration:none; padding:3px 0 3px 10px; border-left:2px solid transparent; margin-left:-10px; }
  nav.toc a:hover { color:var(--indigo); border-left-color:var(--indigo); }
  main { padding:28px 40px 80px; min-width:0; }

  .classbar { background:var(--ink); color:#fff; text-align:center; font-size:11px; font-weight:600;
              letter-spacing:.15em; padding:6px; border-radius:4px; font-family:var(--mono); margin-bottom:20px; }
  @media (prefers-color-scheme: dark) { .classbar { background:#000; } }
  h1.title { font-size:24px; font-weight:700; margin:0 0 2px; letter-spacing:-.01em; }
  .subtitle { color:var(--tx2); font-size:14px; margin:0 0 4px; }
  .docmeta { font-family:var(--mono); font-size:11px; color:var(--tx3); margin-bottom:22px; word-break:break-word; }

  section { margin:0 0 14px; scroll-margin-top:20px; }
  .eyebrow { font-family:var(--mono); font-size:10px; text-transform:uppercase; letter-spacing:.12em; color:var(--indigo); margin:32px 0 4px; }
  h2.sec { font-size:20px; font-weight:700; margin:0 0 14px; padding-bottom:8px; border-bottom:1px solid var(--line); letter-spacing:-.01em; }
  h3.sub { font-size:14px; font-weight:600; margin:18px 0 6px; }
  .layer-divider { margin:44px 0 0; padding-top:8px; border-top:2px solid var(--line2); }
  .layer-divider .lt { font-family:var(--mono); font-size:10px; text-transform:uppercase; letter-spacing:.14em; color:var(--tx3); }
  p { margin:0 0 12px; max-width:var(--maxw); }
  .muted, .empty { color:var(--tx3); }
  .empty { font-style:italic; }
  code, .mono { font-family:var(--mono); font-size:.85em; word-break:break-all; }

  /* verdict */
  .verdict { border:1px solid var(--alert); border-left:5px solid var(--alert); background:var(--alert-soft);
             border-radius:8px; padding:18px 22px; margin:0 0 14px; }
  .verdict.v-warn { border-color:var(--warn); border-left-color:var(--warn); background:var(--warn-soft); }
  .verdict.v-ok   { border-color:var(--verify); border-left-color:var(--verify); background:var(--verify-soft); }
  .verdict .vhead { display:flex; align-items:baseline; gap:12px; flex-wrap:wrap; margin-bottom:14px; }
  .verdict .vstate { font-size:19px; font-weight:700; color:var(--alert); }
  .verdict.v-warn .vstate { color:var(--amber); }
  .verdict.v-ok .vstate { color:var(--verify); }
  .verdict .vpill { font-family:var(--mono); font-size:11px; font-weight:500; padding:3px 10px; border-radius:999px;
                    background:var(--ink); color:#fff; }
  .verdict .vgrid { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; }
  .verdict .vcell .k { font-size:10px; text-transform:uppercase; letter-spacing:.06em; color:var(--tx2); font-family:var(--mono); }
  .verdict .vcell .v { font-size:15px; font-weight:600; margin-top:2px; }
  @media (max-width:640px){ .verdict .vgrid { grid-template-columns:repeat(2,1fr); } }
  .actions { border:1px solid var(--line2); border-radius:8px; padding:14px 20px; margin:0 0 18px; background:var(--card); }
  .actions h3 { font-size:12px; text-transform:uppercase; letter-spacing:.06em; color:var(--tx2); margin:0 0 8px; font-family:var(--mono); }
  .actions ol { margin:0; padding-left:0; list-style:none; counter-reset:act; }
  .actions li { counter-increment:act; padding:5px 0 5px 32px; position:relative; font-size:14px; max-width:var(--maxw); }
  .actions li::before { content:counter(act); position:absolute; left:0; top:5px; width:20px; height:20px;
    background:var(--alert); color:#fff; border-radius:50%; font-size:11px; font-weight:700; display:grid; place-items:center; font-family:var(--mono); }

  /* clock-tamper / reliability banner */
  .tamper { display:flex; gap:12px; align-items:flex-start; background:var(--warn-soft); border:1px solid var(--warn);
            border-radius:8px; padding:12px 16px; margin:0 0 18px; }
  .tamper .ic { font-size:18px; line-height:1.3; }
  .tamper .tx { font-size:13px; }
  .tamper b { color:var(--amber); }

  /* attack-story vertical timeline */
  .storyflow { position:relative; margin:8px 0; padding-left:4px; }
  .step { position:relative; padding:0 0 6px 34px; border-left:2px solid var(--line2); margin-left:8px; }
  .step:last-child { border-left-color:transparent; }
  .step .node { position:absolute; left:-9px; top:2px; width:16px; height:16px; border-radius:50%; background:var(--card); border:3px solid var(--indigo); }
  .step.step-critical .node { border-color:var(--alert); }
  .step.step-high .node { border-color:var(--warn); }
  .step.step-intrusion .node { border-color:var(--indigo); background:var(--indigo); }
  .step.step-intrusion .act { color:var(--indigo); }
  .step .when { font-family:var(--mono); font-size:12px; font-weight:500; color:var(--tx2); }
  .step .act { font-size:16px; font-weight:600; margin:2px 0 4px; }
  .step .desc { font-size:13px; color:var(--tx2); margin:0 0 6px; max-width:var(--maxw); }
  .step .chips { display:flex; gap:6px; flex-wrap:wrap; margin-bottom:16px; }
  .gap-marker { position:relative; padding:0 0 6px 34px; border-left:2px dashed var(--line2); margin-left:8px; }
  .gap-marker .gtx { font-family:var(--mono); font-size:11px; color:var(--warn); padding:8px 0; }
  .chip { font-family:var(--mono); font-size:10px; padding:2px 8px; border-radius:4px; border:1px solid var(--line2); color:var(--tx2); }
  .chip.tech { border-color:var(--indigo); color:var(--indigo); }

  /* severity + confidence badges */
  .badge { display:inline-block; font-family:var(--mono); font-size:10px; font-weight:500; padding:2px 8px; border-radius:4px; white-space:nowrap; }
  .sev-critical { background:var(--alert); color:#fff; }
  .sev-high { background:var(--warn); color:#fff; }
  .sev-medium { background:transparent; border:1px solid var(--amber); color:var(--amber); }
  .sev-low { background:transparent; border:1px solid var(--verify); color:var(--verify); }
  .sev-info { background:transparent; border:1px solid var(--muted); color:var(--muted); }
  .sev-unknown { background:transparent; border:1px solid var(--line2); color:var(--tx3); }
  .conf-confirmed { background:transparent; border:1px solid var(--verify); color:var(--verify); }
  .conf-inferred { background:transparent; border:1px solid var(--amber); color:var(--amber); }
  .sevgrid { display:flex; flex-wrap:wrap; gap:8px; margin:6px 0 16px; }
  .sevcard { border:1px solid var(--line); border-radius:6px; background:var(--card); padding:6px 12px; min-width:5rem;
             text-align:center; text-decoration:none; color:inherit; cursor:pointer; display:block; transition:border-color .12s; }
  .sevcard:hover { border-color:var(--indigo); }
  .sevcard .n { font-size:1.2rem; font-weight:700; display:block; line-height:1.4; }
  tr.sev-hit > td { background:var(--indigo-soft); }
  tr.sev-hit > td:first-child { box-shadow:inset 3px 0 0 var(--indigo); }
  .sevbar { display:flex; gap:6px; flex-wrap:wrap; margin:4px 0 12px; }

  /* tables */
  header.meta, dl.info { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:12px 16px; margin:0 0 14px;
                display:grid; grid-template-columns:max-content 1fr; gap:.3rem 1rem; }
  header.meta dt, dl.info dt { font-weight:600; color:var(--tx2); font-size:13px; }
  header.meta dd, dl.info dd { margin:0; }
  table { border-collapse:collapse; width:100%; margin:8px 0 14px; background:var(--card); border:1px solid var(--line); border-radius:6px; overflow:hidden; }
  th, td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--line); vertical-align:top; font-size:12px; }
  th { font-family:var(--mono); font-size:10px; text-transform:uppercase; letter-spacing:.04em; color:var(--tx2); background:var(--muted-soft); }
  tr:last-child td { border-bottom:none; }

  /* article cluster */
  article.cluster { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:14px 18px; margin:12px 0; }
  article.cluster header { display:flex; gap:14px; flex-wrap:wrap; align-items:baseline; margin-bottom:6px; color:var(--tx2); font-size:12px; font-family:var(--mono); }
  article.cluster h3 { font-size:15px; font-weight:700; margin:0 0 4px; }
  article.cluster h4 { font-size:12px; font-family:var(--mono); text-transform:uppercase; letter-spacing:.04em; color:var(--tx2); margin:14px 0 4px; }
  article.cluster-noise { opacity:.78; border-style:dashed; }
  .narrative p { margin:0 0 .7rem; max-width:var(--maxw); }
  ul.open-q, ul.reco { padding-left:20px; }
  ul.open-q li, ul.reco li { margin-bottom:.3rem; max-width:var(--maxw); }
  dl.scope { display:grid; grid-template-columns:max-content 1fr; gap:.3rem 1rem; margin:.6rem 0; }
  dl.scope dt { font-weight:600; color:var(--tx2); }
  dl.scope dd { margin:0; }
  .scope-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin:6px 0 14px; }
  .scope-card { border:1px solid var(--line); border-radius:8px; padding:12px 16px; background:var(--card); }
  .scope-card .lab { font-size:11px; font-family:var(--mono); text-transform:uppercase; letter-spacing:.05em; color:var(--tx2); margin-bottom:6px; }
  .scope-card .host { font-family:var(--mono); font-weight:500; }
  .scope-card.confirmed { border-left:3px solid var(--alert); }
  @media (max-width:640px){ .scope-grid { grid-template-columns:1fr; } }

  .note { background:var(--indigo-soft); border:1px solid var(--indigo); border-radius:6px; padding:.6rem .9rem; margin:.6rem 0; font-size:.85rem; max-width:var(--maxw); }
  .annot-note { font-size:12px; color:var(--tx3); margin:6px 0 14px; max-width:var(--maxw); }
  .derived-note { font-size:12px; color:var(--tx3); }
  .disclaimer { background:var(--warn-soft); border:1px solid var(--warn); border-radius:6px; padding:.6rem .9rem; margin:.6rem 0; font-size:.85rem; max-width:var(--maxw); }
  .active { background:var(--muted-soft); border:1px solid var(--line); border-radius:6px; padding:.5rem .8rem; margin:.5rem 0; font-size:.85rem; }
  .active .q { font-weight:600; }
  .active pre { background:var(--ink); color:#e6e8eb; padding:.5rem .7rem; border-radius:4px; overflow-x:auto; margin:.3rem 0; font-size:11px; }
  .exec-brief { background:var(--indigo-soft); border-left:4px solid var(--indigo); border-radius:0 6px 6px 0; padding:.8rem 1.1rem; margin:.6rem 0 1rem; }
  .exec-brief h3 { margin:0 0 .6rem; font-size:.78rem; color:var(--indigo); text-transform:uppercase; letter-spacing:.04em; }
  .exec-brief ul { margin:0; padding-left:1.2rem; }
  .exec-brief li { margin-bottom:.35rem; }
  details { border:1px solid var(--line); border-radius:8px; margin:10px 0; background:var(--card); }
  details > summary { cursor:pointer; padding:10px 16px; font-weight:600; font-size:13px; list-style:none; color:var(--tx2); }
  details > summary::-webkit-details-marker { display:none; }
  details > summary::before { content:"▸ "; color:var(--indigo); }
  details[open] > summary::before { content:"▾ "; }
  details .body, details > *:not(summary) { padding:0 16px 12px; }
  details.noise-group > *:not(summary), details.ioc-noise > *:not(summary) { padding:0 16px 8px; }
  .oq-critical { border-left:4px solid var(--alert); padding-left:.6rem; }
  .oq-needs { border-left:4px solid var(--amber); padding-left:.6rem; }
  .oq-supp { color:var(--tx3); }
  footer.audit { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:12px 16px; margin-top:16px;
                 display:grid; grid-template-columns:max-content 1fr; gap:.2rem 1rem; font-size:12px; color:var(--tx2); }
  footer.audit dt { font-weight:600; }
  footer.audit dd { margin:0; font-family:var(--mono); }

  @media print {
    nav.toc { display:none; }
    .layout { display:block; max-width:none; }
    main { padding:0; }
    details { border:none; }
    details > summary::before { content:""; }
    details > *:not(summary) { padding:0; }
    body { font-size:11pt; background:#fff; color:#000; }
    .verdict, .step, article.cluster { break-inside:avoid; }
    .classbar { background:#000 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
    .verdict, .badge, .chip, .tamper, .scope-card { -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  }
</style>
</head>
<body>
<div class="layout">

  <nav class="toc">
    <div class="brand">TLVB<small>{{.Dict.BrandSub}}</small></div>
    <a href="#caseinfo">{{.Dict.CaseInformation}}</a>
    <div class="layer-label">{{.Dict.NavExec}}</div>
    {{if .Verdict}}<a href="#verdict">{{.Dict.NavVerdict}}</a>{{end}}
    {{if .Case.OverallStory}}<a href="#summary">{{.Dict.NavSummary}}</a>{{end}}
    <div class="layer-label">{{.Dict.NavDetails}}</div>
    {{if or .Story .IntrusionPath}}<a href="#story">{{.Dict.NavStory}}</a>{{end}}
    {{if .Scope}}<a href="#scope">{{.Dict.NavScope}}</a>{{end}}
    {{if .Reco}}<a href="#reco">{{.Dict.NavReco}}</a>{{end}}
    <a href="#open">{{.Dict.NavOpen}}</a>
    <div class="layer-label">{{.Dict.NavAnalyst}}</div>
    <a href="#clusters">{{.Dict.NavClusters}}</a>
    {{if .Case.MITREMapping}}<a href="#mitre">{{.Dict.NavMitre}}</a>{{end}}
    <a href="#ioc">{{.Dict.NavIOC}}</a>
    <a href="#evidence">{{.Dict.NavEvidence}}</a>
  </nav>

  <main>
    <div class="classbar">{{.Classification}}</div>
    <h1 class="title">{{.Dict.ReportTitle}}</h1>
    <p class="subtitle">{{.Dict.Subtitle}}{{if .Meta}}{{if .Meta.DisplayName}} — {{.Meta.DisplayName}}{{end}}{{end}}</p>
    <div class="docmeta">case: {{.Case.CaseID}} · {{.Dict.Generated}} {{.GeneratedAt}} · TZ {{.Timezone}} · {{.Dict.Examiner}}: {{.Examiner}}{{if .Case.ModelID}} · {{.Case.ModelID}}{{end}}</div>

    {{/* ===== Case Information ===== */}}
    <section id="caseinfo">
      <div class="eyebrow">Case</div>
      <h2 class="sec">{{.Dict.CaseInformation}}</h2>
      <dl class="info">
        <dt>{{.Dict.Case}}</dt><dd>{{.Case.CaseID}}</dd>
        {{if .Meta}}{{if .Meta.DisplayName}}<dt>{{.Dict.DisplayName}}</dt><dd>{{.Meta.DisplayName}}</dd>{{end}}
        {{if .Meta.Status}}<dt>{{.Dict.Status}}</dt><dd>{{.Meta.Status}}</dd>{{end}}{{end}}
        <dt>{{.Dict.AnalysisDate}}</dt><dd>{{.GeneratedAt}}</dd>
        <dt>{{.Dict.TotalFindings}}</dt><dd>{{.Case.TotalFindings}}</dd>
        <dt>{{.Dict.ClusterCount}}</dt><dd>{{.Case.ClusterCount}}</dd>
        {{if .Meta}}{{if .Meta.Notes}}<dt>{{.Dict.Notes}}</dt><dd>{{.Meta.Notes}}</dd>{{end}}{{end}}
      </dl>
      <p class="muted">{{.Dict.ScopeBody}}</p>
    </section>

    <div class="layer-divider"><span class="lt">— {{.Dict.NavExec}} —</span></div>

    {{/* ===== VERDICT + immediate actions (eye-catch) ===== */}}
    {{if .Verdict}}
    <section id="verdict">
      <div class="eyebrow">Verdict</div>
      <div class="verdict v-{{.Verdict.StateClass}}">
        <div class="vhead">
          <span class="vstate">{{.Verdict.State}}</span>
          {{range .Verdict.Pills}}<span class="vpill">{{.}}</span>{{end}}
        </div>
        <div class="vgrid">
          <div class="vcell"><div class="k">{{.Dict.VEarliest}}</div><div class="v">{{.Verdict.Earliest}}</div></div>
          <div class="vcell"><div class="k">{{.Dict.VDwell}}</div><div class="v">{{.Verdict.Dwell}}</div></div>
          <div class="vcell"><div class="k">{{.Dict.VHosts}}</div><div class="v">{{.Verdict.Hosts}}</div></div>
          <div class="vcell"><div class="k">{{.Dict.VContainment}}</div><div class="v">{{.Verdict.Containment}}</div></div>
        </div>
      </div>
      {{if .Reco}}{{if .Reco.Containment}}
      <div class="actions">
        <h3>{{.Dict.ActionsHeading}}</h3>
        <ol>{{range .Reco.Containment}}<li>{{.}}</li>{{end}}</ol>
      </div>
      {{end}}{{end}}
      <div class="annot-note">{{.Dict.DerivedNote}}</div>
    </section>
    {{end}}

    {{/* ===== Executive Summary (two layers) ===== */}}
    {{if .Case.OverallStory}}
    <section id="summary">
      <div class="eyebrow">Summary</div>
      <h2 class="sec">{{.Dict.ExecutiveSummary}}</h2>
      {{if .IsExecutiveSummaryFallback}}<div class="disclaimer">{{.Dict.ExecSummaryFallbackWarning}}</div>{{end}}
      {{if eq .Case.TimelineReliability "unreliable"}}
      <div class="disclaimer"><strong>{{.Dict.TimelineUnreliableHeading}}</strong>
        <ul>{{range .Case.TimelineNotes}}<li>{{.}}</li>{{end}}</ul></div>
      {{end}}
      {{if .Case.UngroundedMentions}}<div class="disclaimer">{{.Dict.UngroundedHeading}} {{join .Case.UngroundedMentions}}</div>{{end}}
      {{if .ExecBrief}}
      <div class="exec-brief">
        <h3>{{.Dict.ExecBriefHeading}}</h3>
        <ul>{{range bullets .ExecBrief}}<li>{{.}}</li>{{end}}</ul>
      </div>
      <details open>
        <summary>{{.Dict.TechDetailHeading}}</summary>
        <div class="narrative">{{range para .TechSummary}}<p>{{.}}</p>{{end}}</div>
      </details>
      {{else}}
      <div class="narrative">{{range para .TechSummary}}<p>{{.}}</p>{{end}}</div>
      {{end}}
    </section>
    {{end}}

    {{if .Severity}}
    <section id="severity">
      <h3 class="sub">{{.Dict.SeveritySummary}}</h3>
      <div class="sevgrid">
        {{range .Severity}}<a class="sevcard" href="#clusters" data-sevcls="{{sevClass .Severity}}" title="{{$.Dict.SevJumpHint}}"><span class="n">{{.Count}}</span><span class="badge {{sevClass .Severity}}">{{sevLabel .Severity}}</span></a>{{end}}
      </div>
    </section>
    {{end}}

    <div class="layer-divider"><span class="lt">— {{.Dict.NavDetails}} —</span></div>

    {{/* ===== ATTACK STORY — intrusion path is the first step, then the attack
           clusters; the supporting evidence (relevant cluster + earliest events)
           is inlined right after the timeline so the section is self-contained. ===== */}}
    {{if or .Story .IntrusionPath}}
    <section id="story">
      <div class="eyebrow">What happened</div>
      <h2 class="sec">{{.Dict.AttackStorySec}}</h2>
      {{if eq .Case.TimelineReliability "unreliable"}}
      <div class="tamper">
        <span class="ic">⏰</span>
        <span class="tx"><b>{{.Dict.TimelineUnreliableHeading}}</b> {{range .Case.TimelineNotes}}{{.}} {{end}}</span>
      </div>
      {{end}}
      {{if .StoryReordered}}<div class="annot-note">{{.Dict.StoryLogicalOrderNote}}</div>{{end}}
      <div class="storyflow">
        {{if .IntrusionPath}}
        <div class="step step-intrusion">
          <span class="node"></span>
          <div class="act">{{.Dict.IntrusionPathSec}}</div>
          <div class="desc">{{.IntrusionPath}}</div>
          {{if .IntrusionChips}}
          <div class="chips">{{range .IntrusionChips}}<span class="chip tech" title="{{.Title}}">{{.Label}}</span>{{end}}</div>
          {{end}}
        </div>
        {{end}}
        {{range .Story}}
        {{if .GapBefore}}<div class="gap-marker"><div class="gtx">〜 {{.GapBefore}} 〜</div></div>{{end}}
        <div class="step step-{{.WorstSev}}">
          <span class="node"></span>
          <div class="when">{{if .HasTS}}{{fmtTS .StartTS}} ~ {{fmtTS .EndTS}}{{end}}</div>
          <div class="act">#{{.ID}} — {{phaseLabel .AttackPhase}}</div>
          {{if .Desc}}<div class="desc">{{.Desc}}</div>{{end}}
          <div class="chips">
            {{range .Chips}}<span class="chip tech" title="{{.Title}}">{{.Label}}</span>{{end}}
            {{if .WorstSev}}<span class="badge {{sevClass .WorstSev}}">{{sevLabel .WorstSev}}</span>{{end}}
          </div>
        </div>
        {{end}}
      </div>
      {{if .IntrusionPath}}<div class="annot-note">{{.Dict.DerivedNote}}</div>{{end}}
    </section>
    {{end}}

    {{/* ===== Affected Scope ===== */}}
    {{if .Scope}}
    <section id="scope">
      <div class="eyebrow">Affected scope</div>
      <h2 class="sec">{{.Dict.AffectedScopeSec}}</h2>
      <dl class="scope">
        <dt>{{.Dict.ScopeHosts}}</dt><dd>{{if .Scope.Hosts}}{{join .Scope.Hosts}}{{else}}<span class="muted">—</span>{{end}}</dd>
        <dt>{{.Dict.ScopeAccounts}}</dt><dd>{{if .Scope.Accounts}}{{join .Scope.Accounts}}{{else}}<span class="muted">—</span>{{end}}</dd>
        <dt>{{.Dict.ScopeData}}</dt><dd>{{if .Scope.DataAtRisk}}{{join .Scope.DataAtRisk}}{{else}}<span class="muted">—</span>{{end}}</dd>
      </dl>
      <div class="annot-note">{{.Dict.DerivedNote}}</div>
    </section>
    {{end}}

    {{/* ===== 9. Recommendations ===== */}}
    {{if .Reco}}
    <section id="reco">
      <div class="eyebrow">Recommendations</div>
      <h2 class="sec">{{.Dict.RecommendationsSec}}</h2>
      {{if .Reco.Containment}}<h3 class="sub">{{.Dict.RecContainment}}</h3><ul class="reco">{{range .Reco.Containment}}<li>{{.}}</li>{{end}}</ul>{{end}}
      {{if .Reco.Eradication}}<h3 class="sub">{{.Dict.RecEradication}}</h3><ul class="reco">{{range .Reco.Eradication}}<li>{{.}}</li>{{end}}</ul>{{end}}
      {{if .Reco.Recovery}}<h3 class="sub">{{.Dict.RecRecovery}}</h3><ul class="reco">{{range .Reco.Recovery}}<li>{{.}}</li>{{end}}</ul>{{end}}
      <div class="annot-note">{{.Dict.DerivedNote}}</div>
    </section>
    {{end}}

    {{/* ===== 10. Open questions ===== */}}
    {{if or (not .Case.OpenQuestionsSynth.IsEmpty) .Case.OpenQuestions}}
    <section id="open">
      <div class="eyebrow">Open questions</div>
      <h2 class="sec">{{.Dict.CaseOpenQuestions}}</h2>
      {{if not .Case.OpenQuestionsSynth.IsEmpty}}
        {{if .Case.OpenQuestionsSynth.Critical}}<h3 class="sub oq-critical">{{.Dict.OQCritical}}</h3><ol class="open-q">{{range .Case.OpenQuestionsSynth.Critical}}<li>{{.}}</li>{{end}}</ol>{{end}}
        {{if .Case.OpenQuestionsSynth.NeedsCollection}}<h3 class="sub oq-needs">{{.Dict.OQNeedsCollection}}</h3><ul class="open-q">{{range .Case.OpenQuestionsSynth.NeedsCollection}}<li>{{.}}</li>{{end}}</ul>{{end}}
        {{if .Case.OpenQuestionsSynth.Supplementary}}<details><summary class="oq-supp">{{.Dict.OQSupplementary}} ({{len .Case.OpenQuestionsSynth.Supplementary}})</summary><ul class="open-q">{{range .Case.OpenQuestionsSynth.Supplementary}}<li>{{.}}</li>{{end}}</ul></details>{{end}}
      {{else}}
      <ul class="open-q">{{range .Case.OpenQuestions}}<li>{{.}}</li>{{end}}</ul>
      {{end}}
    </section>
    {{end}}

    <div class="layer-divider"><span class="lt">— {{.Dict.NavAnalyst}} —</span></div>

    {{/* ===== 7. Findings by cluster ===== */}}
    <section id="clusters">
      <div class="eyebrow">Detail</div>
      <h2 class="sec">{{.Dict.AttackActivity}}</h2>
      {{if not .AttackClusters}}<p class="empty">{{.Dict.None}}</p>{{end}}
      {{range .AttackClusters}}{{template "clusterArticle" .}}{{end}}
      {{if .NoiseClusters}}
      <details class="noise-group">
        <summary>{{.Dict.NoiseClustersSummary}} ({{len .NoiseClusters}})</summary>
        {{range .NoiseClusters}}{{template "clusterArticle" .}}{{end}}
      </details>
      {{end}}
    </section>

    {{/* ===== MITRE ATT&CK ===== */}}
    {{if .Case.MITREMapping}}
    <section id="mitre">
      <div class="eyebrow">ATT&CK</div>
      <h2 class="sec">{{.Dict.MITREMapping}}</h2>
      <table>
        <thead><tr><th>{{.Dict.Technique}}</th><th>{{.Dict.Tactic}}</th><th>{{.Dict.FindingCount}}</th><th>{{.Dict.ClusterIDs}}</th></tr></thead>
        <tbody>
          {{range .Case.MITREMapping}}
          <tr><td><a href="https://attack.mitre.org/techniques/{{.Technique}}/" target="_blank" rel="noopener">{{.Technique}}</a></td>
              <td>{{.Tactic}}</td><td>{{.FindingCount}}</td>
              <td>{{range $i, $cid := .ClusterIDs}}{{if $i}}, {{end}}#{{$cid}}{{end}}</td></tr>
          {{end}}
        </tbody>
      </table>
      {{if .Case.MITREUnconfirmed}}
      <h3 class="sub">{{.Dict.MITREUnconfirmedHeading}}</h3>
      <p class="derived-note">{{.Dict.MITREUnconfirmedNote}}</p>
      {{if .Case.MITREDemotionNotes}}<ul class="derived-note">{{range .Case.MITREDemotionNotes}}<li>{{.}}</li>{{end}}</ul>{{end}}
      <table>
        <thead><tr><th>{{.Dict.Technique}}</th><th>{{.Dict.ClusterIDs}}</th></tr></thead>
        <tbody>
          {{range .Case.MITREUnconfirmed}}
          <tr><td><a href="https://attack.mitre.org/techniques/{{.Technique}}/" target="_blank" rel="noopener">{{.Technique}}</a></td>
              <td>{{range $i, $cid := .ClusterIDs}}{{if $i}}, {{end}}#{{$cid}}{{end}}</td></tr>
          {{end}}
        </tbody>
      </table>
      {{end}}
    </section>
    {{end}}

    {{/* ===== 8. Indicators of Compromise (three tiers) ===== */}}
    <section id="ioc">
      <div class="eyebrow">Indicators</div>
      <h2 class="sec">{{.Dict.IOCSection}}</h2>
      {{if or .ConfirmedIOCs .SuspectedIOCs .NoiseIOCs}}
      {{if .ConfirmedIOCs}}
      <h3 class="sub">✅ {{.Dict.IOCConfirmed}}</h3>
      <table>
        <thead><tr><th>{{.Dict.IOCType}}</th><th>{{.Dict.IOCValue}}</th><th>{{.Dict.ArtifactName}}</th><th>{{.Dict.IOCCount}}</th></tr></thead>
        <tbody>{{range .ConfirmedIOCs}}<tr><td>{{.Type}}</td><td class="mono">{{.Value}}</td><td>{{.Artifact}}</td><td>{{.Count}}</td></tr>{{end}}</tbody>
      </table>
      {{end}}
      {{if .SuspectedIOCs}}
      <h3 class="sub">⚠️ {{.Dict.IOCSuspected}}</h3>
      <table>
        <thead><tr><th>{{.Dict.IOCType}}</th><th>{{.Dict.IOCValue}}</th><th>{{.Dict.ArtifactName}}</th><th>{{.Dict.IOCCount}}</th></tr></thead>
        <tbody>{{range .SuspectedIOCs}}<tr><td>{{.Type}}</td><td class="mono">{{.Value}}</td><td>{{.Artifact}}</td><td>{{.Count}}</td></tr>{{end}}</tbody>
      </table>
      {{end}}
      {{if .NoiseIOCs}}
      <details class="ioc-noise">
        <summary>🔇 {{.Dict.IOCNoiseHidden}} ({{len .NoiseIOCs}})</summary>
        <table>
          <thead><tr><th>{{.Dict.IOCType}}</th><th>{{.Dict.IOCValue}}</th><th>{{.Dict.ArtifactName}}</th><th>{{.Dict.IOCCount}}</th></tr></thead>
          <tbody>{{range .NoiseIOCs}}<tr><td>{{.Type}}</td><td class="mono">{{.Value}}</td><td>{{.Artifact}}</td><td>{{.Count}}</td></tr>{{end}}</tbody>
        </table>
      </details>
      {{end}}
      {{else}}<p class="empty">{{.Dict.NoIOC}}</p>{{end}}
    </section>

    {{/* ===== Appendix: evidence / methodology / timeline / audit ===== */}}
    <section id="evidence">
      <div class="eyebrow">Appendix</div>
      <h2 class="sec">{{.Dict.NavEvidence}}</h2>

      {{if .Meta}}
      <details open>
        <summary>{{.Dict.EvidenceChain}}</summary>
        {{if .Meta.Evidence}}
        <table>
          <thead><tr><th>{{.Dict.EvidenceID}}</th><th>{{.Dict.SourcePath}}</th><th>{{.Dict.SHA256}}</th>
              <th>{{.Dict.Size}}</th><th>{{.Dict.CollectedAt}}</th><th>{{.Dict.EvidenceTypeCol}}</th><th>{{.Dict.Host}}</th></tr></thead>
          <tbody>
            {{range .Meta.Evidence}}
            <tr><td>{{.EvidenceID}}</td><td class="mono">{{.SourcePath}}</td><td><code>{{if .SHA256}}{{.SHA256}}{{else}}—{{end}}</code></td>
                <td>{{humanBytes .SizeBytes}}</td><td>{{if .RegisteredAt.IsZero}}—{{else}}{{fmtTS .RegisteredAt}}{{end}}</td>
                <td>{{if .EvidenceType}}{{.EvidenceType}}{{else}}—{{end}}</td><td>{{if .SourceHost}}{{.SourceHost}}{{else}}—{{end}}</td></tr>
            {{end}}
          </tbody>
        </table>
        <p class="annot-note">{{.Dict.IntegrityNote}}</p>
        {{else}}<p class="empty">{{.Dict.None}}</p>{{end}}
        {{if .Meta.ArtifactCounts}}
        <h3 class="sub">{{.Dict.ArtifactCoverage}}</h3>
        <table>
          <thead><tr><th>{{.Dict.ArtifactName}}</th><th>{{.Dict.EventCount}}</th></tr></thead>
          <tbody>{{range .Meta.ArtifactCounts}}<tr><td>{{.ArtifactID}}</td><td>{{.EventCount}}</td></tr>{{end}}
            <tr><th>{{.Dict.TotalEvents}}</th><th>{{.Meta.TotalEvents}}</th></tr></tbody>
        </table>
        {{end}}
      </details>
      {{end}}

      <details>
        <summary>{{.Dict.Methodology}}</summary>
        <p class="muted">{{.Dict.MethodologyBody}}</p>
        <p class="muted">{{.Dict.Limitations}}</p>
        {{if .Meta}}{{if .Meta.CollectionGaps}}
        <h3 class="sub">{{.Dict.CompletenessSec}}</h3>
        <p class="muted">{{.Dict.CompletenessBody}}</p>
        <table>
          <thead><tr><th>{{.Dict.CompletenessInput}}</th><th>{{.Dict.CompletenessCapability}}</th><th>{{.Dict.CompletenessStatus}}</th></tr></thead>
          <tbody>{{range .Meta.CollectionGaps}}<tr><td>{{.Label}}</td><td>{{.Capability}}</td><td>{{if .Present}}{{$.Dict.CompletenessPresent}}{{else}}{{$.Dict.CompletenessMissing}} ({{.Importance}}){{end}}</td></tr>{{end}}</tbody>
        </table>
        {{end}}{{end}}
        <div class="disclaimer">{{.Dict.AIDisclaimer}}</div>
      </details>

      {{if .Timeline}}
      <details>
        <summary>{{.Dict.TimelineSection}}</summary>
        <table>
          <thead><tr><th>{{.Dict.TimeCol}} ({{.Timezone}})</th><th>{{.Dict.Severity}}</th><th>{{.Dict.ArtifactName}}</th>
              <th>{{.Dict.EventTypeCol}}</th><th>{{.Dict.Source}}</th><th>{{.Dict.Title}}</th></tr></thead>
          <tbody>
            {{range .Timeline}}
            <tr><td class="mono">{{fmtTS .TS}}</td><td><span class="badge {{sevClass .Severity}}">{{sevLabel .Severity}}</span></td>
                <td>{{.Artifact}}</td><td>{{.EventType}}</td><td>{{.Source}}</td><td>{{.Title}}</td></tr>
            {{end}}
          </tbody>
        </table>
      </details>
      {{end}}

      <footer class="audit">
        <dt>{{.Dict.LLMCalls}}</dt><dd>{{.Case.Audit.LLMCallsTotal}}</dd>
        <dt>{{.Dict.LLMDuration}}</dt><dd>{{printf "%.1f" .Case.Audit.LLMDurationS}}</dd>
        {{if gt .Case.Audit.InputTokensTotal 0}}<dt>{{.Dict.InputTokens}}</dt><dd>{{.Case.Audit.InputTokensTotal}}</dd>{{end}}
        {{if gt .Case.Audit.OutputTokensTotal 0}}<dt>{{.Dict.OutputTokens}}</dt><dd>{{.Case.Audit.OutputTokensTotal}}</dd>{{end}}
        {{if .Case.Audit.SkillSHA256}}<dt>{{.Dict.SkillSHA}}</dt><dd>{{truncate .Case.Audit.SkillSHA256 16}}...</dd>{{end}}
      </footer>
    </section>

  </main>
</div>

{{define "clusterArticle"}}
<article class="cluster{{if .C.IsLikelyNoise}} cluster-noise{{end}}" id="cluster-{{.C.ID}}">
  <h3>#{{if .C.StepNo}}{{.C.StepNo}}{{else}}{{.C.ID}}{{end}} — {{phaseLabel .C.AttackPhase}}
    {{if .C.IsLikelyNoise}}<span class="badge sev-info">{{.Dict.NoiseBadge}}</span>{{else if .C.WorstSeverity}}<span class="badge {{sevClass .C.WorstSeverity}}">{{sevLabel .C.WorstSeverity}}</span>{{end}}
  </h3>
  <header>
    <span><strong>{{.Dict.Window}}:</strong> {{fmtTS .C.StartTS}} ~ {{fmtTS .C.EndTS}}</span>
    <span>{{.Dict.FindingCount}}: {{len .C.Findings}}</span>
    {{if .C.MITRETechniques}}<span>MITRE: {{join .C.MITRETechniques}}</span>{{end}}
  </header>
  {{if .C.Narrative}}
  <h4>{{.Dict.Narrative}}</h4>
  <div class="narrative">{{range para .C.Narrative}}<p>{{.}}</p>{{end}}</div>
  {{end}}
  {{if .C.Findings}}
  <h4>{{.Dict.Findings}}</h4>
  <table>
    <thead><tr><th>{{.Dict.Severity}}</th><th>{{.Dict.Source}}</th><th>{{.Dict.ConfidenceCol}}</th><th>{{.Dict.RuleID}}</th>
        <th>{{.Dict.Title}}</th><th>{{.Dict.FirstSeen}}</th><th>{{.Dict.Artifacts}}</th><th>{{.Dict.EvidenceCountCol}}</th></tr></thead>
    <tbody>
      {{range .C.Findings}}
      <tr><td><span class="badge {{sevClass .Severity}}">{{sevLabel .Severity}}</span></td><td>{{.Source}}</td>
          <td>{{if .Confidence}}<span class="badge conf-{{.Confidence}}">{{.ConfidenceLabel}}</span>{{else}}<span class="muted">—</span>{{end}}</td>
          <td><code>{{.RuleID}}</code></td><td>{{.Title}}</td>
          <td>{{if .HasTS}}{{fmtTS .FirstSeen}}{{else}}<span class="muted">—</span>{{end}}</td>
          <td>{{if .Artifacts}}{{join .Artifacts}}{{else}}<span class="muted">—</span>{{end}}</td>
          <td>{{if .EvidenceCount}}{{.EvidenceCount}}{{else}}<span class="muted">—</span>{{end}}</td></tr>
      {{end}}
    </tbody>
  </table>
  {{end}}
  {{if .C.ActiveSearch}}
  <h4>{{.Dict.ActiveSearch}}</h4>
  {{range .C.ActiveSearch}}
  <div class="active">
    <div class="q">{{.Question}}</div>
    {{if .SQL}}<pre><code>{{.SQL}}</code></pre>{{end}}
    <div><strong>{{$.Dict.HitsCol}}:</strong> {{.Hits}}</div>
    {{if .Answer}}<div><strong>{{$.Dict.AnswerCol}}:</strong> {{.Answer}}</div>{{end}}
    {{if .Error}}<div class="muted">{{.Error}}</div>{{end}}
  </div>
  {{end}}
  {{end}}
  {{if .C.OpenQuestions}}
  <h4>{{.Dict.OpenQuestions}}</h4>
  <ul class="open-q">{{range .C.OpenQuestions}}<li>{{.}}</li>{{end}}</ul>
  {{end}}
</article>
{{end}}

<script>
// Severity-summary navigation: clicking a severity card scrolls to and
// highlights the matching findings in the cluster-detail section (opening any
// collapsed group). Progressive enhancement — without JS the card's href still
// jumps to the findings section. No external assets; the file stays portable.
(function () {
  var sec = document.getElementById('clusters');
  if (!sec) return;
  function clearHits() {
    var hit = document.querySelectorAll('tr.sev-hit');
    for (var i = 0; i < hit.length; i++) hit[i].classList.remove('sev-hit');
  }
  var cards = document.querySelectorAll('a.sevcard[data-sevcls]');
  for (var c = 0; c < cards.length; c++) {
    cards[c].addEventListener('click', function (ev) {
      var cls = this.getAttribute('data-sevcls');
      var all = sec.querySelectorAll('tr');
      var rows = [];
      for (var i = 0; i < all.length; i++) {
        if (all[i].querySelector('td .badge.' + cls)) rows.push(all[i]);
      }
      if (!rows.length) return; // let the href fall through to #clusters
      ev.preventDefault();
      clearHits();
      for (var j = 0; j < rows.length; j++) {
        rows[j].classList.add('sev-hit');
        var d = rows[j].closest('details');
        while (d) { d.open = true; d = d.parentElement ? d.parentElement.closest('details') : null; }
      }
      rows[0].scrollIntoView({ behavior: 'smooth', block: 'center' });
    });
  }
})();
</script>

</body>
</html>
`
