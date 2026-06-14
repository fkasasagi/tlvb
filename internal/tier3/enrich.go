package tier3

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// enrich.go reads the per-finding evidence files written by Tier 1A/1B
// (findings/by-rule/**.json and findings/by-skill/*.json) and derives the
// extra material a forensic report needs but synthesis.json drops:
//
//   - severity counts (dashboard)
//   - per-finding evidence detail (first-seen, artifacts, evidence count)
//   - a chronological "key events" timeline (one row per finding)
//   - an Indicators of Compromise (IOC) table
//
// All of this is best-effort: a missing/unreadable findings dir simply yields
// empty enrichment, and the report still renders from synthesis.json alone.

// findingEvidence is the on-disk Tier 1A evidence row (tier1a.EvidenceRef).
// ts_utc is omitted entirely for artifacts that emit NULL (shimcache etc.),
// so a zero TsUTC means "no timestamp".
type findingEvidence struct {
	AuditID    string         `json:"audit_id"`
	TsUTC      time.Time      `json:"ts_utc"`
	ArtifactID string         `json:"artifact_id"`
	EventType  string         `json:"event_type"`
	Extra      map[string]any `json:"extra"`
}

func (e findingEvidence) hasTS() bool { return !e.TsUTC.IsZero() }

// diskRuleFinding is one Tier 1A by-rule/*.json file (tier1a.Finding). The
// severity / title / MITRE live under rule_meta.
type diskRuleFinding struct {
	RuleID     string `json:"rule_id"`
	RuleSource string `json:"rule_source"`
	RuleMeta   struct {
		Title           string   `json:"title"`
		Level           string   `json:"level"`
		MITRETactics    []string `json:"mitre_tactics"`
		MITRETechniques []string `json:"mitre_techniques"`
	} `json:"rule_meta"`
	Evidence []findingEvidence `json:"evidence"`
}

// diskSkillFile is one Tier 1B by-skill/*.json file (tier1b.AnomalyReport).
// Anomaly findings carry only audit_ids (no inline evidence rows / timestamps),
// so they contribute to severity counts but not to the timeline / IOC tables.
type diskSkillFile struct {
	Skill    string `json:"skill"`
	Findings []struct {
		Summary  string `json:"summary"`
		Severity string `json:"severity"`
		Lens     string `json:"lens"`
	} `json:"findings"`
}

// loadedFinding is the normalised in-memory shape after reading either source.
type loadedFinding struct {
	Source     string
	RuleID     string
	Title      string
	Severity   string
	Tactics    []string // mitre_tactics from rule_meta (by-rule only)
	Techniques []string // mitre_techniques from rule_meta (by-rule only)
	Evidence   []findingEvidence
}

// enrichment is the computed bundle handed to the renderer.
type enrichment struct {
	SeverityCounts []sevCount
	Timeline       []timelineRow
	IOCs           []iocRow
	MITRE          []mitreRow
	// detail keyed by "source\x00ruleid" and by normalised title for fallback.
	detailByKey   map[string]*findingDetail
	detailByTitle map[string]*findingDetail
}

type sevCount struct {
	Severity string
	Count    int
}

type timelineRow struct {
	TS        time.Time
	Artifact  string
	EventType string
	Source    string
	RuleID    string
	Severity  string
	Title     string
	Tactic    string
	Technique string
	Computer  string
	AuditID   string
}

type iocRow struct {
	Type     string // file/path | command | account | host | network | log-source
	Value    string
	Artifact string
	Count    int
	// Confidence buckets the IOC for the report's three-tier table:
	//   confirmed → extracted from a deterministic Tier 1A signature finding
	//   inferred  → extracted from a Tier 1B anomaly (LLM-judged) finding
	//   noise     → a known parser artifact / non-actionable value
	Confidence string
	// Class is the IOC-tab presentation bucket, orthogonal to Confidence
	// (which drives the report's confirmed/suspected/noise tiers):
	//   ioc        → a real indicator (host/account/command/file/network)
	//   source     → a data feed (log-source / channel), not an indicator
	//   provenance → detection metadata leaking as a value (Defender field
	//                labels, the detecting process) — context, not a threat IOC
	//   excluded   → parser noise / sysprep ghost — hidden by default
	Class    string
	tactics  map[string]bool // owning findings' mitre_tactics
	findings map[string]bool // owning findings' titles (for the "src" column)
}

// mitreRow aggregates one MITRE technique across findings. Derived
// deterministically from the rule corpus tags carried by each finding, so
// it is populated even when the Tier 2 LLM left synthesis.json's
// mitre_mapping empty.
type mitreRow struct {
	Tactic        string
	Technique     string
	FindingCount  int
	EvidenceCount int
	worstSeverity string // tracks the strongest finding severity for confidence
}

type findingDetail struct {
	FirstSeen     time.Time
	HasTS         bool
	Artifacts     []string
	EvidenceCount int
}

func detailKey(source, ruleID string) string {
	return strings.ToLower(source) + "\x00" + strings.ToLower(ruleID)
}

// loadEnrichment walks the findings dir. Returns a zero-value (but non-nil)
// enrichment when the dir is absent so callers can use it unconditionally.
func loadEnrichment(findingsDir string) *enrichment {
	en := &enrichment{
		detailByKey:   map[string]*findingDetail{},
		detailByTitle: map[string]*findingDetail{},
	}
	if findingsDir == "" {
		return en
	}
	findings := readFindings(findingsDir)

	sevTotals := map[string]int{}
	iocAgg := map[string]*iocRow{}     // key: type\x00value
	mitreAgg := map[string]*mitreRow{} // key: tactic\x00technique

	for _, f := range findings {
		sevTotals[normSeverity(f.Severity)]++

		// per-finding detail (first-seen, artifacts, evidence count) plus the
		// audit_id / computer of the earliest-stamped evidence (used by the
		// Web UI timeline + Review Gate 2).
		det := &findingDetail{}
		artSet := map[string]bool{}
		var earliestAudit, computer string
		findingConf := iocConfidenceForSource(f.Source)
		for _, ev := range f.Evidence {
			if ev.hasTS() {
				if !det.HasTS || ev.TsUTC.Before(det.FirstSeen) {
					det.FirstSeen = ev.TsUTC
					det.HasTS = true
					earliestAudit = ev.AuditID
				}
			}
			if ev.ArtifactID != "" {
				artSet[ev.ArtifactID] = true
			}
			if computer == "" {
				computer = evComputer(ev)
			}
			collectIOCs(iocAgg, ev, f.Tactics, f.Title, findingConf)
		}
		det.EvidenceCount = len(f.Evidence)
		det.Artifacts = sortedKeys(artSet)
		en.detailByKey[detailKey(f.Source, f.RuleID)] = det
		en.detailByTitle[strings.ToLower(strings.TrimSpace(f.Title))] = det

		// key-event timeline: one row per finding at its earliest evidence ts
		if det.HasTS {
			en.Timeline = append(en.Timeline, timelineRow{
				TS:        det.FirstSeen,
				Artifact:  firstOr(det.Artifacts, ""),
				EventType: firstEventType(f.Evidence),
				Source:    f.Source,
				RuleID:    f.RuleID,
				Severity:  normSeverity(f.Severity),
				Title:     f.Title,
				Tactic:    firstOr(f.Tactics, ""),
				Technique: firstOr(f.Techniques, ""),
				Computer:  computer,
				AuditID:   earliestAudit,
			})
		}

		// MITRE matrix: one entry per (tactic, technique). A finding with N
		// techniques and M tactics contributes to N×M cells; techniques with
		// no tactic land under "(unmapped)" so they still surface.
		tactics := f.Tactics
		if len(tactics) == 0 {
			tactics = []string{""}
		}
		for _, tech := range f.Techniques {
			for _, tac := range tactics {
				key := tac + "\x00" + tech
				m := mitreAgg[key]
				if m == nil {
					m = &mitreRow{Tactic: tac, Technique: tech}
					mitreAgg[key] = m
				}
				m.FindingCount++
				m.EvidenceCount += len(f.Evidence)
				if severityRank(f.Severity) > severityRank(m.worstSeverity) {
					m.worstSeverity = normSeverity(f.Severity)
				}
			}
		}
	}

	sort.Slice(en.Timeline, func(i, j int) bool { return en.Timeline[i].TS.Before(en.Timeline[j].TS) })
	en.SeverityCounts = orderSeverities(sevTotals)
	en.IOCs = finalizeIOCs(iocAgg)
	en.MITRE = finalizeMITRE(mitreAgg)
	return en
}

// readFindings reads by-rule/**/*.json and by-skill/*.json into a flat list.
func readFindings(findingsDir string) []loadedFinding {
	var out []loadedFinding

	byRule := filepath.Join(findingsDir, "by-rule")
	_ = filepath.WalkDir(byRule, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var rf diskRuleFinding
		if json.Unmarshal(body, &rf) != nil || rf.RuleID == "" {
			return nil
		}
		out = append(out, loadedFinding{
			Source:     orStr(rf.RuleSource, "rule"),
			RuleID:     rf.RuleID,
			Title:      rf.RuleMeta.Title,
			Severity:   rf.RuleMeta.Level,
			Tactics:    rf.RuleMeta.MITRETactics,
			Techniques: rf.RuleMeta.MITRETechniques,
			Evidence:   rf.Evidence,
		})
		return nil
	})

	bySkill := filepath.Join(findingsDir, "by-skill")
	if entries, err := os.ReadDir(bySkill); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			body, err := os.ReadFile(filepath.Join(bySkill, e.Name()))
			if err != nil {
				continue
			}
			var sf diskSkillFile
			if json.Unmarshal(body, &sf) != nil {
				continue
			}
			src := orStr(sf.Skill, "anomaly_hunter")
			for _, fn := range sf.Findings {
				out = append(out, loadedFinding{
					Source:   src,
					RuleID:   fn.Lens, // matches Tier 2 FindingRef.RuleID (lens id)
					Title:    fn.Summary,
					Severity: fn.Severity,
					// no inline evidence rows in the anomaly report
				})
			}
		}
	}
	return out
}

// iocKeyClass maps an evidence field key to an IOC type, or "" to skip it.
func iocKeyClass(key string) string {
	k := strings.ToLower(key)
	switch {
	case strings.Contains(k, "commandline") || strings.Contains(k, "command_line"):
		return "command"
	case strings.Contains(k, "image") || strings.Contains(k, "filename") ||
		strings.Contains(k, "newprocessname") || strings.Contains(k, "processname") ||
		strings.Contains(k, "targetobject") || strings.Contains(k, "application") ||
		k == "path" || strings.HasSuffix(k, "path") || strings.Contains(k, "exe"):
		return "file/path"
	case strings.Contains(k, "user") || strings.Contains(k, "account") || strings.Contains(k, "logonid"):
		return "account"
	case strings.Contains(k, "ipaddress") || strings.Contains(k, "ip_address") ||
		strings.Contains(k, "destinationip") || strings.Contains(k, "sourceip") ||
		strings.Contains(k, "url") || strings.Contains(k, "domain"):
		return "network"
	case strings.Contains(k, "computer") || strings.Contains(k, "workstation") ||
		strings.Contains(k, "host") || strings.Contains(k, "machine"):
		return "host"
	case k == "channel":
		return "log-source"
	default:
		return ""
	}
}

func collectIOCs(agg map[string]*iocRow, ev findingEvidence, tactics []string, findingLabel, findingConf string) {
	for k, v := range ev.Extra {
		cls := iocKeyClass(k)
		if cls == "" {
			continue
		}
		val := strings.TrimSpace(fmt.Sprintf("%v", v))
		if val == "" || val == "-" || val == "<nil>" || len(val) > 300 {
			continue
		}
		// Strip leak-y label prefixes (e.g. "Target: DOMAIN\\user") so the IOC
		// reads as a bare value and de-dups against the un-prefixed form.
		val = normalizeIOCValue(cls, val)
		// A value-level parser artifact (e.g. "LogonType 3") is noise no matter
		// which finding surfaced it — keep it out of the confirmed/suspected
		// tiers so it never lands on a blocklist.
		conf := findingConf
		if isParserNoise(cls, val) {
			conf = "noise"
		}
		key := cls + "\x00" + val
		r, ok := agg[key]
		if !ok {
			r = &iocRow{
				Type: cls, Value: val, Artifact: ev.ArtifactID, Count: 0,
				Confidence: conf,
				tactics:    map[string]bool{}, findings: map[string]bool{},
			}
			agg[key] = r
		}
		r.Count++
		r.Confidence = mergeIOCConfidence(r.Confidence, conf)
		for _, t := range tactics {
			if t = strings.TrimSpace(t); t != "" {
				r.tactics[t] = true
			}
		}
		if findingLabel = strings.TrimSpace(findingLabel); findingLabel != "" {
			r.findings[findingLabel] = true
		}
	}
}

// iocConfidenceForSource maps a finding source engine to the IOC confidence tier.
// Mirrors tier2.ProvenanceForSource: deterministic signature rules are
// "confirmed"; the LLM-judged anomaly lens is "inferred" (suspected).
func iocConfidenceForSource(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "anomaly_hunter", "tier1b":
		return "inferred"
	default: // sigma | hayabusa | stix | custom | rule
		return "confirmed"
	}
}

// noiseIOCValues are parser-emitted / non-actionable IOC values that must never
// appear in the confirmed or suspected tiers (report improvement Vol.2: a
// LogonType pushed to a blocklist is actively harmful). Matched case-insensitively
// against the trimmed value.
var noiseIOCValues = map[string]bool{
	"logontype 0":   true,
	"logontype 2":   true,
	"logontype 3":   true,
	"logontype 10":  true,
	"-\\-":          true,
	"\\":            true,
	"parse-pending": true,
	"n/a":           true,
}

// isParserNoise reports whether an IOC value is a known parser artifact rather
// than a real indicator.
func isParserNoise(iocType, value string) bool {
	return noiseIOCValues[strings.ToLower(strings.TrimSpace(value))]
}

// iocLabelPrefixes are label tokens that some Sigma/Defender rules prepend to an
// otherwise-clean value (an SQL/field-label leak), e.g. "Target: WIN\\Administrator".
// Stripped from account values so the IOC reads as a bare DOMAIN\user and de-dups
// against the un-prefixed occurrence.
var iocLabelPrefixes = []string{"target:", "source:", "account name:", "account:", "user:"}

// normalizeIOCValue cleans a raw IOC value before it becomes an aggregation key.
func normalizeIOCValue(cls, val string) string {
	if cls == "account" {
		lower := strings.ToLower(val)
		for _, p := range iocLabelPrefixes {
			if strings.HasPrefix(lower, p) {
				val = strings.TrimSpace(val[len(p):])
				break
			}
		}
	}
	return val
}

// provenanceValuePrefixes mark values that are detection metadata leaking into an
// IOC slot (a Defender field label, the detecting tool/process), not a threat
// indicator. Surfaced in the IOC tab's "provenance" bucket instead of confirmed.
var provenanceValuePrefixes = []string{
	"description:", "process (if real-time detection):", "process name:",
	"modifyingapplication:", "detection source:", "detection time:", "detection user:",
}

func isProvenanceValue(val string) bool {
	lower := strings.ToLower(strings.TrimSpace(val))
	for _, p := range provenanceValuePrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// sysprepGhostSIDs are the well-known service SIDs that, paired with a machine
// account ("\\MINWINPC$"), mark a pre-provisioning Sysprep/WinPE ghost rather
// than a compromised account.
var sysprepGhostSIDs = []string{"$ (s-1-5-18)", "$ (s-1-5-19)", "$ (s-1-5-20)"}

func isSysprepGhost(val string) bool {
	lower := strings.ToLower(val)
	for _, s := range sysprepGhostSIDs {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// iocClass assigns the IOC-tab presentation bucket (see iocRow.Class).
func iocClass(r *iocRow) string {
	if r.Type == "log-source" {
		return "source"
	}
	if isProvenanceValue(r.Value) {
		return "provenance"
	}
	if r.Confidence == "noise" || isSysprepGhost(r.Value) {
		return "excluded"
	}
	return "ioc"
}

// mergeIOCConfidence keeps the strongest confidence seen for an IOC, except that
// a "noise" verdict is sticky (value-level, so it applies to every occurrence).
func mergeIOCConfidence(existing, incoming string) string {
	if existing == "noise" || incoming == "noise" {
		return "noise"
	}
	if iocConfRank(incoming) > iocConfRank(existing) {
		return incoming
	}
	return existing
}

func iocConfRank(c string) int {
	switch c {
	case "confirmed":
		return 3
	case "inferred":
		return 2
	case "noise":
		return 1
	default:
		return 0
	}
}

func finalizeIOCs(agg map[string]*iocRow) []iocRow {
	out := make([]iocRow, 0, len(agg))
	for _, r := range agg {
		r.Class = iocClass(r)
		out = append(out, *r)
	}
	// type asc, then count desc, then value asc — stable, deterministic.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Value < out[j].Value
	})
	const cap = 200
	if len(out) > cap {
		out = out[:cap]
	}
	return out
}

var severityOrder = []string{"critical", "high", "medium", "low", "informational", "unknown"}

func normSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "critical", "crit", "severe":
		return "critical"
	case "high", "hi":
		return "high"
	case "medium", "med", "moderate":
		return "medium"
	case "low", "lo":
		return "low"
	case "info", "informational", "information":
		return "informational"
	case "":
		return "unknown"
	default:
		return s
	}
}

func orderSeverities(totals map[string]int) []sevCount {
	var out []sevCount
	seen := map[string]bool{}
	for _, s := range severityOrder {
		if n := totals[s]; n > 0 {
			out = append(out, sevCount{Severity: s, Count: n})
			seen[s] = true
		}
	}
	// any non-standard severities, deterministically
	var rest []string
	for s := range totals {
		if !seen[s] {
			rest = append(rest, s)
		}
	}
	sort.Strings(rest)
	for _, s := range rest {
		out = append(out, sevCount{Severity: s, Count: totals[s]})
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func firstOr(s []string, def string) string {
	if len(s) > 0 {
		return s[0]
	}
	return def
}

func firstEventType(evs []findingEvidence) string {
	for _, e := range evs {
		if e.EventType != "" {
			return e.EventType
		}
	}
	return ""
}

func orStr(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func severityRank(s string) int {
	switch normSeverity(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// severityConfidence maps a severity to the low|medium|high bucket the Web UI
// MITRE matrix uses to colour each cell.
func severityConfidence(sev string) string {
	switch severityRank(sev) {
	case 4, 3:
		return "high"
	case 2:
		return "medium"
	default:
		return "low"
	}
}

// evComputer pulls a host/computer name out of an evidence row's extra fields.
func evComputer(ev findingEvidence) string {
	for k, v := range ev.Extra {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "computer") || strings.Contains(lk, "workstation") ||
			strings.Contains(lk, "hostname") || lk == "host" {
			if s := strings.TrimSpace(fmt.Sprintf("%v", v)); s != "" && s != "<nil>" && s != "-" {
				return s
			}
		}
	}
	return ""
}

// prettyTactic turns a tactic slug ("credential-access") into a display name
// ("Credential Access"). Empty / "(unmapped)" pass through.
func prettyTactic(slug string) string {
	slug = strings.TrimSpace(slug)
	if slug == "" {
		return ""
	}
	parts := strings.FieldsFunc(slug, func(r rune) bool { return r == '-' || r == '_' || r == ' ' })
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}

func finalizeMITRE(agg map[string]*mitreRow) []mitreRow {
	out := make([]mitreRow, 0, len(agg))
	for _, r := range agg {
		out = append(out, *r)
	}
	// tactic asc, then finding_count desc, then technique asc — deterministic.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tactic != out[j].Tactic {
			return out[i].Tactic < out[j].Tactic
		}
		if out[i].FindingCount != out[j].FindingCount {
			return out[i].FindingCount > out[j].FindingCount
		}
		return out[i].Technique < out[j].Technique
	})
	return out
}

// ----------------------------------------------------------------------------
// Web enrichment — findings-derived Timeline / IOC / MITRE for the Web UI.
//
// The Tier 2 / Tier 3 pipeline writes synthesis.json in the tier2.CaseSynthesis
// shape, which intentionally drops the raw timeline and never stored IOCs; its
// mitre_mapping can also be empty (the LLM often omits it). The Web UI's
// /timeline, /iocs and /mitre endpoints used to read the legacy synthesizer
// model, so after an e2e run all three tabs came up empty. These DTOs let the
// web layer derive the same material the HTML/CSV report derives — straight
// from findings/ — so the source of truth is shared.
// ----------------------------------------------------------------------------

// WebTimelineEntry mirrors the field names the Web UI timeline table reads.
type WebTimelineEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Tactic    string    `json:"tactic,omitempty"`
	Technique string    `json:"technique,omitempty"`
	Computer  string    `json:"computer,omitempty"`
	Summary   string    `json:"summary"`
	Artifact  string    `json:"artifact,omitempty"`
	Severity  string    `json:"severity,omitempty"`
	AuditID   string    `json:"audit_id,omitempty"`
	Source    string    `json:"source,omitempty"`
	RuleID    string    `json:"rule_id,omitempty"`
	// ClusterID / Noise are populated by BuildTimelineView (synthesis-aware);
	// the plain LoadWebEnrichment path leaves them zero.
	ClusterID int  `json:"cluster_id,omitempty"`
	Noise     bool `json:"noise,omitempty"`
}

// WebIOC mirrors the iocDTO the Web UI IOC table reads.
type WebIOC struct {
	Type     string   `json:"type"`
	Value    string   `json:"value"`
	Count    int      `json:"count"`
	Findings []string `json:"findings"`
	Tactics  []string `json:"tactics"`
	// Class is the IOC-tab bucket: ioc | source | provenance | excluded.
	Class string `json:"class,omitempty"`
}

// WebMITRE mirrors the MITRE matrix cell the Web UI reads.
type WebMITRE struct {
	Tactic        string `json:"tactic"`
	TacticName    string `json:"tactic_name"`
	Technique     string `json:"technique"`
	TechniqueName string `json:"technique_name"`
	FindingCount  int    `json:"finding_count"`
	EvidenceCount int    `json:"evidence_count"`
	Confidence    string `json:"confidence"`
}

// WebEnrichment is the findings-derived bundle the Web UI serves.
type WebEnrichment struct {
	Timeline []WebTimelineEntry
	IOCs     []WebIOC
	MITRE    []WebMITRE
}

// LoadWebEnrichment reads findings/ and returns wire-ready Timeline / IOC /
// MITRE data. A missing/unreadable dir yields empty (non-nil) slices.
func LoadWebEnrichment(findingsDir string) *WebEnrichment {
	en := loadEnrichment(findingsDir)
	out := &WebEnrichment{
		Timeline: make([]WebTimelineEntry, 0, len(en.Timeline)),
		IOCs:     make([]WebIOC, 0, len(en.IOCs)),
		MITRE:    make([]WebMITRE, 0, len(en.MITRE)),
	}
	for _, t := range en.Timeline {
		out.Timeline = append(out.Timeline, WebTimelineEntry{
			Timestamp: t.TS,
			Tactic:    t.Tactic,
			Technique: t.Technique,
			Computer:  t.Computer,
			Summary:   t.Title,
			Artifact:  t.Artifact,
			Severity:  t.Severity,
			AuditID:   t.AuditID,
			Source:    t.Source,
			RuleID:    t.RuleID,
		})
	}
	const maxIOCLabels = 8
	for _, r := range en.IOCs {
		labels := sortedKeys(r.findings)
		if len(labels) > maxIOCLabels {
			labels = labels[:maxIOCLabels]
		}
		out.IOCs = append(out.IOCs, WebIOC{
			Type:     r.Type,
			Value:    r.Value,
			Count:    r.Count,
			Findings: labels,
			Tactics:  sortedKeys(r.tactics),
			Class:    r.Class,
		})
	}
	for _, m := range en.MITRE {
		tactic := m.Tactic
		if tactic == "" {
			tactic = "(unmapped)"
		}
		out.MITRE = append(out.MITRE, WebMITRE{
			Tactic:        tactic,
			TacticName:    prettyTactic(m.Tactic),
			Technique:     m.Technique,
			FindingCount:  m.FindingCount,
			EvidenceCount: m.EvidenceCount,
			Confidence:    severityConfidence(m.worstSeverity),
		})
	}
	return out
}
