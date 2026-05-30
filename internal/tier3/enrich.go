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
	Source   string
	RuleID   string
	Title    string
	Severity string
	Evidence []findingEvidence
}

// enrichment is the computed bundle handed to the renderer.
type enrichment struct {
	SeverityCounts []sevCount
	Timeline       []timelineRow
	IOCs           []iocRow
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
	Severity  string
	Title     string
}

type iocRow struct {
	Type     string // file/path | command | account | host | network | log-source
	Value    string
	Artifact string
	Count    int
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
	iocAgg := map[string]*iocRow{} // key: type\x00value

	for _, f := range findings {
		sevTotals[normSeverity(f.Severity)]++

		// per-finding detail (first-seen, artifacts, evidence count)
		det := &findingDetail{}
		artSet := map[string]bool{}
		for _, ev := range f.Evidence {
			if ev.hasTS() {
				if !det.HasTS || ev.TsUTC.Before(det.FirstSeen) {
					det.FirstSeen = ev.TsUTC
					det.HasTS = true
				}
			}
			if ev.ArtifactID != "" {
				artSet[ev.ArtifactID] = true
			}
			collectIOCs(iocAgg, ev)
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
				Severity:  normSeverity(f.Severity),
				Title:     f.Title,
			})
		}
	}

	sort.Slice(en.Timeline, func(i, j int) bool { return en.Timeline[i].TS.Before(en.Timeline[j].TS) })
	en.SeverityCounts = orderSeverities(sevTotals)
	en.IOCs = finalizeIOCs(iocAgg)
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
			Source:   orStr(rf.RuleSource, "rule"),
			RuleID:   rf.RuleID,
			Title:    rf.RuleMeta.Title,
			Severity: rf.RuleMeta.Level,
			Evidence: rf.Evidence,
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

func collectIOCs(agg map[string]*iocRow, ev findingEvidence) {
	for k, v := range ev.Extra {
		cls := iocKeyClass(k)
		if cls == "" {
			continue
		}
		val := strings.TrimSpace(fmt.Sprintf("%v", v))
		if val == "" || val == "-" || val == "<nil>" || len(val) > 300 {
			continue
		}
		key := cls + "\x00" + val
		if r, ok := agg[key]; ok {
			r.Count++
		} else {
			agg[key] = &iocRow{Type: cls, Value: val, Artifact: ev.ArtifactID, Count: 1}
		}
	}
}

func finalizeIOCs(agg map[string]*iocRow) []iocRow {
	out := make([]iocRow, 0, len(agg))
	for _, r := range agg {
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
	case "critical", "high", "medium", "low":
		return s
	case "info", "informational":
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
