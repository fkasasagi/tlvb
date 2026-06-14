package tier3

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/tier2"
)

// ----------------------------------------------------------------------------
// Synthesis-aware Web timeline.
//
// The plain LoadWebEnrichment derives a FLAT, display-time-ordered timeline from
// findings/. That is the same material the report leads with, but the report
// then layers the Tier 2 synthesis on top: clusters (attack phases), a clock-
// reliability verdict, and a logical-order intrusion path. With a clock
// rollback those two views diverge — the report reorders to logical order and
// warns, the Timeline tab historically did not. BuildTimelineView closes that
// gap: it joins the flat finding timeline to synthesis.json so the Timeline tab
// renders the SAME phase grouping / intrusion path / clock warning the report
// uses. (Review IDs T-1..T-4, T-6.)
// ----------------------------------------------------------------------------

// WebTimelineCluster is one attack-phase group for the Timeline tab.
type WebTimelineCluster struct {
	ID          int       `json:"id"`
	AttackPhase string    `json:"attack_phase,omitempty"`
	PhaseLabel  string    `json:"phase_label,omitempty"`
	StartTS     time.Time `json:"start_ts"`
	EndTS       time.Time `json:"end_ts"`
	Narrative   string    `json:"narrative,omitempty"`
	MITRE       []string  `json:"mitre_techniques,omitempty"`
	Noise       bool      `json:"noise"`
	PhaseRank   int       `json:"phase_rank"`
	EventCount  int       `json:"event_count"`
}

// WebIntrusionStep is one logical-order step in the Timeline Kill Chain. Mirrors
// the report's deriveIntrusionPath ordering (non-noise clusters, kill-chain
// rank) so the two surfaces agree.
type WebIntrusionStep struct {
	Step      int      `json:"step"`
	Phase     string   `json:"phase,omitempty"`
	Label     string   `json:"label,omitempty"`
	MITRE     []string `json:"mitre_techniques,omitempty"`
	ClusterID int      `json:"cluster_id,omitempty"`
}

// WebTimelineView is the full payload the /timeline endpoint serves.
type WebTimelineView struct {
	Timeline                  []WebTimelineEntry   `json:"timeline"`
	Clusters                  []WebTimelineCluster `json:"clusters"`
	IntrusionPath             []WebIntrusionStep   `json:"intrusion_path"`
	TimelineReliability       string               `json:"timeline_reliability,omitempty"`
	TimelineNotes             []string             `json:"timeline_notes,omitempty"`
	CrossEvidenceCorrelations []any                `json:"cross_evidence_correlations"`
}

// BuildTimelineView joins findings-derived timeline rows to the Tier 2
// synthesis. synthesisPath may be absent (no Synthesize run yet) — the view
// then degrades to the flat timeline with no clusters / intrusion path.
func BuildTimelineView(findingsDir, synthesisPath string) *WebTimelineView {
	web := LoadWebEnrichment(findingsDir)
	view := &WebTimelineView{
		Timeline:                  web.Timeline,
		Clusters:                  []WebTimelineCluster{},
		IntrusionPath:             []WebIntrusionStep{},
		CrossEvidenceCorrelations: []any{},
	}

	cs, ok := loadSynthesis(synthesisPath)
	if !ok || len(cs.Clusters) == 0 {
		return view
	}
	view.TimelineReliability = cs.TimelineReliability
	view.TimelineNotes = cs.TimelineNotes

	// finding-ref → cluster id index. Primary key is (source, rule_id); a
	// lowercased title is the fallback when a row carries no rule_id.
	byRule := map[string]int{}
	byTitle := map[string]int{}
	noiseByID := map[int]bool{}
	for _, c := range cs.Clusters {
		noise := tier2.IsNoiseCluster(c.AttackPhase, c.Narrative)
		noiseByID[c.ID] = noise
		for _, fr := range c.FindingRefs {
			if fr.RuleID != "" {
				byRule[refKey(fr.Source, fr.RuleID)] = c.ID
			}
			if t := strings.ToLower(strings.TrimSpace(fr.Title)); t != "" {
				if _, seen := byTitle[t]; !seen {
					byTitle[t] = c.ID
				}
			}
		}
	}

	// Assign each timeline entry to a cluster, then count per cluster.
	counts := map[int]int{}
	for i := range view.Timeline {
		t := &view.Timeline[i]
		cid := 0
		if t.RuleID != "" {
			if id, ok := byRule[refKey(t.Source, t.RuleID)]; ok {
				cid = id
			}
		}
		if cid == 0 {
			if id, ok := byTitle[strings.ToLower(strings.TrimSpace(t.Summary))]; ok {
				cid = id
			}
		}
		t.ClusterID = cid
		t.Noise = noiseByID[cid]
		if cid != 0 {
			counts[cid]++
		}
	}

	for _, c := range cs.Clusters {
		view.Clusters = append(view.Clusters, WebTimelineCluster{
			ID:          c.ID,
			AttackPhase: c.AttackPhase,
			PhaseLabel:  phaseLabelJA(c.AttackPhase),
			StartTS:     c.StartTS,
			EndTS:       c.EndTS,
			Narrative:   c.Narrative,
			MITRE:       c.MITRETechniques,
			Noise:       noiseByID[c.ID],
			PhaseRank:   phaseRank(c.AttackPhase),
			EventCount:  counts[c.ID],
		})
	}

	view.IntrusionPath = buildIntrusionSteps(cs)
	return view
}

// buildIntrusionSteps mirrors deriveIntrusionPath's ordering: drop noise
// clusters, then order by kill-chain phase rank (start_ts breaks ties). One step
// per attack cluster so the Timeline Kill Chain matches the report's logic.
func buildIntrusionSteps(cs tier2.CaseSynthesis) []WebIntrusionStep {
	type ord struct {
		c    tier2.SynthCluster
		rank int
	}
	var attack []ord
	for _, c := range cs.Clusters {
		if tier2.IsNoiseCluster(c.AttackPhase, c.Narrative) {
			continue
		}
		attack = append(attack, ord{c, phaseRank(c.AttackPhase)})
	}
	sort.SliceStable(attack, func(i, j int) bool {
		if attack[i].rank != attack[j].rank {
			return attack[i].rank < attack[j].rank
		}
		return attack[i].c.StartTS.Before(attack[j].c.StartTS)
	})
	steps := make([]WebIntrusionStep, 0, len(attack))
	for i, a := range attack {
		steps = append(steps, WebIntrusionStep{
			Step:      i + 1,
			Phase:     a.c.AttackPhase,
			Label:     phaseLabelJA(a.c.AttackPhase),
			MITRE:     a.c.MITRETechniques,
			ClusterID: a.c.ID,
		})
	}
	return steps
}

func refKey(source, ruleID string) string {
	return strings.ToLower(strings.TrimSpace(source)) + "\x00" + strings.TrimSpace(ruleID)
}

// loadSynthesis reads synthesis.json best-effort. Returns ok=false on any error
// so the timeline degrades gracefully when no synthesis exists.
func loadSynthesis(path string) (tier2.CaseSynthesis, bool) {
	var cs tier2.CaseSynthesis
	if path == "" {
		return cs, false
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return cs, false
	}
	if err := json.Unmarshal(body, &cs); err != nil {
		return cs, false
	}
	return cs, true
}
