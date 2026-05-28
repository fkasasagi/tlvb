package synthesizer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/tlvb/tlvb/internal/agents"
)

// TimelineReview is the LLM-driven Tier 2 timeline review (DESIGN §6.7).
//
// It exists because the rule-based Synthesizer (TimelineBuilder +
// ConsistencyChecker R1–R4) catches structural / contradiction cases
// but cannot reason about properties that only emerge from the
// aggregate temporal shape — dwell time, off-hours clustering, burst
// detection, lateral-movement velocity, timestamp anomalies, etc.
//
// The 12 perspectives the LLM applies live in skills/timeline_review.md.
// Adding a perspective there is enough; this Go side just shuttles
// data in and observations out.
//
// Schema is versioned (`schema: "tlvb/timeline-review/v1"`) so
// downstream consumers can detect breaking changes.
type TimelineReview struct {
	Schema        string                  `json:"schema"`
	CaseID        string                  `json:"case_id"`
	EvidenceIDs   []string                `json:"evidence_ids"`
	Language      string                  `json:"language"`
	Narrative     string                  `json:"narrative"`
	Observations  []TimelineObservation   `json:"observations"`
	OpenQuestions []TimelineOpenQuestion  `json:"open_questions"`
	SummaryStats  TimelineSummaryStats    `json:"summary_stats"`
	Audit         TimelineReviewAudit     `json:"audit"`
}

type TimelineObservation struct {
	ObservationID     string   `json:"observation_id"`
	Perspective       string   `json:"perspective"`
	Severity          string   `json:"severity"`
	Summary           string   `json:"summary"`
	EvidenceAuditIDs  []string `json:"evidence_audit_ids"`
	RelatedFindingIDs []string `json:"related_finding_ids,omitempty"`
	RelatedTacticIDs  []string `json:"related_tactic_ids,omitempty"`
	Reasoning         string   `json:"reasoning"`
	NextStep          string   `json:"next_step,omitempty"`
}

type TimelineOpenQuestion struct {
	Question    string `json:"question"`
	Perspective string `json:"perspective,omitempty"`
	NextStep    string `json:"next_step,omitempty"`
}

type TimelineSummaryStats struct {
	DwellTimeHours        float64        `json:"dwell_time_hours"`
	HostCount             int            `json:"host_count"`
	TacticsObservedCount  int            `json:"tactics_observed_count"`
	ObservationsBySeverity map[string]int `json:"observations_by_severity"`
}

type TimelineReviewAudit struct {
	Engine         string  `json:"engine"`
	Model          string  `json:"model"`
	InputTokens    int     `json:"input_tokens"`
	OutputTokens   int     `json:"output_tokens"`
	DurationS      float64 `json:"duration_seconds"`
	SkillFile      string  `json:"skill_file"`
	SkippedReason  string  `json:"skipped_reason,omitempty"`
	PhantomIDsDropped int  `json:"phantom_audit_ids_dropped,omitempty"`
}

// TimelineReviewConfig controls one ReviewTimeline call.
type TimelineReviewConfig struct {
	CaseID       string
	EvidenceIDs  []string
	Language     string        // "ja" | "en"; defaults to "ja"
	Engine       string        // "claude-code" | "anthropic-api"
	APIKey       string
	Model        string
	MaxTokens    int
	Timeout      time.Duration
	SkillsDir    string        // default "skills"
	MaxExcerpt   int           // max timeline rows shown (default 200)
	MaxFindings  int           // max top findings shown (default 50)
}

const timelineReviewSchemaVersion = "tlvb/timeline-review/v1"
const timelineReviewSkill = "timeline_review.md"

// ReviewTimeline calls the timeline-review LLM agent against a freshly
// built CaseSynthesis-like view. The caller (Synthesize) passes the
// in-memory artefacts directly so we don't re-read the DB.
//
// The function is **graceful**: on any error (missing skill file,
// engine unavailable, LLM hallucination, ...) it returns a non-nil
// TimelineReview with an empty observations[] and a populated
// Audit.SkippedReason. This keeps the synthesis pipeline working
// even when LLM access is broken.
func ReviewTimeline(
	ctx context.Context,
	cfg TimelineReviewConfig,
	timeline []TimelineEntry,
	steps []AttackStep,
	inconsistencies []Inconsistency,
	agg *AggregateResult,
) (*TimelineReview, error) {
	if cfg.SkillsDir == "" {
		cfg.SkillsDir = "skills"
	}
	if cfg.Language == "" {
		cfg.Language = "ja"
	}
	if cfg.MaxExcerpt <= 0 {
		cfg.MaxExcerpt = 200
	}
	if cfg.MaxFindings <= 0 {
		cfg.MaxFindings = 50
	}

	tr := &TimelineReview{
		Schema:      timelineReviewSchemaVersion,
		CaseID:      cfg.CaseID,
		EvidenceIDs: append([]string(nil), cfg.EvidenceIDs...),
		Language:    cfg.Language,
		Audit: TimelineReviewAudit{
			Engine:    cfg.Engine,
			Model:     cfg.Model,
			SkillFile: filepath.Join(cfg.SkillsDir, timelineReviewSkill),
		},
	}

	skillPath := filepath.Join(cfg.SkillsDir, timelineReviewSkill)
	skillRaw, err := os.ReadFile(skillPath)
	if err != nil {
		tr.Audit.SkippedReason = fmt.Sprintf("read skill: %v", err)
		return tr, nil
	}

	prompt := buildTimelineReviewPrompt(cfg, timeline, steps, inconsistencies, agg)
	tr.SummaryStats = computeTimelineStats(timeline, agg, nil) // observations filled in later

	engine, err := agents.NewEngine(cfg.Engine, cfg.APIKey, cfg.Model,
		cfg.MaxTokens, cfg.Timeout)
	if err != nil {
		tr.Audit.SkippedReason = fmt.Sprintf("engine init: %v", err)
		return tr, nil
	}
	tr.Audit.Engine = engine.ID()
	tr.Audit.Model = engine.Model()

	t0 := time.Now()
	jsonText, er, err := agents.CallEngine(ctx, engine, string(skillRaw), prompt, 2)
	if er != nil {
		tr.Audit.InputTokens = er.InputTokens
		tr.Audit.OutputTokens = er.OutputTokens
	}
	tr.Audit.DurationS = time.Since(t0).Seconds()
	if err != nil {
		tr.Audit.SkippedReason = fmt.Sprintf("engine call: %v", err)
		return tr, nil
	}

	var parsed TimelineReview
	if err := json.Unmarshal([]byte(jsonText), &parsed); err != nil {
		tr.Audit.SkippedReason = fmt.Sprintf("parse json: %v", err)
		return tr, nil
	}

	// Validate audit_ids against real timeline rows. Drop observations
	// that reference phantom ids; record the count for auditability.
	realIDs := map[string]struct{}{}
	for _, t := range timeline {
		if t.AuditID != "" {
			realIDs[t.AuditID] = struct{}{}
		}
	}
	for _, rep := range agg.Reports {
		for _, f := range rep.Findings {
			for _, ev := range f.Evidence {
				if ev.AuditID != "" {
					realIDs[ev.AuditID] = struct{}{}
				}
			}
		}
	}
	clean, dropped := filterPhantomObservations(parsed.Observations, realIDs)
	parsed.Observations = clean
	tr.Observations = parsed.Observations
	tr.Narrative = parsed.Narrative
	tr.OpenQuestions = parsed.OpenQuestions
	tr.Audit.PhantomIDsDropped = dropped
	// Recompute stats so the response can't lie about counts.
	tr.SummaryStats = computeTimelineStats(timeline, agg, tr.Observations)
	return tr, nil
}

// ----------------------------------------------------------------------
// Prompt construction
// ----------------------------------------------------------------------

func buildTimelineReviewPrompt(
	cfg TimelineReviewConfig,
	timeline []TimelineEntry,
	steps []AttackStep,
	inconsistencies []Inconsistency,
	agg *AggregateResult,
) string {
	// Build the host set and tactics set from the timeline.
	hostSet := map[string]struct{}{}
	tacticSet := map[string]struct{}{}
	var minTS, maxTS time.Time
	for _, t := range timeline {
		if t.Computer != "" {
			hostSet[t.Computer] = struct{}{}
		}
		if t.Tactic != "" {
			tacticSet[t.Tactic] = struct{}{}
		}
		if minTS.IsZero() || t.Timestamp.Before(minTS) {
			minTS = t.Timestamp
		}
		if t.Timestamp.After(maxTS) {
			maxTS = t.Timestamp
		}
	}

	excerpt := make([]map[string]any, 0, min(cfg.MaxExcerpt, len(timeline)))
	for i, t := range timeline {
		if i >= cfg.MaxExcerpt {
			break
		}
		row := map[string]any{
			"audit_id":    t.AuditID,
			"ts":          t.Timestamp.UTC().Format(time.RFC3339Nano),
			"host":        t.Computer,
			"artifact":    t.ArtifactID,
			"signal":      t.Summary,
			"tactic":      t.Tactic,
			"finding_ids": t.FindingIDs,
		}
		excerpt = append(excerpt, row)
	}

	// top findings ranked by confidence (high → medium → low) then by ts.
	type tf struct {
		FindingID  string   `json:"finding_id"`
		TacticID   string   `json:"tactic_id"`
		TechniqueID string  `json:"technique_id"`
		Confidence string   `json:"confidence"`
		TS         string   `json:"ts,omitempty"`
		Summary    string   `json:"summary"`
		Evidence   []string `json:"evidence,omitempty"`
	}
	var tops []tf
	for _, rep := range agg.Reports {
		for _, f := range rep.Findings {
			var evIDs []string
			for _, ev := range f.Evidence {
				if ev.AuditID != "" {
					evIDs = append(evIDs, ev.AuditID)
				}
			}
			tops = append(tops, tf{
				FindingID:   f.FindingID,
				TacticID:    rep.TacticID,
				TechniqueID: f.TechniqueID,
				Confidence:  f.Confidence,
				Summary:     f.Summary,
				Evidence:    evIDs,
			})
		}
	}
	sort.SliceStable(tops, func(i, j int) bool {
		// confidence: high=0, medium=1, low=2, "":3
		order := map[string]int{"high": 0, "medium": 1, "low": 2}
		oi, oj := order[tops[i].Confidence], order[tops[j].Confidence]
		if oi == 0 && tops[i].Confidence == "" {
			oi = 3
		}
		if oj == 0 && tops[j].Confidence == "" {
			oj = 3
		}
		if oi != oj {
			return oi < oj
		}
		return tops[i].FindingID < tops[j].FindingID
	})
	if len(tops) > cfg.MaxFindings {
		tops = tops[:cfg.MaxFindings]
	}

	// consistency_warnings — only severity=warning, lighter shape.
	type cw struct {
		Rule        string `json:"rule"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	}
	var warnings []cw
	for _, inc := range inconsistencies {
		warnings = append(warnings, cw{
			Rule: inc.Rule, Severity: inc.Severity,
			Description: inc.Description,
		})
	}

	tactics := keysSorted(tacticSet)
	hosts := keysSorted(hostSet)

	body := map[string]any{
		"case_id":              cfg.CaseID,
		"evidence_ids":         cfg.EvidenceIDs,
		"language":             cfg.Language,
		"window": map[string]any{
			"min":         tsOrEmpty(minTS),
			"max":         tsOrEmpty(maxTS),
			"span_hours":  durationHours(minTS, maxTS),
		},
		"host_count":           len(hosts),
		"hosts":                hosts,
		"tactics_observed":     tactics,
		"attack_steps":         steps,
		"consistency_warnings": warnings,
		"top_findings":         tops,
		"timeline_excerpt":     excerpt,
		"caps": map[string]any{
			"max_excerpt":  cfg.MaxExcerpt,
			"max_findings": cfg.MaxFindings,
		},
	}
	b, _ := json.Marshal(body)
	return "Below is the timeline-review input for case " + cfg.CaseID +
		". Apply the 12 perspectives in the system prompt and return ONLY " +
		"the TimelineReview JSON.\n\n" + string(b)
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

func tsOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func durationHours(a, b time.Time) float64 {
	if a.IsZero() || b.IsZero() {
		return 0
	}
	return b.Sub(a).Hours()
}

func keysSorted(s map[string]struct{}) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func filterPhantomObservations(
	obs []TimelineObservation, real map[string]struct{},
) ([]TimelineObservation, int) {
	dropped := 0
	out := obs[:0]
	for _, o := range obs {
		// Keep observations that cite at least one real audit_id.
		ok := false
		for _, id := range o.EvidenceAuditIDs {
			if _, present := real[id]; present {
				ok = true
				break
			}
		}
		if !ok {
			dropped++
			continue
		}
		// Strip individual phantom ids.
		clean := o.EvidenceAuditIDs[:0]
		for _, id := range o.EvidenceAuditIDs {
			if _, present := real[id]; present {
				clean = append(clean, id)
			} else {
				dropped++
			}
		}
		o.EvidenceAuditIDs = clean
		out = append(out, o)
	}
	return out, dropped
}

func computeTimelineStats(
	timeline []TimelineEntry, agg *AggregateResult, obs []TimelineObservation,
) TimelineSummaryStats {
	hostSet := map[string]struct{}{}
	tacticSet := map[string]struct{}{}
	for _, t := range timeline {
		if t.Computer != "" {
			hostSet[t.Computer] = struct{}{}
		}
		if t.Tactic != "" {
			tacticSet[t.Tactic] = struct{}{}
		}
	}
	bySev := map[string]int{"info": 0, "warning": 0, "critical": 0}
	for _, o := range obs {
		bySev[o.Severity]++
	}

	// Dwell-time approximation: earliest TA0001 / TA0002 to latest
	// TA0009 / TA0040 in the agg, falling back to overall timeline span.
	var firstHostile, lastObjective time.Time
	earliestByTactic := map[string]time.Time{}
	for _, t := range timeline {
		if t.Tactic == "" {
			continue
		}
		cur, ok := earliestByTactic[t.Tactic]
		if !ok || t.Timestamp.Before(cur) {
			earliestByTactic[t.Tactic] = t.Timestamp
		}
	}
	if ts, ok := earliestByTactic["TA0001"]; ok {
		firstHostile = ts
	} else if ts, ok := earliestByTactic["TA0002"]; ok {
		firstHostile = ts
	}
	for _, ta := range []string{"TA0040", "TA0009", "TA0008"} {
		// pick the LATEST hit across these "late-stage" tactics
		var latestForTactic time.Time
		for _, t := range timeline {
			if t.Tactic == ta && t.Timestamp.After(latestForTactic) {
				latestForTactic = t.Timestamp
			}
		}
		if latestForTactic.After(lastObjective) {
			lastObjective = latestForTactic
		}
	}
	dwell := 0.0
	if !firstHostile.IsZero() && !lastObjective.IsZero() &&
		lastObjective.After(firstHostile) {
		dwell = lastObjective.Sub(firstHostile).Hours()
	}

	return TimelineSummaryStats{
		DwellTimeHours:         dwell,
		HostCount:              len(hostSet),
		TacticsObservedCount:   len(tacticSet),
		ObservationsBySeverity: bySev,
	}
}
