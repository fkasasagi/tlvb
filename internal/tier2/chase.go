package tier2

import (
	"context"
	"sort"
	"strings"
	"time"
)

// --- Tier 2 chase loop -------------------------------------------------
//
// A cluster's raw-timeline window starts as ±TimelineWindow around the hull
// its findings describe. That is enough context to explain the detections,
// but not to notice that the intruder kept working past them: activity that
// no signature fired on simply falls outside the window and the story stops
// at the last alert.
//
// The chase loop closes that gap. After each per-cluster analysis the LLM
// reports which raw events it wants a wider look around
// (clusterAnalysisResp.FollowUpEvents). Any of those lying OUTSIDE the current
// hull pull the hull out to cover them; the window is recomputed as
// ±TimelineWindow around the new hull, the timeline is re-fetched, and the
// cluster is analysed again. The trigger is therefore an existing verdict —
// Tier 1's signatures (already in c.Findings) plus Tier 2's own judgement —
// never a fresh heuristic. How far to reach is mechanical: one more window.
//
// Note the asymmetry the prompt leans on: a follow-up entry is a REQUEST, not
// a claim. An event the analysis could not attribute is exactly what a wider
// window can settle, so uncertainty must push events INTO this list. Asking
// for confident attributions instead makes the loop dead on arrival — the
// ambiguous cases, the ones worth chasing, are the ones it would drop.
//
// Bounded by maxRounds (CLAUDE.md constraint #3) and clamped at the midpoint
// between neighbouring clusters (clusterBoundaries), so a gap between two
// episodes is split between them rather than analysed twice.

// DefaultMaxChaseRounds bounds how far the loop will follow a trail by default.
// Two rounds reach ~3× the base window past the last detection, which covers
// the hands-on-keyboard tail that follows most detections without letting a
// long-running case multiply its LLM cost.
const DefaultMaxChaseRounds = 2

// chaseDeps are the two side-effecting operations the loop needs. Injected so
// the control flow can be tested without a DuckDB handle or an LLM.
type chaseDeps struct {
	// analyse runs one per-cluster LLM pass over c.RawTimelineExcerpt.
	analyse func(ctx context.Context, c *Cluster) (*clusterAnalysisResp, error)
	// refetch replaces c.RawTimelineExcerpt with the rows in [lo, hi].
	refetch func(ctx context.Context, c *Cluster, lo, hi time.Time) error
}

// runChase analyses a cluster, then keeps extending its window while the
// analysis keeps finding attacker activity beyond the hull.
//
// prevBound / nextBound are the boundaries this cluster shares with its
// neighbours (clusterBoundaries; zero when unbounded on that side).
//
// Returns the LAST successful analysis. Degrades gracefully: a failed
// re-fetch or a failed follow-up analysis ends the chase and keeps the
// previous round's result rather than losing the cluster (CLAUDE.md #4).
func runChase(ctx context.Context, c *Cluster, window time.Duration, maxRounds int,
	prevBound, nextBound time.Time, deps chaseDeps, audit *SynthAudit) (*clusterAnalysisResp, error) {

	// record folds one analysis's follow-up requests into the cluster and the
	// audit, and returns their timestamps. Recording happens even when the chase
	// is disabled: the counts are what make a "chase_rounds: 0" result
	// explainable (nothing requested vs. everything already inside the
	// detections), and the rows are the undetected material the analysis leaned
	// on.
	record := func(r *clusterAnalysisResp) []time.Time {
		matched, unresolved := resolveFollowUpEvents(c.RawTimelineExcerpt, r.FollowUpEvents)
		audit.ChaseEventsFlagged += len(matched)
		audit.ChaseEventsUnresolved += unresolved
		c.FollowUpRefs = mergeFollowUpRefs(c.FollowUpRefs, matched)
		return eventTimes(matched)
	}

	resp, err := deps.analyse(ctx, c)
	if err != nil {
		return nil, err
	}
	confirmed := record(resp)

	// Undated clusters have no window to extend; chase disabled means the
	// caller wants the historical single-pass behaviour exactly.
	if maxRounds <= 0 || c.StartTS.IsZero() {
		return resp, nil
	}

	hullLo, hullHi := c.StartTS, c.EndTS
	// The window bounds the CURRENT resp was written from. Restored if a round
	// fetches a wider window but then fails to analyse it, so the cluster never
	// advertises a span its narrative did not see.
	analysedLo, analysedHi := c.WindowStart, c.WindowEnd
	extended := false

	for round := 1; round <= maxRounds; round++ {
		rawLo, rawHi, _ := growHull(hullLo, hullHi, confirmed)

		// Activity traced past a shared boundary belongs to the neighbouring
		// episode's span. Record that the trail runs that way — an evidential
		// claim, unlike the window merely being wide enough to touch the
		// boundary — but do not reach across, or both clusters would analyse
		// the same events.
		if !prevBound.IsZero() && rawLo.Before(prevBound) {
			rawLo = prevBound
			c.ContinuesFromPrev = true
		}
		if !nextBound.IsZero() && rawHi.After(nextBound) {
			rawHi = nextBound
			c.ContinuesIntoNext = true
		}
		newLo, newHi := rawLo, rawHi
		if !newLo.Before(hullLo) && !newHi.After(hullHi) {
			return resp, nil // the trail ended inside the window
		}
		lo, hi := clusterWindow(newLo, newHi, window, prevBound, nextBound)

		// Anchors must be in place BEFORE the fetch — they are what makes the
		// newly opened span sample at all. Harmless if the round then fails:
		// clusterAnchorEpochs only keeps anchors inside the window in force.
		c.ChaseAnchors = appendAnchors(c.ChaseAnchors, confirmed)

		prevExcerpt := c.RawTimelineExcerpt
		if err := deps.refetch(ctx, c, lo, hi); err != nil {
			return resp, nil // fetch commits atomically, so c is untouched
		}
		next, err := deps.analyse(ctx, c)
		if err != nil {
			// Put the cluster back to the state the narrative we are returning
			// was written from — window AND excerpt, since the active-search
			// pass reads the excerpt and would otherwise cite rows from a span
			// the narrative never saw.
			c.WindowStart, c.WindowEnd = analysedLo, analysedHi
			c.RawTimelineExcerpt = prevExcerpt
			return resp, nil
		}

		// Commit the round only now that it produced a narrative.
		hullLo, hullHi = newLo, newHi
		analysedLo, analysedHi = c.WindowStart, c.WindowEnd
		c.ChaseRounds = round
		audit.ChaseRoundsTotal++
		if !extended {
			audit.ChaseClustersExtended++
			extended = true
		}
		resp = next
		confirmed = record(resp)
	}

	// Budget spent. If the trail was still running INSIDE this cluster's own
	// span, say so rather than letting the report imply it was explored to its
	// end. Activity beyond a boundary is the neighbour's to explain and is
	// already reported through the continuity flags, so it does not count as
	// unexplored here.
	stillLo, stillHi, _ := growHull(hullLo, hullHi, confirmed)
	if !prevBound.IsZero() && stillLo.Before(prevBound) {
		stillLo = prevBound
	}
	if !nextBound.IsZero() && stillHi.After(nextBound) {
		stillHi = nextBound
	}
	if stillLo.Before(hullLo) || stillHi.After(hullHi) {
		audit.ChaseRoundsCapped++
	}
	return resp, nil
}

// growHull widens [lo, hi] to cover every confirmed attack-event timestamp,
// reporting whether anything actually moved. Zero timestamps are ignored.
func growHull(lo, hi time.Time, confirmed []time.Time) (time.Time, time.Time, bool) {
	grew := false
	for _, t := range confirmed {
		if t.IsZero() {
			continue
		}
		if t.Before(lo) {
			lo, grew = t, true
		}
		if t.After(hi) {
			hi, grew = t, true
		}
	}
	return lo, hi, grew
}

// clampWindow stops a window at the boundaries this cluster shares with its
// neighbours (clusterBoundaries) so adjacent episodes don't analyse overlapping
// spans. A zero bound means unbounded on that side.
//
// Clamping never erodes this cluster's OWN hull: if a boundary somehow falls
// inside it — only possible on degenerate, overlapping input — the window
// collapses to the hull rather than excluding the cluster's own detections from
// its own analysis.
func clampWindow(lo, hi, hullLo, hullHi, prevBound, nextBound time.Time) (time.Time, time.Time) {
	if !prevBound.IsZero() && lo.Before(prevBound) {
		lo = prevBound
	}
	if lo.After(hullLo) {
		lo = hullLo
	}
	if !nextBound.IsZero() && hi.After(nextBound) {
		hi = nextBound
	}
	if hi.Before(hullHi) {
		hi = hullHi
	}
	return lo, hi
}

// clusterWindow is the single definition of "which raw-timeline span does this
// cluster get": ±window around the given hull, clamped at the shared
// boundaries. Used for the first fetch and for every chase re-fetch, so the two
// cannot drift apart.
func clusterWindow(hullLo, hullHi time.Time, window time.Duration,
	prevBound, nextBound time.Time) (lo, hi time.Time) {
	return clampWindow(hullLo.Add(-window), hullHi.Add(window), hullLo, hullHi, prevBound, nextBound)
}

// resolveFollowUpEvents maps the audit_ids the LLM flagged back to the events in
// the excerpt it was shown, and reports how many DISTINCT ids did not resolve.
// Ids absent from the excerpt, or whose event has no timestamp, are dropped: a
// hallucinated id must not move the window. A persistently non-zero unresolved
// count means the model is inventing ids rather than copying them.
func resolveFollowUpEvents(excerpt []TimelineEvent, ids []string) ([]TimelineEvent, int) {
	if len(ids) == 0 {
		return nil, 0
	}
	byID := make(map[string]TimelineEvent, len(excerpt))
	for _, ev := range excerpt {
		if ev.AuditID == "" || ev.TsUTC.IsZero() {
			continue
		}
		if _, ok := byID[ev.AuditID]; !ok {
			byID[ev.AuditID] = ev
		}
	}
	seen := make(map[string]bool, len(ids))
	var out []TimelineEvent
	unresolved := 0
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ev, ok := byID[id]
		if !ok {
			unresolved++
			continue
		}
		out = append(out, ev)
	}
	return out, unresolved
}

// eventTimes projects resolved events to their timestamps for hull arithmetic.
func eventTimes(evs []TimelineEvent) []time.Time {
	if len(evs) == 0 {
		return nil
	}
	out := make([]time.Time, 0, len(evs))
	for _, ev := range evs {
		out = append(out, ev.TsUTC)
	}
	return out
}

// mergeFollowUpRefs accumulates the flagged events across chase rounds,
// deduplicated by audit_id and kept chronological. These are the cluster's
// undetected-activity evidence: events no signature fired on that the analysis
// nonetheless used (CLAUDE.md #5 — a claim is backed by evidence).
func mergeFollowUpRefs(cur []FollowUpEventRef, add []TimelineEvent) []FollowUpEventRef {
	seen := make(map[string]bool, len(cur)+len(add))
	for _, r := range cur {
		seen[r.AuditID] = true
	}
	for _, ev := range add {
		if seen[ev.AuditID] {
			continue
		}
		seen[ev.AuditID] = true
		cur = append(cur, FollowUpEventRef{
			AuditID:    ev.AuditID,
			TsUTC:      ev.TsUTC,
			ArtifactID: ev.ArtifactID,
			EventType:  ev.EventType,
		})
	}
	sort.Slice(cur, func(i, j int) bool { return cur[i].TsUTC.Before(cur[j].TsUTC) })
	return cur
}

// appendAnchors merges new anchor timestamps into the cluster's set,
// deduplicated to whole seconds (the granularity the SQL sampler orders by)
// and kept chronological.
func appendAnchors(cur, add []time.Time) []time.Time {
	seen := make(map[int64]bool, len(cur)+len(add))
	for _, t := range cur {
		seen[t.Unix()] = true
	}
	for _, t := range add {
		if t.IsZero() || seen[t.Unix()] {
			continue
		}
		seen[t.Unix()] = true
		cur = append(cur, t)
	}
	sort.Slice(cur, func(i, j int) bool { return cur[i].Before(cur[j]) })
	return cur
}

// clusterBoundaries returns the limits of the span clusters[i] owns: the
// MIDPOINT of the gap to the nearest dated cluster on each side. Zero on a side
// with no neighbour there — that direction is unbounded.
//
// The midpoint, rather than the neighbour's hull edge, is what actually keeps
// two adjacent episodes from analysing the same events. A hull-edge boundary
// lets both sides reach all the way across the gap — cluster N forward, cluster
// N+1 backward — so the whole gap lands in both LLM passes. That is not just a
// chase-loop concern: with a ±30 min base window, any two clusters less than an
// hour apart overlap on their FIRST fetch, before any chasing happens. Hence
// every fetch clamps here, not only the re-fetches.
//
// A midpoint also keeps the boundary compatible with the hull protection in
// clampWindow: it always falls outside both hulls (one ends before it, the
// other starts after it), so the two rules can never contradict each other.
// The exception is degenerate input where clusters overlap in time, which
// ClusterFindings does not produce; there the hull wins and some overlap
// returns.
//
// Undated clusters (the no-timestamp bucket ClusterFindings appends last)
// occupy no span and bound nobody. Written to scan the whole slice rather than
// index neighbours, so it does not silently depend on the caller's ordering.
func clusterBoundaries(clusters []Cluster, i int) (prevBound, nextBound time.Time) {
	if i < 0 || i >= len(clusters) {
		return
	}
	self := clusters[i]
	if self.StartTS.IsZero() {
		return
	}
	var prevEnd, nextStart time.Time
	for j := range clusters {
		if j == i {
			continue
		}
		o := clusters[j]
		if o.StartTS.IsZero() {
			continue // undated bucket
		}
		if !o.EndTS.After(self.StartTS) { // ends at or before our hull starts
			if o.EndTS.After(prevEnd) {
				prevEnd = o.EndTS
			}
		}
		if !o.StartTS.Before(self.EndTS) { // starts at or after our hull ends
			if nextStart.IsZero() || o.StartTS.Before(nextStart) {
				nextStart = o.StartTS
			}
		}
	}
	if !prevEnd.IsZero() {
		prevBound = prevEnd.Add(self.StartTS.Sub(prevEnd) / 2)
	}
	if !nextStart.IsZero() {
		// One microsecond back (DuckDB TIMESTAMP resolution) so the boundary
		// instant itself belongs to exactly one side. Both windows are inclusive
		// at both ends, so an event landing precisely on a shared midpoint would
		// otherwise be delivered to both clusters' analyses.
		nextBound = self.EndTS.Add(nextStart.Sub(self.EndTS) / 2).Add(-time.Microsecond)
	}
	return
}
