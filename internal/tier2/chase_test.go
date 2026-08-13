package tier2

import (
	"context"
	"errors"
	"testing"
	"time"
)

func ts(base time.Time, min int) time.Time { return base.Add(time.Duration(min) * time.Minute) }

func TestGrowHull(t *testing.T) {
	base := time.Date(2026, 6, 2, 14, 0, 0, 0, time.UTC)
	cases := []struct {
		name           string
		lo, hi         time.Time
		confirmed      []time.Time
		wantLo, wantHi time.Time
		wantGrew       bool
	}{
		{
			name: "no confirmed events leaves hull untouched",
			lo:   ts(base, 0), hi: ts(base, 10),
			confirmed: nil,
			wantLo:    ts(base, 0), wantHi: ts(base, 10), wantGrew: false,
		},
		{
			name: "events inside the hull do not grow it",
			lo:   ts(base, 0), hi: ts(base, 10),
			confirmed: []time.Time{ts(base, 3), ts(base, 7)},
			wantLo:    ts(base, 0), wantHi: ts(base, 10), wantGrew: false,
		},
		{
			name: "event past the end extends forward only",
			lo:   ts(base, 0), hi: ts(base, 10),
			confirmed: []time.Time{ts(base, 25)},
			wantLo:    ts(base, 0), wantHi: ts(base, 25), wantGrew: true,
		},
		{
			name: "event before the start extends backward only",
			lo:   ts(base, 0), hi: ts(base, 10),
			confirmed: []time.Time{ts(base, -12)},
			wantLo:    ts(base, -12), wantHi: ts(base, 10), wantGrew: true,
		},
		{
			name: "extends both ends from a mixed batch",
			lo:   ts(base, 0), hi: ts(base, 10),
			confirmed: []time.Time{ts(base, -4), ts(base, 5), ts(base, 21)},
			wantLo:    ts(base, -4), wantHi: ts(base, 21), wantGrew: true,
		},
		{
			name: "zero timestamps are ignored",
			lo:   ts(base, 0), hi: ts(base, 10),
			confirmed: []time.Time{{}},
			wantLo:    ts(base, 0), wantHi: ts(base, 10), wantGrew: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lo, hi, grew := growHull(tc.lo, tc.hi, tc.confirmed)
			if !lo.Equal(tc.wantLo) || !hi.Equal(tc.wantHi) {
				t.Errorf("hull: got [%s,%s], want [%s,%s]",
					lo.Format(time.RFC3339), hi.Format(time.RFC3339),
					tc.wantLo.Format(time.RFC3339), tc.wantHi.Format(time.RFC3339))
			}
			if grew != tc.wantGrew {
				t.Errorf("grew: got %v, want %v", grew, tc.wantGrew)
			}
		})
	}
}

func TestClampWindow(t *testing.T) {
	base := time.Date(2026, 6, 2, 14, 0, 0, 0, time.UTC)
	// hull is [base+0, base+10] throughout; the raw window is what gets clamped.
	hullLo, hullHi := ts(base, 0), ts(base, 10)

	cases := []struct {
		name                 string
		lo, hi               time.Time
		prevBound, nextBound time.Time
		wantLo, wantHi       time.Time
	}{
		{
			name: "no boundaries leaves the window alone",
			lo:   ts(base, -30), hi: ts(base, 40),
			wantLo: ts(base, -30), wantHi: ts(base, 40),
		},
		{
			name: "distant boundaries do not clamp",
			lo:   ts(base, -30), hi: ts(base, 40),
			prevBound: ts(base, -600), nextBound: ts(base, 600),
			wantLo: ts(base, -30), wantHi: ts(base, 40),
		},
		{
			name: "forward window stops at the shared boundary",
			lo:   ts(base, -30), hi: ts(base, 40),
			nextBound: ts(base, 25),
			wantLo:    ts(base, -30), wantHi: ts(base, 25),
		},
		{
			name: "backward window stops at the shared boundary",
			lo:   ts(base, -30), hi: ts(base, 40),
			prevBound: ts(base, -18),
			wantLo:    ts(base, -18), wantHi: ts(base, 40),
		},
		{
			// Clamping must never erode this cluster's own hull. Only reachable
			// on degenerate, overlapping input — clusterBoundaries puts a real
			// boundary outside both hulls.
			name: "clamp never cuts into this cluster's hull",
			lo:   ts(base, -30), hi: ts(base, 40),
			prevBound: ts(base, 4), nextBound: ts(base, 6),
			wantLo: hullLo, wantHi: hullHi,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lo, hi := clampWindow(tc.lo, tc.hi, hullLo, hullHi, tc.prevBound, tc.nextBound)
			if !lo.Equal(tc.wantLo) || !hi.Equal(tc.wantHi) {
				t.Errorf("window: got [%s,%s], want [%s,%s]",
					lo.Format(time.RFC3339), hi.Format(time.RFC3339),
					tc.wantLo.Format(time.RFC3339), tc.wantHi.Format(time.RFC3339))
			}
			if lo.After(hullLo) || hi.Before(hullHi) {
				t.Errorf("hull eroded: window [%s,%s] does not cover hull [%s,%s]",
					lo.Format(time.RFC3339), hi.Format(time.RFC3339),
					hullLo.Format(time.RFC3339), hullHi.Format(time.RFC3339))
			}
		})
	}
}

func TestResolveFollowUpEvents(t *testing.T) {
	base := time.Date(2026, 6, 2, 14, 0, 0, 0, time.UTC)
	excerpt := []TimelineEvent{
		{AuditID: "a1", TsUTC: ts(base, 1)},
		{AuditID: "a2", TsUTC: ts(base, 2)},
		{AuditID: "a3"}, // no timestamp
	}
	cases := []struct {
		name           string
		ids            []string
		want           []time.Time
		wantUnresolved int
	}{
		{name: "empty input", ids: nil, want: nil},
		{name: "resolves known ids", ids: []string{"a1", "a2"}, want: []time.Time{ts(base, 1), ts(base, 2)}},
		{
			// Failure mode 1: a hallucinated audit_id must not move the window,
			// and must be counted so the operator can see it happening.
			name: "unknown ids are dropped and counted", ids: []string{"nope", "a1"},
			want: []time.Time{ts(base, 1)}, wantUnresolved: 1,
		},
		{
			name: "ids without a timestamp are dropped", ids: []string{"a3"},
			want: nil, wantUnresolved: 1,
		},
		{name: "whitespace is tolerated", ids: []string{"  a2  "}, want: []time.Time{ts(base, 2)}},
		{name: "duplicates collapse", ids: []string{"a1", "a1"}, want: []time.Time{ts(base, 1)}},
		{
			name: "repeated bad ids count once", ids: []string{"nope", "nope"},
			want: nil, wantUnresolved: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matched, unresolved := resolveFollowUpEvents(excerpt, tc.ids)
			got := eventTimes(matched)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d timestamps %v, want %d %v", len(got), got, len(tc.want), tc.want)
			}
			for i := range tc.want {
				if !got[i].Equal(tc.want[i]) {
					t.Errorf("[%d]: got %s, want %s", i,
						got[i].Format(time.RFC3339), tc.want[i].Format(time.RFC3339))
				}
			}
			if unresolved != tc.wantUnresolved {
				t.Errorf("unresolved: got %d, want %d", unresolved, tc.wantUnresolved)
			}
		})
	}
}

// TestRunChaseRecordsEvidenceWhenDisabled pins the observability contract: even
// with the chase off, the events the analysis flagged are kept as evidence and
// counted, so a zero-round run can be told apart from a run where the model
// reported nothing at all.
func TestRunChaseRecordsEvidenceWhenDisabled(t *testing.T) {
	base := time.Date(2026, 6, 2, 14, 0, 0, 0, time.UTC)
	c := &Cluster{
		ID: 1, StartTS: ts(base, 0), EndTS: ts(base, 10),
		RawTimelineExcerpt: []TimelineEvent{
			{AuditID: "in", TsUTC: ts(base, 5), ArtifactID: "prefetch", EventType: "exec"},
		},
	}
	f := &fakeChase{attackEventsPerRound: [][]string{{"in", "ghost"}}}
	var audit SynthAudit
	if _, err := runChase(context.Background(), c, 30*time.Minute, 0,
		time.Time{}, time.Time{}, f.deps(c), &audit); err != nil {
		t.Fatalf("runChase: %v", err)
	}
	if len(c.FollowUpRefs) != 1 || c.FollowUpRefs[0].AuditID != "in" {
		t.Errorf("FollowUpRefs = %+v, want the one resolvable event", c.FollowUpRefs)
	}
	if c.FollowUpRefs[0].ArtifactID != "prefetch" {
		t.Errorf("artifact not carried into the ref: %+v", c.FollowUpRefs[0])
	}
	if audit.ChaseEventsFlagged != 1 || audit.ChaseEventsUnresolved != 1 {
		t.Errorf("audit flagged=%d unresolved=%d, want 1/1",
			audit.ChaseEventsFlagged, audit.ChaseEventsUnresolved)
	}
	if c.ChaseRounds != 0 {
		t.Errorf("ChaseRounds=%d, want 0 with the chase disabled", c.ChaseRounds)
	}
}

// fakeChase drives runChase without a DB or an LLM. attackEventsPerRound[i]
// is what the analysis "returns" on round i; the refetch hook records the
// window it was asked for and repopulates the excerpt.
type fakeChase struct {
	attackEventsPerRound [][]string
	excerpt              []TimelineEvent
	analyseCalls         int
	refetchCalls         int
	windows              [][2]time.Time
	refetchErr           error
	// analyseErrAtCall makes the Nth (1-based) analyse call fail, modelling a
	// chase round whose re-fetch succeeded but whose model call did not.
	analyseErrAtCall int
}

func (f *fakeChase) deps(c *Cluster) chaseDeps {
	return chaseDeps{
		analyse: func(_ context.Context, cl *Cluster) (*clusterAnalysisResp, error) {
			i := f.analyseCalls
			f.analyseCalls++
			if f.analyseErrAtCall == f.analyseCalls {
				return nil, errors.New("model call failed")
			}
			var ev []string
			if i < len(f.attackEventsPerRound) {
				ev = f.attackEventsPerRound[i]
			}
			return &clusterAnalysisResp{Narrative: "n", FollowUpEvents: ev}, nil
		},
		refetch: func(_ context.Context, cl *Cluster, lo, hi time.Time) error {
			f.refetchCalls++
			f.windows = append(f.windows, [2]time.Time{lo, hi})
			if f.refetchErr != nil {
				return f.refetchErr
			}
			cl.RawTimelineExcerpt = f.excerpt
			cl.WindowStart, cl.WindowEnd = lo, hi
			return nil
		},
	}
}

func TestRunChase(t *testing.T) {
	base := time.Date(2026, 6, 2, 14, 0, 0, 0, time.UTC)
	const W = 30 * time.Minute

	// Excerpt spans well past the hull so the LLM can "find" late events.
	excerpt := []TimelineEvent{
		{AuditID: "in", TsUTC: ts(base, 5)},
		{AuditID: "late1", TsUTC: ts(base, 25)},
		{AuditID: "late2", TsUTC: ts(base, 50)},
		{AuditID: "late3", TsUTC: ts(base, 80)},
		{AuditID: "early", TsUTC: ts(base, -20)},
	}

	newCluster := func() *Cluster {
		return &Cluster{
			ID: 1, StartTS: ts(base, 0), EndTS: ts(base, 10),
			RawTimelineExcerpt: excerpt,
		}
	}

	t.Run("no attack events means no chase", func(t *testing.T) {
		c := newCluster()
		f := &fakeChase{attackEventsPerRound: [][]string{nil}, excerpt: excerpt}
		var audit SynthAudit
		resp, err := runChase(context.Background(), c, W, 2, time.Time{}, time.Time{}, f.deps(c), &audit)
		if err != nil {
			t.Fatalf("runChase: %v", err)
		}
		if resp == nil || resp.Narrative != "n" {
			t.Fatalf("resp: %+v", resp)
		}
		if f.analyseCalls != 1 || f.refetchCalls != 0 {
			t.Errorf("calls: analyse=%d refetch=%d, want 1/0", f.analyseCalls, f.refetchCalls)
		}
		if c.ChaseRounds != 0 || audit.ChaseClustersExtended != 0 {
			t.Errorf("ChaseRounds=%d extended=%d, want 0/0", c.ChaseRounds, audit.ChaseClustersExtended)
		}
	})

	t.Run("events inside the hull do not trigger a chase", func(t *testing.T) {
		c := newCluster()
		f := &fakeChase{attackEventsPerRound: [][]string{{"in"}}, excerpt: excerpt}
		var audit SynthAudit
		if _, err := runChase(context.Background(), c, W, 2, time.Time{}, time.Time{}, f.deps(c), &audit); err != nil {
			t.Fatalf("runChase: %v", err)
		}
		if f.refetchCalls != 0 || c.ChaseRounds != 0 {
			t.Errorf("refetch=%d rounds=%d, want 0/0", f.refetchCalls, c.ChaseRounds)
		}
	})

	t.Run("one late event extends the window forward once", func(t *testing.T) {
		c := newCluster()
		f := &fakeChase{attackEventsPerRound: [][]string{{"late1"}, nil}, excerpt: excerpt}
		var audit SynthAudit
		if _, err := runChase(context.Background(), c, W, 2, time.Time{}, time.Time{}, f.deps(c), &audit); err != nil {
			t.Fatalf("runChase: %v", err)
		}
		if f.analyseCalls != 2 || f.refetchCalls != 1 {
			t.Fatalf("calls: analyse=%d refetch=%d, want 2/1", f.analyseCalls, f.refetchCalls)
		}
		// hull.hi moved 10 -> 25, so the window end must be 25 + W.
		wantHi := ts(base, 25).Add(W)
		if got := f.windows[0][1]; !got.Equal(wantHi) {
			t.Errorf("window hi: got %s, want %s", got.Format(time.RFC3339), wantHi.Format(time.RFC3339))
		}
		// Backward edge is untouched: still the original hull start - W.
		wantLo := ts(base, 0).Add(-W)
		if got := f.windows[0][0]; !got.Equal(wantLo) {
			t.Errorf("window lo: got %s, want %s", got.Format(time.RFC3339), wantLo.Format(time.RFC3339))
		}
		if c.ChaseRounds != 1 || audit.ChaseRoundsTotal != 1 || audit.ChaseClustersExtended != 1 {
			t.Errorf("rounds=%d total=%d extended=%d, want 1/1/1",
				c.ChaseRounds, audit.ChaseRoundsTotal, audit.ChaseClustersExtended)
		}
		// The events that pulled the window must survive as sampling anchors.
		if len(c.ChaseAnchors) == 0 {
			t.Error("ChaseAnchors empty — extended region would not be sampled")
		}
	})

	t.Run("a walking trail stops at the round cap", func(t *testing.T) {
		c := newCluster()
		f := &fakeChase{
			attackEventsPerRound: [][]string{{"late1"}, {"late2"}, {"late3"}, {"late3"}},
			excerpt:              excerpt,
		}
		var audit SynthAudit
		if _, err := runChase(context.Background(), c, W, 2, time.Time{}, time.Time{}, f.deps(c), &audit); err != nil {
			t.Fatalf("runChase: %v", err)
		}
		if c.ChaseRounds != 2 {
			t.Errorf("ChaseRounds=%d, want 2 (the cap)", c.ChaseRounds)
		}
		if f.analyseCalls != 3 {
			t.Errorf("analyse calls=%d, want 3 (initial + 2 chase rounds)", f.analyseCalls)
		}
		if audit.ChaseRoundsCapped != 1 {
			t.Errorf("ChaseRoundsCapped=%d, want 1", audit.ChaseRoundsCapped)
		}
	})

	// "Capped" must mean "budget ran out while the trail was still running",
	// not merely "the budget ran out". A trail that ends exactly as the last
	// round completes was fully explored, and the report must not hedge it.
	t.Run("a trail that ends on the last round is not reported as capped", func(t *testing.T) {
		c := newCluster()
		f := &fakeChase{
			attackEventsPerRound: [][]string{{"late1"}, {"late2"}, nil},
			excerpt:              excerpt,
		}
		var audit SynthAudit
		if _, err := runChase(context.Background(), c, W, 2, time.Time{}, time.Time{}, f.deps(c), &audit); err != nil {
			t.Fatalf("runChase: %v", err)
		}
		if c.ChaseRounds != 2 {
			t.Errorf("ChaseRounds=%d, want 2 (both rounds used)", c.ChaseRounds)
		}
		if audit.ChaseRoundsCapped != 0 {
			t.Errorf("ChaseRoundsCapped=%d, want 0 — the trail ended inside the budget",
				audit.ChaseRoundsCapped)
		}
		if audit.ChaseClustersExtended != 1 {
			t.Errorf("ChaseClustersExtended=%d, want 1 — it counts CLUSTERS, not rounds",
				audit.ChaseClustersExtended)
		}
		if audit.ChaseRoundsTotal != 2 {
			t.Errorf("ChaseRoundsTotal=%d, want 2", audit.ChaseRoundsTotal)
		}
	})

	t.Run("chase disabled reproduces the single-pass behaviour", func(t *testing.T) {
		c := newCluster()
		f := &fakeChase{attackEventsPerRound: [][]string{{"late3"}}, excerpt: excerpt}
		var audit SynthAudit
		if _, err := runChase(context.Background(), c, W, 0, time.Time{}, time.Time{}, f.deps(c), &audit); err != nil {
			t.Fatalf("runChase: %v", err)
		}
		if f.analyseCalls != 1 || f.refetchCalls != 0 || c.ChaseRounds != 0 {
			t.Errorf("analyse=%d refetch=%d rounds=%d, want 1/0/0",
				f.analyseCalls, f.refetchCalls, c.ChaseRounds)
		}
	})

	// Reaching the boundary is a geometric accident of window width; CROSSING it
	// with traced activity is evidence the episodes are one. Only the latter may
	// set the continuity flag, or every pair of clusters 31-59 min apart would
	// claim continuity at the default ±30 min window with nothing between them.
	t.Run("a window touching the boundary does not claim continuity", func(t *testing.T) {
		c := newCluster()
		f := &fakeChase{attackEventsPerRound: [][]string{{"late1"}, nil}, excerpt: excerpt}
		var audit SynthAudit
		nextBound := ts(base, 40) // window would reach 25+30=55, so it clamps here
		if _, err := runChase(context.Background(), c, W, 2, time.Time{}, nextBound, f.deps(c), &audit); err != nil {
			t.Fatalf("runChase: %v", err)
		}
		if got := f.windows[0][1]; !got.Equal(nextBound) {
			t.Errorf("window hi: got %s, want clamp at %s",
				got.Format(time.RFC3339), nextBound.Format(time.RFC3339))
		}
		if c.ContinuesIntoNext {
			t.Error("ContinuesIntoNext set although the traced activity (+25) " +
				"stopped well short of the boundary (+40)")
		}
	})

	t.Run("activity traced past the boundary claims continuity and stops there", func(t *testing.T) {
		c := newCluster()
		// late2 is at +50, beyond the +40 boundary.
		f := &fakeChase{attackEventsPerRound: [][]string{{"late2"}, nil}, excerpt: excerpt}
		var audit SynthAudit
		nextBound := ts(base, 40)
		if _, err := runChase(context.Background(), c, W, 2, time.Time{}, nextBound, f.deps(c), &audit); err != nil {
			t.Fatalf("runChase: %v", err)
		}
		if !c.ContinuesIntoNext {
			t.Error("ContinuesIntoNext not set although activity was traced past the boundary")
		}
		if c.ContinuesFromPrev {
			t.Error("ContinuesFromPrev set without a previous neighbour")
		}
		// The hull stops AT the boundary: events beyond it are the next
		// cluster's to explain, and reaching over would analyse them twice.
		if got := f.windows[0][1]; got.After(nextBound) {
			t.Errorf("window hi %s reached past the boundary %s",
				got.Format(time.RFC3339), nextBound.Format(time.RFC3339))
		}
	})

	t.Run("activity traced past the backward boundary claims continuity", func(t *testing.T) {
		c := newCluster()
		f := &fakeChase{attackEventsPerRound: [][]string{{"early"}, nil}, excerpt: excerpt}
		var audit SynthAudit
		prevBound := ts(base, -10) // "early" is at -20, past it
		if _, err := runChase(context.Background(), c, W, 2, prevBound, time.Time{}, f.deps(c), &audit); err != nil {
			t.Fatalf("runChase: %v", err)
		}
		if !c.ContinuesFromPrev {
			t.Error("ContinuesFromPrev not set although activity was traced past the boundary")
		}
		if got := f.windows[0][0]; got.Before(prevBound) {
			t.Errorf("window lo %s reached past the boundary %s",
				got.Format(time.RFC3339), prevBound.Format(time.RFC3339))
		}
	})

	t.Run("a refetch failure keeps the last good analysis", func(t *testing.T) {
		c := newCluster()
		f := &fakeChase{
			attackEventsPerRound: [][]string{{"late1"}, nil},
			excerpt:              excerpt,
			refetchErr:           errors.New("duckdb exploded"),
		}
		var audit SynthAudit
		resp, err := runChase(context.Background(), c, W, 2, time.Time{}, time.Time{}, f.deps(c), &audit)
		if err != nil {
			t.Fatalf("runChase must degrade gracefully, got error: %v", err)
		}
		if resp == nil || resp.Narrative != "n" {
			t.Fatalf("resp: %+v", resp)
		}
		if f.analyseCalls != 1 {
			t.Errorf("analyse calls=%d, want 1 (no re-analysis after a failed refetch)", f.analyseCalls)
		}
	})

	// A round may fetch a wider window and then fail to analyse it. The
	// narrative we fall back on describes the PREVIOUS window, so the cluster
	// must not go on advertising the wider span — a report that names a window
	// the analysis never read is a report that overstates its own coverage.
	t.Run("a failed analysis does not leave a widened window claim", func(t *testing.T) {
		c := newCluster()
		c.WindowStart, c.WindowEnd = ts(base, 0).Add(-W), ts(base, 10).Add(W)
		initialLo, initialHi := c.WindowStart, c.WindowEnd

		f := &fakeChase{
			attackEventsPerRound: [][]string{{"late1"}},
			excerpt:              excerpt,
			analyseErrAtCall:     2, // initial pass ok, chase round fails
		}
		var audit SynthAudit
		resp, err := runChase(context.Background(), c, W, 2, time.Time{}, time.Time{}, f.deps(c), &audit)
		if err != nil {
			t.Fatalf("runChase must degrade gracefully: %v", err)
		}
		if resp == nil || resp.Narrative != "n" {
			t.Fatalf("resp: %+v", resp)
		}
		if f.refetchCalls != 1 {
			t.Errorf("refetch calls=%d, want 1", f.refetchCalls)
		}
		if !c.WindowStart.Equal(initialLo) || !c.WindowEnd.Equal(initialHi) {
			t.Errorf("window not restored: got [%s,%s], want [%s,%s]",
				c.WindowStart.Format(time.RFC3339), c.WindowEnd.Format(time.RFC3339),
				initialLo.Format(time.RFC3339), initialHi.Format(time.RFC3339))
		}
		if c.ChaseRounds != 0 {
			t.Errorf("ChaseRounds=%d, want 0 — the round produced no narrative", c.ChaseRounds)
		}
		if audit.ChaseRoundsTotal != 0 || audit.ChaseClustersExtended != 0 {
			t.Errorf("audit credited an uncommitted round: total=%d extended=%d",
				audit.ChaseRoundsTotal, audit.ChaseClustersExtended)
		}
	})

	t.Run("undated clusters are skipped", func(t *testing.T) {
		c := &Cluster{ID: 9}
		f := &fakeChase{attackEventsPerRound: [][]string{{"late3"}}, excerpt: excerpt}
		var audit SynthAudit
		if _, err := runChase(context.Background(), c, W, 2, time.Time{}, time.Time{}, f.deps(c), &audit); err != nil {
			t.Fatalf("runChase: %v", err)
		}
		if f.analyseCalls != 1 || f.refetchCalls != 0 {
			t.Errorf("analyse=%d refetch=%d, want 1/0", f.analyseCalls, f.refetchCalls)
		}
	})
}

func TestClusterBoundaries(t *testing.T) {
	base := time.Date(2026, 6, 2, 14, 0, 0, 0, time.UTC)

	cases := []struct {
		name               string
		clusters           []Cluster
		idx                int
		wantPrev, wantNext time.Time
	}{
		{
			name: "first cluster is bounded only on the forward side",
			clusters: []Cluster{
				{ID: 1, StartTS: ts(base, 0), EndTS: ts(base, 10)},
				{ID: 2, StartTS: ts(base, 100), EndTS: ts(base, 110)},
				{ID: 3}, // undated bucket — occupies no span, bounds nobody
			},
			idx: 0, wantNext: ts(base, 55).Add(-time.Microsecond), // midpoint of 10..100
		},
		{
			name: "last cluster is bounded only on the backward side",
			clusters: []Cluster{
				{ID: 1, StartTS: ts(base, 0), EndTS: ts(base, 10)},
				{ID: 2, StartTS: ts(base, 100), EndTS: ts(base, 110)},
				{ID: 3},
			},
			idx: 1, wantPrev: ts(base, 55),
		},
		{
			// The load-bearing property: neighbours agree on one boundary, so
			// no span can land in both clusters' analyses.
			name: "both sides of a gap agree on the same boundary",
			clusters: []Cluster{
				{ID: 1, StartTS: ts(base, 0), EndTS: ts(base, 10)},
				{ID: 2, StartTS: ts(base, 50), EndTS: ts(base, 60)},
			},
			idx: 0, wantNext: ts(base, 30).Add(-time.Microsecond), // 10 + (50-10)/2
		},
		{
			name: "the other side of that same gap sees the same boundary",
			clusters: []Cluster{
				{ID: 1, StartTS: ts(base, 0), EndTS: ts(base, 10)},
				{ID: 2, StartTS: ts(base, 50), EndTS: ts(base, 60)},
			},
			idx: 1, wantPrev: ts(base, 30),
		},
		{
			name: "the undated bucket has no boundaries",
			clusters: []Cluster{
				{ID: 1, StartTS: ts(base, 0), EndTS: ts(base, 10)},
				{ID: 3},
			},
			idx: 1,
		},
		{
			// Ordering is the caller's business, not a precondition of this
			// function: the same answer must come back from a shuffled slice.
			name: "result does not depend on slice ordering",
			clusters: []Cluster{
				{ID: 2, StartTS: ts(base, 100), EndTS: ts(base, 110)},
				{ID: 3},
				{ID: 1, StartTS: ts(base, 0), EndTS: ts(base, 10)},
			},
			idx: 0, wantPrev: ts(base, 55),
		},
		{
			name: "nearest neighbour on each side wins",
			clusters: []Cluster{
				{ID: 1, StartTS: ts(base, -500), EndTS: ts(base, -400)},
				{ID: 2, StartTS: ts(base, -60), EndTS: ts(base, -50)},
				{ID: 3, StartTS: ts(base, 0), EndTS: ts(base, 10)},
				{ID: 4, StartTS: ts(base, 60), EndTS: ts(base, 70)},
				{ID: 5, StartTS: ts(base, 900), EndTS: ts(base, 910)},
			},
			idx: 2, wantPrev: ts(base, -25), wantNext: ts(base, 35).Add(-time.Microsecond),
		},
		{
			name:     "out-of-range index is inert",
			clusters: []Cluster{{ID: 1, StartTS: ts(base, 0), EndTS: ts(base, 10)}},
			idx:      7,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prev, next := clusterBoundaries(tc.clusters, tc.idx)
			if !prev.Equal(tc.wantPrev) || !next.Equal(tc.wantNext) {
				t.Errorf("got (prev=%v,next=%v), want (prev=%v,next=%v)",
					prev, next, tc.wantPrev, tc.wantNext)
			}
		})
	}
}

// TestClusterWindowsNeverOverlap is the property the boundary rule exists for.
// It covers the case that actually shipped broken: with a ±30 min base window,
// clusters less than an hour apart overlapped on their FIRST fetch, before any
// chasing — so the same raw events went to two different LLM passes.
func TestClusterWindowsNeverOverlap(t *testing.T) {
	base := time.Date(2026, 6, 2, 14, 0, 0, 0, time.UTC)
	const W = 30 * time.Minute

	// Gaps chosen around the failure: 31 min (just over the cluster gap, so the
	// pair survives clustering) up to comfortably more than 2×W.
	for _, gapMin := range []int{31, 44, 45, 59, 60, 61, 120} {
		t.Run("gap_"+itoa(gapMin)+"min", func(t *testing.T) {
			clusters := []Cluster{
				{ID: 1, StartTS: ts(base, 0), EndTS: ts(base, 5)},
				{ID: 2, StartTS: ts(base, 5+gapMin), EndTS: ts(base, 10+gapMin)},
			}
			var lo [2]time.Time
			var hi [2]time.Time
			for i := range clusters {
				pb, nb := clusterBoundaries(clusters, i)
				lo[i], hi[i] = clusterWindow(clusters[i].StartTS, clusters[i].EndTS, W, pb, nb)
			}
			if hi[0].After(lo[1]) {
				t.Errorf("windows overlap by %v: cluster1 ends %s, cluster2 starts %s",
					hi[0].Sub(lo[1]), hi[0].Format(time.RFC3339), lo[1].Format(time.RFC3339))
			}
			// Each cluster must still fully contain its own detections.
			for i := range clusters {
				if lo[i].After(clusters[i].StartTS) || hi[i].Before(clusters[i].EndTS) {
					t.Errorf("cluster %d window [%s,%s] does not cover its hull [%s,%s]",
						i+1, lo[i].Format(time.RFC3339), hi[i].Format(time.RFC3339),
						clusters[i].StartTS.Format(time.RFC3339), clusters[i].EndTS.Format(time.RFC3339))
				}
			}
		})
	}
}

// TestClusterWindowGrowsMonotonically pins that a chase round never returns a
// NARROWER window than the initial fetch. It did once: the backward clamp used
// the neighbour's hull edge, which for a 31–59 min gap sits inside this
// cluster's own initial window, so round 1 silently dropped context the first
// pass had already read.
func TestClusterWindowGrowsMonotonically(t *testing.T) {
	base := time.Date(2026, 6, 2, 14, 0, 0, 0, time.UTC)
	const W = 30 * time.Minute
	clusters := []Cluster{
		{ID: 1, StartTS: ts(base, -60), EndTS: ts(base, -45)},
		{ID: 2, StartTS: ts(base, 0), EndTS: ts(base, 10)},
		{ID: 3, StartTS: ts(base, 90), EndTS: ts(base, 100)},
	}
	pb, nb := clusterBoundaries(clusters, 1)
	lo0, hi0 := clusterWindow(clusters[1].StartTS, clusters[1].EndTS, W, pb, nb)

	// A chase round grows the hull both ways and recomputes.
	lo1, hi1 := clusterWindow(ts(base, -5), ts(base, 20), W, pb, nb)

	if lo1.After(lo0) {
		t.Errorf("window shrank backward: round-1 lo %s is later than initial lo %s",
			lo1.Format(time.RFC3339), lo0.Format(time.RFC3339))
	}
	if hi1.Before(hi0) {
		t.Errorf("window shrank forward: round-1 hi %s is earlier than initial hi %s",
			hi1.Format(time.RFC3339), hi0.Format(time.RFC3339))
	}
}
