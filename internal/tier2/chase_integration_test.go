package tier2

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/marcboeker/go-duckdb"
)

// TestChaseAgainstRealTimelineFetch runs the whole loop against a real DuckDB
// with the real fetch wired in as the re-fetch dependency — only the model call
// is faked.
//
// The unit tests substitute a fake re-fetch, so they never exercise the actual
// query, the window arithmetic feeding it, or the fact that each round can only
// flag what the PREVIOUS round's window contained. That last property is what
// makes the loop a walk rather than a single jump: the trail is followed one
// window at a time, each round seeing a little further than the last.
func TestChaseAgainstRealTimelineFetch(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("duckdb", filepath.Join(dir, "cases.duckdb"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE unified_events (
		case_id VARCHAR NOT NULL, evidence_id VARCHAR, artifact_id VARCHAR NOT NULL,
		audit_id VARCHAR NOT NULL, ts_utc TIMESTAMP, event_type VARCHAR NOT NULL,
		computer VARCHAR, payload_json VARCHAR NOT NULL)`); err != nil {
		t.Fatal(err)
	}

	base := time.Date(2026, 6, 2, 14, 0, 0, 0, time.UTC)
	at := func(min int) time.Time { return base.Add(time.Duration(min) * time.Minute) }
	ins := func(art, aud string, ts time.Time, payload string) {
		if _, err := db.Exec(
			`INSERT INTO unified_events VALUES ('C1','E1',?,?,?,?,'WS01',?)`,
			art, aud, ts, art, payload); err != nil {
			t.Fatal(err)
		}
	}

	// One detection at +1, then undetected attacker activity laid out so that
	// each step is reachable only from the window the previous step opened:
	//
	//   hull [0,+2] → initial window [-30,+32]  → "stage" (+25) visible
	//   hull [0,+25] → window [-30,+55]         → "wipe"  (+50) visible
	//   hull [0,+50] → window [-30,+80]
	//
	// A single ±30 pass stops at +32 and never sees the cleanup at all.
	ins("evtx", "det-1", at(1), `{"EventId":"4688"}`)
	for i := 0; i < 20; i++ {
		ins("mft", "churn-"+itoa(i), at(2).Add(time.Duration(i)*time.Second),
			`{"FileName":"temp.tmp"}`)
	}
	ins("mft", "stage", at(25), `{"FileName":"loot.zip"}`)
	ins("mft", "wipe", at(50), `{"FileName":"cleanup.bat"}`)

	c := &Cluster{
		ID: 1, StartTS: base, EndTS: at(2),
		Findings: []Finding{{RuleID: "r1", Evidence: []FindingEvidence{
			{AuditID: "det-1", TsUTC: at(1), HasTS: true, ArtifactID: "evtx"},
		}}},
	}

	const W = 30 * time.Minute
	ctx := context.Background()
	// First fetch, exactly as the runner does it.
	lo, hi := clusterWindow(c.StartTS, c.EndTS, W, time.Time{}, time.Time{})
	if err := FetchClusterTimelineRange(ctx, db, "C1", c, lo, hi, 60); err != nil {
		t.Fatalf("initial fetch: %v", err)
	}

	// The model flags the far-out events as attacker activity. It can only name
	// what it was shown, so feed back whatever of them is in the current excerpt.
	analyseCalls := 0
	deps := chaseDeps{
		analyse: func(_ context.Context, cl *Cluster) (*clusterAnalysisResp, error) {
			analyseCalls++
			var flagged []string
			for _, ev := range cl.RawTimelineExcerpt {
				if ev.AuditID == "stage" || ev.AuditID == "wipe" {
					flagged = append(flagged, ev.AuditID)
				}
			}
			return &clusterAnalysisResp{Narrative: "n", FollowUpEvents: flagged}, nil
		},
		refetch: func(ctx context.Context, cl *Cluster, lo, hi time.Time) error {
			return FetchClusterTimelineRange(ctx, db, "C1", cl, lo, hi, 60)
		},
	}

	var audit SynthAudit
	if _, err := runChase(ctx, c, W, 2, time.Time{}, time.Time{}, deps, &audit); err != nil {
		t.Fatalf("runChase: %v", err)
	}

	if c.ChaseRounds != 2 {
		t.Fatalf("ChaseRounds=%d, want 2 (analyse calls=%d) — the trail should have been "+
			"walked one window at a time", c.ChaseRounds, analyseCalls)
	}
	if !c.WindowEnd.Equal(at(80)) {
		t.Errorf("final window ends %s, want %s (hull grown to +50, plus the ±30 window)",
			c.WindowEnd.Format(time.RFC3339), at(80).Format(time.RFC3339))
	}
	// The cleanup at +50 lies 18 min beyond anything a single ±30 pass could
	// have reached; its presence is the whole point of the feature.
	seen := map[string]bool{}
	for _, ev := range c.RawTimelineExcerpt {
		seen[ev.AuditID] = true
	}
	for _, want := range []string{"stage", "wipe"} {
		if !seen[want] {
			t.Errorf("%q missing from the %d-row final excerpt", want, len(c.RawTimelineExcerpt))
		}
	}
	if len(c.FollowUpRefs) != 2 {
		t.Errorf("FollowUpRefs=%d, want 2 flagged events kept as evidence",
			len(c.FollowUpRefs))
	}
	if audit.ChaseRoundsTotal != 2 || audit.ChaseClustersExtended != 1 {
		t.Errorf("audit: rounds=%d clusters=%d, want 2/1",
			audit.ChaseRoundsTotal, audit.ChaseClustersExtended)
	}
	if audit.ChaseRoundsCapped != 0 {
		t.Errorf("ChaseRoundsCapped=%d, want 0 — the trail ended within the budget",
			audit.ChaseRoundsCapped)
	}
}
