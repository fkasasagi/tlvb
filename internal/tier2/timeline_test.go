package tier2

import (
	"context"
	"database/sql"
	"path/filepath"
	"sort"
	"testing"
	"time"

	_ "github.com/marcboeker/go-duckdb"
)

func TestClusterAnchorEpochs(t *testing.T) {
	base := time.Date(2026, 6, 2, 14, 0, 0, 0, time.UTC)
	c := &Cluster{
		StartTS: base,
		EndTS:   base.Add(10 * time.Minute),
		Findings: []Finding{
			{Evidence: []FindingEvidence{
				{TsUTC: base, HasTS: true},
				{TsUTC: base.Add(500 * time.Millisecond), HasTS: true}, // same second → deduped
				{TsUTC: base.Add(2 * time.Minute), HasTS: true},
			}},
			{Evidence: []FindingEvidence{
				{TsUTC: base.Add(2 * time.Minute), HasTS: true}, // dup across findings
				{TsUTC: time.Time{}, HasTS: false},              // no ts → ignored
				{TsUTC: base.Add(2 * time.Hour), HasTS: true},   // outside hull+window → ignored
			}},
		},
	}
	got := clusterAnchorEpochs(c, c.StartTS.Add(-8*time.Minute), c.EndTS.Add(8*time.Minute))
	want := []int64{base.Unix(), base.Add(2 * time.Minute).Unix()}
	if len(got) != len(want) {
		t.Fatalf("anchors: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("anchor[%d]: got %d, want %d", i, got[i], want[i])
		}
	}
}

// TestFetchClusterTimelineProximityCapturesPostAnchorEvent pins the loot.txt
// fix: over a wide cluster hull, an event a few seconds after a detection
// must survive sampling even though the start of the window is packed with
// unrelated noise. An earliest-N sampler would return only the noise.
func TestFetchClusterTimelineProximityCapturesPostAnchorEvent(t *testing.T) {
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

	start := time.Date(2026, 6, 2, 14, 0, 0, 0, time.UTC)
	anchor := start.Add(30 * time.Minute) // detection fires mid-hull
	ins := func(art, aud string, ts time.Time, payload string) {
		if _, err := db.Exec(
			`INSERT INTO unified_events VALUES ('C1','EV1',?,?,?,?,'WS01',?)`,
			art, aud, ts, art, payload); err != nil {
			t.Fatal(err)
		}
	}
	// 100 unrelated MFT writes at the very start of the window.
	for i := 0; i < 100; i++ {
		ins("mft", "noise-"+itoa(i), start.Add(time.Duration(i)*time.Millisecond),
			`{"FileName":"noise.tmp"}`)
	}
	// The staged-loot file, written 9 s after the detection.
	ins("mft", "loot", anchor.Add(9*time.Second), `{"FileName":"loot.txt"}`)

	c := &Cluster{
		StartTS: start,
		EndTS:   start.Add(60 * time.Minute), // wide hull
		Findings: []Finding{
			{RuleID: "cred-dump", Evidence: []FindingEvidence{
				{AuditID: "anchor", TsUTC: anchor, HasTS: true, ArtifactID: "evtx"},
			}},
		},
	}
	// maxRows 30, single artifact → perArtifact 30, far below the 101 MFT rows.
	if err := FetchClusterTimeline(context.Background(), db, "C1", c, 8*time.Minute, 30); err != nil {
		t.Fatalf("fetch: %v", err)
	}

	var lootSeen bool
	for _, ev := range c.RawTimelineExcerpt {
		if fn, _ := ev.Excerpt["FileName"].(string); fn == "loot.txt" {
			lootSeen = true
		}
	}
	if !lootSeen {
		t.Fatalf("loot.txt (anchor+9s) dropped from %d-row excerpt — proximity sampling regressed",
			len(c.RawTimelineExcerpt))
	}
	// Excerpt must be chronological for the LLM.
	if !sort.SliceIsSorted(c.RawTimelineExcerpt, func(i, j int) bool {
		return c.RawTimelineExcerpt[i].TsUTC.Before(c.RawTimelineExcerpt[j].TsUTC)
	}) {
		t.Errorf("excerpt not sorted chronologically")
	}
}

// TestClusterAnchorEpochsIncludesChaseAnchors pins the load-bearing half of the
// chase loop: a window the loop just extended contains no finding evidence by
// construction (nothing out there was detected), so unless the events the LLM
// flagged become anchors themselves, proximity sampling keeps returning rows
// around the original detections and the extension yields nothing.
func TestClusterAnchorEpochsIncludesChaseAnchors(t *testing.T) {
	base := time.Date(2026, 6, 2, 14, 0, 0, 0, time.UTC)
	c := &Cluster{
		StartTS: base,
		EndTS:   base.Add(10 * time.Minute),
		Findings: []Finding{
			{Evidence: []FindingEvidence{{TsUTC: base, HasTS: true}}},
		},
		ChaseAnchors: []time.Time{
			base.Add(40 * time.Minute), // out where the chase reached
			base.Add(90 * time.Minute), // beyond the window — must be dropped
			base,                       // duplicate of a finding anchor
			base.Add(41 * time.Minute), // kept
			{},                         // zero — must be dropped
		},
	}
	lo, hi := base.Add(-30*time.Minute), base.Add(70*time.Minute)
	got := clusterAnchorEpochs(c, lo, hi)

	want := []int64{
		base.Unix(),
		base.Add(40 * time.Minute).Unix(),
		base.Add(41 * time.Minute).Unix(),
	}
	if len(got) != len(want) {
		t.Fatalf("anchors: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("anchor[%d]: got %d, want %d", i, got[i], want[i])
		}
	}
}

// TestFetchClusterTimelineRangeRebuildsExcerpt pins invariant 1: a re-fetch
// after the chase loop moves a window must REPLACE the excerpt, not append to
// it, or the LLM is shown the same event twice.
func TestFetchClusterTimelineRangeRebuildsExcerpt(t *testing.T) {
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
	for i := 0; i < 5; i++ {
		if _, err := db.Exec(
			`INSERT INTO unified_events VALUES ('C1','E1','prefetch',?,?,'exec','H','{}')`,
			"a"+itoa(i), base.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	c := &Cluster{ID: 1, StartTS: base, EndTS: base.Add(4 * time.Minute)}

	ctx := context.Background()
	if err := FetchClusterTimelineRange(ctx, db, "C1", c, base.Add(-time.Hour), base.Add(time.Hour), 300); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	first := len(c.RawTimelineExcerpt)
	if first != 5 {
		t.Fatalf("first fetch returned %d rows, want 5", first)
	}
	if !c.WindowStart.Equal(base.Add(-time.Hour)) || !c.WindowEnd.Equal(base.Add(time.Hour)) {
		t.Errorf("window bounds not recorded: [%v,%v]", c.WindowStart, c.WindowEnd)
	}

	// Same window again: the excerpt must be identical in size, not doubled.
	if err := FetchClusterTimelineRange(ctx, db, "C1", c, base.Add(-time.Hour), base.Add(time.Hour), 300); err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if got := len(c.RawTimelineExcerpt); got != first {
		t.Errorf("re-fetch appended instead of rebuilding: got %d rows, want %d", got, first)
	}
	seen := map[string]bool{}
	for _, ev := range c.RawTimelineExcerpt {
		if seen[ev.AuditID] {
			t.Fatalf("duplicate audit_id %q in excerpt after re-fetch", ev.AuditID)
		}
		seen[ev.AuditID] = true
	}
}

// TestFetchClusterTimelineRangeLeavesClusterIntactOnError pins the atomicity of
// the fetch. The chase loop treats a failed re-fetch as "keep the previous
// round", so a half-applied fetch would leave the cluster claiming a window it
// never sampled while its narrative came from a narrower one — synthesis.json
// would then overstate how much timeline was actually examined.
func TestFetchClusterTimelineRangeLeavesClusterIntactOnError(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("duckdb", filepath.Join(dir, "cases.duckdb"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE unified_events (
		case_id VARCHAR NOT NULL, evidence_id VARCHAR, artifact_id VARCHAR NOT NULL,
		audit_id VARCHAR NOT NULL, ts_utc TIMESTAMP, event_type VARCHAR NOT NULL,
		computer VARCHAR, payload_json VARCHAR NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 6, 2, 14, 0, 0, 0, time.UTC)
	if _, err := db.Exec(
		`INSERT INTO unified_events VALUES ('C1','E1','prefetch','a0',?,'exec','H','{}')`,
		base); err != nil {
		t.Fatal(err)
	}

	c := &Cluster{ID: 1, StartTS: base, EndTS: base.Add(time.Minute)}
	ctx := context.Background()
	narrowLo, narrowHi := base.Add(-5*time.Minute), base.Add(6*time.Minute)
	if err := FetchClusterTimelineRange(ctx, db, "C1", c, narrowLo, narrowHi, 300); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	before := len(c.RawTimelineExcerpt)
	if before == 0 {
		t.Fatal("fixture produced an empty excerpt")
	}

	// Break the DB, then ask for a WIDER window — the kind of re-fetch a chase
	// round issues.
	db.Close()
	wideLo, wideHi := base.Add(-time.Hour), base.Add(time.Hour)
	if err := FetchClusterTimelineRange(ctx, db, "C1", c, wideLo, wideHi, 300); err == nil {
		t.Fatal("expected an error from a closed database")
	}
	if !c.WindowStart.Equal(narrowLo) || !c.WindowEnd.Equal(narrowHi) {
		t.Errorf("failed fetch advertised the wider window: got [%s,%s], want [%s,%s]",
			c.WindowStart.Format(time.RFC3339), c.WindowEnd.Format(time.RFC3339),
			narrowLo.Format(time.RFC3339), narrowHi.Format(time.RFC3339))
	}
	if got := len(c.RawTimelineExcerpt); got != before {
		t.Errorf("failed fetch discarded the previous excerpt: got %d rows, want %d", got, before)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
