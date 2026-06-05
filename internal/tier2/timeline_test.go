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
	got := clusterAnchorEpochs(c, 8*time.Minute)
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
