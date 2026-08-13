package tier2

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	_ "github.com/marcboeker/go-duckdb"
)

// TestRunClampsEveryClusterWindow drives Run() itself.
//
// Every other test in this package calls clusterBoundaries / clusterWindow /
// runChase directly, which cannot catch the failure mode that actually shipped:
// the helpers were correct and the runner simply did not call them on the first
// fetch, so at ±30 min any two clusters less than an hour apart handed the same
// raw events to two different LLM passes. A test that never goes through Run()
// cannot tell a wired-up boundary from an ignored one.
//
// Uses --dry-run, which returns after the timeline fetch and before any model
// call, and reads the per-cluster windows off the progress stream.
func TestRunClampsEveryClusterWindow(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cases.duckdb")

	db, err := sql.Open("duckdb", dbPath)
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
	at := func(min int) time.Time { return base.Add(time.Duration(min) * time.Minute) }

	// Three clusters 40 min apart — comfortably over the 30 min cluster gap, so
	// they stay separate, and comfortably under 2×30 min, so their ±30 windows
	// would overlap without clamping.
	detTimes := []time.Time{at(0), at(45), at(90)}
	for i, d := range detTimes {
		if _, err := db.Exec(
			`INSERT INTO unified_events VALUES ('C1','E1','evtx',?,?,'evtx','WS01','{"EventId":"4688"}')`,
			"det-"+itoa(i), d); err != nil {
			t.Fatal(err)
		}
	}

	// One Tier 1A finding per detection, on disk in the layout LoadFindings reads.
	byRule := filepath.Join(dir, "findings", "by-rule", "sigma")
	if err := os.MkdirAll(byRule, 0o755); err != nil {
		t.Fatal(err)
	}
	for i, d := range detTimes {
		body := `{"finding_id":"f` + itoa(i) + `","case_id":"C1","rule_id":"r` + itoa(i) + `",
			"rule_source":"sigma","approved":true,
			"rule_meta":{"title":"t","level":"high"},
			"evidence":[{"audit_id":"det-` + itoa(i) + `","ts_utc":"` + d.Format(time.RFC3339) + `",
			"artifact_id":"evtx","event_type":"evtx"}]}`
		if err := os.WriteFile(filepath.Join(byRule, "r"+itoa(i)+".json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	db.Close() // Run opens the DB read-only itself

	var windows [][2]time.Time
	winRe := regexp.MustCompile(`^cluster \d+ window (\S+)\.\.(\S+)$`)
	cfg := Config{
		CaseID:          "C1",
		FindingsBaseDir: filepath.Join(dir, "findings"),
		OutputPath:      filepath.Join(dir, "synthesis.json"),
		DBPath:          dbPath,
		SkillsDir:       filepath.Join("..", "..", "skills"),
		DryRun:          true,
		ProgressFn: func(ev Event) {
			m := winRe.FindStringSubmatch(ev.Message)
			if m == nil {
				return
			}
			lo, err1 := time.Parse(time.RFC3339, m[1])
			hi, err2 := time.Parse(time.RFC3339, m[2])
			if err1 != nil || err2 != nil {
				t.Errorf("unparseable window in %q", ev.Message)
				return
			}
			windows = append(windows, [2]time.Time{lo, hi})
		},
	}

	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.ClusterCount != 3 {
		t.Fatalf("ClusterCount=%d, want 3 (45 min apart, cluster gap 30 min)", rep.ClusterCount)
	}
	if len(windows) != 3 {
		t.Fatalf("got %d cluster windows from the progress stream, want 3", len(windows))
	}

	for i := 1; i < len(windows); i++ {
		if !windows[i-1][1].Before(windows[i][0]) {
			t.Errorf("cluster %d window ends %s but cluster %d starts %s — "+
				"overlapping windows hand the same events to two analyses",
				i, windows[i-1][1].Format(time.RFC3339),
				i+1, windows[i][0].Format(time.RFC3339))
		}
	}
	// Sanity: the clamp is what makes them disjoint. Unclamped, each window
	// would be a full 60 min wide.
	if got := windows[1][1].Sub(windows[1][0]); got >= 60*time.Minute {
		t.Errorf("middle window is %v wide — it was not clamped on either side", got)
	}
}
