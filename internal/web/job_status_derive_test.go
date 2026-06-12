package web

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tlvb/tlvb/internal/casedb"
)

// TestJobStatusOrDerived verifies that a server which has never run a job for a
// case (the state right after a restart, when the in-memory JobsManager is
// empty) still reports finished steps as completed by reconstructing their
// status from durable artifacts — rather than snapping everything to "idle".
func TestJobStatusOrDerived(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "cases.duckdb")
	outRoot := filepath.Join(root, "cases")

	intp := func(v int) *int { return &v }

	// Seed the DB: c_full (2 artifacts, both exit 0), c_partial (1 ok + 1 fail),
	// c_empty (registered, no parse rows).
	m, err := casedb.Open(dbPath, casedb.ReadWrite)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	ctx := context.Background()
	for _, id := range []string{"c_full", "c_partial", "c_empty"} {
		if err := m.RegisterCase(ctx, casedb.CaseRow{
			CaseID: id, Name: id, Examiner: "t", Timezone: "UTC", CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("register %s: %v", id, err)
		}
	}
	now := time.Now().UTC()
	if err := m.BulkInsertParseResults(ctx, []casedb.ParseResultRow{
		{CaseID: "c_full", ArtifactID: "evtx", StartedAt: now, Command: "x", ExitCode: intp(0)},
		{CaseID: "c_full", ArtifactID: "mft", StartedAt: now, Command: "x", ExitCode: intp(0)},
		{CaseID: "c_partial", ArtifactID: "evtx", StartedAt: now, Command: "x", ExitCode: intp(0)},
		{CaseID: "c_partial", ArtifactID: "mft", StartedAt: now, Command: "x", ExitCode: intp(1)},
	}); err != nil {
		t.Fatalf("insert parse_results: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	// Durable artifacts for c_full: findings (in a subdir), synthesis, report,
	// autopilot log. c_empty gets none.
	full := filepath.Join(outRoot, "c_full")
	mustWrite(t, filepath.Join(full, "findings", "by-rule", "sigma", "abc.json"), "{}")
	mustWrite(t, filepath.Join(full, "synthesis.json"), "{}")
	mustWrite(t, filepath.Join(full, "reports", "report.html"), "<html></html>")
	mustWrite(t, filepath.Join(full, "autopilot.log"), "done")

	s, err := New(Config{DBPath: dbPath, OutputsRoot: outRoot})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	cases := []struct {
		name      string
		caseID    string
		kind      JobKind
		wantState string
	}{
		{"parse all-ok -> succeeded", "c_full", JobParse, "succeeded"},
		{"parse mixed -> partial", "c_partial", JobParse, "partial"},
		{"parse none -> idle", "c_empty", JobParse, "idle"},
		{"analyze findings -> succeeded", "c_full", JobAnalyze, "succeeded"},
		{"analyze none -> idle", "c_empty", JobAnalyze, "idle"},
		{"synthesize file -> succeeded", "c_full", JobSynthesize, "succeeded"},
		{"synthesize none -> idle", "c_empty", JobSynthesize, "idle"},
		{"report file -> succeeded", "c_full", JobReport, "succeeded"},
		{"report none -> idle", "c_empty", JobReport, "idle"},
		{"autopilot log -> succeeded", "c_full", JobAutopilot, "succeeded"},
		{"autopilot none -> idle", "c_empty", JobAutopilot, "idle"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.jobStatusOrDerived(ctx, tc.caseID, tc.kind).State
			if got != tc.wantState {
				t.Fatalf("%s/%s: state = %q, want %q", tc.caseID, tc.kind, got, tc.wantState)
			}
		})
	}
}

// TestJobStatusLiveWins confirms a live in-memory job overrides the durable
// derivation: a step that FAILED in this process must keep reading "failed"
// even though c_full has findings on disk that would derive to "succeeded".
func TestJobStatusLiveWins(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "cases.duckdb")
	outRoot := filepath.Join(root, "cases")

	m, err := casedb.Open(dbPath, casedb.ReadWrite)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	_ = m.Close()
	mustWrite(t, filepath.Join(outRoot, "c1", "findings", "by-rule", "sigma", "abc.json"), "{}")

	s, err := New(Config{DBPath: dbPath, OutputsRoot: outRoot})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	s.jobs.Start("c1", JobAnalyze, "", func(ctx context.Context, _ func(string)) (string, error) {
		return "", errors.New("boom")
	})
	waitTerminal(t, s.jobs, "c1", JobAnalyze)

	if got := s.jobStatusOrDerived(context.Background(), "c1", JobAnalyze).State; got != "failed" {
		t.Fatalf("live failed job should win over derived succeeded: got %q", got)
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
