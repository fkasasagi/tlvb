package web

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// waitTerminal polls until the job leaves the "running" state (or times out),
// so the goroutine that StartWithReporter spawns has settled.
func waitTerminal(t *testing.T, m *JobsManager, caseID string, kind JobKind) JobStatus {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st := m.Status(caseID, kind)
		if st.State != "running" {
			return st
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job %s/%s never left running state", caseID, kind)
	return JobStatus{}
}

// A fn returning *partialError must land the job in State="partial" (a
// warning) with the detail in Message — NOT State="failed". This is the
// graceful-degradation contract: a parse where 20/21 artifacts succeeded
// should read as partial, not a red FAIL.
func TestPartialErrorMapsToPartialState(t *testing.T) {
	m := newJobsManager()
	m.StartWithReporter("C1", JobParse, "", func(_ context.Context, _ *Reporter) (string, error) {
		return "parsed 1/1 evidences", &partialError{msg: "一部のアーティファクトのパースでエラー — EV-001: 1/21 artifacts failed"}
	})
	st := waitTerminal(t, m, "C1", JobParse)
	if st.State != "partial" {
		t.Fatalf("state = %q, want partial", st.State)
	}
	if st.Error != "" {
		t.Errorf("partial must not set Error, got %q", st.Error)
	}
	if st.Message == "" {
		t.Errorf("partial should carry the detail in Message, got empty")
	}
}

// A plain error must still map to State="failed" (hard failure path intact).
func TestPlainErrorMapsToFailedState(t *testing.T) {
	m := newJobsManager()
	m.StartWithReporter("C2", JobParse, "", func(_ context.Context, _ *Reporter) (string, error) {
		return "", fmt.Errorf("orchestrator: exit status 2")
	})
	st := waitTerminal(t, m, "C2", JobParse)
	if st.State != "failed" {
		t.Fatalf("state = %q, want failed", st.State)
	}
	if st.Error == "" {
		t.Errorf("failed must set Error")
	}
}

// A nil error is the unchanged success path.
func TestNilErrorMapsToSucceeded(t *testing.T) {
	m := newJobsManager()
	m.StartWithReporter("C3", JobParse, "", func(_ context.Context, _ *Reporter) (string, error) {
		return "done", nil
	})
	st := waitTerminal(t, m, "C3", JobParse)
	if st.State != "succeeded" {
		t.Fatalf("state = %q, want succeeded", st.State)
	}
}

func TestReadParseReport(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "report.json")
	if err := os.WriteFile(good, []byte(`{"artifact_succeeded":20,"artifact_failed":1,"detections":21}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if s, f, ok := readParseReport(good); !ok || s != 20 || f != 1 {
		t.Errorf("good report: got (s=%d f=%d ok=%v), want (20 1 true)", s, f, ok)
	}

	// /dev/null and empty path => ok=false (no counts available)
	if _, _, ok := readParseReport("/dev/null"); ok {
		t.Errorf("/dev/null should yield ok=false")
	}
	if _, _, ok := readParseReport(""); ok {
		t.Errorf("empty path should yield ok=false")
	}

	// missing file => ok=false
	if _, _, ok := readParseReport(filepath.Join(dir, "nope.json")); ok {
		t.Errorf("missing file should yield ok=false")
	}

	// malformed JSON => ok=false
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := readParseReport(bad); ok {
		t.Errorf("malformed JSON should yield ok=false")
	}
}
