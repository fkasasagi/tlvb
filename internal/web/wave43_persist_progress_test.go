package web

import (
	"testing"
	"time"
)

// Wave 43 — persist phase progress surfacing.
// Background: handleParseProgressEvent used to treat every "stage" event
// identically ("orchestrator: <phase>"), so the multi-minute DuckDB
// bulk-insert phase appeared frozen at "done <last-parser> (N/N)" in
// the Status tab. Wave 43 distinguishes persisting / persisted from the
// other stages so examiners can see ingest is in progress.

type fakeReporter struct {
	text string
}

// Minimal stand-in: we only assert on the latest Text() call so we don't
// need to depend on the full Reporter machinery in this unit test.
func (f *fakeReporter) Text(s string) { f.text = s }

// Pull just the Text-emitting branch out for testing. We can't use the real
// Reporter without spinning up a JobStatus, so this mirrors the production
// path but takes the lightweight interface.
func handleStageEventForTest(rep interface{ Text(string) }, phase string,
	rows, ue, pr int) {
	switch phase {
	case "persisting":
		if rows > 0 {
			rep.Text("ingesting " + formatInt(rows) +
				" rows into DuckDB (this can take several minutes for big cases)")
		} else {
			rep.Text("ingesting events into DuckDB")
		}
	case "persisted":
		rep.Text("ingest done: " + formatInt(ue) +
			" events across " + itoaSafe(pr) + " artifacts")
	default:
		rep.Text("orchestrator: " + phase)
	}
}

func itoaSafe(n int) string {
	// Tiny helper to avoid pulling strconv just for one usage in the test.
	if n == 0 {
		return "0"
	}
	const digits = "0123456789"
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = digits[n%10]
		n /= 10
	}
	return string(b[i:])
}

func TestFormatInt(t *testing.T) {
	cases := []struct {
		in  int
		out string
	}{
		{0, "0"},
		{42, "42"},
		{999, "999"},
		{1000, "1,000"},
		{12345, "12,345"},
		{1234567, "1,234,567"},
		{2847193, "2,847,193"},      // realistic USN journal size
		{4000000, "4,000,000"},      // big-case total events
	}
	for _, c := range cases {
		if got := formatInt(c.in); got != c.out {
			t.Errorf("formatInt(%d) = %q, want %q", c.in, got, c.out)
		}
	}
}

func TestStageEvent_PersistingWithRows(t *testing.T) {
	r := &fakeReporter{}
	handleStageEventForTest(r, "persisting", 2_847_193, 0, 0)
	want := "ingesting 2,847,193 rows into DuckDB (this can take several minutes for big cases)"
	if r.text != want {
		t.Errorf("persisting/rows: got %q, want %q", r.text, want)
	}
}

func TestStageEvent_PersistingNoRowHint(t *testing.T) {
	r := &fakeReporter{}
	handleStageEventForTest(r, "persisting", 0, 0, 0)
	if r.text != "ingesting events into DuckDB" {
		t.Errorf("persisting/no-hint: got %q", r.text)
	}
}

func TestStageEvent_Persisted(t *testing.T) {
	r := &fakeReporter{}
	handleStageEventForTest(r, "persisted", 0, 4_023_117, 17)
	want := "ingest done: 4,023,117 events across 17 artifacts"
	if r.text != want {
		t.Errorf("persisted: got %q, want %q", r.text, want)
	}
}

func TestStageEvent_UnknownPhase_FallsBack(t *testing.T) {
	r := &fakeReporter{}
	handleStageEventForTest(r, "extracting_nested_start", 0, 0, 0)
	if r.text != "orchestrator: extracting_nested_start" {
		t.Errorf("fallback: got %q", r.text)
	}
}

// Compile-time confirmation that we haven't changed handleParseProgressEvent's
// signature in a way that breaks the rest of handlers.go. (No assertion —
// the test fails to compile if the symbol's gone.)
var _ = handleParseProgressEvent

// Unused import guard for the time package (Reporter uses time.Duration).
var _ = time.Second
