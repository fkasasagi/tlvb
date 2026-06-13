package tier2

import (
	"testing"
	"time"
)

func TestParseEvtxTime(t *testing.T) {
	got, ok := parseEvtxTime("2026-06-13 01:50:02.4546349")
	if !ok {
		t.Fatal("should parse EvtxECmd time with fractional seconds")
	}
	want := time.Date(2026, 6, 13, 1, 50, 2, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if _, ok := parseEvtxTime(""); ok {
		t.Error("empty string should not parse")
	}
}

// A 16h backward step (lab Set-Date) is a reversal; sub-second W32Time
// corrections are not.
func TestClockReversedFromEvents(t *testing.T) {
	base := time.Date(2026, 6, 12, 9, 50, 0, 0, time.UTC)
	reversal := []timeChangeEvent{
		{Parsed: true, PreviousTime: base.Add(16 * time.Hour), NewTime: base}, // 16h back
	}
	if !clockReversedFromEvents(reversal, clockReversalThreshold) {
		t.Error("a 16h backward step should be a reversal")
	}

	benign := []timeChangeEvent{
		{Parsed: true, PreviousTime: base, NewTime: base.Add(2 * time.Second)}, // forward 2s
		{Parsed: true, PreviousTime: base.Add(time.Second), NewTime: base},     // back 1s (W32Time)
		{Parsed: false, PreviousTime: base.Add(48 * time.Hour), NewTime: base}, // unparsed → ignored
	}
	if clockReversedFromEvents(benign, clockReversalThreshold) {
		t.Error("sub-second corrections / unparsed events must not count as a reversal")
	}
}
