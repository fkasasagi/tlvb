package tier1b

import (
	"strings"
	"testing"
	"time"
)

// extractFieldValue is the tolerant string-level JSON field reader used to
// shrink payloads before sending them to the LLM. It must cope with both
// compact and space-padded formatting and with non-string values, so the
// cases below lock that contract in.
func TestExtractFieldValue(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		key     string
		want    string
		wantOK  bool
	}{
		{"compact string", `{"Channel":"Security"}`, "Channel", "Security", true},
		{"space padded string", `{"Channel": "Security"}`, "Channel", "Security", true},
		{"numeric value", `{"EventId": 4625}`, "EventId", "4625", true},
		{"numeric trailing brace", `{"run_count":12}`, "run_count", "12", true},
		{"escaped quote inside", `{"path":"C:\\a\"b"}`, "path", `C:\\a\"b`, true},
		{"missing key", `{"Channel":"Security"}`, "EventId", "", false},
		{"value ends at comma", `{"a":"x","b":"y"}`, "a", "x", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := extractFieldValue(tc.payload, tc.key)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (got %q)", ok, tc.wantOK, got)
			}
			if ok && got != tc.want {
				t.Errorf("value = %q, want %q", got, tc.want)
			}
		})
	}
}

// shrinkPayload had a field-name bug fixed once (see docs/STATUS.md); these
// cases pin the per-artifact key selection, the unknown-artifact excerpt
// fallback, and the 200-char truncation so it can't silently regress.
func TestShrinkPayloadKnownArtifact(t *testing.T) {
	payload := `{"EventId":"4688","Channel":"Security","Noise":"ignored"}`
	out := shrinkPayload("evtx", payload)
	if out["EventId"] != "4688" {
		t.Errorf("EventId = %v, want 4688", out["EventId"])
	}
	if out["Channel"] != "Security" {
		t.Errorf("Channel = %v, want Security", out["Channel"])
	}
	if _, present := out["Noise"]; present {
		t.Errorf("non-wanted key Noise should be dropped, got %v", out["Noise"])
	}
}

func TestShrinkPayloadUnknownArtifactFallsBackToExcerpt(t *testing.T) {
	payload := `{"whatever":"value"}`
	out := shrinkPayload("totally_unknown", payload)
	if out["_excerpt"] != payload {
		t.Errorf("_excerpt = %v, want full payload %q", out["_excerpt"], payload)
	}
}

func TestShrinkPayloadTruncatesLongValues(t *testing.T) {
	long := strings.Repeat("A", 500)
	payload := `{"KeyPath":"` + long + `"}`
	out := shrinkPayload("registry", payload)
	v, ok := out["KeyPath"].(string)
	if !ok {
		t.Fatalf("KeyPath missing or not string: %v", out["KeyPath"])
	}
	if len(v) != 203 || !strings.HasSuffix(v, "...") { // 200 chars + "..."
		t.Errorf("truncated len = %d (suffix %q), want 203 ending in ...", len(v), v[len(v)-3:])
	}
}

func TestNearAnyTime(t *testing.T) {
	base := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	times := []time.Time{base, base.Add(time.Hour)}
	win := 5 * time.Minute

	if !nearAnyTime(base.Add(3*time.Minute), times, win) {
		t.Error("3min after a reference time should be within 5min window")
	}
	if !nearAnyTime(base.Add(-5*time.Minute), times, win) {
		t.Error("exactly -5min should be within (inclusive) window")
	}
	if nearAnyTime(base.Add(10*time.Minute), times, win) {
		t.Error("10min away from both references should be outside window")
	}
	if nearAnyTime(base, nil, win) {
		t.Error("empty reference list should never match")
	}
}
