package agents

import (
	"encoding/json"
	"strings"
	"testing"
)

// Wave 20b: the Audit struct must carry per-run observability so that
// per_event_sec (Wave 20a's per-event timeout coefficient) can be
// re-calibrated from real LLM runs. These tests pin the JSON contract
// and the EngineResponse plumbing for DurationAPIMS.

func TestAudit_Wave20BFieldsRoundTrip(t *testing.T) {
	in := Audit{
		Iterations:      2,
		InputEvents:     100,
		MaxEvents:       100,
		PromptSizeChars: 87234,
		DurationSec:     12.5,
		DurationAPIMS:   11800,
		TokensInput:     6,
		TokensOutput:    4408,
		CacheHitTok:     2545,
		ModelID:         "claude-haiku-4-5-20251001",
		StopReason:      "end_turn",
		SkillFile:       "skills/persistence.md",
		SkillSHA256:     "deadbeef",
		ValidationOK:    true,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, want := range []string{
		`"prompt_size_chars":87234`,
		`"max_events":100`,
		`"duration_api_ms":11800`,
		`"input_events":100`,
		`"iterations":2`,
		`"duration_seconds":12.5`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing JSON field %q in:\n  %s", want, s)
		}
	}
	// Round-trip.
	var out Audit
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.PromptSizeChars != in.PromptSizeChars {
		t.Errorf("PromptSizeChars: got %d, want %d", out.PromptSizeChars, in.PromptSizeChars)
	}
	if out.MaxEvents != in.MaxEvents {
		t.Errorf("MaxEvents: got %d, want %d", out.MaxEvents, in.MaxEvents)
	}
	if out.DurationAPIMS != in.DurationAPIMS {
		t.Errorf("DurationAPIMS: got %d, want %d", out.DurationAPIMS, in.DurationAPIMS)
	}
}

func TestAudit_Wave20BFieldsOmittedWhenZero(t *testing.T) {
	// When the metrics aren't populated (e.g. Anthropic engine without
	// duration_api_ms support) we don't want to noise up findings.json
	// with zero-valued keys. omitempty handles this for ints.
	in := Audit{
		Iterations:   1,
		InputEvents:  50,
		ModelID:      "claude-sonnet-4-6",
		DurationSec:  3.2,
		TokensInput:  100,
		TokensOutput: 500,
	}
	b, _ := json.Marshal(in)
	s := string(b)
	for _, omit := range []string{
		`"prompt_size_chars"`,
		`"max_events"`,
		`"duration_api_ms"`,
	} {
		if strings.Contains(s, omit) {
			t.Errorf("expected %s to be omitted when zero, got:\n  %s", omit, s)
		}
	}
}

func TestEngineResponse_HasDurationAPIMS(t *testing.T) {
	// Just verifies the field exists and is plumbed — Wave 20b regression
	// guard so a future engine refactor doesn't drop it.
	r := EngineResponse{
		Text:          "{}",
		InputTokens:   100,
		OutputTokens:  50,
		DurationMS:    5000,
		DurationAPIMS: 4500,
	}
	if r.DurationAPIMS != 4500 {
		t.Errorf("DurationAPIMS not set: %d", r.DurationAPIMS)
	}
}
