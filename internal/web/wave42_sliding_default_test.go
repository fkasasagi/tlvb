package web

import (
	"testing"
)

// Wave 42 — sliding-window is now default-on for Tactic Agent runs (B1 fix).
// Verify the env-var semantics so future env-var refactors don't silently
// revert the default.
func TestSlidingWindowDefault(t *testing.T) {
	cases := []struct {
		name, env string
		want      bool
	}{
		// Default on (Wave 42).
		{"unset", "", true},

		// Truthy / synonym handling (kept simple — anything not in the
		// opt-out set means on, including the legacy opt-in "1").
		{"legacy opt-in 1", "1", true},
		{"explicit true", "true", true},
		{"any garbage", "yes-please", true},

		// Opt-out forms (Wave 42 contract).
		{"opt-out 0", "0", false},
		{"opt-out false", "false", false},
		{"opt-out FALSE (case-insensitive)", "FALSE", false},
		{"opt-out off", "off", false},
		{"opt-out no", "no", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("TLVB_SLIDING_WINDOW", c.env)
			if got := slidingWindowDefault(); got != c.want {
				t.Errorf("TLVB_SLIDING_WINDOW=%q: got %v, want %v",
					c.env, got, c.want)
			}
		})
	}
}
