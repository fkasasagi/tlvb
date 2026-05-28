package agents

import (
	"testing"
	"time"
)

// Wave 20a — pin the dynamic-timeout sizing so a future refactor can
// confirm intent. Numbers chosen to match the documented table in
// ComputeTimeout's doc comment; that table is the spec.

func TestComputeTimeout_DefaultsMatchSpec(t *testing.T) {
	cases := []struct {
		name     string
		tactic   string
		events   int
		wantSec  int // expected timeout in seconds
	}{
		// Tactic Agent (regular) — linear formula clamped by floor.
		{"tactic 50 events → floor", "persistence", 50, 600},   // 50*5+300=550 < 600 floor
		{"tactic 100 events → floor", "persistence", 100, 800}, // 100*5+300=800, > floor 600
		{"tactic 200 events", "execution", 200, 1300},
		{"tactic 500 events", "discovery", 500, 2800},
		{"tactic 1000 events → ceiling", "lateral_movement", 1000, 3600},

		// anomaly_hunter — 1.5× multiplier applied before clamping.
		// 100*5+300=800, *1.5=1200
		{"anom 100 events", "anomaly_hunter", 100, 1200},
		{"anom 200 events", "anomaly_hunter", 200, 1950},
		// 500*5+300=2800, *1.5=4200 → clamped to 3600 ceiling.
		{"anom 500 events → ceiling", "anomaly_hunter", 500, 3600},
		// Even very small events still get floor (multiplied or not, floor wins).
		{"anom 0 events → floor", "anomaly_hunter", 0, 600},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset env so test default applies.
			t.Setenv("FINDEVIL_LLM_TIMEOUT_PER_EVENT_SEC", "")
			t.Setenv("FINDEVIL_LLM_TIMEOUT_BUFFER_SEC", "")
			t.Setenv("FINDEVIL_LLM_TIMEOUT_FLOOR_SEC", "")
			t.Setenv("FINDEVIL_LLM_TIMEOUT_CEILING_SEC", "")
			t.Setenv("FINDEVIL_LLM_TIMEOUT_ANOMALY_MULT", "")
			got := ComputeTimeout(tc.tactic, tc.events)
			want := time.Duration(tc.wantSec) * time.Second
			if got != want {
				t.Errorf("ComputeTimeout(%q, %d) = %v, want %v",
					tc.tactic, tc.events, got, want)
			}
		})
	}
}

func TestComputeTimeout_EnvOverrideExtendsBudget(t *testing.T) {
	// Operator on a slow model raises per-event cost; verify it scales.
	t.Setenv("FINDEVIL_LLM_TIMEOUT_PER_EVENT_SEC", "10")  // 2x default
	t.Setenv("FINDEVIL_LLM_TIMEOUT_CEILING_SEC", "7200")  // 2h cap

	got := ComputeTimeout("persistence", 200)
	want := time.Duration(200*10+300) * time.Second // 2300s = ~38 min
	if got != want {
		t.Errorf("env override: got %v want %v", got, want)
	}
}

func TestComputeTimeout_EnvOverrideAnomalyMult(t *testing.T) {
	// Operator believes anomaly_hunter needs 2× (not 1.5×).
	t.Setenv("FINDEVIL_LLM_TIMEOUT_ANOMALY_MULT", "2.0")
	t.Setenv("FINDEVIL_LLM_TIMEOUT_CEILING_SEC", "7200")

	got := ComputeTimeout("anomaly_hunter", 100)
	// 100*5+300 = 800, *2.0 = 1600
	want := 1600 * time.Second
	if got != want {
		t.Errorf("anom mult override: got %v want %v", got, want)
	}
}

func TestComputeTimeout_BadEnvFallsBackToDefault(t *testing.T) {
	// Fat-fingered env vars must not produce zero/negative budgets.
	t.Setenv("FINDEVIL_LLM_TIMEOUT_PER_EVENT_SEC", "nope")
	t.Setenv("FINDEVIL_LLM_TIMEOUT_FLOOR_SEC", "-5")
	t.Setenv("FINDEVIL_LLM_TIMEOUT_CEILING_SEC", "")

	got := ComputeTimeout("persistence", 100)
	// Defaults stick: per_event=5, buffer=300, floor=600
	// 100*5+300=800, > floor=600 → 800
	want := 800 * time.Second
	if got != want {
		t.Errorf("bad env defaults: got %v want %v", got, want)
	}
}

func TestComputeTimeout_NegativeEventsTreatedAsZero(t *testing.T) {
	t.Setenv("FINDEVIL_LLM_TIMEOUT_PER_EVENT_SEC", "")
	t.Setenv("FINDEVIL_LLM_TIMEOUT_BUFFER_SEC", "")
	t.Setenv("FINDEVIL_LLM_TIMEOUT_FLOOR_SEC", "")
	t.Setenv("FINDEVIL_LLM_TIMEOUT_CEILING_SEC", "")
	t.Setenv("FINDEVIL_LLM_TIMEOUT_ANOMALY_MULT", "")
	got := ComputeTimeout("persistence", -100)
	// events clamped to 0 → 0*5+300=300 < floor 600 → 600
	if got != 600*time.Second {
		t.Errorf("negative events: got %v want 600s (floor)", got)
	}
}
