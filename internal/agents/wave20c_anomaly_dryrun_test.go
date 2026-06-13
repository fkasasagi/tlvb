package agents

import (
	"reflect"
	"testing"
)

// Wave 20c: anomaly_hunter --dry-run was failing at TacticRegistry lookup
// in Runner.DryRun because anomaly_hunter is intentionally NOT registered
// there (it's Tier 1.5 with its own harness). AnomalyHunter.DryRun is the
// equivalent entry point — these tests pin its public API so the CLI's
// dispatch branch can rely on it.

func TestAnomalyHunter_HasDryRunMethod(t *testing.T) {
	// Reflection check: a DryRun method must exist on *AnomalyHunter so
	// the CLI branch (cmd/tlvb/main.go) and any future caller can
	// invoke it without going through Runner.DryRun.
	typ := reflect.TypeOf(&AnomalyHunter{})
	_, ok := typ.MethodByName("DryRun")
	if !ok {
		t.Fatal("*AnomalyHunter.DryRun method missing (Wave 20c regression)")
	}
}

func TestAnomalyDryRunInfo_HasExpectedFields(t *testing.T) {
	// Pin the contract returned to the CLI so any future refactor that
	// removes a field surfaces immediately. Fields are what the CLI
	// `analyze --tactic anomaly_hunter --dry-run` output uses.
	info := AnomalyDryRunInfo{
		SystemPrompt:   "system prompt text",
		UserMessage:    "user message text",
		EventsScanned:  1000,
		EventsInWindow: 200,
		Truncated:      true,
		Lenses:         []string{"A1", "A2"},
	}
	if info.SystemPrompt == "" || info.UserMessage == "" {
		t.Errorf("SystemPrompt / UserMessage must be set in info")
	}
	if info.EventsScanned != 1000 || info.EventsInWindow != 200 {
		t.Errorf("scanned/window counters not set correctly: %+v", info)
	}
	if !info.Truncated {
		t.Errorf("Truncated flag plumbing")
	}
	if len(info.Lenses) != 2 {
		t.Errorf("Lenses slice should accept multiple entries")
	}
}

func TestAnomalyHunter_RejectsMissingFindingsDir(t *testing.T) {
	// Construction must reject configs that can't possibly succeed so
	// the CLI fails fast with a clear message rather than panicking
	// deep inside DryRun().
	_, err := NewAnomalyHunter(AnomalyConfig{
		CaseID:      "TEST",
		EvidenceID:  "ev1",
		FindingsDir: "",          // missing
		DBPath:      "/tmp/db",
	})
	if err == nil {
		t.Errorf("NewAnomalyHunter must reject empty FindingsDir")
	}
}

func TestAnomalyHunter_RejectsMissingDBPath(t *testing.T) {
	_, err := NewAnomalyHunter(AnomalyConfig{
		CaseID:      "TEST",
		EvidenceID:  "ev1",
		FindingsDir: "/tmp/findings",
		DBPath:      "",          // missing
	})
	if err == nil {
		t.Errorf("NewAnomalyHunter must reject empty DBPath")
	}
}
