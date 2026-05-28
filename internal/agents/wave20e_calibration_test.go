package agents

import (
	"encoding/json"
	"testing"
	"time"
)

// Wave 20e: the calibration tool reads TacticReport JSONs and pulls
// Audit.{InputEvents, MaxEvents, PromptSizeChars, DurationSec, Iterations,
// ModelID} as the regression inputs. These tests pin that contract so
// renames of those Audit fields fail the build instead of silently breaking
// the per_event_sec recalibration pipeline.

func TestAudit_CalibrationFieldsAccessible(t *testing.T) {
	// The calibration tool reads these via JSON unmarshalling, so the
	// json tags must stay stable too. Encode a populated Audit and
	// verify all six fields round-trip.
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
		ValidationOK:    true,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Audit
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.InputEvents != 100 || out.MaxEvents != 100 ||
		out.PromptSizeChars != 87234 || out.DurationSec != 12.5 ||
		out.Iterations != 2 || out.ModelID == "" {
		t.Errorf("calibration field round-trip broke: %+v", out)
	}
}

func TestTacticReport_HasAuditField(t *testing.T) {
	// The calibration tool unmarshalls findings/*.json into TacticReport
	// and reads rep.Audit. If Audit is renamed or moved, this fails first.
	rep := TacticReport{
		TacticID:   "TA0003",
		TacticName: "Persistence",
		CaseID:     "TEST",
		EvidenceID: "ev1",
		StartedAt:  time.Now(),
		FinishedAt: time.Now(),
		Status:     "completed",
		Audit: Audit{
			InputEvents:     50,
			DurationSec:     30.0,
			PromptSizeChars: 12000,
		},
	}
	if rep.Audit.InputEvents != 50 || rep.Audit.DurationSec != 30.0 ||
		rep.Audit.PromptSizeChars != 12000 {
		t.Errorf("TacticReport.Audit chain broken: %+v", rep.Audit)
	}
}

func TestTacticReport_ArtifactScopeFieldStaysOptional(t *testing.T) {
	// Wave 20h field; the calibration tool reads it via JSON and writes
	// the scope into the CSV output column. omitempty contract: zero
	// value must not serialize.
	rep := TacticReport{TacticID: "T1", CaseID: "c", EvidenceID: "e"}
	b, _ := json.Marshal(rep)
	if got := string(b); contains([]string{got}, `"artifact_scope":""`) {
		t.Errorf("ArtifactScope must be omitempty; got serialized: %s", got)
	}
	rep2 := TacticReport{TacticID: "T1", CaseID: "c", EvidenceID: "e",
		ArtifactScope: "amcache"}
	b2, _ := json.Marshal(rep2)
	// When set, MUST appear in output.
	found := false
	if s := string(b2); len(s) > 0 {
		// Cheap substring check (avoids importing testify).
		needle := `"artifact_scope":"amcache"`
		for i := 0; i+len(needle) <= len(s); i++ {
			if s[i:i+len(needle)] == needle {
				found = true
				break
			}
		}
	}
	if !found {
		t.Errorf("non-empty ArtifactScope must serialize: %s", string(b2))
	}
}
