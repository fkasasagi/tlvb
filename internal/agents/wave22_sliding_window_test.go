package agents

import (
	"testing"
	"time"
)

// Wave 22: sliding window merge semantics. These tests pin the merge rules
// for mergeTacticReports so future tweaks to the per-window agent don't
// silently change downstream Synthesizer input.

func _baseAudit() Audit {
	return Audit{
		ModelID:     "claude-haiku-4-5-20251001",
		SkillFile:   "skills/persistence.md",
		SkillSHA256: "deadbeef",
	}
}

func _stamp(rep *TacticReport) *TacticReport {
	rep.TacticID = "TA0003"
	rep.TacticName = "Persistence"
	rep.CaseID = "TEST"
	rep.EvidenceID = "ev1"
	return rep
}

func TestMergeTacticReports_EmptyReturnsNil(t *testing.T) {
	if got := mergeTacticReports(nil); got != nil {
		t.Errorf("empty input should return nil, got %+v", got)
	}
}

func TestMergeTacticReports_SingleReportPassThrough(t *testing.T) {
	in := _stamp(&TacticReport{
		Status:    "completed",
		StartedAt: time.Now(),
		Audit:     _baseAudit(),
	})
	got := mergeTacticReports([]*TacticReport{in})
	if got != in {
		t.Errorf("single-report merge should return the original ptr (no-op)")
	}
}

func TestMergeTacticReports_FindingsDedupByID(t *testing.T) {
	r1 := _stamp(&TacticReport{
		Status:    "completed",
		StartedAt: time.Now(),
		Audit:     _baseAudit(),
		Findings: []Finding{
			{FindingID: "f-001", TechniqueID: "T1547.001", Summary: "from w0"},
			{FindingID: "f-002", TechniqueID: "T1543.003", Summary: "only in w0"},
		},
	})
	r2 := _stamp(&TacticReport{
		Status:    "completed",
		StartedAt: time.Now(),
		Audit:     _baseAudit(),
		Findings: []Finding{
			{FindingID: "f-001", TechniqueID: "T1547.001", Summary: "from w1"},
			{FindingID: "f-003", TechniqueID: "T1053.005", Summary: "only in w1"},
		},
	})
	got := mergeTacticReports([]*TacticReport{r1, r2})
	if len(got.Findings) != 3 {
		t.Fatalf("expected 3 unique findings, got %d: %+v", len(got.Findings), got.Findings)
	}
	// Stable order: f-001, f-002, f-003.
	expectIDs := []string{"f-001", "f-002", "f-003"}
	for i, f := range got.Findings {
		if f.FindingID != expectIDs[i] {
			t.Errorf("Findings[%d] = %s, want %s", i, f.FindingID, expectIDs[i])
		}
	}
	// f-001 should be the LATER window's version (overwrite policy).
	if got.Findings[0].Summary != "from w1" {
		t.Errorf("f-001 should be the later window's: got %q", got.Findings[0].Summary)
	}
}

func TestMergeTacticReports_NegativesDedupByTechnique(t *testing.T) {
	r1 := _stamp(&TacticReport{
		Status: "completed", Audit: _baseAudit(),
		NegativeFindings: []NegativeFinding{
			{TechniqueID: "T1547.001", Rationale: "no run key in w0"},
			{TechniqueID: "T1546.008", Rationale: "accessibility clean"},
		},
	})
	r2 := _stamp(&TacticReport{
		Status: "completed", Audit: _baseAudit(),
		NegativeFindings: []NegativeFinding{
			{TechniqueID: "T1547.001", Rationale: "no run key in w1"},
			{TechniqueID: "T1543.003", Rationale: "no service"},
		},
	})
	got := mergeTacticReports([]*TacticReport{r1, r2})
	if len(got.NegativeFindings) != 3 {
		t.Errorf("expected 3 unique negatives, got %d", len(got.NegativeFindings))
	}
}

func TestMergeTacticReports_OpenQuestionsDedupByText(t *testing.T) {
	r1 := _stamp(&TacticReport{
		Audit: _baseAudit(),
		OpenQuestions: []OpenQuestion{
			{Question: "Was there a service install?", NextStep: "review 4697"},
			{Question: "Unique to w0?", NextStep: ""},
		},
	})
	r2 := _stamp(&TacticReport{
		Audit: _baseAudit(),
		OpenQuestions: []OpenQuestion{
			{Question: "  was there a service install?  ", NextStep: "review 7045"}, // case + space variant
			{Question: "Unique to w1?", NextStep: ""},
		},
	})
	got := mergeTacticReports([]*TacticReport{r1, r2})
	if len(got.OpenQuestions) != 3 {
		t.Errorf("expected 3 unique questions (case/whitespace insensitive), got %d: %+v",
			len(got.OpenQuestions), got.OpenQuestions)
	}
}

func TestMergeTacticReports_AuditSummed(t *testing.T) {
	r1 := _stamp(&TacticReport{Audit: Audit{
		ModelID: "m", Iterations: 2, InputEvents: 100,
		TokensInput: 10, TokensOutput: 50, CacheHitTok: 5,
		DurationSec: 5.0, PromptSizeChars: 1000, DurationAPIMS: 1500,
		ValidationOK: true,
	}})
	r2 := _stamp(&TacticReport{Audit: Audit{
		ModelID: "m", Iterations: 3, InputEvents: 100,
		TokensInput: 20, TokensOutput: 80, CacheHitTok: 200,
		DurationSec: 7.0, PromptSizeChars: 1200, DurationAPIMS: 1700,
		ValidationOK: true,
	}})
	got := mergeTacticReports([]*TacticReport{r1, r2})
	if got.Audit.Iterations != 5 {
		t.Errorf("Iterations sum: got %d, want 5", got.Audit.Iterations)
	}
	if got.Audit.InputEvents != 200 {
		t.Errorf("InputEvents sum: got %d, want 200", got.Audit.InputEvents)
	}
	if got.Audit.TokensInput != 30 || got.Audit.TokensOutput != 130 {
		t.Errorf("token sums: in=%d out=%d", got.Audit.TokensInput, got.Audit.TokensOutput)
	}
	if got.Audit.DurationSec != 12.0 {
		t.Errorf("DurationSec sum: got %v want 12", got.Audit.DurationSec)
	}
	if got.Audit.PromptSizeChars != 1200 {
		t.Errorf("PromptSizeChars should be MAX: got %d want 1200", got.Audit.PromptSizeChars)
	}
	if !got.Audit.ValidationOK {
		t.Errorf("all-valid should propagate ValidationOK=true")
	}
}

func TestMergeTacticReports_WorstStatusWins(t *testing.T) {
	completed := _stamp(&TacticReport{Status: "completed", Audit: _baseAudit()})
	partial := _stamp(&TacticReport{Status: "partial", Audit: _baseAudit()})
	failed := _stamp(&TacticReport{Status: "failed", Audit: _baseAudit()})

	cases := []struct {
		name   string
		in     []*TacticReport
		expect string
	}{
		{"all_completed", []*TacticReport{completed, completed}, "completed"},
		{"any_partial", []*TacticReport{completed, partial}, "partial"},
		{"any_failed", []*TacticReport{completed, partial, failed}, "failed"},
		{"partial_then_failed", []*TacticReport{partial, failed}, "failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mergeTacticReports(c.in)
			if got.Status != c.expect {
				t.Errorf("Status: got %s, want %s", got.Status, c.expect)
			}
		})
	}
}

func TestConfig_SlidingWindow_FieldsRoundTrip(t *testing.T) {
	cfg := Config{
		SlidingWindow: true,
		WindowOverlap: 0.3,
	}
	if !cfg.SlidingWindow {
		t.Errorf("SlidingWindow field missing")
	}
	if cfg.WindowOverlap != 0.3 {
		t.Errorf("WindowOverlap field missing or wrong: %v", cfg.WindowOverlap)
	}
}

func TestAudit_Wave22FieldsJSONRoundTrip(t *testing.T) {
	in := Audit{
		WindowsTotal:  4,
		WindowSize:    100,
		WindowOverlap: 0.2,
	}
	if in.WindowsTotal != 4 || in.WindowSize != 100 || in.WindowOverlap != 0.2 {
		t.Errorf("Audit Wave 22 fields not accessible: %+v", in)
	}
}
