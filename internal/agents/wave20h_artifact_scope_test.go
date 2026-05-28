package agents

import (
	"sort"
	"testing"
)

// Wave 20h: TacticsForArtifact MUST find every tactic that references the
// artifact in its OR-clauses, and MUST NOT include timeline_review.

func TestTacticsForArtifact_amcache(t *testing.T) {
	got := TacticsForArtifact("amcache")
	// amcache evidences execution (process launch records).
	if !contains(got, "execution") {
		t.Errorf("amcache should at minimum include execution, got %v", got)
	}
	if contains(got, "timeline_review") {
		t.Errorf("timeline_review must be excluded, got %v", got)
	}
}

func TestTacticsForArtifact_scheduled_tasks(t *testing.T) {
	got := TacticsForArtifact("scheduled_tasks")
	// scheduled_tasks shows up in execution (launches), persistence (autostart),
	// and lateral_movement (remote task creation) via tactic_queries.go.
	if !containsAll(got, []string{"execution", "persistence"}) {
		t.Errorf("scheduled_tasks should include {execution, persistence}, got %v", got)
	}
}

func TestTacticsForArtifact_prefetch(t *testing.T) {
	got := TacticsForArtifact("prefetch")
	// prefetch is execution evidence (file execution traces).
	if !contains(got, "execution") {
		t.Errorf("prefetch should include execution, got %v", got)
	}
}

func TestTacticsForArtifact_empty_string_returns_nil(t *testing.T) {
	got := TacticsForArtifact("")
	if len(got) != 0 {
		t.Errorf("empty artifact_id must return empty slice, got %v", got)
	}
}

func TestTacticsForArtifact_unknown_returns_empty(t *testing.T) {
	got := TacticsForArtifact("hypothetical_nonexistent_artifact")
	if len(got) != 0 {
		t.Errorf("unknown artifact must return empty slice, got %v", got)
	}
}

func TestTacticsForArtifact_sorted_output(t *testing.T) {
	// Stable ordering for UI — caller can assume sort.Strings semantics.
	got := TacticsForArtifact("scheduled_tasks")
	sorted := make([]string, len(got))
	copy(sorted, got)
	sort.Strings(sorted)
	for i := range got {
		if got[i] != sorted[i] {
			t.Errorf("output not sorted: got %v, want %v", got, sorted)
			return
		}
	}
}

func TestTacticsForArtifact_excludes_timeline_review(t *testing.T) {
	// timeline_review runs AFTER tactics in synthesizer pipeline, NOT in
	// parallel with them — it must not appear in any per-artifact plan.
	for _, art := range []string{"amcache", "evtx", "mft", "scheduled_tasks", "prefetch"} {
		got := TacticsForArtifact(art)
		if contains(got, "timeline_review") {
			t.Errorf("artifact=%q: timeline_review must be excluded, got %v", art, got)
		}
	}
}

// Verify the SQL prefilter pattern that TacticsForArtifact looks for.
// This is a guard: if someone renames the AND-clause format from
// `artifact_id = 'X'` to e.g. `artifact_id='X'` (no spaces), the helper
// would silently start returning empty results.
func TestTacticsForArtifact_sql_format_assumption_holds(t *testing.T) {
	// Pick a tactic we know references multiple artifacts (the "execution"
	// tactic at line 57+ in tactic_queries.go).
	spec, ok := TacticRegistry["execution"]
	if !ok {
		t.Skip("execution tactic not registered")
	}
	foundDirectFormat := false
	for _, clause := range spec.OrClauses {
		if len(clause) > 0 && (clause[0] == 'a' || clause[0] == '(') {
			// Look for either `artifact_id = 'X'` somewhere in the clause
			if contains([]string{clause}, "artifact_id = '") ||
				stringContains(clause, "artifact_id = '") {
				foundDirectFormat = true
				break
			}
		}
	}
	if !foundDirectFormat {
		t.Errorf(
			"NO OR-clause matches the `artifact_id = 'X'` pattern that "+
				"TacticsForArtifact() searches for. Either the helper or "+
				"the OR-clause format changed — they must stay aligned. "+
				"execution.OrClauses = %v",
			spec.OrClauses,
		)
	}
}

// --- helpers ---

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func containsAll(haystack []string, needles []string) bool {
	for _, n := range needles {
		if !contains(haystack, n) {
			return false
		}
	}
	return true
}

func stringContains(haystack, needle string) bool {
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
