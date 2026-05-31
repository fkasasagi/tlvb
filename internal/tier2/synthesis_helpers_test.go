package tier2

import (
	"reflect"
	"testing"
)

// buildMITREMapping aggregates technique hits across clusters and is what
// feeds the report's MITRE table, so its dedup/count/sort contract matters.
func TestBuildMITREMapping(t *testing.T) {
	clusters := []Cluster{
		{ID: 1, AttackPhase: "execution", MITRETechniques: []string{"T1059", "T1003"}},
		{ID: 2, AttackPhase: "credential-access", MITRETechniques: []string{"T1003"}},
		{ID: 3, MITRETechniques: []string{"T1059"}},
	}
	got := buildMITREMapping(clusters)

	// T1059 and T1003 each appear in 2 clusters -> count 2, tie broken by
	// technique string ascending (T1003 before T1059).
	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d (%+v)", len(got), got)
	}
	if got[0].Technique != "T1003" || got[1].Technique != "T1059" {
		t.Fatalf("tie-break order wrong: %s then %s", got[0].Technique, got[1].Technique)
	}
	for _, e := range got {
		if e.FindingCount != 2 {
			t.Errorf("%s count = %d, want 2", e.Technique, e.FindingCount)
		}
	}
	// T1003's tactic comes from the first cluster that carried it with a phase.
	if got[0].ClusterIDs[0] != 1 || got[0].ClusterIDs[1] != 2 {
		t.Errorf("T1003 ClusterIDs = %v, want sorted [1 2]", got[0].ClusterIDs)
	}
	if got[0].Tactic != "execution" {
		t.Errorf("T1003 tactic = %q, want execution (first phased cluster)", got[0].Tactic)
	}
}

func TestMergeAllOpenQuestions(t *testing.T) {
	clusters := []Cluster{
		{OpenQuestions: []string{"how did they get in?", "  ", "what was exfiltrated?"}},
		{OpenQuestions: []string{"how did they get in?", "any lateral movement?"}},
	}
	got := mergeAllOpenQuestions(clusters)
	want := []string{"how did they get in?", "what was exfiltrated?", "any lateral movement?"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (dedup + drop blank, order preserved)", got, want)
	}
}

func TestMergeUnique(t *testing.T) {
	got := mergeUnique([]string{"a", "b", " "}, []string{"b", "c", "a "})
	// "a " trims to "a" which is already seen, so it's dropped too.
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCountFindings(t *testing.T) {
	clusters := []Cluster{
		{Findings: []Finding{{}, {}}},
		{Findings: nil},
		{Findings: []Finding{{}}},
	}
	if n := countFindings(clusters); n != 3 {
		t.Errorf("countFindings = %d, want 3", n)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("short string should pass through, got %q", got)
	}
	if got := truncate("hello world", 5); got != "hello..." {
		t.Errorf("got %q, want hello...", got)
	}
	if got := truncate("edge", 4); got != "edge" {
		t.Errorf("len==n boundary should not truncate, got %q", got)
	}
}
