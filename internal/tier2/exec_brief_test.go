package tier2

import "testing"

func TestSplitExecBrief(t *testing.T) {
	cases := []struct {
		name         string
		in           string
		wantExec     string
		wantTechHead string // prefix of techSummary
	}{
		{
			name:         "marker splits the two layers",
			in:           "- bullet one\n- bullet two\n---EXEC---\nTechnical paragraph.",
			wantExec:     "- bullet one\n- bullet two",
			wantTechHead: "Technical paragraph.",
		},
		{
			name:         "no marker keeps whole text as technical summary",
			in:           "Just a plain summary with no marker.",
			wantExec:     "",
			wantTechHead: "Just a plain summary with no marker.",
		},
		{
			name:         "marker with nothing after falls back to single layer",
			in:           "Only a brief here\n---EXEC---\n   ",
			wantExec:     "",
			wantTechHead: "Only a brief here",
		},
		{
			name:         "fallback warning (no marker) stays in technical layer",
			in:           fallbackOverallStoryPrefixEN + "\n\ncluster narrative",
			wantExec:     "",
			wantTechHead: fallbackOverallStoryPrefixEN,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			exec, tech := splitExecBrief(c.in)
			if exec != c.wantExec {
				t.Errorf("exec = %q, want %q", exec, c.wantExec)
			}
			if got := tech; len(got) < len(c.wantTechHead) || got[:len(c.wantTechHead)] != c.wantTechHead {
				t.Errorf("tech = %q, want prefix %q", tech, c.wantTechHead)
			}
		})
	}
}

func TestCollectAttackOpenQuestions(t *testing.T) {
	clusters := []Cluster{
		{AttackPhase: "execution", Narrative: "real attack", OpenQuestions: []string{"q1", "q2"}},
		{AttackPhase: "unknown", Narrative: "noise", OpenQuestions: []string{"noise-q"}},                 // dropped (noise)
		{AttackPhase: "lateral-movement", Narrative: "more attack", OpenQuestions: []string{"q2", "q3"}}, // q2 dedup
	}
	got := collectAttackOpenQuestions(clusters)
	want := []string{"q1", "q2", "q3"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("at %d: got %q, want %q", i, got[i], want[i])
		}
	}
}
