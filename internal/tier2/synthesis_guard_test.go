package tier2

import (
	"reflect"
	"testing"
	"time"
)

func TestIsStandardTechniqueID(t *testing.T) {
	for _, ok := range []string{"T1059", "T1003.001", "T1110.001"} {
		if !isStandardTechniqueID(ok) {
			t.Errorf("%q should be a standard technique id", ok)
		}
	}
	for _, bad := range []string{"", "T123", "T12345", "1059", "TA0001", "T1059.1", "web-shell", "T1059.0011"} {
		if isStandardTechniqueID(bad) {
			t.Errorf("%q should NOT be a standard technique id", bad)
		}
	}
}

// Task 2: the finding-derived matrix is the source of truth; an LLM-only
// technique (cluster.MITRETechniques with no backing finding) must NOT appear
// in MITREMapping, only in the unconfirmed list.
func TestBuildMITREMappingDropsLLMOnly(t *testing.T) {
	clusters := []Cluster{{
		ID:              1,
		AttackPhase:     "execution",
		MITRETechniques: []string{"T1505.003", "T1550.002", "not-a-technique"}, // LLM hallucination
		Findings: []Finding{
			{MITRETechniques: []string{"T1059"}, MITRETactic: "execution"},
		},
	}}
	got := buildMITREMapping(clusters)
	if len(got) != 1 || got[0].Technique != "T1059" {
		t.Fatalf("matrix must be finding-derived only, got %+v", got)
	}
	un := buildUnconfirmedMITRE(clusters)
	gotTechs := []string{}
	for _, e := range un {
		gotTechs = append(gotTechs, e.Technique)
	}
	// non-standard "not-a-technique" is dropped entirely; the two standard
	// LLM-only ids land in unconfirmed.
	want := []string{"T1505.003", "T1550.002"}
	if !reflect.DeepEqual(gotTechs, want) {
		t.Errorf("unconfirmed = %v, want %v", gotTechs, want)
	}
}

// Task 4: a cluster affirmatively classified benign (or a temporal outlier)
// must not contribute techniques to the attack matrix.
func TestBuildMITREMappingExcludesBenign(t *testing.T) {
	clusters := []Cluster{
		{ID: 1, AttackPhase: "execution", Findings: []Finding{
			{MITRETechniques: []string{"T1059"}},
		}},
		{ID: 2, AttackPhase: "noise", Narrative: "legitimate software install during first boot", Findings: []Finding{
			{MITRETechniques: []string{"T1112"}}, // benign registry write — must be excluded
		}},
	}
	got := buildMITREMapping(clusters)
	if len(got) != 1 || got[0].Technique != "T1059" {
		t.Fatalf("benign cluster technique leaked into matrix: %+v", got)
	}
}

func TestIsBenignCluster(t *testing.T) {
	cases := []struct {
		name    string
		c       Cluster
		outlier bool
		want    bool
	}{
		{"temporal outlier", Cluster{AttackPhase: "execution"}, true, true},
		{"explicit noise phase", Cluster{AttackPhase: "noise"}, false, true},
		{"sysprep narrative", Cluster{AttackPhase: "execution", Narrative: "This is Sysprep first boot activity"}, false, true},
		{"empty phase is NOT benign", Cluster{AttackPhase: ""}, false, false},
		{"real attack", Cluster{AttackPhase: "credential-access", Narrative: "LSASS dump attempt"}, false, false},
	}
	for _, tc := range cases {
		if got := isBenignCluster(tc.c, tc.outlier); got != tc.want {
			t.Errorf("%s: isBenignCluster = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Task 1: a year-apart provisioning cluster makes the timeline unreliable, so
// no "attacker rewound the clock / re-intrusion" reading is asserted.
func TestDetectTimelineReliability(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	reliable := []Cluster{
		{ID: 1, StartTS: base, EndTS: base},
		{ID: 2, StartTS: base.Add(time.Hour), EndTS: base.Add(time.Hour)},
		{ID: 3, StartTS: base.Add(2 * time.Hour), EndTS: base.Add(2 * time.Hour)},
	}
	if r, _ := detectTimelineReliability(reliable, "en"); r != "reliable" {
		t.Errorf("monotonic clusters should be reliable, got %q", r)
	}

	withOutlier := []Cluster{
		{ID: 1, StartTS: base, EndTS: base},
		{ID: 2, StartTS: base.Add(time.Hour), EndTS: base.Add(time.Hour)},
		{ID: 3, StartTS: base.AddDate(-2, 0, 0), EndTS: base.AddDate(-2, 0, 0)}, // provisioning 2y earlier
	}
	r, notes := detectTimelineReliability(withOutlier, "en")
	if r != "unreliable" {
		t.Fatalf("year-apart cluster should make timeline unreliable, got %q", r)
	}
	if len(notes) == 0 {
		t.Error("unreliable timeline should carry explanatory notes")
	}
}

func TestTimeChangeSubjectBenign(t *testing.T) {
	benign := []struct{ sid, user string }{
		{"S-1-5-19", ""},
		{"S-1-5-18", "SYSTEM"},
		{"", "LOCAL SERVICE"},
		{"", "NT AUTHORITY\\W32Time"},
	}
	for _, b := range benign {
		if !timeChangeSubjectBenign(b.sid, b.user) {
			t.Errorf("4616 by (%q,%q) should be benign time-keeping", b.sid, b.user)
		}
	}
	// An interactive user changing the clock is NOT auto-benign — it needs review.
	if timeChangeSubjectBenign("S-1-5-21-1-2-3-1001", "Administrator") {
		t.Error("4616 by an interactive Administrator must not be classed benign")
	}
}

// Task 2: a tool named in the conclusion with no finding backing is reported as
// ungrounded; the same tool with a backing finding is not.
func TestFindUngroundedMentions(t *testing.T) {
	findings := []Finding{
		{Title: "comsvcs.dll LSASS dump attempt", MITRETechniques: []string{"T1003.001"}},
	}
	prose := "The attacker used Mimikatz to dump credentials and dropped a web shell for persistence; they also performed Pass-the-Hash."
	got := findUngroundedMentions(prose, findings)
	want := []string{"Mimikatz", "Web shell", "Pass-the-Hash"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ungrounded = %v, want %v", got, want)
	}

	// Grounded by a finding that names the tool → not reported.
	grounded := []Finding{{Title: "Mimikatz execution detected", MITRETechniques: []string{"T1003.001"}}}
	if got := findUngroundedMentions("Mimikatz was run", grounded); len(got) != 0 {
		t.Errorf("Mimikatz is backed by a finding, should not be ungrounded: %v", got)
	}

	// Grounded by a corroborating technique tag → not reported.
	pth := []Finding{{Title: "NTLM hash reuse", MITRETechniques: []string{"T1550.002"}}}
	if got := findUngroundedMentions("evidence of Pass-the-Hash", pth); len(got) != 0 {
		t.Errorf("Pass-the-Hash backed by T1550.002 should not be ungrounded: %v", got)
	}
}
