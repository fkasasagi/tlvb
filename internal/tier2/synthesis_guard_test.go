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
		{"noise phase, no high finding", Cluster{AttackPhase: "noise", Findings: []Finding{{Severity: "low"}}}, false, true},
		{"noise phase but HIGH finding stays", Cluster{AttackPhase: "noise", Findings: []Finding{{Severity: "high"}}}, false, false},
		{"empty phase is NOT benign", Cluster{AttackPhase: ""}, false, false},
		{"real attack", Cluster{AttackPhase: "credential-access", Narrative: "LSASS dump attempt"}, false, false},
		// Robust contract: narrative wording never drives exclusion. A real attack
		// cluster that merely NOTES a per-finding false positive (誤検知) or explains
		// provisioning/boot context must NOT be excluded wholesale — that dropped
		// the credential-access and defense-evasion clusters in distrib_winrm_spray.
		{"attack noting a FP is NOT benign", Cluster{AttackPhase: "credential-access", Narrative: "ブルートフォース成功。なお一部の署名は誤検知である。"}, false, false},
		{"attack explaining boot context is NOT benign", Cluster{AttackPhase: "defense-evasion", Narrative: "起動シーケンス後にクロックが巻き戻された"}, false, false},
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
	if r, _ := detectTimelineReliability(reliable, false, "en"); r != "reliable" {
		t.Errorf("monotonic clusters should be reliable, got %q", r)
	}

	// A same-day clock reversal (no year-apart cluster) still makes it unreliable.
	if r, notes := detectTimelineReliability(reliable, true, "en"); r != "unreliable" || len(notes) == 0 {
		t.Errorf("clock reversal should make timeline unreliable with notes, got %q/%d", r, len(notes))
	}

	withOutlier := []Cluster{
		{ID: 1, StartTS: base, EndTS: base},
		{ID: 2, StartTS: base.Add(time.Hour), EndTS: base.Add(time.Hour)},
		{ID: 3, StartTS: base.AddDate(-2, 0, 0), EndTS: base.AddDate(-2, 0, 0)}, // provisioning 2y earlier
	}
	r, notes := detectTimelineReliability(withOutlier, false, "en")
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
	confirmed := map[string]bool{"T1003.001": true} // confirmed matrix has no PtH / web shell
	prose := "The attacker used Mimikatz to dump credentials and dropped a web shell for persistence; they also performed Pass-the-Hash."
	got := findUngroundedMentions(prose, findings, confirmed)
	want := []string{"Mimikatz", "Web shell", "Pass-the-Hash"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ungrounded = %v, want %v", got, want)
	}

	// Tool name grounded by a finding that names the tool → not reported.
	grounded := []Finding{{Title: "Mimikatz execution detected", MITRETechniques: []string{"T1003.001"}}}
	if got := findUngroundedMentions("Mimikatz was run", grounded, confirmed); len(got) != 0 {
		t.Errorf("Mimikatz is backed by a finding, should not be ungrounded: %v", got)
	}

	// Technique phrase grounded by a CONFIRMED technique → not reported.
	if got := findUngroundedMentions("evidence of Pass-the-Hash", nil, map[string]bool{"T1550.002": true}); len(got) != 0 {
		t.Errorf("Pass-the-Hash backed by a confirmed T1550.002 should not be ungrounded: %v", got)
	}

	// Regression: a finding NAMED "Pass the Hash Activity" but DEMOTED (T1550.002
	// not in the confirmed set) must NOT ground the phrase — it stays flagged.
	namedButDemoted := []Finding{{Title: "Pass the Hash Activity 2", MITRETechniques: []string{"T1550.002"}}}
	if got := findUngroundedMentions("evidence of Pass-the-Hash", namedButDemoted, map[string]bool{}); !reflect.DeepEqual(got, []string{"Pass-the-Hash"}) {
		t.Errorf("a demoted PtH must stay flagged despite the finding name, got %v", got)
	}
}

// The corroboration layer demotes finding-derived but FP-prone technique tags
// when the case lacks supporting context — the distrib_winrm_spray failure mode
// where real Sigma rules tagged web shell / PtH / timestomp on unrelated events.
func TestSplitCorroboratedMITRE(t *testing.T) {
	entries := []MITREEntry{
		{Technique: "T1110.001"}, // brute force — always kept
		{Technique: "T1190"},     // public-facing exploit
		{Technique: "T1505.003"}, // web shell
		{Technique: "T1550.002"}, // pass-the-hash
		{Technique: "T1070.006"}, // timestomp
		{Technique: "T1003.001"}, // LSASS dump — kept
	}

	// No web server, a brute-forced account, and a reversed clock → the three
	// uncorroborated tags are demoted; the rest stay confirmed.
	ctx := groundingContext{
		HasWebArtifact:      false,
		BruteForcedAccounts: map[string]bool{"administrator": true},
		ClockReversed:       true,
	}
	keep, demoted, notes := splitCorroboratedMITRE(entries, ctx, "en")
	keptIDs := techIDs(keep)
	demIDs := techIDs(demoted)
	if !reflect.DeepEqual(keptIDs, []string{"T1110.001", "T1003.001"}) {
		t.Errorf("kept = %v, want [T1110.001 T1003.001]", keptIDs)
	}
	if !reflect.DeepEqual(demIDs, []string{"T1190", "T1505.003", "T1550.002", "T1070.006"}) {
		t.Errorf("demoted = %v, want the four uncorroborated tags", demIDs)
	}
	if len(notes) != 4 {
		t.Errorf("want 4 demotion notes, got %d", len(notes))
	}

	// With a web server, no brute force, and a reliable clock → nothing demoted.
	ctx2 := groundingContext{HasWebArtifact: true, BruteForcedAccounts: map[string]bool{}, ClockReversed: false}
	keep2, demoted2, _ := splitCorroboratedMITRE(entries, ctx2, "en")
	if len(demoted2) != 0 || len(keep2) != len(entries) {
		t.Errorf("fully corroborated case demoted %d (want 0)", len(demoted2))
	}
}

func techIDs(es []MITREEntry) []string {
	out := []string{}
	for _, e := range es {
		out = append(out, e.Technique)
	}
	return out
}

func TestContainsWebArtifact(t *testing.T) {
	if !containsWebArtifact([]string{"evtx", "w3c_iis", "mft"}) {
		t.Error("w3c_iis should be recognised as a web artifact")
	}
	if containsWebArtifact([]string{"evtx", "amcache", "registry", "mft", "usn_journal"}) {
		t.Error("a case with no web server must not report a web artifact")
	}
}

func TestBruteForcedAccountsOf(t *testing.T) {
	findings := []Finding{
		{RuleID: "TLVB-BRUTEFORCE-4625", Evidence: []FindingEvidence{
			{Extra: map[string]any{"TargetUserName": `CORP\Administrator`}},
		}},
		{RuleID: "some-sigma-rule", Evidence: []FindingEvidence{
			{Extra: map[string]any{"TargetUserName": "bob"}},
		}},
	}
	got := bruteForcedAccountsOf(findings)
	if !got["administrator"] || got["bob"] {
		t.Errorf("brute-forced accounts = %v, want only administrator", got)
	}
}
