package tier3

import (
	"strings"
	"testing"

	"github.com/tlvb/tlvb/internal/tier2"
)

// bruteForceEntryCS models the WinRM-spray case shape: the only initial-access
// technique was demoted, and the confirmed entry is a successful brute force
// (T1110.001 under credential-access). The intrusion-path step must NOT disclaim
// the entry — that disclaimer contradicted the brute-force conclusion.
func bruteForceEntryCS() tier2.CaseSynthesis {
	return tier2.CaseSynthesis{
		CaseID:              "winrm-spray",
		TimelineReliability: "unreliable",
		Clusters: []tier2.SynthCluster{
			{ID: 1, AttackPhase: "defense-evasion", Narrative: "clock rolled back during provisioning"},
			{ID: 2, AttackPhase: "credential-access", Narrative: "20x 4625 then success from WS01"},
		},
		MITREMapping: []tier2.MITREEntry{
			{Technique: "T1110.001", Tactic: "credential-access", FindingCount: 1, ClusterIDs: []int{2}},
			{Technique: "T1059.001", Tactic: "execution", FindingCount: 2, ClusterIDs: []int{1, 2}},
			{Technique: "T1021.006", Tactic: "execution", FindingCount: 1, ClusterIDs: []int{2}},
		},
		MITREUnconfirmed: []tier2.MITREEntry{
			{Technique: "T1190", Tactic: "initial-access", FindingCount: 1, ClusterIDs: []int{2}},
		},
	}
}

func TestDeriveIntrusionPath_BruteForceIsEntry(t *testing.T) {
	cs := bruteForceEntryCS()
	got := deriveIntrusionPath(cs, "ja")
	if intrusionDisclaimsEntry(got) {
		t.Errorf("brute-force entry must not disclaim the entry point, got %q", got)
	}
	if !strings.Contains(got, "T1110") {
		t.Errorf("intrusion path should cite the brute-force technique T1110, got %q", got)
	}
	// EN side too.
	if got := deriveIntrusionPath(cs, "en"); intrusionDisclaimsEntry(got) || !strings.Contains(got, "T1110") {
		t.Errorf("EN intrusion path wrong: %q", got)
	}
}

// The fixed report must be internally consistent: the gate finds no blockers.
func TestCheckReportConsistency_CleanOnBruteForce(t *testing.T) {
	issues := checkReportConsistency(bruteForceEntryCS(), "ja")
	for _, is := range issues {
		if is.Severity == "blocker" {
			t.Errorf("brute-force case should have no blocker, got %+v", is)
		}
	}
}

// The gate must actually be able to catch the contradiction class — prove the
// two ingredients (disclaimer text + a confirmed entry vector) are detected, so
// a future regression that re-introduces the disclaimer would fire C1.
func TestConsistencyGate_DetectsContradictionClass(t *testing.T) {
	if !intrusionDisclaimsEntry("侵入の入り口（最初の侵入手段）は、今回集めた証拠からは特定できませんでした。") {
		t.Error("disclaimer phrasing should be detected")
	}
	if vec := confirmedEntryVector(bruteForceEntryCS()); !strings.Contains(vec, "T1110") {
		t.Errorf("confirmed entry vector should include T1110, got %q", vec)
	}
}

// No entry vector + unreliable clock → the fallback must not assert a
// timestamp-order "earliest", and the gate must not flag a C2 it just created.
func TestDeriveIntrusionPath_UnreliableNoEarliestClaim(t *testing.T) {
	cs := tier2.CaseSynthesis{
		TimelineReliability: "unreliable",
		Clusters: []tier2.SynthCluster{
			{ID: 1, AttackPhase: "execution", Narrative: "cmd.exe recon burst"},
		},
		MITREMapping: []tier2.MITREEntry{
			{Technique: "T1059", Tactic: "execution", FindingCount: 1, ClusterIDs: []int{1}},
		},
	}
	got := deriveIntrusionPath(cs, "ja")
	if intrusionAssertsEarliest(got) {
		t.Errorf("unreliable timeline must not claim a timestamp-order earliest, got %q", got)
	}
	for _, is := range checkReportConsistency(cs, "ja") {
		if is.Code == "earliest-claim-on-unreliable-timeline" {
			t.Errorf("gate should not flag C2 after the fix avoids the earliest claim")
		}
	}
}

// The fallback skips a leading noise/provisioning cluster rather than naming it
// as the earliest attack phase.
func TestDeriveIntrusionPath_SkipsNoiseCluster(t *testing.T) {
	cs := tier2.CaseSynthesis{
		Clusters: []tier2.SynthCluster{
			{ID: 1, AttackPhase: "noise", Narrative: "Windows OOBE provisioning"},
			{ID: 2, AttackPhase: "execution", Narrative: "cmd.exe recon"},
		},
	}
	got := deriveIntrusionPath(cs, "en")
	if strings.Contains(strings.ToLower(got), "noise") {
		t.Errorf("fallback should skip the noise cluster, got %q", got)
	}
}

// C3: a technique in both the confirmed and unconfirmed matrices is a warning.
func TestCheckReportConsistency_DuplicateTechnique(t *testing.T) {
	cs := tier2.CaseSynthesis{
		MITREMapping:     []tier2.MITREEntry{{Technique: "T1003.001", Tactic: "credential-access"}},
		MITREUnconfirmed: []tier2.MITREEntry{{Technique: "T1003.001"}},
	}
	found := false
	for _, is := range checkReportConsistency(cs, "ja") {
		if is.Code == "technique-confirmed-and-unconfirmed" {
			found = true
		}
	}
	if !found {
		t.Error("expected a technique-confirmed-and-unconfirmed warning")
	}
}
