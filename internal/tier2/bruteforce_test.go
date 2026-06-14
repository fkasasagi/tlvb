package tier2

import (
	"testing"
	"time"
)

func mkFail(ts time.Time, user, sub string) logonEvent {
	return logonEvent{EventID: 4625, TsUTC: ts, TargetUser: user, SubStatus: sub, ArtifactID: "evtx"}
}
func mkOK(ts time.Time, user string) logonEvent {
	return logonEvent{EventID: 4624, TsUTC: ts, TargetUser: user, LogonType: "3", ArtifactID: "evtx"}
}

// Task 3: a same-account 4625 burst followed by a 4624 is T1110.001 with high
// severity and the success attached.
func TestBruteForceBurstThenSuccess(t *testing.T) {
	base := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	var ev []logonEvent
	for i := 0; i < 8; i++ {
		ev = append(ev, mkFail(base.Add(time.Duration(i)*30*time.Second), "Administrator", "0xC000006A"))
	}
	ev = append(ev, mkOK(base.Add(5*time.Minute), "Administrator"))

	got := detectBruteForceBursts(ev, 5, bruteForceFailGap, bruteForceSuccessGap)
	if len(got) != 1 {
		t.Fatalf("want 1 brute-force finding, got %d", len(got))
	}
	f := got[0]
	if f.Severity != "high" {
		t.Errorf("burst+success should be high severity, got %q", f.Severity)
	}
	if len(f.MITRETechniques) != 1 || f.MITRETechniques[0] != "T1110.001" {
		t.Errorf("technique = %v, want [T1110.001]", f.MITRETechniques)
	}
	if f.MITRETactic != "credential-access" {
		t.Errorf("tactic = %q, want credential-access", f.MITRETactic)
	}
	// 8 failures + 1 success = 9 evidence rows.
	if len(f.Evidence) != 9 {
		t.Errorf("evidence rows = %d, want 9", len(f.Evidence))
	}
	if f.Source != "heuristic" {
		t.Errorf("source = %q, want heuristic", f.Source)
	}
	prov, conf := ProvenanceForSource(f.Source)
	if prov != "heuristic" || conf != "confirmed" {
		t.Errorf("provenance/confidence = %q/%q, want heuristic/confirmed", prov, conf)
	}
}

// A burst with no following success is still detected, at medium severity.
func TestBruteForceBurstNoSuccess(t *testing.T) {
	base := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	var ev []logonEvent
	for i := 0; i < 6; i++ {
		ev = append(ev, mkFail(base.Add(time.Duration(i)*time.Second), "svc_backup", "0xC000006A"))
	}
	got := detectBruteForceBursts(ev, 5, bruteForceFailGap, bruteForceSuccessGap)
	if len(got) != 1 || got[0].Severity != "medium" {
		t.Fatalf("want 1 medium finding, got %+v", got)
	}
}

// Below threshold → nothing (a user fat-fingering a password twice).
func TestBruteForceBelowThreshold(t *testing.T) {
	base := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	ev := []logonEvent{
		mkFail(base, "alice", "0xC000006A"),
		mkFail(base.Add(time.Second), "alice", "0xC000006A"),
		mkOK(base.Add(2*time.Second), "alice"),
	}
	if got := detectBruteForceBursts(ev, 5, bruteForceFailGap, bruteForceSuccessGap); len(got) != 0 {
		t.Errorf("two failures is not brute force, got %+v", got)
	}
}

// Two bursts separated by a long gap → two findings (no case-specific timing).
func TestBruteForceTwoBursts(t *testing.T) {
	base := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	var ev []logonEvent
	for i := 0; i < 5; i++ {
		ev = append(ev, mkFail(base.Add(time.Duration(i)*time.Second), "Administrator", "0xC000006A"))
	}
	later := base.Add(2 * time.Hour)
	for i := 0; i < 5; i++ {
		ev = append(ev, mkFail(later.Add(time.Duration(i)*time.Second), "Administrator", "0xC000006A"))
	}
	got := detectBruteForceBursts(ev, 5, bruteForceFailGap, bruteForceSuccessGap)
	if len(got) != 2 {
		t.Fatalf("two separated bursts should yield 2 findings, got %d", len(got))
	}
}

// A successful NTLM logon with no preceding failure burst yields no finding —
// it must NOT be inferred as Pass-the-Hash or brute force.
func TestBruteForceCleanLogonNoFinding(t *testing.T) {
	base := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	ev := []logonEvent{mkOK(base, "Administrator")}
	if got := detectBruteForceBursts(ev, 5, bruteForceFailGap, bruteForceSuccessGap); len(got) != 0 {
		t.Errorf("a clean logon is not brute force / PtH, got %+v", got)
	}
}

// DOMAIN\user and bare user collapse to the same account.
func TestNormUser(t *testing.T) {
	if normUser(`CORP\\Administrator`) != "administrator" {
		t.Errorf("got %q", normUser(`CORP\\Administrator`))
	}
	if normUser("Administrator") != normUser(`CORP\Administrator`) {
		t.Error("domain-qualified and bare names must match")
	}
}

func TestEvtxEventDataValue(t *testing.T) {
	// @Name/#text array shape (what EvtxECmd emits for Security EventData).
	arr := `{"EventData":{"Data":[{"@Name":"TargetUserName","#text":"Administrator"},{"@Name":"SubStatus","#text":"0xC000006A"}]}}`
	if got := evtxEventDataValue(arr, "TargetUserName"); got != "Administrator" {
		t.Errorf("TargetUserName = %q", got)
	}
	if got := evtxEventDataValue(arr, "SubStatus"); got != "0xC000006A" {
		t.Errorf("SubStatus = %q", got)
	}
	if got := evtxEventDataValue(arr, "Missing"); got != "" {
		t.Errorf("absent field should be empty, got %q", got)
	}
	// direct key fallback.
	direct := `{"TargetUserName":"bob","LogonType":"10"}`
	if got := evtxEventDataValue(direct, "LogonType"); got != "10" {
		t.Errorf("direct LogonType = %q", got)
	}
}
