package tier2

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestChasePromptElicitsFollowUpEventsLive drives ONE real model call to check
// the half of the chase loop unit tests cannot reach: whether the per-cluster
// prompt actually makes the model ask for a wider look. Everything downstream
// (hull growth, clamping, re-fetch) is deterministic and covered in
// chase_test.go; if `follow_up_events` comes back empty the whole feature is
// inert no matter how correct that code is.
//
// Opt-in — it calls the model and costs money:
//
//	TLVB_LIVE_LLM=1 go test ./internal/tier2 -run Live -v
//
// The fixture deliberately mixes the two cases that matter. Past the detection
// span sit both clearly attacker-ish activity (an archive appearing, an
// archiver running) AND a genuinely AMBIGUOUS event — an admin logoff followed
// by a reboot, which reads equally as intruder cleanup or as routine
// administration.
//
// The ambiguous one is the point. The first version of this prompt told the
// model to leave out anything it was unsure of, and on a real case
// (winrm_spray_case) it did exactly that: the narrative described a logoff and
// reboot six minutes past the detections, said it could not tell cleanup from
// legitimate work — and returned no events at all, so the window never widened
// and the question stayed unanswered. Uncertainty has to push events INTO the
// list, because a wider window is what settles it.
func TestChasePromptElicitsFollowUpEventsLive(t *testing.T) {
	if os.Getenv("TLVB_LIVE_LLM") == "" {
		t.Skip("set TLVB_LIVE_LLM=1 to run (issues a real model call)")
	}

	skill, err := os.ReadFile(filepath.Join("..", "..", "skills", "timeline_review.md"))
	if err != nil {
		t.Fatalf("read skill: %v", err)
	}

	base := time.Date(2026, 6, 2, 14, 0, 0, 0, time.UTC)
	at := func(min int) time.Time { return base.Add(time.Duration(min) * time.Minute) }

	c := &Cluster{
		ID:          1,
		StartTS:     base,
		EndTS:       at(2),
		WindowStart: base.Add(-30 * time.Minute),
		WindowEnd:   at(32),
		Findings: []Finding{{
			Source: "sigma", RuleID: "cred-dump", Severity: "high",
			Title:           "LSASS memory dump via comsvcs.dll",
			MITRETechniques: []string{"T1003.001"},
			Evidence: []FindingEvidence{
				{AuditID: "det-1", TsUTC: at(1), HasTS: true, ArtifactID: "evtx"},
			},
		}},
		RawTimelineExcerpt: []TimelineEvent{
			{AuditID: "noise-1", TsUTC: base.Add(-20 * time.Minute), ArtifactID: "evtx",
				EventType: "evtx", Excerpt: map[string]any{
					"EventId": "4672", "MapDescription": "Special privileges assigned to new logon",
					"PayloadData1": "SYSTEM"}},
			{AuditID: "det-1", TsUTC: at(1), ArtifactID: "evtx",
				EventType: "evtx", Excerpt: map[string]any{
					"EventId": "4688", "MapDescription": "A new process has been created",
					"PayloadData1": `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Users\Public\lsass.dmp full`}},
			{AuditID: "noise-2", TsUTC: at(6), ArtifactID: "evtx",
				EventType: "evtx", Excerpt: map[string]any{
					"EventId": "4624", "MapDescription": "An account was successfully logged on",
					"PayloadData1": "DWM-3, Logon Type 2"}},
			// --- everything below is OUTSIDE the detection span ---
			{AuditID: "late-1", TsUTC: at(22), ArtifactID: "mft",
				EventType: "mft", Excerpt: map[string]any{
					"ParentPath": `.\Users\Public`, "FileName": "loot.zip", "Extension": ".zip",
					"FileSize": "48211004"}},
			{AuditID: "late-2", TsUTC: at(23), ArtifactID: "prefetch",
				EventType: "prefetch", Excerpt: map[string]any{
					"executable": "7Z.EXE", "run_count": "1"}},
			// Ambiguous on purpose: intruder covering tracks, or an admin
			// finishing for the day? Not decidable from this window — which is
			// exactly why it must be listed.
			{AuditID: "ambiguous-1", TsUTC: at(28), ArtifactID: "evtx",
				EventType: "evtx", Excerpt: map[string]any{
					"EventId": "4634", "MapDescription": "An account was logged off",
					"PayloadData1": "Administrator, Logon Type 10"}},
			{AuditID: "ambiguous-2", TsUTC: at(30), ArtifactID: "evtx",
				EventType: "evtx", Excerpt: map[string]any{
					"EventId": "1074", "MapDescription": "System shutdown initiated",
					"PayloadData1": "explorer.exe, Administrator, no reason supplied"}},
		},
	}

	cfg := Config{
		CaseID:            "LIVE",
		ClaudeBinary:      "claude",
		Language:          "en",
		PerClusterTimeout: 5 * time.Minute,
		OutputPath:        filepath.Join(t.TempDir(), "synthesis.json"),
	}
	userMsg, err := buildClusterUserMessage(c, cfg.Language, "", false, false, DefaultTimelineWindow)
	if err != nil {
		t.Fatalf("build message: %v", err)
	}

	var audit SynthAudit
	resp, err := clusterPass(context.Background(), cfg, c, string(skill), userMsg, &audit, passChase)
	if err != nil {
		t.Fatalf("live model call failed: %v", err)
	}

	t.Logf("follow_up_events = %v", resp.FollowUpEvents)
	t.Logf("narrative = %s", resp.Narrative)

	if len(resp.FollowUpEvents) == 0 {
		t.Fatal("model returned no follow_up_events — the chase loop can never fire; " +
			"the per-cluster prompt or skills/timeline_review.md needs work")
	}
	listed := map[string]bool{}
	for _, id := range resp.FollowUpEvents {
		listed[id] = true
	}
	if !listed["ambiguous-1"] && !listed["ambiguous-2"] {
		t.Errorf("neither ambiguous event was listed (got %v) — the prompt is still "+
			"treating uncertainty as a reason to stay silent, which is the failure "+
			"that made this feature inert on a real case", resp.FollowUpEvents)
	}
	if listed["noise-1"] || listed["noise-2"] {
		t.Errorf("routine background listed (%v) — the prompt has swung too far the "+
			"other way and every window will now be extended", resp.FollowUpEvents)
	}

	matched, unresolved := resolveFollowUpEvents(c.RawTimelineExcerpt, resp.FollowUpEvents)
	if unresolved > 0 {
		t.Errorf("%d flagged audit_id(s) are not in the excerpt — model is inventing ids", unresolved)
	}
	_, _, grew := growHull(c.StartTS, c.EndTS, eventTimes(matched))
	if !grew {
		t.Errorf("nothing listed outside the detection span %s..%s; the staging/archive "+
			"activity at +22..+30 min should have been picked up (listed: %v)",
			c.StartTS.Format(time.RFC3339), c.EndTS.Format(time.RFC3339), resp.FollowUpEvents)
	}
}
