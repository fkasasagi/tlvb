package tier2

import (
	"strings"
	"testing"
)

// TestBuildersInjectExaminerBackground verifies the per-cluster and overall
// prompt builders embed the examiner background as labelled UNVERIFIED context,
// and add nothing when there is no background.
func TestBuildersInjectExaminerBackground(t *testing.T) {
	const bg = "WS01 is the public-facing web server; brute force suspected."
	c := &Cluster{ID: 1, AttackPhase: "initial-access"}

	cm, err := buildClusterUserMessage(c, "en", bg, false, false, DefaultTimelineWindow)
	if err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if !strings.Contains(cm, "WS01 is the public-facing web server") {
		t.Error("cluster message must embed the background text")
	}
	if !strings.Contains(cm, "examiner_background") || !strings.Contains(cm, "NOT evidence") {
		t.Error("cluster message must label background as non-evidence context")
	}
	if cmEmpty, _ := buildClusterUserMessage(c, "en", "", false, false, DefaultTimelineWindow); strings.Contains(cmEmpty, "examiner_background") {
		t.Error("empty background must not add the examiner_background field")
	}

	om, err := buildOverallUserMessage([]Cluster{*c}, false, "en", bg, false, nil)
	if err != nil {
		t.Fatalf("overall: %v", err)
	}
	if !strings.Contains(om, "WS01 is the public-facing web server") {
		t.Error("overall message must embed the background text")
	}
	if !strings.Contains(om, "UNVERIFIED") {
		t.Error("overall message must label the background as unverified")
	}
	if omEmpty, _ := buildOverallUserMessage([]Cluster{*c}, false, "en", "", false, nil); strings.Contains(omEmpty, "WS01") {
		t.Error("empty background must not appear in the overall message")
	}
}
