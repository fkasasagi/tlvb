package tier3

import (
	"strings"
	"testing"

	"github.com/tlvb/tlvb/internal/tier2"
)

// TestBuildReportDigestExaminerBackground verifies the advisory consistency
// reviewer's digest carries the examiner background as labelled UNVERIFIED,
// non-ground-truth context, and omits the section when there is none.
func TestBuildReportDigestExaminerBackground(t *testing.T) {
	cs := tier2.CaseSynthesis{ExecBrief: "brief", TechSummary: "tech"}
	const bg = "Reported by SOC: WS01 alerted on repeated failed logons."

	d := buildReportDigest(cs, &enrichment{}, "ja", bg)
	if !strings.Contains(d, "WS01 alerted on repeated failed logons") {
		t.Error("digest must embed the background text")
	}
	if !strings.Contains(d, "UNVERIFIED") || !strings.Contains(d, "NOT ground truth") {
		t.Error("digest must label background as unverified / not ground truth")
	}

	if dEmpty := buildReportDigest(cs, &enrichment{}, "ja", ""); strings.Contains(dEmpty, "EXAMINER BACKGROUND") {
		t.Error("empty background must not add the EXAMINER BACKGROUND section")
	}
}
