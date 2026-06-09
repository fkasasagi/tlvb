package tier3

import (
	"fmt"
	"strings"

	"github.com/tlvb/tlvb/internal/auditlog"
)

// LogReportAction appends a tier3 "report" entry to the case's actions.jsonl so
// the unified execution log records that the DFIR report was generated. The
// other four tiers (tier0/1a/1b/2) already log here; tier3 was the gap that left
// the WebUI Audit tab's "tier3" filter empty. Best-effort — a nil or unwritable
// log never blocks rendering.
func LogReportAction(actionsPath, caseID string, formats []string, outDir string, nFiles int, durSeconds float64) {
	ok := true
	auditlog.New(actionsPath, caseID).Append(auditlog.Action{
		Actor:           "tier3",
		Kind:            "report",
		Detail:          strings.Join(formats, ","),
		Success:         &ok,
		DurationSeconds: durSeconds,
		Command:         fmt.Sprintf("render %d report file(s) → %s", nFiles, outDir),
	})
}
