package agents

import (
	"encoding/json"
	"fmt"
	"strings"
)

// persistenceWhereClause is the SQL fragment that selects rows relevant to
// TA0003. Stays in lockstep with skills/persistence.md "Techniques in scope".
//
// It's defined as a function (not a constant) so we can build the long
// disjunction in pieces. The result is wrapped in parentheses by callers.
func persistenceWhereClause() string {
	persistenceEventIDs := []string{
		// Service install
		"4697", "7045",
		// Scheduled task lifecycle
		"4698", "4699", "4700", "4701", "4702",
		// Account creation / privilege add / change
		"4720", "4732", "4738", "4724",
	}
	var orParts []string
	orParts = append(orParts,
		`(artifact_id = 'registry' AND payload_json LIKE '%TA0003%')`,
		`artifact_id = 'scheduled_tasks'`,
	)
	for _, id := range persistenceEventIDs {
		orParts = append(orParts,
			fmt.Sprintf(`(artifact_id = 'evtx' AND payload_json LIKE '%%"EventId": "%s"%%')`, id),
		)
	}
	// Sysmon 12/13 — narrower since EventId 12/13 collide with non-Sysmon.
	orParts = append(orParts,
		`(artifact_id = 'evtx' AND payload_json LIKE '%Microsoft-Windows-Sysmon%' `+
			`AND (payload_json LIKE '%"EventId": "12"%' OR payload_json LIKE '%"EventId": "13"%'))`,
	)
	return strings.Join(orParts, " OR ")
}

// shrinkPayload extracts the most useful fields per artifact. The full
// payload (including payload.raw) can be 2 KB per row, blowing up the
// LLM context. Tactic Agents care about a stable subset — anything else
// they need can be fetched via the MCP server with the audit_id.
func shrinkPayload(artifactID, payloadJSON string) map[string]any {
	out := map[string]any{}
	var p map[string]any
	if err := json.Unmarshal([]byte(payloadJSON), &p); err != nil {
		out["_unparsed"] = truncate(payloadJSON, 200)
		return out
	}
	switch artifactID {
	case "registry":
		copyKeys(p, out, "HivePath", "Category", "KeyPath", "ValueName",
			"ValueType", "ValueData", "LastWriteTimestamp", "tactic_hints")
	case "scheduled_tasks":
		copyKeys(p, out, "task_name", "author", "run_as", "registration_date",
			"triggers", "actions", "tactic_hints")
	case "evtx":
		copyKeys(p, out, "TimeCreated", "Provider", "Channel", "EventId",
			"Level", "Computer", "UserId", "MapDescription",
			"PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4",
			"PayloadData5", "PayloadData6", "ExecutableInfo")
	case "amcache":
		copyKeys(p, out, "FileKeyLastWriteTimestamp", "FullPath",
			"SHA1", "amcache_table", "Name", "Publisher")
	case "prefetch":
		copyKeys(p, out, "ExecutableName", "Hash", "RunCount", "LastRun",
			"PreviousRun0", "Size", "FilesLoaded")
	default:
		// Fall back to a small slice of the raw payload.
		for k, v := range p {
			if k == "raw" {
				continue
			}
			out[k] = v
			if len(out) > 12 {
				break
			}
		}
	}
	return out
}

func copyKeys(src, dst map[string]any, keys ...string) {
	for _, k := range keys {
		if v, ok := src[k]; ok {
			dst[k] = v
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}
