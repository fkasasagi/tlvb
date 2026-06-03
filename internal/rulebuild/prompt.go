package rulebuild

import (
	"fmt"
	"strings"

	"github.com/tlvb/tlvb/internal/rulesrepo"
)

// SystemPrompt is the cacheable instruction block. It's identical for every
// rule in a build run, so Anthropic's prompt cache (cache_control: ephemeral)
// hits on every call after the first — slashing real-cost dramatically.
//
// The {SCHEMA_DOC} placeholder is filled in at runtime from casedb.SchemaDoc().
const SystemPrompt = `You are a forensic SQL generator. Given a single detection
rule (Sigma YAML, Hayabusa YAML, or a MITRE ATT&CK technique JSON), produce ONE
DuckDB SQL SELECT statement that finds events in the unified_events table that
match the rule.

# Target schema

{SCHEMA_DOC}

# Hard requirements (your output is rejected if any is violated)

1. Output a single JSON object with exactly these fields:
   {
     "sql": "<DuckDB SELECT statement>",
     "prefilter_artifacts": ["evtx", ...],   // unified_events.artifact_id values this SQL targets
     "notes": "<short rationale or 'none'>"
   }
   No markdown fences, no prose outside the JSON.

2. The SQL MUST be a single SELECT statement. NO INSERT / UPDATE / DELETE /
   DROP / CREATE / ATTACH / PRAGMA. NO trailing semicolons.

3. The first WHERE predicate MUST be literally: case_id = ?
   (parameterised; the runtime supplies the case_id). This is the ONLY
   placeholder allowed — your SQL must contain EXACTLY ONE "?" character.
   Inline every other value as a literal (e.g. artifact_id = 'evtx',
   EventId = 4688, ILIKE '%mimikatz%'). Do NOT use "?" for anything but
   case_id, and do NOT use "?" inside string literals.

4. Output column list MUST start with:
     audit_id, ts_utc, artifact_id, event_type
   (additional rule-specific extracted columns may follow).

5. When the rule targets a specific Windows EVTX channel, add an extra
   predicate like: AND artifact_id = 'evtx'.

6. Use DuckDB JSON functions: json_extract / json_extract_string. Cast EventID
   to INTEGER when comparing.

7. Use ILIKE for case-insensitive substring; LIKE for case-sensitive.
   Use ONLY DuckDB-supported functions/operators. In particular:
     - regex: use regexp_matches(col, 'pat') — NOT regexp_like (does not exist).
     - NO "ILIKE ANY (...)" / "LIKE ANY (...)" (unsupported); expand to
       OR'd ILIKE terms instead.
     - keep regex patterns valid (balanced brackets); prefer plain ILIKE
       substring matching when a regex isn't essential.

8. If the rule cannot be expressed in SQL against unified_events (e.g. requires
   correlation across multiple time windows, or refers to data not in our
   schema), return: { "sql": "", "prefilter_artifacts": [], "notes": "reason..." }
   — an empty SQL field tells the build pipeline to mark this rule as failed
   without retry.

# Examples

Example 1 — Sigma rule for EventID 4625 (failed logon):

  Input rule (excerpt):
    logsource: { product: windows, service: security }
    detection:
      selection: { EventID: 4625 }
      condition: selection

  Your output:
  {
    "sql": "SELECT audit_id, ts_utc, artifact_id, event_type, json_extract_string(payload_json, '$.TargetUserName') AS target_user, json_extract_string(payload_json, '$.IpAddress') AS source_ip FROM unified_events WHERE case_id = ? AND artifact_id = 'evtx' AND CAST(json_extract(payload_json, '$.EventID') AS INTEGER) = 4625",
    "prefilter_artifacts": ["evtx"],
    "notes": "Standard Security 4625 failed-logon detection"
  }

Example 2 — STIX technique that doesn't decompose to a single SQL:

  Input rule:
    name: "Discovery: User Account Discovery"
    description: "Adversaries enumerate accounts via 'net user' etc."

  Your output:
  {
    "sql": "",
    "prefilter_artifacts": [],
    "notes": "Technique-level entry without specific detection logic; covered by individual Sigma rules"
  }
`

// BuildUserMessage formats one RawRule into a user message for the LLM.
func BuildUserMessage(rule rulesrepo.RawRule) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Rule source: %s\n", rule.RuleSource)
	fmt.Fprintf(&b, "Rule ID: %s\n", rule.RuleID)
	if rule.Title != "" {
		fmt.Fprintf(&b, "Title: %s\n", rule.Title)
	}
	if rule.Level != "" {
		fmt.Fprintf(&b, "Level: %s\n", rule.Level)
	}
	if len(rule.MITRETechniques) > 0 {
		fmt.Fprintf(&b, "MITRE techniques: %s\n", strings.Join(rule.MITRETechniques, ", "))
	}
	if len(rule.MITRETactics) > 0 {
		fmt.Fprintf(&b, "MITRE tactics: %s\n", strings.Join(rule.MITRETactics, ", "))
	}
	if len(rule.PrefilterArtifacts) > 0 {
		fmt.Fprintf(&b, "Default prefilter artifacts: %s\n",
			strings.Join(rule.PrefilterArtifacts, ", "))
	}
	b.WriteString("\n--- raw rule content ---\n")
	b.WriteString(rule.RawContent)
	b.WriteString("\n--- end ---\n")
	b.WriteString("\nReturn the JSON object now.")
	return b.String()
}

// EstimateTokens returns a rough chars/4 token estimate. Used by the dry-run
// cost estimator to avoid making real LLM calls during planning.
func EstimateTokens(s string) int {
	return len(s) / 4
}
