package synthesizer

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/agents"
)

// TimelineEntry is one row of the case timeline. The Plaso-style flat
// columns (timestamp, source, summary) make it easy to reformat for HTML
// or CSV reports later.
type TimelineEntry struct {
	Timestamp     time.Time      `json:"timestamp"`
	AuditID       string         `json:"audit_id"`
	ArtifactID    string         `json:"artifact_id"`
	Computer      string         `json:"computer,omitempty"`
	Tactic        string         `json:"tactic,omitempty"`     // ATT&CK ID
	Technique     string         `json:"technique,omitempty"`  // ATT&CK technique ID
	Summary       string         `json:"summary"`              // single-line description
	Confidence    string         `json:"confidence,omitempty"`
	FindingIDs    []string       `json:"finding_ids,omitempty"`
	PayloadDigest map[string]any `json:"payload_digest,omitempty"` // small subset
}

// AttackStep is one node of the inferred Kill-Chain narrative.
type AttackStep struct {
	Step        int       `json:"step"`
	Tactic      string    `json:"tactic"`              // TA000X
	TacticName  string    `json:"tactic_name"`
	Technique   string    `json:"technique,omitempty"` // T1XXX
	Timestamp   time.Time `json:"timestamp"`
	Description string    `json:"description"`
	EvidenceIDs []string  `json:"evidence_ids"`
	FindingIDs  []string  `json:"finding_ids"`
}

// killChainOrder is the canonical Kill-Chain ordering we use to walk
// findings into AttackSteps. Out-of-scope tactics are appended at the end.
var killChainOrder = []string{
	"TA0043", // Reconnaissance
	"TA0042", // Resource Development
	"TA0001", // Initial Access
	"TA0002", // Execution
	"TA0003", // Persistence
	"TA0004", // Privilege Escalation
	"TA0005", // Defense Evasion
	"TA0006", // Credential Access
	"TA0007", // Discovery
	"TA0008", // Lateral Movement
	"TA0009", // Collection
	"TA0011", // Exfiltration
	"TA0010", // Command and Control
	"TA0040", // Impact
}

var killChainName = map[string]string{
	"TA0001": "Initial Access",
	"TA0002": "Execution",
	"TA0003": "Persistence",
	"TA0004": "Privilege Escalation",
	"TA0005": "Defense Evasion",
	"TA0006": "Credential Access",
	"TA0007": "Discovery",
	"TA0008": "Lateral Movement",
	"TA0009": "Collection",
	"TA0010": "Command and Control",
	"TA0011": "Exfiltration",
	"TA0040": "Impact",
	"TA0042": "Resource Development",
	"TA0043": "Reconnaissance",
}

// BuildTimeline resolves every Finding's evidence audit_ids against the
// unified_events table, returns a chronologically-sorted Timeline plus
// inferred Kill-Chain AttackSteps.
//
// Resolution semantics:
//   - audit_ids that exist in DB → real timestamps and payloads
//   - audit_ids that don't exist (hallucinated by the LLM) → skipped, and
//     listed in the returned `unresolved` slice for examiner review
//
// Two findings claiming the same audit_id contribute one timeline entry
// (deduplicated). The Tactic/Technique attribution on that entry is the
// highest-confidence finding's claim.
func BuildTimeline(
	ctx context.Context,
	db *sql.DB,
	caseID string,
	agg *AggregateResult,
) (timeline []TimelineEntry, steps []AttackStep, unresolved []string, err error) {

	// Build audit_id → list of (finding, source) referencing it.
	type ref struct {
		fws    FindingWithSource
		findIdx int
	}
	idx := map[string][]ref{}
	for i, fws := range agg.AllFindings {
		for _, ev := range fws.Finding.Evidence {
			if ev.AuditID == "" {
				continue
			}
			idx[ev.AuditID] = append(idx[ev.AuditID], ref{fws: fws, findIdx: i})
		}
	}
	if len(idx) == 0 {
		return nil, nil, nil, nil
	}

	// Single bulk query — IN (?,?,?,...) is fine for ≤ a few thousand IDs.
	auditIDs := make([]string, 0, len(idx))
	for k := range idx {
		auditIDs = append(auditIDs, k)
	}
	sort.Strings(auditIDs)

	const chunkSize = 500 // DuckDB IN-list pragmatic upper bound
	resolved := map[string]rawEventRow{}
	for i := 0; i < len(auditIDs); i += chunkSize {
		end := i + chunkSize
		if end > len(auditIDs) {
			end = len(auditIDs)
		}
		chunk := auditIDs[i:end]
		rows, qerr := queryEventsByAuditID(ctx, db, caseID, chunk)
		if qerr != nil {
			return nil, nil, nil, qerr
		}
		for k, v := range rows {
			resolved[k] = v
		}
	}

	for _, id := range auditIDs {
		if _, ok := resolved[id]; !ok {
			unresolved = append(unresolved, id)
		}
	}

	// Build TimelineEntry per resolved audit_id.
	for id, row := range resolved {
		refs := idx[id]
		// Pick highest-scored finding as the canonical tactic/technique.
		best := refs[0]
		bestScore := scoreFinding(refs[0].fws)
		for _, r := range refs[1:] {
			if s := scoreFinding(r.fws); s > bestScore {
				best = r
				bestScore = s
			}
		}
		findingIDs := make([]string, 0, len(refs))
		seen := map[string]struct{}{}
		for _, r := range refs {
			if _, dup := seen[r.fws.Finding.FindingID]; dup {
				continue
			}
			seen[r.fws.Finding.FindingID] = struct{}{}
			findingIDs = append(findingIDs, r.fws.Finding.FindingID)
		}
		sort.Strings(findingIDs)

		summary := summariseEvent(row, best.fws)
		entry := TimelineEntry{
			Timestamp:     row.ts,
			AuditID:       id,
			ArtifactID:    row.artifactID,
			Computer:      row.computer,
			Tactic:        best.fws.TacticID,
			Technique:     best.fws.Finding.TechniqueID,
			Summary:       summary,
			Confidence:    best.fws.Finding.Confidence,
			FindingIDs:    findingIDs,
			PayloadDigest: row.digest,
		}
		timeline = append(timeline, entry)
	}

	sort.SliceStable(timeline, func(i, j int) bool {
		if !timeline[i].Timestamp.Equal(timeline[j].Timestamp) {
			return timeline[i].Timestamp.Before(timeline[j].Timestamp)
		}
		return timeline[i].AuditID < timeline[j].AuditID
	})

	steps = inferAttackSteps(timeline, agg)
	sort.Strings(unresolved)
	return timeline, steps, unresolved, nil
}

// rawEventRow is the projection we read from unified_events.
type rawEventRow struct {
	auditID    string
	ts         time.Time
	artifactID string
	computer   string
	digest     map[string]any
}

func queryEventsByAuditID(
	ctx context.Context, db *sql.DB, caseID string, ids []string,
) (map[string]rawEventRow, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	args := []any{caseID}
	placeholders := make([]string, 0, len(ids))
	for _, id := range ids {
		placeholders = append(placeholders, "?")
		args = append(args, id)
	}
	q := `SELECT audit_id, COALESCE(ts_utc, NULL), artifact_id,
	             COALESCE(computer, ''), payload_json
	        FROM unified_events
	       WHERE case_id = ?
	         AND audit_id IN (` + strings.Join(placeholders, ",") + `)`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()
	out := map[string]rawEventRow{}
	for rows.Next() {
		var row rawEventRow
		var ts sql.NullTime
		var payload string
		if err := rows.Scan(&row.auditID, &ts, &row.artifactID,
			&row.computer, &payload); err != nil {
			return nil, err
		}
		if ts.Valid {
			row.ts = ts.Time.UTC()
		}
		row.digest = digestPayload(row.artifactID, payload)
		out[row.auditID] = row
	}
	return out, rows.Err()
}

// digestPayload returns a *very* small subset of payload fields — just
// enough for a one-line timeline summary. Full data lives in DuckDB.
func digestPayload(artifactID, payloadJSON string) map[string]any {
	var p map[string]any
	if err := json.Unmarshal([]byte(payloadJSON), &p); err != nil {
		return map[string]any{"_raw": truncateStr(payloadJSON, 120)}
	}
	out := map[string]any{}
	switch artifactID {
	case "evtx":
		for _, k := range []string{"Provider", "EventId", "Channel", "MapDescription"} {
			if v, ok := p[k]; ok {
				out[k] = v
			}
		}
	case "registry":
		for _, k := range []string{"Category", "KeyPath", "ValueName"} {
			if v, ok := p[k]; ok {
				out[k] = v
			}
		}
	case "scheduled_tasks":
		for _, k := range []string{"task_name", "run_as"} {
			if v, ok := p[k]; ok {
				out[k] = v
			}
		}
	case "prefetch":
		for _, k := range []string{"ExecutableName", "RunCount"} {
			if v, ok := p[k]; ok {
				out[k] = v
			}
		}
	case "amcache":
		for _, k := range []string{"FullPath", "amcache_table"} {
			if v, ok := p[k]; ok {
				out[k] = v
			}
		}
	}
	return out
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}

// summariseEvent builds the timeline's one-line `summary`. Format:
//   "<artifact> <key signal>: <finding-summary-or-finding-id>"
func summariseEvent(row rawEventRow, fws FindingWithSource) string {
	signal := ""
	switch row.artifactID {
	case "evtx":
		eid, _ := row.digest["EventId"].(string)
		prov, _ := row.digest["Provider"].(string)
		map_, _ := row.digest["MapDescription"].(string)
		if map_ != "" {
			signal = fmt.Sprintf("%s/%s %s", prov, eid, map_)
		} else {
			signal = fmt.Sprintf("%s/%s", prov, eid)
		}
	case "registry":
		kp, _ := row.digest["KeyPath"].(string)
		vn, _ := row.digest["ValueName"].(string)
		signal = fmt.Sprintf("%s ::%s", kp, vn)
	case "scheduled_tasks":
		tn, _ := row.digest["task_name"].(string)
		signal = fmt.Sprintf("task=%s", tn)
	case "prefetch":
		en, _ := row.digest["ExecutableName"].(string)
		signal = fmt.Sprintf("ran=%s", en)
	case "amcache":
		fp, _ := row.digest["FullPath"].(string)
		signal = fmt.Sprintf("present=%s", fp)
	default:
		signal = row.artifactID
	}
	if fws.Finding.Summary != "" {
		return fmt.Sprintf("%s — %s", signal, fws.Finding.Summary)
	}
	return signal
}

// inferAttackSteps walks killChainOrder and, for each tactic that has
// findings, picks the earliest finding's earliest evidence timestamp.
// The result is a deterministic narrative skeleton — not a causal proof.
//
// We deliberately keep this *rule-based*: the LLM-driven Corrector would
// be where we ask "is this chain causally sensible" with prompt guidance.
func inferAttackSteps(tl []TimelineEntry, agg *AggregateResult) []AttackStep {
	if len(tl) == 0 {
		return nil
	}

	// tactic → earliest TimelineEntry that mentions it
	earliestByTactic := map[string]TimelineEntry{}
	for _, t := range tl {
		if t.Tactic == "" {
			continue
		}
		cur, ok := earliestByTactic[t.Tactic]
		if !ok || t.Timestamp.Before(cur.Timestamp) {
			earliestByTactic[t.Tactic] = t
		}
	}

	var out []AttackStep
	step := 0
	for _, taID := range killChainOrder {
		te, ok := earliestByTactic[taID]
		if !ok {
			continue
		}
		step++

		// All evidence ids and finding ids attributed to this tactic across
		// the timeline. We don't only take the earliest — we want the full
		// "what happened in this phase" set.
		var evIDs, fIDs []string
		fSeen := map[string]struct{}{}
		for _, t := range tl {
			if t.Tactic != taID {
				continue
			}
			evIDs = append(evIDs, t.AuditID)
			for _, fid := range t.FindingIDs {
				if _, dup := fSeen[fid]; dup {
					continue
				}
				fSeen[fid] = struct{}{}
				fIDs = append(fIDs, fid)
			}
		}

		out = append(out, AttackStep{
			Step:        step,
			Tactic:      taID,
			TacticName:  killChainName[taID],
			Technique:   te.Technique,
			Timestamp:   te.Timestamp,
			Description: te.Summary,
			EvidenceIDs: dedupStrings(evIDs),
			FindingIDs:  fIDs,
		})
	}

	// Sanity: AttackSteps should be non-decreasing in Timestamp by construction
	// (we pick earliest per tactic, then walk Kill Chain). If real data
	// inverts the order (R4 rule fires elsewhere), surface honestly without
	// re-ordering — the timeline still tells the truth.
	return out
}

func dedupStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// _ confirms agents package is referenced (FindingWithSource uses it).
var _ agents.Finding
