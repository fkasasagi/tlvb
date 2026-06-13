package tier2

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// bruteforce.go is the deterministic initial-access detector for issue #82
// (task 3): a short-time burst of failed logons (4625) against ONE account,
// optionally followed by a success (4624), is password guessing / brute force
// (T1110.001) — not Pass-the-Hash. The Tier 1 signature corpus missed the
// single-account spray, so Tier 2 reconstructs it from raw logon events before
// clustering and emits a finding the rest of the pipeline treats like any other.
//
// Pass-the-Hash (T1550.002) is deliberately NOT inferred here: a successful
// NTLM logon is treated as password authentication unless a finding carries
// concrete hash-theft/use evidence (that grounding is enforced in
// synthesis_guard.go via the finding-derived MITRE matrix).

const (
	// bruteForceMinFailures is the generic "several consecutive failures" gate.
	// A handful of same-account failures in a tight window is the universal
	// fingerprint of guessing; it is not tuned to the evaluation case (which had
	// ~20). Kept low enough to catch short dictionaries, high enough to ignore a
	// user fat-fingering their password once or twice.
	bruteForceMinFailures = 5
	// bruteForceFailGap is the max gap between two failures still considered part
	// of the same burst.
	bruteForceFailGap = 10 * time.Minute
	// bruteForceSuccessGap is how soon after the last failure a success must land
	// to be tied to the burst.
	bruteForceSuccessGap = 10 * time.Minute
)

// logonEvent is one normalised 4624/4625 Security record.
type logonEvent struct {
	AuditID     string
	ArtifactID  string
	TsUTC       time.Time
	EventID     int
	TargetUser  string
	SubStatus   string
	LogonType   string
	Workstation string
	IP          string
}

// detectBruteForceFindings queries the case's logon events and reconstructs
// password-guessing bursts. Best-effort: any DB/extract failure returns an
// error the caller logs and ignores (CLAUDE.md graceful degradation).
func detectBruteForceFindings(ctx context.Context, db *sql.DB, caseID string) ([]Finding, error) {
	events, err := fetchLogonEvents(ctx, db, caseID)
	if err != nil {
		return nil, err
	}
	return detectBruteForceBursts(events, bruteForceMinFailures, bruteForceFailGap, bruteForceSuccessGap), nil
}

// detectBruteForceBursts is the pure detection core. For each target account it
// splits the failures into bursts (consecutive failures within failGap) and, for
// any burst of at least minFailures with a consistent failure reason, emits a
// T1110.001 finding — raising severity and attaching the 4624 when a matching
// success lands within successGap.
func detectBruteForceBursts(events []logonEvent, minFailures int, failGap, successGap time.Duration) []Finding {
	if minFailures <= 0 {
		minFailures = bruteForceMinFailures
	}
	if failGap <= 0 {
		failGap = bruteForceFailGap
	}
	if successGap <= 0 {
		successGap = bruteForceSuccessGap
	}

	sorted := append([]logonEvent(nil), events...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].TsUTC.Before(sorted[j].TsUTC) })

	failsByTarget := map[string][]logonEvent{}
	var targetsOrder []string
	var successes []logonEvent
	for _, e := range sorted {
		switch e.EventID {
		case 4625:
			t := normUser(e.TargetUser)
			if t == "" {
				continue // cannot attribute a burst without a target account
			}
			if _, ok := failsByTarget[t]; !ok {
				targetsOrder = append(targetsOrder, t)
			}
			failsByTarget[t] = append(failsByTarget[t], e)
		case 4624:
			successes = append(successes, e)
		}
	}

	var out []Finding
	for _, target := range targetsOrder {
		for _, run := range splitLogonRuns(failsByTarget[target], failGap) {
			if len(run) < minFailures || !consistentSubStatus(run, minFailures) {
				continue
			}
			runEnd := run[len(run)-1].TsUTC
			var succ *logonEvent
			for i := range successes {
				s := successes[i]
				if normUser(s.TargetUser) != target {
					continue
				}
				if !s.TsUTC.Before(runEnd) && s.TsUTC.Sub(runEnd) <= successGap {
					succ = &successes[i]
					break
				}
			}
			out = append(out, makeBruteForceFinding(target, run, succ))
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].FirstTimestamp().Before(out[j].FirstTimestamp())
	})
	return out
}

// splitLogonRuns breaks a target's time-ordered failures into bursts wherever
// the gap to the previous failure exceeds failGap.
func splitLogonRuns(fails []logonEvent, failGap time.Duration) [][]logonEvent {
	var runs [][]logonEvent
	var cur []logonEvent
	for _, f := range fails {
		if len(cur) == 0 || f.TsUTC.Sub(cur[len(cur)-1].TsUTC) <= failGap {
			cur = append(cur, f)
			continue
		}
		runs = append(runs, cur)
		cur = []logonEvent{f}
	}
	if len(cur) > 0 {
		runs = append(runs, cur)
	}
	return runs
}

// consistentSubStatus reports whether the burst reflects one dominant failure
// reason (the spray/guess signature). When SubStatus is unavailable for every
// event it returns true (can't check — accept on count alone); otherwise the
// modal SubStatus must cover at least minFailures of the run.
func consistentSubStatus(run []logonEvent, minFailures int) bool {
	counts := map[string]int{}
	any := false
	for _, e := range run {
		s := strings.ToLower(strings.TrimSpace(e.SubStatus))
		if s == "" {
			continue
		}
		any = true
		counts[s]++
	}
	if !any {
		return true
	}
	best := 0
	for _, n := range counts {
		if n > best {
			best = n
		}
	}
	return best >= minFailures
}

// makeBruteForceFinding builds the synthetic Finding for one detected burst.
func makeBruteForceFinding(target string, run []logonEvent, succ *logonEvent) Finding {
	first := run[0].TsUTC
	sub := modalSubStatus(run)
	src := bruteForceSource(run)

	title := fmt.Sprintf("Password guessing: %d failed logons against %q", len(run), target)
	desc := fmt.Sprintf("%d failed logons (4625) for account %q within a short window%s — single-account password guessing / brute force (T1110.001).",
		len(run), target, srcSuffix(src))
	sev := "medium"
	if succ != nil {
		sev = "high"
		title = fmt.Sprintf("Brute force success: %d failed logons against %q then a successful logon", len(run), target)
		desc += " A successful logon (4624) followed the failures for the same account, indicating the guessed password worked. This is password authentication, NOT Pass-the-Hash, unless separate hash-theft evidence exists."
	}
	if sub != "" {
		desc += fmt.Sprintf(" Dominant failure SubStatus: %s.", sub)
	}

	ev := make([]FindingEvidence, 0, len(run)+1)
	for _, e := range run {
		ev = append(ev, logonEvidence(e))
	}
	if succ != nil {
		ev = append(ev, logonEvidence(*succ))
	}

	return Finding{
		FindingID:       fmt.Sprintf("bruteforce-%s-%d", normUser(target), first.Unix()),
		Source:          "heuristic",
		RuleID:          "TLVB-BRUTEFORCE-4625",
		Title:           title,
		Description:     desc,
		Severity:        sev,
		MITRETechniques: []string{"T1110.001"},
		MITRETactic:     "credential-access",
		Evidence:        ev,
		OriginPath:      "(tier2 deterministic brute-force heuristic)",
	}
}

func logonEvidence(e logonEvent) FindingEvidence {
	extra := map[string]any{"EventId": fmt.Sprintf("%d", e.EventID)}
	if e.TargetUser != "" {
		extra["TargetUserName"] = e.TargetUser
	}
	if e.SubStatus != "" {
		extra["SubStatus"] = e.SubStatus
	}
	if e.LogonType != "" {
		extra["LogonType"] = e.LogonType
	}
	if e.Workstation != "" {
		extra["WorkstationName"] = e.Workstation
	}
	if e.IP != "" {
		extra["IpAddress"] = e.IP
	}
	return FindingEvidence{
		AuditID:    e.AuditID,
		TsUTC:      e.TsUTC,
		HasTS:      !e.TsUTC.IsZero(),
		ArtifactID: orDefault(e.ArtifactID, "evtx"),
		EventType:  "evtx",
		Extra:      extra,
	}
}

// srcSuffix / bruteForceSource surface the distinct source hosts seen in the
// burst (workstation name / IP) without baking any specific value in.
func bruteForceSource(run []logonEvent) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range run {
		for _, v := range []string{strings.TrimSpace(e.Workstation), strings.TrimSpace(e.IP)} {
			if v == "" || v == "-" || seen[strings.ToLower(v)] {
				continue
			}
			seen[strings.ToLower(v)] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func srcSuffix(src []string) string {
	if len(src) == 0 {
		return ""
	}
	return " from " + strings.Join(src, ", ")
}

func modalSubStatus(run []logonEvent) string {
	counts := map[string]int{}
	for _, e := range run {
		s := strings.TrimSpace(e.SubStatus)
		if s != "" {
			counts[s]++
		}
	}
	best, bestN := "", 0
	for s, n := range counts {
		if n > bestN || (n == bestN && s < best) {
			best, bestN = s, n
		}
	}
	return best
}

func normUser(u string) string {
	u = strings.TrimSpace(u)
	// strip DOMAIN\ prefix so DOMAIN\Administrator and Administrator group together
	if i := strings.LastIndex(u, `\`); i >= 0 {
		u = u[i+1:]
	}
	return strings.ToLower(strings.TrimSpace(u))
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// ----------------------------------------------------------------------------
// DB extraction
// ----------------------------------------------------------------------------

// fetchLogonEvents pulls 4624/4625 Security events and extracts the logon
// fields from the EvtxECmd `raw.Payload` EventData (`@Name`/`#text` pairs).
func fetchLogonEvents(ctx context.Context, db *sql.DB, caseID string) ([]logonEvent, error) {
	const q = `SELECT audit_id, ts_utc, artifact_id,
	                  json_extract_string(payload_json, '$.EventId') AS eid,
	                  json_extract_string(payload_json, '$.raw.Payload') AS raw_payload
	             FROM unified_events
	            WHERE case_id = ? AND artifact_id = 'evtx'
	              AND CAST(json_extract_string(payload_json, '$.EventId') AS INTEGER) IN (4624, 4625)`
	rows, err := db.QueryContext(ctx, q, caseID)
	if err != nil {
		return nil, fmt.Errorf("fetch logon events: %w", err)
	}
	defer rows.Close()

	var out []logonEvent
	for rows.Next() {
		var aid, art string
		var ts sql.NullTime
		var eid, rawPayload sql.NullString
		if err := rows.Scan(&aid, &ts, &art, &eid, &rawPayload); err != nil {
			return nil, err
		}
		id := 0
		fmt.Sscanf(strings.TrimSpace(eid.String), "%d", &id)
		if id != 4624 && id != 4625 {
			continue
		}
		ev := logonEvent{AuditID: aid, ArtifactID: art, EventID: id}
		if ts.Valid {
			ev.TsUTC = ts.Time.UTC()
		}
		p := rawPayload.String
		ev.TargetUser = evtxEventDataValue(p, "TargetUserName")
		ev.SubStatus = evtxEventDataValue(p, "SubStatus")
		ev.LogonType = evtxEventDataValue(p, "LogonType")
		ev.Workstation = evtxEventDataValue(p, "WorkstationName")
		ev.IP = evtxEventDataValue(p, "IpAddress")
		out = append(out, ev)
	}
	return out, rows.Err()
}

// evtxEventDataValue extracts one EventData value from an EvtxECmd Payload by
// field name. It handles the `@Name`/`#text` array shape EvtxECmd emits and
// falls back to a direct `"Name":"value"` form. The Payload may itself be a
// JSON-encoded string; we peel one quoting layer when present.
func evtxEventDataValue(payload, name string) string {
	if strings.TrimSpace(payload) == "" {
		return ""
	}
	text := payload
	// Peel one JSON-string layer if EvtxECmd stored Payload encoded.
	var inner string
	if json.Unmarshal([]byte(payload), &inner) == nil && inner != "" {
		text = inner
	}
	if m := atNameTextRe(name).FindStringSubmatch(text); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	if m := directKeyRe(name).FindStringSubmatch(text); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

var (
	atNameTextReCache = map[string]*regexp.Regexp{}
	directKeyReCache  = map[string]*regexp.Regexp{}
)

func atNameTextRe(name string) *regexp.Regexp {
	if re, ok := atNameTextReCache[name]; ok {
		return re
	}
	re := regexp.MustCompile(`"@Name"\s*:\s*"` + regexp.QuoteMeta(name) + `"\s*,\s*"#text"\s*:\s*"([^"]*)"`)
	atNameTextReCache[name] = re
	return re
}

func directKeyRe(name string) *regexp.Regexp {
	if re, ok := directKeyReCache[name]; ok {
		return re
	}
	re := regexp.MustCompile(`"` + regexp.QuoteMeta(name) + `"\s*:\s*"([^"]*)"`)
	directKeyReCache[name] = re
	return re
}
