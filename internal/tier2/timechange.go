package tier2

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// timechange.go detects clock reversals from Security 4616 (system time change)
// events. A backward step in the clock makes the case timeline non-monotonic, so
// "record order vs timestamp" reversals must be read as a re-anchoring problem
// (provisioning / Set-Date), not an attacker timestomp (issue #82, task 1).

// clockReversalThreshold is the minimum backward step that counts as a reversal.
// Normal NTP/W32Time corrections are sub-second to a few seconds; an hour-plus
// jump backward is a deliberate Set-Date / provisioning artifact. Not tuned to
// the evaluation case (which jumped ~16h).
const clockReversalThreshold = time.Hour

// timeChangeEvent is one parsed 4616 record.
type timeChangeEvent struct {
	TsUTC        time.Time
	PreviousTime time.Time
	NewTime      time.Time
	Parsed       bool // both PreviousTime and NewTime parsed
	SubjectSID   string
	SubjectUser  string
}

// clockReversedFromEvents reports whether any 4616 stepped the clock backward by
// more than threshold (PreviousTime later than NewTime).
func clockReversedFromEvents(events []timeChangeEvent, threshold time.Duration) bool {
	for _, e := range events {
		if e.Parsed && e.PreviousTime.Sub(e.NewTime) > threshold {
			return true
		}
	}
	return false
}

// detectClockReversal queries the case's 4616 events and reports whether the
// clock was stepped backward. Best-effort: a DB/parse failure returns (false,
// err) and the caller treats the timeline as not-known-reversed.
func detectClockReversal(ctx context.Context, db *sql.DB, caseID string) (bool, error) {
	const q = `SELECT json_extract_string(payload_json, '$.raw.Payload')
	             FROM unified_events
	            WHERE case_id = ? AND artifact_id = 'evtx'
	              AND CAST(json_extract_string(payload_json, '$.EventId') AS INTEGER) = 4616`
	rows, err := db.QueryContext(ctx, q, caseID)
	if err != nil {
		return false, fmt.Errorf("fetch 4616: %w", err)
	}
	defer rows.Close()

	var events []timeChangeEvent
	for rows.Next() {
		var raw sql.NullString
		if err := rows.Scan(&raw); err != nil {
			return false, err
		}
		p := raw.String
		ev := timeChangeEvent{
			SubjectSID:  evtxEventDataValue(p, "SubjectUserSid"),
			SubjectUser: evtxEventDataValue(p, "SubjectUserName"),
		}
		prev, ok1 := parseEvtxTime(evtxEventDataValue(p, "PreviousTime"))
		nw, ok2 := parseEvtxTime(evtxEventDataValue(p, "NewTime"))
		if ok1 && ok2 {
			ev.PreviousTime, ev.NewTime, ev.Parsed = prev, nw, true
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return clockReversedFromEvents(events, clockReversalThreshold), nil
}

// parseEvtxTime parses the EvtxECmd EventData time format
// ("2026-06-13 01:50:02.4546349"), tolerating the variable-length fractional
// second by truncating at the dot.
func parseEvtxTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if i := strings.IndexByte(s, '.'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, "Z")
	s = strings.Replace(s, "T", " ", 1)
	t, err := time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}
