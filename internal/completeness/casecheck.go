package completeness

import (
	"context"
	"database/sql"
	"fmt"
)

// EvaluateCase queries a parsed case's unified_events for the artefacts and
// EVTX channels actually present, then evaluates each catalogued detection
// input as present or absent. db must be a (read-only) handle to cases.duckdb.
// It returns the per-input results in catalog order plus the distinct EVTX
// channels that were collected. This is the shared entry point used by the CLI
// (`tlvb completeness`), the Web case summary, and the Tier 3 report so they
// all read the same gap analysis.
func EvaluateCase(ctx context.Context, db *sql.DB, caseID string) (results []Result, channels []string, err error) {
	arts, err := distinctStrings(ctx, db,
		"SELECT DISTINCT artifact_id FROM unified_events WHERE case_id = ?", caseID)
	if err != nil {
		return nil, nil, fmt.Errorf("query artifacts: %w", err)
	}
	if len(arts) == 0 {
		return nil, nil, fmt.Errorf("no unified_events for case %q (parse it first?)", caseID)
	}
	present := make(map[string]bool, len(arts))
	for _, a := range arts {
		present[a] = true
	}
	channels, err = distinctStrings(ctx, db,
		"SELECT DISTINCT json_extract_string(payload_json, '$.Channel') "+
			"FROM unified_events WHERE case_id = ? AND artifact_id = 'evtx'", caseID)
	if err != nil {
		return nil, nil, fmt.Errorf("query evtx channels: %w", err)
	}
	return Evaluate(present, channels), channels, nil
}

// CountMissing returns how many catalogued inputs are absent and, of those, how
// many are of "critical" importance.
func CountMissing(results []Result) (total, critical int) {
	for _, r := range results {
		if !r.Present {
			total++
			if r.Importance == "critical" {
				critical++
			}
		}
	}
	return total, critical
}

func distinctStrings(ctx context.Context, db *sql.DB, query, caseID string) ([]string, error) {
	rows, err := db.QueryContext(ctx, query, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s *string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if s != nil && *s != "" {
			out = append(out, *s)
		}
	}
	return out, rows.Err()
}
