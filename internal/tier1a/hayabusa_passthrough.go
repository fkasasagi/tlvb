package tier1a

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// HayabusaPassthroughOptions controls the pass-through pass.
type HayabusaPassthroughOptions struct {
	// IncludeInfoLevel: when false (default), `info` and `low` level hits
	// are skipped to keep the findings folder focused on real attack
	// indicators. Set true if you want the full timeline including noisy
	// background events.
	IncludeInfoLevel bool
}

// RunHayabusaPassthrough scans unified_events for artifact_id='hayabusa'
// rows (precomputed Sigma matches from the Tier 0 Hayabusa parser),
// groups them by Hayabusa's RuleID, and emits one Finding per unique
// rule. Each Finding's evidence list contains every matching event.
//
// rule_source = "hayabusa" — distinct from cached-SQL Sigma findings even
// though the RuleID may coincide with an upstream Sigma UUID (Hayabusa
// runs the Sigma ruleset internally).
func RunHayabusaPassthrough(ctx context.Context, cfg Config, opts HayabusaPassthroughOptions) (*Report, error) {
	if cfg.CaseID == "" {
		return nil, fmt.Errorf("Tier 1A Hayabusa: CaseID is required")
	}
	if cfg.CaseDB == nil {
		return nil, fmt.Errorf("Tier 1A Hayabusa: CaseDB must be open")
	}
	if cfg.FindingsDir == "" {
		return nil, fmt.Errorf("Tier 1A Hayabusa: FindingsDir is required")
	}
	if cfg.MaxEvidence <= 0 {
		cfg.MaxEvidence = 100
	}

	start := time.Now()
	report := &Report{CaseID: cfg.CaseID}

	// Single query yielding rows ordered by rule_id so we can group as we
	// stream. The level filter is applied here so we don't waste memory on
	// info-level rows we'll discard.
	query := `
		SELECT
			json_extract_string(payload_json, '$.RuleID')    AS rule_id,
			json_extract_string(payload_json, '$.RuleTitle') AS rule_title,
			LOWER(COALESCE(json_extract_string(payload_json, '$.Level'), '')) AS lvl,
			audit_id, ts_utc, artifact_id, event_type,
			COALESCE(json_extract_string(payload_json, '$.Channel'), '')         AS channel,
			COALESCE(json_extract_string(payload_json, '$.EventID'), '')         AS event_id,
			COALESCE(json_extract_string(payload_json, '$.Computer'), '')        AS computer,
			COALESCE(json_extract_string(payload_json, '$.Details'), '')         AS details,
			COALESCE(json_extract_string(payload_json, '$.ExtraFieldInfo'), '')  AS extra
		FROM unified_events
		WHERE case_id = ? AND artifact_id = 'hayabusa'
	`
	if !opts.IncludeInfoLevel {
		query += ` AND LOWER(COALESCE(json_extract_string(payload_json, '$.Level'), '')) NOT IN ('info', 'informational', 'low')`
	}
	query += ` ORDER BY 1, ts_utc`

	rows, err := cfg.CaseDB.DB().QueryContext(ctx, query, cfg.CaseID)
	if err != nil {
		return nil, fmt.Errorf("query hayabusa events: %w", err)
	}
	defer rows.Close()

	// Stream and group.
	var (
		curRuleID, curTitle, curLevel string
		curEvidence                    []EvidenceRef
		curTotalRows                   int
	)

	flush := func() error {
		if curRuleID == "" {
			return nil
		}
		f := buildHayabusaFinding(cfg.CaseID, curRuleID, curTitle,
			normaliseLevel(curLevel), curEvidence, curTotalRows, cfg.MaxEvidence)
		outPath := findingPath(cfg.FindingsDir, "hayabusa", curRuleID)
		if err := writeFinding(outPath, f); err != nil {
			return err
		}
		report.Matched++
		report.Findings = append(report.Findings, FindingSummary{
			RuleID:     curRuleID,
			RuleSource: "hayabusa",
			Level:      normaliseLevel(curLevel),
			Title:      curTitle,
			MatchCount: curTotalRows,
			OutputPath: outPath,
			Truncated:  curTotalRows > len(curEvidence),
		})
		emit(cfg.ProgressFn, Event{Index: report.TotalRules, Total: report.TotalRules,
			RuleID: curRuleID, RuleSource: "hayabusa",
			State: "matched", MatchCount: curTotalRows})
		return nil
	}

	for rows.Next() {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		var (
			ruleID, title, lvl, auditID, artifactID, eventType string
			channel, eventID, computer, details, extra        string
			ts                                                 sql.NullTime
		)
		if err := rows.Scan(&ruleID, &title, &lvl, &auditID, &ts,
			&artifactID, &eventType, &channel, &eventID, &computer,
			&details, &extra); err != nil {
			return report, fmt.Errorf("scan: %w", err)
		}

		if ruleID != curRuleID {
			if err := flush(); err != nil {
				return report, err
			}
			curRuleID = ruleID
			curTitle = title
			curLevel = lvl
			curEvidence = nil
			curTotalRows = 0
			report.TotalRules++
		}

		curTotalRows++
		if len(curEvidence) >= cfg.MaxEvidence {
			continue
		}
		ev := EvidenceRef{
			AuditID:    auditID,
			ArtifactID: artifactID,
			EventType:  eventType,
			Extra: map[string]any{
				"channel":  channel,
				"event_id": eventID,
				"computer": computer,
				"details":  details,
			},
		}
		if extra != "" {
			ev.Extra["extra_field_info"] = extra
		}
		if ts.Valid {
			t := ts.Time
			ev.TsUTC = &t
		}
		curEvidence = append(curEvidence, ev)
	}
	if err := rows.Err(); err != nil {
		return report, err
	}
	if err := flush(); err != nil {
		return report, err
	}

	report.DurationS = time.Since(start).Seconds()
	return report, nil
}

// buildHayabusaFinding constructs the Finding object for one Hayabusa rule_id.
func buildHayabusaFinding(caseID, ruleID, title, level string, evidence []EvidenceRef, totalRows, maxEvidence int) Finding {
	approved, approvedBy := AutoApproveByLevel(level)
	return Finding{
		FindingID:  uuid.NewString(),
		CaseID:     caseID,
		RuleID:     ruleID,
		RuleSource: "hayabusa",
		RuleMeta: RuleMeta{
			Title: title,
			Level: level,
		},
		Evidence:    evidence,
		MatchCount:  totalRows,
		Truncated:   totalRows > maxEvidence,
		Approved:    approved,
		ApprovedBy:  approvedBy,
		GeneratedAt: time.Now().UTC(),
		SQL:         "(passthrough: Hayabusa Tier 0 pre-detected; no SQL generated)",
	}
}

// normaliseLevel converts Hayabusa's level naming to Sigma's convention so
// AutoApproveByLevel and Review Gate logic work uniformly.
//   Hayabusa: info | low | med | high | critical
//   Sigma:    informational | low | medium | high | critical
func normaliseLevel(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return "informational"
	case "med":
		return "medium"
	default:
		return strings.ToLower(strings.TrimSpace(s))
	}
}

