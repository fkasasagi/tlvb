package tier1a

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tlvb/tlvb/internal/auditlog"
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
	al := newActionLog(cfg.FindingsDir, cfg.CaseID)

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
			COALESCE(json_extract_string(payload_json, '$.ExtraFieldInfo'), '')  AS extra,
			COALESCE(json_extract_string(payload_json, '$.MitreTactics'), '')    AS mitre_tactics,
			COALESCE(json_extract_string(payload_json, '$.MitreTags'), '')       AS mitre_tags
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
		curTactics, curTechniques     []string
		curEvidence                   []EvidenceRef
		curTotalRows                  int
	)

	flush := func() error {
		if curRuleID == "" {
			return nil
		}
		f := buildHayabusaFinding(cfg.CaseID, curRuleID, curTitle,
			normaliseLevel(curLevel), curTactics, curTechniques,
			curEvidence, curTotalRows, cfg.MaxEvidence)
		outPath := findingPath(cfg.FindingsDir, "hayabusa", curRuleID)
		if err := writeFinding(outPath, f); err != nil {
			return err
		}
		report.Matched++
		al.Append(auditlog.Action{Actor: "tier1a", Kind: "rule_sql",
			RuleID: curRuleID, RuleSource: "hayabusa",
			RowCount: auditlog.IntPtr(curTotalRows), Success: auditlog.BoolPtr(true)})
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
			channel, eventID, computer, details, extra         string
			mitreTactics, mitreTags                            string
			ts                                                 sql.NullTime
		)
		if err := rows.Scan(&ruleID, &title, &lvl, &auditID, &ts,
			&artifactID, &eventType, &channel, &eventID, &computer,
			&details, &extra, &mitreTactics, &mitreTags); err != nil {
			return report, fmt.Errorf("scan: %w", err)
		}

		if ruleID != curRuleID {
			if err := flush(); err != nil {
				return report, err
			}
			curRuleID = ruleID
			curTitle = title
			curLevel = lvl
			curTactics = nil
			curTechniques = nil
			curEvidence = nil
			curTotalRows = 0
			report.TotalRules++
		}

		// MITRE tactics/techniques are a property of the matched rule, so every
		// row in the group carries the same values — EXCEPT rows ingested by an
		// older standard-profile parse, which carry none. Take them from the
		// first row in the group that actually has them, so a partially
		// re-parsed case (one evidence verbose, another still stale) still
		// yields a categorised finding.
		if len(curTactics) == 0 {
			curTactics = normaliseHayabusaTactics(mitreTactics)
		}
		if len(curTechniques) == 0 {
			curTechniques = parseHayabusaTechniques(mitreTags)
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
func buildHayabusaFinding(caseID, ruleID, title, level string, tactics, techniques []string, evidence []EvidenceRef, totalRows, maxEvidence int) Finding {
	approved, approvedBy := AutoApproveByLevel(level)
	return Finding{
		FindingID:  uuid.NewString(),
		CaseID:     caseID,
		RuleID:     ruleID,
		RuleSource: "hayabusa",
		RuleMeta: RuleMeta{
			Title:           title,
			Level:           level,
			MITRETactics:    tactics,
			MITRETechniques: techniques,
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
//
//	Hayabusa: info | low | med | high | critical
//	Sigma:    informational | low | medium | high | critical
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

// hayabusaTacticSlug maps Hayabusa's abbreviated tactic names (the
// `tag_output_str` column of config/mitre_tactics.txt — e.g. "PrivEsc") to the
// ATT&CK tactic slugs the Sigma cached-SQL path already emits (e.g.
// "privilege-escalation"). Aligning the two means Hayabusa and Sigma findings
// for the same tactic land in one UI cluster instead of two.
//
// "Stealth" and "DefImpair" are Hayabusa groupings that both correspond to the
// real ATT&CK Defense Evasion tactic (T1562 "Impair Defenses" lives under it),
// so both fold to "defense-evasion".
var hayabusaTacticSlug = map[string]string{
	"recon":      "reconnaissance",
	"resdev":     "resource-development",
	"initaccess": "initial-access",
	"exec":       "execution",
	"persis":     "persistence",
	"privesc":    "privilege-escalation",
	"stealth":    "defense-evasion",
	"defimpair":  "defense-evasion",
	"credaccess": "credential-access",
	"disc":       "discovery",
	"latmov":     "lateral-movement",
	"collect":    "collection",
	"c2":         "command-and-control",
	"exfil":      "exfiltration",
	"impact":     "impact",
}

// normaliseHayabusaTactics splits Hayabusa's MitreTactics cell (abbreviations
// joined by " ¦ ", e.g. "PrivEsc ¦ Persis") into deduped ATT&CK tactic slugs.
// Unknown tokens are kept lowercased rather than dropped, so an unexpected
// abbreviation still produces a real cluster instead of silently becoming
// "uncategorized".
func normaliseHayabusaTactics(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, tok := range strings.Split(raw, "¦") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		if tok == "" || tok == "-" {
			continue
		}
		if slug, ok := hayabusaTacticSlug[tok]; ok {
			tok = slug
		}
		if !seen[tok] {
			seen[tok] = true
			out = append(out, tok)
		}
	}
	return out
}

// parseHayabusaTechniques pulls the ATT&CK technique IDs out of Hayabusa's
// MitreTags cell. MitreTags also carries software/group tags, so we keep only
// tokens shaped like a technique ID (T#### optionally with a .### sub-technique)
// to match the Sigma path's mitre_techniques field.
func parseHayabusaTechniques(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, tok := range strings.Split(raw, "¦") {
		tok = strings.TrimSpace(tok)
		if !techniqueID.MatchString(tok) || seen[tok] {
			continue
		}
		seen[tok] = true
		out = append(out, tok)
	}
	return out
}

var techniqueID = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
