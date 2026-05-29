package tier1a

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tlvb/tlvb/internal/casedb"
	"github.com/tlvb/tlvb/internal/rulesdb"
)

// Config drives Run().
type Config struct {
	CaseID       string
	RulesDB      *rulesdb.Manager
	CaseDB       *casedb.Manager
	FindingsDir  string // outputs/cases/<id>/findings/by-rule
	SourceFilter string // empty = all sources
	RuleIDFilter string // empty = all rules; otherwise run exactly one rule
	MaxEvidence  int    // cap evidence rows per finding (0 = default 100)
	ProgressFn   func(Event)
}

// Event is the per-rule progress hook.
type Event struct {
	Index, Total int
	RuleID       string
	RuleSource   string
	State        string // "matched" | "no_match" | "error" | "skipped_artifact" | "skipped_source" | "skipped_filter"
	MatchCount   int
	Error        string
}

// Report is returned by Run().
type Report struct {
	CaseID          string
	TotalRules      int
	Matched         int
	NoMatch         int
	SkippedArtifact int
	SkippedSource   int
	SkippedFilter   int
	Errors          int
	Findings        []FindingSummary
	DurationS       float64
}

// FindingSummary is the per-finding summary in the report (full finding goes to disk).
type FindingSummary struct {
	RuleID     string
	RuleSource string
	Level      string
	Title      string
	MatchCount int
	OutputPath string
	Truncated  bool
}

// Run executes all built cached SQL rows against the case and writes
// findings/by-rule/<source>/<id>.json for each rule that hit.
//
// Failure policy: SQL execution errors against individual rules do NOT
// abort the run — they're counted and reported, the rest continues
// (graceful degradation, per CLAUDE.md "重要な制約 4").
func Run(ctx context.Context, cfg Config) (*Report, error) {
	if cfg.CaseID == "" {
		return nil, fmt.Errorf("Tier 1A: CaseID is required")
	}
	if cfg.RulesDB == nil || cfg.CaseDB == nil {
		return nil, fmt.Errorf("Tier 1A: RulesDB and CaseDB must be open")
	}
	if cfg.FindingsDir == "" {
		cfg.FindingsDir = filepath.Join("outputs", "cases", cfg.CaseID, "findings", "by-rule")
	}
	if cfg.MaxEvidence <= 0 {
		cfg.MaxEvidence = 100
	}

	start := time.Now()
	report := &Report{CaseID: cfg.CaseID}

	// 1. Load the set of artifact_ids the case actually has rows for —
	//    used by the prefilter to skip rules targeting absent artifacts.
	availableArtifacts, err := listCaseArtifacts(ctx, cfg.CaseDB, cfg.CaseID)
	if err != nil {
		return nil, fmt.Errorf("list case artifacts: %w", err)
	}

	// 2. List all built rules.
	rows, err := cfg.RulesDB.ListAll(ctx, cfg.SourceFilter, rulesdb.StateBuilt)
	if err != nil {
		return nil, fmt.Errorf("list built rules: %w", err)
	}
	report.TotalRules = len(rows)

	for i, r := range rows {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		if cfg.RuleIDFilter != "" && r.RuleID != cfg.RuleIDFilter {
			report.SkippedFilter++
			emit(cfg.ProgressFn, Event{Index: i + 1, Total: len(rows),
				RuleID: r.RuleID, RuleSource: r.RuleSource,
				State: "skipped_filter"})
			continue
		}

		// Prefilter: skip rules whose required artifacts aren't parsed.
		if !rulePrefilterMatches(r.PrefilterArtifacts, availableArtifacts) {
			report.SkippedArtifact++
			emit(cfg.ProgressFn, Event{Index: i + 1, Total: len(rows),
				RuleID: r.RuleID, RuleSource: r.RuleSource,
				State: "skipped_artifact"})
			continue
		}

		matched, n, err := executeRule(ctx, cfg, r)
		if err != nil {
			report.Errors++
			emit(cfg.ProgressFn, Event{Index: i + 1, Total: len(rows),
				RuleID: r.RuleID, RuleSource: r.RuleSource,
				State: "error", Error: err.Error()})
			continue
		}
		if !matched {
			report.NoMatch++
			emit(cfg.ProgressFn, Event{Index: i + 1, Total: len(rows),
				RuleID: r.RuleID, RuleSource: r.RuleSource,
				State: "no_match"})
			continue
		}
		report.Matched++
		report.Findings = append(report.Findings, FindingSummary{
			RuleID:     r.RuleID,
			RuleSource: r.RuleSource,
			Level:      extractLevel(r.RuleMeta),
			Title:      extractTitle(r.RuleMeta),
			MatchCount: n,
			OutputPath: findingPath(cfg.FindingsDir, r.RuleSource, r.RuleID),
			Truncated:  n > cfg.MaxEvidence,
		})
		emit(cfg.ProgressFn, Event{Index: i + 1, Total: len(rows),
			RuleID: r.RuleID, RuleSource: r.RuleSource,
			State: "matched", MatchCount: n})
	}

	report.DurationS = time.Since(start).Seconds()
	return report, nil
}

// listCaseArtifacts returns the set of artifact_ids the case has rows
// in unified_events for. Used by the prefilter.
func listCaseArtifacts(ctx context.Context, db *casedb.Manager, caseID string) (map[string]bool, error) {
	rows, err := db.DB().QueryContext(ctx,
		`SELECT DISTINCT artifact_id FROM unified_events WHERE case_id = ?`,
		caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out[a] = true
	}
	return out, rows.Err()
}

// rulePrefilterMatches returns true when the rule's required artifacts
// (CSV string from rule_sql_cache.prefilter_artifacts) overlap with the
// case's available artifacts.
// Empty prefilter (== "no constraint") matches anything.
func rulePrefilterMatches(prefilter string, available map[string]bool) bool {
	if prefilter == "" {
		return true
	}
	for _, a := range strings.Split(prefilter, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if available[a] {
			return true
		}
	}
	return false
}

// executeRule runs one cached SQL against the case. Returns (matched, totalRows, err).
// When matched, the Finding JSON has been written to disk.
func executeRule(ctx context.Context, cfg Config, r rulesdb.CacheRow) (bool, int, error) {
	if r.SQL == "" {
		return false, 0, fmt.Errorf("empty cached SQL")
	}
	// Defensive: the SQL was validated at build time, but bind site
	// expects exactly one ? placeholder for case_id. Count and reject
	// otherwise.
	if strings.Count(r.SQL, "?") != 1 {
		return false, 0, fmt.Errorf("expected exactly one ? placeholder, got %d", strings.Count(r.SQL, "?"))
	}

	rows, err := cfg.CaseDB.DB().QueryContext(ctx, r.SQL, cfg.CaseID)
	if err != nil {
		return false, 0, fmt.Errorf("execute SQL: %w", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return false, 0, fmt.Errorf("columns: %w", err)
	}

	evidence, totalRows, err := scanEvidence(rows, cols, cfg.MaxEvidence)
	if err != nil {
		return false, 0, err
	}
	if totalRows == 0 {
		return false, 0, nil
	}

	meta := parseRuleMeta(r.RuleMeta)
	approved, approvedBy := AutoApproveByLevel(meta.Level)
	f := Finding{
		FindingID:   uuid.NewString(),
		CaseID:      cfg.CaseID,
		RuleID:      r.RuleID,
		RuleSource:  r.RuleSource,
		RuleMeta:    meta,
		Evidence:    evidence,
		MatchCount:  totalRows,
		Truncated:   totalRows > len(evidence),
		Approved:    approved,
		ApprovedBy:  approvedBy,
		GeneratedAt: time.Now().UTC(),
		SQL:         r.SQL,
	}

	outPath := findingPath(cfg.FindingsDir, r.RuleSource, r.RuleID)
	if err := writeFinding(outPath, f); err != nil {
		return false, totalRows, fmt.Errorf("write finding: %w", err)
	}
	return true, totalRows, nil
}

// scanEvidence reads up to maxEvidence rows into EvidenceRef while
// counting the total. The canonical first four columns
// (audit_id, ts_utc, artifact_id, event_type) are pulled into named
// fields; anything beyond goes into Extra.
func scanEvidence(rows *sql.Rows, cols []string, maxEvidence int) ([]EvidenceRef, int, error) {
	var (
		out      []EvidenceRef
		totalRows int
	)
	for rows.Next() {
		totalRows++

		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, 0, fmt.Errorf("scan: %w", err)
		}

		if len(out) >= maxEvidence {
			// Continue draining to get accurate totalRows without
			// retaining the row payload.
			continue
		}

		ev := EvidenceRef{}
		extra := map[string]any{}
		for i, name := range cols {
			v := vals[i]
			switch strings.ToLower(name) {
			case "audit_id":
				ev.AuditID = toStr(v)
			case "ts_utc":
				if t, ok := toTime(v); ok {
					tc := t
					ev.TsUTC = &tc
				}
			case "artifact_id":
				ev.ArtifactID = toStr(v)
			case "event_type":
				ev.EventType = toStr(v)
			default:
				extra[name] = normaliseExtra(v)
			}
		}
		if len(extra) > 0 {
			ev.Extra = extra
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, totalRows, nil
}

func writeFinding(path string, f Finding) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o644)
}

// findingPath returns the canonical output path for a (source, rule_id)
// pair. rule_id may contain characters unsafe for filesystems (slashes
// in custom rule names, etc.) — sanitise to underscore.
func findingPath(root, source, ruleID string) string {
	safe := strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(ruleID)
	return filepath.Join(root, source, safe+".json")
}

// parseRuleMeta extracts the structured fields from the JSON blob stored
// in rule_sql_cache.rule_meta. Returns zero-value RuleMeta on parse error.
func parseRuleMeta(raw string) RuleMeta {
	if raw == "" {
		return RuleMeta{}
	}
	var m struct {
		Title           string   `json:"title"`
		Description     string   `json:"description"`
		Level           string   `json:"level"`
		MITRETechniques []string `json:"mitre_techniques"`
		MITRETactics    []string `json:"mitre_tactics"`
		SourcePath      string   `json:"source_path"`
	}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return RuleMeta{}
	}
	return RuleMeta{
		Title:           m.Title,
		Description:     m.Description,
		Level:           m.Level,
		MITRETechniques: m.MITRETechniques,
		MITRETactics:    m.MITRETactics,
		SourcePath:      m.SourcePath,
	}
}

func extractTitle(raw string) string  { return parseRuleMeta(raw).Title }
func extractLevel(raw string) string  { return parseRuleMeta(raw).Level }

// ----------------------------------------------------------------------------
// type helpers — DuckDB driver returns interface{} for unknown columns
// ----------------------------------------------------------------------------

func toStr(v any) string {
	if v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	case []byte:
		return string(s)
	default:
		return fmt.Sprintf("%v", s)
	}
}

func toTime(v any) (time.Time, bool) {
	if v == nil {
		return time.Time{}, false
	}
	switch t := v.(type) {
	case time.Time:
		return t, true
	case string:
		if parsed, err := time.Parse(time.RFC3339Nano, t); err == nil {
			return parsed, true
		}
		if parsed, err := time.Parse("2006-01-02 15:04:05", t); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

// normaliseExtra ensures payloads round-trip cleanly through JSON.
// DuckDB sometimes returns []byte for VARCHAR; convert to string.
func normaliseExtra(v any) any {
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return v
}

func emit(fn func(Event), ev Event) {
	if fn != nil {
		fn(ev)
	}
}
