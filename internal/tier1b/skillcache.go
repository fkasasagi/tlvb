package tier1b

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/tlvb/tlvb/internal/evidencex"
)

// skillSQLPlan is one reusable query the LLM proposes when it judges that a
// recurring anomaly perspective is not yet covered by an existing intent.
// It is stored as a 'candidate' in skill_sql_cache and trialed on later runs.
type skillSQLPlan struct {
	Intent    string `json:"intent"`
	Rationale string `json:"rationale"`
	SQL       string `json:"sql"`
}

// intentInfo is the per-cached-query summary shown to the LLM so it can
// self-judge coverage and avoid proposing duplicates.
type intentInfo struct {
	Intent   string `json:"intent"`
	State    string `json:"state"`
	HitCount int    `json:"hit_count,omitempty"`
}

// ----------------------------------------------------------------------------
// SQL safety (mirrors tier2/active_search.go — copied to keep packages
// decoupled, same as extractFieldValue is duplicated for the same reason).
// ----------------------------------------------------------------------------

var (
	skillDangerousSQL  = regexp.MustCompile(`(?i)\b(insert|update|delete|drop|alter|attach|detach|create|pragma|copy|export)\b`)
	skillStringLiteral = regexp.MustCompile(`'(?:[^']|'')*'`)
)

func validateSkillSQL(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("empty SQL")
	}
	lower := strings.ToLower(s)
	if !strings.HasPrefix(lower, "select ") && !strings.HasPrefix(lower, "with ") {
		return fmt.Errorf("SQL must start with SELECT or WITH")
	}
	stripped := skillStringLiteral.ReplaceAllString(s, "''")
	if skillDangerousSQL.MatchString(stripped) {
		return fmt.Errorf("SQL contains disallowed keyword at statement level")
	}
	if !strings.Contains(s, "case_id") {
		return fmt.Errorf("SQL missing required case_id predicate")
	}
	if strings.Count(s, "?") != 1 {
		return fmt.Errorf("expected exactly one ? placeholder, got %d", strings.Count(s, "?"))
	}
	if strings.HasSuffix(s, ";") {
		return fmt.Errorf("SQL must not end with semicolon")
	}
	return nil
}

// ----------------------------------------------------------------------------
// Execution
// ----------------------------------------------------------------------------

// execSkillSQLAudits runs a validated skill query and returns the audit_ids it
// matched (capped at max) plus the total hit count. The query MUST project an
// audit_id column (the LLM is instructed to lead with audit_id, ts_utc,
// artifact_id).
func execSkillSQLAudits(ctx context.Context, db *sql.DB, caseID, sqlText string, max int) ([]string, int, error) {
	if max <= 0 {
		max = 200
	}
	r, err := db.QueryContext(ctx, sqlText, caseID)
	if err != nil {
		return nil, 0, fmt.Errorf("execute: %w", err)
	}
	defer r.Close()
	cols, err := r.Columns()
	if err != nil {
		return nil, 0, err
	}
	aidx := colIndex(cols, "audit_id")
	if aidx < 0 {
		return nil, 0, fmt.Errorf("skill SQL must project an audit_id column")
	}
	var audits []string
	total := 0
	for r.Next() {
		total++
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := r.Scan(ptrs...); err != nil {
			return audits, total, fmt.Errorf("scan: %w", err)
		}
		if len(audits) < max {
			if a := toStrVal(vals[aidx]); a != "" {
				audits = append(audits, a)
			}
		}
	}
	return audits, total, r.Err()
}

// hydrateCandidates re-reads full rows for the given audit_ids so cache hits
// flow through the same shrinkPayload path as heuristic candidates. Tagged
// with the synthetic "S0" lens (skill-cache origin) and a high score so they
// survive the per-run event cap.
func hydrateCandidates(ctx context.Context, db *sql.DB, caseID string, audits []string) ([]candidate, error) {
	if len(audits) == 0 {
		return nil, nil
	}
	ph := make([]string, len(audits))
	args := make([]any, 0, len(audits)+1)
	args = append(args, caseID)
	for i, a := range audits {
		ph[i] = "?"
		args = append(args, a)
	}
	q := `SELECT audit_id, ts_utc, artifact_id, COALESCE(computer,''), payload_json
	        FROM unified_events
	       WHERE case_id = ? AND audit_id IN (` + strings.Join(ph, ",") + `)`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []candidate
	for rows.Next() {
		var c candidate
		var ts sql.NullTime
		if err := rows.Scan(&c.AuditID, &ts, &c.ArtifactID, &c.Computer, &c.Payload); err != nil {
			return nil, err
		}
		if ts.Valid {
			c.TsUTC = ts.Time.UTC()
			c.HasTS = true
		}
		c.Lenses = []string{"S0"}
		c.Score = 10
		out = append(out, c)
	}
	return out, rows.Err()
}

// mergeCacheCandidates prepends cache-derived candidates (priority — they are
// learned/proven lenses) to the heuristic set, dedups by audit_id (unioning
// lenses), and caps the result at maxEvents.
func mergeCacheCandidates(heuristic, cache []candidate, maxEvents int) []candidate {
	seen := map[string]int{}
	out := make([]candidate, 0, len(heuristic)+len(cache))
	add := func(c candidate) {
		if idx, ok := seen[c.AuditID]; ok {
			out[idx].Lenses = append(out[idx].Lenses, c.Lenses...)
			return
		}
		seen[c.AuditID] = len(out)
		out = append(out, c)
	}
	for _, c := range cache {
		add(c)
	}
	for _, c := range heuristic {
		add(c)
	}
	if maxEvents > 0 && len(out) > maxEvents {
		out = out[:maxEvents]
	}
	return out
}

// promotableHashes returns the distinct sql_sha256 whose produced audit_ids
// were cited by at least one finding. These get promoted to 'canonical'
// (candidates) or have their hit_count bumped (already canonical).
func promotableHashes(findings []AnomalyFinding, auditToSQL map[string][]string) []string {
	set := map[string]bool{}
	for _, f := range findings {
		for _, a := range f.AuditIDs {
			for _, sha := range auditToSQL[a] {
				set[sha] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ----------------------------------------------------------------------------
// LLM output parsing (object {findings, proposed_queries} or bare array)
// ----------------------------------------------------------------------------

// parseAnomalyOutput accepts either the v0.2 object shape
//
//	{"findings": [...], "proposed_queries": [...], "requested_files": [...]}
//
// or the v0.1 bare findings array (back-compat — also what the no-cache path
// still emits). The array branch reuses parseAnomalyFindings. requested_files
// (on-demand evidence extraction) is only honoured in the object shape.
func parseAnomalyOutput(text string) ([]AnomalyFinding, []skillSQLPlan, []evidencex.RequestedFile, error) {
	s := strings.TrimSpace(text)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	s = strings.TrimSpace(s)

	if i := strings.IndexAny(s, "[{"); i > 0 {
		s = s[i:]
	}
	if strings.HasPrefix(s, "{") {
		if j := strings.LastIndex(s, "}"); j >= 0 && j < len(s)-1 {
			s = s[:j+1]
		}
		var obj struct {
			Findings        []AnomalyFinding          `json:"findings"`
			ProposedQueries []skillSQLPlan            `json:"proposed_queries"`
			RequestedFiles  []evidencex.RequestedFile `json:"requested_files"`
		}
		if err := json.Unmarshal([]byte(s), &obj); err != nil {
			return nil, nil, nil, fmt.Errorf("unmarshal object: %w (head: %s)", err, truncate(text, 200))
		}
		return sanitizeFindings(obj.Findings), obj.ProposedQueries, obj.RequestedFiles, nil
	}
	// Array fallback — delegate to the well-tested v0.1 parser.
	fs, err := parseAnomalyFindings(s, nil)
	return fs, nil, nil, err
}

// sanitizeFindings trims/normalises fields and drops entries without a
// summary or evidence — same rule as parseAnomalyFindings's filter loop.
func sanitizeFindings(in []AnomalyFinding) []AnomalyFinding {
	out := in[:0]
	for _, f := range in {
		f.Lens = strings.TrimSpace(f.Lens)
		f.Severity = strings.ToLower(strings.TrimSpace(f.Severity))
		f.Summary = strings.TrimSpace(f.Summary)
		if f.Summary == "" || len(f.AuditIDs) == 0 {
			continue
		}
		out = append(out, f)
	}
	return out
}

// ----------------------------------------------------------------------------
// small helpers
// ----------------------------------------------------------------------------

func colIndex(cols []string, name string) int {
	for i, c := range cols {
		if strings.EqualFold(c, name) {
			return i
		}
	}
	return -1
}

func toStrVal(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []byte:
		return string(t)
	default:
		return fmt.Sprintf("%v", t)
	}
}

func dedupStrings(in []string, limit int) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// distinctIntents collapses cache rows into the intent list shown to the LLM.
func distinctIntents(rows []skillCacheEntry) []intentInfo {
	seen := map[string]bool{}
	var out []intentInfo
	for _, r := range rows {
		key := strings.ToLower(strings.TrimSpace(r.Intent))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, intentInfo{Intent: r.Intent, State: r.State, HitCount: r.HitCount})
	}
	return out
}

// skillCacheEntry is the minimal projection of a rulesdb.SkillSQLRow that the
// runner threads through the cache phase (decoupled from the rulesdb type so
// helpers here stay testable without a DB).
type skillCacheEntry struct {
	SQLSHA256 string
	SQL       string
	Intent    string
	State     string
	HitCount  int
}
