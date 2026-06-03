package tier2

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// activeSearchSystemPrompt is the additional instruction Tier 2 sends
// during active-search rounds. We inject it as a system prompt so the
// per-question prompt stays compact.
const activeSearchSystemPrompt = `You are now in TLVB Tier 2 ACTIVE-SEARCH mode.

Your job: given a cluster's open_questions and current context, propose at
most 3 SQL SELECT statements against the unified_events table that would
help answer those questions.

Hard requirements (failure to comply = the SQL gets rejected):

1. Return ONLY a single JSON array, no markdown fences, no prose. Shape:
   [
     {
       "question": "<the exact open_question text being investigated>",
       "rationale": "<1-line why this SQL helps>",
       "sql": "<a single DuckDB SELECT statement>"
     },
     ...
   ]
   The array MAY be empty if no useful SQL exists.

2. Every SQL MUST start with SELECT (or WITH). NO INSERT/UPDATE/DELETE/
   DROP/CREATE/ALTER/ATTACH/PRAGMA. NO trailing semicolons.

3. The first WHERE predicate MUST be literally: case_id = ?
   The runtime supplies the case_id binding.

4. Output columns MUST start with: audit_id, ts_utc, artifact_id, event_type
   (followed by any rule-specific projected fields).

5. Use DuckDB JSON extraction:
     json_extract_string(payload_json, '$.Key')
   For EVTX events, EventId is a STRING — cast to INTEGER for numeric compares.
   The actual key names in payload_json depend on artifact_id (see context).

6. Add LIMIT N at the end of every SQL (N ≤ 500). Wide windows over MFT
   without LIMIT would be a denial of service.

7. Only propose SQL for questions answerable from unified_events. If the
   question needs data we don't have (e.g. an external GeoIP DB), skip it.
`

// activeSearchSQLEntry is what the LLM hands us. We re-validate and rewrite
// before execution.
type activeSearchSQLEntry struct {
	Question  string `json:"question"`
	Rationale string `json:"rationale"`
	SQL       string `json:"sql"`
}

// generateActiveSearchSQL asks the LLM for SQL plans that address a
// cluster's open_questions.
func generateActiveSearchSQL(ctx context.Context, cfg Config, c *Cluster,
	audit *SynthAudit) ([]activeSearchSQLEntry, error) {
	if len(c.OpenQuestions) == 0 {
		return nil, nil
	}
	prompt, err := buildActiveSearchPrompt(c)
	if err != nil {
		return nil, err
	}
	subCtx, cancel := context.WithTimeout(ctx, cfg.PerClusterTimeout)
	defer cancel()
	startedAt := time.Now()
	out, err := callClaudeCLI(subCtx, cfg, activeSearchSystemPrompt, prompt)
	audit.LLMCallsTotal++
	audit.LLMDurationS += time.Since(startedAt).Seconds()
	if err != nil {
		return nil, fmt.Errorf("active-search LLM: %w", err)
	}
	audit.addUsage(out)
	entries, err := parseActiveSearchEntries(out.Result)
	if err != nil {
		return nil, fmt.Errorf("parse active-search entries: %w (head: %s)",
			err, truncate(out.Result, 200))
	}
	return entries, nil
}

func buildActiveSearchPrompt(c *Cluster) (string, error) {
	type clusterCtx struct {
		ClusterID       int      `json:"cluster_id"`
		AttackPhase     string   `json:"attack_phase,omitempty"`
		WindowStart     string   `json:"window_start,omitempty"`
		WindowEnd       string   `json:"window_end,omitempty"`
		MITRETechniques []string `json:"mitre_techniques,omitempty"`
		Narrative       string   `json:"narrative_so_far,omitempty"`
		OpenQuestions   []string `json:"open_questions"`
	}
	pkt := clusterCtx{
		ClusterID:       c.ID,
		AttackPhase:     c.AttackPhase,
		MITRETechniques: c.MITRETechniques,
		Narrative:       c.Narrative,
		OpenQuestions:   c.OpenQuestions,
	}
	if !c.StartTS.IsZero() {
		pkt.WindowStart = c.StartTS.Format(time.RFC3339)
	}
	if !c.EndTS.IsZero() {
		pkt.WindowEnd = c.EndTS.Format(time.RFC3339)
	}
	body, err := json.MarshalIndent(pkt, "", "  ")
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func parseActiveSearchEntries(text string) ([]activeSearchSQLEntry, error) {
	var out []activeSearchSQLEntry
	if err := decodeFirstJSON(text, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ----------------------------------------------------------------------------
// SQL safety + execution
// ----------------------------------------------------------------------------

// activeSearchDangerousSQL mirrors the rulebuild guard. Kept in this package
// so we don't introduce a cross-tier import.
var (
	activeSearchDangerousSQL  = regexp.MustCompile(`(?i)\b(insert|update|delete|drop|alter|attach|detach|create|pragma|copy|export)\b`)
	activeSearchStringLiteral = regexp.MustCompile(`'(?:[^']|'')*'`)
)

func validateActiveSearchSQL(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("empty SQL")
	}
	lower := strings.ToLower(s)
	if !strings.HasPrefix(lower, "select ") && !strings.HasPrefix(lower, "with ") {
		return fmt.Errorf("SQL must start with SELECT or WITH")
	}
	stripped := activeSearchStringLiteral.ReplaceAllString(s, "''")
	if activeSearchDangerousSQL.MatchString(stripped) {
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

// execActiveSQL runs a validated SELECT and returns the matching rows as
// TimelineEvents (re-using shrinkPayload).
func execActiveSQL(ctx context.Context, db *sql.DB, caseID, sqlText string,
	maxRowsRetained int) (rows int, evidence []TimelineEvent, err error) {

	if maxRowsRetained <= 0 {
		maxRowsRetained = 50
	}
	r, err := db.QueryContext(ctx, sqlText, caseID)
	if err != nil {
		return 0, nil, fmt.Errorf("execute: %w", err)
	}
	defer r.Close()
	cols, err := r.Columns()
	if err != nil {
		return 0, nil, err
	}
	for r.Next() {
		rows++
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := r.Scan(ptrs...); err != nil {
			return rows, evidence, fmt.Errorf("scan: %w", err)
		}
		if len(evidence) >= maxRowsRetained {
			continue // keep counting hits, drop the payload
		}
		ev := TimelineEvent{Excerpt: map[string]any{}}
		for i, col := range cols {
			v := vals[i]
			switch strings.ToLower(col) {
			case "audit_id":
				ev.AuditID = toStr(v)
			case "ts_utc":
				if t, ok := v.(time.Time); ok {
					ev.TsUTC = t.UTC()
				} else if s, ok := v.(string); ok {
					if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
						ev.TsUTC = t.UTC()
					}
				}
			case "artifact_id":
				ev.ArtifactID = toStr(v)
			case "event_type":
				ev.EventType = toStr(v)
			default:
				ev.Excerpt[col] = normaliseAny(v)
			}
		}
		evidence = append(evidence, ev)
	}
	if err := r.Err(); err != nil {
		return rows, evidence, err
	}
	return rows, evidence, nil
}

func toStr(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	default:
		return fmt.Sprintf("%v", t)
	}
}

func normaliseAny(v any) any {
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return v
}

// ----------------------------------------------------------------------------
// LLM interpretation pass
// ----------------------------------------------------------------------------

// interpretActiveSearchResults asks the LLM to read its own SQL results
// and synthesise an answer for each open question.
func interpretActiveSearchResults(ctx context.Context, cfg Config, c *Cluster,
	results []ActiveSearchResult, audit *SynthAudit) (string, error) {

	if len(results) == 0 {
		return "", nil
	}
	type ctxPkt struct {
		ClusterID    int                  `json:"cluster_id"`
		AttackPhase  string               `json:"attack_phase,omitempty"`
		Narrative    string               `json:"narrative_so_far,omitempty"`
		SearchResult []ActiveSearchResult `json:"search_results"`
	}
	pkt := ctxPkt{
		ClusterID:    c.ID,
		AttackPhase:  c.AttackPhase,
		Narrative:    c.Narrative,
		SearchResult: results,
	}
	body, err := json.MarshalIndent(pkt, "", "  ")
	if err != nil {
		return "", err
	}
	system := `You are now in TLVB Tier 2 ACTIVE-SEARCH INTERPRETATION mode.

Your earlier round produced SQL queries and now their results are below.
Write a brief follow-up addendum to the cluster narrative (2-4 sentences)
that incorporates concrete findings the SQL revealed. Cite audit_ids when
relevant. If the SQL returned 0 rows or the evidence is inconclusive,
note that honestly — do not invent answers.

Return ONLY the addendum text. No JSON, no markdown.`
	subCtx, cancel := context.WithTimeout(ctx, cfg.PerClusterTimeout)
	defer cancel()
	startedAt := time.Now()
	out, err := callClaudeCLI(subCtx, cfg, system, string(body))
	audit.LLMCallsTotal++
	audit.LLMDurationS += time.Since(startedAt).Seconds()
	if err != nil {
		return "", err
	}
	audit.addUsage(out)
	return strings.TrimSpace(out.Result), nil
}

// ----------------------------------------------------------------------------
// Orchestrator entry point
// ----------------------------------------------------------------------------

// RunActiveSearch is the top-level helper called from Run() when
// cfg.ActiveSearch is enabled. It walks each cluster, asks the LLM for
// SQL, executes the validated ones, then asks the LLM to interpret
// results, and finally appends an addendum to the cluster narrative.
func RunActiveSearch(ctx context.Context, cfg Config, db *sql.DB,
	clusters []Cluster, audit *SynthAudit) ([]Cluster, error) {

	audit.ActiveSearchEnabled = true
	for i := range clusters {
		c := &clusters[i]
		if len(c.OpenQuestions) == 0 {
			continue
		}
		entries, err := generateActiveSearchSQL(ctx, cfg, c, audit)
		if err != nil {
			// graceful: skip this cluster, keep going
			continue
		}
		var results []ActiveSearchResult
		for _, e := range entries {
			audit.ActiveSQLAttempted++
			res := ActiveSearchResult{
				Question: e.Question,
				SQL:      e.SQL,
			}
			if err := validateActiveSearchSQL(e.SQL); err != nil {
				res.Error = "validation: " + err.Error()
				results = append(results, res)
				continue
			}
			n, ev, err := execActiveSQL(ctx, db, cfg.CaseID, e.SQL, 50)
			if err != nil {
				res.Error = "execute: " + err.Error()
				results = append(results, res)
				continue
			}
			res.Hits = n
			res.Evidence = ev
			audit.ActiveSQLSucceeded++
			results = append(results, res)
		}
		c.ActiveSearch = results

		addendum, err := interpretActiveSearchResults(ctx, cfg, c, results, audit)
		if err != nil {
			continue
		}
		// Attach addendum as an extra paragraph to the narrative for
		// downstream Reporter rendering.
		if addendum != "" {
			c.Narrative = strings.TrimRight(c.Narrative, "\n") + "\n\nActive-search addendum: " + addendum
		}
		// Also stamp the LLM-written answer onto each ActiveSearchResult
		// so the Answer column survives serialisation. Use a single
		// addendum split heuristically — for MVP, attach the full
		// addendum to the FIRST successful search result. v0.2 can ask
		// the LLM to write per-question answers.
		for k := range c.ActiveSearch {
			if c.ActiveSearch[k].Error == "" {
				c.ActiveSearch[k].Answer = addendum
				break
			}
		}
	}
	return clusters, nil
}
