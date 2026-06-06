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

	"github.com/tlvb/tlvb/internal/auditlog"
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
   The actual key names in payload_json depend on artifact_id. The context
   includes a "schema_samples" section showing the REAL keys available per
   artifact (and, for EVTX, per EventId) — only reference keys that appear
   there. A path that is not in the samples returns NULL silently.

5a. EVTX storage shape (CRITICAL — this is where most active-search SQL
    fails). EVTX rows (artifact_id='evtx') are EvtxECmd-flattened and do
    NOT have top-level keys like $.TargetUserName / $.IpAddress /
    $.LogonType / $.CommandLine / $.ScriptBlockText. Writing those returns
    NULL silently. Two correct ways to read EVTX field values:

    (a) PREFERRED — the curated fields are top-level in PayloadData1..6 as
        "Label: value" strings (e.g. "LogonType 5", "TargetServerName:
        localhost", "ScriptBlockText: ..."). WHICH slot holds what varies
        by EventId — read schema_samples.evtx_by_event_id[].payload_data to
        see the real values for this cluster, then:
          json_extract_string(payload_json,'$.PayloadData2')
        optionally with LIKE / regexp_extract to pull the value after the
        "Label: " prefix.

    (b) For a raw Windows EventData field NOT surfaced in PayloadData (the
        names are listed in schema_samples.evtx_by_event_id[].eventdata_
        fields_via_raw_payload), extract it from the nested $.raw.Payload
        with regexp_extract:
          regexp_extract(json_extract_string(payload_json,'$.raw.Payload'),
                         '"@Name":"TargetUserName","#text":"([^"]*)"', 1)
        Replace TargetUserName with the field you need. This is the only
        reliable way to reach IpAddress, SubjectUserName, CommandLine, etc.

    Other directly usable top-level EVTX keys: EventId, Channel, Computer,
    Provider, MapDescription (free-text description), ExecutableInfo.

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
func generateActiveSearchSQL(ctx context.Context, cfg Config, db *sql.DB, c *Cluster,
	audit *SynthAudit) ([]activeSearchSQLEntry, error) {
	if len(c.OpenQuestions) == 0 {
		return nil, nil
	}
	prompt, err := buildActiveSearchPrompt(ctx, db, cfg.CaseID, c)
	if err != nil {
		return nil, err
	}
	subCtx, cancel := context.WithTimeout(ctx, cfg.PerClusterTimeout)
	defer cancel()
	startedAt := time.Now()
	out, err := callClaudeCLI(subCtx, cfg, activeSearchSystemPrompt, prompt)
	dur := time.Since(startedAt)
	audit.LLMCallsTotal++
	audit.LLMDurationS += dur.Seconds()
	auditLLMCall(cfg, "active_search_generate", c.ID, dur, out, err)
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

func buildActiveSearchPrompt(ctx context.Context, db *sql.DB, caseID string, c *Cluster) (string, error) {
	type clusterCtx struct {
		ClusterID       int            `json:"cluster_id"`
		AttackPhase     string         `json:"attack_phase,omitempty"`
		WindowStart     string         `json:"window_start,omitempty"`
		WindowEnd       string         `json:"window_end,omitempty"`
		MITRETechniques []string       `json:"mitre_techniques,omitempty"`
		Narrative       string         `json:"narrative_so_far,omitempty"`
		OpenQuestions   []string       `json:"open_questions"`
		SchemaSamples   *schemaSamples `json:"schema_samples,omitempty"`
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
	// Best-effort: real key/field samples for the artifacts in this cluster so
	// the LLM writes JSON paths that exist instead of guessing. A failure here
	// must not abort the search — the system prompt still carries the EVTX
	// $.raw guidance.
	if ss, err := gatherClusterSchemaSamples(ctx, db, caseID, c); err == nil {
		pkt.SchemaSamples = ss
	}
	body, err := json.MarshalIndent(pkt, "", "  ")
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// schemaSamples inlines the REAL payload_json keys available per artifact (and
// per EVTX EventId) for the events present in this cluster, so the active-search
// LLM stops emitting $.TargetUserName-style paths that EvtxECmd never produced.
type schemaSamples struct {
	Note          string            `json:"note"`
	EVTXByEventID []evtxFieldSample `json:"evtx_by_event_id,omitempty"`
	ByArtifact    []artifactSample  `json:"by_artifact,omitempty"`
}

type evtxFieldSample struct {
	EventID        string `json:"event_id"`
	MapDescription string `json:"map_description,omitempty"`
	// PayloadData maps PayloadData1..6 to its real "Label: value" string for
	// this EventId — the curated, directly-queryable fields. Which slot holds
	// what varies by EventId, so the LLM must read these, not guess.
	PayloadData map[string]string `json:"payload_data,omitempty"`
	// EventDataFields are the raw Windows EventData @Name values available for
	// this EventId. Extract one with:
	//   regexp_extract(json_extract_string(payload_json,'$.raw.Payload'),
	//                  '"@Name":"<name>","#text":"([^"]*)"', 1)
	EventDataFields []string `json:"eventdata_fields_via_raw_payload,omitempty"`
}

type artifactSample struct {
	Artifact     string   `json:"artifact"`
	TopLevelKeys []string `json:"top_level_keys,omitempty"`
	Example      string   `json:"example,omitempty"`
}

// gatherClusterSchemaSamples samples one real row per (EVTX EventId) and per
// non-EVTX artifact present in the cluster, returning their actual key sets.
func gatherClusterSchemaSamples(ctx context.Context, db *sql.DB, caseID string, c *Cluster) (*schemaSamples, error) {
	const maxEvtxIDs, maxArtifacts = 6, 8

	evtxIDs := newOrderedStrSet()
	otherArts := newOrderedStrSet()
	for _, ev := range c.RawTimelineExcerpt {
		switch {
		case ev.ArtifactID == "evtx":
			if eid := toStr(ev.Excerpt["EventId"]); eid != "" {
				evtxIDs.add(eid)
			}
		case ev.ArtifactID != "":
			otherArts.add(ev.ArtifactID)
		}
	}
	// Fallback for undated/empty-excerpt clusters: sample case-wide artifacts.
	if evtxIDs.len() == 0 && otherArts.len() == 0 {
		if arts, err := listArtifacts(ctx, db, caseID); err == nil {
			for _, a := range arts {
				if a == "evtx" {
					continue
				}
				otherArts.add(a)
			}
		}
	}

	ss := &schemaSamples{
		Note: "REAL keys/values for events in this cluster. For EVTX prefer the " +
			"top-level PayloadData1..6 shown per EventId (json_extract_string(payload_json,'$.PayloadDataN')). " +
			"For any eventdata_fields_via_raw_payload name, extract with " +
			"regexp_extract(json_extract_string(payload_json,'$.raw.Payload'),'\"@Name\":\"<name>\",\"#text\":\"([^\"]*)\"',1). " +
			"There are no $.TargetUserName-style top-level keys.",
	}
	for _, eid := range evtxIDs.head(maxEvtxIDs) {
		var payload string
		err := db.QueryRowContext(ctx,
			`SELECT payload_json FROM unified_events
			   WHERE case_id = ? AND artifact_id = 'evtx'
			     AND json_extract_string(payload_json,'$.EventId') = ? LIMIT 1`,
			caseID, eid).Scan(&payload)
		if err != nil {
			continue
		}
		mapDesc, payloadData, eventDataFields := parseEvtxSample(payload)
		ss.EVTXByEventID = append(ss.EVTXByEventID, evtxFieldSample{
			EventID:         eid,
			MapDescription:  truncate(mapDesc, 120),
			PayloadData:     payloadData,
			EventDataFields: eventDataFields,
		})
	}
	for _, art := range otherArts.head(maxArtifacts) {
		var payload string
		err := db.QueryRowContext(ctx,
			`SELECT payload_json FROM unified_events
			   WHERE case_id = ? AND artifact_id = ? LIMIT 1`,
			caseID, art).Scan(&payload)
		if err != nil {
			continue
		}
		ss.ByArtifact = append(ss.ByArtifact, artifactSample{
			Artifact:     art,
			TopLevelKeys: jsonTopLevelKeys(payload),
			Example:      truncate(payload, 240),
		})
	}
	if len(ss.EVTXByEventID) == 0 && len(ss.ByArtifact) == 0 {
		return nil, fmt.Errorf("no schema samples")
	}
	return ss, nil
}

// evtxAtNameRe pulls the @Name values out of the EvtxECmd Payload EventData
// array (`{"@Name":"TargetUserName","#text":"alice"}`).
var evtxAtNameRe = regexp.MustCompile(`"@Name"\s*:\s*"([^"]+)"`)

// parseEvtxSample reads one EVTX payload_json and returns the MapDescription,
// the non-empty PayloadData1..6 "Label: value" strings (the curated, directly
// queryable fields), and the list of raw Windows EventData @Name field names
// that live under $.raw.Payload (queryable via regexp_extract). EvtxECmd does
// NOT expose those EventData fields as top-level keys, which is exactly why
// active-search SQL that wrote $.TargetUserName kept returning NULL.
func parseEvtxSample(payload string) (mapDesc string, payloadData map[string]string, eventDataFields []string) {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(payload), &m) != nil {
		return "", nil, nil
	}
	if v, ok := m["MapDescription"]; ok {
		_ = json.Unmarshal(v, &mapDesc)
	}
	pd := map[string]string{}
	for i := 1; i <= 6; i++ {
		var s string
		if v, ok := m[fmt.Sprintf("PayloadData%d", i)]; ok && json.Unmarshal(v, &s) == nil {
			if strings.TrimSpace(s) != "" {
				pd[fmt.Sprintf("PayloadData%d", i)] = truncate(s, 160)
			}
		}
	}
	if len(pd) > 0 {
		payloadData = pd
	}
	if payText := evtxRawPayloadText(m["raw"]); payText != "" {
		set := newOrderedStrSet()
		for _, mm := range evtxAtNameRe.FindAllStringSubmatch(payText, -1) {
			set.add(mm[1])
		}
		eventDataFields = set.head(set.len())
	}
	return mapDesc, payloadData, eventDataFields
}

// evtxRawPayloadText returns the inner EventData JSON text from the EVTX `raw`
// field, peeling whichever encoding ($.raw as object or JSON-string, then
// $.raw.Payload likewise) EvtxECmd stored it in. Empty string on any miss.
func evtxRawPayloadText(rawRaw json.RawMessage) string {
	if len(rawRaw) == 0 {
		return ""
	}
	rawObj := unmarshalLooseObject(rawRaw)
	if rawObj == nil {
		return ""
	}
	pv, ok := rawObj["Payload"]
	if !ok {
		return ""
	}
	var payStr string
	if json.Unmarshal(pv, &payStr) == nil {
		return payStr // Payload stored as a JSON string
	}
	return string(pv) // Payload stored as a nested object
}

// unmarshalLooseObject decodes a value that may be either a JSON object or a
// JSON-string wrapping one, into a key→raw map. Returns nil on neither.
func unmarshalLooseObject(raw json.RawMessage) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) == nil {
		return m
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && json.Unmarshal([]byte(s), &m) == nil {
		return m
	}
	return nil
}

// jsonTopLevelKeys returns the sorted top-level object keys of a JSON string.
// The input may itself be a JSON-encoded string (EVTX $.raw is) — unmarshal
// peels one quoting layer when needed.
func jsonTopLevelKeys(s string) []string {
	if s == "" {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		var inner string
		if json.Unmarshal([]byte(s), &inner) == nil {
			if json.Unmarshal([]byte(inner), &m) != nil {
				return nil
			}
		} else {
			return nil
		}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// orderedStrSet keeps first-seen order while de-duplicating.
type orderedStrSet struct {
	seen  map[string]bool
	items []string
}

func newOrderedStrSet() *orderedStrSet { return &orderedStrSet{seen: map[string]bool{}} }
func (o *orderedStrSet) add(s string) {
	if !o.seen[s] {
		o.seen[s] = true
		o.items = append(o.items, s)
	}
}
func (o *orderedStrSet) len() int { return len(o.items) }
func (o *orderedStrSet) head(n int) []string {
	if n > len(o.items) {
		n = len(o.items)
	}
	return o.items[:n]
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

// allProjectedColumnsNull reports whether the rows carry at least one projected
// (non-envelope) column AND every such value, across every retained row, is
// null or the empty string. That is the signature of an executed-but-useless
// query — typically a JSON path that does not exist. Returns false when the
// query projected only the envelope columns (nothing to judge) or when any
// projected value is non-empty.
func allProjectedColumnsNull(evidence []TimelineEvent) bool {
	sawProjectedColumn := false
	for _, ev := range evidence {
		for _, v := range ev.Excerpt {
			sawProjectedColumn = true
			if v != nil && toStr(v) != "" {
				return false
			}
		}
	}
	return sawProjectedColumn
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
note that honestly — do not invent answers. A result carrying an "error"
field (e.g. "all projected columns NULL") FAILED — do not treat its
absent/NULL values as evidence; at most note the question remains open.

Return ONLY the addendum text. No JSON, no markdown.`
	subCtx, cancel := context.WithTimeout(ctx, cfg.PerClusterTimeout)
	defer cancel()
	startedAt := time.Now()
	out, err := callClaudeCLI(subCtx, cfg, system, string(body))
	dur := time.Since(startedAt)
	audit.LLMCallsTotal++
	audit.LLMDurationS += dur.Seconds()
	auditLLMCall(cfg, "active_search_interpret", c.ID, dur, out, err)
	if err != nil {
		return "", err
	}
	audit.addUsage(out)
	return strings.TrimSpace(out.Result), nil
}

// ----------------------------------------------------------------------------
// Self-correction (runtime error detection → revise → re-execute)
// ----------------------------------------------------------------------------

// activeSearchCorrectionSystemPrompt drives a focused "fix the SQL you just
// broke" round. It restates the hard requirements and gives failure-specific
// guidance so the model repairs the actual error instead of re-guessing.
const activeSearchCorrectionSystemPrompt = `You are in TLVB Tier 2 ACTIVE-SEARCH SELF-CORRECTION mode.

A DuckDB SELECT you proposed FAILED. You are given the failed SQL, the exact
failure reason, the attempt number, and the real schema_samples for this
cluster. Produce ONE corrected SELECT that fixes that specific failure.

Return ONLY a single JSON object (no array, no markdown fences, no prose):
  {"question":"<unchanged open_question>","rationale":"<what you changed and why>","sql":"<corrected SELECT>"}

Re-apply EVERY hard requirement:
- starts with SELECT or WITH; no INSERT/UPDATE/DELETE/DROP/CREATE/ALTER/ATTACH/PRAGMA; no trailing semicolon
- the first WHERE predicate is literally: case_id = ?   (exactly ONE ? placeholder)
- output columns start with: audit_id, ts_utc, artifact_id, event_type
- end with LIMIT N (N <= 500)

Failure-specific guidance:
- "null_result" / "all projected columns NULL": your JSON paths matched nothing.
  For EVTX do NOT use $.TargetUserName-style top-level keys. Use
  json_extract_string(payload_json,'$.PayloadDataN') (see schema_samples
  payload_data) or, for an eventdata_fields_via_raw_payload name,
  regexp_extract(json_extract_string(payload_json,'$.raw.Payload'),
                 '"@Name":"<name>","#text":"([^"]*)"',1).
- "execute_error": a DuckDB syntax / function / type error — fix the offending expression.
- "validation_error": you violated one of the hard requirements above.

If no meaningful correction is possible, return {"sql":""} and we stop.`

// correctActiveSearchSQL asks the LLM to repair one failed query. ss may be nil
// (the system prompt still carries the EVTX guidance).
func correctActiveSearchSQL(ctx context.Context, cfg Config, question, failedSQL,
	failureReason string, attempt int, ss *schemaSamples, audit *SynthAudit) (string, error) {

	type correctionCtx struct {
		Question      string         `json:"question"`
		FailedSQL     string         `json:"failed_sql"`
		FailureReason string         `json:"failure_reason"`
		Attempt       int            `json:"attempt"`
		SchemaSamples *schemaSamples `json:"schema_samples,omitempty"`
	}
	body, err := json.MarshalIndent(correctionCtx{
		Question:      question,
		FailedSQL:     failedSQL,
		FailureReason: failureReason,
		Attempt:       attempt,
		SchemaSamples: ss,
	}, "", "  ")
	if err != nil {
		return "", err
	}
	subCtx, cancel := context.WithTimeout(ctx, cfg.PerClusterTimeout)
	defer cancel()
	startedAt := time.Now()
	out, err := callClaudeCLI(subCtx, cfg, activeSearchCorrectionSystemPrompt, string(body))
	dur := time.Since(startedAt)
	audit.LLMCallsTotal++
	audit.LLMDurationS += dur.Seconds()
	// Emit with the attempt number so the audit trail pairs each correction
	// round with the active_sql attempt it was trying to fix.
	corrAction := auditlog.Action{Actor: "tier2", Kind: "llm_call", Detail: "active_search_correct",
		Attempt: attempt, Model: cfg.Model, DurationSeconds: dur.Seconds()}
	if err != nil {
		corrAction.Success = auditlog.BoolPtr(false)
		corrAction.Error = truncate(err.Error(), 200)
	} else if out != nil {
		corrAction.Success = auditlog.BoolPtr(true)
		corrAction.InputTokens = out.Usage.InputTokens
		corrAction.OutputTokens = out.Usage.OutputTokens
		corrAction.CacheReadTokens = out.Usage.CacheReadInputTokens
		corrAction.CostUSD = out.TotalCostUSD
	}
	cfg.al.Append(corrAction)
	if err != nil {
		return "", err
	}
	audit.addUsage(out)
	entry, err := parseActiveSearchCorrection(out.Result)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(entry.SQL), nil
}

func parseActiveSearchCorrection(text string) (activeSearchSQLEntry, error) {
	var e activeSearchSQLEntry
	if err := decodeFirstJSON(text, &e); err != nil {
		return e, err
	}
	return e, nil
}

// sqlCorrector asks for a revised SQL given the previous SQL and why it failed.
// The production impl calls the LLM; tests inject a stub. Returning "" (or the
// same SQL, or an error) signals "give up — finalise as failed".
type sqlCorrector func(ctx context.Context, prevSQL, failureReason string, attempt int) (string, error)

// runActiveSQLWithSelfCorrection executes one open-question SQL with up to
// maxCorrect self-correction rounds. Attempt 1 is the LLM's original SQL; on a
// validation / execution / null-result failure it asks `correct` for a revision
// and re-executes, recording every attempt on the result. This is TLVB's
// runtime self-correction: the agent detects its own failed query and fixes it
// without human intervention. The audit counters distinguish first-try success
// from corrected success from unrecoverable failure.
func runActiveSQLWithSelfCorrection(ctx context.Context, db *sql.DB, caseID,
	question, initialSQL string, maxCorrect int, correct sqlCorrector,
	audit *SynthAudit, al *auditlog.Logger, clusterID int) ActiveSearchResult {

	res := ActiveSearchResult{Question: question, SQL: initialSQL}
	sqlText := strings.TrimSpace(initialSQL)

	for attempt := 1; ; attempt++ {
		at := SQLAttempt{N: attempt, SQL: sqlText}
		var okEvidence []TimelineEvent
		if verr := validateActiveSearchSQL(sqlText); verr != nil {
			at.Outcome, at.Error = "validation_error", verr.Error()
		} else if n, rows, eerr := execActiveSQL(ctx, db, caseID, sqlText, 50); eerr != nil {
			at.Outcome, at.Error = "execute_error", eerr.Error()
		} else if n > 0 && allProjectedColumnsNull(rows) {
			// Executed but every projected column is NULL — the classic wrong
			// JSON path. "Executes" yet answers nothing, so treat as a failure
			// the agent should try to correct.
			at.Outcome, at.Error, at.Hits = "null_result",
				"all projected columns NULL — likely wrong JSON path "+
					"(EVTX EventData fields live under $.raw; see schema_samples)", n
		} else {
			at.Outcome, at.Hits, okEvidence = "ok", n, rows
		}
		res.Attempts = append(res.Attempts, at)
		// Stream each attempt to the unified log the moment it happens, so the
		// audit chronology is true: the correction LLM call lands between a
		// failed attempt and its successful retry, not before both. (al is
		// nil-safe — a no-op in unit tests.)
		hits := at.Hits
		al.Append(auditlog.Action{
			Actor: "tier2", Kind: "active_sql", ClusterID: clusterID,
			Attempt: at.N, Outcome: at.Outcome, Command: at.SQL,
			RowCount: &hits, Error: at.Error,
			Success: auditlog.BoolPtr(at.Outcome == "ok"),
		})

		if at.Outcome == "ok" {
			res.SQL, res.Hits, res.Evidence, res.Error = sqlText, at.Hits, okEvidence, ""
			if attempt > 1 {
				res.Corrected = true
				audit.ActiveSQLSelfCorrected++
			}
			audit.ActiveSQLSucceeded++
			return res
		}

		// Failed this attempt. Stop if we have no correction budget left.
		if attempt > maxCorrect {
			res.SQL, res.Hits = sqlText, at.Hits
			res.Error = at.Outcome + ": " + at.Error
			if at.Outcome == "null_result" {
				audit.ActiveSQLNullResult++
			}
			return res
		}
		audit.ActiveSQLCorrectionRounds++
		corrected, cerr := correct(ctx, sqlText, at.Outcome+": "+at.Error, attempt)
		corrected = strings.TrimSpace(corrected)
		if cerr != nil || corrected == "" || corrected == sqlText {
			res.SQL, res.Hits = sqlText, at.Hits
			res.Error = at.Outcome + ": " + at.Error + " (self-correction produced no new query)"
			if at.Outcome == "null_result" {
				audit.ActiveSQLNullResult++
			}
			return res
		}
		sqlText = corrected
	}
}

// demoInjectSQLFault deliberately corrupts a query so the self-correction loop
// has something to recover from. Used ONLY when Config.DemoInjectSQLFault is set
// (a labelled fault-injection switch for demos — never default). It splices in a
// predicate referencing a non-existent column right after the case_id binding;
// DuckDB rejects that at execution (execute_error, "column not found" — a very
// common real LLM SQL mistake), and the correction round removes it and recovers.
// Returns the SQL unchanged when the canonical "case_id = ?" anchor is absent so
// the demo degrades gracefully instead of producing un-fixable SQL.
func demoInjectSQLFault(sqlText string) string {
	const anchor = "case_id = ?"
	idx := strings.Index(sqlText, anchor)
	if idx < 0 {
		return sqlText
	}
	pos := idx + len(anchor)
	return sqlText[:pos] + " AND __demo_injected_fault__ = 1" + sqlText[pos:]
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
	maxCorrect := cfg.MaxSelfCorrect
	switch {
	case maxCorrect == 0:
		maxCorrect = 2 // default: up to 2 self-correction rounds per query
	case maxCorrect < 0:
		maxCorrect = 0 // explicitly disabled
	}
	for i := range clusters {
		c := &clusters[i]
		if len(c.OpenQuestions) == 0 {
			continue
		}
		entries, err := generateActiveSearchSQL(ctx, cfg, db, c, audit)
		if err != nil {
			// graceful: skip this cluster, keep going
			continue
		}
		// Real key/value samples for this cluster, gathered once and reused by
		// every self-correction round (best-effort; nil is fine — the correction
		// system prompt still carries the EVTX guidance).
		ss, _ := gatherClusterSchemaSamples(ctx, db, cfg.CaseID, c)
		var results []ActiveSearchResult
		for ei, e := range entries {
			audit.ActiveSQLAttempted++
			question := e.Question
			initialSQL := e.SQL
			if cfg.DemoInjectSQLFault && ei == 0 {
				// Demo: break the first query of each cluster so the loop recovers.
				initialSQL = demoInjectSQLFault(e.SQL)
			}
			correct := func(cctx context.Context, prevSQL, failureReason string, attempt int) (string, error) {
				return correctActiveSearchSQL(cctx, cfg, question, prevSQL, failureReason, attempt, ss, audit)
			}
			res := runActiveSQLWithSelfCorrection(ctx, db, cfg.CaseID, question, initialSQL,
				maxCorrect, correct, audit, cfg.al, c.ID)
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
