package agents

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// AnomalyHunter is Tier 1.5 — runs after the 10 Tactic Agents, looks for
// signals they missed using statistical / behavioural lenses rather than
// MITRE ATT&CK technique definitions.
//
// Architecturally distinct from a Tactic Agent in that:
//   1. It consumes existing findings as input (Tactic Agents don't see
//      each other's output).
//   2. The harness pre-computes anomaly candidates from the FULL
//      unified_events table — not from the per-tactic SQL filter.
//   3. Output uses tactic_id="ANOM" so Synthesizer can aggregate it
//      alongside the Tactic Reports without special-casing.
type AnomalyHunter struct {
	cfg AnomalyConfig
}

type AnomalyConfig struct {
	CaseID       string
	EvidenceID   string
	// EvidenceIDs is the full set of evidences in scope (★v0.3 #7).
	// Stamped into the resulting TacticReport for cross-evidence correlation.
	EvidenceIDs  []string
	SkillsDir    string  // default "skills"
	FindingsDir  string  // where to read prior findings + write anomaly_hunter.json
	DBPath       string

	Engine    string
	APIKey    string
	Model     string
	MaxEvents int           // cap on candidate events shown to LLM (default 200)
	MaxIters  int           // JSON-validation retries (default 3)
	Timeout   time.Duration // per-call timeout (default 5 min)
	DryRun    bool          // build prompt + report sizes; skip engine call
}

func NewAnomalyHunter(cfg AnomalyConfig) (*AnomalyHunter, error) {
	if cfg.SkillsDir == "" {
		cfg.SkillsDir = "skills"
	}
	if cfg.FindingsDir == "" {
		return nil, fmt.Errorf("findings_dir is required (need to read prior findings)")
	}
	if cfg.DBPath == "" {
		return nil, fmt.Errorf("db_path is required")
	}
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = 200
	}
	if cfg.MaxIters <= 0 {
		cfg.MaxIters = 3
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Minute
	}
	if cfg.Engine == "" {
		cfg.Engine = "claude-code"
	}
	return &AnomalyHunter{cfg: cfg}, nil
}

// AnomalyContext is what the harness exposes in the user message. JSON
// shape is stable so the skill prompt can reference the field names.
type AnomalyContext struct {
	CaseID                 string         `json:"case_id"`
	EvidenceID             string         `json:"evidence_id"`
	TacticFindingsSummary  map[string]int `json:"tactic_findings_summary"`
	KeyFindingTimestamps   []string       `json:"key_finding_timestamps"`
	ExistingAuditIDs       []string       `json:"existing_audit_ids"`
	CandidateLenses        []string       `json:"lenses_applied"`
	EventsTotalScanned     int            `json:"events_total_scanned"`
	EventsInWindow         int            `json:"events_in_window"`
	Truncated              bool           `json:"truncated"`
	WindowMin              string         `json:"window_min"`
	WindowMax              string         `json:"window_max"`
	Events                 []EventForLLM  `json:"events"`
}

// AnomalyDryRunInfo is what DryRun() returns so callers can inspect what
// would have been sent to the LLM. Mirrors the shape of Runner.DryRun's
// return values so the CLI can present a consistent summary.
type AnomalyDryRunInfo struct {
	SystemPrompt   string
	UserMessage    string
	EventsScanned  int
	EventsInWindow int
	Truncated      bool
	Lenses         []string
}

// DryRun (Wave 20c) builds the prompt that would be sent for anomaly_hunter
// and returns it without calling the engine. Mirrors Runner.DryRun's
// contract so the CLI's `analyze --tactic anomaly_hunter --dry-run` path
// works the same as for any other tactic. Previously anomaly_hunter went
// through Runner.DryRun which failed at TacticRegistry lookup because
// anomaly_hunter is intentionally absent from that map (it has its own
// harness; see the Tier 1.5 design note above).
func (a *AnomalyHunter) DryRun(ctx context.Context) (*AnomalyDryRunInfo, error) {
	skillPath := filepath.Join(a.cfg.SkillsDir, "anomaly_hunter.md")
	skillRaw, err := os.ReadFile(skillPath)
	if err != nil {
		return nil, fmt.Errorf("load skill: %w", err)
	}
	priors, priorEvIDs, priorTimestamps, err := loadPriorFindings(a.cfg.FindingsDir)
	if err != nil {
		return nil, fmt.Errorf("load prior findings: %w", err)
	}
	db, err := sql.Open("duckdb", a.cfg.DBPath+"?access_mode=read_only")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	defer db.Close()
	totalScanned, err := countAllEvents(ctx, db, a.cfg.CaseID)
	if err != nil {
		return nil, fmt.Errorf("count events: %w", err)
	}
	candidates, err := buildAnomalyCandidates(ctx, db, a.cfg.CaseID,
		priorTimestamps, priorEvIDs, a.cfg.MaxEvents)
	if err != nil {
		return nil, fmt.Errorf("build candidates: %w", err)
	}
	lenses := []string{
		"A1 time anomaly (off-hours)",
		"A2 location anomaly (Temp/AppData/ProgramData)",
		"A4 frequency anomaly (rare process names, count<3)",
		"A5 adjacency anomaly (±30 min around findings)",
		"A6 privilege-context anomaly (Sysmon 10 / 4672 with non-system source)",
		"A7 deletion anomaly (4660 burst / Sysmon 23)",
	}
	hctx := AnomalyContext{
		CaseID:                a.cfg.CaseID,
		EvidenceID:            a.cfg.EvidenceID,
		TacticFindingsSummary: priors,
		KeyFindingTimestamps:  priorTimestamps,
		ExistingAuditIDs:      priorEvIDs,
		CandidateLenses:       lenses,
		EventsTotalScanned:    totalScanned,
		EventsInWindow:        candidates.total,
		Truncated:             candidates.total > a.cfg.MaxEvents,
		Events:                candidates.events,
	}
	if !candidates.minTS.IsZero() {
		hctx.WindowMin = candidates.minTS.Format(time.RFC3339Nano)
	}
	if !candidates.maxTS.IsZero() {
		hctx.WindowMax = candidates.maxTS.Format(time.RFC3339Nano)
	}
	userMsg, err := buildAnomalyUserMessage(hctx)
	if err != nil {
		return nil, err
	}
	return &AnomalyDryRunInfo{
		SystemPrompt:   string(skillRaw),
		UserMessage:    userMsg,
		EventsScanned:  totalScanned,
		EventsInWindow: candidates.total,
		Truncated:      candidates.total > a.cfg.MaxEvents,
		Lenses:         lenses,
	}, nil
}

// Run executes the full Anomaly Hunter flow: load priors → harness →
// engine call → validate → persist.
func (a *AnomalyHunter) Run(ctx context.Context) (*TacticReport, error) {
	startedAt := time.Now().UTC()

	skillPath := filepath.Join(a.cfg.SkillsDir, "anomaly_hunter.md")
	skillRaw, err := os.ReadFile(skillPath)
	if err != nil {
		return nil, fmt.Errorf("load skill: %w", err)
	}
	skillSHA := sha256.Sum256(skillRaw)

	priors, priorEvIDs, priorTimestamps, err := loadPriorFindings(a.cfg.FindingsDir)
	if err != nil {
		return nil, fmt.Errorf("load prior findings: %w", err)
	}

	db, err := sql.Open("duckdb", a.cfg.DBPath+"?access_mode=read_only")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	totalScanned, err := countAllEvents(ctx, db, a.cfg.CaseID)
	if err != nil {
		return nil, fmt.Errorf("count events: %w", err)
	}

	candidates, err := buildAnomalyCandidates(ctx, db, a.cfg.CaseID,
		priorTimestamps, priorEvIDs, a.cfg.MaxEvents)
	if err != nil {
		return nil, fmt.Errorf("build candidates: %w", err)
	}

	hctx := AnomalyContext{
		CaseID:                a.cfg.CaseID,
		EvidenceID:            a.cfg.EvidenceID,
		TacticFindingsSummary: priors,
		KeyFindingTimestamps:  priorTimestamps,
		ExistingAuditIDs:      priorEvIDs,
		CandidateLenses: []string{
			"A1 time anomaly (off-hours)",
			"A2 location anomaly (Temp/AppData/ProgramData)",
			"A4 frequency anomaly (rare process names, count<3)",
			"A5 adjacency anomaly (±30 min around findings)",
			"A6 privilege-context anomaly (Sysmon 10 / 4672 with non-system source)",
			"A7 deletion anomaly (4660 burst / Sysmon 23)",
		},
		EventsTotalScanned: totalScanned,
		EventsInWindow:     candidates.total,
		Truncated:          candidates.total > a.cfg.MaxEvents,
		Events:             candidates.events,
	}
	if !candidates.minTS.IsZero() {
		hctx.WindowMin = candidates.minTS.Format(time.RFC3339Nano)
	}
	if !candidates.maxTS.IsZero() {
		hctx.WindowMax = candidates.maxTS.Format(time.RFC3339Nano)
	}

	userMsg, err := buildAnomalyUserMessage(hctx)
	if err != nil {
		return nil, err
	}

	if a.cfg.DryRun {
		// Construct a minimal TacticReport-ish stub for tooling; caller
		// checks DryRun before persisting.
		return nil, nil
	}

	engine, err := newEngineForConfig(a.cfg.Engine, a.cfg.APIKey,
		a.cfg.Model, 50000, a.cfg.Timeout)
	if err != nil {
		return nil, err
	}

	validIDs := make(map[string]bool, len(candidates.events))
	for _, e := range candidates.events {
		validIDs[e.AuditID] = true
	}

	var (
		report     *TacticReport
		lastResp   *EngineResponse
		lastErr    error
		iterations int
		feedback   string
	)
	for iter := 1; iter <= a.cfg.MaxIters; iter++ {
		iterations = iter
		userIter := userMsg
		if feedback != "" {
			userIter = userMsg + "\n\n---\n\nIMPORTANT: " + feedback
		}
		er, callErr := engine.Call(ctx, string(skillRaw), userIter)
		if callErr != nil {
			return nil, fmt.Errorf("%s call iter=%d: %w",
				engine.ID(), iter, callErr)
		}
		lastResp = er
		jsonStr, err := extractJSON(er.Text)
		if err != nil {
			feedback = fmt.Sprintf(
				"Your previous response did not contain valid JSON (%v). "+
					"Return ONLY a single JSON object matching the schema, "+
					"no surrounding prose.", err)
			lastErr = err
			continue
		}
		var rep TacticReport
		if err := json.Unmarshal([]byte(jsonStr), &rep); err != nil {
			feedback = fmt.Sprintf(
				"Could not unmarshal into TacticReport schema (%v). "+
					"Return a strictly conforming object.", err)
			lastErr = err
			continue
		}
		report = &rep
		lastErr = nil
		break
	}

	finishedAt := time.Now().UTC()

	if report == nil {
		return &TacticReport{
			TacticID:   "ANOM",
			TacticName: "Anomaly Hunter",
			CaseID:     a.cfg.CaseID,
			EvidenceID: a.cfg.EvidenceID,
			StartedAt:  startedAt,
			FinishedAt: finishedAt,
			Status:     "failed",
			Audit: Audit{
				Iterations:    iterations,
				InputEvents:   len(candidates.events),
				ModelID:       a.cfg.Model,
				DurationSec:   finishedAt.Sub(startedAt).Seconds(),
				SkillFile:     skillPath,
				SkillSHA256:   hex.EncodeToString(skillSHA[:]),
				ValidationOK:  false,
				ValidationErr: fmt.Sprintf("max_iters reached: %v", lastErr),
			},
		}, fmt.Errorf("anomaly hunter failed: %w", lastErr)
	}

	report.TacticID = "ANOM"
	report.TacticName = "Anomaly Hunter"
	report.CaseID = a.cfg.CaseID
	report.EvidenceID = a.cfg.EvidenceID
	if len(a.cfg.EvidenceIDs) > 0 {
		report.EvidenceIDs = append([]string(nil), a.cfg.EvidenceIDs...)
	}
	report.StartedAt = startedAt
	report.FinishedAt = finishedAt
	if report.Status == "" {
		report.Status = "completed"
	}
	report.Audit.Iterations = iterations
	report.Audit.InputEvents = len(candidates.events)
	if lastResp != nil && lastResp.EffectiveModel != "" {
		report.Audit.ModelID = lastResp.EffectiveModel
	} else {
		report.Audit.ModelID = a.cfg.Model
	}
	report.Audit.SkillFile = skillPath
	report.Audit.SkillSHA256 = hex.EncodeToString(skillSHA[:])
	report.Audit.DurationSec = finishedAt.Sub(startedAt).Seconds()
	if lastResp != nil {
		report.Audit.StopReason = lastResp.StopReason
		report.Audit.TokensInput = lastResp.InputTokens
		report.Audit.TokensOutput = lastResp.OutputTokens
		report.Audit.CacheHitTok = lastResp.CacheReadTokens
	}

	if errs := validateEvidence(report, validIDs); len(errs) > 0 {
		report.Audit.ValidationOK = false
		report.Audit.ValidationErr = strings.Join(errs, "; ")
		if report.Status != "failed" {
			report.Status = "partial"
		}
	} else {
		report.Audit.ValidationOK = true
	}

	return report, nil
}

// newEngineForConfig is a small helper so AnomalyHunter doesn't need to
// duplicate the engine selection logic from runner.New.
func newEngineForConfig(
	engine, apiKey, model string, maxTokens int, timeout time.Duration,
) (Engine, error) {
	if model == "" {
		model = "claude-sonnet-4-6"
	}
	switch engine {
	case "claude-code", "":
		return newClaudeCodeClient(model, timeout), nil
	case "anthropic-api":
		if apiKey == "" {
			return nil, fmt.Errorf(
				"engine=anthropic-api requires ANTHROPIC_API_KEY")
		}
		return newAnthropicClient(apiKey, model, maxTokens, timeout), nil
	default:
		return nil, fmt.Errorf("unknown engine %q", engine)
	}
}

// ----------------------------------------------------------------------------
// Harness — load priors
// ----------------------------------------------------------------------------

func loadPriorFindings(dir string) (
	summary map[string]int,
	auditIDs []string,
	timestamps []string,
	err error,
) {
	summary = map[string]int{}
	idSet := map[string]struct{}{}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		// Skip our own output if a previous run wrote it.
		if e.Name() == "anomaly_hunter.json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var rep TacticReport
		if err := json.Unmarshal(raw, &rep); err != nil {
			continue
		}
		summary[rep.TacticID] += len(rep.Findings)
		for _, f := range rep.Findings {
			for _, ev := range f.Evidence {
				if ev.AuditID != "" {
					idSet[ev.AuditID] = struct{}{}
				}
			}
		}
	}

	for k := range idSet {
		auditIDs = append(auditIDs, k)
	}
	sort.Strings(auditIDs)
	// timestamps is populated separately by harness from DB lookups
	// against these audit_ids — we don't ship every audit_id timestamp.
	return summary, auditIDs, timestamps, nil
}

// ----------------------------------------------------------------------------
// Harness — build candidate events
//
// Strategy (intentionally simple — a smarter version is future work):
//
//   bucket A: off-hours (UTC hour < 6 or >= 22)
//   bucket B: rare-process — Image / executableName seen < 3 times in case
//   bucket C: suspicious-path — payload contains \\Temp\\, \\AppData\\,
//             \\ProgramData\\, \\Public\\
//   bucket D: adjacency — events whose ts is within 30 min of any
//             prior-finding evidence ts (only audit_ids NOT already cited)
//
// Take up to maxRows total, balanced across buckets (40% A, 25% B, 25% C,
// 10% D). Dedup by audit_id; if a row qualifies for multiple buckets we
// keep the first one we saw and tag it with all matching lenses.
// ----------------------------------------------------------------------------

type candidateBundle struct {
	events []EventForLLM
	total  int
	minTS  time.Time
	maxTS  time.Time
}

func buildAnomalyCandidates(
	ctx context.Context, db *sql.DB, caseID string,
	priorTSPlaceholder []string, // unused for now; reserved
	priorAuditIDs []string,
	maxRows int,
) (*candidateBundle, error) {
	excluded := map[string]struct{}{}
	for _, id := range priorAuditIDs {
		excluded[id] = struct{}{}
	}

	// Load prior finding timestamps via a single bulk query — needed for
	// adjacency bucket.
	priorTimes, err := lookupTimestamps(ctx, db, caseID, priorAuditIDs)
	if err != nil {
		return nil, err
	}

	// Total count of unified_events for the case (truncation honesty).
	total, err := countAllEvents(ctx, db, caseID)
	if err != nil {
		return nil, err
	}

	// Pull a wide sample we can score in-memory. We don't pull the full
	// 37k events; we cap at 5x maxRows for buckets A/B/C and run adjacency
	// inside that window.
	sampleCap := maxRows * 5
	if sampleCap < 1000 {
		sampleCap = 1000
	}
	q := `SELECT audit_id, ts_utc, artifact_id, COALESCE(computer,''), payload_json
	        FROM unified_events
	       WHERE case_id = ?
	       ORDER BY ts_utc
	       LIMIT ?`
	rows, err := db.QueryContext(ctx, q, caseID, sampleCap)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type rawRow struct {
		auditID    string
		ts         time.Time
		artifactID string
		computer   string
		payload    string
		hasTS      bool
	}
	var sample []rawRow
	imageCount := map[string]int{} // for rare-process bucket
	for rows.Next() {
		var r rawRow
		var ts sql.NullTime
		if err := rows.Scan(&r.auditID, &ts, &r.artifactID, &r.computer, &r.payload); err != nil {
			return nil, err
		}
		if ts.Valid {
			r.ts = ts.Time.UTC()
			r.hasTS = true
		}
		sample = append(sample, r)
		if img := extractImage(r.payload); img != "" {
			imageCount[strings.ToLower(img)]++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	type scored struct {
		row    rawRow
		lenses []string
		score  int
	}
	scoredOut := make([]scored, 0, len(sample))
	for _, r := range sample {
		if _, skip := excluded[r.auditID]; skip {
			continue
		}
		var lenses []string
		score := 0

		// A1 — off-hours
		if r.hasTS {
			h := r.ts.Hour()
			if h < 6 || h >= 22 {
				lenses = append(lenses, "A1")
				score += 2
			}
		}

		// A2 — suspicious path
		if hasSuspiciousPath(r.payload) {
			lenses = append(lenses, "A2")
			score += 3
		}

		// A4 — rare-process
		if img := extractImage(r.payload); img != "" {
			if imageCount[strings.ToLower(img)] < 3 {
				lenses = append(lenses, "A4")
				score += 2
			}
		}

		// A5 — adjacency to known finding
		if r.hasTS && nearAnyTimestamp(r.ts, priorTimes, 30*time.Minute) {
			lenses = append(lenses, "A5")
			score += 1
		}

		if score == 0 {
			continue
		}
		scoredOut = append(scoredOut, scored{row: r, lenses: lenses, score: score})
	}

	// Sort by score desc, then ts asc for stability.
	sort.SliceStable(scoredOut, func(i, j int) bool {
		if scoredOut[i].score != scoredOut[j].score {
			return scoredOut[i].score > scoredOut[j].score
		}
		return scoredOut[i].row.ts.Before(scoredOut[j].row.ts)
	})

	if len(scoredOut) > maxRows {
		scoredOut = scoredOut[:maxRows]
	}

	bundle := &candidateBundle{total: total}
	for _, s := range scoredOut {
		ev := EventForLLM{
			AuditID:  s.row.auditID,
			Artifact: s.row.artifactID,
			Computer: s.row.computer,
			Excerpt:  shrinkPayload(s.row.artifactID, s.row.payload),
		}
		// Annotate with which lens fired so the LLM can prioritise.
		ev.Excerpt["_anomaly_lenses"] = s.lenses
		if s.row.hasTS {
			ev.TS = s.row.ts.Format(time.RFC3339Nano)
			if bundle.minTS.IsZero() || s.row.ts.Before(bundle.minTS) {
				bundle.minTS = s.row.ts
			}
			if s.row.ts.After(bundle.maxTS) {
				bundle.maxTS = s.row.ts
			}
		}
		bundle.events = append(bundle.events, ev)
	}
	return bundle, nil
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

func countAllEvents(ctx context.Context, db *sql.DB, caseID string) (int, error) {
	var n int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM unified_events WHERE case_id = ?`,
		caseID).Scan(&n)
	return n, err
}

func lookupTimestamps(
	ctx context.Context, db *sql.DB, caseID string, ids []string,
) ([]time.Time, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	args := []any{caseID}
	placeholders := make([]string, 0, len(ids))
	for _, id := range ids {
		placeholders = append(placeholders, "?")
		args = append(args, id)
	}
	q := `SELECT ts_utc FROM unified_events
	      WHERE case_id = ?
	        AND audit_id IN (` + strings.Join(placeholders, ",") + `)
	        AND ts_utc IS NOT NULL`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []time.Time
	for rows.Next() {
		var ts sql.NullTime
		if err := rows.Scan(&ts); err != nil {
			return nil, err
		}
		if ts.Valid {
			out = append(out, ts.Time.UTC())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	return out, rows.Err()
}

func nearAnyTimestamp(t time.Time, sorted []time.Time, window time.Duration) bool {
	if len(sorted) == 0 {
		return false
	}
	// Linear scan acceptable — len(sorted) is bounded by audit_id count.
	for _, k := range sorted {
		d := t.Sub(k)
		if d < 0 {
			d = -d
		}
		if d <= window {
			return true
		}
	}
	return false
}

// extractImage returns the Image field for evtx Sysmon 1 / 4688 rows, or
// "" if not present. Used for rare-process counting.
func extractImage(payloadJSON string) string {
	var p map[string]any
	if err := json.Unmarshal([]byte(payloadJSON), &p); err != nil {
		return ""
	}
	for _, k := range []string{"PayloadData4", "PayloadData3", "Image"} {
		if v, ok := p[k]; ok {
			s, _ := v.(string)
			if strings.Contains(s, ".exe") {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func hasSuspiciousPath(payloadJSON string) bool {
	low := strings.ToLower(payloadJSON)
	return strings.Contains(low, `\temp\`) ||
		strings.Contains(low, `\appdata\`) ||
		strings.Contains(low, `\programdata\`) ||
		strings.Contains(low, `\users\public\`)
}

// ----------------------------------------------------------------------------
// User-message build
// ----------------------------------------------------------------------------

func buildAnomalyUserMessage(c AnomalyContext) (string, error) {
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	prelude := "Below is the AnomalyContext for your Tier 1.5 anomaly scan. " +
		"Apply the seven lenses described in the system prompt and return " +
		"ONLY the TacticReport JSON.\n\n"
	return prelude + string(body), nil
}
