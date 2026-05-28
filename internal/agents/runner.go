package agents

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/marcboeker/go-duckdb"
)

// Config controls one Tactic Agent run.
type Config struct {
	Tactic     string        // "persistence" — selects skill file + query
	SkillsDir  string        // default "skills"
	Engine     string        // "claude-code" (default) | "anthropic-api"
	APIKey     string        // ANTHROPIC_API_KEY (required when Engine="anthropic-api")
	Model      string        // default depends on engine
	MaxEvents  int           // default 200 — pre-LLM filter cap
	MaxIters   int           // default 3 — JSON-validation retries
	MaxTokens  int           // default 50000 — Anthropic max_tokens (api only)
	Timeout    time.Duration // default 5 min — wall-clock cap
	DBPath     string        // case DuckDB path
	DryRun     bool          // build prompt + report sizes; skip engine call
	// CorrectionContext is appended to the user message when set. Used by
	// the Corrector to re-run an Agent with the inconsistency it must
	// resolve. Empty for first-pass runs.
	CorrectionContext string

	// EvidenceIDs is the full set of evidences in scope for this run
	// (★v0.3 #7). Stamped into the resulting TacticReport so downstream
	// Tier 2 cross-evidence correlation can reason about coverage. May
	// be nil — Run still works in single-evidence mode using the
	// evidenceID arg only.
	EvidenceIDs []string

	// ArtifactScope (Wave 20h) narrows the SQL prefilter to events from
	// a single artifact_id. The tactic's normal OR-clauses still apply,
	// but the whole filter is AND'd with `artifact_id = ?`. Used by the
	// "Analyze this artifact" UI button to focus an LLM run on one
	// parser's output (e.g. amcache only) without triggering a full
	// cross-artifact analysis. Empty string disables the scope.
	ArtifactScope string

	// SlidingWindow (Wave 22, DESIGN v0.3 #3) enables time-ordered window
	// chunking for Tactic Agent runs when the total matching event count
	// exceeds MaxEvents. When false (default), the runner behaves as before:
	// one LLM call with the first MaxEvents rows and an honest "truncated"
	// flag in the prompt. When true, the runner walks the full match set
	// in ceil((total - WindowSize) / stride) + 1 windows, each call runs
	// the same tactic skill, and findings are merged at the end.
	SlidingWindow bool

	// WindowOverlap (0.0 - 0.5) controls how much adjacent windows share
	// events. Default 0.2 (= 20% of WindowSize). Higher overlap reduces
	// the chance of missing attack chains that straddle window borders
	// at the cost of duplicate LLM cost. Only consulted when
	// SlidingWindow=true.
	WindowOverlap float64
}

// Runner executes one Tactic Agent run end-to-end.
type Runner struct {
	cfg    Config
	engine Engine
}

func defaults(c *Config) {
	if c.SkillsDir == "" {
		c.SkillsDir = "skills"
	}
	if c.Engine == "" {
		c.Engine = "claude-code"
	}
	if c.Model == "" {
		c.Model = "claude-sonnet-4-6"
	}
	if c.MaxEvents == 0 {
		c.MaxEvents = 200
	}
	if c.MaxIters == 0 {
		c.MaxIters = 3
	}
	if c.MaxTokens == 0 {
		c.MaxTokens = 50000
	}
	if c.Timeout == 0 {
		c.Timeout = 5 * time.Minute
	}
}

// New validates config and returns a Runner.
func New(cfg Config) (*Runner, error) {
	defaults(&cfg)
	if cfg.DBPath == "" {
		return nil, fmt.Errorf("DBPath is required")
	}

	r := &Runner{cfg: cfg}
	if cfg.DryRun {
		return r, nil
	}

	switch cfg.Engine {
	case "anthropic-api":
		if cfg.APIKey == "" {
			return nil, fmt.Errorf(
				"engine=anthropic-api requires ANTHROPIC_API_KEY " +
					"(or use --engine claude-code)")
		}
		r.engine = newAnthropicClient(cfg.APIKey, cfg.Model, cfg.MaxTokens, cfg.Timeout)
	case "claude-code":
		r.engine = newClaudeCodeClient(cfg.Model, cfg.Timeout)
	default:
		return nil, fmt.Errorf(
			"unknown engine %q (supported: claude-code, anthropic-api)",
			cfg.Engine)
	}
	return r, nil
}

// DryRun builds the prompt that would be sent and returns it, without
// calling the API. Useful for inspecting context size before paying.
func (r *Runner) DryRun(ctx context.Context, caseID, evidenceID string) (
	systemPrompt, userMsg string, window EventWindow, totalMatching int, err error,
) {
	spec, ok := TacticRegistry[r.cfg.Tactic]
	if !ok {
		return "", "", EventWindow{}, 0,
			fmt.Errorf("unknown tactic %q (registered: %v)",
				r.cfg.Tactic, KnownTactics())
	}
	skillPath := r.cfg.SkillsDir + "/" + spec.Slug + ".md"
	skillRaw, err := os.ReadFile(skillPath)
	if err != nil {
		return "", "", EventWindow{}, 0, fmt.Errorf("load skill %q: %w", skillPath, err)
	}
	db, err := sql.Open("duckdb", r.cfg.DBPath+"?access_mode=read_only")
	if err != nil {
		return "", "", EventWindow{}, 0, fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	w, total, err := queryEventsForTactic(ctx, db, caseID, spec, r.cfg.MaxEvents, r.cfg.ArtifactScope)
	if err != nil {
		return "", "", EventWindow{}, 0, err
	}
	user, err := buildUserMessage(caseID, evidenceID, spec, w, total, r.cfg.MaxEvents)
	if err != nil {
		return "", "", EventWindow{}, 0, err
	}
	return string(skillRaw), user, w, total, nil
}

// Run executes the agent against caseID and returns a TacticReport.
// Wave 22: when SlidingWindow=true and the total match count exceeds
// MaxEvents, the runner walks the full set in ceil((total - WindowSize) /
// stride) + 1 windows (stride = WindowSize × (1 - overlap)) and merges
// the per-window reports. Default WindowOverlap is 0.2.
//
// Steps (per window):
//   1. Load skill file from skills/<tactic>.md
//   2. Query case DB for events relevant to this tactic (capped at MaxEvents)
//   3. Build user-message with EventWindow JSON
//   4. Call engine; loop up to MaxIters on JSON parse failure
//   5. Validate audit_ids reference real rows
//   6. (orchestrator merges N window reports if sliding)
func (r *Runner) Run(ctx context.Context, caseID, evidenceID string) (*TacticReport, error) {
	if !r.cfg.SlidingWindow {
		return r.runWindowAt(ctx, caseID, evidenceID, 0, 1)
	}
	// Wave 22 sliding-window: count total to decide whether to slide.
	spec, ok := TacticRegistry[r.cfg.Tactic]
	if !ok {
		return nil, fmt.Errorf("unknown tactic %q (registered: %v)",
			r.cfg.Tactic, KnownTactics())
	}
	db, err := sql.Open("duckdb", r.cfg.DBPath+"?access_mode=read_only")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	where := strings.Join(spec.OrClauses, " OR ")
	total, err := countTacticEvents(ctx, db, caseID, where, r.cfg.ArtifactScope)
	_ = db.Close()
	if err != nil {
		return nil, fmt.Errorf("count events: %w", err)
	}
	if total <= r.cfg.MaxEvents {
		// Nothing to slide — fall back to 1-shot.
		return r.runWindowAt(ctx, caseID, evidenceID, 0, 1)
	}
	overlap := r.cfg.WindowOverlap
	if overlap <= 0 || overlap > 0.5 {
		overlap = 0.2
	}
	stride := int(float64(r.cfg.MaxEvents) * (1.0 - overlap))
	if stride < 1 {
		stride = 1
	}
	// windowCount = ceil((total - MaxEvents) / stride) + 1
	windowCount := 1 + (total-r.cfg.MaxEvents+stride-1)/stride
	var reports []*TacticReport
	for offset := 0; offset < total; offset += stride {
		rep, err := r.runWindowAt(ctx, caseID, evidenceID, offset, windowCount)
		if err != nil {
			return nil, fmt.Errorf("window offset=%d: %w", offset, err)
		}
		reports = append(reports, rep)
	}
	merged := mergeTacticReports(reports)
	merged.Audit.WindowsTotal = len(reports)
	merged.Audit.WindowSize = r.cfg.MaxEvents
	merged.Audit.WindowOverlap = overlap
	return merged, nil
}

// runWindowAt is the per-window worker. totalWindowsHint is passed for
// observability (= 1 in single-shot mode, > 1 in sliding mode); it does
// not change query behaviour. offset is the row offset into the
// time-ordered match set.
func (r *Runner) runWindowAt(
	ctx context.Context, caseID, evidenceID string, offset, totalWindowsHint int,
) (*TacticReport, error) {
	_ = totalWindowsHint // reserved for future "window i of N" prompt context

	startedAt := time.Now().UTC()

	spec, ok := TacticRegistry[r.cfg.Tactic]
	if !ok {
		return nil, fmt.Errorf("unknown tactic %q (registered: %v)",
			r.cfg.Tactic, KnownTactics())
	}
	skillPath := r.cfg.SkillsDir + "/" + spec.Slug + ".md"
	skillRaw, err := os.ReadFile(skillPath)
	if err != nil {
		return nil, fmt.Errorf("load skill %q: %w", skillPath, err)
	}
	skillSHA := sha256.Sum256(skillRaw)

	db, err := sql.Open("duckdb", r.cfg.DBPath+"?access_mode=read_only")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	window, totalMatching, err := queryEventsForTacticOffset(
		ctx, db, caseID, spec, r.cfg.MaxEvents, offset, r.cfg.ArtifactScope)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}

	validIDs := make(map[string]bool, len(window.Events))
	for _, e := range window.Events {
		validIDs[e.AuditID] = true
	}

	userMsg, err := buildUserMessage(caseID, evidenceID, spec, window, totalMatching, r.cfg.MaxEvents)
	if err != nil {
		return nil, fmt.Errorf("build prompt: %w", err)
	}

	// Iterate: ask, parse, retry on bad JSON.
	var (
		report          *TacticReport
		lastResp        *EngineResponse
		lastErr         error
		iterations      int
		feedback        string
		// Wave 20b: capture the largest prompt sent (= the final iteration
		// after feedback accretes) so calibration can compare ACTUAL bytes
		// sent vs. response latency. We track the max across iters because
		// each retry appends feedback, so the final iter's prompt is the
		// upper-bound the engine actually had to process.
		promptSizeChars int
	)
	for iter := 1; iter <= r.cfg.MaxIters; iter++ {
		iterations = iter
		userIter := userMsg
		if r.cfg.CorrectionContext != "" {
			userIter = userMsg +
				"\n\n---\n\nCORRECTION CONTEXT (Tier 2 Corrector):\n" +
				r.cfg.CorrectionContext
		}
		if feedback != "" {
			userIter += "\n\n---\n\nIMPORTANT: " + feedback
		}
		if size := len(skillRaw) + len(userIter); size > promptSizeChars {
			promptSizeChars = size
		}
		er, err := r.engine.Call(ctx, string(skillRaw), userIter)
		if err != nil {
			return nil, fmt.Errorf("%s call iter=%d: %w",
				r.engine.ID(), iter, err)
		}
		lastResp = er

		jsonStr, err := extractJSON(er.Text)
		if err != nil {
			feedback = fmt.Sprintf(
				"Your previous response did not contain valid JSON (parse error: %v). "+
					"Return ONLY a single JSON object matching the TacticReport schema, "+
					"with no surrounding prose, no markdown fences.", err)
			lastErr = err
			continue
		}
		var rep TacticReport
		if err := json.Unmarshal([]byte(jsonStr), &rep); err != nil {
			feedback = fmt.Sprintf(
				"Your JSON could not be unmarshalled into the TacticReport schema "+
					"(error: %v). Return a strictly conforming object.", err)
			lastErr = err
			continue
		}
		report = &rep
		lastErr = nil
		break
	}

	finishedAt := time.Now().UTC()

	if report == nil {
		// Construct a failure report rather than returning nil — the
		// orchestrator wants to record the attempt.
		return &TacticReport{
			TacticID:      spec.ID,
			TacticName:    spec.Name,
			CaseID:        caseID,
			EvidenceID:    evidenceID,
			ArtifactScope: r.cfg.ArtifactScope,
			StartedAt:     startedAt,
			FinishedAt:    finishedAt,
			Status:        "failed",
			Audit: Audit{
				Iterations:      iterations,
				InputEvents:     len(window.Events),
				MaxEvents:       r.cfg.MaxEvents,
				PromptSizeChars: promptSizeChars,
				ModelID:         r.cfg.Model,
				DurationSec:     finishedAt.Sub(startedAt).Seconds(),
				DurationAPIMS: func() int {
					if lastResp != nil {
						return lastResp.DurationAPIMS
					}
					return 0
				}(),
				SkillFile:     skillPath,
				SkillSHA256:   hex.EncodeToString(skillSHA[:]),
				ValidationOK:  false,
				ValidationErr: fmt.Sprintf("max_iters reached without valid JSON: %v", lastErr),
				TokensInput: func() int {
					if lastResp != nil {
						return lastResp.InputTokens
					}
					return 0
				}(),
				TokensOutput: func() int {
					if lastResp != nil {
						return lastResp.OutputTokens
					}
					return 0
				}(),
			},
		}, fmt.Errorf("agent failed: %w", lastErr)
	}

	// Override server-side metadata fields. The model is allowed to claim
	// findings and reasoning; it doesn't get to set its own audit numbers
	// or the canonical Tactic name.
	report.TacticID = spec.ID
	report.TacticName = spec.Name
	report.CaseID = caseID
	report.EvidenceID = evidenceID
	if len(r.cfg.EvidenceIDs) > 0 {
		report.EvidenceIDs = append([]string(nil), r.cfg.EvidenceIDs...)
	}
	report.StartedAt = startedAt
	report.FinishedAt = finishedAt
	report.ArtifactScope = r.cfg.ArtifactScope
	if report.Status == "" {
		report.Status = "completed"
	}
	report.Audit.Iterations = iterations
	report.Audit.InputEvents = len(window.Events)
	report.Audit.MaxEvents = r.cfg.MaxEvents
	report.Audit.PromptSizeChars = promptSizeChars
	// Prefer the engine's effective model when reported, else the requested
	// model. Differs for claude-code which may route to Haiku for trivial
	// turns — examiner wants to know which model actually wrote the text.
	if lastResp != nil && lastResp.EffectiveModel != "" {
		report.Audit.ModelID = lastResp.EffectiveModel
	} else {
		report.Audit.ModelID = r.cfg.Model
	}
	report.Audit.SkillFile = skillPath
	report.Audit.SkillSHA256 = hex.EncodeToString(skillSHA[:])
	report.Audit.DurationSec = finishedAt.Sub(startedAt).Seconds()
	if lastResp != nil {
		report.Audit.StopReason = lastResp.StopReason
		report.Audit.TokensInput = lastResp.InputTokens
		report.Audit.TokensOutput = lastResp.OutputTokens
		report.Audit.CacheHitTok = lastResp.CacheReadTokens
		report.Audit.DurationAPIMS = lastResp.DurationAPIMS
		report.Audit.TraceID = lastResp.TraceID // Wave 29
	}

	// Validate audit_ids point at real rows we passed in.
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

// validateEvidence checks every Finding.Evidence[].AuditID exists in the
// set we showed the model. Hallucinated IDs are recorded but don't crash —
// Review Gate 1 surfaces them to the examiner.
func validateEvidence(r *TacticReport, valid map[string]bool) []string {
	var errs []string
	for i, f := range r.Findings {
		if len(f.Evidence) == 0 {
			errs = append(errs, fmt.Sprintf(
				"finding[%d] %s has zero evidence rows", i, f.FindingID))
			continue
		}
		for j, e := range f.Evidence {
			if e.AuditID == "" {
				errs = append(errs, fmt.Sprintf(
					"finding[%d].evidence[%d]: empty audit_id", i, j))
				continue
			}
			if !valid[e.AuditID] {
				errs = append(errs, fmt.Sprintf(
					"finding[%d].evidence[%d]: audit_id %q not in input window",
					i, j, e.AuditID))
			}
		}
	}
	return errs
}

// buildUserMessage assembles the JSON the LLM sees in `messages[0].content`.
// Everything is plain JSON — no XML tags, no fences.
func buildUserMessage(
	caseID, evidenceID string,
	spec TacticSpec,
	w EventWindow,
	total, cap int,
) (string, error) {
	body := map[string]any{
		"case_id":            caseID,
		"evidence_id":        evidenceID,
		"tactic":             spec.ID,
		"tactic_name":        spec.Name,
		"events_in_window":   w.Total,
		"events_total_match": total,
		"truncated":          w.Truncated,
		"window_min":         tsOrEmpty(w.WindowMin),
		"window_max":         tsOrEmpty(w.WindowMax),
		"counts_by_artifact": w.Counts,
		"events":             w.Events,
		"caps": map[string]any{
			"max_events_shown": cap,
			"max_iterations":   3,
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	prelude := fmt.Sprintf(
		"Below is the EventWindow for your %s (%s) analysis. Apply the "+
			"procedure in the system prompt and return ONLY the "+
			"TacticReport JSON.\n\n",
		spec.ID, spec.Name)
	return prelude + string(b), nil
}

func tsOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// extractJSON pulls a JSON object out of free-form text. Models sometimes
// emit a fenced code block or surrounding prose despite instructions; we
// recover from that. Strict json.Unmarshal still fails on schema drift.
func extractJSON(text string) (string, error) {
	t := strings.TrimSpace(text)

	// Strip ```json … ``` fences if present.
	if strings.HasPrefix(t, "```") {
		// drop the opening fence line
		if nl := strings.IndexByte(t, '\n'); nl > 0 {
			t = t[nl+1:]
		}
		if i := strings.LastIndex(t, "```"); i >= 0 {
			t = t[:i]
		}
		t = strings.TrimSpace(t)
	}

	if strings.HasPrefix(t, "{") {
		return t, nil
	}

	// Find the first balanced JSON object.
	start := strings.Index(t, "{")
	if start < 0 {
		return "", fmt.Errorf("no '{' found in response")
	}
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(t); i++ {
		ch := t[i]
		if esc {
			esc = false
			continue
		}
		if ch == '\\' {
			esc = true
			continue
		}
		if ch == '"' {
			inStr = !inStr
			continue
		}
		if inStr {
			continue
		}
		switch ch {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return t[start : i+1], nil
			}
		}
	}
	return "", fmt.Errorf("unbalanced braces in response")
}

