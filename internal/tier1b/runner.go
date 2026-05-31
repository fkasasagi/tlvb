package tier1b

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/marcboeker/go-duckdb"
	"github.com/tlvb/tlvb/internal/tier1a"
)

// llmContext is the JSON shape passed to the LLM as the user message.
// Field names mirror skills/anomaly_hunter.md so the prompt can reference them.
type llmContext struct {
	CaseID                string         `json:"case_id"`
	TacticFindingsSummary map[string]int `json:"tactic_findings_summary"`
	KeyFindingTimestamps  []string       `json:"key_finding_timestamps,omitempty"`
	ExistingAuditIDs      []string       `json:"existing_audit_ids,omitempty"`
	LensesApplied         []string       `json:"lenses_applied"`
	EventsTotalScanned    int            `json:"events_total_scanned"`
	EventsInWindow        int            `json:"events_in_window"`
	Truncated             bool           `json:"truncated"`
	WindowMin             string         `json:"window_min,omitempty"`
	WindowMax             string         `json:"window_max,omitempty"`
	Events                []eventForLLM  `json:"events"`
}

type eventForLLM struct {
	AuditID    string         `json:"audit_id"`
	TS         string         `json:"ts,omitempty"`
	ArtifactID string         `json:"artifact_id"`
	Computer   string         `json:"computer,omitempty"`
	Lenses     []string       `json:"_lenses"`
	Excerpt    map[string]any `json:"excerpt"`
}

const skillName = "anomaly_hunter"

// Run executes the Tier 1B MVP for a case. Reads prior Tier 1A findings,
// prefilters anomaly candidates, builds the LLM context, calls Claude CLI
// (or returns dry-run info), writes findings/by-skill/anomaly_hunter.json.
func Run(ctx context.Context, cfg Config) (*Report, error) {
	if cfg.CaseID == "" {
		return nil, fmt.Errorf("Tier 1B: CaseID is required")
	}
	if cfg.DBPath == "" {
		return nil, fmt.Errorf("Tier 1B: DBPath is required")
	}
	if cfg.SkillsDir == "" {
		cfg.SkillsDir = "skills"
	}
	if cfg.FindingsBaseDir == "" {
		cfg.FindingsBaseDir = filepath.Join("outputs", "cases", cfg.CaseID, "findings")
	}
	if cfg.ClaudeBinary == "" {
		cfg.ClaudeBinary = "claude"
	}
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = 200
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Minute
	}

	rep := &Report{CaseID: cfg.CaseID}

	emit(cfg, Event{Phase: "loading", Message: "reading skill + prior findings"})

	skillPath := filepath.Join(cfg.SkillsDir, skillName+".md")
	skillBytes, err := os.ReadFile(skillPath)
	if err != nil {
		return nil, fmt.Errorf("read skill: %w", err)
	}
	skillSHA := sha256.Sum256(skillBytes)
	rep.SkillSHA256 = hex.EncodeToString(skillSHA[:])

	prior, err := loadPriorFindings(cfg.FindingsBaseDir)
	if err != nil {
		return nil, fmt.Errorf("load prior findings: %w", err)
	}
	rep.PriorFindings = prior.Total
	emit(cfg, Event{Phase: "loading",
		Message: fmt.Sprintf("loaded %d prior findings (%d unique audit_ids, %d key timestamps)",
			prior.Total, len(prior.UniqueAudits), len(prior.KeyTimestamps))})

	emit(cfg, Event{Phase: "prefilter", Message: "scoring anomaly candidates"})
	db, err := sql.Open("duckdb", cfg.DBPath+"?access_mode=read_only")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	totalScanned, err := countAllEvents(ctx, db, cfg.CaseID)
	if err != nil {
		return nil, fmt.Errorf("count events: %w", err)
	}
	rep.EventsScanned = totalScanned

	bundle, err := buildCandidates(ctx, db, cfg.CaseID, prior, cfg.MaxEvents)
	if err != nil {
		return nil, fmt.Errorf("build candidates: %w", err)
	}
	rep.EventsInWindow = bundle.Total
	rep.Truncated = bundle.Total > cfg.MaxEvents
	emit(cfg, Event{Phase: "prefilter",
		Message: fmt.Sprintf("scanned=%d, candidates=%d (truncated=%v)",
			totalScanned, bundle.Total, rep.Truncated)})

	hctx := buildLLMContext(cfg.CaseID, prior, bundle)
	userMsg, err := buildUserMessage(hctx)
	if err != nil {
		return nil, err
	}

	if cfg.DryRun {
		emit(cfg, Event{Phase: "llm",
			Message: fmt.Sprintf("dry-run: skill=%d chars / user_msg=%d chars / events_in_window=%d",
				len(skillBytes), len(userMsg), len(bundle.Events))})
		rep.OutputPath = ""
		return rep, nil
	}

	emit(cfg, Event{Phase: "llm", Message: "calling claude CLI"})
	llmStart := time.Now()
	resp, err := callClaudeCLI(ctx, cfg, string(skillBytes), userMsg)
	if err != nil {
		return rep, fmt.Errorf("claude CLI: %w", err)
	}
	rep.LLMCallDurationS = time.Since(llmStart).Seconds()

	// Always persist the raw response next to the report for triage of
	// parse failures or unexpected empties.
	rawDebugPath := filepath.Join(cfg.FindingsBaseDir, "by-skill",
		skillName+".raw_response.txt")
	_ = os.MkdirAll(filepath.Dir(rawDebugPath), 0o755)
	_ = os.WriteFile(rawDebugPath, []byte(resp.Result), 0o644)

	findings, err := parseAnomalyFindings(resp.Result, prior.UniqueAudits)
	if err != nil {
		return rep, fmt.Errorf("parse LLM output: %w (raw saved to %s)", err, rawDebugPath)
	}
	for i := range findings {
		if findings[i].FindingID == "" {
			findings[i].FindingID = uuid.NewString()
		}
		findings[i].GeneratedAt = time.Now().UTC()
		// Severity-based auto-approve, mirroring Tier 1A: critical/high
		// require examiner review; medium/low/info are auto-approved.
		if approved, by := tier1a.AutoApproveByLevel(findings[i].Severity); approved {
			findings[i].Approved = true
			findings[i].ApprovedBy = by
		}
	}

	outPath := filepath.Join(cfg.FindingsBaseDir, "by-skill", skillName+".json")
	if err := writeAnomalyReport(outPath, AnomalyReport{
		CaseID:         cfg.CaseID,
		Skill:          skillName,
		SkillSHA256:    rep.SkillSHA256,
		GeneratedAt:    time.Now().UTC(),
		ModelID:        resp.EffectiveModel,
		EventsScanned:  totalScanned,
		EventsInWindow: bundle.Total,
		PriorFindings:  prior.Total,
		Findings:       findings,
		Audit: AnomalyAudit{
			LLMCallDurationS: rep.LLMCallDurationS,
			InputTokens:      resp.InputTokens,
			OutputTokens:     resp.OutputTokens,
			StopReason:       resp.StopReason,
			SessionID:        resp.SessionID,
		},
	}); err != nil {
		return rep, fmt.Errorf("write anomaly report: %w", err)
	}
	rep.OutputPath = outPath

	for _, f := range findings {
		rep.NewFindings = append(rep.NewFindings, FindingSummary{
			Lens:       f.Lens,
			Severity:   f.Severity,
			Summary:    f.Summary,
			AuditCount: len(f.AuditIDs),
		})
	}
	emit(cfg, Event{Phase: "done",
		Message: fmt.Sprintf("wrote %d findings to %s", len(findings), outPath),
		Count:   len(findings)})
	return rep, nil
}

// buildLLMContext converts our internal state into the wire format the
// skill prompt expects.
func buildLLMContext(caseID string, prior *priorContext, bundle *candidateBundle) llmContext {
	tacticSummary := map[string]int{}
	for _, s := range prior.Summary {
		k := s.Source
		if s.Level != "" {
			k = s.Source + "/" + s.Level
		}
		tacticSummary[k] += s.Count
	}

	lenses := []string{
		"A1 time anomaly (off-hours)",
		"A2 location anomaly (Temp / AppData / Public / ProgramData)",
		"A4 frequency anomaly (rare image, count<3)",
		"A5 adjacency anomaly (±30 min around prior findings)",
		"(A3 / A6 / A7: LLM-side judgment, no pre-score)",
	}

	events := make([]eventForLLM, 0, len(bundle.Events))
	for _, c := range bundle.Events {
		e := eventForLLM{
			AuditID:    c.AuditID,
			ArtifactID: c.ArtifactID,
			Computer:   c.Computer,
			Lenses:     c.Lenses,
			Excerpt:    shrinkPayload(c.ArtifactID, c.Payload),
		}
		if c.HasTS {
			e.TS = c.TsUTC.Format(time.RFC3339Nano)
		}
		events = append(events, e)
	}

	out := llmContext{
		CaseID:                caseID,
		TacticFindingsSummary: tacticSummary,
		KeyFindingTimestamps:  prior.KeyTimestamps,
		ExistingAuditIDs:      prior.UniqueAudits,
		LensesApplied:         lenses,
		EventsTotalScanned:    0, // filled at call-site (totalScanned passed separately)
		EventsInWindow:        bundle.Total,
		Truncated:             bundle.Total > len(events),
		Events:                events,
	}
	if !bundle.MinTS.IsZero() {
		out.WindowMin = bundle.MinTS.Format(time.RFC3339)
	}
	if !bundle.MaxTS.IsZero() {
		out.WindowMax = bundle.MaxTS.Format(time.RFC3339)
	}
	// Cap existing_audit_ids to keep prompt size reasonable. The LLM only
	// needs the set membership to avoid duplicates — 500 is plenty.
	if len(out.ExistingAuditIDs) > 500 {
		out.ExistingAuditIDs = out.ExistingAuditIDs[:500]
	}
	if len(out.KeyFindingTimestamps) > 200 {
		out.KeyFindingTimestamps = out.KeyFindingTimestamps[:200]
	}
	return out
}

func buildUserMessage(hctx llmContext) (string, error) {
	prelude := `Below is the AnomalyContext for your Tier 1.5 anomaly scan.
Apply the lenses defined in your system prompt. Return ONLY a JSON array of
finding objects with this shape:

  [
    {
      "lens": "A1|A2|A4|A5|A6|A7",
      "summary": "1-line title (≤120 chars)",
      "description": "free-text rationale (≤500 chars)",
      "severity": "info|low|medium|high|critical",
      "audit_ids": ["<audit_id from events>", ...],
      "technique_id": "T1059.001",   // optional MITRE T-number
      "tactic": "execution"           // optional kill-chain phase
    },
    ...
  ]

Constraints:
- Every audit_id MUST exist in the events array below. Do NOT invent ids.
- Do NOT duplicate findings already covered by existing_audit_ids (the
  tactic agents / Hayabusa pass-through already reported those).
- Return [] if no genuine anomalies stand out — false positives are
  worse than gaps at this layer.
- No markdown fences, no prose outside the JSON array.

AnomalyContext:
`
	body, err := json.MarshalIndent(hctx, "", "  ")
	if err != nil {
		return "", err
	}
	return prelude + string(body), nil
}

// claudeOutput captures the fields we use from `claude --output-format json`.
type claudeOutput struct {
	IsError        bool    `json:"is_error"`
	Result         string  `json:"result"`
	StopReason     string  `json:"stop_reason"`
	SessionID      string  `json:"session_id"`
	DurationMS     int     `json:"duration_ms"`
	DurationAPIMS  int     `json:"duration_api_ms"`
	TotalCostUSD   float64 `json:"total_cost_usd"`
	EffectiveModel string  `json:"-"`
	InputTokens    int     `json:"-"`
	OutputTokens   int     `json:"-"`
	Usage          struct {
		InputTokens          int `json:"input_tokens"`
		CacheReadInputTokens int `json:"cache_read_input_tokens"`
		OutputTokens         int `json:"output_tokens"`
	} `json:"usage"`
	ModelUsage map[string]struct {
		InputTokens  int `json:"inputTokens"`
		OutputTokens int `json:"outputTokens"`
	} `json:"modelUsage"`
}

func callClaudeCLI(ctx context.Context, cfg Config, systemPrompt, userMsg string) (*claudeOutput, error) {
	args := []string{
		"-p",
		"--output-format", "json",
		"--system-prompt", systemPrompt,
		"--tools", "",
		"--no-session-persistence",
		"--exclude-dynamic-system-prompt-sections",
	}
	if cfg.Model != "" {
		args = append(args, "--model", cfg.Model)
		args = append(args, "--fallback-model", cfg.Model)
	}
	subCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	cmd := exec.CommandContext(subCtx, cfg.ClaudeBinary, args...)
	cmd.Stdin = strings.NewReader(userMsg)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		tail := stderr.String()
		if len(tail) > 400 {
			tail = tail[:400] + "..."
		}
		return nil, fmt.Errorf("exec: %w (stderr: %s)", err, tail)
	}
	var out claudeOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		head := stdout.String()
		if len(head) > 240 {
			head = head[:240] + "..."
		}
		return nil, fmt.Errorf("parse output: %w (head: %s)", err, head)
	}
	if out.IsError {
		return nil, fmt.Errorf("claude reported error (%s): %s",
			out.StopReason, out.Result)
	}
	out.InputTokens = out.Usage.InputTokens
	out.OutputTokens = out.Usage.OutputTokens
	// Pick the model that produced the most output tokens.
	var best string
	var bestOut int
	for k, v := range out.ModelUsage {
		if v.OutputTokens > bestOut {
			bestOut = v.OutputTokens
			best = k
		}
	}
	if best != "" {
		out.EffectiveModel = best
	} else {
		out.EffectiveModel = cfg.Model
	}
	return &out, nil
}

// parseAnomalyFindings extracts the JSON array Claude returned and filters
// out invalid entries (audit_ids must be present somewhere relevant).
func parseAnomalyFindings(text string, _ []string) ([]AnomalyFinding, error) {
	s := strings.TrimSpace(text)
	// Strip markdown fences if Claude wrapped despite our instructions.
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	s = strings.TrimSpace(s)
	// Find the array bounds.
	if i := strings.Index(s, "["); i > 0 {
		s = s[i:]
	}
	if j := strings.LastIndex(s, "]"); j >= 0 && j < len(s)-1 {
		s = s[:j+1]
	}
	var arr []AnomalyFinding
	if err := json.Unmarshal([]byte(s), &arr); err != nil {
		return nil, fmt.Errorf("unmarshal: %w (head: %s)", err, truncate(text, 200))
	}
	out := arr[:0]
	for _, f := range arr {
		f.Lens = strings.TrimSpace(f.Lens)
		f.Severity = strings.ToLower(strings.TrimSpace(f.Severity))
		f.Summary = strings.TrimSpace(f.Summary)
		if f.Summary == "" || len(f.AuditIDs) == 0 {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

func writeAnomalyReport(path string, rep AnomalyReport) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o644)
}

func countAllEvents(ctx context.Context, db *sql.DB, caseID string) (int, error) {
	var n int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM unified_events WHERE case_id = ?`, caseID).Scan(&n)
	return n, err
}

func emit(cfg Config, ev Event) {
	if cfg.ProgressFn != nil {
		cfg.ProgressFn(ev)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
