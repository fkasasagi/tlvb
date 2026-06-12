package rulebuild

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/rulesrepo"
)

// ClaudeCodeBuilder drives the `claude` CLI in non-interactive mode to
// generate SQL from rules. Authentication uses whatever the local Claude
// Code install is configured for (subscription, keychain, or ANTHROPIC_API_KEY
// env var) — the engine does not handle secrets directly.
//
// Why subprocess instead of the API: during development we want to iterate
// on prompts and validate SQL output without paying API fees per rule.
// Production builds switch to AnthropicBuilder via `tlvb rules build --engine
// anthropic-api`.
type ClaudeCodeBuilder struct {
	Binary string // path to `claude` binary; default "claude"
	Model  string // model id used for the actual `claude --model` call

	// SignatureModel overrides the model id recorded in the cache signature
	// (ModelID), decoupling it from the execution Model. Use when filling
	// gaps with a different model (e.g. Opus) without invalidating rows
	// already built under another model — set this to the existing rows'
	// model so the signature matches and they stay 'built'. Empty = use Model.
	SignatureModel string

	Timeout   time.Duration // per-rule timeout
	SchemaDoc string

	// CLI flags that match moai's internal/agents/claude_code.go
	// pattern. Exposed for testability — defaults are sane.
	DisableTools                   bool
	NoSessionPersistence           bool
	ExcludeDynamicSystemPromptSect bool
}

// NewClaudeCodeBuilder returns a builder with sane defaults.
func NewClaudeCodeBuilder(model, schemaDoc string) *ClaudeCodeBuilder {
	return &ClaudeCodeBuilder{
		Binary:                         "claude",
		Model:                          model,
		Timeout:                        300 * time.Second, // some rules trigger long chain-of-thought; 180s was killing antivirus/* etc.
		SchemaDoc:                      schemaDoc,
		DisableTools:                   true,
		NoSessionPersistence:           true,
		ExcludeDynamicSystemPromptSect: true,
	}
}

// ModelID identifies what produced cached SQL. We tag the cache row with
// "claude-code" + the actual effective model the CLI reported (set in
// EffectiveModel) so future cache invalidation can distinguish CLI-built
// rows from API-built rows.
func (b *ClaudeCodeBuilder) ModelID() string {
	m := b.SignatureModel
	if m == "" {
		m = b.Model
	}
	if m != "" {
		return "claude-code/" + m
	}
	return "claude-code/default"
}

func (b *ClaudeCodeBuilder) BuildSQL(ctx context.Context, rule rulesrepo.RawRule, schemaDoc string) (*BuiltSQL, error) {
	if b.Binary == "" {
		b.Binary = "claude"
	}
	doc := schemaDoc
	if doc == "" {
		doc = b.SchemaDoc
	}
	if doc == "" {
		return nil, fmt.Errorf("ClaudeCodeBuilder: schemaDoc not set")
	}
	systemPrompt := strings.Replace(SystemPrompt, "{SCHEMA_DOC}", doc, 1)
	userMsg := BuildUserMessage(rule)

	args := []string{
		"-p",
		"--output-format", "json",
		"--system-prompt", systemPrompt,
	}
	if b.DisableTools {
		args = append(args, "--tools", "")
	}
	if b.NoSessionPersistence {
		args = append(args, "--no-session-persistence")
	}
	if b.ExcludeDynamicSystemPromptSect {
		args = append(args, "--exclude-dynamic-system-prompt-sections")
	}
	if b.Model != "" {
		args = append(args, "--model", b.Model)
		args = append(args, "--fallback-model", b.Model)
	}

	timeout := b.Timeout
	if timeout <= 0 {
		timeout = 300 * time.Second
	}

	// signal:killed has been observed sporadically on the same rule across
	// runs (no OOM in dmesg, ample free RAM) — likely a transient
	// claude-CLI / Node hiccup. Retry exactly once on that specific
	// failure mode; deterministic failures (parse / validation / empty
	// SQL) are NOT retried.
	const maxAttempts = 2
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		out, err := b.runCLIOnce(ctx, timeout, args, userMsg)
		if err == nil {
			return out, nil
		}
		lastErr = err
		if !isRetryableCLIKill(err) || attempt == maxAttempts {
			return nil, err
		}
		// Brief pause so any kernel/Node cleanup can settle.
		time.Sleep(2 * time.Second)
	}
	return nil, lastErr
}

// runCLIOnce performs one full claude-code invocation: spawn the CLI,
// parse its envelope, parse the inner JSON the system prompt asks for,
// and validate the SQL. Separated from BuildSQL so the retry loop can
// reissue cleanly without recomputing args / prompts.
func (b *ClaudeCodeBuilder) runCLIOnce(ctx context.Context, timeout time.Duration,
	args []string, userMsg string) (*BuiltSQL, error) {
	subCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(subCtx, b.Binary, args...)
	cmd.Stdin = strings.NewReader(userMsg)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if resp, perr := parseClaudeCLIResponse(stdout.Bytes()); perr == nil {
			return nil, fmt.Errorf("claude CLI failed (%s): %s",
				resp.StopReason, truncate(resp.Result, 240))
		}
		return nil, fmt.Errorf("claude CLI exec: %w (stderr: %s)",
			err, truncate(stderr.String(), 400))
	}

	resp, err := parseClaudeCLIResponse(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("parse claude output: %w (head: %s)",
			err, truncate(stdout.String(), 240))
	}
	if resp.IsError {
		return nil, fmt.Errorf("claude reported error (%s): %s",
			resp.StopReason, truncate(resp.Result, 240))
	}

	out, err := parseBuilderJSON(resp.Result)
	if err != nil {
		return nil, fmt.Errorf("parse LLM output: %w (raw: %q)",
			err, truncate(resp.Result, 400))
	}
	if err := validateSQL(out.SQL); err != nil {
		return nil, fmt.Errorf("SQL validation: %w", err)
	}
	// Stamp cache row with the actual effective model the CLI reported,
	// not just "claude-code". This lets future cache invalidation
	// distinguish "Sonnet-4-6 result" from "Haiku-4-5 result" even when
	// both come through the CLI.
	out.ModelID = "claude-code/" + pickEffectiveCLIModel(resp, b.Model)
	out.InputTokens = resp.Usage.InputTokens
	out.OutputTokens = resp.Usage.OutputTokens
	out.CacheReadTokens = resp.Usage.CacheReadInputTokens
	return out, nil
}

// isRetryableCLIKill returns true when the error looks like an external
// SIGKILL to the claude CLI subprocess (signal: killed with empty
// stderr). Excludes errors where stderr has content (real CLI failures)
// or where the LLM produced a structured response but we couldn't parse.
func isRetryableCLIKill(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "signal: killed") &&
		strings.Contains(msg, "claude CLI exec:")
}

// claudeCLIResponse is a partial mapping of `claude --output-format json`.
// Duplicated from internal/agents/claude_code.go to keep rulebuild self-
// contained — the two packages will likely diverge as Tier 1A's needs grow.
type claudeCLIResponse struct {
	Type          string  `json:"type"`
	Subtype       string  `json:"subtype"`
	IsError       bool    `json:"is_error"`
	Result        string  `json:"result"`
	StopReason    string  `json:"stop_reason"`
	SessionID     string  `json:"session_id"`
	NumTurns      int     `json:"num_turns"`
	DurationMS    int     `json:"duration_ms"`
	DurationAPIMS int     `json:"duration_api_ms"`
	TotalCostUSD  float64 `json:"total_cost_usd"`
	Usage         struct {
		InputTokens              int `json:"input_tokens"`
		CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
		CacheReadInputTokens     int `json:"cache_read_input_tokens"`
		OutputTokens             int `json:"output_tokens"`
	} `json:"usage"`
	ModelUsage map[string]struct {
		InputTokens  int `json:"inputTokens"`
		OutputTokens int `json:"outputTokens"`
	} `json:"modelUsage"`
}

func parseClaudeCLIResponse(b []byte) (*claudeCLIResponse, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, fmt.Errorf("empty output")
	}
	var r claudeCLIResponse
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// pickEffectiveCLIModel resolves the model that produced the actual SQL
// response. Claude Code may route through Haiku internally for
// classification while running the completion on Sonnet — picking by
// output tokens identifies the model the user actually saw.
func pickEffectiveCLIModel(r *claudeCLIResponse, fallback string) string {
	if len(r.ModelUsage) == 0 {
		if fallback != "" {
			return fallback
		}
		return "unknown"
	}
	var bestModel string
	var bestOut int
	for k, v := range r.ModelUsage {
		if v.OutputTokens > bestOut {
			bestOut = v.OutputTokens
			bestModel = k
		}
	}
	if bestModel == "" && fallback != "" {
		return fallback
	}
	return bestModel
}
