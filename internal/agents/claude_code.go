package agents

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// claudeCodeClient drives the `claude` CLI in non-interactive mode.
// Authentication uses whatever the local Claude Code install is configured
// for (subscription token, keychain, or ANTHROPIC_API_KEY env var) — the
// engine does not handle secrets directly.
//
// Why subprocess instead of API: this lets validation / hackathon /
// classroom setups run agents without the user having to provision an
// API key, by reusing their existing Claude Code session.
type claudeCodeClient struct {
	binary  string
	model   string // empty = let Claude Code default
	timeout time.Duration
}

func newClaudeCodeClient(model string, timeout time.Duration) *claudeCodeClient {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	return &claudeCodeClient{
		binary:  "claude",
		model:   model,
		timeout: timeout,
	}
}

func (c *claudeCodeClient) ID() string    { return "claude-code" }
func (c *claudeCodeClient) Model() string { return c.model }

// Call invokes the Claude Code CLI with --output-format json. The system
// prompt is delivered via --system-prompt (replaces Claude Code's default
// system prompt, including CLAUDE.md auto-discovery). The user message is
// piped via stdin to keep argv size bounded — event windows can be 200 KB.
func (c *claudeCodeClient) Call(
	ctx context.Context, systemPrompt, userMsg string,
) (*EngineResponse, error) {
	args := []string{
		"-p",
		"--output-format", "json",
		"--system-prompt", systemPrompt,
		// Disable all tools — we want a single-call completion, not an
		// agentic loop. Without this Claude Code may try to use Read/Edit
		// against the workspace.
		"--tools", "",
		// Don't write a session under ~/.claude/projects — these are
		// throwaway agent runs.
		"--no-session-persistence",
		// Keep cwd / git status / CLAUDE.md content out of the prompt.
		// (Ignored when --system-prompt is set, but harmless.)
		"--exclude-dynamic-system-prompt-sections",
	}
	if c.model != "" {
		args = append(args, "--model", c.model)
		args = append(args, "--fallback-model", c.model)
	}

	// We honour both the caller's context AND our own timeout. Whichever
	// fires first kills the subprocess (CommandContext sends SIGKILL).
	subCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	cmd := exec.CommandContext(subCtx, c.binary, args...)
	cmd.Stdin = strings.NewReader(userMsg)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	startedAt := time.Now()
	err := cmd.Run()
	wallclock := time.Since(startedAt)

	if err != nil {
		// Exec'd but exited non-zero: claude prints structured error JSON
		// on stdout in many cases (auth errors, API errors). Try to parse
		// stdout first; fall back to the wrapped exec error.
		if resp, perr := parseClaudeOutput(stdout.Bytes()); perr == nil {
			return nil, fmt.Errorf(
				"claude CLI failed (%s): %s",
				resp.StopReason, truncateStr(resp.Result, 240))
		}
		stderrTail := truncateStr(stderr.String(), 400)
		return nil, fmt.Errorf("claude CLI exec: %w (stderr: %s)", err, stderrTail)
	}

	resp, err := parseClaudeOutput(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf(
			"parse claude output: %w (stdout head: %s)",
			err, truncateStr(stdout.String(), 240))
	}
	if resp.IsError {
		return nil, fmt.Errorf(
			"claude reported error (%s): %s",
			resp.StopReason, truncateStr(resp.Result, 240))
	}

	// The CLI's modelUsage may include Haiku tokens from internal
	// routing/classification even when --model targets Sonnet. Use the
	// requested model as the authoritative effective model; fall back to
	// the highest-output-token model only when we didn't request one.
	effective := c.model
	if effective == "" {
		effective = pickEffectiveModel(resp)
	}

	durationMS := resp.DurationMS
	if durationMS == 0 {
		durationMS = int(wallclock / time.Millisecond)
	}

	return &EngineResponse{
		Text:            resp.Result,
		InputTokens:     resp.Usage.InputTokens,
		OutputTokens:    resp.Usage.OutputTokens,
		CacheReadTokens: resp.Usage.CacheReadInputTokens,
		StopReason:      resp.StopReason,
		DurationMS:      durationMS,
		DurationAPIMS:   resp.DurationAPIMS,
		TotalCostUSD:    resp.TotalCostUSD,
		EffectiveModel:  effective,
		TraceID:         resp.SessionID, // Wave 29 — claude-code session_id
	}, nil
}

// claudeCLIResponse is a partial mapping of the `--output-format json`
// envelope. We only project the fields we use.
type claudeCLIResponse struct {
	Type         string  `json:"type"`
	Subtype      string  `json:"subtype"`
	IsError      bool    `json:"is_error"`
	Result       string  `json:"result"`
	StopReason   string  `json:"stop_reason"`
	SessionID    string  `json:"session_id"`
	NumTurns     int     `json:"num_turns"`
	DurationMS   int     `json:"duration_ms"`
	DurationAPIMS int    `json:"duration_api_ms"`
	TotalCostUSD float64 `json:"total_cost_usd"`
	Usage        struct {
		InputTokens              int `json:"input_tokens"`
		CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
		CacheReadInputTokens     int `json:"cache_read_input_tokens"`
		OutputTokens             int `json:"output_tokens"`
	} `json:"usage"`
	ModelUsage map[string]struct {
		InputTokens int `json:"inputTokens"`
		OutputTokens int `json:"outputTokens"`
	} `json:"modelUsage"`
}

func parseClaudeOutput(b []byte) (*claudeCLIResponse, error) {
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

// pickEffectiveModel returns the model that produced the most output
// tokens. Claude Code CLI may use Haiku internally for routing/
// classification (high input tokens) while the actual completion comes
// from Sonnet (high output tokens). Selecting by output tokens picks
// the model that generated the user-visible response.
func pickEffectiveModel(r *claudeCLIResponse) string {
	if len(r.ModelUsage) == 0 {
		return ""
	}
	var bestModel string
	var bestOut int
	for k, v := range r.ModelUsage {
		if v.OutputTokens > bestOut {
			bestOut = v.OutputTokens
			bestModel = k
		}
	}
	return bestModel
}

// truncateStr is local to this file to avoid pulling persistence_query.go's
// unexported truncate.
func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}
