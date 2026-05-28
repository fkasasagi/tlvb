package agents

import "context"

// Engine is the abstraction over how a Tactic Agent reaches a Claude model.
//
// We support two implementations today:
//   - anthropicClient — direct Messages API, requires ANTHROPIC_API_KEY
//   - claudeCodeClient — `claude -p ...` CLI subprocess, uses the local
//     Claude Code session credentials (keychain on most workstations)
//
// Both produce the same EngineResponse, so runner.go is engine-agnostic
// for everything except logging the engine id in the audit trail.
type Engine interface {
	// Call sends one prompt and returns the model's response text plus
	// token usage. The implementation is free to perform retries / caching
	// internally as long as the result is one logical completion.
	Call(ctx context.Context, systemPrompt, userMsg string) (*EngineResponse, error)

	// ID returns a stable identifier for the audit trail
	// ("anthropic-api" | "claude-code").
	ID() string

	// Model returns the model identifier (e.g. "claude-sonnet-4-6"). For
	// claude-code the actual model used per turn is in EngineResponse —
	// this returns the requested model.
	Model() string
}

// EngineResponse is the homogenised result of one Engine.Call.
type EngineResponse struct {
	// Text is the model's textual output. For Tactic Agents this is the
	// raw JSON (or near-JSON) the runner will pass to extractJSON.
	Text string

	// Token accounting. Cache stats are zero when the engine doesn't
	// support prompt caching.
	InputTokens     int
	OutputTokens    int
	CacheReadTokens int

	// StopReason is "end_turn" / "max_tokens" / "stop_sequence" / etc.
	StopReason string

	// DurationMS is wall-clock time inside the engine. For Anthropic API
	// this is HTTP RTT; for Claude Code it includes subprocess startup.
	DurationMS int

	// DurationAPIMS is server-side processing time when the engine reports
	// it separately from total wall clock. Claude Code exposes this as
	// `duration_api_ms`; the Anthropic SDK does not break it out, so this
	// stays 0 on that path. Useful for diagnosing cache-hit vs cache-miss
	// latency (Wave 20b calibration of Wave 20a per_event_sec).
	DurationAPIMS int

	// TotalCostUSD is reported by Claude Code when available; 0 otherwise.
	TotalCostUSD float64

	// EffectiveModel is the model the response actually came from. May
	// differ from the requested model when Claude Code applies routing.
	EffectiveModel string

	// TraceID (Wave 29) is an engine-side identifier that uniquely names
	// this Engine.Call invocation. For claude-code it's the session_id
	// the CLI echoes in `--output-format json`. For the Anthropic SDK
	// path we synthesise one from time + a counter (empty if the engine
	// doesn't expose anything useful). Stamped into TacticReport.Audit
	// so an examiner can pivot from a finding back to the LLM call that
	// produced it (cross-reference with claude-code session logs).
	TraceID string
}
