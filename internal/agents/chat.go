package agents

import (
	"context"
	"fmt"
	"time"

	"github.com/tlvb/tlvb/internal/llm"
)

// Chat runs a single conversational turn against the configured engine.
//
// This is a thin wrapper around Engine.Call that the Web Assistant uses
// to talk to the user about TLVB usage and case findings. Unlike the
// Tactic Agent runner, there is no JSON-validation retry, no event
// window, no skill loading — just one prompt in, one response out.
//
// engine: "claude-code" (default) | "anthropic-api"
// apiKey: required when engine = "anthropic-api"
// model:  empty → engine default
func Chat(
	ctx context.Context,
	engine, model, apiKey string,
	system, user string,
	timeout time.Duration,
) (*EngineResponse, error) {
	if engine == "" {
		engine = "auto"
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	maxTokens := 4096
	if model == "" {
		model = "claude-sonnet-4-6"
	}

	var e Engine
	switch engine {
	case "auto":
		switch t := llm.Resolve(); t.Kind {
		case llm.KindVertex:
			e = newVertexClient(t, model, maxTokens, timeout)
		case llm.KindAnthropic:
			e = newAnthropicClient(t.APIKey(), model, maxTokens, timeout)
		default:
			e = newClaudeCodeClient(model, timeout)
		}
	case "anthropic-api":
		if apiKey == "" {
			return nil, fmt.Errorf("engine=anthropic-api requires ANTHROPIC_API_KEY")
		}
		e = newAnthropicClient(apiKey, model, maxTokens, timeout)
	case "vertex":
		if t := llm.Resolve(); t.Kind == llm.KindVertex {
			e = newVertexClient(t, model, maxTokens, timeout)
		} else {
			return nil, fmt.Errorf("engine=vertex requires a Vertex service-account key")
		}
	case "claude-code":
		e = newClaudeCodeClient(model, timeout)
	default:
		return nil, fmt.Errorf("unknown engine %q (supported: auto, anthropic-api, vertex, claude-code)", engine)
	}
	return e.Call(ctx, system, user)
}
