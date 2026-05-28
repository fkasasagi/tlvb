package agents

import (
	"context"
	"time"
)

// Public wrappers so packages outside `agents` (e.g. synthesizer) can
// reach a Claude model without going through the Tactic/AnomalyHunter
// runners. Used by the Tier 2 TimelineReviewer.
//
// The Engine interface itself is already exported (see engine.go) — what
// was missing was a way to construct an engine and a way to coerce
// free-form model output into clean JSON. Both helpers are deliberately
// thin: same behaviour as the internal counterparts, just public names.

// NewEngine builds an Engine from the same knobs Tactic / Anomaly use.
//
//   engine  — "claude-code" (default if empty) | "anthropic-api"
//   apiKey  — required when engine == "anthropic-api"
//   model   — optional; engine defaults apply when empty
//   maxTok  — Anthropic max_tokens (api only); 0 → 50000
//   timeout — wall-clock cap; 0 → 5 min
func NewEngine(
	engine, apiKey, model string, maxTok int, timeout time.Duration,
) (Engine, error) {
	if maxTok == 0 {
		maxTok = 50000
	}
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	return newEngineForConfig(engine, apiKey, model, maxTok, timeout)
}

// ExtractJSON pulls the first balanced JSON object out of model output,
// tolerating ```json fences or stray prose. Returns an error when no
// well-formed object can be found.
func ExtractJSON(text string) (string, error) {
	return extractJSON(text)
}

// CallEngine is a tiny convenience that combines Engine.Call with
// ExtractJSON + a single JSON-validity retry, suitable for one-shot
// non-Tactic agents (timeline review, future LLM passes). The retry
// reuses the same engine so token accounting stays comparable to the
// Tactic runner.
//
// Returns the cleaned JSON string and the engine's response (so the
// caller can record token usage in the case audit trail).
func CallEngine(
	ctx context.Context,
	eng Engine,
	systemPrompt, userMsg string,
	maxIters int,
) (jsonText string, last *EngineResponse, err error) {
	if maxIters <= 0 {
		maxIters = 2
	}
	current := userMsg
	for iter := 1; iter <= maxIters; iter++ {
		er, callErr := eng.Call(ctx, systemPrompt, current)
		if callErr != nil {
			return "", er, callErr
		}
		last = er
		js, jerr := extractJSON(er.Text)
		if jerr == nil {
			return js, er, nil
		}
		if iter == maxIters {
			return "", er, jerr
		}
		// Append a JSON-correction note for the next iteration.
		current = userMsg + "\n\nNOTE: Your previous reply was not " +
			"valid JSON (" + jerr.Error() + "). Return the JSON object " +
			"only — no markdown fences, no prose."
	}
	return "", last, err
}
