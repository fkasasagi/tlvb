package tier2

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTier2APIModel(t *testing.T) {
	cases := map[string]string{
		"":                      "claude-opus-4-8", // empty → default
		"claude-opus-4-8":       "claude-opus-4-8",
		"claude-opus-4-8[1m]":   "claude-opus-4-8", // strip claude-code routing suffix
		"claude-sonnet-4-6[1m]": "claude-sonnet-4-6",
		"  claude-opus-4-8  ":   "claude-opus-4-8",
	}
	for in, want := range cases {
		if got := tier2APIModel(in); got != want {
			t.Errorf("tier2APIModel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTier2CostUSD(t *testing.T) {
	// Opus 4.8: input $5, output $25, cache-write(5m) $6.25, cache-read $0.50 /Mtok.
	got := tier2CostUSD(1_000_000, 1_000_000, 1_000_000, 1_000_000)
	want := 5.00 + 25.00 + 6.25 + 0.50
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("tier2CostUSD per-1M = %.6f, want %.6f", got, want)
	}
}

// TestCallAnthropicAPI_SystemOnlyCache is the accuracy-neutral guarantee: the
// system prompt carries cache_control, the user message does NOT (so the large
// single-use payload is plain input, not a 1.25x cache write), the model id is
// normalised, and thinking/effort are set so reasoning matches the CLI path.
func TestCallAnthropicAPI_SystemOnlyCache(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"stop_reason":"end_turn",
			"content":[{"type":"thinking","text":""},{"type":"text","text":"hello"}],
			"usage":{"input_tokens":1000,"output_tokens":200,
			         "cache_creation_input_tokens":6000,"cache_read_input_tokens":0}
		}`))
	}))
	defer srv.Close()

	orig := tier2APIURL
	tier2APIURL = srv.URL
	defer func() { tier2APIURL = orig }()

	cfg := Config{Model: "claude-opus-4-8[1m]", PerClusterTimeout: 10 * time.Second}
	out, err := callAnthropicAPI(context.Background(), cfg, "test-key", "SYSTEM PROMPT", "BIG USER PAYLOAD")
	if err != nil {
		t.Fatalf("callAnthropicAPI: %v", err)
	}

	// --- request shape (the accuracy-neutral contract) ---
	sys := captured["system"].([]any)
	sysBlock := sys[0].(map[string]any)
	if _, ok := sysBlock["cache_control"]; !ok {
		t.Error("system block missing cache_control — the stable prefix must be cached")
	}
	if sysBlock["text"] != "SYSTEM PROMPT" {
		t.Errorf("system text = %v, want unchanged 'SYSTEM PROMPT'", sysBlock["text"])
	}
	msgs := captured["messages"].([]any)
	msg0 := msgs[0].(map[string]any)
	if _, ok := msg0["cache_control"]; ok {
		t.Error("user message carries cache_control — single-use payload must NOT be cache-written")
	}
	if msg0["content"] != "BIG USER PAYLOAD" {
		t.Errorf("user content = %v, want unchanged 'BIG USER PAYLOAD'", msg0["content"])
	}
	if captured["model"] != "claude-opus-4-8" {
		t.Errorf("model = %v, want normalised 'claude-opus-4-8'", captured["model"])
	}
	if th, _ := captured["thinking"].(map[string]any); th["type"] != "adaptive" {
		t.Errorf("thinking = %v, want adaptive (accuracy parity with CLI)", captured["thinking"])
	}
	if oc, _ := captured["output_config"].(map[string]any); oc["effort"] != tier2Effort {
		t.Errorf("output_config.effort = %v, want %q", captured["output_config"], tier2Effort)
	}

	// --- response mapping (audit fidelity) ---
	if out.Result != "hello" {
		t.Errorf("Result = %q, want 'hello' (text blocks only, thinking skipped)", out.Result)
	}
	if out.Usage.InputTokens != 1000 || out.Usage.OutputTokens != 200 ||
		out.Usage.CacheCreationInputTokens != 6000 || out.Usage.CacheReadInputTokens != 0 {
		t.Errorf("usage not mapped: %+v", out.Usage)
	}
	wantCost := tier2CostUSD(1000, 200, 6000, 0)
	if math.Abs(out.TotalCostUSD-wantCost) > 1e-9 {
		t.Errorf("TotalCostUSD = %.6f, want %.6f", out.TotalCostUSD, wantCost)
	}
}
