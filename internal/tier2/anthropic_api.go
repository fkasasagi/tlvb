package tier2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/tlvb/tlvb/internal/llm"
)

// Tier 2 Anthropic Messages API path. When ANTHROPIC_API_KEY is set, Tier 2
// LLM calls go through here instead of the `claude -p` CLI (callClaudeCLI).
//
// WHY THIS EXISTS — cache economics, not capability:
// The claude-code CLI auto-applies a prompt-cache breakpoint over the WHOLE
// prompt, so each large single-use user payload (a cluster's raw timeline, an
// active-search result set) is cache-WRITTEN at the 1.25x premium and never
// read back — pure waste (~25% on the bulk of Tier 2's input; measured ~$1.8
// on a single case). This path places cache_control on the stable system
// prompt ONLY, so the reused skill prefix still caches across calls while the
// single-use user payloads are billed as plain input (1.0x).
//
// ACCURACY-NEUTRAL BY CONSTRUCTION:
// The content sent to the model is byte-identical to the CLI path (same system
// prompt, same full user message — nothing is trimmed or summarised). Only the
// cache_control placement (a billing detail) differs. thinking/effort are set
// to match the claude-code default so the model reasons the same way — this is
// a billing change, not a capability downgrade.

// tier2APIURL is a var (not const) so tests can point it at an httptest server.
var tier2APIURL = "https://api.anthropic.com/v1/messages"

const (
	tier2APIVersion   = "2023-06-01"
	tier2MaxTokens    = 32000  // headroom over observed Tier 2 outputs (<= ~12k)
	tier2Effort       = "high" // matches claude-code's default for intelligence-sensitive work
	tier2DefaultModel = "claude-opus-4-8"

	// Opus 4.8 list pricing (USD per 1M tokens). cache write uses the 5-minute
	// ephemeral rate (1.25x input); no >200K long-context premium on Opus 4.8.
	// The Messages API does not return a cost figure, so we compute it here to
	// keep the Tier 2 audit's total_cost_usd consistent with the CLI path.
	// Keep in sync with Opus 4.8 list pricing if it changes.
	tier2CostInputPerM      = 5.00
	tier2CostOutputPerM     = 25.00
	tier2CostCacheWritePerM = 6.25 // 1.25 x input (5-min ephemeral)
	tier2CostCacheReadPerM  = 0.50 // 0.10 x input
)

// tier2APIModel resolves cfg.Model to a bare Anthropic API model id. cfg.Model
// is often empty (CLI default) or carries a claude-code routing suffix like
// "[1m]" that the raw API does not accept.
func tier2APIModel(m string) string {
	if strings.TrimSpace(m) == "" {
		return tier2DefaultModel
	}
	if i := strings.IndexByte(m, '['); i >= 0 {
		m = m[:i]
	}
	return strings.TrimSpace(m)
}

type tier2APIRequest struct {
	// Model is set for the direct API; for Vertex it is omitted (the model is
	// named in the URL) and AnthropicVersion is set instead.
	Model            string            `json:"model,omitempty"`
	AnthropicVersion string            `json:"anthropic_version,omitempty"`
	MaxTokens        int               `json:"max_tokens"`
	Thinking         map[string]string `json:"thinking,omitempty"`
	OutputConfig     map[string]string `json:"output_config,omitempty"`
	System           []tier2SysBlock   `json:"system"`
	Messages         []tier2MsgItem    `json:"messages"`
}

type tier2SysBlock struct {
	Type         string             `json:"type"`
	Text         string             `json:"text"`
	CacheControl *tier2CacheControl `json:"cache_control,omitempty"`
}

type tier2CacheControl struct {
	Type string `json:"type"` // "ephemeral"
}

type tier2MsgItem struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type tier2APIResponse struct {
	StopReason string `json:"stop_reason"`
	Content    []struct {
		Type string `json:"type"` // "text" | "thinking"
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens              int `json:"input_tokens"`
		OutputTokens             int `json:"output_tokens"`
		CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
		CacheReadInputTokens     int `json:"cache_read_input_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// callAnthropicAPI runs one Tier 2 LLM call through the Messages API with the
// system prompt cached (cache_control: ephemeral) and the user message left
// UNcached. Returns the same *claudeOutput shape as callClaudeCLI so call sites
// and the audit are unchanged; total_cost_usd is computed from Opus 4.8 rates.
func callAnthropicAPI(ctx context.Context, cfg Config, apiKey, sysPrompt, userMsg string) (*claudeOutput, error) {
	reqBody := tier2APIRequest{
		Model:        tier2APIModel(cfg.Model),
		MaxTokens:    tier2MaxTokens,
		Thinking:     map[string]string{"type": "adaptive"},
		OutputConfig: map[string]string{"effort": tier2Effort},
		System: []tier2SysBlock{{
			Type:         "text",
			Text:         sysPrompt,
			CacheControl: &tier2CacheControl{Type: "ephemeral"}, // cache the stable prefix ONLY
		}},
		Messages: []tier2MsgItem{{Role: "user", Content: userMsg}}, // single-use: no cache_control
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", tier2APIURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", tier2APIVersion)

	httpClient := &http.Client{Timeout: cfg.PerClusterTimeout}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return parseTier2APIResponse(resp.StatusCode, raw)
}

// callVertexAPI runs one Tier 2 LLM call through Anthropic on Vertex AI. The
// request body is byte-identical to the direct path except the model is named
// in the URL (not the body) and anthropic_version is set; auth is a GCP OAuth
// bearer token. Returns the same *claudeOutput shape so call sites and the
// audit are unchanged.
func callVertexAPI(ctx context.Context, cfg Config, t *llm.Transport, sysPrompt, userMsg string) (*claudeOutput, error) {
	bare := tier2APIModel(cfg.Model)
	reqBody := tier2APIRequest{
		AnthropicVersion: llm.VertexAnthropicVersion,
		MaxTokens:        tier2MaxTokens,
		Thinking:         map[string]string{"type": "adaptive"},
		OutputConfig:     map[string]string{"effort": tier2Effort},
		System: []tier2SysBlock{{
			Type:         "text",
			Text:         sysPrompt,
			CacheControl: &tier2CacheControl{Type: "ephemeral"},
		}},
		Messages: []tier2MsgItem{{Role: "user", Content: userMsg}},
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", t.VertexURL(bare), bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	if err := t.ApplyAuth(ctx, req); err != nil {
		return nil, err
	}
	httpClient := &http.Client{Timeout: cfg.PerClusterTimeout}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return parseTier2APIResponse(resp.StatusCode, raw)
}

// parseTier2APIResponse decodes a Messages-API response (direct or Vertex) into
// the shared *claudeOutput, computing total_cost_usd from Opus 4.8 rates.
func parseTier2APIResponse(status int, raw []byte) (*claudeOutput, error) {
	var ar tier2APIResponse
	if err := json.Unmarshal(raw, &ar); err != nil {
		return nil, fmt.Errorf("parse: %w (head: %s)", err, truncate(string(raw), 200))
	}
	if status != 200 {
		if ar.Error != nil && ar.Error.Message != "" {
			return nil, fmt.Errorf("llm %d %s: %s", status, ar.Error.Type, ar.Error.Message)
		}
		return nil, fmt.Errorf("llm %d: %s", status, truncate(string(raw), 200))
	}

	// Join all text blocks; skip thinking blocks (their text is empty by default).
	var sb strings.Builder
	for _, c := range ar.Content {
		if c.Type == "text" {
			sb.WriteString(c.Text)
		}
	}

	out := &claudeOutput{Result: sb.String(), StopReason: ar.StopReason}
	out.Usage.InputTokens = ar.Usage.InputTokens
	out.Usage.OutputTokens = ar.Usage.OutputTokens
	out.Usage.CacheReadInputTokens = ar.Usage.CacheReadInputTokens
	out.Usage.CacheCreationInputTokens = ar.Usage.CacheCreationInputTokens
	out.InputTokens = ar.Usage.InputTokens
	out.OutputTokens = ar.Usage.OutputTokens
	out.TotalCostUSD = tier2CostUSD(ar.Usage.InputTokens, ar.Usage.OutputTokens,
		ar.Usage.CacheCreationInputTokens, ar.Usage.CacheReadInputTokens)
	return out, nil
}

// tier2CostUSD computes USD cost from Opus 4.8 list rates.
func tier2CostUSD(in, out, cacheWrite, cacheRead int) float64 {
	return float64(in)*tier2CostInputPerM/1e6 +
		float64(out)*tier2CostOutputPerM/1e6 +
		float64(cacheWrite)*tier2CostCacheWritePerM/1e6 +
		float64(cacheRead)*tier2CostCacheReadPerM/1e6
}
