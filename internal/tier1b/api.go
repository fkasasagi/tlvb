package tier1b

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/tlvb/tlvb/internal/llm"
)

// Tier 1B LLM transport. Single-shot anomaly reasoning over cached SQL results.
//
// callClaude dispatches to whichever transport is configured (Anthropic API >
// Vertex AI > hidden `claude` CLI fallback — see internal/llm). The API paths
// cache the stable skill prompt (cache_control: ephemeral) and leave the
// single-use result payload uncached, matching Tier 2's billing strategy. All
// paths send byte-identical content to the model, so detection is unaffected.

const (
	tier1bMaxTokens = 16000
	tier1bEffort    = "high"

	// Opus 4.8 list pricing (USD per 1M tokens), used to fill total_cost_usd
	// on the API paths so the audit matches the CLI path's shape.
	tier1bCostInputPerM      = 5.00
	tier1bCostOutputPerM     = 25.00
	tier1bCostCacheWritePerM = 6.25
	tier1bCostCacheReadPerM  = 0.50
)

type apiRequest struct {
	// Model is set for the direct API; for Vertex it is omitted (the model is
	// named in the URL) and AnthropicVersion is set instead.
	Model            string            `json:"model,omitempty"`
	AnthropicVersion string            `json:"anthropic_version,omitempty"`
	MaxTokens        int               `json:"max_tokens"`
	Thinking         map[string]string `json:"thinking,omitempty"`
	OutputConfig     map[string]string `json:"output_config,omitempty"`
	System           []apiSysBlock     `json:"system"`
	Messages         []apiMsgItem      `json:"messages"`
}

type apiSysBlock struct {
	Type         string           `json:"type"`
	Text         string           `json:"text"`
	CacheControl *apiCacheControl `json:"cache_control,omitempty"`
}

type apiCacheControl struct {
	Type string `json:"type"`
}

type apiMsgItem struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type apiResponse struct {
	Model      string `json:"model"`
	StopReason string `json:"stop_reason"`
	Content    []struct {
		Type string `json:"type"`
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

// callClaude routes one Tier 1B LLM call to the configured transport.
func callClaude(ctx context.Context, cfg Config, systemPrompt, userMsg string) (*claudeOutput, error) {
	switch t := llm.Resolve(); t.Kind {
	case llm.KindVertex:
		return callMessagesAPI(ctx, cfg, t, true, systemPrompt, userMsg)
	case llm.KindAnthropic:
		return callMessagesAPI(ctx, cfg, t, false, systemPrompt, userMsg)
	default:
		return callClaudeCLI(ctx, cfg, systemPrompt, userMsg)
	}
}

// callMessagesAPI performs one Messages-API call (direct or Vertex) and returns
// the shared *claudeOutput. vertex selects the URL/auth/body shape.
func callMessagesAPI(ctx context.Context, cfg Config, t *llm.Transport, vertex bool, systemPrompt, userMsg string) (*claudeOutput, error) {
	model := cfg.Model
	if model == "" {
		model = llm.DefaultModel
	}
	body := apiRequest{
		MaxTokens:    tier1bMaxTokens,
		Thinking:     map[string]string{"type": "adaptive"},
		OutputConfig: map[string]string{"effort": tier1bEffort},
		System: []apiSysBlock{{
			Type:         "text",
			Text:         systemPrompt,
			CacheControl: &apiCacheControl{Type: "ephemeral"},
		}},
		Messages: []apiMsgItem{{Role: "user", Content: userMsg}},
	}
	var endpoint string
	if vertex {
		body.AnthropicVersion = llm.VertexAnthropicVersion
		endpoint = t.VertexURL(model)
	} else {
		body.Model = model
		endpoint = llm.AnthropicMessagesURL
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	if err := t.ApplyAuth(ctx, req); err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: cfg.Timeout}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var ar apiResponse
	if err := json.Unmarshal(raw, &ar); err != nil {
		return nil, fmt.Errorf("parse: %w (head: %s)", err, truncate(string(raw), 200))
	}
	if resp.StatusCode != 200 {
		if ar.Error != nil && ar.Error.Message != "" {
			return nil, fmt.Errorf("llm %d %s: %s", resp.StatusCode, ar.Error.Type, ar.Error.Message)
		}
		return nil, fmt.Errorf("llm %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}

	var sb bytes.Buffer
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
	out.TotalCostUSD = float64(ar.Usage.InputTokens)*tier1bCostInputPerM/1e6 +
		float64(ar.Usage.OutputTokens)*tier1bCostOutputPerM/1e6 +
		float64(ar.Usage.CacheCreationInputTokens)*tier1bCostCacheWritePerM/1e6 +
		float64(ar.Usage.CacheReadInputTokens)*tier1bCostCacheReadPerM/1e6
	if ar.Model != "" {
		out.EffectiveModel = ar.Model
	} else {
		out.EffectiveModel = model
	}
	return out, nil
}
