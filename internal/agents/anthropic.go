package agents

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Minimal Anthropic Messages API client. We avoid the official SDK to keep
// the dep graph tight and to have direct control over prompt-cache headers.

const (
	anthropicAPIURL  = "https://api.anthropic.com/v1/messages"
	anthropicVersion = "2023-06-01"
)

// MsgRequest is what we POST. Only the fields we use.
type msgRequest struct {
	Model     string         `json:"model"`
	MaxTokens int            `json:"max_tokens"`
	System    []sysBlock     `json:"system,omitempty"`
	Messages  []msgItem      `json:"messages"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

type sysBlock struct {
	Type         string        `json:"type"` // "text"
	Text         string        `json:"text"`
	CacheControl *cacheControl `json:"cache_control,omitempty"`
}

type cacheControl struct {
	Type string `json:"type"` // "ephemeral"
}

type msgItem struct {
	Role    string `json:"role"` // "user" | "assistant"
	Content string `json:"content"`
}

// MsgResponse is what we expect back. Only the fields we use.
type msgResponse struct {
	ID         string    `json:"id"`
	Model      string    `json:"model"`
	Role       string    `json:"role"`
	StopReason string    `json:"stop_reason"`
	Content    []content `json:"content"`
	Usage      usage     `json:"usage"`
}

type content struct {
	Type string `json:"type"` // "text"
	Text string `json:"text"`
}

type usage struct {
	InputTokens             int `json:"input_tokens"`
	OutputTokens            int `json:"output_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens"`
}

type apiError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}
type errorResp struct {
	Type  string   `json:"type"`
	Error apiError `json:"error"`
}

type anthropicClient struct {
	apiKey    string
	model     string
	maxTokens int
	http      *http.Client
}

func newAnthropicClient(apiKey, model string, maxTokens int, timeout time.Duration) *anthropicClient {
	return &anthropicClient{
		apiKey:    apiKey,
		model:     model,
		maxTokens: maxTokens,
		http:      &http.Client{Timeout: timeout},
	}
}

// ID identifies this engine in the audit trail.
func (c *anthropicClient) ID() string { return "anthropic-api" }

// Model returns the requested model id.
func (c *anthropicClient) Model() string { return c.model }

// Call satisfies Engine. Delegates to callMessages, normalises usage.
func (c *anthropicClient) Call(
	ctx context.Context, systemPrompt, userMsg string,
) (*EngineResponse, error) {
	startedAt := time.Now()
	mr, err := c.callMessages(ctx, systemPrompt, userMsg, c.maxTokens)
	dur := time.Since(startedAt)
	if err != nil {
		return nil, err
	}
	return &EngineResponse{
		Text:            mr.firstText(),
		InputTokens:     mr.Usage.InputTokens,
		OutputTokens:    mr.Usage.OutputTokens,
		CacheReadTokens: mr.Usage.CacheReadInputTokens,
		StopReason:      mr.StopReason,
		DurationMS:      int(dur / time.Millisecond),
		EffectiveModel:  mr.Model,
	}, nil
}

// callMessages sends one Messages API call. systemPrompt is cached
// (cache_control: ephemeral) since it doesn't change between iterations.
func (c *anthropicClient) callMessages(
	ctx context.Context,
	systemPrompt, userMsg string,
	maxTokens int,
) (*msgResponse, error) {
	body := msgRequest{
		Model:     c.model,
		MaxTokens: maxTokens,
		System: []sysBlock{
			{
				Type:         "text",
				Text:         systemPrompt,
				CacheControl: &cacheControl{Type: "ephemeral"},
			},
		},
		Messages: []msgItem{
			{Role: "user", Content: userMsg},
		},
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", anthropicAPIURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", anthropicVersion)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode != 200 {
		var er errorResp
		if json.Unmarshal(raw, &er) == nil && er.Error.Message != "" {
			return nil, fmt.Errorf("anthropic %d %s: %s",
				resp.StatusCode, er.Error.Type, er.Error.Message)
		}
		return nil, fmt.Errorf("anthropic %d: %s", resp.StatusCode, string(raw))
	}

	var mr msgResponse
	if err := json.Unmarshal(raw, &mr); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w (body: %s)", err, string(raw))
	}
	return &mr, nil
}

// firstText returns the first text content block, joined.
func (m *msgResponse) firstText() string {
	for _, c := range m.Content {
		if c.Type == "text" {
			return c.Text
		}
	}
	return ""
}
