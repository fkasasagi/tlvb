package rulebuild

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/rulesrepo"
)

const (
	anthropicAPIURL  = "https://api.anthropic.com/v1/messages"
	anthropicVersion = "2023-06-01"
)

// AnthropicBuilder uses Anthropic Messages API to convert rules to SQL.
//
// The system prompt is sent with cache_control: ephemeral so subsequent calls
// in the same build run only pay 10% on the cached portion.
type AnthropicBuilder struct {
	APIKey string
	Model  string
	// SignatureModel overrides the cache-signature model id (ModelID),
	// decoupling it from the execution Model — see ClaudeCodeBuilder.
	// Empty = use Model.
	SignatureModel string
	MaxTokens      int
	Timeout        time.Duration
	SchemaDoc      string // injected into the system prompt

	httpClient *http.Client
}

// NewAnthropicBuilder constructs a builder with sane defaults.
func NewAnthropicBuilder(apiKey, model, schemaDoc string) *AnthropicBuilder {
	if model == "" {
		model = "claude-sonnet-4-6"
	}
	return &AnthropicBuilder{
		APIKey:    apiKey,
		Model:     model,
		MaxTokens: 1500, // SQL outputs are short; 1500 is generous
		Timeout:   60 * time.Second,
		SchemaDoc: schemaDoc,
	}
}

func (b *AnthropicBuilder) ModelID() string {
	if b.SignatureModel != "" {
		return b.SignatureModel
	}
	return b.Model
}

func (b *AnthropicBuilder) BuildSQL(ctx context.Context, rule rulesrepo.RawRule, schemaDoc string) (*BuiltSQL, error) {
	if b.APIKey == "" {
		return nil, fmt.Errorf("AnthropicBuilder: APIKey is empty")
	}
	if b.httpClient == nil {
		b.httpClient = &http.Client{Timeout: b.Timeout}
	}
	doc := schemaDoc
	if doc == "" {
		doc = b.SchemaDoc
	}
	if doc == "" {
		return nil, fmt.Errorf("AnthropicBuilder: schemaDoc not set")
	}

	systemPrompt := strings.Replace(SystemPrompt, "{SCHEMA_DOC}", doc, 1)
	userMsg := BuildUserMessage(rule)

	body := msgRequest{
		Model:     b.Model,
		MaxTokens: b.MaxTokens,
		System: []sysBlock{
			{Type: "text", Text: systemPrompt, CacheControl: &cacheControl{Type: "ephemeral"}},
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
	req.Header.Set("x-api-key", b.APIKey)
	req.Header.Set("anthropic-version", anthropicVersion)

	resp, err := b.httpClient.Do(req)
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
	text := mr.firstText()
	if text == "" {
		return nil, fmt.Errorf("LLM returned no text content")
	}

	out, err := parseBuilderJSON(text)
	if err != nil {
		return nil, fmt.Errorf("parse LLM output: %w (raw: %q)", err, truncate(text, 400))
	}
	if err := validateSQL(out.SQL); err != nil {
		return nil, fmt.Errorf("SQL validation: %w", err)
	}
	out.ModelID = mr.Model
	out.InputTokens = mr.Usage.InputTokens
	out.OutputTokens = mr.Usage.OutputTokens
	out.CacheReadTokens = mr.Usage.CacheReadInputTokens
	return out, nil
}

// parseBuilderJSON extracts the JSON object the LLM is supposed to return.
// We strip optional markdown fences defensively because Claude occasionally
// wraps JSON in ```json blocks despite the prompt forbidding it.
func parseBuilderJSON(text string) (*BuiltSQL, error) {
	s := strings.TrimSpace(text)
	// Strip markdown fences.
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	s = strings.TrimSpace(s)

	// If the LLM included prose before the JSON, find the first '{'.
	if i := strings.Index(s, "{"); i > 0 {
		s = s[i:]
	}
	// And trim anything after the matching '}'.
	if j := strings.LastIndex(s, "}"); j >= 0 && j < len(s)-1 {
		s = s[:j+1]
	}

	var raw struct {
		SQL                string   `json:"sql"`
		PrefilterArtifacts []string `json:"prefilter_artifacts"`
		Notes              string   `json:"notes"`
	}
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		return nil, err
	}
	return &BuiltSQL{
		SQL:                strings.TrimSpace(raw.SQL),
		PrefilterArtifacts: raw.PrefilterArtifacts,
		Notes:              raw.Notes,
	}, nil
}

// validateSQL rejects obviously dangerous statements. The empty-SQL case is
// allowed because that's how the LLM tells us "this rule isn't expressible".
//
// Detection patterns frequently embed words like "delete" / "create" inside
// SQL string literals (e.g. ILIKE '%vssadmin delete shadows%'). Those are
// fine. We strip quoted strings BEFORE the dangerous-keyword check so only
// statement-level uses are flagged.
var (
	dangerousSQL    = regexp.MustCompile(`(?i)\b(insert|update|delete|drop|alter|attach|detach|create|pragma|copy|export)\b`)
	singleQuoteLits = regexp.MustCompile(`'(?:[^']|'')*'`) // matches 'foo', 'it''s', etc.
)

func validateSQL(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil // intentional "no SQL" return from the LLM
	}
	lower := strings.ToLower(s)
	if !strings.HasPrefix(lower, "select ") && !strings.HasPrefix(lower, "with ") {
		return fmt.Errorf("SQL must start with SELECT or WITH")
	}
	stripped := singleQuoteLits.ReplaceAllString(s, "''")
	if dangerousSQL.MatchString(stripped) {
		return fmt.Errorf("SQL contains disallowed keyword (insert/update/delete/drop/alter/attach/create/pragma/copy/export) at statement level")
	}
	if !strings.Contains(s, "case_id") {
		return fmt.Errorf("SQL missing required case_id predicate")
	}
	if strings.HasSuffix(s, ";") {
		return fmt.Errorf("SQL must not end with semicolon")
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ----------------------------------------------------------------------------
// Anthropic API wire types (subset; mirrors internal/agents/anthropic.go)
// ----------------------------------------------------------------------------

type msgRequest struct {
	Model     string     `json:"model"`
	MaxTokens int        `json:"max_tokens"`
	System    []sysBlock `json:"system,omitempty"`
	Messages  []msgItem  `json:"messages"`
}

type sysBlock struct {
	Type         string        `json:"type"`
	Text         string        `json:"text"`
	CacheControl *cacheControl `json:"cache_control,omitempty"`
}

type cacheControl struct {
	Type string `json:"type"`
}

type msgItem struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type msgResponse struct {
	ID         string    `json:"id"`
	Model      string    `json:"model"`
	Role       string    `json:"role"`
	StopReason string    `json:"stop_reason"`
	Content    []content `json:"content"`
	Usage      usage     `json:"usage"`
}

type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type usage struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
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

func (m *msgResponse) firstText() string {
	for _, c := range m.Content {
		if c.Type == "text" {
			return c.Text
		}
	}
	return ""
}
