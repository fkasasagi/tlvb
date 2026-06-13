// Package llm centralises how TLVB reaches an LLM at runtime.
//
// TLVB is API-first: when credentials are present in the environment, every
// LLM-using tier (Tier 1A rule build, Tier 1B, Tier 2, and the legacy agent
// runner) goes through a hosted Messages API. Two providers are supported:
//
//   - Anthropic API     — ANTHROPIC_API_KEY
//   - Vertex AI         — a GCP service-account key (Anthropic on Vertex)
//
// If both are configured the Anthropic API wins. If neither is configured the
// local `claude` CLI is used as a hidden fallback (no setup, but not part of
// the documented/supported surface).
//
// Resolution is read from the process environment, which `tlvb` populates from
// .env.local at startup (see internal/common.LoadDotEnv). So an operator only
// has to drop the relevant keys into .env.local — no flags, no per-tier wiring.
package llm

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

// Kind identifies which transport Resolve selected.
type Kind string

const (
	KindAnthropic Kind = "anthropic" // direct Anthropic Messages API (x-api-key)
	KindVertex    Kind = "vertex"    // Anthropic on Vertex AI (GCP SA bearer token)
	KindCLI       Kind = "cli"       // hidden local `claude` CLI fallback
)

const (
	// AnthropicMessagesURL is the direct Messages API endpoint. Kept here so the
	// per-tier clients share one constant, but each tier still owns its own
	// request/response structs (and test seams) for the direct path.
	AnthropicMessagesURL = "https://api.anthropic.com/v1/messages"
	// AnthropicVersionHeader is the anthropic-version header for the direct API.
	AnthropicVersionHeader = "2023-06-01"
	// VertexAnthropicVersion is the body field Vertex requires in place of a
	// top-level `model` (the model is named in the URL path instead).
	VertexAnthropicVersion = "vertex-2023-10-16"

	// DefaultModel is used when an API path needs a model but none was set.
	DefaultModel = "claude-opus-4-8"
	// DefaultRegion is the Vertex region when CLOUD_ML_REGION is unset.
	DefaultRegion = "us-east5"
)

// Transport is an immutable, resolved description of how to reach the LLM.
type Transport struct {
	Kind    Kind
	apiKey  string // anthropic
	project string // vertex
	region  string // vertex
	vmodel  string // vertex model override (TLVB_VERTEX_MODEL), may be ""
	tok     *saTokenSource
}

// Active reports whether an API transport (Anthropic or Vertex) is configured.
// When false, callers fall back to the hidden CLI.
func (t *Transport) Active() bool { return t.Kind == KindAnthropic || t.Kind == KindVertex }

// APIKey returns the Anthropic API key (empty unless Kind == KindAnthropic).
func (t *Transport) APIKey() string { return t.apiKey }

// Label is a short transport name for audit/logging.
func (t *Transport) Label() string { return string(t.Kind) }

// Resolve picks the transport from the environment. Priority:
//
//  1. ANTHROPIC_API_KEY        -> Anthropic API
//  2. Vertex service account   -> Vertex AI
//  3. neither                  -> hidden CLI fallback
func Resolve() *Transport {
	if k := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")); k != "" {
		return &Transport{Kind: KindAnthropic, apiKey: k}
	}
	if t := resolveVertex(); t != nil {
		return t
	}
	return &Transport{Kind: KindCLI}
}

var (
	vertexMu      sync.Mutex
	vertexCached  *Transport
	vertexChecked bool
)

// resolveVertex builds a Vertex transport from a service-account key, memoised
// so the private key is parsed once per process. Returns nil if Vertex is not
// (validly) configured.
func resolveVertex() *Transport {
	vertexMu.Lock()
	defer vertexMu.Unlock()
	if vertexChecked {
		return vertexCached
	}
	vertexChecked = true

	b, ok := loadServiceAccountJSON()
	if !ok {
		return nil
	}
	sa, key, err := parseServiceAccount(b)
	if err != nil {
		return nil
	}
	project := firstNonEmpty(
		os.Getenv("ANTHROPIC_VERTEX_PROJECT_ID"),
		os.Getenv("GOOGLE_CLOUD_PROJECT"),
		sa.ProjectID,
	)
	if project == "" {
		return nil
	}
	region := firstNonEmpty(
		os.Getenv("CLOUD_ML_REGION"),
		os.Getenv("ANTHROPIC_VERTEX_REGION"),
		DefaultRegion,
	)
	vertexCached = &Transport{
		Kind:    KindVertex,
		project: project,
		region:  region,
		vmodel:  strings.TrimSpace(os.Getenv("TLVB_VERTEX_MODEL")),
		tok:     newSATokenSource(sa, key),
	}
	return vertexCached
}

// loadServiceAccountJSON reads the SA key from inline JSON or a file path.
func loadServiceAccountJSON() ([]byte, bool) {
	if inline := strings.TrimSpace(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON")); inline != "" {
		return []byte(inline), true
	}
	if p := strings.TrimSpace(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")); p != "" {
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			return b, true
		}
	}
	return nil, false
}

// VertexModel maps a bare Anthropic model id to the Vertex publisher model id.
// The exact Vertex model string depends on region/availability, so it is
// overridable wholesale via TLVB_VERTEX_MODEL; otherwise the bare id is used.
func (t *Transport) VertexModel(bare string) string {
	if t.vmodel != "" {
		return t.vmodel
	}
	if bare == "" {
		return DefaultModel
	}
	return bare
}

// VertexURL builds the rawPredict endpoint for a given (bare) model. The
// special region "global" uses the non-regional host (aiplatform.googleapis.com
// with locations/global) — many projects' Claude access is provisioned only on
// the global endpoint.
func (t *Transport) VertexURL(bareModel string) string {
	m := url.PathEscape(t.VertexModel(bareModel))
	host := t.region + "-aiplatform.googleapis.com"
	if t.region == "global" {
		host = "aiplatform.googleapis.com"
	}
	return fmt.Sprintf(
		"https://%s/v1/projects/%s/locations/%s/publishers/anthropic/models/%s:rawPredict",
		host, t.project, t.region, m,
	)
}

// ApplyAuth sets Content-Type and the kind-appropriate auth headers on req.
// For Vertex it mints/refreshes the OAuth token (may do a network round-trip).
func (t *Transport) ApplyAuth(ctx context.Context, req *http.Request) error {
	req.Header.Set("Content-Type", "application/json")
	switch t.Kind {
	case KindAnthropic:
		req.Header.Set("x-api-key", t.apiKey)
		req.Header.Set("anthropic-version", AnthropicVersionHeader)
	case KindVertex:
		tok, err := t.tok.token(ctx)
		if err != nil {
			return fmt.Errorf("vertex auth: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	default:
		return fmt.Errorf("transport %q has no HTTP auth", t.Kind)
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}
