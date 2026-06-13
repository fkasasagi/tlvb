package llm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func resetVertexCache() {
	vertexMu.Lock()
	vertexChecked = false
	vertexCached = nil
	vertexMu.Unlock()
}

// saJSON builds a minimal service-account key JSON whose token endpoint is
// tokenURL, signed by a freshly generated RSA key (also returned).
func saJSON(t *testing.T, tokenURL string) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	js := fmt.Sprintf(
		`{"type":"service_account","project_id":"proj-1","private_key":%q,"client_email":"svc@proj-1.iam.gserviceaccount.com","token_uri":%q}`,
		string(pemBytes), tokenURL,
	)
	return js, key
}

func TestResolvePrefersAnthropicKey(t *testing.T) {
	resetVertexCache()
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	// Vertex creds present too — Anthropic must still win.
	js, _ := saJSON(t, "https://oauth2.example/token")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", js)

	tr := Resolve()
	if tr.Kind != KindAnthropic {
		t.Fatalf("Kind = %q, want anthropic (key must outrank vertex)", tr.Kind)
	}
	if !tr.Active() || tr.APIKey() != "sk-ant-test" {
		t.Fatalf("anthropic transport not wired: active=%v key=%q", tr.Active(), tr.APIKey())
	}
}

func TestResolveFallsBackToCLI(t *testing.T) {
	resetVertexCache()
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", "")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

	tr := Resolve()
	if tr.Kind != KindCLI {
		t.Fatalf("Kind = %q, want cli when nothing configured", tr.Kind)
	}
	if tr.Active() {
		t.Fatalf("cli transport must not report Active()")
	}
}

func TestResolveVertexAndMintToken(t *testing.T) {
	resetVertexCache()

	var gotAssertion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotAssertion = r.FormValue("assertion")
		if r.FormValue("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("grant_type = %q", r.FormValue("grant_type"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-123","expires_in":3600}`))
	}))
	defer srv.Close()

	js, key := saJSON(t, srv.URL)
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", js)
	t.Setenv("CLOUD_ML_REGION", "us-central1")
	t.Setenv("TLVB_VERTEX_MODEL", "")

	tr := Resolve()
	if tr.Kind != KindVertex {
		t.Fatalf("Kind = %q, want vertex", tr.Kind)
	}
	if tr.project != "proj-1" || tr.region != "us-central1" {
		t.Fatalf("project/region = %q/%q, want proj-1/us-central1", tr.project, tr.region)
	}

	// URL shape: model is named in the path.
	url := tr.VertexURL("claude-opus-4-8")
	want := "https://us-central1-aiplatform.googleapis.com/v1/projects/proj-1/locations/us-central1/publishers/anthropic/models/claude-opus-4-8:rawPredict"
	if url != want {
		t.Fatalf("VertexURL = %q\nwant %q", url, want)
	}

	// ApplyAuth mints a token (round-trips to the test token endpoint) and sets
	// a Bearer header. The endpoint verifies the JWT was signed by our key.
	req, _ := http.NewRequest("POST", url, nil)
	if err := tr.ApplyAuth(context.Background(), req); err != nil {
		t.Fatalf("ApplyAuth: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer tok-123" {
		t.Fatalf("Authorization = %q, want Bearer tok-123", got)
	}
	if gotAssertion == "" {
		t.Fatal("token endpoint never received an assertion")
	}
	// Verify the assertion's RS256 signature against the SA public key.
	parts := strings.Split(gotAssertion, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion not a 3-part JWT: %q", gotAssertion)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("JWT signature does not verify: %v", err)
	}
}

func TestVertexURLGlobal(t *testing.T) {
	resetVertexCache()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"t","expires_in":3600}`))
	}))
	defer srv.Close()
	js, _ := saJSON(t, srv.URL)
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", js)
	t.Setenv("CLOUD_ML_REGION", "global")
	t.Setenv("TLVB_VERTEX_MODEL", "")

	tr := Resolve()
	got := tr.VertexURL("claude-sonnet-4-5@20250929")
	want := "https://aiplatform.googleapis.com/v1/projects/proj-1/locations/global/publishers/anthropic/models/claude-sonnet-4-5@20250929:rawPredict"
	if got != want {
		t.Fatalf("global VertexURL = %q\nwant %q", got, want)
	}
}

func TestVertexModelOverride(t *testing.T) {
	resetVertexCache()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"t","expires_in":3600}`))
	}))
	defer srv.Close()
	js, _ := saJSON(t, srv.URL)
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", js)
	t.Setenv("TLVB_VERTEX_MODEL", "claude-opus-4-8@20260101")

	tr := Resolve()
	if got := tr.VertexModel("claude-sonnet-4-6"); got != "claude-opus-4-8@20260101" {
		t.Fatalf("VertexModel override = %q", got)
	}
}
