package llm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Vertex AI service-account auth, implemented against the stdlib only so the
// dep graph stays tight (same rationale as the hand-rolled Messages client in
// internal/agents/anthropic.go). We mint a short-lived OAuth access token from
// the SA key via the JWT-bearer grant and cache it until it nears expiry.

const vertexScope = "https://www.googleapis.com/auth/cloud-platform"

// serviceAccount is the subset of a GCP service-account JSON key we use.
type serviceAccount struct {
	Type        string `json:"type"`
	ProjectID   string `json:"project_id"`
	PrivateKey  string `json:"private_key"`
	ClientEmail string `json:"client_email"`
	TokenURI    string `json:"token_uri"`
}

// saTokenSource mints and caches OAuth access tokens for one service account.
type saTokenSource struct {
	sa   *serviceAccount
	key  *rsa.PrivateKey
	http *http.Client

	mu  sync.Mutex
	tok string
	exp time.Time
}

func newSATokenSource(sa *serviceAccount, key *rsa.PrivateKey) *saTokenSource {
	return &saTokenSource{sa: sa, key: key, http: &http.Client{Timeout: 30 * time.Second}}
}

// token returns a valid access token, refreshing when within 60s of expiry.
func (s *saTokenSource) token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tok != "" && time.Until(s.exp) > 60*time.Second {
		return s.tok, nil
	}
	tok, ttl, err := s.mint(ctx)
	if err != nil {
		return "", err
	}
	s.tok = tok
	s.exp = time.Now().Add(time.Duration(ttl) * time.Second)
	return s.tok, nil
}

// mint performs one JWT-bearer token exchange against the SA's token endpoint.
func (s *saTokenSource) mint(ctx context.Context) (string, int, error) {
	now := time.Now()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{
		"iss":   s.sa.ClientEmail,
		"scope": vertexScope,
		"aud":   s.sa.TokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	})
	if err != nil {
		return "", 0, fmt.Errorf("marshal jwt claims: %w", err)
	}
	signingInput := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", 0, fmt.Errorf("sign jwt: %w", err)
	}
	assertion := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)
	req, err := http.NewRequestWithContext(ctx, "POST", s.sa.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.http.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("token endpoint: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", 0, fmt.Errorf("token endpoint %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &tr); err != nil {
		return "", 0, fmt.Errorf("parse token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", 0, fmt.Errorf("token endpoint returned empty access_token")
	}
	if tr.ExpiresIn <= 0 {
		tr.ExpiresIn = 3600
	}
	return tr.AccessToken, tr.ExpiresIn, nil
}

// parseServiceAccount validates a SA JSON key and parses its RSA private key.
func parseServiceAccount(b []byte) (*serviceAccount, *rsa.PrivateKey, error) {
	var sa serviceAccount
	if err := json.Unmarshal(b, &sa); err != nil {
		return nil, nil, fmt.Errorf("parse service-account json: %w", err)
	}
	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, nil, fmt.Errorf("service-account json missing client_email/private_key")
	}
	if sa.TokenURI == "" {
		sa.TokenURI = "https://oauth2.googleapis.com/token"
	}
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return nil, nil, fmt.Errorf("service-account private_key is not valid PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("service-account private key is not RSA")
		}
		return &sa, rsaKey, nil
	}
	// Fall back to PKCS#1 for older keys.
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return &sa, k, nil
	}
	return nil, nil, fmt.Errorf("parse service-account private key (tried PKCS#8 and PKCS#1)")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
