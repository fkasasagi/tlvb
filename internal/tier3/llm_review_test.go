package tier3

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tlvb/tlvb/internal/tier2"
)

func TestExtractJSONObject(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"a":1}`, `{"a":1}`},
		{"```json\n{\"a\":1}\n```", `{"a":1}`},
		{"here you go:\n{\"contradictions\":[]}\nthanks", `{"contradictions":[]}`},
		{"no json here", ""},
	}
	for _, c := range cases {
		if got := extractJSONObject(c.in); got != c.want {
			t.Errorf("extractJSONObject(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseConsistencyReview(t *testing.T) {
	// A grounded item becomes one advisory issue; an empty/ungrounded item is
	// dropped; an all-clear returns nothing.
	raw := `{"contradictions":[
		{"severity":"high","where":"Intrusion Path","conflicts_with":"Conclusion","claim":"入口は不明","why":"結論は総当たり侵入と述べている","grounding":"finding TLVB-BRUTEFORCE-4625"},
		{"severity":"low","where":"","claim":"","why":"","grounding":""}
	]}`
	issues, err := parseConsistencyReview(raw)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(issues) != 1 {
		t.Fatalf("want 1 grounded issue, got %d", len(issues))
	}
	is := issues[0]
	if is.Severity != "advisory" || is.Source != "llm" {
		t.Errorf("LLM item must be advisory/llm, got %s/%s", is.Severity, is.Source)
	}
	if !strings.Contains(is.Detail, "入口は不明") || !strings.Contains(is.Detail, "Intrusion Path") {
		t.Errorf("detail should carry claim + where, got %q", is.Detail)
	}
	if is.Grounding == "" || is.ConflictsWith == "" {
		t.Errorf("grounding/conflicts_with should be preserved, got %+v", is)
	}
}

func TestParseConsistencyReview_Clean(t *testing.T) {
	issues, err := parseConsistencyReview(`{"contradictions":[]}`)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(issues) != 0 {
		t.Errorf("clean report should yield 0 issues, got %d", len(issues))
	}
	if _, err := parseConsistencyReview("garbage no json"); err == nil {
		t.Error("expected error on non-JSON output")
	}
}

func TestConsistencyModel(t *testing.T) {
	for in, want := range map[string]string{
		"":                    "claude-opus-4-8",
		"claude-opus-4-8[1m]": "claude-opus-4-8",
		"claude-sonnet-4-6":   "claude-sonnet-4-6",
	} {
		if got := consistencyModel(in); got != want {
			t.Errorf("consistencyModel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildReportDigest(t *testing.T) {
	cs := bruteForceEntryCS()
	cs.ExecBrief = "WS01 からの総当たりで管理者を侵害"
	cs.Clusters[1].FindingRefs = []tier2.FindingRef{
		{Source: "heuristic", RuleID: "TLVB-BRUTEFORCE-4625", Title: "Password brute force burst", Severity: "high"},
	}
	cs.TotalFindings = 7
	d := buildReportDigest(cs, &enrichment{}, "ja", "")
	for _, want := range []string{
		"EXECUTIVE BRIEF", "INTRUSION PATH (derived)", "FINDINGS (ground truth)",
		"TLVB-BRUTEFORCE-4625", "MITRE CONFIRMED", "T1110.001",
		"TOTAL FINDINGS", "RECOMMENDATIONS (derived)",
	} {
		if !strings.Contains(d, want) {
			t.Errorf("digest missing %q\n---\n%s", want, d)
		}
	}
}

// The advisory prompt must explicitly name the high-FP patterns we deliberately
// route to the LLM (dwell-time, containment, counts, scope) so the model is
// steered to look for them.
func TestConsistencySystemPrompt_NamesAdvisoryPatterns(t *testing.T) {
	p := consistencySystemPrompt("ja")
	for _, want := range []string{"DWELL TIME", "CONTAINMENT", "COUNT vs TOTAL FINDINGS", "HOST/ACCOUNT vs AFFECTED SCOPE", "PITFALL"} {
		if !strings.Contains(p, want) {
			t.Errorf("system prompt should name pattern %q", want)
		}
	}
}

func TestTruncateRuneSafe(t *testing.T) {
	if got := truncate("あいうえお", 3); got != "あいう…" {
		t.Errorf("truncate multibyte = %q", got)
	}
	if got := truncate("abc", 10); got != "abc" {
		t.Errorf("no-trunc = %q", got)
	}
}

// TestLLMConsistencyReview_APIRoundTrip exercises the full advisory path through
// the direct Anthropic API (transport → request → response parse → JSON extract
// → advisory issue) against an httptest server. No real LLM, no cost.
func TestLLMConsistencyReview_APIRoundTrip(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "test-key") // force the Anthropic transport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("x-api-key"); got != "test-key" {
			t.Errorf("x-api-key = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "FINDINGS (ground truth)") {
			t.Errorf("request body should carry the digest, got %s", truncate(string(body), 120))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"{\"contradictions\":[{\"severity\":\"high\",\"where\":\"Intrusion Path\",\"conflicts_with\":\"Conclusion\",\"claim\":\"入口不明と記載\",\"why\":\"結論は総当たり侵入と述べている\",\"grounding\":\"T1110.001\"}]}"}],"usage":{"input_tokens":1200,"output_tokens":80}}`))
	}))
	defer srv.Close()
	old := consistencyAPIURL
	consistencyAPIURL = srv.URL
	defer func() { consistencyAPIURL = old }()

	issues, meta := llmConsistencyReview(context.Background(), Config{Language: "ja"}, bruteForceEntryCS(), &enrichment{})
	if meta == nil || !meta.Ran {
		t.Fatalf("meta should record a successful run, got %+v", meta)
	}
	if meta.InputTokens != 1200 || meta.OutputTokens != 80 {
		t.Errorf("usage not recorded: %+v", meta)
	}
	if len(issues) != 1 || issues[0].Severity != "advisory" || issues[0].Source != "llm" {
		t.Fatalf("want 1 advisory/llm issue, got %+v", issues)
	}
	if !strings.Contains(issues[0].Detail, "入口不明") {
		t.Errorf("detail should carry the claim, got %q", issues[0].Detail)
	}
}
