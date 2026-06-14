package tier3

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/llm"
	"github.com/tlvb/tlvb/internal/tier2"
)

// llm_review.go is the ADVISORY, opt-in half of the report consistency gate. The
// deterministic gate (consistency.go) catches contradiction CLASSES it can
// pattern-match; this pass hands the fully-assembled report — the same prose a
// human reads — plus the findings (ground truth) to an LLM and asks it to flag
// FREE-TEXT internal contradictions: a claim in one section that another section
// or the evidence refutes, of a shape no fixed rule anticipated.
//
// It is advisory by construction: its findings never block the report and never
// auto-edit it. They are surfaced for Review Gate 2 so a human decides. The
// model is told the findings are the source of truth and to GROUND each call
// (裏取り) — an item it cannot tie to a section + the evidence is dropped. This
// keeps the non-deterministic layer honest without letting it rewrite the
// deterministic conclusions.

const (
	consistencyLLMTimeout   = 4 * time.Minute
	consistencyMaxTokens    = 8000
	consistencyDefaultModel = "claude-opus-4-8"
	consistencyAPIVersion   = "2023-06-01"
	// narrativeCap bounds each cluster narrative in the digest so a pathological
	// case cannot blow up the prompt; contradictions live in the opening claims.
	narrativeCap = 2400
)

// consistencyAPIURL is a var (not const) so tests can point the direct-API path
// at an httptest server.
var consistencyAPIURL = "https://api.anthropic.com/v1/messages"

// llmConsistencyReview runs the advisory pass and returns the advisory issues
// plus an audit. It is best-effort: a missing transport or any error yields zero
// issues and a populated meta.Error — never a hard failure.
func llmConsistencyReview(ctx context.Context, cfg Config, cs tier2.CaseSynthesis, en *enrichment) ([]ConsistencyIssue, *LLMReviewMeta) {
	t := llm.Resolve()
	meta := &LLMReviewMeta{Requested: true, Transport: t.Label(), Model: consistencyModel(cfg.Model)}

	sys := consistencySystemPrompt(cfg.Language)
	digest := buildReportDigest(cs, en, cfg.Language)

	out, err := callConsistencyLLM(ctx, cfg, t, sys, digest)
	if err != nil {
		meta.Error = truncate(err.Error(), 300)
		return nil, meta
	}
	meta.Ran = true
	meta.InputTokens = out.inputTokens
	meta.OutputTokens = out.outputTokens
	meta.CostUSD = out.costUSD

	issues, perr := parseConsistencyReview(out.text)
	if perr != nil {
		meta.Error = truncate(perr.Error(), 300)
		return nil, meta
	}
	return issues, meta
}

// consistencyModel strips a claude-code routing suffix ("[1m]") and defaults to
// Opus 4.8.
func consistencyModel(m string) string {
	m = strings.TrimSpace(m)
	if i := strings.IndexByte(m, '['); i >= 0 {
		m = strings.TrimSpace(m[:i])
	}
	if m == "" {
		return consistencyDefaultModel
	}
	return m
}

// consistencySystemPrompt instructs the reviewer. Kept in English (the model
// reasons in it regardless) but it must WRITE its findings in the report's
// language so the advisory reads alongside the report.
func consistencySystemPrompt(lang string) string {
	outLang := "Japanese"
	if strings.EqualFold(lang, "en") {
		outLang = "English"
	}
	return `You are a meticulous DFIR report reviewer. You are given a forensic incident report (its prose sections, derived sections, MITRE matrix, timeline notes) and the list of underlying FINDINGS, which are the ground truth.

Your ONLY job is to find INTERNAL CONTRADICTIONS:
- two statements in the report that cannot both be true (e.g. "the entry point is unknown" vs "the attacker broke in via brute force from WS01"); or
- a statement in the report's prose that the FINDINGS directly refute (e.g. asserting a tool/technique as fact that no finding supports, or naming a host/account/time that conflicts with the findings).

PAY PARTICULAR ATTENTION to these recurring patterns (still apply the conservative, grounded rules below — only report a GENUINE conflict, and respect each pitfall):
1. DWELL TIME vs UNRELIABLE TIMELINE — the prose states a specific dwell time or duration as fact (e.g. "the attacker was present for 3 days", "約40分後") while the TIMELINE RELIABILITY section says the timeline is unreliable / the clock was rolled back. A hard duration cannot be asserted on an unreliable clock. (A duration that is explicitly hedged as approximate/uncertain is NOT a contradiction.)
2. CONTAINMENT vs RECOMMENDATIONS — the summary claims containment/eradication is already complete ("the threat was contained/removed/isolated") while the RECOMMENDATIONS still tell the reader to isolate / contain / reset credentials. Both cannot be true. (A summary that says containment status is unknown is NOT a contradiction.)
3. COUNT vs TOTAL FINDINGS — a count in the prose contradicts the authoritative TOTAL FINDINGS / the FINDINGS list. PITFALL: event counts ("20 failed logons", "3 processes spawned") are NOT the finding count — they describe events, not findings. Only flag a real mismatch of the SAME quantity; never flag an event-count-vs-finding-count difference.
4. HOST/ACCOUNT vs AFFECTED SCOPE — a host or account the prose names as compromised/affected is absent from the AFFECTED SCOPE, or the scope lists one the narrative never ties to the attack. PITFALL: a host named only as the SOURCE/origin of an attack, or one explicitly excluded as benign/uncertain, is NOT a scope omission.

STRICT RULES:
- Report a contradiction ONLY when two specific statements genuinely conflict. Do NOT report mere incompleteness, open questions, hedged language, or things that are simply "not mentioned". Missing information is not a contradiction.
- GROUND every item: name the two conflicting statements (which sections) and, when the conflict is with evidence, cite the finding(s). If you cannot ground it, do not report it.
- Be conservative. A report with no real contradiction must return an empty list. False alarms are worse than misses here.
- The FINDINGS are authoritative. The prose is what you check against them and against itself.

Return STRICT JSON only, no prose, no markdown fences:
{"contradictions":[{"severity":"high|medium|low","where":"section A","conflicts_with":"section B or finding","claim":"the statement","why":"why the two cannot both be true","grounding":"finding ids / section names that corroborate the call"}]}

Write the "claim", "why", "where", "conflicts_with" and "grounding" values in ` + outLang + `. Return {"contradictions":[]} if the report is internally consistent.`
}

// buildReportDigest assembles the human-facing report text the reviewer checks,
// plus the findings ground-truth block. It mirrors what the renderer shows the
// reader (including the DERIVED sections — intrusion path / scope / reco — since
// those are exactly where a derivation can drift from the prose).
func buildReportDigest(cs tier2.CaseSynthesis, en *enrichment, lang string) string {
	var b strings.Builder
	w := func(h, body string) {
		if strings.TrimSpace(body) == "" {
			return
		}
		b.WriteString("## ")
		b.WriteString(h)
		b.WriteString("\n")
		b.WriteString(strings.TrimSpace(body))
		b.WriteString("\n\n")
	}

	w("EXECUTIVE BRIEF", cs.ExecBrief)
	tech := cs.TechSummary
	if tech == "" {
		tech = cs.OverallStory
	}
	w("TECHNICAL SUMMARY", tech)
	w("INTRUSION PATH (derived)", deriveIntrusionPath(cs, lang, nil))
	// Authoritative finding count for pattern #3 (count vs total findings).
	w("TOTAL FINDINGS", fmt.Sprintf("%d", cs.TotalFindings))

	if sv := deriveAffectedScope(cs, en, lang); sv != nil {
		var sb strings.Builder
		if len(sv.Hosts) > 0 {
			sb.WriteString("hosts: " + strings.Join(sv.Hosts, ", ") + "\n")
		}
		if len(sv.Accounts) > 0 {
			sb.WriteString("accounts: " + strings.Join(sv.Accounts, ", ") + "\n")
		}
		if len(sv.DataAtRisk) > 0 {
			sb.WriteString("data at risk: " + strings.Join(sv.DataAtRisk, "; ") + "\n")
		}
		w("AFFECTED SCOPE (derived)", sb.String())
	}

	// Recommendations for pattern #2 (containment-complete vs still-recommend-isolate).
	if rv := deriveRecommendations(cs, lang); rv != nil {
		var rb strings.Builder
		if len(rv.Containment) > 0 {
			rb.WriteString("containment: " + strings.Join(rv.Containment, "; ") + "\n")
		}
		if len(rv.Eradication) > 0 {
			rb.WriteString("eradication: " + strings.Join(rv.Eradication, "; ") + "\n")
		}
		if len(rv.Recovery) > 0 {
			rb.WriteString("recovery: " + strings.Join(rv.Recovery, "; ") + "\n")
		}
		w("RECOMMENDATIONS (derived)", rb.String())
	}

	if cs.TimelineReliability != "" {
		w("TIMELINE RELIABILITY", cs.TimelineReliability+"\n"+strings.Join(cs.TimelineNotes, "\n"))
	}

	// MITRE matrices — the confirmed vs unconfirmed split is a common place for a
	// prose claim to contradict the authoritative matrix.
	if len(cs.MITREMapping) > 0 {
		var ids []string
		for _, m := range cs.MITREMapping {
			ids = append(ids, m.Technique+"("+m.Tactic+")")
		}
		w("MITRE CONFIRMED", strings.Join(ids, ", "))
	}
	if len(cs.MITREUnconfirmed) > 0 {
		var ids []string
		for _, m := range cs.MITREUnconfirmed {
			ids = append(ids, m.Technique)
		}
		w("MITRE UNCONFIRMED (not asserted)", strings.Join(ids, ", "))
	}
	if len(cs.MITREDemotionNotes) > 0 {
		w("MITRE DEMOTION NOTES", strings.Join(cs.MITREDemotionNotes, "\n"))
	}
	if len(cs.UngroundedMentions) > 0 {
		w("UNGROUNDED MENTIONS (flagged, not asserted)", strings.Join(cs.UngroundedMentions, ", "))
	}

	// Per-cluster narratives + their finding backbone.
	for _, c := range cs.Clusters {
		var cb strings.Builder
		cb.WriteString("phase: " + c.AttackPhase + "\n")
		cb.WriteString(truncate(c.Narrative, narrativeCap) + "\n")
		if len(c.MITRETechniques) > 0 {
			cb.WriteString("techniques: " + strings.Join(c.MITRETechniques, ", ") + "\n")
		}
		w(fmt.Sprintf("CLUSTER %d NARRATIVE", c.ID), cb.String())
	}

	// FINDINGS ground truth — the evidence backbone, deduplicated.
	b.WriteString("## FINDINGS (ground truth)\n")
	seen := map[string]bool{}
	for _, c := range cs.Clusters {
		for _, f := range c.FindingRefs {
			key := f.Source + "/" + f.RuleID + "/" + f.Title
			if seen[key] {
				continue
			}
			seen[key] = true
			b.WriteString(fmt.Sprintf("- [%s] %s (%s/%s)\n",
				orStr(f.Severity, "?"), f.Title, f.Source, f.RuleID))
		}
	}
	return b.String()
}

// consistencyResult is the normalised return of one consistency LLM call.
type consistencyResult struct {
	text         string
	inputTokens  int
	outputTokens int
	costUSD      float64
}

// callConsistencyLLM dispatches one call to whichever transport is configured.
func callConsistencyLLM(ctx context.Context, cfg Config, t *llm.Transport, sys, user string) (*consistencyResult, error) {
	switch t.Kind {
	case llm.KindAnthropic:
		return callConsistencyAPI(ctx, cfg, consistencyAPIURL, false, t, sys, user)
	case llm.KindVertex:
		return callConsistencyAPI(ctx, cfg, t.VertexURL(consistencyModel(cfg.Model)), true, t, sys, user)
	default:
		return callConsistencyCLI(ctx, cfg, sys, user)
	}
}

type consistencyAPIReq struct {
	Model            string              `json:"model,omitempty"`
	AnthropicVersion string              `json:"anthropic_version,omitempty"`
	MaxTokens        int                 `json:"max_tokens"`
	Thinking         map[string]string   `json:"thinking,omitempty"`
	System           string              `json:"system"`
	Messages         []map[string]string `json:"messages"`
}

type consistencyAPIResp struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// callConsistencyAPI handles both the direct Anthropic API and Vertex (model in
// the URL + anthropic_version + OAuth bearer). No prompt caching: this is a
// single one-shot call per report.
func callConsistencyAPI(ctx context.Context, cfg Config, url string, vertex bool, t *llm.Transport, sys, user string) (*consistencyResult, error) {
	body := consistencyAPIReq{
		MaxTokens: consistencyMaxTokens,
		Thinking:  map[string]string{"type": "adaptive"},
		System:    sys,
		Messages:  []map[string]string{{"role": "user", "content": user}},
	}
	if vertex {
		body.AnthropicVersion = llm.VertexAnthropicVersion
	} else {
		body.Model = consistencyModel(cfg.Model)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if vertex {
		if err := t.ApplyAuth(ctx, req); err != nil {
			return nil, err
		}
	} else {
		req.Header.Set("x-api-key", t.APIKey())
		req.Header.Set("anthropic-version", consistencyAPIVersion)
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	var ar consistencyAPIResp
	if err := json.Unmarshal(raw, &ar); err != nil {
		return nil, fmt.Errorf("parse: %w (head: %s)", err, truncate(string(raw), 200))
	}
	if resp.StatusCode != 200 {
		if ar.Error != nil && ar.Error.Message != "" {
			return nil, fmt.Errorf("llm %d %s: %s", resp.StatusCode, ar.Error.Type, ar.Error.Message)
		}
		return nil, fmt.Errorf("llm %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var sb strings.Builder
	for _, c := range ar.Content {
		if c.Type == "text" {
			sb.WriteString(c.Text)
		}
	}
	return &consistencyResult{
		text:         sb.String(),
		inputTokens:  ar.Usage.InputTokens,
		outputTokens: ar.Usage.OutputTokens,
		costUSD: float64(ar.Usage.InputTokens)*tier2CostInputPerM()/1e6 +
			float64(ar.Usage.OutputTokens)*tier2CostOutputPerM()/1e6,
	}, nil
}

// callConsistencyCLI is the hidden-CLI fallback (no API/Vertex transport).
func callConsistencyCLI(ctx context.Context, cfg Config, sys, user string) (*consistencyResult, error) {
	bin := orStr(cfg.ClaudeBinary, "claude")
	if _, err := exec.LookPath(bin); err != nil && !strings.ContainsRune(bin, '/') {
		return nil, fmt.Errorf("no API/Vertex transport and %q not on PATH", bin)
	}
	args := []string{"-p", "--output-format", "json", "--system-prompt", sys,
		"--tools", "", "--no-session-persistence", "--exclude-dynamic-system-prompt-sections"}
	if m := consistencyModel(cfg.Model); m != "" {
		args = append(args, "--model", m, "--fallback-model", m)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = strings.NewReader(user)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("exec: %w (stderr: %s)", err, truncate(stderr.String(), 200))
	}
	var out struct {
		IsError bool   `json:"is_error"`
		Result  string `json:"result"`
		Usage   struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
		TotalCostUSD float64 `json:"total_cost_usd"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("parse: %w (head: %s)", err, truncate(stdout.String(), 200))
	}
	if out.IsError {
		return nil, fmt.Errorf("claude error: %s", truncate(out.Result, 200))
	}
	return &consistencyResult{
		text:         out.Result,
		inputTokens:  out.Usage.InputTokens,
		outputTokens: out.Usage.OutputTokens,
		costUSD:      out.TotalCostUSD,
	}, nil
}

// reviewContradiction is one item the model returns.
type reviewContradiction struct {
	Severity      string `json:"severity"`
	Where         string `json:"where"`
	ConflictsWith string `json:"conflicts_with"`
	Claim         string `json:"claim"`
	Why           string `json:"why"`
	Grounding     string `json:"grounding"`
}

// parseConsistencyReview extracts the contradiction list from the model output
// (tolerating markdown fences / leading prose) and maps each grounded item to an
// advisory ConsistencyIssue. Items with no claim or no reason are dropped.
func parseConsistencyReview(text string) ([]ConsistencyIssue, error) {
	js := extractJSONObject(text)
	if js == "" {
		return nil, fmt.Errorf("no JSON object in model output")
	}
	var parsed struct {
		Contradictions []reviewContradiction `json:"contradictions"`
	}
	if err := json.Unmarshal([]byte(js), &parsed); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	var out []ConsistencyIssue
	for _, c := range parsed.Contradictions {
		claim := strings.TrimSpace(c.Claim)
		why := strings.TrimSpace(c.Why)
		if claim == "" || why == "" {
			continue // ungrounded / empty — drop it
		}
		detail := claim
		if c.Where != "" {
			detail = "[" + c.Where + "] " + detail
		}
		detail += " — " + why
		out = append(out, ConsistencyIssue{
			Code:          "llm-detected-contradiction",
			Severity:      "advisory",
			Source:        "llm",
			Detail:        detail,
			ConflictsWith: strings.TrimSpace(c.ConflictsWith),
			Grounding:     strings.TrimSpace(c.Grounding),
			Resolution:    "Review Gate 2 で人手確認 / Verify at Review Gate 2 before sign-off",
		})
	}
	return out, nil
}

// extractJSONObject returns the substring from the first '{' to the last '}',
// or "" if none — enough to survive ```json fences and stray prose.
func extractJSONObject(s string) string {
	i := strings.IndexByte(s, '{')
	j := strings.LastIndexByte(s, '}')
	if i < 0 || j <= i {
		return ""
	}
	return s[i : j+1]
}

// tier2CostInputPerM / tier2CostOutputPerM mirror the Opus 4.8 list rates used
// by Tier 2, kept here so the advisory pass reports a comparable cost without
// reaching into the tier2 package's unexported consts.
func tier2CostInputPerM() float64  { return 5.00 }
func tier2CostOutputPerM() float64 { return 25.00 }

// truncate caps s to n runes, appending "…" when it had to cut.
func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
