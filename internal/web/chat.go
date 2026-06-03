package web

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/agents"
	"github.com/tlvb/tlvb/internal/tier2"
)

// ----------------------------------------------------------------------------
// /api/chat — single-turn chat assistant
//
// Stateless from the server's perspective: the client owns the conversation
// history and posts the full message list each time. We build a system
// prompt with TLVB orientation + optional per-case context, serialize
// the prior turns into one user message (so the existing Engine.Call
// signature works for both engines without modification), and return one
// assistant turn.
// ----------------------------------------------------------------------------

type chatMessage struct {
	Role    string `json:"role"` // "user" | "assistant"
	Content string `json:"content"`
}

type chatRequest struct {
	Messages []chatMessage `json:"messages"`
	CaseID   string        `json:"case_id,omitempty"`
	Engine   string        `json:"engine,omitempty"`
	Model    string        `json:"model,omitempty"`
}

type chatResponse struct {
	Role         string  `json:"role"`
	Content      string  `json:"content"`
	Engine       string  `json:"engine"`
	Model        string  `json:"model,omitempty"`
	InputTokens  int     `json:"input_tokens"`
	OutputTokens int     `json:"output_tokens"`
	DurationMS   int     `json:"duration_ms"`
	CostUSD      float64 `json:"cost_usd,omitempty"`
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	var req chatRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, 400, "bad json: %v", err)
		return
	}
	if len(req.Messages) == 0 {
		writeError(w, 400, "messages must not be empty")
		return
	}
	last := req.Messages[len(req.Messages)-1]
	if last.Role != "user" || strings.TrimSpace(last.Content) == "" {
		writeError(w, 400, "last message must be a non-empty user message")
		return
	}

	engine := req.Engine
	if engine == "" {
		engine = "claude-code"
	}
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if engine == "anthropic-api" && apiKey == "" {
		writeError(w, 400, "engine=anthropic-api requires ANTHROPIC_API_KEY in server env")
		return
	}

	system := s.buildChatSystemPrompt(req.CaseID)
	user := buildChatUserMessage(req.Messages)

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()

	resp, err := agents.Chat(ctx, engine, req.Model, apiKey, system, user, 90*time.Second)
	if err != nil {
		writeError(w, 502, "chat engine error: %v", err)
		return
	}

	out := chatResponse{
		Role:         "assistant",
		Content:      resp.Text,
		Engine:       engine,
		Model:        resp.EffectiveModel,
		InputTokens:  resp.InputTokens,
		OutputTokens: resp.OutputTokens,
		DurationMS:   resp.DurationMS,
		CostUSD:      resp.TotalCostUSD,
	}
	if out.Model == "" {
		out.Model = req.Model
	}
	writeJSON(w, 200, out)
}

// ----------------------------------------------------------------------------
// System prompt construction
// ----------------------------------------------------------------------------

// orientationPrompt is the static TLVB briefing. Kept short so per-turn
// token cost stays bounded — the full USER_GUIDE is large but most of it is
// not needed in-conversation. We focus on terms / pipeline / where things
// live so the assistant can answer "how do I X?" type questions accurately.
const orientationPrompt = `You are TLVB Assistant, an AI integrated into the TLVB DFIR
(Digital Forensics & Incident Response) tool. Your job is to help an
examiner (the user) two ways:

  1. **Use TLVB correctly** — pipeline steps, CLI commands, Web UI tabs.
  2. **Interpret analysis results** — explain findings, suggest follow-ups,
     translate technical terms.

Respond in the same language the user writes in (Japanese ⇄ English are both
common). Be concise; show command examples in fenced code blocks.

============================================================================
ABOUT TLVB  (Timeline Longa, Vita Brevis)
============================================================================

TLVB is an autonomous IR agent system that extracts attack traces from
Windows forensic artifacts. It runs on SANS SIFT Workstation and is built
in tiers:
  - Tier 0  — Parse Windows artifacts via SIFT tools → unified_events (DuckDB)
  - Tier 1A — Signature agent: a rule corpus (Sigma / Hayabusa / ATT&CK STIX /
              custom) is pre-compiled to SQL at BUILD time; at runtime it just
              runs the cached SQL (zero LLM) and every hit becomes a finding
  - Tier 1B — Skills-driven anomaly agent: runs cached SQL from skills/*.md,
              then an LLM reasons over the results + Tier 1A findings and may
              propose new queries that grow the cache across cases
  - Tier 2  — Timeline Analysis Agent (LLM): clusters findings and analyses
              each cluster's ±N-min raw timeline; optional active search adds
              hypothesis-driven wide-range SQL → synthesis.json
  - Tier 3  — DFIR Reporter: HTML / CSV / JSON (ja/en)
  - Web UI Examiner Portal with Review Gates (0 / 1A / 1B / 2)

============================================================================
PIPELINE (in order)
============================================================================

  1. Parse    — SIFT tools → unified_events DuckDB rows (Tier 0)
  2. Tier 1A  — cached signature SQL → findings/by-rule/<source>/<id>.json
  3. Tier 1B  — skills anomaly (+LLM) → findings/by-skill/<skill>.json
  4. Tier 2   — timeline synthesis → synthesis.json
  5. Tier 3   — report → outputs/cases/<id>/reports/

CLI equivalents:
  tlvb parse       --case-id ID --evidence-id ID --input PATH
  tlvb analyze     CASE_ID --tier 1a                  (cached signature SQL)
  tlvb analyze     CASE_ID --tier 1b [--skill NAME]   (anomaly / lens)
  tlvb synthesize  CASE_ID [--active-search]          (Tier 2)
  tlvb report      CASE_ID [--language ja|en] [--only-approved]   (Tier 3)
  tlvb run         CASE_ID --evidence PATH --tier all (one-shot)
  tlvb rules       build|list                         (compile corpus → SQL)
  tlvb serve       --port 8080                        (Web UI)
  tlvb review      CASE_ID --gate 1a                  (CLI review)

============================================================================
RULE CORPUS (Tier 1A) & SKILLS (Tier 1B)
============================================================================

Tier 1A rules carry a rule_source (one of 4):
  sigma     — SigmaHQ detection rules (git submodule)
  hayabusa  — Hayabusa built-in rules / EVTX pass-through
  stix      — MITRE ATT&CK techniques (STIX 2.1)
  custom    — in-house rules
Each rule is compiled once to DuckDB SQL and cached in rules.duckdb. Memory /
Sysmon rules carry requires_artifact and are skipped when that artifact is
absent (auto-enabled later, no rebuild).

Tier 1B lenses live in skills/*.md (default anomaly_hunter; tactic skills are
opt-in via --skill). Queries the LLM proves useful are promoted to a canonical
cache and re-run LLM-free on later cases.

============================================================================
PARSERS (Tier 0)
============================================================================

evtx, amcache, prefetch, registry, scheduled_tasks, shimcache, mft ($MFT),
shellbags, jumplists, lnk, recyclebin, win10timeline, usn_journal, hayabusa,
srum, browser_history (+ skeletons: sqlecmd / bulk_extractor / yara /
volatility3 / w3c_iis).

============================================================================
WEB UI TABS (per case)
============================================================================

  Events     — parsed unified_events browser + parse_results
  Findings   — Review Gate 1A (signature) + 1B (anomaly), severity-ranked,
               Approve/Reject, cluster bulk-approve, evidence drill-down
  Timeline   — key-event timeline derived from findings
  IOC        — indicators derived from finding evidence (file/path, command,
               account, host, network, log-source)
  MITRE Map  — tactic × technique grid coloured by confidence
  Report     — embedded HTML report + CSV/JSON downloads
  Rules      — global Rule Library: build coverage + learned Tier 1B lenses
  Audit      — actions.jsonl (parser orchestrator activity)

============================================================================
KEY CONCEPTS
============================================================================

  Tier 1A finding — one rule hit, saved as
                    findings/by-rule/<rule_source>/<rule_id>.json with
                    rule_meta (title, level, mitre_techniques / mitre_tactics)
  Tier 1B finding — one anomaly, under findings/by-skill/<skill>.json
  rule_id         — upstream ID, unchanged (Sigma UUID / STIX Txxxx / …);
                    primary key is (rule_id, rule_source)
  audit_id        — SHA-256 prefix of one parsed event; the unit of evidence
                    a finding cites
  severity        — critical | high | medium | low (from the rule level)
  Review Gate 1A  — critical/high need review; medium/low auto-approve
                    (examiner can override); cluster bulk-approve available
  Tier 1A rule    — runtime LLM-ZERO by design (cached SQL only)
  synthesis.json  — Tier 2 output: clusters + overall_story + mitre_mapping
                    + open_questions

When the user asks about a specific finding/timeline event/IOC and case
context is provided below, ground your answer in that data. When no case
context is provided, answer about TLVB itself.

Never invent rule_ids, audit_ids, or counts — if you're not sure, say so.`

// buildChatSystemPrompt assembles orientation + optional case context.
// Case context is intentionally summarised (not the full synthesis.json)
// to keep token cost bounded — the user can paste specific finding text
// into the chat if they want deep analysis on one item.
func (s *Server) buildChatSystemPrompt(caseID string) string {
	if caseID == "" {
		return orientationPrompt
	}
	cs, err := s.loadSynthesis(caseID)
	if err != nil {
		// No synthesis yet (only parsed, only analyzed, or new case) — degrade
		// gracefully and tell the assistant.
		return orientationPrompt + fmt.Sprintf(
			"\n\n============================================================================\n"+
				"CURRENT CASE: %s\n"+
				"============================================================================\n\n"+
				"Synthesis has not yet been generated for this case "+
				"(loadSynthesis: %v). The user may be asking about Parse output "+
				"only, or about how to proceed. Suggest the next pipeline step "+
				"as appropriate.\n", caseID, err)
	}
	return orientationPrompt + "\n\n" + summariseCaseForChat(cs)
}

// summariseCaseForChat produces the dynamic case context block. Keep it
// dense — bullet points + counts beat narrative for context windows.
func summariseCaseForChat(cs *tier2.CaseSynthesis) string {
	var b strings.Builder
	fmt.Fprintf(&b, "============================================================================\n")
	fmt.Fprintf(&b, "CURRENT CASE: %s\n", cs.CaseID)
	fmt.Fprintf(&b, "============================================================================\n\n")
	fmt.Fprintf(&b, "generated_at: %s   model: %s\n\n",
		cs.GeneratedAt.UTC().Format(time.RFC3339), orDash(cs.ModelID))
	fmt.Fprintf(&b, "Overall story (Tier 2 synthesis):\n  %s\n\n",
		truncateForChat(cs.OverallStory, 1200))

	// Stats
	fmt.Fprintf(&b, "Stats:\n")
	fmt.Fprintf(&b, "  total_findings=%d  clusters=%d  llm_calls=%d  cost=$%.4f\n",
		cs.TotalFindings, cs.ClusterCount, cs.Audit.LLMCallsTotal, cs.Audit.TotalCostUSD)

	// Clusters — phase, finding count, techniques, 1-line narrative
	if len(cs.Clusters) > 0 {
		fmt.Fprintf(&b, "\nClusters:\n")
		for _, c := range cs.Clusters {
			phase := c.AttackPhase
			if phase == "" {
				phase = "(unphased)"
			}
			fmt.Fprintf(&b, "  [cluster %d] %s — %d findings · techniques: %s\n",
				c.ID, phase, len(c.FindingRefs), strings.Join(c.MITRETechniques, ", "))
			if c.Narrative != "" {
				fmt.Fprintf(&b, "    %s\n", truncateForChat(c.Narrative, 200))
			}
		}
	}

	// MITRE top entries
	if len(cs.MITREMapping) > 0 {
		fmt.Fprintf(&b, "\nMITRE ATT&CK mapping (top 10 by finding_count):\n")
		mm := make([]tier2.MITREEntry, len(cs.MITREMapping))
		copy(mm, cs.MITREMapping)
		sort.SliceStable(mm, func(i, j int) bool {
			return mm[i].FindingCount > mm[j].FindingCount
		})
		shown := mm
		if len(shown) > 10 {
			shown = shown[:10]
		}
		for _, m := range shown {
			fmt.Fprintf(&b, "  %s/%s — findings=%d\n",
				orDash(m.Tactic), m.Technique, m.FindingCount)
		}
	}

	// Open questions carried by the synthesis
	if len(cs.OpenQuestions) > 0 {
		fmt.Fprintf(&b, "\nOpen questions:\n")
		for _, q := range cs.OpenQuestions {
			fmt.Fprintf(&b, "  - %s\n", truncateForChat(q, 200))
		}
	}

	return b.String()
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func truncateForChat(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// buildChatUserMessage serialises the conversation history into a single
// string. Why: Engine.Call takes one prompt — it doesn't accept a message
// list. For chat use this is fine because both backends (claude-code,
// anthropic-api) handle the inlined-history pattern competently.
//
// Format chosen so the LLM can clearly distinguish past turns from the
// current question.
func buildChatUserMessage(msgs []chatMessage) string {
	if len(msgs) == 1 {
		return msgs[0].Content
	}
	var b strings.Builder
	b.WriteString("<conversation_history>\n")
	for _, m := range msgs[:len(msgs)-1] {
		role := "user"
		if m.Role == "assistant" {
			role = "assistant"
		}
		fmt.Fprintf(&b, "[%s] %s\n", role, m.Content)
	}
	b.WriteString("</conversation_history>\n\n")
	b.WriteString("<current_question>\n")
	b.WriteString(msgs[len(msgs)-1].Content)
	b.WriteString("\n</current_question>\n")
	return b.String()
}
