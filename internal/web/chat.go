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
	"github.com/tlvb/tlvb/internal/synthesizer"
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
	Role    string `json:"role"`    // "user" | "assistant"
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
ABOUT TLVB
============================================================================

TLVB is a MITRE ATT&CK tactics-driven autonomous IR agent system that
runs on SANS SIFT Workstation. It:
  - Parses Windows forensic artifacts via SIFT tools (Tier 0)
  - Runs 10+ Tactic Agents in parallel via Claude (Tier 1)
  - Synthesizes results, checks consistency, builds a Kill Chain (Tier 2)
  - Generates HTML/CSV/JSON reports (Tier 3)
  - Provides a Web UI Examiner Portal with Approve/Reject (Review Gate 1)

============================================================================
PIPELINE (in order)
============================================================================

  1. Parse        — SIFT tools → unified_events DuckDB rows
  2. Analyze All  — 10 Tactic Agents run, output findings/<tactic>.json
  3. Synthesize   — aggregate + consistency check + timeline + Kill Chain
                    → synthesis.json (optional Corrector loop re-runs
                    flagged tactics)
  4. Generate Report — HTML / CSV / JSON to outputs/cases/<id>/reports/

CLI equivalents:
  tlvb parse       --case-id ID --evidence-id ID --input PATH
  tlvb analyze     CASE_ID --tactic <slug>   (or --tactic anomaly_hunter)
  tlvb synthesize  CASE_ID [--correct]
  tlvb report      CASE_ID [--language ja|en] [--only-approved]
  tlvb run         CASE_ID --evidence PATH    (one-shot)
  tlvb serve       --port 8080                (Web UI)
  tlvb review      CASE_ID --gate 1           (CLI review)

============================================================================
TACTIC AGENTS (10 + 1)
============================================================================

  TA0001 initial_access        — how the attacker got in
  TA0002 execution             — what programs they ran
  TA0003 persistence           — how they stayed in
  TA0004 privilege_escalation  — how they got admin
  TA0005 defense_evasion       — how they hid (log clears, etc.)
  TA0006 credential_access     — how they stole passwords
  TA0007 discovery             — what they reconnoitered
  TA0008 lateral_movement      — how they moved between hosts
  TA0009 collection            — what data they gathered
  TA0040 impact                — how they damaged things
  ANOM   anomaly_hunter         — Tier 1.5, anomalies outside the 10

============================================================================
PARSERS (P0 + P1)
============================================================================

P0: evtx, amcache, prefetch, registry (RECmd/RegRipper), scheduled_tasks
P1: shimcache, mft ($MFT), shellbags, jumplists, lnk, recyclebin,
    win10timeline (ActivitiesCache.db)

============================================================================
WEB UI TABS (per case)
============================================================================

  Events     — parsed unified_events browser + parse_results
  Findings   — Tactic-grouped, Approve/Reject, evidence drill-down
  Timeline   — chronological + Kill Chain diagram
  IOC        — extracted indicators (file_path / domain / ipv4 / sha256 / etc)
  MITRE Map  — Tactic × Technique grid coloured by max confidence
  Report     — embedded HTML report + CSV/JSON downloads
  Audit      — actions.jsonl (parser orchestrator activity)

============================================================================
KEY CONCEPTS
============================================================================

  finding_id   — F-<tactic>-<seq> e.g. F-persistence-001
  audit_id     — SHA-256 prefix of one parsed event; the unit of evidence
                 a finding cites
  confidence   — high (red) | medium (yellow) | low (green)
  Approved     — examiner-confirmed; included in --only-approved reports
  Rejected     — examiner-dismissed (with reason); excluded
  Review Gate  — examiner checkpoint between AI tiers (Gate 1 = findings)
  Synthesizer  — deterministic Tier 2 (no LLM); Corrector adds optional LLM
  R1-R4        — consistency rules (e.g. R1 = log-clear vs. low lateral
                 findings count → suspicious blind spot)

When the user asks about a specific finding/timeline event/IOC and case
context is provided below, ground your answer in that data. When no case
context is provided, answer about TLVB itself.

Never invent finding_ids, audit_ids, or counts — if you're not sure, say so.`

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
func summariseCaseForChat(cs *synthesizer.CaseSynthesis) string {
	var b strings.Builder
	fmt.Fprintf(&b, "============================================================================\n")
	fmt.Fprintf(&b, "CURRENT CASE: %s\n", cs.CaseID)
	fmt.Fprintf(&b, "============================================================================\n\n")
	fmt.Fprintf(&b, "evidence_id: %s   timezone: %s   generated_at: %s\n\n",
		cs.EvidenceID, cs.Timezone, cs.GeneratedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "Executive summary (synthesizer-generated):\n  %s\n\n",
		cs.ExecutiveSummary)

	// Stats
	fmt.Fprintf(&b, "Stats:\n")
	fmt.Fprintf(&b, "  total_findings=%d  clusters=%d  merged_duplicates=%d  "+
		"unique_evidence=%d  timeline_rows=%d  unresolved_audit_ids=%d\n",
		cs.Stats.TotalFindings, cs.Stats.ClusterCount, cs.Stats.MergedFindings,
		cs.Stats.UniqueEvidenceIDs, len(cs.Timeline), len(cs.UnresolvedRefs))
	if len(cs.Stats.FindingsByTactic) > 0 {
		fmt.Fprintf(&b, "  findings_by_tactic: %s\n",
			formatCountMap(cs.Stats.FindingsByTactic))
	}
	if len(cs.Stats.ConfidenceDistribution) > 0 {
		fmt.Fprintf(&b, "  confidence: %s\n",
			formatCountMap(cs.Stats.ConfidenceDistribution))
	}

	// Affected scope
	if len(cs.AffectedScope.CompromisedHosts) > 0 {
		fmt.Fprintf(&b, "\nCompromised hosts: %s\n",
			strings.Join(cs.AffectedScope.CompromisedHosts, ", "))
	}

	// Kill Chain
	if len(cs.IntrusionPath) > 0 {
		fmt.Fprintf(&b, "\nInferred Kill Chain:\n")
		for _, step := range cs.IntrusionPath {
			fmt.Fprintf(&b, "  %d. %s (%s) %s — %s\n",
				step.Step, step.Tactic, step.TacticName,
				step.Timestamp.UTC().Format("2006-01-02 15:04:05Z"),
				truncateForChat(step.Description, 150))
		}
	}

	// Top findings per tactic — id + technique + confidence + 1-line summary
	if len(cs.FindingsByTactic) > 0 {
		fmt.Fprintf(&b, "\nFindings (Examiner-facing IDs are stable):\n")
		tids := make([]string, 0, len(cs.FindingsByTactic))
		for k := range cs.FindingsByTactic {
			tids = append(tids, k)
		}
		sort.Strings(tids)
		for _, tid := range tids {
			list := cs.FindingsByTactic[tid]
			if len(list) == 0 {
				continue
			}
			fmt.Fprintf(&b, "  [%s] %d findings:\n", tid, len(list))
			shown := list
			if len(shown) > 5 {
				shown = shown[:5]
			}
			for _, f := range shown {
				state := "pending"
				if f.Approved {
					state = "approved"
				} else if f.Rejected {
					state = "rejected"
				}
				fmt.Fprintf(&b, "    - %s [%s/%s] %s — %s\n",
					f.FindingID, f.Confidence, state, f.TechniqueID,
					truncateForChat(f.Summary, 120))
			}
			if len(list) > 5 {
				fmt.Fprintf(&b, "    ... +%d more in this tactic\n", len(list)-5)
			}
		}
	}

	// Inconsistencies
	if len(cs.Inconsistencies) > 0 {
		fmt.Fprintf(&b, "\nConsistency rule hits:\n")
		for _, inc := range cs.Inconsistencies {
			fmt.Fprintf(&b, "  [%s/%s] %s\n",
				inc.Rule, inc.Severity, truncateForChat(inc.Description, 200))
		}
	}

	// MITRE top entries
	if len(cs.MITREMapping) > 0 {
		fmt.Fprintf(&b, "\nMITRE ATT&CK mapping (top 10 by finding_count):\n")
		mm := make([]synthesizer.MITREMappingEntry, len(cs.MITREMapping))
		copy(mm, cs.MITREMapping)
		sort.SliceStable(mm, func(i, j int) bool {
			return mm[i].FindingCount > mm[j].FindingCount
		})
		shown := mm
		if len(shown) > 10 {
			shown = shown[:10]
		}
		for _, m := range shown {
			fmt.Fprintf(&b, "  %s/%s — %s · findings=%d evidence=%d conf=%s\n",
				m.Tactic, m.Technique, m.TechniqueName,
				m.FindingCount, m.EvidenceCount, m.Confidence)
		}
	}

	return b.String()
}

func formatCountMap(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, " ")
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
