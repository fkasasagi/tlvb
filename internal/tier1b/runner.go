package tier1b

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/marcboeker/go-duckdb"
	"github.com/tlvb/tlvb/internal/auditlog"
	"github.com/tlvb/tlvb/internal/casedb"
	"github.com/tlvb/tlvb/internal/common"
	"github.com/tlvb/tlvb/internal/evidencex"
	"github.com/tlvb/tlvb/internal/rulesdb"
	"github.com/tlvb/tlvb/internal/tier1a"
)

// newActionLog returns a unified-execution-log writer for the case, or nil when
// FindingsBaseDir isn't the production .../<case>/findings dir (e.g. unit tests).
func newActionLog(findingsBaseDir, caseID string) *auditlog.Logger {
	if filepath.Base(findingsBaseDir) != "findings" {
		return nil
	}
	return auditlog.New(filepath.Join(filepath.Dir(findingsBaseDir), "actions.jsonl"), caseID)
}

// llmContext is the JSON shape passed to the LLM as the user message.
// Field names mirror skills/anomaly_hunter.md so the prompt can reference them.
type llmContext struct {
	CaseID                string                  `json:"case_id"`
	TacticFindingsSummary map[string]int          `json:"tactic_findings_summary"`
	KeyFindingTimestamps  []string                `json:"key_finding_timestamps,omitempty"`
	ExistingAuditIDs      []string                `json:"existing_audit_ids,omitempty"`
	LensesApplied         []string                `json:"lenses_applied"`
	EventsTotalScanned    int                     `json:"events_total_scanned"`
	EventsInWindow        int                     `json:"events_in_window"`
	Truncated             bool                    `json:"truncated"`
	WindowMin             string                  `json:"window_min,omitempty"`
	WindowMax             string                  `json:"window_max,omitempty"`
	ExistingIntents       []intentInfo            `json:"existing_skill_intents,omitempty"`
	ExaminerBackground    *common.ExaminerContext `json:"examiner_background,omitempty"`
	Events                []eventForLLM           `json:"events"`
}

type eventForLLM struct {
	AuditID    string         `json:"audit_id"`
	TS         string         `json:"ts,omitempty"`
	ArtifactID string         `json:"artifact_id"`
	Computer   string         `json:"computer,omitempty"`
	Lenses     []string       `json:"_lenses"`
	Excerpt    map[string]any `json:"excerpt"`
}

const defaultSkill = "anomaly_hunter"

// Run executes the Tier 1B MVP for a case. Reads prior Tier 1A findings,
// prefilters anomaly candidates, builds the LLM context, calls Claude CLI
// (or returns dry-run info), writes findings/by-skill/anomaly_hunter.json.
func Run(ctx context.Context, cfg Config) (*Report, error) {
	if cfg.CaseID == "" {
		return nil, fmt.Errorf("Tier 1B: CaseID is required")
	}
	if cfg.DBPath == "" {
		return nil, fmt.Errorf("Tier 1B: DBPath is required")
	}
	if cfg.Skill == "" {
		cfg.Skill = defaultSkill
	}
	if cfg.SkillsDir == "" {
		cfg.SkillsDir = "skills"
	}
	if cfg.FindingsBaseDir == "" {
		cfg.FindingsBaseDir = filepath.Join("outputs", "cases", cfg.CaseID, "findings")
	}
	if cfg.ClaudeBinary == "" {
		cfg.ClaudeBinary = "claude"
	}
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = 200
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Minute
	}
	if cfg.SchemaVersion == "" {
		cfg.SchemaVersion = "unknown"
	}
	if cfg.ModelID == "" {
		if cfg.Model != "" {
			cfg.ModelID = cfg.Model
		} else {
			cfg.ModelID = "claude-code-default"
		}
	}

	rep := &Report{CaseID: cfg.CaseID}

	emit(cfg, Event{Phase: "loading", Message: "reading skill + prior findings"})

	skillPath := filepath.Join(cfg.SkillsDir, cfg.Skill+".md")
	skillBytes, err := os.ReadFile(skillPath)
	if err != nil {
		return nil, fmt.Errorf("read skill: %w", err)
	}
	skillSHA := sha256.Sum256(skillBytes)
	rep.SkillSHA256 = hex.EncodeToString(skillSHA[:])

	prior, err := loadPriorFindings(cfg.FindingsBaseDir)
	if err != nil {
		return nil, fmt.Errorf("load prior findings: %w", err)
	}
	rep.PriorFindings = prior.Total
	emit(cfg, Event{Phase: "loading",
		Message: fmt.Sprintf("loaded %d prior findings (%d unique audit_ids, %d key timestamps)",
			prior.Total, len(prior.UniqueAudits), len(prior.KeyTimestamps))})

	emit(cfg, Event{Phase: "prefilter", Message: "scoring anomaly candidates"})
	db, err := sql.Open("duckdb", cfg.DBPath+"?access_mode=read_only")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	totalScanned, err := countAllEvents(ctx, db, cfg.CaseID)
	if err != nil {
		return nil, fmt.Errorf("count events: %w", err)
	}
	rep.EventsScanned = totalScanned

	bundle, err := buildCandidates(ctx, db, cfg.CaseID, prior, cfg.MaxEvents)
	if err != nil {
		return nil, fmt.Errorf("build candidates: %w", err)
	}
	rep.EventsInWindow = bundle.Total
	rep.Truncated = bundle.Total > cfg.MaxEvents
	emit(cfg, Event{Phase: "prefilter",
		Message: fmt.Sprintf("scanned=%d, candidates=%d (truncated=%v)",
			totalScanned, bundle.Total, rep.Truncated)})

	// --- Tier 1B v0.2: skill SQL cache (canonical + candidate execution) ---
	// Learned queries augment the heuristic prefilter: canonical SQL runs
	// with zero LLM cost, candidate SQL runs on a trial basis. Hits are
	// merged into the candidate bundle so the LLM interprets them alongside
	// heuristic candidates; auditToSQL lets us promote a query when the LLM
	// cites one of its rows in a finding. Fully optional — any failure here
	// degrades gracefully to the v0.1 heuristic-only path.
	var (
		cacheMgr        *rulesdb.Manager
		auditToSQL      = map[string][]string{}
		existingIntents []intentInfo
	)
	cacheEnabled := !cfg.NoSkillCache && cfg.RulesDBPath != ""
	if cacheEnabled && cfg.DryRun {
		if _, statErr := os.Stat(cfg.RulesDBPath); statErr != nil {
			cacheEnabled = false // don't create rules.duckdb just to dry-run
		}
	}
	if cacheEnabled {
		m, openErr := rulesdb.Open(cfg.RulesDBPath, rulesdb.ReadWrite)
		if openErr != nil {
			emit(cfg, Event{Phase: "cache",
				Message: "skill cache disabled (open failed): " + openErr.Error()})
			cacheEnabled = false
		} else {
			cacheMgr = m
			defer cacheMgr.Close()
		}
	}
	if cacheEnabled {
		rep.CacheEnabled = true
		cacheRows, listErr := cacheMgr.ListSkillSQL(ctx, cfg.Skill, cfg.SchemaVersion, cfg.ModelID)
		if listErr != nil {
			emit(cfg, Event{Phase: "cache", Message: "list skill SQL failed: " + listErr.Error()})
		} else {
			rep.SkillSQLAvailable = len(cacheRows)
			entries := make([]skillCacheEntry, 0, len(cacheRows))
			var allAudits []string
			for _, r := range cacheRows {
				entries = append(entries, skillCacheEntry{
					SQLSHA256: r.SQLSHA256, SQL: r.SQL, Intent: r.Intent,
					State: string(r.State), HitCount: r.HitCount,
				})
				if err := validateSkillSQL(r.SQL); err != nil {
					continue // stored row no longer passes the guard — skip
				}
				audits, n, execErr := execSkillSQLAudits(ctx, db, cfg.CaseID, r.SQL, cfg.MaxEvents)
				if execErr != nil {
					continue // graceful: one bad query doesn't abort the run
				}
				rep.SkillSQLExecuted++
				rep.SkillSQLHits += n
				for _, a := range audits {
					auditToSQL[a] = append(auditToSQL[a], r.SQLSHA256)
					allAudits = append(allAudits, a)
				}
			}
			existingIntents = distinctIntents(entries)
			if cacheCands, hErr := hydrateCandidates(ctx, db, cfg.CaseID,
				dedupStrings(allAudits, cfg.MaxEvents)); hErr == nil && len(cacheCands) > 0 {
				bundle.Events = mergeCacheCandidates(bundle.Events, cacheCands, cfg.MaxEvents)
			}
			emit(cfg, Event{Phase: "cache",
				Message: fmt.Sprintf("cache queries=%d executed=%d hits=%d merged_candidates=%d",
					rep.SkillSQLAvailable, rep.SkillSQLExecuted, rep.SkillSQLHits, len(bundle.Events))})
		}
	}

	evidenceEnabled := cfg.EvidenceFetch
	bg := casedb.ReadBackground(ctx, db, cfg.CaseID)
	hctx := buildLLMContext(cfg.CaseID, bg, prior, bundle, existingIntents)
	userMsg, err := buildUserMessage(hctx, cacheEnabled, evidenceEnabled)
	if err != nil {
		return nil, err
	}

	if cfg.DryRun {
		emit(cfg, Event{Phase: "llm",
			Message: fmt.Sprintf("dry-run: skill=%d chars / user_msg=%d chars / events_in_window=%d",
				len(skillBytes), len(userMsg), len(bundle.Events))})
		rep.OutputPath = ""
		return rep, nil
	}

	emit(cfg, Event{Phase: "llm", Message: "calling LLM"})
	al := newActionLog(cfg.FindingsBaseDir, cfg.CaseID)
	llmStart := time.Now()
	resp, err := callClaude(ctx, cfg, string(skillBytes), userMsg)
	if err != nil {
		al.Append(auditlog.Action{Actor: "tier1b", Kind: "llm_call", Detail: cfg.Skill,
			DurationSeconds: time.Since(llmStart).Seconds(),
			Success:         auditlog.BoolPtr(false), Error: err.Error()})
		return rep, fmt.Errorf("claude CLI: %w", err)
	}
	rep.LLMCallDurationS = time.Since(llmStart).Seconds()
	rep.InputTokens = resp.InputTokens
	rep.CacheReadTokens = resp.Usage.CacheReadInputTokens
	rep.OutputTokens = resp.OutputTokens
	rep.TotalCostUSD = resp.TotalCostUSD
	al.Append(auditlog.Action{Actor: "tier1b", Kind: "llm_call", Detail: cfg.Skill,
		Model: resp.EffectiveModel, DurationSeconds: rep.LLMCallDurationS,
		InputTokens: resp.InputTokens, OutputTokens: resp.OutputTokens,
		CacheReadTokens: resp.Usage.CacheReadInputTokens, CostUSD: resp.TotalCostUSD,
		Success: auditlog.BoolPtr(true)})

	// Always persist the raw response next to the report for triage of
	// parse failures or unexpected empties.
	rawDebugPath := filepath.Join(cfg.FindingsBaseDir, "by-skill",
		cfg.Skill+".raw_response.txt")
	_ = os.MkdirAll(filepath.Dir(rawDebugPath), 0o755)
	_ = os.WriteFile(rawDebugPath, []byte(resp.Result), 0o644)

	findings, plans, requested, err := parseAnomalyOutput(resp.Result)
	if err != nil {
		return rep, fmt.Errorf("parse LLM output: %w (raw saved to %s)", err, rawDebugPath)
	}

	// --- On-demand evidence extraction (agent-driven file fetch) ---
	// If the LLM asked to read specific files, extract them read-only from the
	// case's disk image and run a bounded follow-up pass with their contents so
	// the findings are grounded in what the files actually contain. Every step
	// degrades gracefully: no image / mount failure / parse error simply keeps
	// the prior pass's findings (CLAUDE.md #4 graceful degradation).
	var evidenceSummaries []evidencex.FetchSummary
	if evidenceEnabled && len(requested) > 0 {
		maxRounds := cfg.MaxEvidenceRounds
		if maxRounds <= 0 {
			maxRounds = 1
		}
		evTimeout := cfg.EvidenceTimeout
		if evTimeout <= 0 {
			evTimeout = 10 * time.Minute
		}
		rc := evidencex.RoundConfig{
			Config: evidencex.Config{
				PythonBin: cfg.PythonBin,
				RepoDir:   cfg.RepoDir,
				Timeout:   evTimeout,
			},
			CaseID:     cfg.CaseID,
			OutBaseDir: filepath.Join(filepath.Dir(cfg.FindingsBaseDir), "extractions", "on-demand"),
			MaxFiles:   cfg.MaxEvidenceFiles,
		}
		curUserMsg := userMsg
		for rep.EvidenceRounds < maxRounds && len(requested) > 0 {
			rep.FilesRequested += len(requested)
			round, rerr := evidencex.RunRound(ctx, db, rc, requested)
			if rerr != nil {
				emit(cfg, Event{Phase: "evidence", Message: "fetch failed: " + rerr.Error()})
				break
			}
			if !round.Available {
				emit(cfg, Event{Phase: "evidence",
					Message: "no mountable disk image in this case — skipping file fetch"})
				break
			}
			summaries := round.Summaries()
			evidenceSummaries = append(evidenceSummaries, summaries...)
			for _, s := range summaries {
				ok := s.Status == "ok"
				if ok {
					rep.FilesExtracted++
				}
				al.Append(auditlog.Action{Actor: "tier1b", Kind: "evidence_fetch",
					Detail: s.Target, Success: auditlog.BoolPtr(ok), Error: s.Error})
			}
			remaining := maxRounds - rep.EvidenceRounds - 1
			curUserMsg = curUserMsg + "\n\n" + round.PreviewBlock + finalizeNote(remaining)
			emit(cfg, Event{Phase: "evidence",
				Message: fmt.Sprintf("round %d: requested=%d extracted=%d, re-analysing",
					rep.EvidenceRounds+1, len(summaries), countOK(summaries))})

			llmStart2 := time.Now()
			resp2, err2 := callClaude(ctx, cfg, string(skillBytes), curUserMsg)
			if err2 != nil {
				al.Append(auditlog.Action{Actor: "tier1b", Kind: "llm_call",
					Detail:          cfg.Skill + " (evidence round)",
					DurationSeconds: time.Since(llmStart2).Seconds(),
					Success:         auditlog.BoolPtr(false), Error: err2.Error()})
				emit(cfg, Event{Phase: "evidence", Message: "re-analysis call failed: " + err2.Error()})
				break
			}
			rep.LLMCallDurationS += time.Since(llmStart2).Seconds()
			rep.InputTokens += resp2.InputTokens
			rep.CacheReadTokens += resp2.Usage.CacheReadInputTokens
			rep.OutputTokens += resp2.OutputTokens
			rep.TotalCostUSD += resp2.TotalCostUSD
			al.Append(auditlog.Action{Actor: "tier1b", Kind: "llm_call",
				Detail: cfg.Skill + " (evidence round)", Model: resp2.EffectiveModel,
				DurationSeconds: time.Since(llmStart2).Seconds(),
				InputTokens:     resp2.InputTokens, OutputTokens: resp2.OutputTokens,
				CacheReadTokens: resp2.Usage.CacheReadInputTokens, CostUSD: resp2.TotalCostUSD,
				Success: auditlog.BoolPtr(true)})
			_ = os.WriteFile(rawDebugPath, []byte(resp2.Result), 0o644)

			f2, p2, req2, perr := parseAnomalyOutput(resp2.Result)
			if perr != nil {
				emit(cfg, Event{Phase: "evidence",
					Message: "re-analysis parse failed, keeping prior findings: " + perr.Error()})
				break
			}
			findings = f2
			if len(p2) > 0 {
				plans = p2
			}
			requested = req2
			rep.EvidenceRounds++
		}
	}

	for i := range findings {
		if findings[i].FindingID == "" {
			findings[i].FindingID = uuid.NewString()
		}
		findings[i].GeneratedAt = time.Now().UTC()
		// Severity-based auto-approve, mirroring Tier 1A: critical/high
		// require examiner review; medium/low/info are auto-approved.
		if approved, by := tier1a.AutoApproveByLevel(findings[i].Severity); approved {
			findings[i].Approved = true
			findings[i].ApprovedBy = by
		}
	}

	outPath := filepath.Join(cfg.FindingsBaseDir, "by-skill", cfg.Skill+".json")
	if err := writeAnomalyReport(outPath, AnomalyReport{
		CaseID:         cfg.CaseID,
		Skill:          cfg.Skill,
		SkillSHA256:    rep.SkillSHA256,
		GeneratedAt:    time.Now().UTC(),
		ModelID:        resp.EffectiveModel,
		EventsScanned:  totalScanned,
		EventsInWindow: bundle.Total,
		PriorFindings:  prior.Total,
		Findings:       findings,
		Audit: AnomalyAudit{
			LLMCallDurationS:    rep.LLMCallDurationS,
			InputTokens:         rep.InputTokens,
			CacheReadTokens:     rep.CacheReadTokens,
			CacheCreationTokens: resp.Usage.CacheCreationInputTokens,
			OutputTokens:        rep.OutputTokens,
			TotalCostUSD:        rep.TotalCostUSD,
			StopReason:          resp.StopReason,
			SessionID:           resp.SessionID,
			EvidenceRounds:      rep.EvidenceRounds,
		},
		EvidenceFetches: evidenceSummaries,
	}); err != nil {
		return rep, fmt.Errorf("write anomaly report: %w", err)
	}
	rep.OutputPath = outPath

	// --- Tier 1B v0.2: grow the skill SQL cache ---
	// Newly-proposed queries become 'candidate' rows (trialed next run); any
	// cached query whose rows the LLM cited in a finding is promoted to
	// 'canonical' (zero-LLM from now on). This is the cross-case learning
	// loop — cost decreases as proven lenses accumulate.
	if cacheEnabled && cacheMgr != nil {
		rep.CandidatesProposed = len(plans)
		for _, p := range plans {
			if validateSkillSQL(p.SQL) != nil {
				continue // never store a query that fails the safety guard
			}
			inserted, upErr := cacheMgr.UpsertSkillCandidate(ctx, rulesdb.SkillSQLRow{
				Skill: cfg.Skill, SQL: p.SQL, Intent: p.Intent,
				OriginCase: cfg.CaseID, SchemaVersion: cfg.SchemaVersion, ModelID: cfg.ModelID,
			})
			if upErr == nil && inserted {
				rep.CandidatesAppended++
			}
		}
		for _, sha := range promotableHashes(findings, auditToSQL) {
			if cacheMgr.PromoteSkillSQL(ctx, cfg.Skill, sha, cfg.CaseID) == nil {
				rep.Promoted++
			}
		}
		if rep.CandidatesProposed > 0 || rep.Promoted > 0 {
			emit(cfg, Event{Phase: "cache",
				Message: fmt.Sprintf("proposed=%d appended=%d promoted=%d",
					rep.CandidatesProposed, rep.CandidatesAppended, rep.Promoted)})
		}
	}

	for _, f := range findings {
		rep.NewFindings = append(rep.NewFindings, FindingSummary{
			Lens:       f.Lens,
			Severity:   f.Severity,
			Summary:    f.Summary,
			AuditCount: len(f.AuditIDs),
		})
	}
	emit(cfg, Event{Phase: "done",
		Message: fmt.Sprintf("wrote %d findings to %s", len(findings), outPath),
		Count:   len(findings)})
	return rep, nil
}

// buildLLMContext converts our internal state into the wire format the
// skill prompt expects. existingIntents lists the skill SQL cache's current
// coverage so the LLM can self-judge what new queries (if any) to propose.
func buildLLMContext(caseID, background string, prior *priorContext, bundle *candidateBundle, existingIntents []intentInfo) llmContext {
	tacticSummary := map[string]int{}
	for _, s := range prior.Summary {
		k := s.Source
		if s.Level != "" {
			k = s.Source + "/" + s.Level
		}
		tacticSummary[k] += s.Count
	}

	lenses := []string{
		"A1 time anomaly (off-hours)",
		"A2 location anomaly (Temp / AppData / Public / ProgramData)",
		"A4 frequency anomaly (rare image, count<3)",
		"A5 adjacency anomaly (±30 min around prior findings)",
		"(A3 / A6 / A7: LLM-side judgment, no pre-score)",
	}

	events := make([]eventForLLM, 0, len(bundle.Events))
	for _, c := range bundle.Events {
		e := eventForLLM{
			AuditID:    c.AuditID,
			ArtifactID: c.ArtifactID,
			Computer:   c.Computer,
			Lenses:     c.Lenses,
			Excerpt:    shrinkPayload(c.ArtifactID, c.Payload),
		}
		if c.HasTS {
			e.TS = c.TsUTC.Format(time.RFC3339Nano)
		}
		events = append(events, e)
	}

	out := llmContext{
		CaseID:                caseID,
		TacticFindingsSummary: tacticSummary,
		KeyFindingTimestamps:  prior.KeyTimestamps,
		ExistingAuditIDs:      prior.UniqueAudits,
		LensesApplied:         lenses,
		EventsTotalScanned:    0, // filled at call-site (totalScanned passed separately)
		EventsInWindow:        bundle.Total,
		Truncated:             bundle.Total > len(events),
		ExistingIntents:       existingIntents,
		ExaminerBackground:    common.NewExaminerContext(background),
		Events:                events,
	}
	if !bundle.MinTS.IsZero() {
		out.WindowMin = bundle.MinTS.Format(time.RFC3339)
	}
	if !bundle.MaxTS.IsZero() {
		out.WindowMax = bundle.MaxTS.Format(time.RFC3339)
	}
	// Cap existing_audit_ids to keep prompt size reasonable. The LLM only
	// needs the set membership to avoid duplicates — 500 is plenty.
	if len(out.ExistingAuditIDs) > 500 {
		out.ExistingAuditIDs = out.ExistingAuditIDs[:500]
	}
	if len(out.KeyFindingTimestamps) > 200 {
		out.KeyFindingTimestamps = out.KeyFindingTimestamps[:200]
	}
	return out
}

// findingShapeDoc is the shared description of one finding object.
const findingShapeDoc = `    {
      "lens": "A1|A2|A4|A5|A6|A7",
      "summary": "1-line title (≤120 chars)",
      "description": "free-text rationale (≤500 chars)",
      "severity": "info|low|medium|high|critical",
      "audit_ids": ["<audit_id from events>", ...],
      "technique_id": "T1059.001",   // optional MITRE T-number
      "tactic": "execution"           // optional kill-chain phase
    }`

// outputAuthorityNote makes the Tier 1B user-message contract authoritative
// over the skill .md system prompt. The 10 MITRE Tactic Agent skills define
// their own output format (per-technique verdicts / TacticReport); when one of
// them is used as a Tier 1B lens we must override that so the response matches
// the {findings, proposed_queries} shape the runner parses.
const outputAuthorityNote = `IMPORTANT: your system prompt supplies the detection lenses/domain knowledge
for this scan. IGNORE any output-format, schema, or per-technique-verdict
workflow it describes — for THIS Tier 1B run, emit ONLY the JSON specified
below and nothing else.

`

func buildUserMessage(hctx llmContext, cacheEnabled, evidenceEnabled bool) (string, error) {
	prelude := arrayPrelude
	if cacheEnabled || evidenceEnabled {
		prelude = objectPrelude(cacheEnabled, evidenceEnabled)
	}
	body, err := json.MarshalIndent(hctx, "", "  ")
	if err != nil {
		return "", err
	}
	return outputAuthorityNote + prelude + string(body), nil
}

// arrayPrelude is the v0.1 bare-array contract (no cache, no evidence fetch).
const arrayPrelude = `Below is the AnomalyContext for your Tier 1.5 anomaly scan.
Apply the lenses defined in your system prompt. Return ONLY a JSON array of
finding objects with this shape:

  [
` + findingShapeDoc + `,
    ...
  ]

Constraints:
- Every audit_id MUST exist in the events array below. Do NOT invent ids.
- Do NOT duplicate findings already covered by existing_audit_ids (the
  tactic agents / Hayabusa pass-through already reported those).
- Return [] if no genuine anomalies stand out — false positives are
  worse than gaps at this layer.
- No markdown fences, no prose outside the JSON array.

AnomalyContext:
`

// objectPrelude builds the {findings, proposed_queries?, requested_files?}
// contract. proposed_queries appears only with the skill SQL cache on;
// requested_files only with on-demand evidence extraction enabled.
func objectPrelude(cacheEnabled, evidenceEnabled bool) string {
	var b strings.Builder
	b.WriteString(`Below is the AnomalyContext for your Tier 1.5 anomaly scan.
Apply the lenses defined in your system prompt. Return ONLY a JSON OBJECT
with these keys, no markdown fences, no prose outside the object:

  {
    "findings": [
` + findingShapeDoc + `,
      ...
    ]`)
	if cacheEnabled {
		b.WriteString(`,
    "proposed_queries": [
      {
        "intent": "<short reusable-lens label, e.g. 'rare service install off-hours'>",
        "rationale": "<1-line why this generalises beyond this case>",
        "sql": "<a single DuckDB SELECT against unified_events>"
      },
      ...
    ]`)
	}
	if evidenceEnabled {
		b.WriteString(`,
    "requested_files": [
      {
        "path": "<file path seen in an event — Windows 'C:\\..\\x.ps1' or NTFS-relative>",
        "evidence_id": "<optional: which disk image, only if the case has several>",
        "rationale": "<1-line: what reading this file would tell you>"
      },
      ...
    ]`)
	}
	b.WriteString(`
  }

findings rules:
- Every audit_id MUST exist in the events array below. Do NOT invent ids.
- Do NOT duplicate findings already covered by existing_audit_ids.
- Use [] if no genuine anomalies stand out — false positives are worse
  than gaps at this layer.
`)
	if cacheEnabled {
		b.WriteString(`
proposed_queries rules (OPTIONAL — use [] if nothing generalises):
- existing_skill_intents lists lenses the cache ALREADY runs every case
  (their hits appear in events tagged lens "S0"). Do NOT re-propose those.
- Only propose a query for a RECURRING anomaly perspective worth running on
  FUTURE cases automatically (zero-LLM). Propose at most 3.
- Each sql MUST: start with SELECT or WITH; contain NO INSERT/UPDATE/DELETE/
  DROP/CREATE/ALTER/ATTACH/PRAGMA; have its first WHERE predicate be exactly
  "case_id = ?"; contain exactly one ? placeholder; lead its output columns
  with audit_id, ts_utc, artifact_id; end with LIMIT N (N≤500); no trailing
  semicolon. Use json_extract_string(payload_json, '$.Key') for fields.
`)
	}
	if evidenceEnabled {
		b.WriteString(`
requested_files rules (OPTIONAL — use [] if you don't need any file's contents):
- Use this ONLY when an event references a file whose CONTENTS would change
  your verdict: a dropped script (.ps1/.bat/.vbs/.hta/.js), a config, a
  suspicious binary you want to read strings from, a staged archive, etc.
- The file is extracted READ-ONLY from the case's disk image and its contents
  are returned to you for a bounded follow-up pass — so you investigate it
  directly instead of guessing from the event alone.
- Request only a few of the most decision-relevant files. Do NOT request files
  already fully represented by the events above.
`)
	}
	b.WriteString("\nAnomalyContext:\n")
	return b.String()
}

// finalizeNote steers the follow-up pass after the extracted-file previews:
// conclude from what was read; request more files only if a round remains.
func finalizeNote(remainingRounds int) string {
	if remainingRounds > 0 {
		return fmt.Sprintf(`

Use the file contents above to finalize. Return the SAME JSON object shape and
put your conclusions in findings (cite audit_ids; reference what the files
contained). You MAY request more files via requested_files ONLY if essential —
%d more round(s) will be honoured.
`, remainingRounds)
	}
	return `

Use the file contents above to finalize. Return the SAME JSON object shape and
put your conclusions in findings (cite audit_ids; reference what the files
contained). This is the LAST round — do NOT request more files; set
requested_files to [].
`
}

func countOK(s []evidencex.FetchSummary) int {
	n := 0
	for _, x := range s {
		if x.Status == "ok" {
			n++
		}
	}
	return n
}

// claudeOutput captures the fields we use from `claude --output-format json`.
type claudeOutput struct {
	IsError        bool    `json:"is_error"`
	Result         string  `json:"result"`
	StopReason     string  `json:"stop_reason"`
	SessionID      string  `json:"session_id"`
	DurationMS     int     `json:"duration_ms"`
	DurationAPIMS  int     `json:"duration_api_ms"`
	TotalCostUSD   float64 `json:"total_cost_usd"`
	EffectiveModel string  `json:"-"`
	InputTokens    int     `json:"-"`
	OutputTokens   int     `json:"-"`
	Usage          struct {
		InputTokens              int `json:"input_tokens"`
		CacheReadInputTokens     int `json:"cache_read_input_tokens"`
		CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
		OutputTokens             int `json:"output_tokens"`
	} `json:"usage"`
	ModelUsage map[string]struct {
		InputTokens  int `json:"inputTokens"`
		OutputTokens int `json:"outputTokens"`
	} `json:"modelUsage"`
}

func callClaudeCLI(ctx context.Context, cfg Config, systemPrompt, userMsg string) (*claudeOutput, error) {
	args := []string{
		"-p",
		"--output-format", "json",
		"--system-prompt", systemPrompt,
		"--tools", "",
		"--no-session-persistence",
		"--exclude-dynamic-system-prompt-sections",
	}
	if cfg.Model != "" {
		args = append(args, "--model", cfg.Model)
		args = append(args, "--fallback-model", cfg.Model)
	}
	subCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	cmd := exec.CommandContext(subCtx, cfg.ClaudeBinary, args...)
	cmd.Stdin = strings.NewReader(userMsg)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		tail := stderr.String()
		if len(tail) > 400 {
			tail = tail[:400] + "..."
		}
		return nil, fmt.Errorf("exec: %w (stderr: %s)", err, tail)
	}
	var out claudeOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		head := stdout.String()
		if len(head) > 240 {
			head = head[:240] + "..."
		}
		return nil, fmt.Errorf("parse output: %w (head: %s)", err, head)
	}
	if out.IsError {
		return nil, fmt.Errorf("claude reported error (%s): %s",
			out.StopReason, out.Result)
	}
	out.InputTokens = out.Usage.InputTokens
	out.OutputTokens = out.Usage.OutputTokens
	// Pick the model that produced the most output tokens.
	var best string
	var bestOut int
	for k, v := range out.ModelUsage {
		if v.OutputTokens > bestOut {
			bestOut = v.OutputTokens
			best = k
		}
	}
	if best != "" {
		out.EffectiveModel = best
	} else {
		out.EffectiveModel = cfg.Model
	}
	return &out, nil
}

// parseAnomalyFindings extracts the JSON array Claude returned and filters
// out invalid entries (audit_ids must be present somewhere relevant).
func parseAnomalyFindings(text string, _ []string) ([]AnomalyFinding, error) {
	s := strings.TrimSpace(text)
	// Strip markdown fences if Claude wrapped despite our instructions.
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	s = strings.TrimSpace(s)
	// Find the array bounds.
	if i := strings.Index(s, "["); i > 0 {
		s = s[i:]
	}
	if j := strings.LastIndex(s, "]"); j >= 0 && j < len(s)-1 {
		s = s[:j+1]
	}
	var arr []AnomalyFinding
	if err := json.Unmarshal([]byte(s), &arr); err != nil {
		return nil, fmt.Errorf("unmarshal: %w (head: %s)", err, truncate(text, 200))
	}
	out := arr[:0]
	for _, f := range arr {
		f.Lens = strings.TrimSpace(f.Lens)
		f.Severity = strings.ToLower(strings.TrimSpace(f.Severity))
		f.Summary = strings.TrimSpace(f.Summary)
		if f.Summary == "" || len(f.AuditIDs) == 0 {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

func writeAnomalyReport(path string, rep AnomalyReport) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o644)
}

func countAllEvents(ctx context.Context, db *sql.DB, caseID string) (int, error) {
	var n int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM unified_events WHERE case_id = ?`, caseID).Scan(&n)
	return n, err
}

func emit(cfg Config, ev Event) {
	if cfg.ProgressFn != nil {
		cfg.ProgressFn(ev)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
