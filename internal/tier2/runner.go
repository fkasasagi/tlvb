package tier2

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
	"sort"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/auditlog"
	"github.com/tlvb/tlvb/internal/casedb"
	"github.com/tlvb/tlvb/internal/common"
	"github.com/tlvb/tlvb/internal/evidencex"
	"github.com/tlvb/tlvb/internal/llm"

	_ "github.com/marcboeker/go-duckdb"
)

// Config drives Run.
type Config struct {
	CaseID string
	// CaseBackground is examiner-supplied UNVERIFIED case context. When empty,
	// Run() loads it from cases.duckdb. Injected into the per-cluster, overall,
	// and active-search prompts to steer interpretation — never as evidence.
	CaseBackground    string
	FindingsBaseDir   string        // outputs/cases/<id>/findings
	OutputPath        string        // outputs/cases/<id>/synthesis.json (default)
	DBPath            string        // outputs/cases.duckdb
	SkillsDir         string        // default "skills"
	SkillName         string        // default "timeline_review" (skills/<name>.md)
	ClaudeBinary      string        // default "claude"
	Model             string        // empty = CLI default
	Language          string        // "ja" | "en"  (default: "ja")
	ClusterGap        time.Duration // default 30 min
	TimelineWindow    time.Duration // default 5 min
	MaxRowsPerCluster int           // default 300
	PerClusterTimeout time.Duration // default 5 min
	ActiveSearch      bool          // enable hypothesis-driven SQL pass per cluster
	MaxSelfCorrect    int           // active-search SQL self-correction rounds (0 = default 2; <0 disables)
	MaxReframe        int           // active-search investigative-pivot rounds on a 0-row query (0 = default 1; <0 disables)
	// ReproduceLLMFault rewrites the first active-search SQL per cluster to
	// reproduce a realistic field-as-column LLM mistake so the self-correction
	// loop visibly fires. A labelled reproduction aid for filming the demo /
	// the "show self-correction at least once" requirement — never on by default.
	ReproduceLLMFault bool
	DryRun            bool
	ProgressFn        func(Event)

	// --- On-demand evidence extraction (agent-driven file fetch) ---
	// When enabled, a cluster analysis may list files in `requested_files`; the
	// runner extracts them read-only from the case's disk image and re-analyses
	// the cluster with their contents. Degrades to a single pass when there's no
	// mountable image or the mount tools are unavailable.
	EvidenceFetch     bool
	MaxEvidenceRounds int           // fetch+reanalyse rounds per cluster (default 1)
	MaxEvidenceFiles  int           // files fetched per round (default 8)
	EvidenceTimeout   time.Duration // per-fetch wall-clock budget (default 10m)
	PythonBin         string        // interpreter for parsers.evidence_fetch
	RepoDir           string        // module root for the import (default: cwd)

	// al is the unified execution-log writer (outputs/cases/<id>/actions.jsonl).
	// Set internally by Run(); nil in unit tests (a nil *Logger is a no-op).
	al *auditlog.Logger
}

// Event is the progress hook.
type Event struct {
	Phase   string // "loading" | "clustering" | "timeline" | "llm" | "writing" | "done"
	Message string
	Count   int
}

// Report mirrors what gets returned to the CLI.
type Report struct {
	CaseID           string
	TotalFindings    int
	ClusterCount     int
	ClustersAnalyzed int
	OutputPath       string
	Duration         float64

	// LLM token / cost totals across all Tier 2 calls (from SynthAudit).
	LLMCalls        int
	InputTokens     int
	CacheReadTokens int
	OutputTokens    int
	TotalCostUSD    float64

	// Active-search self-correction accounting (only meaningful with --active-search).
	ActiveSQLAttempted        int
	ActiveSQLSucceeded        int
	ActiveSQLSelfCorrected    int
	ActiveSQLCorrectionRounds int
	ActiveSQLReframed         int
	ActiveSQLNoEvidence       int

	// On-demand evidence extraction accounting.
	EvidenceRounds int
	FilesRequested int
	FilesExtracted int
}

// Run executes the Tier 2 MVP. Reads Tier 1 findings, clusters them
// temporally, fetches raw-timeline excerpts, calls Claude per cluster,
// writes synthesis.json.
func Run(ctx context.Context, cfg Config) (*Report, error) {
	if cfg.CaseID == "" {
		return nil, fmt.Errorf("Tier 2: CaseID is required")
	}
	if cfg.DBPath == "" {
		return nil, fmt.Errorf("Tier 2: DBPath is required")
	}
	if cfg.FindingsBaseDir == "" {
		cfg.FindingsBaseDir = filepath.Join("outputs", "cases", cfg.CaseID, "findings")
	}
	if cfg.OutputPath == "" {
		cfg.OutputPath = filepath.Join("outputs", "cases", cfg.CaseID, "synthesis.json")
	}
	if cfg.SkillsDir == "" {
		cfg.SkillsDir = "skills"
	}
	if cfg.SkillName == "" {
		cfg.SkillName = "timeline_review"
	}
	if cfg.ClaudeBinary == "" {
		cfg.ClaudeBinary = "claude"
	}
	if cfg.ClusterGap <= 0 {
		cfg.ClusterGap = 30 * time.Minute
	}
	if cfg.TimelineWindow <= 0 {
		cfg.TimelineWindow = 5 * time.Minute
	}
	if cfg.MaxRowsPerCluster <= 0 {
		cfg.MaxRowsPerCluster = 300
	}
	if cfg.PerClusterTimeout <= 0 {
		cfg.PerClusterTimeout = 5 * time.Minute
	}
	if cfg.Language == "" {
		cfg.Language = "ja"
	}
	// Append Tier 2 activity to the same actions.jsonl the Tier 0 orchestrator
	// writes, so the case has one ordered, timestamped execution log.
	cfg.al = auditlog.New(filepath.Join(filepath.Dir(cfg.OutputPath), "actions.jsonl"), cfg.CaseID)

	start := time.Now()
	rep := &Report{CaseID: cfg.CaseID}

	emit(cfg, Event{Phase: "loading", Message: "reading findings"})
	findings, err := LoadFindings(cfg.FindingsBaseDir)
	if err != nil {
		return nil, fmt.Errorf("load findings: %w", err)
	}
	rep.TotalFindings = len(findings)
	if len(findings) == 0 {
		return rep, fmt.Errorf("no findings under %s (run Tier 1A / 1B first)", cfg.FindingsBaseDir)
	}

	db, err := sql.Open("duckdb", cfg.DBPath+"?access_mode=read_only")
	if err != nil {
		return rep, fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	// Examiner-provided background (UNVERIFIED context) for the LLM prompts.
	// Best-effort: a missing column / older DB degrades to "". An explicit
	// cfg.CaseBackground (e.g. a test) wins.
	if cfg.CaseBackground == "" {
		cfg.CaseBackground = casedb.ReadBackground(ctx, db, cfg.CaseID)
	}

	findings, err = EnrichTimestamps(ctx, db, cfg.CaseID, findings)
	if err != nil {
		return rep, fmt.Errorf("enrich timestamps: %w", err)
	}

	// Deterministic initial-access reconstruction (issue #82, task 3): a
	// single-account 4625 burst → 4624 success is password guessing (T1110.001)
	// the signature corpus can miss. Best-effort — a DB/extract failure is logged
	// and the pipeline continues.
	gctx := groundingContext{BruteForcedAccounts: map[string]bool{}}
	if bf, bfErr := detectBruteForceFindings(ctx, db, cfg.CaseID); bfErr != nil {
		emit(cfg, Event{Phase: "loading",
			Message: fmt.Sprintf("brute-force heuristic skipped: %v", bfErr)})
	} else if len(bf) > 0 {
		findings = append(findings, bf...)
		rep.TotalFindings = len(findings)
		gctx.BruteForcedAccounts = bruteForcedAccountsOf(bf)
		emit(cfg, Event{Phase: "loading",
			Message: fmt.Sprintf("brute-force heuristic added %d finding(s)", len(bf))})
	}

	// Grounding context for the corroboration layer (issue #82, tasks 1/2/4):
	// whether the case has a web server (for web-shell / public-facing claims) and
	// whether the clock was stepped backward (timeline non-monotonic). Best-effort.
	if arts, aerr := listArtifacts(ctx, db, cfg.CaseID); aerr == nil {
		gctx.HasWebArtifact = containsWebArtifact(arts)
	}
	// Parser-independent corroboration: even with no web-log artifact, a web
	// document root / live IIS config on disk (MFT) confirms a web server exists
	// (so a web-shell claim stays admissible). Its ABSENCE is what lets the layer
	// confidently demote a web-shell FP. Best-effort.
	if !gctx.HasWebArtifact {
		if onDisk, derr := detectWebServerOnDisk(ctx, db, cfg.CaseID); derr == nil && onDisk {
			gctx.HasWebArtifact = true
			emit(cfg, Event{Phase: "loading",
				Message: "web document root / IIS config found on disk (MFT) — web-shell claims are corroboratable"})
		}
	}
	if rev, rerr := detectClockReversal(ctx, db, cfg.CaseID); rerr == nil && rev {
		gctx.ClockReversed = true
		emit(cfg, Event{Phase: "loading",
			Message: "clock reversal detected (4616 backward jump) — timeline flagged unreliable"})
	}

	emit(cfg, Event{Phase: "clustering",
		Message: fmt.Sprintf("clustering %d findings with %v gap", len(findings), cfg.ClusterGap)})
	clusters := ClusterFindings(findings, cfg.ClusterGap)
	rep.ClusterCount = len(clusters)
	emit(cfg, Event{Phase: "clustering",
		Message: fmt.Sprintf("formed %d clusters", len(clusters))})

	emit(cfg, Event{Phase: "timeline", Message: "fetching ±N min raw timeline per cluster"})
	for i := range clusters {
		if err := FetchClusterTimeline(ctx, db, cfg.CaseID, &clusters[i],
			cfg.TimelineWindow, cfg.MaxRowsPerCluster); err != nil {
			return rep, fmt.Errorf("cluster %d timeline: %w", clusters[i].ID, err)
		}
	}

	// Load skill prompt.
	skillPath := filepath.Join(cfg.SkillsDir, cfg.SkillName+".md")
	skillBytes, err := os.ReadFile(skillPath)
	if err != nil {
		return rep, fmt.Errorf("read skill %s: %w", skillPath, err)
	}
	skillSHA := sha256.Sum256(skillBytes)
	skillSHAHex := hex.EncodeToString(skillSHA[:])

	if cfg.DryRun {
		_ = skillBytes
		emit(cfg, Event{Phase: "llm",
			Message: fmt.Sprintf("dry-run: clusters=%d (skip LLM)", len(clusters))})
		return rep, nil
	}

	emit(cfg, Event{Phase: "llm",
		Message: fmt.Sprintf("calling claude for %d clusters", len(clusters))})

	audit := SynthAudit{ClustersAnalysed: 0, SkillSHA256: skillSHAHex}
	for i := range clusters {
		if err := analyseClusterLLM(ctx, cfg, &clusters[i], string(skillBytes), &audit, db, gctx.ClockReversed); err != nil {
			// graceful: skip the cluster but keep going
			audit.ClustersSkippedNoLLM++
			emit(cfg, Event{Phase: "llm",
				Message: fmt.Sprintf("cluster %d skipped: %v", clusters[i].ID, err)})
			continue
		}
		audit.ClustersAnalysed++
		emit(cfg, Event{Phase: "llm",
			Message: fmt.Sprintf("cluster %d analysed (%d findings)",
				clusters[i].ID, len(clusters[i].Findings))})
	}
	rep.ClustersAnalyzed = audit.ClustersAnalysed

	// Active search pass — hypothesis-driven SQL for each cluster's
	// open_questions. Runs only when --active-search is enabled, and
	// graceful-fails per-cluster.
	if cfg.ActiveSearch {
		emit(cfg, Event{Phase: "llm",
			Message: "active-search pass for open_questions"})
		clusters, _ = RunActiveSearch(ctx, cfg, db, clusters, &audit)
	}

	// Deterministic coverage backstop: append a neutral sentence to any cluster
	// whose narrative silently dropped a salient detection (a security-control-
	// blocked attempt, recon, persistence, or any other tactic the cluster's
	// critical/high findings prove). Applied HERE, before the overall pass, so the
	// case-wide story — built from cluster narratives — also reflects it instead of
	// inheriting the omission. Tactic-agnostic; noise clusters are skipped.
	applyCoverageBackstop(clusters, cfg.Language)

	// Overall synthesis call: uses a dedicated system prompt
	// (skills/overall_synthesis.md, NOT the cluster-analysis
	// timeline_review.md) to write one case-wide story.
	overallSkillPath := filepath.Join(cfg.SkillsDir, "overall_synthesis.md")
	overallSkillBytes, err2 := os.ReadFile(overallSkillPath)
	if err2 != nil {
		overallSkillBytes = skillBytes // fall back to the cluster skill if absent
	}
	// Uncorroborated FP-prone claims (web shell with no web server, PtH explained
	// by a brute-force burst): steer the narrative away from asserting them even
	// when a finding is tagged, and reframe the open questions below.
	uncorrobAliases := uncorroboratedClaimAliases(gctx)
	overall, err := analyseOverallLLM(ctx, cfg, clusters, string(overallSkillBytes), &audit, gctx.ClockReversed, uncorrobAliases)
	overallFallback := false
	if err != nil {
		// Fall back to a deterministic per-cluster stitch so the report
		// still has SOMETHING in the Executive Summary slot.
		emit(cfg, Event{Phase: "llm",
			Message: fmt.Sprintf("overall LLM failed (%v) — falling back to per-cluster stitch", err)})
		overall = fallbackOverallStory(clusters, cfg.Language)
		overallFallback = true
	}

	// Consolidate the per-cluster open questions into the prioritised
	// three-tier view (critical / needs-collection / supplementary). Runs after
	// every cluster's questions exist; best-effort, so a failure just leaves the
	// flat OpenQuestions list for the report to fall back to.
	oqSynth, oqErr := analyseOpenQuestionsLLM(ctx, cfg, clusters, &audit)
	if oqErr != nil {
		emit(cfg, Event{Phase: "llm",
			Message: fmt.Sprintf("open-questions synthesis failed (%v) — using flat list", oqErr)})
	}

	emit(cfg, Event{Phase: "writing",
		Message: fmt.Sprintf("writing %s", cfg.OutputPath)})
	cs := buildCaseSynthesis(cfg.CaseID, findings, clusters, overall, audit, cfg.Language, gctx)
	cs.OverallStoryFallback = overallFallback
	if !oqSynth.IsEmpty() {
		// Close the loop on the prioritised view too: drop questions about
		// uncorroborated claims and append a resolved note (the flat list is
		// reframed inside buildCaseSynthesis).
		cs.OpenQuestionsSynth = reframeOpenQuestionsSynth(oqSynth, uncorrobAliases, strings.ToLower(cfg.Language) != "en")
	}
	if err := writeSynthesis(cfg.OutputPath, cs); err != nil {
		return rep, err
	}
	rep.OutputPath = cfg.OutputPath
	rep.Duration = time.Since(start).Seconds()
	rep.LLMCalls = audit.LLMCallsTotal
	rep.InputTokens = audit.InputTokensTotal
	rep.CacheReadTokens = audit.CacheReadTokensTotal
	rep.OutputTokens = audit.OutputTokensTotal
	rep.TotalCostUSD = audit.TotalCostUSD
	rep.ActiveSQLAttempted = audit.ActiveSQLAttempted
	rep.ActiveSQLSucceeded = audit.ActiveSQLSucceeded
	rep.ActiveSQLSelfCorrected = audit.ActiveSQLSelfCorrected
	rep.ActiveSQLCorrectionRounds = audit.ActiveSQLCorrectionRounds
	rep.ActiveSQLReframed = audit.ActiveSQLReframed
	rep.ActiveSQLNoEvidence = audit.ActiveSQLNoEvidence
	rep.EvidenceRounds = audit.EvidenceRounds
	rep.FilesRequested = audit.EvidenceFilesRequest
	rep.FilesExtracted = audit.EvidenceFilesGot
	emit(cfg, Event{Phase: "done",
		Message: fmt.Sprintf("done in %.1fs (%d clusters, %d LLM calls)",
			rep.Duration, len(clusters), audit.LLMCallsTotal),
		Count: len(clusters)})
	return rep, nil
}

// OverallRegenReport summarises a RegenerateOverall run.
type OverallRegenReport struct {
	OutputPath string
	Chars      int
	Paragraphs int
	Fallback   bool // true when the LLM failed and the deterministic stitch was used
	LLMCalls   int
	Duration   float64
}

// RegenerateOverall re-runs ONLY the case-wide overall synthesis against an
// existing synthesis.json and writes the new overall_story back in place,
// leaving every cluster, finding_ref and the MITRE mapping untouched. It is the
// cheap path for refreshing the executive summary after a prompt or timeout
// change without paying for a full re-clustering + per-cluster + active-search
// run. Reads/writes cfg.OutputPath.
func RegenerateOverall(ctx context.Context, cfg Config) (*OverallRegenReport, error) {
	if cfg.OutputPath == "" {
		return nil, fmt.Errorf("RegenerateOverall: OutputPath is required")
	}
	if cfg.ClaudeBinary == "" {
		cfg.ClaudeBinary = "claude"
	}
	if cfg.PerClusterTimeout <= 0 {
		cfg.PerClusterTimeout = 5 * time.Minute
	}
	if cfg.SkillsDir == "" {
		cfg.SkillsDir = "skills"
	}

	body, err := os.ReadFile(cfg.OutputPath)
	if err != nil {
		return nil, fmt.Errorf("read synthesis: %w", err)
	}
	var cs CaseSynthesis
	if err := json.Unmarshal(body, &cs); err != nil {
		return nil, fmt.Errorf("parse synthesis: %w", err)
	}
	if len(cs.Clusters) == 0 {
		return nil, fmt.Errorf("synthesis has no clusters to summarise")
	}

	// Reconstruct the minimal Cluster shape the overall pass needs. finding_count
	// is the only thing derived from findings, so a length-only slice suffices.
	clusters := make([]Cluster, 0, len(cs.Clusters))
	for _, sc := range cs.Clusters {
		clusters = append(clusters, Cluster{
			ID:              sc.ID,
			StartTS:         sc.StartTS,
			EndTS:           sc.EndTS,
			AttackPhase:     sc.AttackPhase,
			Narrative:       sc.Narrative,
			MITRETechniques: sc.MITRETechniques,
			OpenQuestions:   sc.OpenQuestions,
			Findings:        make([]Finding, len(sc.FindingRefs)),
		})
	}

	overallSkillPath := filepath.Join(cfg.SkillsDir, "overall_synthesis.md")
	skill, err := os.ReadFile(overallSkillPath)
	if err != nil {
		// fall back to the configured cluster skill if the overall one is absent
		name := cfg.SkillName
		if name == "" {
			name = "timeline_review"
		}
		skill, err = os.ReadFile(filepath.Join(cfg.SkillsDir, name+".md"))
		if err != nil {
			return nil, fmt.Errorf("read overall skill: %w", err)
		}
	}

	start := time.Now()
	var audit SynthAudit
	rep := &OverallRegenReport{OutputPath: cfg.OutputPath}
	// Reuse the verdicts the full run already stored: the timeline reliability
	// steers away from clock-reversal hallucinations, and the demoted techniques
	// (MITREUnconfirmed) steer away from asserting uncorroborated FP claims.
	uncorrobAliases := uncorroboratedClaimAliasesFromTechniques(cs.MITREUnconfirmed)
	overall, err := analyseOverallLLM(ctx, cfg, clusters, string(skill), &audit,
		cs.TimelineReliability == "unreliable", uncorrobAliases)
	if err != nil {
		emit(cfg, Event{Phase: "llm",
			Message: fmt.Sprintf("overall LLM failed (%v) — falling back to per-cluster stitch", err)})
		overall = fallbackOverallStory(clusters, cfg.Language)
		rep.Fallback = true
	}

	execBrief, techSummary := splitExecBrief(overall)
	cs.OverallStory = techSummary
	cs.ExecBrief = execBrief
	cs.TechSummary = techSummary
	cs.OverallStoryFallback = rep.Fallback

	// Consolidate the per-cluster open questions into the prioritised
	// three-tier view as well, so the cheap "refresh executive summary" path
	// also refreshes the Open Questions section. Best-effort: a failure leaves
	// the existing flat OpenQuestions list (and prior synthesis) untouched.
	ja := strings.ToLower(cfg.Language) != "en"
	if oq, oqErr := analyseOpenQuestionsLLM(ctx, cfg, clusters, &audit); oqErr == nil && !oq.IsEmpty() {
		cs.OpenQuestionsSynth = reframeOpenQuestionsSynth(oq, uncorrobAliases, ja)
	} else if oqErr != nil {
		emit(cfg, Event{Phase: "llm",
			Message: fmt.Sprintf("open-questions synthesis failed (%v) — keeping flat list", oqErr)})
	}
	// Reframe the stored flat list too, so an uncorroborated-claim question
	// resolved here is not left asking to confirm the claim.
	cs.OpenQuestions = reframeResolvedOpenQuestions(cs.OpenQuestions, uncorrobAliases, ja)

	if err := writeSynthesis(cfg.OutputPath, cs); err != nil {
		return nil, err
	}

	rep.Chars = len(overall)
	rep.Paragraphs = len(strings.Split(strings.TrimSpace(overall), "\n\n"))
	rep.LLMCalls = audit.LLMCallsTotal
	rep.Duration = time.Since(start).Seconds()
	return rep, nil
}

// ----------------------------------------------------------------------------
// LLM per-cluster analysis
// ----------------------------------------------------------------------------

func analyseClusterLLM(ctx context.Context, cfg Config, c *Cluster, systemPrompt string,
	audit *SynthAudit, db *sql.DB, clockReversed bool) error {

	evidenceEnabled := cfg.EvidenceFetch && db != nil
	userMsg, err := buildClusterUserMessage(c, cfg.Language, cfg.CaseBackground, evidenceEnabled, clockReversed)
	if err != nil {
		return err
	}

	resp, err := clusterPass(ctx, cfg, c, systemPrompt, userMsg, audit, true)
	if err != nil {
		return err
	}

	// --- On-demand evidence extraction (agent-driven file fetch) ---
	// If the analysis asked to read specific files, extract them read-only from
	// the case's disk image and re-analyse this cluster with their contents so
	// the narrative is grounded in what the files contain. Bounded by
	// MaxEvidenceRounds; every step degrades gracefully (CLAUDE.md #4).
	if evidenceEnabled && len(resp.RequestedFiles) > 0 {
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
				PythonBin: cfg.PythonBin, RepoDir: cfg.RepoDir, Timeout: evTimeout,
			},
			CaseID:     cfg.CaseID,
			OutBaseDir: filepath.Join(filepath.Dir(cfg.FindingsBaseDir), "extractions", "on-demand"),
			MaxFiles:   cfg.MaxEvidenceFiles,
		}
		curUserMsg := userMsg
		requested := resp.RequestedFiles
		rounds := 0
		for rounds < maxRounds && len(requested) > 0 {
			audit.EvidenceFilesRequest += len(requested)
			round, rerr := evidencex.RunRound(ctx, db, rc, requested)
			if rerr != nil {
				emit(cfg, Event{Phase: "evidence",
					Message: fmt.Sprintf("cluster %d fetch failed: %v", c.ID, rerr)})
				break
			}
			if !round.Available {
				emit(cfg, Event{Phase: "evidence",
					Message: "no mountable disk image in this case — skipping file fetch"})
				break
			}
			summaries := round.Summaries()
			c.EvidenceFetches = append(c.EvidenceFetches, summaries...)
			for _, s := range summaries {
				ok := s.Status == "ok"
				if ok {
					audit.EvidenceFilesGot++
				}
				cfg.al.Append(auditlog.Action{Actor: "tier2", Kind: "evidence_fetch",
					Detail: s.Target, Success: auditlog.BoolPtr(ok), Error: s.Error})
			}
			remaining := maxRounds - rounds - 1
			curUserMsg = curUserMsg + "\n\n" + round.PreviewBlock + clusterFinalizeNote(remaining)
			emit(cfg, Event{Phase: "evidence",
				Message: fmt.Sprintf("cluster %d: extracted %d/%d file(s), re-analysing",
					c.ID, countOKSummaries(summaries), len(summaries))})

			resp2, perr := clusterPass(ctx, cfg, c, systemPrompt, curUserMsg, audit, false)
			if perr != nil {
				emit(cfg, Event{Phase: "evidence",
					Message: fmt.Sprintf("cluster %d re-analysis failed, keeping prior: %v", c.ID, perr)})
				break
			}
			resp = resp2
			requested = resp2.RequestedFiles
			rounds++
			audit.EvidenceRounds++
		}
	}

	c.Narrative = resp.Narrative
	c.AttackPhase = resp.AttackPhase
	c.MITRETechniques = mergeUnique(c.MITRETechniques, resp.MITRETechniques)
	c.OpenQuestions = resp.OpenQuestions
	return nil
}

// clusterPass runs one cluster LLM call + parse + audit. On a parse error
// during the FIRST pass it persists the raw output and sets a degraded
// narrative so the operator still gets something; on a follow-up (evidence)
// pass it returns the error and lets the caller keep the prior response.
func clusterPass(ctx context.Context, cfg Config, c *Cluster, systemPrompt, userMsg string,
	audit *SynthAudit, first bool) (*clusterAnalysisResp, error) {
	subCtx, cancel := context.WithTimeout(ctx, cfg.PerClusterTimeout)
	defer cancel()

	startedAt := time.Now()
	out, err := callClaude(subCtx, cfg, systemPrompt, userMsg)
	dur := time.Since(startedAt)
	audit.LLMDurationS += dur.Seconds()
	audit.LLMCallsTotal++
	label := "cluster_analysis"
	if !first {
		label = "cluster_analysis_evidence"
	}
	auditLLMCall(cfg, label, c.ID, dur, out, err)
	if err != nil {
		return nil, err
	}
	audit.addUsage(out)

	resp, perr := parseClusterAnalysis(out.Result)
	if perr != nil {
		dumpRawResponse(cfg, c.ID, label, out.Result)
		if first {
			c.Narrative = "(LLM returned non-JSON output; raw text follows)\n\n" +
				strings.TrimSpace(out.Result)
		}
		return nil, perr
	}
	return resp, nil
}

// clusterFinalizeNote steers the cluster's follow-up pass after the
// extracted-file previews are appended to its user message.
func clusterFinalizeNote(remaining int) string {
	if remaining > 0 {
		return fmt.Sprintf(`

Use the file contents above to finalize this cluster's analysis. Return the SAME
JSON object (same language). You MAY request more files via requested_files ONLY
if essential — %d more round(s) will be honoured.
`, remaining)
	}
	return `

Use the file contents above to finalize this cluster's analysis. Return the SAME
JSON object (same language). This is the LAST round — do NOT request more files;
omit requested_files or set it to [].
`
}

func countOKSummaries(s []evidencex.FetchSummary) int {
	n := 0
	for _, x := range s {
		if x.Status == "ok" {
			n++
		}
	}
	return n
}

func analyseOverallLLM(ctx context.Context, cfg Config, clusters []Cluster,
	systemPrompt string, audit *SynthAudit, clockReversed bool, uncorrobAliases map[string][]string) (string, error) {

	// The overall call aggregates EVERY cluster's narrative, so it routinely
	// needs more wall-clock than a single per-cluster call. Giving it the flat
	// per-cluster timeout made multi-cluster cases (e.g. advm2_3 with 11
	// clusters) consistently hit "context deadline exceeded" and fall back to
	// the deterministic stitch — the root cause behind issue #51's "executive
	// summary not functioning". Scale the budget with the cluster count.
	timeout := overallSynthTimeout(cfg.PerClusterTimeout, len(clusters))

	// The overall synthesis is the single most important Tier 2 output (the
	// report's executive summary) and it runs LAST — after every per-cluster
	// and active-search call. Callers wrap the whole run in one deadline (the
	// Web synthesize job uses a flat 15/25 min for the entire pipeline), so by
	// the time control reaches here that deadline is frequently already spent.
	// The call then fails instantly with "context deadline exceeded" (~0s) and
	// the report silently degrades to the fallback stitch + warning banner.
	// Detach from the parent's spent deadline so the overall pass always gets
	// its own budget; a genuine cancellation (Ctrl-C / superseded job) is still
	// honoured below and inside detachedDeadlineContext.
	if ctx.Err() == context.Canceled {
		return "", ctx.Err()
	}

	// Try with full per-cluster narratives first. If claude CLI fails
	// (commonly exit 1 with no stderr — usually transient or context-size
	// driven), retry once with compacted narratives (each truncated to
	// 1500 chars). Both attempts share the same overall LLM duration /
	// token counters.
	for attempt := 1; attempt <= 2; attempt++ {
		compacted := attempt == 2
		userMsg, err := buildOverallUserMessage(clusters, compacted, cfg.Language, cfg.CaseBackground, clockReversed, uncorrobAliases)
		if err != nil {
			return "", err
		}
		subCtx, cancel := detachedDeadlineContext(ctx, timeout)
		startedAt := time.Now()
		out, err := callClaude(subCtx, cfg, systemPrompt, userMsg)
		dur := time.Since(startedAt)
		audit.LLMDurationS += dur.Seconds()
		audit.LLMCallsTotal++
		cancel()
		auditLLMCall(cfg, "overall_synthesis", 0, dur, out, err)
		if err == nil {
			audit.addUsage(out)
			return strings.TrimSpace(out.Result), nil
		}
		// transient — wait a bit before retry, but only if there are
		// more attempts. Honour a genuine cancel; a spent parent deadline
		// is exactly what we detach from, so don't let it abort the retry.
		if attempt < 2 {
			if ctx.Err() == context.Canceled {
				return "", ctx.Err()
			}
			time.Sleep(3 * time.Second)
		} else {
			// last attempt failed → return error so the caller can
			// build a fallback overall_story locally.
			return "", err
		}
	}
	return "", fmt.Errorf("analyseOverallLLM: exhausted retries")
}

// execBriefMarker separates the non-technical Executive Brief (Layer 1) from
// the technical summary (Layer 2) in the overall-synthesis LLM output. Kept in
// sync with skills/overall_synthesis.md.
const execBriefMarker = "---EXEC---"

// splitExecBrief splits the overall-synthesis raw output on execBriefMarker into
// (execBrief, techSummary). When the marker is absent (older prompt, or the
// deterministic fallback stitch), execBrief is empty and techSummary is the
// whole text — so the report degrades to a single-layer executive summary.
func splitExecBrief(raw string) (execBrief, techSummary string) {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, execBriefMarker); i >= 0 {
		execBrief = strings.TrimSpace(raw[:i])
		techSummary = strings.TrimSpace(raw[i+len(execBriefMarker):])
		// A marker with nothing after it is useless — treat the brief as the
		// whole story rather than dropping the technical layer.
		if techSummary == "" {
			return "", execBrief
		}
		return execBrief, techSummary
	}
	return "", raw
}

// analyseOpenQuestionsLLM consolidates the per-cluster open questions into the
// prioritised three-tier view via skills/open_questions_synthesis.md. Questions
// from likely-noise clusters are dropped first (their narratives are demoted in
// the report, so their questions are off-topic). Returns an empty synthesis and
// NO error when there is nothing to consolidate or the skill is absent; returns
// an error only on a genuine LLM call/parse failure so the caller can log it and
// fall back to the flat OpenQuestions list.
func analyseOpenQuestionsLLM(ctx context.Context, cfg Config, clusters []Cluster,
	audit *SynthAudit) (OpenQuestionsSynthesis, error) {

	var empty OpenQuestionsSynthesis

	questions := collectAttackOpenQuestions(clusters)
	if len(questions) == 0 {
		return empty, nil
	}

	skillPath := filepath.Join(cfg.SkillsDir, "open_questions_synthesis.md")
	skill, err := os.ReadFile(skillPath)
	if err != nil {
		return empty, nil // skill not installed → silently skip
	}
	if ctx.Err() == context.Canceled {
		return empty, ctx.Err()
	}

	userMsg := buildOpenQuestionsUserMessage(questions, cfg.Language)
	timeout := cfg.PerClusterTimeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	subCtx, cancel := detachedDeadlineContext(ctx, timeout)
	defer cancel()

	startedAt := time.Now()
	out, err := callClaude(subCtx, cfg, string(skill), userMsg)
	dur := time.Since(startedAt)
	audit.LLMDurationS += dur.Seconds()
	audit.LLMCallsTotal++
	auditLLMCall(cfg, "open_questions_synthesis", 0, dur, out, err)
	if err != nil {
		return empty, err
	}
	audit.addUsage(out)

	var synth OpenQuestionsSynthesis
	if perr := decodeFirstJSON(out.Result, &synth); perr != nil {
		dumpRawResponse(cfg, 0, "open_questions_synthesis", out.Result)
		return empty, fmt.Errorf("parse open-questions JSON: %w", perr)
	}
	return synth, nil
}

// collectAttackOpenQuestions gathers the deduplicated open questions of the
// non-noise clusters, in cluster order.
func collectAttackOpenQuestions(clusters []Cluster) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range clusters {
		if IsNoiseCluster(c.AttackPhase, c.Narrative) {
			continue
		}
		for _, q := range c.OpenQuestions {
			q = strings.TrimSpace(q)
			if q == "" || seen[q] {
				continue
			}
			seen[q] = true
			out = append(out, q)
		}
	}
	return out
}

func buildOpenQuestionsUserMessage(questions []string, lang string) string {
	langInst := "出力する各論点は日本語で記述してください（入力の言語に合わせる）。"
	if strings.ToLower(lang) == "en" {
		langInst = "Write every output question in English."
	}
	body, _ := json.MarshalIndent(questions, "", "  ")
	return langInst + `

Below is the flat list of per-cluster open questions from one Windows forensic
investigation. Consolidate and prioritise them into the three-tier JSON object
described in your instructions. Return ONLY the JSON object.

OpenQuestions:
` + string(body)
}

// detachedDeadlineContext returns a context for the overall-synthesis LLM call
// that carries its OWN timeout, independent of any (already-spent) deadline on
// the parent. The overall pass runs last in a Tier 2 run, so inheriting the
// parent's deadline meant the per-cluster phase could leave it with no time and
// the executive summary would fail instantly. A genuine cancellation of the
// parent (Ctrl-C / superseded job) still propagates to the returned context;
// the parent merely running out its deadline does not. The caller must call the
// returned cancel func.
func detachedDeadlineContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), timeout)
	if parent.Done() != nil {
		go func() {
			select {
			case <-parent.Done():
				if parent.Err() == context.Canceled {
					cancel()
				}
			case <-ctx.Done():
			}
		}()
	}
	return ctx, cancel
}

// noiseNarrativeKeywords are substrings that, when present in a cluster's
// narrative, mark it as likely benign / pre-existing system activity rather
// than attacker action. Kept deliberately specific (no bare "正規"/"legitimate")
// so genuine attack narratives that merely use those words are not misflagged.
var noiseNarrativeKeywords = []string{
	"誤検知", "false positive", "false-positive",
	"正規のインストール", "正規のバックグラウンド", "正規のソフトウェア",
	"legitimate install", "legitimate software", "benign system",
	"sysprep", "first boot", "初回ブート", "vm 作成", "vm作成", "os セットアップ",
}

// IsNoiseCluster applies a conservative heuristic to decide whether a cluster
// is likely pre-existing system noise (OS setup, Sysprep, VM first-boot,
// legitimate software installs) instead of attacker activity. It is cheap by
// design — phase + narrative keywords only, no LLM — so the same call can run
// at synthesis time (fallback summary, overall LLM input) and at report time
// (Tier 3 noise badge), keeping the three call sites consistent.
func IsNoiseCluster(attackPhase, narrative string) bool {
	phase := strings.ToLower(strings.TrimSpace(attackPhase))
	if phase == "" || phase == "unknown" || phase == "noise" {
		return true
	}
	lower := strings.ToLower(narrative)
	for _, kw := range noiseNarrativeKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// fallbackOverallStoryPrefixJA / EN are the warning banners prepended to a
// fallback executive summary. Tier 3 detects these exact prefixes to render a
// visual disclaimer, so keep them in sync with html.go's buildView().
const (
	fallbackOverallStoryPrefixJA = "【注意: このサマリは LLM 生成に失敗したため、攻撃クラスタ要約の自動連結で代替しています。人手でのレビューと再実行が必要です。】"
	fallbackOverallStoryPrefixEN = "[NOTE: This summary is a fallback auto-stitch because the LLM overall synthesis failed. Manual review and re-run required.]"
)

// overallSynthTimeout returns the wall-clock budget for the case-wide overall
// synthesis call. Unlike a per-cluster call it aggregates every cluster, so it
// gets a base of 2× the per-cluster timeout plus 30s per cluster, capped at
// 20 min. (Issue #51: the flat per-cluster budget made multi-cluster cases
// time out and fall back to the deterministic stitch.)
func overallSynthTimeout(perCluster time.Duration, nClusters int) time.Duration {
	if perCluster <= 0 {
		perCluster = 5 * time.Minute
	}
	t := perCluster*2 + time.Duration(nClusters)*30*time.Second
	if max := 20 * time.Minute; t > max {
		t = max
	}
	return t
}

// fallbackOverallStory builds a deterministic overall_story by stitching
// together each cluster's narrative. Called when the LLM-based overall
// pass fails — the operator still gets a coherent case-level summary
// instead of an empty section in the report. Likely-noise clusters are
// dropped so the fallback summary does not present VM-creation / Sysprep
// activity as part of the attack chain, and a warning banner is prepended
// so the operator (and Tier 3) knows this is a degraded summary.
func fallbackOverallStory(clusters []Cluster, lang string) string {
	ja := strings.ToLower(lang) != "en"

	// Separate attack clusters from likely-noise clusters.
	var attackClusters []Cluster
	for _, c := range clusters {
		if !IsNoiseCluster(c.AttackPhase, c.Narrative) {
			attackClusters = append(attackClusters, c)
		}
	}
	if len(attackClusters) == 0 {
		attackClusters = clusters // nothing classified as attack → keep all
	}

	var sb strings.Builder
	if ja {
		sb.WriteString(fallbackOverallStoryPrefixJA)
	} else {
		sb.WriteString(fallbackOverallStoryPrefixEN)
	}
	for _, c := range attackClusters {
		if c.Narrative == "" {
			continue
		}
		sb.WriteString("\n\n")
		sb.WriteString(c.Narrative)
	}
	return sb.String()
}

// temporalOutlierClusters flags clusters whose time window sits more than a
// year away from the median cluster — a strong signal of pre-existing system
// activity (VM creation, Sysprep) bundled into the same case as the real
// incident. Returns a bool slice aligned with the input. Needs at least three
// timestamped clusters for a stable median; otherwise nothing is flagged.
func temporalOutlierClusters(clusters []Cluster) []bool {
	flags := make([]bool, len(clusters))

	type centered struct {
		idx    int
		center time.Time
	}
	var pts []centered
	for i, c := range clusters {
		if c.StartTS.IsZero() {
			continue
		}
		center := c.StartTS
		if !c.EndTS.IsZero() && c.EndTS.After(c.StartTS) {
			center = c.StartTS.Add(c.EndTS.Sub(c.StartTS) / 2)
		}
		pts = append(pts, centered{idx: i, center: center})
	}
	if len(pts) < 3 {
		return flags
	}

	sorted := append([]centered(nil), pts...)
	sort.Slice(sorted, func(a, b int) bool {
		return sorted[a].center.Before(sorted[b].center)
	})
	median := sorted[len(sorted)/2].center

	const outlierGap = 365 * 24 * time.Hour
	for _, p := range pts {
		d := p.center.Sub(median)
		if d < 0 {
			d = -d
		}
		if d > outlierGap {
			flags[p.idx] = true
		}
	}
	return flags
}

type clusterAnalysisResp struct {
	Narrative       string                    `json:"narrative"`
	AttackPhase     string                    `json:"attack_phase"`
	MITRETechniques []string                  `json:"mitre_techniques"`
	OpenQuestions   []string                  `json:"open_questions"`
	RequestedFiles  []evidencex.RequestedFile `json:"requested_files,omitempty"`
}

func parseClusterAnalysis(text string) (*clusterAnalysisResp, error) {
	var out clusterAnalysisResp
	if err := decodeFirstJSON(text, &out); err != nil {
		return nil, fmt.Errorf("unmarshal: %w (head: %s)", err, truncate(text, 200))
	}
	return &out, nil
}

func buildClusterUserMessage(c *Cluster, lang, background string, evidenceEnabled, clockReversed bool) (string, error) {
	type fLite struct {
		Source          string   `json:"source"`
		RuleID          string   `json:"rule_id"`
		Title           string   `json:"title"`
		Severity        string   `json:"severity"`
		Description     string   `json:"description,omitempty"`
		MITRETechniques []string `json:"mitre_techniques,omitempty"`
		MITRETactic     string   `json:"mitre_tactic,omitempty"`
		EvidenceCount   int      `json:"evidence_count"`
		FirstTimestamp  string   `json:"first_timestamp,omitempty"`
	}
	var fls []fLite
	for _, f := range c.Findings {
		fl := fLite{
			Source:          f.Source,
			RuleID:          f.RuleID,
			Title:           f.Title,
			Severity:        f.Severity,
			Description:     f.Description,
			MITRETechniques: f.MITRETechniques,
			MITRETactic:     f.MITRETactic,
			EvidenceCount:   len(f.Evidence),
		}
		if ts := f.FirstTimestamp(); !ts.IsZero() {
			fl.FirstTimestamp = ts.Format(time.RFC3339)
		}
		fls = append(fls, fl)
	}
	type ctx struct {
		ClusterID          int                     `json:"cluster_id"`
		WindowStart        string                  `json:"window_start,omitempty"`
		WindowEnd          string                  `json:"window_end,omitempty"`
		ExaminerBackground *common.ExaminerContext `json:"examiner_background,omitempty"`
		Findings           []fLite                 `json:"findings"`
		RawTimelineEvents  []TimelineEvent         `json:"raw_timeline_events"`
	}
	pkt := ctx{
		ClusterID:          c.ID,
		ExaminerBackground: common.NewExaminerContext(background),
		Findings:           fls,
		RawTimelineEvents:  c.RawTimelineExcerpt,
	}
	if !c.StartTS.IsZero() {
		pkt.WindowStart = c.StartTS.Format(time.RFC3339)
	}
	if !c.EndTS.IsZero() {
		pkt.WindowEnd = c.EndTS.Format(time.RFC3339)
	}
	body, err := json.MarshalIndent(pkt, "", "  ")
	if err != nil {
		return "", err
	}
	langInst := "Output language: Japanese (日本語). Write ALL prose fields (narrative, open_questions) in Japanese."
	if strings.ToLower(lang) == "en" {
		langInst = "Output language: English. Write ALL prose fields in English."
	}
	reqFilesKey := ""
	reqFilesRule := ""
	if evidenceEnabled {
		reqFilesKey = `,
    "requested_files": [
      {
        "path": "<file path seen in the findings/timeline — Windows 'C:\\..\\x.ps1' or NTFS-relative>",
        "evidence_id": "<optional: which disk image, only if the case has several>",
        "rationale": "<1-line: what reading this file would confirm about the attack chain>"
      }
    ]`
		reqFilesRule = `

requested_files (OPTIONAL — use [] or omit if no file's contents are needed):
- Use ONLY when reading a file referenced in this cluster would resolve an
  open_question or confirm the chain: a dropped script, a config, a staged
  archive, a suspicious binary you want strings from.
- The file is extracted READ-ONLY from the case's disk image and its contents
  are returned to you for a bounded follow-up pass, so you can ground the
  narrative in what the file actually contains instead of inferring.
- Request only the few most decision-relevant files.`
	}
	prelude := `Below is one TEMPORAL CLUSTER of Tier 1 findings from a Windows
forensic case, plus the raw timeline events from unified_events that fall
in the same ±5 min window. Reconstruct the attack-chain story for this
cluster.

` + langInst + `

Return ONLY a single JSON object:

  {
    "narrative": "(1-3 paragraphs for a human reader. Do NOT embed rule_ids, audit_ids, or UUIDs in the prose — those belong in the evidence arrays only. Mention tools, accounts, and techniques by descriptive name.)",
    "attack_phase": "(one of: initial-access | execution | persistence | privilege-escalation | defense-evasion | credential-access | discovery | lateral-movement | collection | command-and-control | exfiltration | impact | reconnaissance | noise | unknown. Use \"noise\" ONLY when the ENTIRE cluster is benign pre-existing system activity — e.g. a pure OS-boot sequence or provisioning with no attacker action mixed in. If the cluster contains ANY attacker activity (recon, execution, credential access) alongside a benign event like a clock change, classify it by the ATTACK phase, not noise.)",
    "mitre_techniques": ["T1059", "T1003.001"],
    "open_questions": [
      "(specific evidence gap or unresolved question — same language as narrative)",
      ...
    ]` + reqFilesKey + `
  }

No markdown fences, no text outside the JSON.

COVERAGE REQUIREMENT (account for every significant finding — do not silently drop detected attacker activity):
- Every critical/high finding in this cluster MUST be reflected in the narrative prose, whatever its tactic (discovery, credential-access, execution, persistence, lateral-movement, collection, exfiltration, command-and-control, impact, ...). Do NOT omit a detected attacker action just because the dominant event in the cluster is something else.
- If a finding is itself a DETECTION or BLOCK by a security control (antivirus / EDR / Microsoft Defender / AMSI / AppLocker — e.g. a quarantine of a credential-dumping tool), narrate it as an ATTEMPTED action that the control detected and, where the evidence shows it, blocked: state that the attempt occurred AND that it was caught, so the underlying action did NOT succeed. Do not omit it, and do not describe a blocked action as having succeeded.
- This does NOT license over-claiming: never assert a tool, technique, or successful outcome the findings do not support. "Attempted but detected/blocked" and "evidence does not show success" are the correct framings; the absence of a finding is never evidence that something succeeded.` + reqFilesRule + clusterTimelineWarning(clockReversed) + `

ClusterContext:
`
	return prelude + string(body), nil
}

// clusterTimelineWarning steers a per-cluster narrative away from the
// clock-reversal hallucination (attacker timestomp / re-intrusion) when the case
// timeline is known to be non-monotonic. Empty when the clock is reliable.
func clusterTimelineWarning(clockReversed bool) string {
	if !clockReversed {
		return ""
	}
	return `

TIMELINE WARNING: this case's clock was stepped backward (a system time change),
so event timestamps are NOT a reliable order and may sit out of sequence. Do NOT
describe an attacker "rewinding the clock", a "re-intrusion", or a "second phase"
to explain out-of-order events — treat a backward time change as most likely
provisioning / OS-setup / a Set-Date correction unless an attacker-context process
demonstrably called a time-change API. Prefer "timeline unreliable / re-anchor
required" over an anti-forensic conclusion.`
}

func buildOverallUserMessage(clusters []Cluster, compactNarratives bool, lang, background string, clockReversed bool, uncorrobAliases map[string][]string) (string, error) {
	type clite struct {
		ID               int      `json:"cluster_id"`
		AttackPhase      string   `json:"attack_phase,omitempty"`
		Narrative        string   `json:"narrative,omitempty"`
		MITRETechniques  []string `json:"mitre_techniques,omitempty"`  // finding-derived (confirmed)
		MITREUnconfirmed []string `json:"mitre_unconfirmed,omitempty"` // LLM-suggested, no finding backing
		WindowStart      string   `json:"window_start,omitempty"`
		WindowEnd        string   `json:"window_end,omitempty"`
		FindingCount     int      `json:"finding_count"`
		IsNoiseCandidate bool     `json:"is_noise_candidate,omitempty"`
	}
	const compactMaxChars = 1500
	temporalOutlier := temporalOutlierClusters(clusters)
	var cls []clite
	for i, c := range clusters {
		narrative := c.Narrative
		if compactNarratives && len(narrative) > compactMaxChars {
			narrative = narrative[:compactMaxChars] + "...[truncated for retry]"
		}
		cl := clite{
			ID:               c.ID,
			AttackPhase:      c.AttackPhase,
			Narrative:        narrative,
			MITRETechniques:  findingTechniqueUnion(c),
			MITREUnconfirmed: clusterUnconfirmedTechniques(c),
			FindingCount:     len(c.Findings),
			// Use the STRICT benign predicate (not IsNoiseCluster): a cluster that
			// merely notes a per-finding false positive must not be flagged "noise"
			// to the overall LLM, or it drops the real attack from the summary.
			IsNoiseCandidate: isBenignCluster(c, temporalOutlier[i]),
		}
		if !c.StartTS.IsZero() {
			cl.WindowStart = c.StartTS.Format(time.RFC3339)
		}
		if !c.EndTS.IsZero() {
			cl.WindowEnd = c.EndTS.Format(time.RFC3339)
		}
		cls = append(cls, cl)
	}
	body, err := json.MarshalIndent(cls, "", "  ")
	if err != nil {
		return "", err
	}
	langInst := "出力言語: 日本語。本文はすべて日本語で記述してください。"
	if strings.ToLower(lang) == "en" {
		langInst = "Output language: English."
	}

	// Deterministic steering directives (issue #82): keep the executive summary
	// grounded and prevent the clock-reversal → "attacker rewound time / re-intrusion"
	// hallucination at generation time. These are derived facts, not prompt fluff.
	var directives strings.Builder
	directives.WriteString(`
GROUNDING RULES (must follow):
- Treat mitre_techniques as confirmed; treat mitre_unconfirmed as UNVERIFIED hypotheses — never assert them as fact and never present them as the attack's techniques.
- Do NOT name a specific offensive tool (e.g. Mimikatz) or technique (e.g. web shell, Pass-the-Hash) unless a cluster narrative or finding explicitly supports it. If unsupported, omit it or mark it as an open question.
- Do NOT claim credential theft / lateral movement / re-intrusion succeeded unless the evidence shows it; "evidence does not show X" is a valid statement.
`)
	if rel, notes := detectTimelineReliability(clusters, clockReversed, lang); rel == "unreliable" {
		directives.WriteString("- TIMELINE RELIABILITY: UNRELIABLE. ")
		directives.WriteString(strings.Join(notes, " "))
		directives.WriteString("\n  Do NOT attribute time reversals/jumps to an attacker timestomp or a later re-intrusion. Treat them as re-anchoring / provisioning artifacts first.\n")
	}
	// Per-claim corroboration overrides: forbid asserting an FP-prone claim the
	// case does not corroborate, even when a finding is tagged with it (the
	// generic rule above let a "Web Shell Detection"-titled finding through).
	for _, line := range uncorroboratedClaimDirectives(uncorrobAliases, strings.ToLower(lang) != "en") {
		directives.WriteString(line)
		directives.WriteString("\n")
	}
	directives.WriteString(common.ExaminerContextPrompt(background))

	return langInst + directives.String() + `
Below are the per-cluster narratives you produced for a Windows
forensic case. Write a single 4-5 paragraph case-level story that connects
them into one attack timeline. Mention concrete techniques, host names, and
accounts by name. Be honest about gaps. Do NOT embed rule_ids, audit_ids,
or UUIDs in the prose. Return plain text only, no markdown.

ClusterSummaries:
` + string(body), nil
}

// ----------------------------------------------------------------------------
// claude CLI
// ----------------------------------------------------------------------------

type claudeOutput struct {
	IsError      bool    `json:"is_error"`
	Result       string  `json:"result"`
	StopReason   string  `json:"stop_reason"`
	SessionID    string  `json:"session_id"`
	TotalCostUSD float64 `json:"total_cost_usd"`
	Usage        struct {
		InputTokens              int `json:"input_tokens"`
		CacheReadInputTokens     int `json:"cache_read_input_tokens"`
		CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
		OutputTokens             int `json:"output_tokens"`
	} `json:"usage"`
	InputTokens  int `json:"-"`
	OutputTokens int `json:"-"`
}

// auditLLMCall appends one llm_call record to the unified execution log. detail
// names the sub-kind (e.g. "cluster_analysis"). Logs both success and failure
// so the audit trail shows attempts that errored, not just the ones that worked.
func auditLLMCall(cfg Config, detail string, clusterID int, dur time.Duration, out *claudeOutput, callErr error) {
	a := auditlog.Action{
		Actor:           "tier2",
		Kind:            "llm_call",
		Detail:          detail,
		ClusterID:       clusterID,
		Model:           cfg.Model,
		DurationSeconds: dur.Seconds(),
	}
	if callErr != nil {
		a.Success = auditlog.BoolPtr(false)
		a.Error = truncate(callErr.Error(), 200)
	} else if out != nil {
		a.Success = auditlog.BoolPtr(true)
		a.InputTokens = out.Usage.InputTokens
		a.OutputTokens = out.Usage.OutputTokens
		a.CacheReadTokens = out.Usage.CacheReadInputTokens
		a.CostUSD = out.TotalCostUSD
	}
	cfg.al.Append(a)
}

// callClaude dispatches one Tier 2 LLM call to whichever transport is
// configured (Anthropic API > Vertex AI > hidden CLI fallback — see
// internal/llm). The API paths cache the system prompt ONLY, so the large
// single-use user payloads are billed as plain input instead of being
// cache-written at the 1.25x premium. All paths send byte-identical content to
// the model, so analysis is unaffected.
func callClaude(ctx context.Context, cfg Config, sysPrompt, userMsg string) (*claudeOutput, error) {
	switch t := llm.Resolve(); t.Kind {
	case llm.KindVertex:
		return callVertexAPI(ctx, cfg, t, sysPrompt, userMsg)
	case llm.KindAnthropic:
		return callAnthropicAPI(ctx, cfg, t.APIKey(), sysPrompt, userMsg)
	default:
		return callClaudeCLI(ctx, cfg, sysPrompt, userMsg)
	}
}

func callClaudeCLI(ctx context.Context, cfg Config, sysPrompt, userMsg string) (*claudeOutput, error) {
	args := []string{
		"-p",
		"--output-format", "json",
		"--system-prompt", sysPrompt,
		"--tools", "",
		"--no-session-persistence",
		"--exclude-dynamic-system-prompt-sections",
	}
	if cfg.Model != "" {
		args = append(args, "--model", cfg.Model)
		args = append(args, "--fallback-model", cfg.Model)
	}
	cmd := exec.CommandContext(ctx, cfg.ClaudeBinary, args...)
	cmd.Stdin = strings.NewReader(userMsg)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("exec: %w (stderr: %s)", err, truncate(stderr.String(), 200))
	}
	var out claudeOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("parse: %w (head: %s)", err, truncate(stdout.String(), 200))
	}
	if out.IsError {
		return nil, fmt.Errorf("claude error (%s): %s", out.StopReason, truncate(out.Result, 200))
	}
	out.InputTokens = out.Usage.InputTokens
	out.OutputTokens = out.Usage.OutputTokens
	return &out, nil
}

// ----------------------------------------------------------------------------
// synthesis assembly
// ----------------------------------------------------------------------------

// normalizeSynthLang collapses the language config to the two values the
// narratives are actually written in ("en" | "ja"), so synthesis.json records a
// canonical value Tier 3 can compare against.
func normalizeSynthLang(lang string) string {
	if strings.EqualFold(strings.TrimSpace(lang), "en") {
		return "en"
	}
	return "ja"
}

func buildCaseSynthesis(caseID string, findings []Finding, clusters []Cluster,
	overall string, audit SynthAudit, lang string, gctx groundingContext) CaseSynthesis {

	execBrief, techSummary := splitExecBrief(overall)
	cs := CaseSynthesis{
		CaseID:        caseID,
		GeneratedAt:   time.Now().UTC(),
		Language:      normalizeSynthLang(lang),
		TotalFindings: countFindings(clusters),
		ClusterCount:  len(clusters),
		OverallStory:  techSummary,
		ExecBrief:     execBrief,
		TechSummary:   techSummary,
		Audit:         audit,
	}

	for _, c := range clusters {
		sc := SynthCluster{
			ID:               c.ID,
			StartTS:          c.StartTS,
			EndTS:            c.EndTS,
			AttackPhase:      c.AttackPhase,
			Narrative:        c.Narrative,
			MITRETechniques:  findingTechniqueUnion(c),
			MITREUnconfirmed: clusterUnconfirmedTechniques(c),
			OpenQuestions:    c.OpenQuestions,
			ActiveSearch:     c.ActiveSearch,
			EvidenceFetches:  c.EvidenceFetches,
		}
		for _, f := range c.Findings {
			prov, conf := ProvenanceForSource(f.Source)
			sc.FindingRefs = append(sc.FindingRefs, FindingRef{
				Source:     f.Source,
				RuleID:     f.RuleID,
				Title:      f.Title,
				Severity:   f.Severity,
				Provenance: prov,
				Confidence: conf,
			})
		}
		// (cluster narratives already carry the deterministic coverage addendum:
		// applyCoverageBackstop ran before the overall-synthesis pass, so sc.Narrative
		// inherits it via c.Narrative above.)
		cs.Clusters = append(cs.Clusters, sc)
	}

	// Authoritative matrix = finding-derived, then split by corroboration: tags a
	// high-impact technique needs case-level support for (web shell with no web
	// server, PtH explained by a brute-force burst, timestomp on a reversed clock)
	// are demoted to unconfirmed rather than asserted (issue #82, tasks 1/2/4).
	confirmed, demoted, demoteNotes := splitCorroboratedMITRE(buildMITREMapping(clusters), gctx, lang)
	cs.MITREMapping = confirmed
	cs.MITREUnconfirmed = append(buildUnconfirmedMITRE(clusters), demoted...)
	cs.MITREDemotionNotes = demoteNotes
	// Close the corroboration loop on the flat open-questions list: a question
	// asking to confirm/locate an uncorroborated claim (e.g. "find the web
	// shell's hash") is replaced by a resolved note, so the report does not send
	// an analyst hunting for an artifact the case shows is absent.
	cs.OpenQuestions = reframeResolvedOpenQuestions(
		mergeAllOpenQuestions(clusters), uncorroboratedClaimAliases(gctx), strings.ToLower(lang) != "en")
	cs.TimelineReliability, cs.TimelineNotes = detectTimelineReliability(clusters, gctx.ClockReversed, lang)
	confirmedTech := map[string]bool{}
	for _, e := range confirmed {
		confirmedTech[e.Technique] = true
	}
	cs.UngroundedMentions = findUngroundedMentions(execBrief+"\n"+techSummary, findings, confirmedTech)
	return cs
}

// isBenignCluster reports whether a cluster must be excluded from the attack
// MITRE matrix and IOC derivation because it is pre-existing system /
// provisioning activity (issue #82, task 4 — stop benign boot/provisioning being
// double-counted as attacker action).
//
// It keys ONLY off robust, unambiguous signals: a temporal outlier (a cluster a
// year+ from the others = provisioning bundled into the case) or an explicit
// "noise" AttackPhase (the LLM's affirmative judgment). It deliberately does NOT
// sniff narrative keywords: the LLM routinely discusses provisioning / boot /
// false-positive context INSIDE a genuine attack cluster, and a single such word
// must never exclude a real attack wholesale. (Regression caught in the
// distrib_winrm_spray run: the credential-access cluster — brute force + recon —
// was dropped because its narrative mentioned 誤検知 for one signature, taking
// T1110.001 with it; the defense-evasion cluster was dropped for mentioning the
// provisioning context.) The corroboration layer (splitCorroboratedMITRE) is the
// transparent path for demoting specific FP-prone technique tags with a recorded
// reason, rather than silently dropping a cluster.
func isBenignCluster(c Cluster, temporalOutlier bool) bool {
	if temporalOutlier {
		return true
	}
	// An LLM "noise" label only excludes a cluster that carries NO high/critical
	// signature finding. This is the deterministic safety net: a real attack
	// cluster always carries high-severity Tier 1 hits, so even if the LLM
	// mislabels it "noise" (it over-applied the label to a WinRM attack session
	// that merely started with a benign clock change in the distrib_winrm_spray
	// run), its techniques are never silently dropped from the matrix.
	if strings.TrimSpace(strings.ToLower(c.AttackPhase)) == "noise" {
		return !clusterHasSignificantFinding(c)
	}
	return false
}

// clusterHasSignificantFinding reports whether any finding in the cluster is
// high or critical severity — the signal that real attacker activity is present
// regardless of how the LLM phased the cluster.
func clusterHasSignificantFinding(c Cluster) bool {
	for _, f := range c.Findings {
		switch strings.ToLower(strings.TrimSpace(f.Severity)) {
		case "high", "critical":
			return true
		}
	}
	return false
}

// buildMITREMapping builds the authoritative, case-wide MITRE matrix from the
// DETERMINISTIC finding-derived techniques only (findingTechniqueUnion), never
// from the cluster LLM's free-form mitre_techniques — those go to
// MITREUnconfirmed. Clusters classified benign (provisioning / temporal
// outliers) are excluded so their techniques don't inflate the attack matrix
// (issue #82, tasks 2 + 4).
func buildMITREMapping(clusters []Cluster) []MITREEntry {
	outliers := temporalOutlierClusters(clusters)

	// technique -> authoritative tactic, learned from finding rule_meta
	// (preferred over the cluster's coarse AttackPhase).
	techTactic := map[string]string{}
	for _, c := range clusters {
		for _, f := range c.Findings {
			if f.MITRETactic == "" {
				continue
			}
			for _, t := range f.MITRETechniques {
				if techTactic[t] == "" {
					techTactic[t] = f.MITRETactic
				}
			}
		}
	}

	type k struct{ technique string }
	type v struct {
		count    int
		clusters map[int]struct{}
		tactic   string
	}
	bucket := map[k]*v{}
	for i, c := range clusters {
		if isBenignCluster(c, outliers[i]) {
			continue
		}
		for _, t := range findingTechniqueUnion(c) {
			key := k{technique: t}
			if bucket[key] == nil {
				bucket[key] = &v{clusters: map[int]struct{}{}}
			}
			bucket[key].count++
			bucket[key].clusters[c.ID] = struct{}{}
			if bucket[key].tactic == "" {
				if tac := techTactic[t]; tac != "" {
					bucket[key].tactic = tac
				} else if c.AttackPhase != "" {
					bucket[key].tactic = c.AttackPhase
				}
			}
		}
	}
	out := make([]MITREEntry, 0, len(bucket))
	for kk, vv := range bucket {
		ids := make([]int, 0, len(vv.clusters))
		for cid := range vv.clusters {
			ids = append(ids, cid)
		}
		sort.Ints(ids)
		out = append(out, MITREEntry{
			Technique:    kk.technique,
			Tactic:       vv.tactic,
			FindingCount: vv.count,
			ClusterIDs:   ids,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FindingCount != out[j].FindingCount {
			return out[i].FindingCount > out[j].FindingCount
		}
		return out[i].Technique < out[j].Technique
	})
	return out
}

// buildUnconfirmedMITRE aggregates the techniques the cluster LLM narratives
// proposed but NO finding backs (clusterUnconfirmedTechniques). These are the
// "参考 / unconfirmed" entries the report shows separately from the
// finding-derived matrix so an LLM guess (web shell, Pass-the-Hash) is never
// silently promoted to a confirmed technique (issue #82, task 2).
func buildUnconfirmedMITRE(clusters []Cluster) []MITREEntry {
	type v struct {
		count    int
		clusters map[int]struct{}
	}
	bucket := map[string]*v{}
	for _, c := range clusters {
		for _, t := range clusterUnconfirmedTechniques(c) {
			if bucket[t] == nil {
				bucket[t] = &v{clusters: map[int]struct{}{}}
			}
			bucket[t].count++
			bucket[t].clusters[c.ID] = struct{}{}
		}
	}
	out := make([]MITREEntry, 0, len(bucket))
	for tech, vv := range bucket {
		ids := make([]int, 0, len(vv.clusters))
		for cid := range vv.clusters {
			ids = append(ids, cid)
		}
		sort.Ints(ids)
		out = append(out, MITREEntry{Technique: tech, FindingCount: vv.count, ClusterIDs: ids})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FindingCount != out[j].FindingCount {
			return out[i].FindingCount > out[j].FindingCount
		}
		return out[i].Technique < out[j].Technique
	})
	return out
}

func mergeAllOpenQuestions(clusters []Cluster) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range clusters {
		for _, q := range c.OpenQuestions {
			q = strings.TrimSpace(q)
			if q == "" || seen[q] {
				continue
			}
			seen[q] = true
			out = append(out, q)
		}
	}
	return out
}

func countFindings(clusters []Cluster) int {
	n := 0
	for _, c := range clusters {
		n += len(c.Findings)
	}
	return n
}

// dumpRawResponse saves an LLM response that failed to parse so the
// operator can triage it after the fact. Path: outputs/cases/<id>/synthesis_debug/.
func dumpRawResponse(cfg Config, clusterID int, label, text string) {
	dir := filepath.Join(filepath.Dir(cfg.OutputPath), "synthesis_debug")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	name := fmt.Sprintf("cluster%02d_%s_%s.txt", clusterID, label,
		time.Now().UTC().Format("20060102T150405Z"))
	_ = os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644)
}

func writeSynthesis(path string, cs CaseSynthesis) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(cs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o644)
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

func mergeUnique(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range append(a, b...) {
		x = strings.TrimSpace(x)
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func emit(cfg Config, ev Event) {
	if cfg.ProgressFn != nil {
		cfg.ProgressFn(ev)
	}
}
