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

	_ "github.com/marcboeker/go-duckdb"
)

// Config drives Run.
type Config struct {
	CaseID            string
	FindingsBaseDir   string        // outputs/cases/<id>/findings
	OutputPath        string        // outputs/cases/<id>/synthesis.json (default)
	DBPath            string        // outputs/cases.duckdb
	SkillsDir         string        // default "skills"
	SkillName         string        // default "timeline_review" (skills/<name>.md)
	ClaudeBinary      string        // default "claude"
	Model             string        // empty = CLI default
	ClusterGap        time.Duration // default 30 min
	TimelineWindow    time.Duration // default 5 min
	MaxRowsPerCluster int           // default 300
	PerClusterTimeout time.Duration // default 5 min
	ActiveSearch      bool          // enable hypothesis-driven SQL pass per cluster
	DryRun            bool
	ProgressFn        func(Event)
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

	findings, err = EnrichTimestamps(ctx, db, cfg.CaseID, findings)
	if err != nil {
		return rep, fmt.Errorf("enrich timestamps: %w", err)
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
		if err := analyseClusterLLM(ctx, cfg, &clusters[i], string(skillBytes), &audit); err != nil {
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

	// Overall synthesis call: feed the per-cluster narratives back to LLM
	// for one case-wide story. Keep prompt small (cluster summaries only).
	overall, err := analyseOverallLLM(ctx, cfg, clusters, string(skillBytes), &audit)
	if err != nil {
		// Fall back to a deterministic per-cluster stitch so the report
		// still has SOMETHING in the Executive Summary slot.
		emit(cfg, Event{Phase: "llm",
			Message: fmt.Sprintf("overall LLM failed (%v) — falling back to per-cluster stitch", err)})
		overall = fallbackOverallStory(clusters)
	}

	emit(cfg, Event{Phase: "writing",
		Message: fmt.Sprintf("writing %s", cfg.OutputPath)})
	cs := buildCaseSynthesis(cfg.CaseID, findings, clusters, overall, audit)
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
	emit(cfg, Event{Phase: "done",
		Message: fmt.Sprintf("done in %.1fs (%d clusters, %d LLM calls)",
			rep.Duration, len(clusters), audit.LLMCallsTotal),
		Count: len(clusters)})
	return rep, nil
}

// ----------------------------------------------------------------------------
// LLM per-cluster analysis
// ----------------------------------------------------------------------------

func analyseClusterLLM(ctx context.Context, cfg Config, c *Cluster, systemPrompt string,
	audit *SynthAudit) error {

	userMsg, err := buildClusterUserMessage(c)
	if err != nil {
		return err
	}
	subCtx, cancel := context.WithTimeout(ctx, cfg.PerClusterTimeout)
	defer cancel()

	startedAt := time.Now()
	out, err := callClaudeCLI(subCtx, cfg, systemPrompt, userMsg)
	dur := time.Since(startedAt)
	audit.LLMDurationS += dur.Seconds()
	audit.LLMCallsTotal++
	if err != nil {
		return err
	}
	audit.addUsage(out)

	resp, err := parseClusterAnalysis(out.Result)
	if err != nil {
		// Persist the raw LLM output for triage and degrade gracefully:
		// keep the raw text as the cluster's narrative so the operator
		// still gets the analysis instead of an empty cluster.
		dumpRawResponse(cfg, c.ID, "cluster_analysis", out.Result)
		c.Narrative = "(LLM returned non-JSON output; raw text follows)\n\n" +
			strings.TrimSpace(out.Result)
		return err
	}
	c.Narrative = resp.Narrative
	c.AttackPhase = resp.AttackPhase
	c.MITRETechniques = mergeUnique(c.MITRETechniques, resp.MITRETechniques)
	c.OpenQuestions = resp.OpenQuestions
	return nil
}

func analyseOverallLLM(ctx context.Context, cfg Config, clusters []Cluster,
	systemPrompt string, audit *SynthAudit) (string, error) {

	// Try with full per-cluster narratives first. If claude CLI fails
	// (commonly exit 1 with no stderr — usually transient or context-size
	// driven), retry once with compacted narratives (each truncated to
	// 1500 chars). Both attempts share the same overall LLM duration /
	// token counters.
	for attempt := 1; attempt <= 2; attempt++ {
		compacted := attempt == 2
		userMsg, err := buildOverallUserMessage(clusters, compacted)
		if err != nil {
			return "", err
		}
		subCtx, cancel := context.WithTimeout(ctx, cfg.PerClusterTimeout)
		startedAt := time.Now()
		out, err := callClaudeCLI(subCtx, cfg, systemPrompt, userMsg)
		dur := time.Since(startedAt)
		audit.LLMDurationS += dur.Seconds()
		audit.LLMCallsTotal++
		cancel()
		if err == nil {
			audit.addUsage(out)
			return strings.TrimSpace(out.Result), nil
		}
		// transient — wait a bit before retry, but only if there are
		// more attempts.
		if attempt < 2 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(3 * time.Second):
			}
		} else {
			// last attempt failed → return error so the caller can
			// build a fallback overall_story locally.
			return "", err
		}
	}
	return "", fmt.Errorf("analyseOverallLLM: exhausted retries")
}

// fallbackOverallStory builds a deterministic overall_story by stitching
// together each cluster's narrative. Called when the LLM-based overall
// pass fails — the operator still gets a coherent case-level summary
// instead of an empty section in the report.
func fallbackOverallStory(clusters []Cluster) string {
	var sb strings.Builder
	sb.WriteString("(LLM overall synthesis unavailable; auto-stitched per-cluster narratives follow.)\n\n")
	for i, c := range clusters {
		if i > 0 {
			sb.WriteString("\n\n")
		}
		fmt.Fprintf(&sb, "Cluster #%d", c.ID)
		if !c.StartTS.IsZero() && !c.EndTS.IsZero() {
			fmt.Fprintf(&sb, " (%s ~ %s)",
				c.StartTS.UTC().Format(time.RFC3339),
				c.EndTS.UTC().Format(time.RFC3339))
		}
		if c.AttackPhase != "" {
			fmt.Fprintf(&sb, " — %s", c.AttackPhase)
		}
		sb.WriteString(":\n")
		if c.Narrative != "" {
			sb.WriteString(c.Narrative)
		} else {
			sb.WriteString("(no narrative)")
		}
	}
	return sb.String()
}

type clusterAnalysisResp struct {
	Narrative       string   `json:"narrative"`
	AttackPhase     string   `json:"attack_phase"`
	MITRETechniques []string `json:"mitre_techniques"`
	OpenQuestions   []string `json:"open_questions"`
}

func parseClusterAnalysis(text string) (*clusterAnalysisResp, error) {
	var out clusterAnalysisResp
	if err := decodeFirstJSON(text, &out); err != nil {
		return nil, fmt.Errorf("unmarshal: %w (head: %s)", err, truncate(text, 200))
	}
	return &out, nil
}

func buildClusterUserMessage(c *Cluster) (string, error) {
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
		ClusterID         int             `json:"cluster_id"`
		WindowStart       string          `json:"window_start,omitempty"`
		WindowEnd         string          `json:"window_end,omitempty"`
		Findings          []fLite         `json:"findings"`
		RawTimelineEvents []TimelineEvent `json:"raw_timeline_events"`
	}
	pkt := ctx{
		ClusterID:         c.ID,
		Findings:          fls,
		RawTimelineEvents: c.RawTimelineExcerpt,
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
	prelude := `Below is one TEMPORAL CLUSTER of Tier 1 findings from a Windows
forensic case, plus the raw timeline events from unified_events that fall
in the same ±5 min window. Reconstruct the attack-chain story for this
cluster.

Return ONLY a single JSON object:

  {
    "narrative":   "(1-3 paragraphs reconstructing what happened in this cluster, citing the finding rule_ids you used)",
    "attack_phase": "(one of: initial-access | execution | persistence | privilege-escalation | defense-evasion | credential-access | discovery | lateral-movement | collection | command-and-control | exfiltration | impact | reconnaissance | unknown)",
    "mitre_techniques": ["T1059", "T1003.001", ...],
    "open_questions": [
      "(any specific evidence missing / unresolved within this cluster)",
      ...
    ]
  }

No markdown fences, no text outside the JSON.

ClusterContext:
`
	return prelude + string(body), nil
}

func buildOverallUserMessage(clusters []Cluster, compactNarratives bool) (string, error) {
	type clite struct {
		ID              int      `json:"cluster_id"`
		AttackPhase     string   `json:"attack_phase,omitempty"`
		Narrative       string   `json:"narrative,omitempty"`
		MITRETechniques []string `json:"mitre_techniques,omitempty"`
		WindowStart     string   `json:"window_start,omitempty"`
		WindowEnd       string   `json:"window_end,omitempty"`
		FindingCount    int      `json:"finding_count"`
	}
	const compactMaxChars = 1500
	var cls []clite
	for _, c := range clusters {
		narrative := c.Narrative
		if compactNarratives && len(narrative) > compactMaxChars {
			narrative = narrative[:compactMaxChars] + "...[truncated for retry]"
		}
		cl := clite{
			ID:              c.ID,
			AttackPhase:     c.AttackPhase,
			Narrative:       narrative,
			MITRETechniques: c.MITRETechniques,
			FindingCount:    len(c.Findings),
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
	return `Below are the per-cluster narratives you produced for a Windows
forensic case. Write a single 2-4 paragraph case-level story that connects
them into one attack timeline. Mention concrete techniques and dwell time
where you can; be honest about gaps. Return plain text, no markdown.

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

func buildCaseSynthesis(caseID string, _ []Finding, clusters []Cluster,
	overall string, audit SynthAudit) CaseSynthesis {

	cs := CaseSynthesis{
		CaseID:        caseID,
		GeneratedAt:   time.Now().UTC(),
		TotalFindings: countFindings(clusters),
		ClusterCount:  len(clusters),
		OverallStory:  overall,
		Audit:         audit,
	}

	for _, c := range clusters {
		sc := SynthCluster{
			ID:              c.ID,
			StartTS:         c.StartTS,
			EndTS:           c.EndTS,
			AttackPhase:     c.AttackPhase,
			Narrative:       c.Narrative,
			MITRETechniques: c.MITRETechniques,
			OpenQuestions:   c.OpenQuestions,
			ActiveSearch:    c.ActiveSearch,
		}
		for _, f := range c.Findings {
			sc.FindingRefs = append(sc.FindingRefs, FindingRef{
				Source:   f.Source,
				RuleID:   f.RuleID,
				Title:    f.Title,
				Severity: f.Severity,
			})
		}
		cs.Clusters = append(cs.Clusters, sc)
	}

	cs.MITREMapping = buildMITREMapping(clusters)
	cs.OpenQuestions = mergeAllOpenQuestions(clusters)
	return cs
}

func buildMITREMapping(clusters []Cluster) []MITREEntry {
	type k struct{ technique string }
	type v struct {
		count    int
		clusters map[int]struct{}
		tactic   string
	}
	bucket := map[k]*v{}
	for _, c := range clusters {
		for _, t := range c.MITRETechniques {
			key := k{technique: t}
			if bucket[key] == nil {
				bucket[key] = &v{clusters: map[int]struct{}{}}
			}
			bucket[key].count++
			bucket[key].clusters[c.ID] = struct{}{}
			if bucket[key].tactic == "" && c.AttackPhase != "" {
				bucket[key].tactic = c.AttackPhase
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
