// Package mcp implements the TLVB Tier 0 MCP server.
//
// Design principles (from docs/valhuntir_analysis.md §5.1):
//   - read-only functions only — no shell execution exposed to LLMs
//   - safety_tier classification (SAFE/CONFIRM/AUTO) per Valhuntir convention
//   - dynamic tool discovery so artifacts.yaml is the single source of truth
//
// Parsing is invoked out-of-band (orchestrator / CLI). This server exposes
// query access to:
//   - artifact catalog (config/artifacts.yaml)
//   - case / evidence registry (DuckDB)
//   - parsed UnifiedEvent rows (DuckDB)
//   - parser execution metadata (which command ran, success/failure)
//
// Why read-only here: the MCP is consumed by Tactic Agents which must not be
// able to mutate evidence or trigger arbitrary commands (CLAUDE.md constraints
// 1 & 2). Mutations live in a separate orchestrator process.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/tlvb/tlvb/internal/agents"
	"github.com/tlvb/tlvb/internal/casedb"
	"github.com/tlvb/tlvb/internal/common"
)

// SafetyTier mirrors Valhuntir's classification (forensic-mcp). Every tool we
// register declares one. For Tier 0 every tool is SAFE because writes are not
// possible from this server, but we keep the field so Review Gate 0 can render
// the same column the Examiner Portal does.
type SafetyTier string

const (
	TierSAFE    SafetyTier = "SAFE"
	TierCONFIRM SafetyTier = "CONFIRM" // unused at Tier 0; reserved for orchestrator MCP
	TierAUTO    SafetyTier = "AUTO"    // unused at Tier 0
)

// Server bundles dependencies shared by all tool handlers.
type Server struct {
	mcp         *server.MCPServer
	catalog     *common.ArtifactCatalog // loaded from config/artifacts.yaml
	cases       *casedb.Manager         // DuckDB-backed read access
	outputsRoot string                  // outputs/cases — for findings/synthesis fetch
	rulesDBPath string                  // outputs/rules.duckdb — for list_cache_status
	logger      common.Logger
}

// Config is the server bootstrap config.
type Config struct {
	Name          string
	Version       string
	ArtifactsYAML string // path to config/artifacts.yaml
	CaseDBPath    string // path to outputs/cases.duckdb
	OutputsRoot   string // path to outputs/cases (for findings/*.json read)
	RulesDBPath   string // path to outputs/rules.duckdb (for list_cache_status)
}

// New builds a server with read-only tools registered. Call Serve to run it.
func New(cfg Config, logger common.Logger) (*Server, error) {
	catalog, err := common.LoadArtifactCatalog(cfg.ArtifactsYAML)
	if err != nil {
		return nil, fmt.Errorf("load artifact catalog %q: %w", cfg.ArtifactsYAML, err)
	}

	cases, err := casedb.Open(cfg.CaseDBPath, casedb.ReadOnly)
	if err != nil {
		return nil, fmt.Errorf("open case db %q: %w", cfg.CaseDBPath, err)
	}

	mcpSrv := server.NewMCPServer(
		cfg.Name,
		cfg.Version,
		// Tools-only server. No prompts, no resources for MVP.
		server.WithToolCapabilities(false),
		server.WithLogging(),
		server.WithInstructions(serverInstructions),
	)

	outRoot := cfg.OutputsRoot
	if outRoot == "" {
		// Fall back to outputs/cases relative to the DB file's parent.
		// Lets existing callers that don't yet pass OutputsRoot still work.
		outRoot = filepath.Join(filepath.Dir(cfg.CaseDBPath), "cases")
	}
	rulesDB := cfg.RulesDBPath
	if rulesDB == "" {
		rulesDB = filepath.Join(filepath.Dir(cfg.CaseDBPath), "rules.duckdb")
	}
	s := &Server{
		mcp:         mcpSrv,
		catalog:     catalog,
		cases:       cases,
		outputsRoot: outRoot,
		rulesDBPath: rulesDB,
		logger:      logger,
	}
	s.registerTools()
	return s, nil
}

// ServeStdio runs the server over stdio (MVP transport — same as Valhuntir's
// gateway-to-backend bridge).
func (s *Server) ServeStdio(ctx context.Context) error {
	return server.ServeStdio(s.mcp)
}

// Close releases resources (DuckDB connection).
func (s *Server) Close() error {
	if s.cases != nil {
		return s.cases.Close()
	}
	return nil
}

// serverInstructions is delivered during MCP session init. Aligns with
// Valhuntir §2.2 "命令文集約" pattern — each backend describes its scope so
// the LLM client gets a coherent briefing.
const serverInstructions = `
TLVB Tier 0 MCP Server (read-only).

Use this server to query the artifact catalog, registered cases, evidence
metadata, and parsed UnifiedEvent records produced by Tier 0 parsers.

Constraints:
  - All tools are read-only. Cannot register evidence, run parsers, or mutate
    case state from here.
  - Evidence files (under /cases or any registered evidence directory) are
    immutable. This server only ever reads parser output stored in DuckDB.
  - Timestamps in returned rows are normalised to UTC.

Workflow:
  1. list_artifacts — discover what artifact types TLVB supports
  2. list_cases     — pick a case_id
  3. list_evidence  — see what was registered in that case
  4. get_unified_events — fetch parsed rows for an artifact, with filters
  5. get_parse_result   — execution metadata (command, exit, stderr) for audit
`

// ----------------------------------------------------------------------------
// Tool registration
// ----------------------------------------------------------------------------

func (s *Server) registerTools() {
	s.mcp.AddTool(
		mcp.NewTool("list_artifacts",
			mcp.WithDescription(
				"List artifact types defined in config/artifacts.yaml "+
					"(P0/P1, parser path, caveats). SAFE.",
			),
		),
		s.handleListArtifacts,
	)

	s.mcp.AddTool(
		mcp.NewTool("get_artifact_definition",
			mcp.WithDescription(
				"Get full artifact definition (tool, command template, "+
					"unified_event_mapping, caveats) for a single artifact id. SAFE.",
			),
			mcp.WithString("artifact_id",
				mcp.Required(),
				mcp.Description("e.g. 'evtx', 'amcache', 'prefetch'"),
			),
		),
		s.handleGetArtifactDefinition,
	)

	s.mcp.AddTool(
		mcp.NewTool("list_cases",
			mcp.WithDescription("List registered cases with status. SAFE."),
		),
		s.handleListCases,
	)

	s.mcp.AddTool(
		mcp.NewTool("get_case_status",
			mcp.WithDescription(
				"Detailed case status: evidence count, parse results, "+
					"finding count by status. SAFE.",
			),
			mcp.WithString("case_id", mcp.Required()),
		),
		s.handleGetCaseStatus,
	)

	s.mcp.AddTool(
		mcp.NewTool("list_evidence",
			mcp.WithDescription(
				"List registered evidence files for a case "+
					"(path, sha256, size, registration time). SAFE.",
			),
			mcp.WithString("case_id", mcp.Required()),
		),
		s.handleListEvidence,
	)

	s.mcp.AddTool(
		mcp.NewTool("get_unified_events",
			mcp.WithDescription(
				"Query UnifiedEvent rows produced by Tier 0 parsers. "+
					"Filters: artifact_id, time range, computer, free-text grep. SAFE.",
			),
			mcp.WithString("case_id", mcp.Required()),
			mcp.WithString("artifact_id",
				mcp.Description("evtx | amcache | prefetch | registry | scheduled_task"),
			),
			mcp.WithString("start_time", mcp.Description("ISO8601 UTC, inclusive")),
			mcp.WithString("end_time", mcp.Description("ISO8601 UTC, exclusive")),
			mcp.WithString("computer", mcp.Description("exact match on Computer field")),
			mcp.WithString("contains", mcp.Description("substring match across all fields")),
			mcp.WithNumber("limit", mcp.Description("default 100, max 5000")),
			mcp.WithNumber("offset", mcp.Description("default 0")),
		),
		s.handleGetUnifiedEvents,
	)

	s.mcp.AddTool(
		mcp.NewTool("get_parse_result",
			mcp.WithDescription(
				"Execution metadata of parser runs for one artifact: command, "+
					"exit_code, stdout/stderr tails, output paths, timestamps. "+
					"Returns a JSON array with one row per evidence whose run "+
					"parsed the artifact ('' evidence_id on legacy data). SAFE.",
			),
			mcp.WithString("case_id", mcp.Required()),
			mcp.WithString("artifact_id", mcp.Required()),
		),
		s.handleGetParseResult,
	)

	s.mcp.AddTool(
		mcp.NewTool("health",
			mcp.WithDescription(
				"Server health: catalog loaded, casedb reachable, schema version. SAFE.",
			),
		),
		s.handleHealth,
	)

	// Findings access — read-only listing + per-finding fetch. Lets a
	// downstream MCP client (Claude Code, Claude Desktop, etc.) browse
	// what the Tactic Agents produced without going through the Web UI.
	s.mcp.AddTool(
		mcp.NewTool("list_findings",
			mcp.WithDescription(
				"List all findings produced by Tactic Agents for a case. "+
					"Optional tactic filter (e.g. 'persistence') restricts to one slug. "+
					"SAFE (read-only)."),
			mcp.WithString("case_id", mcp.Required()),
			mcp.WithString("tactic",
				mcp.Description("optional tactic slug filter (initial_access / "+
					"persistence / ... / anomaly_hunter)")),
		),
		s.handleListFindings,
	)
	s.mcp.AddTool(
		mcp.NewTool("get_finding",
			mcp.WithDescription(
				"Fetch a single finding by finding_id (e.g. 'F-persistence-001') "+
					"with full evidence list, reasoning, and review state. SAFE."),
			mcp.WithString("case_id", mcp.Required()),
			mcp.WithString("finding_id", mcp.Required()),
		),
		s.handleGetFinding,
	)
	// Wave 30 — review state read-only access. The MCP server intentionally
	// stays read-only (no approve/reject via LLM) to honor the CLAUDE.md
	// "review.* via Web only" guard; these two tools just surface state.
	s.mcp.AddTool(
		mcp.NewTool("get_parse_review",
			mcp.WithDescription(
				"Read Review Gate 0 (per-artifact parse-result approval) state "+
					"for a case. Returns {auto_skip, reviews: {artifact_id: "+
					"{state, reason, reviewed_by, reviewed_at}}}. SAFE (read-only)."),
			mcp.WithString("case_id", mcp.Required()),
		),
		s.handleGetParseReview,
	)
	s.mcp.AddTool(
		mcp.NewTool("get_timeline_review",
			mcp.WithDescription(
				"Read Review Gate 2 (per-timeline-entry approval, Wave 21) state "+
					"for a case. Returns {auto_skip, reviews: {audit_id: "+
					"{state, reason, reviewed_by, reviewed_at}}}. SAFE (read-only)."),
			mcp.WithString("case_id", mcp.Required()),
		),
		s.handleGetTimelineReview,
	)
	// Wave 31 — TTP-based query tools (DESIGN v0.3 #6).
	s.mcp.AddTool(
		mcp.NewTool("events_by_ttp",
			mcp.WithDescription(
				"Query unified_events for rows associated with a MITRE ATT&CK "+
					"technique (e.g. T1547.001) via payload substring match. "+
					"Optional limit (default 50, max 500). SAFE (read-only)."),
			mcp.WithString("case_id", mcp.Required()),
			mcp.WithString("technique_id", mcp.Required(),
				mcp.Description("MITRE technique ID, e.g. T1078 / T1547.001")),
			mcp.WithNumber("limit",
				mcp.Description("max rows returned (default 50, capped at 500)")),
		),
		s.handleEventsByTTP,
	)
	s.mcp.AddTool(
		mcp.NewTool("mitre_required_artifacts",
			mcp.WithDescription(
				"Return the list of artifact_ids commonly required to evidence a "+
					"MITRE technique (e.g. T1547.001 → registry / lnk). Derived "+
					"from a static table in DESIGN.md §4.3. SAFE."),
			mcp.WithString("technique_id", mcp.Required()),
		),
		s.handleMitreRequiredArtifacts,
	)
	s.mcp.AddTool(
		mcp.NewTool("correlation_cross_evidence",
			mcp.WithDescription(
				"Return cross-evidence correlations detected by the synthesizer "+
					"(Wave 24). Same as reading synthesis.json::"+
					"cross_evidence_correlations but exposed as a typed MCP tool. "+
					"SAFE (read-only)."),
			mcp.WithString("case_id", mcp.Required()),
		),
		s.handleCorrelationCrossEvidence,
	)

	// TLVB-native findings / synthesis / rule-cache access (findings_tier.go).
	// The legacy list_findings/get_finding above target the findevil
	// TacticReport schema; these target findings/by-rule + by-skill +
	// synthesis.json + rules.duckdb that the TLVB pipeline actually produces.
	s.mcp.AddTool(
		mcp.NewTool("list_findings_by_rule",
			mcp.WithDescription(
				"List TLVB Tier 1A (signature, by-rule) + Tier 1B (anomaly, by-skill) "+
					"findings for a case. Optional filters: source (tier1a|tier1b), "+
					"rule_source (sigma|hayabusa|stix|custom), severity, review_state "+
					"(approved|auto_approved|rejected|pending). SAFE (read-only)."),
			mcp.WithString("case_id", mcp.Required()),
			mcp.WithString("source", mcp.Description("tier1a | tier1b")),
			mcp.WithString("rule_source", mcp.Description("sigma | hayabusa | stix | custom")),
			mcp.WithString("severity", mcp.Description("critical | high | medium | low | info")),
			mcp.WithString("review_state", mcp.Description("approved | auto_approved | rejected | pending")),
		),
		s.handleListFindingsByRule,
	)
	s.mcp.AddTool(
		mcp.NewTool("search_findings",
			mcp.WithDescription(
				"Substring search across TLVB findings (title / rule_id / MITRE "+
					"technique / skill / lens), case-insensitive. SAFE (read-only)."),
			mcp.WithString("case_id", mcp.Required()),
			mcp.WithString("query", mcp.Required(),
				mcp.Description("e.g. 'lsass', 'T1003', 'mimikatz', 'A5'")),
		),
		s.handleSearchFindings,
	)
	s.mcp.AddTool(
		mcp.NewTool("get_synthesis",
			mcp.WithDescription(
				"Fetch the Tier 2 synthesis.json (attack-chain narrative, clusters, "+
					"mitre_mapping, open_questions) for a case. SAFE (read-only)."),
			mcp.WithString("case_id", mcp.Required()),
		),
		s.handleGetSynthesis,
	)
	s.mcp.AddTool(
		mcp.NewTool("list_cache_status",
			mcp.WithDescription(
				"Rule SQL cache status from rules.duckdb: rule_sql_cache build "+
					"coverage (built/pending/failed per source) + skill_sql_cache "+
					"(Tier 1B learned lenses, candidate/canonical). Global, not "+
					"case-scoped. SAFE (read-only)."),
		),
		s.handleListCacheStatus,
	)
}

// ----------------------------------------------------------------------------
// Handlers (skeleton — full implementations land in Phase 1.x / 2)
// ----------------------------------------------------------------------------

func (s *Server) handleListArtifacts(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	summary := s.catalog.Summary()
	return jsonResult(summary)
}

func (s *Server) handleGetArtifactDefinition(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := req.RequireString("artifact_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	def, ok := s.catalog.Get(id)
	if !ok {
		return mcp.NewToolResultError(fmt.Sprintf("unknown artifact_id %q", id)), nil
	}
	return jsonResult(def)
}

func (s *Server) handleListCases(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	cases, err := s.cases.ListCases(ctx)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("list cases: %v", err)), nil
	}
	return jsonResult(cases)
}

func (s *Server) handleGetCaseStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	caseID, err := req.RequireString("case_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	status, err := s.cases.GetCaseStatus(ctx, caseID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("case status: %v", err)), nil
	}
	return jsonResult(status)
}

func (s *Server) handleListEvidence(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	caseID, err := req.RequireString("case_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	rows, err := s.cases.ListEvidence(ctx, caseID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("list evidence: %v", err)), nil
	}
	return jsonResult(rows)
}

func (s *Server) handleGetUnifiedEvents(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	caseID, err := req.RequireString("case_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	q := casedb.UnifiedEventQuery{
		CaseID:     caseID,
		ArtifactID: req.GetString("artifact_id", ""),
		StartTime:  req.GetString("start_time", ""),
		EndTime:    req.GetString("end_time", ""),
		Computer:   req.GetString("computer", ""),
		Contains:   req.GetString("contains", ""),
		Limit:      int(req.GetFloat("limit", 100)),
		Offset:     int(req.GetFloat("offset", 0)),
	}
	if q.Limit <= 0 || q.Limit > 5000 {
		q.Limit = 100
	}
	rows, err := s.cases.QueryUnifiedEvents(ctx, q)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("query events: %v", err)), nil
	}
	return jsonResult(rows)
}

func (s *Server) handleGetParseResult(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	caseID, err := req.RequireString("case_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	artifactID, err := req.RequireString("artifact_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	prs, err := s.cases.GetParseResults(ctx, caseID, artifactID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("get parse result: %v", err)), nil
	}
	return jsonResult(prs)
}

func (s *Server) handleHealth(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	h := map[string]any{
		"status":           "ok",
		"catalog_version":  s.catalog.Version(),
		"artifact_count":   s.catalog.Count(),
		"casedb_reachable": s.cases.Ping(ctx) == nil,
		"schema_version":   "tlvb/mcp/v1",
	}
	return jsonResult(h)
}

// jsonResult marshals v as JSON and wraps it in a tool result. Tactic Agents
// receive structured JSON which is easier to ground than free-form text.
func jsonResult(v any) (*mcp.CallToolResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal result: %w", err)
	}
	return mcp.NewToolResultText(string(b)), nil
}

// ----------------------------------------------------------------------------
// Findings access (read-only) — list_findings + get_finding
//
// Tactic Agents persist their output as JSON files under
// outputs/cases/<id>/findings/<tactic>.json (TacticReport schema).
// These two tools let an MCP client browse the same data the Web UI's
// Findings tab serves, without going through HTTP.
// ----------------------------------------------------------------------------

type findingDTO struct {
	agents.Finding
	Tactic     string `json:"tactic"`
	TacticID   string `json:"tactic_id"`
	TacticName string `json:"tactic_name"`
}

func (s *Server) handleListFindings(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	caseID, err := req.RequireString("case_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	tacticFilter, _ := req.RequireString("tactic") // optional
	out, err := s.collectFindings(caseID, tacticFilter)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("list findings: %v", err)), nil
	}
	return jsonResult(out)
}

func (s *Server) handleGetFinding(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	caseID, err := req.RequireString("case_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	findingID, err := req.RequireString("finding_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	// Legacy TacticReport findings (findevil schema) first.
	all, err := s.collectFindings(caseID, "")
	if err == nil {
		for _, f := range all {
			if f.FindingID == findingID {
				return jsonResult(f)
			}
		}
	}
	// Fall back to the TLVB-native by-rule / by-skill tree — this is what the
	// current pipeline produces, so it is the common case.
	tier, terr := s.collectTierFindings(caseID)
	if terr == nil {
		for _, f := range tier {
			if f.FindingID == findingID {
				return jsonResult(f)
			}
		}
	}
	if err != nil && terr != nil {
		return mcp.NewToolResultError(fmt.Sprintf("get finding: %v", err)), nil
	}
	return mcp.NewToolResultError(
		fmt.Sprintf("finding %q not found in case %q", findingID, caseID)), nil
}

// collectFindings walks every TacticReport JSON for the case, returning
// each Finding tagged with its parent tactic slug + ATT&CK id+name.
// Mirrors internal/web/handlers.go::collectFindings — kept as a private
// duplicate rather than a shared package because the two callers have
// different DTO surfaces (web wraps for HTTP, mcp returns directly).
func (s *Server) collectFindings(caseID, tacticFilter string) ([]findingDTO, error) {
	dir := filepath.Join(s.outputsRoot, caseID, "findings")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("findings dir: %w", err)
	}
	var out []findingDTO
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		slug := strings.TrimSuffix(e.Name(), ".json")
		if tacticFilter != "" && slug != tacticFilter {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var rep agents.TacticReport
		if err := json.Unmarshal(body, &rep); err != nil {
			continue
		}
		for _, f := range rep.Findings {
			out = append(out, findingDTO{
				Finding:    f,
				Tactic:     slug,
				TacticID:   rep.TacticID,
				TacticName: rep.TacticName,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].TacticID != out[j].TacticID {
			return out[i].TacticID < out[j].TacticID
		}
		return out[i].FindingID < out[j].FindingID
	})
	return out, nil
}

// ----------------------------------------------------------------------------
// Review state read-only access (Wave 30)
//
// Surfaces parse_review.json (Gate 0) and timeline_gate.json (Gate 2) via
// MCP so an LLM-driven analysis can see what the examiner has approved /
// rejected without going through the Web REST API. Intentionally
// read-only — mutating review state belongs to the human in the loop,
// not to the LLM.
// ----------------------------------------------------------------------------

func (s *Server) handleGetParseReview(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return s.readGateFile(req, "parse_review.json")
}

func (s *Server) handleGetTimelineReview(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return s.readGateFile(req, "timeline_gate.json")
}

// ----------------------------------------------------------------------------
// Wave 31 — TTP-based query tools (DESIGN v0.3 #6)
// ----------------------------------------------------------------------------

// mitreRequiredArtifacts (Wave 31) — static mapping derived from DESIGN.md
// §4.3 and the Tactic Agent skill files (skills/*.md). Intentionally a
// small curated table rather than a full ATT&CK download; agents can read
// the skill files directly if they need exhaustive coverage.
var mitreRequiredArtifacts = map[string][]string{
	"T1078":     {"evtx", "registry"},                   // Valid Accounts
	"T1547.001": {"registry", "lnk"},                    // Run keys / Startup
	"T1547.004": {"registry"},                           // Winlogon helper DLL
	"T1546.008": {"registry"},                           // Accessibility features IFEO
	"T1546.012": {"registry"},                           // IFEO Debugger
	"T1543.003": {"registry", "evtx"},                   // Windows Service
	"T1053.005": {"scheduled_tasks", "evtx"},            // Scheduled Task
	"T1059.001": {"evtx", "prefetch"},                   // PowerShell
	"T1059.003": {"evtx", "prefetch"},                   // CMD
	"T1110":     {"evtx"},                               // Brute Force
	"T1003":     {"evtx", "prefetch", "amcache"},        // OS credential dump
	"T1021":     {"evtx"},                               // Remote Services
	"T1021.001": {"evtx"},                               // RDP
	"T1021.002": {"evtx"},                               // SMB/Admin Shares
	"T1070.001": {"evtx"},                               // Indicator Removal (logs)
	"T1070.004": {"usn_journal", "mft"},                 // File Deletion
	"T1112":     {"registry"},                           // Modify Registry
	"T1083":     {"prefetch", "shellbags", "jumplists"}, // File and Directory Discovery
	"T1105":     {"browser_history", "evtx", "mft"},     // Ingress Tool Transfer
	"T1486":     {"mft", "usn_journal", "evtx"},         // Data Encrypted for Impact
}

func (s *Server) handleEventsByTTP(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	caseID, err := req.RequireString("case_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	tid, err := req.RequireString("technique_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	limit := 50
	if n, ok := req.GetArguments()["limit"].(float64); ok {
		if v := int(n); v > 0 && v <= 500 {
			limit = v
		}
	}
	// Use the existing UnifiedEvents query helper via casedb.Manager —
	// simpler than opening a raw sql.DB here.
	evs, err := s.cases.QueryUnifiedEvents(ctx, casedb.UnifiedEventQuery{
		CaseID:   caseID,
		Contains: tid,
		Limit:    limit,
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("query: %v", err)), nil
	}
	type evDTO struct {
		AuditID    string `json:"audit_id"`
		Timestamp  string `json:"ts_utc"`
		ArtifactID string `json:"artifact_id"`
		Computer   string `json:"computer"`
		Payload    string `json:"payload_json"`
	}
	out := make([]evDTO, 0, len(evs))
	for _, e := range evs {
		out = append(out, evDTO{
			AuditID:    e.AuditID,
			Timestamp:  e.TsUTC.Format(time.RFC3339),
			ArtifactID: e.ArtifactID,
			Computer:   e.Computer,
			Payload:    e.PayloadJSON,
		})
	}
	return jsonResult(map[string]any{
		"technique_id": tid,
		"case_id":      caseID,
		"limit":        limit,
		"row_count":    len(out),
		"events":       out,
	})
}

func (s *Server) handleMitreRequiredArtifacts(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	tid, err := req.RequireString("technique_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	arts := mitreRequiredArtifacts[tid]
	return jsonResult(map[string]any{
		"technique_id": tid,
		"artifact_ids": arts,
		"covered":      len(arts) > 0,
		"note":         "static mapping from DESIGN.md §4.3; not exhaustive",
	})
}

func (s *Server) handleCorrelationCrossEvidence(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	caseID, err := req.RequireString("case_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	path := filepath.Join(s.outputsRoot, caseID, "synthesis.json")
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return jsonResult(map[string]any{
				"case_id":                     caseID,
				"cross_evidence_correlations": []any{},
				"note":                        "synthesis.json not present — run Synthesize first",
			})
		}
		return mcp.NewToolResultError(fmt.Sprintf("read synthesis: %v", err)), nil
	}
	var doc struct {
		CrossEvidence []any `json:"cross_evidence_correlations"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("unmarshal: %v", err)), nil
	}
	return jsonResult(map[string]any{
		"case_id":                     caseID,
		"cross_evidence_correlations": doc.CrossEvidence,
		"count":                       len(doc.CrossEvidence),
	})
}

// readGateFile returns the gate JSON doc verbatim. Missing file → empty
// {"auto_skip": false, "reviews": {}} so callers always get a stable shape.
func (s *Server) readGateFile(req mcp.CallToolRequest, filename string) (*mcp.CallToolResult, error) {
	caseID, err := req.RequireString("case_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	path := filepath.Join(s.outputsRoot, caseID, filename)
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return jsonResult(map[string]any{
				"case_id":   caseID,
				"auto_skip": false,
				"reviews":   map[string]any{},
				"note":      fmt.Sprintf("%s not present — gate untouched", filename),
			})
		}
		return mcp.NewToolResultError(fmt.Sprintf("read %s: %v", filename, err)), nil
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("unmarshal %s: %v", filename, err)), nil
	}
	return jsonResult(doc)
}
