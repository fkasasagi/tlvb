// Package mcp — TLVB-native findings / synthesis / rule-cache tools.
//
// The legacy list_findings / get_finding tools (server.go) read the findevil
// TacticReport schema (findings/<tactic>.json), which the TLVB pipeline no
// longer produces. These tools expose the TLVB-native layout instead:
//
//	findings/by-rule/<rule_source>/<rule_id>.json   (tier1a.Finding)
//	findings/by-skill/<skill>.json                  (tier1b.AnomalyReport)
//	synthesis.json                                  (Tier 2 output)
//	outputs/rules.duckdb                            (rule + skill SQL cache)
//
// All read-only (CLAUDE.md constraints 1 & 2).
package mcp

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/tlvb/tlvb/internal/rulesdb"
	"github.com/tlvb/tlvb/internal/tier1a"
	"github.com/tlvb/tlvb/internal/tier1b"
)

// tierFindingDTO is the unified shape returned for both Tier 1A (signature)
// and Tier 1B (anomaly) findings.
type tierFindingDTO struct {
	FindingID     string   `json:"finding_id"`
	Source        string   `json:"source"` // "tier1a" | "tier1b"
	RuleID        string   `json:"rule_id,omitempty"`
	RuleSource    string   `json:"rule_source,omitempty"` // sigma|hayabusa|stix|custom
	Skill         string   `json:"skill,omitempty"`       // tier1b skill name
	Lens          string   `json:"lens,omitempty"`        // tier1b A1/A2/...
	Title         string   `json:"title"`
	Severity      string   `json:"severity"`
	Tactic        string   `json:"tactic,omitempty"`
	Techniques    []string `json:"mitre_techniques,omitempty"`
	EvidenceCount int      `json:"evidence_count"`
	AuditIDs      []string `json:"audit_ids,omitempty"`
	ReviewState   string   `json:"review_state"` // approved|auto_approved|rejected|pending
	GeneratedAt   string   `json:"generated_at,omitempty"`
	File          string   `json:"file"`
}

func reviewState(approved, rejected bool, approvedBy string) string {
	switch {
	case rejected:
		return "rejected"
	case approved && strings.HasPrefix(approvedBy, "auto"):
		return "auto_approved"
	case approved:
		return "approved"
	default:
		return "pending"
	}
}

// collectTierFindings walks the TLVB-native findings tree for a case.
func (s *Server) collectTierFindings(caseID string) ([]tierFindingDTO, error) {
	base := filepath.Join(s.outputsRoot, caseID, "findings")
	var out []tierFindingDTO

	// --- Tier 1A: findings/by-rule/<source>/<id>.json ---
	byRule := filepath.Join(base, "by-rule")
	_ = filepath.WalkDir(byRule, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		var f tier1a.Finding
		if json.Unmarshal(body, &f) != nil || f.FindingID == "" {
			return nil
		}
		title := f.RuleMeta.Title
		if title == "" {
			title = f.RuleID
		}
		ec := f.MatchCount
		if ec == 0 {
			ec = len(f.Evidence)
		}
		audits := make([]string, 0, len(f.Evidence))
		for _, e := range f.Evidence {
			audits = append(audits, e.AuditID)
		}
		var tactic string
		if len(f.RuleMeta.MITRETactics) > 0 {
			tactic = f.RuleMeta.MITRETactics[0]
		}
		dto := tierFindingDTO{
			FindingID: f.FindingID, Source: "tier1a",
			RuleID: f.RuleID, RuleSource: f.RuleSource,
			Title: title, Severity: f.RuleMeta.Level, Tactic: tactic,
			Techniques:    f.RuleMeta.MITRETechniques,
			EvidenceCount: ec, AuditIDs: audits,
			ReviewState: reviewState(f.Approved, f.Rejected, f.ApprovedBy),
			File:        relUnder(base, path),
		}
		if !f.GeneratedAt.IsZero() {
			dto.GeneratedAt = f.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
		}
		out = append(out, dto)
		return nil
	})

	// --- Tier 1B: findings/by-skill/<skill>.json ---
	bySkill := filepath.Join(base, "by-skill")
	entries, _ := os.ReadDir(bySkill)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		body, rerr := os.ReadFile(filepath.Join(bySkill, e.Name()))
		if rerr != nil {
			continue
		}
		var rep tier1b.AnomalyReport
		if json.Unmarshal(body, &rep) != nil {
			continue
		}
		for _, af := range rep.Findings {
			var techs []string
			if af.TechniqueID != "" {
				techs = []string{af.TechniqueID}
			}
			dto := tierFindingDTO{
				FindingID: af.FindingID, Source: "tier1b",
				Skill: rep.Skill, Lens: af.Lens,
				Title: af.Summary, Severity: af.Severity, Tactic: af.Tactic,
				Techniques:    techs,
				EvidenceCount: len(af.AuditIDs), AuditIDs: af.AuditIDs,
				ReviewState: reviewState(af.Approved, af.Rejected, af.ApprovedBy),
				File:        relUnder(base, filepath.Join(bySkill, e.Name())),
			}
			if !af.GeneratedAt.IsZero() {
				dto.GeneratedAt = af.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
			}
			out = append(out, dto)
		}
	}

	// Severity desc, then source, then id — stable display order.
	sevRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := sevRank[out[i].Severity], sevRank[out[j].Severity]
		if ri != rj {
			return ri < rj
		}
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].FindingID < out[j].FindingID
	})
	return out, nil
}

func relUnder(base, path string) string {
	if r, err := filepath.Rel(base, path); err == nil {
		return r
	}
	return path
}

// ----------------------------------------------------------------------------
// Handlers
// ----------------------------------------------------------------------------

// list_findings_by_rule — Tier 1A (by-rule) + Tier 1B (by-skill) findings,
// with optional source / rule_source / severity / review_state filters.
func (s *Server) handleListFindingsByRule(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	caseID, err := req.RequireString("case_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	all, err := s.collectTierFindings(caseID)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	src := strings.ToLower(req.GetString("source", ""))
	ruleSrc := strings.ToLower(req.GetString("rule_source", ""))
	sev := strings.ToLower(req.GetString("severity", ""))
	state := strings.ToLower(req.GetString("review_state", ""))
	out := make([]tierFindingDTO, 0, len(all))
	for _, f := range all {
		if src != "" && f.Source != src {
			continue
		}
		if ruleSrc != "" && strings.ToLower(f.RuleSource) != ruleSrc {
			continue
		}
		if sev != "" && strings.ToLower(f.Severity) != sev {
			continue
		}
		if state != "" && f.ReviewState != state {
			continue
		}
		out = append(out, f)
	}
	return jsonResult(map[string]any{
		"case_id":  caseID,
		"count":    len(out),
		"findings": out,
	})
}

// search_findings — substring match across title / rule_id / technique /
// skill / lens (case-insensitive).
func (s *Server) handleSearchFindings(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	caseID, err := req.RequireString("case_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	query, err := req.RequireString("query")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	q := strings.ToLower(strings.TrimSpace(query))
	all, err := s.collectTierFindings(caseID)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	out := make([]tierFindingDTO, 0)
	for _, f := range all {
		hay := strings.ToLower(strings.Join([]string{
			f.Title, f.RuleID, f.Skill, f.Lens, strings.Join(f.Techniques, " "),
		}, " "))
		if q == "" || strings.Contains(hay, q) {
			out = append(out, f)
		}
	}
	return jsonResult(map[string]any{
		"case_id": caseID, "query": query, "count": len(out), "findings": out,
	})
}

// get_synthesis — return the Tier 2 synthesis.json for a case (parsed).
func (s *Server) handleGetSynthesis(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	caseID, err := req.RequireString("case_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	path := filepath.Join(s.outputsRoot, caseID, "synthesis.json")
	body, rerr := os.ReadFile(path)
	if rerr != nil {
		if os.IsNotExist(rerr) {
			return jsonResult(map[string]any{
				"case_id": caseID, "present": false,
				"note": "synthesis.json not present — run `tlvb synthesize` (Tier 2) first",
			})
		}
		return mcp.NewToolResultError(rerr.Error()), nil
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return mcp.NewToolResultError("unmarshal synthesis: " + err.Error()), nil
	}
	return jsonResult(map[string]any{"case_id": caseID, "present": true, "synthesis": doc})
}

// list_cache_status — rule_sql_cache (Tier 1A build coverage) + skill_sql_cache
// (Tier 1B learned lenses) status from rules.duckdb.
func (s *Server) handleListCacheStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if s.rulesDBPath == "" {
		return jsonResult(map[string]any{"available": false, "note": "rules.duckdb path not configured"})
	}
	m, err := rulesdb.Open(s.rulesDBPath, rulesdb.ReadOnly)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return jsonResult(map[string]any{"available": false, "note": "rules.duckdb not present — run `tlvb rules build`"})
		}
		return mcp.NewToolResultError("open rules db: " + err.Error()), nil
	}
	defer m.Close()

	counts, err := m.CountRulesBySourceState(ctx)
	if err != nil {
		return mcp.NewToolResultError("rule counts: " + err.Error()), nil
	}
	type srcCov struct {
		Source  string `json:"source"`
		Built   int    `json:"built"`
		Pending int    `json:"pending"`
		Failed  int    `json:"failed"`
		Total   int    `json:"total"`
	}
	bySrc := map[string]*srcCov{}
	byState := map[string]int{}
	total := 0
	for _, c := range counts {
		sc := bySrc[c.Source]
		if sc == nil {
			sc = &srcCov{Source: c.Source}
			bySrc[c.Source] = sc
		}
		switch c.State {
		case rulesdb.StateBuilt:
			sc.Built += c.Count
		case rulesdb.StatePending:
			sc.Pending += c.Count
		case rulesdb.StateFailed:
			sc.Failed += c.Count
		}
		sc.Total += c.Count
		byState[string(c.State)] += c.Count
		total += c.Count
	}
	srcList := make([]srcCov, 0, len(bySrc))
	for _, sc := range bySrc {
		srcList = append(srcList, *sc)
	}
	sort.Slice(srcList, func(i, j int) bool { return srcList[i].Source < srcList[j].Source })

	skc, _ := m.CountSkillByState(ctx)
	return jsonResult(map[string]any{
		"available": true,
		"rules": map[string]any{
			"total":     total,
			"by_state":  byState,
			"by_source": srcList,
		},
		"skills": map[string]any{
			"candidate": skc[rulesdb.SkillCandidate],
			"canonical": skc[rulesdb.SkillCanonical],
			"total":     skc[rulesdb.SkillCandidate] + skc[rulesdb.SkillCanonical],
		},
	})
}
