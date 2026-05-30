// Package web — Review Gate 1A.
//
// Exposes the unified TLVB findings view (Tier 1A by-rule + Tier 1B by-skill)
// to the browser as `/api/cases/{id}/findings*`. Per-finding and bulk
// approve / reject / reset mutations rewrite the underlying JSON files
// (findings/by-rule/<source>/<id>.json or findings/by-skill/<skill>.json)
// in place — there is no separate review ledger.
//
// Sort order:
//   1. severity desc (critical, high, medium, low, info)
//   2. pending before reviewed
//   3. finding_id (stable tiebreaker)
package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/tier1a"
	"github.com/tlvb/tlvb/internal/tier1b"
)

// ReviewFinding is the wire shape returned to the Review Gate 1A UI.
// Both Tier 1A (signature rule hit) and Tier 1B (skill-driven anomaly)
// flatten into this so the front-end has one render path.
type ReviewFinding struct {
	FindingID       string                  `json:"finding_id"`
	Source          string                  `json:"source"`                 // "tier1a" | "tier1b"
	RuleSource      string                  `json:"rule_source,omitempty"`  // sigma/hayabusa/stix/custom/skill
	RuleID          string                  `json:"rule_id,omitempty"`      // rule_id (1A) or skill name (1B)
	Title           string                  `json:"title"`
	Description     string                  `json:"description,omitempty"`
	Severity        string                  `json:"severity"`               // critical|high|medium|low|info
	MITRETechniques []string                `json:"mitre_techniques,omitempty"`
	MITRETactics    []string                `json:"mitre_tactics,omitempty"`
	Lens            string                  `json:"lens,omitempty"`         // 1B only (A1/A2/A4/A5/…)
	MatchCount      int                     `json:"match_count"`            // 1A rows / 1B audit_id count
	Truncated       bool                    `json:"truncated,omitempty"`
	EvidencePreview []ReviewEvidencePreview `json:"evidence_preview,omitempty"`

	Approved     bool      `json:"approved"`
	Rejected     bool      `json:"rejected"`
	AutoApproved bool      `json:"auto_approved"`
	ApprovedBy   string    `json:"approved_by,omitempty"`
	RejectReason string    `json:"reject_reason,omitempty"`
	ReviewedAt   time.Time `json:"reviewed_at,omitempty"`
	ReviewedBy   string    `json:"reviewed_by,omitempty"`

	GeneratedAt time.Time `json:"generated_at"`
	SourcePath  string    `json:"source_path,omitempty"` // rule yml path (1A) or skill .md (1B)
}

// ReviewEvidencePreview is a 1-line evidence pointer shown in the row.
// Full evidence is reached by drilling into the finding JSON file.
type ReviewEvidencePreview struct {
	AuditID    string     `json:"audit_id"`
	TsUTC      *time.Time `json:"ts_utc,omitempty"`
	ArtifactID string     `json:"artifact_id,omitempty"`
	EventType  string     `json:"event_type,omitempty"`
}

// findingLocator records where a finding lives on disk so the mutation
// path can rewrite the right JSON. Two layouts:
//   - by-rule/<source>/<id>.json — IsRule=true, one finding per file
//   - by-skill/<skill>.json     — IsRule=false, N findings per file (Index)
type findingLocator struct {
	Path   string
	IsRule bool
	Index  int
}

// ----------------------------------------------------------------------------
// REST handlers
// ----------------------------------------------------------------------------

func (s *Server) handleListReviewFindings(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	out, _, err := s.loadAllReviewFindings(caseID)
	if err != nil {
		writeError(w, 404, "%v", err)
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleApproveReviewFinding(w http.ResponseWriter, r *http.Request) {
	s.applyReviewSingle(w, r, "approve", "")
}

func (s *Server) handleRejectReviewFinding(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	_ = decodeJSON(r, &req)
	s.applyReviewSingle(w, r, "reject", req.Reason)
}

func (s *Server) handleResetReviewFinding(w http.ResponseWriter, r *http.Request) {
	s.applyReviewSingle(w, r, "reset", "")
}

// handleBulkReviewFindings runs approve/reject/reset over many finding_ids
// in one request. Used by the cluster bulk-approve button in the UI.
//
// Body:
//
//	{
//	  "finding_ids": ["…", "…"],
//	  "action":      "approve" | "reject" | "reset",
//	  "reason":      "…"   // optional for action=reject
//	}
func (s *Server) handleBulkReviewFindings(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	var req struct {
		FindingIDs []string `json:"finding_ids"`
		Action     string   `json:"action"`
		Reason     string   `json:"reason"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, 400, "bad json: %v", err)
		return
	}
	if len(req.FindingIDs) == 0 {
		writeError(w, 400, "finding_ids[] required")
		return
	}
	if req.Action != "approve" && req.Action != "reject" && req.Action != "reset" {
		writeError(w, 400, "action must be approve|reject|reset")
		return
	}
	examiner := r.Header.Get("X-Examiner")
	if examiner == "" {
		examiner = "examiner-web"
	}
	res, err := s.applyReviewMutation(caseID, req.FindingIDs, req.Action, req.Reason, examiner)
	if err != nil {
		writeError(w, 500, "%v", err)
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) applyReviewSingle(w http.ResponseWriter, r *http.Request, action, reason string) {
	caseID := r.PathValue("id")
	fid := r.PathValue("fid")
	if fid == "" {
		writeError(w, 400, "finding_id required")
		return
	}
	examiner := r.Header.Get("X-Examiner")
	if examiner == "" {
		examiner = "examiner-web"
	}
	res, err := s.applyReviewMutation(caseID, []string{fid}, action, reason, examiner)
	if err != nil {
		writeError(w, 500, "%v", err)
		return
	}
	if res.Updated == 0 {
		writeError(w, 404, "finding %q not found", fid)
		return
	}
	writeJSON(w, 200, map[string]any{
		"status":      "ok",
		"finding_id":  fid,
		"action":      action,
		"reason":      reason,
		"reviewed_by": examiner,
	})
}

// ----------------------------------------------------------------------------
// Loader (Tier 1A by-rule + Tier 1B by-skill → unified ReviewFinding list)
// ----------------------------------------------------------------------------

func (s *Server) loadAllReviewFindings(caseID string) ([]ReviewFinding, map[string]findingLocator, error) {
	findingsRoot := filepath.Join(s.cfg.OutputsRoot, caseID, "findings")
	if info, err := os.Stat(findingsRoot); err != nil || !info.IsDir() {
		return nil, nil, fmt.Errorf("findings dir not found: %s", findingsRoot)
	}

	out := []ReviewFinding{}
	locators := map[string]findingLocator{}

	// by-rule/<source>/<rule_id>.json
	byRuleRoot := filepath.Join(findingsRoot, "by-rule")
	if entries, err := os.ReadDir(byRuleRoot); err == nil {
		for _, srcDir := range entries {
			if !srcDir.IsDir() {
				continue
			}
			srcRoot := filepath.Join(byRuleRoot, srcDir.Name())
			files, err := os.ReadDir(srcRoot)
			if err != nil {
				continue
			}
			for _, fent := range files {
				if fent.IsDir() || !strings.HasSuffix(fent.Name(), ".json") {
					continue
				}
				path := filepath.Join(srcRoot, fent.Name())
				body, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				var f tier1a.Finding
				if err := json.Unmarshal(body, &f); err != nil {
					continue
				}
				out = append(out, convertTier1AFinding(f))
				locators[f.FindingID] = findingLocator{Path: path, IsRule: true}
			}
		}
	}

	// by-skill/<skill>.json
	bySkillRoot := filepath.Join(findingsRoot, "by-skill")
	if entries, err := os.ReadDir(bySkillRoot); err == nil {
		for _, fent := range entries {
			if fent.IsDir() || !strings.HasSuffix(fent.Name(), ".json") {
				continue
			}
			path := filepath.Join(bySkillRoot, fent.Name())
			body, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var rep tier1b.AnomalyReport
			if err := json.Unmarshal(body, &rep); err != nil {
				continue
			}
			for i, af := range rep.Findings {
				out = append(out, convertTier1BFinding(rep, af))
				locators[af.FindingID] = findingLocator{Path: path, IsRule: false, Index: i}
			}
		}
	}

	sortReviewFindings(out)
	return out, locators, nil
}

func convertTier1AFinding(f tier1a.Finding) ReviewFinding {
	rf := ReviewFinding{
		FindingID:       f.FindingID,
		Source:          "tier1a",
		RuleSource:      f.RuleSource,
		RuleID:          f.RuleID,
		Title:           f.RuleMeta.Title,
		Description:     f.RuleMeta.Description,
		Severity:        normaliseSeverity(f.RuleMeta.Level),
		MITRETechniques: f.RuleMeta.MITRETechniques,
		MITRETactics:    f.RuleMeta.MITRETactics,
		MatchCount:      f.MatchCount,
		Truncated:       f.Truncated,
		Approved:        f.Approved,
		Rejected:        f.Rejected,
		AutoApproved:    strings.HasPrefix(f.ApprovedBy, "auto:"),
		ApprovedBy:      f.ApprovedBy,
		RejectReason:    f.RejectReason,
		ReviewedAt:      f.ReviewedAt,
		ReviewedBy:      f.ReviewedBy,
		GeneratedAt:     f.GeneratedAt,
		SourcePath:      f.RuleMeta.SourcePath,
	}
	if rf.Title == "" {
		rf.Title = f.RuleID
	}
	for i, e := range f.Evidence {
		if i >= 3 {
			break
		}
		rf.EvidencePreview = append(rf.EvidencePreview, ReviewEvidencePreview{
			AuditID:    e.AuditID,
			TsUTC:      e.TsUTC,
			ArtifactID: e.ArtifactID,
			EventType:  e.EventType,
		})
	}
	return rf
}

func convertTier1BFinding(rep tier1b.AnomalyReport, af tier1b.AnomalyFinding) ReviewFinding {
	rf := ReviewFinding{
		FindingID:    af.FindingID,
		Source:       "tier1b",
		RuleSource:   "skill",
		RuleID:       rep.Skill,
		Title:        af.Summary,
		Description:  af.Description,
		Severity:     normaliseSeverity(af.Severity),
		Lens:         af.Lens,
		MatchCount:   len(af.AuditIDs),
		Approved:     af.Approved,
		Rejected:     af.Rejected,
		AutoApproved: strings.HasPrefix(af.ApprovedBy, "auto:"),
		ApprovedBy:   af.ApprovedBy,
		RejectReason: af.RejectReason,
		ReviewedAt:   af.ReviewedAt,
		ReviewedBy:   af.ReviewedBy,
		GeneratedAt:  af.GeneratedAt,
	}
	if af.TechniqueID != "" {
		rf.MITRETechniques = []string{af.TechniqueID}
	}
	if af.Tactic != "" {
		rf.MITRETactics = []string{af.Tactic}
	}
	for i, id := range af.AuditIDs {
		if i >= 3 {
			break
		}
		rf.EvidencePreview = append(rf.EvidencePreview, ReviewEvidencePreview{AuditID: id})
	}
	return rf
}

func normaliseSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "critical", "high", "medium", "low", "info":
		return s
	case "informational":
		return "info"
	}
	return ""
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info":
		return 4
	}
	return 5
}

func sortReviewFindings(rs []ReviewFinding) {
	sort.SliceStable(rs, func(i, j int) bool {
		si, sj := severityRank(rs[i].Severity), severityRank(rs[j].Severity)
		if si != sj {
			return si < sj
		}
		pi := !rs[i].Approved && !rs[i].Rejected
		pj := !rs[j].Approved && !rs[j].Rejected
		if pi != pj {
			return pi
		}
		return rs[i].FindingID < rs[j].FindingID
	})
}

// ----------------------------------------------------------------------------
// Mutations (in-place rewrite of finding JSON)
// ----------------------------------------------------------------------------

type reviewMutationResult struct {
	Updated  int      `json:"updated"`
	NotFound []string `json:"not_found,omitempty"`
}

func (s *Server) applyReviewMutation(
	caseID string, findingIDs []string, action, reason, examiner string,
) (*reviewMutationResult, error) {
	_, locators, err := s.loadAllReviewFindings(caseID)
	if err != nil {
		return nil, err
	}

	// Map path -> set of finding_ids to touch in that file (1B can hold N).
	touched := map[string][]string{}
	notFound := []string{}
	for _, id := range findingIDs {
		if loc, ok := locators[id]; ok {
			touched[loc.Path] = append(touched[loc.Path], id)
		} else {
			notFound = append(notFound, id)
		}
	}

	res := &reviewMutationResult{}
	now := time.Now().UTC()

	for path, ids := range touched {
		loc := locators[ids[0]]
		if loc.IsRule {
			body, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", path, err)
			}
			var f tier1a.Finding
			if err := json.Unmarshal(body, &f); err != nil {
				return nil, fmt.Errorf("unmarshal %s: %w", path, err)
			}
			applyMutationTier1A(&f, action, reason, examiner, now)
			out, err := json.MarshalIndent(f, "", "  ")
			if err != nil {
				return nil, fmt.Errorf("marshal %s: %w", path, err)
			}
			if err := os.WriteFile(path, out, 0o644); err != nil {
				return nil, fmt.Errorf("write %s: %w", path, err)
			}
			res.Updated++
		} else {
			body, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", path, err)
			}
			var rep tier1b.AnomalyReport
			if err := json.Unmarshal(body, &rep); err != nil {
				return nil, fmt.Errorf("unmarshal %s: %w", path, err)
			}
			byID := map[string]bool{}
			for _, id := range ids {
				byID[id] = true
			}
			for i := range rep.Findings {
				if byID[rep.Findings[i].FindingID] {
					applyMutationTier1B(&rep.Findings[i], action, reason, examiner, now)
					res.Updated++
				}
			}
			out, err := json.MarshalIndent(rep, "", "  ")
			if err != nil {
				return nil, fmt.Errorf("marshal %s: %w", path, err)
			}
			if err := os.WriteFile(path, out, 0o644); err != nil {
				return nil, fmt.Errorf("write %s: %w", path, err)
			}
		}
	}

	sort.Strings(notFound)
	res.NotFound = notFound
	return res, nil
}

func applyMutationTier1A(f *tier1a.Finding, action, reason, examiner string, now time.Time) {
	switch action {
	case "approve":
		f.Approved = true
		f.Rejected = false
		f.RejectReason = ""
		f.ApprovedBy = examiner
		f.ReviewedAt = now
		f.ReviewedBy = examiner
	case "reject":
		f.Approved = false
		f.Rejected = true
		f.RejectReason = reason
		f.ApprovedBy = ""
		f.ReviewedAt = now
		f.ReviewedBy = examiner
	case "reset":
		approved, by := tier1a.AutoApproveByLevel(f.RuleMeta.Level)
		f.Approved = approved
		f.Rejected = false
		f.RejectReason = ""
		f.ApprovedBy = by
		f.ReviewedAt = time.Time{}
		f.ReviewedBy = ""
	}
}

func applyMutationTier1B(f *tier1b.AnomalyFinding, action, reason, examiner string, now time.Time) {
	switch action {
	case "approve":
		f.Approved = true
		f.Rejected = false
		f.RejectReason = ""
		f.ApprovedBy = examiner
		f.ReviewedAt = now
		f.ReviewedBy = examiner
	case "reject":
		f.Approved = false
		f.Rejected = true
		f.RejectReason = reason
		f.ApprovedBy = ""
		f.ReviewedAt = now
		f.ReviewedBy = examiner
	case "reset":
		approved, by := tier1a.AutoApproveByLevel(f.Severity)
		f.Approved = approved
		f.Rejected = false
		f.RejectReason = ""
		f.ApprovedBy = by
		f.ReviewedAt = time.Time{}
		f.ReviewedBy = ""
	}
}
