// Package web — Case state snapshot.
//
// /api/cases/{id}/summary returns a static view of where the case currently
// stands across the four pipeline tiers (parse / Tier 1 findings / synthesis
// / report). It complements the existing per-step JobStatus endpoints
// which only show what's running *now* — the summary stays informative
// even after a fresh server restart with no jobs in flight.
package web

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/casedb"
)

// CaseSummary is the wire shape returned to the UI.
type CaseSummary struct {
	CaseID    string           `json:"case_id"`
	Parse     *ParseSummary    `json:"parse,omitempty"`
	Tier1A    *FindingsSummary `json:"tier1a,omitempty"`
	Tier1B    *FindingsSummary `json:"tier1b,omitempty"`
	Synthesis *SynthSummary    `json:"synthesis,omitempty"`
	Report    *ReportSummary   `json:"report,omitempty"`
}

type ParseSummary struct {
	EvidenceCount int               `json:"evidence_count"`
	EventsTotal   int64             `json:"events_total"`
	Artifacts     []ArtifactSummary `json:"artifacts,omitempty"`
	LastParsedAt  string            `json:"last_parsed_at,omitempty"`
}

type ArtifactSummary struct {
	ArtifactID string `json:"artifact_id"`
	EventCount int64  `json:"event_count"`
}

type FindingsSummary struct {
	FindingsCount     int            `json:"findings_count"`
	BySeverity        map[string]int `json:"by_severity"`
	BySource          map[string]int `json:"by_source,omitempty"`
	PendingCount      int            `json:"pending_count"`
	ApprovedCount     int            `json:"approved_count"`
	AutoApprovedCount int            `json:"auto_approved_count"`
	RejectedCount     int            `json:"rejected_count"`
	LastUpdated       string         `json:"last_updated,omitempty"`
}

type SynthSummary struct {
	Present             bool   `json:"present"`
	TotalFindings       int    `json:"total_findings,omitempty"`
	ClustersCount       int    `json:"clusters_count,omitempty"`
	TechniquesCount     int    `json:"techniques_count,omitempty"`
	OpenQuestionsCount  int    `json:"open_questions_count,omitempty"`
	ActiveSearchEnabled bool   `json:"active_search_enabled,omitempty"`
	ActiveSQLAttempted  int    `json:"active_sql_attempted,omitempty"`
	ActiveSQLSucceeded  int    `json:"active_sql_succeeded,omitempty"`
	LLMCallsTotal       int    `json:"llm_calls_total,omitempty"`
	GeneratedAt         string `json:"generated_at,omitempty"`
	ModelID             string `json:"model_id,omitempty"`
}

type ReportSummary struct {
	Formats     []string `json:"formats"`
	GeneratedAt string   `json:"generated_at,omitempty"`
}

func (s *Server) handleGetCaseSummary(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	sum := CaseSummary{CaseID: caseID}

	sum.Parse = s.summariseParse(caseID)
	sum.Tier1A, sum.Tier1B = s.summariseFindings(caseID)
	sum.Synthesis = s.summariseSynthesis(caseID)
	sum.Report = s.summariseReport(caseID)

	writeJSON(w, 200, sum)
}

// ----------------------------------------------------------------------------
// Parse: query unified_events for per-artifact event counts.
// ----------------------------------------------------------------------------

func (s *Server) summariseParse(caseID string) *ParseSummary {
	var ps ParseSummary
	err := s.withDB(casedb.ReadOnly, func(m *casedb.Manager) error {
		// per-artifact counts + total
		rows, err := m.DB().Query(
			`SELECT artifact_id, COUNT(*) AS n
			 FROM unified_events
			 WHERE case_id = ?
			 GROUP BY artifact_id
			 ORDER BY n DESC`, caseID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a string
			var n int64
			if err := rows.Scan(&a, &n); err != nil {
				return err
			}
			ps.Artifacts = append(ps.Artifacts, ArtifactSummary{ArtifactID: a, EventCount: n})
			ps.EventsTotal += n
		}
		if err := rows.Err(); err != nil {
			return err
		}
		// evidence count
		row := m.DB().QueryRow(
			`SELECT COUNT(DISTINCT evidence_id) FROM unified_events WHERE case_id = ?`,
			caseID)
		if err := row.Scan(&ps.EvidenceCount); err != nil {
			return err
		}
		// last parsed at (max ingested_at if available, else max ts_utc)
		var ts *time.Time
		row = m.DB().QueryRow(
			`SELECT MAX(ts_utc) FROM unified_events WHERE case_id = ?`, caseID)
		_ = row.Scan(&ts)
		if ts != nil && !ts.IsZero() {
			ps.LastParsedAt = ts.UTC().Format(time.RFC3339)
		}
		return nil
	})
	if err != nil {
		// No parse data yet — return nil to omit the section from the response.
		return nil
	}
	if ps.EventsTotal == 0 && ps.EvidenceCount == 0 {
		return nil
	}
	return &ps
}

// ----------------------------------------------------------------------------
// Findings: reuse the unified loadAllReviewFindings to summarise both tiers.
// ----------------------------------------------------------------------------

func (s *Server) summariseFindings(caseID string) (*FindingsSummary, *FindingsSummary) {
	findings, _, err := s.loadAllReviewFindings(caseID)
	if err != nil {
		return nil, nil
	}
	a := &FindingsSummary{BySeverity: map[string]int{}, BySource: map[string]int{}}
	b := &FindingsSummary{BySeverity: map[string]int{}, BySource: map[string]int{}}
	var latestA, latestB time.Time
	for _, f := range findings {
		dst := a
		if f.Source == "tier1b" {
			dst = b
		}
		dst.FindingsCount++
		if f.Severity != "" {
			dst.BySeverity[f.Severity]++
		}
		key := f.RuleSource
		if key == "" {
			key = f.Source
		}
		dst.BySource[key]++
		switch {
		case f.Rejected:
			dst.RejectedCount++
		case f.AutoApproved:
			dst.AutoApprovedCount++
		case f.Approved:
			dst.ApprovedCount++
		default:
			dst.PendingCount++
		}
		if f.GeneratedAt.IsZero() {
			continue
		}
		if f.Source == "tier1a" && f.GeneratedAt.After(latestA) {
			latestA = f.GeneratedAt
		} else if f.Source == "tier1b" && f.GeneratedAt.After(latestB) {
			latestB = f.GeneratedAt
		}
	}
	if !latestA.IsZero() {
		a.LastUpdated = latestA.UTC().Format(time.RFC3339)
	}
	if !latestB.IsZero() {
		b.LastUpdated = latestB.UTC().Format(time.RFC3339)
	}
	if a.FindingsCount == 0 {
		a = nil
	}
	if b.FindingsCount == 0 {
		b = nil
	}
	return a, b
}

// ----------------------------------------------------------------------------
// Synthesis: parse the subset of fields needed for the UI summary.
// Reading raw JSON keeps us decoupled from tier2 vs synthesizer schemas.
// ----------------------------------------------------------------------------

func (s *Server) summariseSynthesis(caseID string) *SynthSummary {
	path := filepath.Join(s.cfg.OutputsRoot, caseID, "synthesis.json")
	body, err := os.ReadFile(path)
	if err != nil {
		return &SynthSummary{Present: false}
	}
	var raw struct {
		GeneratedAt   string            `json:"generated_at"`
		ModelID       string            `json:"model_id"`
		TotalFindings int               `json:"total_findings"`
		ClusterCount  int               `json:"cluster_count"`
		Clusters      []json.RawMessage `json:"clusters"`
		MITREMapping  []json.RawMessage `json:"mitre_mapping"`
		OpenQuestions []string          `json:"open_questions"`
		Audit         struct {
			LLMCallsTotal       int  `json:"llm_calls_total"`
			ActiveSearchEnabled bool `json:"active_search_enabled"`
			ActiveSQLAttempted  int  `json:"active_sql_attempted"`
			ActiveSQLSucceeded  int  `json:"active_sql_succeeded"`
		} `json:"audit"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return &SynthSummary{Present: false}
	}
	clustersCount := raw.ClusterCount
	if clustersCount == 0 {
		clustersCount = len(raw.Clusters)
	}
	return &SynthSummary{
		Present:             true,
		TotalFindings:       raw.TotalFindings,
		ClustersCount:       clustersCount,
		TechniquesCount:     len(raw.MITREMapping),
		OpenQuestionsCount:  len(raw.OpenQuestions),
		ActiveSearchEnabled: raw.Audit.ActiveSearchEnabled,
		ActiveSQLAttempted:  raw.Audit.ActiveSQLAttempted,
		ActiveSQLSucceeded:  raw.Audit.ActiveSQLSucceeded,
		LLMCallsTotal:       raw.Audit.LLMCallsTotal,
		GeneratedAt:         raw.GeneratedAt,
		ModelID:             raw.ModelID,
	}
}

// ----------------------------------------------------------------------------
// Report: probe outputs/cases/<id>/reports/ for produced files.
// ----------------------------------------------------------------------------

func (s *Server) summariseReport(caseID string) *ReportSummary {
	reportsRoot := filepath.Join(s.cfg.OutputsRoot, caseID, "reports")
	entries, err := os.ReadDir(reportsRoot)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var generated time.Time
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		switch {
		case strings.HasSuffix(name, ".html"):
			seen["html"] = true
		case strings.HasSuffix(name, ".csv"):
			seen["csv"] = true
		case strings.HasSuffix(name, ".json"):
			seen["json"] = true
		}
		if fi, err := e.Info(); err == nil && fi.ModTime().After(generated) {
			generated = fi.ModTime()
		}
	}
	if len(seen) == 0 {
		return nil
	}
	formats := make([]string, 0, len(seen))
	for k := range seen {
		formats = append(formats, k)
	}
	sort.Strings(formats)
	rs := &ReportSummary{Formats: formats}
	if !generated.IsZero() {
		rs.GeneratedAt = generated.UTC().Format(time.RFC3339)
	}
	return rs
}
