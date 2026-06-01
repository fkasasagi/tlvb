// Package web — Rule Library.
//
// The Rule Library is a GLOBAL (not case-scoped) view of rules.duckdb:
//   - rule_sql_cache build coverage (built / pending / failed per source)
//     and a filterable, paginated list of the generated SQL — what Tier 1A
//     will execute at runtime.
//   - skill_sql_cache (Tier 1B v0.2 learned lenses): candidate / canonical
//     queries with their intent and hit_count.
//
// Builds run offline via `tlvb rules build`, so there is no live progress to
// stream here; the summary is a coverage snapshot that stays meaningful after
// a server restart. All endpoints degrade gracefully when rules.duckdb does
// not exist yet (Available=false / empty rows), never a 500.
package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/rulesdb"
)

var errRulesDBMissing = errors.New("rules.duckdb not found")

// withRulesDB opens rules.duckdb read-only under a dedicated mutex (separate
// file from cases.duckdb). Returns errRulesDBMissing when the DB is absent so
// callers can answer with an empty-but-valid payload.
func (s *Server) withRulesDB(fn func(*rulesdb.Manager) error) error {
	s.rulesMu.Lock()
	defer s.rulesMu.Unlock()
	m, err := rulesdb.Open(s.cfg.RulesDBPath, rulesdb.ReadOnly)
	if err != nil {
		// rulesdb.Open returns an error containing "does not exist" for a
		// missing file in read-only mode.
		if strings.Contains(err.Error(), "does not exist") {
			return errRulesDBMissing
		}
		return err
	}
	defer m.Close()
	return fn(m)
}

// ----------------------------------------------------------------------------
// Wire types
// ----------------------------------------------------------------------------

type RulesSummary struct {
	Available bool              `json:"available"`
	Rules     RuleCacheSummary  `json:"rules"`
	Skills    SkillCacheSummary `json:"skills"`
}

type RuleCacheSummary struct {
	Total    int              `json:"total"`
	ByState  map[string]int   `json:"by_state"`
	BySource []SourceCoverage `json:"by_source"`
}

type SourceCoverage struct {
	Source  string `json:"source"`
	Built   int    `json:"built"`
	Pending int    `json:"pending"`
	Failed  int    `json:"failed"`
	Total   int    `json:"total"`
}

type SkillCacheSummary struct {
	Total     int `json:"total"`
	Candidate int `json:"candidate"`
	Canonical int `json:"canonical"`
}

type RuleRow struct {
	RuleID             string   `json:"rule_id"`
	RuleSource         string   `json:"rule_source"`
	State              string   `json:"state"`
	Level              string   `json:"level,omitempty"`
	Title              string   `json:"title,omitempty"`
	MitreTechniques    []string `json:"mitre_techniques,omitempty"`
	PrefilterArtifacts string   `json:"prefilter_artifacts,omitempty"`
	GeneratedAt        string   `json:"generated_at,omitempty"`
	SQL                string   `json:"sql,omitempty"`
	ErrorMessage       string   `json:"error_message,omitempty"`
}

type RuleListResponse struct {
	Total  int       `json:"total"`
	Offset int       `json:"offset"`
	Limit  int       `json:"limit"`
	Rows   []RuleRow `json:"rows"`
}

type SkillRow struct {
	Skill        string `json:"skill"`
	Intent       string `json:"intent,omitempty"`
	State        string `json:"state"`
	HitCount     int    `json:"hit_count"`
	OriginCase   string `json:"origin_case,omitempty"`
	LastUsedCase string `json:"last_used_case,omitempty"`
	GeneratedAt  string `json:"generated_at,omitempty"`
	SQL          string `json:"sql,omitempty"`
}

// ----------------------------------------------------------------------------
// Handlers
// ----------------------------------------------------------------------------

// GET /api/rules/summary
func (s *Server) handleGetRulesSummary(w http.ResponseWriter, r *http.Request) {
	out := RulesSummary{
		Available: true,
		Rules:     RuleCacheSummary{ByState: map[string]int{}},
	}
	err := s.withRulesDB(func(m *rulesdb.Manager) error {
		counts, err := m.CountRulesBySourceState(r.Context())
		if err != nil {
			return err
		}
		bySource := map[string]*SourceCoverage{}
		for _, c := range counts {
			sc := bySource[c.Source]
			if sc == nil {
				sc = &SourceCoverage{Source: c.Source}
				bySource[c.Source] = sc
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
			out.Rules.ByState[string(c.State)] += c.Count
			out.Rules.Total += c.Count
		}
		for _, sc := range bySource {
			out.Rules.BySource = append(out.Rules.BySource, *sc)
		}
		sort.Slice(out.Rules.BySource, func(i, j int) bool {
			return out.Rules.BySource[i].Source < out.Rules.BySource[j].Source
		})
		skc, err := m.CountSkillByState(r.Context())
		if err != nil {
			return err
		}
		out.Skills.Candidate = skc[rulesdb.SkillCandidate]
		out.Skills.Canonical = skc[rulesdb.SkillCanonical]
		out.Skills.Total = out.Skills.Candidate + out.Skills.Canonical
		return nil
	})
	if errors.Is(err, errRulesDBMissing) {
		out.Available = false
		writeJSON(w, 200, out)
		return
	}
	if err != nil {
		writeError(w, 500, "rules summary: %v", err)
		return
	}
	writeJSON(w, 200, out)
}

// GET /api/rules?source=&state=&q=&limit=100&offset=0
func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	source := q.Get("source")
	state := q.Get("state")
	search := strings.ToLower(strings.TrimSpace(q.Get("q")))
	limit := atoiDefault(q.Get("limit"), 100)
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset := atoiDefault(q.Get("offset"), 0)
	if offset < 0 {
		offset = 0
	}

	resp := RuleListResponse{Offset: offset, Limit: limit, Rows: []RuleRow{}}
	err := s.withRulesDB(func(m *rulesdb.Manager) error {
		rows, err := m.ListAll(r.Context(), source, rulesdb.CacheState(state))
		if err != nil {
			return err
		}
		filtered := make([]RuleRow, 0, len(rows))
		for _, cr := range rows {
			rr := toRuleRow(cr)
			if search != "" && !ruleMatches(rr, search) {
				continue
			}
			filtered = append(filtered, rr)
		}
		resp.Total = len(filtered)
		if offset < len(filtered) {
			end := offset + limit
			if end > len(filtered) {
				end = len(filtered)
			}
			resp.Rows = filtered[offset:end]
		}
		return nil
	})
	if errors.Is(err, errRulesDBMissing) {
		writeJSON(w, 200, resp)
		return
	}
	if err != nil {
		writeError(w, 500, "list rules: %v", err)
		return
	}
	writeJSON(w, 200, resp)
}

// GET /api/rules/skills
func (s *Server) handleListSkillSQL(w http.ResponseWriter, r *http.Request) {
	resp := struct {
		Rows []SkillRow `json:"rows"`
	}{Rows: []SkillRow{}}
	err := s.withRulesDB(func(m *rulesdb.Manager) error {
		rows, err := m.ListAllSkillSQL(r.Context())
		if err != nil {
			return err
		}
		for _, sr := range rows {
			resp.Rows = append(resp.Rows, toSkillRow(sr))
		}
		return nil
	})
	if errors.Is(err, errRulesDBMissing) {
		writeJSON(w, 200, resp)
		return
	}
	if err != nil {
		writeError(w, 500, "list skill SQL: %v", err)
		return
	}
	writeJSON(w, 200, resp)
}

// ----------------------------------------------------------------------------
// Mapping helpers
// ----------------------------------------------------------------------------

func toRuleRow(cr rulesdb.CacheRow) RuleRow {
	rr := RuleRow{
		RuleID:             cr.RuleID,
		RuleSource:         cr.RuleSource,
		State:              string(cr.State),
		PrefilterArtifacts: cr.PrefilterArtifacts,
		SQL:                cr.SQL,
		ErrorMessage:       cr.ErrorMessage,
	}
	if cr.GeneratedAt != nil && !cr.GeneratedAt.IsZero() {
		rr.GeneratedAt = cr.GeneratedAt.UTC().Format(time.RFC3339)
	}
	if cr.RuleMeta != "" {
		var meta struct {
			Level           string   `json:"level"`
			Title           string   `json:"title"`
			MitreTechniques []string `json:"mitre_techniques"`
		}
		if json.Unmarshal([]byte(cr.RuleMeta), &meta) == nil {
			rr.Level = meta.Level
			rr.Title = meta.Title
			rr.MitreTechniques = meta.MitreTechniques
		}
	}
	return rr
}

func ruleMatches(rr RuleRow, search string) bool {
	return strings.Contains(strings.ToLower(rr.RuleID), search) ||
		strings.Contains(strings.ToLower(rr.Title), search) ||
		strings.Contains(strings.ToLower(rr.SQL), search) ||
		strings.Contains(strings.ToLower(strings.Join(rr.MitreTechniques, " ")), search)
}

func toSkillRow(sr rulesdb.SkillSQLRow) SkillRow {
	out := SkillRow{
		Skill:        sr.Skill,
		Intent:       sr.Intent,
		State:        string(sr.State),
		HitCount:     sr.HitCount,
		OriginCase:   sr.OriginCase,
		LastUsedCase: sr.LastUsedCase,
		SQL:          sr.SQL,
	}
	if sr.GeneratedAt != nil && !sr.GeneratedAt.IsZero() {
		out.GeneratedAt = sr.GeneratedAt.UTC().Format(time.RFC3339)
	}
	return out
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
