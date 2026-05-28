package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/tlvb/tlvb/internal/casedb"
)

// ----------------------------------------------------------------------------
// Review Gate 0 — per-artifact parse-result approval (★v0.3 #2)
//
// State is stored as JSON at outputs/cases/<id>/parse_review.json. We keep
// it on disk (not in DuckDB) so the read-only DB path stays untouched and
// the file is self-evidently part of the case workspace.
//
// Shape:
//   {
//     "case_id": "...",
//     "auto_skip": false,             // true => Analyze ignores per-artifact state
//     "reviews": {
//       "evtx":     {"state": "approved", ...},
//       "amcache":  {"state": "rejected", "reason": "garbage output", ...}
//     }
//   }
// ----------------------------------------------------------------------------

const parseReviewFile = "parse_review.json"

type parseReview struct {
	State      string    `json:"state"` // pending | approved | rejected | skipped
	Reason     string    `json:"reason,omitempty"`
	ReviewedBy string    `json:"reviewed_by,omitempty"`
	ReviewedAt time.Time `json:"reviewed_at,omitempty"`
}

type parseReviewDoc struct {
	CaseID   string                 `json:"case_id"`
	AutoSkip bool                   `json:"auto_skip"`
	Reviews  map[string]parseReview `json:"reviews"`
}

// One global lock per case so concurrent UI clicks (Approve + Reject on
// different artifacts) don't lose each other's writes. parse_review.json
// is small so we always read-modify-write under the lock.
var (
	parseReviewLocksMu sync.Mutex
	parseReviewLocks   = map[string]*sync.Mutex{}
)

func parseReviewLock(caseID string) *sync.Mutex {
	parseReviewLocksMu.Lock()
	defer parseReviewLocksMu.Unlock()
	if mu, ok := parseReviewLocks[caseID]; ok {
		return mu
	}
	mu := &sync.Mutex{}
	parseReviewLocks[caseID] = mu
	return mu
}

func (s *Server) parseReviewPath(caseID string) string {
	return filepath.Join(s.cfg.OutputsRoot, caseID, parseReviewFile)
}

func (s *Server) loadParseReview(caseID string) parseReviewDoc {
	doc := parseReviewDoc{CaseID: caseID, Reviews: map[string]parseReview{}}
	body, err := os.ReadFile(s.parseReviewPath(caseID))
	if err != nil {
		return doc // missing file → empty state, all artifacts treated as pending
	}
	_ = json.Unmarshal(body, &doc) // bad JSON → reset to empty (defensive)
	if doc.Reviews == nil {
		doc.Reviews = map[string]parseReview{}
	}
	doc.CaseID = caseID
	return doc
}

func (s *Server) saveParseReview(doc parseReviewDoc) error {
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	path := s.parseReviewPath(doc.CaseID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o644)
}

// ----------------------------------------------------------------------------
// REST handlers
// ----------------------------------------------------------------------------

// GET /api/cases/:id/parse-review
func (s *Server) handleGetParseReview(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	mu := parseReviewLock(caseID)
	mu.Lock()
	doc := s.loadParseReview(caseID)
	mu.Unlock()

	// Augment with the current artifact_id list from parse_results so the
	// UI can render rows even for artifacts the user hasn't acted on yet.
	artifacts, _ := s.parseResultArtifactIDs(r.Context(), caseID)
	for _, aid := range artifacts {
		if _, ok := doc.Reviews[aid]; !ok {
			doc.Reviews[aid] = parseReview{State: "pending"}
		}
	}

	// Roll-up summary so the UI can show e.g. "approved 3/12, pending 8, rejected 1"
	counts := map[string]int{"approved": 0, "rejected": 0, "pending": 0, "skipped": 0}
	for _, r := range doc.Reviews {
		s := r.State
		if s == "" {
			s = "pending"
		}
		counts[s]++
	}
	writeJSON(w, 200, map[string]any{
		"case_id":   caseID,
		"auto_skip": doc.AutoSkip,
		"reviews":   doc.Reviews,
		"counts":    counts,
		"total":     len(doc.Reviews),
		"all_approved_or_skipped": doc.AutoSkip || (counts["pending"] == 0 && counts["rejected"] == 0),
	})
}

// POST /api/cases/:id/parse-review/{artifact}/approve
func (s *Server) handleApproveParseResult(w http.ResponseWriter, r *http.Request) {
	s.mutateParseReview(w, r, "approved", "")
}

// POST /api/cases/:id/parse-review/{artifact}/reject (body: {reason: "..."})
func (s *Server) handleRejectParseResult(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	_ = decodeJSON(r, &req)
	s.mutateParseReview(w, r, "rejected", req.Reason)
}

// POST /api/cases/:id/parse-review/skip-all (body: {auto_skip: true|false})
// When auto_skip flips to true, every currently-pending artifact is marked
// as "skipped" so the roll-up reflects that the gate was waived.
func (s *Server) handleParseReviewSkipAll(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	var req struct {
		AutoSkip bool `json:"auto_skip"`
	}
	_ = decodeJSON(r, &req)

	examiner := r.Header.Get("X-Examiner")
	if examiner == "" {
		examiner = "examiner-web"
	}

	mu := parseReviewLock(caseID)
	mu.Lock()
	defer mu.Unlock()
	doc := s.loadParseReview(caseID)
	doc.AutoSkip = req.AutoSkip

	if req.AutoSkip {
		artifacts, _ := s.parseResultArtifactIDs(r.Context(), caseID)
		now := time.Now().UTC()
		for _, aid := range artifacts {
			cur := doc.Reviews[aid]
			if cur.State == "approved" || cur.State == "rejected" {
				continue // honour explicit examiner decisions
			}
			doc.Reviews[aid] = parseReview{
				State:      "skipped",
				ReviewedBy: examiner,
				ReviewedAt: now,
			}
		}
	}
	if err := s.saveParseReview(doc); err != nil {
		writeError(w, 500, "save: %v", err)
		return
	}
	writeJSON(w, 200, map[string]any{"status": "ok", "auto_skip": doc.AutoSkip})
}

func (s *Server) mutateParseReview(w http.ResponseWriter, r *http.Request, newState, reason string) {
	caseID := r.PathValue("id")
	artifact := r.PathValue("artifact")
	if artifact == "" {
		writeError(w, 400, "artifact required")
		return
	}
	// Wave 39 bug A fix: validate artifact_id against the case's known set
	// from parse_results to prevent path-traversal-style writes
	// (e.g. POST /parse-review/..%2Fadmin/approve was previously accepted
	// and stored "../admin" as a key in parse_review.json). Restrict to
	// IDs that the orchestrator actually emitted for this case.
	knownIDs, _ := s.parseResultArtifactIDs(r.Context(), caseID)
	allowed := false
	for _, id := range knownIDs {
		if id == artifact {
			allowed = true
			break
		}
	}
	if !allowed {
		writeError(w, 404, "unknown artifact_id %q for case %q "+
			"(must be one of parse_results)", artifact, caseID)
		return
	}
	examiner := r.Header.Get("X-Examiner")
	if examiner == "" {
		examiner = "examiner-web"
	}
	mu := parseReviewLock(caseID)
	mu.Lock()
	defer mu.Unlock()
	doc := s.loadParseReview(caseID)
	doc.Reviews[artifact] = parseReview{
		State:      newState,
		Reason:     reason,
		ReviewedBy: examiner,
		ReviewedAt: time.Now().UTC(),
	}
	if err := s.saveParseReview(doc); err != nil {
		writeError(w, 500, "save: %v", err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"status":      "ok",
		"artifact_id": artifact,
		"state":       newState,
		"reason":      reason,
		"reviewed_by": examiner,
	})
}

// ----------------------------------------------------------------------------
// Gating helper used by handleStartAnalyzeAll / handleStartAnalyzeOne
// ----------------------------------------------------------------------------

// gateAllowsAnalyze returns nil if the examiner has approved (or skip-all'd)
// the parse results so Analyze may proceed. Returns a descriptive error
// otherwise. The ?force=true URL flag bypasses the gate.
func (s *Server) gateAllowsAnalyze(r *http.Request, caseID string) error {
	if r.URL.Query().Get("force") == "true" {
		return nil
	}
	mu := parseReviewLock(caseID)
	mu.Lock()
	doc := s.loadParseReview(caseID)
	mu.Unlock()
	if doc.AutoSkip {
		return nil
	}
	artifacts, _ := s.parseResultArtifactIDs(r.Context(), caseID)
	if len(artifacts) == 0 {
		// No parse results at all — Analyze will fail later with a clearer
		// message than "Gate 0 not satisfied"; let it through.
		return nil
	}
	pending, rejected := []string{}, []string{}
	for _, aid := range artifacts {
		st := doc.Reviews[aid].State
		switch st {
		case "approved", "skipped":
			// ok
		case "rejected":
			rejected = append(rejected, aid)
		default:
			pending = append(pending, aid)
		}
	}
	if len(pending) == 0 && len(rejected) == 0 {
		return nil
	}
	parts := []string{}
	if len(pending) > 0 {
		sort.Strings(pending)
		parts = append(parts, fmt.Sprintf("pending: %v", pending))
	}
	if len(rejected) > 0 {
		sort.Strings(rejected)
		parts = append(parts,
			fmt.Sprintf("rejected: %v (re-parse or approve to proceed)", rejected))
	}
	return fmt.Errorf("Review Gate 0 not satisfied — %s. "+
		"Approve in the Events tab, or POST skip-all=true, or pass ?force=true",
		joinStrings(parts, "; "))
}

// parseResultArtifactIDs reads the artifact_ids in the case's parse_results
// table — used to enumerate what the examiner is reviewing.
func (s *Server) parseResultArtifactIDs(ctx context.Context, caseID string) ([]string, error) {
	var ids []string
	err := s.withDB(casedb.ReadOnly, func(m *casedb.Manager) error {
		// GetCaseStatus also returns parse_results with artifact_id;
		// borrow that rather than adding a new query.
		st, err := m.GetCaseStatus(ctx, caseID)
		if err != nil {
			return err
		}
		for _, pr := range st.ParseResults {
			ids = append(ids, pr.ArtifactID)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(ids)
	return ids, nil
}

func joinStrings(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}
