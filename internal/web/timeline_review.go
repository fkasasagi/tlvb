package web

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tlvb/tlvb/internal/tier3"
)

// ----------------------------------------------------------------------------
// Review Gate 2 — per-timeline-entry approval (DESIGN §6.5)
//
// After Tier 2 Synthesizer produces synthesis.json::timeline, the examiner
// walks every TimelineEntry and approves / rejects it before the Report
// Generator (Tier 3) runs. Approved entries flow into the HTML/CSV/JSON
// report; rejected ones are dropped (or marked) so the final deliverable
// reflects examiner judgement, not raw LLM output.
//
// State is stored at outputs/cases/<id>/timeline_gate.json. The filename
// is deliberately NOT "timeline_review.json" — that name is already taken
// by the optional LLM 12-perspective review (internal/synthesizer/
// timeline_review.go). The two are orthogonal:
//   - synthesis.json::timeline_review = LLM observations on the timeline
//   - timeline_gate.json              = examiner approvals on entries
//
// Shape:
//   {
//     "case_id": "...",
//     "auto_skip": false,             // true => Report ignores per-entry state
//     "reviews": {
//       "<audit_id>": {"state": "approved", ...},
//       "<audit_id>": {"state": "rejected", "reason": "noise", ...}
//     }
//   }
// ----------------------------------------------------------------------------

const timelineGateFile = "timeline_gate.json"

type timelineGateReview struct {
	State      string    `json:"state"` // pending | approved | rejected | skipped
	Reason     string    `json:"reason,omitempty"`
	ReviewedBy string    `json:"reviewed_by,omitempty"`
	ReviewedAt time.Time `json:"reviewed_at,omitempty"`
}

type timelineGateDoc struct {
	CaseID   string                        `json:"case_id"`
	AutoSkip bool                          `json:"auto_skip"`
	Reviews  map[string]timelineGateReview `json:"reviews"`
}

// One global lock per case so concurrent UI clicks on different timeline
// entries don't lose each other's writes. timeline_gate.json is small so
// we always read-modify-write under the lock.
var (
	timelineGateLocksMu sync.Mutex
	timelineGateLocks   = map[string]*sync.Mutex{}
)

func timelineGateLock(caseID string) *sync.Mutex {
	timelineGateLocksMu.Lock()
	defer timelineGateLocksMu.Unlock()
	if mu, ok := timelineGateLocks[caseID]; ok {
		return mu
	}
	mu := &sync.Mutex{}
	timelineGateLocks[caseID] = mu
	return mu
}

func (s *Server) timelineGatePath(caseID string) string {
	return filepath.Join(s.cfg.OutputsRoot, caseID, timelineGateFile)
}

func (s *Server) loadTimelineGate(caseID string) timelineGateDoc {
	doc := timelineGateDoc{CaseID: caseID, Reviews: map[string]timelineGateReview{}}
	body, err := os.ReadFile(s.timelineGatePath(caseID))
	if err != nil {
		return doc // missing file → empty state, all entries treated as pending
	}
	_ = json.Unmarshal(body, &doc) // bad JSON → reset (defensive)
	if doc.Reviews == nil {
		doc.Reviews = map[string]timelineGateReview{}
	}
	doc.CaseID = caseID
	return doc
}

func (s *Server) saveTimelineGate(doc timelineGateDoc) error {
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	path := s.timelineGatePath(doc.CaseID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o644)
}

// timelineEntryAuditIDs returns the audit_id of every entry in the case
// timeline. Used to populate the gate doc with pending rows for entries the
// examiner hasn't acted on yet, and to validate approve/reject targets.
//
// Gate 2 sits between Tier 2 and Tier 3, so it stays a no-op until
// synthesis.json exists (the UI shows a "synthesize first" hint instead of
// breaking). Once it does, the audit_id set is derived from findings via the
// SAME tier3 enrichment the Timeline tab renders — the tier2 synthesis.json
// no longer stores a raw timeline, so reading findings keeps the gate's known
// set in lockstep with what the examiner actually sees (previously this read
// the legacy synthesis.json::timeline field and came back empty, which 404'd
// every approve/reject click).
func (s *Server) timelineEntryAuditIDs(caseID string) ([]string, error) {
	if _, err := os.Stat(filepath.Join(s.cfg.OutputsRoot, caseID, "synthesis.json")); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	en := tier3.LoadWebEnrichment(s.findingsDir(caseID))
	seen := map[string]bool{}
	out := make([]string, 0, len(en.Timeline))
	for _, t := range en.Timeline {
		if t.AuditID != "" && !seen[t.AuditID] {
			seen[t.AuditID] = true
			out = append(out, t.AuditID)
		}
	}
	return out, nil
}

// ----------------------------------------------------------------------------
// REST handlers
// ----------------------------------------------------------------------------

// GET /api/cases/:id/timeline-review
func (s *Server) handleGetTimelineReview(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	mu := timelineGateLock(caseID)
	mu.Lock()
	doc := s.loadTimelineGate(caseID)
	mu.Unlock()

	// Augment with the current TimelineEntry audit_ids from synthesis.json
	// so the UI can render rows for entries the user hasn't acted on yet.
	auditIDs, _ := s.timelineEntryAuditIDs(caseID)
	for _, aid := range auditIDs {
		if _, ok := doc.Reviews[aid]; !ok {
			doc.Reviews[aid] = timelineGateReview{State: "pending"}
		}
	}

	counts := map[string]int{"approved": 0, "rejected": 0, "pending": 0, "skipped": 0}
	for _, rv := range doc.Reviews {
		st := rv.State
		if st == "" {
			st = "pending"
		}
		counts[st]++
	}
	writeJSON(w, 200, map[string]any{
		"case_id":   caseID,
		"auto_skip": doc.AutoSkip,
		"reviews":   doc.Reviews,
		"counts":    counts,
		"total":     len(doc.Reviews),
		"all_approved_or_skipped": doc.AutoSkip ||
			(counts["pending"] == 0 && counts["rejected"] == 0),
	})
}

// POST /api/cases/:id/timeline-review/{audit_id}/approve
func (s *Server) handleApproveTimelineEntry(w http.ResponseWriter, r *http.Request) {
	s.mutateTimelineGate(w, r, "approved", "")
}

// POST /api/cases/:id/timeline-review/{audit_id}/reject  (body: {reason: "..."})
func (s *Server) handleRejectTimelineEntry(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	_ = decodeJSON(r, &req)
	s.mutateTimelineGate(w, r, "rejected", req.Reason)
}

// POST /api/cases/:id/timeline-review/{audit_id}/reset
// Clears a prior approve/reject so the entry returns to pending — the
// timeline counterpart of the findings review "リセット" action.
func (s *Server) handleResetTimelineEntry(w http.ResponseWriter, r *http.Request) {
	s.mutateTimelineGate(w, r, "pending", "")
}

// POST /api/cases/:id/timeline-review/skip-all  (body: {auto_skip: true|false})
// When auto_skip flips to true, every currently-pending entry is marked
// as "skipped" so the roll-up reflects that the gate was waived. Explicit
// approved/rejected decisions are preserved.
func (s *Server) handleTimelineReviewSkipAll(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	var req struct {
		AutoSkip bool `json:"auto_skip"`
	}
	_ = decodeJSON(r, &req)

	examiner := r.Header.Get("X-Examiner")
	if examiner == "" {
		examiner = "examiner-web"
	}

	mu := timelineGateLock(caseID)
	mu.Lock()
	defer mu.Unlock()
	doc := s.loadTimelineGate(caseID)
	doc.AutoSkip = req.AutoSkip

	if req.AutoSkip {
		auditIDs, _ := s.timelineEntryAuditIDs(caseID)
		now := time.Now().UTC()
		for _, aid := range auditIDs {
			cur := doc.Reviews[aid]
			if cur.State == "approved" || cur.State == "rejected" {
				continue
			}
			doc.Reviews[aid] = timelineGateReview{
				State:      "skipped",
				ReviewedBy: examiner,
				ReviewedAt: now,
			}
		}
	}
	if err := s.saveTimelineGate(doc); err != nil {
		writeError(w, 500, "save: %v", err)
		return
	}
	writeJSON(w, 200, map[string]any{"status": "ok", "auto_skip": doc.AutoSkip})
}

func (s *Server) mutateTimelineGate(w http.ResponseWriter, r *http.Request, newState, reason string) {
	caseID := r.PathValue("id")
	auditID := r.PathValue("audit_id")
	if auditID == "" {
		writeError(w, 400, "audit_id required")
		return
	}
	// Wave 39 bug A fix: validate audit_id against the case's known set
	// from synthesis.json::timeline so path-traversal-style writes
	// (e.g. POST /timeline-review/..%2Fevil/approve) can't pollute
	// timeline_gate.json. Restrict to audit_ids that the synthesizer
	// actually placed in the case timeline.
	knownIDs, _ := s.timelineEntryAuditIDs(caseID)
	allowed := false
	for _, id := range knownIDs {
		if id == auditID {
			allowed = true
			break
		}
	}
	if !allowed {
		writeError(w, 404, "unknown audit_id %q for case %q "+
			"(must be a synthesis.json timeline entry)", auditID, caseID)
		return
	}
	examiner := r.Header.Get("X-Examiner")
	if examiner == "" {
		examiner = "examiner-web"
	}
	mu := timelineGateLock(caseID)
	mu.Lock()
	defer mu.Unlock()
	doc := s.loadTimelineGate(caseID)
	if newState == "pending" {
		// Reset: drop the prior decision entirely so the entry falls back to
		// the default pending state (the GET handler re-synthesizes it).
		delete(doc.Reviews, auditID)
	} else {
		doc.Reviews[auditID] = timelineGateReview{
			State:      newState,
			Reason:     reason,
			ReviewedBy: examiner,
			ReviewedAt: time.Now().UTC(),
		}
	}
	if err := s.saveTimelineGate(doc); err != nil {
		writeError(w, 500, "save: %v", err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"status":      "ok",
		"audit_id":    auditID,
		"state":       newState,
		"reason":      reason,
		"reviewed_by": examiner,
	})
}

// ----------------------------------------------------------------------------
// Gating helper used by handleStartReport (Tier 3 entry)
// ----------------------------------------------------------------------------

// gateAllowsReport returns nil if the examiner has approved (or skip-all'd)
// the timeline so the Report Generator may proceed. Returns a descriptive
// error otherwise. The ?force=true URL flag bypasses the gate (symmetric
// with gateAllowsAnalyze for Gate 0).
//
// If synthesis.json doesn't exist yet (synthesizer not run), the gate is a
// no-op — Report generation itself will fail with a clearer error.
func (s *Server) gateAllowsReport(r *http.Request, caseID string) error {
	if r.URL.Query().Get("force") == "true" {
		return nil
	}
	mu := timelineGateLock(caseID)
	mu.Lock()
	doc := s.loadTimelineGate(caseID)
	mu.Unlock()
	if doc.AutoSkip {
		return nil
	}
	auditIDs, _ := s.timelineEntryAuditIDs(caseID)
	if len(auditIDs) == 0 {
		// Synthesis not produced yet → let downstream surface its own error
		// instead of double-reporting from the gate.
		return nil
	}
	var pending, rejected []string
	for _, aid := range auditIDs {
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
	if len(pending) > 0 || len(rejected) > 0 {
		return gateBlockedError{Pending: pending, Rejected: rejected, GateName: "Review Gate 2 (timeline)"}
	}
	return nil
}

// gateBlockedError mirrors the parse-review gate's error shape so the UI
// can render either gate's rejection with the same template.
type gateBlockedError struct {
	GateName string
	Pending  []string
	Rejected []string
}

func (e gateBlockedError) Error() string {
	return e.GateName + " not satisfied — pending=" +
		intToStr(len(e.Pending)) + " rejected=" + intToStr(len(e.Rejected)) +
		". Approve in the Timeline tab, or POST skip-all=true, or pass ?force=true"
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	// Cheap itoa without importing strconv just for one int.
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
