package web

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ----------------------------------------------------------------------------
// Review of disk-image extractions (Issue #23, "extracts" section in
// Review Gate 0). State is stored at outputs/cases/<id>/extract_review.json
// alongside parse_review.json — same shape, different keys (target labels
// from parsers/image_extractor.py rather than artifact_ids).
//
// extract.log itself (one JSONL row per file the image_extractor touched)
// is the source of truth for which targets exist; this file just carries
// approve/reject state on top.
// ----------------------------------------------------------------------------

const extractReviewFile = "extract_review.json"
const extractLogFile = "extract.log"

type extractReview struct {
	State      string    `json:"state"` // pending | approved | rejected
	Reason     string    `json:"reason,omitempty"`
	ReviewedBy string    `json:"reviewed_by,omitempty"`
	ReviewedAt time.Time `json:"reviewed_at,omitempty"`
}

type extractReviewDoc struct {
	CaseID  string                   `json:"case_id"`
	Reviews map[string]extractReview `json:"reviews"`
}

type extractRecord struct {
	Target        string  `json:"target"`
	Status        string  `json:"status"` // ok | not_found | fail | skip
	Partition     *int    `json:"partition,omitempty"`
	Inum          string  `json:"inum,omitempty"`
	SHA256        string  `json:"sha256,omitempty"`
	Bytes         int64   `json:"bytes"`
	ExtractedPath string  `json:"extracted_path,omitempty"`
	Error         string  `json:"error,omitempty"`
}

type extractHeader struct {
	Schema       string         `json:"schema"`
	ImagePath    string         `json:"image_path"`
	ImageFormat  string         `json:"image_format"`
	MountMethod  string         `json:"mount_method"`
	Summary      map[string]any `json:"summary"`
}

var (
	extractReviewLocksMu sync.Mutex
	extractReviewLocks   = map[string]*sync.Mutex{}
)

func extractReviewLock(caseID string) *sync.Mutex {
	extractReviewLocksMu.Lock()
	defer extractReviewLocksMu.Unlock()
	if mu, ok := extractReviewLocks[caseID]; ok {
		return mu
	}
	mu := &sync.Mutex{}
	extractReviewLocks[caseID] = mu
	return mu
}

func (s *Server) extractReviewPath(caseID string) string {
	return filepath.Join(s.cfg.OutputsRoot, caseID, extractReviewFile)
}

func (s *Server) extractLogPath(caseID string) string {
	return filepath.Join(s.cfg.OutputsRoot, caseID, extractLogFile)
}

func (s *Server) loadExtractReview(caseID string) extractReviewDoc {
	doc := extractReviewDoc{CaseID: caseID, Reviews: map[string]extractReview{}}
	body, err := os.ReadFile(s.extractReviewPath(caseID))
	if err != nil {
		return doc
	}
	_ = json.Unmarshal(body, &doc)
	if doc.Reviews == nil {
		doc.Reviews = map[string]extractReview{}
	}
	doc.CaseID = caseID
	return doc
}

func (s *Server) saveExtractReview(doc extractReviewDoc) error {
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	path := s.extractReviewPath(doc.CaseID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o644)
}

// readExtractLog parses outputs/cases/<id>/extract.log into a header + list.
// Returns empty values (not an error) when the case had no image input,
// so the UI can show "no extractions for this case" without a 404.
func (s *Server) readExtractLog(caseID string) (extractHeader, []extractRecord) {
	var header extractHeader
	var recs []extractRecord
	f, err := os.Open(s.extractLogPath(caseID))
	if err != nil {
		return header, recs
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 4<<20)
	first := true
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		if first {
			first = false
			_ = json.Unmarshal(line, &header)
			continue
		}
		var r extractRecord
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		recs = append(recs, r)
	}
	return header, recs
}

// GET /api/cases/:id/extracts
func (s *Server) handleGetExtracts(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	header, recs := s.readExtractLog(caseID)

	mu := extractReviewLock(caseID)
	mu.Lock()
	doc := s.loadExtractReview(caseID)
	mu.Unlock()

	// Stamp each record with current review state — default pending.
	type augmented struct {
		extractRecord
		State      string    `json:"state"`
		Reason     string    `json:"reason,omitempty"`
		ReviewedBy string    `json:"reviewed_by,omitempty"`
		ReviewedAt time.Time `json:"reviewed_at,omitempty"`
	}
	out := make([]augmented, 0, len(recs))
	counts := map[string]int{"approved": 0, "rejected": 0, "pending": 0}
	for _, rec := range recs {
		rv, ok := doc.Reviews[rec.Target]
		if !ok {
			rv.State = "pending"
		}
		if rv.State == "" {
			rv.State = "pending"
		}
		counts[rv.State]++
		out = append(out, augmented{
			extractRecord: rec,
			State:         rv.State,
			Reason:        rv.Reason,
			ReviewedBy:    rv.ReviewedBy,
			ReviewedAt:    rv.ReviewedAt,
		})
	}
	writeJSON(w, 200, map[string]any{
		"case_id":  caseID,
		"header":   header,
		"records":  out,
		"counts":   counts,
		"total":    len(out),
	})
}

// POST /api/cases/:id/extracts/{target}/approve
func (s *Server) handleApproveExtract(w http.ResponseWriter, r *http.Request) {
	s.mutateExtractReview(w, r, "approved", "")
}

// POST /api/cases/:id/extracts/{target}/reject
func (s *Server) handleRejectExtract(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	_ = decodeJSON(r, &req)
	s.mutateExtractReview(w, r, "rejected", req.Reason)
}

func (s *Server) mutateExtractReview(w http.ResponseWriter, r *http.Request, newState, reason string) {
	caseID := r.PathValue("id")
	target := r.PathValue("target")
	if target == "" {
		writeError(w, 400, "target required")
		return
	}
	examiner := r.Header.Get("X-Examiner")
	if examiner == "" {
		examiner = "examiner-web"
	}
	mu := extractReviewLock(caseID)
	mu.Lock()
	defer mu.Unlock()
	doc := s.loadExtractReview(caseID)
	doc.Reviews[target] = extractReview{
		State:      newState,
		Reason:     reason,
		ReviewedBy: examiner,
		ReviewedAt: time.Now().UTC(),
	}
	if err := s.saveExtractReview(doc); err != nil {
		writeError(w, 500, "save: %v", err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"status": "ok",
		"target": target,
		"state":  newState,
		"reason": reason,
	})
}

// targetsAlpha returns the list of extract target labels in alphabetic
// order — used by callers that want a stable enumeration.
func extractTargetsSorted(recs []extractRecord) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.Target)
	}
	sort.Strings(out)
	return out
}
