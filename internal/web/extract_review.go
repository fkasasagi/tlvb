package web

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	EvidenceID    string `json:"evidence_id,omitempty"`
	Target        string `json:"target"`
	Status        string `json:"status"` // ok | not_found | fail | skip
	Partition     *int   `json:"partition,omitempty"`
	Inum          string `json:"inum,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	Bytes         int64  `json:"bytes"`
	ExtractedPath string `json:"extracted_path,omitempty"`
	Error         string `json:"error,omitempty"`
}

type extractHeader struct {
	Schema      string         `json:"schema"`
	EvidenceID  string         `json:"evidence_id,omitempty"`
	ImagePath   string         `json:"image_path"`
	ImageFormat string         `json:"image_format"`
	MountMethod string         `json:"mount_method"`
	Summary     map[string]any `json:"summary"`
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

// parseExtractLogFile parses one extract-log JSONL file into its header
// (first line) + records. Returns zero values (not an error) when the file
// is missing so callers can treat "no image input" as an empty result.
func parseExtractLogFile(path string) (extractHeader, []extractRecord) {
	var header extractHeader
	var recs []extractRecord
	f, err := os.Open(path)
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

// readExtractLogs returns the case's extraction headers + records, grouped so
// each record carries the evidence_id it came from.
//
// Multi-evidence cases write one log per image to extracts/<evidence_id>.log
// (parsers/image_extractor.py); when that directory exists we read every file
// and stamp records with their evidence id (from the header, falling back to
// the filename). Older single-image cases only have the legacy case-level
// extract.log, which we read as a single (possibly unattributed) group.
func (s *Server) readExtractLogs(caseID string) ([]extractHeader, []extractRecord) {
	dir := filepath.Join(s.cfg.OutputsRoot, caseID, "extracts")
	entries, err := os.ReadDir(dir)
	if err == nil {
		var headers []extractHeader
		var recs []extractRecord
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
				continue
			}
			h, rs := parseExtractLogFile(filepath.Join(dir, e.Name()))
			ev := h.EvidenceID
			if ev == "" {
				ev = strings.TrimSuffix(e.Name(), ".log")
			}
			h.EvidenceID = ev
			headers = append(headers, h)
			for i := range rs {
				if rs[i].EvidenceID == "" {
					rs[i].EvidenceID = ev
				}
				recs = append(recs, rs[i])
			}
		}
		if len(headers) > 0 || len(recs) > 0 {
			return headers, recs
		}
	}
	// Legacy single-image case: one extract.log at the case root.
	h, rs := parseExtractLogFile(s.extractLogPath(caseID))
	for i := range rs {
		if rs[i].EvidenceID == "" {
			rs[i].EvidenceID = h.EvidenceID
		}
	}
	if h.Schema == "" && len(rs) == 0 {
		return nil, nil
	}
	return []extractHeader{h}, rs
}

// extractReviewKey is the per-record key used in extract_review.json. It is
// namespaced by evidence_id so the same target label (e.g. "MFT") on two
// different disk images doesn't collide on one review state. Legacy records
// with no evidence_id keep the bare target, preserving existing review state.
func extractReviewKey(evidenceID, target string) string {
	if evidenceID == "" {
		return target
	}
	return evidenceID + "::" + target
}

// GET /api/cases/:id/extracts
func (s *Server) handleGetExtracts(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	headers, recs := s.readExtractLogs(caseID)

	mu := extractReviewLock(caseID)
	mu.Lock()
	doc := s.loadExtractReview(caseID)
	mu.Unlock()

	// Stamp each record with current review state — default pending. The
	// review_key is namespaced by evidence_id so the UI approves/rejects the
	// right per-evidence record (and same-named targets across images don't
	// share state).
	type augmented struct {
		extractRecord
		ReviewKey  string    `json:"review_key"`
		State      string    `json:"state"`
		Reason     string    `json:"reason,omitempty"`
		ReviewedBy string    `json:"reviewed_by,omitempty"`
		ReviewedAt time.Time `json:"reviewed_at,omitempty"`
	}
	out := make([]augmented, 0, len(recs))
	counts := map[string]int{"approved": 0, "rejected": 0, "pending": 0}
	for _, rec := range recs {
		key := extractReviewKey(rec.EvidenceID, rec.Target)
		rv, ok := doc.Reviews[key]
		if !ok {
			// Fall back to the legacy bare-target key so reviews recorded
			// before evidence namespacing still show through.
			rv, ok = doc.Reviews[rec.Target]
		}
		if !ok || rv.State == "" {
			rv.State = "pending"
		}
		counts[rv.State]++
		out = append(out, augmented{
			extractRecord: rec,
			ReviewKey:     key,
			State:         rv.State,
			Reason:        rv.Reason,
			ReviewedBy:    rv.ReviewedBy,
			ReviewedAt:    rv.ReviewedAt,
		})
	}
	resp := map[string]any{
		"case_id": caseID,
		"headers": headers,
		"records": out,
		"counts":  counts,
		"total":   len(out),
	}
	// Backward-compatible single header for older UI builds.
	if len(headers) > 0 {
		resp["header"] = headers[0]
	} else {
		resp["header"] = extractHeader{}
	}
	writeJSON(w, 200, resp)
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
