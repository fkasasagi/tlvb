package web

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/agents"
	"github.com/tlvb/tlvb/internal/casedb"
	"github.com/tlvb/tlvb/internal/common"
	"github.com/tlvb/tlvb/internal/llm"
	"github.com/tlvb/tlvb/internal/rulesdb"
	"github.com/tlvb/tlvb/internal/tier1a"
	"github.com/tlvb/tlvb/internal/tier1b"
	"github.com/tlvb/tlvb/internal/tier2"
	"github.com/tlvb/tlvb/internal/tier3"
)

// formatInt renders an int with thousands separators (e.g. 2_847_193 →
// "2,847,193") so progress text "ingesting 2,847,193 rows" is readable
// at a glance. Used by handleParseProgressEvent (Wave 43).
func formatInt(n int) string {
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
		if len(s) > pre {
			b.WriteByte(',')
		}
	}
	for i := pre; i < len(s); i += 3 {
		b.WriteString(s[i : i+3])
		if i+3 < len(s) {
			b.WriteByte(',')
		}
	}
	return b.String()
}

// slidingWindowDefault returns whether Tactic Agent runs should use the
// chunked sliding-window execution. Wave 42 flipped this to default on so
// large cases don't silently truncate to the oldest MaxEvents rows
// (B1 indictment). Operators can opt out with TLVB_SLIDING_WINDOW=0
// (or false / off). TLVB_SLIDING_WINDOW=1 was the old opt-in toggle
// — kept as a synonym so existing operators' env vars stay valid.
func slidingWindowDefault() bool {
	v := strings.ToLower(os.Getenv("TLVB_SLIDING_WINDOW"))
	if v == "0" || v == "false" || v == "off" || v == "no" {
		return false
	}
	return true
}

// ----------------------------------------------------------------------------
// Cases
// ----------------------------------------------------------------------------

// caseSummary is the row a UI list shows. It augments CaseRow with a
// pipeline-step status block computed from disk artifacts (parse_results,
// findings dir, synthesis.json, reports dir) so the UI can render badges
// without a chain of follow-up requests.
type caseSummary struct {
	casedb.CaseRow
	EvidenceCount   int   `json:"evidence_count"`
	UnifiedRowCount int64 `json:"unified_event_rows"`
	HasFindings     bool  `json:"has_findings"`
	HasSynthesis    bool  `json:"has_synthesis"`
	HasReport       bool  `json:"has_report"`
	FindingsCount   int   `json:"findings_count"`
}

func (s *Server) handleListCases(w http.ResponseWriter, r *http.Request) {
	// Fresh install: no DB yet means no cases (a read-only open would error).
	if _, statErr := os.Stat(s.cfg.DBPath); os.IsNotExist(statErr) {
		writeJSON(w, 200, []caseSummary{})
		return
	}
	var rows []casedb.CaseRow
	var eventCounts map[string]int64
	var evidenceCounts map[string]int
	// One read-only open, three set-based queries against small tables (cases,
	// parse_results, evidence) — none of which scan the multi-GB unified_events
	// fact table. The old code re-opened the DB and COUNT-scanned unified_events
	// once *per case*, which both pegged serve under polling and tripped a
	// go-duckdb hang on large DBs, leaving /api/cases (and thus the Dashboard)
	// stuck for minutes. Read-only so the Dashboard stays reachable (busy, not
	// hung) while a Parse holds the DB — listing is the user's escape hatch.
	err := s.withDB(casedb.ReadOnly, func(m *casedb.Manager) error {
		var ierr error
		if rows, ierr = m.ListCases(r.Context()); ierr != nil {
			return ierr
		}
		// Counts are best-effort enrichment: a failure here must not blank the
		// whole Dashboard, so fall back to empty maps rather than erroring.
		if eventCounts, ierr = m.EventCountsByCase(r.Context()); ierr != nil {
			eventCounts = map[string]int64{}
		}
		if evidenceCounts, ierr = m.CountEvidenceByCase(r.Context()); ierr != nil {
			evidenceCounts = map[string]int{}
		}
		return nil
	})
	if err != nil {
		if writeIfDBBusy(w, err) {
			return
		}
		writeError(w, 500, "list cases: %v", err)
		return
	}
	out := make([]caseSummary, 0, len(rows))
	for _, c := range rows {
		summary := caseSummary{CaseRow: c}
		summary.EvidenceCount = evidenceCounts[c.CaseID]
		summary.UnifiedRowCount = eventCounts[c.CaseID]
		summary.populateArtifactStatus(s.cfg.OutputsRoot)
		out = append(out, summary)
	}
	writeJSON(w, 200, out)
}

// errCaseExists signals that a create targeted a case_id that is still present.
// RegisterCase is an UPSERT, so without this guard a plain create would silently
// reuse the old row and inherit its evidence / events / parse_results (the
// "deleted case carries over" bug). The carry-over is keyed purely on case_id —
// a shared human name is irrelevant.
var errCaseExists = errors.New("case already exists")

func (s *Server) handleCreateCase(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CaseID     string `json:"case_id"`
		Name       string `json:"name"`
		Examiner   string `json:"examiner"`
		Timezone   string `json:"timezone"`
		Language   string `json:"language"`
		Background string `json:"background"`
		Overwrite  bool   `json:"overwrite"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, 400, "bad json: %v", err)
		return
	}
	if req.CaseID == "" || req.Name == "" {
		writeError(w, 400, "case_id and name are required")
		return
	}
	if req.Examiner == "" {
		req.Examiner = "examiner-web"
	}
	if req.Timezone == "" {
		req.Timezone = "UTC"
	}

	// Overwrite wipes the existing case's data — refuse while its pipeline is
	// mid-flight, same guard as delete.
	if req.Overwrite {
		for _, k := range []JobKind{JobParse, JobAnalyze, JobSynthesize, JobReport} {
			if s.jobs.IsRunning(req.CaseID, k) {
				writeError(w, 409, "case %q has a running %s job; wait for it to finish", req.CaseID, k)
				return
			}
		}
	}

	row := casedb.CaseRow{
		CaseID:     req.CaseID,
		Name:       req.Name,
		Examiner:   req.Examiner,
		Timezone:   req.Timezone,
		Background: req.Background,
		CreatedAt:  time.Now().UTC(),
	}
	overwrote := false
	err := s.withDB(casedb.ReadWrite, func(m *casedb.Manager) error {
		if existing, gerr := m.GetCaseStatus(r.Context(), req.CaseID); gerr == nil {
			if !req.Overwrite {
				return fmt.Errorf("%w: %q has %d evidence / %d events — delete it first, or recreate with overwrite=true",
					errCaseExists, req.CaseID, existing.EvidenceCount, existing.UnifiedRowCount)
			}
			// overwrite=true: clear the old case (DB rows) before recreating so
			// the new case starts clean instead of inheriting old rows. Mirrors
			// the case-import overwrite flow.
			if derr := deleteCase(r.Context(), m, req.CaseID); derr != nil {
				return fmt.Errorf("overwrite: clear existing case: %w", derr)
			}
			if cerr := m.Checkpoint(r.Context()); cerr != nil {
				s.logger.Warn("checkpoint after overwrite-delete failed", "case", req.CaseID, "err", cerr)
			}
			overwrote = true
		}
		return m.RegisterCase(r.Context(), row)
	})
	if err != nil {
		if errors.Is(err, errCaseExists) {
			writeError(w, 409, "%v", err)
			return
		}
		writeError(w, 500, "register case: %v", err)
		return
	}
	// On overwrite, also drop the stale workspace dir (findings / synthesis /
	// reports) so on-disk artifacts from the old case don't resurface.
	if overwrote {
		if rerr := os.RemoveAll(filepath.Join(s.cfg.OutputsRoot, req.CaseID)); rerr != nil {
			s.logger.Warn("overwrite: delete case workspace failed", "case", req.CaseID, "err", rerr)
		}
	}
	writeJSON(w, 201, row)
}

func (s *Server) handleGetCase(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var st *casedb.CaseStatus
	// Read-only: GetCaseStatus only SELECTs, and a read lock lets case-detail
	// polling keep working while a read-only Analyze/Synthesize job runs (a
	// ReadWrite open here would take the exclusive lock and re-block readers).
	err := s.withDB(casedb.ReadOnly, func(m *casedb.Manager) error {
		var ierr error
		st, ierr = m.GetCaseStatus(r.Context(), id)
		return ierr
	})
	if err != nil {
		if writeIfDBBusy(w, err) {
			return
		}
		writeError(w, 404, "%v", err)
		return
	}
	summary := caseSummary{
		CaseRow:         st.Case,
		EvidenceCount:   st.EvidenceCount,
		UnifiedRowCount: st.UnifiedRowCount,
	}
	summary.populateArtifactStatus(s.cfg.OutputsRoot)

	// Include parse results + evidence list + per-job statuses.
	var evidence []casedb.EvidenceRow
	_ = s.withDB(casedb.ReadOnly, func(m *casedb.Manager) error {
		evidence, _ = m.ListEvidence(r.Context(), id)
		return nil
	})
	writeJSON(w, 200, map[string]any{
		"case":          summary,
		"evidence":      evidence,
		"parse_results": st.ParseResults,
		"jobs": map[string]JobStatus{
			"parse":      s.jobStatusOrDerived(r.Context(), id, JobParse),
			"analyze":    s.jobStatusOrDerived(r.Context(), id, JobAnalyze),
			"synthesize": s.jobStatusOrDerived(r.Context(), id, JobSynthesize),
			"report":     s.jobStatusOrDerived(r.Context(), id, JobReport),
		},
	})
}

// handleUpdateCaseBackground replaces a case's examiner background (the
// "Context" editor in the Web UI). Background often emerges mid-investigation,
// so it is editable after creation; the next Tier 1B/2/3 run picks up the new
// text from the DB. Empty body clears it.
func (s *Server) handleUpdateCaseBackground(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Background string `json:"background"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, 400, "bad json: %v", err)
		return
	}
	err := s.withDB(casedb.ReadWrite, func(m *casedb.Manager) error {
		return m.UpdateCaseBackground(r.Context(), id, req.Background)
	})
	if err != nil {
		if writeIfDBBusy(w, err) {
			return
		}
		writeError(w, 404, "%v", err)
		return
	}
	writeJSON(w, 200, map[string]string{"case_id": id, "background": req.Background})
}

func (s *Server) handleDeleteCase(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// Don't delete a case whose pipeline is mid-flight.
	for _, k := range []JobKind{JobParse, JobAnalyze, JobSynthesize, JobReport} {
		if s.jobs.IsRunning(id, k) {
			writeError(w, 409, "case %q has a running %s job; wait for it to finish", id, k)
			return
		}
	}
	err := s.withDB(casedb.ReadWrite, func(m *casedb.Manager) error {
		if derr := deleteCase(r.Context(), m, id); derr != nil {
			return derr
		}
		// Flush the delete out of the WAL immediately. Dropping a large case
		// writes MBs to the WAL; if it lingers, go-duckdb stalls replaying it on
		// later read-only opens, making /api/cases and case detail hang. We hold
		// the exclusive write lock here, so this is the natural place to checkpoint.
		// Best-effort: the rows are already gone, so a checkpoint failure must not
		// fail the delete (the WAL is flushed later at threshold / clean shutdown).
		if cerr := m.Checkpoint(r.Context()); cerr != nil {
			s.logger.Warn("checkpoint after delete failed", "case", id, "err", cerr)
		}
		return nil
	})
	if err != nil {
		writeError(w, 500, "delete case: %v", err)
		return
	}
	// Delete the case workspace directory too (findings, synthesis, reports).
	if err := os.RemoveAll(filepath.Join(s.cfg.OutputsRoot, id)); err != nil {
		s.logger.Warn("delete case workspace failed", "case", id, "err", err)
	}
	writeJSON(w, 200, map[string]string{"status": "deleted", "case_id": id})
}

// handleSetEvidenceTimezone sets (or clears) the per-evidence display timezone.
// Body: {"timezone": "Asia/Tokyo"}. An empty string clears the override so the
// evidence inherits the case timezone. The value must be a loadable IANA zone
// (or "UTC"). Stored events are never rewritten — this only drives display-time
// conversion (Web UI + Tier 3 reports) and the source zone used to canonicalise
// naive-local artifacts (IIS native / web error logs) on the *next* parse.
func (s *Server) handleSetEvidenceTimezone(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	evID := r.PathValue("evid")
	var req struct {
		Timezone string `json:"timezone"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, 400, "bad json: %v", err)
		return
	}
	tz := strings.TrimSpace(req.Timezone)
	if tz != "" {
		if _, err := time.LoadLocation(tz); err != nil {
			writeError(w, 400, "invalid timezone %q: %v", tz, err)
			return
		}
	}
	err := s.withDB(casedb.ReadWrite, func(m *casedb.Manager) error {
		return m.UpdateEvidenceTimezone(r.Context(), caseID, evID, tz)
	})
	if err != nil {
		writeError(w, 500, "set evidence timezone: %v", err)
		return
	}
	writeJSON(w, 200, map[string]string{
		"case_id": caseID, "evidence_id": evID, "timezone": tz})
}

func (sm *caseSummary) populateArtifactStatus(outputsRoot string) {
	dir := filepath.Join(outputsRoot, sm.CaseID)
	// Findings live under findings/by-rule/<source>/*.json and
	// findings/by-skill/*.json — count recursively (a top-level-only count
	// always returned 0 once findings moved into those subdirectories).
	sm.FindingsCount = countFindingsJSON(filepath.Join(dir, "findings"))
	sm.HasFindings = sm.FindingsCount > 0
	if fileExists(filepath.Join(dir, "synthesis.json")) {
		sm.HasSynthesis = true
	}
	if fileExists(filepath.Join(dir, "reports", "report.html")) {
		sm.HasReport = true
	}
}

// ----------------------------------------------------------------------------
// Parse
// ----------------------------------------------------------------------------

// parseEvidenceItem is one row in the multi-evidence Parse request.
// evidence_id is optional — if empty, a timestamped one is auto-generated.
type parseEvidenceItem struct {
	EvidencePath string `json:"evidence_path"`
	EvidenceID   string `json:"evidence_id,omitempty"`
}

func (s *Server) handleStartParse(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		// New (★v0.3 #1): list of evidences to parse sequentially.
		Evidences []parseEvidenceItem `json:"evidences,omitempty"`
		// Back-compat single-evidence form (still accepted; folded into Evidences).
		EvidencePath string `json:"evidence_path,omitempty"`
		EvidenceID   string `json:"evidence_id,omitempty"`
		// Issue #23: input shape hint. One of:
		//   "" / "auto"   — let the orchestrator decide (default)
		//   "image"       — disk image; image_format below pins or auto-picks
		//   "cdir"        — category-folder layout
		//   "washizukami" — Washizukami-Collector preserved-tree layout
		InputMode string `json:"input_mode,omitempty"`
		// ImageFormat is consulted only when InputMode="image":
		//   "" / "auto" — magic-byte detection by image_extractor
		//   "ewf" | "raw" | "vmdk" | "vhd" | "vhdx"
		ImageFormat string `json:"image_format,omitempty"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, 400, "bad json: %v", err)
		return
	}
	// Validate input-type hints before kicking off the long-running job —
	// catches "image" mode being declared against a directory upload.
	mode := strings.ToLower(strings.TrimSpace(req.InputMode))
	switch mode {
	case "", "auto", "image", "cdir", "washizukami":
		// ok
	default:
		writeError(w, 400, "input_mode must be one of: auto|image|cdir|washizukami (got %q)", req.InputMode)
		return
	}
	imgFmt := strings.ToLower(strings.TrimSpace(req.ImageFormat))
	switch imgFmt {
	case "", "auto", "ewf", "raw", "vmdk", "vhd", "vhdx":
		// ok
	default:
		writeError(w, 400, "image_format must be one of: auto|ewf|raw|vmdk|vhd|vhdx (got %q)", req.ImageFormat)
		return
	}
	// Fold legacy single-evidence body into the list shape.
	if req.EvidencePath != "" {
		req.Evidences = append(req.Evidences,
			parseEvidenceItem{EvidencePath: req.EvidencePath, EvidenceID: req.EvidenceID})
	}
	if len(req.Evidences) == 0 {
		writeError(w, 400, "evidences[] (or evidence_path) is required")
		return
	}
	// Auto-generate evidence_id where blank; reject obviously bad rows.
	now := time.Now().UTC()
	for i := range req.Evidences {
		req.Evidences[i].EvidencePath = strings.TrimSpace(req.Evidences[i].EvidencePath)
		if req.Evidences[i].EvidencePath == "" {
			writeError(w, 400, "evidences[%d].evidence_path is empty", i)
			return
		}
		if strings.TrimSpace(req.Evidences[i].EvidenceID) == "" {
			// Distinct timestamp per row by adding the index suffix — a tight
			// loop in the same second otherwise produces duplicates.
			req.Evidences[i].EvidenceID = fmt.Sprintf("EV-%s-%d",
				now.Format("20060102-150405"), i+1)
		}
	}

	dbPath := s.cfg.DBPath
	caseID := id
	dbMu := &s.dbMu
	evidences := req.Evidences

	// Subkind = first evidence_id (or "<n> evidences" if multi) — shows
	// up in JobStatus so the UI can identify the run.
	subkind := evidences[0].EvidenceID
	if len(evidences) > 1 {
		subkind = fmt.Sprintf("%d evidences", len(evidences))
	}

	st := s.jobs.StartWithReporter(id, JobParse, subkind, func(ctx context.Context, rep *Reporter) (string, error) {
		// Hold the global db mutex for the whole job — Python orchestrator
		// opens the DB RW per-evidence, so any other handler that writes
		// would race the orchestrator's write lock.
		dbMu.Lock()
		defer dbMu.Unlock()

		// Per-evidence sequential loop. Graceful degradation: a failure in
		// one evidence is recorded but doesn't abort the rest — same model
		// as Analyze All. Tier 1 (Analyze) only proceeds for evidences
		// that succeeded here.
		ok, failed := []string{}, []string{}
		var partial []string // per-evidence "some artifacts failed but data was ingested" notes
		var firstErr error
		total := len(evidences)
		for i, ev := range evidences {
			rep.SetAll(
				fmt.Sprintf("evidence %d/%d: %s", i+1, total, ev.EvidenceID),
				i, total, 0,
			)
			artSucceeded, artFailed, err := s.parseOneEvidence(ctx, rep, caseID, ev.EvidenceID, ev.EvidencePath, dbPath, i+1, total, mode, imgFmt)
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s: %v", ev.EvidenceID, err))
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			ok = append(ok, ev.EvidenceID)
			// Graceful degradation: the orchestrator exited non-zero because
			// some artifacts failed, but events were still ingested. Don't
			// flag the whole job red — note it as a partial result.
			if artFailed > 0 {
				partial = append(partial, fmt.Sprintf("%s: %d/%d artifacts failed",
					ev.EvidenceID, artFailed, artSucceeded+artFailed))
			}
		}
		rep.SetAll(
			fmt.Sprintf("done %d/%d evidences (%d ok, %d failed)", total, total, len(ok), len(failed)),
			total, total, 0,
		)
		msg := fmt.Sprintf("parsed %d/%d evidences (ok=%d failed=%d)",
			total, total, len(ok), len(failed))
		if len(failed) > 0 {
			return msg, fmt.Errorf("some evidences failed: %s", strings.Join(failed, "; "))
		}
		// No hard failures, but some artifacts within otherwise-successful
		// evidences failed to parse → partial (warning, not FAIL).
		if len(partial) > 0 {
			return msg, &partialError{msg: "一部のアーティファクトのパースでエラー — " + strings.Join(partial, "; ")}
		}
		return msg, nil
	})
	writeJSON(w, 202, st)
}

// parseOneEvidence runs the orchestrator subprocess for a single evidence
// and tails its PROGRESS|<json> stderr stream into the Reporter so the UI
// shows per-artifact progress within the current evidence.
//
// Returns (artifactSucceeded, artifactFailed, err). A nil err means the
// evidence is usable: either the orchestrator exited 0, OR it exited
// non-zero but at least one artifact parsed and its events were ingested
// (partial success — artifactFailed > 0). A non-nil err is a hard failure
// (couldn't run, nothing parsed, structural error) and aborts this evidence.
// The caller (handleStartParse) uses the counts to classify the job as
// succeeded / partial / failed.
func (s *Server) parseOneEvidence(
	ctx context.Context, rep *Reporter,
	caseID, evID, evPath, dbPath string,
	evIdx, evTotal int,
	inputMode, imageFormat string,
) (artifactSucceeded, artifactFailed int, retErr error) {
	rep.Text(fmt.Sprintf("evidence %d/%d (%s): registering", evIdx, evTotal, evID))
	abs, err := filepath.Abs(evPath)
	if err != nil {
		return 0, 0, fmt.Errorf("resolve path: %w", err)
	}
	stInfo, err := os.Stat(abs)
	if err != nil {
		return 0, 0, fmt.Errorf("evidence path: %w", err)
	}
	// Issue #23: validate the declared input mode matches the file shape
	// the operator pointed us at. Auto-detect mode skips this check.
	if inputMode == "image" && stInfo.IsDir() {
		return 0, 0, fmt.Errorf("input_mode=image requires a file, got directory: %s", abs)
	}
	if (inputMode == "cdir" || inputMode == "washizukami") && !stInfo.IsDir() {
		// .zip is permitted because stage_input unpacks it transparently.
		if !strings.HasSuffix(strings.ToLower(abs), ".zip") {
			return 0, 0, fmt.Errorf("input_mode=%s requires a directory or .zip, got file: %s", inputMode, abs)
		}
	}
	mgr, err := casedb.Open(dbPath, casedb.ReadWrite)
	if err != nil {
		return 0, 0, err
	}
	// Wave 16: surface RegisterEvidence errors instead of dropping them.
	// Previously the error was swallowed with `_ = ...`, which masked PK
	// conflicts (same evidence_id reused across cases) and made Analyze
	// fail later with "case <X> has no registered evidence" — a confusing
	// downstream symptom rather than the real cause. Now any DB error
	// (PK conflict, IO, lock contention) aborts the parse cleanly with
	// the underlying message in the job report.
	if err := mgr.RegisterEvidence(ctx, casedb.EvidenceRow{
		EvidenceID:   evID,
		CaseID:       caseID,
		Path:         abs,
		SHA256:       "(parse-pending)",
		SizeBytes:    0,
		EvidenceType: "auto",
		RegisteredAt: time.Now().UTC(),
	}); err != nil {
		_ = mgr.Close()
		return 0, 0, fmt.Errorf("register evidence %s under case %s: %w", evID, caseID, err)
	}
	_ = mgr.Close()

	rep.Text(fmt.Sprintf("evidence %d/%d (%s): running orchestrator", evIdx, evTotal, evID))
	ws := filepath.Join("outputs", "cases", caseID)
	_ = os.MkdirAll(ws, 0o755)
	// Issue #19: propagate the timezone to the orchestrator so the underlying
	// tools (e.g. `psort.py -z`) render their output in the examiner's local
	// time and naive-local artifacts (IIS native / web error logs) get
	// canonicalised to UTC against the right source zone. The per-evidence
	// timezone overrides the case timezone when set (empty → inherit case).
	effectiveTZ := "UTC"
	if mgr2, mgrErr := casedb.Open(dbPath, casedb.ReadOnly); mgrErr == nil {
		if cs, gerr := mgr2.GetCaseStatus(ctx, caseID); gerr == nil && cs.Case.Timezone != "" {
			effectiveTZ = cs.Case.Timezone
		}
		if evs, lerr := mgr2.ListEvidence(ctx, caseID); lerr == nil {
			for _, e := range evs {
				if e.EvidenceID == evID && e.Timezone != "" {
					effectiveTZ = e.Timezone
					break
				}
			}
		}
		_ = mgr2.Close()
	}
	// Capture the orchestrator's JSON report (artifact_succeeded /
	// artifact_failed) so we can tell a partial parse (some artifacts failed
	// but events were ingested) from a total failure. Without it we'd only
	// see the exit code (0 vs 2) and have to call any failure a hard FAIL.
	reportFile, rfErr := os.CreateTemp("", "tlvb-parse-report-*.json")
	reportPath := "/dev/null"
	if rfErr == nil {
		reportPath = reportFile.Name()
		_ = reportFile.Close()
		defer os.Remove(reportPath)
	}
	argv := []string{
		"-m", "parsers.orchestrator",
		"--case-id", caseID, "--evidence-id", evID,
		"--input", abs, "--db", dbPath, "--workspace", ws,
		"--timezone", effectiveTZ,
		"--report-json", reportPath,
		"--progress",
	}
	// Issue #23: when the operator explicitly declares the input shape,
	// forward it as a CLI flag so the orchestrator can record it in the
	// audit trail (and the future image_extractor accepts a forced format).
	if inputMode != "" && inputMode != "auto" {
		argv = append(argv, "--input-mode", inputMode)
	}
	if imageFormat != "" && imageFormat != "auto" {
		argv = append(argv, "--image-format", imageFormat)
	}
	cmd := exec.CommandContext(ctx, common.ResolvePython(), argv...)
	var sb strings.Builder
	cmd.Stdout = &sb
	stderrPipe, perr := cmd.StderrPipe()
	if perr != nil {
		return 0, 0, fmt.Errorf("stderr pipe: %w", perr)
	}
	if err := cmd.Start(); err != nil {
		return 0, 0, fmt.Errorf("start orchestrator: %w", err)
	}
	parseStart := time.Now()
	var parserDurations time.Duration
	doneCount := 0
	var totalCount int
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		scanner := bufio.NewScanner(stderrPipe)
		scanner.Buffer(make([]byte, 1<<20), 4<<20)
		for scanner.Scan() {
			line := scanner.Text()
			const tag = "PROGRESS|"
			if strings.HasPrefix(line, tag) {
				var ev map[string]any
				if err := json.Unmarshal([]byte(line[len(tag):]), &ev); err == nil {
					handleParseProgressEvent(rep, ev, &totalCount, &doneCount,
						&parserDurations, parseStart)
				}
				continue
			}
			sb.WriteString(line)
			sb.WriteString("\n")
		}
	}()
	<-readDone
	waitErr := cmd.Wait()

	// Best-effort read of the orchestrator's report (post-merge artifact
	// counts). Available regardless of exit code.
	succeeded, failed, haveReport := readParseReport(reportPath)

	if waitErr != nil {
		tail := sb.String()
		if len(tail) > 2000 {
			tail = "...[truncated]\n" + tail[len(tail)-2000:]
		}
		// Graceful degradation: the orchestrator exits non-zero whenever any
		// artifact failed (orchestrator.py returns 2 if artifact_failed > 0).
		// If at least one artifact still parsed and we could read the report,
		// treat it as a *partial* success — events were ingested, so the case
		// is usable. The caller turns this into a "partial" job state (warning)
		// rather than a hard FAIL. Only a run that produced nothing usable
		// (no report, or zero successful artifacts) is a hard failure.
		if haveReport && succeeded > 0 {
			return succeeded, failed, nil
		}
		return succeeded, failed, fmt.Errorf("orchestrator: %w\n%s", waitErr, tail)
	}
	return succeeded, failed, nil
}

// readParseReport reads the orchestrator's --report-json output and returns
// the post-merge artifact-level counts. ok=false means the report was
// missing or unparseable (e.g. /dev/null fallback, or the orchestrator
// crashed before writing it).
func readParseReport(path string) (succeeded, failed int, ok bool) {
	if path == "" || path == "/dev/null" {
		return 0, 0, false
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false
	}
	var rep struct {
		ArtifactSucceeded int `json:"artifact_succeeded"`
		ArtifactFailed    int `json:"artifact_failed"`
	}
	if err := json.Unmarshal(body, &rep); err != nil {
		return 0, 0, false
	}
	return rep.ArtifactSucceeded, rep.ArtifactFailed, true
}

func (s *Server) handleParseStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.jobStatusOrDerived(r.Context(), r.PathValue("id"), JobParse))
}

// handleParseProgressEvent translates one PROGRESS|<json> event from the
// Python orchestrator into a Reporter update.
//
// Events the orchestrator emits today (parsers/orchestrator.py):
//
//	{"type":"stage", "phase":"extracting"|"detecting"}
//	{"type":"detect_done", "total":N, "artifact_ids":[...]}
//	{"type":"parse_start", "artifact_id":..., "i":..., "of":N}
//	{"type":"parse_done",  "artifact_id":..., "i":..., "of":N, "ok":bool, "row_count":N, "duration_s":F}
//
// totalCount / doneCount / parserDurations live in the caller's scope so we
// can compute a forward ETA from observed per-parser durations.
func handleParseProgressEvent(
	rep *Reporter, ev map[string]any,
	totalCount, doneCount *int,
	parserDurations *time.Duration, jobStart time.Time,
) {
	t, _ := ev["type"].(string)
	switch t {
	case "stage":
		phase, _ := ev["phase"].(string)
		// Wave 43: surface persist (= DuckDB bulk insert) progress so the
		// Status tab doesn't sit at "done <last-parser> (N/N)" for the
		// several minutes USN journal / MFT ingest takes. We don't have a
		// progress callback inside DuckDB itself, so we just stamp the
		// stage marker — but with row-count context so the examiner can
		// estimate elapsed time.
		switch phase {
		case "persisting":
			rows, _ := ev["rows"].(float64)
			if rows > 0 {
				rep.Text(fmt.Sprintf(
					"ingesting %s rows into DuckDB (this can take several minutes for big cases)",
					formatInt(int(rows))))
			} else {
				rep.Text("ingesting events into DuckDB")
			}
		case "persisted":
			ue, _ := ev["unified_events"].(float64)
			pr, _ := ev["parse_results"].(float64)
			rep.Text(fmt.Sprintf(
				"ingest done: %s events across %d artifacts",
				formatInt(int(ue)), int(pr)))
		default:
			rep.Text("orchestrator: " + phase)
		}
	case "detect_done":
		if v, ok := ev["total"].(float64); ok {
			*totalCount = int(v)
		}
		rep.SetAll(fmt.Sprintf("detected %d artifacts", *totalCount),
			0, *totalCount, 0)
	case "parse_start":
		aid, _ := ev["artifact_id"].(string)
		i, _ := ev["i"].(float64)
		of, _ := ev["of"].(float64)
		rep.SetAll(
			fmt.Sprintf("parsing %s (%d/%d)", aid, int(i), int(of)),
			*doneCount, int(of),
			etaSeconds(*doneCount, int(of), jobStart, *parserDurations, 60),
		)
	case "parse_done":
		dur, _ := ev["duration_s"].(float64)
		*parserDurations += time.Duration(dur * float64(time.Second))
		*doneCount++
		of, _ := ev["of"].(float64)
		aid, _ := ev["artifact_id"].(string)
		rep.SetAll(
			fmt.Sprintf("done %s (%d/%d)", aid, *doneCount, int(of)),
			*doneCount, int(of),
			etaSeconds(*doneCount, int(of), jobStart, *parserDurations, 60),
		)
	}
}

// ----------------------------------------------------------------------------
// Analyze
// ----------------------------------------------------------------------------

var defaultTactics = []string{
	"initial_access", "execution", "persistence", "privilege_escalation",
	"defense_evasion", "credential_access", "discovery", "lateral_movement",
	"collection", "impact",
}

func (s *Server) handleStartAnalyzeAll(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Model string `json:"model"`
		// IncludeAnomaly opts into the Tier 1B anomaly_hunter pass (LLM). Tier
		// 1A (cached signature SQL, no LLM) always runs. Default false keeps
		// the Analyze button LLM-free, mirroring the old "Include anomaly"
		// opt-in.
		IncludeAnomaly bool `json:"include_anomaly"`
	}
	_ = decodeJSON(r, &req)

	caseID := id
	dbPath := s.cfg.DBPath
	rulesDBPath := s.cfg.RulesDBPath
	if rulesDBPath == "" {
		rulesDBPath = filepath.Join("outputs", "rules.duckdb")
	}
	root := s.cfg.OutputsRoot
	dbMu := &s.dbMu
	model := req.Model
	includeAnomaly := req.IncludeAnomaly

	// Review Gate 0 — block Analyze unless parse results have been approved
	// (or skip-all is enabled, or ?force=true is passed). ★v0.3 #2.
	if err := s.gateAllowsAnalyze(r, id); err != nil {
		writeError(w, 409, "%v", err)
		return
	}

	// Tier 1A (signature SQL) + optional Tier 1B (anomaly_hunter) — the same
	// agents `tlvb run` drives. Writes findings/by-rule/** and
	// findings/by-skill/**, which is what the migrated Tier 2 synthesize reads.
	st := s.jobs.StartWithReporter(id, JobAnalyze, "all", func(ctx context.Context, rep *Reporter) (string, error) {
		// Analyze opens the case DB read-only (Tier 1A/1B read unified_events,
		// write findings to disk), so take a read lock — Events / case-detail
		// reads run concurrently. A writer (parse / delete) still blocks.
		dbMu.RLock()
		defer dbMu.RUnlock()

		findingsBase := filepath.Join(root, caseID, "findings")

		// ---- Tier 1A: cached signature SQL (runtime LLM-zero) ----
		rep.Text("Tier 1A: running cached signature SQL")
		cdb, err := casedb.Open(dbPath, casedb.ReadOnly)
		if err != nil {
			return "", fmt.Errorf("open case db: %w", err)
		}
		rdb, err := rulesdb.Open(rulesDBPath, rulesdb.ReadOnly)
		if err != nil {
			cdb.Close()
			return "", fmt.Errorf("open rules db: %w", err)
		}
		a1cfg := tier1a.Config{
			CaseID:      caseID,
			RulesDB:     rdb,
			CaseDB:      cdb,
			FindingsDir: filepath.Join(findingsBase, "by-rule"),
			MaxEvidence: 100,
		}
		rep1a, runErr := tier1a.Run(ctx, a1cfg)
		if runErr != nil {
			cdb.Close()
			rdb.Close()
			return "", fmt.Errorf("tier 1a: %w", runErr)
		}
		// Hayabusa pass-through (Tier 0 pre-detected events → findings).
		hb := 0
		if passRep, perr := tier1a.RunHayabusaPassthrough(ctx, a1cfg,
			tier1a.HayabusaPassthroughOptions{}); perr == nil {
			hb = passRep.Matched
		}
		cdb.Close()
		rdb.Close()
		rep.Text(fmt.Sprintf("Tier 1A: %d rule matches + %d Hayabusa", rep1a.Matched, hb))

		// ---- Tier 1B: skills-driven anomaly (LLM, opt-in) ----
		anomaly := 0
		if includeAnomaly {
			rep.Text("Tier 1B: anomaly_hunter (LLM)")
			modelID := model
			if modelID == "" {
				modelID = "claude-code-default"
			}
			rep1b, berr := tier1b.Run(ctx, tier1b.Config{
				CaseID:          caseID,
				Skill:           "anomaly_hunter",
				SkillsDir:       "skills",
				FindingsBaseDir: findingsBase,
				DBPath:          dbPath,
				MaxEvents:       200,
				Model:           model,
				Timeout:         8 * time.Minute,
				RulesDBPath:     rulesDBPath,
				SchemaVersion:   casedb.SchemaVersion(),
				ModelID:         modelID,
			})
			if berr != nil {
				// Tier 1A findings are already written; surface the 1B failure
				// without discarding the successful 1A run (graceful degrade).
				return fmt.Sprintf("Tier 1A: %d rules + %d Hayabusa; Tier 1B failed",
					rep1a.Matched, hb), fmt.Errorf("tier 1b: %w", berr)
			}
			anomaly = len(rep1b.NewFindings)
		}
		return fmt.Sprintf("Tier 1A: %d rules + %d Hayabusa; Tier 1B: %d anomaly",
			rep1a.Matched, hb, anomaly), nil
	})
	writeJSON(w, 202, st)
}

// etaSeconds returns a forward-looking estimate based on per-tactic average.
// While zero tactics have completed it falls back to the baseline guess.
func etaSeconds(completed, total int, jobStart time.Time, totalDur time.Duration, baselineSecPerTactic int) int {
	remaining := total - completed
	if remaining <= 0 {
		return 0
	}
	if completed == 0 {
		return baselineSecPerTactic * remaining
	}
	avg := totalDur.Seconds() / float64(completed)
	return int(avg * float64(remaining))
}

func (s *Server) handleStartAnalyzeOne(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tactic := r.PathValue("tactic")
	var req struct {
		Engine string `json:"engine"`
		Model  string `json:"model"`
	}
	_ = decodeJSON(r, &req)
	if req.Engine == "" {
		req.Engine = "auto"
	}

	caseID := id
	dbPath := s.cfg.DBPath
	dbMu := &s.dbMu
	engine := req.Engine
	model := req.Model

	// Review Gate 0 — same gating as Analyze All. ★v0.3 #2.
	if err := s.gateAllowsAnalyze(r, id); err != nil {
		writeError(w, 409, "%v", err)
		return
	}

	st := s.jobs.Start(id, JobAnalyze, tactic, func(ctx context.Context, progress func(string)) (string, error) {
		// Read-only analyze (see Analyze-all): share the lock so reads stay live.
		dbMu.RLock()
		defer dbMu.RUnlock()

		progress(fmt.Sprintf("running tactic %s", tactic))
		evIDs, err := allEvidenceIDs(ctx, dbPath, caseID)
		if err != nil {
			return "", err
		}
		if err := runOneTactic(ctx, caseID, evIDs[0], tactic, engine, model, dbPath, evIDs); err != nil {
			return "", err
		}
		return fmt.Sprintf("tactic %s completed", tactic), nil
	})
	writeJSON(w, 202, st)
}

// handleStartAnalyzeArtifact (Wave 20h) runs only the tactics whose SQL
// prefilter references the given artifact_id, each with its prefilter
// AND'd by artifact_id = <id>. Useful when the examiner wants to focus
// LLM analysis on a single parser's output (e.g. "look at amcache only")
// without paying for tactics that have no rows in this artifact.
//
// POST /api/cases/{id}/analyze/artifact/{artifact_id}
//
//	body: {"engine": "...", "model": "..."} (both optional)
//	202: JobStatus (poll /analyze/status to track)
//	409: Review Gate 0 blocks (parse not approved)
//	404: no tactic references this artifact (empty plan)
func (s *Server) handleStartAnalyzeArtifact(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	artifact := r.PathValue("artifact_id")
	var req struct {
		Engine string `json:"engine"`
		Model  string `json:"model"`
	}
	_ = decodeJSON(r, &req)
	if req.Engine == "" {
		req.Engine = "auto"
	}

	relevant := agents.TacticsForArtifact(artifact)
	if len(relevant) == 0 {
		writeError(w, 404, "no tactic prefilter references artifact_id=%q", artifact)
		return
	}

	caseID := id
	dbPath := s.cfg.DBPath
	dbMu := &s.dbMu
	engine := req.Engine
	model := req.Model

	if err := s.gateAllowsAnalyze(r, id); err != nil {
		writeError(w, 409, "%v", err)
		return
	}

	subkind := "artifact=" + artifact
	st := s.jobs.StartWithReporter(id, JobAnalyze, subkind, func(ctx context.Context, rep *Reporter) (string, error) {
		// Read-only analyze (see Analyze-all): share the lock so reads stay live.
		dbMu.RLock()
		defer dbMu.RUnlock()

		evIDs, err := allEvidenceIDs(ctx, dbPath, caseID)
		if err != nil {
			return "", err
		}
		evID := evIDs[0]

		total := len(relevant)
		const baselineSecPerTactic = 180
		rep.SetAll(
			fmt.Sprintf("artifact=%s scope: %d tactic(s)", artifact, total),
			0, total, baselineSecPerTactic*total,
		)

		var failed []string
		var done []string
		var totalTacticDuration time.Duration
		jobStart := time.Now()
		for i, tac := range relevant {
			tacticStart := time.Now()
			completedSoFar := len(done) + len(failed)
			rep.SetAll(
				fmt.Sprintf("running %s (%d/%d) scope=%s", tac, i+1, total, artifact),
				completedSoFar, total,
				etaSeconds(completedSoFar, total, jobStart, totalTacticDuration, baselineSecPerTactic),
			)
			if err := runOneTacticScoped(ctx, caseID, evID, tac, engine, model, dbPath, evIDs, artifact); err != nil {
				failed = append(failed, fmt.Sprintf("%s: %v", tac, err))
			} else {
				done = append(done, tac)
			}
			totalTacticDuration += time.Since(tacticStart)
			rep.SetAll(
				fmt.Sprintf("done %s (%d/%d) scope=%s", tac, i+1, total, artifact),
				i+1, total,
				etaSeconds(i+1, total, jobStart, totalTacticDuration, baselineSecPerTactic),
			)
		}
		msg := fmt.Sprintf("artifact=%s completed=%d failed=%d", artifact, len(done), len(failed))
		if len(failed) > 0 {
			return msg, fmt.Errorf("some tactics failed for artifact=%s: %s",
				artifact, strings.Join(failed, "; "))
		}
		return msg, nil
	})
	writeJSON(w, 202, st)
}

func (s *Server) handleAnalyzeStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.jobStatusOrDerived(r.Context(), r.PathValue("id"), JobAnalyze))
}

func firstEvidenceID(ctx context.Context, dbPath, caseID string) (string, error) {
	ids, err := allEvidenceIDs(ctx, dbPath, caseID)
	if err != nil {
		return "", err
	}
	return ids[0], nil
}

// allEvidenceIDs returns every evidence_id registered under the case, in
// registration order. Used by Analyze All / Analyze One / Synthesize so a
// multi-evidence case is reasoned about as a whole (★v0.3 #7).
func allEvidenceIDs(ctx context.Context, dbPath, caseID string) ([]string, error) {
	mgr, err := casedb.Open(dbPath, casedb.ReadOnly)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	defer mgr.Close()
	ev, err := mgr.ListEvidence(ctx, caseID)
	if err != nil {
		return nil, err
	}
	if len(ev) == 0 {
		return nil, fmt.Errorf("case %q has no registered evidence; run parse first", caseID)
	}
	out := make([]string, len(ev))
	for i, e := range ev {
		out[i] = e.EvidenceID
	}
	return out, nil
}

func runOneTactic(ctx context.Context, caseID, evID, tactic, engine, model, dbPath string, evIDs []string) error {
	return runOneTacticScoped(ctx, caseID, evID, tactic, engine, model, dbPath, evIDs, "")
}

// runOneTacticScoped (Wave 20h) is the artifact-aware variant. When
// artifactScope is non-empty, the SQL prefilter is AND'd with
// `artifact_id = <scope>` and the resulting report is written to
// `findings/by-artifact/<scope>/<tactic>.json` so it doesn't clobber
// the full-case findings/<tactic>.json. Passing "" reproduces the
// original cross-artifact behaviour.
func runOneTacticScoped(ctx context.Context, caseID, evID, tactic, engine, model, dbPath string, evIDs []string, artifactScope string) error {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if engine == "anthropic-api" && apiKey == "" {
		return fmt.Errorf("ANTHROPIC_API_KEY required for engine=anthropic-api")
	}
	// Wave 19 then Wave 20a: dynamic timeout based on MaxEvents, with
	// env-var override. Replaced the fixed 20m / MaxEvents 200 setup
	// after observing on real SRL-2018 / TANAKA cases that anomaly_hunter
	// SIGKILL'd at the 10-minute fixed cap. The new policy:
	//   - MaxEvents stays at 400 (prefilter cap, prompt size predictable)
	//   - Timeout scales linearly: ~5s/event + 300s buffer, clamped to
	//     [10 min, 60 min]. anomaly_hunter gets a 1.5× multiplier.
	//   - Operator can override every knob via env var (see ComputeTimeout
	//     docstring for the TLVB_LLM_TIMEOUT_* family).
	const maxEvents = 400
	cfg := agents.Config{
		Tactic:        tactic,
		Engine:        engine,
		APIKey:        apiKey,
		Model:         model,
		MaxEvents:     maxEvents,
		MaxIters:      3,
		Timeout:       agents.ComputeTimeout(tactic, maxEvents),
		DBPath:        dbPath,
		EvidenceIDs:   evIDs,                  // ★v0.3 #7 — full case scope stamped on the report
		ArtifactScope: artifactScope,          // Wave 20h
		SlidingWindow: slidingWindowDefault(), // Wave 22 + Wave 42 (default on)
		WindowOverlap: 0.2,                    // Wave 22 default
	}
	// Wave 20h: scoped runs go under findings/by-artifact/<scope>/ so they
	// don't overwrite the cross-artifact findings/<tactic>.json. The
	// synthesizer + review UI continue to read findings/ for the canonical
	// case-wide view; by-artifact/ is opt-in deep-dive material that the
	// examiner triggers explicitly.
	var dir string
	if artifactScope == "" {
		dir = filepath.Join("outputs", "cases", caseID, "findings")
	} else {
		dir = filepath.Join("outputs", "cases", caseID, "findings", "by-artifact", artifactScope)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	var report *agents.TacticReport
	if tactic == "anomaly_hunter" {
		ah, err := agents.NewAnomalyHunter(agents.AnomalyConfig{
			CaseID: caseID, EvidenceID: evID, EvidenceIDs: evIDs, FindingsDir: dir,
			DBPath: dbPath, Engine: engine, APIKey: apiKey, Model: model,
			MaxEvents: maxEvents, MaxIters: 3, Timeout: cfg.Timeout, // Wave 20a
		})
		if err != nil {
			return err
		}
		actx, cancel := context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
		report, err = ah.Run(actx)
		if err != nil && report == nil {
			return err
		}
	} else {
		runner, err := agents.New(cfg)
		if err != nil {
			return err
		}
		actx, cancel := context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
		report, err = runner.Run(actx, caseID, evID)
		if err != nil && report == nil {
			return err
		}
	}
	if report == nil {
		return fmt.Errorf("no report produced")
	}
	body, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, tactic+".json"), body, 0o644)
}

// ----------------------------------------------------------------------------
// Synthesize
// ----------------------------------------------------------------------------

func (s *Server) handleStartSynthesize(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Model        string `json:"model"`
		ActiveSearch bool   `json:"active_search"`
	}
	_ = decodeJSON(r, &req)

	caseID := id
	dbPath := s.cfg.DBPath
	dbMu := &s.dbMu
	root := s.cfg.OutputsRoot
	model := req.Model
	activeSearch := req.ActiveSearch

	st := s.jobs.Start(id, JobSynthesize, fmt.Sprintf("active_search=%v", activeSearch), func(ctx context.Context, progress func(string)) (string, error) {
		// Tier 2 opens the case DB read-only (access_mode=read_only); take a read
		// lock so Events / case-detail reads run concurrently with synthesis.
		dbMu.RLock()
		defer dbMu.RUnlock()

		// Tier 2 (Timeline Analysis Agent) — same pipeline the CLI `tlvb run`
		// drives. Active search adds a hypothesis-driven wide-range SQL pass
		// per cluster, so give it a longer budget.
		timeout := 15 * time.Minute
		if activeSearch {
			timeout = 25 * time.Minute
		}
		sctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		rep, err := tier2.Run(sctx, tier2.Config{
			CaseID:          caseID,
			FindingsBaseDir: filepath.Join(root, caseID, "findings"),
			OutputPath:      filepath.Join(root, caseID, "synthesis.json"),
			DBPath:          dbPath,
			Model:           model,
			ActiveSearch:    activeSearch,
			ProgressFn: func(e tier2.Event) {
				if e.Message != "" {
					progress(e.Message)
				} else if e.Phase != "" {
					progress(e.Phase)
				}
			},
		})
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("findings=%d clusters=%d analyzed=%d cost=$%.4f",
			rep.TotalFindings, rep.ClusterCount, rep.ClustersAnalyzed, rep.TotalCostUSD), nil
	})
	writeJSON(w, 202, st)
}

func (s *Server) handleSynthesizeStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.jobStatusOrDerived(r.Context(), r.PathValue("id"), JobSynthesize))
}

func (s *Server) handleGetSynthesis(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cs, err := s.loadSynthesis(id)
	if err != nil {
		writeError(w, 404, "%v", err)
		return
	}
	writeJSON(w, 200, cs)
}

func (s *Server) loadSynthesis(caseID string) (*tier2.CaseSynthesis, error) {
	path := filepath.Join(s.cfg.OutputsRoot, caseID, "synthesis.json")
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read synthesis: %w", err)
	}
	var cs tier2.CaseSynthesis
	if err := json.Unmarshal(body, &cs); err != nil {
		return nil, fmt.Errorf("parse synthesis: %w", err)
	}
	return &cs, nil
}

// ----------------------------------------------------------------------------
// Report
// ----------------------------------------------------------------------------

func (s *Server) handleStartReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Language     string   `json:"language"`
		Formats      []string `json:"formats"`
		OnlyApproved bool     `json:"only_approved"`
		// Timezone is the display timezone selected in the Web UI; the report
		// renders all timestamps in it. Empty or the per-evidence sentinel
		// ("__evidence__", which can't map to a single document) falls back to
		// the case timezone.
		Timezone string `json:"timezone"`
	}
	_ = decodeJSON(r, &req)
	if req.Language == "" {
		req.Language = "ja"
	}
	if len(req.Formats) == 0 {
		req.Formats = []string{"html", "csv", "json"}
	}

	// Review Gate 2 — block Report unless timeline has been approved (or
	// skip-all is enabled, or ?force=true is passed). Wave 21, DESIGN §6.5.
	// gateAllowsReport is a no-op when synthesis.json doesn't exist yet,
	// so the existing "synthesize first" error path stays untouched.
	if err := s.gateAllowsReport(r, id); err != nil {
		writeError(w, 409, "%v", err)
		return
	}

	caseID := id
	root := s.cfg.OutputsRoot
	lang := req.Language
	formats := req.Formats
	onlyApproved := req.OnlyApproved
	// "__evidence__" is the Web UI's per-evidence sentinel — it can't map to a
	// single report document, so it falls back to the case timezone below.
	reqTZ := req.Timezone
	if reqTZ == "__evidence__" {
		reqTZ = ""
	}

	st := s.jobs.Start(id, JobReport, lang, func(ctx context.Context, progress func(string)) (string, error) {
		progress("rendering report")
		// Forensic case metadata (evidence inventory, chain-of-custody SHA-256,
		// per-artifact event counts) for the report's section 4. Best-effort —
		// nil simply omits that section, matching the CLI `report --tier 3`.
		meta, examiner, caseTZ, caseBG := s.reportCaseMeta(ctx, caseID)
		// Report display timezone: the Web UI selection wins; fall back to the
		// case timezone when none was sent (or the per-evidence sentinel).
		reportTZ := caseTZ
		if reqTZ != "" {
			reportTZ = reqTZ
		}
		// Tier 3 (DFIR Reporter) — same renderer the CLI `tlvb report --tier 3`
		// drives. Reads the tier2 synthesis.json + derives timeline/IOC/MITRE
		// from findings/. Timestamps render in the case timezone (UTC store →
		// display conversion); empty/unloadable falls back to UTC.
		t3Start := time.Now()
		res, err := tier3.Render(tier3.Config{
			CaseID:              caseID,
			SynthesisPath:       filepath.Join(root, caseID, "synthesis.json"),
			OutDir:              filepath.Join(root, caseID, "reports"),
			FindingsDir:         filepath.Join(root, caseID, "findings"),
			Formats:             formats,
			Language:            lang,
			TranslateNarratives: true,
			Timezone:            reportTZ,
			OnlyApproved:        onlyApproved,
			CaseMeta:            meta,
			Examiner:            examiner,
			CaseBackground:      caseBG,
		})
		if err != nil {
			return "", err
		}
		// Log tier3 to the unified execution log so the Audit tab's tier3
		// filter (and the .fcz export) reflects report generation.
		tier3.LogReportAction(filepath.Join(root, caseID, "actions.jsonl"),
			caseID, formats, res.OutDir, len(res.Files), time.Since(t3Start).Seconds())
		return fmt.Sprintf("wrote %d files to %s", len(res.Files), res.OutDir), nil
	})
	writeJSON(w, 202, st)
}

func (s *Server) handleReportStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.jobStatusOrDerived(r.Context(), r.PathValue("id"), JobReport))
}

// reportCaseMeta mirrors the CLI's loadReportCaseMeta (cmd/tlvb/report_tier3.go):
// it pulls case identity, the evidence inventory and per-artifact event counts
// from cases.duckdb so the Tier 3 report's "Evidence & Chain of Custody"
// section renders. Best-effort — a DB error returns (nil, "") and the report
// simply omits that section (the section template is wrapped in {{if .Meta}}).
func (s *Server) reportCaseMeta(ctx context.Context, caseID string) (*tier3.CaseMeta, string, string, string) {
	meta := &tier3.CaseMeta{}
	examiner := ""
	timezone := ""
	background := ""
	err := s.withDB(casedb.ReadOnly, func(m *casedb.Manager) error {
		if cases, err := m.ListCases(ctx); err == nil {
			for _, c := range cases {
				if c.CaseID == caseID {
					meta.DisplayName = c.Name
					meta.Status = c.Status
					meta.CreatedAt = c.CreatedAt
					examiner = c.Examiner
					timezone = c.Timezone
					background = c.Background
					break
				}
			}
		}
		if evs, err := m.ListEvidence(ctx, caseID); err == nil {
			for _, e := range evs {
				meta.Evidence = append(meta.Evidence, tier3.EvidenceItem{
					EvidenceID:   e.EvidenceID,
					SourcePath:   filepath.Base(e.Path),
					SHA256:       e.SHA256,
					SizeBytes:    e.SizeBytes,
					RegisteredAt: e.RegisteredAt,
					SourceHost:   e.SourceHost,
					EvidenceType: e.EvidenceType,
				})
			}
		}
		// Per-artifact event counts (Tier 0 coverage) — best-effort raw query.
		rows, qerr := m.DB().QueryContext(ctx,
			`SELECT artifact_id, COUNT(*) AS n
			 FROM unified_events WHERE case_id = ?
			 GROUP BY artifact_id ORDER BY n DESC`, caseID)
		if qerr == nil {
			defer rows.Close()
			for rows.Next() {
				var a string
				var n int
				if rows.Scan(&a, &n) == nil {
					meta.ArtifactCounts = append(meta.ArtifactCounts,
						tier3.ArtifactCount{ArtifactID: a, EventCount: n})
					meta.TotalEvents += n
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, "", "", ""
	}
	if meta.DisplayName == "" && len(meta.Evidence) == 0 && len(meta.ArtifactCounts) == 0 {
		return nil, examiner, timezone, background
	}
	return meta, examiner, timezone, background
}

func (s *Server) handleGetReportHTML(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.cfg.OutputsRoot, r.PathValue("id"), "reports", "report.html")
	body, err := os.ReadFile(path)
	if err != nil {
		writeError(w, 404, "no report.html: %v", err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(body)
}

func (s *Server) handleGetReportCSV(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !isSafeName(name) {
		writeError(w, 400, "bad name")
		return
	}
	path := filepath.Join(s.cfg.OutputsRoot, r.PathValue("id"), "reports", name+".csv")
	body, err := os.ReadFile(path)
	if err != nil {
		writeError(w, 404, "no %s.csv: %v", name, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, name))
	_, _ = w.Write(body)
}

func (s *Server) handleGetReportJSON(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.cfg.OutputsRoot, r.PathValue("id"), "reports", "report.json")
	body, err := os.ReadFile(path)
	if err != nil {
		writeError(w, 404, "no report.json: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(body)
}

func isSafeName(s string) bool {
	if s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\\") {
		return false
	}
	return true
}

// Findings handlers are implemented in review_gate_1a.go (Review Gate 1A,
// unified Tier 1A by-rule + Tier 1B by-skill view).

// ----------------------------------------------------------------------------
// Timeline / IOC / MITRE / Events / Audit
// ----------------------------------------------------------------------------

// findingsDir is the per-case findings/ directory (Tier 1A by-rule + Tier 1B
// by-skill). The Timeline / IOC / MITRE tabs are derived from it because the
// current tier2 synthesis.json no longer carries that material (it drops the
// raw timeline, never stored IOCs, and its mitre_mapping is often empty).
func (s *Server) findingsDir(caseID string) string {
	return filepath.Join(s.cfg.OutputsRoot, caseID, "findings")
}

func (s *Server) handleGetTimeline(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// BuildTimelineView joins the findings-derived flat timeline to the Tier 2
	// synthesis (clusters / clock reliability / logical-order intrusion path) so
	// the Timeline tab renders the SAME phase grouping + clock warning the report
	// uses. Degrades to a flat timeline when no synthesis.json exists yet.
	synthPath := filepath.Join(s.cfg.OutputsRoot, id, "synthesis.json")
	view := tier3.BuildTimelineView(s.findingsDir(id), synthPath)
	writeJSON(w, 200, view)
}

func (s *Server) handleGetIOCs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	en := tier3.LoadWebEnrichment(s.findingsDir(id))
	writeJSON(w, 200, en.IOCs)
}

func (s *Server) handleGetMITRE(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	en := tier3.LoadWebEnrichment(s.findingsDir(id))
	writeJSON(w, 200, en.MITRE)
}

func (s *Server) handleQueryEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	q := casedb.UnifiedEventQuery{
		CaseID:     id,
		ArtifactID: r.URL.Query().Get("artifact_id"),
		EvidenceID: r.URL.Query().Get("evidence_id"),
		AuditID:    r.URL.Query().Get("audit_id"),
		StartTime:  r.URL.Query().Get("start"),
		EndTime:    r.URL.Query().Get("end"),
		Computer:   r.URL.Query().Get("computer"),
		Contains:   r.URL.Query().Get("contains"),
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			q.Limit = n
		}
	}
	if q.Limit <= 0 {
		q.Limit = 200
	}
	// Wave 39 bug B fix: hard cap to prevent client-side DoS.
	// Without this, `?limit=1000000` previously triggered ~1.6 GB
	// memory allocations (HTTP 500) and `?limit=100000` returned
	// 164 MB responses. Cap to 10000 with a clear note in the JSON.
	const maxEventsLimit = 10000
	limitCapped := false
	if q.Limit > maxEventsLimit {
		q.Limit = maxEventsLimit
		limitCapped = true
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			q.Offset = n
		}
	}
	var rows []casedb.UnifiedEventRow
	err := s.withDB(casedb.ReadOnly, func(m *casedb.Manager) error {
		var ierr error
		rows, ierr = m.QueryUnifiedEvents(r.Context(), q)
		return ierr
	})
	if err != nil {
		if writeIfDBBusy(w, err) {
			return
		}
		writeError(w, 500, "query events: %v", err)
		return
	}
	resp := map[string]any{
		"count":  len(rows),
		"limit":  q.Limit,
		"offset": q.Offset,
		"events": rows,
	}
	if limitCapped {
		resp["note"] = fmt.Sprintf("limit capped to %d for memory safety (Wave 39 fix)", maxEventsLimit)
	}
	writeJSON(w, 200, resp)
}

// handleGetAudit streams the actions.jsonl audit log line by line, optionally
// filtering by `tier` query param (matches the JSON `actor` prefix
// e.g. tier0-orchestrator → tier=tier0).
func (s *Server) handleGetAudit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tierFilter := r.URL.Query().Get("tier")
	path := filepath.Join(s.cfg.OutputsRoot, id, "actions.jsonl")
	f, err := os.Open(path)
	if err != nil {
		writeError(w, 404, "no audit log: %v", err)
		return
	}
	defer f.Close()

	// enr joins each thin audit row back to the rich "what / why" context the
	// agent produced (rule intent + SQL, cluster narrative, active-search
	// question/answer, anomaly findings) so the Audit tab is legible to a human.
	enr := newAuditEnricher(s.cfg.OutputsRoot, id)
	out := []map[string]any{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if tierFilter != "" {
			actor, _ := rec["actor"].(string)
			if !strings.HasPrefix(actor, tierFilter) {
				continue
			}
		}
		if ex := enr.explain(rec); ex != nil {
			rec["explain"] = ex
		}
		out = append(out, rec)
	}
	writeJSON(w, 200, out)
}

// deleteCase delegates to casedb.Manager.DeleteCase. Kept as a one-line
// helper so handler code reads consistently with other DB ops.
func deleteCase(ctx context.Context, m *casedb.Manager, caseID string) error {
	return m.DeleteCase(ctx, caseID)
}

// handleHealthLLM reports whether either of the LLM access paths is
// available so the WebUI Analyze modal can warn upfront instead of
// failing at iter=1 with "claude: executable not found".
//
// Returns:
//
//	{
//	  "claude_cli":     bool   // `claude` exists on PATH
//	  "claude_version": string // captured if claude_cli=true
//	  "api_key_set":    bool   // ANTHROPIC_API_KEY env var non-empty
//	  "ok":             bool   // claude_cli OR api_key_set (analyze can run)
//	}
func (s *Server) handleHealthLLM(w http.ResponseWriter, r *http.Request) {
	transport := llm.Resolve()
	out := map[string]any{
		"claude_cli":     false,
		"claude_version": "",
		// api_key_set stays the wire name for back-compat, but now reflects any
		// configured API transport (Anthropic API or Vertex AI).
		"api_key_set": transport.Active(),
		"transport":   transport.Label(),
	}
	if path, err := exec.LookPath("claude"); err == nil {
		out["claude_cli"] = true
		// Try `claude --version` with a tight timeout so we don't block
		// the health check if the CLI is hung. Best-effort: any error
		// just leaves claude_version blank.
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, path, "--version")
		if vb, err := cmd.Output(); err == nil {
			out["claude_version"] = strings.TrimSpace(string(vb))
		}
	}
	out["ok"] = out["claude_cli"].(bool) || out["api_key_set"].(bool)
	writeJSON(w, 200, out)
}

// handleCancelJob factory returns a handler for /<step>/cancel endpoints.
// One factory call per JobKind (parse/analyze/synthesize/report) so the
// route registration in server.go stays declarative — Issue #8.
func (s *Server) handleCancelJob(kind JobKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		ok := s.jobs.Cancel(id, kind)
		if !ok {
			writeError(w, 409, "no running %s job for case %q (or already finished)", kind, id)
			return
		}
		writeJSON(w, 200, map[string]any{
			"status":  "canceling",
			"case_id": id,
			"kind":    kind,
		})
	}
}
