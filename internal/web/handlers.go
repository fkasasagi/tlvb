package web

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/agents"
	"github.com/tlvb/tlvb/internal/casedb"
	"github.com/tlvb/tlvb/internal/common"
	"github.com/tlvb/tlvb/internal/reporter"
	"github.com/tlvb/tlvb/internal/synthesizer"
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
// (B1 indictment). Operators can opt out with FINDEVIL_SLIDING_WINDOW=0
// (or false / off). FINDEVIL_SLIDING_WINDOW=1 was the old opt-in toggle
// — kept as a synonym so existing operators' env vars stay valid.
func slidingWindowDefault() bool {
	v := strings.ToLower(os.Getenv("FINDEVIL_SLIDING_WINDOW"))
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
	EvidenceCount   int  `json:"evidence_count"`
	UnifiedRowCount int64 `json:"unified_event_rows"`
	HasFindings     bool `json:"has_findings"`
	HasSynthesis    bool `json:"has_synthesis"`
	HasReport       bool `json:"has_report"`
	FindingsCount   int  `json:"findings_count"`
}

func (s *Server) handleListCases(w http.ResponseWriter, r *http.Request) {
	var rows []casedb.CaseRow
	err := s.withDB(casedb.ReadWrite, func(m *casedb.Manager) error {
		var ierr error
		rows, ierr = m.ListCases(r.Context())
		return ierr
	})
	if err != nil {
		writeError(w, 500, "list cases: %v", err)
		return
	}
	out := make([]caseSummary, 0, len(rows))
	for _, c := range rows {
		summary := caseSummary{CaseRow: c}
		// Best-effort enrich; ignore individual-case errors.
		_ = s.withDB(casedb.ReadWrite, func(m *casedb.Manager) error {
			st, err := m.GetCaseStatus(r.Context(), c.CaseID)
			if err == nil && st != nil {
				summary.EvidenceCount = st.EvidenceCount
				summary.UnifiedRowCount = st.UnifiedRowCount
			}
			return nil
		})
		summary.populateArtifactStatus(s.cfg.OutputsRoot)
		out = append(out, summary)
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleCreateCase(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CaseID   string `json:"case_id"`
		Name     string `json:"name"`
		Examiner string `json:"examiner"`
		Timezone string `json:"timezone"`
		Language string `json:"language"`
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

	row := casedb.CaseRow{
		CaseID:    req.CaseID,
		Name:      req.Name,
		Examiner:  req.Examiner,
		Timezone:  req.Timezone,
		CreatedAt: time.Now().UTC(),
	}
	err := s.withDB(casedb.ReadWrite, func(m *casedb.Manager) error {
		return m.RegisterCase(r.Context(), row)
	})
	if err != nil {
		writeError(w, 500, "register case: %v", err)
		return
	}
	writeJSON(w, 201, row)
}

func (s *Server) handleGetCase(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var st *casedb.CaseStatus
	err := s.withDB(casedb.ReadWrite, func(m *casedb.Manager) error {
		var ierr error
		st, ierr = m.GetCaseStatus(r.Context(), id)
		return ierr
	})
	if err != nil {
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
		"case":             summary,
		"evidence":         evidence,
		"parse_results":    st.ParseResults,
		"jobs": map[string]JobStatus{
			"parse":      s.jobs.Status(id, JobParse),
			"analyze":    s.jobs.Status(id, JobAnalyze),
			"synthesize": s.jobs.Status(id, JobSynthesize),
			"report":     s.jobs.Status(id, JobReport),
		},
	})
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
		// The casedb package only exposes RegisterCase so we use raw SQL for delete.
		// NB: this leaves evidence/unified_events orphan-rows behind by design —
		// chain-of-custody record. UI delete just hides the case.
		return deleteCase(r.Context(), m, id)
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

func (sm *caseSummary) populateArtifactStatus(outputsRoot string) {
	dir := filepath.Join(outputsRoot, sm.CaseID)
	findings := filepath.Join(dir, "findings")
	if entries, err := os.ReadDir(findings); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
				sm.FindingsCount++
			}
		}
		sm.HasFindings = sm.FindingsCount > 0
	}
	if _, err := os.Stat(filepath.Join(dir, "synthesis.json")); err == nil {
		sm.HasSynthesis = true
	}
	if _, err := os.Stat(filepath.Join(dir, "reports", "report.html")); err == nil {
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
		var firstErr error
		total := len(evidences)
		for i, ev := range evidences {
			rep.SetAll(
				fmt.Sprintf("evidence %d/%d: %s", i+1, total, ev.EvidenceID),
				i, total, 0,
			)
			err := s.parseOneEvidence(ctx, rep, caseID, ev.EvidenceID, ev.EvidencePath, dbPath, i+1, total, mode, imgFmt)
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s: %v", ev.EvidenceID, err))
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			ok = append(ok, ev.EvidenceID)
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
		return msg, nil
	})
	writeJSON(w, 202, st)
}

// parseOneEvidence runs the orchestrator subprocess for a single evidence
// and tails its PROGRESS|<json> stderr stream into the Reporter so the UI
// shows per-artifact progress within the current evidence.
//
// Returns nil on success, or an error with the stderr tail attached.
// The caller (handleStartParse) accumulates ok/failed lists for graceful
// degradation across multiple evidences.
func (s *Server) parseOneEvidence(
	ctx context.Context, rep *Reporter,
	caseID, evID, evPath, dbPath string,
	evIdx, evTotal int,
	inputMode, imageFormat string,
) error {
	rep.Text(fmt.Sprintf("evidence %d/%d (%s): registering", evIdx, evTotal, evID))
	abs, err := filepath.Abs(evPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	stInfo, err := os.Stat(abs)
	if err != nil {
		return fmt.Errorf("evidence path: %w", err)
	}
	// Issue #23: validate the declared input mode matches the file shape
	// the operator pointed us at. Auto-detect mode skips this check.
	if inputMode == "image" && stInfo.IsDir() {
		return fmt.Errorf("input_mode=image requires a file, got directory: %s", abs)
	}
	if (inputMode == "cdir" || inputMode == "washizukami") && !stInfo.IsDir() {
		// .zip is permitted because stage_input unpacks it transparently.
		if !strings.HasSuffix(strings.ToLower(abs), ".zip") {
			return fmt.Errorf("input_mode=%s requires a directory or .zip, got file: %s", inputMode, abs)
		}
	}
	mgr, err := casedb.Open(dbPath, casedb.ReadWrite)
	if err != nil {
		return err
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
		return fmt.Errorf("register evidence %s under case %s: %w", evID, caseID, err)
	}
	_ = mgr.Close()

	rep.Text(fmt.Sprintf("evidence %d/%d (%s): running orchestrator", evIdx, evTotal, evID))
	ws := filepath.Join("outputs", "cases", caseID)
	_ = os.MkdirAll(ws, 0o755)
	// Issue #19: propagate the case timezone to the orchestrator so the
	// underlying tools (e.g. `psort.py -z`) render their output in the
	// examiner's local time.
	caseTZ := "UTC"
	if mgr2, mgrErr := casedb.Open(dbPath, casedb.ReadOnly); mgrErr == nil {
		if cs, gerr := mgr2.GetCaseStatus(ctx, caseID); gerr == nil && cs.Case.Timezone != "" {
			caseTZ = cs.Case.Timezone
		}
		_ = mgr2.Close()
	}
	argv := []string{
		"-m", "parsers.orchestrator",
		"--case-id", caseID, "--evidence-id", evID,
		"--input", abs, "--db", dbPath, "--workspace", ws,
		"--timezone", caseTZ,
		"--report-json", "/dev/null",
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
		return fmt.Errorf("stderr pipe: %w", perr)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start orchestrator: %w", err)
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
	if err := cmd.Wait(); err != nil {
		tail := sb.String()
		if len(tail) > 2000 {
			tail = "...[truncated]\n" + tail[len(tail)-2000:]
		}
		return fmt.Errorf("orchestrator: %w\n%s", err, tail)
	}
	return nil
}

func (s *Server) handleParseStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.jobs.Status(r.PathValue("id"), JobParse))
}

// handleParseProgressEvent translates one PROGRESS|<json> event from the
// Python orchestrator into a Reporter update.
//
// Events the orchestrator emits today (parsers/orchestrator.py):
//   {"type":"stage", "phase":"extracting"|"detecting"}
//   {"type":"detect_done", "total":N, "artifact_ids":[...]}
//   {"type":"parse_start", "artifact_id":..., "i":..., "of":N}
//   {"type":"parse_done",  "artifact_id":..., "i":..., "of":N, "ok":bool, "row_count":N, "duration_s":F}
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
		Engine   string   `json:"engine"`
		Model    string   `json:"model"`
		Tactics  []string `json:"tactics"`
		IncludeAnomaly bool `json:"include_anomaly"`
	}
	_ = decodeJSON(r, &req)
	if req.Engine == "" {
		req.Engine = "claude-code"
	}
	tactics := req.Tactics
	if len(tactics) == 0 {
		tactics = defaultTactics
	}

	caseID := id
	dbPath := s.cfg.DBPath
	dbMu := &s.dbMu
	engine := req.Engine
	model := req.Model
	includeAnomaly := req.IncludeAnomaly

	// Review Gate 0 — block Analyze unless parse results have been approved
	// (or skip-all is enabled, or ?force=true is passed). ★v0.3 #2.
	if err := s.gateAllowsAnalyze(r, id); err != nil {
		writeError(w, 409, "%v", err)
		return
	}

	st := s.jobs.StartWithReporter(id, JobAnalyze, "all", func(ctx context.Context, rep *Reporter) (string, error) {
		dbMu.Lock()
		defer dbMu.Unlock()

		evIDs, err := allEvidenceIDs(ctx, dbPath, caseID)
		if err != nil {
			return "", err
		}
		evID := evIDs[0] // primary, for back-compat with TacticReport.EvidenceID
		all := append([]string(nil), tactics...)
		if includeAnomaly {
			all = append(all, "anomaly_hunter")
		}
		total := len(all)
		// Initial bar at 0/N + a baseline ETA from a hard-coded 3-min/tactic
		// guess (replaced after the first tactic completes with the real
		// average). Without this the bar shows N/A for several minutes.
		const baselineSecPerTactic = 180
		rep.SetAll(fmt.Sprintf("starting %d tactics", total), 0, total, baselineSecPerTactic*total)

		var failed []string
		var done []string
		var totalTacticDuration time.Duration
		jobStart := time.Now()
		for i, tac := range all {
			tacticStart := time.Now()
			completedSoFar := len(done) + len(failed)
			rep.SetAll(
				fmt.Sprintf("running %s (%d/%d)", tac, i+1, total),
				completedSoFar, total,
				etaSeconds(completedSoFar, total, jobStart, totalTacticDuration, baselineSecPerTactic),
			)
			if err := runOneTactic(ctx, caseID, evID, tac, engine, model, dbPath, evIDs); err != nil {
				failed = append(failed, fmt.Sprintf("%s: %v", tac, err))
			} else {
				done = append(done, tac)
			}
			totalTacticDuration += time.Since(tacticStart)
			rep.SetAll(
				fmt.Sprintf("done %s (%d/%d)", tac, i+1, total),
				i+1, total,
				etaSeconds(i+1, total, jobStart, totalTacticDuration, baselineSecPerTactic),
			)
		}
		msg := fmt.Sprintf("completed=%d failed=%d", len(done), len(failed))
		if len(failed) > 0 {
			return msg, fmt.Errorf("some tactics failed: %s", strings.Join(failed, "; "))
		}
		return msg, nil
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
		req.Engine = "claude-code"
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
		dbMu.Lock()
		defer dbMu.Unlock()

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
//   body: {"engine": "...", "model": "..."} (both optional)
//   202: JobStatus (poll /analyze/status to track)
//   409: Review Gate 0 blocks (parse not approved)
//   404: no tactic references this artifact (empty plan)
func (s *Server) handleStartAnalyzeArtifact(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	artifact := r.PathValue("artifact_id")
	var req struct {
		Engine string `json:"engine"`
		Model  string `json:"model"`
	}
	_ = decodeJSON(r, &req)
	if req.Engine == "" {
		req.Engine = "claude-code"
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
		dbMu.Lock()
		defer dbMu.Unlock()

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
	writeJSON(w, 200, s.jobs.Status(r.PathValue("id"), JobAnalyze))
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
	//     docstring for the FINDEVIL_LLM_TIMEOUT_* family).
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
		EvidenceIDs:   evIDs, // ★v0.3 #7 — full case scope stamped on the report
		ArtifactScope: artifactScope, // Wave 20h
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
		Correct        bool   `json:"correct"`
		Engine         string `json:"engine"`
		Model          string `json:"model"`
		ReviewTimeline bool   `json:"review_timeline"`
		ReviewLanguage string `json:"review_language"`
	}
	_ = decodeJSON(r, &req)
	if req.Engine == "" {
		req.Engine = "claude-code"
	}
	if req.ReviewLanguage == "" {
		req.ReviewLanguage = "ja"
	}

	caseID := id
	dbPath := s.cfg.DBPath
	dbMu := &s.dbMu
	correct := req.Correct
	engine := req.Engine
	model := req.Model
	reviewTimeline := req.ReviewTimeline
	reviewLanguage := req.ReviewLanguage

	st := s.jobs.Start(id, JobSynthesize, fmt.Sprintf("correct=%v", correct), func(ctx context.Context, progress func(string)) (string, error) {
		dbMu.Lock()
		defer dbMu.Unlock()

		progress("aggregating findings")
		evIDs, _ := allEvidenceIDs(ctx, dbPath, caseID)
		var evID string
		if len(evIDs) > 0 {
			evID = evIDs[0]
		}
		cfg := synthesizer.Config{
			CaseID:      caseID,
			EvidenceID:  evID,
			EvidenceIDs: evIDs, // ★v0.3 #7 — full case scope into synthesis
			Timezone:    "UTC",
			FindingsDir: filepath.Join("outputs", "cases", caseID, "findings"),
			DBPath:      dbPath,
			Correct:     correct,
			Language:    reviewLanguage, // Wave 26 — drives Recommendations ja/en
		}
		if correct {
			// Wave 20a: corrector も動的 timeout に揃える。tactic="" は
			// anomaly_hunter ではないので 1.5× multiplier は適用されない
			// (= 標準 tactic と同じバジェット)。
			const correctorMaxEvents = 100
			cfg.CorrectorCfg = synthesizer.CorrectionConfig{
				Engine:       engine,
				APIKey:       os.Getenv("ANTHROPIC_API_KEY"),
				Model:        model,
				MaxRounds:    1,
				AgentTimeout: agents.ComputeTimeout("", correctorMaxEvents),
				MaxEvents:    correctorMaxEvents,
				MaxIters:     3,
			}
		}
		if reviewTimeline {
			cfg.ReviewTimeline = true
			cfg.TimelineReviewCfg = synthesizer.TimelineReviewConfig{
				Language:    reviewLanguage,
				Engine:      engine,
				APIKey:      os.Getenv("ANTHROPIC_API_KEY"),
				Model:       model,
				MaxTokens:   50000,
				Timeout:     5 * time.Minute,
				SkillsDir:   "skills",
				MaxExcerpt:  200,
				MaxFindings: 50,
			}
		}
		timeout := 5 * time.Minute
		if correct {
			timeout = 30 * time.Minute
		}
		if reviewTimeline {
			timeout += 7 * time.Minute
		}
		sctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		cs, err := synthesizer.Synthesize(sctx, cfg)
		if err != nil {
			return "", err
		}
		out := filepath.Join("outputs", "cases", caseID, "synthesis.json")
		body, err := json.MarshalIndent(cs, "", "  ")
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(out, body, 0o644); err != nil {
			return "", err
		}
		return fmt.Sprintf("findings=%d clusters=%d inconsistencies=%d",
			cs.Stats.TotalFindings, cs.Stats.ClusterCount, len(cs.Inconsistencies)), nil
	})
	writeJSON(w, 202, st)
}

func (s *Server) handleSynthesizeStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.jobs.Status(r.PathValue("id"), JobSynthesize))
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

func (s *Server) loadSynthesis(caseID string) (*synthesizer.CaseSynthesis, error) {
	path := filepath.Join(s.cfg.OutputsRoot, caseID, "synthesis.json")
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read synthesis: %w", err)
	}
	var cs synthesizer.CaseSynthesis
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

	st := s.jobs.Start(id, JobReport, lang, func(ctx context.Context, progress func(string)) (string, error) {
		progress("rendering report")
		cfg := reporter.Config{
			CaseID:        caseID,
			SynthesisPath: filepath.Join(root, caseID, "synthesis.json"),
			OutDir:        filepath.Join(root, caseID, "reports"),
			Formats:       formats,
			Language:      lang,
			OnlyApproved:  onlyApproved,
		}
		res, err := reporter.Render(cfg)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("wrote %d files to %s", len(res.Files), res.OutDir), nil
	})
	writeJSON(w, 202, st)
}

func (s *Server) handleReportStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.jobs.Status(r.PathValue("id"), JobReport))
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

// ----------------------------------------------------------------------------
// Findings  (read + approve/reject)
// ----------------------------------------------------------------------------

type findingDTO struct {
	agents.Finding
	Tactic     string `json:"tactic"`      // slug, e.g. persistence
	TacticID   string `json:"tactic_id"`
	TacticName string `json:"tactic_name"`
}

// handleListFindings returns every finding across every TacticReport JSON.
func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dtos, err := s.collectFindings(id, "")
	if err != nil {
		writeError(w, 404, "%v", err)
		return
	}
	writeJSON(w, 200, dtos)
}

func (s *Server) handleListFindingsByTactic(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tactic := r.PathValue("tactic")
	dtos, err := s.collectFindings(id, tactic)
	if err != nil {
		writeError(w, 404, "%v", err)
		return
	}
	writeJSON(w, 200, dtos)
}

func (s *Server) collectFindings(caseID, tacticFilter string) ([]findingDTO, error) {
	dir := filepath.Join(s.cfg.OutputsRoot, caseID, "findings")
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

func (s *Server) handleApproveFinding(w http.ResponseWriter, r *http.Request) {
	s.singleFindingAction(w, r, "approve", "")
}

func (s *Server) handleRejectFinding(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	_ = decodeJSON(r, &req)
	s.singleFindingAction(w, r, "reject", req.Reason)
}

// handleResetFinding clears approved/rejected/reason/reviewer back to the
// pre-review (pending) state. Issue #7 — examiners want to be able to
// undo their decision and re-review.
func (s *Server) handleResetFinding(w http.ResponseWriter, r *http.Request) {
	s.singleFindingAction(w, r, "reset", "")
}

// handleBulkFindingsAction performs one of approve / reject / reset on a
// list of finding_ids in a single request. Issue #5 (bulk select) +
// Issue #10 (approve all). The returned counts let the UI update its
// view incrementally rather than re-fetching everything.
//
// Body:
//
//	{
//	  "finding_ids": ["F-persistence-001", "F-execution-002", ...],
//	  "action":      "approve" | "reject" | "reset",
//	  "reason":      "..."     // optional for action=reject (Issue #21)
//	}
func (s *Server) handleBulkFindingsAction(w http.ResponseWriter, r *http.Request) {
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
	res, err := s.applyFindingMutations(caseID, req.FindingIDs, req.Action, req.Reason, examiner)
	if err != nil {
		writeError(w, 500, "%v", err)
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) singleFindingAction(w http.ResponseWriter, r *http.Request, action, reason string) {
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
	res, err := s.applyFindingMutations(caseID, []string{fid}, action, reason, examiner)
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

// findingMutationResult is the shape returned to the bulk caller.
type findingMutationResult struct {
	Updated  int      `json:"updated"`
	NotFound []string `json:"not_found,omitempty"`
}

// applyFindingMutations is the single source of truth for editing finding
// review state. Walks every TacticReport JSON once, applies every matching
// finding_id in one pass, then writes each touched file once.
func (s *Server) applyFindingMutations(
	caseID string, findingIDs []string, action, reason, examiner string,
) (*findingMutationResult, error) {
	dir := filepath.Join(s.cfg.OutputsRoot, caseID, "findings")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("no findings: %w", err)
	}
	wanted := make(map[string]bool, len(findingIDs))
	for _, id := range findingIDs {
		wanted[id] = true
	}
	res := &findingMutationResult{}
	now := time.Now().UTC()

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var rep agents.TacticReport
		if err := json.Unmarshal(body, &rep); err != nil {
			continue
		}
		changed := false
		for i := range rep.Findings {
			f := &rep.Findings[i]
			if !wanted[f.FindingID] {
				continue
			}
			switch action {
			case "approve":
				f.Approved = true
				f.Rejected = false
				f.RejectReason = ""
				f.ReviewedAt = now
				f.ReviewedBy = examiner
			case "reject":
				f.Approved = false
				f.Rejected = true
				f.RejectReason = reason
				f.ReviewedAt = now
				f.ReviewedBy = examiner
			case "reset":
				f.Approved = false
				f.Rejected = false
				f.RejectReason = ""
				f.ReviewedAt = time.Time{}
				f.ReviewedBy = ""
			}
			res.Updated++
			delete(wanted, f.FindingID)
			changed = true
		}
		if changed {
			out, err := json.MarshalIndent(rep, "", "  ")
			if err != nil {
				return nil, fmt.Errorf("marshal: %w", err)
			}
			if err := os.WriteFile(path, out, 0o644); err != nil {
				return nil, fmt.Errorf("write: %w", err)
			}
		}
	}
	for id := range wanted {
		res.NotFound = append(res.NotFound, id)
	}
	sort.Strings(res.NotFound)
	return res, nil
}

// ----------------------------------------------------------------------------
// Timeline / IOC / MITRE / Events / Audit
// ----------------------------------------------------------------------------

func (s *Server) handleGetTimeline(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cs, err := s.loadSynthesis(id)
	if err != nil {
		writeError(w, 404, "%v", err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"timeline":                    cs.Timeline,
		"intrusion_path":              cs.IntrusionPath,
		"cross_evidence_correlations": cs.CrossEvidenceCorrelations, // Wave 27
	})
}

// iocDTO is the JSON-friendly shape for an IOC. The reporter's IOCExtraction
// stores findings/tactics as map sets — convert to sorted slices for the wire.
type iocDTO struct {
	Type     string   `json:"type"`
	Value    string   `json:"value"`
	Count    int      `json:"count"`
	Findings []string `json:"findings"`
	Tactics  []string `json:"tactics"`
}

func (s *Server) handleGetIOCs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cs, err := s.loadSynthesis(id)
	if err != nil {
		writeError(w, 404, "%v", err)
		return
	}
	raw := reporter.ExtractIOCs(cs)
	out := make([]iocDTO, 0, len(raw))
	for _, ioc := range raw {
		findings := make([]string, 0, len(ioc.Findings))
		for k := range ioc.Findings {
			findings = append(findings, k)
		}
		sort.Strings(findings)
		tactics := make([]string, 0, len(ioc.Tactics))
		for k := range ioc.Tactics {
			tactics = append(tactics, k)
		}
		sort.Strings(tactics)
		out = append(out, iocDTO{
			Type:     string(ioc.Type),
			Value:    ioc.Value,
			Count:    len(ioc.Findings),
			Findings: findings,
			Tactics:  tactics,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Value < out[j].Value
	})
	writeJSON(w, 200, out)
}

func (s *Server) handleGetMITRE(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cs, err := s.loadSynthesis(id)
	if err != nil {
		writeError(w, 404, "%v", err)
		return
	}
	writeJSON(w, 200, cs.MITREMapping)
}

func (s *Server) handleQueryEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	q := casedb.UnifiedEventQuery{
		CaseID:     id,
		ArtifactID: r.URL.Query().Get("artifact_id"),
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
	out := map[string]any{
		"claude_cli":     false,
		"claude_version": "",
		"api_key_set":    os.Getenv("ANTHROPIC_API_KEY") != "",
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
