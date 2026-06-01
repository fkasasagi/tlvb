// Package web is the HTTP/JSON layer that exposes the TLVB pipeline
// (Tier 0 → Tier 3) to a browser-based Examiner UI.
//
// All UI assets are embedded via go:embed so a single `tlvb` binary
// ships with the front-end. Long-running jobs (parse / analyze /
// synthesize / report) execute in goroutines tracked by a JobsManager;
// the front-end polls /api/cases/:id/<step>/status for progress.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	tlvb "github.com/tlvb/tlvb"
	"github.com/tlvb/tlvb/internal/casedb"
)

// uiFS aliases the package-level UI embed declared in uiassets.go.
// The embed lives at the module root so the directory layout can be
// `ui/` (rather than `internal/web/ui/`).
var uiFS = tlvb.UI

// Config controls one server instance.
type Config struct {
	Addr        string // ":8080"
	DBPath      string // outputs/cases.duckdb
	RulesDBPath string // outputs/rules.duckdb (rule + skill SQL cache; Rule Library view)
	OutputsRoot string // outputs/cases
	Logger      *slog.Logger
}

// Server is the long-lived HTTP server.
type Server struct {
	cfg     Config
	mux     *http.ServeMux
	jobs    *JobsManager
	dbMu    sync.Mutex // serialises every casedb.Open call to avoid file-lock fights with async jobs
	rulesMu sync.Mutex // serialises rules.duckdb opens (separate file from cases.duckdb)
	logger  *slog.Logger
}

// New constructs a Server. Caller must call Start to bind the listener.
func New(cfg Config) (*Server, error) {
	if cfg.DBPath == "" {
		return nil, errors.New("web.New: DBPath required")
	}
	if cfg.OutputsRoot == "" {
		cfg.OutputsRoot = filepath.Join("outputs", "cases")
	}
	if cfg.RulesDBPath == "" {
		cfg.RulesDBPath = filepath.Join("outputs", "rules.duckdb")
	}
	if cfg.Addr == "" {
		cfg.Addr = ":8080"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	s := &Server{
		cfg:    cfg,
		mux:    http.NewServeMux(),
		jobs:   newJobsManager(),
		logger: cfg.Logger,
	}
	s.routes()
	return s, nil
}

// Handler returns the http.Handler (useful for tests).
func (s *Server) Handler() http.Handler {
	return logMiddleware(s.logger, s.mux)
}

// Start binds the listener and serves until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("tlvb web server listening",
			"addr", s.cfg.Addr, "db", s.cfg.DBPath, "outputs", s.cfg.OutputsRoot)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		} else {
			errCh <- nil
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

// ----------------------------------------------------------------------------
// Routing
// ----------------------------------------------------------------------------

func (s *Server) routes() {
	// REST API.
	s.mux.HandleFunc("GET /api/cases", s.handleListCases)
	s.mux.HandleFunc("POST /api/cases", s.handleCreateCase)
	s.mux.HandleFunc("GET /api/cases/{id}", s.handleGetCase)
	s.mux.HandleFunc("DELETE /api/cases/{id}", s.handleDeleteCase)

	s.mux.HandleFunc("POST /api/cases/{id}/parse", s.handleStartParse)
	s.mux.HandleFunc("GET /api/cases/{id}/parse/status", s.handleParseStatus)

	s.mux.HandleFunc("POST /api/cases/{id}/analyze", s.handleStartAnalyzeAll)
	s.mux.HandleFunc("POST /api/cases/{id}/analyze/artifact/{artifact_id}", s.handleStartAnalyzeArtifact)
	s.mux.HandleFunc("POST /api/cases/{id}/analyze/{tactic}", s.handleStartAnalyzeOne)
	s.mux.HandleFunc("GET /api/cases/{id}/analyze/status", s.handleAnalyzeStatus)

	// Wave 33 — server-side autopilot (Parse→Analyze→Synth→Report chain).
	s.mux.HandleFunc("POST /api/cases/{id}/autopilot", s.handleStartAutopilot)
	s.mux.HandleFunc("GET /api/cases/{id}/autopilot/status", s.handleAutopilotStatus) // Wave 34

	s.mux.HandleFunc("POST /api/cases/{id}/synthesize", s.handleStartSynthesize)
	s.mux.HandleFunc("GET /api/cases/{id}/synthesis", s.handleGetSynthesis)
	s.mux.HandleFunc("GET /api/cases/{id}/synthesize/status", s.handleSynthesizeStatus)

	s.mux.HandleFunc("POST /api/cases/{id}/report", s.handleStartReport)
	s.mux.HandleFunc("GET /api/cases/{id}/report/status", s.handleReportStatus)
	s.mux.HandleFunc("GET /api/cases/{id}/report/html", s.handleGetReportHTML)
	s.mux.HandleFunc("GET /api/cases/{id}/report/csv/{name}", s.handleGetReportCSV)
	s.mux.HandleFunc("GET /api/cases/{id}/report/json", s.handleGetReportJSON)

	// Case-state snapshot (Status tab — parse / findings / synthesis / report).
	s.mux.HandleFunc("GET /api/cases/{id}/summary", s.handleGetCaseSummary)

	// Rule Library — global (not case-scoped) view of rules.duckdb: rule_sql_cache
	// build coverage + skill_sql_cache (Tier 1B v0.2 learned lenses). rule_library.go.
	s.mux.HandleFunc("GET /api/rules/summary", s.handleGetRulesSummary)
	s.mux.HandleFunc("GET /api/rules/skills", s.handleListSkillSQL)
	s.mux.HandleFunc("GET /api/rules", s.handleListRules)

	// Review Gate 1A — unified Tier 1A by-rule + Tier 1B by-skill findings.
	// Implementation lives in review_gate_1a.go.
	s.mux.HandleFunc("GET /api/cases/{id}/findings", s.handleListReviewFindings)
	s.mux.HandleFunc("POST /api/cases/{id}/findings/{fid}/approve", s.handleApproveReviewFinding)
	s.mux.HandleFunc("POST /api/cases/{id}/findings/{fid}/reject", s.handleRejectReviewFinding)
	s.mux.HandleFunc("POST /api/cases/{id}/findings/{fid}/reset", s.handleResetReviewFinding)
	s.mux.HandleFunc("POST /api/cases/{id}/findings/bulk", s.handleBulkReviewFindings)

	s.mux.HandleFunc("GET /api/cases/{id}/timeline", s.handleGetTimeline)
	s.mux.HandleFunc("GET /api/cases/{id}/iocs", s.handleGetIOCs)
	s.mux.HandleFunc("GET /api/cases/{id}/events", s.handleQueryEvents)
	s.mux.HandleFunc("GET /api/cases/{id}/mitre", s.handleGetMITRE)
	s.mux.HandleFunc("GET /api/cases/{id}/audit", s.handleGetAudit)

	// Assistant chat (single-turn, stateless).
	s.mux.HandleFunc("POST /api/chat", s.handleChat)

	// LLM availability pre-check (used by Analyze modals to warn the
	// examiner when neither `claude` CLI nor ANTHROPIC_API_KEY is set
	// rather than failing later at iter=1).
	s.mux.HandleFunc("GET /api/health/llm", s.handleHealthLLM)

	// Job cancellation (Issue #8). One endpoint per JobKind so the
	// URL is self-documenting in the WebUI's network tab. The same
	// JobsManager.Cancel is called for all of them.
	s.mux.HandleFunc("POST /api/cases/{id}/parse/cancel", s.handleCancelJob(JobParse))
	s.mux.HandleFunc("POST /api/cases/{id}/analyze/cancel", s.handleCancelJob(JobAnalyze))
	s.mux.HandleFunc("POST /api/cases/{id}/synthesize/cancel", s.handleCancelJob(JobSynthesize))
	s.mux.HandleFunc("POST /api/cases/{id}/report/cancel", s.handleCancelJob(JobReport))

	// Review Gate 0 — per-artifact parse-result approval (★v0.3 #2).
	s.mux.HandleFunc("GET /api/cases/{id}/parse-review", s.handleGetParseReview)
	s.mux.HandleFunc("POST /api/cases/{id}/parse-review/{artifact}/approve", s.handleApproveParseResult)
	s.mux.HandleFunc("POST /api/cases/{id}/parse-review/{artifact}/reject", s.handleRejectParseResult)
	s.mux.HandleFunc("POST /api/cases/{id}/parse-review/skip-all", s.handleParseReviewSkipAll)

	// Review Gate 2 — per-timeline-entry approval (Wave 21, DESIGN §6.5).
	s.mux.HandleFunc("GET /api/cases/{id}/timeline-review", s.handleGetTimelineReview)
	s.mux.HandleFunc("POST /api/cases/{id}/timeline-review/{audit_id}/approve", s.handleApproveTimelineEntry)
	s.mux.HandleFunc("POST /api/cases/{id}/timeline-review/{audit_id}/reject", s.handleRejectTimelineEntry)
	s.mux.HandleFunc("POST /api/cases/{id}/timeline-review/skip-all", s.handleTimelineReviewSkipAll)

	// Disk-image extraction review (Issue #23).
	s.mux.HandleFunc("GET /api/cases/{id}/extracts", s.handleGetExtracts)
	s.mux.HandleFunc("POST /api/cases/{id}/extracts/{target}/approve", s.handleApproveExtract)
	s.mux.HandleFunc("POST /api/cases/{id}/extracts/{target}/reject", s.handleRejectExtract)

	// Case export / import (Issue #16 / DESIGN v0.4 REQ-2).
	s.mux.HandleFunc("GET /api/cases/{id}/export", s.handleCaseExport)
	s.mux.HandleFunc("POST /api/cases/import", s.handleCaseImport)

	// UI.
	uiSub, _ := fs.Sub(uiFS, "ui")
	staticSub, _ := fs.Sub(uiSub, "static")
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))
	s.mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		// Anything not matched by /static/ or /api/ falls back to index.html
		// so the SPA can run client-side routing on /cases/<id> URLs.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		body, err := fs.ReadFile(uiSub, "index.html")
		if err != nil {
			http.Error(w, "ui not embedded: "+err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(body)
	})
}

// ----------------------------------------------------------------------------
// Common helpers
// ----------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		// Body partly written — nothing we can do.
		_ = err
	}
}

func writeError(w http.ResponseWriter, code int, format string, args ...any) {
	writeJSON(w, code, map[string]any{
		"error": fmt.Sprintf(format, args...),
	})
}

func decodeJSON(r *http.Request, dst any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil // optional body
	}
	return json.Unmarshal(body, dst)
}

// withDB acquires the global DB mutex, opens a fresh casedb.Manager,
// invokes fn, and tears down. Any returned error becomes a 500 JSON.
func (s *Server) withDB(mode casedb.Mode, fn func(m *casedb.Manager) error) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	m, err := casedb.Open(s.cfg.DBPath, mode)
	if err != nil {
		return fmt.Errorf("open casedb: %w", err)
	}
	defer m.Close()
	return fn(m)
}

func logMiddleware(logger *slog.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, code: 200}
		h.ServeHTTP(rw, r)
		// Skip noisy /static and status polls below info.
		if strings.HasPrefix(r.URL.Path, "/static/") {
			return
		}
		level := slog.LevelInfo
		if strings.HasSuffix(r.URL.Path, "/status") {
			level = slog.LevelDebug
		}
		logger.Log(r.Context(), level, "http",
			"method", r.Method, "path", r.URL.Path,
			"status", rw.code, "dur_ms", time.Since(start).Milliseconds())
	})
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(c int) {
	s.code = c
	s.ResponseWriter.WriteHeader(c)
}
