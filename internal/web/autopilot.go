package web

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Wave 33 — server-side autopilot endpoint.
//
// POST /api/cases/{id}/autopilot {evidence, evidence_id?, engine?, language?}
//
// Executes the entire Tier 0/1/2/3 pipeline in a single background job.
// Unlike the JS-side Wave 23 orchestration, the chain survives a client
// disconnect because the heavy work lives in a server-owned goroutine
// (subprocess actually — see below).
//
// Implementation: shells out to `tlvb run` with --skip-correct off,
// which already implements the full pipeline with graceful per-tactic
// degradation. Captures stdout/stderr into the JobStatus progress field
// so the Status tab can show real-time per-stage updates. Both Review
// Gates are auto-skipped on entry so the chain doesn't block on examiner
// approval.
//
// Why subprocess instead of in-process Go? The CLI already has runFullPipeline
// with caps + error handling. Wrapping it in a goroutine here would require
// refactoring runFullPipeline to return progress incrementally; for hackathon
// scope it's enough to capture its stdout as opaque text and route via
// JobStatus.Progress.

func (s *Server) handleStartAutopilot(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Evidence   string `json:"evidence"`    // input path (file or dir)
		EvidenceID string `json:"evidence_id"` // optional
		Engine     string `json:"engine"`      // auto (default) | anthropic-api | vertex
		Language   string `json:"language"`    // ja | en (report locale)
		CaseName   string `json:"case_name"`   // optional, for first-time init
	}
	_ = decodeJSON(r, &req)
	if req.Evidence == "" {
		writeError(w, 400, "evidence path is required")
		return
	}
	if req.Engine == "" {
		req.Engine = "auto"
	}
	// Wave 39 bug C fix: engine validation. Without this, `engine=
	// "nonsense"` was accepted with HTTP 202 and the subprocess
	// failed late, leaving the examiner with a vague "exit 1" error.
	switch req.Engine {
	case "auto", "anthropic-api", "vertex", "claude-code":
		// ok
	default:
		writeError(w, 400, "unknown engine %q (allowed: auto, anthropic-api, vertex, claude-code)", req.Engine)
		return
	}
	if req.Language == "" {
		req.Language = "ja"
	}
	if req.EvidenceID == "" {
		req.EvidenceID = "EV-001"
	}

	caseID := id
	evID := req.EvidenceID
	evPath := req.Evidence
	engine := req.Engine
	dbPath := s.cfg.DBPath

	// Pre-skip both gates so the pipeline doesn't block on examiner approval.
	// Same effect as the Wave 23 client-side POSTs — duplicating server-side
	// for resilience against a client that never sets them.
	{
		mu := parseReviewLock(caseID)
		mu.Lock()
		doc := s.loadParseReview(caseID)
		doc.AutoSkip = true
		_ = s.saveParseReview(doc)
		mu.Unlock()
	}
	{
		mu := timelineGateLock(caseID)
		mu.Lock()
		doc := s.loadTimelineGate(caseID)
		doc.AutoSkip = true
		_ = s.saveTimelineGate(doc)
		mu.Unlock()
	}

	subkind := "autopilot"
	st := s.jobs.StartWithReporter(id, JobAutopilot, subkind, func(ctx context.Context, rep *Reporter) (string, error) {
		rep.Text("autopilot: invoking tlvb run")
		// Locate the tlvb binary (same path the server itself runs from).
		binPath, _ := os.Executable()
		if binPath == "" {
			binPath = "tlvb"
		}
		args := []string{"run", caseID,
			"--evidence", evPath,
			"--evidence-id", evID,
			"--db", dbPath,
			"--engine", engine,
		}
		if req.CaseName != "" {
			args = append(args, "--name", req.CaseName)
		}
		cmd := exec.CommandContext(ctx, binPath, args...)

		// Stream stdout into the JobStatus.Progress field one line at a time.
		// `tlvb run` already emits per-stage [run] lines, perfect input
		// for the Status tab event log (Wave 20g).
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return "", fmt.Errorf("stdout pipe: %w", err)
		}
		cmd.Stderr = cmd.Stdout // merge stderr for simplicity
		if err := cmd.Start(); err != nil {
			return "", fmt.Errorf("start tlvb run: %w", err)
		}
		// Drain output → reporter.
		buf := make([]byte, 4096)
		var collected strings.Builder
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				chunk := string(buf[:n])
				collected.WriteString(chunk)
				// Update progress with last non-empty line so Status tab
				// shows the most recent meaningful stage marker.
				if line := lastNonEmptyLine(chunk); line != "" {
					rep.Text(truncate(line, 200))
				}
			}
			if err != nil {
				break
			}
		}
		waitErr := cmd.Wait()
		// Persist full transcript so the examiner can read it from the case
		// dir even after the JobStatus rolls over.
		_ = os.MkdirAll(filepath.Join(s.cfg.OutputsRoot, caseID), 0o755)
		_ = os.WriteFile(
			filepath.Join(s.cfg.OutputsRoot, caseID, "autopilot.log"),
			[]byte(collected.String()), 0o644,
		)
		if waitErr != nil {
			return "", fmt.Errorf("tlvb run: %w", waitErr)
		}
		return fmt.Sprintf("autopilot complete (%d bytes log)", collected.Len()), nil
	})
	_ = time.Now() // no-op; placeholder for future ETA hinting
	writeJSON(w, 202, st)
}

// GET /api/cases/{id}/autopilot/status (Wave 34)
func (s *Server) handleAutopilotStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.jobStatusOrDerived(r.Context(), r.PathValue("id"), JobAutopilot))
}

func lastNonEmptyLine(s string) string {
	lines := strings.Split(s, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" {
			return t
		}
	}
	return ""
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
