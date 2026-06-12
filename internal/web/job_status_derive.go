package web

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/tlvb/tlvb/internal/casedb"
)

// jobStatusOrDerived returns the live in-memory job status for (caseID, kind),
// or — when no job has run in *this* server process — a status reconstructed
// from the durable artifacts the step leaves behind.
//
// The JobsManager is purely in-memory and is wiped when the server restarts,
// so without this fallback every finished step (parse, analyze, …) snaps back
// to "idle" after a restart even though its output is sitting on disk. Live
// state always wins: a running / failed / partial / canceled job in this
// process carries progress, timestamps and error text we can't reconstruct, so
// we only fall back when the tracker reports "idle".
func (s *Server) jobStatusOrDerived(ctx context.Context, caseID string, kind JobKind) JobStatus {
	st := s.jobs.Status(caseID, kind)
	if st.State != "idle" {
		return st
	}
	if derived, ok := s.deriveJobStatus(ctx, caseID, kind); ok {
		return derived
	}
	return st
}

// deriveJobStatus reconstructs a terminal JobStatus from a completed step's
// durable output: parse_results in cases.duckdb for parse, on-disk artifacts
// for the rest. Returns ok=false when there's no sign the step ever ran, so the
// caller keeps the "idle" zero-value.
//
// The synthesized status carries no StartedAt/FinishedAt (those are lost on
// restart) and a Message tagged "(previous run)" so the UI/event-log can tell a
// reconstructed state apart from one observed live.
func (s *Server) deriveJobStatus(ctx context.Context, caseID string, kind JobKind) (JobStatus, bool) {
	dir := filepath.Join(s.cfg.OutputsRoot, caseID)
	done := func(state, msg string) (JobStatus, bool) {
		return JobStatus{CaseID: caseID, Kind: kind, State: state, Message: msg}, true
	}
	switch kind {
	case JobParse:
		ok, fail, found := s.parseOutcome(ctx, caseID)
		if !found {
			return JobStatus{}, false
		}
		switch {
		case fail == 0:
			return done("succeeded", fmt.Sprintf("%d artifact(s) parsed (previous run)", ok))
		case ok == 0:
			return done("failed", "all artifacts failed to parse (previous run)")
		default:
			return done("partial", fmt.Sprintf("%d ok / %d failed (previous run)", ok, fail))
		}
	case JobAnalyze:
		if countFindingsJSON(filepath.Join(dir, "findings")) > 0 {
			return done("succeeded", "findings present (previous run)")
		}
	case JobSynthesize:
		if fileExists(filepath.Join(dir, "synthesis.json")) {
			return done("succeeded", "synthesis present (previous run)")
		}
	case JobReport:
		if fileExists(filepath.Join(dir, "reports", "report.html")) {
			return done("succeeded", "report present (previous run)")
		}
	case JobAutopilot:
		// autopilot.log is written unconditionally at the end of a `tlvb run`
		// (success or failure). Its presence means a full-pipeline run finished
		// in an earlier session; the per-stage badges carry the substance.
		if fileExists(filepath.Join(dir, "autopilot.log")) {
			return done("succeeded", "autopilot ran (previous run)")
		}
	}
	return JobStatus{}, false
}

// parseOutcome tallies parse_results exit codes for a case. found=false when the
// case has no parse_results rows (never parsed) or the DB can't be read — either
// way we don't synthesize a parse status. A nil exit_code (row written before
// the artifact finished) counts as a failure, matching how a crashed or killed
// parse should read.
func (s *Server) parseOutcome(ctx context.Context, caseID string) (ok, fail int, found bool) {
	_ = s.withDB(casedb.ReadOnly, func(m *casedb.Manager) error {
		st, err := m.GetCaseStatus(ctx, caseID)
		if err != nil {
			return err
		}
		for _, pr := range st.ParseResults {
			found = true
			if pr.ExitCode != nil && *pr.ExitCode == 0 {
				ok++
			} else {
				fail++
			}
		}
		return nil
	})
	return ok, fail, found
}

// countFindingsJSON counts *.json files anywhere under findingsDir
// (findings/by-rule/<source>/*.json and findings/by-skill/*.json). An earlier
// top-level-only count always returned 0 because findings moved into those
// subdirectories; *.raw_response.txt sidecars are skipped by the suffix check.
func countFindingsJSON(findingsDir string) int {
	n := 0
	_ = filepath.WalkDir(findingsDir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // missing/unreadable subtree → just skip it
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			n++
		}
		return nil
	})
	return n
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
