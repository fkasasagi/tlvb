package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/tlvb/tlvb/internal/casedb"
	"github.com/tlvb/tlvb/internal/exporter"
)

// handleCaseExport streams a .fcz tarball back to the client.
// Query params:
//   - include_evidence=true|false (default false)
//
// We render into a temp file first (the exporter wants a path it can
// open repeatedly to hash + tar), then stream that file out.
func (s *Server) handleCaseExport(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	includeEv := r.URL.Query().Get("include_evidence") == "true"

	tmp, err := os.CreateTemp("", "tlvb-export-*.fcz")
	if err != nil {
		writeError(w, 500, "tempfile: %v", err)
		return
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	if err := s.withDB(casedb.ReadOnly, func(m *casedb.Manager) error {
		_, err := exporter.Export(r.Context(), m, exporter.ExportOptions{
			CaseID:          caseID,
			OutputsRoot:     s.cfg.OutputsRoot,
			DBPath:          s.cfg.DBPath,
			OutputPath:      tmpPath,
			IncludeEvidence: includeEv,
			ExportedBy:      "webui",
		})
		return err
	}); err != nil {
		writeError(w, 500, "export: %v", err)
		return
	}

	f, err := os.Open(tmpPath)
	if err != nil {
		writeError(w, 500, "open export: %v", err)
		return
	}
	defer f.Close()
	fi, _ := f.Stat()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s.fcz"`, sanitizeFilename(caseID)))
	if fi != nil {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", fi.Size()))
	}
	if _, err := io.Copy(w, f); err != nil {
		// Best-effort — header already sent.
		return
	}
}

// handleCaseImport accepts a multipart upload of a .fcz file.
// Body: multipart/form-data with one file field named "file".
// Query params:
//   - overwrite=true to replace existing case rows + workspace
//   - force=true to ignore SHA-256 mismatches
func (s *Server) handleCaseImport(w http.ResponseWriter, r *http.Request) {
	overwrite := r.URL.Query().Get("overwrite") == "true"
	force := r.URL.Query().Get("force") == "true"

	// 5 GiB cap — a real case can be huge once findings + reports are
	// included, but anything above this is almost certainly user error.
	if err := r.ParseMultipartForm(5 << 30); err != nil {
		writeError(w, 400, "parse multipart: %v", err)
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, 400, "missing file field: %v", err)
		return
	}
	defer file.Close()

	tmp, err := os.CreateTemp("", "tlvb-upload-*.fcz")
	if err != nil {
		writeError(w, 500, "tempfile: %v", err)
		return
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := io.Copy(tmp, file); err != nil {
		tmp.Close()
		writeError(w, 500, "save upload: %v", err)
		return
	}
	tmp.Close()

	var rep *exporter.ImportReport
	err = s.withDB(casedb.ReadWrite, func(m *casedb.Manager) error {
		r2, e := exporter.Import(context.Background(), m, exporter.ImportOptions{
			InputPath:   tmpPath,
			OutputsRoot: s.cfg.OutputsRoot,
			DBPath:      s.cfg.DBPath,
			Overwrite:   overwrite,
			Force:       force,
		})
		rep = r2
		return e
	})
	if err != nil {
		writeError(w, 400, "import: %v", err)
		return
	}
	writeJSON(w, 200, rep)
}

// sanitizeFilename keeps the case_id usable in Content-Disposition. We
// strip any character that isn't alphanumeric / dash / underscore /
// period — that covers the common case_id naming convention
// (INC-2026-0001) without letting "../" or stray quotes through.
func sanitizeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	if out == "" {
		out = "case"
	}
	return out
}

// (placeholder used by linter — keeps filepath import live when build
// tags strip code paths.)
var _ = filepath.Join
