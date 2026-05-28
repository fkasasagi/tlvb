// Package exporter implements case-level export / import for portability
// across hosts (Issue #16 / DESIGN v0.4 REQ-2).
//
// On the wire a case is a single gzipped tarball with the conventional
// extension ".fcz" (TLVB Case). Inside, the layout is:
//
//	<case_id>/
//	├── manifest.json           — schema, row counts, sha256 of every file
//	├── case.json               — single CaseRow
//	├── evidence.jsonl          — N EvidenceRow rows
//	├── parse_results.jsonl     — N ParseResultRow rows
//	├── unified_events.jsonl    — case-scoped unified_events
//	└── workspace/              — outputs/cases/<id>/ tree (workspace files
//	                              only; findings/, reports/, parse_review.json,
//	                              actions.jsonl all included as-is)
//
// Integrity guarantee: every payload file's SHA-256 is in manifest.files.
// Import re-hashes each file and aborts on mismatch unless --force is set.
//
// Scope deliberately excludes:
//   - encryption / signing (future work)
//   - the raw collected evidence archives (huge; opt-in via IncludeEvidence)
//   - DuckDB row export from tables TLVB doesn't own (none today)
package exporter

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/casedb"
)

// ManifestSchema is the canonical schema id for the .fcz manifest.
// Bump on any breaking change to the file layout or field semantics.
const ManifestSchema = "tlvb/case-export/v1"

// FileEntry records one payload file's identity in the manifest. Used
// for integrity verification on import.
type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type Manifest struct {
	Schema           string         `json:"schema"`
	CaseID           string         `json:"case_id"`
	ExportedAt       time.Time      `json:"exported_at"`
	ExportedBy       string         `json:"exported_by,omitempty"`
	TLVBVersion  string         `json:"tlvb_version,omitempty"`
	IncludeEvidence  bool           `json:"include_evidence"`
	WorkspaceFiles   int            `json:"workspace_files"`
	RowCounts        map[string]int `json:"row_counts"`
	Files            []FileEntry    `json:"files"`
}

// ExportOptions bundles the knobs the caller passes through. Each is
// optional; defaults match the doc-comment expectations.
type ExportOptions struct {
	CaseID          string
	OutputsRoot     string  // outputs/cases — workspace lives at <OutputsRoot>/<CaseID>/
	DBPath          string  // DuckDB path for case rows
	OutputPath      string  // where to write the .fcz tarball
	IncludeEvidence bool    // also include extractions/ (large)
	ExportedBy      string  // e.g. "operator@host"; defaults to $USER@$HOSTNAME
	TLVBVersion string  // optional build-stamp
}

// Export builds a .fcz tarball describing the case. Returns the
// generated manifest so callers can render a summary.
func Export(ctx context.Context, mgr *casedb.Manager, opt ExportOptions) (*Manifest, error) {
	if opt.CaseID == "" {
		return nil, errors.New("export: --case-id is required")
	}
	if opt.OutputPath == "" {
		return nil, errors.New("export: --out is required")
	}
	if opt.OutputsRoot == "" {
		opt.OutputsRoot = filepath.Join("outputs", "cases")
	}
	if opt.ExportedBy == "" {
		opt.ExportedBy = defaultExportedBy()
	}

	// Build a temp working dir so we can stage files, hash them, and
	// finally tar them up in a single pass.
	staging, err := os.MkdirTemp("", "tlvb-export-")
	if err != nil {
		return nil, fmt.Errorf("export: tempdir: %w", err)
	}
	defer os.RemoveAll(staging)

	caseDir := filepath.Join(staging, opt.CaseID)
	if err := os.MkdirAll(caseDir, 0o755); err != nil {
		return nil, fmt.Errorf("export: mkdir %s: %w", caseDir, err)
	}

	rc := map[string]int{}

	// ---- case row -----------------------------------------------------
	st, err := mgr.GetCaseStatus(ctx, opt.CaseID)
	if err != nil {
		return nil, fmt.Errorf("export: get case: %w", err)
	}
	if err := writeJSON(filepath.Join(caseDir, "case.json"), st.Case); err != nil {
		return nil, err
	}
	rc["case"] = 1

	// ---- evidence rows -----------------------------------------------
	evs, err := mgr.ListEvidence(ctx, opt.CaseID)
	if err != nil {
		return nil, fmt.Errorf("export: list evidence: %w", err)
	}
	if err := writeJSONL(filepath.Join(caseDir, "evidence.jsonl"), evs); err != nil {
		return nil, err
	}
	rc["evidence"] = len(evs)

	// ---- parse_results -----------------------------------------------
	prs := st.ParseResults
	if err := writeJSONL(filepath.Join(caseDir, "parse_results.jsonl"), prs); err != nil {
		return nil, err
	}
	rc["parse_results"] = len(prs)

	// ---- unified_events ----------------------------------------------
	uePath := filepath.Join(caseDir, "unified_events.jsonl")
	n, err := dumpUnifiedEvents(ctx, mgr, opt.CaseID, uePath)
	if err != nil {
		return nil, fmt.Errorf("export: dump unified_events: %w", err)
	}
	rc["unified_events"] = n

	// ---- workspace tree ----------------------------------------------
	wsSrc := filepath.Join(opt.OutputsRoot, opt.CaseID)
	wsDst := filepath.Join(caseDir, "workspace")
	wsFiles := 0
	if fi, err := os.Stat(wsSrc); err == nil && fi.IsDir() {
		wsFiles, err = copyWorkspace(wsSrc, wsDst, opt.IncludeEvidence)
		if err != nil {
			return nil, fmt.Errorf("export: copy workspace: %w", err)
		}
	}

	// ---- manifest (after staging is final, so SHA-256 covers everything) ----
	files, err := hashTree(caseDir)
	if err != nil {
		return nil, fmt.Errorf("export: hash tree: %w", err)
	}
	manifest := &Manifest{
		Schema:          ManifestSchema,
		CaseID:          opt.CaseID,
		ExportedAt:      time.Now().UTC(),
		ExportedBy:      opt.ExportedBy,
		TLVBVersion: opt.TLVBVersion,
		IncludeEvidence: opt.IncludeEvidence,
		WorkspaceFiles:  wsFiles,
		RowCounts:       rc,
		Files:           files,
	}
	if err := writeJSON(filepath.Join(caseDir, "manifest.json"), manifest); err != nil {
		return nil, err
	}

	// ---- tar.gz the staging dir --------------------------------------
	if err := os.MkdirAll(filepath.Dir(opt.OutputPath), 0o755); err != nil {
		return nil, fmt.Errorf("export: mkdir output: %w", err)
	}
	if err := tarGzDir(staging, opt.OutputPath); err != nil {
		return nil, fmt.Errorf("export: tar.gz: %w", err)
	}
	return manifest, nil
}

// ----------------------------------------------------------------------
// Helpers — kept unexported so the surface area stays minimal.
// ----------------------------------------------------------------------

func writeJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func writeJSONL(path string, rows any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	// We accept any slice type — encode each element on its own line.
	// Reflection is overkill for the handful of row shapes we have;
	// the caller hands us a concrete []T, so json.Encoder works.
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	switch xs := rows.(type) {
	case []casedb.EvidenceRow:
		for _, r := range xs {
			if err := enc.Encode(r); err != nil {
				return err
			}
		}
	case []casedb.ParseResultRow:
		for _, r := range xs {
			if err := enc.Encode(r); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("writeJSONL: unsupported row type %T", rows)
	}
	return nil
}

// dumpUnifiedEvents streams the case-scoped rows out. We do not load
// the whole result into memory because a real case can have millions
// of rows.
func dumpUnifiedEvents(ctx context.Context, mgr *casedb.Manager, caseID, path string) (int, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)

	const pageSize = 5000
	offset := 0
	total := 0
	for {
		evs, err := mgr.QueryUnifiedEvents(ctx, casedb.UnifiedEventQuery{
			CaseID: caseID, Limit: pageSize, Offset: offset,
		})
		if err != nil {
			return total, err
		}
		if len(evs) == 0 {
			break
		}
		for _, e := range evs {
			if err := enc.Encode(e); err != nil {
				return total, err
			}
		}
		total += len(evs)
		offset += pageSize
		if len(evs) < pageSize {
			break
		}
	}
	return total, nil
}

// copyWorkspace walks the case workspace dir and copies each file under
// dst preserving the relative layout. When include_evidence=false the
// `extractions/` subtree is omitted (it can be many GiB and is fully
// reproducible from the parsers).
func copyWorkspace(src, dst string, includeEvidence bool) (int, error) {
	count := 0
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		// Skip extractions/ unless include_evidence is set.
		if !includeEvidence {
			top := strings.SplitN(rel, string(os.PathSeparator), 2)[0]
			if top == "extractions" {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := copyFile(p, target); err != nil {
			return err
		}
		count++
		return nil
	})
	return count, err
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// hashTree walks the staged case dir and computes SHA-256 for every
// payload file. The manifest itself is created after this call so it
// isn't in the list (the importer recomputes hashes against the
// manifest, so including the manifest in itself is impossible by
// construction).
func hashTree(root string) ([]FileEntry, error) {
	var out []FileEntry
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		// Skip the manifest itself (added later by writeJSON).
		if filepath.Base(rel) == "manifest.json" && filepath.Dir(rel) != "." {
			// Won't happen with current layout but be defensive.
			return nil
		}
		h := sha256.New()
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			return err
		}
		out = append(out, FileEntry{
			Path:   filepath.ToSlash(rel),
			SHA256: hex.EncodeToString(h.Sum(nil)),
			Bytes:  info.Size(),
		})
		return nil
	})
	return out, err
}

// tarGzDir bundles every file under root into a gzip+tar at out.
func tarGzDir(root, out string) error {
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	return filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if rel == "." {
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			in, err := os.Open(p)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(tw, in)
			in.Close()
			if copyErr != nil {
				return copyErr
			}
		}
		return nil
	})
}

func defaultExportedBy() string {
	user := os.Getenv("USER")
	if user == "" {
		user = "unknown"
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "host"
	}
	return user + "@" + host
}
