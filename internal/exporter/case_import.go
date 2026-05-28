package exporter

import (
	"archive/tar"
	"bufio"
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

	"github.com/tlvb/tlvb/internal/casedb"
)

// ImportOptions: knobs for unpacking + verifying + loading a .fcz.
//
// `Overwrite=false` means import aborts if the case_id already exists.
// `Force=false` means import aborts on any SHA-256 mismatch.
type ImportOptions struct {
	InputPath   string  // .fcz tarball
	OutputsRoot string  // outputs/cases — workspace will be written under <OutputsRoot>/<CaseID>/
	DBPath      string  // DuckDB
	Overwrite   bool    // replace existing case (DELETE rows + clear workspace) before importing
	Force       bool    // proceed even if a payload hash doesn't match the manifest
}

// ImportReport summarizes what was imported. The CLI prints it back to
// stdout so operators have a single-line audit trail.
type ImportReport struct {
	CaseID         string         `json:"case_id"`
	Schema         string         `json:"schema"`
	WorkspaceFiles int            `json:"workspace_files"`
	RowCounts      map[string]int `json:"row_counts"`
	Verified       int            `json:"sha256_verified"`
	Mismatched     int            `json:"sha256_mismatched"`
	Overwritten    bool           `json:"overwritten"`
}

// Import reads a .fcz, verifies integrity, and loads rows + workspace
// into the target environment.
//
// Steps:
//  1. Unpack the tarball into a temp dir.
//  2. Read manifest.json; verify schema version + recompute every
//     payload SHA-256.
//  3. If the case already exists and !Overwrite → abort.
//     If Overwrite → DELETE rows + RemoveAll workspace.
//  4. Insert rows (case, evidence, parse_results, unified_events).
//  5. Move workspace/ into <OutputsRoot>/<CaseID>/.
func Import(ctx context.Context, mgr *casedb.Manager, opt ImportOptions) (*ImportReport, error) {
	if opt.InputPath == "" {
		return nil, errors.New("import: --in is required")
	}
	if opt.OutputsRoot == "" {
		opt.OutputsRoot = filepath.Join("outputs", "cases")
	}

	staging, err := os.MkdirTemp("", "tlvb-import-")
	if err != nil {
		return nil, fmt.Errorf("import: tempdir: %w", err)
	}
	defer os.RemoveAll(staging)

	if err := untarGz(opt.InputPath, staging); err != nil {
		return nil, fmt.Errorf("import: untar: %w", err)
	}

	// Tarball root layout: <case_id>/manifest.json + ...
	caseDir, err := findCaseDir(staging)
	if err != nil {
		return nil, err
	}

	// ---- manifest ----------------------------------------------------
	var manifest Manifest
	mf, err := os.Open(filepath.Join(caseDir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("import: open manifest: %w", err)
	}
	if err := json.NewDecoder(mf).Decode(&manifest); err != nil {
		mf.Close()
		return nil, fmt.Errorf("import: decode manifest: %w", err)
	}
	mf.Close()
	if manifest.Schema != ManifestSchema {
		return nil, fmt.Errorf("import: schema %q not supported (expected %q)",
			manifest.Schema, ManifestSchema)
	}
	if manifest.CaseID == "" {
		return nil, errors.New("import: manifest missing case_id")
	}

	// ---- verify SHA-256 ----------------------------------------------
	verified, mismatched := 0, 0
	for _, fe := range manifest.Files {
		p := filepath.Join(caseDir, filepath.FromSlash(fe.Path))
		h, err := sha256File(p)
		if err != nil {
			return nil, fmt.Errorf("import: hash %s: %w", fe.Path, err)
		}
		if h == fe.SHA256 {
			verified++
		} else {
			mismatched++
			if !opt.Force {
				return nil, fmt.Errorf(
					"import: sha256 mismatch on %s (got %s want %s); rerun with --force to ignore",
					fe.Path, h, fe.SHA256)
			}
		}
	}

	// ---- handle existing case ----------------------------------------
	existing, _ := mgr.GetCaseStatus(ctx, manifest.CaseID)
	overwritten := false
	if existing != nil {
		if !opt.Overwrite {
			return nil, fmt.Errorf(
				"import: case %q already exists; rerun with --overwrite to replace",
				manifest.CaseID)
		}
		if err := mgr.DeleteCaseRows(ctx, manifest.CaseID); err != nil {
			return nil, fmt.Errorf("import: delete existing rows: %w", err)
		}
		wsPath := filepath.Join(opt.OutputsRoot, manifest.CaseID)
		if err := os.RemoveAll(wsPath); err != nil {
			return nil, fmt.Errorf("import: clear existing workspace: %w", err)
		}
		overwritten = true
	}

	// ---- insert rows -------------------------------------------------
	if err := insertCaseRow(ctx, mgr, caseDir); err != nil {
		return nil, fmt.Errorf("import: case row: %w", err)
	}
	if err := insertEvidence(ctx, mgr, caseDir); err != nil {
		return nil, fmt.Errorf("import: evidence rows: %w", err)
	}
	if err := insertParseResults(ctx, mgr, caseDir); err != nil {
		return nil, fmt.Errorf("import: parse_results: %w", err)
	}
	if err := insertUnifiedEvents(ctx, mgr, caseDir); err != nil {
		return nil, fmt.Errorf("import: unified_events: %w", err)
	}

	// ---- workspace ---------------------------------------------------
	wsSrc := filepath.Join(caseDir, "workspace")
	wsDst := filepath.Join(opt.OutputsRoot, manifest.CaseID)
	if fi, err := os.Stat(wsSrc); err == nil && fi.IsDir() {
		if err := os.MkdirAll(filepath.Dir(wsDst), 0o755); err != nil {
			return nil, fmt.Errorf("import: mkdir outputs: %w", err)
		}
		// We copy (not rename) because staging may be on a different
		// filesystem than OutputsRoot.
		if err := copyDir(wsSrc, wsDst); err != nil {
			return nil, fmt.Errorf("import: copy workspace: %w", err)
		}
	}

	return &ImportReport{
		CaseID:         manifest.CaseID,
		Schema:         manifest.Schema,
		WorkspaceFiles: manifest.WorkspaceFiles,
		RowCounts:      manifest.RowCounts,
		Verified:       verified,
		Mismatched:     mismatched,
		Overwritten:    overwritten,
	}, nil
}

// ----------------------------------------------------------------------
// Insertion paths — read JSONL files staged from the tarball, push to
// the casedb manager via the bulk-insert helpers.
// ----------------------------------------------------------------------

func insertCaseRow(ctx context.Context, mgr *casedb.Manager, caseDir string) error {
	body, err := os.ReadFile(filepath.Join(caseDir, "case.json"))
	if err != nil {
		return err
	}
	var c casedb.CaseRow
	if err := json.Unmarshal(body, &c); err != nil {
		return err
	}
	return mgr.RegisterCase(ctx, c)
}

func insertEvidence(ctx context.Context, mgr *casedb.Manager, caseDir string) error {
	rows, err := readJSONL[casedb.EvidenceRow](filepath.Join(caseDir, "evidence.jsonl"))
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	return mgr.BulkInsertEvidence(ctx, rows)
}

func insertParseResults(ctx context.Context, mgr *casedb.Manager, caseDir string) error {
	rows, err := readJSONL[casedb.ParseResultRow](filepath.Join(caseDir, "parse_results.jsonl"))
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	return mgr.BulkInsertParseResults(ctx, rows)
}

func insertUnifiedEvents(ctx context.Context, mgr *casedb.Manager, caseDir string) error {
	// Stream in batches so a million-row case doesn't OOM the importer.
	path := filepath.Join(caseDir, "unified_events.jsonl")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	const batchSize = 5000
	batch := make([]casedb.UnifiedEventRow, 0, batchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := mgr.BulkInsertUnifiedEvents(ctx, batch); err != nil {
			return err
		}
		batch = batch[:0]
		return nil
	}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r casedb.UnifiedEventRow
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return fmt.Errorf("unified_events.jsonl: %w", err)
		}
		batch = append(batch, r)
		if len(batch) >= batchSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return flush()
}

// readJSONL parses every newline-delimited JSON record into a slice of
// T. Used for small / bounded row sets (case, evidence, parse_results).
func readJSONL[T any](path string) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	var out []T
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var v T
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, sc.Err()
}

// ----------------------------------------------------------------------
// Tar / hash / copy helpers
// ----------------------------------------------------------------------

func untarGz(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		// Path safety: reject "../" / absolute / symlinks.
		clean := filepath.Clean(hdr.Name)
		if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") ||
			strings.Contains(clean, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("untar: unsafe member %q", hdr.Name)
		}
		target := filepath.Join(dst, clean)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		default:
			// Skip symlinks, hardlinks, device nodes — they're a
			// security risk and TLVB never produces them.
		}
	}
}

func findCaseDir(root string) (string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}
	// Find the single top-level directory under root.
	var dir string
	for _, e := range entries {
		if e.IsDir() {
			if dir != "" {
				return "", fmt.Errorf("import: tarball has multiple top-level dirs")
			}
			dir = e.Name()
		}
	}
	if dir == "" {
		return "", errors.New("import: tarball has no case directory")
	}
	return filepath.Join(root, dir), nil
}

func sha256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return copyFile(p, target)
	})
}
