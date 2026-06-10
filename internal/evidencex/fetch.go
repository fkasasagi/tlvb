// Package evidencex provides on-demand extraction of arbitrary files from a
// case's forensic disk image, so the Tier 1B / Tier 2 analysis agents can
// inspect a file's *contents* — not just its normalized event in
// unified_events — when their reasoning calls for it.
//
// The actual mount + carve is delegated to parsers/evidence_fetch.py (which
// reuses image_extractor's read-only mount primitives); this package resolves
// which image to mount, invokes that CLI, and turns the extracted bytes into a
// bounded, LLM-friendly preview block for a second analysis pass.
//
// Design constraints (mirroring CLAUDE.md):
//   - read-only by construction — the Python side mounts read-only and never
//     touches the original; this package only reads back what it produced.
//   - bounded — callers cap the number of files and the preview size so a
//     stray request can't blow up prompt cost or wall-clock.
//   - graceful degradation — a mount failure / missing image returns a
//     manifest with Error set and empty Results; the analysis run continues.
package evidencex

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// FileResult is one extracted (or attempted) file in a Manifest.
type FileResult struct {
	Target        string `json:"target"`         // the path the agent requested, verbatim
	NTFSPath      string `json:"ntfs_path"`      // normalised NTFS-relative path
	Status        string `json:"status"`         // ok | not_found | fail | skip
	Partition     *int   `json:"partition"`      // volume index it was found in
	Inum          string `json:"inum"`           // MFT inode string
	SHA256        string `json:"sha256"`         // of the extracted bytes
	Bytes         int64  `json:"bytes"`          // extracted size
	ExtractedPath string `json:"extracted_path"` // where the copy was written
	Error         string `json:"error"`          // populated on fail/skip
}

// Manifest is the JSON the Python CLI emits for one fetch request.
type Manifest struct {
	ImagePath   string       `json:"image_path"`
	ImageFormat string       `json:"image_format"`
	MountMethod string       `json:"mount_method"`
	OutDir      string       `json:"out_dir"`
	Error       string       `json:"error"` // top-level failure (not an image / mount failed)
	Results     []FileResult `json:"results"`
}

// Config locates the Python interpreter + module root and bounds the run.
type Config struct {
	PythonBin string        // resolved interpreter (common.ResolvePython())
	RepoDir   string        // dir from which `python -m parsers.evidence_fetch` imports
	Timeout   time.Duration // overall wall-clock budget for the whole request
}

// ImageEvidence is one disk-image evidence row eligible for on-demand fetch.
type ImageEvidence struct {
	EvidenceID string
	Path       string
	Type       string
}

// imageExts mirrors image_extractor._IMAGE_EXTENSIONS so we only offer fetch
// for evidence we can actually mount (a triage zip can't be re-mounted here).
var imageExts = map[string]bool{
	".e01": true, ".ex01": true, ".s01": true, ".l01": true,
	".raw": true, ".dd": true, ".img": true, ".001": true,
	".vmdk": true, ".vhd": true, ".vhdx": true,
}

// ListImageEvidence returns the case's evidence rows that are mountable disk
// images. db is an already-open cases.duckdb handle (read-only is fine).
func ListImageEvidence(ctx context.Context, db *sql.DB, caseID string) ([]ImageEvidence, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT evidence_id, path, COALESCE(evidence_type, '') FROM evidence WHERE case_id = ?`,
		caseID)
	if err != nil {
		return nil, fmt.Errorf("query evidence: %w", err)
	}
	defer rows.Close()
	var out []ImageEvidence
	for rows.Next() {
		var e ImageEvidence
		if err := rows.Scan(&e.EvidenceID, &e.Path, &e.Type); err != nil {
			return nil, err
		}
		ext := strings.ToLower(filepath.Ext(e.Path))
		if imageExts[ext] || strings.EqualFold(e.Type, "image") {
			out = append(out, e)
		}
	}
	return out, rows.Err()
}

// Fetch mounts imagePath and extracts each target once, returning the manifest.
// A non-nil error is only returned for harness-level problems (couldn't launch
// Python, unparseable output); per-target misses and mount failures are carried
// in the returned Manifest so the caller degrades gracefully.
func Fetch(ctx context.Context, cfg Config, imagePath, evidenceID, outDir string, targets []string) (*Manifest, error) {
	if cfg.PythonBin == "" {
		cfg.PythonBin = "python3"
	}
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}

	args := []string{"-m", "parsers.evidence_fetch", "--image", imagePath, "--out", outDir}
	if evidenceID != "" {
		args = append(args, "--evidence-id", evidenceID)
	}
	// Per-target TSK timeout: a slice of the overall budget, floored so a
	// single slow icat doesn't starve the rest.
	perTarget := 600
	if cfg.Timeout > 0 {
		if s := int(cfg.Timeout.Seconds()); s > 0 {
			perTarget = s
		}
	}
	args = append(args, "--timeout", strconv.Itoa(perTarget))
	for _, t := range targets {
		if strings.TrimSpace(t) == "" {
			continue
		}
		args = append(args, "--target", t)
	}

	cmd := exec.CommandContext(ctx, cfg.PythonBin, args...)
	cmd.Dir = cfg.RepoDir
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		tail := stderr.String()
		if len(tail) > 400 {
			tail = tail[len(tail)-400:]
		}
		return nil, fmt.Errorf("evidence_fetch: %w (stderr: %s)", err, tail)
	}
	var m Manifest
	if err := json.Unmarshal([]byte(stdout.String()), &m); err != nil {
		head := stdout.String()
		if len(head) > 240 {
			head = head[:240] + "..."
		}
		return nil, fmt.Errorf("parse manifest: %w (head: %s)", err, head)
	}
	return &m, nil
}
