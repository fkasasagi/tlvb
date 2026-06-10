package evidencex

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
)

// RequestedFile is one file an analysis agent asked to inspect. Path may be a
// Windows path (C:\...) or NTFS-relative; EvidenceID is optional and only
// needed to disambiguate when a case bundles more than one disk image.
type RequestedFile struct {
	Path       string `json:"path"`
	EvidenceID string `json:"evidence_id,omitempty"`
	Rationale  string `json:"rationale,omitempty"`
}

// RoundConfig parameterises one fetch+preview round.
type RoundConfig struct {
	Config     // PythonBin / RepoDir / Timeout
	CaseID     string
	OutBaseDir string      // e.g. outputs/cases/<id>/extractions/on-demand
	MaxFiles   int         // cap on files fetched per round (default 8)
	Caps       PreviewCaps // preview size bounds (default DefaultCaps)
}

// RoundResult carries everything the caller needs: the text block to append to
// the next LLM message, the per-file previews, and the raw manifests for audit.
type RoundResult struct {
	PreviewBlock string
	Previews     []FilePreview
	Manifests    []*Manifest
	UsedImages   []string
	Available    bool // false when the case has no mountable image evidence
}

// RunRound resolves the case's image evidence, fetches the requested files
// (one mount per image), and builds a preview block. db is an open cases.duckdb
// handle. Returns Available=false (and a nil-ish result) when there is no
// mountable image — the caller should then skip the second analysis pass.
func RunRound(ctx context.Context, db *sql.DB, rc RoundConfig, requested []RequestedFile) (*RoundResult, error) {
	if rc.MaxFiles <= 0 {
		rc.MaxFiles = 8
	}
	if rc.Caps == (PreviewCaps{}) {
		rc.Caps = DefaultCaps()
	}

	images, err := ListImageEvidence(ctx, db, rc.CaseID)
	if err != nil {
		return nil, err
	}
	if len(images) == 0 {
		return &RoundResult{Available: false}, nil
	}

	// Dedupe (evidence,path) and cap the total. Group targets per image so we
	// mount each image at most once.
	byEvidence := map[string][]string{}
	order := []string{} // preserve image order for stable output
	seen := map[string]bool{}
	defaultImg := images[0].EvidenceID
	imgByID := map[string]ImageEvidence{}
	for _, im := range images {
		imgByID[im.EvidenceID] = im
	}
	count := 0
	for _, rf := range requested {
		if count >= rc.MaxFiles {
			break
		}
		path := strings.TrimSpace(rf.Path)
		if path == "" {
			continue
		}
		evID := rf.EvidenceID
		if _, ok := imgByID[evID]; !ok {
			evID = defaultImg // unknown / unspecified → the sole/first image
		}
		key := evID + "\x00" + path
		if seen[key] {
			continue
		}
		seen[key] = true
		if _, ok := byEvidence[evID]; !ok {
			order = append(order, evID)
		}
		byEvidence[evID] = append(byEvidence[evID], path)
		count++
	}

	res := &RoundResult{Available: true}
	var previews []FilePreview
	for _, evID := range order {
		im := imgByID[evID]
		outDir := filepath.Join(rc.OutBaseDir, sanitizeID(evID))
		m, ferr := Fetch(ctx, rc.Config, im.Path, evID, outDir, byEvidence[evID])
		if ferr != nil {
			// Harness-level failure for this image: synthesise missing previews
			// so the agent learns the fetch failed rather than silently dropping.
			for _, t := range byEvidence[evID] {
				previews = append(previews, FilePreview{
					Target: t, Status: "fail", Kind: "missing",
					Note: "extraction failed: " + ferr.Error(),
				})
			}
			continue
		}
		res.Manifests = append(res.Manifests, m)
		res.UsedImages = append(res.UsedImages, im.Path)
		if m.Error != "" {
			for _, t := range byEvidence[evID] {
				previews = append(previews, FilePreview{
					Target: t, Status: "fail", Kind: "missing",
					Note: "image not mountable: " + m.Error,
				})
			}
			continue
		}
		for _, r := range m.Results {
			previews = append(previews, Preview(r, rc.Caps))
		}
	}
	res.Previews = previews
	res.PreviewBlock = BuildPreviewBlock(previews)
	return res, nil
}

func sanitizeID(s string) string {
	if s == "" {
		return "default"
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// FetchSummary is a compact per-file audit record for actions.jsonl / reports.
type FetchSummary struct {
	Target        string `json:"target"`
	Status        string `json:"status"`
	Bytes         int64  `json:"bytes,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	ExtractedPath string `json:"extracted_path,omitempty"`
	Error         string `json:"error,omitempty"`
}

// Summaries flattens the round's manifests into audit records.
func (r *RoundResult) Summaries() []FetchSummary {
	var out []FetchSummary
	for _, m := range r.Manifests {
		for _, fr := range m.Results {
			out = append(out, FetchSummary{
				Target: fr.Target, Status: fr.Status, Bytes: fr.Bytes,
				SHA256: fr.SHA256, ExtractedPath: fr.ExtractedPath, Error: fr.Error,
			})
		}
	}
	return out
}
