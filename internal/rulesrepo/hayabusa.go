package rulesrepo

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// HayabusaLoader walks rules/hayabusa/upstream/hayabusa/**.yml.
//
// The upstream Hayabusa repo also contains rules/hayabusa/upstream/sigma/
// which is a vendored copy of SigmaHQ/sigma with Hayabusa patches. We
// intentionally do NOT load that subtree to avoid double-counting against
// the SigmaHQ submodule we already loaded. If a divergence between
// Hayabusa's Sigma patches and upstream Sigma proves to matter for
// detection quality, we can revisit this decision.
type HayabusaLoader struct {
	// Root is the path to the hayabusa/ subdir, NOT the top of the submodule.
	// Typically "rules/hayabusa/upstream/hayabusa".
	Root              string
	IncludeSysmon     bool
	IncludeNonWindows bool
}

// NewHayabusaLoader returns a loader rooted at rules/hayabusa/upstream/hayabusa
// with the TLVB defaults (Sysmon off, Windows only).
func NewHayabusaLoader(root string) *HayabusaLoader {
	return &HayabusaLoader{Root: root}
}

func (l *HayabusaLoader) Source() string { return "hayabusa" }

func (l *HayabusaLoader) LoadAll(ctx context.Context) ([]RawRule, error) {
	if l.Root == "" {
		return nil, fmt.Errorf("HayabusaLoader.Root is empty")
	}
	if _, err := os.Stat(l.Root); err != nil {
		return nil, fmt.Errorf("hayabusa root %q: %w", l.Root, err)
	}

	var out []RawRule
	err := filepath.WalkDir(l.Root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".yml") {
			return nil
		}
		rule, ok, err := loadSigmaStyleYAML(path, l.Root, "hayabusa", l.IncludeSysmon, l.IncludeNonWindows)
		if err != nil {
			out = append(out, RawRule{
				RuleSource: "hayabusa",
				SourcePath: relPath(l.Root, path),
				Skip:       true,
				SkipReason: fmt.Sprintf("parse error: %v", err),
			})
			return nil
		}
		if !ok {
			return nil
		}
		out = append(out, rule)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
