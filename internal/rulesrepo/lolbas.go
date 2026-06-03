package rulesrepo

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LOLBASLoader walks rules/lolbas/upstream/yml/**.yml — the LOLBAS-Project
// catalogue of Living-Off-The-Land binaries/scripts. Each YAML describes one
// abusable Windows binary (Name) with example Commands, each carrying a
// MitreID. Unlike Sigma these are not detection rules; the build pipeline's
// LLM turns each entry into SQL that flags the binary's abusive invocation in
// process-creation (EVTX 4688) events.
//
// rule_source = "lolbas" — extends the documented {sigma,hayabusa,stix,custom}
// set with a forensic LOLBin catalogue. LOLBAS has no upstream UUID, so the
// binary Name (e.g. "Certutil.exe") is used as rule_id.
type LOLBASLoader struct {
	// Root is the yml/ subdir, NOT the submodule top — keeps Archive-Old-Version
	// and docs out of the corpus. Typically "rules/lolbas/upstream/yml".
	Root string
}

// NewLOLBASLoader returns a loader rooted at rules/lolbas/upstream/yml.
func NewLOLBASLoader(root string) *LOLBASLoader { return &LOLBASLoader{Root: root} }

func (l *LOLBASLoader) Source() string { return "lolbas" }

type lolbasCommand struct {
	Command     string `yaml:"Command"`
	Description string `yaml:"Description"`
	Usecase     string `yaml:"Usecase"`
	Category    string `yaml:"Category"`
	MitreID     string `yaml:"MitreID"`
}

type lolbasDoc struct {
	Name        string          `yaml:"Name"`
	Description string          `yaml:"Description"`
	Commands    []lolbasCommand `yaml:"Commands"`
}

func (l *LOLBASLoader) LoadAll(ctx context.Context) ([]RawRule, error) {
	if l.Root == "" {
		return nil, fmt.Errorf("LOLBASLoader.Root is empty")
	}
	if _, err := os.Stat(l.Root); err != nil {
		return nil, fmt.Errorf("lolbas root %q: %w", l.Root, err)
	}

	var out []RawRule
	err := filepath.WalkDir(l.Root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".yml") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			out = append(out, RawRule{
				RuleSource: "lolbas", SourcePath: relPath(l.Root, path),
				Skip: true, SkipReason: fmt.Sprintf("read error: %v", err),
			})
			return nil
		}
		var doc lolbasDoc
		if err := yaml.Unmarshal(content, &doc); err != nil || strings.TrimSpace(doc.Name) == "" {
			out = append(out, RawRule{
				RuleSource: "lolbas", SourcePath: relPath(l.Root, path),
				Skip: true, SkipReason: "parse error or missing Name",
			})
			return nil
		}

		// Distinct MITRE techniques across the binary's example commands.
		seen := map[string]bool{}
		var techs []string
		for _, c := range doc.Commands {
			t := strings.TrimSpace(c.MitreID)
			if t == "" || seen[t] {
				continue
			}
			seen[t] = true
			techs = append(techs, t)
		}

		out = append(out, RawRule{
			RuleID:             strings.TrimSpace(doc.Name), // no UUID upstream — name is the id
			RuleSource:         "lolbas",
			RuleSHA256:         sha256Hex(content),
			SourcePath:         relPath(l.Root, path),
			PrefilterArtifacts: []string{"evtx"}, // LOLBin abuse surfaces in 4688 process creation
			Title:              strings.TrimSpace(doc.Name),
			Description:        strings.TrimSpace(doc.Description),
			Level:              "medium", // a LOLBin invocation is a medium-severity signal by default
			MITRETechniques:    techs,
			RawContent:         string(content),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
