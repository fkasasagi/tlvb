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

// ForensicLoader walks rules/forensic/**.yml — TLVB's own catalogue of
// detections over Windows FORENSIC EXECUTION ARTIFACTS (Prefetch, Amcache,
// registry UserAssist/AppCompat, ShimCache, $MFT, browser history). These
// artifacts record that a binary ran / was present / was downloaded
// INDEPENDENTLY of Security 4688 + Sysmon, so they catch execution on hosts
// where process-creation auditing is off — exactly the gap that let case_R's
// browser-delivered niceeditor.exe (run from Downloads) slip past Tier 1A,
// since the entire Sigma/Hayabusa corpus only ever queries EVTX.
//
// Unlike Sigma these are not log-source detections: each YAML states a
// detection INTENT (which artifacts, which fields, which paths) and the build
// pipeline's LLM turns it into one DuckDB SELECT over unified_events, guided by
// the per-artifact field docs + recommended SQL in casedb.SchemaDoc().
//
// rule_source = "forensic" — extends the {sigma,hayabusa,stix,custom,lolbas}
// set. rule_id is the human-authored `id:` field (no upstream UUID exists).
// The rule's `artifacts:` list becomes PrefilterArtifacts, which feeds
// casedb.SchemaVersionFor so a rule's cache key folds in ONLY the schema
// sections for the artifacts it actually targets.
type ForensicLoader struct {
	// Root is the forensic rules dir, typically "rules/forensic".
	Root string
}

// NewForensicLoader returns a loader rooted at rules/forensic.
func NewForensicLoader(root string) *ForensicLoader { return &ForensicLoader{Root: root} }

func (l *ForensicLoader) Source() string { return "forensic" }

type forensicMITRE struct {
	Tactics    []string `yaml:"tactics"`
	Techniques []string `yaml:"techniques"`
}

type forensicDoc struct {
	ID          string        `yaml:"id"`
	Title       string        `yaml:"title"`
	Level       string        `yaml:"level"`
	Description string        `yaml:"description"`
	Detection   string        `yaml:"detection"`
	Artifacts   []string      `yaml:"artifacts"`
	MITRE       forensicMITRE `yaml:"mitre"`
	References  []string      `yaml:"references"`
}

func (l *ForensicLoader) LoadAll(ctx context.Context) ([]RawRule, error) {
	if l.Root == "" {
		return nil, fmt.Errorf("ForensicLoader.Root is empty")
	}
	if _, err := os.Stat(l.Root); err != nil {
		return nil, fmt.Errorf("forensic root %q: %w", l.Root, err)
	}

	var out []RawRule
	err := filepath.WalkDir(l.Root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		name := strings.ToLower(d.Name())
		if d.IsDir() || !(strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			out = append(out, RawRule{
				RuleSource: "forensic", SourcePath: relPath(l.Root, path),
				Skip: true, SkipReason: fmt.Sprintf("read error: %v", err),
			})
			return nil
		}
		var doc forensicDoc
		if err := yaml.Unmarshal(content, &doc); err != nil || strings.TrimSpace(doc.ID) == "" {
			out = append(out, RawRule{
				RuleSource: "forensic", SourcePath: relPath(l.Root, path),
				Skip: true, SkipReason: "parse error or missing id",
			})
			return nil
		}

		level := strings.ToLower(strings.TrimSpace(doc.Level))
		if level == "" {
			level = "medium"
		}

		out = append(out, RawRule{
			RuleID:             strings.TrimSpace(doc.ID),
			RuleSource:         "forensic",
			RuleSHA256:         sha256Hex(content),
			SourcePath:         relPath(l.Root, path),
			PrefilterArtifacts: normaliseArtifacts(doc.Artifacts),
			Title:              strings.TrimSpace(doc.Title),
			Description:        strings.TrimSpace(doc.Description),
			Level:              level,
			MITRETechniques:    dedupTrim(doc.MITRE.Techniques),
			MITRETactics:       dedupTrim(doc.MITRE.Tactics),
			RawContent:         string(content),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// normaliseArtifacts trims, lowercases and dedups the rule's declared target
// artifacts (the prefilter). Order is preserved so the YAML's listed order is
// the column-precedence hint the LLM sees.
func normaliseArtifacts(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range in {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

// dedupTrim trims and dedups a string slice, preserving first-seen order.
func dedupTrim(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
