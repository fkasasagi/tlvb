package common

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ArtifactCatalog wraps config/artifacts.yaml. Loaded once at server start.
type ArtifactCatalog struct {
	doc       artifactDoc
	byID      map[string]ArtifactDef
}

type artifactDoc struct {
	Version                     string        `yaml:"version"`
	Schema                      string        `yaml:"schema"`
	Artifacts                   []ArtifactDef `yaml:"artifacts"`
	Defaults                    Defaults      `yaml:"defaults"`
	UnifiedEventRequiredFields  []string      `yaml:"unified_event_required_fields"`
}

// ArtifactDef mirrors one entry under `artifacts:` in artifacts.yaml.
// Kept loose (map for unified_event_mapping) so we can extend without breaking.
type ArtifactDef struct {
	ID                    string                 `yaml:"id" json:"id"`
	Name                  string                 `yaml:"name" json:"name"`
	Tier                  string                 `yaml:"tier" json:"tier"`
	SafetyTier            string                 `yaml:"safety_tier" json:"safety_tier"`
	Parser                string                 `yaml:"parser" json:"parser"`
	Tool                  Tool                   `yaml:"tool" json:"tool"`
	Input                 InputSpec              `yaml:"input" json:"input"`
	CommandTemplate       string                 `yaml:"command_template" json:"command_template"`
	Output                OutputSpec             `yaml:"output" json:"output"`
	Fallback              *Fallback              `yaml:"fallback,omitempty" json:"fallback,omitempty"`
	UnifiedEventMapping   map[string]string      `yaml:"unified_event_mapping" json:"unified_event_mapping"`
	Caveats               []string               `yaml:"caveats" json:"caveats"`
}

type Tool struct {
	Name    string `yaml:"name" json:"name"`
	Version string `yaml:"version" json:"version"`
	Binary  string `yaml:"binary" json:"binary"`
	DLL     string `yaml:"dll" json:"dll,omitempty"`
}

type InputSpec struct {
	Mode    string `yaml:"mode" json:"mode"` // "file" | "dir"
	Pattern string `yaml:"pattern" json:"pattern"`
}

type OutputSpec struct {
	Format          string `yaml:"format" json:"format"`
	DefaultCSVName  string `yaml:"default_csv_name" json:"default_csv_name"`
}

type Fallback struct {
	CommandTemplate string `yaml:"command_template" json:"command_template"`
	OutputCSVName   string `yaml:"output_csv_name" json:"output_csv_name"`
}

type Defaults struct {
	TimeoutSeconds      int    `yaml:"timeout_seconds"`
	OutputEncoding      string `yaml:"output_encoding"`
	Timezone            string `yaml:"timezone"`
	UnifiedEventSchema  string `yaml:"unified_event_schema"`
}

// LoadArtifactCatalog parses YAML and indexes by id.
func LoadArtifactCatalog(path string) (*ArtifactCatalog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	var doc artifactDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse %q: %w", path, err)
	}
	if len(doc.Artifacts) == 0 {
		return nil, fmt.Errorf("%q contains no artifacts", path)
	}
	idx := make(map[string]ArtifactDef, len(doc.Artifacts))
	for _, a := range doc.Artifacts {
		if a.ID == "" {
			return nil, fmt.Errorf("artifact entry without id in %q", path)
		}
		if _, dup := idx[a.ID]; dup {
			return nil, fmt.Errorf("duplicate artifact id %q in %q", a.ID, path)
		}
		idx[a.ID] = a
	}
	return &ArtifactCatalog{doc: doc, byID: idx}, nil
}

// Version returns the catalog's declared schema version.
func (c *ArtifactCatalog) Version() string { return c.doc.Version }

// Count is the number of registered artifact definitions.
func (c *ArtifactCatalog) Count() int { return len(c.byID) }

// Get returns an ArtifactDef by id.
func (c *ArtifactCatalog) Get(id string) (ArtifactDef, bool) {
	d, ok := c.byID[id]
	return d, ok
}

// Summary returns a slim view (id/name/tier/tool) suitable for list_artifacts.
// Full definitions are accessible via get_artifact_definition.
func (c *ArtifactCatalog) Summary() []ArtifactSummary {
	out := make([]ArtifactSummary, 0, len(c.doc.Artifacts))
	for _, a := range c.doc.Artifacts {
		out = append(out, ArtifactSummary{
			ID:         a.ID,
			Name:       a.Name,
			Tier:       a.Tier,
			SafetyTier: a.SafetyTier,
			Tool:       a.Tool.Name,
			InputMode:  a.Input.Mode,
			Caveats:    a.Caveats,
		})
	}
	return out
}

type ArtifactSummary struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Tier       string   `json:"tier"`
	SafetyTier string   `json:"safety_tier"`
	Tool       string   `json:"tool"`
	InputMode  string   `json:"input_mode"`
	Caveats    []string `json:"caveats"`
}
