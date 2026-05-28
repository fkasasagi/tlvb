package rulesrepo

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// STIXLoader walks rules/stix/mitre-attack/enterprise-attack/attack-pattern/*.json.
//
// Unlike Sigma/Hayabusa, STIX attack-pattern objects do NOT contain detection
// logic — they describe the technique. The Tier 1A build prompt is responsible
// for synthesising detection SQL from the technique description + data sources.
// STIX rules are therefore most useful as a "catch-all" layer for techniques
// not covered by any specific Sigma/Hayabusa rule.
type STIXLoader struct {
	// Root points at the attack-pattern directory.
	// Typically "rules/stix/mitre-attack/enterprise-attack/attack-pattern".
	Root              string
	IncludeNonWindows bool // include techniques where x_mitre_platforms lacks "Windows"
	IncludeRevoked    bool
	IncludeDeprecated bool
}

// NewSTIXLoader returns a loader rooted at enterprise-attack/attack-pattern
// with the TLVB defaults (Windows-only, no revoked/deprecated).
func NewSTIXLoader(root string) *STIXLoader {
	return &STIXLoader{Root: root}
}

func (l *STIXLoader) Source() string { return "stix" }

// stixBundle and stixAttackPattern reflect the subset of STIX 2.x we read.
type stixBundle struct {
	Type    string             `json:"type"`
	Objects []stixAttackPattern `json:"objects"`
}

type stixAttackPattern struct {
	Type                 string                 `json:"type"`
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name"`
	Description          string                 `json:"description"`
	Revoked              bool                   `json:"revoked"`
	Deprecated           bool                   `json:"x_mitre_deprecated"`
	Platforms            []string               `json:"x_mitre_platforms"`
	DataSources          []string               `json:"x_mitre_data_sources"`
	KillChainPhases      []stixKillChainPhase   `json:"kill_chain_phases"`
	ExternalReferences   []stixExternalRef      `json:"external_references"`
}

type stixKillChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

type stixExternalRef struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
	URL        string `json:"url,omitempty"`
}

func (l *STIXLoader) LoadAll(ctx context.Context) ([]RawRule, error) {
	if l.Root == "" {
		return nil, fmt.Errorf("STIXLoader.Root is empty")
	}
	if _, err := os.Stat(l.Root); err != nil {
		return nil, fmt.Errorf("stix root %q: %w", l.Root, err)
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
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}
		rule, ok, err := l.loadOne(path)
		if err != nil {
			out = append(out, RawRule{
				RuleSource: "stix",
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

func (l *STIXLoader) loadOne(path string) (RawRule, bool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return RawRule{}, false, err
	}
	var bundle stixBundle
	if err := json.Unmarshal(content, &bundle); err != nil {
		return RawRule{}, false, fmt.Errorf("json: %w", err)
	}
	var ap *stixAttackPattern
	for i := range bundle.Objects {
		if bundle.Objects[i].Type == "attack-pattern" {
			ap = &bundle.Objects[i]
			break
		}
	}
	if ap == nil {
		return RawRule{}, false, nil // file holds no attack-pattern
	}

	// Extract the ATT&CK T-number (e.g. "T1053.005").
	var techID string
	for _, ref := range ap.ExternalReferences {
		if ref.SourceName == "mitre-attack" && ref.ExternalID != "" {
			techID = ref.ExternalID
			break
		}
	}
	if techID == "" {
		return RawRule{}, false, nil // no T-number, not a real technique row
	}

	// Skip filters.
	if ap.Revoked && !l.IncludeRevoked {
		return RawRule{
			RuleID: techID, RuleSource: "stix",
			RuleSHA256: sha256Hex(content),
			SourcePath: relPath(l.Root, path),
			Title:      ap.Name,
			Skip:       true,
			SkipReason: "revoked technique",
		}, true, nil
	}
	if ap.Deprecated && !l.IncludeDeprecated {
		return RawRule{
			RuleID: techID, RuleSource: "stix",
			RuleSHA256: sha256Hex(content),
			SourcePath: relPath(l.Root, path),
			Title:      ap.Name,
			Skip:       true,
			SkipReason: "deprecated technique",
		}, true, nil
	}
	if !l.IncludeNonWindows {
		hasWindows := false
		for _, p := range ap.Platforms {
			if strings.EqualFold(p, "windows") {
				hasWindows = true
				break
			}
		}
		if !hasWindows {
			return RawRule{
				RuleID: techID, RuleSource: "stix",
				RuleSHA256: sha256Hex(content),
				SourcePath: relPath(l.Root, path),
				Title:      ap.Name,
				Skip:       true,
				SkipReason: fmt.Sprintf("not a Windows technique (platforms=%v)", ap.Platforms),
			}, true, nil
		}
	}

	// Extract tactics from kill_chain_phases (mitre-attack chain only).
	var tactics []string
	for _, p := range ap.KillChainPhases {
		if p.KillChainName == "mitre-attack" && p.PhaseName != "" {
			tactics = append(tactics, p.PhaseName)
		}
	}

	// Pretty-print the attack-pattern object only (not the full bundle) so
	// the LLM prompt is tighter.
	apJSON, err := json.MarshalIndent(ap, "", "  ")
	if err != nil {
		apJSON = content
	}

	return RawRule{
		RuleID:             techID,
		RuleSource:         "stix",
		RuleSHA256:         sha256Hex(content),
		SourcePath:         relPath(l.Root, path),
		PrefilterArtifacts: []string{"evtx"}, // default; richer mapping is future work
		Title:              ap.Name,
		Description:        strings.TrimSpace(ap.Description),
		Level:              "medium", // STIX has no severity; medium is a neutral default
		MITRETechniques:    []string{techID},
		MITRETactics:       tactics,
		RawContent:         string(apJSON),
	}, true, nil
}
