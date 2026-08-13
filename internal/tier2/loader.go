package tier2

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LoadFindings reads all Tier 1 outputs (by-rule + by-skill) for a case
// and returns the unified Finding slice. Missing dirs are tolerated.
//
// findingsBase is "outputs/cases/<id>/findings".
func LoadFindings(findingsBase string) ([]Finding, error) {
	var out []Finding

	// Tier 1A: findings/by-rule/<source>/<rule_id>.json — one file per finding.
	byRule := filepath.Join(findingsBase, "by-rule")
	if _, err := os.Stat(byRule); err == nil {
		more, err := loadByRuleDir(byRule)
		if err != nil {
			return nil, fmt.Errorf("load by-rule: %w", err)
		}
		out = append(out, more...)
	}

	// Tier 1B: findings/by-skill/<skill>.json — wrapped report with multiple findings.
	bySkill := filepath.Join(findingsBase, "by-skill")
	if _, err := os.Stat(bySkill); err == nil {
		more, err := loadBySkillDir(bySkill)
		if err != nil {
			return nil, fmt.Errorf("load by-skill: %w", err)
		}
		out = append(out, more...)
	}

	return mergeHayabusaIntoSigma(out), nil
}

// dropRejected removes findings an examiner rejected at Review Gate 1A/1B and
// reports how many went. Approved is deliberately NOT required:
// tier1a.AutoApproveByLevel leaves critical/high at Approved=false until a
// human looks at them, so gating on it would silently delete exactly the
// findings that matter most.
func dropRejected(in []Finding) ([]Finding, int) {
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		if f.Rejected {
			continue
		}
		out = append(out, f)
	}
	return out, len(in) - len(out)
}

// mergeHayabusaIntoSigma drops Hayabusa pass-through findings that duplicate a
// Sigma signature finding. Hayabusa runs the SigmaHQ ruleset internally, so the
// SAME rule fires in both engines and lands as two findings (rule_source
// "hayabusa" and "sigma"). The match key is the rule TITLE, not the rule_id:
// Hayabusa re-IDs upstream Sigma rules (UUIDv5) so the ids differ, but the title
// is preserved verbatim.
//
// Hayabusa findings with no Sigma twin are KEPT — these are Hayabusa's genuine
// added value: native (ruletype:Hayabusa) rules absent from SigmaHQ, and Sigma
// categories TLVB does not prebake into SQL (process_creation, ps_script,
// wmi_event). Only the redundant overlap is folded.
//
// Non-destructive on disk: the raw by-rule/hayabusa/*.json files stay for audit
// (the cross-detection is still recorded); only the in-memory view Tier 2
// clusters / Tier 3 reports is deduplicated. The Sigma twin survives because its
// evidence points at the real source events (EVTX), whereas the Hayabusa twin's
// evidence is the tool's own artifact_id='hayabusa' projection of the same rows.
func mergeHayabusaIntoSigma(in []Finding) []Finding {
	sigmaTitles := map[string]bool{}
	for i := range in {
		if strings.EqualFold(in[i].Source, "sigma") {
			sigmaTitles[normMergeTitle(in[i].Title)] = true
		}
	}
	out := make([]Finding, 0, len(in))
	for i := range in {
		if strings.EqualFold(in[i].Source, "hayabusa") && sigmaTitles[normMergeTitle(in[i].Title)] {
			continue // folded into the Sigma twin
		}
		out = append(out, in[i])
	}
	return out
}

// normMergeTitle is the case/space-insensitive title key used to pair a Hayabusa
// pass-through finding with its Sigma twin.
func normMergeTitle(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func loadByRuleDir(root string) ([]Finding, error) {
	var out []Finding
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// Tier 1A Finding shape (see internal/tier1a/finding.go).
		var f1a struct {
			FindingID  string `json:"finding_id"`
			CaseID     string `json:"case_id"`
			RuleID     string `json:"rule_id"`
			RuleSource string `json:"rule_source"`
			RuleMeta   struct {
				Title           string   `json:"title"`
				Level           string   `json:"level"`
				MITRETechniques []string `json:"mitre_techniques"`
				MITRETactics    []string `json:"mitre_tactics"`
			} `json:"rule_meta"`
			Approved bool `json:"approved"`
			Rejected bool `json:"rejected"`
			Evidence []struct {
				AuditID    string         `json:"audit_id"`
				TsUTC      time.Time      `json:"ts_utc"`
				ArtifactID string         `json:"artifact_id"`
				EventType  string         `json:"event_type"`
				Extra      map[string]any `json:"extra"`
			} `json:"evidence"`
		}
		if err := json.Unmarshal(body, &f1a); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		if f1a.RuleID == "" {
			return nil // not a Tier 1A finding
		}
		f := Finding{
			FindingID:       f1a.FindingID,
			Source:          f1a.RuleSource,
			RuleID:          f1a.RuleID,
			Title:           f1a.RuleMeta.Title,
			Severity:        f1a.RuleMeta.Level,
			MITRETechniques: f1a.RuleMeta.MITRETechniques,
			OriginPath:      path,
			Approved:        f1a.Approved,
			Rejected:        f1a.Rejected,
		}
		if len(f1a.RuleMeta.MITRETactics) > 0 {
			f.MITRETactic = f1a.RuleMeta.MITRETactics[0]
		}
		for _, e := range f1a.Evidence {
			f.Evidence = append(f.Evidence, FindingEvidence{
				AuditID:    e.AuditID,
				TsUTC:      e.TsUTC,
				HasTS:      !e.TsUTC.IsZero(),
				ArtifactID: e.ArtifactID,
				EventType:  e.EventType,
				Extra:      e.Extra,
			})
		}
		out = append(out, f)
		return nil
	})
	return out, err
}

func loadBySkillDir(root string) ([]Finding, error) {
	var out []Finding
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		// Skip raw response debug dumps.
		if !strings.HasSuffix(name, ".json") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// Tier 1B AnomalyReport shape (see internal/tier1b/types.go).
		var rep struct {
			CaseID   string `json:"case_id"`
			Skill    string `json:"skill"`
			Findings []struct {
				FindingID   string   `json:"finding_id"`
				Lens        string   `json:"lens"`
				Summary     string   `json:"summary"`
				Description string   `json:"description"`
				Severity    string   `json:"severity"`
				AuditIDs    []string `json:"audit_ids"`
				TechniqueID string   `json:"technique_id"`
				Tactic      string   `json:"tactic"`
				Approved    bool     `json:"approved"`
				Rejected    bool     `json:"rejected"`
			} `json:"findings"`
		}
		if err := json.Unmarshal(body, &rep); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		for _, af := range rep.Findings {
			f := Finding{
				FindingID:   af.FindingID,
				Source:      rep.Skill,
				RuleID:      af.Lens, // lens id stands in for rule_id here
				Title:       af.Summary,
				Description: af.Description,
				Severity:    af.Severity,
				MITRETactic: af.Tactic,
				OriginPath:  path,
				Approved:    af.Approved,
				Rejected:    af.Rejected,
			}
			if af.TechniqueID != "" {
				f.MITRETechniques = []string{af.TechniqueID}
			}
			// Evidence has only audit_id at this stage — timestamps will be
			// looked up from unified_events during cluster timeline expansion.
			for _, aid := range af.AuditIDs {
				f.Evidence = append(f.Evidence, FindingEvidence{
					AuditID: aid,
				})
			}
			out = append(out, f)
		}
		return nil
	})
	return out, err
}
