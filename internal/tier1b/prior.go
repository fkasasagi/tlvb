package tier1b

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// priorRow captures one prior finding's evidence reference: audit_id +
// timestamp (best-effort, for adjacency anomaly bucketing).
type priorRow struct {
	AuditID string
	TsUTC   time.Time
	HasTS   bool
}

// priorSummary is the per-(rule_source,level) aggregate used for the
// LLM's "what's already covered" context.
type priorSummary struct {
	Source string
	Level  string
	Count  int
}

type priorContext struct {
	Rows          []priorRow
	Summary       []priorSummary
	UniqueAudits  []string // for dedup against new findings
	KeyTimestamps []string // ISO8601 strings, sorted earliest first
	Total         int      // total prior findings considered
}

// loadPriorFindings walks findings/by-rule/**/*.json and findings/by-skill/*.json
// (if any) and collects audit_ids + timestamps for Tier 1B context.
//
// findingsBase is "outputs/cases/<id>/findings".
func loadPriorFindings(findingsBase string) (*priorContext, error) {
	pc := &priorContext{}
	bySource := map[string]map[string]int{} // source → level → count

	walk := func(root string) error {
		if _, err := os.Stat(root); err != nil {
			return nil // dir missing is fine — case may have no findings yet
		}
		return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			// Try Tier 1A Finding shape first.
			var f1a struct {
				RuleSource string `json:"rule_source"`
				RuleMeta   struct {
					Level string `json:"level"`
				} `json:"rule_meta"`
				Evidence []struct {
					AuditID string    `json:"audit_id"`
					TsUTC   time.Time `json:"ts_utc"`
				} `json:"evidence"`
			}
			if err := json.Unmarshal(body, &f1a); err == nil && f1a.RuleSource != "" {
				if bySource[f1a.RuleSource] == nil {
					bySource[f1a.RuleSource] = map[string]int{}
				}
				bySource[f1a.RuleSource][f1a.RuleMeta.Level]++
				pc.Total++
				for _, e := range f1a.Evidence {
					pc.Rows = append(pc.Rows, priorRow{
						AuditID: e.AuditID,
						TsUTC:   e.TsUTC,
						HasTS:   !e.TsUTC.IsZero(),
					})
				}
				return nil
			}
			// (Future) Tier 1B AnomalyReport shape — skip self-loops for now.
			return nil
		})
	}
	if err := walk(filepath.Join(findingsBase, "by-rule")); err != nil {
		return nil, err
	}

	// Dedupe audits and timestamps.
	auditSet := map[string]bool{}
	tsSet := map[time.Time]bool{}
	for _, r := range pc.Rows {
		if r.AuditID != "" {
			auditSet[r.AuditID] = true
		}
		if r.HasTS {
			tsSet[r.TsUTC.Truncate(time.Second)] = true
		}
	}
	for a := range auditSet {
		pc.UniqueAudits = append(pc.UniqueAudits, a)
	}
	for ts := range tsSet {
		pc.KeyTimestamps = append(pc.KeyTimestamps, ts.UTC().Format(time.RFC3339))
	}

	for src, levels := range bySource {
		for lvl, n := range levels {
			pc.Summary = append(pc.Summary, priorSummary{
				Source: src, Level: lvl, Count: n,
			})
		}
	}
	return pc, nil
}
