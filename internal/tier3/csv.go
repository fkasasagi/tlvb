package tier3

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/tier2"
)

// renderFindingsCSV: one row per finding reference inside each cluster.
// Use UTF-8 BOM so Excel auto-detects the encoding.
func renderFindingsCSV(path string, cs tier2.CaseSynthesis) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return err
	}
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{
		"cluster_id", "cluster_attack_phase", "cluster_window_start", "cluster_window_end",
		"source", "rule_id", "title", "severity",
	}); err != nil {
		return err
	}
	for _, c := range cs.Clusters {
		for _, fr := range c.FindingRefs {
			row := []string{
				fmt.Sprintf("%d", c.ID),
				c.AttackPhase,
				formatTS(c.StartTS),
				formatTS(c.EndTS),
				fr.Source,
				fr.RuleID,
				fr.Title,
				fr.Severity,
			}
			if err := w.Write(row); err != nil {
				return err
			}
		}
	}
	return nil
}

// renderMITRECSV: one row per MITRE technique with cluster IDs joined.
func renderMITRECSV(path string, cs tier2.CaseSynthesis) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return err
	}
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{
		"technique", "tactic", "finding_count", "cluster_ids",
	}); err != nil {
		return err
	}
	for _, m := range cs.MITREMapping {
		ids := make([]string, 0, len(m.ClusterIDs))
		for _, id := range m.ClusterIDs {
			ids = append(ids, fmt.Sprintf("%d", id))
		}
		row := []string{
			m.Technique,
			m.Tactic,
			fmt.Sprintf("%d", m.FindingCount),
			strings.Join(ids, ";"),
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// renderClustersCSV: one row per cluster with a brief narrative.
func renderClustersCSV(path string, cs tier2.CaseSynthesis) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return err
	}
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{
		"cluster_id", "attack_phase", "window_start", "window_end",
		"finding_count", "mitre_techniques", "open_questions_count", "narrative",
	}); err != nil {
		return err
	}
	for _, c := range cs.Clusters {
		row := []string{
			fmt.Sprintf("%d", c.ID),
			c.AttackPhase,
			formatTS(c.StartTS),
			formatTS(c.EndTS),
			fmt.Sprintf("%d", len(c.FindingRefs)),
			strings.Join(c.MITRETechniques, "; "),
			fmt.Sprintf("%d", len(c.OpenQuestions)),
			oneLine(c.Narrative),
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func formatTS(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// oneLine flattens newlines so the CSV row is single-line.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}
