package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/tlvb/tlvb/internal/casedb"
)

// runStatus implements `tlvb status CASE_ID` — a one-shot inspector that
// gathers per-case state from cases.duckdb, the findings tree, the
// synthesis file, and the reports directory.
func runStatus(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: tlvb status CASE_ID [...]")
	}
	caseID := args[0]
	rest := args[1:]
	if strings.HasPrefix(caseID, "-") {
		return fmt.Errorf("first argument must be CASE_ID, got %q", caseID)
	}
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	dbPath := fs.String("db", "outputs/cases.duckdb", "case DuckDB path")
	caseRoot := fs.String("case-root", "",
		"case workspace root (default: outputs/cases/<id>)")
	verbose := fs.Bool("v", false,
		"verbose mode (list each parsed artifact and each finding file)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *caseRoot == "" {
		*caseRoot = filepath.Join("outputs", "cases", caseID)
	}

	mgr, err := casedb.Open(*dbPath, casedb.ReadOnly)
	if err != nil {
		return fmt.Errorf("open case db (read-only): %w", err)
	}
	defer mgr.Close()
	ctx := context.Background()

	cs, err := mgr.GetCaseStatus(ctx, caseID)
	if err != nil {
		return fmt.Errorf("get case status: %w", err)
	}

	// 1. Case metadata.
	fmt.Printf("Case: %s\n", cs.Case.CaseID)
	fmt.Printf("  name:        %s\n", cs.Case.Name)
	fmt.Printf("  examiner:    %s\n", cs.Case.Examiner)
	fmt.Printf("  timezone:    %s\n", cs.Case.Timezone)
	fmt.Printf("  status:      %s\n", cs.Case.Status)
	fmt.Printf("  created at:  %s\n", cs.Case.CreatedAt.UTC().Format(time.RFC3339))
	fmt.Println()

	// 2. Evidence and parse_results.
	fmt.Printf("Evidence and parsing:\n")
	fmt.Printf("  evidence rows:        %d\n", cs.EvidenceCount)
	fmt.Printf("  parse_results rows:   %d\n", len(cs.ParseResults))
	fmt.Printf("  unified_events rows:  %s\n", commaInt64(cs.UnifiedRowCount))
	if *verbose && len(cs.ParseResults) > 0 {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "    ARTIFACT\tROWS\tEXIT\tDURATION")
		for _, pr := range cs.ParseResults {
			rows := int64(-1)
			if pr.RowCount != nil {
				rows = *pr.RowCount
			}
			exit := "-"
			if pr.ExitCode != nil {
				exit = fmt.Sprintf("%d", *pr.ExitCode)
			}
			dur := "-"
			if pr.FinishedAt != nil {
				dur = pr.FinishedAt.Sub(pr.StartedAt).Truncate(time.Millisecond).String()
			}
			fmt.Fprintf(w, "    %s\t%d\t%s\t%s\n", pr.ArtifactID, rows, exit, dur)
		}
		w.Flush()
	}
	fmt.Println()

	// 3. Findings walk.
	findingsBase := filepath.Join(*caseRoot, "findings")
	stats := walkFindings(findingsBase)
	if stats.totalByRule+stats.totalBySkill == 0 {
		fmt.Printf("Findings: (none — run `tlvb analyze CASE_ID --tier 1a/--tier 1b` first)\n\n")
	} else {
		fmt.Printf("Findings:\n")
		fmt.Printf("  by-rule files:        %d\n", stats.totalByRule)
		fmt.Printf("  by-skill files:       %d\n", stats.totalBySkill)
		if len(stats.bySource) > 0 {
			fmt.Printf("  by source:\n")
			keys := sortedKeys(stats.bySource)
			for _, k := range keys {
				fmt.Printf("    %-20s %d\n", k+":", stats.bySource[k])
			}
		}
		if len(stats.bySeverity) > 0 {
			fmt.Printf("  by severity:\n")
			for _, sev := range []string{"critical", "high", "medium", "low", "informational"} {
				if n := stats.bySeverity[sev]; n > 0 {
					fmt.Printf("    %-20s %d\n", sev+":", n)
				}
			}
		}
		fmt.Println()
	}

	// 4. Synthesis.
	synthPath := filepath.Join(*caseRoot, "synthesis.json")
	if fi, err := os.Stat(synthPath); err == nil {
		fmt.Printf("Synthesis: %s (%d bytes, generated %s)\n", synthPath, fi.Size(),
			fi.ModTime().UTC().Format(time.RFC3339))
		if sum, err := readSynthesisSummary(synthPath); err == nil {
			fmt.Printf("  total findings:       %d\n", sum.TotalFindings)
			fmt.Printf("  clusters:             %d\n", sum.ClusterCount)
			fmt.Printf("  mitre techniques:     %d\n", sum.MITRECount)
			if sum.HasOverallStory {
				fmt.Printf("  overall_story:        present (%d chars)\n", sum.OverallStoryLen)
			} else {
				fmt.Printf("  overall_story:        (empty)\n")
			}
			if sum.ActiveSearchSucceeded > 0 || sum.ActiveSearchAttempted > 0 {
				fmt.Printf("  active-search:        %d/%d succeeded\n",
					sum.ActiveSearchSucceeded, sum.ActiveSearchAttempted)
			}
		}
		fmt.Println()
	} else {
		fmt.Printf("Synthesis: (none — run `tlvb synthesize CASE_ID --tier 2` first)\n\n")
	}

	// 5. Reports.
	reportsDir := filepath.Join(*caseRoot, "reports")
	if _, err := os.Stat(reportsDir); err == nil {
		files, _ := filepath.Glob(filepath.Join(reportsDir, "*"))
		if len(files) > 0 {
			fmt.Printf("Reports: %s\n", reportsDir)
			sort.Strings(files)
			for _, f := range files {
				fi, err := os.Stat(f)
				if err != nil {
					continue
				}
				fmt.Printf("  [%-20s] %s bytes  %s\n",
					filepath.Base(f),
					commaInt64(fi.Size()),
					fi.ModTime().UTC().Format(time.RFC3339))
			}
		} else {
			fmt.Printf("Reports: (empty dir — run `tlvb report CASE_ID --tier 3` first)\n")
		}
	} else {
		fmt.Printf("Reports: (none — run `tlvb report CASE_ID --tier 3` first)\n")
	}

	return nil
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

type findingStats struct {
	totalByRule  int
	totalBySkill int
	bySource     map[string]int // by-rule rule_source / by-skill skill name
	bySeverity   map[string]int
}

func walkFindings(base string) findingStats {
	s := findingStats{bySource: map[string]int{}, bySeverity: map[string]int{}}
	byRule := filepath.Join(base, "by-rule")
	if _, err := os.Stat(byRule); err == nil {
		filepath.WalkDir(byRule, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			var f struct {
				RuleSource string `json:"rule_source"`
				RuleMeta   struct {
					Level string `json:"level"`
				} `json:"rule_meta"`
			}
			if err := json.Unmarshal(body, &f); err != nil {
				return nil
			}
			s.totalByRule++
			if f.RuleSource != "" {
				s.bySource[f.RuleSource]++
			}
			if f.RuleMeta.Level != "" {
				s.bySeverity[f.RuleMeta.Level]++
			}
			return nil
		})
	}
	bySkill := filepath.Join(base, "by-skill")
	if _, err := os.Stat(bySkill); err == nil {
		filepath.WalkDir(bySkill, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			var rep struct {
				Skill    string `json:"skill"`
				Findings []struct {
					Severity string `json:"severity"`
				} `json:"findings"`
			}
			if err := json.Unmarshal(body, &rep); err != nil {
				return nil
			}
			s.totalBySkill += len(rep.Findings)
			if rep.Skill != "" {
				s.bySource[rep.Skill] += len(rep.Findings)
			}
			for _, f := range rep.Findings {
				if f.Severity != "" {
					s.bySeverity[f.Severity]++
				}
			}
			return nil
		})
	}
	return s
}

type synthesisSummary struct {
	TotalFindings         int
	ClusterCount          int
	MITRECount            int
	HasOverallStory       bool
	OverallStoryLen       int
	ActiveSearchAttempted int
	ActiveSearchSucceeded int
}

func readSynthesisSummary(path string) (*synthesisSummary, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cs struct {
		TotalFindings int      `json:"total_findings"`
		ClusterCount  int      `json:"cluster_count"`
		OverallStory  string   `json:"overall_story"`
		MITREMapping  []struct{} `json:"mitre_mapping"`
		Audit         struct {
			ActiveSQLAttempted int `json:"active_sql_attempted"`
			ActiveSQLSucceeded int `json:"active_sql_succeeded"`
		} `json:"audit"`
	}
	if err := json.Unmarshal(body, &cs); err != nil {
		return nil, err
	}
	sum := &synthesisSummary{
		TotalFindings:         cs.TotalFindings,
		ClusterCount:          cs.ClusterCount,
		MITRECount:            len(cs.MITREMapping),
		HasOverallStory:       len(strings.TrimSpace(cs.OverallStory)) > 0,
		OverallStoryLen:       len(cs.OverallStory),
		ActiveSearchAttempted: cs.Audit.ActiveSQLAttempted,
		ActiveSearchSucceeded: cs.Audit.ActiveSQLSucceeded,
	}
	return sum, nil
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func commaInt64(n int64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	for i, ch := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(ch)
	}
	return b.String()
}
