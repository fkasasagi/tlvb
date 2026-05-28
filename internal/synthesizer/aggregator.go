// Package synthesizer implements Tier 2 — DESIGN.md §6.
//
// Aggregator → ConsistencyChecker → TimelineBuilder → (Corrector, future).
// Outputs a CaseSynthesis JSON document.
package synthesizer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tlvb/tlvb/internal/agents"
)

// FindingWithSource tags a Finding with the slug of the Tactic Agent that
// produced it. Necessary because Finding.TacticID/TacticName aren't on the
// Finding type itself — they live on the parent TacticReport.
type FindingWithSource struct {
	Tactic     string         // slug, e.g. "persistence"
	TacticID   string         // e.g. "TA0003"
	TacticName string         // e.g. "Persistence"
	Source     string         // path of the source TacticReport file
	Confidence string         // copied for sorting convenience
	Finding    agents.Finding // original
}

// FindingCluster is a set of findings that overlap on at least one evidence
// audit_id (transitively). When two Tactic Agents independently surface the
// same UnifiedEvent, that's signal — we group them rather than report a
// duplicate finding to the examiner.
type FindingCluster struct {
	ClusterID      string              `json:"cluster_id"`
	PrimaryTactic  string              `json:"primary_tactic"`  // highest-confidence member's tactic
	PrimaryFinding agents.Finding      `json:"primary_finding"` // highest-confidence representative
	AlsoSeenIn     []string            `json:"also_seen_in"`    // other tactic_ids
	AuditIDs       []string            `json:"audit_ids"`       // union, sorted
	Members        []FindingWithSource `json:"members"`
}

// Stats is the case-level summary (DESIGN.md §6.2).
type Stats struct {
	TacticsRun               []string       `json:"tactics_run"`
	FindingsByTactic         map[string]int `json:"findings_by_tactic"`
	ConfidenceDistribution   map[string]int `json:"confidence_distribution"`
	NegativeFindingsByTactic map[string]int `json:"negative_findings_by_tactic"`
	OpenQuestionsByTactic    map[string]int `json:"open_questions_by_tactic"`
	UniqueEvidenceIDs        int            `json:"unique_evidence_audit_ids"`
	TotalFindings            int            `json:"total_findings"`
	ClusterCount             int            `json:"cluster_count"`
	MergedFindings           int            `json:"merged_findings"` // total - clusters
}

// AggregateResult is what the Aggregator hands to ConsistencyChecker /
// TimelineBuilder. JSON-encodeable so we can stash it for debugging.
type AggregateResult struct {
	CaseID       string                  `json:"case_id"`
	Reports      []agents.TacticReport   `json:"-"` // not in JSON; Stats summarises
	ReportPaths  []string                `json:"report_paths"`
	AllFindings  []FindingWithSource     `json:"-"` // flattened, pre-cluster
	Clusters     []FindingCluster        `json:"clusters"`
	Stats        Stats                   `json:"stats"`
	ReportsByTac map[string]agents.TacticReport `json:"-"` // slug → report
}

// Aggregate reads every *.json under findingsDir, parses it as a
// TacticReport, and produces the merged result.
func Aggregate(caseID, findingsDir string) (*AggregateResult, error) {
	entries, err := os.ReadDir(findingsDir)
	if err != nil {
		return nil, fmt.Errorf("read findings dir %q: %w", findingsDir, err)
	}

	res := &AggregateResult{
		CaseID:       caseID,
		ReportsByTac: map[string]agents.TacticReport{},
		Stats: Stats{
			FindingsByTactic:         map[string]int{},
			ConfidenceDistribution:   map[string]int{},
			NegativeFindingsByTactic: map[string]int{},
			OpenQuestionsByTactic:    map[string]int{},
		},
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(findingsDir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %q: %w", path, err)
		}
		var rep agents.TacticReport
		if err := json.Unmarshal(raw, &rep); err != nil {
			return nil, fmt.Errorf("parse %q: %w", path, err)
		}
		// Defensive: enforce case_id match. Reject reports that don't belong
		// to this case rather than silently mixing data.
		if rep.CaseID != "" && rep.CaseID != caseID {
			return nil, fmt.Errorf(
				"%q: case_id %q != requested %q",
				path, rep.CaseID, caseID)
		}

		slug := strings.TrimSuffix(e.Name(), ".json")
		res.Reports = append(res.Reports, rep)
		res.ReportPaths = append(res.ReportPaths, path)
		res.ReportsByTac[slug] = rep

		res.Stats.TacticsRun = append(res.Stats.TacticsRun, rep.TacticID)
		res.Stats.FindingsByTactic[rep.TacticID] = len(rep.Findings)
		res.Stats.NegativeFindingsByTactic[rep.TacticID] = len(rep.NegativeFindings)
		res.Stats.OpenQuestionsByTactic[rep.TacticID] = len(rep.OpenQuestions)

		for _, f := range rep.Findings {
			res.AllFindings = append(res.AllFindings, FindingWithSource{
				Tactic:     slug,
				TacticID:   rep.TacticID,
				TacticName: rep.TacticName,
				Source:     path,
				Confidence: f.Confidence,
				Finding:    f,
			})
			res.Stats.ConfidenceDistribution[normaliseConfidence(f.Confidence)]++
		}
	}
	sort.Strings(res.Stats.TacticsRun)
	res.Stats.TacticsRun = uniq(res.Stats.TacticsRun)
	res.Stats.TotalFindings = len(res.AllFindings)

	// Cluster by evidence overlap.
	res.Clusters = clusterFindings(res.AllFindings)
	res.Stats.ClusterCount = len(res.Clusters)
	res.Stats.MergedFindings = res.Stats.TotalFindings - res.Stats.ClusterCount
	if res.Stats.MergedFindings < 0 {
		res.Stats.MergedFindings = 0
	}
	res.Stats.UniqueEvidenceIDs = countUniqueEvidence(res.AllFindings)

	return res, nil
}

// clusterFindings groups findings that share at least one audit_id, using
// union-find. Two findings F1, F2 land in the same cluster if there exists
// any chain F1↔A↔F2 where A is an audit_id appearing in both.
func clusterFindings(all []FindingWithSource) []FindingCluster {
	n := len(all)
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(x int) int {
		if parent[x] != x {
			parent[x] = find(parent[x])
		}
		return parent[x]
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[ra] = rb
		}
	}

	// audit_id → indices that reference it
	idx := map[string][]int{}
	for i, fs := range all {
		for _, ev := range fs.Finding.Evidence {
			if ev.AuditID == "" {
				continue
			}
			idx[ev.AuditID] = append(idx[ev.AuditID], i)
		}
	}
	for _, group := range idx {
		for i := 1; i < len(group); i++ {
			union(group[0], group[i])
		}
	}

	// Group by root.
	roots := map[int][]int{}
	for i := 0; i < n; i++ {
		r := find(i)
		roots[r] = append(roots[r], i)
	}
	rootKeys := make([]int, 0, len(roots))
	for k := range roots {
		rootKeys = append(rootKeys, k)
	}
	sort.Ints(rootKeys)

	out := make([]FindingCluster, 0, len(roots))
	clusterCounter := 0
	for _, root := range rootKeys {
		members := roots[root]
		clusterCounter++
		var fc FindingCluster
		fc.ClusterID = fmt.Sprintf("C-%03d", clusterCounter)

		// Pick highest-confidence representative; tie-break by
		// most evidence rows; tie-break by lexical finding_id.
		best := members[0]
		bestScore := scoreFinding(all[best])
		for _, m := range members[1:] {
			s := scoreFinding(all[m])
			if s > bestScore {
				best = m
				bestScore = s
			}
		}

		fc.PrimaryFinding = all[best].Finding
		fc.PrimaryTactic = all[best].TacticID

		seenTactics := map[string]struct{}{all[best].TacticID: {}}
		auditSet := map[string]struct{}{}
		for _, m := range members {
			fwsm := all[m]
			fc.Members = append(fc.Members, fwsm)
			if _, dup := seenTactics[fwsm.TacticID]; !dup && fwsm.TacticID != all[best].TacticID {
				fc.AlsoSeenIn = append(fc.AlsoSeenIn, fwsm.TacticID)
				seenTactics[fwsm.TacticID] = struct{}{}
			}
			for _, ev := range fwsm.Finding.Evidence {
				if ev.AuditID != "" {
					auditSet[ev.AuditID] = struct{}{}
				}
			}
		}
		sort.Strings(fc.AlsoSeenIn)
		fc.AuditIDs = sortedKeys(auditSet)
		out = append(out, fc)
	}

	// Sort clusters: by primary tactic ID then by ClusterID.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].PrimaryTactic != out[j].PrimaryTactic {
			return out[i].PrimaryTactic < out[j].PrimaryTactic
		}
		return out[i].ClusterID < out[j].ClusterID
	})
	return out
}

// scoreFinding returns a sortable score: higher = better representative.
// confidence weight (high>medium>low) + |evidence|.
func scoreFinding(f FindingWithSource) int {
	c := 0
	switch normaliseConfidence(f.Finding.Confidence) {
	case "high":
		c = 3
	case "medium":
		c = 2
	case "low":
		c = 1
	}
	return c*100 + len(f.Finding.Evidence)
}

func normaliseConfidence(c string) string {
	c = strings.ToLower(strings.TrimSpace(c))
	switch c {
	case "high", "medium", "low":
		return c
	default:
		return "low"
	}
}

func countUniqueEvidence(all []FindingWithSource) int {
	seen := map[string]struct{}{}
	for _, f := range all {
		for _, ev := range f.Finding.Evidence {
			if ev.AuditID != "" {
				seen[ev.AuditID] = struct{}{}
			}
		}
	}
	return len(seen)
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func uniq(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := in[:0]
	last := ""
	for i, s := range in {
		if i == 0 || s != last {
			out = append(out, s)
			last = s
		}
	}
	return out
}
