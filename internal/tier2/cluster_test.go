package tier2

import (
	"testing"
	"time"
)

func mkFinding(t time.Time, hasTS bool, ruleID string) Finding {
	return Finding{
		RuleID: ruleID,
		Evidence: []FindingEvidence{
			{TsUTC: t, HasTS: hasTS},
		},
	}
}

func TestClusterFindingsBasicGap(t *testing.T) {
	t0 := time.Date(2026, 5, 19, 13, 0, 0, 0, time.UTC)
	findings := []Finding{
		mkFinding(t0, true, "r1"),
		mkFinding(t0.Add(10*time.Minute), true, "r2"), // same cluster
		mkFinding(t0.Add(2*time.Hour), true, "r3"),    // new cluster
		mkFinding(t0.Add(2*time.Hour+5*time.Minute), true, "r4"),
	}
	clusters := ClusterFindings(findings, 30*time.Minute)
	if len(clusters) != 2 {
		t.Fatalf("expected 2 clusters, got %d", len(clusters))
	}
	if len(clusters[0].Findings) != 2 {
		t.Errorf("cluster 0 size: got %d, want 2", len(clusters[0].Findings))
	}
	if len(clusters[1].Findings) != 2 {
		t.Errorf("cluster 1 size: got %d, want 2", len(clusters[1].Findings))
	}
}

func TestClusterFindingsUndatedBundled(t *testing.T) {
	t0 := time.Date(2026, 5, 19, 13, 0, 0, 0, time.UTC)
	findings := []Finding{
		mkFinding(t0, true, "r1"),
		mkFinding(time.Time{}, false, "r-undated"),
	}
	clusters := ClusterFindings(findings, 30*time.Minute)
	if len(clusters) != 2 {
		t.Fatalf("expected 2 clusters (1 dated + 1 undated), got %d", len(clusters))
	}
	// undated cluster should be the last one with zero StartTS
	undated := &clusters[len(clusters)-1]
	if !undated.StartTS.IsZero() {
		t.Errorf("undated cluster should have zero StartTS, got %v", undated.StartTS)
	}
	if undated.Findings[0].RuleID != "r-undated" {
		t.Errorf("undated finding misplaced: %v", undated.Findings[0].RuleID)
	}
}

func TestClusterFindingsWideSpanFindingDoesNotBridge(t *testing.T) {
	// A single rule whose evidence spans ~2 years (e.g. amcache matching both a
	// 2024 provisioning entry and the 2026 intrusion) must NOT glue the two
	// episodes into one cluster. Clustering keys on FirstTimestamp only.
	y2024 := time.Date(2024, 7, 24, 23, 39, 0, 0, time.UTC)
	y2026 := time.Date(2026, 6, 2, 14, 25, 0, 0, time.UTC)
	findings := []Finding{
		// benign 2024 provisioning finding
		mkFinding(y2024, true, "prov"),
		// wide-span finding: first evidence in 2024, latest in 2026
		{RuleID: "wide", Evidence: []FindingEvidence{
			{TsUTC: y2024.Add(time.Minute), HasTS: true},
			{TsUTC: y2026.Add(-time.Minute), HasTS: true},
		}},
		// the 2026 attack finding
		mkFinding(y2026, true, "attack"),
	}
	clusters := ClusterFindings(findings, 30*time.Minute)
	if len(clusters) != 2 {
		t.Fatalf("wide-span finding bridged episodes: got %d clusters, want 2", len(clusters))
	}
	// 2024 cluster holds prov + wide (both first-ts in 2024); attack is alone.
	if clusters[0].EndTS.After(y2024.Add(time.Hour)) {
		t.Errorf("2024 cluster EndTS leaked into 2026: %v", clusters[0].EndTS)
	}
	if len(clusters[1].Findings) != 1 || clusters[1].Findings[0].RuleID != "attack" {
		t.Errorf("attack finding not isolated: %+v", clusters[1].Findings)
	}
}

func TestClusterFindingsEndTSExpandsAcrossFindings(t *testing.T) {
	t0 := time.Date(2026, 5, 19, 13, 0, 0, 0, time.UTC)
	t1 := t0.Add(15 * time.Minute)
	t2 := t0.Add(25 * time.Minute)
	findings := []Finding{
		{RuleID: "r1", Evidence: []FindingEvidence{{TsUTC: t0, HasTS: true}, {TsUTC: t1, HasTS: true}}},
		{RuleID: "r2", Evidence: []FindingEvidence{{TsUTC: t2, HasTS: true}}},
	}
	clusters := ClusterFindings(findings, 30*time.Minute)
	if len(clusters) != 1 {
		t.Fatalf("expected 1 cluster, got %d", len(clusters))
	}
	if !clusters[0].EndTS.Equal(t2) {
		t.Errorf("EndTS should expand to %v, got %v", t2, clusters[0].EndTS)
	}
}
