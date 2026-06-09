package tier2

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBuildOverallUserMessageCompacts(t *testing.T) {
	longNarrative := strings.Repeat("x", 3000)
	clusters := []Cluster{
		{
			ID:          1,
			StartTS:     time.Now(),
			EndTS:       time.Now(),
			Narrative:   longNarrative,
			AttackPhase: "execution",
		},
	}
	// Without compaction: narrative preserved as-is.
	full, err := buildOverallUserMessage(clusters, false, "ja")
	if err != nil {
		t.Fatalf("full: %v", err)
	}
	if !strings.Contains(full, longNarrative) {
		t.Error("non-compact build should preserve full narrative")
	}
	// With compaction: narrative truncated to 1500 + marker.
	compact, err := buildOverallUserMessage(clusters, true, "ja")
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	if strings.Contains(compact, longNarrative) {
		t.Error("compact build should NOT contain full narrative")
	}
	if !strings.Contains(compact, "...[truncated for retry]") {
		t.Error("compact build should include truncation marker")
	}
}

func TestFallbackOverallStory(t *testing.T) {
	t0 := time.Date(2026, 5, 19, 13, 50, 0, 0, time.UTC)
	t1 := time.Date(2026, 5, 19, 14, 20, 0, 0, time.UTC)
	clusters := []Cluster{
		{
			ID:          1,
			StartTS:     t0,
			EndTS:       t1,
			AttackPhase: "execution",
			Narrative:   "cluster 1 narrative",
		},
		{
			ID:          2,
			AttackPhase: "lateral-movement",
			Narrative:   "cluster 2 narrative",
		},
	}
	got := fallbackOverallStory(clusters, "ja")
	// The fallback now concatenates raw cluster narratives only — no
	// "(LLM overall synthesis unavailable...)" banner (P1) and no
	// "Cluster #N"/phase/timestamp scaffolding leaking into the prose.
	if strings.Contains(got, "LLM overall synthesis unavailable") {
		t.Error("fallback must NOT expose the system error banner")
	}
	for _, unwanted := range []string{"Cluster #1", "Cluster #2", "2026-05-19T13:50:00Z"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("fallback should not embed scaffolding %q", unwanted)
		}
	}
	for _, want := range []string{"cluster 1 narrative", "cluster 2 narrative"} {
		if !strings.Contains(got, want) {
			t.Errorf("fallback missing narrative %q", want)
		}
	}
}

func TestFallbackOverallStoryEmptyNarrative(t *testing.T) {
	got := fallbackOverallStory([]Cluster{
		{ID: 1, AttackPhase: "execution", Narrative: ""},
	}, "ja")
	// An empty narrative contributes nothing — no "(no narrative)" placeholder
	// leaking into the executive summary.
	if strings.Contains(got, "(no narrative)") {
		t.Error("empty narrative must not render a placeholder")
	}
	// The fallback now always carries a warning banner (issue #51) so the
	// operator knows the LLM overall synthesis failed even when no narrative
	// text survives. With all narratives empty the output is just the banner.
	if got != fallbackOverallStoryPrefixJA {
		t.Errorf("expected banner-only output, got %q", got)
	}
}

func TestFallbackOverallStoryDropsNoise(t *testing.T) {
	t0 := time.Date(2026, 5, 19, 13, 50, 0, 0, time.UTC)
	t1 := time.Date(2026, 5, 19, 14, 20, 0, 0, time.UTC)
	clusters := []Cluster{
		{ID: 1, StartTS: t0, EndTS: t1, AttackPhase: "execution", Narrative: "real attack narrative"},
		// noise: empty attack phase
		{ID: 2, AttackPhase: "", Narrative: "VM first boot — likely benign"},
		// noise: narrative keyword
		{ID: 3, AttackPhase: "persistence", Narrative: "これは誤検知と思われる正規のインストール"},
	}
	got := fallbackOverallStory(clusters, "en")
	if !strings.HasPrefix(got, fallbackOverallStoryPrefixEN) {
		t.Errorf("fallback must start with the warning banner, got %q", got)
	}
	if !strings.Contains(got, "real attack narrative") {
		t.Error("attack-cluster narrative must be present")
	}
	for _, noise := range []string{"VM first boot", "誤検知"} {
		if strings.Contains(got, noise) {
			t.Errorf("noise narrative %q must be dropped from the fallback", noise)
		}
	}
}

func TestIsNoiseCluster(t *testing.T) {
	cases := []struct {
		name      string
		phase     string
		narrative string
		want      bool
	}{
		{"empty phase", "", "anything", true},
		{"unknown phase", "unknown", "anything", true},
		{"attack phase clean", "execution", "mimikatz dumped LSASS", false},
		{"false positive keyword", "persistence", "this is a false positive", true},
		{"japanese 誤検知", "lateral-movement", "正規のバックグラウンド処理で誤検知", true},
		{"sysprep keyword", "execution", "Sysprep generalization run", true},
		{"benign word alone is not enough", "execution", "the binary is not benign at all", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsNoiseCluster(c.phase, c.narrative); got != c.want {
				t.Errorf("IsNoiseCluster(%q, %q) = %v, want %v", c.phase, c.narrative, got, c.want)
			}
		})
	}
}

func TestTemporalOutlierClusters(t *testing.T) {
	mk := func(year int) Cluster {
		ts := time.Date(year, 5, 19, 12, 0, 0, 0, time.UTC)
		return Cluster{StartTS: ts, EndTS: ts.Add(30 * time.Minute)}
	}
	// Three clusters in 2026 + one Sysprep-era cluster in 2024.
	clusters := []Cluster{mk(2026), mk(2026), mk(2026), mk(2024)}
	flags := temporalOutlierClusters(clusters)
	if flags[3] != true {
		t.Error("the 2024 cluster should be flagged as a temporal outlier")
	}
	for i := 0; i < 3; i++ {
		if flags[i] {
			t.Errorf("cluster %d (2026) should not be a temporal outlier", i)
		}
	}
	// Too few clusters for a stable median → nothing flagged.
	if got := temporalOutlierClusters([]Cluster{mk(2026), mk(2024)}); got[1] {
		t.Error("with <3 clusters no temporal outlier should be flagged")
	}
}

func TestOverallSynthTimeout(t *testing.T) {
	base := 5 * time.Minute
	// Single cluster: base 2× + 30s.
	if got := overallSynthTimeout(base, 1); got != 10*time.Minute+30*time.Second {
		t.Errorf("1 cluster: got %v", got)
	}
	// 11 clusters (tamu2_3): 10m + 5m30s = 15m30s — comfortably above the flat
	// 5-min budget that caused the timeout-driven fallback.
	if got := overallSynthTimeout(base, 11); got != 15*time.Minute+30*time.Second {
		t.Errorf("11 clusters: got %v", got)
	}
	if got := overallSynthTimeout(base, 11); got <= base {
		t.Errorf("overall budget must exceed the per-cluster budget, got %v", got)
	}
	// Capped at 20 min for pathological cluster counts.
	if got := overallSynthTimeout(base, 1000); got != 20*time.Minute {
		t.Errorf("cap: got %v", got)
	}
	// Zero per-cluster falls back to the 5-min default base.
	if got := overallSynthTimeout(0, 0); got != 10*time.Minute {
		t.Errorf("zero per-cluster: got %v", got)
	}
}

func TestBuildOverallUserMessageValidJSON(t *testing.T) {
	// Sanity: the output is valid JSON that parses as an array of objects.
	clusters := []Cluster{
		{ID: 1, AttackPhase: "execution", Narrative: "a"},
		{ID: 2, AttackPhase: "impact", Narrative: "b"},
	}
	msg, err := buildOverallUserMessage(clusters, false, "ja")
	if err != nil {
		t.Fatal(err)
	}
	// extract the JSON array portion
	body, err := extractFirstJSONValue(msg)
	if err != nil {
		t.Fatalf("extract JSON: %v", err)
	}
	var arr []map[string]any
	if err := json.Unmarshal([]byte(body), &arr); err != nil {
		t.Fatalf("body not valid JSON: %v\n%s", err, body)
	}
	if len(arr) != 2 {
		t.Errorf("expected 2 clusters in JSON, got %d", len(arr))
	}
}
