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
	if strings.TrimSpace(got) != "" {
		t.Errorf("expected empty output for all-empty narratives, got %q", got)
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
