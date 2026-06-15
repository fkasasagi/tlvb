package tier3

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tlvb/tlvb/internal/tier2"
)

func TestContainsJapanese(t *testing.T) {
	cases := map[string]bool{
		"powershell.exe spawned mimi.exe": false,
		"攻撃者は RDP でログインした":                true,
		"T1059.001 was observed":          false,
		"ブルートフォース":                        true,
	}
	for s, want := range cases {
		if got := containsJapanese(s); got != want {
			t.Errorf("containsJapanese(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestSynthesisLang(t *testing.T) {
	// Explicit stamp wins.
	if got := synthesisLang(&tier2.CaseSynthesis{Language: "EN"}); got != "en" {
		t.Errorf("stamped EN → %q, want en", got)
	}
	// No stamp → sniff Japanese prose.
	jaCS := &tier2.CaseSynthesis{ExecBrief: "攻撃の概要"}
	if got := synthesisLang(jaCS); got != "ja" {
		t.Errorf("ja prose → %q, want ja", got)
	}
	// No stamp, English-only prose → en.
	enCS := &tier2.CaseSynthesis{ExecBrief: "Overview of the intrusion."}
	if got := synthesisLang(enCS); got != "en" {
		t.Errorf("en prose → %q, want en", got)
	}
}

func TestCollectTranslatableWriteBack(t *testing.T) {
	cs := &tier2.CaseSynthesis{
		OverallStory:  "story",
		ExecBrief:     "brief",
		TimelineNotes: []string{"note1", ""},
		OpenQuestions: []string{"q1"},
		Clusters: []tier2.SynthCluster{
			{Narrative: "narr", OpenQuestions: []string{"cq1"},
				ActiveSearch: []tier2.ActiveSearchResult{{Question: "asq", Answer: "asa"}}},
		},
	}
	ptrs := collectTranslatable(cs)
	// story, brief, note1 (empty skipped), q1, narr, cq1, asq, asa = 8
	if len(ptrs) != 8 {
		t.Fatalf("collectTranslatable = %d pointers, want 8", len(ptrs))
	}
	for _, p := range ptrs {
		*p = "X" + *p
	}
	if cs.OverallStory != "Xstory" || cs.Clusters[0].ActiveSearch[0].Answer != "Xasa" {
		t.Errorf("write-back via pointers did not mutate cs: %+v", cs)
	}
}

func TestMaybeTranslateNoOp(t *testing.T) {
	// Opt-in off → untouched even on language mismatch.
	cs := tier2.CaseSynthesis{Language: "ja", ExecBrief: "概要"}
	maybeTranslateNarratives(Config{Language: "en", TranslateNarratives: false}, &cs)
	if cs.ExecBrief != "概要" {
		t.Errorf("opt-in off should not translate, got %q", cs.ExecBrief)
	}
	// Same language → untouched (and no LLM call).
	cs2 := tier2.CaseSynthesis{Language: "ja", ExecBrief: "概要"}
	maybeTranslateNarratives(Config{Language: "ja", TranslateNarratives: true}, &cs2)
	if cs2.ExecBrief != "概要" {
		t.Errorf("same language should not translate, got %q", cs2.ExecBrief)
	}
}

// TestMaybeTranslateRoundTrip stubs the Anthropic API and verifies the prose is
// rewritten in place (and only the prose — a rule title stays verbatim).
func TestMaybeTranslateRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(raw, &req)
		var in struct {
			Segments []string `json:"segments"`
		}
		_ = json.Unmarshal([]byte(req.Messages[0].Content), &in)
		out := make([]string, len(in.Segments))
		for i, s := range in.Segments {
			out[i] = "[EN] " + s // deterministic stand-in for a translation
		}
		segs, _ := json.Marshal(struct {
			Segments []string `json:"segments"`
		}{Segments: out})
		resp := map[string]any{
			"content": []map[string]string{{"type": "text", "text": string(segs)}},
			"usage":   map[string]int{"input_tokens": 10, "output_tokens": 20},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	t.Setenv("ANTHROPIC_API_KEY", "test-key") // force the Anthropic transport
	old := consistencyAPIURL
	consistencyAPIURL = srv.URL
	defer func() { consistencyAPIURL = old }()

	cs := tier2.CaseSynthesis{
		Language:     "ja",
		ExecBrief:    "攻撃の概要",
		OverallStory: "詳細な物語",
		Clusters: []tier2.SynthCluster{{
			Narrative:   "クラスタの解説",
			FindingRefs: []tier2.FindingRef{{Source: "sigma", RuleID: "x", Title: "Mimikatz Execution"}},
		}},
	}
	maybeTranslateNarratives(Config{Language: "en", TranslateNarratives: true}, &cs)

	if !strings.HasPrefix(cs.ExecBrief, "[EN] ") || !strings.HasPrefix(cs.Clusters[0].Narrative, "[EN] ") {
		t.Errorf("prose not translated: brief=%q narr=%q", cs.ExecBrief, cs.Clusters[0].Narrative)
	}
	if cs.Clusters[0].FindingRefs[0].Title != "Mimikatz Execution" {
		t.Errorf("rule title must stay verbatim, got %q", cs.Clusters[0].FindingRefs[0].Title)
	}
	if cs.Language != "en" {
		t.Errorf("cs.Language should be stamped en after translation, got %q", cs.Language)
	}
}
