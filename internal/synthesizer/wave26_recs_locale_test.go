package synthesizer

import (
	"strings"
	"testing"
)

// Wave 26: Recommendations ja/en locale pin. Each key must have both
// variants and they must be non-empty.

func TestRecsLocale_AllEntriesHaveBothLanguages(t *testing.T) {
	if len(recsLocale) == 0 {
		t.Fatal("recsLocale is empty")
	}
	for key, e := range recsLocale {
		if strings.TrimSpace(e.JA) == "" {
			t.Errorf("recsLocale[%q].JA is empty", key)
		}
		if strings.TrimSpace(e.EN) == "" {
			t.Errorf("recsLocale[%q].EN is empty", key)
		}
	}
}

func TestRec_PicksLangCorrectly(t *testing.T) {
	en := rec("en", "impact_containment")
	ja := rec("ja", "impact_containment")
	if !strings.Contains(en, "Isolate") {
		t.Errorf("en variant missing expected text: %s", en)
	}
	if !strings.Contains(ja, "隔離") {
		t.Errorf("ja variant missing expected text: %s", ja)
	}
	if en == ja {
		t.Errorf("en and ja should differ; both = %s", en)
	}
}

func TestRec_UnknownLangFallsBackToEN(t *testing.T) {
	// Any unrecognised lang (e.g. "fr", "zh", "") falls back to EN —
	// most conservative default for international report generation.
	got := rec("fr", "impact_containment")
	if !strings.Contains(got, "Isolate") {
		t.Errorf("unknown lang should fall back to EN: %s", got)
	}
	got2 := rec("", "impact_containment")
	if !strings.Contains(got2, "Isolate") {
		t.Errorf("empty lang should fall back to EN: %s", got2)
	}
}

func TestRec_UnknownKeyReturnsKey(t *testing.T) {
	// Defensive: an unknown key returns the key itself rather than
	// crashing or returning empty. Helps spot typos in dev.
	got := rec("ja", "definitely_does_not_exist_xyz")
	if got != "definitely_does_not_exist_xyz" {
		t.Errorf("unknown key should return the key string itself, got %q", got)
	}
}

func TestRecsLocale_ExpectedKeysPresent(t *testing.T) {
	// Pin the set of keys generateRecommendations uses so renaming a
	// key without updating both sides fails fast.
	expected := []string{
		"impact_containment",
		"impact_recovery",
		"cred_containment",
		"cred_eradication",
		"persistence_eradication",
		"lateral_containment",
		"r1_log_clear",
	}
	for _, k := range expected {
		if _, ok := recsLocale[k]; !ok {
			t.Errorf("recsLocale missing required key %q", k)
		}
	}
}

func TestConfig_HasLanguageField(t *testing.T) {
	cfg := Config{Language: "ja"}
	if cfg.Language != "ja" {
		t.Errorf("Config.Language field missing or wrong: %v", cfg.Language)
	}
}
