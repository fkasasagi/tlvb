package tier3

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The explicit overall_story_fallback flag must trigger the executive-summary
// warning banner even when the story carries no legacy "[NOTE:" prefix.
func TestRenderHTML_FallbackFlagShowsBanner(t *testing.T) {
	cs := makeCS()
	cs.OverallStoryFallback = true // story text itself has no banner prefix
	_, outDir := renderFromSynth(t, cs, []string{"html"}, "en")
	body, err := os.ReadFile(filepath.Join(outDir, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "auto-stitch of the attack-cluster narratives") {
		t.Error("fallback banner missing despite overall_story_fallback=true")
	}
	// Atomic write: no temp file may remain next to the report.
	if _, err := os.Stat(filepath.Join(outDir, "report.html.tmp")); !os.IsNotExist(err) {
		t.Errorf("leftover report.html.tmp (stat err=%v)", err)
	}
}

func TestRenderHTML_NoFallbackBannerByDefault(t *testing.T) {
	_, outDir := renderFromSynth(t, makeCS(), []string{"html"}, "en")
	body, err := os.ReadFile(filepath.Join(outDir, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "auto-stitch of the attack-cluster narratives") {
		t.Error("fallback banner shown for a non-fallback synthesis")
	}
}
