package rulesrepo

import (
	"context"
	"os"
	"testing"
)

func TestHayabusaLoaderSmoke(t *testing.T) {
	root := "../../rules/hayabusa/upstream/hayabusa"
	if _, err := os.Stat(root); err != nil {
		t.Skipf("hayabusa submodule not checked out at %s — skipping", root)
	}
	l := NewHayabusaLoader(root)
	rules, err := l.LoadAll(context.Background())
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(rules) < 50 {
		t.Fatalf("expected at least 50 hayabusa-original rules, got %d", len(rules))
	}
	var built, skipped, sysmon int
	for _, r := range rules {
		if r.Skip {
			skipped++
			if r.RequiresSysmon {
				sysmon++
			}
		} else {
			built++
			if r.RuleSource != "hayabusa" {
				t.Errorf("built rule has wrong source: %s", r.RuleSource)
			}
		}
	}
	t.Logf("hayabusa rules: total=%d built=%d skipped=%d (sysmon=%d)",
		len(rules), built, skipped, sysmon)
}
