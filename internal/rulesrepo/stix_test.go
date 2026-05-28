package rulesrepo

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestSTIXLoaderSmoke(t *testing.T) {
	root := "../../rules/stix/mitre-attack/enterprise-attack/attack-pattern"
	if _, err := os.Stat(root); err != nil {
		t.Skipf("stix submodule not checked out at %s — skipping", root)
	}
	l := NewSTIXLoader(root)
	rules, err := l.LoadAll(context.Background())
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(rules) < 100 {
		t.Fatalf("expected at least 100 stix techniques, got %d", len(rules))
	}
	var built, revoked, deprecated, nonwin, hasT, hasName int
	for _, r := range rules {
		if r.Skip {
			switch {
			case strings.Contains(r.SkipReason, "revoked"):
				revoked++
			case strings.Contains(r.SkipReason, "deprecated"):
				deprecated++
			case strings.Contains(r.SkipReason, "Windows"):
				nonwin++
			}
		} else {
			built++
			if strings.HasPrefix(r.RuleID, "T") {
				hasT++
			}
			if r.Title != "" {
				hasName++
			}
		}
	}
	t.Logf("stix rules: total=%d built=%d (T*=%d named=%d) skipped: revoked=%d deprecated=%d non-windows=%d",
		len(rules), built, hasT, hasName, revoked, deprecated, nonwin)
	if built == 0 {
		t.Fatal("no built stix rules")
	}
	if hasT != built {
		t.Errorf("not all built rules have T-prefixed rule_id (%d/%d)", hasT, built)
	}
	if hasName != built {
		t.Errorf("not all built rules have a name (%d/%d)", hasName, built)
	}
}
