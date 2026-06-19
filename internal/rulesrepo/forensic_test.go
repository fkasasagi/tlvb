package rulesrepo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeForensic(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestForensicLoader(t *testing.T) {
	root := t.TempDir()
	// A valid multi-artifact rule whose mitre/artifact lists contain dups that
	// must be deduped, and whose level is uppercase (must be normalised).
	writeForensic(t, root, "exec_from_download.yml", `---
id: forensic-exec-from-download
title: Executable ran from Downloads
level: HIGH
artifacts: [prefetch, amcache, prefetch]
mitre:
  tactics: [execution, execution]
  techniques: [T1204.002]
description: A binary ran from a user Downloads folder.
detection: Match the documented path field per artifact for an .exe under Downloads.
`)
	// A rule with no level → defaults to medium; nested .yaml extension + subdir.
	writeForensic(t, filepath.Join(root, "sub"), "browser.yaml", `---
id: forensic-browser-provenance
title: Browser payload provenance
artifacts: [browser_history]
description: Typed download of an executable.
`)
	// Malformed (no id) → must Skip.
	writeForensic(t, root, "broken.yml", "title: no id here\nartifacts: [mft]\n")

	rules, err := NewForensicLoader(root).LoadAll(context.Background())
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules (2 valid + 1 skip), got %d", len(rules))
	}

	var exec, browser, broken *RawRule
	for i := range rules {
		switch rules[i].RuleID {
		case "forensic-exec-from-download":
			exec = &rules[i]
		case "forensic-browser-provenance":
			browser = &rules[i]
		}
		if rules[i].Skip {
			broken = &rules[i]
		}
	}

	if exec == nil {
		t.Fatal("exec rule not found")
	}
	if exec.RuleSource != "forensic" {
		t.Errorf("source wrong: %q", exec.RuleSource)
	}
	if exec.Level != "high" {
		t.Errorf("level should be lowercased to 'high', got %q", exec.Level)
	}
	// prefetch appears twice → dedup to {prefetch, amcache} preserving order.
	if len(exec.PrefilterArtifacts) != 2 ||
		exec.PrefilterArtifacts[0] != "prefetch" || exec.PrefilterArtifacts[1] != "amcache" {
		t.Errorf("prefilter dedup/order wrong: %v", exec.PrefilterArtifacts)
	}
	if len(exec.MITRETactics) != 1 || exec.MITRETactics[0] != "execution" {
		t.Errorf("tactics dedup wrong: %v", exec.MITRETactics)
	}
	if len(exec.MITRETechniques) != 1 || exec.MITRETechniques[0] != "T1204.002" {
		t.Errorf("techniques wrong: %v", exec.MITRETechniques)
	}
	if exec.RuleSHA256 == "" || exec.RawContent == "" || exec.Title == "" {
		t.Errorf("sha/rawcontent/title wrong: %+v", exec)
	}

	if browser == nil {
		t.Fatal("browser rule not found (subdir/.yaml not walked?)")
	}
	if browser.Level != "medium" {
		t.Errorf("missing level should default to 'medium', got %q", browser.Level)
	}

	if broken == nil || broken.SkipReason == "" {
		t.Error("malformed entry should be Skip with a reason")
	}
}
