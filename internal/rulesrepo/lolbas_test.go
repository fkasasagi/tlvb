package rulesrepo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeLOLBAS(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLOLBASLoader(t *testing.T) {
	root := t.TempDir()
	// A valid LOLBin with two commands sharing a MitreID (must dedup) plus a
	// distinct one.
	writeLOLBAS(t, filepath.Join(root, "OSBinaries"), "Certutil.yml", `---
Name: Certutil.exe
Description: Windows binary for handling certificates
Commands:
  - Command: certutil.exe -urlcache -f {REMOTEURL} {PATH}
    Usecase: Download file
    Category: Download
    MitreID: T1105
  - Command: certutil.exe -URL {REMOTEURL}
    Usecase: Download file
    Category: Download
    MitreID: T1105
  - Command: certutil -encode {PATH} {OUT}
    Usecase: Encode
    Category: Encode
    MitreID: T1027
`)
	// A malformed entry (no Name) → must be Skip.
	writeLOLBAS(t, filepath.Join(root, "OSScripts"), "Broken.yml", "Description: no name here\n")

	rules, err := NewLOLBASLoader(root).LoadAll(context.Background())
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules (1 valid + 1 skip), got %d", len(rules))
	}

	var cert, broken *RawRule
	for i := range rules {
		switch {
		case rules[i].RuleID == "Certutil.exe":
			cert = &rules[i]
		case rules[i].Skip:
			broken = &rules[i]
		}
	}
	if cert == nil {
		t.Fatal("Certutil rule not found")
	}
	if cert.RuleSource != "lolbas" || cert.Level != "medium" {
		t.Errorf("source/level wrong: %+v", cert)
	}
	if len(cert.PrefilterArtifacts) != 1 || cert.PrefilterArtifacts[0] != "evtx" {
		t.Errorf("prefilter wrong: %v", cert.PrefilterArtifacts)
	}
	// T1105 appears twice → dedup to {T1105, T1027}.
	if len(cert.MITRETechniques) != 2 {
		t.Errorf("expected 2 distinct techniques, got %v", cert.MITRETechniques)
	}
	if cert.RuleSHA256 == "" || cert.RawContent == "" || cert.Title != "Certutil.exe" {
		t.Errorf("sha/rawcontent/title wrong: %+v", cert)
	}
	if broken == nil || broken.SkipReason == "" {
		t.Error("malformed entry should be Skip with a reason")
	}
}
