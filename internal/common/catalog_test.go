package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validCatalogYAML = `version: "test-1"
schema: "uev-1"
artifacts:
  - id: evtx
    name: Windows Event Logs
    tier: "0"
    safety_tier: A
    tool:
      name: evtx_dump
    input:
      mode: file
      pattern: "*.evtx"
    caveats:
      - needs admin
  - id: amcache
    name: Amcache
    tier: "0"
    tool:
      name: AmcacheParser
    input:
      mode: file
`

func TestLoadArtifactCatalog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifacts.yaml")
	if err := os.WriteFile(path, []byte(validCatalogYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := LoadArtifactCatalog(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Version() != "test-1" {
		t.Errorf("Version() = %q, want test-1", c.Version())
	}
	if c.Count() != 2 {
		t.Errorf("Count() = %d, want 2", c.Count())
	}
	d, ok := c.Get("evtx")
	if !ok || d.Name != "Windows Event Logs" || d.Tool.Name != "evtx_dump" || d.Input.Mode != "file" {
		t.Errorf("Get(evtx) = %+v, ok=%v", d, ok)
	}
	if _, ok := c.Get("nonexistent"); ok {
		t.Error("Get(nonexistent) should return ok=false")
	}
	sum := c.Summary()
	if len(sum) != 2 {
		t.Fatalf("Summary() len = %d, want 2", len(sum))
	}
	// Summary preserves source order and the slim projection.
	if sum[0].ID != "evtx" || sum[0].Tool != "evtx_dump" ||
		sum[0].InputMode != "file" || len(sum[0].Caveats) != 1 {
		t.Errorf("Summary()[0] = %+v", sum[0])
	}
	if sum[1].ID != "amcache" {
		t.Errorf("Summary()[1].ID = %q, want amcache", sum[1].ID)
	}
}

func TestLoadArtifactCatalogErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadArtifactCatalog(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("missing file should error")
	}
	cases := map[string]string{
		"no_artifacts": "version: x\nartifacts: []\n",
		"missing_id":   "version: x\nartifacts:\n  - name: NoID\n",
		"duplicate_id": "version: x\nartifacts:\n  - id: dup\n  - id: dup\n",
		"bad_yaml":     "version: x\nartifacts: [unterminated\n",
	}
	for name, body := range cases {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".yaml")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadArtifactCatalog(p); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
