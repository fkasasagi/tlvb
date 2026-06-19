package casedb

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSchemaVersionStable(t *testing.T) {
	// Same DDL → same version, deterministic across runs.
	v1 := SchemaVersion()
	v2 := SchemaVersion()
	if v1 != v2 {
		t.Fatalf("SchemaVersion not stable across calls: %q vs %q", v1, v2)
	}
	if !strings.HasPrefix(v1, "uev-") {
		t.Errorf("SchemaVersion should have uev- prefix, got %q", v1)
	}
	if len(v1) != len("uev-")+16 {
		t.Errorf("SchemaVersion unexpected length: %q (want uev- + 16 hex)", v1)
	}
}

func TestSchemaVersionChangesWhenDDLChanges(t *testing.T) {
	// Sanity check: if someone changes UnifiedEventsDDL, the version key
	// changes accordingly. We verify by hand-computing a deliberately
	// modified DDL hash and confirming it differs from the real one.
	modified := UnifiedEventsDDL + "\n-- one more byte"
	h := sha256.Sum256([]byte(modified))
	mockVer := "uev-" + hex.EncodeToString(h[:8])
	if mockVer == SchemaVersion() {
		t.Fatal("Hash collision between real and modified DDL — schema_version is not invalidated correctly")
	}
}

func TestSchemaDocMentionsKeyColumns(t *testing.T) {
	doc := SchemaDoc()
	for _, col := range []string{"case_id", "artifact_id", "audit_id", "ts_utc", "event_type", "payload_json"} {
		if !strings.Contains(doc, col) {
			t.Errorf("SchemaDoc missing column %q — LLM prompt would be incomplete", col)
		}
	}
	// LLM SQL constraints: must mention case_id ? predicate requirement.
	if !strings.Contains(doc, "case_id = ?") {
		t.Error("SchemaDoc should require parameterised case_id predicate")
	}
}

// TestSchemaVersionForSectioned locks the per-artifact sectioning contract that
// lets us add/expand a forensic section without rebuilding unrelated rules.
func TestSchemaVersionForSectioned(t *testing.T) {
	evtx := SchemaVersionFor([]string{"evtx"})

	// Deterministic + well-formed.
	if evtx != SchemaVersionFor([]string{"evtx"}) {
		t.Fatal("SchemaVersionFor not deterministic")
	}
	if !strings.HasPrefix(evtx, "uev-") || len(evtx) != len("uev-")+16 {
		t.Errorf("malformed key %q", evtx)
	}

	// A per-artifact key must differ from the whole-doc key and from other
	// artifacts — that difference is what scopes invalidation.
	if evtx == SchemaVersion() {
		t.Error("evtx-only key must differ from whole-doc SchemaVersion")
	}
	if evtx == SchemaVersionFor([]string{"prefetch"}) {
		t.Error("evtx and prefetch keys must differ")
	}

	// Order-independent and deduplicated.
	if SchemaVersionFor([]string{"evtx", "amcache"}) != SchemaVersionFor([]string{"amcache", "evtx"}) {
		t.Error("key must be order-independent")
	}
	if SchemaVersionFor([]string{"evtx", "evtx"}) != evtx {
		t.Error("duplicate artifacts must not change the key")
	}

	// Empty / whitespace prefilter falls back to the whole-doc key (a rule that
	// may read anything depends on everything).
	if SchemaVersionFor(nil) != SchemaVersion() {
		t.Error("empty prefilter must fall back to SchemaVersion")
	}
	if SchemaVersionFor([]string{"", "  "}) != SchemaVersion() {
		t.Error("whitespace-only prefilter must fall back to SchemaVersion")
	}

	// Artifacts without a dedicated section share the misc section, so they
	// hash to the same key — verified against two known section-less artifacts.
	if SchemaVersionFor([]string{"shellbags"}) != SchemaVersionFor([]string{"scheduled_tasks"}) {
		t.Error("section-less artifacts should share the misc-section key")
	}
	if _, ok := schemaSections["shellbags"]; ok {
		t.Error("precondition: shellbags should NOT have a dedicated section")
	}
}

// TestSchemaDocCoversForensicExecutionArtifacts guards that the doc actually
// teaches the LLM the (corrected) forensic execution-artifact fields — the gap
// that let browser-downloaded malware go undetected.
func TestSchemaDocCoversForensicExecutionArtifacts(t *testing.T) {
	doc := SchemaDoc()
	for _, want := range []string{
		"artifact_id='prefetch'", "files_loaded",
		"artifact_id='amcache'", "IsOsComponent",
		"artifact_id='registry'", "UserAssist",
		"artifact_id='browser_history'", "Directory listing",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("SchemaDoc missing forensic guidance %q", want)
		}
	}
	// The old doc carried wrong forensic keys; make sure they're gone.
	for _, gone := range []string{"$.ExecutableName", "$.LastVisited"} {
		if strings.Contains(doc, gone) {
			t.Errorf("SchemaDoc still contains stale/wrong key %q", gone)
		}
	}
}
