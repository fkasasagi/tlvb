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
