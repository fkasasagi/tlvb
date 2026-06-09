package casedb

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/marcboeker/go-duckdb"
)

// TestReadOnlyEngineBlocksWrites is the read-only BACKSTOP: even if a write
// statement somehow reached the analysis-time connection (e.g. a SELECT-only
// validator bypass), the case DuckDB is opened with access_mode=read_only and
// the engine itself must reject every mutation. This is the last line of
// defence behind the Tier 2 SQL validator (see
// internal/tier2/active_search_bypass_test.go).
func TestReadOnlyEngineBlocksWrites(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cases.duckdb")

	// Create the DB (+schema) read-write, then close so it can be reopened RO.
	rw, err := Open(p, ReadWrite)
	if err != nil {
		t.Fatalf("open read-write: %v", err)
	}
	if err := rw.Close(); err != nil {
		t.Fatalf("close read-write: %v", err)
	}

	// Open a raw read-only connection to the same file — exactly how the MCP
	// server and the Tier 1/2 analysis runtime open it.
	ro, err := sql.Open("duckdb", p+"?access_mode=read_only")
	if err != nil {
		t.Fatalf("open read-only: %v", err)
	}
	defer ro.Close()

	// A read must still succeed.
	var one int
	if err := ro.QueryRow("SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatalf("read-only SELECT should work, got %d err=%v", one, err)
	}

	// Every mutation must be rejected by the engine.
	writes := map[string]string{
		"create": "CREATE TABLE evil (x INTEGER)",
		"insert": "INSERT INTO unified_events (case_id) VALUES ('x')",
		"update": "UPDATE unified_events SET computer = 'x'",
		"delete": "DELETE FROM unified_events",
		"drop":   "DROP TABLE unified_events",
	}
	for name, q := range writes {
		if _, err := ro.Exec(q); err == nil {
			t.Errorf("read-only connection ACCEPTED a write (%s): %q", name, q)
		}
	}
}

// TestReadOnlyManagerGuardsWrites confirms the Manager-level guard rejects write
// APIs when opened ReadOnly — a check in FRONT of the engine, so a bug in a
// caller fails fast with a clear error instead of relying on the driver.
func TestReadOnlyManagerGuardsWrites(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cases.duckdb")
	rw, err := Open(p, ReadWrite)
	if err != nil {
		t.Fatalf("open read-write: %v", err)
	}
	rw.Close()

	ro, err := Open(p, ReadOnly)
	if err != nil {
		t.Fatalf("open read-only: %v", err)
	}
	defer ro.Close()

	if err := ro.DeleteCase(context.Background(), "any"); err == nil {
		t.Error("DeleteCase on a read-only Manager should return an error, got nil")
	}
}
