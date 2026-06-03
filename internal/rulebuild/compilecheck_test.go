package rulebuild

import "testing"

const testUnifiedEventsDDL = `CREATE TABLE unified_events (
	case_id      VARCHAR NOT NULL,
	evidence_id  VARCHAR,
	artifact_id  VARCHAR NOT NULL,
	audit_id     VARCHAR NOT NULL,
	ts_utc       TIMESTAMP,
	event_type   VARCHAR NOT NULL,
	computer     VARCHAR,
	payload_json VARCHAR NOT NULL
)`

func TestSQLCompiler(t *testing.T) {
	c, err := NewSQLCompiler(testUnifiedEventsDDL)
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	defer c.Close()

	// Valid SQL that runs against the schema → no error.
	ok := "SELECT audit_id, ts_utc, artifact_id, event_type FROM unified_events WHERE case_id = ? AND artifact_id = 'evtx' AND json_extract_string(payload_json, '$.EventId') = '4688'"
	if err := c.Check(ok); err != nil {
		t.Errorf("valid SQL rejected: %v", err)
	}

	// regexp_like does not exist in DuckDB → must be caught.
	if err := c.Check("SELECT audit_id, ts_utc, artifact_id, event_type FROM unified_events WHERE case_id = ? AND regexp_like(computer, 'host')"); err == nil {
		t.Error("regexp_like should be rejected by compile-check")
	}
	// regexp_matches IS supported → must pass.
	if err := c.Check("SELECT audit_id, ts_utc, artifact_id, event_type FROM unified_events WHERE case_id = ? AND regexp_matches(computer, 'host')"); err != nil {
		t.Errorf("regexp_matches should pass: %v", err)
	}
	// Malformed regex literal → caught at execution even on an empty table.
	if err := c.Check(`SELECT audit_id, ts_utc, artifact_id, event_type FROM unified_events WHERE case_id = ? AND regexp_matches(computer, '[^ \]')`); err == nil {
		t.Error("malformed regex should be rejected")
	}
	// A wholly unknown column → bind/catalog error.
	if err := c.Check("SELECT audit_id FROM unified_events WHERE case_id = ? AND no_such_col = 1"); err == nil {
		t.Error("unknown column should be rejected")
	}

	// nil compiler is a no-op.
	var nilC *SQLCompiler
	if err := nilC.Check("SELECT 1"); err != nil {
		t.Errorf("nil compiler Check should be nil, got %v", err)
	}
}

func TestNewSQLCompilerEmptyDDL(t *testing.T) {
	// Empty DDL disables the gate (nil compiler, no error).
	c, err := NewSQLCompiler("")
	if err != nil {
		t.Fatalf("empty ddl: %v", err)
	}
	if c != nil {
		t.Fatal("empty ddl should yield a nil compiler")
	}
}
