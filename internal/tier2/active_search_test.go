package tier2

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/marcboeker/go-duckdb"
)

func TestValidateActiveSearchSQL(t *testing.T) {
	cases := []struct {
		sql, wantErr string
	}{
		// OK cases
		{"SELECT audit_id, ts_utc, artifact_id, event_type FROM unified_events WHERE case_id = ? LIMIT 50", ""},
		{"select audit_id from unified_events where case_id = ? AND artifact_id='prefetch' limit 100", ""},
		// Reject cases
		{"", "empty"},
		{"DELETE FROM unified_events WHERE case_id = ?", "must start with SELECT"},
		{"SELECT * FROM unified_events", "case_id"},
		{"SELECT audit_id FROM unified_events WHERE case_id = ?;", "semicolon"},
		{"SELECT audit_id FROM unified_events WHERE case_id = ? AND audit_id = ?", "exactly one ?"},
		{"SELECT audit_id FROM unified_events WHERE case_id = ?; DROP TABLE foo", "disallowed"},
		// dangerous keyword inside a string literal is OK
		{"SELECT audit_id, ts_utc, artifact_id, event_type FROM unified_events WHERE case_id = ? AND payload_json ILIKE '%vssadmin delete shadows%' LIMIT 10", ""},
	}
	for i, c := range cases {
		err := validateActiveSearchSQL(c.sql)
		if c.wantErr == "" {
			if err != nil {
				t.Errorf("case %d: unexpected error: %v (SQL: %q)", i, err, c.sql)
			}
			continue
		}
		if err == nil {
			t.Errorf("case %d: expected error containing %q, got nil (SQL: %q)", i, c.wantErr, c.sql)
			continue
		}
		if !contains(err.Error(), c.wantErr) {
			t.Errorf("case %d: error %q does not contain %q", i, err.Error(), c.wantErr)
		}
	}
}

func TestParseActiveSearchEntries(t *testing.T) {
	cases := []struct {
		name, input string
		wantCount   int
	}{
		{"empty array", "[]", 0},
		{"single entry", `[{"question":"q1","rationale":"r1","sql":"SELECT 1"}]`, 1},
		{"markdown wrapped",
			"```json\n[{\"question\":\"q1\",\"rationale\":\"r1\",\"sql\":\"SELECT 1\"}]\n```",
			1},
		{"prose preamble",
			"Here are the SQLs:\n\n[{\"question\":\"q\",\"sql\":\"SELECT 1\"}]",
			1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseActiveSearchEntries(c.input)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(got) != c.wantCount {
				t.Errorf("count: got %d, want %d", len(got), c.wantCount)
			}
		})
	}
}

func TestExecActiveSQL(t *testing.T) {
	dir := t.TempDir()
	dbpath := filepath.Join(dir, "cases.duckdb")
	db, err := sql.Open("duckdb", dbpath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE unified_events (
		case_id VARCHAR NOT NULL, evidence_id VARCHAR, artifact_id VARCHAR NOT NULL,
		audit_id VARCHAR NOT NULL, ts_utc TIMESTAMP, event_type VARCHAR NOT NULL,
		computer VARCHAR, payload_json VARCHAR NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	ts := time.Date(2026, 5, 19, 14, 0, 0, 0, time.UTC)
	for i, payload := range []string{
		`{"x":"hit-1"}`, `{"x":"hit-2"}`, `{"x":"hit-3"}`,
	} {
		audit := []string{"aud-1", "aud-2", "aud-3"}[i]
		if _, err := db.Exec(
			`INSERT INTO unified_events VALUES (?, 'EV1', 'evtx', ?, ?, 'evtx', 'WS01', ?)`,
			"C1", audit, ts, payload); err != nil {
			t.Fatal(err)
		}
	}
	sqlText := `SELECT audit_id, ts_utc, artifact_id, event_type,
	                json_extract_string(payload_json, '$.x') AS x
	            FROM unified_events
	            WHERE case_id = ? AND artifact_id = 'evtx'
	            LIMIT 10`
	hits, ev, err := execActiveSQL(context.Background(), db, "C1", sqlText, 10)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if hits != 3 {
		t.Errorf("hits: got %d, want 3", hits)
	}
	if len(ev) != 3 {
		t.Errorf("evidence: got %d, want 3", len(ev))
	}
	if x, _ := ev[0].Excerpt["x"].(string); x == "" {
		t.Errorf("excerpt missing x: %v", ev[0].Excerpt)
	}
}

func TestExecActiveSQLEvidenceCap(t *testing.T) {
	dir := t.TempDir()
	dbpath := filepath.Join(dir, "cases.duckdb")
	db, err := sql.Open("duckdb", dbpath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE unified_events (
		case_id VARCHAR NOT NULL, evidence_id VARCHAR, artifact_id VARCHAR NOT NULL,
		audit_id VARCHAR NOT NULL, ts_utc TIMESTAMP, event_type VARCHAR NOT NULL,
		computer VARCHAR, payload_json VARCHAR NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	ts := time.Now()
	for i := 0; i < 100; i++ {
		_, _ = db.Exec(
			`INSERT INTO unified_events VALUES (?, 'EV1', 'mft', ?, ?, 'mft', 'WS01', '{}')`,
			"C1", "aud-"+string(rune('a'+i%26))+string(rune('a'+i/26)), ts)
	}
	hits, ev, err := execActiveSQL(context.Background(), db, "C1",
		"SELECT audit_id, ts_utc, artifact_id, event_type FROM unified_events WHERE case_id = ? LIMIT 200",
		10)
	if err != nil {
		t.Fatal(err)
	}
	if hits != 100 {
		t.Errorf("hits: got %d, want 100", hits)
	}
	if len(ev) != 10 {
		t.Errorf("evidence cap: got %d, want 10", len(ev))
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
