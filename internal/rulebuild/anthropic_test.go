package rulebuild

import (
	"strings"
	"testing"
)

func TestValidateSQL_OK(t *testing.T) {
	cases := []string{
		"SELECT audit_id, ts_utc, artifact_id, event_type FROM unified_events WHERE case_id = ?",
		"select * from unified_events where case_id = ?",
		"WITH x AS (SELECT 1) SELECT audit_id FROM unified_events WHERE case_id = ?",
		"", // empty SQL = LLM said "no SQL applicable", allowed
	}
	for i, s := range cases {
		if err := validateSQL(s); err != nil {
			t.Errorf("case %d: unexpected error %v for SQL %q", i, err, s)
		}
	}
}

func TestValidateSQL_Rejects(t *testing.T) {
	cases := []struct {
		sql, wantErrSubstr string
	}{
		// Prefix check fires first for these (they don't start with SELECT/WITH).
		{"DELETE FROM unified_events WHERE case_id = ?", "must start with SELECT"},
		{"UPDATE unified_events SET case_id = 'x' WHERE case_id = ?", "must start with SELECT"},
		{"INSERT INTO unified_events VALUES (...)", "must start with SELECT"},
		{"DROP TABLE unified_events", "must start with SELECT"},
		{"PRAGMA foreign_keys = on", "must start with SELECT"},
		// SELECT but missing case_id.
		{"SELECT * FROM unified_events", "case_id"},
		// SELECT, has case_id, but trailing semicolon.
		{"SELECT * FROM unified_events WHERE case_id = ?;", "semicolon"},
		// SELECT with embedded DROP — dangerous-keyword check fires before
		// the semicolon check.
		{"SELECT audit_id FROM unified_events WHERE case_id = ?; DROP TABLE foo", "disallowed"},
	}
	for i, c := range cases {
		err := validateSQL(c.sql)
		if err == nil {
			t.Errorf("case %d: expected error for SQL %q", i, c.sql)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErrSubstr) {
			t.Errorf("case %d: error %q doesn't contain %q", i, err.Error(), c.wantErrSubstr)
		}
	}
}

func TestParseBuilderJSON(t *testing.T) {
	cases := []struct {
		name, input string
		wantSQL     string
		wantPrefilter []string
	}{
		{
			name: "clean JSON",
			input: `{"sql":"SELECT audit_id FROM unified_events WHERE case_id = ?","prefilter_artifacts":["evtx"],"notes":"ok"}`,
			wantSQL: "SELECT audit_id FROM unified_events WHERE case_id = ?",
			wantPrefilter: []string{"evtx"},
		},
		{
			name: "markdown-wrapped",
			input: "```json\n{\"sql\":\"SELECT audit_id FROM unified_events WHERE case_id = ?\",\"prefilter_artifacts\":[\"evtx\"],\"notes\":\"x\"}\n```",
			wantSQL: "SELECT audit_id FROM unified_events WHERE case_id = ?",
			wantPrefilter: []string{"evtx"},
		},
		{
			name: "prose preamble",
			input: `Here is my output:

{"sql":"SELECT audit_id FROM unified_events WHERE case_id = ?","prefilter_artifacts":["evtx"],"notes":"x"}`,
			wantSQL: "SELECT audit_id FROM unified_events WHERE case_id = ?",
			wantPrefilter: []string{"evtx"},
		},
		{
			name: "empty SQL signal",
			input: `{"sql":"","prefilter_artifacts":[],"notes":"not expressible"}`,
			wantSQL: "",
			wantPrefilter: []string{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseBuilderJSON(c.input)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got.SQL != c.wantSQL {
				t.Errorf("SQL: got %q, want %q", got.SQL, c.wantSQL)
			}
			if len(got.PrefilterArtifacts) != len(c.wantPrefilter) {
				t.Errorf("prefilter length: got %v, want %v", got.PrefilterArtifacts, c.wantPrefilter)
			}
		})
	}
}

func TestSystemPromptHasSchemaPlaceholder(t *testing.T) {
	if !strings.Contains(SystemPrompt, "{SCHEMA_DOC}") {
		t.Fatal("SystemPrompt missing {SCHEMA_DOC} placeholder — Replace() would no-op")
	}
}
