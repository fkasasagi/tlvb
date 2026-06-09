package tier2

import "testing"

// Adversarial "bypass" tests for the Tier 2 active-search guardrail
// (CLAUDE.md constraints: read-only-by-construction, SELECT-only, single bind).
//
// validateActiveSearchSQL is the FIRST line of defence: it must reject any SQL
// an LLM (or a prompt-injected one) could emit to escape the read-only,
// single-statement SELECT contract. The read-only DuckDB connection is the
// second line (see internal/casedb/readonly_bypass_test.go) — together they are
// defence in depth.

// TestActiveSearchValidatorRejectsBypassAttempts feeds the validator a battery
// of escape attempts. Every one MUST be rejected.
func TestActiveSearchValidatorRejectsBypassAttempts(t *testing.T) {
	attacks := []struct {
		name string
		sql  string
	}{
		{"insert_union", "SELECT audit_id FROM unified_events WHERE case_id = ? UNION INSERT INTO unified_events VALUES (1)"},
		{"update_subquery", "SELECT 1 FROM unified_events WHERE case_id = ? AND (UPDATE unified_events SET computer='x')"},
		{"delete_stacked", "SELECT 1 FROM unified_events WHERE case_id = ? ; DELETE FROM unified_events"},
		{"drop_stacked", "SELECT 1 FROM unified_events WHERE case_id = ? ; DROP TABLE unified_events"},
		{"alter_stacked", "SELECT 1 FROM unified_events WHERE case_id = ? ; ALTER TABLE unified_events ADD c INT"},
		{"create_stacked", "SELECT 1 FROM unified_events WHERE case_id = ? ; CREATE TABLE evil(x INT)"},
		{"attach_rw", "SELECT 1 FROM unified_events WHERE case_id = ? ; ATTACH 'evil.db' AS e"},
		{"detach", "SELECT 1 FROM unified_events WHERE case_id = ? ; DETACH e"},
		{"copy_exfil", "SELECT 1 FROM unified_events WHERE case_id = ? ; COPY unified_events TO '/tmp/x.csv'"},
		{"export_db", "SELECT 1 FROM unified_events WHERE case_id = ? ; EXPORT DATABASE '/tmp/d'"},
		{"pragma_prefix", "PRAGMA database_list"},
		{"mixed_case_drop", "SeLeCt 1 FROM unified_events WHERE case_id = ? ; DrOp TABLE unified_events"},
		{"with_prefix_delete", "WITH t AS (SELECT 1) DELETE FROM unified_events WHERE case_id = ?"},
		{"multiple_binds", "SELECT 1 FROM unified_events WHERE case_id = ? AND computer = ?"},
		{"trailing_semicolon", "SELECT 1 FROM unified_events WHERE case_id = ?;"},
		// The headline gap closed by the bare-semicolon hardening: a mid-statement
		// ';' smuggling a second (stacked) statement that contains NO banned
		// keyword would have slipped past the old trailing-only check.
		{"stacked_select_midsemicolon", "SELECT 1 FROM unified_events WHERE case_id = ? ; SELECT 2"},
		{"no_case_id", "SELECT 1 FROM unified_events WHERE evidence_id = ?"},
		{"not_select_prefix", "DELETE FROM unified_events WHERE case_id = ?"},
		{"empty", "   "},
		{"zero_binds_write", "SELECT 1 FROM unified_events WHERE case_id = 'C1' ; UPDATE x SET y=1"},
	}
	for _, a := range attacks {
		t.Run(a.name, func(t *testing.T) {
			if err := validateActiveSearchSQL(a.sql); err == nil {
				t.Errorf("validator ACCEPTED a bypass attempt that must be rejected:\n  %s", a.sql)
			}
		})
	}
}

// TestActiveSearchValidatorAcceptsLegitimate confirms the hardening did not start
// rejecting normal single-statement SELECT/WITH queries — including ones whose
// STRING LITERALS contain a ';' or a banned keyword (those are stripped before
// the checks, so they must still pass).
func TestActiveSearchValidatorAcceptsLegitimate(t *testing.T) {
	ok := []struct {
		name string
		sql  string
	}{
		{"plain_select", "SELECT audit_id, ts_utc, artifact_id, event_type FROM unified_events WHERE case_id = ? LIMIT 50"},
		{"with_cte", "WITH t AS (SELECT * FROM unified_events WHERE case_id = ?) SELECT * FROM t LIMIT 10"},
		{"semicolon_inside_literal", "SELECT audit_id FROM unified_events WHERE case_id = ? AND payload_json LIKE '%;%' LIMIT 5"},
		{"banned_word_inside_literal", "SELECT audit_id FROM unified_events WHERE case_id = ? AND payload_json LIKE '%create table%' LIMIT 5"},
	}
	for _, c := range ok {
		t.Run(c.name, func(t *testing.T) {
			if err := validateActiveSearchSQL(c.sql); err != nil {
				t.Errorf("validator rejected a legitimate query: %v\n  %s", err, c.sql)
			}
		})
	}
}
