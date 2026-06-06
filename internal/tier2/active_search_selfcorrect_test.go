package tier2

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tlvb/tlvb/internal/auditlog"

	_ "github.com/marcboeker/go-duckdb"
)

// newSelfCorrectDB builds an in-memory-ish DuckDB with one EVTX row whose real
// shape mirrors EvtxECmd (PayloadData1 holds a value; $.TargetUserName does NOT
// exist at top level — querying it returns NULL, the classic mistake the
// self-correction loop must recover from).
func newSelfCorrectDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("duckdb", filepath.Join(t.TempDir(), "cases.duckdb"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE unified_events (
		case_id VARCHAR NOT NULL, evidence_id VARCHAR, artifact_id VARCHAR NOT NULL,
		audit_id VARCHAR NOT NULL, ts_utc TIMESTAMP, event_type VARCHAR NOT NULL,
		computer VARCHAR, payload_json VARCHAR NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO unified_events VALUES ('C1','EV1','evtx','e1',NULL,'evtx','WS01',?)`,
		evtxTestPayload(t)); err != nil {
		t.Fatal(err)
	}
	return db
}

const (
	// projects $.TargetUserName which is NOT a top-level EVTX key → NULL → null_result.
	badNullSQL = `SELECT audit_id, ts_utc, artifact_id, event_type, ` +
		`json_extract_string(payload_json,'$.TargetUserName') AS target ` +
		`FROM unified_events WHERE case_id = ? LIMIT 5`
	// projects $.PayloadData1 ("Target: alice") which is a real top-level key → ok.
	goodSQL = `SELECT audit_id, ts_utc, artifact_id, event_type, ` +
		`json_extract_string(payload_json,'$.PayloadData1') AS target ` +
		`FROM unified_events WHERE case_id = ? LIMIT 5`
	// validates (SELECT/case_id/single ?/no semicolon) but errors at execution.
	execErrSQL = `SELECT audit_id, ts_utc, artifact_id, event_type, ` +
		`no_such_fn(payload_json) AS x FROM unified_events WHERE case_id = ? LIMIT 5`
)

func TestSelfCorrectionRecoversNullResult(t *testing.T) {
	db := newSelfCorrectDB(t)
	var audit SynthAudit

	calls := 0
	correct := func(_ context.Context, prevSQL, reason string, attempt int) (string, error) {
		calls++
		if !strings.Contains(reason, "null_result") {
			t.Errorf("expected null_result in reason, got %q", reason)
		}
		return goodSQL, nil
	}

	res := runActiveSQLWithSelfCorrection(context.Background(), db, "C1",
		"who logged on?", badNullSQL, 2, correct, &audit, nil, 0)

	if !res.Corrected {
		t.Errorf("Corrected = false, want true")
	}
	if res.Error != "" {
		t.Errorf("Error = %q, want empty", res.Error)
	}
	if len(res.Attempts) != 2 {
		t.Fatalf("Attempts = %d, want 2: %+v", len(res.Attempts), res.Attempts)
	}
	if res.Attempts[0].Outcome != "null_result" || res.Attempts[1].Outcome != "ok" {
		t.Errorf("attempt outcomes = %q,%q", res.Attempts[0].Outcome, res.Attempts[1].Outcome)
	}
	if res.Hits < 1 || len(res.Evidence) < 1 {
		t.Errorf("Hits=%d Evidence=%d, want >=1", res.Hits, len(res.Evidence))
	}
	if calls != 1 {
		t.Errorf("corrector calls = %d, want 1", calls)
	}
	if audit.ActiveSQLSelfCorrected != 1 || audit.ActiveSQLSucceeded != 1 ||
		audit.ActiveSQLCorrectionRounds != 1 || audit.ActiveSQLNullResult != 0 {
		t.Errorf("audit = %+v", audit)
	}
}

func TestSelfCorrectionFirstTryOK(t *testing.T) {
	db := newSelfCorrectDB(t)
	var audit SynthAudit

	correct := func(context.Context, string, string, int) (string, error) {
		t.Fatal("corrector must not be called when first attempt succeeds")
		return "", nil
	}
	res := runActiveSQLWithSelfCorrection(context.Background(), db, "C1",
		"q", goodSQL, 2, correct, &audit, nil, 0)

	if res.Corrected || res.Error != "" {
		t.Errorf("Corrected=%v Error=%q", res.Corrected, res.Error)
	}
	if len(res.Attempts) != 1 || res.Attempts[0].Outcome != "ok" {
		t.Errorf("Attempts = %+v", res.Attempts)
	}
	if audit.ActiveSQLSucceeded != 1 || audit.ActiveSQLCorrectionRounds != 0 ||
		audit.ActiveSQLSelfCorrected != 0 {
		t.Errorf("audit = %+v", audit)
	}
}

func TestSelfCorrectionGivesUp(t *testing.T) {
	db := newSelfCorrectDB(t)
	var audit SynthAudit

	// Corrector signals "no meaningful fix" by returning "".
	correct := func(context.Context, string, string, int) (string, error) {
		return "", nil
	}
	res := runActiveSQLWithSelfCorrection(context.Background(), db, "C1",
		"q", badNullSQL, 2, correct, &audit, nil, 0)

	if res.Corrected {
		t.Errorf("Corrected = true, want false")
	}
	if !strings.Contains(res.Error, "null_result") {
		t.Errorf("Error = %q, want null_result mention", res.Error)
	}
	if len(res.Attempts) != 1 {
		t.Errorf("Attempts = %d, want 1 (gave up after first round)", len(res.Attempts))
	}
	if audit.ActiveSQLNullResult != 1 || audit.ActiveSQLSucceeded != 0 ||
		audit.ActiveSQLSelfCorrected != 0 || audit.ActiveSQLCorrectionRounds != 1 {
		t.Errorf("audit = %+v", audit)
	}
}

func TestSelfCorrectionRecoversExecError(t *testing.T) {
	db := newSelfCorrectDB(t)
	var audit SynthAudit

	correct := func(_ context.Context, _ string, reason string, _ int) (string, error) {
		if !strings.Contains(reason, "execute_error") {
			t.Errorf("expected execute_error in reason, got %q", reason)
		}
		return goodSQL, nil
	}
	res := runActiveSQLWithSelfCorrection(context.Background(), db, "C1",
		"q", execErrSQL, 2, correct, &audit, nil, 0)

	if !res.Corrected || res.Error != "" {
		t.Errorf("Corrected=%v Error=%q", res.Corrected, res.Error)
	}
	if len(res.Attempts) != 2 || res.Attempts[0].Outcome != "execute_error" {
		t.Errorf("Attempts = %+v", res.Attempts)
	}
	if audit.ActiveSQLSelfCorrected != 1 {
		t.Errorf("audit = %+v", audit)
	}
}

func TestSelfCorrectionDisabled(t *testing.T) {
	db := newSelfCorrectDB(t)
	var audit SynthAudit

	correct := func(context.Context, string, string, int) (string, error) {
		t.Fatal("corrector must not be called when maxCorrect=0")
		return "", nil
	}
	// maxCorrect=0 → attempt 1 fails and we stop immediately (old behaviour).
	res := runActiveSQLWithSelfCorrection(context.Background(), db, "C1",
		"q", badNullSQL, 0, correct, &audit, nil, 0)

	if res.Corrected || len(res.Attempts) != 1 {
		t.Errorf("Corrected=%v Attempts=%d", res.Corrected, len(res.Attempts))
	}
	if audit.ActiveSQLNullResult != 1 || audit.ActiveSQLCorrectionRounds != 0 {
		t.Errorf("audit = %+v", audit)
	}
}

func TestDemoInjectSQLFault(t *testing.T) {
	out := demoInjectSQLFault(goodSQL)
	if out == goodSQL || !strings.Contains(out, "__demo_injected_fault__") {
		t.Fatalf("fault not injected: %q", out)
	}
	// Must still pass the SELECT-only validator so it reaches execution and
	// fails there (execute_error) rather than being rejected up front.
	if err := validateActiveSearchSQL(out); err != nil {
		t.Fatalf("injected SQL should still validate, got: %v", err)
	}
	if got := demoInjectSQLFault("SELECT 1"); got != "SELECT 1" {
		t.Errorf("no case_id anchor → unchanged, got %q", got)
	}
}

func TestDemoFaultRecoversViaSelfCorrection(t *testing.T) {
	db := newSelfCorrectDB(t)
	var audit SynthAudit
	injected := demoInjectSQLFault(goodSQL)

	// The injected SQL must genuinely fail at execution.
	if _, _, err := execActiveSQL(context.Background(), db, "C1", injected, 50); err == nil {
		t.Fatal("injected SQL expected to fail at execution")
	}

	correct := func(_ context.Context, _ string, reason string, _ int) (string, error) {
		if !strings.Contains(reason, "execute_error") {
			t.Errorf("expected execute_error in reason, got %q", reason)
		}
		return goodSQL, nil // the LLM drops the bogus predicate and recovers
	}
	res := runActiveSQLWithSelfCorrection(context.Background(), db, "C1",
		"q", injected, 2, correct, &audit, nil, 0)

	if !res.Corrected || res.Error != "" {
		t.Errorf("Corrected=%v Error=%q", res.Corrected, res.Error)
	}
	if len(res.Attempts) != 2 || res.Attempts[0].Outcome != "execute_error" ||
		res.Attempts[1].Outcome != "ok" {
		t.Errorf("Attempts = %+v", res.Attempts)
	}
	if audit.ActiveSQLSelfCorrected != 1 {
		t.Errorf("audit = %+v", audit)
	}
}

func readActions(t *testing.T, path string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read actions: %v", err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad action line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// TestSelfCorrectionAuditChronology pins the fix that each attempt is logged the
// moment it happens: the correction LLM call must land BETWEEN the failed
// attempt and the successful retry, not before both.
func TestSelfCorrectionAuditChronology(t *testing.T) {
	db := newSelfCorrectDB(t)
	var audit SynthAudit
	path := filepath.Join(t.TempDir(), "actions.jsonl")
	al := auditlog.New(path, "C1")

	// The stub corrector emits its own marker (as the real correctActiveSearchSQL
	// does) so we can assert ordering deterministically without an LLM.
	correct := func(_ context.Context, _, _ string, attempt int) (string, error) {
		al.Append(auditlog.Action{Actor: "tier2", Kind: "llm_call",
			Detail: "active_search_correct", Attempt: attempt})
		return goodSQL, nil
	}
	res := runActiveSQLWithSelfCorrection(context.Background(), db, "C1", "q",
		demoInjectSQLFault(goodSQL), 2, correct, &audit, al, 7)
	if !res.Corrected {
		t.Fatalf("expected corrected, got %+v", res)
	}

	var seq []string
	for _, r := range readActions(t, path) {
		switch r["kind"] {
		case "active_sql":
			seq = append(seq, fmt.Sprintf("active_sql/att%v/%v", r["attempt"], r["outcome"]))
			if r["cluster_id"] != float64(7) {
				t.Errorf("cluster_id = %v, want 7", r["cluster_id"])
			}
		case "llm_call":
			seq = append(seq, fmt.Sprintf("%v/att%v", r["detail"], r["attempt"]))
		}
	}
	want := []string{"active_sql/att1/execute_error", "active_search_correct/att1", "active_sql/att2/ok"}
	if strings.Join(seq, " -> ") != strings.Join(want, " -> ") {
		t.Errorf("audit chronology = %v\n            want %v", seq, want)
	}
}

// sanity: the two fixture SQLs really do behave as the tests assume against
// DuckDB (guards against a fixture rot where both project non-null).
func TestSelfCorrectionFixturesBehaveAsExpected(t *testing.T) {
	db := newSelfCorrectDB(t)
	ctx := context.Background()

	n, ev, err := execActiveSQL(ctx, db, "C1", badNullSQL, 50)
	if err != nil {
		t.Fatalf("badNullSQL exec: %v", err)
	}
	if n == 0 || !allProjectedColumnsNull(ev) {
		t.Fatalf("badNullSQL expected rows with all-null projection, got n=%d null=%v", n, allProjectedColumnsNull(ev))
	}
	n, ev, err = execActiveSQL(ctx, db, "C1", goodSQL, 50)
	if err != nil {
		t.Fatalf("goodSQL exec: %v", err)
	}
	if n == 0 || allProjectedColumnsNull(ev) {
		t.Fatalf("goodSQL expected non-null projection, got n=%d null=%v", n, allProjectedColumnsNull(ev))
	}
	if _, _, err := execActiveSQL(ctx, db, "C1", execErrSQL, 50); err == nil {
		t.Fatalf("execErrSQL expected an execution error, got nil")
	}
}
