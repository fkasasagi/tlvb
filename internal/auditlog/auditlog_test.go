package auditlog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("bad json line %q: %v", sc.Text(), err)
		}
		out = append(out, m)
	}
	return out
}

func TestAppendEnvelopeAndFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "actions.jsonl")
	l := New(path, "CASE1")
	l.Append(Action{Actor: "tier2", Kind: "llm_call", Detail: "cluster_analysis",
		ClusterID: 3, Model: "claude-sonnet-4-6", InputTokens: 10, OutputTokens: 20,
		CostUSD: 0.5, DurationSeconds: 1.25, Success: BoolPtr(true)})
	l.Append(Action{Actor: "tier2", Kind: "active_sql", Attempt: 1, Outcome: "execute_error",
		Command: "SELECT 1", RowCount: IntPtr(0), Error: "boom", Success: BoolPtr(false)})

	rows := readLines(t, path)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	// envelope is always present
	for _, r := range rows {
		if r["ts"] == "" || r["ts"] == nil {
			t.Errorf("missing ts: %v", r)
		}
		if r["case_id"] != "CASE1" {
			t.Errorf("case_id = %v, want CASE1", r["case_id"])
		}
	}
	if rows[0]["kind"] != "llm_call" || rows[0]["detail"] != "cluster_analysis" ||
		rows[0]["model"] != "claude-sonnet-4-6" {
		t.Errorf("row0 = %v", rows[0])
	}
	if rows[1]["outcome"] != "execute_error" || rows[1]["success"] != false ||
		rows[1]["error"] != "boom" {
		t.Errorf("row1 = %v", rows[1])
	}
	// row_count 0 must still serialise (pointer, not omitempty-on-zero)
	if rows[1]["row_count"] != float64(0) {
		t.Errorf("row_count = %v, want 0", rows[1]["row_count"])
	}
}

func TestOmitemptyKeepsRecordsLean(t *testing.T) {
	path := filepath.Join(t.TempDir(), "actions.jsonl")
	New(path, "C").Append(Action{Actor: "tier2", Kind: "llm_call"})
	rows := readLines(t, path)
	// only envelope keys present (ts/case_id/actor/kind) — no zero-valued noise
	for _, k := range []string{"success", "row_count", "model", "cost_usd", "attempt", "input_tokens"} {
		if _, ok := rows[0][k]; ok {
			t.Errorf("unexpected empty field %q present: %v", k, rows[0])
		}
	}
}

func TestNilLoggerNoop(t *testing.T) {
	var l *Logger                               // nil
	l.Append(Action{Actor: "tier2", Kind: "x"}) // must not panic
}

func TestConcurrentAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "actions.jsonl")
	l := New(path, "C")
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			l.Append(Action{Actor: "tier2", Kind: "active_sql", Attempt: n})
		}(i)
	}
	wg.Wait()
	if rows := readLines(t, path); len(rows) != 50 {
		t.Fatalf("rows = %d, want 50 (no interleaving/loss)", len(rows))
	}
}
