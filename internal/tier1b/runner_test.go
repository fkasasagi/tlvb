package tier1b

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/marcboeker/go-duckdb"
)

func setupDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dir := t.TempDir()
	dbpath := filepath.Join(dir, "cases.duckdb")
	db, err := sql.Open("duckdb", dbpath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE unified_events (
		case_id VARCHAR NOT NULL, evidence_id VARCHAR, artifact_id VARCHAR NOT NULL,
		audit_id VARCHAR NOT NULL, ts_utc TIMESTAMP, event_type VARCHAR NOT NULL,
		computer VARCHAR, payload_json VARCHAR NOT NULL)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	return db, dbpath
}

func insertEvent(t *testing.T, db *sql.DB, caseID, audit, artifact string, ts time.Time, payload string) {
	t.Helper()
	if _, err := db.Exec(
		`INSERT INTO unified_events VALUES (?, 'EV1', ?, ?, ?, ?, 'WS01', ?)`,
		caseID, artifact, audit, ts, artifact, payload); err != nil {
		t.Fatalf("insert: %v", err)
	}
}

func TestLoadPriorFindings(t *testing.T) {
	dir := t.TempDir()
	byRule := filepath.Join(dir, "by-rule", "sigma")
	if err := os.MkdirAll(byRule, 0o755); err != nil {
		t.Fatal(err)
	}
	// One finding with 2 evidence rows.
	f := map[string]any{
		"rule_source": "sigma",
		"rule_meta":   map[string]any{"level": "high"},
		"evidence": []map[string]any{
			{"audit_id": "aud-1", "ts_utc": "2026-05-19T13:50:28Z"},
			{"audit_id": "aud-2", "ts_utc": "2026-05-19T13:56:27Z"},
		},
	}
	body, _ := json.Marshal(f)
	if err := os.WriteFile(filepath.Join(byRule, "rule-1.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	pc, err := loadPriorFindings(dir)
	if err != nil {
		t.Fatalf("loadPriorFindings: %v", err)
	}
	if pc.Total != 1 {
		t.Errorf("Total: got %d, want 1", pc.Total)
	}
	if len(pc.UniqueAudits) != 2 {
		t.Errorf("UniqueAudits: got %d, want 2", len(pc.UniqueAudits))
	}
	if len(pc.KeyTimestamps) != 2 {
		t.Errorf("KeyTimestamps: got %d, want 2", len(pc.KeyTimestamps))
	}
}

func TestBuildCandidatesOffHoursLens(t *testing.T) {
	db, _ := setupDB(t)
	defer db.Close()
	t0 := time.Date(2026, 5, 19, 3, 0, 0, 0, time.UTC) // 03:00 = off-hours
	t1 := time.Date(2026, 5, 19, 14, 0, 0, 0, time.UTC) // 14:00 = business hours
	insertEvent(t, db, "C1", "off-1", "evtx", t0, `{"x":1}`)
	insertEvent(t, db, "C1", "biz-1", "evtx", t1, `{"x":1}`)

	prior := &priorContext{}
	bundle, err := buildCandidates(context.Background(), db, "C1", prior, 10)
	if err != nil {
		t.Fatalf("buildCandidates: %v", err)
	}
	var ids []string
	for _, c := range bundle.Events {
		ids = append(ids, c.AuditID)
	}
	if len(ids) != 1 || ids[0] != "off-1" {
		t.Errorf("expected only off-hours event, got %v", ids)
	}
	if bundle.Events[0].Lenses[0] != "A1" {
		t.Errorf("expected A1 lens, got %v", bundle.Events[0].Lenses)
	}
}

func TestBuildCandidatesSuspiciousPathLens(t *testing.T) {
	db, _ := setupDB(t)
	defer db.Close()
	t1 := time.Date(2026, 5, 19, 14, 0, 0, 0, time.UTC) // business hours
	insertEvent(t, db, "C1", "temp-1", "evtx", t1,
		`{"ExecutableInfo":"C:\\Users\\bob\\AppData\\Local\\Temp\\evil.exe"}`)
	insertEvent(t, db, "C1", "public-1", "evtx", t1,
		`{"ExecutableInfo":"C:\\Users\\Public\\stager.exe"}`)
	// system-1 has a benign path; flood it 5x so the rare-process lens
	// (A4) doesn't fire and we can verify A2 is the only signal.
	insertEvent(t, db, "C1", "system-1", "evtx", t1,
		`{"ExecutableInfo":"C:\\Windows\\System32\\svchost.exe"}`)
	for i := 0; i < 4; i++ {
		insertEvent(t, db, "C1", "system-1-dup-"+string(rune('a'+i)), "evtx", t1,
			`{"ExecutableInfo":"C:\\Windows\\System32\\svchost.exe"}`)
	}

	bundle, err := buildCandidates(context.Background(), db, "C1", &priorContext{}, 10)
	if err != nil {
		t.Fatalf("buildCandidates: %v", err)
	}
	// Find events that fired A2.
	var a2Events []candidate
	for _, c := range bundle.Events {
		if containsStr(c.Lenses, "A2") {
			a2Events = append(a2Events, c)
		}
	}
	if len(a2Events) != 2 {
		t.Errorf("expected 2 A2-flagged events, got %d (total=%d)",
			len(a2Events), len(bundle.Events))
	}
}

func TestBuildCandidatesExcludesPriorAudits(t *testing.T) {
	db, _ := setupDB(t)
	defer db.Close()
	t0 := time.Date(2026, 5, 19, 3, 0, 0, 0, time.UTC)
	insertEvent(t, db, "C1", "off-1", "evtx", t0, `{"x":1}`)
	insertEvent(t, db, "C1", "off-2", "evtx", t0.Add(time.Second), `{"x":1}`)

	prior := &priorContext{UniqueAudits: []string{"off-1"}}
	bundle, _ := buildCandidates(context.Background(), db, "C1", prior, 10)
	if len(bundle.Events) != 1 || bundle.Events[0].AuditID != "off-2" {
		t.Errorf("expected only off-2, got %d events", len(bundle.Events))
	}
}

func TestBuildCandidatesAdjacencyLens(t *testing.T) {
	db, _ := setupDB(t)
	defer db.Close()
	priorT := time.Date(2026, 5, 19, 14, 0, 0, 0, time.UTC)
	near := priorT.Add(10 * time.Minute)
	far := priorT.Add(2 * time.Hour)
	insertEvent(t, db, "C1", "near-1", "evtx", near, `{"x":1}`)
	insertEvent(t, db, "C1", "far-1", "evtx", far, `{"x":1}`)

	prior := &priorContext{KeyTimestamps: []string{priorT.Format(time.RFC3339)}}
	bundle, _ := buildCandidates(context.Background(), db, "C1", prior, 10)
	var ids []string
	for _, c := range bundle.Events {
		ids = append(ids, c.AuditID)
	}
	if len(ids) != 1 || ids[0] != "near-1" {
		t.Errorf("adjacency: expected only near-1, got %v", ids)
	}
}

func TestParseAnomalyFindings(t *testing.T) {
	cases := []struct {
		name, input string
		wantCount   int
	}{
		{"empty array", "[]", 0},
		{"single finding", `[{"lens":"A2","summary":"x","severity":"high","audit_ids":["aud-1"]}]`, 1},
		{"markdown wrapped", "```json\n[]\n```", 0},
		{"missing audit_ids drops entry",
			`[{"lens":"A1","summary":"x","severity":"low","audit_ids":[]},{"lens":"A2","summary":"y","severity":"high","audit_ids":["aud-9"]}]`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseAnomalyFindings(c.input, nil)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(got) != c.wantCount {
				t.Errorf("count: got %d, want %d", len(got), c.wantCount)
			}
		})
	}
}

func TestExtractImage(t *testing.T) {
	// extractImage scans the raw payload string without JSON unescaping
	// (it's used for fast in-memory grouping). The returned string is
	// the literal characters between "Key":" and the next " — so escaped
	// backslashes remain doubled. That's fine since downstream usage
	// only needs consistency for case-insensitive map keys.
	cases := []struct {
		name, payload, want string
	}{
		{"ExecutableInfo full cmdline ends at .exe",
			`{"ExecutableInfo":"C:\\Users\\Public\\mimi.exe privilege::debug"}`,
			`C:\\Users\\Public\\mimi.exe`},
		{"Image field",
			`{"Image":"C:\\Windows\\System32\\notepad.exe"}`,
			`C:\\Windows\\System32\\notepad.exe`},
		{"FullPath (MFT)",
			`{"FullPath":"C:\\Users\\bob\\file.docx"}`,
			`C:\\Users\\bob\\file.docx`},
		{"none", `{"x":1}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractImage(c.payload)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestHasSuspiciousPath(t *testing.T) {
	cases := []struct {
		payload string
		want    bool
	}{
		{`{"x":"C:\\Users\\bob\\AppData\\Local\\Temp\\evil.exe"}`, true},
		{`{"x":"C:\\Users\\Public\\stager.exe"}`, true},
		{`{"x":"C:\\ProgramData\\config"}`, true},
		{`{"x":"C:\\Windows\\System32\\svchost.exe"}`, false},
		{`{"x":"C:\\Program Files\\App\\app.exe"}`, false},
	}
	for i, c := range cases {
		if got := hasSuspiciousPath(c.payload); got != c.want {
			t.Errorf("case %d (%q): got %v, want %v", i, c.payload, got, c.want)
		}
	}
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
