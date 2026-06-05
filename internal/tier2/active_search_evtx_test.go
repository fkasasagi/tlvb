package tier2

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"

	_ "github.com/marcboeker/go-duckdb"
)

func TestAllProjectedColumnsNull(t *testing.T) {
	mk := func(rows ...map[string]any) []TimelineEvent {
		var out []TimelineEvent
		for _, r := range rows {
			out = append(out, TimelineEvent{Excerpt: r})
		}
		return out
	}
	cases := []struct {
		name string
		ev   []TimelineEvent
		want bool
	}{
		{"all null projected", mk(map[string]any{"target": nil, "ip": ""}, map[string]any{"target": nil, "ip": ""}), true},
		{"one non-null", mk(map[string]any{"target": nil}, map[string]any{"target": "alice"}), false},
		{"envelope only (no projected col)", mk(map[string]any{}, map[string]any{}), false},
		{"empty evidence", nil, false},
		{"single null col", mk(map[string]any{"x": nil}), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := allProjectedColumnsNull(c.ev); got != c.want {
				t.Errorf("allProjectedColumnsNull = %v, want %v", got, c.want)
			}
		})
	}
}

// evtxTestPayload builds a payload_json mirroring the real EvtxECmd shape:
// curated PayloadData1..6 "Label: value" strings at top level, and the full
// Windows EventData as an @Name/#text array inside the nested-string $.raw.Payload.
func evtxTestPayload(t *testing.T) string {
	t.Helper()
	rawPayload := `{"EventData":{"Data":[` +
		`{"@Name":"TargetUserName","#text":"alice"},` +
		`{"@Name":"IpAddress","#text":"10.0.0.1"},` +
		`{"@Name":"LogonType","#text":"3"}]}}`
	b, err := json.Marshal(map[string]any{
		"EventId":        "4624",
		"Channel":        "Security",
		"MapDescription": "Successful logon",
		"PayloadData1":   "Target: alice",
		"PayloadData2":   "LogonType 3",
		"PayloadData3":   "", // empty slot must be dropped
		"raw":            map[string]any{"Channel": "Security", "Payload": rawPayload},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseEvtxSample(t *testing.T) {
	mapDesc, pd, fields := parseEvtxSample(evtxTestPayload(t))

	if mapDesc != "Successful logon" {
		t.Errorf("mapDesc = %q", mapDesc)
	}
	// only the two non-empty PayloadData slots survive
	if len(pd) != 2 || pd["PayloadData2"] != "LogonType 3" || pd["PayloadData1"] != "Target: alice" {
		t.Errorf("payloadData = %v", pd)
	}
	if _, ok := pd["PayloadData3"]; ok {
		t.Errorf("empty PayloadData3 should be dropped: %v", pd)
	}
	// the real EventData field names must surface from $.raw.Payload — the
	// whole point of the fix (LLM was guessing $.TargetUserName before)
	want := map[string]bool{"TargetUserName": true, "IpAddress": true, "LogonType": true}
	if len(fields) != len(want) {
		t.Fatalf("eventDataFields = %v, want %v", fields, want)
	}
	for _, f := range fields {
		if !want[f] {
			t.Errorf("unexpected eventdata field %q", f)
		}
	}
}

func TestParseEvtxSampleGarbage(t *testing.T) {
	if md, pd, f := parseEvtxSample("not json"); md != "" || pd != nil || f != nil {
		t.Errorf("garbage payload should yield zero values, got %q %v %v", md, pd, f)
	}
}

func TestGatherClusterSchemaSamples(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("duckdb", filepath.Join(dir, "cases.duckdb"))
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
	mft, _ := json.Marshal(map[string]any{"FileName": "loot.txt", "ParentPath": "\\Users\\x"})
	ins := func(art, aud, payload string) {
		if _, err := db.Exec(
			`INSERT INTO unified_events VALUES ('C1','EV1',?,?,NULL,?,'WS01',?)`,
			art, aud, art, payload); err != nil {
			t.Fatal(err)
		}
	}
	ins("evtx", "e1", evtxTestPayload(t))
	ins("mft", "m1", string(mft))

	c := &Cluster{RawTimelineExcerpt: []TimelineEvent{
		{ArtifactID: "evtx", Excerpt: map[string]any{"EventId": "4624"}},
		{ArtifactID: "mft", Excerpt: map[string]any{"FileName": "loot.txt"}},
	}}
	ss, err := gatherClusterSchemaSamples(context.Background(), db, "C1", c)
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if len(ss.EVTXByEventID) != 1 || ss.EVTXByEventID[0].EventID != "4624" {
		t.Fatalf("evtx samples = %+v", ss.EVTXByEventID)
	}
	got := ss.EVTXByEventID[0]
	if got.PayloadData["PayloadData2"] != "LogonType 3" {
		t.Errorf("payload_data not sampled: %v", got.PayloadData)
	}
	hasTUN := false
	for _, k := range got.EventDataFields {
		if k == "TargetUserName" {
			hasTUN = true
		}
	}
	if !hasTUN {
		t.Errorf("eventdata fields missing TargetUserName: %v", got.EventDataFields)
	}
	if len(ss.ByArtifact) != 1 || ss.ByArtifact[0].Artifact != "mft" {
		t.Errorf("artifact samples = %+v", ss.ByArtifact)
	}
}
