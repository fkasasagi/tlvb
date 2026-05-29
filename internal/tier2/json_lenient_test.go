package tier2

import (
	"strings"
	"testing"
)

func TestExtractFirstJSONValueObject(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain", `{"x":1}`, `{"x":1}`},
		{"nested", `{"a":{"b":2},"c":[1,2,3]}`, `{"a":{"b":2},"c":[1,2,3]}`},
		{"prose preamble", "Here you go:\n\n{\"x\":1}", `{"x":1}`},
		{"trailing junk", `{"x":1}garbage\nmore`, `{"x":1}`},
		{"markdown fence", "```json\n{\"x\":1}\n```", `{"x":1}`},
		{"double trailing brace", `{"x":1}}`, `{"x":1}`},
		{"string with brace inside", `{"x":"value with } char"}`, `{"x":"value with } char"}`},
		{"escaped quote in string", `{"x":"with \"quote\""}`, `{"x":"with \"quote\""}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := extractFirstJSONValue(c.in)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if got != c.want {
				t.Errorf("\ngot:  %q\nwant: %q", got, c.want)
			}
		})
	}
}

func TestExtractFirstJSONValueArray(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain array", `[1,2,3]`, `[1,2,3]`},
		{"array of objects", `[{"x":1},{"y":2}]`, `[{"x":1},{"y":2}]`},
		{"prose preamble", `Answer: [1,2,3]`, `[1,2,3]`},
		{"trailing junk", `[1,2,3]\nrest`, `[1,2,3]`},
		{"markdown fence", "```json\n[1,2]\n```", `[1,2]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := extractFirstJSONValue(c.in)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if got != c.want {
				t.Errorf("\ngot:  %q\nwant: %q", got, c.want)
			}
		})
	}
}

func TestExtractFirstJSONValueNoMatch(t *testing.T) {
	for _, in := range []string{
		"",
		"no JSON here",
		"just words and 1234",
	} {
		_, err := extractFirstJSONValue(in)
		if err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

func TestDecodeFirstJSON_StructDirect(t *testing.T) {
	type T struct {
		A string `json:"a"`
		B int    `json:"b"`
	}
	var out T
	if err := decodeFirstJSON(`Here you go: {"a":"hi","b":42} trailing`, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.A != "hi" || out.B != 42 {
		t.Errorf("got %+v", out)
	}
}

func TestDecodeFirstJSON_ArrayWrappingStruct(t *testing.T) {
	// LLM wrapped a single object in an array; caller expected object.
	type T struct {
		A string `json:"a"`
	}
	var out T
	if err := decodeFirstJSON(`[{"a":"v1"}, {"a":"v2"}]`, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.A != "v1" {
		t.Errorf("expected first element, got %+v", out)
	}
}

func TestDecodeFirstJSON_ObjectInsteadOfArray(t *testing.T) {
	// LLM returned a single object; caller expected an array.
	type T struct {
		A string `json:"a"`
	}
	var out []T
	if err := decodeFirstJSON(`{"a":"only"}`, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 1 || out[0].A != "only" {
		t.Errorf("expected [{a:only}], got %+v", out)
	}
}

func TestParseClusterAnalysisRecovery(t *testing.T) {
	// Simulate the failure mode observed in real e2e: extra closing brace
	// after a valid object.
	resp, err := parseClusterAnalysis(`{"narrative":"text","attack_phase":"execution","mitre_techniques":["T1059"],"open_questions":["q1"]}}}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Narrative != "text" || resp.AttackPhase != "execution" {
		t.Errorf("got %+v", resp)
	}
	if len(resp.MITRETechniques) != 1 || resp.MITRETechniques[0] != "T1059" {
		t.Errorf("techniques: %v", resp.MITRETechniques)
	}
}

func TestParseClusterAnalysisProsePreamble(t *testing.T) {
	input := `Sure, here's my analysis:

{"narrative":"x","attack_phase":"execution","mitre_techniques":[],"open_questions":[]}

Let me know if you need more.`
	resp, err := parseClusterAnalysis(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Narrative != "x" {
		t.Errorf("got narrative %q", resp.Narrative)
	}
}

func TestParseClusterAnalysisArrayWrapped(t *testing.T) {
	// LLM defied instructions and wrapped in array.
	input := `[{"narrative":"first","attack_phase":"discovery","mitre_techniques":["T1082"],"open_questions":[]}]`
	resp, err := parseClusterAnalysis(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.AttackPhase != "discovery" {
		t.Errorf("got %+v", resp)
	}
}

func TestParseActiveSearchEntriesObjectInsteadOfArray(t *testing.T) {
	// LLM returned a single object; we want a 1-element list.
	input := `{"question":"q","rationale":"r","sql":"SELECT 1 FROM unified_events WHERE case_id = ?"}`
	got, err := parseActiveSearchEntries(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 || got[0].Question != "q" {
		t.Errorf("expected 1 entry, got %+v", got)
	}
}

func TestParseActiveSearchEntriesUnbalanced(t *testing.T) {
	// Genuinely malformed should still error so caller can save raw.
	_, err := parseActiveSearchEntries(`[{"question":"q",`)
	if err == nil {
		t.Error("expected error for unbalanced input")
	}
	if !strings.Contains(err.Error(), "unbalanced") {
		t.Logf("error: %v", err)
	}
}
