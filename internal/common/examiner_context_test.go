package common

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewExaminerContext(t *testing.T) {
	if NewExaminerContext("") != nil {
		t.Error("empty background must yield nil (omitted from JSON)")
	}
	if NewExaminerContext("   \n\t ") != nil {
		t.Error("whitespace-only background must yield nil")
	}
	ec := NewExaminerContext("  WS01 is the public web server.  ")
	if ec == nil {
		t.Fatal("non-empty background must yield a context")
	}
	if ec.Text != "WS01 is the public web server." {
		t.Errorf("text not trimmed: %q", ec.Text)
	}
	if !strings.Contains(ec.Note, "NOT evidence") {
		t.Errorf("note must flag the background as non-evidence: %q", ec.Note)
	}
	// The note must travel with the text in the marshalled JSON so the model
	// always sees the guardrail next to the content.
	b, _ := json.Marshal(ec)
	s := string(b)
	if !strings.Contains(s, "_note") || !strings.Contains(s, "WS01") {
		t.Errorf("marshalled context missing note/text: %s", s)
	}
}

func TestExaminerContextPrompt(t *testing.T) {
	if ExaminerContextPrompt("") != "" {
		t.Error("empty background must yield an empty prompt block")
	}
	if ExaminerContextPrompt("  \n ") != "" {
		t.Error("whitespace-only must yield empty")
	}
	p := ExaminerContextPrompt("brute force suspected from WS01")
	if !strings.Contains(p, "brute force suspected from WS01") {
		t.Error("prompt must contain the background text")
	}
	if !strings.Contains(p, "UNVERIFIED") || !strings.Contains(p, "NOT evidence") {
		t.Errorf("prompt must carry the unverified / not-evidence guardrail: %q", p)
	}
}
