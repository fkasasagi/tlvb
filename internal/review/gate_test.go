package review

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestReadAction(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		wantAction string
		wantArg    string
	}{
		{"approve short", "a\n", "approve", ""},
		{"approve upper", "A\n", "approve", ""},
		{"approve word", "approve\n", "approve", ""},
		{"skip short", "s\n", "skip", ""},
		{"skip word", "skip\n", "skip", ""},
		{"skip-all upper S", "S\n", "skip_all", ""},
		{"skip-all word", "skip-all\n", "skip_all", ""},
		{"quit", "q\n", "quit", ""},
		{"unknown falls back to skip", "wat\n", "skip", ""},
		{"empty/eof falls back to skip", "", "skip", ""},
		{"reject with reason", "r\nthreat actor present\n", "reject", "threat actor present"},
		{"reject blank reason", "reject\n\n", "reject", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rd := bufio.NewReader(strings.NewReader(c.input))
			var w bytes.Buffer
			action, arg, err := readAction(&w, rd)
			if err != nil {
				t.Fatalf("readAction err: %v", err)
			}
			if action != c.wantAction || arg != c.wantArg {
				t.Errorf("readAction(%q) = (%q, %q), want (%q, %q)",
					c.input, action, arg, c.wantAction, c.wantArg)
			}
		})
	}
}

func TestWrap(t *testing.T) {
	// Short string (<= width) is returned unchanged.
	if got := wrap("short", 10, "  "); got != "short" {
		t.Errorf("short string wrapped: %q", got)
	}
	// Wrapping backtracks to the nearest space and indents continuations.
	got := wrap("the quick brown fox", 10, "  ")
	want := "the quick\n  brown fox"
	if got != want {
		t.Errorf("wrap mismatch:\n got=%q\nwant=%q", got, want)
	}
	// Every continuation line carries the indent; first line does not.
	multi := wrap(strings.Repeat("word ", 12), 12, ">>")
	for i, line := range strings.Split(multi, "\n") {
		if i > 0 && !strings.HasPrefix(line, ">>") {
			t.Errorf("continuation line %d missing indent: %q", i, line)
		}
		if i == 0 && strings.HasPrefix(line, ">>") {
			t.Errorf("first line should not be indented: %q", line)
		}
	}
}
