package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDotEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	content := strings.Join([]string{
		"# a comment line",
		"",
		"TLVB_DOTENV_BASIC=hello",
		"TLVB_DOTENV_SPACES=bar baz", // unquoted value with a space
		`TLVB_DOTENV_DQUOTE="quoted val"`,
		"TLVB_DOTENV_SQUOTE='single'",
		"TLVB_DOTENV_EQ=a=b=c", // only the first '=' splits
		"   TLVB_DOTENV_TRIM   =  trimmed  ",
		"=novalue_is_skipped", // '=' at index 0 -> skipped
		"lineWithNoEquals",    // no '=' -> skipped
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	keys := []string{
		"TLVB_DOTENV_BASIC", "TLVB_DOTENV_SPACES", "TLVB_DOTENV_DQUOTE",
		"TLVB_DOTENV_SQUOTE", "TLVB_DOTENV_EQ", "TLVB_DOTENV_TRIM",
	}
	for _, k := range keys {
		os.Unsetenv(k)
	}
	t.Cleanup(func() {
		for _, k := range keys {
			os.Unsetenv(k)
		}
	})

	n, err := LoadDotEnv(path)
	if err != nil {
		t.Fatalf("LoadDotEnv: %v", err)
	}
	want := map[string]string{
		"TLVB_DOTENV_BASIC":  "hello",
		"TLVB_DOTENV_SPACES": "bar baz",
		"TLVB_DOTENV_DQUOTE": "quoted val",
		"TLVB_DOTENV_SQUOTE": "single",
		"TLVB_DOTENV_EQ":     "a=b=c",
		"TLVB_DOTENV_TRIM":   "trimmed",
	}
	for k, v := range want {
		if got := os.Getenv(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if n != len(want) {
		t.Errorf("loaded count = %d, want %d (comment/blank/no-value/no-equals skipped)", n, len(want))
	}
}

func TestLoadDotEnvDoesNotOverrideExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	body := "TLVB_DOTENV_PRESET=fromfile\nTLVB_DOTENV_FRESH=fresh\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// Shell-supplied value must win over the file (t.Setenv auto-restores).
	t.Setenv("TLVB_DOTENV_PRESET", "fromshell")
	os.Unsetenv("TLVB_DOTENV_FRESH")
	t.Cleanup(func() { os.Unsetenv("TLVB_DOTENV_FRESH") })

	n, err := LoadDotEnv(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("TLVB_DOTENV_PRESET"); got != "fromshell" {
		t.Errorf("preset overridden: got %q, want fromshell", got)
	}
	if got := os.Getenv("TLVB_DOTENV_FRESH"); got != "fresh" {
		t.Errorf("fresh key not loaded: got %q", got)
	}
	if n != 1 {
		t.Errorf("loaded = %d, want 1 (preset already set -> not counted)", n)
	}
}

func TestLoadDotEnvMissingFileIsNoError(t *testing.T) {
	n, err := LoadDotEnv(filepath.Join(t.TempDir(), "does-not-exist.env"))
	if err != nil || n != 0 {
		t.Fatalf("missing file: got (%d, %v), want (0, nil)", n, err)
	}
}
