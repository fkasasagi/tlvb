package exporter

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestTarGzRoundTrip(t *testing.T) {
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "a.txt"), "alpha")
	writeFile(t, filepath.Join(src, "sub", "b.json"), `{"k":1}`)
	writeFile(t, filepath.Join(src, "sub", "deep", "c.bin"), "\x00\x01\x02 binary data")

	arc := filepath.Join(t.TempDir(), "case.fcz")
	if err := tarGzDir(src, arc); err != nil {
		t.Fatalf("tarGzDir: %v", err)
	}

	dst := t.TempDir()
	if err := untarGz(arc, dst); err != nil {
		t.Fatalf("untarGz: %v", err)
	}

	srcHashes, err := hashTree(src)
	if err != nil {
		t.Fatalf("hashTree(src): %v", err)
	}
	dstHashes, err := hashTree(dst)
	if err != nil {
		t.Fatalf("hashTree(dst): %v", err)
	}
	if len(srcHashes) != 3 {
		t.Fatalf("expected 3 files in source tree, got %d", len(srcHashes))
	}
	// Same relative paths, sizes and SHA-256 after a full archive round-trip.
	if !reflect.DeepEqual(srcHashes, dstHashes) {
		t.Errorf("round-trip mismatch:\n src=%+v\n dst=%+v", srcHashes, dstHashes)
	}
}

func TestHashTreeIsDeterministicAndContentSensitive(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "x"), "content")
	first, err := hashTree(dir)
	if err != nil || len(first) != 1 {
		t.Fatalf("hashTree: %v len=%d", err, len(first))
	}
	if first[0].Path != "x" || first[0].Bytes != int64(len("content")) || first[0].SHA256 == "" {
		t.Fatalf("entry shape wrong: %+v", first[0])
	}
	// Re-hash unchanged tree -> identical.
	again, _ := hashTree(dir)
	if !reflect.DeepEqual(first, again) {
		t.Error("hashTree not deterministic on unchanged tree")
	}
	// Mutate content -> SHA changes.
	writeFile(t, filepath.Join(dir, "x"), "different")
	mutated, _ := hashTree(dir)
	if mutated[0].SHA256 == first[0].SHA256 {
		t.Error("SHA256 did not change after content mutation")
	}
}

func TestUntarGzRejectsPathTraversal(t *testing.T) {
	// Hand-build a malicious archive with a "../escape.txt" member.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("pwned")
	hdr := &tar.Header{
		Name: "../escape.txt", Mode: 0o644,
		Size: int64(len(body)), Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gz.Close()

	arc := filepath.Join(t.TempDir(), "evil.fcz")
	if err := os.WriteFile(arc, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	dst := t.TempDir()
	err := untarGz(arc, dst)
	if err == nil {
		t.Fatal("untarGz accepted a ../ traversal member")
	}
	if !strings.Contains(err.Error(), "unsafe member") {
		t.Fatalf("expected 'unsafe member' error, got: %v", err)
	}
	// And nothing was written outside dst.
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(dst), "escape.txt")); statErr == nil {
		t.Error("traversal wrote a file outside the destination")
	}
}
