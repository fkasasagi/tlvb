package evidencex

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/marcboeker/go-duckdb"
)

// Real-image integration tests for on-demand evidence extraction. They mount an
// actual forensic disk image with SIFT tools (ewfmount / Sleuth Kit), so they
// are env-guarded and skipped by default — plain `go test ./...` never runs them.
//
// To run against a real E01 (or raw/vmdk/vhd...):
//
//	TLVB_E2E_REPO=$PWD \
//	TLVB_E2E_IMAGE=/path/to/disk.E01 \
//	go test ./internal/evidencex/ -run TestE2EFetchRealImage -v
//
//	TLVB_E2E_REPO=$PWD TLVB_E2E_DB=/abs/outputs/cases.duckdb TLVB_E2E_CASE=<case_id> \
//	go test ./internal/evidencex/ -run TestE2ERunRoundRealCase -v
//
// TLVB_E2E_REPO must be the module root (the dir containing parsers/) so the
// Python `-m parsers.evidence_fetch` import resolves. TLVB_E2E_CASE must be a
// case whose evidence row points at a currently-accessible disk image.

// TestE2EFetchRealImage drives Go → Python → mount → manifest → preview against
// a real image: the exact path the Tier 1B/2 runners take to read a file's bytes.
func TestE2EFetchRealImage(t *testing.T) {
	img := os.Getenv("TLVB_E2E_IMAGE")
	if img == "" {
		t.Skip("set TLVB_E2E_IMAGE (and TLVB_E2E_REPO) to run the real-image E2E")
	}
	cfg := Config{PythonBin: "python3", RepoDir: os.Getenv("TLVB_E2E_REPO"), Timeout: 8 * time.Minute}
	out := t.TempDir()
	targets := []string{
		`C:\Windows\System32\config\SOFTWARE`, // binary registry hive → hexdump preview
		"$MFT",                                // NTFS metadata file (MFT entry 0)
		`C:\Windows\System32\config\NOPE_DOES_NOT_EXIST.dat`, // negative control
	}
	m, err := Fetch(context.Background(), cfg, img, "E2E", out, targets)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if m.Error != "" {
		t.Fatalf("manifest error: %s", m.Error)
	}
	if m.MountMethod == "" || m.ImageFormat == "" {
		t.Fatalf("missing mount metadata: %+v", m)
	}
	byTarget := map[string]FileResult{}
	for _, r := range m.Results {
		byTarget[r.Target] = r
	}
	if sw := byTarget[`C:\Windows\System32\config\SOFTWARE`]; sw.Status != "ok" || sw.Bytes == 0 || sw.SHA256 == "" {
		t.Fatalf("SOFTWARE not extracted cleanly: %+v", sw)
	}
	if mft := byTarget["$MFT"]; mft.Status != "ok" || mft.Bytes == 0 {
		t.Fatalf("$MFT not extracted: %+v", mft)
	}
	if nope := byTarget[`C:\Windows\System32\config\NOPE_DOES_NOT_EXIST.dat`]; nope.Status != "not_found" {
		t.Fatalf("bogus path should be not_found, got %+v", nope)
	}

	var previews []FilePreview
	for _, r := range m.Results {
		previews = append(previews, Preview(r, DefaultCaps()))
	}
	block := BuildPreviewBlock(previews)
	if !strings.Contains(block, "binary") || !strings.Contains(block, "NOT AVAILABLE") {
		t.Fatalf("preview block missing expected sections:\n%s", block)
	}
	t.Logf("E2E OK: format=%s mount=%s SOFTWARE=%d bytes",
		m.ImageFormat, m.MountMethod, byTarget[`C:\Windows\System32\config\SOFTWARE`].Bytes)
}

// TestE2ERunRoundRealCase drives the orchestration layer the runners invoke
// AFTER the LLM emits requested_files: resolve the image from cases.duckdb
// (ListImageEvidence) → mount + extract (Fetch) → preview block (RunRound).
// Deterministic, no LLM.
func TestE2ERunRoundRealCase(t *testing.T) {
	dbPath := os.Getenv("TLVB_E2E_DB")
	caseID := os.Getenv("TLVB_E2E_CASE")
	if dbPath == "" || caseID == "" {
		t.Skip("set TLVB_E2E_DB, TLVB_E2E_CASE (and TLVB_E2E_REPO) to run the real-case RunRound E2E")
	}
	db, err := sql.Open("duckdb", dbPath+"?access_mode=read_only")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	rc := RoundConfig{
		Config:     Config{PythonBin: "python3", RepoDir: os.Getenv("TLVB_E2E_REPO"), Timeout: 8 * time.Minute},
		CaseID:     caseID,
		OutBaseDir: t.TempDir(),
		MaxFiles:   4,
	}
	requested := []RequestedFile{ // simulate what the LLM would put in requested_files
		{Path: `C:\Windows\System32\config\SOFTWARE`, Rationale: "confirm installed software"},
		{Path: `C:\Windows\System32\drivers\etc\hosts`, Rationale: "check for C2 host pinning"},
		{Path: `C:\Windows\System32\config\NOPE_DOES_NOT_EXIST.dat`, Rationale: "negative control"},
	}
	res, err := RunRound(context.Background(), db, rc, requested)
	if err != nil {
		t.Fatalf("RunRound: %v", err)
	}
	if !res.Available {
		t.Fatalf("ListImageEvidence found no mountable image for case %s", caseID)
	}
	sums := res.Summaries()
	okCount := 0
	for _, s := range sums {
		if s.Status == "ok" {
			okCount++
		}
		t.Logf("  %-55s %-9s %d bytes", s.Target, s.Status, s.Bytes)
	}
	if okCount == 0 {
		t.Fatalf("expected >=1 OK extraction, got none: %+v", sums)
	}
	if !strings.Contains(res.PreviewBlock, "EXTRACTED FILES") {
		t.Fatalf("preview block malformed")
	}
	t.Logf("RunRound OK: images=%v, %d/%d files extracted", res.UsedImages, okCount, len(sums))
}
