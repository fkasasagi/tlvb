package web

import (
	"os"
	"path/filepath"
	"testing"
)

// writeExtractLog writes a minimal extract-log JSONL (header + records) so the
// reader has something realistic to parse.
func writeExtractLog(t *testing.T, path, evidenceID, imagePath string, targets ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	lines := []string{
		`{"schema":"findevil/extract-log/v1","evidence_id":"` + evidenceID +
			`","image_path":"` + imagePath + `","image_format":"ewf","mount_method":"ewfmount"}`,
	}
	for _, tg := range targets {
		lines = append(lines, `{"evidence_id":"`+evidenceID+`","target":"`+tg+`","status":"ok","bytes":10}`)
	}
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadExtractLogsMultiEvidence(t *testing.T) {
	root := t.TempDir()
	s := &Server{cfg: Config{OutputsRoot: filepath.Join(root, "cases")}}
	caseDir := filepath.Join(root, "cases", "AD")
	writeExtractLog(t, filepath.Join(caseDir, "extracts", "dc01.log"),
		"dc01", "/img/dc01.E01", "MFT", "SOFTWARE")
	writeExtractLog(t, filepath.Join(caseDir, "extracts", "ws01.log"),
		"ws01", "/img/ws01.E01", "MFT", "SYSTEM")

	headers, recs := s.readExtractLogs("AD")
	if len(headers) != 2 {
		t.Fatalf("want 2 headers, got %d", len(headers))
	}
	if len(recs) != 4 {
		t.Fatalf("want 4 records, got %d", len(recs))
	}
	// Every record must carry its source evidence id.
	for _, r := range recs {
		if r.EvidenceID != "dc01" && r.EvidenceID != "ws01" {
			t.Fatalf("record %q has unexpected evidence_id %q", r.Target, r.EvidenceID)
		}
	}
	// The same target on two images must produce distinct, namespaced keys so
	// approving dc01's MFT doesn't approve ws01's MFT.
	if k := extractReviewKey("dc01", "MFT"); k != "dc01::MFT" {
		t.Fatalf("review key = %q, want dc01::MFT", k)
	}
	if extractReviewKey("dc01", "MFT") == extractReviewKey("ws01", "MFT") {
		t.Fatal("same-named targets on different evidences collide on one review key")
	}
}

func TestReadExtractLogsLegacySingle(t *testing.T) {
	root := t.TempDir()
	s := &Server{cfg: Config{OutputsRoot: filepath.Join(root, "cases")}}
	caseDir := filepath.Join(root, "cases", "OLD")
	// Legacy layout: a single case-level extract.log with no evidence_id.
	writeExtractLog(t, filepath.Join(caseDir, "extract.log"), "", "/img/one.E01", "MFT")

	headers, recs := s.readExtractLogs("OLD")
	if len(headers) != 1 || len(recs) != 1 {
		t.Fatalf("legacy: want 1 header / 1 record, got %d / %d", len(headers), len(recs))
	}
	// No evidence_id → bare-target key preserves pre-namespacing review state.
	if k := extractReviewKey(recs[0].EvidenceID, recs[0].Target); k != "MFT" {
		t.Fatalf("legacy review key = %q, want MFT", k)
	}
}

func TestReadExtractLogsNone(t *testing.T) {
	root := t.TempDir()
	s := &Server{cfg: Config{OutputsRoot: filepath.Join(root, "cases")}}
	headers, recs := s.readExtractLogs("NOPE")
	if headers != nil || recs != nil {
		t.Fatalf("no extract data should return nil/nil, got %v / %v", headers, recs)
	}
}
