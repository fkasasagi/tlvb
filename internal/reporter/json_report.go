package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tlvb/tlvb/internal/synthesizer"
)

// JSONReport wraps the CaseSynthesis with Tier 3 metadata. Consumers that
// just want CaseSynthesis can read the `synthesis` field; consumers that
// want to know which tool produced this and when can read `report_meta`.
type JSONReport struct {
	ReportMeta ReportMeta                   `json:"report_meta"`
	Synthesis  *synthesizer.CaseSynthesis   `json:"synthesis"`
}

type ReportMeta struct {
	CaseID          string    `json:"case_id"`
	GeneratedAt     time.Time `json:"generated_at"`
	GeneratorVersion string   `json:"generator_version"`
	SourcePath      string    `json:"source_synthesis_path"`
	Language        string    `json:"language"`
}

// writeJSON writes the JSON report. Pretty-printed (2-space indent) so it's
// directly diffable; consumers that want compact JSON can re-marshal.
func writeJSON(cs *synthesizer.CaseSynthesis, cfg Config) (string, error) {
	report := JSONReport{
		ReportMeta: ReportMeta{
			CaseID:          cs.CaseID,
			GeneratedAt:     time.Now().UTC(),
			GeneratorVersion: reporterVersion,
			SourcePath:      cfg.SynthesisPath,
			Language:        cfg.Language,
		},
		Synthesis: cs,
	}
	body, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	out := filepath.Join(cfg.OutDir, "report.json")
	if err := os.WriteFile(out, body, 0o644); err != nil {
		return "", fmt.Errorf("write %q: %w", out, err)
	}
	return out, nil
}
