package tier3

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tlvb/tlvb/internal/tier2"
)

// Render is the entry point. Reads synthesis.json, dispatches to
// per-format renderers, writes outputs to OutDir.
func Render(cfg Config) (*Report, error) {
	if cfg.CaseID == "" {
		return nil, fmt.Errorf("CaseID is required")
	}
	if cfg.SynthesisPath == "" {
		cfg.SynthesisPath = filepath.Join("outputs", "cases", cfg.CaseID, "synthesis.json")
	}
	if cfg.OutDir == "" {
		cfg.OutDir = filepath.Join("outputs", "cases", cfg.CaseID, "reports")
	}
	if len(cfg.Formats) == 0 {
		cfg.Formats = []string{"html", "csv", "json"}
	}
	if cfg.Language == "" {
		cfg.Language = "ja"
	}

	body, err := os.ReadFile(cfg.SynthesisPath)
	if err != nil {
		return nil, fmt.Errorf("read synthesis: %w", err)
	}
	var cs tier2.CaseSynthesis
	if err := json.Unmarshal(body, &cs); err != nil {
		return nil, fmt.Errorf("parse synthesis: %w", err)
	}
	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}

	rep := &Report{
		CaseID:      cfg.CaseID,
		OutDir:      cfg.OutDir,
		GeneratedAt: time.Now().UTC(),
		Sections:    len(cs.Clusters),
	}

	for _, f := range cfg.Formats {
		switch f {
		case "html":
			out := filepath.Join(cfg.OutDir, "report.html")
			if err := renderHTML(out, cs, cfg.Language); err != nil {
				return rep, fmt.Errorf("render html: %w", err)
			}
			rep.Files = append(rep.Files, fileMeta("html", out))
		case "csv":
			fp := filepath.Join(cfg.OutDir, "findings.csv")
			mp := filepath.Join(cfg.OutDir, "mitre.csv")
			cp := filepath.Join(cfg.OutDir, "clusters.csv")
			if err := renderFindingsCSV(fp, cs); err != nil {
				return rep, fmt.Errorf("render findings csv: %w", err)
			}
			if err := renderMITRECSV(mp, cs); err != nil {
				return rep, fmt.Errorf("render mitre csv: %w", err)
			}
			if err := renderClustersCSV(cp, cs); err != nil {
				return rep, fmt.Errorf("render clusters csv: %w", err)
			}
			rep.Files = append(rep.Files,
				fileMeta("csv-findings", fp),
				fileMeta("csv-mitre", mp),
				fileMeta("csv-clusters", cp),
			)
		case "json":
			out := filepath.Join(cfg.OutDir, "report.json")
			if err := renderJSON(out, cs); err != nil {
				return rep, fmt.Errorf("render json: %w", err)
			}
			rep.Files = append(rep.Files, fileMeta("json", out))
		default:
			return rep, fmt.Errorf("unknown format %q (want html|csv|json)", f)
		}
	}
	return rep, nil
}

// renderJSON writes a pretty-printed copy of synthesis.json under reports/.
// Even though synthesis.json IS already JSON, having it under reports/
// makes the report dir self-contained for archival / handover.
func renderJSON(path string, cs tier2.CaseSynthesis) error {
	body, err := json.MarshalIndent(cs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o644)
}

func fileMeta(format, path string) OutputFile {
	fi, _ := os.Stat(path)
	out := OutputFile{Format: format, Path: path}
	if fi != nil {
		out.SizeBytes = fi.Size()
	}
	return out
}
