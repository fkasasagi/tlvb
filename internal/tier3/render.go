package tier3

import (
	"context"
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
	if cfg.FindingsDir == "" {
		cfg.FindingsDir = filepath.Join("outputs", "cases", cfg.CaseID, "findings")
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

	// Report display timezone: events are stored UTC; the report renders them
	// in the case timezone (Config.Timezone). Resolved once and threaded into
	// every renderer so HTML and CSV agree.
	loc, _ := reportLocation(cfg.Timezone)

	// Best-effort enrichment from per-finding evidence files (severity counts,
	// IOCs, key-event timeline, MITRE matrix, per-finding evidence detail).
	en := loadEnrichment(cfg.FindingsDir)

	// The Tier 2 LLM frequently leaves synthesis.json's mitre_mapping empty
	// (it relies on per-cluster LLM output). Fall back to the deterministic
	// findings-derived MITRE so the report's MITRE section, mitre.csv and the
	// rule-based intrusion path / affected scope are populated. This mirrors
	// how IOCs and the timeline are already derived from findings.
	if len(cs.MITREMapping) == 0 {
		cs.MITREMapping = mitreEntriesFromEnrichment(en)
	}

	rep := &Report{
		CaseID:      cfg.CaseID,
		OutDir:      cfg.OutDir,
		GeneratedAt: time.Now().UTC(),
		Sections:    len(cs.Clusters),
	}

	// Self-check gate: verify the derived sections do not contradict the
	// synthesis (or each other) before the report is treated as done, and
	// persist the result to reports/report_consistency.json. Runs on the same
	// `cs` the renderers consume, so what it checks is what gets written. The
	// optional advisory LLM pass (cfg.ConsistencyLLM) gets its own bounded
	// deadline so a slow/hung model never stalls report generation.
	gateCtx, gateCancel := context.WithTimeout(context.Background(), consistencyLLMTimeout)
	rep.ConsistencyIssues = runConsistencyGate(gateCtx, cfg, cs, en)
	gateCancel()

	for _, f := range cfg.Formats {
		switch f {
		case "html":
			out := filepath.Join(cfg.OutDir, "report.html")
			if err := renderHTML(out, cs, cfg, en, loc); err != nil {
				return rep, fmt.Errorf("render html: %w", err)
			}
			rep.Files = append(rep.Files, fileMeta("html", out))
		case "csv":
			fp := filepath.Join(cfg.OutDir, "findings.csv")
			mp := filepath.Join(cfg.OutDir, "mitre.csv")
			cp := filepath.Join(cfg.OutDir, "clusters.csv")
			ip := filepath.Join(cfg.OutDir, "ioc.csv")
			tp := filepath.Join(cfg.OutDir, "timeline.csv")
			if err := renderFindingsCSV(fp, cs, loc); err != nil {
				return rep, fmt.Errorf("render findings csv: %w", err)
			}
			if err := renderMITRECSV(mp, cs); err != nil {
				return rep, fmt.Errorf("render mitre csv: %w", err)
			}
			if err := renderClustersCSV(cp, cs, loc); err != nil {
				return rep, fmt.Errorf("render clusters csv: %w", err)
			}
			if err := renderIOCCSV(ip, en); err != nil {
				return rep, fmt.Errorf("render ioc csv: %w", err)
			}
			if err := renderTimelineCSV(tp, en, loc); err != nil {
				return rep, fmt.Errorf("render timeline csv: %w", err)
			}
			rep.Files = append(rep.Files,
				fileMeta("csv-findings", fp),
				fileMeta("csv-mitre", mp),
				fileMeta("csv-clusters", cp),
				fileMeta("csv-ioc", ip),
				fileMeta("csv-timeline", tp),
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

// mitreEntriesFromEnrichment projects the findings-derived MITRE matrix onto
// the tier2.MITREEntry shape the report renderers consume. Used only as a
// fallback when synthesis.json carried no mitre_mapping. ClusterIDs is left
// empty — enrichment is finding-scoped, not cluster-scoped.
func mitreEntriesFromEnrichment(en *enrichment) []tier2.MITREEntry {
	out := make([]tier2.MITREEntry, 0, len(en.MITRE))
	for _, m := range en.MITRE {
		out = append(out, tier2.MITREEntry{
			Technique:    m.Technique,
			Tactic:       m.Tactic,
			FindingCount: m.FindingCount,
		})
	}
	return out
}

func fileMeta(format, path string) OutputFile {
	fi, _ := os.Stat(path)
	out := OutputFile{Format: format, Path: path}
	if fi != nil {
		out.SizeBytes = fi.Size()
	}
	return out
}
