package reporter

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/agents"
	"github.com/tlvb/tlvb/internal/synthesizer"
)

// writeCSVs emits findings.csv, timeline.csv, and iocs.csv side-by-side in
// cfg.OutDir. Returns a map[shortName]path for the caller's manifest.
//
// All three files use UTF-8 with a BOM so Excel auto-detects encoding —
// otherwise Japanese examiner labels mojibake on default Windows locales.
func writeCSVs(cs *synthesizer.CaseSynthesis, cfg Config) (map[string]string, error) {
	out := map[string]string{}

	if path, err := writeFindingsCSV(cs, cfg.OutDir); err != nil {
		return out, err
	} else {
		out["findings"] = path
	}

	if path, err := writeTimelineCSV(cs, cfg.OutDir); err != nil {
		return out, err
	} else {
		out["timeline"] = path
	}

	if path, err := writeIOCsCSV(cs, cfg.OutDir); err != nil {
		return out, err
	} else {
		out["iocs"] = path
	}

	if path, err := writeFailedArtifactsCSV(cs, cfg.OutDir); err != nil {
		return out, err
	} else if path != "" {
		out["failed_artifacts"] = path
	}

	return out, nil
}

// writeFailedArtifactsCSV emits a row per artifact whose parser run did not
// complete successfully. Returns "" when no failures are recorded — the
// caller skips manifesting it. Issue #26.
func writeFailedArtifactsCSV(cs *synthesizer.CaseSynthesis, outDir string) (string, error) {
	if len(cs.FailedArtifacts) == 0 {
		return "", nil
	}
	path := filepath.Join(outDir, "failed_artifacts.csv")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil { // UTF-8 BOM
		return "", err
	}
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{
		"case_id", "artifact_id", "stage", "exit_code", "reason", "command",
	}); err != nil {
		return "", err
	}
	for _, fa := range cs.FailedArtifacts {
		exit := ""
		if fa.ExitCode != nil {
			exit = fmt.Sprintf("%d", *fa.ExitCode)
		}
		if err := w.Write([]string{
			cs.CaseID, fa.ArtifactID, fa.Stage, exit, fa.Reason, fa.Command,
		}); err != nil {
			return "", err
		}
	}
	return path, nil
}

// ---- findings.csv ----------------------------------------------------------

func writeFindingsCSV(cs *synthesizer.CaseSynthesis, outDir string) (string, error) {
	path := filepath.Join(outDir, "findings.csv")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil { // UTF-8 BOM
		return "", err
	}

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"case_id", "evidence_id", "tactic_id", "tactic_name",
		"finding_id", "technique_id", "technique_name",
		"confidence", "summary", "reasoning",
		"evidence_count", "evidence_audit_ids",
	}
	if err := w.Write(header); err != nil {
		return "", err
	}

	// findings_by_tactic is already grouped; iterate in tactic-id order.
	tacticIDs := make([]string, 0, len(cs.FindingsByTactic))
	for k := range cs.FindingsByTactic {
		tacticIDs = append(tacticIDs, k)
	}
	sort.Strings(tacticIDs)

	for _, tid := range tacticIDs {
		for _, fdg := range cs.FindingsByTactic[tid] {
			ids := make([]string, 0, len(fdg.Evidence))
			for _, ev := range fdg.Evidence {
				ids = append(ids, ev.AuditID)
			}
			row := []string{
				cs.CaseID, cs.EvidenceID,
				tid, lookupTacticName(cs, tid),
				fdg.FindingID, fdg.TechniqueID, fdg.TechniqueName,
				fdg.Confidence, fdg.Summary, fdg.Reasoning,
				fmt.Sprintf("%d", len(fdg.Evidence)),
				strings.Join(ids, ";"),
			}
			if err := w.Write(row); err != nil {
				return "", err
			}
		}
	}
	return path, nil
}

func lookupTacticName(cs *synthesizer.CaseSynthesis, tacticID string) string {
	for _, m := range cs.MITREMapping {
		if m.Tactic == tacticID && m.TacticName != "" {
			return m.TacticName
		}
	}
	for _, s := range cs.IntrusionPath {
		if s.Tactic == tacticID {
			return s.TacticName
		}
	}
	return ""
}

// ---- timeline.csv ----------------------------------------------------------

func writeTimelineCSV(cs *synthesizer.CaseSynthesis, outDir string) (string, error) {
	path := filepath.Join(outDir, "timeline.csv")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return "", err
	}

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"timestamp_utc", "audit_id", "artifact_id", "computer",
		"tactic", "technique", "confidence",
		"summary", "finding_ids",
	}
	if err := w.Write(header); err != nil {
		return "", err
	}

	for _, t := range cs.Timeline {
		row := []string{
			t.Timestamp.UTC().Format(time.RFC3339Nano),
			t.AuditID, t.ArtifactID, t.Computer,
			t.Tactic, t.Technique, t.Confidence,
			t.Summary, strings.Join(t.FindingIDs, ";"),
		}
		if err := w.Write(row); err != nil {
			return "", err
		}
	}
	return path, nil
}

// ---- iocs.csv --------------------------------------------------------------

// IOC types emitted in priority order — most-specific first so a single
// payload string is classified once.
type iocType string

const (
	iocSHA256       iocType = "sha256"
	iocSHA1         iocType = "sha1"
	iocMD5          iocType = "md5"
	iocIPv4         iocType = "ipv4"
	iocURL          iocType = "url"
	iocDomain       iocType = "domain"
	iocFilePath     iocType = "file_path"
	iocRegistryKey  iocType = "registry_key"
	iocServiceName  iocType = "service_name"
	iocScheduledTask iocType = "scheduled_task"
)

// IOCExtraction is one (type, value) record with attribution to the
// findings that produced it. We dedup by (type, value).
type IOCExtraction struct {
	Type     iocType
	Value    string
	Findings map[string]struct{} // finding_id set
	Tactics  map[string]struct{} // tactic_id set
}

func writeIOCsCSV(cs *synthesizer.CaseSynthesis, outDir string) (string, error) {
	path := filepath.Join(outDir, "iocs.csv")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return "", err
	}

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"ioc_type", "ioc_value", "count", "source_findings", "source_tactics",
	}
	if err := w.Write(header); err != nil {
		return "", err
	}

	iocs := ExtractIOCs(cs)
	for _, ioc := range iocs {
		findingsList := sortedSet(ioc.Findings)
		tacticsList := sortedSet(ioc.Tactics)
		row := []string{
			string(ioc.Type), ioc.Value,
			fmt.Sprintf("%d", len(ioc.Findings)),
			strings.Join(findingsList, ";"),
			strings.Join(tacticsList, ";"),
		}
		if err := w.Write(row); err != nil {
			return "", err
		}
	}
	return path, nil
}

// ExtractIOCs walks all finding text fields (summary, reasoning, evidence
// excerpt) and pulls regex-matched indicators. Public so html_report.go
// can reuse the same logic for the IOC Summary section.
func ExtractIOCs(cs *synthesizer.CaseSynthesis) []IOCExtraction {
	idx := map[string]*IOCExtraction{} // key = type|value

	add := func(typ iocType, value, findingID, tacticID string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		key := string(typ) + "|" + strings.ToLower(value)
		ex, ok := idx[key]
		if !ok {
			ex = &IOCExtraction{
				Type:     typ,
				Value:    value,
				Findings: map[string]struct{}{},
				Tactics:  map[string]struct{}{},
			}
			idx[key] = ex
		}
		if findingID != "" {
			ex.Findings[findingID] = struct{}{}
		}
		if tacticID != "" {
			ex.Tactics[tacticID] = struct{}{}
		}
	}

	// Walk findings_by_tactic so we have tactic_id attribution.
	for tid, list := range cs.FindingsByTactic {
		for _, fdg := range list {
			extractFromText(fdg.Summary, fdg.FindingID, tid, add)
			extractFromText(fdg.Reasoning, fdg.FindingID, tid, add)
			for _, ev := range fdg.Evidence {
				extractFromText(ev.Excerpt, fdg.FindingID, tid, add)
			}
		}
	}

	// Stable order for diffability.
	keys := make([]string, 0, len(idx))
	for k := range idx {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]IOCExtraction, 0, len(keys))
	for _, k := range keys {
		out = append(out, *idx[k])
	}
	return out
}

// ---- regex-driven extraction ----------------------------------------------

var (
	rxSHA256        = regexp.MustCompile(`\b[A-Fa-f0-9]{64}\b`)
	rxSHA1          = regexp.MustCompile(`\b[A-Fa-f0-9]{40}\b`)
	rxMD5           = regexp.MustCompile(`\b[A-Fa-f0-9]{32}\b`)
	rxIPv4          = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`)
	rxURL           = regexp.MustCompile(`https?://[^\s<>"\'\)]+`)
	rxDomain        = regexp.MustCompile(`\b[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}(?:\.[a-zA-Z0-9][a-zA-Z0-9\-]{0,62})+\.(?:com|net|org|io|biz|info|jp|cn|ru|tk|cc|to|me|us|uk|de|fr|app|dev|xyz|co|tv)\b`)
	// File path: drive letter + colon + backslash, terminate at quote/space/end
	rxFilePath      = regexp.MustCompile(`[A-Za-z]:\\[^"'\s<>|]+`)
	// Registry key: starts with HKLM/HKEY_*/HKCU/HKCR (case-insensitive)
	rxRegistryKey   = regexp.MustCompile(`(?i)\bH(?:K(?:LM|CU|CR|U|CC)|KEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG))\\[^"'\s<>|]+`)
	// "Name: <svc_name>" pattern in 7045 excerpts
	rxServiceName   = regexp.MustCompile(`\bName:\s*([A-Za-z_][A-Za-z0-9_\-]{0,63})\b`)
	rxTaskName      = regexp.MustCompile(`\bTaskName:\s*(\\[^\s,;'"]+)`)
)

func extractFromText(text, findingID, tacticID string, add func(iocType, string, string, string)) {
	if text == "" {
		return
	}

	// SHA256 must be tried before SHA1 / MD5 because the regexes overlap.
	for _, v := range rxSHA256.FindAllString(text, -1) {
		add(iocSHA256, v, findingID, tacticID)
	}
	// To avoid double-counting a SHA256 as also-a-SHA1-prefix, mask the
	// SHA256 hits before SHA1 / MD5 scan.
	masked := rxSHA256.ReplaceAllString(text, strings.Repeat(" ", 64))
	for _, v := range rxSHA1.FindAllString(masked, -1) {
		add(iocSHA1, v, findingID, tacticID)
	}
	masked = rxSHA1.ReplaceAllString(masked, strings.Repeat(" ", 40))
	for _, v := range rxMD5.FindAllString(masked, -1) {
		add(iocMD5, v, findingID, tacticID)
	}

	for _, v := range rxIPv4.FindAllString(text, -1) {
		// Skip RFC3330 reserved that aren't useful as IOCs:
		// 0.0.0.0, 255.255.255.255. Local 127/8 still useful (scoped C2).
		if v == "0.0.0.0" || v == "255.255.255.255" {
			continue
		}
		add(iocIPv4, v, findingID, tacticID)
	}

	for _, v := range rxURL.FindAllString(text, -1) {
		add(iocURL, strings.TrimRight(v, ".,;)"), findingID, tacticID)
	}

	// Domain: strip URLs first to avoid double-counting host parts.
	noURLs := rxURL.ReplaceAllString(text, " ")
	for _, v := range rxDomain.FindAllString(noURLs, -1) {
		add(iocDomain, strings.ToLower(v), findingID, tacticID)
	}

	for _, v := range rxFilePath.FindAllString(text, -1) {
		add(iocFilePath, strings.TrimRight(v, ".,;)"), findingID, tacticID)
	}
	for _, v := range rxRegistryKey.FindAllString(text, -1) {
		add(iocRegistryKey, strings.TrimRight(v, ".,;)"), findingID, tacticID)
	}
	for _, m := range rxServiceName.FindAllStringSubmatch(text, -1) {
		add(iocServiceName, m[1], findingID, tacticID)
	}
	for _, m := range rxTaskName.FindAllStringSubmatch(text, -1) {
		add(iocScheduledTask, m[1], findingID, tacticID)
	}
}

func sortedSet(s map[string]struct{}) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// _ keeps the agents import alive — Findings field uses agents.Finding.
var _ agents.Finding
