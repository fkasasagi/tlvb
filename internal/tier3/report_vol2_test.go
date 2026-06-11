package tier3

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tlvb/tlvb/internal/tier2"
)

// writeFinding drops one by-rule/<source>/<id>.json so loadEnrichment derives an
// IOC from its evidence's extra fields.
func writeFinding(t *testing.T, findingsDir, source, id, extraKey, extraVal string) {
	t.Helper()
	dir := filepath.Join(findingsDir, "by-rule", source)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{
  "rule_id": "` + id + `",
  "rule_source": "` + source + `",
  "rule_meta": {"title": "Finding ` + id + `", "level": "high",
    "mitre_tactics": ["execution"], "mitre_techniques": ["T1059.001"]},
  "evidence": [{"audit_id": "a-` + id + `", "ts_utc": "2026-05-19T13:50:00Z",
    "artifact_id": "evtx", "event_type": "process",
    "extra": {"` + extraKey + `": "` + extraVal + `"}}]
}`
	if err := os.WriteFile(filepath.Join(dir, id+".json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestReportVol2Sections renders a synthesis that exercises every report
// improvement Vol.2 feature and asserts the new structure renders:
//   - two-layer executive summary (ExecBrief box + collapsible technical detail)
//   - noise clusters demoted to a collapsed group at the end of section 7
//   - open questions split into 3 prioritised tiers
//   - IOCs split into confirmed / noise, with a parser-noise value kept OUT of
//     the confirmed table.
func TestReportVol2Sections(t *testing.T) {
	cs := tier2.CaseSynthesis{
		CaseID:        "VOL2",
		GeneratedAt:   time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC),
		TotalFindings: 2,
		ClusterCount:  2,
		OverallStory:  "Technical paragraph one.\n\nTechnical paragraph two.",
		ExecBrief:     "- システムA が攻撃者に侵害された\n- 重要データの持ち出しの恐れがある",
		TechSummary:   "Technical paragraph one.\n\nTechnical paragraph two.",
		OpenQuestionsSynth: tier2.OpenQuestionsSynthesis{
			Critical:        []string{"初期侵入経路は何か"},
			NeedsCollection: []string{"メモリダンプ取得で C2 を確認する"},
			Supplementary:   []string{"タイムゾーン補正の要否"},
		},
		Clusters: []tier2.SynthCluster{
			{
				ID:          1,
				StartTS:     time.Date(2026, 5, 19, 13, 50, 0, 0, time.UTC),
				EndTS:       time.Date(2026, 5, 19, 14, 0, 0, 0, time.UTC),
				AttackPhase: "execution",
				Narrative:   "ATTACK_CLUSTER_NARRATIVE encoded powershell ran",
				FindingRefs: []tier2.FindingRef{{Source: "sigma", RuleID: "rA", Title: "Finding rA", Severity: "high"}},
			},
			{
				// AttackPhase "unknown" → IsNoiseCluster true → demoted.
				ID:          2,
				StartTS:     time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
				EndTS:       time.Date(2020, 1, 1, 0, 5, 0, 0, time.UTC),
				AttackPhase: "unknown",
				Narrative:   "NOISE_CLUSTER_NARRATIVE vm first boot",
				FindingRefs: []tier2.FindingRef{{Source: "sigma", RuleID: "rB", Title: "Finding rB", Severity: "low"}},
			},
		},
	}

	dir := t.TempDir()
	findingsDir := filepath.Join(dir, "findings")
	writeFinding(t, findingsDir, "sigma", "rA", "CommandLine", "powershell -enc ZXZpbA==")
	writeFinding(t, findingsDir, "sigma", "rB", "AccountName", "LogonType 3")

	synthPath := filepath.Join(dir, "synthesis.json")
	synthBody, err := json.MarshalIndent(cs, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(synthPath, synthBody, 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "reports")
	if _, err := Render(Config{
		CaseID:        "VOL2",
		SynthesisPath: synthPath,
		FindingsDir:   findingsDir,
		OutDir:        outDir,
		Formats:       []string{"html"},
		Language:      "ja",
	}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(outDir, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)

	// Feature 1: two-layer executive summary.
	for _, want := range []string{
		dictJA.ExecBriefHeading,
		"システムA が攻撃者に侵害された",
		dictJA.TechDetailHeading,
		"Technical paragraph one.",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("exec summary missing %q", want)
		}
	}

	// Feature 2: noise cluster collapsed at end; attack cluster stays up top.
	if !strings.Contains(s, dictJA.NoiseClustersSummary) {
		t.Error("noise cluster group heading missing")
	}
	iAttack := strings.Index(s, "ATTACK_CLUSTER_NARRATIVE")
	iNoiseGroup := strings.Index(s, dictJA.NoiseClustersSummary)
	iNoiseCluster := strings.Index(s, "NOISE_CLUSTER_NARRATIVE")
	if iAttack < 0 || iNoiseCluster < 0 {
		t.Fatal("cluster narratives missing")
	}
	if !(iAttack < iNoiseGroup && iNoiseGroup < iNoiseCluster) {
		t.Errorf("ordering wrong: attack=%d noiseGroup=%d noiseCluster=%d (attack must precede the collapsed noise group)",
			iAttack, iNoiseGroup, iNoiseCluster)
	}

	// Feature 3: three open-question tiers.
	for _, want := range []string{
		dictJA.OQCritical, "初期侵入経路は何か",
		dictJA.OQNeedsCollection, "メモリダンプ",
		dictJA.OQSupplementary,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("open questions missing %q", want)
		}
	}

	// Feature 4: IOC tiers — confirmed present, parser noise demoted and kept
	// out of the confirmed table.
	if !strings.Contains(s, dictJA.IOCConfirmed) {
		t.Error("confirmed IOC heading missing")
	}
	if !strings.Contains(s, "powershell -enc") {
		t.Error("real command IOC missing from report")
	}
	if !strings.Contains(s, dictJA.IOCNoiseHidden) {
		t.Error("parser-noise IOC group heading missing")
	}
	iNoiseIOC := strings.Index(s, dictJA.IOCNoiseHidden)
	iLogonType := strings.Index(s, "LogonType 3")
	if iLogonType < 0 {
		t.Fatal("LogonType 3 value not rendered at all")
	}
	if iLogonType < iNoiseIOC {
		t.Error("LogonType 3 must render inside the parser-noise group, not in the confirmed IOC table")
	}
}
