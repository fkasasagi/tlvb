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

func makeCS() tier2.CaseSynthesis {
	return tier2.CaseSynthesis{
		CaseID:        "T1",
		GeneratedAt:   time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC),
		ModelID:       "claude-mock-1",
		TotalFindings: 5,
		ClusterCount:  2,
		OverallStory:  "Overall story line 1.\n\nLine 2 paragraph.",
		Clusters: []tier2.SynthCluster{
			{
				ID:              1,
				StartTS:         time.Date(2026, 5, 19, 13, 50, 0, 0, time.UTC),
				EndTS:           time.Date(2026, 5, 19, 14, 0, 0, 0, time.UTC),
				AttackPhase:     "execution",
				Narrative:       "powershell.exe spawned mimi.exe",
				MITRETechniques: []string{"T1059.001", "T1003.001"},
				OpenQuestions:   []string{"who is the source IP?"},
				FindingRefs: []tier2.FindingRef{
					{Source: "sigma", RuleID: "r1", Title: "Encoded PS", Severity: "high"},
					{Source: "hayabusa", RuleID: "h1", Title: "Mimikatz Execution", Severity: "high"},
				},
			},
			{
				ID:          2,
				StartTS:     time.Date(2026, 5, 20, 6, 32, 0, 0, time.UTC),
				EndTS:       time.Date(2026, 5, 20, 6, 33, 0, 0, time.UTC),
				AttackPhase: "lateral-movement",
				Narrative:   "RDP from public IP",
				FindingRefs: []tier2.FindingRef{{Source: "hayabusa", RuleID: "rdp", Title: "RDP Logon", Severity: "medium"}},
			},
		},
		MITREMapping: []tier2.MITREEntry{
			{Technique: "T1059.001", Tactic: "execution", FindingCount: 2, ClusterIDs: []int{1}},
			{Technique: "T1021.001", Tactic: "lateral-movement", FindingCount: 1, ClusterIDs: []int{2}},
		},
		Audit: tier2.SynthAudit{LLMCallsTotal: 3, LLMDurationS: 12.3,
			InputTokensTotal: 1234, OutputTokensTotal: 567,
			SkillSHA256: "abcdef0123456789aaaaa"},
	}
}

// helper to render from an in-memory CaseSynthesis: write to tmp file, then call Render.
func renderFromSynth(t *testing.T, cs tier2.CaseSynthesis, formats []string, lang string) (*Report, string) {
	t.Helper()
	dir := t.TempDir()
	synthPath := filepath.Join(dir, "synthesis.json")
	body, _ := json.MarshalIndent(cs, "", "  ")
	if err := os.WriteFile(synthPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "reports")
	rep, err := Render(Config{
		CaseID:        cs.CaseID,
		SynthesisPath: synthPath,
		OutDir:        outDir,
		Formats:       formats,
		Language:      lang,
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return rep, outDir
}

func TestRenderHTML(t *testing.T) {
	rep, outDir := renderFromSynth(t, makeCS(), []string{"html"}, "ja")
	if len(rep.Files) != 1 || rep.Files[0].Format != "html" {
		t.Fatalf("expected 1 html file, got %v", rep.Files)
	}
	body, err := os.ReadFile(filepath.Join(outDir, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	// Spot-check expected content.
	for _, want := range []string{
		"TLVB", "T1", "powershell.exe spawned mimi.exe",
		"T1059.001", "T1003.001", "Encoded PS", "Mimikatz Execution",
		"RDP from public IP",
		"who is the source IP?",
		"エグゼクティブサマリ",                // JA dict
		"侵入経路 (Intrusion Path)",     // rule-derived; present whenever clusters exist
		"今後の推奨事項 (Recommendations)", // rule-derived; present from generic items
		"MITRE ATT&amp;CK",          // template encodes & → &amp;
	} {
		if !strings.Contains(s, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
}

func TestRenderHTMLEnLang(t *testing.T) {
	_, outDir := renderFromSynth(t, makeCS(), []string{"html"}, "en")
	body, _ := os.ReadFile(filepath.Join(outDir, "report.html"))
	s := string(body)
	if !strings.Contains(s, "Executive Summary") {
		t.Error("EN dict should contain 'Executive Summary'")
	}
	if strings.Contains(s, "全体ストーリー") {
		t.Error("EN report should not contain JA labels")
	}
}

// deriveIntrusionPath / deriveAffectedScope / deriveRecommendations are
// rule-based, so test them directly rather than through the full HTML render
// (the scope section only appears when there is host/account/data to show).
func TestDeriveIRSections(t *testing.T) {
	cs := makeCS()
	cs.MITREMapping = append(cs.MITREMapping,
		tier2.MITREEntry{Technique: "T1003.001", Tactic: "credential-access", FindingCount: 1, ClusterIDs: []int{1}},
		tier2.MITREEntry{Technique: "T1078", Tactic: "initial-access", FindingCount: 1, ClusterIDs: []int{2}},
	)
	en := &enrichment{IOCs: []iocRow{
		{Type: "host", Value: "HOST-A"},
		{Type: "account", Value: "alice"},
	}}

	if got := deriveIntrusionPath(cs, "ja", nil); !strings.Contains(got, "T1078") {
		t.Errorf("intrusion path should cite the initial-access technique, got %q", got)
	}

	sv := deriveAffectedScope(cs, en, "ja")
	if sv == nil {
		t.Fatal("scope should be non-nil when IOCs carry host/account")
	}
	if len(sv.Hosts) != 1 || sv.Hosts[0] != "HOST-A" {
		t.Errorf("scope hosts = %v, want [HOST-A]", sv.Hosts)
	}
	if len(sv.Accounts) != 1 || sv.Accounts[0] != "alice" {
		t.Errorf("scope accounts = %v, want [alice]", sv.Accounts)
	}
	if len(sv.DataAtRisk) == 0 {
		t.Error("credential-access tactic should add a data-at-risk entry")
	}

	reco := deriveRecommendations(cs, "ja")
	if reco == nil || len(reco.Containment) == 0 || len(reco.Recovery) == 0 {
		t.Fatalf("recommendations should be populated, got %+v", reco)
	}
}

// When there are no IOCs and no scope-bearing tactics, the scope section is
// omitted entirely (nil) rather than rendered empty.
func TestDeriveAffectedScopeEmpty(t *testing.T) {
	cs := tier2.CaseSynthesis{} // no clusters, no mapping
	if sv := deriveAffectedScope(cs, &enrichment{}, "ja"); sv != nil {
		t.Errorf("scope should be nil with no IOCs/tactics, got %+v", sv)
	}
}

func TestRenderCSV(t *testing.T) {
	rep, outDir := renderFromSynth(t, makeCS(), []string{"csv"}, "ja")
	if len(rep.Files) != 5 {
		t.Fatalf("expected 5 csv files, got %d", len(rep.Files))
	}
	for _, fname := range []string{"findings.csv", "mitre.csv", "clusters.csv", "ioc.csv", "timeline.csv"} {
		body, err := os.ReadFile(filepath.Join(outDir, fname))
		if err != nil {
			t.Fatalf("read %s: %v", fname, err)
		}
		s := string(body)
		// UTF-8 BOM present (3 bytes 0xEF 0xBB 0xBF) so Excel auto-detects encoding.
		if !strings.HasPrefix(s, "\xEF\xBB\xBF") {
			t.Errorf("%s missing UTF-8 BOM", fname)
		}
	}
	// findings.csv should have one row per FindingRef + header.
	body, _ := os.ReadFile(filepath.Join(outDir, "findings.csv"))
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 1+3 { // 1 header + 3 finding rows (cluster1: 2 + cluster2: 1)
		t.Errorf("findings.csv line count: got %d, want 4", len(lines))
	}
}

func TestRenderJSON(t *testing.T) {
	rep, outDir := renderFromSynth(t, makeCS(), []string{"json"}, "ja")
	if len(rep.Files) != 1 || rep.Files[0].Format != "json" {
		t.Fatalf("expected 1 json file, got %v", rep.Files)
	}
	body, _ := os.ReadFile(filepath.Join(outDir, "report.json"))
	var cs tier2.CaseSynthesis
	if err := json.Unmarshal(body, &cs); err != nil {
		t.Fatalf("report.json invalid: %v", err)
	}
	if cs.CaseID != "T1" || cs.ClusterCount != 2 {
		t.Errorf("round-trip mismatch: %+v", cs)
	}
}

func TestRenderAllFormatsDefault(t *testing.T) {
	rep, _ := renderFromSynth(t, makeCS(), nil, "")
	// nil formats → default html+csv+json = 7 files (1 html + 5 csv + 1 json)
	if len(rep.Files) != 7 {
		t.Errorf("expected 7 files for default formats, got %d (%+v)",
			len(rep.Files), rep.Files)
	}
}

func TestSplitParagraphs(t *testing.T) {
	got := splitParagraphs("para 1.\n\npara 2.\n\n\npara 3.")
	if len(got) != 3 {
		t.Fatalf("got %d paras, want 3", len(got))
	}
	if got[2] != "para 3." {
		t.Errorf("got %q", got[2])
	}
	if got := splitParagraphs(""); got != nil {
		t.Errorf("empty input should yield nil, got %v", got)
	}
}

func TestReportTimezoneFormatting(t *testing.T) {
	// reportLocation falls back to UTC on empty/garbage, echoes valid zones.
	if loc, label := reportLocation(""); loc != time.UTC || label != "UTC" {
		t.Errorf("reportLocation(\"\"): got (%v,%q), want (UTC,UTC)", loc, label)
	}
	if loc, label := reportLocation("Not/AZone"); loc != time.UTC || label != "UTC" {
		t.Errorf("reportLocation(garbage): got (%v,%q), want (UTC,UTC)", loc, label)
	}
	jst, label := reportLocation("Asia/Tokyo")
	if label != "Asia/Tokyo" {
		t.Fatalf("reportLocation label: got %q", label)
	}

	// 13:00 UTC == 22:00 JST (+09:00). formatTSIn preserves the offset.
	utc := time.Date(2026, 6, 10, 13, 0, 0, 0, time.UTC)
	if got := formatTSIn(utc, jst); got != "2026-06-10T22:00:00+09:00" {
		t.Errorf("formatTSIn JST: got %q, want 2026-06-10T22:00:00+09:00", got)
	}
	if got := formatTSIn(utc, time.UTC); got != "2026-06-10T13:00:00Z" {
		t.Errorf("formatTSIn UTC: got %q, want 2026-06-10T13:00:00Z", got)
	}
	if got := formatTSIn(time.Time{}, jst); got != "" {
		t.Errorf("formatTSIn(zero): got %q, want empty", got)
	}
}

func TestSeverityClass(t *testing.T) {
	cases := map[string]string{
		"critical":      "sev-critical",
		"HIGH":          "sev-high",
		"medium":        "sev-medium",
		"low":           "sev-low",
		"informational": "sev-info",
		"info":          "sev-info",
		"":              "sev-unknown",
		"weird":         "sev-unknown",
	}
	for k, want := range cases {
		if got := severityClass(k); got != want {
			t.Errorf("severityClass(%q): got %q, want %q", k, got, want)
		}
	}
}
