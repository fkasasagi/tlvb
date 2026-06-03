package tier3

import (
	"os"
	"path/filepath"
	"testing"
)

// LoadWebEnrichment is what the Web UI's /timeline, /iocs and /mitre endpoints
// serve. After the tier2 migration synthesis.json no longer carries this
// material, so it must be derivable straight from findings/.
func TestLoadWebEnrichment(t *testing.T) {
	dir := t.TempDir()
	byRule := filepath.Join(dir, "by-rule", "sigma")
	if err := os.MkdirAll(byRule, 0o755); err != nil {
		t.Fatal(err)
	}
	finding := `{
	  "rule_id": "r1",
	  "rule_source": "sigma",
	  "rule_meta": {
	    "title": "LSASS dump via procdump",
	    "level": "critical",
	    "mitre_tactics": ["credential-access"],
	    "mitre_techniques": ["T1003.001"]
	  },
	  "evidence": [
	    {"audit_id":"aid-1","ts_utc":"2026-05-19T13:50:28Z","artifact_id":"evtx","event_type":"process_creation",
	     "extra":{"CommandLine":"procdump -ma lsass.exe out.dmp","Computer":"HOST-A"}}
	  ]
	}`
	if err := os.WriteFile(filepath.Join(byRule, "r1.json"), []byte(finding), 0o644); err != nil {
		t.Fatal(err)
	}

	en := LoadWebEnrichment(dir)

	// Timeline: one row, carrying the finding's tactic/technique + the
	// evidence's audit_id and computer (needed by the UI + Review Gate 2).
	if len(en.Timeline) != 1 {
		t.Fatalf("timeline len = %d, want 1", len(en.Timeline))
	}
	tl := en.Timeline[0]
	if tl.Tactic != "credential-access" || tl.Technique != "T1003.001" {
		t.Errorf("timeline tactic/technique = %q/%q", tl.Tactic, tl.Technique)
	}
	if tl.AuditID != "aid-1" {
		t.Errorf("timeline audit_id = %q, want aid-1", tl.AuditID)
	}
	if tl.Computer != "HOST-A" {
		t.Errorf("timeline computer = %q, want HOST-A", tl.Computer)
	}

	// MITRE: one (tactic, technique) cell with high confidence (critical sev).
	if len(en.MITRE) != 1 {
		t.Fatalf("mitre len = %d, want 1", len(en.MITRE))
	}
	m := en.MITRE[0]
	if m.Technique != "T1003.001" || m.Tactic != "credential-access" {
		t.Errorf("mitre cell = %q/%q", m.Tactic, m.Technique)
	}
	if m.FindingCount != 1 || m.EvidenceCount != 1 {
		t.Errorf("mitre counts = finding %d / evidence %d, want 1/1", m.FindingCount, m.EvidenceCount)
	}
	if m.Confidence != "high" {
		t.Errorf("mitre confidence = %q, want high", m.Confidence)
	}
	if m.TacticName != "Credential Access" {
		t.Errorf("mitre tactic_name = %q, want Credential Access", m.TacticName)
	}

	// IOC: the command line + host should surface, tagged with the tactic.
	var sawCmd, sawHost bool
	for _, i := range en.IOCs {
		if i.Type == "command" {
			sawCmd = true
			if len(i.Tactics) != 1 || i.Tactics[0] != "credential-access" {
				t.Errorf("command IOC tactics = %v, want [credential-access]", i.Tactics)
			}
		}
		if i.Type == "host" {
			sawHost = true
		}
	}
	if !sawCmd || !sawHost {
		t.Errorf("expected command + host IOCs, sawCmd=%v sawHost=%v", sawCmd, sawHost)
	}
}
