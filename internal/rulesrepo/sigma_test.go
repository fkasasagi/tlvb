package rulesrepo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSigmaLoaderSmoke(t *testing.T) {
	// Smoke test against the actual checked-out Sigma submodule. We don't
	// care about the exact count — we just want to confirm the loader
	// reads YAML, skips non-Windows, and tags Sysmon-only rules.
	root := "../../rules/sigma/upstream/rules"
	if _, err := os.Stat(root); err != nil {
		t.Skipf("sigma submodule not checked out at %s — skipping", root)
	}
	l := NewSigmaLoader(root)
	rules, err := l.LoadAll(context.Background())
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(rules) < 100 {
		t.Fatalf("expected at least 100 sigma rules, got %d", len(rules))
	}

	var built, skipped, sysmon, nonwin int
	for _, r := range rules {
		if r.Skip {
			skipped++
			if r.RequiresSysmon {
				sysmon++
			}
			if r.SkipReason != "" && r.SkipReason[:1] == "n" {
				// "non-Windows..."
				nonwin++
			}
		} else {
			built++
		}
	}
	t.Logf("sigma rules: total=%d built=%d skipped=%d (sysmon=%d non-windows=%d)",
		len(rules), built, skipped, sysmon, nonwin)

	// Confirm rule_id, sha256, and prefilter are populated on the first
	// built rule.
	for _, r := range rules {
		if !r.Skip {
			if r.RuleID == "" {
				t.Errorf("built rule has empty RuleID: %s", r.SourcePath)
			}
			if r.RuleSHA256 == "" || len(r.RuleSHA256) != 64 {
				t.Errorf("built rule has malformed RuleSHA256: %q", r.RuleSHA256)
			}
			if len(r.PrefilterArtifacts) == 0 {
				t.Errorf("built Windows sigma rule should target evtx: %s", r.SourcePath)
			}
			if r.RawContent == "" {
				t.Errorf("built rule has empty RawContent: %s", r.SourcePath)
			}
			break
		}
	}
}

func TestSigmaLoaderTinyFixture(t *testing.T) {
	dir := t.TempDir()
	mkRule(t, dir, "win_proc.yml", `
title: Test Process Creation
id: 11111111-2222-3333-4444-555555555555
status: stable
description: A Sysmon process_creation test rule.
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
    condition: selection
level: medium
`)
	mkRule(t, dir, "win_security.yml", `
title: Failed Logon
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
status: stable
tags:
    - attack.credential-access
    - attack.t1110
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
level: high
`)
	mkRule(t, dir, "linux_proc.yml", `
title: Linux Curl
id: 22222222-3333-4444-5555-666666666666
status: stable
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: 'curl'
    condition: selection
level: low
`)
	mkRule(t, dir, "notarule.yml", `
title: Just metadata
description: A fixture YAML with no id — must be ignored without error.
`)

	l := NewSigmaLoader(dir)
	rules, err := l.LoadAll(context.Background())
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules (no-id is silently skipped), got %d", len(rules))
	}

	var win_proc, win_sec, linux *RawRule
	for i := range rules {
		switch rules[i].RuleID {
		case "11111111-2222-3333-4444-555555555555":
			win_proc = &rules[i]
		case "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee":
			win_sec = &rules[i]
		case "22222222-3333-4444-5555-666666666666":
			linux = &rules[i]
		}
	}
	if win_proc == nil || win_sec == nil || linux == nil {
		t.Fatal("expected all 3 fixtures to be loaded")
	}

	// win_proc: process_creation is NOT Sysmon-only — Sigma intends it to
	// compile to either Sysmon EID 1 or Security 4688, and we handle 4688
	// via SchemaDoc. So this rule should be buildable (not skipped).
	if win_proc.Skip || win_proc.RequiresSysmon {
		t.Errorf("win_proc (process_creation) should NOT be skipped: skip=%v sysmon=%v reason=%q",
			win_proc.Skip, win_proc.RequiresSysmon, win_proc.SkipReason)
	}
	if got := win_proc.MITRETechniques; len(got) != 1 || got[0] != "T1059.001" {
		t.Errorf("win_proc techniques: got %v", got)
	}

	// win_sec: Windows Security service, NOT Sysmon → built
	if win_sec.Skip || win_sec.RequiresSysmon {
		t.Errorf("win_sec should NOT be skipped: skip=%v sysmon=%v",
			win_sec.Skip, win_sec.RequiresSysmon)
	}
	if win_sec.Level != "high" {
		t.Errorf("win_sec level: got %q", win_sec.Level)
	}
	if got := win_sec.MITRETechniques; len(got) != 1 || got[0] != "T1110" {
		t.Errorf("win_sec techniques: got %v", got)
	}

	// linux: non-Windows → Skip
	if !linux.Skip {
		t.Errorf("linux rule should be skipped")
	}
}

func TestSigmaLoaderIncludeSysmonFlag(t *testing.T) {
	dir := t.TempDir()
	// Use an actual Sysmon-only category (image_load) — process_creation
	// is now treated as Sigma-abstract and never skipped.
	mkRule(t, dir, "win_imgload.yml", `
title: Sysmon Image Load Test
id: 22222222-3333-4444-5555-666666666666
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded|endswith: '\amsi.dll'
    condition: selection
level: low
`)
	l := NewSigmaLoader(dir)
	l.IncludeSysmon = true
	rules, _ := l.LoadAll(context.Background())
	if len(rules) != 1 {
		t.Fatalf("got %d rules", len(rules))
	}
	if rules[0].Skip {
		t.Errorf("IncludeSysmon=true should not skip Sysmon rule")
	}
	if !rules[0].RequiresSysmon {
		t.Errorf("RequiresSysmon should still be true (informational flag)")
	}
}

func mkRule(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
