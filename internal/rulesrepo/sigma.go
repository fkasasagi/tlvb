package rulesrepo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// SigmaLoader walks rules/sigma/upstream/rules/**.yml.
type SigmaLoader struct {
	// Root is the directory to walk. Typically "rules/sigma/upstream/rules".
	Root string
	// IncludeSysmon: when false (default), rules whose logsource implies
	// Sysmon (service=sysmon or category in the Sysmon-typical set) are
	// returned with Skip=true. See CLAUDE.md "Memory / Sysmon ルール".
	IncludeSysmon bool
	// IncludeNonWindows: when false (default), Linux/macOS rules are
	// returned with Skip=true. TLVB targets Windows triage.
	IncludeNonWindows bool
}

// NewSigmaLoader returns a loader rooted at rules/sigma/upstream/rules with
// the TLVB defaults (Sysmon off, Windows only).
func NewSigmaLoader(root string) *SigmaLoader {
	return &SigmaLoader{Root: root}
}

func (l *SigmaLoader) Source() string { return "sigma" }

// sigmaDoc is the subset of the Sigma YAML schema we care about. Fields
// we don't read still round-trip via RawContent.
type sigmaDoc struct {
	ID          string                 `yaml:"id"`
	Title       string                 `yaml:"title"`
	Description string                 `yaml:"description"`
	Status      string                 `yaml:"status"`
	Level       string                 `yaml:"level"`
	Tags        []string               `yaml:"tags"`
	Logsource   sigmaLogsource         `yaml:"logsource"`
	Detection   map[string]interface{} `yaml:"detection"`
}

type sigmaLogsource struct {
	Product    string `yaml:"product"`
	Category   string `yaml:"category"`
	Service    string `yaml:"service"`
	Definition string `yaml:"definition"`
}

// unsupportedCategories lists Sigma logsource.category values that target
// data sources outside TLVB's Windows host-forensics scope (Web proxies,
// network firewalls, database audit logs, web-server access logs). These
// rules can't possibly match anything in unified_events, so we skip them
// at load time rather than spend LLM cost generating SQL that returns 0
// rows. Discovered empirically: 24/26 sigma build failures on 2026-05-30
// were "empty SQL" responses on these categories — the LLM correctly
// concludes no mapping exists.
var unsupportedCategories = map[string]bool{
	"proxy":     true,
	"firewall":  true,
	"database":  true,
	"webserver": true,
}

// unsupportedProducts skips rules whose product is a web/app server that
// runs on Windows but whose logs Tier 0 doesn't ingest.
var unsupportedProducts = map[string]bool{
	"apache":  true,
	"nginx":   true,
	"tomcat":  true,
	"haproxy": true,
}

// unsupportedServices catches Sigma rules whose logsource block omits
// product and category entirely (e.g. web/product/apache/*.yml sets
// only `service: apache`) — the product/category gates above miss them
// but they target the same out-of-scope logs.
var unsupportedServices = map[string]bool{
	"apache":  true,
	"nginx":   true,
	"tomcat":  true,
	"haproxy": true,
	"iis":     true, // IIS access log — Tier 0 W3C parser is still skeleton
	"sshd":    true,
	"syslog":  true,
	"auditd":  true,
}

// sysmonCategories lists Sigma logsource.category values that have NO
// Windows-builtin equivalent. Rules with these categories require Sysmon
// to produce data at all, so we skip them when --include-sysmon is off.
//
// NOTE: process_creation is intentionally NOT in this list. Sigma intends
// process_creation as abstract — backends can compile it to Sysmon EID 1
// OR Security EID 4688. Our LLM prompt (SchemaDoc) documents both field
// layouts so the generated SQL covers 4688 as well.
//
// dns_query is also NOT in this list — the Windows-builtin
// Microsoft-Windows-DNS-Client/Operational channel provides equivalent
// data (EventId 3008 etc.).
var sysmonCategories = map[string]bool{
	"network_connection":       true,
	"image_load":               true,
	"file_event":               true,
	"registry_event":           true,
	"registry_set":             true,
	"registry_add":             true,
	"registry_delete":          true,
	"create_remote_thread":     true,
	"create_stream_hash":       true,
	"pipe_created":             true,
	"process_access":           true,
	"process_tampering":        true,
	"raw_access_thread":        true,
	"wmi_event":                true,
	"driver_load":              true,
	"sysmon_status":            true,
	"sysmon_error":             true,
	"file_change":              true,
	"file_delete":              true,
	"file_rename":              true,
	"file_executable_detected": true,
}

// LoadAll walks Root and returns one RawRule per *.yml file. Malformed or
// non-Sigma files (deprecated/, regression_data/) are returned with
// Skip=true so the build summary can surface them.
func (l *SigmaLoader) LoadAll(ctx context.Context) ([]RawRule, error) {
	if l.Root == "" {
		return nil, fmt.Errorf("SigmaLoader.Root is empty")
	}
	if _, err := os.Stat(l.Root); err != nil {
		return nil, fmt.Errorf("sigma root %q: %w", l.Root, err)
	}

	var out []RawRule
	err := filepath.WalkDir(l.Root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".yml") {
			return nil
		}
		rule, ok, err := l.loadOne(path)
		if err != nil {
			// Treat as a skip rather than an abort — one malformed
			// upstream file shouldn't stop the build.
			out = append(out, RawRule{
				RuleSource: l.Source(),
				SourcePath: relPath(l.Root, path),
				Skip:       true,
				SkipReason: fmt.Sprintf("parse error: %v", err),
			})
			return nil
		}
		if !ok {
			return nil // silently skip non-rules
		}
		out = append(out, rule)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// loadOne reads a single YAML file. Returns ok=false for files that are
// not Sigma rules (e.g. test fixtures that lack an `id`).
func (l *SigmaLoader) loadOne(path string) (RawRule, bool, error) {
	return loadSigmaStyleYAML(path, l.Root, "sigma", l.IncludeSysmon, l.IncludeNonWindows)
}

// loadSigmaStyleYAML is shared between Sigma and Hayabusa loaders since
// both repos use the Sigma YAML schema. The only difference is rule_source.
func loadSigmaStyleYAML(path, root, source string, includeSysmon, includeNonWindows bool) (RawRule, bool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return RawRule{}, false, err
	}
	var doc sigmaDoc
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return RawRule{}, false, fmt.Errorf("yaml: %w", err)
	}
	if doc.ID == "" {
		return RawRule{}, false, nil // not a rule file
	}

	techniques, tactics := extractMITREFromSigmaTags(doc.Tags)
	rule := RawRule{
		RuleID:          doc.ID,
		RuleSource:      source,
		RuleSHA256:      sha256Hex(content),
		SourcePath:      relPath(root, path),
		Title:           doc.Title,
		Description:     strings.TrimSpace(doc.Description),
		Level:           strings.ToLower(strings.TrimSpace(doc.Level)),
		MITRETechniques: techniques,
		MITRETactics:    tactics,
		RawContent:      string(content),
	}

	// Skip / prefilter decisions based on logsource.
	product := strings.ToLower(strings.TrimSpace(doc.Logsource.Product))
	category := strings.ToLower(strings.TrimSpace(doc.Logsource.Category))
	service := strings.ToLower(strings.TrimSpace(doc.Logsource.Service))

	if product != "" && product != "windows" {
		if unsupportedProducts[product] {
			rule.Skip = true
			rule.SkipReason = "unsupported logsource (product=" + product + " is out of TLVB host-forensics scope)"
			return rule, true, nil
		}
		if !includeNonWindows {
			rule.Skip = true
			rule.SkipReason = "non-Windows logsource (product=" + product + ")"
			return rule, true, nil
		}
	}

	if unsupportedCategories[category] {
		rule.Skip = true
		rule.SkipReason = "unsupported logsource (category=" + category + " is out of TLVB host-forensics scope)"
		return rule, true, nil
	}

	if unsupportedServices[service] {
		rule.Skip = true
		rule.SkipReason = "unsupported logsource (service=" + service + " is out of TLVB host-forensics scope)"
		return rule, true, nil
	}

	isSysmon := service == "sysmon" || sysmonCategories[category]
	if isSysmon {
		rule.RequiresSysmon = true
		if !includeSysmon {
			rule.Skip = true
			rule.SkipReason = "Sysmon-only logsource (service=" + service + ", category=" + category + ")"
		}
	}

	// All Windows EVTX-derived rules target unified_events.artifact_id="evtx"
	// (Tier 0 routes EvtxECmd / Hayabusa / Sysmon EVTX into the same table).
	rule.PrefilterArtifacts = []string{"evtx"}

	return rule, true, nil
}

// extractMITREFromSigmaTags parses Sigma's `attack.tNNNN` / `attack.<tactic>` tags.
func extractMITREFromSigmaTags(tags []string) (techniques, tactics []string) {
	for _, t := range tags {
		s := strings.ToLower(strings.TrimSpace(t))
		if !strings.HasPrefix(s, "attack.") {
			continue
		}
		val := strings.TrimPrefix(s, "attack.")
		switch {
		case len(val) >= 5 && (val[0] == 't' || val[0] == 'T') && isDigit(val[1]):
			// Technique: "t1003" or "t1003.001"
			techniques = append(techniques, strings.ToUpper(val))
		case len(val) >= 2 && (val[0] == 'g' || val[0] == 's' || val[0] == 'm') && isDigit(val[1]):
			// Group (gNNNN), Software (sNNNN), Mitigation (mNNNN) — skip, not techniques
		default:
			// Treat as a tactic slug ("credential-access", "execution", etc.)
			tactics = append(tactics, val)
		}
	}
	return
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func relPath(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return p
	}
	return rel
}
