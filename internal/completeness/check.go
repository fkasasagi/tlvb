// Package completeness reports which detection-relevant collection inputs are
// present or absent in a parsed case, so an examiner can tell a genuine
// detection MISS apart from a DATA GAP.
//
// Motivation: on the WINDEV validation image the C2 step was undetectable not
// because the rules failed but because Microsoft-Windows-DNS-Client/Operational
// and Microsoft-Windows-PowerShell/Operational were never collected. Silent
// absence reads as "covered, found nothing" when the truth is "couldn't look".
// This makes the gap explicit.
package completeness

import "strings"

// Input is one detection-relevant collection input — a Tier 0 artefact or an
// EVTX channel — and the detection capability it unlocks.
type Input struct {
	Key        string   `json:"key"`
	Kind       string   `json:"kind"`       // "artifact" | "evtx_channel"
	Label      string   `json:"label"`      // human-readable name
	Capability string   `json:"capability"` // what detection becomes possible
	Importance string   `json:"importance"` // "critical" | "high" | "medium"
	Match      []string `json:"-"`          // evtx_channel: case-insensitive substrings (any = present)
}

// Result pairs a catalogued input with whether it was found in the case.
type Result struct {
	Input
	Present bool `json:"present"`
}

// catalog is the fixed set of inputs TLVB's detections care about. It is
// deliberately focused on what current Tier 1A / custom rules consume plus the
// channels whose absence silently disables whole classes of detection.
var catalog = []Input{
	// --- EVTX channels ---
	{Key: "evtx:security", Kind: "evtx_channel", Label: "Security.evtx",
		Match:      []string{"security"},
		Capability: "process creation (4688), logon (4624/4625), audit log clear (1102) — most signature detections",
		Importance: "critical"},
	{Key: "evtx:system", Kind: "evtx_channel", Label: "System.evtx",
		Match:      []string{"system"},
		Capability: "service install (7045), driver/system events",
		Importance: "high"},
	{Key: "evtx:powershell_operational", Kind: "evtx_channel",
		Label:      "Microsoft-Windows-PowerShell/Operational",
		Match:      []string{"powershell/operational", "powershell%4operational"},
		Capability: "PowerShell ScriptBlock (4104) — decoded/obfuscated payloads, in-memory C2",
		Importance: "high"},
	{Key: "evtx:dns_client", Kind: "evtx_channel",
		Label:      "Microsoft-Windows-DNS-Client/Operational",
		Match:      []string{"dns-client", "dns client"},
		Capability: "DNS query (3008) / NXDOMAIN beaconing & DGA — C2 detection",
		Importance: "high"},
	{Key: "evtx:sysmon", Kind: "evtx_channel",
		Label:      "Microsoft-Windows-Sysmon/Operational",
		Match:      []string{"sysmon"},
		Capability: "Sysmon process/network/image-load telemetry (richer than 4688)",
		Importance: "medium"},
	{Key: "evtx:taskscheduler", Kind: "evtx_channel",
		Label:      "Microsoft-Windows-TaskScheduler/Operational",
		Match:      []string{"taskscheduler"},
		Capability: "scheduled-task registration/run detail (persistence)",
		Importance: "medium"},
	// --- Tier 0 artefacts ---
	{Key: "usn_journal", Kind: "artifact", Label: "$UsnJrnl ($J)",
		Capability: "file rename/delete — ransomware (.locked), tool self-deletion",
		Importance: "high"},
	{Key: "mft", Kind: "artifact", Label: "$MFT",
		Capability: "full filesystem timeline, file existence & timestamps",
		Importance: "high"},
	{Key: "amcache", Kind: "artifact", Label: "Amcache.hve",
		Capability: "program execution/staging evidence (SHA1, full path)",
		Importance: "high"},
	{Key: "registry", Kind: "artifact", Label: "Registry hives",
		Capability: "persistence (Run keys, services), configuration",
		Importance: "high"},
	{Key: "prefetch", Kind: "artifact", Label: "Prefetch",
		Capability: "program execution (run count, first/last run)",
		Importance: "medium"},
	{Key: "shellbags", Kind: "artifact", Label: "Shellbags",
		Capability: "folder/UNC navigation — admin-share access (lateral movement)",
		Importance: "medium"},
	{Key: "lnk", Kind: "artifact", Label: "LNK / jumplists",
		Capability: "opened-file/shortcut metadata (initial access)",
		Importance: "medium"},
	{Key: "browser_history", Kind: "artifact", Label: "Browser history",
		Capability: "downloads / browsing (delivery)",
		Importance: "medium"},
}

// Catalog returns a copy-safe view of the detection-input catalog.
func Catalog() []Input { return catalog }

// Evaluate marks each catalogued input present or absent. presentArtifacts is
// the set of artifact_ids found in unified_events; presentChannels are the
// distinct EVTX Channel values (matched case-insensitively, substring).
func Evaluate(presentArtifacts map[string]bool, presentChannels []string) []Result {
	lc := make([]string, 0, len(presentChannels))
	for _, c := range presentChannels {
		if c != "" {
			lc = append(lc, strings.ToLower(c))
		}
	}
	out := make([]Result, 0, len(catalog))
	for _, in := range catalog {
		present := false
		switch in.Kind {
		case "artifact":
			present = presentArtifacts[in.Key]
		case "evtx_channel":
			present = anyChannelMatches(lc, in.Match)
		}
		out = append(out, Result{Input: in, Present: present})
	}
	return out
}

func anyChannelMatches(lowerChannels, tokens []string) bool {
	for _, ch := range lowerChannels {
		for _, tok := range tokens {
			if strings.Contains(ch, strings.ToLower(tok)) {
				return true
			}
		}
	}
	return false
}

// Missing returns only the absent results, preserving catalog order.
func Missing(results []Result) []Result {
	out := make([]Result, 0)
	for _, r := range results {
		if !r.Present {
			out = append(out, r)
		}
	}
	return out
}
