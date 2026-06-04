package completeness

import "testing"

func resultByKey(rs []Result, key string) (Result, bool) {
	for _, r := range rs {
		if r.Key == key {
			return r, true
		}
	}
	return Result{}, false
}

// The WINDEV validation image: Security/System/Application EVTX only, no
// PowerShell/DNS/Sysmon channels; usn/mft/amcache/registry/etc. all present.
func TestEvaluateWindevCollection(t *testing.T) {
	arts := map[string]bool{
		"evtx": true, "usn_journal": true, "mft": true, "amcache": true,
		"registry": true, "prefetch": true, "shellbags": true, "lnk": true,
		"browser_history": true,
	}
	channels := []string{"Security", "System", "Application"}
	rs := Evaluate(arts, channels)

	want := map[string]bool{
		"evtx:security":               true,
		"evtx:system":                 true,
		"evtx:powershell_operational": false, // the S4 gap
		"evtx:dns_client":             false, // the S4 gap
		"evtx:sysmon":                 false,
		"usn_journal":                 true,
		"mft":                         true,
		"amcache":                     true,
		"shellbags":                   true,
	}
	for key, exp := range want {
		r, ok := resultByKey(rs, key)
		if !ok {
			t.Fatalf("catalog missing key %q", key)
		}
		if r.Present != exp {
			t.Errorf("%s: present=%v, want %v", key, r.Present, exp)
		}
	}

	// The missing set must include the C2-relevant channels and nothing present.
	miss := Missing(rs)
	missKeys := map[string]bool{}
	for _, m := range miss {
		missKeys[m.Key] = true
		if m.Present {
			t.Errorf("Missing() returned a present input: %s", m.Key)
		}
	}
	for _, k := range []string{"evtx:powershell_operational", "evtx:dns_client", "evtx:sysmon"} {
		if !missKeys[k] {
			t.Errorf("expected %s in missing set", k)
		}
	}
}

func TestEvaluateChannelMatchingIsCaseAndFormatTolerant(t *testing.T) {
	cases := []struct {
		name    string
		channel string
		key     string
	}{
		{"powershell slash form", "Microsoft-Windows-PowerShell/Operational", "evtx:powershell_operational"},
		{"powershell pct4 form", "Microsoft-Windows-PowerShell%4Operational", "evtx:powershell_operational"},
		{"dns client dash", "Microsoft-Windows-DNS-Client/Operational", "evtx:dns_client"},
		{"sysmon lowercase", "microsoft-windows-sysmon/operational", "evtx:sysmon"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rs := Evaluate(map[string]bool{"evtx": true}, []string{tc.channel})
			r, _ := resultByKey(rs, tc.key)
			if !r.Present {
				t.Errorf("channel %q should mark %s present", tc.channel, tc.key)
			}
		})
	}
}

func TestEvaluateNoEvtxMarksAllChannelsMissing(t *testing.T) {
	rs := Evaluate(map[string]bool{"mft": true}, nil)
	for _, r := range rs {
		if r.Kind == "evtx_channel" && r.Present {
			t.Errorf("%s should be absent when no channels collected", r.Key)
		}
	}
	if r, _ := resultByKey(rs, "mft"); !r.Present {
		t.Errorf("mft should be present")
	}
}

func TestCatalogShapeIsSane(t *testing.T) {
	seen := map[string]bool{}
	for _, in := range Catalog() {
		if in.Key == "" || in.Label == "" || in.Capability == "" {
			t.Errorf("incomplete catalog entry: %+v", in)
		}
		if in.Kind != "artifact" && in.Kind != "evtx_channel" {
			t.Errorf("%s: bad kind %q", in.Key, in.Kind)
		}
		if in.Kind == "evtx_channel" && len(in.Match) == 0 {
			t.Errorf("%s: evtx_channel needs Match tokens", in.Key)
		}
		switch in.Importance {
		case "critical", "high", "medium":
		default:
			t.Errorf("%s: bad importance %q", in.Key, in.Importance)
		}
		if seen[in.Key] {
			t.Errorf("duplicate catalog key %q", in.Key)
		}
		seen[in.Key] = true
	}
}
