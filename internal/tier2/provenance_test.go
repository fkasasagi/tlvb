package tier2

import "testing"

func TestProvenanceForSource(t *testing.T) {
	cases := []struct{ src, prov, conf string }{
		{"sigma", "signature", "confirmed"},
		{"hayabusa", "signature", "confirmed"},
		{"custom", "signature", "confirmed"},
		{"stix", "signature", "confirmed"},
		{"anomaly_hunter", "anomaly-llm", "inferred"},
		{"tier1b", "anomaly-llm", "inferred"},
		{"", "signature", "confirmed"}, // unknown defaults to the signature/confirmed branch
	}
	for _, c := range cases {
		p, conf := ProvenanceForSource(c.src)
		if p != c.prov || conf != c.conf {
			t.Errorf("ProvenanceForSource(%q) = (%q,%q), want (%q,%q)", c.src, p, conf, c.prov, c.conf)
		}
	}
}
