package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// The Web UI was migrated off the legacy synthesizer model: loadSynthesis +
// /api/cases/{id}/synthesis now parse the tier2.CaseSynthesis shape that the
// CLI `tlvb run` writes. This locks that in so a future schema drift surfaces
// as a failing test rather than an empty Synthesis view.
func TestGetSynthesisServesTier2Shape(t *testing.T) {
	root := t.TempDir()
	caseID := "CASE-X"
	caseDir := filepath.Join(root, "cases", caseID)
	if err := os.MkdirAll(caseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Minimal tier2-format synthesis.json (the shape `tlvb run` emits).
	synth := `{
	  "case_id": "CASE-X",
	  "generated_at": "2026-06-03T00:00:00Z",
	  "total_findings": 3,
	  "cluster_count": 1,
	  "overall_story": "procdump dumped lsass then renamed to mimi.exe",
	  "clusters": [
	    {"id": 1, "attack_phase": "credential-access", "narrative": "n",
	     "finding_refs": [{"source":"sigma","rule_id":"r1","title":"LSASS dump","severity":"critical"}],
	     "mitre_techniques": ["T1003.001"]}
	  ],
	  "mitre_mapping": [
	    {"tactic":"credential-access","technique":"T1003.001","finding_count":3,"cluster_ids":[1]}
	  ]
	}`
	if err := os.WriteFile(filepath.Join(caseDir, "synthesis.json"), []byte(synth), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Server{cfg: Config{OutputsRoot: filepath.Join(root, "cases")}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/cases/{id}/synthesis", s.handleGetSynthesis)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/cases/"+caseID+"/synthesis", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	var got struct {
		CaseID       string `json:"case_id"`
		OverallStory string `json:"overall_story"`
		ClusterCount int    `json:"cluster_count"`
		Clusters     []struct {
			ID              int      `json:"id"`
			MITRETechniques []string `json:"mitre_techniques"`
		} `json:"clusters"`
		MITREMapping []struct {
			Technique string `json:"technique"`
		} `json:"mitre_mapping"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal tier2 synthesis response: %v", err)
	}
	if got.CaseID != caseID || got.OverallStory == "" {
		t.Errorf("missing tier2 fields: case_id=%q overall_story=%q", got.CaseID, got.OverallStory)
	}
	if len(got.Clusters) != 1 || len(got.Clusters[0].MITRETechniques) != 1 {
		t.Errorf("clusters not served in tier2 shape: %+v", got.Clusters)
	}
	if len(got.MITREMapping) != 1 || got.MITREMapping[0].Technique != "T1003.001" {
		t.Errorf("mitre_mapping not served: %+v", got.MITREMapping)
	}
}
