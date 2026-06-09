package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/tlvb/tlvb/internal/tier1a"
	"github.com/tlvb/tlvb/internal/tier1b"
	"github.com/tlvb/tlvb/internal/tier2"
)

// auditExplain carries the human-readable "what / why" context attached to one
// actions.jsonl record so the Web UI Audit tab can show what the agent did and
// why it decided to, instead of opaque rule UUIDs, cluster numbers and token
// counts. The rich data already exists in the case's findings/**/*.json and
// synthesis.json — auditEnricher joins it back onto each thin audit row at read
// time. All fields are optional (omitempty) so a record only carries the detail
// relevant to its actor/kind.
type auditExplain struct {
	// Tier 1A signature-rule context (joined by rule_source + rule_id).
	RuleTitle       string   `json:"rule_title,omitempty"`
	RuleDescription string   `json:"rule_description,omitempty"`
	MITRE           []string `json:"mitre,omitempty"`
	SourcePath      string   `json:"source_path,omitempty"`
	SQL             string   `json:"sql,omitempty"` // the Tier 1A SQL is not on the row itself

	// Tier 2 active-search context (joined by cluster_id + the logged SQL).
	Question string `json:"question,omitempty"`
	Answer   string `json:"answer,omitempty"`

	// Tier 2 cluster / overall narrative context (joined by cluster_id).
	AttackPhase   string   `json:"attack_phase,omitempty"`
	Narrative     string   `json:"narrative,omitempty"`
	OpenQuestions []string `json:"open_questions,omitempty"`

	// Tier 1B anomaly context (joined by skill name).
	EventsScanned int                   `json:"events_scanned,omitempty"`
	PriorFindings int                   `json:"prior_findings,omitempty"`
	Findings      []auditExplainFinding `json:"findings,omitempty"`
}

// auditExplainFinding is one Tier 1B anomaly the LLM produced, summarised for
// the audit row ("what it found / why it's suspicious").
type auditExplainFinding struct {
	Summary     string `json:"summary,omitempty"`
	Description string `json:"description,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Technique   string `json:"technique,omitempty"`
}

// auditEnricher resolves explain context for audit records of one case. Reads
// are lazy and cached: synthesis.json is parsed at most once, and each finding
// file at most once, so enriching a whole actions.jsonl touches each backing
// file a single time regardless of how many rows reference it.
type auditEnricher struct {
	caseDir string

	synthLoaded bool
	clusters    map[int]*tier2.SynthCluster        // cluster id → cluster
	activeByID  map[int][]tier2.ActiveSearchResult // cluster id → active searches
	overall     string                             // synthesis.overall_story

	ruleCache  map[string]*tier1a.Finding       // "source\x00id" → finding (nil = absent)
	skillCache map[string]*tier1b.AnomalyReport // skill name → report (nil = absent)
}

func newAuditEnricher(outputsRoot, caseID string) *auditEnricher {
	return &auditEnricher{
		caseDir:    filepath.Join(outputsRoot, caseID),
		ruleCache:  map[string]*tier1a.Finding{},
		skillCache: map[string]*tier1b.AnomalyReport{},
	}
}

// explain returns the human context for one audit record, or nil if the
// record's actor/kind has no enrichment (e.g. Tier 0 parse rows, or an entry
// whose backing file is missing).
func (e *auditEnricher) explain(rec map[string]any) *auditExplain {
	actor, _ := rec["actor"].(string)
	kind, _ := rec["kind"].(string)
	detail, _ := rec["detail"].(string)
	switch {
	case actor == "tier1a" && kind == "rule_sql":
		return e.explainRule(rec)
	case actor == "tier1b" && kind == "llm_call":
		return e.explainAnomaly(detail)
	case actor == "tier2" && kind == "active_sql":
		return e.explainActiveSQL(rec)
	case actor == "tier2" && kind == "llm_call":
		return e.explainTier2LLM(rec, detail)
	}
	return nil
}

// explainRule joins a Tier 1A rule_sql row to its emitted finding so the row
// shows the rule's intent (title/description/MITRE) and the SQL it ran.
func (e *auditEnricher) explainRule(rec map[string]any) *auditExplain {
	id, _ := rec["rule_id"].(string)
	src, _ := rec["rule_source"].(string)
	if id == "" || src == "" {
		return nil
	}
	f := e.loadRuleFinding(src, id)
	if f == nil { // no finding file (e.g. a failed rule_sql) — nothing to explain
		return nil
	}
	ex := &auditExplain{
		RuleTitle:       f.RuleMeta.Title,
		RuleDescription: f.RuleMeta.Description,
		SourcePath:      f.RuleMeta.SourcePath,
		SQL:             f.SQL,
	}
	ex.MITRE = append(ex.MITRE, f.RuleMeta.MITRETactics...)
	ex.MITRE = append(ex.MITRE, f.RuleMeta.MITRETechniques...)
	if len(ex.MITRE) == 0 {
		ex.MITRE = nil
	}
	return ex
}

// explainAnomaly joins a Tier 1B llm_call row to the skill's report so the row
// shows the anomalies the LLM flagged and the scan scope it reasoned over.
func (e *auditEnricher) explainAnomaly(skill string) *auditExplain {
	if skill == "" {
		return nil
	}
	r := e.loadSkill(skill)
	if r == nil {
		return nil
	}
	ex := &auditExplain{
		EventsScanned: r.EventsScanned,
		PriorFindings: r.PriorFindings,
	}
	for _, f := range r.Findings {
		ex.Findings = append(ex.Findings, auditExplainFinding{
			Summary:     f.Summary,
			Description: f.Description,
			Severity:    f.Severity,
			Technique:   f.TechniqueID,
		})
	}
	if ex.EventsScanned == 0 && ex.PriorFindings == 0 && len(ex.Findings) == 0 {
		return nil
	}
	return ex
}

// explainActiveSQL joins a Tier 2 active_sql row to the open question that
// motivated the query and the LLM's interpretation of the result. Matching is
// by cluster_id then exact (whitespace-normalised) SQL — robust because the
// audit logs every attempt and synthesis keeps each attempt's SQL.
func (e *auditEnricher) explainActiveSQL(rec map[string]any) *auditExplain {
	e.loadSynth()
	cid := intFromRec(rec, "cluster_id")
	cmd, _ := rec["command"].(string)
	want := normalizeSQL(cmd)
	for _, as := range e.activeByID[cid] {
		if normalizeSQL(as.SQL) == want {
			return &auditExplain{Question: as.Question, Answer: as.Answer}
		}
		for _, at := range as.Attempts {
			if normalizeSQL(at.SQL) == want {
				return &auditExplain{Question: as.Question, Answer: as.Answer}
			}
		}
	}
	// SQL didn't line up (e.g. truncated) but the cluster did — still surface
	// the questions active search was exploring so the row isn't opaque.
	if c := e.clusters[cid]; c != nil && len(c.OpenQuestions) > 0 {
		return &auditExplain{OpenQuestions: c.OpenQuestions}
	}
	return nil
}

// explainTier2LLM joins a Tier 2 llm_call row to the narrative / questions its
// cluster produced. detail names the sub-kind (cluster_analysis,
// overall_synthesis, active_search_generate/interpret).
func (e *auditEnricher) explainTier2LLM(rec map[string]any, detail string) *auditExplain {
	e.loadSynth()
	cid := intFromRec(rec, "cluster_id")
	switch detail {
	case "overall_synthesis":
		if e.overall == "" {
			return nil
		}
		return &auditExplain{Narrative: e.overall}
	case "cluster_analysis":
		c := e.clusters[cid]
		if c == nil {
			return nil
		}
		return &auditExplain{
			AttackPhase:   c.AttackPhase,
			Narrative:     c.Narrative,
			OpenQuestions: c.OpenQuestions,
		}
	case "active_search_generate", "active_search_interpret":
		c := e.clusters[cid]
		if c == nil {
			return nil
		}
		return &auditExplain{
			AttackPhase:   c.AttackPhase,
			OpenQuestions: c.OpenQuestions,
		}
	}
	return nil
}

func (e *auditEnricher) loadSynth() {
	if e.synthLoaded {
		return
	}
	e.synthLoaded = true
	e.clusters = map[int]*tier2.SynthCluster{}
	e.activeByID = map[int][]tier2.ActiveSearchResult{}
	b, err := os.ReadFile(filepath.Join(e.caseDir, "synthesis.json"))
	if err != nil {
		return
	}
	var syn tier2.CaseSynthesis
	if json.Unmarshal(b, &syn) != nil {
		return
	}
	e.overall = syn.OverallStory
	for i := range syn.Clusters {
		c := &syn.Clusters[i]
		e.clusters[c.ID] = c
		if len(c.ActiveSearch) > 0 {
			e.activeByID[c.ID] = c.ActiveSearch
		}
	}
}

func (e *auditEnricher) loadRuleFinding(source, id string) *tier1a.Finding {
	key := source + "\x00" + id
	if f, ok := e.ruleCache[key]; ok {
		return f
	}
	var f *tier1a.Finding
	p := filepath.Join(e.caseDir, "findings", "by-rule", source, sanitizeFindingID(id)+".json")
	if b, err := os.ReadFile(p); err == nil {
		var ff tier1a.Finding
		if json.Unmarshal(b, &ff) == nil {
			f = &ff
		}
	}
	e.ruleCache[key] = f
	return f
}

func (e *auditEnricher) loadSkill(skill string) *tier1b.AnomalyReport {
	if r, ok := e.skillCache[skill]; ok {
		return r
	}
	var r *tier1b.AnomalyReport
	p := filepath.Join(e.caseDir, "findings", "by-skill", sanitizeFindingID(skill)+".json")
	if b, err := os.ReadFile(p); err == nil {
		var rr tier1b.AnomalyReport
		if json.Unmarshal(b, &rr) == nil {
			r = &rr
		}
	}
	e.skillCache[skill] = r
	return r
}

// sanitizeFindingID mirrors tier1a.findingPath's filename sanitisation so we
// read back the same path the runtime wrote (rule ids may contain / \ :).
func sanitizeFindingID(id string) string {
	return strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(id)
}

func intFromRec(rec map[string]any, key string) int {
	switch v := rec[key].(type) {
	case float64: // JSON numbers decode to float64
		return int(v)
	case int:
		return v
	}
	return 0
}

// normalizeSQL collapses all runs of whitespace to single spaces and trims, so
// SQL logged in actions.jsonl matches SQL stored in synthesis.json regardless
// of incidental formatting differences.
func normalizeSQL(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
