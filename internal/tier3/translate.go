package tier3

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unicode"

	"github.com/tlvb/tlvb/internal/llm"
	"github.com/tlvb/tlvb/internal/tier2"
)

// translate.go is the report-time narrative translation pass. The static UI
// labels already follow Config.Language via the ja/en dictionaries, but the
// substance of the report — the executive summary, per-cluster narratives, open
// questions, timeline notes and active-search answers — is LLM prose baked into
// synthesis.json at Tier 2 time, in whatever language Tier 2 ran in. Rendering a
// report in a DIFFERENT language than the synthesis used therefore produced a
// mixed-language document (English labels over Japanese prose, or vice versa).
//
// When Config.TranslateNarratives is set and the report language differs from
// the synthesis language, this pass collects every verbatim prose string, asks
// the (already Tier-3-available) LLM to translate them as one batch, and writes
// the results back into the in-memory CaseSynthesis the renderers consume — so
// HTML, CSV and report.json all read in the requested language. The canonical
// Tier 2 synthesis.json on disk is left untouched (it stays the source-language
// artifact; re-rendering in the original language re-reads it verbatim).
//
// Best-effort by construction: a missing transport, a failed call, or a
// length-mismatched response leaves the narratives as-is and logs a warning. It
// never fails the report. Tier 1A stays LLM-free — this is a Tier 3 concern.

const translateMaxTokens = 32000

// maybeTranslateNarratives translates cs's LLM prose into cfg.Language in place
// when cfg.TranslateNarratives is set and the synthesis was written in a
// different language. No-op (and no LLM call) when the languages already match,
// the opt-in is off, or there is nothing to translate.
func maybeTranslateNarratives(cfg Config, cs *tier2.CaseSynthesis) {
	if !cfg.TranslateNarratives {
		return
	}
	target := normalizeReportLang(cfg.Language)
	source := synthesisLang(cs)
	if source == target {
		return
	}
	ptrs := collectTranslatable(cs)
	if len(ptrs) == 0 {
		return
	}

	t := llm.Resolve()
	src := make([]string, len(ptrs))
	for i, p := range ptrs {
		src[i] = *p
	}

	ctx, cancel := context.WithTimeout(context.Background(), consistencyLLMTimeout)
	defer cancel()
	out, err := translateSegments(ctx, cfg, t, src, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tier3: narrative translation %s→%s skipped (%s transport): %v\n",
			source, target, t.Label(), err)
		return
	}
	if len(out) != len(ptrs) {
		fmt.Fprintf(os.Stderr, "tier3: narrative translation skipped — model returned %d of %d segments\n",
			len(out), len(ptrs))
		return
	}
	for i, p := range ptrs {
		if s := strings.TrimSpace(out[i]); s != "" {
			*p = out[i]
		}
	}
	// Record the language the rendered report is actually in so report.json is
	// self-consistent with the html/csv siblings.
	cs.Language = target
}

// normalizeReportLang collapses the report language config to "en" | "ja".
func normalizeReportLang(lang string) string {
	if strings.EqualFold(strings.TrimSpace(lang), "en") {
		return "en"
	}
	return "ja"
}

// synthesisLang reports the language the narratives are written in. It trusts
// the explicit cs.Language stamp when present (synthesis written after that
// field was added); otherwise it sniffs the prose for Japanese characters so
// older synthesis.json still translates correctly.
func synthesisLang(cs *tier2.CaseSynthesis) string {
	if l := strings.TrimSpace(cs.Language); l != "" {
		return normalizeReportLang(l)
	}
	probe := cs.ExecBrief + "\n" + cs.TechSummary + "\n" + cs.OverallStory
	for _, c := range cs.Clusters {
		probe += "\n" + c.Narrative
		if len(probe) > 4000 {
			break
		}
	}
	if containsJapanese(probe) {
		return "ja"
	}
	return "en"
}

// containsJapanese reports whether s holds any Hiragana, Katakana or Han
// character — a reliable signal for Japanese prose vs the English alternative.
func containsJapanese(s string) bool {
	for _, r := range s {
		if unicode.In(r, unicode.Hiragana, unicode.Katakana, unicode.Han) {
			return true
		}
	}
	return false
}

// collectTranslatable returns pointers to every verbatim LLM-prose string in cs,
// in a stable order, skipping empties. Writing through the pointers updates cs in
// place. Excluded by design: MITRE technique IDs, attack-phase keys (label-mapped
// by the dict), detection-rule titles/descriptions (kept as the upstream English
// identifiers for cross-reference), SQL, timestamps and event IDs.
func collectTranslatable(cs *tier2.CaseSynthesis) []*string {
	var ps []*string
	add := func(p *string) {
		if strings.TrimSpace(*p) != "" {
			ps = append(ps, p)
		}
	}
	add(&cs.OverallStory)
	add(&cs.ExecBrief)
	add(&cs.TechSummary)
	for i := range cs.TimelineNotes {
		add(&cs.TimelineNotes[i])
	}
	for i := range cs.MITREDemotionNotes {
		add(&cs.MITREDemotionNotes[i])
	}
	for i := range cs.UngroundedMentions {
		add(&cs.UngroundedMentions[i])
	}
	for i := range cs.OpenQuestions {
		add(&cs.OpenQuestions[i])
	}
	for i := range cs.OpenQuestionsSynth.Critical {
		add(&cs.OpenQuestionsSynth.Critical[i])
	}
	for i := range cs.OpenQuestionsSynth.NeedsCollection {
		add(&cs.OpenQuestionsSynth.NeedsCollection[i])
	}
	for i := range cs.OpenQuestionsSynth.Supplementary {
		add(&cs.OpenQuestionsSynth.Supplementary[i])
	}
	for ci := range cs.Clusters {
		add(&cs.Clusters[ci].Narrative)
		for i := range cs.Clusters[ci].OpenQuestions {
			add(&cs.Clusters[ci].OpenQuestions[i])
		}
		for i := range cs.Clusters[ci].ActiveSearch {
			add(&cs.Clusters[ci].ActiveSearch[i].Question)
			add(&cs.Clusters[ci].ActiveSearch[i].Answer)
		}
	}
	return ps
}

// translateSegments asks the LLM to translate every string in src into the
// target language as one batch, preserving order and count. The segment indices
// are echoed so a misaligned response is detectable by the caller (it checks the
// returned length) rather than silently corrupting the report.
func translateSegments(ctx context.Context, cfg Config, t *llm.Transport, src []string, target string) ([]string, error) {
	sys := translateSystemPrompt(target)
	bundle, err := json.Marshal(struct {
		Segments []string `json:"segments"`
	}{Segments: src})
	if err != nil {
		return nil, fmt.Errorf("marshal segments: %w", err)
	}
	out, err := callLLMOneShot(ctx, cfg, t, sys, string(bundle), translateMaxTokens, false)
	if err != nil {
		return nil, err
	}
	js := extractJSONObject(out.text)
	if js == "" {
		return nil, fmt.Errorf("no JSON object in model output")
	}
	var parsed struct {
		Segments []string `json:"segments"`
	}
	if err := json.Unmarshal([]byte(js), &parsed); err != nil {
		return nil, fmt.Errorf("decode segments: %w", err)
	}
	return parsed.Segments, nil
}

// translateSystemPrompt instructs the translator. The model reasons in English
// but writes the segment values in the target language.
func translateSystemPrompt(target string) string {
	name := "Japanese (日本語)"
	if target == "en" {
		name = "English"
	}
	return `You are a professional translator for DFIR (digital forensic incident response) reports.

You are given a JSON object {"segments":[...]} — an ordered array of natural-language strings taken from a forensic report (executive summary, attack narratives, open questions, timeline notes, investigative answers).

Translate every string into ` + name + `.

RULES:
- Return STRICT JSON only: {"segments":[...]} with EXACTLY the same number of elements, in the SAME order. Element i of your output is the translation of element i of the input.
- Do NOT add, remove, merge, split or reorder elements. Do NOT add commentary, keys or markdown fences.
- Translate only the surrounding prose. Keep VERBATIM: file paths, registry keys, command lines, process/host/account names, IP addresses, hashes, event IDs, MITRE technique IDs (e.g. T1059.001), detection-rule names, SQL, timestamps and numbers.
- Preserve the meaning, tone and any hedging precisely — do not strengthen "possible/likely" into certainty.
- If a string is already in ` + name + `, return it unchanged.`
}
