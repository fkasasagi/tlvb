package agents

import (
	"strings"
)

// mergeTacticReports (Wave 22 sliding-window) merges N per-window
// TacticReports into a single canonical report. Used by Runner.Run when
// SlidingWindow=true and the match set exceeds MaxEvents.
//
// Merge rules (kept simple — the LLM's downstream consumer is the
// Synthesizer which already dedupes findings across tactic boundaries):
//
//   findings           — dedup by FindingID (later windows overwrite earlier,
//                        which is fine because per-tactic LLM rarely
//                        invents the same finding_id twice; if it does,
//                        the later window saw more context).
//   negative_findings  — dedup by TechniqueID (a tactic that's "absent"
//                        in window 1 and absent in window 2 is still
//                        absent; record only once).
//   open_questions    — concatenated, then deduplicated by Question text
//                        (case-insensitive trim).
//   summary           — joined with " | " separators (only non-empty).
//   audit             — counters summed (Iterations, TokensInput,
//                        TokensOutput, CacheHitTok, DurationSec); max'd
//                        (PromptSizeChars); first non-zero kept
//                        (DurationAPIMS); from last report (ModelID,
//                        SkillFile, SkillSHA256, StopReason).
//                        InputEvents = sum across windows (overlapping
//                        rows counted only once via dedup if you trust
//                        the audit_id check, but conservatively summed
//                        here; the calibration tool handles per-window
//                        analysis separately).
//   ArtifactScope     — first non-empty (all windows share it).
//   EvidenceIDs       — from first report (all windows share).
//   Status            — "failed" if any failed, "partial" if any partial,
//                        else "completed".
//
// Returns nil if the input slice is empty.
func mergeTacticReports(reports []*TacticReport) *TacticReport {
	if len(reports) == 0 {
		return nil
	}
	if len(reports) == 1 {
		// Avoid the merge overhead for the trivial case.
		return reports[0]
	}

	first := reports[0]
	merged := &TacticReport{
		TacticID:      first.TacticID,
		TacticName:    first.TacticName,
		CaseID:        first.CaseID,
		EvidenceID:    first.EvidenceID,
		EvidenceIDs:   first.EvidenceIDs,
		ArtifactScope: first.ArtifactScope,
		StartedAt:     first.StartedAt,
		Audit: Audit{
			SkillFile:   first.Audit.SkillFile,
			SkillSHA256: first.Audit.SkillSHA256,
			ModelID:     first.Audit.ModelID,
			MaxEvents:   first.Audit.MaxEvents,
		},
	}

	findingsByID := map[string]Finding{}
	negsByTech := map[string]NegativeFinding{}
	var openQs []OpenQuestion
	seenQs := map[string]bool{}
	var summaries []string
	statusRank := map[string]int{"completed": 0, "partial": 1, "failed": 2}
	worstStatus := 0
	var anyValidationErrs []string
	allValid := true

	for _, r := range reports {
		if r == nil {
			continue
		}
		for _, f := range r.Findings {
			findingsByID[f.FindingID] = f
		}
		for _, n := range r.NegativeFindings {
			negsByTech[n.TechniqueID] = n
		}
		for _, q := range r.OpenQuestions {
			key := strings.ToLower(strings.TrimSpace(q.Question))
			if seenQs[key] {
				continue
			}
			seenQs[key] = true
			openQs = append(openQs, q)
		}
		if s := strings.TrimSpace(r.Summary); s != "" {
			summaries = append(summaries, s)
		}
		if rank, ok := statusRank[r.Status]; ok && rank > worstStatus {
			worstStatus = rank
		}
		merged.Audit.Iterations += r.Audit.Iterations
		merged.Audit.InputEvents += r.Audit.InputEvents
		merged.Audit.TokensInput += r.Audit.TokensInput
		merged.Audit.TokensOutput += r.Audit.TokensOutput
		merged.Audit.CacheHitTok += r.Audit.CacheHitTok
		merged.Audit.DurationSec += r.Audit.DurationSec
		if r.Audit.PromptSizeChars > merged.Audit.PromptSizeChars {
			merged.Audit.PromptSizeChars = r.Audit.PromptSizeChars
		}
		if merged.Audit.DurationAPIMS == 0 && r.Audit.DurationAPIMS > 0 {
			merged.Audit.DurationAPIMS = r.Audit.DurationAPIMS
		}
		if r.Audit.StopReason != "" {
			merged.Audit.StopReason = r.Audit.StopReason
		}
		if r.Audit.ValidationErr != "" {
			anyValidationErrs = append(anyValidationErrs, r.Audit.ValidationErr)
		}
		if !r.Audit.ValidationOK {
			allValid = false
		}
		if !r.FinishedAt.IsZero() && r.FinishedAt.After(merged.FinishedAt) {
			merged.FinishedAt = r.FinishedAt
		}
	}

	// Flatten findings / negatives map → slice with stable order: findings
	// keep their FindingID lex order so two runs of the same case produce
	// the same merged report (relevant for diff-based regression tests).
	for _, f := range findingsByID {
		merged.Findings = append(merged.Findings, f)
	}
	sortFindings(merged.Findings)
	for _, n := range negsByTech {
		merged.NegativeFindings = append(merged.NegativeFindings, n)
	}
	sortNegatives(merged.NegativeFindings)
	merged.OpenQuestions = openQs

	merged.Summary = strings.Join(summaries, " | ")
	merged.Status = []string{"completed", "partial", "failed"}[worstStatus]
	merged.Audit.ValidationOK = allValid
	if len(anyValidationErrs) > 0 {
		merged.Audit.ValidationErr = strings.Join(anyValidationErrs, "; ")
	}
	return merged
}

// sortFindings keeps merged output stable across runs (lex by FindingID).
func sortFindings(fs []Finding) {
	for i := 0; i < len(fs); i++ {
		for j := i + 1; j < len(fs); j++ {
			if fs[j].FindingID < fs[i].FindingID {
				fs[i], fs[j] = fs[j], fs[i]
			}
		}
	}
}

// sortNegatives stable by TechniqueID.
func sortNegatives(ns []NegativeFinding) {
	for i := 0; i < len(ns); i++ {
		for j := i + 1; j < len(ns); j++ {
			if ns[j].TechniqueID < ns[i].TechniqueID {
				ns[i], ns[j] = ns[j], ns[i]
			}
		}
	}
}
