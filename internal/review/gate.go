// Package review implements Review Gates 0/1/2 from DESIGN.md §6.5 / §9.
//
// This is the CLI version — Web UI is future work. The CLI fulfils the
// minimum human-in-the-loop contract: every Tactic Agent finding can be
// shown to an Examiner one at a time and explicitly approved / rejected.
// Approval state is stored on the Finding itself (Approved bool /
// Rejected bool / RejectReason / ReviewedAt / ReviewedBy) so that
// downstream consumers (Synthesizer, Reporter) can filter without a
// separate ledger file.
//
// This first cut implements Gate 1 (per-finding review). Gate 0
// (parser-result review) and Gate 2 (timeline review) reuse the same
// prompt loop with different fixture types — to be added.
package review

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tlvb/tlvb/internal/agents"
)

// Config controls one review session.
type Config struct {
	CaseID      string
	FindingsDir string
	Examiner    string // sets Finding.ReviewedBy
	In          io.Reader
	Out         io.Writer
}

// Result summarises the session for the caller.
type Result struct {
	Approved  int
	Rejected  int
	Skipped   int       // already-reviewed findings carried forward
	Quit      bool      // true if Examiner pressed [q]uit early
	Touched   []string  // paths that were rewritten
	StartedAt time.Time
	FinishedAt time.Time
}

// Run iterates every finding in every TacticReport under cfg.FindingsDir
// and prompts the Examiner. Each (a)pprove / (r)eject sets fields on the
// Finding and the file is rewritten on session end (or after every
// finding, if you prefer paranoid persistence — see PersistAfterEach).
//
// Behaviour summary:
//   - Already-approved or already-rejected findings are skipped (with a
//     note) so the session is resumable.
//   - "skip all" applies to remaining findings in this session only —
//     does NOT mark anything in the file.
func RunGate1(cfg Config) (*Result, error) {
	if cfg.CaseID == "" {
		return nil, fmt.Errorf("case_id is required")
	}
	if cfg.FindingsDir == "" {
		return nil, fmt.Errorf("findings_dir is required")
	}
	if cfg.In == nil {
		cfg.In = os.Stdin
	}
	if cfg.Out == nil {
		cfg.Out = os.Stdout
	}
	if cfg.Examiner == "" {
		cfg.Examiner = "examiner-cli"
	}

	res := &Result{StartedAt: time.Now().UTC()}
	defer func() { res.FinishedAt = time.Now().UTC() }()

	files, err := listReportFiles(cfg.FindingsDir)
	if err != nil {
		return res, err
	}
	if len(files) == 0 {
		fmt.Fprintln(cfg.Out, "(no TacticReport files in findings dir)")
		return res, nil
	}

	rd := bufio.NewReader(cfg.In)
	skipAll := false

	totalFindings := 0
	for _, f := range files {
		rep, err := loadReport(f)
		if err != nil {
			return res, fmt.Errorf("load %q: %w", f, err)
		}
		totalFindings += len(rep.Findings)
	}

	idx := 0
	for _, path := range files {
		rep, err := loadReport(path)
		if err != nil {
			return res, fmt.Errorf("load %q: %w", path, err)
		}
		fileTouched := false
		for i := range rep.Findings {
			idx++
			f := &rep.Findings[i]

			// Resume-friendly: don't re-prompt approved/rejected items.
			if f.Approved || f.Rejected {
				res.Skipped++
				printResumed(cfg.Out, idx, totalFindings, f)
				continue
			}
			if skipAll {
				res.Skipped++
				continue
			}

			printPrompt(cfg.Out, idx, totalFindings, rep.TacticID, rep.TacticName, f)
			action, reason, err := readAction(cfg.Out, rd)
			if err != nil {
				return res, err
			}

			switch action {
			case "approve":
				f.Approved = true
				f.ReviewedAt = time.Now().UTC()
				f.ReviewedBy = cfg.Examiner
				res.Approved++
				fileTouched = true
				fmt.Fprintln(cfg.Out, "  → APPROVED")
			case "reject":
				f.Rejected = true
				f.RejectReason = reason
				f.ReviewedAt = time.Now().UTC()
				f.ReviewedBy = cfg.Examiner
				res.Rejected++
				fileTouched = true
				if reason == "" {
					fmt.Fprintln(cfg.Out, "  → REJECTED (no reason)")
				} else {
					fmt.Fprintln(cfg.Out, "  → REJECTED:", reason)
				}
			case "skip":
				res.Skipped++
				fmt.Fprintln(cfg.Out, "  → skipped (no state written)")
			case "skip_all":
				skipAll = true
				res.Skipped++
				fmt.Fprintln(cfg.Out, "  → skipping all remaining findings")
			case "quit":
				res.Quit = true
				if fileTouched {
					if err := saveReport(path, rep); err != nil {
						return res, err
					}
					res.Touched = append(res.Touched, path)
				}
				fmt.Fprintln(cfg.Out, "→ quit. partial session saved.")
				return res, nil
			}
		}
		if fileTouched {
			if err := saveReport(path, rep); err != nil {
				return res, err
			}
			res.Touched = append(res.Touched, path)
		}
	}
	sort.Strings(res.Touched)
	return res, nil
}

// ---- prompt I/O ------------------------------------------------------------

func printPrompt(w io.Writer, idx, total int, tacticID, tacticName string, f *agents.Finding) {
	bar := strings.Repeat("─", 70)
	fmt.Fprintf(w, "\n%s\n", bar)
	fmt.Fprintf(w, "Finding %d / %d  ·  %s %s  ·  %s [%s]\n",
		idx, total, tacticID, tacticName, f.FindingID, strings.ToUpper(f.Confidence))
	fmt.Fprintf(w, "%s\n", bar)
	fmt.Fprintf(w, "Technique: %s — %s\n", f.TechniqueID, f.TechniqueName)
	fmt.Fprintf(w, "Summary:   %s\n", wrap(f.Summary, 76, "           "))
	fmt.Fprintf(w, "Reasoning: %s\n", wrap(f.Reasoning, 76, "           "))
	fmt.Fprintf(w, "Evidence (%d):\n", len(f.Evidence))
	for j, ev := range f.Evidence {
		fmt.Fprintf(w, "  [%d] %s/%s\n", j+1, ev.SourceArtifact, ev.AuditID)
		fmt.Fprintf(w, "      %s\n", wrap(ev.Excerpt, 72, "      "))
	}
	fmt.Fprintf(w, "\n[a]pprove  [r]eject  [s]kip  [S]kip all remaining  [q]uit > ")
}

func printResumed(w io.Writer, idx, total int, f *agents.Finding) {
	state := "approved"
	if f.Rejected {
		state = "rejected"
	}
	fmt.Fprintf(w, "Finding %d / %d  ·  %s [%s]  → already %s, skipped\n",
		idx, total, f.FindingID, strings.ToUpper(f.Confidence), state)
}

func readAction(w io.Writer, rd *bufio.Reader) (string, string, error) {
	line, err := rd.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", err
	}
	line = strings.TrimSpace(line)
	switch line {
	case "a", "A", "approve":
		return "approve", "", nil
	case "r", "R", "reject":
		fmt.Fprintf(w, "Reject reason (one line, optional — blank = no reason): ")
		reason, _ := rd.ReadString('\n')
		return "reject", strings.TrimSpace(reason), nil
	case "s", "skip":
		return "skip", "", nil
	case "S", "skip-all":
		return "skip_all", "", nil
	case "q", "Q", "quit":
		return "quit", "", nil
	default:
		// Treat anything unrecognised (including EOF) as skip — friendlier
		// than crashing in non-tty contexts.
		return "skip", "", nil
	}
}

// ---- file I/O --------------------------------------------------------------

func listReportFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	sort.Strings(out)
	return out, nil
}

func loadReport(path string) (*agents.TacticReport, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rep agents.TacticReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, err
	}
	return &rep, nil
}

func saveReport(path string, rep *agents.TacticReport) error {
	body, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o644)
}

// wrap soft-wraps `s` at width chars and indents continuation lines.
func wrap(s string, width int, indent string) string {
	if len(s) <= width {
		return s
	}
	var b strings.Builder
	for i, r := 0, []rune(s); i < len(r); {
		end := i + width
		if end > len(r) {
			end = len(r)
		}
		// Backtrack to nearest space if we're mid-word.
		if end < len(r) && r[end] != ' ' {
			for j := end; j > i+width/2; j-- {
				if r[j] == ' ' {
					end = j
					break
				}
			}
		}
		if i > 0 {
			b.WriteString("\n")
			b.WriteString(indent)
		}
		b.WriteString(strings.TrimSpace(string(r[i:end])))
		i = end
	}
	return b.String()
}
