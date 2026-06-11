package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/tlvb/tlvb/internal/casedb"
	"github.com/tlvb/tlvb/internal/rulebuild"
	"github.com/tlvb/tlvb/internal/rulesdb"
	"github.com/tlvb/tlvb/internal/rulesrepo"
)

// runRules dispatches `tlvb rules ...` subcommands.
func runRules(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: tlvb rules build|list|export|import ...")
	}
	switch args[0] {
	case "build":
		return runRulesBuild(args[1:])
	case "list":
		return runRulesList(args[1:])
	case "export":
		return runRulesExport(args[1:])
	case "import":
		return runRulesImport(args[1:])
	case "prune-skills":
		return runRulesPruneSkills(args[1:])
	case "revalidate-sql":
		return runRulesRevalidateSQL(args[1:])
	default:
		return fmt.Errorf("unknown rules subcommand %q (want build|list|export|import|prune-skills|revalidate-sql)", args[0])
	}
}

func runRulesBuild(args []string) error {
	fs := flag.NewFlagSet("rules build", flag.ContinueOnError)
	rulesRoot := fs.String("rules-root", "rules",
		"top-level rules dir (submodules live under here)")
	rulesDBPath := fs.String("rules-db", "outputs/rules.duckdb",
		"path to the rule SQL cache DB")
	source := fs.String("source", "",
		"restrict to one loader: sigma | hayabusa | stix (default: all)")
	dryRun := fs.Bool("dry-run", false,
		"do not call the LLM; just plan + cost estimate")
	maxRules := fs.Int("max-rules", 0,
		"stop after N successfully-attempted rules (0 = no limit)")
	budgetYen := fs.Float64("budget-yen", 0,
		"stop when running cost exceeds this many yen (0 = no limit)")
	force := fs.Bool("force", false,
		"rebuild rules even when cache signature matches")
	ruleIDsCSV := fs.String("rule-ids", "",
		"comma-separated rule_ids to build (debugging / targeted rebuild). "+
			"Other rules are filtered out entirely.")
	model := fs.String("model", "claude-sonnet-4-6",
		"model id used for SQL generation (engine-specific)")
	cacheModelID := fs.String("cache-model-id", "",
		"override the model id recorded in the cache signature (default: --model). "+
			"Set to the existing rows' model to fill gaps with a different --model "+
			"without invalidating them (e.g. --model claude-opus-4-8 --cache-model-id claude-sonnet-4-6)")
	engine := fs.String("engine", "claude-code",
		"build engine: claude-code (uses local `claude` CLI, no API key needed) | anthropic-api")
	timeoutSec := fs.Int("timeout-seconds", 0,
		"per-rule LLM timeout in seconds (0 = engine default 300). Raise for rules "+
			"that trigger long chain-of-thought and get killed at the default.")
	rateIn := fs.Float64("rate-yen-per-m-input", 450.0,
		"cost rate: yen per 1M input tokens (Sonnet 4.6 list price default)")
	rateOut := fs.Float64("rate-yen-per-m-output", 2250.0,
		"cost rate: yen per 1M output tokens")
	rateCache := fs.Float64("rate-yen-per-m-cache-read", 45.0,
		"cost rate: yen per 1M cache-read tokens")
	if err := fs.Parse(args); err != nil {
		return err
	}

	loaders, err := buildLoaders(*rulesRoot, *source)
	if err != nil {
		return err
	}
	if len(loaders) == 0 {
		return fmt.Errorf("no loaders available under %s (did you check out the submodules?)", *rulesRoot)
	}

	db, err := rulesdb.Open(*rulesDBPath, rulesdb.ReadWrite)
	if err != nil {
		return fmt.Errorf("open rules db: %w", err)
	}
	defer db.Close()

	var builder rulebuild.Builder
	switch *engine {
	case "anthropic-api":
		apiKey := os.Getenv("ANTHROPIC_API_KEY")
		if !*dryRun && apiKey == "" {
			return fmt.Errorf("--engine anthropic-api requires ANTHROPIC_API_KEY (use --dry-run to plan, or --engine claude-code)")
		}
		b := rulebuild.NewAnthropicBuilder(apiKey, *model, casedb.SchemaDoc())
		b.SignatureModel = *cacheModelID
		if *timeoutSec > 0 {
			b.Timeout = time.Duration(*timeoutSec) * time.Second
		}
		builder = b
	case "claude-code":
		if !*dryRun {
			if _, err := exec.LookPath("claude"); err != nil {
				return fmt.Errorf("--engine claude-code requires the `claude` binary on PATH (install Claude Code CLI, or use --engine anthropic-api)")
			}
		}
		b := rulebuild.NewClaudeCodeBuilder(*model, casedb.SchemaDoc())
		b.SignatureModel = *cacheModelID
		if *timeoutSec > 0 {
			b.Timeout = time.Duration(*timeoutSec) * time.Second
		}
		builder = b
	default:
		return fmt.Errorf("unknown --engine %q (want claude-code | anthropic-api)", *engine)
	}
	// Runtime compile-check gate (known issue #6): reject generated SQL that
	// won't execute against unified_events before it's cached as "built".
	compiler, err := rulebuild.NewSQLCompiler(casedb.UnifiedEventsDDL)
	if err != nil {
		return fmt.Errorf("init sql compiler: %w", err)
	}
	defer compiler.Close()

	pipeline := &rulebuild.Pipeline{
		Loaders:   loaders,
		Builder:   builder,
		RulesDB:   db,
		Compiler:  compiler,
		SchemaDoc: casedb.SchemaDoc(),
		SchemaVer: casedb.SchemaVersion(),
		Rates: rulebuild.Rates{
			YenPerMInputTokens:     *rateIn,
			YenPerMOutputTokens:    *rateOut,
			YenPerMCacheReadTokens: *rateCache,
		},
		MaxRules:      *maxRules,
		BudgetYen:     *budgetYen,
		SourceFilter:  *source,
		Force:         *force,
		Progress:      progressPrinter(),
		RuleIDsFilter: splitCSV(*ruleIDsCSV),
	}

	ctx := context.Background()

	if *dryRun {
		rep, err := pipeline.Plan(ctx)
		if err != nil {
			return err
		}
		printDryRun(rep, *model, casedb.SchemaVersion())
		return nil
	}

	fmt.Fprintf(os.Stderr, "tlvb rules build — model=%s schema_version=%s\n",
		*model, casedb.SchemaVersion())
	rep, err := pipeline.Build(ctx)
	if err != nil {
		return err
	}
	printBuildReport(rep)
	return nil
}

func runRulesList(args []string) error {
	fs := flag.NewFlagSet("rules list", flag.ContinueOnError)
	rulesDBPath := fs.String("rules-db", "outputs/rules.duckdb",
		"path to the rule SQL cache DB")
	source := fs.String("source", "",
		"restrict to one source: sigma | hayabusa | stix (default: all)")
	state := fs.String("state", "",
		"filter by state: pending | built | failed (default: all)")
	showSQL := fs.Bool("show-sql", false,
		"print the cached SQL body for each row (long output)")
	skills := fs.Bool("skills", false,
		"list the Tier 1B skill_sql_cache (learned lenses) instead of rule_sql_cache")
	if err := fs.Parse(args); err != nil {
		return err
	}

	db, err := rulesdb.Open(*rulesDBPath, rulesdb.ReadOnly)
	if err != nil {
		return fmt.Errorf("open rules db (read-only): %w", err)
	}
	defer db.Close()

	ctx := context.Background()
	if *skills {
		return listSkillCache(ctx, db, *showSQL)
	}
	rows, err := db.ListAll(ctx, *source, rulesdb.CacheState(*state))
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}

	counts, _ := db.CountByState(ctx)
	fmt.Printf("Rule SQL cache  (sigma=%d hayabusa=%d stix=%d custom=%d)\n",
		countBySource(rows, "sigma"), countBySource(rows, "hayabusa"),
		countBySource(rows, "stix"), countBySource(rows, "custom"))
	fmt.Printf("States: built=%d pending=%d failed=%d\n\n",
		counts[rulesdb.StateBuilt], counts[rulesdb.StatePending], counts[rulesdb.StateFailed])

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SOURCE\tRULE_ID\tSTATE\tMODEL\tGENERATED\tPREFILTER\tERROR")
	for _, r := range rows {
		ts := "-"
		if r.GeneratedAt != nil {
			ts = r.GeneratedAt.UTC().Format(time.RFC3339)
		}
		errMsg := truncateStr(r.ErrorMessage, 60)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.RuleSource, truncateStr(r.RuleID, 40), r.State, r.ModelID, ts,
			r.PrefilterArtifacts, errMsg)
	}
	w.Flush()

	if *showSQL {
		fmt.Println()
		for _, r := range rows {
			if r.SQL == "" {
				continue
			}
			fmt.Printf("# %s/%s\n%s\n\n", r.RuleSource, r.RuleID, r.SQL)
		}
	}
	return nil
}

// ruleExportRow is the diffable, git-vendorable shape of one built rule.
// generated_at / state / error_message are intentionally dropped: state is
// always 'built' for an export, and generated_at would churn the diff on every
// rebuild even when the SQL is byte-identical. The (rule_sha256, schema_version,
// model_id) triple is kept so a fresh clone can tell whether the vendored SQL
// still matches its rule corpus / build model.
type ruleExportRow struct {
	RuleID             string          `json:"rule_id"`
	RuleSource         string          `json:"rule_source"`
	RuleSHA256         string          `json:"rule_sha256"`
	SchemaVersion      string          `json:"schema_version"`
	ModelID            string          `json:"model_id"`
	PrefilterArtifacts []string        `json:"prefilter_artifacts"`
	SQL                string          `json:"sql"`
	RuleMeta           json.RawMessage `json:"rule_meta,omitempty"`
}

// runRulesExport writes the *built* rule SQL cache to diffable JSONL under
// --out-dir, one file per source (<source>.sql.jsonl). This lets the
// LLM-generated SQL be committed to git so a fresh clone reuses it instead of
// re-running the (Sonnet-quota / yen-costing) build. Rows arrive ordered by
// (rule_source, rule_id) so each file is deterministic without re-sorting.
func runRulesExport(args []string) error {
	fs := flag.NewFlagSet("rules export", flag.ContinueOnError)
	rulesDBPath := fs.String("rules-db", "outputs/rules.duckdb",
		"path to the rule SQL cache DB")
	source := fs.String("source", "",
		"restrict to one source: sigma | hayabusa | stix | custom (default: all)")
	outDir := fs.String("out-dir", "rules/built",
		"directory to write <source>.sql.jsonl files into")
	if err := fs.Parse(args); err != nil {
		return err
	}

	db, err := rulesdb.Open(*rulesDBPath, rulesdb.ReadOnly)
	if err != nil {
		return fmt.Errorf("open rules db (read-only): %w", err)
	}
	defer db.Close()

	ctx := context.Background()
	rows, err := db.ListAll(ctx, *source, rulesdb.StateBuilt)
	if err != nil {
		return fmt.Errorf("list built rules: %w", err)
	}
	if len(rows) == 0 {
		return fmt.Errorf("no built rules to export (source=%q)", *source)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", *outDir, err)
	}

	type srcOut struct {
		f   *os.File
		w   *bufio.Writer
		enc *json.Encoder
	}
	outs := map[string]*srcOut{}
	counts := map[string]int{}
	closeAll := func() {
		for _, o := range outs {
			o.w.Flush()
			o.f.Close()
		}
	}
	defer closeAll()

	for _, r := range rows {
		o, ok := outs[r.RuleSource]
		if !ok {
			path := filepath.Join(*outDir, r.RuleSource+".sql.jsonl")
			f, err := os.Create(path)
			if err != nil {
				return fmt.Errorf("create %s: %w", path, err)
			}
			w := bufio.NewWriter(f)
			enc := json.NewEncoder(w)
			// Keep <, >, & literal so the SQL stays readable in the diff.
			enc.SetEscapeHTML(false)
			o = &srcOut{f: f, w: w, enc: enc}
			outs[r.RuleSource] = o
		}
		if err := o.enc.Encode(buildExportRow(r)); err != nil {
			return fmt.Errorf("encode %s/%s: %w", r.RuleSource, r.RuleID, err)
		}
		counts[r.RuleSource]++
	}
	closeAll()

	srcs := make([]string, 0, len(counts))
	for s := range counts {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)
	for _, s := range srcs {
		fmt.Printf("wrote %d %s rules -> %s\n", counts[s], s,
			filepath.Join(*outDir, s+".sql.jsonl"))
	}
	return nil
}

// buildExportRow maps a cache row to its JSONL projection: the comma-separated
// prefilter string becomes a real array, and rule_meta is embedded as raw JSON
// (compacted by the encoder) rather than a JSON-in-string blob. Empty/invalid
// meta is handled defensively so one bad row can't break the whole export.
func buildExportRow(r rulesdb.CacheRow) ruleExportRow {
	arts := []string{}
	for _, a := range strings.Split(r.PrefilterArtifacts, ",") {
		if a = strings.TrimSpace(a); a != "" {
			arts = append(arts, a)
		}
	}
	row := ruleExportRow{
		RuleID:             r.RuleID,
		RuleSource:         r.RuleSource,
		RuleSHA256:         r.RuleSHA256,
		SchemaVersion:      r.SchemaVersion,
		ModelID:            r.ModelID,
		PrefilterArtifacts: arts,
		SQL:                r.SQL,
	}
	if meta := strings.TrimSpace(r.RuleMeta); meta != "" {
		if json.Valid([]byte(meta)) {
			row.RuleMeta = json.RawMessage(meta)
		} else {
			b, _ := json.Marshal(meta)
			row.RuleMeta = json.RawMessage(b)
		}
	}
	return row
}

// runRulesImport seeds rule_sql_cache from the vendored JSONL written by
// `rules export`, so a fresh clone reuses the built SQL instead of re-running
// the (Sonnet-quota / yen-costing) build.
//
// Default (safe) mode never touches a rule that already exists in the DB, in
// any state — existing built rules cannot be degraded; only genuinely-missing
// rules are inserted. --overwrite replaces existing rows with the snapshot.
func runRulesImport(args []string) error {
	fs := flag.NewFlagSet("rules import", flag.ContinueOnError)
	rulesDBPath := fs.String("rules-db", "outputs/rules.duckdb",
		"path to the rule SQL cache DB (created if missing)")
	source := fs.String("source", "",
		"restrict to one source: sigma | hayabusa | stix | custom (default: all *.sql.jsonl)")
	inDir := fs.String("in-dir", "rules/built",
		"directory holding the <source>.sql.jsonl files to import")
	overwrite := fs.Bool("overwrite", false,
		"replace rules that already exist in the cache (default: leave existing rules untouched)")
	dryRun := fs.Bool("dry-run", false,
		"parse and report what would be imported without writing")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var files []string
	if *source != "" {
		files = []string{filepath.Join(*inDir, *source+".sql.jsonl")}
	} else {
		matches, err := filepath.Glob(filepath.Join(*inDir, "*.sql.jsonl"))
		if err != nil {
			return fmt.Errorf("scan %s: %w", *inDir, err)
		}
		sort.Strings(matches)
		files = matches
	}
	if len(files) == 0 {
		return fmt.Errorf("no *.sql.jsonl files found in %s", *inDir)
	}

	// Parse everything up front so a malformed file fails before we touch the DB.
	var rows []rulesdb.CacheRow
	perSource := map[string]int{}
	skipped := 0
	for _, f := range files {
		fr, sk, err := parseImportFile(f)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		skipped += sk
		for _, r := range fr {
			perSource[r.RuleSource]++
			rows = append(rows, r)
		}
	}
	if len(rows) == 0 {
		return fmt.Errorf("no valid rows parsed from %s", *inDir)
	}

	// The Tier 1A loader only loads rows whose (schema_version, model_id)
	// match the running binary, so importing a stale vendored JSONL would
	// otherwise succeed yet silently produce zero hits at runtime.
	if n, vers := staleSchemaRows(rows, casedb.SchemaVersion()); n > 0 {
		fmt.Fprintf(os.Stderr,
			"WARNING: %d/%d rule(s) have schema_version %s != current %s — "+
				"they will be imported but IGNORED at Tier 1A runtime until rebuilt (tlvb rules build)\n",
			n, len(rows), strings.Join(vers, ","), casedb.SchemaVersion())
	}

	srcs := make([]string, 0, len(perSource))
	for s := range perSource {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)

	mode := "safe (existing rules preserved)"
	if *overwrite {
		mode = "overwrite"
	}

	if *dryRun {
		for _, s := range srcs {
			fmt.Printf("would import %d %s rules\n", perSource[s], s)
		}
		if skipped > 0 {
			fmt.Printf("(%d malformed line(s) would be skipped)\n", skipped)
		}
		fmt.Printf("dry-run: nothing written  [mode: %s]\n", mode)
		return nil
	}

	db, err := rulesdb.Open(*rulesDBPath, rulesdb.ReadWrite)
	if err != nil {
		return fmt.Errorf("open rules db: %w", err)
	}
	defer db.Close()

	ctx := context.Background()
	var inserted, updated, preserved int
	for _, r := range rows {
		action, err := db.SeedBuilt(ctx, r, *overwrite)
		if err != nil {
			return fmt.Errorf("seed %s/%s: %w", r.RuleSource, r.RuleID, err)
		}
		switch action {
		case "inserted":
			inserted++
		case "updated":
			updated++
		case "skipped":
			preserved++
		}
	}

	fmt.Printf("imported into %s  [mode: %s]\n", *rulesDBPath, mode)
	fmt.Printf("  inserted=%d  updated=%d  preserved=%d", inserted, updated, preserved)
	if skipped > 0 {
		fmt.Printf("  malformed_skipped=%d", skipped)
	}
	fmt.Println()
	return nil
}

// parseImportFile reads one <source>.sql.jsonl into CacheRows. Malformed lines
// (bad JSON, or missing rule_id/rule_source/sql) are warned about and skipped
// so one bad row can't abort a whole import; the count is returned.
// staleSchemaRows counts rows whose schema_version differs from the running
// binary's, returning the count and the sorted set of stale versions seen.
func staleSchemaRows(rows []rulesdb.CacheRow, current string) (int, []string) {
	seen := map[string]bool{}
	n := 0
	for _, r := range rows {
		if r.SchemaVersion != current {
			n++
			seen[r.SchemaVersion] = true
		}
	}
	vers := make([]string, 0, len(seen))
	for v := range seen {
		vers = append(vers, v)
	}
	sort.Strings(vers)
	return n, vers
}

func parseImportFile(path string) ([]rulesdb.CacheRow, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// A row carries the full SQL (~19KB max) plus meta; raise the line cap well
	// above bufio's 64KB default so long rules don't trip "token too long".
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var out []rulesdb.CacheRow
	skipped, ln := 0, 0
	for sc.Scan() {
		ln++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var er ruleExportRow
		if err := json.Unmarshal([]byte(line), &er); err != nil {
			fmt.Fprintf(os.Stderr, "warn: %s:%d: invalid JSON, skipped: %v\n", path, ln, err)
			skipped++
			continue
		}
		if er.RuleID == "" || er.RuleSource == "" || er.SQL == "" {
			fmt.Fprintf(os.Stderr, "warn: %s:%d: missing rule_id/rule_source/sql, skipped\n", path, ln)
			skipped++
			continue
		}
		meta := ""
		if len(er.RuleMeta) > 0 {
			meta = string(er.RuleMeta)
		}
		out = append(out, rulesdb.CacheRow{
			RuleID:             er.RuleID,
			RuleSource:         er.RuleSource,
			RuleSHA256:         er.RuleSHA256,
			SchemaVersion:      er.SchemaVersion,
			ModelID:            er.ModelID,
			SQL:                er.SQL,
			PrefilterArtifacts: strings.Join(er.PrefilterArtifacts, ","),
			RuleMeta:           meta,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, skipped, fmt.Errorf("scan %s: %w", path, err)
	}
	return out, skipped, nil
}

// listSkillCache renders the Tier 1B skill_sql_cache (learned lenses).
func listSkillCache(ctx context.Context, db *rulesdb.Manager, showSQL bool) error {
	rows, err := db.ListAllSkillSQL(ctx)
	if err != nil {
		return fmt.Errorf("list skill cache: %w", err)
	}
	counts, _ := db.CountSkillByState(ctx)
	fmt.Printf("Tier 1B skill SQL cache  (canonical=%d candidate=%d total=%d)\n\n",
		counts[rulesdb.SkillCanonical], counts[rulesdb.SkillCandidate], len(rows))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SKILL\tSTATE\tHITS\tORIGIN\tLAST_USED\tGENERATED\tINTENT")
	for _, r := range rows {
		ts := "-"
		if r.GeneratedAt != nil {
			ts = r.GeneratedAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
			r.Skill, r.State, r.HitCount,
			orDash(r.OriginCase), orDash(r.LastUsedCase), ts,
			truncateStr(r.Intent, 60))
	}
	w.Flush()

	if showSQL {
		fmt.Println()
		for _, r := range rows {
			fmt.Printf("# %s [%s] %s\n%s\n\n", r.Skill, r.State, r.Intent, r.SQL)
		}
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// runRulesPruneSkills removes never-promoted (hit_count=0) skill candidates
// older than --max-age-days so the cache doesn't accumulate dead lenses as it
// grows across cases. Canonical (proven) queries are never touched.
func runRulesPruneSkills(args []string) error {
	fs := flag.NewFlagSet("rules prune-skills", flag.ContinueOnError)
	rulesDBPath := fs.String("rules-db", "outputs/rules.duckdb",
		"path to the rule SQL cache DB")
	maxAgeDays := fs.Float64("max-age-days", 30,
		"prune unpromoted (hit_count=0) candidates generated more than this many "+
			"days ago (0 = prune ALL unpromoted candidates regardless of age)")
	dryRun := fs.Bool("dry-run", false,
		"show what would be pruned without deleting")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cutoff := time.Now().Add(-time.Duration(*maxAgeDays * 24 * float64(time.Hour)))
	ctx := context.Background()

	mode := rulesdb.ReadWrite
	if *dryRun {
		mode = rulesdb.ReadOnly
	}
	db, err := rulesdb.Open(*rulesDBPath, mode)
	if err != nil {
		return fmt.Errorf("open rules db: %w", err)
	}
	defer db.Close()

	if *dryRun {
		victims, err := db.ListPrunableSkillCandidates(ctx, cutoff)
		if err != nil {
			return err
		}
		fmt.Printf("dry-run: %d candidate(s) would be pruned (hit_count=0, older than %.0f days)\n",
			len(victims), *maxAgeDays)
		for _, r := range victims {
			ts := "-"
			if r.GeneratedAt != nil {
				ts = r.GeneratedAt.UTC().Format(time.RFC3339)
			}
			fmt.Printf("  %s  [%s]  %s\n", ts, r.Skill, truncateStr(r.Intent, 70))
		}
		return nil
	}

	n, err := db.PruneSkillCandidates(ctx, cutoff)
	if err != nil {
		return err
	}
	fmt.Printf("pruned %d unpromoted skill candidate(s) older than %.0f days\n", n, *maxAgeDays)
	return nil
}

// runRulesRevalidateSQL re-checks every 'built' rule's cached SQL against the
// unified_events schema (empty-table execution) and marks rows whose SQL no
// longer runs as 'failed' — so a subsequent `rules build` regenerates them
// into executable SQL. Sonnet-free. Cleans up known issue #6's existing rows.
func runRulesRevalidateSQL(args []string) error {
	fs := flag.NewFlagSet("rules revalidate-sql", flag.ContinueOnError)
	rulesDBPath := fs.String("rules-db", "outputs/rules.duckdb", "path to the rule SQL cache DB")
	source := fs.String("source", "", "restrict to one source: sigma | hayabusa | stix (default: all)")
	dryRun := fs.Bool("dry-run", false, "report broken rows without marking them failed")
	if err := fs.Parse(args); err != nil {
		return err
	}

	compiler, err := rulebuild.NewSQLCompiler(casedb.UnifiedEventsDDL)
	if err != nil {
		return fmt.Errorf("init sql compiler: %w", err)
	}
	defer compiler.Close()

	mode := rulesdb.ReadWrite
	if *dryRun {
		mode = rulesdb.ReadOnly
	}
	db, err := rulesdb.Open(*rulesDBPath, mode)
	if err != nil {
		return fmt.Errorf("open rules db: %w", err)
	}
	defer db.Close()

	ctx := context.Background()
	rows, err := db.ListAll(ctx, *source, rulesdb.StateBuilt)
	if err != nil {
		return fmt.Errorf("list built: %w", err)
	}

	var broken, marked int
	for _, r := range rows {
		// Match the Tier 1A runtime contract: exactly one ? (case_id). The
		// runtime rejects other counts before execution, so compiler.Check
		// (which binds a single arg) won't surface them — check explicitly.
		var reason string
		if n := strings.Count(r.SQL, "?"); n != 1 {
			reason = fmt.Sprintf("expected exactly one ? placeholder, got %d", n)
		} else if cerr := compiler.Check(r.SQL); cerr != nil {
			reason = cerr.Error()
		}
		if reason == "" {
			continue
		}
		broken++
		fmt.Printf("  BROKEN %s/%s: %s\n", r.RuleSource, r.RuleID, truncateStr(reason, 80))
		if !*dryRun {
			if err := db.MarkFailed(ctx, r.RuleID, r.RuleSource, "revalidate: "+reason); err == nil {
				marked++
			}
		}
	}
	fmt.Printf("\nrevalidate-sql — checked %d built rows, %d broken", len(rows), broken)
	if *dryRun {
		fmt.Printf(" (dry-run: none marked). Run without --dry-run to mark them failed, then `rules build` to regenerate.\n")
	} else {
		fmt.Printf(", %d marked failed. Run `rules build` to regenerate them into executable SQL.\n", marked)
	}
	return nil
}

// buildLoaders constructs the standard Sigma + Hayabusa + STIX loader set,
// optionally narrowed by --source.
func buildLoaders(rulesRoot, sourceFilter string) ([]rulesrepo.Loader, error) {
	var out []rulesrepo.Loader

	addIfExists := func(path string, mk func(p string) rulesrepo.Loader, name string) {
		if sourceFilter != "" && sourceFilter != name {
			return
		}
		if _, err := os.Stat(path); err == nil {
			out = append(out, mk(path))
		}
	}

	addIfExists(filepath.Join(rulesRoot, "sigma", "upstream", "rules"),
		func(p string) rulesrepo.Loader { return rulesrepo.NewSigmaLoader(p) }, "sigma")
	addIfExists(filepath.Join(rulesRoot, "hayabusa", "upstream", "hayabusa"),
		func(p string) rulesrepo.Loader { return rulesrepo.NewHayabusaLoader(p) }, "hayabusa")
	addIfExists(filepath.Join(rulesRoot, "stix", "mitre-attack", "enterprise-attack", "attack-pattern"),
		func(p string) rulesrepo.Loader { return rulesrepo.NewSTIXLoader(p) }, "stix")
	addIfExists(filepath.Join(rulesRoot, "lolbas", "upstream", "yml"),
		func(p string) rulesrepo.Loader { return rulesrepo.NewLOLBASLoader(p) }, "lolbas")
	return out, nil
}

func progressPrinter() func(rulebuild.BuildEvent) {
	lastIdx := 0
	return func(ev rulebuild.BuildEvent) {
		switch ev.Phase {
		case "done":
			fmt.Fprintf(os.Stderr, "\n[done] processed=%d total_cost=%.2f yen\n",
				ev.Total, ev.CostYen)
			return
		case "building":
			// Print every 25 to keep stderr readable; always surface signals
			// that an examiner cares about (failed + purged stale rows).
			isAlwaysOn := ev.State == "failed" || ev.State == "skipped_loader_purged"
			if ev.Index-lastIdx < 25 && !isAlwaysOn {
				return
			}
			if !isAlwaysOn {
				lastIdx = ev.Index
			}
			fmt.Fprintf(os.Stderr, "[build %d/%d] %s/%s -> %s  (cost so far: %.2f yen)",
				ev.Index, ev.Total, ev.RuleSource, ev.RuleID, ev.State, ev.CostYen)
			if ev.Error != "" {
				fmt.Fprintf(os.Stderr, "  err=%s", truncateStr(ev.Error, 80))
			}
			fmt.Fprintln(os.Stderr)
		}
	}
}

func printDryRun(rep *rulebuild.DryRunReport, model, schemaVer string) {
	fmt.Printf("Dry-run report\n")
	fmt.Printf("  model:           %s\n", model)
	fmt.Printf("  schema_version:  %s\n", schemaVer)
	fmt.Printf("  total rules:     %d\n", rep.TotalRules)
	fmt.Printf("  to build:        %d\n", rep.ToBuild)
	fmt.Printf("  already cached:  %d\n", rep.AlreadyCached)
	fmt.Printf("  skipped (loader): %d\n", rep.SkippedByLoader)
	if len(rep.SkippedReasons) > 0 {
		keys := make([]string, 0, len(rep.SkippedReasons))
		for k := range rep.SkippedReasons {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Printf("    breakdown:\n")
		for _, k := range keys {
			fmt.Printf("      %-12s %d\n", k+":", rep.SkippedReasons[k])
		}
	}
	fmt.Printf("\nProjected cost (worst case, ignores prompt-cache savings):\n")
	fmt.Printf("  est input tokens:  %s\n", commaInt(rep.EstInputTokens))
	fmt.Printf("  est output tokens: %s\n", commaInt(rep.EstOutputTokens))
	fmt.Printf("  est cost:          %.2f yen\n", rep.EstCostYen)
	fmt.Printf("\nReal cost is typically 30-60%% of the above thanks to prompt-cache hits.\n")
}

func printBuildReport(rep *rulebuild.BuildReport) {
	fmt.Printf("\nBuild summary\n")
	fmt.Printf("  stopped_reason:  %s\n", rep.StoppedReason)
	fmt.Printf("  total rules:     %d\n", rep.TotalRules)
	fmt.Printf("  built:           %d\n", rep.Built)
	fmt.Printf("  failed:          %d\n", rep.Failed)
	fmt.Printf("  skipped cached:  %d\n", rep.SkippedCached)
	fmt.Printf("  skipped loader:  %d\n", rep.SkippedLoader)
	fmt.Printf("  actual cost:     %.2f yen\n", rep.ActualCostYen)
	if rep.StoppedReason == "budget" || rep.StoppedReason == "max_rules" {
		fmt.Printf("\nNote: build did not finish.  Re-run the same command to continue.\n")
	}
}

func countBySource(rows []rulesdb.CacheRow, src string) int {
	n := 0
	for _, r := range rows {
		if r.RuleSource == src {
			n++
		}
	}
	return n
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// splitCSV trims and splits a comma-separated list. Empty input returns nil.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// commaInt formats an integer with comma thousands separators (no extra deps).
func commaInt(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	for i, ch := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(ch)
	}
	return b.String()
}
