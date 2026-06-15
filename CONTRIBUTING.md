# Contributing

Thanks for considering a contribution! This is a hackathon-MVP project, so
the scope is intentionally narrow. Big changes are best discussed in an
issue first.

## Setup

```bash
./scripts/setup.sh    # verify prerequisites + go build
./scripts/verify.sh   # environment sanity check
```

## Workflow

1. Create a feature branch off `main`
2. Follow these conventions:
   - **Go**: 1.22+ idioms, `errgroup` / `context.Context` for goroutines,
     `fmt.Errorf("ctx: %w", err)` for error wrapping, `_test.go` files for
     table-driven tests
   - **Python**: 3.11+, type hints required, parsers under `parsers/`
     conform to the `parsers.base.parse(req)` interface
   - **Output discipline**: never write to `/`, evidence dirs, or
     `outputs/cases.duckdb` from parser code; use `output_dir`
3. Run the local checks:
   ```bash
   make lint
   make test
   make build
   ```
4. Write a Conventional Commits message (`feat:` / `fix:` / `docs:` / `test:`)
5. Open a PR

## Adding a new parser

1. Create `parsers/<artifact>_parser.py`. For single-CSV EZ Tools, use the
   `parsers/_ezt_csv.py` helper — see `shimcache_parser.py` as a template
   (~30 lines).
2. Register a detection rule in `parsers/orchestrator.py::_DETECTORS`
   (or add a custom pass for non-glob detection like the `lnk` pass).
3. Add an entry to `config/artifacts.yaml` with `tool`, `command_template`,
   and `unified_event_mapping`.
4. Update [`docs/tool_inventory.md`](docs/tool_inventory.md) with the
   verified version.

## Adding a new Tactic Agent

1. Author `skills/<slug>.md` (system prompt — see existing files for the
   format expected by the runner).
2. Register in `internal/agents/tactic_queries.go::TacticRegistry` with
   ATT&CK ID, name, and SQL OR-clauses for prefiltering.
3. Confirm via:
   ```bash
   tlvb analyze CASE_ID --tactic <slug> --dry-run
   ```

## Documentation: avoid local-only paths

When you write README / `docs/` / `scripts/` / Slack handoffs, **never
hardcode an absolute path that exists only on your machine**. Concrete
rules:

- Don't write `/cases/evtx-samples/...`, `/home/<you>/...`, or
  `~/<your-clone>/...` as if everyone has it. Even on SIFT Workstation
  these paths are populated by individual operators, not by the OS.
- If a sample is required, name the **upstream source** and the exact
  command to obtain it, e.g.:
  ```bash
  git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git \
      /cases/evtx-samples
  ```
  before referring to anything beneath that path.
- Add a "any path is fine" hint where it applies — `--evidence` accepts
  any directory or .zip the OS can read.
- After editing docs, re-read them as a colleague who just `git pull`ed
  with no prior context. If a step requires data, env vars, apt packages,
  or external auth that isn't called out, fix the doc before merging.

## Forensic discipline

These forensic rules are non-negotiable:

- Never modify files under `/cases/`, `/mnt/`, `/media/`, or any
  `evidence/` directory
- Output goes to `./analysis/`, `./exports/`, `./reports/`, or
  `./outputs/`
- Timestamps are ISO8601 UTC internally
- MCP tools must be **read-only**; the `execute_shell` API must NEVER be
  exposed to LLM clients
- Findings must cite evidence (`audit_id`, `source_artifact`); never
  invent IDs
