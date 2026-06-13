# TLVB

**TLVB** — *Timeline Longa, Vita Brevis*
(the timeline is long, life is short — so we automate the hunt for an attacker's traces)

*日本語版: [README.ja.md](README.ja.md)*

An autonomous IR agent that combines Sigma / Hayabusa / ATT&CK STIX rules with skills-driven anomaly detection to extract traces of an attack from Windows forensic artifacts, then has an LLM reconstruct the attack chain and emit HTML/CSV/JSON reports.

## Status

🟢 **v0.1 — the full pipeline, stages (a)–(g), runs end to end.** On a real Windows 11 triage image, TLVB detected, reconstructed, and reported an 8-step attack scenario end to end, confirmed as of 2026-05-29. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the system diagram and [`NEW_CONTRIBUTIONS.md`](NEW_CONTRIBUTIONS.md) for what is new hackathon work vs. reused foundation.

```
INPUT (collector zip / disk image / live triage)
  ↓
Tier 0   Parser ×N (Python) → unified_events @ DuckDB         🟢
  ↓        wraps EZ Tools / Hayabusa / Plaso / SrumECmd / etc.
Tier 1A  Signature-driven (★ zero runtime LLM)                🟢
          at build time: Sigma/Hayabusa/STIX → SQL, cached
          at runtime: execute cached SQL + Hayabusa pass-through
  ↓     → findings/by-rule/<source>/<rule_id>.json
Tier 1B  Skills-driven Anomaly                                🟢
          off-hours / suspicious path / rare process / adjacency
          feeds 5×N samples to the LLM (claude CLI) to extract
          abstract patterns
  ↓     → findings/by-skill/<skill>.json
Tier 2   Timeline Analysis                                    🟢
          clusters findings on 30-min gaps, generates a
          per-cluster narrative from ±5-min raw timeline
          --active-search drills into open questions via SQL
  ↓     → synthesis.json
Tier 3   Reporter                                             🟢
          HTML (self-contained, dark mode, MITRE links) / CSV / JSON
        → outputs/cases/<id>/reports/
```

## Usage

```bash
# First-time setup — this alone gets you to a working Tier 1A
# (verifies prerequisites, creates .venv, runs go build, and imports the
#  vendored rule SQL cache — all automatically)
./scripts/setup.sh

# Run every tier in one command (evidence location is up to you:
#  zip / disk image / triage directory). Tier 2's self-correcting,
#  re-sequencing active-search agent (the autonomy showcase: it fixes its own
#  failed queries and pivots when a query finds nothing) runs BY DEFAULT;
#  add --no-active-search for a cheaper, non-agentic run.
./bin/tlvb run MY-CASE-001 --tier all --evidence /path/to/triage.zip

# Or run the tiers step by step (setup.sh has already imported the Tier 1A SQL cache)
./bin/tlvb case init --case-id MY-CASE-001 --name "Sep IR" --examiner alice
./bin/tlvb parse --case-id MY-CASE-001 --evidence-id EV-001 --input triage.zip
./bin/tlvb analyze MY-CASE-001 --tier 1a
./bin/tlvb analyze MY-CASE-001 --tier 1b
./bin/tlvb synthesize MY-CASE-001 --tier 2 --active-search
./bin/tlvb report MY-CASE-001 --tier 3 --format html,csv,json --language en

# (Optional) You only need the git submodules + an LLM if you want to
#   regenerate the rules yourself. setup.sh has already imported the vendored
#   SQL cache, so this is normally unnecessary.
git submodule update --init --recursive          # Sigma / Hayabusa / mitre-attack
./bin/tlvb rules build --engine claude-code --max-rules 100

# Web UI / MCP server
./bin/tlvb serve --port 8080     # http://localhost:8080
./bin/tlvb mcp-serve              # connect from an MCP client over stdio
```

For the LLM, TLVB supports both the **claude CLI** (free, used via your subscription) and the **Anthropic API** (`ANTHROPIC_API_KEY`). For a step-by-step walkthrough with expected output, see [`docs/QUICKSTART.md`](docs/QUICKSTART.md); the full design is in [`docs/DESIGN.md`](docs/DESIGN.md).

## Detection capability (real-machine validation, 2026-05-29)

Processing an 86 MB Win11 triage zip in a single command:

| Stage | Count | Examples |
|---|---|---|
| Tier 0 unified_events | 470,372 | mft 459k / evtx 5.6k / hayabusa 1k / amcache 2k / lnk 11 / ... |
| Tier 1A cached SQL | 3 | Eventlog Cleared / LSASS Dump Keyword In CommandLine, etc. |
| Tier 1A Hayabusa pass-through | 32 | Mimikatz Execution / Suspicious Eventlog Clearing / etc. |
| Tier 1B Skills-driven Anomaly | 4 | mimi.exe+procdump masquerade / anti-recovery cluster (vssadmin+wbadmin+bcdedit), etc. |
| Tier 2 attack-chain narrative | 2 clusters | main activity 13:50–14:23 / RDP re-entry the next morning at 06:32 (16.5 h dwell time) |
| Tier 2 active-search | 6 SQL | corroborated "procdump → mimi.exe rename" via amcache SHA1 match |
| Tier 3 HTML report | 26 KB | opens directly in a browser (inline CSS, dark mode) |

Total time: **about 5 minutes** (parse measured separately; this covers analyze + synthesize + report only).

## Design decisions

- **Tier 1A has zero runtime LLM**: it only executes cached SQL. LLM cost is paid once, at build time (a few yen per rule, Sonnet 4.6).
- **rule_id keeps the upstream original ID unmodified**: Sigma UUIDs / STIX T-numbers / Hayabusa UUIDs are used as-is, with a `rule_source` auxiliary column to disambiguate.
- **Sysmon-only rules are excluded by default**: real-world IR often lacks Sysmon. They can be enabled dynamically via `requires_artifact`.
- **Severity-based auto-approve**: critical/high findings require review; the rest are auto-approved, and the Examiner can always override.

## Security & human-in-the-loop

Guardrails are enforced in code, not in the prompt: the MCP surface is **read-only** (no `execute_shell`, DB opened `access_mode=read_only`), active-search SQL is validated **SELECT-only / single-bind / no-DDL**, Tier 1A is **LLM-free at runtime**, and the original evidence is never mutated. Approve/reject at each Review Gate is a human-only action — the agent has no self-approve capability. See [`docs/SECURITY_GUARDRAILS.md`](docs/SECURITY_GUARDRAILS.md) and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §2–§4.

## Key documents

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — end-to-end pipeline, security boundaries, self-correction (with diagrams)
- [`NEW_CONTRIBUTIONS.md`](NEW_CONTRIBUTIONS.md) — what is new hackathon work vs. reused foundation
- [`docs/ACCURACY.md`](docs/ACCURACY.md) — self-assessment of detection accuracy, false positives, misses, and hallucination
- [`docs/QUICKSTART.md`](docs/QUICKSTART.md) — detailed walkthrough, including how to try it yourself
- [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) — complete beginner-friendly guide + glossary
- [`docs/EVIDENCE_DATASETS.md`](docs/EVIDENCE_DATASETS.md) — what TLVB was tested on and where the data came from
- [`docs/EXECUTION_LOG.md`](docs/EXECUTION_LOG.md) — agent execution log & finding traceability
- [`docs/SECURITY_GUARDRAILS.md`](docs/SECURITY_GUARDRAILS.md) — the enforced security boundaries
- [`docs/DESIGN.md`](docs/DESIGN.md) — TLVB v0.1 design document
- [`CLAUDE.md`](CLAUDE.md) — guide for Claude Code + the agreed design conventions

## License

See [LICENSE](LICENSE).
