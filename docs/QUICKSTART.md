# TLVB Quickstart — Try It Yourself

This document is a step-by-step guide for anyone who wants to actually run TLVB.
It assumes SIFT Workstation as the primary environment, but it works anywhere as
long as Linux + the Claude Code CLI are installed.

*日本語版: [QUICKSTART.ja.md](QUICKSTART.ja.md)*

Every command is written to be run from **the clone of this repository (the
repository root)**. All paths in the body are relative to the repository root.

Estimated time:

| Item | Time | LLM calls |
|---|---|---|
| 0a. Build + verify help | 2 min | none |
| 0b. Fetch sample EVTX | 1 min | none |
| 1. Inspect via the MCP server | 5 min | none |
| 2. Try out a Review Gate 1 | 5 min | none (requires Step 4 or 5 first) |
| 3. `analyze --tier 1a` (optionally 1b) on a small new case | 5–10 min | none for Tier 1A / 1 call for 1B |
| 4. The full pipeline (`run`) on a small new case | 35 min | yes (11 calls) |

---

## Prerequisites

```bash
which claude && claude --version    # Claude Code CLI (for --engine claude-code, recommended)
which go && go version              # Go 1.25.5+ (apt install golang-go is fine)
which python3 && python3 --version  # 3.11+
which dotnet && dotnet --version    # 9.x (to run EZ Tools)
ls /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll   # required parser (standard SIFT path)
```

`ANTHROPIC_API_KEY` is **not required**. TLVB reuses the Claude Code CLI's session
authentication as-is, so LLM calls go through without setting a separate key
(if you want to run in API mode, use `--engine anthropic-api` +
`export ANTHROPIC_API_KEY=...`).

---

## 0a. Build (first time only)

```bash
# Assumes you are at the root, right after cloning the repository
./scripts/setup.sh           # verifies dependencies + creates .venv + go build
./bin/tlvb version
# → tlvb 0.1.0-dev
```

> If `.venv` creation fails because `python3-venv` is not installed (e.g. on
> Ubuntu 24.04), pass `./scripts/setup.sh --auto-install-deps` to install it
> automatically via sudo apt (without that flag, you only get a message
> prompting you to install it manually).

> If you routinely use `--engine anthropic-api`, place a `.env.local` at the
> repository root containing `ANTHROPIC_API_KEY=...`, and start with
> `tlvb serve --env-file .env.local`; the browser UI will then automatically
> run via the API too.

### 0a-bis. About altpf (the Prefetch primary engine)

Prefetch parsing uses **altpf** (a native Linux Go tool, PECmd-compatible CSV,
full LastRun + PreviousRun0..6, ~1000x faster than Plaso) as the primary engine,
with Plaso `psteal.py` as the fallback.

**As soon as you run `./scripts/setup.sh`, v0.5.1 is automatically installed at
`/opt/altpf/altpf`** (fetched via gh / curl → two-stage SHA-256 verification →
installed, idempotent). No additional manual work is needed.

Only special cases require manual operation:

```bash
./scripts/install_altpf.sh --check          # verify only (no download)
./scripts/install_altpf.sh --force          # reinstall (when you want to update the version)
./scripts/install_altpf.sh                  # manual reinstall if setup skipped it
```

Parsing still runs even without altpf (Plaso fallback / LastRun only). You can
tell which path was used **from the parse command in the UI's Audit tab**: if the
`command` column shows `/opt/altpf/altpf -d ...` it was altpf; if it shows
`psteal.py --source ... --parsers prefetch` it was the Plaso fallback.

Help:

```bash
./bin/tlvb help
```

This prints the list of subcommands. Each subcommand shows its detailed flags
with `-h`:

```bash
./bin/tlvb analyze -h
./bin/tlvb synthesize -h
./bin/tlvb run -h
```

## 0b. Fetch sample EVTX data

For validation, the quickest path is the **public collection**
[**EVTX-ATTACK-SAMPLES**](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
(about 200 evtx files organized by MITRE ATT&CK tactic).

```bash
# Clone anywhere you like (the SIFT convention is /cases/, but under $HOME is fine too)
EVTX_DIR=./evtx-samples       # ← whatever path you prefer
sudo mkdir -p "$(dirname $EVTX_DIR)" && sudo chown $USER "$(dirname $EVTX_DIR)" 2>/dev/null
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git "$EVTX_DIR"

# Verify
ls "$EVTX_DIR/Persistence/" | head -3
```

> **Note**: Wherever the following steps write `$EVTX_DIR`, they refer to the
> variable you set above. If you work in a different shell, run
> `export EVTX_DIR=...` again.
> It works on any directory containing any `.evtx` files, so evtx pulled from a
> Windows machine's `C:\Windows\System32\winevt\Logs\` is fine too.

---

## 1. Inspect a case via the MCP server (no LLM calls)

TLVB's Tier 0 MCP server can be connected from Claude Code / Cursor / any MCP
client to query the contents of a case read-only.

```bash
# Start it (stdio mode — connect to it from a client)
./bin/tlvb mcp-serve --log-level info
```

You can write a "send one JSON-RPC turn" smoke test against the server alone as
follows (on the first run the case list is empty, so `list_cases` returns an
empty result too):

```bash
{
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"smoke","version":"0"},"capabilities":{}}}'
  printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_cases","arguments":{}}}'
  sleep 0.3
} | ./bin/tlvb mcp-serve --log-level error 2>/dev/null | python3 -m json.tool
```

All 19 tools exposed — the 10 core ones below; see the `tools/list` output above for the full list:

| Tool | Purpose |
|---|---|
| `list_artifacts` | the artifact types that are supported |
| `get_artifact_definition` | detailed definition of one artifact (including caveats) |
| `list_cases` | list of registered cases |
| `get_case_status` | details of one case + parse results |
| `list_evidence` | the evidence registered for a case |
| `get_unified_events` | fetch parsed events with SQL-like filters |
| `get_parse_result` | the exact command, success/failure, and stderr of an individual parser |
| `list_findings` | filter the AI findings within a case by tactic / state |
| `get_finding` | details of one finding (evidence array, confidence, etc.) |
| `health` | server liveness check |

**Everything is read-only.** It is structurally impossible to trigger `parse` /
`analyze` over MCP (per CLAUDE.md: "never expose `execute_shell` over MCP").

---

## 2. Try out a Review Gate (no LLM calls)

> **The main path is the Web UI Review Gate 1A (signature findings) / 1B
> (anomaly findings)** (`tlvb serve` → Findings tab). These read Tier 1A's
> `findings/by-rule/` and Tier 1B's `findings/by-skill/`, and support
> severity-based auto-approve and per-cluster bulk approval.
>
> The CLI `tlvb review` below is a demo for the **legacy (TacticReport) format
> only**; it cannot read the new pipeline's (tier1a/1b) findings. It only works
> when you have tactic-agent findings from the `tlvb analyze --legacy` family.
> (The examples below use `MY-TEST-001`.)

```bash
CASE=MY-TEST-001    # replace with the case ID you created in Step 3 / 4

# Copy just some of the findings files to use as the review target
TEST=/tmp/tlvb-review-test
mkdir -p $TEST/findings
cp outputs/cases/$CASE/findings/persistence.json $TEST/findings/

# Start the review session (about 10 findings appear)
./bin/tlvb review $CASE \
    --findings-dir $TEST/findings \
    --examiner "$USER"
```

Keys:

| Key | Action |
|---|---|
| `a` | approve (sets `approved=true`) |
| `r` | reject (sets `rejected=true` + prompts for a reason) |
| `s` | skip (leaves state unchanged) |
| `S` | skip all remaining (leaves state unchanged) |
| `q` | abort (state so far is saved) |

After the session ends, confirm the flags were written to the file:

```bash
python3 -c "
import json
r = json.load(open('$TEST/findings/persistence.json'))
for f in r['findings']:
    state = 'unreviewed'
    if f.get('approved'): state = 'APPROVED by ' + f.get('reviewed_by','')
    elif f.get('rejected'): state = 'REJECTED: ' + f.get('reject_reason','')
    print(f'  {f[\"finding_id\"]}: {state}')
"
```

Regenerate the HTML from approved findings only (`--only-approved`):

```bash
./bin/tlvb synthesize $CASE \
    --findings-dir $TEST/findings \
    --out $TEST/synthesis.json
./bin/tlvb report $CASE \
    --synthesis $TEST/synthesis.json \
    --out-dir $TEST/reports \
    --only-approved \
    --format html
```

Open `$TEST/reports/report.html` in any browser (`xdg-open` / `firefox` /
`chromium-browser`); §5 Findings by Tactic will contain only the approved ones.

---

## 3. Try Tier 1A on a small new case (no LLM calls, optionally Tier 1B)

Run just the Persistence Agent over the EVTX sample `Other` (~8 files / 750
events).

```bash
# Carry over the EVTX_DIR you set in 0b
EVTX_DIR=${EVTX_DIR:-./evtx-samples}

# 3-1: register the case
./bin/tlvb case init \
    --case-id MY-TEST-001 \
    --name "first-test" \
    --examiner "$USER"

# 3-2: Tier 0 — parse the 8 EVTX files and load them into the DB (~3 s)
./bin/tlvb parse \
    --case-id MY-TEST-001 \
    --evidence-id EV-OTHER-001 \
    --input "$EVTX_DIR/Other" \
    --only evtx

# 3-2-bis: to register multiple Evidence at once, use --inputs (★v0.3 #1)
# ./bin/tlvb parse \
#     --case-id MY-TEST-001 \
#     --inputs "$EVTX_DIR/Other,$EVTX_DIR/Persistence" \
#     --only evtx

# 3-3: Tier 1A — execute the cached signature SQL (no LLM, seconds to tens of seconds)
./bin/tlvb analyze MY-TEST-001 --tier 1a

# Optional: Tier 1B — the anomaly hunter (LLM, ~a few minutes). Uses the claude CLI, no API key needed
./bin/tlvb analyze MY-TEST-001 --tier 1b --skill anomaly_hunter

# 3-4: look at the output (Tier 1A is under by-rule/, Tier 1B under by-skill/)
ls -R outputs/cases/MY-TEST-001/findings/
cat outputs/cases/MY-TEST-001/findings/by-rule/sigma/*.json | python3 -m json.tool | head -50
```

Tier 1A does not call the LLM, so it needs neither an API key nor the claude CLI.
Only Tier 1B uses the LLM, and it runs without an API key if the `claude` CLI is
present.

---

## 4. Try the full pipeline (Tier 1A is LLM-free / a few LLM calls across Tier 1B + Tier 2 · ~$1 · about 10 min)

```bash
EVTX_DIR=${EVTX_DIR:-./evtx-samples}

./bin/tlvb run MY-FULL-001 \
    --tier all \
    --evidence "$EVTX_DIR/Other" \
    --name "first-full-run" \
    --examiner "$USER" \
    --active-search
```

`--active-search` turns on the self-correcting Tier 2 agent — the autonomy
showcase. It proposes SQL to answer each cluster's open questions and recovers
with no human in the loop two ways: it **fixes** a query that errors or returns
all-NULL, and when a query runs clean but finds **0 rows** it **re-sequences**
to a different artifact/field/hypothesis. Every attempt lands in
`actions.jsonl`. Drop the flag for a cheaper, non-agentic run.

This single command runs Tier 0→1A→1B→2→3:

```
[run] case-init  ok  (new case)
[run] tier0      ok  in 3.2s    (parser → unified_events)
[run] tier1a     ok  in ~10s    (cached signature SQL + Hayabusa, LLM=0)
[run] tier1b     ok  in ~4min   (anomaly_hunter skill, LLM)
[run] tier2      ok  in ~3min   (Timeline Analysis, LLM)
[run] tier3      ok  in 0.5s    (HTML/CSV/JSON DFIR report, LLM=0)
[run] DONE  case=MY-FULL-001  total=~8min
```

If one stage fails, the case as a whole does not stop — it is logged with
`[FAIL]` and the run moves on.

To skip only certain stages (`--skip-1a` / `--skip-1b` / `--skip-2` /
`--skip-report`):

```bash
# Tier 0 (parse) is already done, redo from Tier 1A
./bin/tlvb run MY-FULL-001 --tier all --skip-parse

# Tier 1A/1B are done, start from Tier 2
./bin/tlvb run MY-FULL-001 --tier all --skip-parse --skip-1a --skip-1b

# Enable Tier 2 active search (wide-range SQL)
./bin/tlvb run MY-FULL-001 --tier all --skip-parse --active-search
```

When it finishes:

```bash
# Open the report (from a machine with a GUI session)
xdg-open outputs/cases/MY-FULL-001/reports/report.html
# If that does not work, call the browser directly:
#   firefox outputs/cases/MY-FULL-001/reports/report.html
#   chromium-browser outputs/cases/MY-FULL-001/reports/report.html

# Check the contents of the DB
python3 -c "
import duckdb
con = duckdb.connect('outputs/cases.duckdb', read_only=True)
print(con.execute('SELECT * FROM cases').fetchall())
print(con.execute('SELECT artifact_id, COUNT(*) FROM unified_events WHERE case_id=? GROUP BY 1', ['MY-FULL-001']).fetchall())
"
```

For an explanation of the report, also read
`outputs/cases/MY-FULL-001/reports/HANDOFF.md`. Include that file when you
distribute the HTML to your team.

---

## 5. Run it on your own evidence

Instead of `$EVTX_DIR/Other`, pass your own investigation target. The input is
**a directory or a .zip** (for example, you can pass the output zip from
Washizukami-Collector or CDIR-Collector as-is — auxiliary files like
collector.log are picked up automatically if present).

```bash
# (example) a quarantined incident zip
./bin/tlvb run INC-2026-9001 \
    --evidence /path/to/triage_collector.zip \
    --evidence-id EV-COLL-001 \
    --name "ACME-Corp-IR-Sep" \
    --examiner alice \
    --engine claude-code
```

The zip is extracted to `outputs/cases/<id>/extractions/extracted/` (the
original files are left unchanged).

Detectable artifacts (key ones, excerpted):

| Type | Detection pattern | Required files |
|---|---|---|
| EVTX | `**/*.evtx` | Windows Event Logs |
| Amcache | `**/Amcache.hve` | registry hive |
| Prefetch | `**/Prefetch/*.pf` | %SystemRoot%\Prefetch |
| Registry | parent dir of `SOFTWARE`/`SYSTEM`/`NTUSER.DAT`, etc. | registry hives |
| Scheduled Tasks | `**/System32/Tasks/**` | XML task files |
| Shimcache | `**/SYSTEM` (hive) | SYSTEM hive |
| MFT | `**/$MFT` | $MFT |
| LNK / Jumplists / Recycle Bin | various patterns | Windows shell artifacts |
| Browser History | `**/User Data/*/History`, `**/Profiles/*/places.sqlite` | Chrome/Edge/Firefox |
| Washizukami audit log | `**/collection.log` | Washizukami-Collector output |

Types that are not included are ignored as out of MVP scope (shown as skipped in
the log). For the full parser list, see `config/artifacts.yaml`.

---

## 6. Re-analyze an existing case

Useful when you have rebuilt the rule corpus or added a new skill:

```bash
CASE=MY-FULL-001    # your case ID

# Re-run Tier 1A (cached signature SQL, no LLM)
./bin/tlvb analyze $CASE --tier 1a

# Additionally run Tier 1B (anomaly_hunter) on an existing case
./bin/tlvb analyze $CASE --tier 1b --skill anomaly_hunter

# Re-synthesize with Tier 2 (default; use --active-search for wide-range exploration)
./bin/tlvb synthesize $CASE

# Regenerate the report (Tier 3 by default)
./bin/tlvb report $CASE --format html,csv,json
```

Re-run only a specific Tier 1B skill (lens):

```bash
./bin/tlvb analyze $CASE --tier 1b --skill credential_access
./bin/tlvb synthesize $CASE
./bin/tlvb report $CASE --format html
```

---

## 7. Do it all in the Web UI

If you prefer the Web UI over the CLI:

```bash
./bin/tlvb serve --port 8080
# → http://localhost:8080/ in your browser
# → to access remotely (from outside the VM), use http://<VM-IP>:8080/
```

In the Web UI:
- Create new case → Parse → Analyze All → Synthesize → Generate Report in a
  straight line of 4 buttons (each button has a progress bar + ETA to its right)
- Approve / Reject in the Findings tab (= Review Gate 1)
- Review Gate 0 in the Events tab (approving parse results)
- The floating 💬 button opens the TLVB Assistant chat

For details, see [`USER_GUIDE.md`](USER_GUIDE.md).

---

## 8. When things don't work (Troubleshooting)

### `claude: command not found`
The Claude Code CLI is not on PATH. Check whether it is at `/usr/bin/claude` or
`~/.local/bin/claude`. If not, install it with
`npm install -g @anthropic-ai/claude-code`. As an alternative, use
`--engine anthropic-api` + the `ANTHROPIC_API_KEY` environment variable.

### `engine=anthropic-api requires ANTHROPIC_API_KEY`
Either pass `--engine claude-code` explicitly, or run
`export ANTHROPIC_API_KEY=sk-ant-...` before invoking.

### `claude CLI failed (...): Not logged in · Please run /login`
You are passing `--bare` to Claude Code, or this is the first launch. Start
`claude` interactively once and run `/login` to create a session.

### `xdg-open: no method available`
A browser cannot be launched from a headless shell (e.g. via Claude Code). Run
`chromium-browser <path>` or `firefox <path>` from a GUI terminal, or type
`! chromium-browser <path>` at the Claude Code prompt (the `!` prefix
instruction).

### `dotnet: command not found`
EZ Tools won't run. `apt install -y dotnet-runtime-9.0`, or check the standard
SIFT path `/usr/bin/dotnet`.

### `error: externally-managed-environment` (PEP 668)
The system pip is rejected on Ubuntu 24.04+. `scripts/setup.sh` creates
`./.venv/` and installs `duckdb` there. If the venv module is missing, run
`sudo apt install python3-venv python3-full` first.

### `case has no registered evidence`
Run `tlvb parse` first (or the Parse button in the Web UI).

### Tier 1B (anomaly_hunter) ends with `status=partial`
Normal behavior: the LLM conservatively marked insufficient evidence. `partial`
is not a failure in itself but a sign to prompt Examiner review.

### The Corrector keeps returning `retried_no_change`
It means the LLM holds a consistent finding — which is healthy. Consistency
contradictions remain as cases requiring the Examiner's manual investigation.

### DuckDB lock error
Multiple `tlvb` processes have the DB open for writing. Run `pkill tlvb` and
retry. This happens when the MCP server and a parse run concurrently.

### The Web UI's Analyze All is rejected with 409
Review Gate 0 is not yet approved. Approve each parse result in the Events tab,
check "Skip Review Gate 0", or append `?force=true` to the URL.

### mft / usn_journal / shellbags / browser_history don't appear in Parse Results (resolved in Wave 15)
**Resolved automatically from Wave 15 onward.** Collector-flattened naming that
prepends a prefix, like `Web/Chrome/Tanaka_Default_History` (TANAKA /
KAPE-NTFS bundled / FastIR families), is absorbed by the basename regex in
`parsers/_collector_prefix.py`. **An artifact still not visible in the UI** is
one of these four:

- **🟢 OK**: a green badge means parse succeeded (row_count > 0)
- **🟡 EMPTY**: parse succeeded but 0 rows (the collector gathered only the file
  and its contents were empty, etc.)
- **⚪ NOT_PRESENT**: the input does not contain that artifact (e.g. the triage
  zip did not collect `Users/*/AppData/` → `jumplists` `lnk` `recyclebin`
  `win10timeline` are all NOT_PRESENT). **This is by design, not a bug.**
- **🔴 FAIL**: the parser is installed and the input has the files, but an error
  occurred during parsing (corrupt file / missing tool, etc.)

In versions before Wave 15, a detection miss simply showed "no rows" in the UI
with no way to tell why; now all 17 implemented types always have a row in Parse
Results.

### The Prefetch parse command is `psteal.py` / engine=plaso in the Events tab
**This is the fallback path, by design.** The Prefetch primary is altpf
(`/opt/altpf/altpf`); if altpf is not installed, it falls back automatically to
Plaso `psteal.py` (graceful degradation). To install altpf:

```bash
./scripts/install_altpf.sh --check     # check current state
./scripts/install_altpf.sh             # install /opt/altpf/altpf at v0.5.1
```

After installing altpf and re-parsing, the command column in the Audit tab
changes to `/opt/altpf/altpf -d ...` and `payload.engine` in Events becomes
`altpf`. Because altpf expands LastRun + PreviousRun0..6 into independent
unified_event rows (identified by the `run_kind` field), it gives a higher
resolution of execution history than the Plaso fallback (LastRun only).

---

## 9. Landmarks for the key paths (relative to repository root)

```
./
├── bin/tlvb                       # the built CLI
├── outputs/
│   ├── cases.duckdb                   # cross-case DB (mostly read-only)
│   ├── rules.duckdb                    # Tier 1A rule SQL cache
│   └── cases/<case_id>/
│       ├── findings/
│       │   ├── by-rule/<source>/<id>.json  # Tier 1A signature findings
│       │   └── by-skill/<skill>.json       # Tier 1B anomaly findings
│       ├── extractions/               # parser intermediate data
│       ├── synthesis.json             # Tier 2 CaseSynthesis
│       ├── parse_review.json          # Review Gate 0 state
│       ├── timeline_gate.json         # Review Gate 2 state
│       ├── actions.jsonl              # audit trail
│       └── reports/
│           ├── report.html            # main deliverable (Tier 3)
│           ├── report.json            # machine-readable version
│           ├── findings.csv           # for Excel import
│           ├── mitre.csv  clusters.csv
│           ├── timeline.csv  ioc.csv
│           └── HANDOFF.md             # distribution notes
├── skills/<skill>.md                  # Tier 1B skills (default anomaly_hunter)
├── config/artifacts.yaml              # artifact definitions
├── parsers/                           # Tier 0 (Python)
├── internal/                          # Tier 1–3 + web (Go)
└── docs/
    ├── DESIGN.md                      # design document v0.3
    ├── ARCHITECTURE.md                # end-to-end pipeline + security boundaries
    ├── USER_GUIDE.md                  # complete beginner-friendly guide + glossary
    ├── tool_inventory.md              # SIFT tool validation results
    ├── valhuntir_analysis.md          # reference repository analysis
    └── QUICKSTART.md                  # this file
```

The evidence (`$EVTX_DIR` or your own investigation zip) is **read-only**.
Everything that gets written is consolidated entirely under **`outputs/`**
(per CLAUDE.md: "evidence is read-only").

---

## 10. Next steps

- Run `tlvb run` once through with your own investigation case
- Distribute the HTML report to your team (zip + verify SHA-256 — see
  `HANDOFF.md`)
- Customize `skills/<skill>.md` (the Tier 1B lenses) to your organization's TTPs
  (add the query intent for a new perspective)
- Add your own rules under `rules/custom/` and reflect them into Tier 1A with
  `tlvb rules build`
- Add your own parser to `config/artifacts.yaml` (Linux syslog, etc.)
- Add your own rule R5+ to `internal/synthesizer/consistency.go`

If you get stuck, read [`DESIGN.md`](DESIGN.md) (the system design document v0.3),
[`ARCHITECTURE.md`](ARCHITECTURE.md) (the end-to-end pipeline + security
boundaries), and [`USER_GUIDE.md`](USER_GUIDE.md) (the complete beginner-friendly
guide) together.
