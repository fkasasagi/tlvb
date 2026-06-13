# Agent Execution Log & Finding Traceability

> Submission deliverable ⑨ ("agent execution log"). TLVB is a **multi-agent
> pipeline** (Tier 0 → 1A → 1B → 2 → 3). Every tier appends to **one ordered,
> timestamped `actions.jsonl`** per case. This document explains the log format
> and shows, with a concrete example, how a judge traces any finding back to the
> exact tool execution that produced it.

A committed sample is included so the format can be inspected without running the
pipeline:

- [`samples/WIN11-TEST-001.actions.jsonl`](samples/WIN11-TEST-001.actions.jsonl) — full
  122-record execution log for one real case (Tier 0 → Tier 2).
- [`samples/WIN11-TEST-001.finding-sigma-mimikatz.json`](samples/WIN11-TEST-001.finding-sigma-mimikatz.json)
  — one finding from that run, used in the worked example below.

> Note: live case data lives under `outputs/cases/<id>/` (git-ignored). The files
> above are committed copies of a genuine run so the artifact ships with the repo.

---

## 1. Where the log lives

```
outputs/cases/<case-id>/actions.jsonl     # one JSON object per line, append-only, chronological
```

Writer: [`internal/auditlog/auditlog.go`](../internal/auditlog/auditlog.go). Every
tier holds an `*auditlog.Logger` and appends records as it runs; writes are
mutex-guarded and best-effort (an unwritable log never aborts the analysis it
records). The `ts` field is stamped `RFC3339Nano` (UTC) at append time, so the
file is a true chronological trace across all agents.

Three ways to read it:

| Surface | How |
|---|---|
| File | `cat outputs/cases/<id>/actions.jsonl \| jq` |
| Web UI | **Audit** tab — renders every record with a tier filter; LLM calls show `model` + `tok=in/out` + `$cost`, SQL records expand to the full query, failed records are highlighted red. Served by `GET /api/cases/{id}/audit`. |
| MCP | finding-retrieval tools expose `audit_ids` per finding for an external LLM client. |

---

## 2. Record schema

One flat JSON object per line (`auditlog.Action`). Fields are `omitempty`, so
each record carries only what is relevant to its `kind`.

| Field | Meaning |
|---|---|
| `ts` | RFC3339Nano UTC timestamp (append time) |
| `case_id` | case identifier |
| `actor` | which agent emitted it: `tier0-orchestrator` \| `tier1a` \| `tier1b` \| `tier2` |
| `kind` | `parse` \| `skip` \| `rule_sql` \| `llm_call` \| `active_sql` |
| `detail` | sub-kind for LLM calls: `anomaly_hunter`, `cluster_analysis`, `active_search_generate`, `active_search_interpret`, `overall_synthesis`, … |
| `success` | true/false (present on every executed step) |
| `duration_seconds` | wall-clock for the step |
| `command` | the **SQL text** (for `active_sql`) or tool command line (for Tier 0 `parse`) |
| `row_count` | rows returned by a SQL execution |
| `error` | error text when `success=false` |
| `model` | model id of the LLM call (e.g. `claude-opus-4-8[1m]`) |
| `input_tokens` / `output_tokens` / `cache_read_tokens` | **token usage** per LLM call |
| `cost_usd` | per-call cost in USD |
| `rule_id` / `rule_source` | which signature rule ran (`sigma` \| `hayabusa` \| `stix` \| `custom`) |
| `cluster_id` / `attempt` / `outcome` | Tier 2 active-search loop coordinates (which cluster, which self-correction round, and `ok` \| `execute_error` \| `validation_error` \| `null_result`) |

---

## 3. What each agent logs

The sample case ([`samples/WIN11-TEST-001.actions.jsonl`](samples/WIN11-TEST-001.actions.jsonl),
122 records) breaks down as:

| Agent | `kind` | n | What it proves |
|---|---|---|---|
| `tier0-orchestrator` | `parse` / `skip` | 23 / 8 | every parser invocation (exact tool command line, exit code, row count, duration) and every artifact deliberately skipped |
| `tier1a` | `rule_sql` | 75 | every **signature rule that fired** (rule id + source + matched row count). Runtime is **LLM-free**, so these are deterministic and reproducible |
| `tier1b` | `llm_call` | 2 | the two skill-driven anomaly passes (`anomaly_hunter`, `credential_access`), each with model + tokens + cost |
| `tier2` | `llm_call` | 8 | per-cluster analysis (×2), active-search query generation (×2) and interpretation (×2), and overall synthesis (×2) |
| `tier2` | `active_sql` | 6 | every hypothesis-driven SQL the agent issued at runtime — full query text, `outcome`, `row_count`, and `attempt` number |

Token / cost accounting is therefore visible **per LLM call** and is also
aggregated into `synthesis.json → audit` (e.g. this run: Tier 2 = 8 calls,
in 368 / cache_read 7412 / out 36804 tokens, $2.4467). A reviewer can see exactly
where generative reasoning was used and what it cost.

---

## 4. Worked example — trace a finding to its tool execution

Take the finding **"Mimikatz Use"** (Sigma rule `06d71506`). Three hops, all in
the committed sample:

**Hop 1 — the tool execution** (`actions.jsonl`):

```json
{"ts":"2026-06-07T06:23:52.751463303Z","case_id":"WIN11-TEST-001","actor":"tier1a",
 "kind":"rule_sql","success":true,"row_count":1,
 "rule_id":"06d71506-7beb-4f22-8888-e2e5e2ca7fd8","rule_source":"sigma"}
```

This is the cached signature SQL for that Sigma rule firing once, at a precise
timestamp.

**Hop 2 — the finding** ([`samples/…finding-sigma-mimikatz.json`](samples/WIN11-TEST-001.finding-sigma-mimikatz.json)):

```jsonc
{
  "finding_id": "4427c020-d170-41ae-a8bb-91a8dfa7424d",
  "rule_id": "06d71506-7beb-4f22-8888-e2e5e2ca7fd8", "rule_source": "sigma",
  "rule_meta": { "title": "Mimikatz Use", "level": "high" },
  "generated_at": "2026-06-07T06:24:45...",          // matches the actions.jsonl ts
  "sql": "SELECT ... FROM unified_events WHERE case_id = ? AND artifact_id = 'evtx'
          AND ... payload_json ILIKE '%sekurlsa::%' ...",   // the EXACT query that ran
  "evidence": [ { "audit_id": "9adcdc85ed43ebc152bc2f1fcc47a5a8",
                  "artifact_id": "evtx", "event_type": "evtx" } ]
}
```

The finding embeds **the literal SQL** that produced it and the `audit_id` of
every matched event.

**Hop 3 — the raw evidence** (`unified_events`, queryable read-only via MCP or
the Web timeline):

```
audit_id = 9adcdc85ed43ebc152bc2f1fcc47a5a8
  ts_utc      2026-05-19 13:56:27.371
  artifact    evtx   event_type evtx   computer WinDev2407Eval
  payload     {"EventId":"4688","Channel":"Security","MapDescription":"A new
               process has been created", ... mimikatz "sekurlsa::logonpasswords" ...}
```

So: **finding → embedded SQL + `audit_id` → the exact Security-4688 process-creation
event**, and independently **finding's `rule_id` → the `rule_sql` record in
`actions.jsonl` → when that rule fired**. No step is inferred; every hop is a
stored identifier.

The same chain holds for the LLM tiers via `audit_ids`:

- **Tier 1B** anomaly findings carry `audit_ids[]` + `skill_sha256` + `model_id`,
  and the matching `actions.jsonl` `llm_call` record carries the tokens/cost.
- **Tier 2** clusters carry `finding_refs[]` (with a `provenance` =
  `signature`\|`anomaly-llm` and `confidence` = `confirmed`\|`inferred` label), and
  each active-search SQL it issued appears as an `active_sql` record with its full
  query text.

---

## 5. Runtime autonomy is logged too (self-correction & graceful degradation)

The execution log is not just a success ledger — it records how the agent's
approach **changed at runtime**:

- **Active-search self-correction.** When a hypothesis SQL fails or returns
  all-NULL, Tier 2 feeds the DB error back to the LLM and re-runs the revised
  query; each attempt is a separate `active_sql` record with an incrementing
  `attempt` and an `outcome`, so the **error → revise → recover** sequence is
  visible in chronological order. A query that runs clean but returns 0 rows is
  not an error — the agent re-asks from a different angle (a `no_evidence` attempt
  followed by an `active_search_reframe` LLM call and a re-sequenced retry), which
  is how the loop fires unprompted on real data. (In the older sample run all 6
  queries succeeded on `attempt=1`; to guarantee the error→correction loop fires
  on camera, run Tier 2 with `--reproduce-llm-fault`, which reproduces the most
  common real LLM mistake — treating an EventData field as a column — rather than
  injecting a synthetic marker.)

  *Observed, injection-free.* On a real Windows triage case (1.1 GB; Evtx /
  Registry / Prefetch / SRUM / NTFS) the re-sequencing arc fired **six times**
  with no `--reproduce-llm-fault` — the agent's own queries genuinely found
  nothing and it pivoted. The chronological log (timestamps show a real ~30 s
  model round-trip between the empty result and the retry, not an instant scripted
  fix) reads:

  ```
  20:09:13  active_sql            cl=6 attempt=1 outcome=no_evidence rows=0
  20:09:46  llm_call active_search_reframe  cl=6 attempt=1            (~33 s)
  20:09:46  active_sql            cl=6 attempt=2 outcome=ok          rows=51
  ```

  The attempt-1 query asked its open question from one angle, matched 0 rows, and
  the reframe re-issued from a different artifact/field; attempt 2 found 51
  events. (Literal log redacted of host/IP/account identifiers — it is real
  triage data; re-run any case with `--active-search` to reproduce the structure.)
- **Graceful degradation.** The sample run also shows two `overall_synthesis`
  `llm_call` records with `success=false` (`error":"exec: exit status 1"`); the
  pipeline fell back to a per-cluster stitch rather than aborting. Failures are
  logged honestly, not hidden.

---

## 6. Reproduce it

`unified_events` for the sample case is already parsed, so the LLM-free Tier 1A
re-run is instant and free; the full re-run was produced with:

```bash
make build
# Tier 1A — cached signature SQL, no LLM (deterministic, 75 rule_sql records)
./bin/tlvb analyze   WIN11-TEST-001 --tier 1a --db outputs/cases.duckdb
# Tier 1B — skills-driven anomaly (2 llm_call records)
./bin/tlvb analyze   WIN11-TEST-001 --tier 1b --skills anomaly_hunter,credential_access --db outputs/cases.duckdb
# Tier 2 — timeline + hypothesis-driven active search (llm_call + active_sql records)
./bin/tlvb synthesize WIN11-TEST-001 --tier 2 --active-search --db outputs/cases.duckdb
```

Or the whole pipeline in one shot (re-parsing from evidence):

```bash
./bin/tlvb run CASE_ID --tier all --evidence PATH --active-search
```

Then open the **Audit** tab in the Web UI (`make run`) or read
`outputs/cases/<id>/actions.jsonl` directly.

---

See [`ARCHITECTURE.md`](ARCHITECTURE.md) §4 (self-correction & audit trail) and
[`ACCURACY.md`](ACCURACY.md) §5–6 (traceability & reproducibility) for how this
fits the wider design.
