# Security Guardrails — adversarial verification

> FIND EVIL! judging axis ④ *Constraint Implementation*. This document states
> TLVB's hard safety constraints, **where each is enforced in code**, and the
> **adversarial "bypass" tests** that prove an LLM (or a prompt-injected one)
> cannot escape them. The guarantees are enforced *in code, not in the prompt*.

## Threat model

The agentic core runs LLM-proposed actions. We assume the LLM may be wrong,
jailbroken, or prompt-injected by attacker-controlled evidence (e.g. a malicious
filename or log line that ends up in a prompt). The guardrails must hold **even
if the model actively tries to break them**. We therefore test the *negative*:
feed each control its worst-case input and assert it refuses.

Design principle: **defence in depth** — every mutation path has at least two
independent controls, so a single bypass is not sufficient to cause harm.

## The four guardrails

### 1. MCP surface is read-only — `execute_shell` is never exposed
- **Invariant:** the LLM-facing MCP server registers only read-only tools; no
  shell/exec, no write, no review-approval tool.
- **Enforced:** `internal/mcp/server.go` — `registerTools()` registers 19
  read-only tools; `New()` opens the case DB with `casedb.ReadOnly`. There is no
  code path from a tool handler to a mutation or a shell.
- **Adversarial test:** `internal/mcp/readonly_surface_test.go` —
  `TestMCPSurfaceIsReadOnly` enumerates the *actual* registered tool set
  (`MCPServer.ListTools()`) and fails if any tool name implies execution,
  mutation, registration, or review-approval. Adding a forbidden tool breaks CI.

### 2. Tier 2 active-search SQL is SELECT-only, single-statement, single-bind
- **Invariant:** LLM-proposed SQL must be one read-only `SELECT`/`WITH`
  statement, scoped by exactly one `case_id = ?` bind; no DDL/DML, no stacked
  statements.
- **Enforced:** `internal/tier2/active_search.go` — `validateActiveSearchSQL()`
  requires a `SELECT`/`WITH` prefix, bans `insert|update|delete|drop|alter|attach|detach|create|pragma|copy|export`
  at statement level (string literals are blanked first), requires a `case_id`
  predicate, requires exactly one `?`, and **rejects any bare semicolon**.
  `execActiveSQL()` binds only `caseID`.
- **Hardening done here:** the semicolon check previously rejected only a
  *trailing* `;`, so a mid-statement `;` (e.g. `... WHERE case_id = ? ; SELECT 2`)
  carrying a second stacked statement with no banned keyword could slip through.
  It now rejects **any** bare semicolon — single-statement only.
- **Adversarial test:** `internal/tier2/active_search_bypass_test.go` —
  `TestActiveSearchValidatorRejectsBypassAttempts` (20 escape attempts: stacked
  DDL/DML, `ATTACH`/`COPY`/`EXPORT`, mixed-case keywords, multiple binds,
  trailing & mid-statement `;`, `WITH`-prefixed `DELETE`, …) all rejected;
  `TestActiveSearchValidatorAcceptsLegitimate` confirms normal queries — including
  ones with a `;` or a banned word *inside a string literal* — still pass.

### 3. The case DB is opened read-only at analysis time (the backstop)
- **Invariant:** at runtime the case DuckDB is read-only; even a write that
  somehow reached the connection cannot mutate evidence.
- **Enforced:** `internal/casedb/manager.go` — `Open(path, ReadOnly)` appends
  `?access_mode=read_only`; write APIs (`RegisterCase`/`RegisterEvidence`/
  `DeleteCase`, bulk inserts) also guard on `mode == ReadOnly`. The MCP server
  and Tier 1/2 analysis open read-only; only Tier 0 ingest opens read-write.
- **Adversarial test:** `internal/casedb/readonly_bypass_test.go` —
  `TestReadOnlyEngineBlocksWrites` opens a raw read-only connection and asserts
  `CREATE/INSERT/UPDATE/DELETE/DROP` are all rejected by the engine while
  `SELECT` still works; `TestReadOnlyManagerGuardsWrites` asserts the Manager
  guard rejects writes before the engine. This is the **second line of defence**
  behind guardrail #2: a SQL-validator bypass still cannot write.

### 4. Review approval is human-only
- **Invariant:** findings are approved/rejected only by a human Examiner via the
  CLI Review Gate or the Web Review UI — never by the LLM, never via MCP.
- **Enforced:** approval mutations live in `internal/review/gate.go` (CLI, prompts
  the Examiner) and `internal/web/review_gate_1a.go` (Web handlers, examiner from
  the `X-Examiner` header). The MCP server exposes only `get_parse_review` /
  `get_timeline_review`, which **read** review state.
- **Adversarial test:** covered by guardrail #1's surface test — the denylist
  includes `approve`/`reject`/`set_review`, so no approval tool can be exposed to
  the LLM.

## Running the guardrail tests

```bash
go test ./internal/tier2/  -run 'ActiveSearchValidator'   -v   # SELECT-only / single-statement / single-bind
go test ./internal/casedb/ -run 'ReadOnly'                -v   # read-only engine + Manager guard
go test ./internal/mcp/    -run 'SurfaceIsReadOnly'       -v   # read-only MCP tool surface
```

All run offline (no LLM, no network) and are part of `make test-go`.
