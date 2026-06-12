# TLVB — Originality & New Contributions

*Prepared for the FIND EVIL! (SANS / Devpost) judges.*

This document states, precisely, **what in this repository is substantially new
work created during the hackathon window (15 Apr – 15 Jun 2026)**, what is reused
foundation, and how TLVB differs from the author's related submission. It exists
to satisfy the rule that submissions be *"substantially new work created during
the hackathon period"* with *"the novel contribution clearly documented,"* and
that, where an entrant submits more than one project, each be *"unique and
substantially different from each of the Entrant's other Submissions."*

---

## 1. Two related submissions, one author

The author is submitting **two distinct projects: `moai` and `TLVB`.** Both
are the author's own work, both were private until submission, and **both were
built during the hackathon window** — `moai` is *not* a pre-existing
third-party project. They were developed in parallel and share a common
forensic-parsing/storage foundation, but they implement **fundamentally
different agent architectures.** The rest of this document focuses on TLVB's
novel contribution and its distinction from `moai`.

> If only one of the two is reviewed, TLVB stands on its own: every component in
> §4 was authored during the window, on top of the openly-disclosed foundation
> in §3.

---

## 2. The core distinction: Tactic-Agent vs. Tier-separated pre-bake

The two projects answer "how should an LLM drive a Windows IR investigation?"
in two genuinely different ways.

| | **moai** (sibling submission) | **TLVB** (this repo) |
|---|---|---|
| Organising idea | **Tactic agents** — one LLM agent per MITRE tactic | **Tiers** — signature → anomaly → timeline, separated by *when the LLM runs* |
| Where the LLM runs | At **runtime**, repeatedly: each tactic agent sweeps a sliding window of events (`internal/agents/`), then a synthesiser reconciles them (`internal/synthesizer/`, consistency rules R1–R4) | **Split by design**: Tier 1A runs the LLM **only at build time** to pre-bake rules into SQL, and is **LLM-zero at runtime**; LLM reasoning is concentrated in Tier 1B (anomaly) and Tier 2 (timeline) |
| Detection substrate | Per-tactic prompt + LLM judgement over windows | A compiled **SQL rule cache** (`outputs/rules.duckdb`) executed deterministically, plus a *learning* skill cache that grows across cases |
| Cost / reproducibility | LLM cost scales with case size and tactic count | Tier 1A has a **fixed, LLM-free runtime cost**; the same case yields the same signature findings every run |
| Self-correction | not a first-class loop | **runtime error-detection → revise → re-execute** loop in Tier 2 active-search (see §4.4) |

This is not a rename or a refactor of `moai` — it is a different control
flow, a different cost model, and a different data substrate (a pre-baked SQL
cache and a cross-case learning cache that `moai` does not have).

---

## 3. Reused foundation (honestly disclosed)

The following are **not** claimed as new hackathon work. They are the shared
base the author built earlier and/or thin wrappers over established OSS, and are
disclosed here so the novel work in §4 is unambiguous:

- **Tier 0 parsers** — `parsers/` (Python). Wrappers that drive standard
  **SIFT Workstation** tools (Zimmerman EZ Tools, Hayabusa, Plaso, The Sleuth
  Kit, `bulk_extractor`, Volatility 3) and normalise their output into a unified
  event schema. The forensic parsing is the tools' work, not ours.
- **Case store** — `internal/casedb/` (a DuckDB wrapper), `internal/exporter/`
  (`.fcz` export/import), `internal/common/` (logging, dotenv, catalogs).
- **Web UI shell & MCP base** — `ui/` (vanilla-JS SPA) and the read-only MCP
  server skeleton in `internal/mcp/`.
- **Third-party rule corpora** (vendored, unmodified, under their own licences):
  **SigmaHQ/sigma**, **Yamato-Security/hayabusa-rules**, **MITRE/cti** (ATT&CK
  STIX), **LOLBAS** — consumed as inputs, not authored here.
- **Go / Python libraries**: `marcboeker/go-duckdb`, `google/uuid`, the
  Anthropic SDK / `claude` CLI, DuckDB.

---

## 4. TLVB's novel contributions (authored in the window)

Each item below was written during the hackathon window. Paths point at the new
code so the contribution is verifiable.

### 4.1 Build-time rule compilation → SQL cache
`internal/rulesrepo/` (Sigma / Hayabusa / STIX / LOLBAS loaders),
`internal/rulebuild/` (LLM pipeline that translates each rule into a DuckDB
`SELECT`, with cost guards: `--dry-run`, `--budget-yen`, `--max-rules`, resume),
`internal/rulesdb/` (the `rule_sql_cache` table with content-hash / schema /
model invalidation). **~1,700 Sigma rules compiled to validated SQL.** This
build-once / run-many design is the basis for the LLM-zero runtime tier.

### 4.2 Tier 1A — signature runtime, **zero runtime LLM**
`internal/tier1a/`. Executes the cached SQL against a case, emits one finding
per hit, applies severity-based auto-approve. No LLM is called at runtime — a
deliberate architectural guarantee of cost and reproducibility. Includes a
Hayabusa pass-through and **10 hand-authored forensic SQL rules** (`rules/built/
custom.sql.jsonl`) covering non-EVTX artefacts (USN ransomware rename, LNK
double-extension, Run-key/scheduled-task masquerade, NTDS.dit exfil, etc.).

### 4.3 Tier 1B — skills-driven anomaly with a **cross-case learning cache**
`internal/tier1b/`. A heuristic pre-filter feeds an LLM that reasons over
anomalies *and proposes new SQL*; proposed queries are stored as **candidates**
and promoted to **canonical** once they back a finding, after which they run
LLM-free. The cache (`skill_sql_cache`) grows across cases — the system gets
cheaper and sharper the more it is used. This learning loop is new in TLVB.

### 4.4 Tier 2 — timeline analysis with **runtime self-correction**
`internal/tier2/`. Passive mode clusters findings and has the LLM reconstruct
the attack narrative from the surrounding raw timeline; active mode generates
hypothesis-driven wide-range SQL. **Self-correction (`active_search.go`):** when
a generated query fails validation, errors in DuckDB, or returns all-NULL
projections, the failure and the real schema are fed back to the LLM, which
revises the SQL and re-runs it (bounded retries). Every attempt is recorded, so
the *error → revise → recover* sequence is auditable — directly addressing the
"Self-Correction" mandatory feature.

### 4.5 Tier 3 — DFIR report generator
`internal/tier3/`. Renders `synthesis.json` into a SANS-DFIR / NIST SP 800-86 /
ISO 27042-structured report (intrusion path, affected scope, chain-of-custody
with SHA-256, IOC table, MITRE map, recommendations, **AI-use disclosure**).

### 4.6 Unified, timestamped execution log
`internal/auditlog/` + emission across all tiers. Every signature hit, LLM call
(with token/cost), active-search SQL attempt, and self-correction retry is
appended — in true chronological order — to one per-case `actions.jsonl` that
the Audit tab renders. This is the agent execution log the rules ask for, and
the substrate for audit-trail review.

### 4.7 Confirmed-vs-inferred provenance labelling
Each finding is labelled **`confirmed`** (a deterministic Tier 1A signature
matched real logged events) or **`inferred`** (a Tier 1B LLM judgement), shown
in `synthesis.json`, the report's *Confidence* column, and the Review UI —
addressing the "distinguish confirmed from inferred" accuracy requirement.

### 4.8 Collection-completeness check
`internal/completeness/`. Distinguishes *"we looked and found nothing"* from
*"we could not look"* by reconciling expected detection inputs (EVTX channels,
artefacts) against what a case actually contains — a guard against silently
over-claiming coverage (anti-hallucination on the evidence side).

---

## 5. How the new work meets the mandatory features

| FIND EVIL! mandatory feature | TLVB component (new in §4) |
|---|---|
| **Self-Correction** | Tier 2 active-search error→revise→re-execute loop (§4.4), logged per attempt (§4.6) |
| **Accuracy Validation** (traceable to artefact/offset/log entry) | Every finding carries `audit_id` + `artifact_id`; confirmed-vs-inferred labels (§4.7); completeness check (§4.8) |
| **Analytical Reasoning** (structured narrative, not raw logs) | Tier 2 attack-chain synthesis → Tier 3 DFIR report (§4.4–§4.5) |

Architectural guardrails (favoured by the judging criteria) are enforced by
construction, not by prompt: the MCP surface is **read-only** (no
`execute_shell`, DB opened `access_mode=read_only`), active-search SQL is
**SELECT-only / single-bind / no-DDL** validated, and Tier 1A is **LLM-free at
runtime**.

---

## 6. Summary

`moai` and `TLVB` are two of the author's own projects, both built in the
window, sharing a parsing/storage base but realising **different agent
architectures** — tactic-agents vs. tiered build-time pre-bake with a learning
SQL cache and runtime self-correction. The components in §4 constitute TLVB's
new, documented contribution on top of the openly-disclosed foundation in §3.
