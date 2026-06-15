# TLVB — Accuracy Report

*Prepared for the FIND EVIL! judges.* This is TLVB's self-assessment of
**detection accuracy, false positives, misses, and hallucination**, and of how
the system approaches **evidence completeness**. Figures come from runs against
**solved** datasets (the ground-truth answer key is known), so every claim is
checked against the intended scenario rather than asserted.

> Scope note: TLVB targets **Windows host forensics** (EVTX, MFT, USN, registry,
> amcache, prefetch, shellbags, LNK, …). Memory and network captures are out of
> scope for this submission; we say so rather than over-claim.

---

## 1. Headline

- Across three solved datasets, TLVB **detected every attack step that is
  technically detectable from the collected evidence.** The few misses trace to
  **data gaps** (a log channel was never collected) or **file-only artefacts**,
  not to detection-logic errors — and TLVB reports those gaps explicitly.
- The hand-authored forensic rules carry **regression tests with negative
  examples**; on real data they fire with **zero false positives**.
- **Hallucination is bounded by construction:** the signature tier is
  deterministic SQL (a match exists in the data or it does not — nothing is
  invented), and the LLM tiers carry NULL-result / self-correction guards plus a
  `confirmed` vs `inferred` label so machine-confirmed evidence is never
  conflated with model inference.

---

## 2. Detection results (solved datasets)

| Dataset | Form | Ground truth | TLVB result |
|---|---|---|---|
| `WINDEV triage` (WinDev2407Eval) | triage collection | 8-step scenario | **All detectable steps covered** — strong on S1/S2/S3/S5/S7/S8, S6 corroborated (medium). Only miss **S4 (C2)**: the DNS-Client / PowerShell-Operational channels **were never collected** → physically undetectable (a data gap, not a logic gap). |
| `findevil-win11.E01` | full disk image | 8-step scenario | **12 / 13 under a strict scoring criterion.** S1–S3, S5, S7, S8 all ✅; S4 (C2) detected here via a new reserved-TLD PowerShell rule (the E01 retained the DNS NXDOMAIN + PowerShell-4104 C2 traces the triage lacked); scheduled-task masquerade raised to high. 101 Tier 1A findings (sigma 53 + hayabusa 42 + custom 7). |
| `findevil-ad` (DC01 + WS01) | 2 split-EWF images | 12 detection points (LNK → full domain compromise) | **11 / 12 (92 %).** 126 Tier 1A findings (sigma 68 + hayabusa 54 + custom). Two gaps closed during testing with new rules (hidden-PowerShell scheduled task; NTDS.dit exfil to a writable path), each **FP 0**. Remaining miss **#5 (loot.txt)** is a *file-only* artefact; the credential-access it stages is itself caught by #4/#7. |
| `winrm_spray` (`dc03.E01`) | full disk image | 5-step WinRM intrusion where **credential theft is BLOCKED** by Defender/AMSI | **All 5 detectable steps covered, and the over-claim test PASSED.** Single-account brute-force → WinRM remote exec → recon burst → LSASS-dump *attempt* → WMI persistence all detected; crucially the theft is judged **not successful** ("no evidence the dump itself succeeded"), and the benign Set-Date/provisioning clock-step is **not** misread as attacker time-stomping. Precision caveats (honestly logged): a few provisioning-noise techniques leak into the *confirmed* MITRE map, one anomaly finding over-reads benign jumplists as "collection staging," and the attacker workstation `WS01` is named in prose but missing from the structured IOC export. Full write-up → [`eval/winrm_spray_accuracy.md`](../eval/winrm_spray_accuracy.md). |

**Why the misses are honest, not hidden:**
- **`WINDEV` S4** — the C2 evidence lives in EVTX channels that the triage tool
  never captured. TLVB's `internal/completeness` check surfaces exactly this:
  it reports PowerShell-Operational / DNS-Client as **MISSING**, so the absence
  reads as *"could not look"*, not *"looked and found nothing."*
- **`findevil-ad` DC01** — Process Creation (4688), File Share (5140) and
  Directory-Service-Change (5136) auditing were **disabled** on the DC, and no
  Golden Ticket was used (so no 4769). Those events do not exist in the
  evidence; the scenario's own answer key marks them undetectable. This is an
  auditing-policy limitation of the victim host, not a TLVB inaccuracy.

---

## 3. False positives

The signature corpus (Sigma / Hayabusa / STIX) plus **10 hand-authored forensic
SQL rules** (`rules/built/custom.sql.jsonl`) cover non-EVTX artefacts. Each
custom rule is pinned by a regression test
(`tests/rules/test_custom_forensic_rules.py`) that asserts the **exact** set of
matched `audit_id`s against a synthetic `unified_events` fixture, and **embeds
negative examples / known false-positive bait**, e.g.:

- OneDrive under a user path **must not** trip the Run-key masquerade rule.
- `eventbeacons.dat` / `SubmissionPayload.json` deletions **must not** trip the
  hacktool self-deletion rule.
- `publicize.exe` (Program Files) and `claude.exe` (Roaming) **must not** trip
  the world-writable-execution rule.
- Legitimate `\Windows\NTDS\`, System32, WinSxS paths **must not** trip the
  NTDS.dit-exfil rule.

On the real solved datasets these rules fire cleanly — e.g. NTDS.dit-exfil 1 hit
/ FP 0, hidden-PowerShell-task 12 hits / FP 0, reserved-TLD-C2 14 hits / FP 0,
scheduled-task-masquerade 4 hits / FP 0, world-writable-execution 2 hits / FP 0.

**Over-fitting guard (a rejected rule).** A timestamp-manipulation heuristic
(`$SI` created < `$FN` created) was *evaluated and rejected*: on a real `$MFT`
it was **True for 60.6 % (≈278 k records) — normal Windows behaviour** — so as a
Tier 1A rule it would have produced mass false positives. It was dropped after
checking real data instead of trusting the hypothesis.

---

## 4. Hallucination self-assessment

TLVB separates *deterministic* detection from *generative* reasoning so an LLM
can never silently fabricate a finding:

- **Tier 1A (signature) is LLM-free at runtime.** It executes pre-compiled SQL;
  a hit is a row that exists in `unified_events`. There is no text generation in
  the loop, so a Tier 1A finding cannot be hallucinated — only the rule's
  *interpretation* is a heuristic, which is why findings still require review.
- **Tier 2 active-search rejects "executed-but-useless" answers.** A query that
  runs but returns rows whose projected columns are all NULL (the classic wrong
  JSON-path mistake) is flagged **failed**, its evidence discarded, and the
  interpretation step is told *"a result with an error field FAILED — do not
  treat its NULL values as evidence."* The same failure drives the
  **self-correction** loop instead of being narrated as a fact.
- **A 0-row query is an honest negative, never a fabricated one.** When an
  active-search query runs cleanly but matches nothing, TLVB does not invent an
  answer: the agent judges whether "nothing here" is the genuine result or a
  wrong-angle query and, if the latter, **re-sequences** to a different
  artifact/field/hypothesis (an `active_search_reframe`); otherwise the gap is
  recorded as an open question. On a real triage case this re-sequencing fired
  **six times unprompted** (no fault injection) — e.g. a query found 0 rows and
  the pivoted retry found 51 events — demonstrating genuine runtime course
  correction rather than confident guessing (see `EXECUTION_LOG.md` §5).
- **`confirmed` vs `inferred` labels.** Every finding is tagged `confirmed` (a
  deterministic signature matched real logged events) or `inferred` (a Tier 1B
  LLM judgement), shown in the report's *Confidence* column and the Review UI,
  so a reader never mistakes an inference for established fact.
- **Open questions are first-class.** Unresolved points are recorded as
  `open_questions` in the synthesis rather than papered over with a confident
  narrative.

Residual risk: the Tier 2 **narrative** is LLM-written and can still
mis-characterise causality even when every cited `audit_id` is real (observed
once: a staged `loot.txt` was correctly surfaced but initially read as a
training-range artefact). This is mitigated by citing audit_ids, the
confirmed/inferred split, and the mandatory human Review Gate — not eliminated.

---

## 5. Evidence completeness & integrity

- **Traceability.** Every finding is backed by `audit_id` + `source_artifact`
  (+ timestamp); the Tier 3 report lists per-evidence **SHA-256** and a
  chain-of-custody section.
- **Completeness vs. detection failure.** `internal/completeness` keeps a
  catalogue of detection-relevant inputs (EVTX channels: Security / System /
  PowerShell-Operational / DNS-Client / Sysmon / TaskScheduler; Tier 0
  artefacts: USN / MFT / amcache / registry / prefetch / shellbags / LNK /
  browser) and reports, per case, which are **present** vs **MISSING** — so an
  empty result is never silently read as "clean."
- **Execution log.** Every tool execution, LLM call (with token/cost), SQL
  attempt and self-correction retry is appended to one timestamped
  `actions.jsonl`, giving an auditable trail from raw evidence to conclusion.

---

## 6. Reproducibility

Tier 1A is deterministic: the same case against the same SQL cache yields the
same signature findings on every run, at a fixed (LLM-free) runtime cost. The
LLM tiers record their model id and token/cost in the synthesis audit and in
`actions.jsonl`, so a reviewer can see exactly where generative reasoning was
used and what it cost.

See `NEW_CONTRIBUTIONS.md` (what is new), `docs/ARCHITECTURE.md` (how it fits
together), and `docs/STATUS.md` (per-feature status).
