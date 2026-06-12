# TLVB User Guide (for first-time users)

This document is a hands-on guide that lets you use TLVB even without a
security background.

*日本語版: [USER_GUIDE.ja.md](USER_GUIDE.ja.md)*

We avoid jargon in the main text where we can, and add explanations where
needed. Detailed definitions of the terms are collected in
**Appendix A: Glossary** at the end.
**Bold terms** in the main text are explained in the glossary.

---

## Table of Contents

- [1. What is TLVB?](#1-what-is-tlvb)
- [2. What can it do?](#2-what-can-it-do)
- [3. Try it in 5 minutes](#3-try-it-in-5-minutes)
- [4. Complete Web UI guide](#4-complete-web-ui-guide)
  - [4.1 Launching and accessing](#41-launching-and-accessing)
  - [4.2 Dashboard screen](#42-dashboard-screen)
  - [4.3 Case detail screen](#43-case-detail-screen)
  - [4.4 The pipeline (four steps)](#44-the-pipeline-four-steps)
  - [4.5 Findings tab — a list of what happened](#45-findings-tab--a-list-of-what-happened)
  - [4.6 Timeline tab — viewing chronologically](#46-timeline-tab--viewing-chronologically)
  - [4.7 IOC tab — a list of indicators](#47-ioc-tab--a-list-of-indicators)
  - [4.8 MITRE Map tab — a map of attacker techniques](#48-mitre-map-tab--a-map-of-attacker-techniques)
  - [4.9 Report tab — viewing and downloading the report](#49-report-tab--viewing-and-downloading-the-report)
  - [4.10 Audit tab — operation history](#410-audit-tab--operation-history)
- [5. You can do the same from the CLI](#5-you-can-do-the-same-from-the-cli)
- [6. Common troubleshooting](#6-common-troubleshooting)
- [Appendix A: Glossary](#appendix-a-glossary)
- [Appendix B: The big picture](#appendix-b-the-big-picture)

---

## 1. What is TLVB?

A tool that **automatically investigates the contents of a PC that may have
been the victim of a cyberattack**.

For example, when a company PC is suspected of having been compromised by
someone, an expert (a **forensics** practitioner) extracts the contents of
that PC and goes through the log files, configuration files, and so on one
by one.

This is time-consuming work; even for a veteran, a single case commonly
takes anywhere from a few days to a few weeks.

TLVB hands that **initial triage** off to an **AI agent** to automate it, so
that the human only needs to review the "things that look important."

```
[data from a PC suspected of being attacked] → [TLVB] → [list of suspicious points]
                                       ↓
                                  human review (approve/reject)
                                       ↓
                                  [investigation report (HTML/CSV/JSON)]
```

> **Key principle**:
> TLVB **never rewrites** the original evidence data.
> All output is written out to a separate location (`outputs/cases/<case-id>/`).
> This is to preserve a state in which the evidence can be used in a legal
> setting.

---

## 2. What can it do?

### Input

- **evidence data** extracted from a PC
  (a ZIP file, or an already-extracted directory)

### Output

| Output | Description |
|---|---|
| **Findings** | A list saying "here is some suspicious behavior" |
| **Timeline** | What events happened at what time, arranged chronologically |
| **IOC (Indicators of Compromise)** | The concrete values that are traces of an attack (suspicious IP addresses, file hashes, etc.) |
| **MITRE Map** | A map that fits the "attacker techniques" into an industry-standard taxonomy (**MITRE ATT&CK**) |
| **HTML report** | A human-facing report that brings all of the above together |
| **CSV / JSON** | Data for reuse in Excel or other tools |

### Work that is automated

It runs 10 kinds of investigation (in jargon, called a **Tactic** — i.e., a
category of things attackers do) in parallel.

| Number | Tactic | "What was the attacker trying to do?" |
|---|---|---|
| TA0001 | **Initial Access** | How did they get in? |
| TA0002 | **Execution** | What programs did they run? |
| TA0003 | **Persistence** | Did they plant a mechanism to stick around after reboot? |
| TA0004 | Privilege Escalation | Did they seize stronger privileges? |
| TA0005 | Defense Evasion | Did they try to erase their traces? |
| TA0006 | Credential Access | Did they steal passwords, etc.? |
| TA0007 | Discovery | Did they reconnoiter the internal network? |
| TA0008 | Lateral Movement | Did they move to another PC? |
| TA0009 | Collection | Did they gather data? |
| TA0040 | Impact | Did they encrypt or destroy data? |

In addition, the **Anomaly Hunter** looks for "something is off" behavior that
does not fit into the categories above.

---

## 3. Try it in 5 minutes

A sample case `INC-2026-0003` is already prepared, so you can look at the
screens right away.

### Step 1 — Start the web server

```bash
cd tlvb            # the root of the repository you git cloned
go build -o /tmp/tlvb ./cmd/tlvb
/tmp/tlvb serve --port 8080
```

> Leave the terminal you started it in open.
> To stop it, press `Ctrl-C`.

### Step 2 — Open it in a browser

If you launched it on a VM, access it from a browser on the **same VM**:

```
http://localhost:8080/
```

If you want to access it from the **host PC**, use the VM's IP address:

```bash
# Check the IP on the VM
hostname -I
# e.g.: 192.168.44.129
```

Open `http://192.168.44.129:8080/` in the host PC's browser.
(The numbers differ depending on your environment.)

### Step 3 — Open the sample case

A card for `INC-2026-0003` is shown on the dashboard screen, so **click** it.

When the case detail screen opens:

1. **Findings tab**: 50 findings, grouped by tactic
2. **Timeline tab**: what happened, arranged chronologically
3. **MITRE Map tab**: a bird's-eye, map-like view of attacker techniques
4. **Report tab**: the finished HTML report, viewable inside an iframe

That gives you a feel for it.

---

## 4. Complete Web UI guide

### 4.1 Launching and accessing

```bash
/tmp/tlvb serve --port 8080 [--db PATH] [--outputs DIR]
```

| Option | Default | Description |
|---|---|---|
| `--port` | `8080` | The port number to listen on |
| `--db` | `outputs/cases.duckdb` | The database file that stores case information |
| `--outputs` | `outputs/cases` | The per-case working directory |
| `--addr` | (empty) | Specify the bind address directly (e.g., `127.0.0.1:8080` to restrict to local only) |

> Security note: by default it listens on **all network interfaces**. Run it
> only in a trusted environment such as an internal network. Running it on a
> server directly exposed to the internet is not recommended.

### 4.2 Dashboard screen

URL: `http://<host>:8080/`

This is the first screen that opens. It has two sections.

#### New-case creation form (top)

| Field | Example | Description |
|---|---|---|
| Case ID | `INC-2026-0042` | A name that identifies the case. Matching it to an internal ticket number makes things easier to organize |
| Name | `Workstation alert from SOC` | A brief description of this case |
| Examiner | `tanaka` | The investigator's name (used later in the record of "who approved what") |
| Timezone | `UTC` | The timezone in which timestamps are displayed |
| Language | `ja` | The report language (`ja` = Japanese, `en` = English) |

Pressing "**Create case**" creates a new case.

#### Case list (bottom)

Each case is laid out as a card. The badges shown on a card:

| Badge | Meaning |
|---|---|
| `N evidence` | The number of registered evidence items |
| `N events` | The number of parsed events |
| `N findings` | The number of findings |
| `synth` | **Tier 2** (timeline synthesis) is complete |
| `report` | A report has been generated |
| `no parse yet` | Nothing has been processed yet |

Clicking a card takes you to that case's detail screen.

### 4.3 Case detail screen

URL: `http://<host>:8080/#/cases/<case-id>`

Screen layout:

1. **Header**: case ID, name, investigator, creation timestamp. A "Delete case" button in the top right
2. **Pipeline action bar**: four buttons (`Parse` → `Analyze All` → `Synthesize` → `Generate Report`)
3. **Tab bar**: six tabs (`Findings` / `Timeline` / `IOC` / `MITRE Map` / `Report` / `Audit`)

> **About deletion**: pressing "Delete case" removes the case information in
> the database and the working directory (`outputs/cases/<id>/`).
> The original evidence data (in a separate location) is left untouched.

### 4.4 The pipeline (four steps)

> **Features added 2026-05**:
> - **Parse multiple evidence at once** (Issue #1 / v0.3 #1) — in the Parse modal, the `+ Add evidence` button lets you add as many items as you like
> - **Auto-pilot toggle** (Issue #11/#12) — a "skip Review Gate 0" checkbox in the Parse / Analyze modals. When ON, it skips human review and proceeds to the next step
> - **Cancel button** (Issue #8) — while each step is running, an **`✕ cancel`** button appears below the progress block. You can abort partway through in case of a mistaken run or a runaway (the progress bar switches to a gray italic `canceled` display)
> - **Up-front LLM-access warning** — the moment you open the Analyze modal, a red warning appears if neither the `claude` CLI nor `ANTHROPIC_API_KEY` is present (previously this only surfaced after running)

The investigation has four steps. They must be run in order.

```
[Parse]  →  [Analyze All]      →  [Synthesize]   →  [Generate Report]
break down   Tier 1A signature   Tier 2 does       Tier 3 turns it
the evidence SQL                 timeline          into a report
             (+ optionally       synthesis
             Tier 1B)
```

Pressing each button opens a confirmation modal where you can specify
fine-grained options. To the right of the button, a status (`idle` /
`running...` / `ok` / `FAIL`) is shown in real time (auto-refreshed every
2 seconds).

#### Step 1: Parse

Breaks down the log files and configuration files contained in the evidence
data, each with its dedicated tool, and stores the results in the database.

Input modal:

| Field | Example |
|---|---|
| Evidence path | `./evtx-samples` (a folder or ZIP of evidence data) |
| Evidence ID | `EV-001` (auto-numbered if omitted) |

Processing time: depends on the amount of evidence data, but typically
5–30 minutes.

#### Step 2: Analyze All (analysis — Tier 1A + optionally Tier 1B)

**Tier 1A (signature)** always runs: it executes the rule corpus
(Sigma / Hayabusa / STIX / custom / LOLBAS), compiled into SQL at build time,
against this case, and turns hits into findings. **Because it does not call
an LLM, it is free and completes in seconds to tens of seconds.** Optionally,
you can also enable the **Tier 1B (anomaly_hunter)** LLM pass.

Input modal:

| Field | Description |
|---|---|
| Also run Tier 1B (anomaly_hunter, LLM) | When checked, the Tier 1B anomaly hunter also runs (incurs LLM charges). OFF by default |
| Tier 1B model | Leave empty for the claude CLI's default model |

> **Note**: Tier 1A needs no LLM and is free. Only when you enable Tier 1B
> does it call an AI model, so a token usage fee (around $1 per case) applies.

Processing time: Tier 1A ≈ seconds to tens of seconds, Tier 1B (when enabled)
≈ a few minutes.

#### Step 3: Synthesize (synthesis — Tier 2)

The **Tier 2 (timeline analysis agent)** clusters the Tier 1A / 1B findings
temporally, and an LLM analyzes the raw timeline around each cluster to infer
the **Kill Chain** (the flow of the attack), the overall story, and the MITRE
mapping. The output is `synthesis.json`.

Input modal:

| Field | Description |
|---|---|
| Active search | When checked, runs additional hypothesis-driven, wide-range SQL on the open questions of each cluster (more thorough, slower) |

> **Note**: Tier 2 calls an LLM, so a token usage fee applies (around $1 per
> case). If you want to use the older Synthesizer with its consistency checks
> (R1–R4) and Corrector, use the CLI with
> `tlvb synthesize CASE_ID --legacy [--correct]`.

Processing time: a few minutes depending on the number of clusters (increases
further when active search is enabled).

#### Step 4: Generate Report

Formats the synthesis result for humans.

Input modal:

| Field | Description |
|---|---|
| Language | `日本語` or `English` |
| Only approved | When checked, includes only the findings you approved in the Findings tab |

Processing time: a few seconds.

### 4.5 Findings tab — a list of what happened

In this tab, you review "the suspicious points TLVB found" one by one.
This is the **Examiner's (investigator's) main workspace**.

#### Display

Grouped by tactic, each finding carries the following information:

```
[high] T1543.003 — Create or Modify System Process: Windows Service
                                          F-persistence-001  [pending]

Suspicious Windows services were created on multiple hosts (spoolfool, msdhch, ...)

[expand] reasoning: the rationale for why it was judged so
[▸ N evidence rows] (click to expand)

[Approve] [Reject]
```

| Element | Description |
|---|---|
| **Red badge `high`** | High confidence (MUST review) |
| **Yellow badge `medium`** | Medium confidence (review if possible) |
| **Green badge `low`** | Low confidence (possible false positive) |
| **technique_id** | The MITRE ATT&CK **technique ID** (a clue for investigating) |
| **summary** | A summary of what happened |
| **reasoning** | The rationale the AI used to make that judgment |
| **evidence rows** | Click to expand and see the original logs that serve as evidence |
| **finding_id** | The ID of this finding (`F-<tactic>-<serial>`) |

#### Approve and Reject — the Review Gate

Each finding has two buttons:

- **Approve**: judge "this is a real compromise" → shown with a green border
- **Reject**: judge "this is a false positive / no problem" → shown with a red border
  - pressing it opens a **modal to enter a reason** (retained later for auditing)

> What a **Review Gate** is:
> a mechanism in which **a human reviews the AI's results before proceeding to
> the next stage**. By not over-trusting the AI and always leaving the final
> judgment to a human, it prevents false positives from slipping into the
> report.

The approval state is written back to the original
`findings/by-rule/<rule_source>/*.json` (Tier 1A) and
`findings/by-skill/*.json` (Tier 1B) files.
If you check "Only approved" when generating the report, only the approved
ones appear in the final report.

#### Bulk-selection mode (added 2026-05 — Issue #5/#10)

Approving 50+ findings one at a time is laborious, so a **checkbox-based bulk
operation** is available:

- there is a **checkbox** to the left of each finding row, and multiple selection is possible
- the header of a tactic group also has a **"select all" checkbox** that lets you bulk-select just that tactic
- after selecting, change them in bulk with **`Approve selected` / `Reject selected` / `Reset selected`** in the top toolbar
- the **`Approve all visible (N)`** button bulk-approves all currently displayed (post-filter) items

#### Filters (Issue #4)

With the **`all` / `pending` / `reviewed`** buttons in the toolbar:
- **all**: show all findings
- **pending**: show only un-reviewed ones
- **reviewed**: show only approved/rejected ones

You can switch filters while the selection state and scroll position are
preserved.

#### Undo (Issue #7)

For an approved/rejected finding, a **`Reset` button** appears on the right of
its row. Clicking it returns it to the pending state and the Approve/Reject
buttons appear again (a remedy for when you approve something by mistake).

#### Collapsing tactic groups (Issue #6)

Each tactic (Initial Access / Execution / Persistence, etc.) is displayed
**collapsed** by default. Click the header to expand/collapse. This change is
to keep scrolling under control with long findings lists.

### 4.6 Timeline tab — viewing chronologically

Displays "when, where, and what happened" in a chronological table.
Used to follow the flow of the attack.

#### Kill Chain diagram (top)

Following the `Initial Access → Execution → Persistence → ... → Impact` flow,
it lays out the earliest event at each stage with arrows.
It lets you grasp at a glance **in what order the attacker did what**.

#### Timeline table (bottom)

| Column | Contents |
|---|---|
| Timestamp | Time of occurrence (UTC) |
| Tactic | Which tactic it is classified under |
| Technique | The ID of the more specific technique |
| Computer | Which PC it happened on |
| Summary | A one-line statement of what happened |

The rows are arranged in time order.

### 4.7 IOC tab — a list of indicators

An **IOC (Indicator of Compromise)** is a "concrete value" that is a trace of
an attack. Examples:

- a suspicious IP address: `203.0.113.45`
- a suspicious domain: `evil-c2.example.com`
- a suspicious file hash: `sha256:abc123...`
- a suspicious file path: `C:\Users\Public\malware.exe`

IOCs are used when checking "have other PCs been hit by the same attack?" A
common usage is to feed these values into other PCs on the internal network,
or into a **SIEM** (security monitoring system), to scan for them.

#### Display

Grouped by type. Example types:

- `domain`
- `ipv4` (IP address)
- `sha256` / `sha1` / `md5` (file hashes)
- `file_path`
- `registry_key` (a Windows registry key)
- `service_name` (a Windows service name)

#### CSV download

Pressing the "Download CSV" button downloads all IOCs as a CSV file
(`iocs.csv`).

### 4.8 MITRE Map tab — a map of attacker techniques

**MITRE ATT&CK** is a knowledge base that catalogs "techniques attackers
commonly use" from attack cases around the world. It is the industry's de
facto standard.

In this tab, the findings that were discovered are mapped onto and displayed
on the ATT&CK map.

#### Display

```
TA0001 (Initial Access)    │ [T1133 (External Remote)] [T1190 (Public-Facing App)]
TA0002 (Execution)         │ [T1059.001 (PowerShell)] [T1204.002 (User Execution)]
TA0003 (Persistence)       │ [T1543.003 (Service)] [T1547.001 (Run Key)] ...
...
```

Each cell contains:

- **Technique ID**: a number such as T1543.003
- **Technique Name**: the name of the technique
- **count**: the number of findings and the number of evidence items
- **color**: red (high) / yellow (medium) / green (low) according to confidence

Clicking a cell takes you to the Findings tab.

### 4.9 Report tab — viewing and downloading the report

Once you run "Generate Report," you can view the result in this tab.

#### Buttons

| Button | Use |
|---|---|
| Open HTML | Open the HTML report in a separate tab |
| Findings CSV | Findings CSV (opens in Excel) |
| Timeline CSV | Timeline CSV |
| IOC CSV | IOC CSV |
| JSON | The full JSON data for machine processing |

#### iframe preview

The HTML report is embedded at the bottom.
The contents of the report include the following sections:

1. Executive summary
2. Scope of impact
3. Intrusion path (Kill Chain)
4. Attack timeline
5. List of findings (Tier 1A by rule_source, Tier 1B by skill)
6. Open questions and consistency checks
7. Recommended actions
8. IOC summary
9. MITRE ATT&CK mapping
10. Audit trail
11. Appendix: evidence details

### 4.10 Audit tab — operation history

Every process TLVB executed (parsing, analysis, etc.) is retained
chronologically.

| Column | Contents |
|---|---|
| Timestamp | When it was executed |
| Actor | Who (or what) executed it (e.g., `tier0-orchestrator`) |
| Kind | What kind of process it was (e.g., `parse`, `analyze`) |
| Body | Details (command, line count, elapsed time, etc.) |

With "Tier filter" you can narrow down by `tier0` (parse) / `tier1`
(analysis) / `tier2` (synthesis) / `tier3` (report).

> The audit log is an important record for proving "when, who, and what was
> done" in a legal setting. The original `outputs/cases/<id>/actions.jsonl` is
> stored in a one-event-per-line format.

---

## 5. You can do the same from the CLI

The Web UI is a wrapper around the backend REST API. You can also run the
same processes directly from the command line (handy when you want to
automate).

```bash
# Create a case
tlvb case init --case-id INC-2026-0042 --name "test case" --examiner tanaka

# Step 1: parse
tlvb parse --case-id INC-2026-0042 --evidence-id EV-001 --input ./evtx-samples

# Step 2: analysis — Tier 1A (signature SQL, no LLM)
tlvb analyze INC-2026-0042 --tier 1a
# optional: Tier 1B anomaly hunter (LLM)
tlvb analyze INC-2026-0042 --tier 1b --skill anomaly_hunter

# Step 3: synthesis — Tier 2 (LLM). --active-search for wide-range exploration too
tlvb synthesize INC-2026-0042

# Step 4: report — Tier 3
tlvb report INC-2026-0042 --format html,csv,json --language ja

# All steps at once (Tier 0→1A→1B→2→3)
tlvb run INC-2026-0042 --tier all --evidence ./evtx-samples --name "auto"

# Interactively Approve/Reject
tlvb review INC-2026-0042 --gate 1a --examiner tanaka
```

Help: `tlvb --help`

---

## 6. Common troubleshooting

### Q. I can't reach the VM's Web UI from the host PC's browser

- Check the VM's IP: `hostname -I`
- Confirm the host PC can ping that IP
- Access `http://<VM's IP>:8080/` from the host PC
- If it doesn't work, set up port forwarding for VMnet8 (NAT) in VMware's
  "Virtual Network Editor" (`Host port 8080 → VM IP:8080`)

### Q. The Parse button errors out

- Is the evidence data path correct?
- Is the path a directory visible from the VM? (paths on the host side cannot be specified)
- Are there analyzable files in the folder at that path?
  (Windows event logs `.evtx`, registry hives, Amcache, etc.)

### Q. Analyze fails immediately

- Parse must have completed first
- To use the `claude-code` engine, the `claude` command is required
- To use the `anthropic-api` engine, `export ANTHROPIC_API_KEY=sk-ant-xxx`

### Q. Synthesize says no findings were found

- No Analyze succeeded. Please rerun Analyze

### Q. Nothing shows up in the Findings tab

- Analyze has not completed yet
- Check the status of `Analyze All` in the pipeline bar

### Q. I want to redo the data from scratch

- On the dashboard, case card → detail → "Delete case"
- The working directory (`outputs/cases/<id>/`) is also deleted
- The original evidence data is left untouched

### Q. The AI seems to be wrong

- That is exactly why the Review Gate (Approve/Reject in the Findings tab) exists
- If you judge "this is wrong," record a **Reject + reason**
- If you enable "Only approved" when generating the final report, the rejected
  ones will not be included in the report
- If you want to undo a finding you once approved, you can return it to pending
  with the **Reset** button on its row (added 2026-05)

### Q. I want to stop the pipeline partway through

- An **`✕ cancel`** button appears below the progress block of each step (added 2026-05)
- Click → confirm → the job is aborted and goes to the `canceled` state
- DuckDB / partial output is left in place, so you can resume from the next Parse / Analyze

### Q. Doing `export ANTHROPIC_API_KEY=...` every time is a hassle

- If you create a `.env.local` file at the root of the repository and write `ANTHROPIC_API_KEY=sk-ant-...`, it is loaded automatically when `tlvb serve` starts (added 2026-05)
- A value explicitly `export`ed in the shell takes precedence, so a temporary override is also possible

---

## Appendix A: Glossary

Security and forensics jargon, in the order it appeared in this document.

### Basic concepts

| Term | Description |
|---|---|
| **Incident** | The unit of an event suspected to be a cyberattack. One TLVB "case" = one incident |
| **Incident Response (IR)** | The overall response activity when an incident occurs |
| **Forensics (Digital Forensics, DFIR)** | The technique of collecting and analyzing evidence left on a computer in a legally admissible form. Literally "digital forensics" |
| **Evidence** | The material used to judge whether an attack occurred. A copy of a hard disk, log files, memory dumps, etc. |
| **Chain of Custody** | The record of "whose hands the evidence passed through, and who did what and when." Essential for evidence to be accepted in court |
| **Read-Only** | The operational principle of **never rewriting** the original evidence files. TLVB upholds this too |

### How attacks work, and countermeasures

| Term | Description |
|---|---|
| **MITRE ATT&CK** | A catalog of attacker techniques published by MITRE Corporation (US). The industry-standard classification system |
| **Tactic** | The top-level category of ATT&CK. The "attacker's objective" (e.g., get in, stick around, steal information). TLVB handles 10 of them |
| **Technique** | A concrete means of achieving a tactic. E.g., T1543.003 is the "create a Windows service to stick around" technique |
| **Initial Access** | The technique used to first break into a system (phishing emails, exploiting vulnerabilities, etc.) |
| **Execution** | Running a malicious program after breaking in |
| **Persistence** | Planting a mechanism to stick around after reboot (auto-start registry, service registration, scheduled tasks, etc.) |
| **Privilege Escalation** | Escalating from a regular user to administrator privileges |
| **Defense Evasion** | Acts such as erasing logs, evading detection, and hiding traces |
| **Credential Access** | Stealing passwords and authentication tokens |
| **Discovery** | The act of investigating "what kind of environment is this?" (enumerating users, network reconnaissance, etc.) |
| **Lateral Movement** | Moving from one PC to another |
| **Collection** | The act of gathering the data to be exfiltrated |
| **Impact** | The final act of encrypting (ransomware), deleting, or destroying data |
| **Kill Chain** | The idea that an attack proceeds in stages, like "intrusion → persistence → privilege escalation → lateral movement → data theft." Originally proposed by Lockheed Martin |

### Types of evidence

| Term | Description |
|---|---|
| **EVTX** | The Windows event log file format. The `.evtx` extension. Logon history, service starts, PowerShell execution, etc. are recorded |
| **EventID** | The type number of an event within EVTX. E.g., `4624` = successful logon, `7045` = new service installed |
| **Sysmon** | A detailed-logging tool from Microsoft. Records process starts, network connections, file changes, etc. in fine detail |
| **Registry** | The Windows configuration database. Frequently abused as a place where malware plants auto-start entries |
| **Amcache** | A file in which Windows records "executables that have previously run on this PC." Traces of malware the attacker deleted can remain |
| **Prefetch** | A file in which Windows caches "recently executed programs" to speed up startup. Likewise useful for after-the-fact tracking |
| **Shimcache (AppCompatCache)** | The Windows application-compatibility database. Traces of executed .exe files remain |
| **MFT (Master File Table)** | The table of contents of the NTFS file system. Information about deleted files also partially remains |
| **USN Journal** | NTFS's file-change history. You can tell "when which file was created/deleted" |

### Analysis-related

| Term | Description |
|---|---|
| **IOC (Indicator of Compromise)** | A concrete value that identifies an attack (IP address, domain, hash, file path, etc.) |
| **Hash** | A short string computed from a file (SHA-256, MD5, etc.). Used to determine whether two files are the same |
| **C2 / C&C (Command and Control)** | A server attackers use to remotely operate the breached host. C2 domains/IPs are shared as IOCs |
| **TTP (Tactics, Techniques, Procedures)** | The three-level hierarchy of ATT&CK that represents an attacker's behavior patterns |
| **Sigma** | A generic format for writing rules to detect attacks from logs |
| **YARA** | A rule format for describing malware file patterns. Searches for specific strings/byte sequences within a binary |
| **Timeline** | Data arranging "what happened when" chronologically. Built by merging multiple pieces of evidence by time |
| **Plaso / log2timeline** | The standard tool for combining many kinds of evidence into a single timeline |

### Monitoring/detection-related

| Term | Description |
|---|---|
| **SIEM (Security Information and Event Management)** | A monitoring system that collects logs from various internal devices and performs correlation analysis. Splunk, Elastic SIEM, QRadar, etc. |
| **EDR (Endpoint Detection and Response)** | Software that resides on each PC and monitors behavior. CrowdStrike, SentinelOne, Defender for Endpoint, etc. |
| **SOC (Security Operations Center)** | The team/department that performs security monitoring |
| **Detection rule** | A rule that says "raise an alert when a log matching this condition appears" |
| **False Positive (FP)** | Judging something as an attack when it is not |
| **False Negative (FN)** | Missing an attack when it is one. TLVB aims to reduce these with AI + the Review Gate |

### TLVB-specific terms

| Term | Description |
|---|---|
| **Tier 1A (signature)** | Compiles the rule corpus (Sigma / Hayabusa / ATT&CK STIX / custom / LOLBAS) into SQL **at build time** (`tlvb rules build`), and **at runtime** merely runs the cached SQL (zero LLM). A hit = a finding |
| **Tier 1B (anomaly hunter)** | The skills in `skills/*.md` execute SQL → an LLM infers abstract anomalies together with the Tier 1A findings, and devises new queries if needed (the cache grows). Default skill = anomaly_hunter (tactic skills are opt-in via `--skill`) |
| **Anomaly Hunter** | The default Tier 1B skill. Looks for "something is off" behavior that does not match existing rules |
| **finding** | Tier 1A is saved to `findings/by-rule/<rule_source>/<rule_id>.json`, Tier 1B to `findings/by-skill/<skill>.json` |
| **rule_source** | The origin of a Tier 1A rule: `sigma` / `hayabusa` / `stix` / `custom` / `lolbas`. The primary key is `(rule_id, rule_source)`, and rule_id preserves the upstream original ID |
| **Tier 2 (timeline analysis)** | Clusters the Tier 1 findings, and an LLM analyzes the ±N-minute raw timeline of each cluster. With `--active-search`, it also runs hypothesis-driven, wide-range SQL. Output = `synthesis.json` (clusters + overall_story + mitre_mapping + open_questions) |
| **Tier 3 (reporter)** | Generates an HTML / CSV / JSON DFIR report from `synthesis.json` + findings (zero LLM) |
| **Review Gate** | The human review between each Tier. Gate 0 (parse) / **1A** (signature findings, auto-approved by severity) / **1B** (anomaly findings) / 2 (timeline) |
| **Examiner** | The investigator (you, the user). Approve/reject operations are recorded under the Examiner's name |
| **Tier 0/1/2/3** | TLVB's processing layers. **Tier 0** = parsers / **Tier 1A** = signature SQL (LLM=0) / **Tier 1B** = skill anomaly (LLM) / **Tier 2** = timeline analysis + synthesis (LLM) / **Tier 3** = report (LLM=0) |
| **legacy (moai)** | The old implementation's Tactic Agent / TacticReport / Synthesizer / Corrector. Currently opt-in via `tlvb synthesize --legacy` / `report --legacy` (the default is tier2/tier3) |
| **audit_id** | The ID (hash) of an individual log event. Lets a finding uniquely point to "which log it is based on" |

### Tools/files-related

| Term | Description |
|---|---|
| **MCP (Model Context Protocol)** | A standard protocol for AI agents to call external tools. Used internally by TLVB |
| **EZ Tools** | Eric Zimmerman's suite of analysis tools, widely used in the forensics field. EvtxECmd, AmcacheParser, RECmd, etc. |
| **SIFT Workstation** | A forensics-specific Linux environment (Ubuntu-based) provided by the SANS Institute. TLVB's assumed operating environment |
| **DuckDB** | The embedded database TLVB uses to store event data (similar to SQLite, but analytics-oriented) |

---

## Appendix B: The big picture

### Processing flow

```
┌────────────────────────────────────────────────────────────────────┐
│                     user                                            │
│  ┌────────┐                                                         │
│  │ browser │ ⇄ http://localhost:8080/                               │
│  └────────┘                                                         │
└────────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────────────┐
│  tlvb serve  (Go binary — UI is embedded too)                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │ REST API     │  │ JobsManager  │  │ Embedded UI (HTML/CSS/JS)│  │
│  │ /api/cases   │  │ (goroutine)  │  │ /static/app.js etc.      │  │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────────────┐
│  Tier 0:  Parser orchestrator (Python + EZ Tools)                  │
│           ↓ convert evidence files into structured data (unified_events) │
│  Tier 1A: Signature SQL (cached rules → DuckDB, zero LLM)           │
│           ↓ output hits to findings/by-rule/                        │
│  Tier 1B: Anomaly Hunter skill (Claude, LLM, optional) → by-skill/  │
│  Tier 2:  Timeline Analysis Agent (Claude) → synthesis, timeline, KC│
│  Tier 3:  Reporter (Go) → HTML/CSV/JSON DFIR report (zero LLM)      │
└────────────────────────────────────────────────────────────────────┘
                            │
                            ▼
        outputs/cases/<case-id>/                      outputs/cases.duckdb
        ├── findings/*.json   ← findings by tactic     (DB of all events)
        ├── synthesis.json    ← synthesis result
        ├── reports/          ← HTML/CSV/JSON report
        └── actions.jsonl     ← audit log
```

### Web UI page hierarchy

```
/  (dashboard)
└─ #/cases/<id>  (case detail)
   ├─ ?tab=findings   (findings + Approve/Reject)
   ├─ ?tab=timeline   (chronological + Kill Chain)
   ├─ ?tab=iocs       (indicators of compromise)
   ├─ ?tab=mitre      (MITRE ATT&CK map)
   ├─ ?tab=report     (HTML/CSV/JSON report)
   └─ ?tab=audit      (operation history)
```

### Review Gates (human intervention points)

```
Tier 0 ─→ [Gate 0] ─→ Tier 1A/1B ─→ [Gate 1A/1B] ─→ Tier 2 ─→ [Gate 2] ─→ Tier 3
            ↑                       ↑                       ↑
            review the              Approve/Reject          review the
            parser results          the findings           timeline
                                    (Findings tab)
```

What is implemented in the current Web UI is mainly **Gate 1** (Approve/Reject
in the Findings tab).

---

**For questions or improvement requests, please use a GitHub Issue or
`examiner@example.com`.**
