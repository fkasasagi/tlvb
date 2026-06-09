# Evidence Datasets

> **FIND EVIL! deliverable ⑦ — what TLVB was tested on, where it came from, and
> what TLVB found.** The primary dataset is the **findevil-ad** Active Directory
> compromise scenario: two acquired disk images with a complete, machine-readable
> ground-truth answer key. Detection accuracy (true/false positives, misses,
> hallucination) is reported separately in [`ACCURACY.md`](ACCURACY.md); this
> document is the dataset **provenance, scenario, and answer-key map**.

## Datasets at a glance

| Dataset | Hosts / format | Ground truth | Result |
|---|---|---|---|
| **findevil-ad** (primary) | DC01 + WS01, two split-EWF disk images | full answer key (per-step timestamps, MITRE, event-log records) | **11 / 12 detection points (92 %)** — see `ACCURACY.md` |
| WINDEV triage | single Win11 triage collection | all detectable steps | see `ACCURACY.md` |
| findevil-win11.E01 | single Win11 disk image | answer key | **12 / 13 (strict)** — see `ACCURACY.md` |

The rest of this document details **findevil-ad** (the one the examiner pointed
TLVB at). The other two are summarised in `ACCURACY.md` §detection-results.

---

## 1. findevil-ad — Active Directory compromise scenario

### 1.1 What it is

A purpose-built two-host Active Directory range (`corp.local`) in which an
LNK-borne initial compromise escalates to **full domain takeover** in three
stages over ~10 minutes.

| Item | Value |
|---|---|
| Domain | `corp.local` |
| DC01 | Windows Server 2022 — `192.168.50.10` |
| WS01 | Windows 11 Enterprise Eval (WinDev2407Eval) — `192.168.50.20` |
| Attacker account | `CORP\taro.yamada` (a normal Domain User) |
| Activity window | 2026-06-02 23:24:41 – 23:34:27 JST (+09:00) |
| Package id | `findevil-ad-20260602` |

### 1.2 Provenance & acquisition (chain of custody)

The range was **built by the project author** for TLVB validation (it is not a
third-party/public corpus). Both hosts were imaged at rest after all three
attack stages completed.

| Host | Source size | EWF segments | Imager | MD5 | SHA-1 | Verified |
|---|---|---|---|---|---|---|
| **DC01** | 61,440 MB (physical) | `.E01`–`.E05` | FTK Imager 4.7.1.2 | `926f416f1383b8a12adeb09d4af400b4` | `fa031de1fd612dbac11b28e5ab356f7123be49b6` | ✅ MD5+SHA-1 re-verified post-acquisition |
| **WS01** | 128,000 MB (physical) | `.E01`–`.E22` | FTK Imager 4.7.1.2 | `8d2a04376a42426cafb4189638670cc3` | `9386abebf47141f03be394291bd86751826d2037` | ✅ MD5+SHA-1 re-verified post-acquisition |

- Acquisition metadata (case number `findevil-ad-20260602`, examiner, segment
  list, verification log) ships beside each image as `<host>.E01.txt`.
- **Integrity in TLVB:** originals are never modified — `image_extractor.py`
  mounts the EWF read-only and copies out only a triage subset; the case DuckDB
  is opened `access_mode=read_only` at analysis time (see
  [`SECURITY_GUARDRAILS.md`](SECURITY_GUARDRAILS.md)). TLVB additionally records a
  **SHA-256** of each registered evidence item so the Tier 3 report carries a
  chain-of-custody section independent of the acquisition MD5/SHA-1 above.

### 1.3 Running it (placement-agnostic)

The image set can live **anywhere** — pass the **first EWF segment** (`*.E01`)
to TLVB and it follows the `.E0N` chain automatically. Analyse both hosts as a
single case with two evidence items:

```bash
# <DATASET> = wherever you placed the findevil-ad-20260602 image set
./bin/tlvb run AD-CASE --evidence <DATASET>/dc01/dc01.E01 --evidence-id DC01
./bin/tlvb parse  AD-CASE --evidence <DATASET>/ws01/ws01.E01 --evidence-id WS01
# (or: case init → parse per evidence → analyze --tier 1a/1b → synthesize → report)
```

The ground-truth files live under `<DATASET>/groundtruth/` (see §1.5) and are
**not** fed to TLVB — they are the answer key for scoring only.

### 1.4 The attack (3 stages)

Timestamps are the ground-truth step markers (JST). Full per-step detail is in
`groundtruth/scenario_ad_groundtruth.md`.

**Stage 1 — Initial Access → Lateral Movement (WS01), 23:24–23:25**
LNK `invoice_2026Q2.pdf.lnk` run via `explorer.exe` → encoded PowerShell →
persistence (Run key `…\sysupdate\svchost.exe` + scheduled tasks `UpdateCheck`,
`Sysinfo`) → domain/account/trust/remote discovery → **LSASS dump** (`procdump64
-ma lsass.exe`, 66.5 MB) + `mimikatz sekurlsa::logonpasswords` → SMB sweep of
DC01 shares → reads `handover_memo_old.txt` from `\\DC01\IT_Shared`, saves
`loot.txt` (Administrator creds).

**Stage 2 — Privilege Escalation → Domain Compromise (WS01→DC01), 23:30–23:31**
PSSession to DC01 as `CORP\svc_backup` → `lsadump::lsa /patch` dumps **all**
domain NTLM hashes (Administrator/krbtgt/taro.yamada/svc_backup/DC01$/WS01$) →
**Golden Ticket generated** (`kerberos::golden`, but never used) → creates domain
user `backdoor_admin` and adds it to **Domain Admins** (23:31:02).

**Stage 3 — Exfiltration + DC01 Persistence (WS01→DC01), 23:33–23:34**
PSSession to DC01 as `Administrator`, copies `mimikatz.exe` → second
`lsadump::lsa` on DC01 → **VSS snapshot** `{5AE815AD-…}` → copies **`NTDS.dit`
(16 MB) + SYSTEM hive**, transfers `NTDS.dit` back to WS01 → DC01 SYSTEM
scheduled task `…\WindowsUpdate\SysCheck` (ONSTART) → changes AD Administrator /
DSRM password → deletes temp files (anti-forensics).

### 1.5 Ground-truth answer key

`<DATASET>/groundtruth/`:

| File | What it is |
|---|---|
| `scenario_ad_groundtruth.md` (617 lines) | the authoritative answer key: per-step story, exact timestamps, **MITRE technique per step**, DC01 event-log records (4624/4688/4698/4720/4728/4724, LogonType analysis, VSS), and "additional findings" (why Golden Ticket leaves no 4769, why DC01 4688 is absent, how taro.yamada reached C$). |
| `groundtruth_stage{1,2,3}_*.csv` | machine-readable step timeline (`Timestamp,Phase,Action`) — one row per attacker action, used for precise scoring/temporal checks. |

**12 named detection points** (from the dataset README), with the host and the
backing artefact:

| # | Detection point | Host | Artefact |
|---|---|---|---|
| 1 | LNK initial access | WS01 | `invoice_2026Q2.pdf.lnk` (Zone.Identifier ZoneId=3) |
| 2 | Persistence — Run key | WS01 | `HKCU\…\Run\SystemUpdate` |
| 3 | Persistence — scheduled task | WS01 | `UpdateCheck` / `Sysinfo` |
| 4 | LSASS dump | WS01 | `lsass.dmp` (66.5 MB) / `procdump64.exe` |
| 5 | Credential theft (loot) | WS01 | `loot.txt` / `handover_memo_old.txt` |
| 6 | PSSession (svc_backup) | DC01 | Security 4624 (23:30:23–) |
| 7 | `lsadump::lsa` | DC01 | Security 4624 (Administrator, 23:30:24–) |
| 8 | `backdoor_admin` created | DC01 | Security 4720/4724/4728 (23:31:02) |
| 9 | NTDS.dit exfiltration | WS01 | `ntds.dit` (16 MB) / `SYSTEM` hive |
| 10 | DC01 persistence task | DC01 | `SysCheck` (SYSTEM / ONSTART) |
| 11 | AD password change | DC01 | Security 4724 (23:34:22) |
| 12 | Anti-forensics cleanup | DC01 | temp-file deletion |

**MITRE ATT&CK techniques exercised (17):** T1566.001, T1204.002, T1059.001,
T1547.001, T1053.005, T1087.002, T1482, T1018, T1003.001, T1021.002, T1558.001,
T1136.002, T1098.007, T1021.006, T1003.003, T1098, T1070.

### 1.6 What TLVB found

Full scoring is in [`ACCURACY.md`](ACCURACY.md). Summary: **11 / 12 (92 %)**,
126 Tier 1A findings (Sigma 68 + Hayabusa 54 + custom). The single miss is **#5
(loot.txt)** — a *file-only* artefact; the credential-access it stages is itself
caught by #4 and #7. Two gaps surfaced during testing were closed with new
**custom forensic rules** (hidden-PowerShell scheduled task; NTDS.dit exfil to a
user-writable path), each with **0 false positives** on this data.

### 1.7 Known detection limits (data gaps, not logic gaps)

These are stated up front so a miss is read as a **collection gap** — which
`tlvb completeness` surfaces explicitly — rather than a TLVB failure:

- **DC01 audit policy** disabled *Process Creation* (no 4688 for
  mimikatz/schtasks), *File Share* (no 5140 for SMB), and *Directory Service
  Changes* (no 5136). Those events simply do not exist in the image.
- **Golden Ticket** was generated but **never used**, so no 4769 exists; only the
  `mimikatz` execution is observable from Windows logs. Not detecting ticket use
  is correct, not a miss.

### 1.8 Out-of-scenario artefacts

`C:\Tools\findevil_kit\` on WS01 holds the **operator's** orchestration scripts
and logs used to *build* the scenario — not attacker activity. Per the dataset
README: attacker-used payloads (`mimikatz.exe`, `procdump64.exe`, `svchost.exe`)
are in-scenario; `create_lnk.ps1`, `run_all_stage*.ps1`, and
`output\groundtruth_*.csv`/`*.log` are operator tooling and should not be scored
as findings.

---

## 2. Other validation datasets

Two single-host datasets corroborate the host-artefact coverage; their scoring
lives in [`ACCURACY.md`](ACCURACY.md):

- **WINDEV triage** — a Windows 11 triage collection; every *collected* attack
  step is detected (the one undetectable step is on an uncollected channel).
- **findevil-win11.E01** — a full Windows 11 disk image; **12 / 13 strict**, the
  miss traced to a file-only artefact.
