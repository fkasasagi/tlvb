"""Regression tests for parsers.orchestrator._bulk_insert_unified_events.

The bulk insert was rewritten from per-row ``executemany`` to a single
``read_json`` INSERT...SELECT (~150x faster on large $MFT/$UsnJrnl dumps).
These pin the behaviour that matters downstream: every JSONL line lands as one
row, the unified-event envelope columns are populated, ``payload`` survives as
extractable JSON text regardless of its per-artefact shape, and a blank /
unparseable timestamp becomes NULL instead of aborting the file.
"""

from __future__ import annotations

import json
import pathlib

import pytest

duckdb = pytest.importorskip("duckdb")  # skip where the runtime dep is absent

from parsers.orchestrator import (  # noqa: E402 — after importorskip guard
    _bulk_insert_unified_events,
    _ensure_schema,
)


def _con(tmp_path):
    con = duckdb.connect(str(tmp_path / "c.duckdb"))
    _ensure_schema(con)
    return con


def _write(tmp_path, events):
    p = tmp_path / "events.jsonl"
    with p.open("w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
    return p


def _event(**over):
    ev = {
        "artifact_id": "evtx",
        "audit_id": "a1",
        "timestamp": "2026-05-19 14:00:13.280973",
        "event_type": "windows_event",
        "computer": "HOST1",
        "payload": {"EventId": 4688, "Image": "C:\\x.exe"},
    }
    ev.update(over)
    return ev


def test_every_line_becomes_one_row(tmp_path):
    p = _write(tmp_path, [_event(audit_id=f"a{i}") for i in range(50)])
    con = _con(tmp_path)
    n = _bulk_insert_unified_events(con, "CASE", "EV", p)
    assert n == 50
    assert con.execute("SELECT count(*) FROM unified_events").fetchone()[0] == 50


def test_envelope_columns_and_payload_extract(tmp_path):
    p = _write(tmp_path, [_event()])
    con = _con(tmp_path)
    _bulk_insert_unified_events(con, "CASE", "EV", p)
    row = con.execute(
        """SELECT case_id, evidence_id, artifact_id, audit_id, event_type, computer,
                  json_extract_string(payload_json, '$.Image') AS image,
                  CAST(json_extract(payload_json, '$.EventId') AS INTEGER) AS eid
           FROM unified_events"""
    ).fetchone()
    assert row[0] == "CASE" and row[1] == "EV"
    assert row[2] == "evtx" and row[3] == "a1"
    assert row[4] == "windows_event" and row[5] == "HOST1"
    assert row[6] == "C:\\x.exe"
    assert row[7] == 4688


def test_timestamp_parsed_and_blank_becomes_null(tmp_path):
    p = _write(tmp_path, [
        _event(audit_id="good", timestamp="2026-05-19 14:00:13.280973"),
        _event(audit_id="blank", timestamp=""),
        _event(audit_id="missing", timestamp=None),
    ])
    con = _con(tmp_path)
    _bulk_insert_unified_events(con, "CASE", "EV", p)
    got = dict(con.execute(
        "SELECT audit_id, ts_utc FROM unified_events").fetchall())
    assert str(got["good"]).startswith("2026-05-19 14:00:13")
    assert got["blank"] is None
    assert got["missing"] is None


def test_heterogeneous_payload_shapes_preserved(tmp_path):
    # different artefacts carry totally different payload keys — all must survive
    p = _write(tmp_path, [
        _event(artifact_id="usn_journal", audit_id="u",
               payload={"Name": "doc.locked", "UpdateReasons": "RenameNewName"}),
        _event(artifact_id="registry", audit_id="r",
               payload={"KeyPath": "...\\Run", "ValueName": "X", "ValueData": "y"}),
    ])
    con = _con(tmp_path)
    _bulk_insert_unified_events(con, "CASE", "EV", p)
    name = con.execute(
        "SELECT json_extract_string(payload_json,'$.Name') FROM unified_events WHERE audit_id='u'"
    ).fetchone()[0]
    vd = con.execute(
        "SELECT json_extract_string(payload_json,'$.ValueData') FROM unified_events WHERE audit_id='r'"
    ).fetchone()[0]
    assert name == "doc.locked"
    assert vd == "y"
    # payload_json is NOT NULL — never empty
    assert con.execute(
        "SELECT count(*) FROM unified_events WHERE payload_json IS NULL OR payload_json=''"
    ).fetchone()[0] == 0


def test_missing_or_empty_file_returns_zero(tmp_path):
    con = _con(tmp_path)
    assert _bulk_insert_unified_events(con, "C", "E", tmp_path / "nope.jsonl") == 0
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    assert _bulk_insert_unified_events(con, "C", "E", empty) == 0
