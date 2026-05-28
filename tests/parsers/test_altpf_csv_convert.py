"""Tests for parsers.prefetch_parser altpf primary path (Issue #27).

altpf is the new primary engine (replaces Plaso as primary; Plaso is now
the fallback when altpf fails). These tests cover:

  - CSV→UnifiedEvent conversion produces one event per LastRun + each
    non-blank PreviousRunN.
  - Blank PreviousRun slots are skipped (Windows leaves them zero-init).
  - Timestamp parsing handles altpf's default `%Y-%m-%d %H:%M:%S` layout
    and degrades to empty string on garbage.
  - The PECmd-compatible CSV column order is consumed correctly.

Real altpf binary execution is exercised in docs/TEST_FEATURES.csv F2-03.
These tests focus on the in-process conversion + helpers.
"""

from __future__ import annotations

import pathlib

import pytest

from parsers.base import ParseRequest
from parsers.prefetch_parser import (
    ARTIFACT_ID,
    _altpf_ts,
    _convert_altpf,
    _csv_row_count,
    _find_altpf_csv,
)


_HEADER = (
    "SourceFile,SourceFilename,SourceCreated,SourceModified,SourceAccessed,"
    "ExecutableName,Hash,Size,Version,RunCount,"
    "LastRun,PreviousRun0,PreviousRun1,PreviousRun2,"
    "PreviousRun3,PreviousRun4,PreviousRun5,PreviousRun6,"
    "Volume0Name,Volume0Serial,Volume0Created,"
    "Volume1Name,Volume1Serial,Volume1Created,"
    "Directories,FilesLoaded,ParseError"
)


def _make_csv(tmp_path: pathlib.Path, body: str,
              name: str = "20260516120000_altpf_Output.csv") -> pathlib.Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def _req(case_id: str = "T", evid: str = "E") -> ParseRequest:
    return ParseRequest(
        input_path=pathlib.Path("/dev/null"),
        output_dir=pathlib.Path("/dev/null"),
        case_id=case_id, evidence_id=evid,
        timezone="UTC",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_altpf_ts_iso_normalisation():
    assert _altpf_ts("2026-02-14 13:07:13") == "2026-02-14 13:07:13"


def test_altpf_ts_strips_whitespace():
    assert _altpf_ts("  2026-02-14 13:07:13  ") == "2026-02-14 13:07:13"


@pytest.mark.parametrize("bad", ["", "garbage", "2026/02/14", "not-a-date"])
def test_altpf_ts_empty_or_garbage_returns_empty(bad):
    assert _altpf_ts(bad) == ""


def test_find_altpf_csv_picks_latest_by_suffix(tmp_path):
    (tmp_path / "20260515120000_altpf_Output.csv").write_text(_HEADER + "\n")
    (tmp_path / "20260516120000_altpf_Output.csv").write_text(_HEADER + "\n")
    found = _find_altpf_csv(tmp_path, suffix="_altpf_Output.csv")
    assert found is not None
    assert found.name == "20260516120000_altpf_Output.csv"


def test_find_altpf_csv_returns_none_when_missing(tmp_path):
    assert _find_altpf_csv(tmp_path, suffix="_altpf_Output.csv") is None


def test_csv_row_count_counts_data_rows_only(tmp_path):
    p = _make_csv(tmp_path, _HEADER + "\nA,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z,err\n")
    assert _csv_row_count(p) == 1


def test_csv_row_count_handles_missing_file(tmp_path):
    assert _csv_row_count(tmp_path / "nope.csv") == 0
    assert _csv_row_count(None) == 0


# ---------------------------------------------------------------------------
# _convert_altpf — main conversion logic
# ---------------------------------------------------------------------------


def test_convert_altpf_emits_one_event_per_run_timestamp(tmp_path):
    """LastRun + 3 PreviousRunN → 4 UnifiedEvents."""
    row = ",".join([
        "/path/CHROME.EXE-AED7BA3C.pf",
        "CHROME.EXE-AED7BA3C.pf",
        "2026-02-14 13:07:13", "2026-02-14 13:07:13", "2026-02-14 13:07:13",
        "CHROME.EXE", "0xAED7BA3C", "100000", "Windows 11", "5",
        "2026-02-14 13:07:13",
        "2026-02-13 09:12:00", "2026-02-12 18:30:00", "2026-02-11 12:00:00",
        "", "", "", "",
        "\\VOLUME{a}", "0xCAFE", "2020-09-27 04:32:04",
        "", "", "",
        '"WINDOWS"', '"NTDLL.DLL"', "",
    ])
    p = _make_csv(tmp_path, _HEADER + "\n" + row + "\n")
    events = list(_convert_altpf(p, _req()))
    assert len(events) == 4
    run_kinds = sorted(e["payload"]["run_kind"] for e in events)
    assert run_kinds == ["last_run", "previous_run_0", "previous_run_1", "previous_run_2"]
    assert all(e["payload"]["executable"] == "CHROME.EXE" for e in events)
    last = next(e for e in events if e["payload"]["run_kind"] == "last_run")
    assert last["timestamp"] == "2026-02-14 13:07:13"


def test_convert_altpf_skips_blank_previous_runs(tmp_path):
    """Only LastRun set → 1 event."""
    row = ",".join([
        "/p/A.pf", "A.pf", "2026-02-14 00:00:00", "2026-02-14 00:00:00", "2026-02-14 00:00:00",
        "A.EXE", "0x1", "100", "Windows 10", "1",
        "2026-02-14 00:00:00",
        "", "", "", "", "", "", "",
        "", "", "", "", "", "",
        "", "", "",
    ])
    p = _make_csv(tmp_path, _HEADER + "\n" + row + "\n")
    events = list(_convert_altpf(p, _req()))
    assert len(events) == 1
    assert events[0]["payload"]["run_kind"] == "last_run"


def test_convert_altpf_emits_event_even_when_lastrun_blank(tmp_path):
    """Blank LastRun still emits a row (ts_utc='') so row count matches source."""
    row = ",".join([
        "/p/B.pf", "B.pf", "2026-02-14 00:00:00", "2026-02-14 00:00:00", "2026-02-14 00:00:00",
        "B.EXE", "0x2", "200", "Windows 10", "0",
        "",
        "", "", "", "", "", "", "",
        "", "", "", "", "", "",
        "", "", "(ParseError msg)",
    ])
    p = _make_csv(tmp_path, _HEADER + "\n" + row + "\n")
    events = list(_convert_altpf(p, _req()))
    assert len(events) == 1
    assert events[0]["payload"]["run_kind"] == "last_run"
    assert events[0]["timestamp"] == ""
    assert events[0]["payload"]["parse_error"] == "(ParseError msg)"


def test_convert_altpf_artifact_id_constant():
    assert ARTIFACT_ID == "prefetch"
