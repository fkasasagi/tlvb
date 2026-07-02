"""Dry-run tests for Wave 8 P2 parsers (#24).

These exercise the *no-input* / *no-binary* branches so we know each
parser fails cleanly with an actionable error message instead of
crashing the orchestrator. Real execution paths require the actual
tools and are covered by docs/TEST_TIER0.md §11–§13.
"""

from __future__ import annotations

import pathlib

import pytest

from parsers import hayabusa_parser, srum_parser, usn_journal_parser
from parsers.base import ParseRequest


def _req(input_path: pathlib.Path, output_dir: pathlib.Path) -> ParseRequest:
    return ParseRequest(
        input_path=input_path,
        output_dir=output_dir,
        case_id="TST",
        evidence_id="EV-001",
        timezone="UTC",
        timeout_seconds=30,
    )


# ---------------------------------------------------------------------------
# USN journal
# ---------------------------------------------------------------------------


def test_usn_journal_missing_input(tmp_path):
    req = _req(tmp_path / "nope" / "$J", tmp_path / "out")
    res = usn_journal_parser.parse(req)
    assert res.success is False
    assert res.error is not None
    assert "input_path does not exist" in res.error
    assert res.parser_version.startswith("usn_journal_parser/")


def test_usn_journal_rejects_directory_input(tmp_path):
    d = tmp_path / "j_as_dir"
    d.mkdir()
    res = usn_journal_parser.parse(_req(d, tmp_path / "out"))
    assert res.success is False
    assert "expected $J file" in (res.error or "")


def test_usn_journal_sibling_mft_detection(tmp_path):
    # Synthetic $J + $MFT pair — verify _sibling_mft picks the sibling.
    j = tmp_path / "$J"; j.write_bytes(b"")
    mft = tmp_path / "$MFT"; mft.write_bytes(b"")
    assert usn_journal_parser._sibling_mft(j) == mft

    j2 = tmp_path / "lone" / "$J"
    j2.parent.mkdir()
    j2.write_bytes(b"")
    assert usn_journal_parser._sibling_mft(j2) is None


# ---------------------------------------------------------------------------
# Hayabusa
# ---------------------------------------------------------------------------


def test_hayabusa_graceful_skip_when_binary_missing(tmp_path, monkeypatch):
    # Force "not installed" by stubbing the binary lookup.
    monkeypatch.setattr(hayabusa_parser, "_locate_binary", lambda: None)
    res = hayabusa_parser.parse(_req(tmp_path, tmp_path / "out"))
    assert res.success is False
    assert "not installed" in (res.error or "").lower()
    assert res.command == "(tool not installed)"


# ---------------------------------------------------------------------------
# SRUM
# ---------------------------------------------------------------------------


def test_srum_graceful_skip_when_dll_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(srum_parser, "SRUMECMD_DLL", "/does/not/exist.dll")
    fake_srudb = tmp_path / "SRUDB.dat"
    fake_srudb.write_bytes(b"")
    res = srum_parser.parse(_req(fake_srudb, tmp_path / "out"))
    assert res.success is False
    assert "SrumECmd is not installed" in (res.error or "")


def test_srum_sibling_software_detection(tmp_path):
    srudb = tmp_path / "sru" / "SRUDB.dat"
    srudb.parent.mkdir()
    srudb.write_bytes(b"")
    assert srum_parser._sibling_software(srudb) is None

    sw = tmp_path / "sru" / "SOFTWARE"
    sw.write_bytes(b"")
    assert srum_parser._sibling_software(srudb) == sw
