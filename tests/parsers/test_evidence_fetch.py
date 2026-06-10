"""Tests for parsers.evidence_fetch — on-demand single/multi file extraction.

The mount + TSK carve path needs a real disk image and SIFT tools, so it is
exercised by integration runs, not here. These unit tests cover the pure logic:
path normalisation, traversal rejection, and the top-level graceful-degradation
behaviour (a non-image input must return a parseable manifest with `error` set,
never raise).
"""

from __future__ import annotations

import json
import pathlib

import pytest

from parsers import evidence_fetch


@pytest.mark.parametrize("raw,want", [
    (r"C:\Users\bob\AppData\Local\Temp\evil.exe", "Users/bob/AppData/Local/Temp/evil.exe"),
    (r"\\host\share\x", "host/share/x"),
    ("$Extend/$UsnJrnl:$J", "$Extend/$UsnJrnl:$J"),
    ("/Windows//System32/config/SYSTEM", "Windows/System32/config/SYSTEM"),
    ("$MFT", "$MFT"),
    ('  "D:/logs/app.log"  ', "logs/app.log"),
])
def test_normalize_target_ok(raw, want):
    assert evidence_fetch.normalize_target(raw) == want


@pytest.mark.parametrize("raw", [
    r"C:\Users\..\..\Windows",
    "a/../b",
    "   ",
    "/",
    "..",
])
def test_normalize_target_rejects(raw):
    with pytest.raises(ValueError):
        evidence_fetch.normalize_target(raw)


def test_fetch_files_non_image_degrades(tmp_path: pathlib.Path):
    """A non-image input returns a manifest with error set, not an exception."""
    bogus = tmp_path / "notes.txt"
    bogus.write_text("just some text, definitely not a disk image", encoding="utf-8")
    out = tmp_path / "out"
    manifest = evidence_fetch.fetch_files(bogus, ["$MFT"], out)
    assert manifest["error"]
    assert "not a recognised disk image" in manifest["error"]
    assert manifest["results"] == []
    assert manifest["image_format"] is None


def test_cli_main_emits_json(tmp_path: pathlib.Path, capsys):
    bogus = tmp_path / "x.bin"
    bogus.write_bytes(b"\x01\x02\x03not an image")
    out = tmp_path / "out"
    rc = evidence_fetch.main([
        "--image", str(bogus),
        "--out", str(out),
        "--evidence-id", "EV-001",
        "--target", r"C:\Windows\System32\config\SYSTEM",
    ])
    assert rc == 0
    captured = capsys.readouterr().out.strip()
    manifest = json.loads(captured)
    assert manifest["evidence_id"] == "EV-001"
    assert manifest["error"]
    assert manifest["results"] == []
