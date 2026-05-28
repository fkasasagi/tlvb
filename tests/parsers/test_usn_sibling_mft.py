"""Tests for parsers/usn_journal_parser._sibling_mft (Wave 15).

MFTECmd resolves USN FileReference numbers → full paths only when the
parser passes ``-m <sibling $MFT>``. The collectors that triage cases
flatten files and prepend `<drive>_` tokens (TANAKA / KAPE-NTFS bundled),
so the sibling lookup must accept those prefixes — otherwise USN
ParentPath / FullName columns are populated with FRN-only strings even
though the matching $MFT is right next to it on disk.
"""

from __future__ import annotations

import pathlib

import pytest

from parsers.usn_journal_parser import _sibling_mft


def test_sibling_finds_plain_dollar_mft(tmp_path):
    j = tmp_path / "$J"
    j.write_bytes(b"")
    (tmp_path / "$MFT").write_bytes(b"")
    s = _sibling_mft(j)
    assert s is not None
    assert s.name == "$MFT"


def test_sibling_finds_drive_prefix_mft(tmp_path):
    j = tmp_path / "C_$UsnJrnl-$J"
    j.write_bytes(b"")
    (tmp_path / "C_$MFT").write_bytes(b"")
    s = _sibling_mft(j)
    assert s is not None
    assert s.name == "C_$MFT"


def test_sibling_returns_none_when_no_mft(tmp_path):
    j = tmp_path / "$J"
    j.write_bytes(b"")
    # No $MFT in the dir, only an unrelated file.
    (tmp_path / "Security.evtx").write_bytes(b"")
    assert _sibling_mft(j) is None


def test_sibling_ignores_decoy(tmp_path):
    j = tmp_path / "$J"
    j.write_bytes(b"")
    # Decoy filenames that mention MFT but aren't the real hive.
    (tmp_path / "My$MFT.txt").write_bytes(b"")
    (tmp_path / "$MFTmirr").write_bytes(b"")
    (tmp_path / "$MFT.bak").write_bytes(b"")
    assert _sibling_mft(j) is None
