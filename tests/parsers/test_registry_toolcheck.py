"""Toolchain preflight for registry_parser (RECmd DLL + Kroll batch file)."""

from __future__ import annotations

import pathlib

from parsers import registry_parser
from parsers.base import ParseRequest


def _req(tmp_path: pathlib.Path) -> ParseRequest:
    hives = tmp_path / "hives"
    hives.mkdir(exist_ok=True)
    return ParseRequest(
        input_path=hives,
        output_dir=tmp_path / "out",
        case_id="T",
        evidence_id="E",
    )


def test_fails_actionably_when_recmd_dll_missing(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        registry_parser, "DLL", str(tmp_path / "missing" / "RECmd.dll")
    )
    res = registry_parser.parse(_req(tmp_path))
    assert not res.success
    assert "required file not found" in (res.error or "")
    assert "RECmd" in (res.error or "")


def test_fails_actionably_when_kroll_batch_missing(tmp_path, monkeypatch) -> None:
    # Pretend the DLL exists but the batch file does not.
    fake_dll = tmp_path / "RECmd.dll"
    fake_dll.write_bytes(b"")
    monkeypatch.setattr(registry_parser, "DLL", str(fake_dll))
    monkeypatch.setattr(
        registry_parser, "KROLL_BATCH", str(tmp_path / "missing" / "Kroll_Batch.reb")
    )
    res = registry_parser.parse(_req(tmp_path))
    assert not res.success
    assert "Kroll_Batch.reb" in (res.error or "")
