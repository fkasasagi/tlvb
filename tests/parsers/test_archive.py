"""Tests for parsers/_archive.py (v0.4 REQ-1).

Fixtures are generated in-process (no static binary blobs committed).
Each test asserts:
  1. The expected ExtractRecord.result string.
  2. That extracted files appear at the documented destination.
  3. That audit events are emitted in the right shape.
"""

from __future__ import annotations

import gzip
import io
import os
import pathlib
import tarfile
import zipfile

import pytest

from parsers import _archive


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_zip(path: pathlib.Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)


def _make_tar(
    path: pathlib.Path,
    members: dict[str, bytes],
    mode: str = "w:gz",
) -> None:
    with tarfile.open(path, mode=mode) as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def _make_traversal_tar(path: pathlib.Path, target: str) -> None:
    """Tar with a symlink member pointing outside the extraction dir."""
    with tarfile.open(path, mode="w") as tf:
        info = tarfile.TarInfo(name="evil_link")
        info.type = tarfile.SYMTYPE
        info.linkname = target
        tf.addfile(info)


def _run(root: pathlib.Path, workspace: pathlib.Path) -> tuple[
    list[_archive.ExtractRecord], list[dict]
]:
    """Drive extract_nested_recursively + capture audit events."""
    audit: list[dict] = []
    progress: list[dict] = []
    workspace.mkdir(parents=True, exist_ok=True)
    records = _archive.extract_nested_recursively(
        root,
        workspace=workspace,
        config_path=None,  # use DEFAULTS
        progress_emit=progress.append,
        audit_emit=audit.append,
    )
    return records, audit


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def test_extracts_plain_zip(tmp_path: pathlib.Path) -> None:
    root = tmp_path / "stage"
    root.mkdir()
    _make_zip(root / "host1.zip", {
        "Registry/SOFTWARE": b"hive-bytes",
        "evtx/Security.evtx": b"evtx-bytes",
    })

    records, audit = _run(root, tmp_path / "ws")

    assert len(records) == 1
    rec = records[0]
    assert rec.result == "ok"
    assert rec.format == "zip"
    assert rec.members == 2
    # Files actually landed.
    nested_dir = tmp_path / "ws" / "extracted" / "__nested__"
    extracted = list(nested_dir.rglob("SOFTWARE"))
    assert extracted, "SOFTWARE should be present after extraction"
    # Audit event has expected kind + format.
    assert any(e["kind"] == "nested_extract" and e["format"] == "zip" for e in audit)


def test_extracts_tar_gz(tmp_path: pathlib.Path) -> None:
    root = tmp_path / "stage"
    root.mkdir()
    _make_tar(
        root / "registry.tar.gz",
        {"SYSTEM": b"hive", "SOFTWARE": b"hive"},
        mode="w:gz",
    )
    records, _ = _run(root, tmp_path / "ws")
    assert len(records) == 1
    assert records[0].result == "ok"
    assert records[0].format == "tar.gz"
    assert records[0].members == 2


def test_extracts_7z(tmp_path: pathlib.Path) -> None:
    pytest.importorskip("py7zr")
    import py7zr  # noqa: PLC0415  — guarded by importorskip

    root = tmp_path / "stage"
    root.mkdir()
    src = root / "host.7z"
    with py7zr.SevenZipFile(src, "w") as zf:
        zf.writestr(b"evtx-bytes", "Security.evtx")

    records, _ = _run(root, tmp_path / "ws")
    assert len(records) == 1
    assert records[0].result == "ok"
    assert records[0].format == "7z"
    assert records[0].members == 1


def test_extracts_bare_gz(tmp_path: pathlib.Path) -> None:
    root = tmp_path / "stage"
    root.mkdir()
    payload = b"system-hive-bytes" * 1024  # >16 KiB so ratio check is meaningful
    src = root / "SYSTEM.gz"
    with gzip.open(src, "wb") as fh:
        fh.write(payload)

    records, _ = _run(root, tmp_path / "ws")
    assert len(records) == 1
    assert records[0].result == "ok"
    assert records[0].format == "gz"
    # Output file (.gz suffix stripped) exists under __nested__/<sha>/SYSTEM.
    nested_dir = tmp_path / "ws" / "extracted" / "__nested__"
    out = list(nested_dir.rglob("SYSTEM"))
    assert out and out[0].read_bytes() == payload


def test_recurses_into_nested_zip(tmp_path: pathlib.Path) -> None:
    """zip-in-zip should be unpacked on the second pass."""
    root = tmp_path / "stage"
    root.mkdir()
    inner_path = tmp_path / "inner.zip"
    _make_zip(inner_path, {"Registry/SOFTWARE": b"deep"})
    outer_data = inner_path.read_bytes()
    inner_path.unlink()
    _make_zip(root / "outer.zip", {"inner.zip": outer_data})

    records, _ = _run(root, tmp_path / "ws")
    assert len(records) == 2
    results = sorted(r.depth for r in records)
    assert results == [1, 2]
    assert all(r.result == "ok" for r in records)
    nested_dir = tmp_path / "ws" / "extracted" / "__nested__"
    assert list(nested_dir.rglob("SOFTWARE"))


# ---------------------------------------------------------------------------
# Skip paths
# ---------------------------------------------------------------------------


def test_skip_path_traversal_zip(tmp_path: pathlib.Path) -> None:
    root = tmp_path / "stage"
    root.mkdir()
    # Use ZipInfo directly so we keep the literal "../" segment.
    src = root / "evil.zip"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("../../etc/passwd_takeover", b"hacked")
        zf.writestr("benign.txt", b"ok")

    records, audit = _run(root, tmp_path / "ws")
    assert len(records) == 1
    assert records[0].result == _archive.SKIP_PATH_TRAVERSAL
    # No file should have been written (we reject before extracting).
    nested_dir = tmp_path / "ws" / "extracted" / "__nested__"
    if nested_dir.exists():
        assert not list(nested_dir.rglob("passwd_takeover"))
    assert audit and audit[0]["result"] == _archive.SKIP_PATH_TRAVERSAL


def test_skip_symlink_tar(tmp_path: pathlib.Path) -> None:
    root = tmp_path / "stage"
    root.mkdir()
    _make_traversal_tar(root / "evil.tar", target="/etc/passwd")

    records, _ = _run(root, tmp_path / "ws")
    assert len(records) == 1
    assert records[0].result == _archive.SKIP_PATH_TRAVERSAL


def test_skip_bomb_ratio_zip(tmp_path: pathlib.Path) -> None:
    """Highly compressible payload — large uncompressed, tiny compressed."""
    root = tmp_path / "stage"
    root.mkdir()
    # 20 MiB of zeros → deflate compresses to ~20 KiB → ratio ≈ 1000.
    payload = b"\x00" * (20 * 1024 * 1024)
    with zipfile.ZipFile(
        root / "bomb.zip", "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9,
    ) as zf:
        zf.writestr("payload.bin", payload)

    records, _ = _run(root, tmp_path / "ws")
    assert len(records) == 1
    assert records[0].result == _archive.SKIP_BOMB_RATIO
    assert records[0].compression_ratio is not None
    assert records[0].compression_ratio > 200


def test_skip_encrypted_7z(tmp_path: pathlib.Path) -> None:
    """Password-protected 7z should skip with skip:encrypted, not crash."""
    pytest.importorskip("py7zr")
    import py7zr  # noqa: PLC0415  — guarded by importorskip

    root = tmp_path / "stage"
    root.mkdir()
    src = root / "secret.7z"
    with py7zr.SevenZipFile(src, "w", password="hunter2") as zf:
        zf.writestr(b"top-secret", "plain.txt")

    records, _ = _run(root, tmp_path / "ws")
    assert len(records) == 1
    assert records[0].result == _archive.SKIP_ENCRYPTED


def test_skip_format_mismatch(tmp_path: pathlib.Path) -> None:
    """A non-archive file named .zip should be rejected by magic check."""
    root = tmp_path / "stage"
    root.mkdir()
    (root / "fake.zip").write_bytes(b"not actually a zip file at all")

    records, _ = _run(root, tmp_path / "ws")
    assert len(records) == 1
    assert records[0].result == _archive.SKIP_FORMAT_MISMATCH


def test_depth_cap(tmp_path: pathlib.Path) -> None:
    """Build a 6-level zip chain; default max_depth=4 stops at level 4.

    Chain: outer.zip → level5.zip → level4.zip → … → level1.zip → leaf.txt
    """
    root = tmp_path / "stage"
    root.mkdir()
    last_bytes = b"leaf-bytes"
    last_name = "leaf.txt"
    for i in range(1, 6):  # build innermost-out: level1 .. level5
        scratch = tmp_path / f"build_{i}.zip"
        _make_zip(scratch, {last_name: last_bytes})
        last_bytes = scratch.read_bytes()
        last_name = f"level{i}.zip"
        scratch.unlink()
    (root / "outer.zip").write_bytes(last_bytes)

    records, _ = _run(root, tmp_path / "ws")
    ok_depths = sorted(r.depth for r in records if r.result == "ok")
    assert ok_depths == [1, 2, 3, 4]


def test_disabled_when_max_depth_zero(tmp_path: pathlib.Path, monkeypatch) -> None:
    """max_depth=0 in config disables nested extraction entirely."""
    root = tmp_path / "stage"
    root.mkdir()
    _make_zip(root / "a.zip", {"f": b"x"})

    # Patch DEFAULTS for this test only.
    monkeypatch.setitem(_archive.DEFAULTS, "max_depth", 0)
    records, _ = _run(root, tmp_path / "ws")
    assert records == []


def test_load_config_broken_yaml_warns_and_uses_defaults(
    tmp_path: pathlib.Path, capsys
) -> None:
    bad = tmp_path / "staging.yaml"
    bad.write_bytes(b"\x00\xff\x00 not yaml")
    cfg = _archive.load_config(bad)
    assert cfg == dict(_archive.DEFAULTS)
    err = capsys.readouterr().err
    assert "WARNING" in err
    assert "staging defaults" in err
