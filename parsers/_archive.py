"""Nested archive extraction (Tier 0 staging, v0.4 REQ-1).

Single entry point: ``extract_nested_recursively(root, workspace, ...)``.

Why this lives in its own module:
  * orchestrator.stage_input() only knows about the *top-level* input.
    Collectors like KAPE, CyLR, Velociraptor and in-house bundlers very
    often produce zip-in-zip or per-category sub-archives. Anything we
    don't unpack stays invisible to the detector / parsers.
  * Supporting .zip, .7z and the .tar family means three different
    libraries (zipfile / py7zr / tarfile). The orchestrator should not
    care about that — this module abstracts it.

Safety:
  * Path-traversal members (``../`` / absolute / symlink / hardlink /
    device / FIFO) are rejected *before* extraction.
  * Per-member uncompressed-size cap, total cumulative cap, and
    compression-ratio cap (separate cap for LZMA-based formats) defend
    against decompression bombs.
  * Encrypted archives are skipped with a structured reason; we never
    prompt for passwords.
  * py7zr is *optional*. If the import fails, .7z is skipped per-file
    rather than killing the whole staging run.

Audit:
  * Every extract attempt (ok or skipped) is appended to
    ``actions.jsonl`` via ``append_event(...)`` so Review Gate 0 can
    surface the decision to the examiner.

The module deliberately exposes plain functions (no class) — keeps the
call-site in orchestrator.py readable and testing trivial.
"""

from __future__ import annotations

import dataclasses
import datetime
import gzip
import hashlib
import pathlib
import shutil
import sys
import tarfile
import time
import zipfile
from collections.abc import Callable
from typing import Any

# py7zr is optional. Import lazily and remember the failure so we can
# emit a clean skip reason instead of crashing.
try:
    import py7zr  # type: ignore[import-untyped]
    _PY7ZR_ERR: Exception | None = None
except Exception as exc:  # noqa: BLE001  — any import-time error is "missing"
    py7zr = None  # type: ignore[assignment]
    _PY7ZR_ERR = exc


# ---------------------------------------------------------------------------
# Defaults — mirrored from config/staging.yaml.
# ---------------------------------------------------------------------------

DEFAULTS: dict[str, Any] = {
    "supported_extensions": [
        ".zip", ".7z",
        ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz",
        ".gz",
    ],
    "max_depth": 4,
    "max_total_extracted_bytes": 50 * 1024 * 1024 * 1024,  # 50 GiB
    "max_member_uncompressed_bytes": 4 * 1024 * 1024 * 1024,  # 4 GiB
    "compression_ratio_cap": 200,
    "compression_ratio_cap_lzma": 500,
    "on_encrypted": "skip",
    "on_missing_backend": "skip",
}


def load_config(config_path: pathlib.Path | None) -> dict[str, Any]:
    """Read config/staging.yaml if present, else return DEFAULTS.

    Missing keys fall back to DEFAULTS (graceful — operators can override
    a single value without re-listing all of them).
    """
    cfg = dict(DEFAULTS)
    if config_path is None or not config_path.exists():
        return cfg
    try:
        # Tiny YAML reader — we only need flat key:value + a single list.
        # Importing PyYAML would add a runtime dep just for this file.
        cfg.update(_read_simple_yaml(config_path))
    except Exception as exc:  # noqa: BLE001
        # Defaults are safe; an operator with a broken yaml shouldn't
        # block parsing entirely — but they should be able to see why
        # their override was ignored.
        print(
            f"[archive] WARNING: failed to read {config_path}: {exc} — "
            "using staging defaults",
            file=sys.stderr,
        )
    return cfg


def _read_simple_yaml(p: pathlib.Path) -> dict[str, Any]:
    """Parse the limited subset of YAML used in staging.yaml.

    Supports the ``nested_archive:`` block with scalar values plus the
    ``supported_extensions`` list. Anything fancier (nested mappings,
    flow-style) is intentionally unsupported — we keep this dependency-
    free.
    """
    out: dict[str, Any] = {}
    in_nested = False
    in_list_key: str | None = None
    list_buf: list[str] = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line == "nested_archive:":
            in_nested = True
            continue
        if not in_nested:
            continue
        if not line.startswith(" "):
            # Left margin → new top-level section, leave nested_archive block.
            in_nested = False
            if in_list_key is not None:
                out[in_list_key] = list_buf
                in_list_key = None
                list_buf = []
            continue
        stripped = line.strip()
        if stripped.startswith("- "):
            if in_list_key is not None:
                list_buf.append(stripped[2:].strip())
            continue
        if in_list_key is not None:
            out[in_list_key] = list_buf
            in_list_key = None
            list_buf = []
        if ":" not in stripped:
            continue
        key, _, val = stripped.partition(":")
        key = key.strip()
        val = val.split("#", 1)[0].strip()
        if not val:
            in_list_key = key
            list_buf = []
            continue
        if val.lstrip("-").isdigit():
            out[key] = int(val)
        else:
            out[key] = val.strip('"').strip("'")
    if in_list_key is not None:
        out[in_list_key] = list_buf
    return out


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

# Magic-byte signatures keyed by canonical format id.
_MAGICS: dict[str, list[bytes]] = {
    "zip":     [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    "7z":      [b"7z\xbc\xaf\x27\x1c"],
    "gz":      [b"\x1f\x8b"],
    "bz2":     [b"BZh"],
    "xz":      [b"\xfd7zXZ\x00"],
}


def _format_from_name(name: str) -> str | None:
    """Map a file name to a canonical format id, multi-suffix aware."""
    n = name.lower()
    # Order matters — check the compound suffixes first.
    if n.endswith(".tar.gz") or n.endswith(".tgz"):
        return "tar.gz"
    if n.endswith(".tar.bz2") or n.endswith(".tbz2"):
        return "tar.bz2"
    if n.endswith(".tar.xz") or n.endswith(".txz"):
        return "tar.xz"
    if n.endswith(".tar"):
        return "tar"
    if n.endswith(".zip"):
        return "zip"
    if n.endswith(".7z"):
        return "7z"
    if n.endswith(".gz"):
        return "gz"
    return None


def _verify_magic(path: pathlib.Path, fmt: str) -> bool:
    """Confirm the file's leading bytes match the declared format.

    For tar / tar.gz / tar.bz2 / tar.xz we check the *outer* container
    (gzip/bz2/xz magic at byte 0, or ``ustar`` at offset 257 for raw tar)
    rather than fully decoding.
    """
    try:
        with path.open("rb") as fh:
            head = fh.read(512)
    except OSError:
        return False
    if fmt == "zip":
        return any(head.startswith(m) for m in _MAGICS["zip"])
    if fmt == "7z":
        return head.startswith(_MAGICS["7z"][0])
    if fmt == "gz":
        return head.startswith(_MAGICS["gz"][0])
    if fmt == "tar.gz":
        return head.startswith(_MAGICS["gz"][0])
    if fmt == "tar.bz2":
        return head.startswith(_MAGICS["bz2"][0])
    if fmt == "tar.xz":
        return head.startswith(_MAGICS["xz"][0])
    if fmt == "tar":
        # POSIX tar: "ustar" magic at offset 257 — or pre-POSIX with
        # a sane checksum field. We accept the POSIX form and fall
        # through to tarfile.is_tarfile() for the older variant.
        if len(head) >= 263 and head[257:262] == b"ustar":
            return True
        try:
            return tarfile.is_tarfile(path)
        except (OSError, tarfile.TarError):
            return False
    return False


# ---------------------------------------------------------------------------
# Public data shapes
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class ExtractRecord:
    """One extraction attempt — ok or skip — recorded for audit.

    Fields mirror the JSON shape persisted to actions.jsonl.
    """

    format: str
    src: str               # relative to evidence root
    dst_dir: str | None    # null when skipped
    depth: int
    members: int           # 0 when skipped before iteration
    bytes_uncompressed: int
    compression_ratio: float | None
    result: str            # "ok" or "skip:<reason>"
    duration_ms: int

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


# Skip reasons surfaced in result strings.
SKIP_FORMAT_MISMATCH   = "skip:format_mismatch"
SKIP_DEPTH_EXCEEDED    = "skip:depth_exceeded"
SKIP_TOTAL_SIZE        = "skip:total_size_exceeded"
SKIP_BOMB_RATIO        = "skip:bomb_ratio"
SKIP_BOMB_MEMBER       = "skip:bomb_member_size"
SKIP_PATH_TRAVERSAL    = "skip:path_traversal"
SKIP_ENCRYPTED         = "skip:encrypted"
SKIP_MISSING_BACKEND   = "skip:missing_backend"
SKIP_UNREADABLE        = "skip:unreadable"
SKIP_UNSUPPORTED       = "skip:unsupported_format"


# ---------------------------------------------------------------------------
# Path validation
# ---------------------------------------------------------------------------


def _safe_member_path(dst_root: pathlib.Path, member_name: str) -> pathlib.Path | None:
    """Resolve a member path; return None if it would escape ``dst_root``.

    Rejects:
      * Absolute paths (Windows ``C:\\...`` or POSIX ``/...``).
      * Paths that resolve outside ``dst_root`` after ``..`` collapses.
      * Empty / dot-only segments.
    """
    if not member_name:
        return None
    norm = member_name.replace("\\", "/")
    # Absolute paths — POSIX or Windows drive letter.
    if norm.startswith("/") or (len(norm) >= 2 and norm[1] == ":"):
        return None
    candidate = (dst_root / norm).resolve()
    try:
        candidate.relative_to(dst_root.resolve())
    except ValueError:
        return None
    return candidate


# ---------------------------------------------------------------------------
# Per-format extractors
# ---------------------------------------------------------------------------


def _extract_zip(
    src: pathlib.Path,
    dst: pathlib.Path,
    *,
    cfg: dict[str, Any],
    budget_remaining: int,
) -> tuple[str, int, int, float | None]:
    """Return (result, members, bytes_uncompressed, ratio).

    Used uniformly across formats so the caller can build one
    ExtractRecord shape.
    """
    try:
        zf = zipfile.ZipFile(src, "r")
    except (zipfile.BadZipFile, OSError):
        return SKIP_UNREADABLE, 0, 0, None
    try:
        infos = zf.infolist()
        # Encryption: any encrypted member ⇒ skip whole archive.
        if any((info.flag_bits & 0x1) for info in infos):
            return SKIP_ENCRYPTED, 0, 0, None
        total_uncomp = 0
        total_comp = 0
        for info in infos:
            if info.file_size > cfg["max_member_uncompressed_bytes"]:
                return SKIP_BOMB_MEMBER, 0, 0, None
            total_uncomp += info.file_size
            total_comp += max(info.compress_size, 1)
            if _safe_member_path(dst, info.filename) is None:
                return SKIP_PATH_TRAVERSAL, 0, 0, None
        ratio = (total_uncomp / total_comp) if total_comp else 0.0
        cap = cfg["compression_ratio_cap"]
        if ratio > cap and total_uncomp > 16 * 1024 * 1024:  # ignore tiny archives
            return SKIP_BOMB_RATIO, 0, 0, ratio
        if total_uncomp > budget_remaining:
            return SKIP_TOTAL_SIZE, 0, 0, ratio
        dst.mkdir(parents=True, exist_ok=True)
        for info in infos:
            if info.is_dir():
                continue
            safe = _safe_member_path(dst, info.filename)
            if safe is None:
                return SKIP_PATH_TRAVERSAL, 0, 0, ratio
            safe.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src_fh, safe.open("wb") as dst_fh:
                shutil.copyfileobj(src_fh, dst_fh)
        return "ok", len(infos), total_uncomp, ratio
    finally:
        zf.close()


def _extract_7z(
    src: pathlib.Path,
    dst: pathlib.Path,
    *,
    cfg: dict[str, Any],
    budget_remaining: int,
) -> tuple[str, int, int, float | None]:
    if py7zr is None:
        return SKIP_MISSING_BACKEND, 0, 0, None
    try:
        with py7zr.SevenZipFile(src, mode="r") as zf:
            if zf.password_protected:
                return SKIP_ENCRYPTED, 0, 0, None
            infos = zf.list()
            total_uncomp = 0
            for info in infos:
                size = int(getattr(info, "uncompressed", 0) or 0)
                if size > cfg["max_member_uncompressed_bytes"]:
                    return SKIP_BOMB_MEMBER, 0, 0, None
                total_uncomp += size
                name = getattr(info, "filename", "") or ""
                if _safe_member_path(dst, name) is None:
                    return SKIP_PATH_TRAVERSAL, 0, 0, None
            comp = src.stat().st_size or 1
            ratio = total_uncomp / comp
            cap = cfg["compression_ratio_cap_lzma"]
            if ratio > cap and total_uncomp > 16 * 1024 * 1024:
                return SKIP_BOMB_RATIO, 0, 0, ratio
            if total_uncomp > budget_remaining:
                return SKIP_TOTAL_SIZE, 0, 0, ratio
            dst.mkdir(parents=True, exist_ok=True)
            zf.extractall(path=str(dst))
            return "ok", len(infos), total_uncomp, ratio
    except (py7zr.exceptions.PasswordRequired, py7zr.exceptions.UnsupportedCompressionMethodError):  # type: ignore[union-attr]
        return SKIP_ENCRYPTED, 0, 0, None
    except (py7zr.exceptions.Bad7zFile, OSError):  # type: ignore[union-attr]
        return SKIP_UNREADABLE, 0, 0, None


def _extract_tar(
    src: pathlib.Path,
    dst: pathlib.Path,
    *,
    fmt: str,
    cfg: dict[str, Any],
    budget_remaining: int,
) -> tuple[str, int, int, float | None]:
    mode_map = {
        "tar":     "r:",
        "tar.gz":  "r:gz",
        "tar.bz2": "r:bz2",
        "tar.xz":  "r:xz",
    }
    mode = mode_map[fmt]
    try:
        tf = tarfile.open(src, mode=mode)
    except (tarfile.TarError, OSError, EOFError):
        return SKIP_UNREADABLE, 0, 0, None
    try:
        members = tf.getmembers()
        # Reject anything that isn't a regular file or directory:
        # symlinks/hardlinks/device/fifo are all attack vectors.
        for m in members:
            if m.islnk() or m.issym() or m.isdev() or m.isfifo() or m.ischr() or m.isblk():
                return SKIP_PATH_TRAVERSAL, 0, 0, None
            if _safe_member_path(dst, m.name) is None:
                return SKIP_PATH_TRAVERSAL, 0, 0, None
            if m.size > cfg["max_member_uncompressed_bytes"]:
                return SKIP_BOMB_MEMBER, 0, 0, None
        total_uncomp = sum(m.size for m in members if m.isreg())
        comp = src.stat().st_size or 1
        ratio = total_uncomp / comp
        cap = (
            cfg["compression_ratio_cap_lzma"]
            if fmt == "tar.xz"
            else cfg["compression_ratio_cap"]
        )
        if ratio > cap and total_uncomp > 16 * 1024 * 1024:
            return SKIP_BOMB_RATIO, 0, 0, ratio
        if total_uncomp > budget_remaining:
            return SKIP_TOTAL_SIZE, 0, 0, ratio
        dst.mkdir(parents=True, exist_ok=True)
        # Python 3.12+: tarfile.data_filter strips uid/gid + sanitizes paths.
        tf.extractall(path=str(dst), filter="data")
        return "ok", len(members), total_uncomp, ratio
    except (tarfile.TarError, OSError) as exc:
        # data_filter raises tarfile.AbsolutePathError /
        # tarfile.OutsideDestinationError for traversal attempts even if
        # our pre-check misses something obscure (e.g. PAX header tricks).
        if "outside" in str(exc).lower() or "absolute" in str(exc).lower():
            return SKIP_PATH_TRAVERSAL, 0, 0, None
        return SKIP_UNREADABLE, 0, 0, None
    finally:
        tf.close()


def _extract_gz(
    src: pathlib.Path,
    dst: pathlib.Path,
    *,
    cfg: dict[str, Any],
    budget_remaining: int,
) -> tuple[str, int, int, float | None]:
    """Single-member gzip → write one file beside dst."""
    # Output file name: strip the trailing .gz from the source name.
    name = src.name
    if name.lower().endswith(".gz"):
        name = name[:-3]
    if not name:
        name = "decompressed"
    out_path = dst / name
    safe = _safe_member_path(dst, name)
    if safe is None:
        return SKIP_PATH_TRAVERSAL, 0, 0, None
    try:
        dst.mkdir(parents=True, exist_ok=True)
        written = 0
        with gzip.open(src, "rb") as src_fh, out_path.open("wb") as dst_fh:
            while True:
                # Stream in chunks so we can enforce caps mid-flight.
                chunk = src_fh.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > cfg["max_member_uncompressed_bytes"]:
                    dst_fh.close()
                    out_path.unlink(missing_ok=True)
                    return SKIP_BOMB_MEMBER, 0, 0, None
                if written > budget_remaining:
                    dst_fh.close()
                    out_path.unlink(missing_ok=True)
                    return SKIP_TOTAL_SIZE, 0, 0, None
                dst_fh.write(chunk)
        comp = src.stat().st_size or 1
        ratio = written / comp
        if ratio > cfg["compression_ratio_cap"] and written > 16 * 1024 * 1024:
            out_path.unlink(missing_ok=True)
            return SKIP_BOMB_RATIO, 0, 0, ratio
        return "ok", 1, written, ratio
    except (OSError, gzip.BadGzipFile):
        out_path.unlink(missing_ok=True)
        return SKIP_UNREADABLE, 0, 0, None


# ---------------------------------------------------------------------------
# Top-level driver
# ---------------------------------------------------------------------------


def _short_sha(path: pathlib.Path) -> str:
    """8-char hex digest of the path string — for unique nested dst dirs."""
    return hashlib.sha256(str(path).encode("utf-8")).hexdigest()[:8]


def _discover_archives(
    roots: list[pathlib.Path], exts: list[str],
    marker_root: pathlib.Path,
) -> list[pathlib.Path]:
    """Find archive files inside ``roots``, sorted for determinism.

    We pass *both* the staged evidence root and the nested-extraction
    root so a zip-in-zip produced on pass N is still picked up on pass
    N+1 — even when the evidence root is a read-only directory and
    therefore can't host new extractions itself.

    Already-extracted archives are recognised by a sha-keyed marker
    file under ``marker_root/_markers/`` so we never touch the
    (potentially read-only) evidence dir.
    """
    out: list[pathlib.Path] = []
    seen: set[pathlib.Path] = set()
    for root in roots:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if _is_handled(p, marker_root):
                continue
            name = p.name.lower()
            if not any(name.endswith(e) for e in exts):
                continue
            if p in seen:
                continue
            seen.add(p)
            out.append(p)
    out.sort()
    return out


def extract_nested_recursively(
    root: pathlib.Path,
    *,
    workspace: pathlib.Path,
    config_path: pathlib.Path | None = None,
    progress_emit: Callable[[dict], None] | None = None,
    audit_emit: Callable[[dict], None] | None = None,
) -> list[ExtractRecord]:
    """Walk ``root``, recursively extracting supported archives.

    Returns the list of every extract attempt (ok or skip), in execution
    order. The caller is expected to surface this list through the
    parse_review.json `nested_extractions` field and ``actions.jsonl``.

    The function never raises for an individual archive failure — the
    whole point is graceful degradation; the extracted subtree may be
    partial and the orchestrator continues with whatever is there.
    """
    cfg = load_config(config_path)
    if cfg["max_depth"] <= 0:
        return []

    records: list[ExtractRecord] = []
    total_bytes = 0
    nested_root = workspace / "extracted" / "__nested__"
    nested_root.mkdir(parents=True, exist_ok=True)
    marker_root = workspace / "extracted"

    for depth in range(1, int(cfg["max_depth"]) + 1):
        archives = _discover_archives(
            [root, nested_root], cfg["supported_extensions"], marker_root,
        )
        if not archives:
            break
        for src in archives:
            rel = _relpath(src, root)
            fmt = _format_from_name(src.name)
            if fmt is None:
                continue  # _discover_archives filtered by ext, defensive only
            t0 = time.monotonic()
            if not _verify_magic(src, fmt):
                rec = ExtractRecord(
                    format=fmt, src=rel, dst_dir=None, depth=depth,
                    members=0, bytes_uncompressed=0, compression_ratio=None,
                    result=SKIP_FORMAT_MISMATCH,
                    duration_ms=int((time.monotonic() - t0) * 1000),
                )
                _record(rec, records, progress_emit, audit_emit)
                # Mark so we don't reconsider it next pass.
                _mark_handled(src, marker_root)
                continue
            dst = nested_root / _short_sha(src)
            budget = int(cfg["max_total_extracted_bytes"]) - total_bytes
            if fmt == "zip":
                result, members, bytes_, ratio = _extract_zip(
                    src, dst, cfg=cfg, budget_remaining=budget,
                )
            elif fmt == "7z":
                result, members, bytes_, ratio = _extract_7z(
                    src, dst, cfg=cfg, budget_remaining=budget,
                )
            elif fmt in {"tar", "tar.gz", "tar.bz2", "tar.xz"}:
                result, members, bytes_, ratio = _extract_tar(
                    src, dst, fmt=fmt, cfg=cfg, budget_remaining=budget,
                )
            elif fmt == "gz":
                result, members, bytes_, ratio = _extract_gz(
                    src, dst, cfg=cfg, budget_remaining=budget,
                )
            else:
                result, members, bytes_, ratio = SKIP_UNSUPPORTED, 0, 0, None
            if result == "ok":
                total_bytes += bytes_
            rec = ExtractRecord(
                format=fmt, src=rel,
                dst_dir=_relpath(dst, root) if result == "ok" else None,
                depth=depth, members=members,
                bytes_uncompressed=bytes_,
                compression_ratio=round(ratio, 3) if ratio is not None else None,
                result=result,
                duration_ms=int((time.monotonic() - t0) * 1000),
            )
            _record(rec, records, progress_emit, audit_emit)
            _mark_handled(src, marker_root)
            if result == SKIP_TOTAL_SIZE:
                # Hard stop — extracting anything more would just compound
                # the overrun. Emit a single trailing event so the UI knows
                # we're bailing, then return.
                return records
    return records


def _mark_handled(src: pathlib.Path, marker_root: pathlib.Path) -> None:
    """Record that ``src`` has been processed so subsequent passes skip it.

    Markers live under ``marker_root / "_markers" / <sha8 of full path>``
    rather than next to the source archive. That way the evidence dir
    stays untouched (chain-of-custody) AND restarts after a partial run
    don't re-process an already-extracted archive (the marker survives
    workspace re-creation only if marker_root persists).
    """
    try:
        markers_dir = marker_root / "_markers"
        markers_dir.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(str(src.resolve()).encode("utf-8")).hexdigest()[:16]
        (markers_dir / digest).touch()
    except OSError:
        pass  # marker is best-effort; worst case we re-attempt next pass


def _is_handled(src: pathlib.Path, marker_root: pathlib.Path) -> bool:
    try:
        digest = hashlib.sha256(str(src.resolve()).encode("utf-8")).hexdigest()[:16]
        return (marker_root / "_markers" / digest).exists()
    except OSError:
        return False


def _record(
    rec: ExtractRecord,
    records: list[ExtractRecord],
    progress_emit: Callable[[dict], None] | None,
    audit_emit: Callable[[dict], None] | None,
) -> None:
    records.append(rec)
    if progress_emit is not None:
        try:
            progress_emit({
                "type": "stage",
                "phase": "extracting_nested",
                "format": rec.format,
                "depth": rec.depth,
                "src": rec.src,
                "members_extracted": rec.members,
                "result": rec.result,
            })
        except Exception:  # noqa: BLE001
            pass
    if audit_emit is not None:
        try:
            audit_emit({
                "ts": datetime.datetime.now(datetime.UTC)
                    .isoformat(timespec="seconds"),
                "actor": "tier0-stage",
                "kind": "nested_extract",
                **rec.as_dict(),
            })
        except Exception:  # noqa: BLE001
            pass


def _relpath(p: pathlib.Path, root: pathlib.Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)
