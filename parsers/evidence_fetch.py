"""On-demand evidence file extraction (Tier 1B / Tier 2 agent-driven).

Unlike :func:`image_extractor.extract`, which pulls a *fixed triage subset*
during Tier 0, this module extracts an **arbitrary set of files that an
analysis agent requests at runtime**, so the agent can inspect their contents
directly instead of only the normalized events in ``unified_events``.

It deliberately reuses ``image_extractor``'s mount + single-file extraction
primitives (:func:`image_extractor._mount_image` /
:func:`image_extractor._extract_one`) so the chain-of-custody guarantees are
identical: the image is mounted **read-only**, the original is never touched,
and extracted copies live entirely under the given ``--out`` directory. One
mount serves every target in a request, amortising the (slow) mount cost.

CLI::

    python -m parsers.evidence_fetch \\
        --image /path/to/disk.E01 \\
        --out   outputs/cases/<id>/extractions/on-demand/<evidence_id> \\
        [--evidence-id ev-001] [--timeout 600] \\
        --target 'C:\\Users\\bob\\AppData\\Local\\Temp\\evil.exe' \\
        --target '$MFT'

Targets may be Windows paths (``C:\\Users\\...``), UNC-ish (``\\\\host\\share``),
or NTFS-relative paths; :func:`normalize_target` strips the drive / leading
separators and converts backslashes so Sleuth Kit's ``ifind`` accepts them.
``..`` traversal segments are rejected.

Output: a single JSON object on **stdout**::

    {"image_path", "image_format", "mount_method", "out_dir",
     "results": [{"target", "ntfs_path", "status", "partition", "inum",
                  "sha256", "bytes", "extracted_path", "error"}, ...]}

On a top-level failure (not an image / mount failed) the JSON still parses and
carries ``"error"`` plus an empty ``results`` list so the Go caller degrades
gracefully rather than crashing the analysis run.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import re
import sys

from parsers import image_extractor

_DRIVE = re.compile(r"^[A-Za-z]:/")


def normalize_target(raw: str) -> str:
    """Normalise a requested path to an NTFS-relative path ``ifind`` accepts.

    - ``\\`` → ``/`` (Windows separators)
    - strips a drive prefix (``C:/``) and any leading separators
    - collapses duplicate separators
    - rejects ``..`` traversal segments

    ADS specs such as ``$Extend/$UsnJrnl:$J`` are preserved (the ``:`` is part
    of the stream name, not a drive); ``_extract_one`` understands them.
    """
    s = raw.strip().strip('"').strip("'").replace("\\", "/")
    if _DRIVE.match(s):
        s = s[3:]
    s = re.sub(r"/{2,}", "/", s).lstrip("/")
    parts = [p for p in s.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ValueError(f"path traversal not allowed: {raw!r}")
    if not parts:
        raise ValueError(f"empty target after normalisation: {raw!r}")
    return "/".join(parts)


def _safe_rel(ntfs_path: str) -> str:
    """Map an NTFS path to a filesystem-safe relative destination.

    Keeps ``/`` as directory separators (so the staged tree mirrors the source)
    but replaces ``:`` (ADS) which is illegal in a path component.
    """
    return ntfs_path.replace(":", "_")


def fetch_files(
    image_path: pathlib.Path,
    targets: list[str],
    out_dir: pathlib.Path,
    *,
    evidence_id: str | None = None,
    timeout_seconds: int = 600,
) -> dict:
    """Mount ``image_path`` read-only and extract each target once.

    Returns a JSON-serialisable manifest dict. Never raises for per-target
    misses — those are recorded with ``status="not_found"``. Top-level
    problems (not an image, mount failure) populate the ``error`` key and
    leave ``results`` empty.
    """
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    fmt = image_extractor.detect_image(image_path)
    if fmt is None:
        return {
            "image_path": str(image_path),
            "image_format": None,
            "mount_method": None,
            "out_dir": str(out_dir),
            "error": f"not a recognised disk image: {image_path}",
            "results": [],
        }

    # Normalise up-front so a bad target is reported without aborting the rest.
    bad: dict[str, str] = {}
    normalised: list[tuple[str, str | None]] = []
    for t in targets:
        try:
            normalised.append((t, normalize_target(t)))
        except ValueError as exc:
            bad[t] = str(exc)
            normalised.append((t, None))

    mount_method, raw_device, partitions, mount_cleanup = image_extractor._mount_image(
        image_path, fmt, out_dir,
    )

    results: list[dict] = []
    try:
        if not raw_device or not partitions:
            return {
                "image_path": str(image_path),
                "image_format": fmt,
                "mount_method": mount_method,
                "out_dir": str(out_dir),
                "error": f"mount produced no usable volume (mount_method={mount_method})",
                "results": [],
            }

        for original, ntfs in normalised:
            if ntfs is None:
                results.append({
                    "target": original, "ntfs_path": None, "status": "fail",
                    "partition": None, "inum": None, "sha256": None, "bytes": 0,
                    "extracted_path": None, "error": bad.get(original, "invalid target"),
                })
                continue
            rec = None
            for part_idx, offset_bytes in partitions:
                dest = out_dir / _safe_rel(ntfs)
                r = image_extractor._extract_one(
                    raw_device, offset_bytes, ntfs, dest, original,
                    part_idx, timeout_seconds,
                )
                if r.status == "ok":
                    rec = r
                    break
                # Prefer the most informative non-ok record (a real fail over a
                # bare not_found, but anything over None).
                if rec is None or (rec.status == "not_found" and r.status == "fail"):
                    rec = r
            d = dataclasses.asdict(rec) if rec is not None else {
                "target": original, "status": "not_found",
            }
            d["target"] = original
            d["ntfs_path"] = ntfs
            results.append(d)
    finally:
        mount_cleanup()

    return {
        "image_path": str(image_path),
        "image_format": fmt,
        "mount_method": mount_method,
        "out_dir": str(out_dir),
        "error": None,
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="parsers.evidence_fetch",
        description="Extract arbitrary files from a forensic disk image on demand.",
    )
    ap.add_argument("--image", required=True, help="path to the disk image (E01/raw/vmdk/vhd/vhdx)")
    ap.add_argument("--out", required=True, help="output directory for extracted files")
    ap.add_argument("--evidence-id", default=None, help="evidence id (stamped into the manifest)")
    ap.add_argument("--timeout", type=int, default=600, help="per-target TSK timeout (seconds)")
    ap.add_argument("--target", action="append", default=[],
                    help="a file/dir path to extract (repeatable). Windows or NTFS-relative.")
    args = ap.parse_args(argv)

    manifest = fetch_files(
        pathlib.Path(args.image),
        list(args.target),
        pathlib.Path(args.out),
        evidence_id=args.evidence_id,
        timeout_seconds=args.timeout,
    )
    if args.evidence_id:
        manifest["evidence_id"] = args.evidence_id
    json.dump(manifest, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
