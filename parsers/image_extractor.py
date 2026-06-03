"""Disk-image extraction front-end (Issue #23, fimagex-compatible).

Detects an evidence file as a forensic disk image (E01 / raw dd/img /
VMDK / VHD / VHDX) and extracts a *triage subset* of files onto a
staging directory that the downstream artifact detectors can walk like
any other dir-style input.

What this module does:
  1. Format detection by extension + magic bytes (no heuristics — file
     header gates the mount path so we never feed a VMDK to ewfmount).
  2. Mount the image read-only via the appropriate SIFT tool:
       - .E01 / .Ex01 .... → ``ewfmount`` (FUSE)
       - .raw / .dd / .img → loop-back via ``losetup -fP --read-only``
       - .vmdk / .vhd / .vhdx → ``qemu-nbd --read-only``
  3. Enumerate filesystem partitions via ``mmls`` (single-volume images
     fall back to offset 0).
  4. Use Sleuth Kit ``fls -r -p`` to enumerate NTFS metadata, match
     entries against a curated *triage path list*, and copy them out
     with ``icat``.
  5. Write ``extract.log`` — one JSONL row per target with
     ``{path, status, sha256, partition, inum}`` so the Web UI's
     "extracts" section can show the same fields fimagex's
     ``extract.log`` does.
  6. Return the staging directory path so the orchestrator can run
     ``detect()`` on it.

Anti-goals for the MVP:
  - File carving (handled later by ``photorec``/``foremost`` add-ons).
  - Full tsk_recover dumps (too heavy for triage; we extract ~30 keyed
     paths, not the whole tree).
  - Encrypted volume handling (BitLocker, VeraCrypt) — out of scope.

All commands respect chain-of-custody (read-only mounts, original image
never touched, extracted copies live entirely under workspace/extracted/).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pathlib
import re
import shlex
import subprocess
import time
from typing import Iterable, List, Optional

from parsers.base import run_command


# Recognised image extensions, in matching priority order. Magic-byte checks
# further down disambiguate ambiguous extensions (a renamed VHD masquerading
# as .raw still gets caught).
_IMAGE_EXTENSIONS = {
    ".e01": "ewf", ".ex01": "ewf", ".s01": "ewf", ".l01": "ewf",
    ".raw": "raw", ".dd":  "raw", ".img": "raw", ".001": "raw",
    ".vmdk": "vmdk",
    ".vhd":  "vhd",
    ".vhdx": "vhdx",
}

# Magic-byte signatures — first 16 bytes.
_MAGIC_EWF  = b"EVF\x09\x0d\x0a\xff\x00"          # libewf
_MAGIC_EWF2 = b"EVF2\x0d\x0a\x81\x00"             # E01 v2
_MAGIC_VMDK = b"KDMV"                              # COWD = COW; KDMV = sparse
_MAGIC_VHDX = b"vhdxfile"
# .vhd has its footer (last 512 bytes) starting with "conectix" — header-side
# detection is unreliable, so we rely on extension for VHD.

# Triage path list (Windows). Wave 18b: the label now **mirrors the NTFS
# source path** (no friendly rename) so the staging tree preserves the
# original Windows directory structure. This is what lets the downstream
# orchestrator detectors — which use globs like `**/System32/Tasks/**`,
# `**/AutomaticDestinations`, `**/$Recycle.Bin` — find each artefact after
# extraction. Earlier Wave 18 mapped Windows/System32/Tasks → scheduled_tasks/dir,
# which extracted the files correctly but hid them from the glob, so they
# stayed NOT_PRESENT despite the contents being on disk.
_TRIAGE_PATHS: list[tuple[str, str]] = [
    # (relative_ntfs_path, staging_relpath — same as source path)
    (r"$MFT",                                                    "$MFT"),
    (r"$Extend/$UsnJrnl:$J",                                     "$J"),
    (r"$LogFile",                                                "$LogFile"),
    # Wave 20d: paired transaction logs (.LOG1/.LOG2) are mandatory siblings.
    # AmcacheParser / AppCompatCacheParser refuse to parse a "dirty" hive
    # when the logs are missing ("Registry hive is dirty and no transaction
    # logs were found in the same directory! ... Aborting!!"). RECmd is more
    # lenient, which is why registry parses OK while shimcache/amcache fail
    # on the same SYSTEM hive on the same case. Extract the logs alongside.
    (r"Windows/System32/config/SYSTEM",                          "Windows/System32/config/SYSTEM"),
    (r"Windows/System32/config/SYSTEM.LOG1",                     "Windows/System32/config/SYSTEM.LOG1"),
    (r"Windows/System32/config/SYSTEM.LOG2",                     "Windows/System32/config/SYSTEM.LOG2"),
    (r"Windows/System32/config/SOFTWARE",                        "Windows/System32/config/SOFTWARE"),
    (r"Windows/System32/config/SOFTWARE.LOG1",                   "Windows/System32/config/SOFTWARE.LOG1"),
    (r"Windows/System32/config/SOFTWARE.LOG2",                   "Windows/System32/config/SOFTWARE.LOG2"),
    (r"Windows/System32/config/SECURITY",                        "Windows/System32/config/SECURITY"),
    (r"Windows/System32/config/SECURITY.LOG1",                   "Windows/System32/config/SECURITY.LOG1"),
    (r"Windows/System32/config/SECURITY.LOG2",                   "Windows/System32/config/SECURITY.LOG2"),
    (r"Windows/System32/config/SAM",                             "Windows/System32/config/SAM"),
    (r"Windows/System32/config/SAM.LOG1",                        "Windows/System32/config/SAM.LOG1"),
    (r"Windows/System32/config/SAM.LOG2",                        "Windows/System32/config/SAM.LOG2"),
    (r"Windows/System32/config/DEFAULT",                         "Windows/System32/config/DEFAULT"),
    (r"Windows/System32/config/DEFAULT.LOG1",                    "Windows/System32/config/DEFAULT.LOG1"),
    (r"Windows/System32/config/DEFAULT.LOG2",                    "Windows/System32/config/DEFAULT.LOG2"),
    (r"Windows/AppCompat/Programs/Amcache.hve",                  "Windows/AppCompat/Programs/Amcache.hve"),
    (r"Windows/AppCompat/Programs/Amcache.hve.LOG1",             "Windows/AppCompat/Programs/Amcache.hve.LOG1"),
    (r"Windows/AppCompat/Programs/Amcache.hve.LOG2",             "Windows/AppCompat/Programs/Amcache.hve.LOG2"),
    (r"Windows/Prefetch",                                        "Windows/Prefetch"),
    (r"Windows/System32/winevt/Logs",                            "Windows/System32/winevt/Logs"),
    (r"Windows/System32/Tasks",                                  "Windows/System32/Tasks"),
    (r"Windows/System32/sru/SRUDB.dat",                          "Windows/System32/sru/SRUDB.dat"),
    (r"$Recycle.Bin",                                            "$Recycle.Bin"),
]

# Per-user paths — applied to every Users/<u>/ subdir we discover. The
# staging relpath also mirrors the source so the staging tree looks like
# `users/<u>/<source-relative-path>/...`.
_PER_USER_TRIAGE: list[tuple[str, str]] = [
    # Wave 20d: per-user hive LOG siblings (RegRipper / RECmd are lenient but
    # other future per-user hive parsers may not be — extract for consistency
    # with the system-hive set above).
    (r"NTUSER.DAT",                                              "NTUSER.DAT"),
    (r"NTUSER.DAT.LOG1",                                         "NTUSER.DAT.LOG1"),
    (r"NTUSER.DAT.LOG2",                                         "NTUSER.DAT.LOG2"),
    (r"AppData/Local/Microsoft/Windows/UsrClass.dat",            "AppData/Local/Microsoft/Windows/UsrClass.dat"),
    (r"AppData/Local/Microsoft/Windows/UsrClass.dat.LOG1",       "AppData/Local/Microsoft/Windows/UsrClass.dat.LOG1"),
    (r"AppData/Local/Microsoft/Windows/UsrClass.dat.LOG2",       "AppData/Local/Microsoft/Windows/UsrClass.dat.LOG2"),
    (r"AppData/Roaming/Microsoft/Windows/Recent",                "AppData/Roaming/Microsoft/Windows/Recent"),
    (r"AppData/Local/Microsoft/Windows/Recent",                  "AppData/Local/Microsoft/Windows/Recent"),
    (r"AppData/Local/Microsoft/Edge/User Data/Default/History",  "AppData/Local/Microsoft/Edge/User Data/Default/History"),
    (r"AppData/Local/Google/Chrome/User Data/Default/History",   "AppData/Local/Google/Chrome/User Data/Default/History"),
    (r"AppData/Local/ConnectedDevicesPlatform",                  "AppData/Local/ConnectedDevicesPlatform"),
]


@dataclasses.dataclass
class ExtractRecord:
    target: str
    status: str                        # ok / not_found / fail / skip
    partition: Optional[int] = None
    inum: Optional[str] = None
    sha256: Optional[str] = None
    bytes: int = 0
    extracted_path: Optional[str] = None
    error: Optional[str] = None


@dataclasses.dataclass
class ExtractionResult:
    staging_dir: pathlib.Path          # downstream detect() walks this
    extract_log: pathlib.Path
    records: list[ExtractRecord]
    image_format: str
    mount_method: str
    summary: dict


def detect_image(path: pathlib.Path) -> str | None:
    """Return one of {ewf, raw, vmdk, vhd, vhdx} or None when ``path`` is not
    a recognisable disk image. Extension is the gate; magic bytes promote
    raw→vmdk/vhdx when a renamed file is detected.
    """
    if not path.is_file():
        return None
    ext = path.suffix.lower()
    declared = _IMAGE_EXTENSIONS.get(ext)
    try:
        with path.open("rb") as fh:
            head = fh.read(16)
    except OSError:
        return None

    if head.startswith(_MAGIC_EWF) or head.startswith(_MAGIC_EWF2):
        return "ewf"
    if head.startswith(_MAGIC_VMDK):
        return "vmdk"
    if head.startswith(_MAGIC_VHDX):
        return "vhdx"
    return declared


def is_image(path: pathlib.Path) -> bool:
    return detect_image(path) is not None


def extract(
    image_path: pathlib.Path,
    workspace: pathlib.Path,
    *,
    target_paths: Iterable[tuple[str, str]] = _TRIAGE_PATHS,
    timeout_seconds: int = 1800,
) -> ExtractionResult:
    """Mount + extract a triage subset.

    Returns an :class:`ExtractionResult`. On any unrecoverable error the
    result still carries an ``extract.log`` with the failure recorded so
    Review Gate 0 can surface what went wrong instead of erroring the
    whole pipeline.
    """
    fmt = detect_image(image_path)
    if fmt is None:
        raise ValueError(f"not a recognised disk image: {image_path}")

    staging_root = workspace / "extracted"
    staging_root.mkdir(parents=True, exist_ok=True)
    extract_log = workspace / "extract.log"

    records: list[ExtractRecord] = []
    started = time.time()

    mount_method, raw_device, partitions, mount_cleanup = _mount_image(
        image_path, fmt, workspace,
    )

    try:
        if not partitions:
            records.append(ExtractRecord(
                target="(image scan)",
                status="fail",
                error=f"no NTFS partitions discovered (mount_method={mount_method})",
            ))
        for part_idx, offset_bytes in partitions:
            staging_for_part = staging_root / f"part{part_idx:02d}"
            staging_for_part.mkdir(exist_ok=True)
            # Static targets — pull each.
            for ntfs_path, label in target_paths:
                rec = _extract_one(
                    raw_device, offset_bytes, ntfs_path,
                    staging_for_part / label, label, part_idx,
                    timeout_seconds,
                )
                records.append(rec)
            # Per-user expansion under Users/.
            for user_dir in _list_dir(raw_device, offset_bytes, "Users", timeout_seconds):
                for sub_path, sub_label in _PER_USER_TRIAGE:
                    full = f"Users/{user_dir}/{sub_path}"
                    full_label = f"{sub_label}#{user_dir}"
                    rec = _extract_one(
                        raw_device, offset_bytes, full,
                        staging_for_part / "users" / user_dir / sub_label,
                        full_label, part_idx, timeout_seconds,
                    )
                    records.append(rec)
    finally:
        mount_cleanup()

    elapsed = time.time() - started
    summary = {
        "total": len(records),
        "ok":        sum(1 for r in records if r.status == "ok"),
        "not_found": sum(1 for r in records if r.status == "not_found"),
        "fail":      sum(1 for r in records if r.status == "fail"),
        "skip":      sum(1 for r in records if r.status == "skip"),
        "elapsed_seconds": round(elapsed, 3),
    }

    with extract_log.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "schema": "findevil/extract-log/v1",
            "image_path": str(image_path),
            "image_format": fmt,
            "mount_method": mount_method,
            "summary": summary,
        }) + "\n")
        for r in records:
            fh.write(json.dumps(dataclasses.asdict(r)) + "\n")

    return ExtractionResult(
        staging_dir=staging_root,
        extract_log=extract_log,
        records=records,
        image_format=fmt,
        mount_method=mount_method,
        summary=summary,
    )


# ----------------------------------------------------------------------------
# Mount layer
# ----------------------------------------------------------------------------

def _mount_image(image: pathlib.Path, fmt: str, workspace: pathlib.Path):
    """Mount ``image`` and return ``(method, raw_device, partitions, cleanup)``.

    - ``raw_device`` is either a path to a raw block-style file (post-EWF)
      or a block device node (post-NBD/losetup) — both accepted by Sleuth
      Kit's ``-o`` offset addressing.
    - ``partitions`` is a list of ``(part_idx, offset_bytes)`` extracted
      from ``mmls``. Single-volume images yield ``[(0, 0)]``.
    - ``cleanup`` is a callable that unmounts/detaches; safe to call
      multiple times.
    """
    cleanups: list = []

    def cleanup():
        for fn in reversed(cleanups):
            try:
                fn()
            except Exception:
                pass
        cleanups.clear()

    if fmt == "ewf":
        mp = workspace / "ewfmount"
        mp.mkdir(exist_ok=True)
        rc, out, err, _ = run_command(["ewfmount", str(image), str(mp)],
                                      timeout=120)
        if rc != 0:
            cleanup()
            return ("ewfmount-failed", "", [],
                    lambda: None)
        cleanups.append(lambda: subprocess.run(
            ["fusermount", "-u", str(mp)], check=False))
        # ewfmount exposes a single file ``ewf1`` representing the raw image.
        raw = mp / "ewf1"
        if not raw.is_file():
            return ("ewfmount-no-ewf1", "", [], cleanup)
        partitions = _enumerate_partitions(str(raw))
        return ("ewfmount", str(raw), partitions, cleanup)

    if fmt == "raw":
        partitions = _enumerate_partitions(str(image))
        return ("raw-direct", str(image), partitions, cleanup)

    if fmt in ("vmdk", "vhd", "vhdx"):
        # qemu-nbd requires the `nbd` kernel module + sudo. On stock SIFT
        # this is available but needs root; document the failure cleanly
        # so Review Gate 0 can point the operator at the install hint.
        nbd = _find_free_nbd()
        if nbd is None:
            return ("qemu-nbd-no-device", "", [], cleanup)
        rc, out, err, _ = run_command(
            ["sudo", "-n", "qemu-nbd", "--read-only", "--connect=" + nbd,
             "--format", fmt, str(image)], timeout=120)
        if rc != 0:
            cleanup()
            return ("qemu-nbd-failed", "", [], lambda: None)
        cleanups.append(lambda: subprocess.run(
            ["sudo", "-n", "qemu-nbd", "--disconnect", nbd], check=False))
        # Settle the device-mapper if partitions are nested.
        subprocess.run(["sudo", "-n", "partprobe", nbd], check=False, timeout=30)
        partitions = _enumerate_partitions(nbd)
        return ("qemu-nbd", nbd, partitions, cleanup)

    return ("unknown", "", [], cleanup)


def _find_free_nbd() -> str | None:
    for i in range(0, 16):
        nbd = f"/dev/nbd{i}"
        sysfs = pathlib.Path(f"/sys/class/block/nbd{i}/pid")
        if pathlib.Path(nbd).exists() and not sysfs.exists():
            return nbd
    return None


# ----------------------------------------------------------------------------
# Filesystem walk via Sleuth Kit
# ----------------------------------------------------------------------------

# An mmls row: "<entry>: <slot> <start> <end> <length> [size] <description>".
# Capture START / END / LENGTH sectors (mmls reports the offset columns in
# sectors — see the "Units are in N-byte sectors" header; the older
# `-B`=bytes assumption was wrong and broke every GPT image). MBR and GPT
# rows share these five leading columns.
_MMLS_ROW = re.compile(r"^\s*\d+:\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)\b")
# Rows that are not extractable data volumes: GPT/MBR metadata, unallocated
# gaps, and the EFI/MSR system partitions. Everything else is a candidate —
# crucially GPT labels the Windows NTFS volume "Basic data partition", not
# "NTFS", so we must NOT key off the filesystem name.
_MMLS_SKIP = re.compile(
    r"unallocated|EFI system|Microsoft reserved|"
    r"\bTable\b|GPT Header|Primary\b|Secondary\b",
    re.I,
)


def _enumerate_partitions(raw_device: str) -> list[tuple[int, int]]:
    """Return ``[(part_idx, offset_bytes)]`` for candidate data volumes.

    Parses every ``mmls`` row and keeps the data volumes, dropping GPT/MBR
    metadata, unallocated gaps and the EFI/MSR system partitions. This
    handles GPT disks (modern Windows) where the NTFS volume is labelled
    "Basic data partition" rather than "NTFS". Non-OS volumes that slip
    through (e.g. a recovery partition) are harmless — the per-target
    extraction just records them as ``not_found``.

    Falls back to ``[(0, 0)]`` (single-volume / no partition table) when
    ``mmls`` errors out — covers single-partition raw dumps.
    """
    if not raw_device:
        return []
    rc, out, _, _ = run_command(["mmls", "-aB", raw_device], timeout=60)
    if rc != 0 or not out:
        return [(0, 0)]
    out_parts: list[tuple[int, int]] = []
    for line in out.splitlines():
        m = _MMLS_ROW.match(line)
        if not m:
            continue
        start_sector = int(m.group(1))
        length = int(m.group(3))
        if start_sector == 0 or length == 0 or _MMLS_SKIP.search(line):
            continue
        # Downstream TSK callers recover the sector offset with `// 512`,
        # so store start_sector * 512 here (512-byte sectors).
        out_parts.append((len(out_parts), start_sector * 512))
    return out_parts or [(0, 0)]


def _list_dir(raw_device: str, offset_bytes: int, ntfs_path: str,
              timeout: int) -> list[str]:
    """Return immediate subdir names of ``ntfs_path``. Best-effort.

    Wave 18 fix: resolve ``ntfs_path`` → inum via ifind first, then pass
    the **inum** to fls (not the textual path — fls would treat that as a
    second image file and error out). Also drop the ``-r`` recursive flag
    so we get exactly the direct children, not the full subtree.
    """
    if not raw_device:
        return []
    inum = _ifind(raw_device, offset_bytes, ntfs_path, timeout)
    if inum is None:
        return []
    # -D restricts to directory entries, no -r so we list only the
    # immediate children. With -p the output prefixes each line with the
    # full path, but at this point we only care about the basename.
    cmd = ["fls", "-D", "-p", "-o", str(offset_bytes // 512),
           raw_device, inum]
    rc, out, _, _ = run_command(cmd, timeout=timeout)
    if rc != 0 or not out:
        return []
    names: set[str] = set()
    for line in out.splitlines():
        # Lines look like "d/d 12345-128-1:	SomeUser" (no path prefix when
        # we list by inum without -r). Tolerate both with-prefix and
        # bare forms because behaviour has varied across TSK versions.
        # Anchor on "d/" so regular files don't sneak in if a TSK version
        # ignores the -D flag.
        m = re.match(r"^d/[a-z]\s+\S+:\s+(.+?)/?\s*$", line)
        if not m:
            continue
        path = m.group(1)
        # Strip any "Users/" prefix if fls inserted it, take the last
        # path segment as the directory name we care about.
        name = path.rsplit("/", 1)[-1]
        if name and name not in (".", ".."):
            names.add(name)
    return sorted(names)


_FLS_INUM = re.compile(r"^[a-z\-]/[a-z\-]\s+(\d+(?:-\d+-\d+)?)(?:\(realloc\))?:")


def _extract_one(raw_device: str, offset_bytes: int, ntfs_path: str,
                 dest: pathlib.Path, label: str, partition: int,
                 timeout: int) -> ExtractRecord:
    """Extract one file (or whole directory, when ``ntfs_path`` resolves to
    a directory) into ``dest``.

    Records into ExtractRecord. Bubbles ``not_found`` for paths not present
    in the volume (most images won't have every triage path) — fimagex
    treats this as benign and so do we.
    """
    if not raw_device:
        return ExtractRecord(target=label, partition=partition, status="skip",
                             error="no raw device (mount failed earlier)")

    # Wave 20d: Alternate Data Stream (ADS) handling. For a path like
    # `$Extend/$UsnJrnl:$J`, `ifind -n` resolves the FILE inum (55815)
    # but `icat <inum>` then returns the file's DEFAULT $DATA — which for
    # $UsnJrnl is the 32-byte $Max stream, NOT the multi-GB $J ADS we
    # actually want. Resolve the ADS attribute id explicitly so icat is
    # called with `<inum>-128-<attrid>`. The $J stream is non-resident
    # sparse and can be 9+ GB allocated with only a small tail of real
    # records (leading region is pruned-zeros). Stream through a
    # sparse-aware writer so the staging dir doesn't balloon to the
    # full allocated size on disk.
    if ":" in ntfs_path:
        file_path, ads_name = ntfs_path.rsplit(":", 1)
        inum = _ifind(raw_device, offset_bytes, file_path, timeout)
        if inum is None:
            return ExtractRecord(target=label, partition=partition,
                                 status="not_found")
        attr_spec = _resolve_ads(raw_device, offset_bytes, inum,
                                 ads_name, timeout)
        if attr_spec is None:
            return ExtractRecord(target=label, partition=partition,
                                 status="not_found", inum=inum,
                                 error=f"ADS ':{ads_name}' not in attribute table")
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            return _icat_to_file_sparse(
                raw_device, offset_bytes, attr_spec, dest, label,
                partition, timeout,
            )
        except Exception as exc:
            return ExtractRecord(target=label, partition=partition,
                                 status="fail", inum=inum, error=str(exc))

    inum = _ifind(raw_device, offset_bytes, ntfs_path, timeout)
    if inum is None:
        return ExtractRecord(target=label, partition=partition, status="not_found")

    # Determine whether the target is a directory by listing it.
    is_dir = _is_directory(raw_device, offset_bytes, inum, timeout)

    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        if is_dir:
            return _extract_directory(
                raw_device, offset_bytes, ntfs_path, dest, label, partition,
                inum, timeout,
            )
        return _icat_to_file(
            raw_device, offset_bytes, inum, dest, label, partition, timeout,
        )
    except Exception as exc:
        return ExtractRecord(target=label, partition=partition, status="fail",
                             inum=inum, error=str(exc))


def _ifind(raw_device: str, offset_bytes: int, ntfs_path: str,
           timeout: int) -> str | None:
    """Look up an NTFS file by name → MFT inum string.

    Sleuth Kit ifind quirks:
      - Reports "File not found" with **exit code 0** on miss.
      - Returns the literal "0" for `/$MFT` because $MFT IS MFT entry 0 —
        we must NOT treat that as a miss (an earlier version of this
        function did, dropping `$MFT` from every extraction).
    """
    cmd = ["ifind", "-n", ntfs_path, "-o", str(offset_bytes // 512), raw_device]
    rc, out, _, _ = run_command(cmd, timeout=timeout)
    if rc != 0:
        return None
    line = out.strip().splitlines()[0] if out.strip() else ""
    if not line or line.startswith("File not found"):
        return None
    return line


# Matches istat's `Type: $DATA (128-87)   Name: $J ...` attribute table line.
# Captures (type, id, name). Tolerant of whitespace because istat columns
# vary across TSK versions.
_ISTAT_ADS = re.compile(
    r"Type:\s+\$DATA\s+\((\d+)-(\d+)\)\s+Name:\s+(\S+)"
)


def _resolve_ads(raw_device: str, offset_bytes: int, inum: str,
                 ads_name: str, timeout: int) -> str | None:
    """Resolve an NTFS Alternate Data Stream name → ``inum-type-id`` spec.

    Sleuth Kit's ``ifind -n 'path:adsname'`` only returns the FILE inum, not
    the ADS attribute id. ``icat <inum>`` then defaults to the file's
    primary $DATA stream, which for $UsnJrnl is the 32-byte $Max metadata
    rather than the multi-GB $J record stream. Walk istat's attribute table
    to find the requested ADS by name and return the icat-ready
    ``<inum>-<type>-<id>`` spec (or None if the ADS is missing).
    """
    cmd = ["istat", "-o", str(offset_bytes // 512), raw_device, inum]
    rc, out, _, _ = run_command(cmd, timeout=timeout)
    if rc != 0 or not out:
        return None
    for line in out.splitlines():
        m = _ISTAT_ADS.match(line.strip())
        if not m:
            continue
        attr_type, attr_id, name = m.group(1), m.group(2), m.group(3)
        if name == ads_name:
            return f"{inum}-{attr_type}-{attr_id}"
    return None


def _is_directory(raw_device: str, offset_bytes: int, inum: str,
                  timeout: int) -> bool:
    """Wave 18 fix: scan the istat header block, not just line 0.

    Sleuth Kit's istat for NTFS prints:
        MFT Entry Header Values:        <- line 0
        Entry: 21866        Sequence: 10
        $LogFile Sequence Number: 42968407519
        Allocated Directory             <- typically line 3 or 4 (varies)
        Links: 1
        ...
    The earlier implementation only looked at line 0, which never contains
    "Directory", so every directory was treated as a file. That made
    `_extract_directory` unreachable and the triage paths like
    `Windows/Prefetch` / `Windows/System32/winevt/Logs` were icat'd as if
    they were a single file — yielding a ~200-byte index record instead of
    the actual *.pf / *.evtx contents.
    Scan the first 12 lines (the header section is short) and also accept
    "Deleted Directory" so already-unlinked dirs are still recognised.
    """
    cmd = ["istat", "-o", str(offset_bytes // 512), raw_device, inum]
    rc, out, _, _ = run_command(cmd, timeout=timeout)
    if rc != 0 or not out:
        return False
    for line in out.splitlines()[:12]:
        if "Directory" in line:  # "Allocated Directory" / "Deleted Directory"
            return True
    return False


def _icat_to_file_sparse(raw_device: str, offset_bytes: int, attr_spec: str,
                         dest: pathlib.Path, label: str, partition: int,
                         timeout: int) -> ExtractRecord:
    """Sparse-aware extraction for ADS that may be non-resident-sparse.

    Streams ``icat`` stdout through a 64 KiB block reader. Blocks that are
    entirely zero are skipped via ``seek()`` (creating sparse holes on
    filesystems that support them — ext4, btrfs, xfs all do). Final size
    is preserved with ``truncate()`` so the apparent length still matches
    what MFTECmd expects when parsing $UsnJrnl:$J. Disk usage drops from
    ~9 GiB (full allocated) to a few hundred KiB for a typical journal
    whose leading region is pruned-zeros.

    SHA-256 is computed across the actual byte stream (including the
    zero holes) so the audit hash matches what a non-sparse copy would
    have produced. The hash is computed in the same loop as the writer
    to avoid a second pass over disk.
    """
    import hashlib as _hashlib

    BLOCK = 64 * 1024
    cmd_str = " ".join(["icat", "-o", str(offset_bytes // 512),
                        shlex.quote(raw_device), attr_spec])
    try:
        proc = subprocess.Popen(
            ["icat", "-o", str(offset_bytes // 512), raw_device, attr_spec],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        h = _hashlib.sha256()
        total = 0
        try:
            with dest.open("wb") as out_fh:
                while True:
                    chunk = proc.stdout.read(BLOCK)
                    if not chunk:
                        break
                    h.update(chunk)
                    if chunk == b"\x00" * len(chunk):
                        # All-zero block → leave a sparse hole.
                        out_fh.seek(len(chunk), 1)  # 1 = SEEK_CUR
                    else:
                        out_fh.write(chunk)
                    total += len(chunk)
                # Truncate to actual stream length so the file size on disk
                # matches the original ADS init_size (matters for MFTECmd
                # offset arithmetic on $J).
                out_fh.truncate(total)
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return ExtractRecord(target=label, partition=partition,
                                 status="fail", inum=attr_spec,
                                 error="icat timeout")

        if proc.returncode != 0:
            stderr = proc.stderr.read().decode("utf-8", "replace")[:300]
            return ExtractRecord(target=label, partition=partition,
                                 status="fail", inum=attr_spec,
                                 error=f"icat exit={proc.returncode}: {stderr}")
        return ExtractRecord(
            target=label, partition=partition, status="ok",
            inum=attr_spec, sha256=h.hexdigest(), bytes=total,
            extracted_path=str(dest),
        )
    except Exception as exc:
        return ExtractRecord(target=label, partition=partition,
                             status="fail", inum=attr_spec, error=str(exc))


def _icat_to_file(raw_device: str, offset_bytes: int, inum: str,
                  dest: pathlib.Path, label: str, partition: int,
                  timeout: int) -> ExtractRecord:
    cmd_str = " ".join(["icat", "-o", str(offset_bytes // 512), shlex.quote(raw_device), inum])
    try:
        with dest.open("wb") as out_fh:
            proc = subprocess.run(
                ["icat", "-o", str(offset_bytes // 512), raw_device, inum],
                stdout=out_fh, stderr=subprocess.PIPE, timeout=timeout,
            )
        if proc.returncode != 0:
            return ExtractRecord(target=label, partition=partition,
                                 status="fail", inum=inum,
                                 error=f"icat exit={proc.returncode}: " +
                                       proc.stderr.decode("utf-8", "replace")[:300])
        size = dest.stat().st_size if dest.exists() else 0
        return ExtractRecord(
            target=label, partition=partition, status="ok",
            inum=inum, sha256=_sha256(dest), bytes=size,
            extracted_path=str(dest),
        )
    except subprocess.TimeoutExpired:
        return ExtractRecord(target=label, partition=partition, status="fail",
                             inum=inum, error="icat timeout")


def _extract_directory(raw_device: str, offset_bytes: int, ntfs_path: str,
                       dest_dir: pathlib.Path, label: str, partition: int,
                       inum: str, timeout: int) -> ExtractRecord:
    """Recursively copy every file under ``ntfs_path`` into ``dest_dir``.

    Wave 18 fix: pass the directory **inum** to fls, not the textual path.
    Sleuth Kit's fls signature is ``fls [opts] IMAGE [INUM]`` — when given
    a path string it treats it as a *second image file* and errors out
    ("raw_open: image \"Windows/Prefetch\" - No such file"). The earlier
    implementation passed the path so rc was non-zero for every directory
    and we silently returned ``status=fail``. Combined with the Bug X
    (_is_directory always returned False) this meant directory triage
    paths never produced any output at all — the user saw `prefetch/dir`
    in the log as a 200-byte file because the *file* path icat'd the
    dir's index allocation. Both must be fixed together.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["fls", "-r", "-p", "-o", str(offset_bytes // 512),
           raw_device, inum]
    rc, out, _, _ = run_command(cmd, timeout=timeout)
    if rc != 0:
        return ExtractRecord(target=label, partition=partition,
                             status="fail", inum=inum,
                             error=f"fls -r exit={rc}")
    extracted = 0
    failed = 0
    for line in out.splitlines():
        # Process only regular-file entries: "r/r ...:	relative/path"
        if not line.startswith("r/r"):
            continue
        m = _FLS_INUM.search(line)
        if not m:
            continue
        ent_inum = m.group(1)
        try:
            tab = line.index("\t")
        except ValueError:
            continue
        rel = line[tab + 1:].strip()
        if not rel:
            continue
        # Strip the leading ntfs_path prefix when fls prepends it.
        if rel.startswith(ntfs_path + "/"):
            rel = rel[len(ntfs_path) + 1:]
        rel = rel.replace(":", "_")          # ADS chars
        target = dest_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        rec = _icat_to_file(raw_device, offset_bytes, ent_inum, target,
                            f"{label}/{rel}", partition, timeout)
        if rec.status == "ok":
            extracted += 1
        else:
            failed += 1
    return ExtractRecord(
        target=label, partition=partition,
        status="ok" if extracted > 0 else "not_found",
        inum=inum,
        bytes=sum((dest_dir / p).stat().st_size
                  for p in os.listdir(dest_dir)
                  if (dest_dir / p).is_file()),
        extracted_path=str(dest_dir),
        error=None if failed == 0 else f"{failed} files failed to extract",
    )


def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
