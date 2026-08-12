"""bulk_extractor parser (Wave 37) — IOC extraction from raw bytes.

bulk_extractor (https://github.com/simsong/bulk_extractor) scans a disk
image or any raw byte stream for forensically interesting patterns:
emails, URLs, IPs, credit card numbers, telephone numbers, base64 blobs,
EXIF, etc. Each scanner emits its own histogram file under the output
directory.

For TLVB we ingest a curated subset (`email.txt`, `url.txt`,
`domain.txt`, `ip.txt`) as UnifiedEvents of type `ioc` so the Tier 1
agents and Tier 3 report can cross-reference them with timeline rows.

Status: skeleton — runs bulk_extractor with default scanner set if the
binary is present; flattens 4 output files into UnifiedEvent rows.

SIFT install: bulk_extractor v1.6.1 already in PATH (`/usr/local/bin`).
"""

from __future__ import annotations

import shutil

from parsers.base import (
    ParseRequest,
    ParseResult,
    audit_id,
    fail,
    make_unified_event,
    now_iso,
    run_command,
    tail,
    write_unified_events,
)

ARTIFACT_ID = "bulk_extractor"
PARSER_VERSION = "bulk_extractor_parser/0.1.0-skeleton"
BULK_BIN = "bulk_extractor"  # expects PATH lookup
IOC_FILES = (
    "email.txt",
    "url.txt",
    "domain.txt",
    "ip.txt",
)


def parse(req: ParseRequest) -> ParseResult:
    started = now_iso()
    req.output_dir.mkdir(parents=True, exist_ok=True)
    if not req.input_path.exists():
        return fail(
            artifact_id=ARTIFACT_ID, command="(no command issued)",
            started=started,
            error=f"input_path does not exist: {req.input_path}",
            parser_version=PARSER_VERSION,
        )
    if shutil.which(BULK_BIN) is None:
        return fail(
            artifact_id=ARTIFACT_ID,
            command="(bulk_extractor not installed)",
            started=started,
            error=(
                "bulk_extractor binary not found in PATH. "
                "Install via: apt install bulk-extractor "
                "(SIFT default already has it at /usr/local/bin/bulk_extractor)."
            ),
            parser_version=PARSER_VERSION,
        )
    work = req.output_dir / "be_work"
    if work.exists():
        # bulk_extractor refuses to overwrite an existing output dir.
        # Clean it so re-runs don't fail.
        import shutil as _sh
        _sh.rmtree(work, ignore_errors=True)
    cmd = [BULK_BIN, "-o", str(work), str(req.input_path)]
    cmd_str = " ".join(cmd)
    rc, stdout, stderr, elapsed = run_command(cmd, timeout=req.timeout_seconds)
    if rc != 0:
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"bulk_extractor exit={rc}", exit_code=rc,
            stdout_tail=tail(stdout), stderr_tail=tail(stderr),
            parser_version=PARSER_VERSION,
        )

    def _iter() -> Iterator[dict]:
        idx = 0
        for fname in IOC_FILES:
            p = work / fname
            if not p.is_file():
                continue
            ioc_type = fname.rsplit(".", 1)[0]
            with p.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    # bulk_extractor lines: "<offset>\t<value>\t<context>"
                    parts = s.split("\t", 2)
                    if len(parts) < 2:
                        continue
                    offset, value = parts[0], parts[1]
                    ctx = parts[2] if len(parts) > 2 else ""
                    yield make_unified_event(
                        case_id=req.case_id,
                        evidence_id=req.evidence_id,
                        artifact_id=ARTIFACT_ID,
                        audit=audit_id(req.case_id, ARTIFACT_ID, idx,
                                       f"{ioc_type}|{value}|{offset}"),
                        ts_utc="",  # bulk_extractor lines aren't timestamped
                        event_type="ioc_" + ioc_type,
                        payload={
                            "ioc_type": ioc_type,
                            "value": value,
                            "byte_offset": offset,
                            "context": ctx,
                        },
                        parser_version=PARSER_VERSION,
                    )
                    idx += 1

    jsonl_path = req.output_dir / "bulk_extractor.jsonl"
    try:
        from collections.abc import Iterator  # noqa: F401
        row_count = write_unified_events(jsonl_path, _iter())
    except Exception as exc:
        return fail(
            artifact_id=ARTIFACT_ID, command=cmd_str, started=started,
            error=f"convert IOC files→JSONL: {exc}", exit_code=rc,
            stdout_tail=tail(stdout), stderr_tail=tail(stderr),
            parser_version=PARSER_VERSION,
        )
    return ParseResult(
        artifact_id=ARTIFACT_ID, success=True,
        command=cmd_str, exit_code=rc,
        started_at=started, finished_at=now_iso(),
        duration_seconds=round(elapsed, 3),
        stdout_tail=tail(stdout), stderr_tail=tail(stderr),
        output_csv=str(work),
        output_jsonl=str(jsonl_path),
        row_count=row_count,
        parser_version=PARSER_VERSION,
        notes=[
            f"bulk_extractor processed {req.input_path} (rc={rc}).",
            f"Ingested IOC categories: {', '.join(IOC_FILES)}.",
            "Other scanners (exif, telephone, ccn, base64) skipped — "
            "out of MVP scope.",
        ],
    )
