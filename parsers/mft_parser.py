"""MFT parser via MFTECmd.

Wraps EZ Tools' MFTECmd (1.3.0.0). Input is a $MFT file. Output is a
single CSV with one row per file system record (deleted records included).

Forensic value: filesystem timeline ground truth. Use the four
``Created/LastModified/LastRecordChange/LastAccess`` ($SI) columns.

This parser handles only ``$MFT``. ``$J`` (USN), ``$Boot``, ``$SDS``, and
``$I30`` are different shapes and would each warrant their own detector.
"""

from __future__ import annotations

from parsers._ezt_csv import EztSpec, run_simple_ezt
from parsers.base import ParseRequest, ParseResult


ARTIFACT_ID = "mft"
PARSER_VERSION = "mft_parser/1.0.0+mftecmd-1.3.0.0"

_SPEC = EztSpec(
    artifact_id=ARTIFACT_ID,
    parser_version=PARSER_VERSION,
    dll="/opt/zimmermantools/MFTECmd.dll",
    input_mode="file",
    csv_filename="mft.csv",
    jsonl_filename="mft.jsonl",
    # $SI Created is the most useful for "when did this file appear"; fall
    # back to LastModified0x10 / LastRecordChange0x10 if not present.
    timestamp_columns=["Created0x10", "LastModified0x10", "LastRecordChange0x10"],
    event_type="mft",
    caveats=[
        "$SI timestamps (0x10) can be manipulated by user-mode malware (timestomp). "
        "Cross-check with $FN (0x30) timestamps in the row.",
        "Deleted records are included (InUse=False); their timestamps reflect last "
        "MFT entry update before deletion, not actual file deletion time.",
        "This detector handles $MFT only. $J (USN journal), $Boot, $SDS, and $I30 "
        "require dedicated detectors / re-runs of MFTECmd with -m option.",
    ],
)


def parse(req: ParseRequest) -> ParseResult:
    return run_simple_ezt(_SPEC, req)
