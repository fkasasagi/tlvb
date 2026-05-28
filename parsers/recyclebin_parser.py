"""Recycle Bin parser via RBCmd.

Wraps EZ Tools' RBCmd (1.6.1.0). Input is a directory containing
``$Recycle.Bin`` ``$I*`` index files (or the root ``$Recycle.Bin``).

Forensic value: recovers original filename / path / size / deletion
timestamp for files sent to the Recycle Bin (Win Vista+). Predates
INFO2 format on XP — RBCmd handles both.
"""

from __future__ import annotations

from parsers._ezt_csv import EztSpec, run_simple_ezt
from parsers.base import ParseRequest, ParseResult


ARTIFACT_ID = "recyclebin"
PARSER_VERSION = "recyclebin_parser/1.0.0+rbcmd-1.6.1.0"

_SPEC = EztSpec(
    artifact_id=ARTIFACT_ID,
    parser_version=PARSER_VERSION,
    dll="/opt/zimmermantools/RBCmd.dll",
    input_mode="dir",
    csv_filename="recyclebin.csv",
    jsonl_filename="recyclebin.jsonl",
    timestamp_columns=["DeletedOn"],
    event_type="recyclebin",
    caveats=[
        "Per-SID: the parent folder under $Recycle.Bin is the user's SID at "
        "deletion time.",
        "Files emptied from the Recycle Bin leave no trace here — pair with "
        "MFT $J (USN journal) for hard deletes.",
    ],
)


def parse(req: ParseRequest) -> ParseResult:
    return run_simple_ezt(_SPEC, req)
