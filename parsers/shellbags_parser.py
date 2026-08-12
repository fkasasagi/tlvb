"""Shellbags parser via SBECmd.

Wraps EZ Tools' SBECmd (2.1.0.0). Input is a directory of NTUSER.DAT /
UsrClass.DAT hives. Output is per-hive CSVs that we union into one
UnifiedEvent stream.

Forensic value: every shell-folder a user has navigated through Explorer
leaves a record here, even if the folder no longer exists. Useful for
proving access to a specific path that might otherwise be denied.
"""

from __future__ import annotations

from parsers._ezt_csv import EztSpec, run_simple_ezt
from parsers.base import ParseRequest, ParseResult

ARTIFACT_ID = "shellbags"
PARSER_VERSION = "shellbags_parser/1.0.0+sbecmd-2.1.0.0"

_SPEC = EztSpec(
    artifact_id=ARTIFACT_ID,
    parser_version=PARSER_VERSION,
    dll="/opt/zimmermantools/SBECmd.dll",
    input_mode="dir",
    csv_filename="shellbags.csv",
    jsonl_filename="shellbags.jsonl",
    # SBECmd column varies by version; LastWriteTime is the canonical one.
    timestamp_columns=["LastWriteTime", "FirstInteracted", "LastInteracted"],
    event_type="shellbags",
    caveats=[
        "Shellbags persist after the target folder is deleted — useful negative "
        "evidence for paths that no longer exist on disk.",
        "Per-user artifact: each NTUSER.DAT / UsrClass.DAT yields its own bag set.",
    ],
)


def parse(req: ParseRequest) -> ParseResult:
    return run_simple_ezt(_SPEC, req)
