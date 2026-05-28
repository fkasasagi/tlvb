"""LNK shortcut parser via LECmd.

Wraps EZ Tools' LECmd (1.5.1.0). Input is a directory of ``.lnk`` files.

Forensic value: every LNK is a recipe pointing at the original file —
target path, drive serial, MAC of the host that created it (when
applicable), original timestamps. Especially useful when the target file
has been deleted.
"""

from __future__ import annotations

from parsers._ezt_csv import EztSpec, run_simple_ezt
from parsers.base import ParseRequest, ParseResult


ARTIFACT_ID = "lnk"
PARSER_VERSION = "lnk_parser/1.0.0+lecmd-1.5.1.0"

_SPEC = EztSpec(
    artifact_id=ARTIFACT_ID,
    parser_version=PARSER_VERSION,
    dll="/opt/zimmermantools/LECmd.dll",
    input_mode="dir",
    csv_filename="lnk.csv",
    jsonl_filename="lnk.jsonl",
    timestamp_columns=["TargetCreated", "TargetModified", "SourceCreated"],
    event_type="lnk",
    extra_args=["--all"],
    caveats=[
        "MachineID may be the source host, not the analysed host — useful for "
        "cross-host correlation when removable media is involved.",
        "Volume serial number can identify the drive the target lived on at "
        "creation time.",
    ],
)


def parse(req: ParseRequest) -> ParseResult:
    return run_simple_ezt(_SPEC, req)
