"""Jumplists parser via JLECmd.

Wraps EZ Tools' JLECmd (1.5.1.0). Input is a directory containing
``*.automaticDestinations-ms`` and/or ``*.customDestinations-ms`` files
(typically ``%APPDATA%\\Microsoft\\Windows\\Recent\\``).

Forensic value: which files a user opened recently with which apps,
plus path/host/network share metadata.
"""

from __future__ import annotations

from parsers._ezt_csv import EztSpec, run_simple_ezt
from parsers.base import ParseRequest, ParseResult


ARTIFACT_ID = "jumplists"
PARSER_VERSION = "jumplists_parser/1.0.0+jlecmd-1.5.1.0"

_SPEC = EztSpec(
    artifact_id=ARTIFACT_ID,
    parser_version=PARSER_VERSION,
    dll="/opt/zimmermantools/JLECmd.dll",
    input_mode="dir",
    csv_filename="jumplists.csv",
    jsonl_filename="jumplists.jsonl",
    timestamp_columns=["TargetCreated", "TargetModified", "SourceCreated"],
    event_type="jumplists",
    extra_args=["--all"],
    caveats=[
        "Per-user artifact. AppId in the filename maps to a specific application "
        "(see https://github.com/EricZimmerman/JLECmd for the bundled list).",
        "TargetCreated/Modified/Accessed describe the LNK target file at the time "
        "the jumplist entry was written — not the current file state.",
    ],
)


def parse(req: ParseRequest) -> ParseResult:
    return run_simple_ezt(_SPEC, req)
