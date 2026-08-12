"""IIS applicationHost.config — registered HTTP module inventory parser.

IIS persistence (MITRE T1505.004 "Server Software Component: IIS Components")
is established by registering a native or managed HTTP module that loads into
the IIS worker process and runs on every request. The registration lives in
``%windir%\\System32\\inetsrv\\config\\applicationHost.config``:

  <globalModules>
      <add name="MyModule" image="C:\\Windows\\System32\\evil.dll" />   <!-- native -->
  </globalModules>
  <system.webServer>
      <modules>
          <add name="MyManagedModule" type="Ns.Type, Assembly" />       <!-- managed -->
      </modules>
  </system.webServer>

The DLL/assembly itself is rarely caught by signature scans (it is just a DLL),
but the *registration entry* is a durable, high-fidelity artefact: a legitimate
IIS box only ever references modules under ``%windir%\\System32\\inetsrv\\`` or
``%windir%\\Microsoft.NET\\``. An ``image=`` that points anywhere else (System32
root, inetpub, Temp, a user profile, an upload dir) is the tell-tale sign of an
``appcmd install module`` / GodPotato-style backdoor.

This parser does NOT decide good/evil — it normalises every registered module to
``artifact_id='iis_module'`` so Tier 1A rules (see
``custom/iis_native_module_nonstandard_image.yml``) can flag the non-standard
image paths. Emitting the full inventory (legitimate modules included) is
deliberate: the baseline is what makes the one rogue entry obvious.

Input: a single ``applicationHost.config`` file (or a directory containing one).
"""

from __future__ import annotations

import datetime
import pathlib
import xml.etree.ElementTree as ET
from collections.abc import Iterator

from parsers.base import (
    ParseRequest,
    ParseResult,
    audit_id,
    fail,
    make_unified_event,
    now_iso,
    write_unified_events,
)

ARTIFACT_ID = "iis_module"
PARSER_VERSION = "iis_module_parser/0.1.0"


def _find_config(input_path: pathlib.Path) -> pathlib.Path | None:
    """Resolve the applicationHost.config file from a file or directory input."""
    if input_path.is_file():
        return input_path
    if input_path.is_dir():
        for cand in input_path.rglob("*"):
            if cand.is_file() and cand.name.lower() == "applicationhost.config":
                return cand
    return None


def _expand_image(image: str) -> str:
    """Expand the IIS config env vars in an image path so a rule can pattern-match
    a concrete path. IIS only expands %windir% / %ProgramFiles% style tokens."""
    repl = {
        "%windir%": r"C:\Windows",
        "%systemroot%": r"C:\Windows",
        "%programfiles%": r"C:\Program Files",
        "%programfiles(x86)%": r"C:\Program Files (x86)",
        "%systemdrive%": "C:",
    }
    out = image
    low = out.lower()
    for token, val in repl.items():
        idx = low.find(token)
        while idx != -1:
            out = out[:idx] + val + out[idx + len(token):]
            low = out.lower()
            idx = low.find(token)
    return out


def _file_mtime_iso(path: pathlib.Path) -> str:
    """Best-effort event timestamp: the config file's last-modified time (when the
    module set was last edited). Extraction may not preserve original mtimes, so
    this is advisory — the detection is state-based, not time-based."""
    try:
        ts = path.stat().st_mtime
        return (
            datetime.datetime.fromtimestamp(ts, tz=datetime.UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except OSError:
        return ""


def _iter_modules(cfg: pathlib.Path) -> Iterator[dict]:
    """Yield one record per registered module (native globalModules + managed
    <modules> additions, including those inside <location> blocks)."""
    tree = ET.parse(cfg)
    root = tree.getroot()

    # Native modules: every <globalModules>/<add image=...> anywhere in the file.
    for gm in root.iter("globalModules"):
        for add in gm.findall("add"):
            name = add.get("name", "")
            image = add.get("image", "")
            yield {
                "module_name": name,
                "module_kind": "native",
                "image": image,
                "image_expanded": _expand_image(image),
                "precondition": add.get("preCondition", ""),
                "config_section": "globalModules",
            }

    # Managed modules: <modules>/<add type=...> (server-wide and per-<location>).
    for loc_path, modules_el in _iter_modules_elements(root):
        for add in modules_el.findall("add"):
            mtype = add.get("type", "")
            if not mtype:
                # name-only entries just enable a globalModule; not a new code path
                continue
            yield {
                "module_name": add.get("name", ""),
                "module_kind": "managed",
                "image": mtype,
                "image_expanded": mtype,
                "precondition": add.get("preCondition", ""),
                "config_section": "modules",
                "location_path": loc_path,
            }


def _iter_modules_elements(root: ET.Element) -> Iterator[tuple[str, ET.Element]]:
    """Yield (location_path, <modules> element) for the server-wide section and
    every <location> override."""
    for sws in root.iter("system.webServer"):
        for modules_el in sws.findall("modules"):
            yield ("", modules_el)
    for loc in root.iter("location"):
        loc_path = loc.get("path", "")
        for sws in loc.findall("system.webServer"):
            for modules_el in sws.findall("modules"):
                yield (loc_path, modules_el)


def parse(req: ParseRequest) -> ParseResult:
    started = now_iso()
    req.output_dir.mkdir(parents=True, exist_ok=True)

    cfg = _find_config(req.input_path)
    if cfg is None or not cfg.exists():
        return fail(
            artifact_id=ARTIFACT_ID, command="(in-process parse)",
            started=started,
            error=f"no applicationHost.config under: {req.input_path}",
            parser_version=PARSER_VERSION,
        )

    ts_utc = _file_mtime_iso(cfg)
    computer = ""

    def _iter() -> Iterator[dict]:
        idx = 0
        for rec in _iter_modules(cfg):
            payload = dict(rec)
            payload["config_path"] = str(cfg)
            yield make_unified_event(
                case_id=req.case_id,
                evidence_id=req.evidence_id,
                artifact_id=ARTIFACT_ID,
                audit=audit_id(req.case_id, ARTIFACT_ID, idx,
                               f"{rec.get('config_section')}|{rec.get('module_name')}|{rec.get('image')}"),
                ts_utc=ts_utc,
                event_type="iis_module_registration",
                computer=computer,
                payload=payload,
                parser_version=PARSER_VERSION,
            )
            idx += 1

    jsonl_path = req.output_dir / "iis_module.jsonl"
    try:
        row_count = write_unified_events(jsonl_path, _iter())
    except ET.ParseError as exc:
        return fail(
            artifact_id=ARTIFACT_ID, command="(in-process parse)",
            started=started,
            error=f"applicationHost.config is not well-formed XML: {exc}",
            parser_version=PARSER_VERSION,
        )
    except Exception as exc:  # noqa: BLE001 — surface any parse error as a FAIL row
        return fail(
            artifact_id=ARTIFACT_ID, command="(in-process parse)",
            started=started,
            error=f"parse applicationHost.config→JSONL: {exc}",
            parser_version=PARSER_VERSION,
        )

    if row_count == 0:
        return fail(
            artifact_id=ARTIFACT_ID, command="(in-process parse)",
            started=started,
            error="applicationHost.config parsed but no <globalModules>/<modules> entries found",
            parser_version=PARSER_VERSION,
        )

    finished = now_iso()
    return ParseResult(
        artifact_id=ARTIFACT_ID,
        success=True,
        command="(in-process parse)",
        exit_code=0,
        started_at=started,
        finished_at=finished,
        duration_seconds=0.0,
        output_jsonl=str(jsonl_path),
        row_count=row_count,
        parser_version=PARSER_VERSION,
        notes=[
            "IIS applicationHost.config registered modules normalised to "
            "artifact_id='iis_module' (module_name/module_kind/image/image_expanded).",
            "Detection is state-based: a native module whose image= path is outside "
            "%windir%\\System32\\inetsrv\\ or %windir%\\Microsoft.NET\\ indicates "
            "T1505.004 IIS-component persistence. ts_utc is the config file mtime "
            "(advisory — extraction may not preserve original mtimes).",
        ],
    )
