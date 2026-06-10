"""Tests for parsers.w3c_iis_parser — W3C / IIS native / NCSA web access logs.

Phase 1 of IIS support (2026-06-09): the 0.1.0 skeleton only read the W3C
#Fields layout and dumped raw columns. 0.2.0 detects three on-disk formats and
normalises ALL of them to canonical W3C field names (cs-uri-stem, cs-uri-query,
c-ip, cs-method, sc-status, cs-User-Agent) so the Sigma category:webserver rule
corpus matches regardless of source format.

Asserted here:
  - format auto-detection (w3c / iis / ncsa)
  - field normalisation to W3C names across all three layouts
  - URI stem/query split
  - timestamp handling (W3C & NCSA → UTC 'Z'; IIS native LOCAL → UTC via the
    evidence timezone)
  - multiple #Fields headers in one W3C file (config change / log roll)
  - computer derivation (s-computername > s-ip)
"""

from __future__ import annotations

import json
import pathlib

from parsers.base import ParseRequest
from parsers import w3c_iis_parser as P


def _req(input_path: pathlib.Path, out: pathlib.Path, tz: str = "UTC") -> ParseRequest:
    return ParseRequest(input_path=input_path, output_dir=out,
                        case_id="T", evidence_id="EV", timezone=tz)


def _events(jsonl_path: str) -> list[dict]:
    return [json.loads(ln)
            for ln in pathlib.Path(jsonl_path).read_text().splitlines()]


def _write(tmp_path: pathlib.Path, name: str, content: str) -> pathlib.Path:
    d = tmp_path / name
    d.mkdir()
    (d / "access.log").write_text(content)
    return d


W3C_LOG = """\
#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Fields: date time c-ip cs-username s-ip s-port cs-method cs-uri-stem cs-uri-query sc-status cs-User-Agent time-taken
2026-05-21 12:34:56 192.0.2.4 - 10.0.0.5 443 GET /index.html - 200 Mozilla/5.0 12
2026-05-21 12:35:01 203.0.113.9 - 10.0.0.5 443 GET /admin/../../win.ini - 404 sqlmap/1.5 8
"""

# IIS native: fixed columns, ", " delimited, trailing comma, LOCAL time.
IIS_NATIVE_LOG = """\
192.0.2.4, -, 05/21/26, 12:34:56, W3SVC1, WEBSRV01, 10.0.0.5, 12, 163, 3223, 200, 0, GET, /index.html, -,
203.0.113.9, -, 05/21/26, 12:35:01, W3SVC1, WEBSRV01, 10.0.0.5, 8, 0, 0, 404, 0, GET, /default.aspx, id=1,
"""

NCSA_LOG = """\
192.0.2.4 - - [21/May/2026:12:34:56 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
203.0.113.9 - admin [21/May/2026:12:35:01 +0000] "POST /upload.php?x=1 HTTP/1.1" 200 145 "http://ref/" "sqlmap/1.5"
"""


def test_w3c_detect_and_normalise(tmp_path):
    res = P.parse(_req(_write(tmp_path, "w3c", W3C_LOG), tmp_path / "out"))
    assert res.success and res.row_count == 2
    evs = _events(res.output_jsonl)
    assert all(e["payload"]["log_format"] == "w3c" for e in evs)
    assert evs[0]["payload"]["cs-uri-stem"] == "/index.html"
    assert evs[0]["payload"]["cs-method"] == "GET"
    assert evs[0]["payload"]["sc-status"] == "200"
    assert evs[0]["payload"]["cs-User-Agent"] == "Mozilla/5.0"
    assert evs[0]["timestamp"] == "2026-05-21T12:34:56Z"
    assert evs[0]["computer"] == "10.0.0.5"  # no s-computername → s-ip
    # traversal preserved verbatim in the stem (Sigma path-traversal rule target)
    assert "../" in evs[1]["payload"]["cs-uri-stem"]
    assert evs[1]["payload"]["cs-User-Agent"] == "sqlmap/1.5"


def test_iis_native_detect_and_normalise(tmp_path):
    res = P.parse(_req(_write(tmp_path, "iis", IIS_NATIVE_LOG), tmp_path / "out"))
    assert res.success and res.row_count == 2
    evs = _events(res.output_jsonl)
    assert all(e["payload"]["log_format"] == "iis" for e in evs)
    assert evs[0]["payload"]["cs-uri-stem"] == "/index.html"
    assert evs[0]["computer"] == "WEBSRV01"  # s-computername
    # IIS native carries LOCAL time (no offset); evidence tz=UTC here → UTC ISO.
    assert evs[0]["timestamp"] == "2026-05-21T12:34:56+00:00"
    assert evs[1]["payload"]["cs-uri-stem"] == "/default.aspx"
    assert evs[1]["payload"]["cs-uri-query"] == "id=1"
    assert any("LOCAL time" in n for n in res.notes)


def test_iis_native_local_to_utc(tmp_path):
    # IIS native LOCAL time with evidence timezone=Asia/Tokyo (UTC+9):
    # 12:34:56 JST → 03:34:56 UTC. W3C/NCSA paths are unaffected by tz.
    res = P.parse(_req(_write(tmp_path, "iis", IIS_NATIVE_LOG),
                       tmp_path / "out", tz="Asia/Tokyo"))
    assert res.success
    evs = _events(res.output_jsonl)
    assert evs[0]["timestamp"] == "2026-05-21T03:34:56+00:00"
    assert any("Asia/Tokyo" in n for n in res.notes)


def test_ncsa_detect_split_uri_and_ua(tmp_path):
    res = P.parse(_req(_write(tmp_path, "ncsa", NCSA_LOG), tmp_path / "out"))
    assert res.success and res.row_count == 2
    evs = _events(res.output_jsonl)
    assert all(e["payload"]["log_format"] == "ncsa" for e in evs)
    # query split out of the request target
    assert evs[1]["payload"]["cs-uri-stem"] == "/upload.php"
    assert evs[1]["payload"]["cs-uri-query"] == "x=1"
    assert evs[1]["payload"]["cs-method"] == "POST"
    assert evs[1]["payload"]["cs-username"] == "admin"
    assert evs[1]["payload"]["cs-User-Agent"] == "sqlmap/1.5"
    # offset-stamped time → UTC Z
    assert evs[0]["timestamp"] == "2026-05-21T12:34:56Z"


def test_w3c_multiple_fields_headers(tmp_path):
    # A second #Fields with a DIFFERENT column order mid-file (config change /
    # log roll). The parser must re-bind the field map, not keep the first one.
    log = (
        "#Fields: date time cs-method cs-uri-stem sc-status\n"
        "2026-05-21 00:00:01 GET /a 200\n"
        "#Fields: date time cs-uri-stem cs-method sc-status\n"
        "2026-05-21 00:00:02 /b POST 500\n"
    )
    src = tmp_path / "roll"
    src.mkdir()
    (src / "u_ex.log").write_text(log)
    res = P.parse(_req(src, tmp_path / "out"))
    assert res.success and res.row_count == 2
    evs = _events(res.output_jsonl)
    assert evs[0]["payload"]["cs-uri-stem"] == "/a"
    assert evs[0]["payload"]["cs-method"] == "GET"
    assert evs[1]["payload"]["cs-uri-stem"] == "/b"   # reordered header honoured
    assert evs[1]["payload"]["cs-method"] == "POST"
    assert evs[1]["payload"]["sc-status"] == "500"


def test_unrecognised_input_returns_fail(tmp_path):
    src = tmp_path / "empty"
    src.mkdir()
    (src / "junk.log").write_text("not a web log line at all\n")
    res = P.parse(_req(src, tmp_path / "out"))
    assert not res.success


# ---------------------------------------------------------------------------
# Orchestrator: content-based, path-AGNOSTIC detection. IIS log output dirs are
# admin-configurable (applicationHost.config <logFile directory>), so the
# detector must classify *.log by CONTENT, not by a path glob — and must NOT
# misroute ordinary application logs to the web-log parser.
# ---------------------------------------------------------------------------

def test_detector_is_content_based_and_path_agnostic(tmp_path):
    from parsers.orchestrator import detect
    (tmp_path / "D/CustomLogs").mkdir(parents=True)         # W3C at non-default path
    (tmp_path / "D/CustomLogs/web.log").write_text(W3C_LOG)
    (tmp_path / "x").mkdir()                                # NCSA elsewhere
    (tmp_path / "x/access.log").write_text(NCSA_LOG)
    (tmp_path / "y").mkdir()                                # IIS-native elsewhere
    (tmp_path / "y/inetsv1.log").write_text(IIS_NATIVE_LOG)
    (tmp_path / "setup.log").write_text("Installation started\nComponent X installed\n")
    (tmp_path / "app.log").write_text("INFO start\nERROR boom\n")

    web = sorted(str(d.input_path.relative_to(tmp_path))
                 for d in detect(tmp_path) if d.artifact_id == "w3c_iis")
    assert "D/CustomLogs/web.log" in web   # W3C at arbitrary path
    assert "x/access.log" in web           # NCSA at arbitrary path
    assert "y/inetsv1.log" in web          # IIS-native at arbitrary path
    assert not any(n.endswith(("setup.log", "app.log")) for n in web)  # no false positives


# ---------------------------------------------------------------------------
# image_extractor: resolve admin-configured IIS log dirs from
# applicationHost.config, so a relocated log dir is still pulled from the image.
# ---------------------------------------------------------------------------

def test_iis_log_dirs_from_config(tmp_path):
    from parsers.image_extractor import _iis_log_dirs_from_config, _winpath_to_partrel
    assert _winpath_to_partrel(r"%SystemDrive%\inetpub\logs\LogFiles") == "inetpub/logs/LogFiles"
    assert _winpath_to_partrel(r"D:\WebLogs\kintai") == "WebLogs/kintai"
    cfg = tmp_path / "applicationHost.config"
    cfg.write_text(
        '<configuration><system.applicationHost><sites>'
        '<siteDefaults><logFile directory="%SystemDrive%\\inetpub\\logs\\LogFiles" /></siteDefaults>'
        '<site name="kintai"><logFile directory="D:\\WebLogs\\kintai" /></site>'
        '</sites></system.applicationHost></configuration>')
    assert sorted(_iis_log_dirs_from_config(cfg)) == ["WebLogs/kintai", "inetpub/logs/LogFiles"]
    assert _iis_log_dirs_from_config(tmp_path / "nope") == []   # missing → graceful
