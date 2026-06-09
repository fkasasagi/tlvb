"""Tests for parsers.web_error_parser + the 2-stage web-log detector.

Apache/nginx/Tomcat ACCESS logs are NCSA (→ w3c_iis, see test_w3c_iis.py); their
ERROR / diagnostic logs are non-NCSA (→ web_error). This covers the new error
parser (3 formats), the content-based 2-stage routing in the orchestrator, and
the image_extractor config-resolution helpers (httpd.conf / nginx.conf /
server.xml).
"""

from __future__ import annotations

import json
import pathlib

from parsers.base import ParseRequest
from parsers import web_error_parser as P


def _req(inp: pathlib.Path, out: pathlib.Path) -> ParseRequest:
    return ParseRequest(input_path=inp, output_dir=out, case_id="T", evidence_id="EV")


def _events(p: str) -> list[dict]:
    return [json.loads(ln) for ln in pathlib.Path(p).read_text().splitlines()]


APACHE = (
    "[Sun Jun 08 13:18:17.123456 2026] [core:error] [pid 1:tid 2] [client 192.168.50.1:54321] AH01071: x\n"
    "[Sun Jun 08 13:19:01 2026] [authz_core:error] [pid 1] [client 203.0.113.9:1111] AH01630: denied\n"
)
NGINX = (
    '2026/06/08 13:18:17 [error] 12345#0: *1 open() "/x/../../etc/passwd" failed, client: 192.168.50.1, server: s\n'
    "2026/06/08 13:20:00 [warn] 12345#0: *2 upstream timed out, client: 203.0.113.9, server: s\n"
)
TOMCAT = (
    "08-Jun-2026 13:18:17.123 SEVERE [http-nio-8080-exec-1] org.apache.catalina.X threw exception\n"
    "08-Jun-2026 13:18:18.000 INFO [main] org.apache.catalina.startup.Catalina.start started\n"
)


def _write(tmp: pathlib.Path, name: str, fname: str, content: str) -> pathlib.Path:
    d = tmp / name
    d.mkdir()
    (d / fname).write_text(content)
    return d


def test_apache_error(tmp_path):
    res = P.parse(_req(_write(tmp_path, "ap", "error_log", APACHE), tmp_path / "o"))
    assert res.success and res.row_count == 2
    evs = _events(res.output_jsonl)
    assert all(e["payload"]["server_type"] == "apache" for e in evs)
    assert evs[0]["payload"]["severity"] == "error"        # "core:error" → "error"
    assert evs[0]["payload"]["client_ip"] == "192.168.50.1"  # :port dropped
    assert evs[0]["timestamp"] == "2026-06-08T13:18:17.123456"
    assert evs[1]["payload"]["client_ip"] == "203.0.113.9"


def test_nginx_error(tmp_path):
    res = P.parse(_req(_write(tmp_path, "ng", "error.log", NGINX), tmp_path / "o"))
    assert res.success and res.row_count == 2
    evs = _events(res.output_jsonl)
    assert all(e["payload"]["server_type"] == "nginx" for e in evs)
    assert evs[0]["payload"]["severity"] == "error"
    assert evs[0]["payload"]["client_ip"] == "192.168.50.1"   # extracted from message
    assert evs[1]["payload"]["severity"] == "warn"


def test_tomcat_catalina(tmp_path):
    res = P.parse(_req(_write(tmp_path, "tc", "catalina.out", TOMCAT), tmp_path / "o"))
    assert res.success and res.row_count == 2
    evs = _events(res.output_jsonl)
    assert all(e["payload"]["server_type"] == "tomcat" for e in evs)
    assert evs[0]["payload"]["severity"] == "severe"
    assert evs[1]["payload"]["severity"] == "info"


def test_unrecognised_returns_fail(tmp_path):
    d = tmp_path / "x"
    d.mkdir()
    (d / "app.log").write_text("INFO just an ordinary application log line\n")
    res = P.parse(_req(d, tmp_path / "o"))
    assert not res.success


# ---------------------------------------------------------------------------
# 2-stage content-based detector: access (NCSA) → w3c_iis, error → web_error.
# ---------------------------------------------------------------------------

def test_two_stage_detector_routing(tmp_path):
    from parsers.orchestrator import detect
    (tmp_path / "a").mkdir()
    (tmp_path / "a/error_log").write_text(APACHE)        # Apache error (no ext)
    (tmp_path / "n").mkdir()
    (tmp_path / "n/error.log").write_text(NGINX)         # nginx error (.log)
    (tmp_path / "t").mkdir()
    (tmp_path / "t/catalina.out").write_text(TOMCAT)     # Tomcat (.out)
    (tmp_path / "a/access_log").write_text(              # NCSA access → w3c_iis
        '192.168.50.1 - - [08/Jun/2026:13:18:17 +0000] "GET /x HTTP/1.1" 200 10 "-" "curl"\n')
    (tmp_path / "setup.log").write_text("Installation started\nDone\n")  # ordinary

    by: dict[str, list[str]] = {}
    for d in detect(tmp_path):
        by.setdefault(d.artifact_id, []).append(d.input_path.name)
    assert sorted(by.get("web_error", [])) == ["catalina.out", "error.log", "error_log"]
    assert "access_log" in by.get("w3c_iis", [])
    assert not any("setup.log" in v for vs in by.values() for v in vs)


# ---------------------------------------------------------------------------
# image_extractor config resolution (Apache ServerRoot-rel + absolute, nginx
# absolute, Tomcat AccessLogValve dir).
# ---------------------------------------------------------------------------

def test_config_resolution(tmp_path):
    from parsers.image_extractor import (
        _apache_log_paths_from_config,
        _nginx_log_paths_from_config,
        _tomcat_log_dirs_from_config,
    )
    ap = tmp_path / "httpd.conf"
    ap.write_text('ServerRoot "C:/Apache24"\n'
                  'CustomLog "logs/access.log" combined\n'
                  'ErrorLog "D:/w/err.log"\n'
                  '# CustomLog "logs/commented.log"\n')
    apr = _apache_log_paths_from_config(ap)
    assert "Apache24/logs/access.log" in apr
    assert "w/err.log" in apr
    assert not any("commented" in x for x in apr)

    ng = tmp_path / "nginx.conf"
    ng.write_text("error_log D:\\nl\\error.log warn;\naccess_log off;\n")
    assert "nl/error.log" in _nginx_log_paths_from_config(ng)
    assert not any(x == "off" for x in _nginx_log_paths_from_config(ng))

    tc = tmp_path / "server.xml"
    tc.write_text('<Server><Valve className="x.AccessLogValve" directory="E:\\tl"/></Server>')
    assert _tomcat_log_dirs_from_config(tc) == ["tl"]
