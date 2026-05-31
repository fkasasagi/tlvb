#!/usr/bin/env bash
# FindEvil environment verification.
#
# Runs deeper checks than scripts/setup.sh:
#   - All registered parsers can import (Python)
#   - Orchestrator detection works on a synthetic evidence tree
#   - Go binary boots and `version` returns
#   - DuckDB driver loads
#   - Optional: real subprocess round-trip with one EZ Tool
#
# Use this as a pre-flight after setup.sh, or on a colleague's machine
# after they clone the repo.

set -euo pipefail

cd "$(dirname "$0")/.."

red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

errors=0

bold "[1/8] Go binary"
if [[ ! -x bin/tlvb ]]; then
  yellow "  ! bin/tlvb not built — running go build"
  go build -o bin/tlvb ./cmd/tlvb
fi
ver=$(./bin/tlvb version 2>&1 | head -1 || true)
if [[ -n "$ver" ]]; then
  green "  ✓ $ver"
else
  red "  ✗ bin/tlvb version failed"
  errors=$((errors + 1))
fi

# Prefer the project-local venv if setup.sh created one (PEP 668 fix).
PY=python3
if [[ -x ./.venv/bin/python3 ]]; then
  PY=./.venv/bin/python3
fi

bold "[2/8] Python parser modules import (using $PY)"
if "$PY" -c "
from parsers import (
    base, _ezt_csv, _archive, orchestrator, image_extractor,
    evtx_parser, amcache_parser, prefetch_parser, registry_parser, scheduled_tasks_parser,
    shimcache_parser, mft_parser, shellbags_parser, jumplists_parser,
    lnk_parser, recyclebin_parser, win10timeline_parser,
    browser_history_parser, washizukami_audit_parser,
    usn_journal_parser, hayabusa_parser, srum_parser,
)
ids = [m.ARTIFACT_ID for m in (
    evtx_parser, amcache_parser, prefetch_parser, registry_parser, scheduled_tasks_parser,
    shimcache_parser, mft_parser, shellbags_parser, jumplists_parser,
    lnk_parser, recyclebin_parser, win10timeline_parser,
    browser_history_parser, washizukami_audit_parser,
    usn_journal_parser, hayabusa_parser, srum_parser,
)]
print('  ✓ %d parsers loaded: %s' % (len(ids), ', '.join(ids)))
" 2>&1; then
  :
else
  red "  ✗ parser import failed"
  errors=$((errors + 1))
fi

bold "[3/8] Orchestrator detection (synthetic fixture)"
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture"/Windows/System32/{winevt/Logs,Tasks,config} \
         "$fixture"/Windows/AppCompat/Programs \
         "$fixture"/Windows/Prefetch \
         "$fixture"/Users/test/AppData/Roaming/Microsoft/Windows/Recent \
         "$fixture"/Users/test/AppData/Local/ConnectedDevicesPlatform/L.test \
         "$fixture"/Users/test/AppData/Local/Google/Chrome/User\ Data/Default \
         "$fixture"/Users/test/AppData/Roaming/Mozilla/Firefox/Profiles/abc.default \
         "$fixture"/'$Recycle.Bin'/S-1-5-21-test
mkdir -p "$fixture"/Windows/System32/sru
touch "$fixture"/Windows/System32/winevt/Logs/Security.evtx \
      "$fixture"/Windows/AppCompat/Programs/Amcache.hve \
      "$fixture"/Windows/Prefetch/CMD.EXE-12345678.pf \
      "$fixture"/Windows/System32/config/SYSTEM \
      "$fixture"/Users/test/NTUSER.DAT \
      "$fixture"/'$MFT' \
      "$fixture"/'$J' \
      "$fixture"/Windows/System32/sru/SRUDB.dat \
      "$fixture"/Users/test/AppData/Roaming/Microsoft/Windows/Recent/foo.lnk \
      "$fixture"/Users/test/AppData/Local/ConnectedDevicesPlatform/L.test/ActivitiesCache.db \
      "$fixture"/Users/test/AppData/Local/Google/Chrome/User\ Data/Default/History \
      "$fixture"/Users/test/AppData/Roaming/Mozilla/Firefox/Profiles/abc.default/places.sqlite

count=$("$PY" -c "
import pathlib
from parsers.orchestrator import detect
hits = detect(pathlib.Path('$fixture'))
ids = sorted({h.artifact_id for h in hits})
print(' '.join(ids))
" 2>&1)
expected_min=13      # +2 for Wave 8: usn_journal, srum
got=$(echo "$count" | wc -w)
if [[ $got -ge $expected_min ]]; then
  green "  ✓ detected $got artifact types: $count"
else
  red "  ✗ only detected $got types (expected ≥$expected_min): $count"
  errors=$((errors + 1))
fi

bold "[4/8] DuckDB Go driver"
# mktemp -u gives a path *without* creating the file — DuckDB rejects
# empty-byte files. Letting tlvb create it fresh is the realistic test.
test_db=$(mktemp -u -t tlvb-verify-XXXXXX.duckdb)
test_outputs=$(mktemp -d -t tlvb-verify-out-XXXXXX)
trap 'rm -rf "$fixture" "$test_db" "$test_outputs"' EXIT
if ./bin/tlvb case init --case-id VERIFY-001 --name "verify" --examiner verify --db "$test_db" 2>&1 | head -1 | grep -q registered; then
  green "  ✓ DuckDB write + casedb roundtrip"
else
  red "  ✗ casedb roundtrip failed"
  errors=$((errors + 1))
fi

bold "[5/8] Web server boot"
PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()")
./bin/tlvb serve --port "$PORT" --db "$test_db" --outputs "$test_outputs" >/tmp/tlvb-verify-srv.log 2>&1 &
PID=$!
sleep 1
if kill -0 "$PID" 2>/dev/null; then
  if python3 -c "
import urllib.request, json
r = urllib.request.urlopen('http://127.0.0.1:$PORT/api/cases', timeout=5)
print('  ✓ /api/cases returned %d (%d bytes)' % (r.status, len(r.read())))
" 2>&1; then
    :
  else
    red "  ✗ /api/cases probe failed (server log: /tmp/tlvb-verify-srv.log)"
    errors=$((errors + 1))
  fi
  kill "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
else
  red "  ✗ server failed to start (log: /tmp/tlvb-verify-srv.log)"
  errors=$((errors + 1))
fi

bold "[6/8] image_extractor format detection sanity (Wave 8 #23)"
if "$PY" -c "
import pathlib, tempfile, os
from parsers import image_extractor as ie

with tempfile.TemporaryDirectory() as td:
    root = pathlib.Path(td)
    # EWF magic + .raw extension — magic wins.
    p1 = root / 'a.raw'; p1.write_bytes(ie._MAGIC_EWF + b'\\x00' * 16)
    assert ie.detect_image(p1) == 'ewf', 'magic-byte detection failed'
    # VMDK magic.
    p2 = root / 'b.bin'; p2.write_bytes(ie._MAGIC_VMDK + b'\\x00' * 16)
    assert ie.detect_image(p2) == 'vmdk'
    # Plain raw by extension.
    p3 = root / 'c.dd'; p3.write_bytes(b'\\x00' * 16)
    assert ie.detect_image(p3) == 'raw'
    # Unknown.
    p4 = root / 'd.txt'; p4.write_bytes(b'hello')
    assert ie.detect_image(p4) is None
    print('  ✓ image_extractor detect_image (4/4 cases)')
" 2>&1; then
  :
else
  red "  ✗ image_extractor sanity failed"
  errors=$((errors + 1))
fi

bold "[7/8] artifacts.yaml integrity (parser module exists for every artifact)"
# pyyaml は dev のみのため、regex で `parser: ` 行を抽出 → importlib で全件 import チェック
if "$PY" -c "
import importlib, re, pathlib
mods = re.findall(r'^\s*parser:\s*(\S+)\s*$',
                  pathlib.Path('config/artifacts.yaml').read_text(),
                  flags=re.M)
ids = re.findall(r'^\s*- id:\s*(\S+)\s*$',
                 pathlib.Path('config/artifacts.yaml').read_text(),
                 flags=re.M)
missing = []
for m in mods:
    try:
        importlib.import_module(m)
    except Exception as e:
        missing.append(m + ' (' + type(e).__name__ + ': ' + str(e) + ')')
if missing:
    print('  ✗ broken: ' + ', '.join(missing))
    raise SystemExit(1)
print('  ✓ artifacts.yaml: %d ids declared, %d parser modules all importable' % (len(ids), len(mods)))
" 2>&1; then
  :
else
  red "  ✗ artifacts.yaml integrity failed"
  errors=$((errors + 1))
fi

bold "[8/9] pytest (Wave 8 + 既存)"
if [[ -x ./.venv/bin/pytest ]]; then
  if PYTHONPATH=. ./.venv/bin/pytest tests/ -q 2>&1 | tail -3; then
    green "  ✓ pytest passed"
  else
    red "  ✗ pytest failed"
    errors=$((errors + 1))
  fi
else
  yellow "  ! .venv/bin/pytest not present — skipped"
fi

# Wave 15: keep the human-facing STATUS.md §3 matrix in sync with the
# implementation-side config/artifacts.yaml. A drift here means we're
# either advertising an artefact we haven't implemented (or vice versa)
# — both produce confusing UX (NOT_PRESENT rows for artefacts that don't
# exist, or invisible artefacts that *are* implemented).
bold "[9/9] STATUS.md ↔ config/artifacts.yaml integrity"
if "$PY" - <<'PYEOF'; then
import pathlib, re, sys
try:
    import yaml
except ImportError:
    print("    SKIP (PyYAML not installed)", file=sys.stderr)
    sys.exit(0)

repo = pathlib.Path(".")
with (repo / "config" / "artifacts.yaml").open() as fh:
    cfg = yaml.safe_load(fh) or {}
yaml_ids = {a["id"] for a in (cfg.get("artifacts") or []) if "id" in a}

# Extract "parser モジュール" column from docs/STATUS.md §3 — the rows
# we care about look like:   `parsers/<name>_parser.py` (path-form) or
# `parsers.<name>_parser` (dotted module form). Pick up either.
status_path = repo / "docs" / "STATUS.md"
text = status_path.read_text(encoding="utf-8")
status_ids = set(re.findall(r"parsers[/.]([a-z0-9_]+)_parser", text))

# Map STATUS.md slugs to artifact ids (mostly identity, a few alias).
alias = {"win10_timeline": "win10timeline", "recycle_bin": "recyclebin"}
status_ids = {alias.get(s, s) for s in status_ids}

only_in_yaml   = yaml_ids - status_ids
only_in_status = status_ids - yaml_ids
ok = True
# STATUS.md may legitimately list parsers we haven't put in artifacts.yaml
# (e.g. helper modules). Only flag *artifact ids* declared in yaml that
# the status tracker doesn't mention — those are real drift.
if only_in_yaml:
    print(f"    yaml-only (not mentioned in STATUS.md): {sorted(only_in_yaml)}")
    ok = False
sys.exit(0 if ok else 1)
PYEOF
  green "  ✓ artifacts.yaml is referenced in STATUS.md"
else
  red "  ✗ STATUS.md §3 doesn't mention every artifacts.yaml entry"
  errors=$((errors + 1))
fi

echo
echo "─────────────────────────────────────────────"
if [[ $errors -eq 0 ]]; then
  green "All checks passed. Ready to serve."
  exit 0
else
  red "$errors check(s) failed."
  exit 1
fi
