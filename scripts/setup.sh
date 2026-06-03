#!/usr/bin/env bash
# TLVB setup — verify prerequisites and build the binary.
#
# Tested on SANS SIFT Workstation (Ubuntu 22.04+). Runs idempotent: re-run
# anytime to refresh the build. By default does NOT install missing system
# packages — that's intentional, since DFIR environments often have bespoke
# tool layouts and `sudo apt` may not be desired. Pass --auto-install-deps
# to opt in to automatic apt installation of python3.X-venv / python3.X-dev
# / python3-full (Issue #18: SIFT 2024+ ships python3.12 but only the
# generic python3-venv stub, so we need the version-specific package).
# Falls back to the generic names when the version-specific install fails.

set -euo pipefail

cd "$(dirname "$0")/.."

# ---- args ------------------------------------------------------------------
AUTO_INSTALL=0
for arg in "$@"; do
  case "$arg" in
    --auto-install-deps)
      AUTO_INSTALL=1
      ;;
    -h|--help)
      cat <<USAGE
Usage: $(basename "$0") [--auto-install-deps]

  --auto-install-deps   On Debian/Ubuntu, run \`sudo apt install -y\`
                         for python3-venv / python3-full when missing.
                         Default: off — print install hint only.
USAGE
      exit 0
      ;;
  esac
done

# ---- pretty output ---------------------------------------------------------
red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
blue()   { printf '\033[0;34m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

bold "TLVB setup — $(pwd)"
echo

# ---- core toolchain --------------------------------------------------------
errors=0
warnings=0

require_cmd() {
  local name="$1" hint="$2" min="${3:-}"
  if ! command -v "$name" >/dev/null 2>&1; then
    red "  ✗ $name not found"
    echo "      install: $hint"
    errors=$((errors + 1))
    return 1
  fi
  local v
  case "$name" in
    go)      v=$(go version 2>/dev/null | awk '{print $3}') ;;
    python3) v=$(python3 --version 2>&1 | awk '{print $2}') ;;
    dotnet)  v=$(dotnet --info 2>/dev/null | awk '/Version:/ {print $2; exit}') ;;
    *)       v="present" ;;
  esac
  green "  ✓ $name ($v)"
  return 0
}

bold "[1/4] Core toolchain"
require_cmd go      "https://go.dev/doc/install (need 1.22+)"          || true
require_cmd python3 "apt install python3 python3-pip"                  || true
require_cmd dotnet  "https://dotnet.microsoft.com/download (6.0+)"     || true

# Optional: claude CLI for default engine
bold "[2/4] LLM access"
if command -v claude >/dev/null 2>&1; then
  green "  ✓ claude CLI ($(claude --version 2>&1 | head -1))"
elif [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
  green "  ✓ ANTHROPIC_API_KEY is set"
else
  yellow "  ! no claude CLI and no ANTHROPIC_API_KEY"
  echo "      install one before running 'analyze' or 'run':"
  echo "         curl -fsSL claude.ai/install.sh | bash      (Claude Code CLI)"
  echo "         export ANTHROPIC_API_KEY=sk-ant-...         (direct API)"
  warnings=$((warnings + 1))
fi

# ---- DFIR tools (Tier 0 parsers depend on these) ---------------------------
bold "[3/4] DFIR parsers (Tier 0)"
EZT=/opt/zimmermantools

check_dll() {
  local artifact="$1" dll="$2" tier="$3"
  if [[ -f "$dll" ]]; then
    green "  ✓ $tier $artifact ($(basename "$dll"))"
  else
    if [[ "$tier" == "P0" ]]; then
      red "  ✗ $tier $artifact missing: $dll"
      errors=$((errors + 1))
    else
      yellow "  ! $tier $artifact missing: $dll"
      warnings=$((warnings + 1))
    fi
  fi
}

check_dll "evtx"            "$EZT/EvtxeCmd/EvtxECmd.dll" "P0"
check_dll "amcache"         "$EZT/AmcacheParser.dll"      "P0"
check_dll "prefetch"        "$EZT/PECmd.dll"              "P0"
check_dll "registry"        "$EZT/RECmd/RECmd.dll"        "P0"

if command -v log2timeline.py >/dev/null 2>&1; then
  green "  ✓ P0 plaso (log2timeline.py $(log2timeline.py --version 2>&1 | head -1 | awk '{print $NF}'))"
else
  red "  ✗ P0 plaso not found"
  echo "      install: apt install plaso-tools  (or use the GIFT PPA)"
  errors=$((errors + 1))
fi

check_dll "shimcache"      "$EZT/AppCompatCacheParser.dll" "P1"
check_dll "mft"            "$EZT/MFTECmd.dll"              "P1"
check_dll "shellbags"      "$EZT/SBECmd.dll"               "P1"
check_dll "jumplists"      "$EZT/JLECmd.dll"               "P1"
check_dll "lnk"            "$EZT/LECmd.dll"                "P1"
check_dll "recyclebin"     "$EZT/RBCmd.dll"                "P1"
check_dll "win10timeline"  "$EZT/WxTCmd.dll"               "P1"

# altpf — Prefetch primary engine (Wave 12 / Issue #27). Linux-native pure-Go
# binary that beats Plaso ~1000x and exposes LastRun + PreviousRun0..6. We
# install it by default so `./scripts/setup.sh` is the only command users
# need to run; this is safe because the installer is sudo-free for /opt
# (chowned on first run), idempotent, and SHA-256-verified. If install fails
# (no network, no gh+curl, etc.) we fall through to a warning — TLVB
# continues to work via the Plaso `psteal.py --parsers prefetch` fallback
# (LastRun only).
if [[ -x /opt/altpf/altpf ]]; then
  altpf_sha=$(sha256sum /opt/altpf/altpf 2>/dev/null | awk '{print substr($1,1,12)}')
  green "  ✓ P0 altpf (/opt/altpf/altpf, sha256:${altpf_sha}...)"
else
  yellow "  ! altpf not present — installing via scripts/install_altpf.sh"
  if ./scripts/install_altpf.sh 2>&1 | sed 's/^/      /'; then
    green "    ✓ altpf installed"
  else
    yellow "    ! altpf install failed — Prefetch will use Plaso psteal fallback"
    echo  "      retry manually with: ./scripts/install_altpf.sh"
    warnings=$((warnings + 1))
  fi
fi

# Hayabusa — optional EVTX threat-hunting engine (Yamato Security). Mirrors
# the altpf installer pattern: idempotent, SHA-256 verified, sudo-free for
# a writable /opt/hayabusa. Absent → orchestrator silently skips the
# artefact (graceful degradation, see parsers/orchestrator.py::_hayabusa_present),
# so install failure is a warning, not an error. Set TLVB_SKIP_HAYABUSA=1
# in the environment to opt out — useful for air-gapped setups where the
# 30 MB GitHub download isn't reachable.
if [[ "${TLVB_SKIP_HAYABUSA:-0}" == "1" ]]; then
  yellow "  ! hayabusa install skipped (TLVB_SKIP_HAYABUSA=1)"
elif [[ -x /opt/hayabusa/hayabusa ]]; then
  haya_sha=$(sha256sum /opt/hayabusa/hayabusa 2>/dev/null | awk '{print substr($1,1,12)}')
  green "  ✓ P1 hayabusa (/opt/hayabusa/hayabusa, sha256:${haya_sha}...)"
else
  yellow "  ! hayabusa not present — installing via scripts/install_hayabusa.sh"
  if ./scripts/install_hayabusa.sh 2>&1 | sed 's/^/      /'; then
    green "    ✓ hayabusa installed"
  else
    yellow "    ! hayabusa install failed — evtx Sigma hunting will be skipped"
    echo  "      retry manually with: ./scripts/install_hayabusa.sh"
    echo  "      or pass TLVB_SKIP_HAYABUSA=1 to silence this in air-gapped setups"
    warnings=$((warnings + 1))
  fi
fi

# ---- Python deps -----------------------------------------------------------
#
# Modern distributions (Ubuntu 24.04+, Debian 12+) ship Python 3.12+ with
# PEP 668 enabled — `pip install` against the system Python is rejected by
# default. We side-step that by creating a project-local virtual env at
# ./.venv and installing into it. The Go binary's parser dispatcher then
# prefers ./.venv/bin/python3 when present (see internal/common/python.go).
bold "[4/4] Python deps (venv)"
VENV=./.venv

# Detect the running python's MAJOR.MINOR so --auto-install-deps can
# request the version-specific apt packages (Issue #18). SIFT 2024+
# defaults to python3.12 but only ships the generic python3-venv stub,
# so `apt install python3-venv` doesn't actually pull python3.12-venv.
PY_VER=$(python3 -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "")

if [[ ! -x "$VENV/bin/python3" ]]; then
  if python3 -m venv "$VENV" 2>/tmp/tlvb-venv.err; then
    green "  ✓ created $VENV"
  else
    red   "  ✗ python3 -m venv failed:"
    cat /tmp/tlvb-venv.err | sed 's/^/      /'
    if [[ $AUTO_INSTALL -eq 1 ]] && command -v apt-get >/dev/null 2>&1; then
      # Build the apt package list, version-specific first.
      apt_pkgs=()
      if [[ -n "$PY_VER" ]]; then
        apt_pkgs+=("python${PY_VER}-venv" "python${PY_VER}-dev")
      fi
      apt_pkgs+=("python3-venv" "python3-full" "python3-dev")
      yellow "  ! --auto-install-deps was passed — running: sudo apt install -y ${apt_pkgs[*]}"
      # apt-get returns non-zero if *any* requested package is missing
      # from the repo (e.g. python3.10-venv on Ubuntu 24.04). Try the
      # version-specific bundle first, then fall back to the generic.
      install_ok=0
      if sudo apt install -y "${apt_pkgs[@]}" 2>&1 | tail -3; then
        install_ok=1
      else
        yellow "  ! version-specific install failed; retrying with generic only"
        if sudo apt install -y python3-venv python3-full python3-dev 2>&1 | tail -3; then
          install_ok=1
        fi
      fi
      if [[ $install_ok -eq 1 ]] && python3 -m venv "$VENV" 2>/tmp/tlvb-venv.err; then
        green "  ✓ created $VENV (after auto-install)"
      else
        red "  ✗ venv still failing after apt install:"
        cat /tmp/tlvb-venv.err | sed 's/^/      /'
        errors=$((errors + 1))
      fi
    else
      if [[ -n "$PY_VER" ]]; then
        echo "      install: sudo apt update && sudo apt install -y python${PY_VER}-venv python${PY_VER}-dev python3-full"
        echo "               (or generic: sudo apt install -y python3-venv python3-full)"
      else
        echo "      install: sudo apt install python3-venv python3-full"
      fi
      echo "      or re-run: $0 --auto-install-deps"
      errors=$((errors + 1))
    fi
  fi
fi

if [[ -x "$VENV/bin/python3" ]]; then
  # duckdb is the must-have runtime; py7zr is needed by REQ-1 (nested
  # archive extraction). We install both together so one pip resolver
  # invocation does the work.
  declare -a missing_pkgs=()
  "$VENV/bin/python3" -c "import duckdb" 2>/dev/null || missing_pkgs+=("duckdb")
  "$VENV/bin/python3" -c "import py7zr" 2>/dev/null || missing_pkgs+=("py7zr>=0.21")
  "$VENV/bin/python3" -c "import yaml"   2>/dev/null || missing_pkgs+=("pyyaml")
  if [[ ${#missing_pkgs[@]} -eq 0 ]]; then
    green "  ✓ duckdb + py7zr + pyyaml already in $VENV"
  else
    yellow "  ! installing into $VENV: ${missing_pkgs[*]}"
    if "$VENV/bin/pip" install --quiet --upgrade pip >/dev/null 2>&1 \
       && "$VENV/bin/pip" install --quiet "${missing_pkgs[@]}" 2>/tmp/tlvb-pip.err; then
      green "    installed: ${missing_pkgs[*]}"
    else
      red   "    pip install FAILED:"
      tail -10 /tmp/tlvb-pip.err 2>/dev/null | sed 's/^/      /'
      errors=$((errors + 1))
    fi
  fi
fi

# ---- Go build --------------------------------------------------------------
echo
bold "Building bin/tlvb ..."
mkdir -p bin
if go build -o bin/tlvb ./cmd/tlvb; then
  green "  ✓ built $(pwd)/bin/tlvb ($(du -h bin/tlvb | awk '{print $1}'))"
else
  red "  ✗ go build failed"
  errors=$((errors + 1))
fi

# ---- seed rule SQL cache ---------------------------------------------------
# The LLM-built Tier 1A SQL lives in outputs/rules.duckdb, which is gitignored.
# A fresh clone instead carries the vendored JSONL snapshot (rules/built/) — seed
# it so Tier 1A has cached SQL without re-running the costly `rules build`. Safe
# mode: existing rules are never overwritten, so re-running setup is a no-op.
if [[ -x bin/tlvb ]] && compgen -G 'rules/built/*.sql.jsonl' >/dev/null; then
  echo
  bold "Seeding rule SQL cache (rules/built → outputs/rules.duckdb) ..."
  if ./bin/tlvb rules import 2>&1 | sed 's/^/  /'; then
    green "  ✓ rule SQL cache seeded"
  else
    yellow "  ! rules import failed — Tier 1A will have no cached SQL until you"
    yellow "    run './bin/tlvb rules import' (or 'rules build') manually"
    warnings=$((warnings + 1))
  fi
fi

# ---- summary ---------------------------------------------------------------
echo
echo "─────────────────────────────────────────────"
if [[ $errors -eq 0 ]]; then
  if [[ $warnings -eq 0 ]]; then
    green "Setup OK"
  else
    green "Setup OK with $warnings warning(s) — see above"
  fi
  echo
  blue "Next:"
  echo "  ./scripts/verify.sh           # detailed environment check"
  echo "  ./bin/tlvb serve --port 8080"
  echo "  open http://localhost:8080/   # or http://<VM-IP>:8080/"
  exit 0
else
  red "Setup FAILED — $errors error(s), $warnings warning(s)"
  echo
  echo "Fix the items marked ✗ above and re-run ./scripts/setup.sh"
  exit 1
fi
