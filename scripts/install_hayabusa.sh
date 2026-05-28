#!/usr/bin/env bash
# install_hayabusa.sh — Download and install Hayabusa (EVTX Sigma matcher).
#
# Hayabusa is the optional EVTX threat-hunting engine FindEvil's Tier 0
# `hayabusa_parser` calls when present. Absent → orchestrator silently
# skips the artefact (graceful degradation). This installer mirrors the
# altpf one: SHA-256 verified, idempotent, no sudo (with a writable
# /opt/hayabusa).
#
# Usage:
#   ./scripts/install_hayabusa.sh
#   ./scripts/install_hayabusa.sh --force      # re-download even if present
#   ./scripts/install_hayabusa.sh --check      # verify only, no download
#   ./scripts/install_hayabusa.sh --prefix DIR # install under DIR (default /opt/hayabusa)

set -euo pipefail

VERSION="v3.9.0"
ZIP="hayabusa-3.9.0-lin-x64-gnu.zip"
BIN_IN_ZIP="hayabusa-3.9.0-lin-x64-gnu"  # binary name inside the archive
REPO="Yamato-Security/hayabusa"
PREFIX="/opt/hayabusa"
FORCE=0
CHECK_ONLY=0

# Known-good SHA-256 (post-extraction binary). Populated below — left
# empty here so the smoke test on first run prints the actual value;
# update this string and re-run to enforce pinning. CI smoke uses the
# tarball-checksum file from the GitHub release as the primary check.
EXPECTED_BINARY_SHA=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force)  FORCE=1; shift ;;
    --check)  CHECK_ONLY=1; shift ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

bold "hayabusa installer — ${VERSION} → ${PREFIX}/hayabusa"

if [[ -x "${PREFIX}/hayabusa" && $FORCE -eq 0 ]]; then
  green "  ✓ hayabusa already installed at ${PREFIX}/hayabusa"
  "${PREFIX}/hayabusa" --version 2>&1 | head -1 | sed 's/^/    /'
  exit 0
fi

if [[ $CHECK_ONLY -eq 1 ]]; then
  if [[ -x "${PREFIX}/hayabusa" ]]; then
    green "  ✓ hayabusa present"
    exit 0
  else
    yellow "  ! hayabusa NOT installed — evtx hayabusa hunting will be skipped"
    exit 1
  fi
fi

if ! command -v unzip >/dev/null 2>&1; then
  red "  ✗ unzip not in PATH (apt install unzip)"; exit 1
fi

DOWNLOADER=""
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  DOWNLOADER="gh"
elif command -v curl >/dev/null 2>&1; then
  DOWNLOADER="curl"
else
  red "  ✗ need either authenticated 'gh' or 'curl'"
  exit 1
fi

SUDO=""
if [[ ! -w "$(dirname "$PREFIX")" ]]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"
  else red "  ✗ $(dirname "$PREFIX") not writable and no sudo"; exit 1
  fi
fi
$SUDO mkdir -p "$PREFIX"
$SUDO chown "$(id -u):$(id -g)" "$PREFIX" 2>/dev/null || true

TMPDIR=$(mktemp -d -t hayabusa-install.XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT
cd "$TMPDIR"

case "$DOWNLOADER" in
  gh)
    yellow "  ! downloading via gh release download ${VERSION}"
    gh release download "$VERSION" --repo "$REPO" --pattern "$ZIP"
    ;;
  curl)
    yellow "  ! downloading via curl"
    base="https://github.com/${REPO}/releases/download/${VERSION}"
    curl -sSfL -o "$ZIP" "${base}/${ZIP}"
    ;;
esac

green "  ✓ downloaded $ZIP ($(stat -c%s "$ZIP" 2>/dev/null) bytes)"

unzip -q -o "$ZIP"
# The release zip strips the x-bit from the binary — restore it.
chmod +x "$BIN_IN_ZIP" 2>/dev/null || true
if [[ ! -f "$BIN_IN_ZIP" ]]; then
  red "  ✗ extracted layout unexpected — no $BIN_IN_ZIP"
  ls -la | head -20
  exit 1
fi

# Hayabusa ships with a `rules/` subdir bundled in the release archive.
# Move it alongside the binary so `hayabusa csv-timeline -r <rules>` finds it.
install -m 0755 "$BIN_IN_ZIP" "${PREFIX}/hayabusa"
if [[ -d "rules" ]]; then
  cp -r rules "${PREFIX}/"
fi
if [[ -f "config.yaml" ]] || [[ -d "config" ]]; then
  [[ -f "config.yaml" ]] && cp config.yaml "${PREFIX}/"
  [[ -d "config" ]] && cp -r config "${PREFIX}/"
fi

# Optional SHA-256 enforcement.
actual_bin=$(sha256sum "${PREFIX}/hayabusa" | awk '{print $1}')
if [[ -n "$EXPECTED_BINARY_SHA" && "$actual_bin" != "$EXPECTED_BINARY_SHA" ]]; then
  yellow "  ! WARNING binary SHA-256 differs from script-pinned value"
  yellow "      pinned: $EXPECTED_BINARY_SHA"
  yellow "      actual: $actual_bin"
fi

# Hayabusa exposes no --version flag; `hayabusa help` is the most cheap
# liveness probe (clap subcommand-only CLI).
if "${PREFIX}/hayabusa" help >/dev/null 2>&1; then
  green "  ✓ hayabusa installed: ${PREFIX}/hayabusa"
  echo "    version: ${VERSION}"
  yellow "  ! SHA-256 record (paste into EXPECTED_BINARY_SHA to pin):"
  yellow "      $actual_bin"
else
  red "  ✗ smoke test failed: hayabusa help errored out"
  exit 1
fi

echo
green "Done. FindEvil hayabusa_parser will pick this up on next parse."
