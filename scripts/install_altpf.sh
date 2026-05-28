#!/usr/bin/env bash
# install_altpf.sh — Download and install altpf (Prefetch primary engine).
#
# altpf is the Prefetch parser primary engine (Wave 12 / Issue #27). It is
# a pure-Go Linux-native parser with PECmd-compatible CSV output (LastRun +
# PreviousRun0..6). FindEvil will fall back to Plaso `psteal.py --parsers
# prefetch` automatically when altpf is absent, so this installer is
# **optional** — but recommended for full PreviousRunN visibility and ~1000x
# faster parsing than Plaso.
#
# Idempotent: re-running with an existing /opt/altpf/altpf at the expected
# SHA-256 is a no-op. Use --force to re-download anyway.
#
# Usage:
#   ./scripts/install_altpf.sh               # default install to /opt/altpf
#   ./scripts/install_altpf.sh --force       # re-download even if present
#   ./scripts/install_altpf.sh --prefix DIR  # install under DIR (default /opt/altpf)
#   ./scripts/install_altpf.sh --check       # verify only, no download
#
# Requires: gh (GitHub CLI) authenticated, OR curl + jq fallback for raw
# release download. sudo only needed if PREFIX is root-owned.

set -euo pipefail

VERSION="v0.5.1"
TARBALL="altpf-${VERSION}-linux-amd64.tar.gz"
CHECKSUMS="altpf-${VERSION}-checksums.txt"
REPO="fkasasagi/altpf"
PREFIX="/opt/altpf"
FORCE=0
CHECK_ONLY=0

# Known-good SHA-256 of altpf v0.5.1 linux-amd64 binary (post-extraction).
# Cross-checked against docs/tool_inventory.md §11.
EXPECTED_BINARY_SHA="e6c6ea4659bec7bdd5765a3c32906b5e22303a1b428f7638201f18dbe8512469"

# ---- args ------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --force)   FORCE=1; shift ;;
    --check)   CHECK_ONLY=1; shift ;;
    --prefix)  PREFIX="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

bold "altpf installer — ${VERSION} → ${PREFIX}/altpf"

# ---- already installed? ----------------------------------------------------
if [[ -x "${PREFIX}/altpf" && $FORCE -eq 0 ]]; then
  actual=$(sha256sum "${PREFIX}/altpf" | awk '{print $1}')
  if [[ "$actual" == "$EXPECTED_BINARY_SHA" ]]; then
    green "  ✓ altpf already installed at ${PREFIX}/altpf (SHA-256 matches)"
    "${PREFIX}/altpf" -h 2>&1 | head -1 | sed 's/^/    /'
    exit 0
  else
    yellow "  ! altpf exists at ${PREFIX}/altpf but SHA-256 differs:"
    yellow "      expected: ${EXPECTED_BINARY_SHA}"
    yellow "      actual:   ${actual}"
    yellow "    re-installing (use --force=0 to skip; not implemented — just remove file)"
  fi
fi

if [[ $CHECK_ONLY -eq 1 ]]; then
  if [[ -x "${PREFIX}/altpf" ]]; then
    green "  ✓ altpf present at ${PREFIX}/altpf"
    exit 0
  else
    yellow "  ! altpf NOT installed at ${PREFIX}/altpf (Plaso fallback will be used)"
    exit 1
  fi
fi

# ---- preflight -------------------------------------------------------------
if ! command -v sha256sum >/dev/null 2>&1; then
  red "  ✗ sha256sum not in PATH (coreutils)"; exit 1
fi

DOWNLOADER=""
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  DOWNLOADER="gh"
elif command -v curl >/dev/null 2>&1; then
  DOWNLOADER="curl"
else
  red   "  ✗ need either authenticated 'gh' CLI or 'curl' to download"
  echo  "      gh:   gh auth login"
  echo  "      curl: apt install curl"
  exit 1
fi

# ---- prepare PREFIX --------------------------------------------------------
SUDO=""
if [[ ! -w "$(dirname "$PREFIX")" ]]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    red "  ✗ $(dirname "$PREFIX") is not writable and sudo is missing"
    exit 1
  fi
fi

$SUDO mkdir -p "$PREFIX"
$SUDO chown "$(id -u):$(id -g)" "$PREFIX" 2>/dev/null || true

# ---- download to tmp -------------------------------------------------------
TMPDIR=$(mktemp -d -t altpf-install.XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

cd "$TMPDIR"
case "$DOWNLOADER" in
  gh)
    yellow "  ! downloading via gh release download ${VERSION}"
    gh release download "$VERSION" --repo "$REPO" \
        --pattern "$TARBALL" --pattern "$CHECKSUMS"
    ;;
  curl)
    yellow "  ! downloading via curl"
    base="https://github.com/${REPO}/releases/download/${VERSION}"
    curl -sSfL -o "$TARBALL" "${base}/${TARBALL}"
    curl -sSfL -o "$CHECKSUMS" "${base}/${CHECKSUMS}"
    ;;
esac

# ---- verify tarball SHA-256 against published checksums --------------------
expected_tar=$(grep -- "linux-amd64" "$CHECKSUMS" | awk '{print $1}')
actual_tar=$(sha256sum "$TARBALL" | awk '{print $1}')
if [[ "$expected_tar" != "$actual_tar" ]]; then
  red   "  ✗ tarball SHA-256 mismatch"
  echo  "      expected: $expected_tar"
  echo  "      actual:   $actual_tar"
  exit 1
fi
green "  ✓ tarball SHA-256 verified ($actual_tar)"

# ---- extract & install -----------------------------------------------------
tar xzf "$TARBALL"
extracted_dir="altpf-${VERSION}-linux-amd64"
if [[ ! -x "${extracted_dir}/altpf" ]]; then
  red "  ✗ extracted layout unexpected — no ${extracted_dir}/altpf"
  ls -la "$extracted_dir" || true
  exit 1
fi

# Second integrity check: the binary itself matches the recorded hash.
actual_bin=$(sha256sum "${extracted_dir}/altpf" | awk '{print $1}')
if [[ "$actual_bin" != "$EXPECTED_BINARY_SHA" ]]; then
  yellow "  ! WARNING binary SHA-256 differs from script-pinned value"
  yellow "      script pin: $EXPECTED_BINARY_SHA"
  yellow "      downloaded: $actual_bin"
  yellow "    tarball signature was valid; this may indicate an upstream"
  yellow "    release update. Proceeding, but please update"
  yellow "    EXPECTED_BINARY_SHA in $(basename "$0") if intentional."
fi

# Place files atomically under PREFIX.
install -m 0755 "${extracted_dir}/altpf" "${PREFIX}/altpf"
install -m 0644 "$CHECKSUMS" "${PREFIX}/${CHECKSUMS}"
[[ -f "${extracted_dir}/README.md" ]] && install -m 0644 "${extracted_dir}/README.md" "${PREFIX}/README.altpf.md"
[[ -f "${extracted_dir}/LICENSE"   ]] && install -m 0644 "${extracted_dir}/LICENSE"   "${PREFIX}/LICENSE.altpf"

# ---- smoke test ------------------------------------------------------------
if "${PREFIX}/altpf" -h >/dev/null 2>&1; then
  green "  ✓ altpf installed: ${PREFIX}/altpf"
  "${PREFIX}/altpf" -h 2>&1 | head -1 | sed 's/^/    /'
else
  red "  ✗ ${PREFIX}/altpf failed smoke test"
  exit 1
fi

echo
green "Done. FindEvil prefetch_parser will pick this up automatically on next parse."
