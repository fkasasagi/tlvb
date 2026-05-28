"""Build the FindEvil MITRE ATT&CK RAG corpus.

Fetches the **enterprise-attack** STIX bundle from MITRE's `cti` repo
(per DESIGN v0.3 #11 — ICS / Mobile / Pre-attack are out of scope for
the Windows-targeted FindEvil), parses it, and writes one Markdown
file per Tactic and per Technique under
``rag/mitre_attack/tactics/<TA000X>_<slug>/``.

Output layout::

    rag/mitre_attack/tactics/
    ├── TA0001_initial_access/
    │   ├── _index.md           ← Tactic overview + technique list
    │   ├── T1078.md            ← per-technique detail
    │   ├── T1078.001.md        ← sub-techniques
    │   └── ...
    └── ...

Each Tactic appears in exactly **one** category dir even when STIX lists
the technique under multiple tactics — we duplicate the file across
each, since a Tactic-Agent reading its own dir doesn't have to know
about cross-tactic linkage.

Usage::

    python3 rag/build_rag.py [--source <URL or local file>] [--output-dir rag/mitre_attack/tactics] [--skip-fetch]

Re-running is idempotent — existing .md files are overwritten with
fresh content from the latest STIX bundle. Hand-curated
``*.windows.md`` files (per the layout in DESIGN.md §8.4) are NOT
touched, only auto-generated ``T<id>.md`` and ``_index.md``.

Dependencies: stdlib only (urllib + json).
"""

from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import sys
import urllib.request
from typing import Any


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

# Single-file STIX bundle that mirrors all enterprise-attack content.
# This file is what MITRE ATT&CK Navigator + most downstream tools fetch.
DEFAULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
DEFAULT_OUTPUT_DIR = "rag/mitre_attack/tactics"


# ---------------------------------------------------------------------------
# STIX fetch
# ---------------------------------------------------------------------------

def fetch_bundle(source: str) -> dict[str, Any]:
    """Load the STIX bundle from a URL or local file path.

    Path heuristic: if `source` starts with http(s):// it's fetched via
    urllib; otherwise treated as a local filesystem path.
    """
    if source.startswith(("http://", "https://")):
        print(f"[fetch] {source}", file=sys.stderr)
        with urllib.request.urlopen(source, timeout=120) as resp:  # noqa: S310
            data = resp.read()
        print(f"[fetch] {len(data):,} bytes", file=sys.stderr)
    else:
        p = pathlib.Path(source)
        print(f"[load] {p}", file=sys.stderr)
        data = p.read_bytes()
    return json.loads(data)


# ---------------------------------------------------------------------------
# STIX parsing
# ---------------------------------------------------------------------------

def split_objects(bundle: dict[str, Any]) -> tuple[list[dict], list[dict], dict[str, dict]]:
    """Walk the STIX bundle and return:
        - tactics       : x-mitre-tactic objects
        - techniques    : attack-pattern objects (incl. sub-techniques)
        - by_id         : id → object lookup (for relationship resolution)
    """
    tactics: list[dict] = []
    techniques: list[dict] = []
    by_id: dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        oid = obj.get("id", "")
        by_id[oid] = obj
        t = obj.get("type")
        if t == "x-mitre-tactic":
            if not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
                tactics.append(obj)
        elif t == "attack-pattern":
            if not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
                techniques.append(obj)
    return tactics, techniques, by_id


def attack_id(obj: dict[str, Any]) -> str:
    """Pull the canonical ATT&CK external_id (TA000X / T1XXX) from a STIX obj."""
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "") or ""
    return ""


def attack_url(obj: dict[str, Any]) -> str:
    """Pull the public ATT&CK page URL from external_references."""
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "") or ""
    return ""


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def slugify(s: str) -> str:
    """ATT&CK tactic name → directory-safe slug ("Initial Access" → "initial_access")."""
    return "".join(c if c.isalnum() else "_" for c in s.lower()).strip("_")


def md_escape(s: str) -> str:
    """Minimal Markdown-safe pass — Markdown is permissive enough that we
    only need to defang ``|`` characters that would break embedded tables."""
    return (s or "").replace("|", "\\|")


def render_tactic_index(tactic: dict[str, Any], techniques: list[dict[str, Any]]) -> str:
    """_index.md for one Tactic. Lists every technique under it with one-line summary."""
    name = tactic.get("name", "")
    aid = attack_id(tactic)
    url = attack_url(tactic)
    desc = (tactic.get("description") or "").strip()
    short = tactic.get("x_mitre_shortname") or slugify(name)

    lines = [
        f"# {aid} — {name}",
        "",
        f"**Shortname**: `{short}`",
        f"**Reference**: {url}" if url else "",
        "",
        "## Description",
        "",
        desc or "(no description)",
        "",
        "## Techniques in this Tactic",
        "",
    ]
    if not techniques:
        lines.append("(none)")
    else:
        for t in sorted(techniques, key=lambda x: attack_id(x)):
            tid = attack_id(t)
            tname = t.get("name", "")
            tsummary = (t.get("description") or "").split("\n")[0].strip()
            if len(tsummary) > 200:
                tsummary = tsummary[:200] + "..."
            lines.append(f"- **`{tid}`** [{md_escape(tname)}]({tid}.md) — {md_escape(tsummary)}")
    lines.append("")
    return "\n".join(lines)


def render_technique(t: dict[str, Any], parent_tactic_name: str) -> str:
    """One TXXXX.md page. Includes description, platforms, detection,
    data_sources — the fields a Tactic Agent would actually read."""
    tid = attack_id(t)
    name = t.get("name", "")
    url = attack_url(t)
    desc = (t.get("description") or "").strip()
    platforms = t.get("x_mitre_platforms") or []
    data_sources = t.get("x_mitre_data_sources") or []
    detection = (t.get("x_mitre_detection") or "").strip()
    permissions = t.get("x_mitre_permissions_required") or []

    lines = [
        f"# {tid} — {name}",
        "",
        f"**Tactic**: {parent_tactic_name}",
        f"**Reference**: {url}" if url else "",
        "",
        "## Description",
        "",
        desc or "(no description)",
        "",
    ]
    if platforms:
        lines += ["## Platforms", "", ", ".join(md_escape(p) for p in platforms), ""]
    if data_sources:
        lines += ["## Data Sources", ""]
        for ds in data_sources:
            lines.append(f"- {md_escape(ds)}")
        lines.append("")
    if permissions:
        lines += ["## Permissions Required", "", ", ".join(md_escape(p) for p in permissions), ""]
    if detection:
        lines += ["## Detection", "", detection, ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build(source: str, output_dir: pathlib.Path) -> int:
    bundle = fetch_bundle(source)
    tactics, techniques, by_id = split_objects(bundle)
    print(f"[parse] tactics={len(tactics)}  techniques={len(techniques)}", file=sys.stderr)

    # Pre-index techniques by tactic shortname
    by_tactic: dict[str, list[dict]] = {}
    for t in techniques:
        for kc in t.get("kill_chain_phases") or []:
            if kc.get("kill_chain_name") != "mitre-attack":
                continue
            phase = kc.get("phase_name")
            if phase:
                by_tactic.setdefault(phase, []).append(t)

    output_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for tactic in tactics:
        aid = attack_id(tactic)
        if not aid:
            continue
        slug = tactic.get("x_mitre_shortname") or slugify(tactic.get("name", ""))
        tactic_dir = output_dir / f"{aid}_{slug}"
        tactic_dir.mkdir(parents=True, exist_ok=True)

        ts_for_this = by_tactic.get(slug, [])
        idx_md = render_tactic_index(tactic, ts_for_this)
        (tactic_dir / "_index.md").write_text(idx_md, encoding="utf-8")
        written += 1

        for t in ts_for_this:
            tid = attack_id(t)
            if not tid:
                continue
            md = render_technique(t, tactic.get("name", ""))
            (tactic_dir / f"{tid}.md").write_text(md, encoding="utf-8")
            written += 1

    # Top-level manifest so Tactic Agents can discover what's available
    manifest_path = output_dir.parent / "MANIFEST.json"
    manifest = {
        "schema": "findevil/rag/mitre/v1",
        "generated_at": datetime.datetime.now(datetime.timezone.utc)
            .replace(microsecond=0).isoformat(),
        "source": source,
        "scope": "enterprise-attack",
        "tactic_count": len(tactics),
        "technique_count": len(techniques),
        "tactics": [
            {
                "id": attack_id(t),
                "name": t.get("name"),
                "shortname": t.get("x_mitre_shortname"),
                "techniques": len(by_tactic.get(t.get("x_mitre_shortname") or "", [])),
            }
            for t in sorted(tactics, key=lambda x: attack_id(x))
        ],
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[done] wrote {written} .md files + MANIFEST.json under {output_dir.parent}",
          file=sys.stderr)
    return written


def _main() -> int:
    p = argparse.ArgumentParser(prog="rag.build_rag")
    p.add_argument("--source", default=DEFAULT_SOURCE_URL,
                   help=f"STIX bundle URL or local file (default: {DEFAULT_SOURCE_URL})")
    p.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR,
                   help=f"output directory for tactic/technique md (default: {DEFAULT_OUTPUT_DIR})")
    args = p.parse_args()
    try:
        build(args.source, pathlib.Path(args.output_dir))
        return 0
    except Exception as exc:  # noqa: BLE001 — top-level CLI guard
        print(f"build failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(_main())
