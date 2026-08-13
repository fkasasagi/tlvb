"""Prefix-tolerant basename matchers for collector "flatten" output formats.

Many triage collectors flatten NTFS / hive / browser-profile trees and
prepend a `<drive>_` or `<user>_` token to each filename so all artefacts
land in a single category directory:

    NTFS/C_$MFT, NTFS/C_$UsnJrnl-$J          (TANAKA / KAPE NTFS bundled)
    Registry/Tanaka_NTUSER.dat               (TANAKA hive per-user)
    Web/Chrome/Tanaka_Default_History        (TANAKA browser flatten)

The orchestrator detector, `usn_journal_parser._sibling_mft`, and the
test fixtures all share the same regex set so the detection behaviour
stays in sync — owning the patterns in one module is what keeps this
honest. Adding a new collector format = updating the regex here once.

Patterns are case-insensitive where the underlying artefact convention is
(e.g. `$MFT`/`$mft`, `NTUSER.DAT`/`NTUSER.dat`). Anchored with `\\A...\\Z`
via `fullmatch()` at the call site to avoid `My$MFT.txt` style decoys.
"""

from __future__ import annotations

import re
import urllib.parse

# ---------------------------------------------------------------------------
# NTFS metadata files
# ---------------------------------------------------------------------------

# `$MFT` with optional single-letter drive prefix (`C_$MFT`, `D_$MFT`, ...).
MFT_RE = re.compile(r"^(?:[A-Za-z]_)?\$MFT$", re.IGNORECASE)

# `$J` with optional drive prefix and optional `$UsnJrnl-`/`$UsnJrnl_` middle.
# The `$J` is the alternate data stream of `$Extend\$UsnJrnl`; collectors render
# that `:$J` separator differently — some keep the `$` (`$UsnJrnl-$J`,
# `$UsnJrnl_$J`), others drop it (`$UsnJrnl_J`, seen from the WINDEV triage
# collector), so the `$` before the final `J` is optional in the prefixed form.
# `:` is the *canonical* NTFS form (`$UsnJrnl:$J`) and is accepted too — a
# collector that preserves the real stream name (Velociraptor's `ntfs`
# accessor, once its `%3A` escape is decoded) must not be the odd one out.
# Also accepts the legacy `USNJournal__J` convention that older Velociraptor
# artifact packs emitted. A bare `J` (no `$` and no `$UsnJrnl` prefix) is
# intentionally NOT matched, to avoid grabbing unrelated single-letter files.
USN_J_RE = re.compile(
    r"^(?:[A-Za-z]_)?(?:\$UsnJrnl[-_:]\$?J|\$J)$|^USNJournal__J$",
    re.IGNORECASE,
)


def is_usn_journal(name: str) -> bool:
    """True when ``name`` denotes the USN journal in any collector dialect.

    The journal is the only artefact TLVB parses whose real name contains a
    character a host filesystem forbids — the `:` of the `$UsnJrnl:$J` stream.
    Containers that preserve the real name must therefore escape it, and
    Velociraptor percent-encodes: its `ntfs` accessor stages the journal as

        uploads/ntfs/%5C%5C.%5CC%3A/$Extend/$UsnJrnl%3A$J

    Decoding is safe to add because `USN_J_RE` contains no `%`: a name that
    matches raw can never contain an escape, so unquoting can only ever *add*
    matches and never reinterpret one the old code already accepted. That —
    not the ordering below — is what guarantees existing collector layouts
    keep detecting exactly as before. The `%` early-out is just there to skip
    the decode for the overwhelming majority of filenames.

    Files are never renamed on disk; this is a matching-time view of the name.

    Every other artefact (`$MFT`, the hives, `History`, `*.pf`) has a name that
    needs no escaping, which is why the decode lives here and not in a generic
    pass over all the patterns.
    """
    if USN_J_RE.fullmatch(name):
        return True
    if "%" not in name:
        return False
    return bool(USN_J_RE.fullmatch(urllib.parse.unquote(name)))


# ---------------------------------------------------------------------------
# Registry hives (per-user — system hives like SOFTWARE/SYSTEM live elsewhere
# and are handled by the orchestrator's existing `_REGISTRY_HIVE_NAMES` set
# because they are *never* per-user-prefixed by collectors we have seen).
# ---------------------------------------------------------------------------

# `NTUSER.DAT` with optional `<user>_` prefix. The user token is the same
# loose `<word-with-dots-and-dashes>_` form as the browser regex below; it
# accepts ASCII account names like `Tanaka`, `vagrant`, `Default`, plus
# domain-style `CORP.example`.
NTUSER_RE = re.compile(
    r"^(?:[A-Za-z][A-Za-z0-9._-]*_)?NTUSER\.DAT$",
    re.IGNORECASE,
)

# `UsrClass.DAT` with the same optional user prefix.
USRCLASS_RE = re.compile(
    r"^(?:[A-Za-z][A-Za-z0-9._-]*_)?USRCLASS\.DAT$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Browser history databases
# ---------------------------------------------------------------------------

# Chromium-family `History` (Chrome, Edge, Brave, Opera, ...). The file has
# no extension on disk, so we leave the basename match case-sensitive to
# avoid matching `history.log` and similar lowercase decoys.
CHROMIUM_HIST_RE = re.compile(
    r"^(?:[A-Za-z][A-Za-z0-9._-]*_)?History$"
)

# Firefox `places.sqlite` (and forks: Waterfox, LibreWolf etc. use the same
# filename). Case-insensitive: collectors sometimes upper-case `Places.sqlite`.
PLACES_SQLITE_RE = re.compile(
    r"^(?:[A-Za-z][A-Za-z0-9._-]*_)?places\.sqlite$",
    re.IGNORECASE,
)
