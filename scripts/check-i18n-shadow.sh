#!/usr/bin/env bash
#
# check-i18n-shadow.sh — guard ui/static/app.js against shadowing the i18n
# translation function t().
#
# Background
# ----------
# ui/static/app.js defines a single global translation function `t(s)` and
# wraps every UI string as t("…"). Binding `t` to anything else (a loop var,
# a function/arrow parameter, a local const) shadows that function; any t("…")
# call reached in that scope then throws `TypeError: t is not a function` and
# the view dies at render time.
#
# This has regressed repeatedly (PRs #109/#110/#111, commits 1479fad / aafa023)
# because manual review kept missing one `.map((t) => …)` or stray `const t`.
# Convention: in app.js, never bind the name `t` to anything but the global
# translation function. Use tactic / tech / entry / row / tMs / ts instead.
#
# This script enforces that convention. It is wired into `make lint` and CI.
set -euo pipefail

cd "$(dirname "$0")/.."
FILE="ui/static/app.js"

if [ ! -f "$FILE" ]; then
  echo "check-i18n-shadow: $FILE not found" >&2
  exit 2
fi

# 1) Syntax check (cheap, catches broken edits before the file is embedded).
#    GitHub runners ship Node; skip gracefully where it is absent.
if command -v node >/dev/null 2>&1; then
  node --check "$FILE"
else
  echo "check-i18n-shadow: node not found; skipping JS syntax check"
fi

# 2) Shadow guard. Match *binding* forms of an identifier named `t`
#    (declarations, loop vars, function/arrow params, catch params, and
#    object/array destructuring like `const {t}` / `const [t]`).
#    Deliberately does NOT match t(...) calls or `t` passed as an argument —
#    those are uses of the global function, not shadows.
#
#    The global definition `function t(s) {` is not matched by any branch
#    (its `t` is the function name, before the paren, with no `t` param).
#
#    This is a line-oriented grep heuristic, not a parser. Known blind spots
#    (rare in this hand-formatted file): a param list split across multiple
#    lines, or a `t` bound behind a nested-paren default like `(x=(f()), t)`.
pattern='(\b(const|let|var)[[:space:]]+t\b[[:space:]]*(=|of[[:space:]]|in[[:space:]]))'
pattern+='|(\([^()]*\bt\b[^()]*\)[[:space:]]*=>)'
pattern+='|((^|[^.[:alnum:]_])t[[:space:]]*=>)'
pattern+='|(\bfunction\b[^(]*\([^()]*\bt\b[^()]*\))'
pattern+='|(\bcatch[[:space:]]*\([[:space:]]*t[[:space:]]*\))'
pattern+='|(\b(const|let|var)[[:space:]]+[{[][^]}=]*\bt\b[^]}=]*[]}])'

hits="$(grep -nE "$pattern" "$FILE" || true)"

if [ -n "$hits" ]; then
  {
    echo "ERROR: $FILE binds the i18n function name 't' (shadowing risk)."
    echo "Reserve t() for translation; rename the local var/param"
    echo "(e.g. tactic / tech / entry / row / tMs / ts). Offending lines:"
    echo "$hits"
  } >&2
  exit 1
fi

echo "i18n shadow guard: OK — no 't' shadows in $FILE"
