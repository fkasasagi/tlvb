#!/usr/bin/env bash
#
# session.sh — multi-session coordination for parallel Claude Code work.
#
# Problem it solves: several Claude Code sessions edit one repo concurrently and
# clobber each other (same working dir, same files) without knowing what the
# others are doing. This gives each session its own git worktree (so physical
# conflicts vanish) plus a shared "who is doing what right now" board.
#
# The board lives in   <main-repo>/.git/claude-sessions/   — one file per
# session. That path is shared by every worktree (git common dir), is NOT
# tracked by git (so it never causes merge conflicts), and one-file-per-session
# means two sessions writing at once never collide.
#
# Project-specific heavy gitignored dirs that should be SHARED across worktrees
# (instead of each worktree rebuilding them) are declared in a `.session-board`
# file at the repo root — one dir name per line, `#` comments allowed, e.g.:
#       outputs        # DuckDB caches (rules.duckdb / cases.duckdb)
#       .venv
# `new` and `link-shared` symlink each listed dir back to the main worktree.
#
# Subcommands:
#   board [--hook]              show the board; --hook emits SessionStart JSON
#   claim <area> [note]         register THIS session (area = comma/space pkgs)
#   release [--quiet]           remove THIS session's entry (SessionEnd hook)
#   new <slug> [base-branch]    create a worktree+branch with shared dirs linked
#   link-shared                 symlink THIS worktree's shared dirs to main repo
#
set -uo pipefail

STALE_HOURS=8
BOARD_NAME="claude-sessions"
SHARE_CONF=".session-board"

is_git() { git rev-parse --git-dir >/dev/null 2>&1; }

git_common_abs() {
  local cdir
  cdir=$(git rev-parse --git-common-dir 2>/dev/null) || return 1
  (cd "$cdir" && pwd)
}

# The main worktree is the parent of the git common dir (<main>/.git).
main_root() { dirname "$(git_common_abs)"; }
board_dir() { echo "$(git_common_abs)/$BOARD_NAME"; }
proj_name() { basename "$(main_root)"; }

cur_branch() {
  local b
  b=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
  [ "$b" = "HEAD" ] && b="detached-$(basename "$(pwd)")"
  echo "$b"
}

session_file() {
  local key
  key=$(cur_branch | tr '/ ' '__')
  echo "$(board_dir)/${key}.session"
}

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }
field() { sed -n "s/^$2=//p" "$1" 2>/dev/null | head -1; }

cmd_claim() {
  is_git || { echo "not a git repo — session board unavailable" >&2; return 0; }
  local area="${1:-}" note="${2:-}"
  if [ -z "$area" ]; then
    echo "usage: session.sh claim <area> [note]   (area e.g. internal/tier2 or pkg/a,pkg/b)" >&2
    return 2
  fi
  local dir file started
  dir=$(board_dir); mkdir -p "$dir"
  file=$(session_file)
  started=$(now_iso)
  [ -f "$file" ] && started=$(field "$file" started)
  {
    echo "branch=$(cur_branch)"
    echo "worktree=$(pwd)"
    echo "area=$area"
    echo "note=$note"
    echo "status=active"
    echo "started=$started"
    echo "updated=$(now_iso)"
  } > "$file"
  echo "claimed: $(cur_branch) → [$area]${note:+ ($note)}"
  cmd_board
}

cmd_release() {
  is_git || return 0
  local quiet=""
  [ "${1:-}" = "--quiet" ] && quiet=1
  local file
  file=$(session_file)
  if [ -f "$file" ]; then
    rm -f "$file"
    [ -z "$quiet" ] && echo "released: $(cur_branch)"
  else
    [ -z "$quiet" ] && echo "no active board entry for $(cur_branch)"
  fi
  return 0
}

# Render the board to stdout. Returns 0 always.
cmd_board() {
  is_git || return 0
  local dir
  dir=$(board_dir)
  local files=()
  if [ -d "$dir" ]; then
    while IFS= read -r f; do files+=("$f"); done < <(ls -1 "$dir"/*.session 2>/dev/null)
  fi
  local hint="${SESSION_CLAIM_HINT:-scripts/session.sh claim <area> [note]}"
  echo "═══ active sessions · $(proj_name) ════════════════════════════"
  if [ "${#files[@]}" -eq 0 ]; then
    echo "  (none registered)"
    echo "  → register this session: $hint"
    echo "════════════════════════════════════════════════════════════════"
    return 0
  fi

  local now_s nowfmt me
  nowfmt=$(now_iso)
  now_s=$(date -u -d "$nowfmt" +%s 2>/dev/null || echo 0)
  me=$(session_file)

  declare -A token_owners=()
  local f
  for f in "${files[@]}"; do
    local branch area updated note upd_s age_h mark self
    branch=$(field "$f" branch); area=$(field "$f" area)
    updated=$(field "$f" updated); note=$(field "$f" note)
    upd_s=$(date -u -d "$updated" +%s 2>/dev/null || echo "$now_s")
    age_h=$(( (now_s - upd_s) / 3600 ))
    mark=""; [ "$age_h" -ge "$STALE_HOURS" ] && mark=" ⏰stale(${age_h}h)"
    self=""; [ "$f" = "$me" ] && self=" «this»"
    printf "  %-34s [%s]%s%s\n" "$branch" "$area" "$self" "$mark"
    [ -n "$note" ] && printf "      ↳ %s\n" "$note"
    if [ "$age_h" -lt "$STALE_HOURS" ]; then
      local tok
      for tok in ${area//,/ }; do token_owners[$tok]+="${branch}|"; done
    fi
  done

  local warned="" tok
  for tok in "${!token_owners[@]}"; do
    local owners="${token_owners[$tok]}"
    if [ "$(echo "$owners" | tr '|' '\n' | grep -c .)" -ge 2 ]; then
      [ -z "$warned" ] && { echo "  ──"; warned=1; }
      printf "  ⚠ overlap on %-22s %s\n" "$tok" "$(echo "$owners" | sed 's/|/ , /g; s/ , $//')"
    fi
  done
  [ -n "$warned" ] && echo "  ⚠ overlap = merge-conflict risk. keep areas disjoint."
  [ -f "$me" ] || echo "  → this session is unregistered: $hint"
  echo "════════════════════════════════════════════════════════════════"
  return 0
}

# Emit the board wrapped as SessionStart additionalContext so the model is
# guaranteed to see it (not relying on plain-stdout surfacing). Silent + exit 0
# in non-git projects so a user-scoped hook is harmless everywhere.
cmd_board_hook() {
  is_git || return 0
  local txt esc
  txt="$(cmd_board)"
  [ -z "$txt" ] && return 0
  esc=$(printf '%s' "$txt" | sed -e ':a' -e 'N' -e '$!ba' \
        -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\n/\\n/g')
  printf '{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"%s"}}\n' "$esc"
}

# symlink each dir listed in .session-board from <src-root> into <dst-worktree>
link_shared_dirs() {
  local src="$1" dst="$2" conf="$1/$SHARE_CONF"
  [ -f "$conf" ] || return 0
  local line d
  while IFS= read -r line || [ -n "$line" ]; do
    d="${line%%#*}"; d="$(echo "$d" | xargs)"
    [ -z "$d" ] && continue
    if [ -e "$dst/$d" ] && [ ! -L "$dst/$d" ]; then
      echo "skip $d (exists in worktree, not a symlink)"; continue
    fi
    if [ -d "$src/$d" ]; then
      ln -sfn "$src/$d" "$dst/$d"
      echo "linked $d/ → $src/$d"
    fi
  done < "$conf"
}

cmd_new() {
  is_git || { echo "not a git repo" >&2; return 1; }
  local slug="${1:-}" base="${2:-}"
  if [ -z "$slug" ]; then
    echo "usage: session.sh new <slug> [base-branch]" >&2
    return 2
  fi
  [ -z "$base" ] && base=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
  [ -z "$base" ] && base="HEAD"
  local root wt
  root=$(main_root)
  wt="$root/.claude/worktrees/$slug"
  if [ -e "$wt" ]; then echo "worktree already exists: $wt" >&2; return 1; fi
  git worktree add -b "$slug" "$wt" "$base" || return 1
  link_shared_dirs "$root" "$wt"
  echo
  echo "worktree ready: $wt   (branch: $slug, base: $base)"
  echo "  cd \"$wt\" && claude        # then: scripts/session.sh claim <area>"
}

cmd_link_shared() {
  is_git || { echo "not a git repo" >&2; return 1; }
  local root here
  root=$(main_root); here="$(pwd)"
  if [ "$here" = "$root" ]; then echo "this IS the main repo; nothing to link"; return 0; fi
  link_shared_dirs "$root" "$here"
}

case "${1:-}" in
  board)        shift; [ "${1:-}" = "--hook" ] && cmd_board_hook || cmd_board ;;
  claim)        shift; cmd_claim "$@" ;;
  release)      shift; cmd_release "$@" ;;
  new)          shift; cmd_new "$@" ;;
  link-shared)  cmd_link_shared ;;
  *)
    echo "usage: session.sh {board [--hook]|claim <area> [note]|release|new <slug> [base]|link-shared}" >&2
    exit 2 ;;
esac
