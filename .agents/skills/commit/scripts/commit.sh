#!/usr/bin/env bash
# Deterministic commit: stage every working file, screen the index, commit.
#
# Usage:
#   commit.sh -m "Subject" [-m "Body paragraph"]... [--dry-run]
#
# Steps are fixed: repository checks, stage everything, run preflight.sh,
# validate the message, commit. Nothing is auto-generated and nothing is
# pushed. Exit codes: 0 success, 1 blocked by a safety check, 2 usage or
# environment error. On failure the index is left staged for inspection.

set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
preflight="$script_dir/preflight.sh"

die() {
  printf 'error: %s\n' "$1" >&2
  exit "${2:-1}"
}

usage() {
  cat <<'EOF'
Deterministic commit: stage every working file, screen the index, commit.

Usage: commit.sh -m "Subject" [-m "Body paragraph"]... [--dry-run]

  -m TEXT     Message part; repeat to add body paragraphs
  --dry-run   Stage and screen, show what would be committed, commit nothing
  -h, --help  Show this help

Exit codes: 0 success, 1 blocked by a safety check, 2 usage/environment error.
EOF
}

messages=()
dry_run=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    -m)
      [ "$#" -ge 2 ] || die "-m requires a value" 2
      [ -n "$2" ] || die "-m requires a non-empty value" 2
      messages+=("$2")
      shift 2
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1 (try --help)" 2
      ;;
  esac
done

# --- Repository and environment checks -------------------------------------

git rev-parse --git-dir >/dev/null 2>&1 || die "not inside a git repository" 2
cd "$(git rev-parse --show-toplevel)" || die "cannot enter repository root" 2

[ -f "$preflight" ] || die "screening script not found: $preflight" 2
[ -n "$(git config user.name || true)" ] || die "git user.name is not configured" 2
[ -n "$(git config user.email || true)" ] || die "git user.email is not configured" 2

gitdir=$(git rev-parse --git-dir)
for marker in rebase-merge rebase-apply MERGE_HEAD CHERRY_PICK_HEAD REVERT_HEAD BISECT_LOG; do
  if [ -e "$gitdir/$marker" ]; then
    die "git operation in progress ($marker); finish or abort it first" 1
  fi
done

git symbolic-ref -q HEAD >/dev/null \
  || die "HEAD is detached; check out a branch before committing" 1

# --- Stage every working file ----------------------------------------------

printf 'Staging all working files...\n'
git add -A

if git diff --cached --quiet; then
  printf 'Nothing to commit.\n'
  exit 0
fi

# --- Screen the index ------------------------------------------------------

if ! bash "$preflight"; then
  die "screening flagged issues; nothing was committed (index left staged, 'git reset' to unstage)" 1
fi

if [ "$dry_run" -eq 1 ]; then
  printf '\nDry run: index screened, nothing committed.\n'
  git diff --cached --stat
  exit 0
fi

# --- Validate the message --------------------------------------------------

if [ "${#messages[@]}" -eq 0 ]; then
  die "a message is required: pass -m \"Subject\" (and optionally -m \"Body\")" 2
fi

subject=${messages[0]}
if [ "${#subject}" -gt 100 ]; then
  die "subject is ${#subject} characters; keep it under 100 (target 72)" 2
fi
if [ "${#subject}" -gt 72 ]; then
  printf 'warning: subject is %d characters (target is 72)\n' "${#subject}" >&2
fi
case "$subject" in
  *.)
    printf 'warning: subject ends with a period\n' >&2
    ;;
esac

attribution_re='co-authored-by|generated[ -]by|generated[ -]with|assisted-by|written[ -]by[ -](an?[ -])?(ai|model)|deepseek|chatgpt|openai|anthropic|claude|copilot|\bllm\b|\bai\b'
for message in "${messages[@]}"; do
  if printf '%s\n' "$message" | grep -Eqi "$attribution_re"; then
    die "message contains attribution or tool/model wording: $message" 1
  fi
done

# --- Commit and report -----------------------------------------------------

commit_args=()
for message in "${messages[@]}"; do
  commit_args+=(-m "$message")
done

if ! git commit "${commit_args[@]}"; then
  die "git commit failed (see hook output above); index left staged" 1
fi

printf '\nCommitted %s\n' "$(git rev-parse --short HEAD)"
git log -1 --format='%h %s'
git show --stat --format='' HEAD | tail -n 1
if [ -n "$(git status --porcelain)" ]; then
  printf '\nnote: files changed during the commit remain unstaged:\n'
  git status --short
fi
