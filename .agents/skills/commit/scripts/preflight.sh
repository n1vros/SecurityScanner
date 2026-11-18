#!/usr/bin/env bash
# Read-only pre-commit screening for the `commit` skill.
#
# Inspects the staged index and reports:
#   - sensitive filenames (.env, keys, dumps, databases, logs, ...)
#   - secret-like content in added lines
#   - unresolved conflict markers
#   - binary blobs and files over 1 MiB
#   - a missing git identity, which would make the commit fail anyway
#
# Exit codes:
#   0  clean (nothing staged or nothing suspicious)
#   1  findings to review before committing
#   2  not usable (no repository, no git identity)
#
# It never stages, commits, or modifies the working tree.

set -uo pipefail

RED=''
BOLD=''
RESET=''
if [ -t 1 ]; then
  RED=$'\033[31m'
  BOLD=$'\033[1m'
  RESET=$'\033[0m'
fi

findings=0
note() { printf '%s%s%s\n' "$BOLD" "$1" "$RESET"; }
flag() { printf '%s  ! %s%s\n' "$RED" "$1" "$RESET"; findings=$((findings + 1)); }

# --- Preconditions ---------------------------------------------------------

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  printf 'Not inside a git repository.\n' >&2
  exit 2
fi

cd "$(git rev-parse --show-toplevel)" || exit 2

if [ -z "$(git config user.name || true)" ] || [ -z "$(git config user.email || true)" ]; then
  printf 'Git identity is not configured (user.name / user.email); the commit would fail.\n' >&2
  exit 2
fi

# --- Overview --------------------------------------------------------------

note "Working tree"
git status --short || true

staged=$(git diff --cached --name-only)
if [ -z "$staged" ]; then
  printf '\nNothing staged; nothing to screen.\n'
  exit 0
fi

count=$(printf '%s\n' "$staged" | wc -l | tr -d ' ')
note "Staged files ($count)"
printf '%s\n' "$staged" | sed 's/^/  /'

# --- 1. Sensitive filenames ------------------------------------------------

note ""
note "Sensitive filenames"
sensitive_re='(^|/)(\.env(\.[^/]*)?|gcp\.json|\.credentials\.?yaml|id_(rsa|dsa|ecdsa|ed25519)(\.[^/]*)?|[^/]*\.(pem|key|p12|pfx|jks|keystore|kdbx|ovpn|sqlite3?|db|dump|bak|log))$'
hits=$(printf '%s\n' "$staged" | grep -Ei "$sensitive_re" \
  | grep -Ev '\.env\.(example|sample|template|dist)$' || true)
if [ -n "$hits" ]; then
  while IFS= read -r f; do flag "sensitive name: $f"; done <<<"$hits"
else
  printf '  none\n'
fi

# --- 2. Secret-like content in added lines ---------------------------------

note ""
note "Secret-like content in added lines"
secret_re='(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]+|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,})'
key_re='(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|private[_-]?key|webhook[_-]?url|bearer [A-Za-z0-9._-]{20,})[[:space:]]*[:=]'
scan_paths=()
while IFS= read -r staged_path; do
  [ -n "$staged_path" ] || continue
  case "$(basename "$staged_path")" in
    .env.example|.env.sample|.env.template|.env.dist) continue ;;
  esac
  scan_paths+=(":$staged_path")
done <<<"$staged"

if [ "${#scan_paths[@]}" -eq 0 ]; then
  content_hits=""
else
  content_hits=$(git diff --cached -U0 --no-color -- "${scan_paths[@]}" \
  | grep -E '^\+[^+]' \
  | grep -Ei "$secret_re|$key_re" \
  | grep -Eiv '(example|sample|placeholder|redacted|<[a-z_ -]+>|your[_-]|xxx+|changeme|dummy|test[_-]?key|0123456789|localhost|\$\{[A-Z_][A-Z0-9_]*|\$[A-Z_][A-Z0-9_]*)' \
  | head -40 || true)
fi
if [ -n "$content_hits" ]; then
  while IFS= read -r line; do flag "${line:0:200}"; done <<<"$content_hits"
  printf '  (match context is in the staged diff; inspect with: git diff --cached)\n'
else
  printf '  none\n'
fi

# --- 3. Conflict markers ---------------------------------------------------

note ""
note "Conflict markers"
conflict_hits=$(git diff --cached -U0 --no-color | grep -E '^\+(<{7}|={7}|>{7})( |$)' || true)
if [ -n "$conflict_hits" ]; then
  while IFS= read -r line; do flag "$line"; done <<<"$conflict_hits"
else
  printf '  none\n'
fi

# --- 4. Binary blobs -------------------------------------------------------

note ""
note "Binary blobs"
binary_hits=$(git diff --cached --numstat | awk -F'\t' '$1 == "-" { print $3 }' | while IFS= read -r f; do
  [ -n "$f" ] || continue
  git cat-file -e ":$f" 2>/dev/null && printf '%s\n' "$f"
done || true)
if [ -n "$binary_hits" ]; then
  while IFS= read -r f; do flag "binary file: $f"; done <<<"$binary_hits"
else
  printf '  none\n'
fi

# --- 5. Large files --------------------------------------------------------

note ""
note "Files over 1 MiB"
large=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  size=$(git cat-file -s ":$f" 2>/dev/null || printf '0')
  if [ "${size:-0}" -gt 1048576 ]; then
    flag "large file: $f ($(awk -v s="$size" 'BEGIN { printf "%.1f", s / 1048576 }') MiB)"
    large=1
  fi
done <<<"$staged"
[ "$large" -eq 0 ] && printf '  none\n'

# --- Summary ---------------------------------------------------------------

note ""
if [ "$findings" -gt 0 ]; then
  printf '%s%d finding(s) to review before committing.%s\n' "$RED" "$findings" "$RESET"
  printf 'Unstage what does not belong with: git restore --staged <path>\n'
  exit 1
fi

printf 'No findings.\n'
exit 0
