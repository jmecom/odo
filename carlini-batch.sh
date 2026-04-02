#!/usr/bin/env bash
# Clone multiple repositories and run carlini.sh against each one.
#
# Usage: ./carlini-batch.sh [wrapper options] [repo ...] [-- carlini options]
#   ./carlini-batch.sh --repo-file repos.txt
#   ./carlini-batch.sh https://github.com/acme/api.git git@github.com:acme/web.git
#   ./carlini-batch.sh --repo-file repos.txt -- --max-files 50 --smart-discover-files

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./carlini-batch.sh [wrapper options] [repo ...] [-- carlini options]

Wrapper options:
  --repo-file FILE   Read repositories from FILE, one per line.
  --clone-root DIR   Directory to clone repositories into. Default: ./clones
  --out-root DIR     Directory to store per-repo reports in. Default: ~/bughunt-reports
  --fail-fast        Stop after the first clone or audit failure.
  -h, --help         Show this help text.

Examples:
  ./carlini-batch.sh --repo-file repos.txt
  ./carlini-batch.sh https://github.com/acme/api.git git@github.com:acme/web.git
  ./carlini-batch.sh --repo-file repos.txt --clone-root /tmp/repos --out-root /tmp/reports -- --max-files 50

Notes:
  - Repositories can be remote URLs or local git repository paths.
  - Arguments after `--` are forwarded to carlini.sh for every repo.
  - Each repo gets its own OUTDIR under --out-root.
EOF
}

SCRIPT_DIR=$(
  cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
)
CARLINI_BIN="${CARLINI_BIN:-$SCRIPT_DIR/carlini.sh}"
REPO_FILE=""
CLONE_ROOT="${CLONE_ROOT:-clones}"
OUT_ROOT="${OUT_ROOT:-$HOME/bughunt-reports}"
FAIL_FAST=false
REPOS=()
CARLINI_ARGS=()

die() {
  echo "$*" >&2
  exit 1
}

require_arg() {
  local flag="$1"
  [[ $# -ge 2 ]] || die "Missing value for $flag"
}

slug_repo() {
  printf '%s' "$1" | sed -E \
    -e 's#^[^@]+@##' \
    -e 's#^[A-Za-z][A-Za-z0-9+.-]*://##' \
    -e 's#:#/#' \
    -e 's#/$##' \
    -e 's#\.git$##' \
    -e 's#[^A-Za-z0-9._-]+#_#g'
}

load_repo_file() {
  local file="$1"
  local line repo

  [[ -f "$file" ]] || die "Repo list file not found: $file"

  while IFS= read -r line || [[ -n "$line" ]]; do
    repo=$(printf '%s' "$line" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    [[ -z "$repo" ]] && continue
    [[ "$repo" == \#* ]] && continue
    REPOS+=("$repo")
  done <"$file"
}

clone_repo() {
  local repo="$1"
  local dest="$2"

  if [[ -d "$dest/.git" ]]; then
    echo "    Reusing existing clone: $dest"
    return 0
  fi

  if [[ -e "$dest" ]]; then
    echo "    Destination exists and is not a git repo: $dest" >&2
    return 1
  fi

  git clone "$repo" "$dest"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
  --repo-file)
    require_arg "$@"
    REPO_FILE="$2"
    shift 2
    ;;
  --clone-root)
    require_arg "$@"
    CLONE_ROOT="$2"
    shift 2
    ;;
  --out-root)
    require_arg "$@"
    OUT_ROOT="$2"
    shift 2
    ;;
  --fail-fast)
    FAIL_FAST=true
    shift
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  --)
    shift
    CARLINI_ARGS=("$@")
    break
    ;;
  -*)
    die "Unknown wrapper option: $1"
    ;;
  *)
    REPOS+=("$1")
    shift
    ;;
  esac
done

command -v git &>/dev/null || die "git required in PATH"
[[ -x "$CARLINI_BIN" ]] || die "carlini.sh not found or not executable: $CARLINI_BIN"

if [[ -n "$REPO_FILE" ]]; then
  load_repo_file "$REPO_FILE"
fi

[[ ${#REPOS[@]} -gt 0 ]] || die "No repositories provided. Use positional args or --repo-file."

mkdir -p "$CLONE_ROOT" "$OUT_ROOT"

failures=0
failed_repos=()
total=${#REPOS[@]}

for i in "${!REPOS[@]}"; do
  repo="${REPOS[$i]}"
  slug=$(slug_repo "$repo")
  [[ -n "$slug" ]] || slug="repo_$((i + 1))"

  clone_dir="$CLONE_ROOT/$slug"
  repo_out_dir="$OUT_ROOT/$slug"

  echo "=== [$((i + 1))/$total] $repo ==="
  echo "    Clone dir: $clone_dir"
  echo "    Output dir: $repo_out_dir"

  if ! clone_repo "$repo" "$clone_dir"; then
    failures=$((failures + 1))
    failed_repos+=("$repo (clone)")
    $FAIL_FAST && exit 1
    echo ""
    continue
  fi

  mkdir -p "$repo_out_dir"

  if ((${#CARLINI_ARGS[@]} > 0)); then
    audit_cmd=(env OUTDIR="$repo_out_dir" "$CARLINI_BIN" "${CARLINI_ARGS[@]}" "$clone_dir")
  else
    audit_cmd=(env OUTDIR="$repo_out_dir" "$CARLINI_BIN" "$clone_dir")
  fi

  if "${audit_cmd[@]}"; then
    echo "    Audit completed for $repo"
  else
    failures=$((failures + 1))
    failed_repos+=("$repo (audit)")
    echo "    Audit failed for $repo" >&2
    $FAIL_FAST && exit 1
  fi

  echo ""
done

if ((failures > 0)); then
  echo "Completed with $failures failure(s):" >&2
  for failed in "${failed_repos[@]}"; do
    echo "  - $failed" >&2
  done
  exit 1
fi

echo "Completed $total repos. Clones: $CLONE_ROOT | Reports: $OUT_ROOT"
