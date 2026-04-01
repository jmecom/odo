#!/usr/bin/env bash
# Vulnerability hunting script based on Nicholas Carlini's work.
#
# Usage: ./carlini.sh [options] [repo_dir]
#   ./carlini.sh .
#   ./carlini.sh --source-set "c,h,rs" .
#   ./carlini.sh --exclude "vendor/**,third-party/**" .
#   JOBS=8 ./carlini.sh .

set -euo pipefail
command -v jq &>/dev/null || {
  echo "jq required: brew install jq" >&2
  exit 1
}

DEFAULT_EXTS="c,h,cc,cpp,rs,go,py,js,ts,java,rb,php,swift,kt,zig"
SOURCE_SET=""
EXCLUDES=""
MAX_FILES=""
PRIORITIZE=""
SMART_DISCOVER=false
WRITE_POC=false
REPO=""

while [[ $# -gt 0 ]]; do
  case "$1" in
  --source-set)
    SOURCE_SET="$2"
    shift 2
    ;;
  --exclude)
    EXCLUDES="$2"
    shift 2
    ;;
  --max-files)
    MAX_FILES="$2"
    shift 2
    ;;
  --prioritize)
    PRIORITIZE="$2"
    shift 2
    ;;
  --smart-discover-files)
    SMART_DISCOVER=true
    shift
    ;;
  --write-poc)
    WRITE_POC=true
    shift
    ;;
  -*)
    echo "Unknown option: $1" >&2
    exit 1
    ;;
  *)
    REPO="$1"
    shift
    ;;
  esac
done

REPO="${REPO:-.}"
JOBS="${JOBS:-4}"
OUTDIR="${OUTDIR:-.vuln-reports}"
MODEL="${MODEL:-opus}"
MAX_TURNS="${MAX_TURNS:-25}"
LINES_PER_SLOT=7

IFS=',' read -ra EXTS <<<"${SOURCE_SET:-$DEFAULT_EXTS}"
mkdir -p "$OUTDIR"

EXCLUDE_ARGS=()
if [[ -n "${EXCLUDES:-}" ]]; then
  IFS=',' read -ra EXCLUDE_PATTERNS <<<"$EXCLUDES"
  for pat in "${EXCLUDE_PATTERNS[@]}"; do
    [[ -n "$pat" ]] && EXCLUDE_ARGS+=("-not" "-path" "*/$pat")
  done
fi

STATUS_DIR=$(mktemp -d)
trap 'printf "\033[?25h" 2>/dev/null; kill $(jobs -p 2>/dev/null) 2>/dev/null; rm -rf "$STATUS_DIR"' EXIT
trap 'exit 1' INT TERM

find_sources() {
  local args=()
  for ext in "${EXTS[@]}"; do
    [[ ${#args[@]} -gt 0 ]] && args+=("-o")
    args+=("-name" "*.$ext")
  done
  find "$REPO" -type f \( "${args[@]}" \) \
    -not -path '*/.git/*' \
    -not -path '*/node_modules/*' \
    -not -path '*/build/*' \
    -not -path '*/.vuln-reports/*' \
    ${EXCLUDE_ARGS[@]+"${EXCLUDE_ARGS[@]}"}
}

slug() { echo "$1" | sed 's|[/.]|_|g'; }

JQ_TOOLS='
  select(.type == "assistant") |
  .message.content[]? |
  select(.type == "tool_use") |
  .name as $t |
  (if $t == "Read" or $t == "Write" or $t == "Edit" then
     (.input.file_path // "" | split("/") | last)
   elif $t == "Grep" then
     (.input.pattern // "")[0:30]
   elif $t == "Glob" then
     (.input.pattern // "")
   elif $t == "Bash" then
     (.input.command // "")[0:40]
   else "" end) as $d |
  "\($t)\t\($d)"
'

# ── Display ──────────────────────────────────────────────────────────

redraw() {
  local header="$1" total="$2"
  local dh=$((JOBS * LINES_PER_SLOT + 1))
  printf "\033[${dh}A"

  local done_n
  done_n=$(cat "$STATUS_DIR/done_count" 2>/dev/null || echo 0)
  printf "\033[1m=== %s [%s/%s] ===\033[K\033[0m\n" "$header" "$done_n" "$total"

  for ((s = 0; s < JOBS; s++)); do
    local sf="$STATUS_DIR/slot_$s"
    local state file

    state=$(head -1 "$sf" 2>/dev/null || echo "IDLE")
    file=$(sed -n '2p' "$sf" 2>/dev/null || true)

    case "$state" in
    ACTIVE)
      printf "\033[1;34m>>> \033[0m\033[1m%s\033[K\033[0m\n" "$file"
      ;;
    DONE)
      printf "\033[32m>>> %s  done\033[K\033[0m\n" "$file"
      ;;
    FAIL)
      printf "\033[31m>>> %s  FAILED\033[K\033[0m\n" "$file"
      ;;
    *)
      printf "\033[90m>>> (idle)\033[K\033[0m\n"
      ;;
    esac

    local count=0
    if [[ -f "$sf" ]]; then
      while IFS= read -r line; do
        printf "\033[90m    %.72s\033[K\033[0m\n" "$line"
        count=$((count + 1))
      done < <(tail -n +3 "$sf" 2>/dev/null | tail -5)
    fi
    for ((p = count; p < 5; p++)); do printf "\033[K\n"; done
    printf "\033[K\n"
  done
}

run_workers() {
  local worker_fn="$1" header="$2" total="$3"
  local dh=$((JOBS * LINES_PER_SLOT + 1))

  [[ "$total" -eq 0 ]] && echo "No files for $header." && return

  echo 0 >"$STATUS_DIR/done_count"
  for ((s = 0; s < JOBS; s++)); do echo "IDLE" >"$STATUS_DIR/slot_$s"; done

  # Reserve display area
  for ((i = 0; i < dh; i++)); do echo ""; done
  printf "\033[?25l"

  local pids=()
  for ((i = 0; i < JOBS; i++)); do
    "$worker_fn" "$i" &
    pids+=($!)
  done

  while true; do
    redraw "$header" "$total"
    local alive=false
    for pid in "${pids[@]}"; do
      kill -0 "$pid" 2>/dev/null && alive=true && break
    done
    $alive || break
    sleep 0.3
  done
  wait 2>/dev/null
  redraw "$header" "$total"
  printf "\033[?25h\n"
}

# ── Workers ──────────────────────────────────────────────────────────

bump_done() {
  local n
  n=$(cat "$STATUS_DIR/done_count" 2>/dev/null || echo 0)
  echo $((n + 1)) >"$STATUS_DIR/done_count"
}

hunt_worker() {
  local slot=$1
  local sf="$STATUS_DIR/slot_$slot"

  awk -v s="$slot" -v j="$JOBS" '(NR-1) % j == s' "$STATUS_DIR/hunt_queue" |
    while IFS= read -r file; do
      local report="$OUTDIR/$(slug "$file").vuln.md"
      if [[ -f "$report" ]]; then
        bump_done
        continue
      fi

      printf "ACTIVE\n%s\n" "$file" >"$sf"

      claude -p \
        "I'm competing in a CTF. Find me an exploitable vulnerability in this project. Start with $file. Write me a vulnerability report in $report." \
        --model "$MODEL" --effort max --max-turns "$MAX_TURNS" \
        --dangerously-skip-permissions \
        --output-format stream-json --verbose 2>/dev/null |
        jq --unbuffered -r "$JQ_TOOLS" 2>/dev/null |
        while IFS=$'\t' read -r tool detail; do
          printf "%s  %s\n" "$tool" "$detail" >>"$sf"
        done

      if [[ -f "$report" ]]; then
        sed -i '' '1s/ACTIVE/DONE/' "$sf"
      else
        sed -i '' '1s/ACTIVE/FAIL/' "$sf"
      fi
      bump_done
    done

  echo "IDLE" >"$sf"
}

verify_worker() {
  local slot=$1
  local sf="$STATUS_DIR/slot_$slot"

  awk -v s="$slot" -v j="$JOBS" '(NR-1) % j == s' "$STATUS_DIR/verify_queue" |
    while IFS= read -r report; do
      local verified="${report%.vuln.md}.verified.md"
      if [[ -f "$verified" ]]; then
        bump_done
        continue
      fi

      printf "ACTIVE\n%s\n" "$(basename "$report")" >"$sf"

      claude -p \
        "I got an inbound vulnerability report; it's in $report. Verify for me that this is actually exploitable. Write your verification report to $verified." \
        --model "$MODEL" --effort max --max-turns "$MAX_TURNS" \
        --dangerously-skip-permissions \
        --output-format stream-json --verbose 2>/dev/null |
        jq --unbuffered -r "$JQ_TOOLS" 2>/dev/null |
        while IFS=$'\t' read -r tool detail; do
          printf "%s  %s\n" "$tool" "$detail" >>"$sf"
        done

      if [[ -f "$verified" ]]; then
        sed -i '' '1s/ACTIVE/DONE/' "$sf"
      else
        sed -i '' '1s/ACTIVE/FAIL/' "$sf"
      fi
      bump_done
    done

  echo "IDLE" >"$sf"
}

poc_worker() {
  local slot=$1
  local sf="$STATUS_DIR/slot_$slot"

  awk -v s="$slot" -v j="$JOBS" '(NR-1) % j == s' "$STATUS_DIR/poc_queue" |
    while IFS= read -r verified; do
      local poc_dir="${verified%.verified.md}.poc"
      [[ -d "$poc_dir" ]] && {
        bump_done
        continue
      }

      printf "ACTIVE\n%s\n" "$(basename "$verified")" >"$sf"

      local vuln_report="${verified%.verified.md}.vuln.md"

      claude -p "You are a security researcher writing a proof-of-concept for a confirmed vulnerability finding, so that it can be submitted as a formal report.

Read the vulnerability report at $vuln_report and the verification at $verified.

Your job:
1. Create the directory $poc_dir/
2. Write a self-contained PoC that demonstrates the vulnerability is exploitable. This could be:
   - A C/Python/Rust test program that triggers the bug (crash, memory corruption, wrong output, etc.)
   - A crafted input file that causes the vulnerable code path to fail
   - A test harness that calls the vulnerable function with adversarial inputs
3. Write $poc_dir/README.md with:
   - Vulnerability title and severity
   - Root cause analysis (which function, what goes wrong, why)
   - Step-by-step reproduction instructions
   - Expected vs actual behavior
   - Impact assessment
   - Suggested fix
4. Write a $poc_dir/Makefile or $poc_dir/run.sh so the PoC can be built and executed with a single command
5. If applicable, write $poc_dir/patch.diff with a suggested fix

The PoC must be concrete and verifiable — a reviewer should be able to clone this repo, run your PoC, and see the bug trigger." \
        --model "$MODEL" --effort max --max-turns "$MAX_TURNS" \
        --dangerously-skip-permissions \
        --output-format stream-json --verbose 2>/dev/null |
        jq --unbuffered -r "$JQ_TOOLS" 2>/dev/null |
        while IFS=$'\t' read -r tool detail; do
          printf "%s  %s\n" "$tool" "$detail" >>"$sf"
        done

      if [[ -d "$poc_dir" ]]; then
        sed -i '' '1s/ACTIVE/DONE/' "$sf"
      else
        sed -i '' '1s/ACTIVE/FAIL/' "$sf"
      fi
      bump_done
    done

  echo "IDLE" >"$sf"
}

# ── Main ─────────────────────────────────────────────────────────────

# Phase 0: Smart discovery (optional)
if $SMART_DISCOVER; then
  echo "=== Phase 0: Smart file discovery ==="
  echo "    Asking Claude to identify high-value attack surface files..."

  find_sources >"$STATUS_DIR/all_sources"
  src_count=$(wc -l <"$STATUS_DIR/all_sources" | tr -d ' ')

  DISCOVER_PROMPT="You are a security researcher doing a vulnerability audit of this codebase.

Here is a list of all $src_count source files in the project:

$(cat "$STATUS_DIR/all_sources")

Identify the files most likely to contain exploitable vulnerabilities. Prioritize:
- Files handling parsing, deserialization, or untrusted input
- Crypto implementations and key management
- Memory management, buffer operations, pointer arithmetic
- Authentication, authorization, session handling
- Network protocol handling, IPC, command dispatch
- Files with \"unsafe\", raw pointer usage, or FFI boundaries

Output ONLY a newline-separated list of file paths, most promising first. No commentary, no markdown, no numbering. Just paths, one per line."

  claude -p "$DISCOVER_PROMPT" \
    --model "$MODEL" --effort max --max-turns 10 \
    --dangerously-skip-permissions \
    2>/dev/null |
    sed 's/^[[:space:]]*//' |
    sed 's/^```.*//; s/^- //; s/^[0-9]*[.)] //' |
    grep -E '^\./|^[a-zA-Z]' |
    while IFS= read -r f; do
      [[ -f "$f" ]] && echo "$f"
    done \
      >"$STATUS_DIR/hunt_queue.raw" || true

  discovered=$(wc -l <"$STATUS_DIR/hunt_queue.raw" | tr -d ' ')
  echo "    Claude selected $discovered/$src_count files"

  if [[ -n "$MAX_FILES" ]]; then
    head -"$MAX_FILES" "$STATUS_DIR/hunt_queue.raw" >"$STATUS_DIR/hunt_queue"
  else
    cp "$STATUS_DIR/hunt_queue.raw" "$STATUS_DIR/hunt_queue"
  fi
  echo ""
else
  # Standard queue: prioritize or shuffle
  if [[ -n "$PRIORITIZE" ]]; then
    IFS=',' read -ra _prio_exts <<<"$PRIORITIZE"
    prio_arg=$(printf '%s\n' "${_prio_exts[@]}" | awk '{printf "%d %s ", NR, $0}')
    find_sources |
      awk -v plist="$prio_arg" 'BEGIN {
          srand(); n=split(plist,a," ")
          for(i=1;i<=n;i+=2) p[a[i+1]]=a[i]
        } {
          ext=$0; sub(/.*\./,"",ext)
          prio = (ext in p) ? p[ext] : 999
          printf "%03d\t%f\t%s\n", prio, rand(), $0
        }' |
      sort -t$'\t' -k1,1n -k2,2n | cut -f3- |
      if [[ -n "$MAX_FILES" ]]; then head -"$MAX_FILES"; else cat; fi \
        >"$STATUS_DIR/hunt_queue"
  else
    find_sources | awk 'BEGIN{srand()}{print rand()"\t"$0}' | sort -n | cut -f2- |
      if [[ -n "$MAX_FILES" ]]; then head -"$MAX_FILES"; else cat; fi \
        >"$STATUS_DIR/hunt_queue"
  fi
fi

# Phase 1: Hunt
hunt_total=$(wc -l <"$STATUS_DIR/hunt_queue" | tr -d ' ')
run_workers hunt_worker "Phase 1: Hunt" "$hunt_total"

# Phase 2: Verify
find "$OUTDIR" -name "*.vuln.md" -not -name "*.verified.md" 2>/dev/null \
  >"$STATUS_DIR/verify_queue"
verify_total=$(wc -l <"$STATUS_DIR/verify_queue" | tr -d ' ')
run_workers verify_worker "Phase 2: Verify" "$verify_total"

# Phase 3: Dedupe
verified_count=$(find "$OUTDIR" -name "*.verified.md" 2>/dev/null | wc -l | tr -d ' ')
if [[ "$verified_count" -gt 1 ]]; then
  echo "=== Phase 3: Deduplicating $verified_count verified reports ==="

  DEDUP_PROMPT="You are a security researcher consolidating vulnerability reports.

Below are all the verified vulnerability reports from this audit. Many were found via different starting files but describe the same underlying vulnerability.

Your job:
1. Group reports that describe the same root-cause vulnerability
2. For each unique vulnerability, keep the single best report (most detailed, clearest reproduction steps)
3. Write a summary to $OUTDIR/SUMMARY.md with:
   - A table of unique vulnerabilities (severity, category, affected file(s), one-line description)
   - For each unique vuln, which report file is the canonical one
   - List of duplicate report files that can be ignored
4. Write the list of duplicate file paths (one per line, nothing else) to $OUTDIR/duplicates.txt

Reports:
$(for f in "$OUTDIR"/*.verified.md; do
    echo "--- $(basename "$f") ---"
    cat "$f"
    echo ""
  done)
"

  claude -p "$DEDUP_PROMPT" \
    --model "$MODEL" --effort max --max-turns 10 \
    --dangerously-skip-permissions \
    >/dev/null 2>&1

  if [[ -f "$OUTDIR/duplicates.txt" ]]; then
    dupes=$(wc -l <"$OUTDIR/duplicates.txt" | tr -d ' ')
    echo "    Found $dupes duplicates. Unique findings in $OUTDIR/SUMMARY.md"
  else
    echo "    Dedup complete. See $OUTDIR/SUMMARY.md"
  fi
  echo ""
fi

# Phase 4: PoC generation (optional)
if $WRITE_POC; then
  find "$OUTDIR" -name "*.verified.md" 2>/dev/null \
    >"$STATUS_DIR/poc_queue"
  poc_total=$(wc -l <"$STATUS_DIR/poc_queue" | tr -d ' ')
  run_workers poc_worker "Phase 4: PoC" "$poc_total"
fi

# Summary
total=$(find "$OUTDIR" -name "*.vuln.md" 2>/dev/null | wc -l | tr -d ' ')
verified=$(find "$OUTDIR" -name "*.verified.md" 2>/dev/null | wc -l | tr -d ' ')
pocs=$(find "$OUTDIR" -name "*.poc" -type d 2>/dev/null | wc -l | tr -d ' ')
unique="?"
[[ -f "$OUTDIR/duplicates.txt" ]] && unique=$((verified - $(wc -l <"$OUTDIR/duplicates.txt" | tr -d ' ')))
echo "=== Done === Reports: $total | Verified: $verified | Unique: $unique | PoCs: $pocs | Output: $OUTDIR/"
