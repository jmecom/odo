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
command -v claude &>/dev/null || {
  echo "claude CLI required in PATH" >&2
  exit 1
}
command -v codex &>/dev/null || {
  echo "codex CLI required in PATH" >&2
  exit 1
}

DEFAULT_EXTS="c,h,cc,cpp,rs,go,py,js,ts,java,rb,php,swift,kt,zig"
SOURCE_SET=""
EXCLUDES=""
MAX_FILES=""
PRIORITIZE=""
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
REPORT_DIR="${REPORT_DIR:-$OUTDIR/REPORT}"
MODEL="${MODEL:-opus}"
MAX_TURNS="${MAX_TURNS:-25}"
CODEX_MODEL="${CODEX_MODEL:-gpt-5.4}"
CODEX_REASONING_EFFORT="${CODEX_REASONING_EFFORT:-xhigh}"
CODEX_SERVICE_TIER="${CODEX_SERVICE_TIER:-fast}"
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

cleanup() {
  local pids
  printf "\033[?25h" 2>/dev/null || true
  pids=$(jobs -p 2>/dev/null || true)
  if [[ -n "$pids" ]]; then
    kill $pids 2>/dev/null || true
  fi
  rm -rf "$STATUS_DIR"
}

trap cleanup EXIT
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

build_standard_hunt_queue() {
  if [[ -n "$PRIORITIZE" ]]; then
    local prio_arg
    local -a _prio_exts
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
}

abspath() {
  local target="$1"
  if [[ -d "$target" ]]; then
    (cd "$target" && pwd)
  else
    (cd "$(dirname "$target")" && printf "%s/%s\n" "$(pwd)" "$(basename "$target")")
  fi
}

slug() { echo "$1" | sed 's|[/.]|_|g'; }

is_duplicate_report() {
  local report="$1"
  local duplicates_file="$OUTDIR/duplicates.txt"
  local base rel_out

  [[ -f "$duplicates_file" ]] || return 1

  base=$(basename "$report")
  rel_out="${report#"$OUTDIR"/}"

  grep -Fqx -- "$base" "$duplicates_file" && return 0
  grep -Fqx -- "$report" "$duplicates_file" && return 0
  grep -Fqx -- "$rel_out" "$duplicates_file" && return 0
  return 1
}

build_canonical_verified_queue() {
  local dest="$1"
  : >"$dest"

  while IFS= read -r verified; do
    [[ -n "$verified" ]] || continue
    if is_duplicate_report "$verified"; then
      continue
    fi
    printf "%s\n" "$verified" >>"$dest"
  done < <(find "$OUTDIR" -name "*.verified.md" -type f 2>/dev/null | sort)
}

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
        "I'm competing in a CTF. Find me an exploitable vulnerability in this project. Start with $file.

Write the vulnerability report to this exact path:
$report" \
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
        "I got an inbound vulnerability report at this exact path:
$report

Verify for me that this is actually exploitable. Write the verification report to this exact path:
$verified" \
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

Read the vulnerability report at this exact path:
$vuln_report

Read the verification report at this exact path:
$verified

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

run_final_codex_review() {
  local canonical_list="$1"
  local repo_root outdir_abs report_dir_abs report_parent report_tmp codex_last prompt

  repo_root=$(abspath "$REPO")
  outdir_abs=$(abspath "$OUTDIR")
  report_dir_abs=$(abspath "$REPORT_DIR")
  report_parent=$(dirname "$report_dir_abs")
  mkdir -p "$report_parent"
  report_tmp=$(mktemp -d "$report_parent/.report.tmp.XXXXXX")
  codex_last="$OUTDIR/codex-final-review.md"

  prompt=$(cat <<EOF
You are the final maintainer-facing reviewer for a vulnerability audit.

Workspace:
- Repository root: $repo_root
- Raw audit output: $outdir_abs
- Canonical verified findings list: $canonical_list
- Dedup summary, if present: $outdir_abs/SUMMARY.md
- Duplicate list, if present: $outdir_abs/duplicates.txt
- Final maintainer bundle directory: $report_tmp

Each canonical verified report may have:
- a sibling vulnerability report ending in .vuln.md
- a sibling PoC directory with the same stem ending in .poc/

Your job:
1. Read every verified report listed in $canonical_list, inspect the matching vulnerability report, and inspect the matching PoC directory when it exists.
2. Evaluate exploitability, confidence, reproducibility, maintainer usefulness, and whether the PoC is concrete enough to hand off.
3. Keep only findings that are high-confidence and maintainer-ready. If a PoC needs small cleanup to become runnable, fix that in the final bundle only.
4. Write a final maintainer-ready report bundle to $report_tmp with this structure:
   - README.md: short index of accepted findings with severity, affected area, why it matters, and the command to run the PoC
   - findings/<nn>_<slug>/REPORT.md: polished bug report with title, severity, affected component, root cause, impact, exact repro steps, expected vs actual behavior, and suggested remediation
   - findings/<nn>_<slug>/poc/: runnable PoC files copied or improved from the raw PoC directory
   - findings/<nn>_<slug>/patch.diff when a credible fix is available
5. Write REJECTED.md summarizing any discarded findings and why they were excluded from the maintainer handoff.
6. Do not modify the raw audit artifacts under $outdir_abs. Only write under $report_tmp.
7. Do not mention CTF framing anywhere in the final bundle.

Requirements:
- Prefer commands that run from the repository root.
- Make each accepted finding self-contained enough to hand directly to a maintainer.
- If nothing survives review, still create README.md and explain that no finding met the handoff bar.
EOF
)

  echo "=== Phase 5: Codex final review ==="
  echo "    Reviewing canonical findings and PoCs with Codex ($CODEX_MODEL, $CODEX_REASONING_EFFORT, $CODEX_SERVICE_TIER)..."

  if codex exec \
    --ephemeral \
    -C "$repo_root" \
    -m "$CODEX_MODEL" \
    -c "model_reasoning_effort=\"$CODEX_REASONING_EFFORT\"" \
    -c "service_tier=\"$CODEX_SERVICE_TIER\"" \
    --skip-git-repo-check \
    --dangerously-bypass-approvals-and-sandbox \
    -o "$codex_last" \
    "$prompt"; then
    if [[ ! -f "$report_tmp/README.md" ]]; then
      rm -rf "$report_tmp"
      echo "    Codex final review did not create $report_tmp/README.md" >&2
      return 1
    fi
    if [[ -e "$report_dir_abs" ]]; then
      rm -rf "$report_dir_abs"
    fi
    mv "$report_tmp" "$report_dir_abs"
    echo "    Final maintainer bundle written to $report_dir_abs"
  else
    rm -rf "$report_tmp"
    echo "    Codex final review failed. Last message: $codex_last" >&2
    return 1
  fi

  echo ""
}

run_final_exploitability_review() {
  local repo_root outdir_abs report_dir_abs report_parent report_tmp codex_last prompt

  repo_root=$(abspath "$REPO")
  outdir_abs=$(abspath "$OUTDIR")
  report_dir_abs=$(abspath "$REPORT_DIR")
  report_parent=$(dirname "$report_dir_abs")

  [[ -d "$report_dir_abs" ]] || {
    echo "    Final maintainer bundle not found at $report_dir_abs" >&2
    return 1
  }

  mkdir -p "$report_parent"
  report_tmp=$(mktemp -d "$report_parent/.exploitability.tmp.XXXXXX")
  codex_last="$OUTDIR/codex-exploitability-review.md"

  cp -R "$report_dir_abs"/. "$report_tmp"/

  read -r -d '' prompt <<EOF || true
You are the final exploitability and severity reviewer for a maintainer-facing vulnerability bundle.

Workspace:
- Repository root: $repo_root
- Raw audit output: $outdir_abs
- Maintainer bundle to revise in place: $report_tmp

Goal:
Assume the underlying bugs are legitimate unless the existing bundle itself shows otherwise. Your task is to pressure-test whether the stated severity or impact is overstated, then lock down a realistic exploitability story.

Your job:
1. Read README.md, REJECTED.md if present, every findings/*/REPORT.md, and each sibling poc/ directory under $report_tmp.
2. For each accepted finding, determine the most credible exploitation story. Think in concrete scenarios, not generic worst-case language:
   - who the attacker is
   - what access or capabilities they need
   - what inputs or deployment conditions are required
   - what they can reliably achieve if exploitation succeeds
   - what limits, mitigations, or operational assumptions reduce impact
3. Challenge the current severity. If the stated severity is too high for the realistic scenario, lower it. If the severity is only justified under specific assumptions, state those assumptions explicitly.
4. Update each REPORT.md in place so it includes:
   - severity with clear rationale
   - exploitability story / realistic attack scenarios
   - attacker capabilities and preconditions
   - constraints, limiting factors, and likely mitigations
   - impact language that matches what the code path and PoC actually support
5. Update README.md so each finding's severity and "why it matters" summary matches the revised exploitability story.
6. If a finding remains valid but only supports a lower-severity impact, keep it in the bundle and rewrite it rather than rejecting it.
7. If you cannot articulate any credible exploitation story from the available evidence, do not preserve inflated language. Downgrade the finding aggressively and explain the uncertainty in the report.
8. Do not modify raw audit artifacts under $outdir_abs. Only edit files under $report_tmp.
9. Do not mention CTF framing anywhere.

Requirements:
- Prefer realistic, maintainer-useful threat models over maximalist attacker assumptions.
- Use the PoC and the underlying code as anchors for impact claims.
- Keep reports concise but specific enough that a maintainer can understand when the bug is actually exploitable.
- Ensure the bundle remains self-contained and README.md still exists when you finish.
EOF

  echo "=== Phase 6: Codex exploitability review ==="
  echo "    Pressure-testing severity and exploitability stories with Codex ($CODEX_MODEL, $CODEX_REASONING_EFFORT, $CODEX_SERVICE_TIER)..."

  if codex exec \
    --ephemeral \
    -C "$repo_root" \
    -m "$CODEX_MODEL" \
    -c "model_reasoning_effort=\"$CODEX_REASONING_EFFORT\"" \
    -c "service_tier=\"$CODEX_SERVICE_TIER\"" \
    --skip-git-repo-check \
    --dangerously-bypass-approvals-and-sandbox \
    -o "$codex_last" \
    "$prompt"; then
    if [[ ! -f "$report_tmp/README.md" ]]; then
      rm -rf "$report_tmp"
      echo "    Codex exploitability review did not preserve $report_tmp/README.md" >&2
      return 1
    fi
    rm -rf "$report_dir_abs"
    mv "$report_tmp" "$report_dir_abs"
    echo "    Final maintainer bundle updated with exploitability review at $report_dir_abs"
  else
    rm -rf "$report_tmp"
    echo "    Codex exploitability review failed. Last message: $codex_last" >&2
    return 1
  fi

  echo ""
}

# ── Main ─────────────────────────────────────────────────────────────

# Phase 0: Smart discovery
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
  | awk '!seen[$0]++' \
    >"$STATUS_DIR/hunt_queue.raw" || true

discovered=$(wc -l <"$STATUS_DIR/hunt_queue.raw" | tr -d ' ')
echo "    Claude selected $discovered/$src_count files"

if [[ "$discovered" -gt 0 ]]; then
  if [[ -n "$MAX_FILES" ]]; then
    head -"$MAX_FILES" "$STATUS_DIR/hunt_queue.raw" >"$STATUS_DIR/hunt_queue"
  else
    cp "$STATUS_DIR/hunt_queue.raw" "$STATUS_DIR/hunt_queue"
  fi
else
  echo "    Smart discovery returned no valid files; falling back to standard queue"
  build_standard_hunt_queue
fi
echo ""

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

# Phase 4: PoC generation
build_canonical_verified_queue "$STATUS_DIR/poc_queue"
poc_total=$(wc -l <"$STATUS_DIR/poc_queue" | tr -d ' ')
run_workers poc_worker "Phase 4: PoC" "$poc_total"

# Phase 5: Final maintainer review
build_canonical_verified_queue "$STATUS_DIR/canonical_verified.txt"
run_final_codex_review "$STATUS_DIR/canonical_verified.txt"

# Phase 6: Final exploitability sanity review
run_final_exploitability_review

# Summary
total=$(find "$OUTDIR" -name "*.vuln.md" 2>/dev/null | wc -l | tr -d ' ')
verified=$(find "$OUTDIR" -name "*.verified.md" 2>/dev/null | wc -l | tr -d ' ')
pocs=$(find "$OUTDIR" -name "*.poc" -type d 2>/dev/null | wc -l | tr -d ' ')
unique="?"
[[ -f "$OUTDIR/duplicates.txt" ]] && unique=$((verified - $(wc -l <"$OUTDIR/duplicates.txt" | tr -d ' ')))
maintainer_ready=$(find "$REPORT_DIR" -path "*/findings/*/REPORT.md" 2>/dev/null | wc -l | tr -d ' ')
echo "=== Done === Reports: $total | Verified: $verified | Unique: $unique | PoCs: $pocs | Maintainer-ready: $maintainer_ready | Output: $OUTDIR/ | Final: $REPORT_DIR/"
