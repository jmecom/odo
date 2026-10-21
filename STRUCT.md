# struct

`struct` reduces attack surface through three AI-assisted passes, independent
verification, and delivery of modified source on a named Git branch. Eligible
changes are validated together and committed in a separate checkout, ready for
review. It is named for Chris Rohlf (`@struct`) and reconstructs the method in
[Using Claude to reduce the attack surface of code](https://www.anthropic.com/research/attack-surface-reduction).
It is not Anthropic's unpublished skill or an exact reproduction of its tooling.
Changes requiring a decision about supported non-default behavior remain explicit
human choices.

The orchestrator requires Python 3.10+, Git, and an authenticated agent CLI on a
Unix host; it has no third-party Python dependencies. It runs Codex with Astra
(`gpt-6-astra`) by default. Each pass gets a fresh agent session and a short handoff
from the preceding pass. `--model` overrides the model.

## Run the workflow

Start with a dry run to inspect the generated prompts and manifest:

```sh
./struct /path/to/project --dry-run
```

To use an installed Claude CLI instead, pass `--runner claude`; its default model
comes from the CLI unless `--model` is supplied. For compatibility, `--claude-bin`
also selects Claude when `--runner` is omitted.

Run against a committed revision, supplying the project's own verification commands:

```sh
./struct /path/to/project \
  --ref HEAD \
  --context /path/to/audit-context.md \
  --build-command 'make' \
  --test-command 'make test' \
  --black-box-command './tests/black-box.sh'
```

The context file should describe required features, supported configurations,
deployment boundaries, and compatibility requirements. Missing traffic or test
coverage does not establish that a feature is unnecessary. Identify the evidence
for intended behavior separately from observations of current behavior.

The default output directory is a sibling of the target repository named
`<repo>-struct-<UTCtimestamp>-<suffix>`. The workflow starts from the selected
committed revision and leaves the original working tree unchanged. Uncommitted
work is not part of that revision. After verification, eligible changes become a
commit in `RUN/deliveries/<unique>/source`; `RUN/delivery.json` records the branch,
commit, selection and validation results. Nothing is pushed by default.

```sh
./struct --resume /path/to/project-struct-20261021T120000Z-abc123
```

Resume uses the saved runner and settings, including for a prepared dry run.
Older runs without a recorded runner continue with Claude.
Completed results and artifact fingerprints are checked before reuse; altered
evidence requires a new run. Incomplete attempts are archived under `attempts/`
before retry. A finished audit can produce a delivery without new model sessions;
an already completed delivery with the same selection is reused. A dry run pins
the commit and creates prompts and manifests without cloning source, invoking a
model, executing target commands or committing changes.

## Three passes

1. **Default exposure.** Find implementations reachable under the shipped default
   configuration that required default functionality does not need. This pass may
   produce a minimal gate patch. Changes to non-default behavior require a human
   decision.
2. **Early reachability.** Examine sensitive work before authentication, required
   interaction, configuration checks, or protocol-state boundaries. Consider
   configurations beyond the defaults; proposed changes remain review-required.
3. **Configuration interactions.** Find accepted combinations that silently weaken
   a security control or leave effective behavior inconsistent with the settings.
   Proposed changes remain review-required.

Each pass produces an entry-point inventory and machine-readable findings. A
finding should identify the input, sensitive implementation, intended gate,
relevant configuration, and dynamic evidence. A static call path is a hypothesis,
not proof of runtime reachability. The report must state which configurations
and paths were examined; this is not an exhaustive configuration search.

## Deliver modified source

Delivery automatically selects fully replayed `verified` patches. To include a
fully replayed `review-required` patch, explicitly accept its pass-qualified ID:

```sh
./struct --resume /path/to/run \
  --accept-reviewed 02-early-execution/E02 \
  --branch struct/earlier-challenge-check
```

Repeat `--accept-reviewed PASS/ID` for each decision. Acceptance does not change
the finding's classification or waive verification: `hypothesis` and `reproduced`
findings remain ineligible. Without eligible changes, the tool records
`no-changes` and does not claim to have transformed source.

The runner assembles the selected patches against the pinned revision, deduplicates
byte-identical patches, and reruns full verification against the combined changes.
Probe and test copies are separate from the delivery checkout. Only production
changes are committed, after successful validation. Patch conflicts or combined
regression failures stop delivery while preserving the completed audit and its
evidence.

`--branch NAME` names the branch in the delivery checkout. Publish explicitly by
supplying a remote URL or filesystem path, for example
`--push git@github.com:OWNER/REPO.git`. No remote is inferred; a remote name such as
`origin` is not accepted. Publication follows validation and never uses force.
These delivery options can accompany `--resume`; they do not override saved audit
commands. The tool does not merge or deploy changes.

## Verification

The orchestrator replays verification independently of the agent's claims. Each
probe gets a fresh source copy and build; compatibility suites use separate copies.
Verification requires project tests, a black-box command, and finding evidence:

- The same negative probe exits `1` with `reached: true` on the baseline and `0`
  with `reached: false` after the patch. An unrelated baseline failure is not
  evidence of unwanted execution; setup or unexpected failures should exit `2`.
- The positive probe exits `0` with `reached: true` on both versions. Its observable
  `result` must match, demonstrating that the exercised allowed case is preserved.
- The build command, when supplied, and both regression suites succeed against
  both versions. Only the black-box command's stdout must match exactly.

Each probe's final stdout line must be JSON with `reached` (boolean), `trace`
(nonempty detail from actual instrumentation), and `result` (observable outcome).
The negative probe must observe the operation itself, not infer reachability from
an error response. The same probes and fixtures are used on both revisions.

The baseline probe still runs when verification commands are missing. Successful
reproduction remains `reproduced` until all verification requirements are met.
Passing replay checks yields `verified` only for default-exposure patches with
no reported behavior change; other passes and non-default or unknown behavior
changes remain `review-required`.

Delivery repeats these checks with the complete selected patch set, including each
finding's negative and positive probes. Passing individual patches alone is
insufficient to commit their combination.

Strict black-box stdout comparison can reject compatible results with variable
timings or paths; supply stable, meaningful output without suppressing failures.
Passing these checks supports the exercised cases, not general behavioral
equivalence or absence of vulnerabilities. Review the delivered commit and its
traces before adopting the change.

## Options

| Option | Meaning |
| --- | --- |
| `--ref REF` | Committed revision to audit; defaults to `HEAD`. |
| `--out RUN_DIR` | Choose a new output directory outside the target repository. |
| `--context FILE` | Supply requirements and deployment context. |
| `--build-command CMD` | Shell command for building each verification copy. |
| `--test-command CMD` | Project regression command. |
| `--black-box-command CMD` | Black-box compatibility regression command. |
| `--runner codex\|claude` | Agent CLI; defaults to `codex`. |
| `--model NAME` | Model override; Codex defaults to `gpt-6-astra`, Claude to its CLI default. |
| `--codex-bin PATH` | Codex executable; defaults to `codex`. |
| `--claude-bin PATH` | Claude executable; defaults to `claude`; implies Claude if no runner is set. |
| `--timeout SECONDS` | Timeout per audit/replay command; defaults to `1800`. |
| `--max-turns N` | Claude-only turn limit per pass; defaults to `100`; rejected for Codex. |
| `--dry-run` | Prepare an inspectable run without executing the audit. |
| `--resume RUN_DIR` | Continue a run or deliver changes from its completed audit. |
| `--accept-reviewed PASS/ID` | Include a fully replayed review-required finding; repeat for each accepted change. |
| `--branch NAME` | Name the branch containing the delivered source commit. |
| `--push URL_OR_PATH` | Explicitly publish to this destination after validation, without force; no remote is inferred. |

Codex runs noninteractively in an ephemeral session with a `workspace-write`
sandbox, the artifact directory additionally writable, and approval prompts
disabled. Its configured environment and rules otherwise apply. There is no
native Codex turn limit here; `--timeout` bounds each pass. Claude uses safe mode,
automatic permissions, and no session persistence. Neither runner uses a
permission bypass flag.

The orchestrator's build and replay commands execute directly on the host, outside
the agent's sandbox. Source copies do not isolate those processes. Run an untrusted
target inside a disposable VM with only the access the audit requires.

## Artifacts

Start with `delivery.json` for the source checkout, branch, commit and delivery
outcome; `deliveries/<unique>/` retains each delivery's source and validation
records. `SUMMARY.md` and `manifest.json` describe the audit. Each `passes/<pass>/`
directory holds `prompt.md`, `result.json`, logs and supporting artifacts.
`verification/` records independent replay for individual findings. Keep the
evidence with the revision and configuration context so another reviewer can
reproduce the claims.

## Test the runner

```sh
python3 -m unittest discover -s tests -p 'test_struct.py' -v
```

These integration tests use temporary Git repositories, an instrumented target,
and fake Codex and Claude CLIs. They exercise real patch application, subprocess
replay and Git delivery without making model calls or scanning an external project.
