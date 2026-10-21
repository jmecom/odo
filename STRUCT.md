# struct

`struct` runs a three-pass, AI-assisted attack-surface audit of a Git revision.
It is named for Chris Rohlf (`@struct`) and reconstructs the method described in
[Using Claude to reduce the attack surface of code](https://www.anthropic.com/research/attack-surface-reduction).
It is not Anthropic's unpublished skill or an exact reproduction of its tooling.

The orchestrator requires Python 3.10+, Git, and an installed, authenticated Claude
CLI on a Unix host; it has no third-party Python dependencies. Each pass gets a
fresh Claude session and a short handoff from the preceding pass. The model is
the CLI default unless `--model` is supplied.

## Run an audit

Start with a dry run to inspect the generated prompts and manifest:

```sh
./struct /path/to/project --dry-run
```

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
`<repo>-struct-<UTCtimestamp>-<suffix>`. The audit works from snapshots of the selected
committed revision; it does not edit the original working tree. Uncommitted work
is not part of that revision.

```sh
./struct --resume /path/to/project-struct-20261021T120000Z-abc123
```

Resume uses the saved settings and also starts an audit prepared with `--dry-run`.
Completed results and artifact fingerprints are checked before reuse; altered
evidence requires a new run. Incomplete attempts are archived under `attempts/`
before retry. A dry run pins the commit and creates prompts and manifests without
cloning source, invoking Claude, or executing target commands.

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

Strict black-box stdout comparison can reject compatible results with variable
timings or paths; supply stable, meaningful output without suppressing failures.
Passing these checks supports the exercised cases, not general behavioral
equivalence or absence of vulnerabilities. Review the traces and patches before
adopting a change; the tool does not merge or deploy them.

## Options

| Option | Meaning |
| --- | --- |
| `--ref REF` | Committed revision to audit; defaults to `HEAD`. |
| `--out RUN_DIR` | Choose a new output directory outside the target repository. |
| `--context FILE` | Supply requirements and deployment context. |
| `--build-command CMD` | Shell command for building each verification copy. |
| `--test-command CMD` | Project regression command. |
| `--black-box-command CMD` | Black-box compatibility regression command. |
| `--model NAME` | Override the Claude CLI's default model. |
| `--claude-bin PATH` | Claude executable; defaults to `claude`. |
| `--timeout SECONDS` | Timeout per audit/replay command; defaults to `1800`. |
| `--max-turns N` | Claude turn limit per pass; defaults to `100`. |
| `--dry-run` | Prepare an inspectable run without executing the audit. |
| `--resume RUN_DIR` | Continue an existing run with its saved settings. |

Claude runs noninteractively with `--safe-mode`, automatic permissions, and session
persistence disabled; no permission bypass flag is used. The installed CLI must
support these options. Source copies isolate repository changes, **not process
access**: Claude, build scripts, and replay commands execute on the host. Run an
untrusted target inside a disposable VM with only the access the audit requires.

## Artifacts

Start with `SUMMARY.md` and `manifest.json`. Each `passes/<pass>/` directory holds
`prompt.md`, `result.json`, logs, and supporting artifacts. `verification/` records
the independent replay results for individual findings. Keep these with the
revision and configuration context so another reviewer can reproduce the claims.

## Test the runner

```sh
python3 -m unittest discover -s tests -p 'test_struct.py' -v
```

These integration tests use temporary Git repositories and an instrumented target
with a fake Claude CLI. They exercise real patch application and subprocess replay
without making model calls or scanning an external project.
