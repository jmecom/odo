"""Black-box checks for struct; no model calls or network services are used."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest


RUNNER = Path(__file__).resolve().parents[1] / "struct"
PASSES = (
    "01-default-exposure",
    "02-early-execution",
    "03-configuration-interactions",
)
SERVICE = '''import json
import sys

GUARDED = False
RESULT = "ok"

def sensitive():
    return {"reached": True, "trace": "service.sensitive entered", "result": RESULT}

denied = sys.argv[1] == "denied"
if denied and GUARDED:
    print(json.dumps({"reached": False, "trace": "gate rejected before sensitive", "result": "rejected"}))
    raise SystemExit(0)
print(json.dumps(sensitive()))
raise SystemExit(1 if denied else 0)
'''
SUITE = '''import json
import subprocess
import sys

response = subprocess.run([sys.executable, "service.py", "allowed"], capture_output=True, text=True, check=True)
observed = json.loads(response.stdout)
assert observed["reached"] is True and observed["result"] == "ok", observed
print("allowed request: ok")
'''

# This fake follows the real CLI's structured-output interface. It generates a
# genuine git patch and probes a subprocess in the runner's independent trees.
FAKE_AGENT = r'''
import json
import os
from pathlib import Path
import subprocess
import sys

configuration = json.loads(Path(os.environ["STRUCT_TEST_CONFIG"]).read_text())
is_codex = len(sys.argv) > 1 and sys.argv[1] == "exec"
name = os.environ["STRUCT_PASS"]
source = Path(os.environ["STRUCT_SOURCE"])
artifacts = Path(os.environ["STRUCT_ARTIFACTS"])
log = Path(os.environ["STRUCT_TEST_LOG"])
previous = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
attempt = 1 + sum(item["pass"] == name for item in previous)
record = {
    "pass": name,
    "runner": "codex" if is_codex else "claude",
    "pid": os.getpid(),
    "attempt": attempt,
    "argv": sys.argv[1:],
    "prompt": sys.stdin.read(),
    "source": str(source),
    "source_text": (source / "service.py").read_text(),
    "prior_agent_marker": (source / "agent_was_here").exists(),
}
with log.open("a") as handle:
    handle.write(json.dumps(record) + "\n")

if configuration.get("fail_once") == name and attempt == 1:
    print("simulated transient CLI failure", file=sys.stderr)
    raise SystemExit(7)
if configuration.get("timeout_once") == name and attempt == 1:
    import time
    time.sleep(30)

findings = []
for spec in configuration.get("findings", {}).get(name, []):
    identifier = spec.get("id", "exposure")
    mode = spec.get("mode", "nominal")
    folder = artifacts / identifier
    folder.mkdir()
    probe_text = ''' + repr('''import json
import os
from pathlib import Path
import subprocess
import sys

source = Path(os.environ["STRUCT_SOURCE"])
kind = sys.argv[1]
mode = MODE
state = source / ".positive_ran"
if mode == "contaminate" and kind == "negative" and state.exists():
    print(json.dumps({"reached": False, "trace": "prior positive case disabled the operation", "result": "rejected"}))
    raise SystemExit(0)
observed = subprocess.run([sys.executable, str(source / "service.py"), "denied" if kind == "negative" else "allowed"], capture_output=True, text=True)
if mode == "contaminate" and kind == "positive":
    state.write_text("state must not carry over to the negative check")
if mode == "no-marker":
    print("operation observed, but required marker deliberately omitted")
else:
    print(observed.stdout, end="")
if mode == "exit-two" and kind == "negative":
    raise SystemExit(2)
if mode == "positive-failure" and kind == "positive":
    raise SystemExit(2)
raise SystemExit(observed.returncode)
''') + r'''
    (folder / "probe.py").write_text(probe_text.replace("MODE", repr(mode)))
    trace = subprocess.run([sys.executable, str(source / "service.py"), "denied"], capture_output=True, text=True)
    (folder / "trace.json").write_text(trace.stdout)
    original = (source / "service.py").read_text()
    patched = original.replace("GUARDED = False", "GUARDED = True")
    if mode == "result-mismatch":
        patched = patched.replace('RESULT = "ok"', 'RESULT = "changed"')
    if mode == "bool-int":
        patched = patched.replace('RESULT = True', 'RESULT = 1')
    if mode == "contaminate":
        patched = original + "\n# Ineffective candidate: operation is still reachable.\n"
    (source / "service.py").write_text(patched)
    difference = subprocess.run(["git", "-C", str(source), "diff", "--", "service.py"], capture_output=True, text=True, check=True)
    (folder / "gate.patch").write_text(difference.stdout)
    (source / "service.py").write_text(original)
    evidence = [identifier + "/trace.json", identifier + "/probe.py"]
    if mode in ("escape-parent", "escape-symlink"):
        outside = artifacts.parent / "outside-evidence.txt"
        outside.write_text("not in the artifact directory")
        if mode == "escape-parent":
            evidence = ["../outside-evidence.txt"]
        else:
            (folder / "outside-link").symlink_to(outside)
            evidence = [identifier + "/outside-link"]
    findings.append({
        "id": identifier,
        "title": "Unnecessary operation before the gate",
        "entry_point": "service.py denied request",
        "sensitive_operation": "service.sensitive",
        "expected_gate": "GUARDED check before sensitive()",
        "configuration": "fixture shipped defaults",
        "rationale": "PRIVATE_DISCOVERY_DETAIL: denied requests do not need the operation",
        "recommendation": "Enable the request gate before entering sensitive()",
        "patch": identifier + "/gate.patch",
        "behavior_change": spec.get("behavior_change", "none"),
        "source_locations": ["service.py:7"],
        "evidence": evidence,
        "negative_argv": [sys.executable, "{artifacts}/" + identifier + "/probe.py", "negative"],
        "positive_argv": [sys.executable, "{artifacts}/" + identifier + "/probe.py", "positive"],
        "limitations": ["One instrumented fixture and configuration only"],
    })

(source / "agent_was_here").write_text(name)
result = {
    "inventory": ["service.py request entry"],
    "configurations": ["GUARDED=False by default"],
    "coverage": "Exercised the fixture request dispatcher",
    "unexamined": ["Other deployments"],
    "handoff": "handoff from " + name,
    "findings": findings,
}
if is_codex:
    output = Path(sys.argv[sys.argv.index("--output-last-message") + 1])
    mode = configuration.get("codex_protocol", "success")
    if mode != "missing-final":
        output.write_text("{broken" if mode == "malformed-final" else json.dumps({} if mode == "invalid-final" else result))
    print(json.dumps({"type": "thread.started", "thread_id": "fake-" + name}))
    if mode == "malformed-events":
        print("this line is not JSON")
    if mode == "non-object-event":
        print("[]")
    if mode == "untyped-event":
        print(json.dumps({"message": "missing event type"}))
    if mode == "error":
        print(json.dumps({"type": "error", "message": "simulated stream error"}))
    if mode == "turn-failed":
        print(json.dumps({"type": "turn.failed", "error": {"message": "simulated failed turn"}}))
    elif mode != "missing-completion":
        print(json.dumps({"type": "turn.completed", "usage": {"input_tokens": 1, "output_tokens": 1}}))
    raise SystemExit(0)
envelope = {"type": "result", "subtype": "success", "is_error": False, "structured_output": result}
if configuration.get("invalid_envelope") == name:
    envelope["subtype"] = "error_max_turns"
if configuration.get("denied_tools") == name:
    envelope["permission_denials"] = [{"tool_name": "Bash"}]
print(json.dumps(envelope))
'''


class StructBlackBoxTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="struct-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "target"
        self.repo.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "Struct test")
        self.git("config", "user.email", "struct-test@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.hooksPath", "/dev/null")
        (self.repo / "service.py").write_text(SERVICE)
        (self.repo / "project_tests.py").write_text(SUITE)
        (self.repo / "black_box.py").write_text(SUITE)
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "instrumented baseline")
        self.commit = self.git("rev-parse", "HEAD").stdout.strip()
        self.fake = self.root / "fake-claude"
        self.fake.write_text("#!" + sys.executable + "\n" + textwrap.dedent(FAKE_AGENT))
        self.fake.chmod(0o755)
        (self.root / "claude").symlink_to(self.fake)
        self.fake_codex = self.root / "codex"
        self.fake_codex.write_text(self.fake.read_text())
        self.fake_codex.chmod(0o755)
        self.configuration = self.root / "fake-config.json"
        self.log = self.root / "calls.jsonl"
        self.configuration.write_text("{}")
        self.env = {
            **os.environ,
            "STRUCT_TEST_CONFIG": str(self.configuration),
            "STRUCT_TEST_LOG": str(self.log),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PATH": str(self.root) + os.pathsep + os.environ.get("PATH", ""),
        }
        self.python = shlex.quote(sys.executable)
        self.out = self.root / "audit"

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.repo), *args], text=True, capture_output=True, check=True,
        )

    def invoke(self, *args):
        return subprocess.run(
            [sys.executable, str(RUNNER), *map(str, args)],
            env=self.env, capture_output=True, text=True, timeout=60,
        )

    def start(self, config=None, *, test_command=None, black_box_command=None, missing=None, extra=(), codex=False):
        self.configuration.write_text(json.dumps(config or {}))
        args = [self.repo, "--out", self.out, "--timeout", "10"]
        if not codex:
            args += ["--claude-bin", self.fake]
        args += ["--build-command", f"{self.python} -m py_compile service.py"]
        if missing != "tests":
            args += ["--test-command", test_command or f"{self.python} project_tests.py"]
        if missing != "black-box":
            args += ["--black-box-command", black_box_command or f"{self.python} black_box.py"]
        return self.invoke(*args, *extra)

    def assert_success(self, process):
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def manifest(self):
        return json.loads((self.out / "manifest.json").read_text())

    def outcome(self, name=PASSES[0], identifier="exposure"):
        path = self.out / "verification" / name / identifier / "result.json"
        return json.loads(path.read_text())

    def finding_config(self, **finding):
        return {"findings": {PASSES[0]: [finding]}}

    def test_codex_defaults_to_astra_and_replays_the_finding(self):
        self.assert_success(self.start(self.finding_config(), codex=True))
        self.assertEqual(self.manifest()["runner"], "codex")
        self.assertEqual(self.manifest()["model"], "gpt-6-astra")
        self.assertEqual(self.outcome()["status"], "verified")
        calls = self.calls()
        self.assertEqual([call["pass"] for call in calls], list(PASSES))
        for index, call in enumerate(calls):
            argv = call["argv"]
            self.assertEqual(call["runner"], "codex")
            self.assertEqual(argv[0], "exec")
            self.assertIn("--ephemeral", argv)
            self.assertIn("--json", argv)
            self.assertEqual(argv[argv.index("--model") + 1], "gpt-6-astra")
            self.assertEqual(argv[argv.index("--sandbox") + 1], "workspace-write")
            self.assertIn('approval_policy="never"', argv)
            self.assertNotIn("--max-turns", argv)
            directory = self.out / "passes" / call["pass"]
            self.assertEqual(Path(argv[argv.index("--add-dir") + 1]).resolve(), (directory / "artifacts").resolve())
            schema = json.loads(Path(argv[argv.index("--output-schema") + 1]).read_text())
            self.assertIn("findings", schema["required"])
            self.assertEqual(Path(argv[argv.index("--output-last-message") + 1]).resolve(), (directory / "codex.result.json").resolve())
            self.assertTrue((directory / "codex.stdout.log").is_file())
            self.assertFalse((directory / "claude.stdout.log").exists())
            self.assertFalse(call["prior_agent_marker"])
            if index:
                self.assertIn("handoff from " + PASSES[index - 1], call["prompt"])

    def test_codex_model_override_and_custom_binary(self):
        self.assert_success(self.start(codex=True, extra=("--model", "custom-codex-model", "--codex-bin", self.fake_codex)))
        self.assertEqual(self.manifest()["model"], "custom-codex-model")
        for call in self.calls():
            self.assertEqual(call["argv"][call["argv"].index("--model") + 1], "custom-codex-model")

    def test_explicit_claude_uses_cli_default_model_and_turn_limit(self):
        self.assert_success(self.invoke(self.repo, "--out", self.out, "--runner", "claude", "--max-turns", "4"))
        self.assertEqual(self.manifest()["runner"], "claude")
        for call in self.calls():
            self.assertEqual(call["runner"], "claude")
            self.assertNotIn("--model", call["argv"])
            self.assertEqual(call["argv"][call["argv"].index("--max-turns") + 1], "4")

    def test_conflicting_runners_and_codex_turn_limit_are_rejected(self):
        cases = (
            ("--runner", "codex", "--claude-bin", self.fake),
            ("--runner", "claude", "--codex-bin", self.fake_codex),
            ("--claude-bin", self.fake, "--codex-bin", self.fake_codex),
            ("--max-turns", "4"),
        )
        for index, args in enumerate(cases):
            with self.subTest(args=args):
                result = self.invoke(self.repo, "--out", self.root / ("conflict-" + str(index)), *args)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.calls())

    def test_codex_incomplete_failed_or_malformed_output_cannot_complete_pass(self):
        modes = ("error", "turn-failed", "missing-completion", "malformed-events",
                 "non-object-event", "untyped-event", "malformed-final", "invalid-final", "missing-final")
        for mode in modes:
            with self.subTest(mode=mode):
                self.out = self.root / ("codex-" + mode)
                result = self.start({"codex_protocol": mode}, codex=True)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.manifest()["status"], "failed")
                self.assertEqual(self.manifest()["passes"][PASSES[0]]["status"], "failed")
                self.assertFalse((self.out / "passes" / PASSES[0] / "result.json").exists())
                self.assertFalse((self.out / "verification").exists())

    def test_codex_resume_keeps_frozen_runner_and_default_model(self):
        self.assertNotEqual(self.start({"fail_once": PASSES[1]}, codex=True).returncode, 0)
        self.assertEqual(self.manifest()["runner"], "codex")
        self.assertEqual(self.manifest()["model"], "gpt-6-astra")
        rejected = self.invoke("--resume", self.out, "--model", "different-model")
        self.assertNotEqual(rejected.returncode, 0)
        self.assert_success(self.invoke("--resume", self.out))
        self.assertEqual([call["pass"] for call in self.calls()], [PASSES[0], PASSES[1], PASSES[1], PASSES[2]])
        for call in self.calls():
            self.assertEqual(call["runner"], "codex")
            self.assertEqual(call["argv"][call["argv"].index("--model") + 1], "gpt-6-astra")

    def test_old_manifest_without_runner_resumes_with_claude(self):
        self.assert_success(self.start(extra=("--dry-run",)))
        manifest = self.manifest()
        del manifest["runner"]
        (self.out / "manifest.json").write_text(json.dumps(manifest))
        self.assert_success(self.invoke("--resume", self.out))
        self.assertEqual(len(self.calls()), 3)
        for call in self.calls():
            self.assertEqual(call["runner"], "claude")
            self.assertNotIn("--model", call["argv"])

    def test_nominal_replay_fresh_sessions_short_handoff_and_unchanged_original(self):
        (self.repo / "service.py").write_text(SERVICE + "\nUNCOMMITTED = True\n")
        (self.repo / "untracked.txt").write_text("keep me")
        before = self.git("status", "--porcelain").stdout
        original = (self.repo / "service.py").read_text()
        result = self.start(self.finding_config())
        self.assert_success(result)
        self.assertEqual(self.git("status", "--porcelain").stdout, before)
        self.assertEqual((self.repo / "service.py").read_text(), original)
        self.assertEqual((self.repo / "untracked.txt").read_text(), "keep me")
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), self.commit)
        calls = self.calls()
        self.assertEqual([call["pass"] for call in calls], list(PASSES))
        self.assertEqual(len({call["source"] for call in calls}), 3)
        for index, call in enumerate(calls):
            self.assertIn("-p", call["argv"])
            self.assertIn("--no-session-persistence", call["argv"])
            self.assertNotIn("--model", call["argv"])
            self.assertNotIn("--resume", call["argv"])
            self.assertNotIn("--dangerously-skip-permissions", call["argv"])
            self.assertEqual(call["source_text"], SERVICE)
            self.assertFalse(call["prior_agent_marker"])
            self.assertNotIn("PRIVATE_DISCOVERY_DETAIL", call["prompt"])
            if index:
                self.assertIn("handoff from " + PASSES[index - 1], call["prompt"])
            if index == 2:
                self.assertNotIn("handoff from " + PASSES[0], call["prompt"])
        outcome = self.outcome()
        self.assertEqual(outcome["status"], "verified")
        self.assertIs(outcome["replay_passed"], True)
        for label, expected in (("baseline-negative", (1, True)), ("patched-negative", (0, False))):
            check = outcome["checks"][label]
            self.assertEqual((check["exit_code"], check["probe"]["reached"]), expected)
            self.assertTrue(Path(check["stdout"]).is_file())
        self.assertEqual(self.manifest()["status"], "completed")
        self.assertIn("not establish", (self.out / "SUMMARY.md").read_text())

    def test_dry_run_does_not_invoke_model_or_target_and_can_resume(self):
        marker = self.root / "should-not-exist"
        command = "touch " + shlex.quote(str(marker))
        result = self.start(test_command=command, black_box_command=command, extra=("--dry-run",))
        self.assert_success(result)
        self.assertFalse(self.log.exists())
        self.assertFalse(marker.exists())
        self.assertEqual(self.manifest()["status"], "planned")
        for name in PASSES:
            self.assertTrue((self.out / "passes" / name / "prompt.md").is_file())
            self.assertFalse((self.out / "passes" / name / "source").exists())
        self.assert_success(self.invoke("--resume", self.out))
        self.assertEqual(len(self.calls()), 3)
        self.assertEqual(self.manifest()["status"], "completed")

    def test_resume_retries_failed_pass_and_preserves_completed_pass(self):
        config = self.finding_config()
        config["fail_once"] = PASSES[1]
        first = self.start(config)
        self.assertNotEqual(first.returncode, 0)
        completed = self.out / "passes" / PASSES[0] / "result.json"
        original = completed.read_bytes()
        self.assertEqual(self.manifest()["passes"][PASSES[0]]["status"], "completed")
        self.assert_success(self.invoke("--resume", self.out))
        self.assertEqual(completed.read_bytes(), original)
        self.assertEqual([call["pass"] for call in self.calls()], [PASSES[0], PASSES[1], PASSES[1], PASSES[2]])
        self.assertEqual(len(list((self.out / "attempts").iterdir())), 1)
        self.assertEqual(self.manifest()["status"], "completed")
        self.assert_success(self.invoke("--resume", self.out))
        self.assertEqual(len(self.calls()), 4)

    def test_resuming_completed_run_in_dry_mode_does_not_downgrade_it(self):
        self.assert_success(self.start())
        before = self.manifest()
        self.assert_success(self.invoke("--resume", self.out, "--dry-run"))
        self.assertEqual(self.manifest(), before)
        self.assertEqual(len(self.calls()), 3)

    def test_dry_resume_of_failed_run_preserves_retry_state(self):
        self.assertNotEqual(self.start({"fail_once": PASSES[1]}).returncode, 0)
        before = self.manifest()
        self.assert_success(self.invoke("--resume", self.out, "--dry-run"))
        after = self.manifest()
        self.assertEqual(after["status"], before["status"])
        self.assertEqual(after["passes"][PASSES[0]], before["passes"][PASSES[0]])
        self.assertEqual(after["passes"][PASSES[1]], before["passes"][PASSES[1]])
        self.assertEqual(len(self.calls()), 2)
        self.assert_success(self.invoke("--resume", self.out))
        self.assertEqual(self.manifest()["status"], "completed")
        self.assertEqual([call["pass"] for call in self.calls()], [PASSES[0], PASSES[1], PASSES[1], PASSES[2]])

    def test_timed_out_model_can_resume_cleanly(self):
        result = self.start({"timeout_once": PASSES[0]}, extra=("--timeout", "1"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Timed out after 1s", result.stderr)
        self.assertEqual(self.manifest()["passes"][PASSES[0]]["status"], "failed")
        self.assertFalse((self.out / "passes" / PASSES[0] / "result.json").exists())
        self.assert_success(self.invoke("--resume", self.out))
        self.assertEqual([call["pass"] for call in self.calls()], [PASSES[0], PASSES[0], PASSES[1], PASSES[2]])
        self.assertEqual(self.manifest()["status"], "completed")
        self.assertEqual(len(list((self.out / "attempts").iterdir())), 1)

    def test_sigterm_cancels_model_and_records_interrupted_state(self):
        self.configuration.write_text(json.dumps({"timeout_once": PASSES[0]}))
        command = [sys.executable, str(RUNNER), str(self.repo), "--out", str(self.out),
                   "--claude-bin", str(self.fake), "--timeout", "60"]
        process = subprocess.Popen(command, env=self.env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, start_new_session=True)
        child_pid = None
        try:
            deadline = time.monotonic() + 10
            calls = []
            while process.poll() is None and time.monotonic() < deadline:
                try:
                    calls = self.calls()
                except json.JSONDecodeError:
                    pass  # The fake may still be writing its one log record.
                if calls:
                    break
                time.sleep(0.05)
            self.assertTrue(calls, "fake model did not start")
            child_pid = calls[0]["pid"]
            process.terminate()
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 130, stdout + stderr)
            self.assertEqual(self.manifest()["status"], "interrupted")
            self.assertEqual(self.manifest()["passes"][PASSES[0]]["status"], "interrupted")
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
            if child_pid is not None:
                try:
                    os.killpg(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_missing_suites_never_verify(self):
        for missing in ("tests", "black-box"):
            with self.subTest(missing=missing):
                self.out = self.root / ("audit-missing-" + missing)
                self.assert_success(self.start(self.finding_config(), missing=missing))
                outcome = self.outcome()
                self.assertEqual(outcome["status"], "reproduced")
                self.assertNotIn("replay_passed", outcome)

    def test_error_exit_or_missing_marker_does_not_confirm_reachability(self):
        for mode in ("exit-two", "no-marker"):
            with self.subTest(mode=mode):
                self.out = self.root / ("audit-" + mode)
                self.assert_success(self.start(self.finding_config(mode=mode)))
                self.assertEqual(self.outcome()["status"], "hypothesis")
                self.assertNotIn("replay_passed", self.outcome())

    def test_failed_positive_control_prevents_verification(self):
        self.assert_success(self.start(self.finding_config(mode="positive-failure")))
        outcome = self.outcome()
        self.assertEqual(outcome["status"], "reproduced")
        self.assertTrue(any("positive control failed" in item for item in outcome["limitations"]))

    def test_positive_observable_mismatch_prevents_verification(self):
        self.assert_success(self.start(self.finding_config(mode="result-mismatch"), test_command="true", black_box_command="true"))
        outcome = self.outcome()
        self.assertEqual(outcome["status"], "reproduced")
        self.assertTrue(any("Positive-control observable results differed" in item for item in outcome["limitations"]))

    def test_black_box_output_mismatch_prevents_verification(self):
        command = self.python + " -c " + shlex.quote("import os; print(os.getcwd())")
        self.assert_success(self.start(self.finding_config(), black_box_command=command))
        outcome = self.outcome()
        self.assertEqual(outcome["status"], "reproduced")
        self.assertTrue(any("Black-box stdout differed" in item for item in outcome["limitations"]))

    def test_positive_json_boolean_and_number_are_different_observations(self):
        (self.repo / "service.py").write_text(SERVICE.replace('RESULT = "ok"', 'RESULT = True'))
        self.git("add", "service.py")
        self.git("commit", "--quiet", "-m", "boolean baseline result")
        self.assert_success(self.start(self.finding_config(mode="bool-int"), test_command="true", black_box_command="true"))
        outcome = self.outcome()
        self.assertEqual(outcome["status"], "reproduced")
        self.assertTrue(any("Positive-control observable results differed" in item for item in outcome["limitations"]))

    def test_positive_probe_cannot_make_an_ineffective_patch_appear_to_gate(self):
        self.assert_success(self.start(self.finding_config(mode="contaminate")))
        outcome = self.outcome()
        self.assertEqual(outcome["status"], "reproduced")
        self.assertEqual(outcome["checks"]["patched-negative"]["exit_code"], 1)
        self.assertIs(outcome["checks"]["patched-negative"]["probe"]["reached"], True)
        self.assertTrue(any("Patched probe did not demonstrate rejection" in item for item in outcome["limitations"]))

    def test_nondefault_unknown_and_later_passes_remain_review_required(self):
        config = {"findings": {
            PASSES[0]: [{"id": "nondefault", "behavior_change": "nondefault"}, {"id": "unknown", "behavior_change": "unknown"}],
            PASSES[1]: [{"id": "early"}],
            PASSES[2]: [{"id": "interactions"}],
        }}
        self.assert_success(self.start(config))
        for name, identifiers in ((PASSES[0], ("nondefault", "unknown")), (PASSES[1], ("early",)), (PASSES[2], ("interactions",))):
            for identifier in identifiers:
                with self.subTest(name=name, identifier=identifier):
                    outcome = self.outcome(name, identifier)
                    self.assertEqual(outcome["status"], "review-required")
                    self.assertIs(outcome["replay_passed"], True)

    def test_artifact_traversal_and_escaping_symlink_are_rejected(self):
        for mode in ("escape-parent", "escape-symlink"):
            with self.subTest(mode=mode):
                self.out = self.root / ("audit-" + mode)
                result = self.start(self.finding_config(mode=mode))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("outside artifact directory", result.stderr)
                self.assertFalse((self.out / "verification").exists())
                self.assertNotEqual(self.manifest()["passes"][PASSES[0]]["status"], "completed")

    def test_non_success_cli_envelope_cannot_complete_a_pass(self):
        result = self.start({"invalid_envelope": PASSES[0]})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotEqual(self.manifest()["passes"][PASSES[0]]["status"], "completed")

    def test_denied_model_tools_cannot_complete_a_pass(self):
        result = self.start({"denied_tools": PASSES[0]})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(self.manifest()["passes"][PASSES[0]]["status"], "completed")

    def test_resume_rejects_changed_evidence_and_setting_overrides(self):
        self.assert_success(self.start(self.finding_config()))
        overridden = self.invoke("--resume", self.out, "--test-command", "true")
        self.assertNotEqual(overridden.returncode, 0)
        self.assertIn("saved settings", overridden.stderr)
        evidence = self.out / "passes" / PASSES[0] / "artifacts" / "exposure" / "trace.json"
        evidence.write_text("changed after completion")
        result = self.invoke("--resume", self.out)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Completed evidence changed", result.stderr)
        self.assertEqual(len(self.calls()), 3)


if __name__ == "__main__":
    unittest.main()
