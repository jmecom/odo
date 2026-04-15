#!/usr/bin/env python3
"""
Vulnerability hunting script based on Nicholas Carlini's workflow.

Usage:
  ./carlini.py [options] [repo_dir]
  ./carlini.py .
  ./carlini.py --codex-only .
  ./carlini.py --claude-only .
  ./carlini.py --claude-only --codex-smart-files .
  ./carlini.py --preserve-model-params .
  ./carlini.py --source-set "c,h,rs" .
  ./carlini.py --exclude "vendor/**,third-party/**" .
  JOBS=8 ./carlini.py .
"""

from __future__ import annotations

import argparse
import atexit
import fnmatch
import hashlib
import json
import os
import queue
import random
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import traceback
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Sequence


DEFAULT_EXTS = "c,h,cc,cpp,rs,go,py,js,ts,java,rb,php,swift,kt,zig"
LINES_PER_SLOT = 7
CLAUDE_FATAL_PAT = re.compile(
    r"Invalid API key|Fix external API key|Please log in|Please login|"
    r"not authenticated|authentication failed|unauthorized|401",
    re.IGNORECASE,
)
CLAUDE_RATE_LIMIT_PAT = re.compile(r"\b429\b|rate limit|too many requests", re.IGNORECASE)


@dataclass
class Config:
    repo: str
    codex_only: bool
    claude_only: bool
    codex_smart_files: bool
    preserve_model_params: bool
    jobs: int
    outdir: str
    report_dir: str
    model: str
    claude_effort: str
    max_turns: int
    codex_model: str
    codex_reasoning_effort: str
    codex_service_tier: str
    claude_rate_limit_max_retries: int
    claude_rate_limit_backoff_seconds: int
    claude_rate_limit_max_backoff_seconds: int
    exts: list[str]
    excludes: list[str]
    max_files: int | None
    prioritize: list[str]


@dataclass
class SlotStatus:
    state: str = "IDLE"
    file: str = ""
    logs: deque[str] = field(default_factory=lambda: deque(maxlen=5))


class CarliniRunner:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.cwd = Path.cwd()
        self.repo_root = self.abspath(cfg.repo)
        self.outdir_abs = self.abspath(cfg.outdir)
        self.report_dir_abs = self.abspath(cfg.report_dir)
        self.status_tmp = tempfile.TemporaryDirectory(prefix="carlini-status.")
        self.status_dir = Path(self.status_tmp.name)
        self.done_count = 0
        self.done_lock = threading.Lock()
        self.slots = [SlotStatus() for _ in range(cfg.jobs)]
        self.slot_lock = threading.Lock()
        self.display_enabled = sys.stdout.isatty()
        self._active_procs: set[subprocess.Popen[str]] = set()
        self._proc_lock = threading.Lock()
        self._display_hidden_cursor = False
        self._duplicates_cache: set[str] | None = None
        self.outdir_abs.mkdir(parents=True, exist_ok=True)

    def install_signal_handlers(self) -> None:
        def _handle_signal(signum: int, _frame: object) -> None:
            self.cleanup()
            raise SystemExit(1)

        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)
        atexit.register(self.cleanup)

    def cleanup(self) -> None:
        if self._display_hidden_cursor:
            sys.stdout.write("\033[?25h")
            sys.stdout.flush()
            self._display_hidden_cursor = False
        with self._proc_lock:
            procs = list(self._active_procs)
        for proc in procs:
            if proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
        try:
            self.status_tmp.cleanup()
        except Exception:
            pass

    def terminate_active_procs(self) -> None:
        with self._proc_lock:
            procs = list(self._active_procs)
        for proc in procs:
            if proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass

    def register_proc(self, proc: subprocess.Popen[str]) -> None:
        with self._proc_lock:
            self._active_procs.add(proc)

    def unregister_proc(self, proc: subprocess.Popen[str]) -> None:
        with self._proc_lock:
            self._active_procs.discard(proc)

    def abspath(self, target: str | Path) -> Path:
        p = Path(target).expanduser()
        if p.is_absolute():
            return p.resolve(strict=False)
        return (self.cwd / p).resolve(strict=False)

    def slug(self, value: str) -> str:
        return value.replace("/", "_").replace(".", "_")

    def require_cli_tools(self) -> None:
        if self.needs_codex() and shutil.which("codex") is None:
            raise SystemExit(
                "codex CLI required in PATH (or remove --codex-smart-files / pass --claude-only)"
            )
        if not self.cfg.codex_only and shutil.which("claude") is None:
            raise SystemExit("claude CLI required in PATH (or pass --codex-only)")

    def needs_codex(self) -> bool:
        return (not self.cfg.claude_only) or self.cfg.codex_smart_files

    def claude_output_has_fatal_error(self, path: Path) -> bool:
        if not path.exists():
            return False
        try:
            return bool(CLAUDE_FATAL_PAT.search(path.read_text(errors="replace")))
        except OSError:
            return False

    def first_nonempty_line(self, path: Path) -> str:
        if not path.exists():
            return ""
        try:
            for line in path.read_text(errors="replace").splitlines():
                if line.strip():
                    return line.strip()
        except OSError:
            return ""
        return ""

    def claude_output_has_rate_limit_error(self, path: Path) -> bool:
        if not path.exists():
            return False
        try:
            return bool(CLAUDE_RATE_LIMIT_PAT.search(path.read_text(errors="replace")))
        except OSError:
            return False

    def claude_retry_sleep_seconds(self, attempt: int) -> int:
        base = max(1, self.cfg.claude_rate_limit_backoff_seconds)
        cap = max(base, self.cfg.claude_rate_limit_max_backoff_seconds)
        return min(base * (2 ** max(0, attempt - 1)), cap)

    def finalize_captured_output(
        self, temp_path: Path, dest_path: Path | None, stream
    ) -> None:
        try:
            data = temp_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            data = ""
        if dest_path is None:
            if data:
                print(data, end="", file=stream)
                stream.flush()
            return
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_text(data, encoding="utf-8")

    def new_temp_capture_path(self, suffix: str) -> Path:
        fd, name = tempfile.mkstemp(prefix="carlini-claude.", suffix=suffix)
        os.close(fd)
        return Path(name)

    def preflight_claude_cli(self) -> None:
        if self.cfg.codex_only:
            return
        out = self.outdir_abs / "claude-healthcheck.out"
        err = self.outdir_abs / "claude-healthcheck.stderr"
        for path in (out, err):
            if path.exists():
                path.unlink()
        rc = self.run_claude_exec_with_turn_limit(
            "Reply with exactly OK.",
            1,
            stdout_path=out,
            stderr_path=err,
        )
        if rc != 0:
            detail = self.first_nonempty_line(err) or self.first_nonempty_line(out)
            if detail:
                raise SystemExit(f"Claude CLI health check failed: {detail}")
            raise SystemExit(f"Claude CLI health check failed. See {out} and {err}")
        if self.claude_output_has_fatal_error(out) or self.claude_output_has_fatal_error(err):
            detail = self.first_nonempty_line(out) or self.first_nonempty_line(err)
            if detail:
                raise SystemExit(
                    f"Claude CLI returned an authentication/configuration error: {detail}"
                )
            raise SystemExit(
                f"Claude CLI returned an authentication/configuration error. See {out} and {err}"
            )
        for path in (out, err):
            if path.exists():
                path.unlink()

    def describe_claude_model_params(self) -> str:
        if self.cfg.preserve_model_params:
            return "CLI defaults"
        return f"model={self.cfg.model}, effort={self.cfg.claude_effort}, max-turns={self.cfg.max_turns}"

    def describe_codex_model_params(self) -> str:
        if self.cfg.preserve_model_params:
            return "CLI defaults"
        return (
            f"model={self.cfg.codex_model}, reasoning={self.cfg.codex_reasoning_effort}, "
            f"service-tier={self.cfg.codex_service_tier}"
        )

    def build_codex_cmd(self, prompt: str, extra_args: Sequence[str]) -> list[str]:
        cmd = ["codex", "exec", "--ephemeral", "-C", str(self.repo_root)]
        if not self.cfg.preserve_model_params:
            cmd += ["-m", self.cfg.codex_model]
            cmd += ["-c", f'model_reasoning_effort="{self.cfg.codex_reasoning_effort}"']
            cmd += ["-c", f'service_tier="{self.cfg.codex_service_tier}"']
        cmd += ["--skip-git-repo-check", "--dangerously-bypass-approvals-and-sandbox"]
        cmd += list(extra_args)
        cmd.append(prompt)
        return cmd

    def build_claude_cmd(self, turn_limit: int, extra_args: Sequence[str]) -> list[str]:
        cmd = ["claude", "-p", "--input-format", "text"]
        if not self.cfg.preserve_model_params:
            cmd += ["--model", self.cfg.model]
            cmd += ["--effort", self.cfg.claude_effort]
            cmd += ["--max-turns", str(turn_limit)]
        cmd += ["--dangerously-skip-permissions"]
        cmd += list(extra_args)
        return cmd

    def run_cmd(
        self,
        cmd: Sequence[str],
        *,
        stdout_path: Path | None = None,
        stderr_path: Path | None = None,
    ) -> int:
        stdout_fh = None
        stderr_fh = None
        try:
            stdout_fh = open(stdout_path, "w", encoding="utf-8") if stdout_path else None
            stderr_fh = open(stderr_path, "w", encoding="utf-8") if stderr_path else None
            proc = subprocess.run(
                list(cmd),
                text=True,
                cwd=str(self.repo_root),
                stdout=stdout_fh if stdout_fh else None,
                stderr=stderr_fh if stderr_fh else None,
                check=False,
            )
            return proc.returncode
        finally:
            if stdout_fh:
                stdout_fh.close()
            if stderr_fh:
                stderr_fh.close()

    def run_codex_exec(
        self,
        prompt: str,
        *extra_args: str,
        stdout_path: Path | None = None,
        stderr_path: Path | None = None,
    ) -> int:
        return self.run_cmd(
            self.build_codex_cmd(prompt, extra_args),
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )

    def run_claude_exec_with_turn_limit(
        self,
        prompt: str,
        turn_limit: int,
        *extra_args: str,
        stdout_path: Path | None = None,
        stderr_path: Path | None = None,
    ) -> int:
        cmd = self.build_claude_cmd(turn_limit, extra_args)
        attempt = 1

        while True:
            stdout_capture = self.new_temp_capture_path(".stdout")
            stderr_capture = self.new_temp_capture_path(".stderr")
            try:
                with stdout_capture.open("w", encoding="utf-8") as stdout_fh, stderr_capture.open(
                    "w", encoding="utf-8"
                ) as stderr_fh:
                    proc = subprocess.run(
                        cmd,
                        input=prompt,
                        text=True,
                        cwd=str(self.repo_root),
                        stdout=stdout_fh,
                        stderr=stderr_fh,
                        check=False,
                    )
                rc = proc.returncode
                rate_limited = self.claude_output_has_rate_limit_error(
                    stdout_capture
                ) or self.claude_output_has_rate_limit_error(stderr_capture)
                if rc != 0 and rate_limited and attempt < self.cfg.claude_rate_limit_max_retries:
                    sleep_s = self.claude_retry_sleep_seconds(attempt)
                    detail = self.first_nonempty_line(stderr_capture) or self.first_nonempty_line(
                        stdout_capture
                    )
                    if detail:
                        print(
                            f"Claude rate limited; retrying in {sleep_s}s "
                            f"(attempt {attempt + 1}/{self.cfg.claude_rate_limit_max_retries}): "
                            f"{detail}",
                            file=sys.stderr,
                        )
                    else:
                        print(
                            f"Claude rate limited; retrying in {sleep_s}s "
                            f"(attempt {attempt + 1}/{self.cfg.claude_rate_limit_max_retries})",
                            file=sys.stderr,
                        )
                    time.sleep(sleep_s)
                    attempt += 1
                    continue

                self.finalize_captured_output(stdout_capture, stdout_path, sys.stdout)
                self.finalize_captured_output(stderr_capture, stderr_path, sys.stderr)
                return rc
            finally:
                stdout_capture.unlink(missing_ok=True)
                stderr_capture.unlink(missing_ok=True)

    def run_claude_exec(
        self,
        prompt: str,
        *extra_args: str,
        stdout_path: Path | None = None,
        stderr_path: Path | None = None,
    ) -> int:
        return self.run_claude_exec_with_turn_limit(
            prompt,
            self.cfg.max_turns,
            *extra_args,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )

    def append_slot_log(self, slot: int, line: str) -> None:
        sanitized = re.sub(r"[\r\n\t]+", " ", line).rstrip()
        with self.slot_lock:
            self.slots[slot].logs.append(sanitized)

    def set_slot(self, slot: int, *, state: str | None = None, file: str | None = None) -> None:
        with self.slot_lock:
            if state is not None:
                self.slots[slot].state = state
            if file is not None:
                self.slots[slot].file = file
            if state in {"DONE", "FAIL", "IDLE"}:
                self.slots[slot].logs.clear()

    def _extract_claude_tool_lines(self, obj: dict) -> Iterator[str]:
        if obj.get("type") != "assistant":
            return
        message = obj.get("message") or {}
        for item in message.get("content", []):
            if item.get("type") != "tool_use":
                continue
            tool = item.get("name", "")
            detail = ""
            input_obj = item.get("input") or {}
            if tool in {"Read", "Write", "Edit"}:
                detail = Path(input_obj.get("file_path", "")).name
            elif tool == "Grep":
                detail = str(input_obj.get("pattern", ""))[:30]
            elif tool == "Glob":
                detail = str(input_obj.get("pattern", ""))
            elif tool == "Bash":
                detail = str(input_obj.get("command", ""))[:40]
            yield f"{tool}  {detail}".rstrip()

    def _extract_codex_tool_lines(self, obj: dict) -> Iterator[str]:
        if obj.get("type") == "item.started":
            item = obj.get("item") or {}
            if item.get("type") == "command_execution":
                command = str(item.get("command", ""))[:40]
                yield f"Bash  {command}".rstrip()
        elif obj.get("type") == "item.completed":
            item = obj.get("item") or {}
            if item.get("type") == "agent_message":
                text = re.sub(r"[\r\n\t]+", " ", str(item.get("text", "")))[:60]
                yield f"Codex  {text}".rstrip()

    def run_claude_slot_prompt(self, prompt: str, slot: int) -> None:
        cmd = self.build_claude_cmd(
            self.cfg.max_turns,
            ["--output-format", "stream-json", "--verbose"],
        )
        attempt = 1

        while True:
            stdout_capture = self.new_temp_capture_path(".slot.stdout")
            stderr_capture = self.new_temp_capture_path(".slot.stderr")
            proc: subprocess.Popen[str] | None = None
            try:
                with stdout_capture.open("w", encoding="utf-8") as stdout_fh, stderr_capture.open(
                    "w", encoding="utf-8"
                ) as stderr_fh:
                    proc = subprocess.Popen(
                        cmd,
                        text=True,
                        cwd=str(self.repo_root),
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=stderr_fh,
                    )
                    self.register_proc(proc)
                    try:
                        if proc.stdin is not None:
                            try:
                                proc.stdin.write(prompt)
                            except BrokenPipeError:
                                pass
                            finally:
                                proc.stdin.close()
                        assert proc.stdout is not None
                        for raw in proc.stdout:
                            stdout_fh.write(raw)
                            raw = raw.strip()
                            if not raw:
                                continue
                            try:
                                obj = json.loads(raw)
                            except json.JSONDecodeError:
                                continue
                            for line in self._extract_claude_tool_lines(obj):
                                self.append_slot_log(slot, line)
                        rc = proc.wait()
                    finally:
                        self.unregister_proc(proc)

                rate_limited = self.claude_output_has_rate_limit_error(
                    stdout_capture
                ) or self.claude_output_has_rate_limit_error(stderr_capture)
                if rc != 0 and rate_limited and attempt < self.cfg.claude_rate_limit_max_retries:
                    sleep_s = self.claude_retry_sleep_seconds(attempt)
                    self.append_slot_log(slot, f"Claude  rate limited, retrying in {sleep_s}s")
                    time.sleep(sleep_s)
                    attempt += 1
                    continue
                return
            finally:
                if proc is not None:
                    self.unregister_proc(proc)
                stdout_capture.unlink(missing_ok=True)
                stderr_capture.unlink(missing_ok=True)

    def run_codex_slot_prompt(self, prompt: str, slot: int) -> None:
        cmd = self.build_codex_cmd(prompt, ["--json"])
        proc = subprocess.Popen(
            cmd,
            text=True,
            cwd=str(self.repo_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self.register_proc(proc)
        try:
            assert proc.stdout is not None
            for raw in proc.stdout:
                raw = raw.strip()
                if not raw or not raw.startswith("{"):
                    continue
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                for line in self._extract_codex_tool_lines(obj):
                    self.append_slot_log(slot, line)
            proc.wait()
        finally:
            self.unregister_proc(proc)

    def run_slot_prompt(self, prompt: str, slot: int) -> None:
        if self.cfg.codex_only:
            self.run_codex_slot_prompt(prompt, slot)
        else:
            self.run_claude_slot_prompt(prompt, slot)

    def path_matches_user_exclude(self, rel_path: str) -> bool:
        posix = Path(rel_path).as_posix()
        for pat in self.cfg.excludes:
            if fnmatch.fnmatch(posix, pat) or fnmatch.fnmatch(posix, f"*/{pat}"):
                return True
        return False

    def is_within(self, path: Path, root: Path) -> bool:
        try:
            path.resolve(strict=False).relative_to(root.resolve(strict=False))
            return True
        except ValueError:
            return False

    def find_sources(self) -> list[str]:
        repo_path = Path(self.cfg.repo)
        results: list[str] = []
        exts = {ext for ext in self.cfg.exts if ext}
        for root, dirs, files in os.walk(repo_path):
            root_path = Path(root)
            root_abs = self.abspath(root_path)
            if self.is_within(root_abs, self.outdir_abs):
                dirs[:] = []
                continue
            root_parts = set(root_path.parts)
            dirs[:] = [
                d
                for d in dirs
                if d not in {".git", "node_modules", "build", ".vuln-reports"}
                and not self.is_within(self.abspath(root_path / d), self.outdir_abs)
            ]
            if root_parts & {".git", "node_modules", "build", ".vuln-reports"}:
                continue
            for name in files:
                if "." not in name:
                    continue
                ext = name.rsplit(".", 1)[1]
                if ext not in exts:
                    continue
                path = os.path.join(root, name)
                if self.is_within(self.abspath(path), self.outdir_abs):
                    continue
                if self.path_matches_user_exclude(path):
                    continue
                results.append(path)
        return results

    def write_lines(self, path: Path, lines: Iterable[str]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            for line in lines:
                fh.write(f"{line}\n")

    def read_lines(self, path: Path) -> list[str]:
        if not path.exists():
            return []
        return [line.rstrip("\n") for line in path.read_text(encoding="utf-8", errors="replace").splitlines()]

    def build_standard_hunt_queue(self, sources: Sequence[str]) -> list[str]:
        items = list(sources)
        if self.cfg.prioritize:
            ranks = {ext: idx + 1 for idx, ext in enumerate(self.cfg.prioritize)}
            items.sort(key=lambda p: (ranks.get(Path(p).suffix.lstrip("."), 999), random.random()))
        else:
            random.shuffle(items)
        if self.cfg.max_files is not None:
            items = items[: self.cfg.max_files]
        self.write_lines(self.status_dir / "hunt_queue", items)
        return items

    def sanitize_discovery_output(self, src: Path, dest: Path) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for raw in self.read_lines(src):
            line = raw.rstrip("\r").strip()
            if not line:
                continue
            if line.startswith("```"):
                continue
            line = re.sub(r"^- ", "", line)
            line = re.sub(r"^[0-9]+[.)] ", "", line)
            if Path(line).is_file() and line not in seen:
                seen.add(line)
                out.append(line)
        self.write_lines(dest, out)
        return out

    def build_all_sources(self) -> tuple[list[str], Path]:
        sources = self.find_sources()
        out = self.outdir_abs / "all_sources.txt"
        self.write_lines(out, sources)
        return sources, out

    def run_smart_discovery(self, src_count: int) -> list[str]:
        provider_label = "Codex" if (self.cfg.codex_only or self.cfg.codex_smart_files) else "Claude"
        print("=== Phase 0: Smart file discovery ===")
        print(f"    Asking {provider_label} to identify high-value attack surface files...")
        hunt_queue_raw = self.status_dir / "hunt_queue.raw"
        self.write_lines(hunt_queue_raw, [])

        source_list = self.outdir_abs / "all_sources.txt"
        raw_candidates = self.outdir_abs / "hunt_queue.discovery.raw"
        if raw_candidates.exists():
            raw_candidates.unlink()

        prompt = textwrap.dedent(
            f"""\
            You are a security researcher doing a vulnerability audit of this codebase.

            Workspace:
            - Repository root: {self.repo_root}
            - Complete source file list ({src_count} files): {source_list}
            - Output file: {raw_candidates}

            Read the file list and identify the files most likely to contain exploitable vulnerabilities. Prioritize:
            - Files handling parsing, deserialization, or untrusted input
            - Crypto implementations and key management
            - Memory management, buffer operations, pointer arithmetic
            - Authentication, authorization, session handling
            - Network protocol handling, IPC, command dispatch
            - Files with "unsafe", raw pointer usage, or FFI boundaries

            Write ONLY a newline-separated list of file paths, most promising first, to {raw_candidates}.
            If you cannot write the file for any reason, output ONLY the newline-separated file paths on stdout with no commentary, markdown, or numbering.
            """
        ).strip()

        discovery_last = None
        discovery_stderr = None
        if self.cfg.codex_only or self.cfg.codex_smart_files:
            discovery_last = self.outdir_abs / "codex-discovery.md"
            rc = self.run_codex_exec(prompt, "-o", str(discovery_last), stdout_path=Path(os.devnull), stderr_path=Path(os.devnull))
            if rc == 0 and raw_candidates.exists():
                discovered = self.sanitize_discovery_output(raw_candidates, hunt_queue_raw)
            else:
                discovered = []
        else:
            discovery_last = self.outdir_abs / "claude-discovery.md"
            discovery_stderr = self.outdir_abs / "claude-discovery.stderr"
            rc = self.run_claude_exec_with_turn_limit(
                prompt,
                10,
                stdout_path=discovery_last,
                stderr_path=discovery_stderr,
            )
            if rc == 0:
                if raw_candidates.exists():
                    discovered = self.sanitize_discovery_output(raw_candidates, hunt_queue_raw)
                else:
                    discovered = self.sanitize_discovery_output(discovery_last, hunt_queue_raw)
            else:
                discovered = []

        print(f"    {provider_label} selected {len(discovered)}/{src_count} files")
        if discovered:
            if self.cfg.max_files is not None:
                discovered = discovered[: self.cfg.max_files]
            self.write_lines(self.status_dir / "hunt_queue", discovered)
            print("")
            return discovered

        print("    Smart discovery returned no valid files; falling back to standard queue")
        if discovery_last and discovery_last.exists():
            print(f"    Last discovery output saved to {discovery_last}")
        if discovery_stderr and discovery_stderr.exists() and discovery_stderr.stat().st_size > 0:
            print(f"    Discovery stderr saved to {discovery_stderr}")
        print("")
        return self.build_standard_hunt_queue(self.read_lines(source_list))

    def _get_duplicates_set(self) -> set[str]:
        if self._duplicates_cache is None:
            duplicates_file = Path(self.cfg.outdir) / "duplicates.txt"
            if duplicates_file.exists():
                self._duplicates_cache = set(self.read_lines(duplicates_file))
            else:
                self._duplicates_cache = set()
        return self._duplicates_cache

    def is_duplicate_report(self, report: Path) -> bool:
        lines = self._get_duplicates_set()
        if not lines:
            return False
        base = report.name
        rel_out = str(report).removeprefix(f"{self.cfg.outdir}/")
        return base in lines or str(report) in lines or rel_out in lines

    def build_canonical_verified_queue(self, dest: Path) -> list[str]:
        verified_reports = sorted(Path(self.cfg.outdir).rglob("*.verified.md"))
        lines = [str(p) for p in verified_reports if not self.is_duplicate_report(p)]
        self.write_lines(dest, lines)
        return lines

    def fingerprint_update(self, hasher: hashlib._Hash, label: str, data: bytes) -> None:
        hasher.update(label.encode("utf-8", errors="replace"))
        hasher.update(b"\0")
        hasher.update(str(len(data)).encode("ascii"))
        hasher.update(b"\0")
        hasher.update(data)
        hasher.update(b"\0")

    def fingerprint_file(self, hasher: hashlib._Hash, label: str, path: Path) -> None:
        if not path.is_file():
            self.fingerprint_update(hasher, f"missing:{label}", b"")
            return
        self.fingerprint_update(hasher, f"path:{label}", path.read_bytes())

    def fingerprint_tree(self, hasher: hashlib._Hash, label: str, root: Path) -> None:
        if not root.is_dir():
            self.fingerprint_update(hasher, f"missing-dir:{label}", b"")
            return
        self.fingerprint_update(hasher, f"dir:{label}", b"")
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            rel = path.relative_to(root).as_posix()
            self.fingerprint_update(
                hasher,
                f"{label}/{rel}",
                path.read_bytes(),
            )

    def compute_final_review_inputs_fingerprint(self, canonical_list: Path) -> str:
        hasher = hashlib.sha256()
        canonical_list_abs = self.abspath(canonical_list)
        self.fingerprint_file(hasher, "canonical_verified.txt", canonical_list_abs)
        self.fingerprint_file(hasher, "SUMMARY.md", self.outdir_abs / "SUMMARY.md")
        self.fingerprint_file(hasher, "duplicates.txt", self.outdir_abs / "duplicates.txt")

        for verified_str in self.read_lines(canonical_list_abs):
            verified = self.abspath(verified_str)
            self.fingerprint_file(hasher, verified.as_posix(), verified)
            vuln = Path(str(verified).replace(".verified.md", ".vuln.md"))
            self.fingerprint_file(hasher, vuln.as_posix(), vuln)
            poc_dir = Path(str(verified).replace(".verified.md", ".poc"))
            self.fingerprint_tree(
                hasher,
                poc_dir.as_posix(),
                poc_dir,
            )
        return hasher.hexdigest()

    def compute_report_dir_fingerprint(self, report_dir: Path) -> str:
        hasher = hashlib.sha256()
        ignored = {
            ".final-review-inputs.cksum",
            ".exploitability-review-complete",
            ".exploitability-review-inputs.cksum",
        }
        if not report_dir.is_dir():
            self.fingerprint_update(hasher, "missing-report-dir", b"")
            return hasher.hexdigest()

        for path in sorted(p for p in report_dir.rglob("*") if p.is_file()):
            rel = path.relative_to(report_dir).as_posix()
            if rel in ignored:
                continue
            self.fingerprint_update(hasher, rel, path.read_bytes())
        return hasher.hexdigest()

    def redraw(self, header: str, total: int) -> None:
        if not self.display_enabled:
            return
        dh = self.cfg.jobs * LINES_PER_SLOT + 1
        sys.stdout.write(f"\033[{dh}A")
        with self.done_lock:
            done_n = self.done_count
        sys.stdout.write(f"\033[1m=== {header} [{done_n}/{total}] ===\033[K\033[0m\n")
        with self.slot_lock:
            snapshot = [
                (slot.state, slot.file, list(slot.logs))
                for slot in self.slots
            ]
        for state, file_name, logs in snapshot:
            if state == "ACTIVE":
                sys.stdout.write(f"\033[1;34m>>> \033[0m\033[1m{file_name}\033[K\033[0m\n")
            elif state == "DONE":
                sys.stdout.write(f"\033[32m>>> {file_name}  done\033[K\033[0m\n")
            elif state == "FAIL":
                sys.stdout.write(f"\033[31m>>> {file_name}  FAILED\033[K\033[0m\n")
            else:
                sys.stdout.write("\033[90m>>> (idle)\033[K\033[0m\n")
            count = 0
            for line in logs[-5:]:
                sys.stdout.write(f"\033[90m    {line[:72]}\033[K\033[0m\n")
                count += 1
            for _ in range(count, 5):
                sys.stdout.write("\033[K\n")
            sys.stdout.write("\033[K\n")
        sys.stdout.flush()

    def bump_done(self) -> None:
        with self.done_lock:
            self.done_count += 1

    def run_workers(self, worker_fn, header: str, items: list[str]) -> None:
        total = len(items)
        if total == 0:
            print(f"No files for {header}.")
            return

        with self.done_lock:
            self.done_count = 0
        with self.slot_lock:
            self.slots = [SlotStatus() for _ in range(self.cfg.jobs)]

        if self.display_enabled:
            dh = self.cfg.jobs * LINES_PER_SLOT + 1
            sys.stdout.write("\n" * dh)
            sys.stdout.write("\033[?25l")
            sys.stdout.flush()
            self._display_hidden_cursor = True

        work_queue: queue.Queue[str] = queue.Queue()
        for item in items:
            work_queue.put(item)
        stop_event = threading.Event()
        error_lock = threading.Lock()
        first_error: list[str] = []

        def worker_wrapper(slot: int) -> None:
            try:
                worker_fn(slot, work_queue, stop_event)
            except BaseException as exc:
                with error_lock:
                    if not first_error:
                        first_error.append("".join(traceback.format_exception(exc)))
                stop_event.set()
                self.terminate_active_procs()
                self.set_slot(slot, state="FAIL")

        threads = [
            threading.Thread(target=worker_wrapper, args=(slot,), daemon=True)
            for slot in range(self.cfg.jobs)
        ]
        for thread in threads:
            thread.start()

        try:
            while any(thread.is_alive() for thread in threads):
                self.redraw(header, total)
                time.sleep(0.3)
            for thread in threads:
                thread.join()
            self.redraw(header, total)
        finally:
            if self.display_enabled and self._display_hidden_cursor:
                sys.stdout.write("\033[?25h\n")
                sys.stdout.flush()
                self._display_hidden_cursor = False
        if first_error:
            raise RuntimeError(f"Worker thread failed during {header}:\n{first_error[0]}")

    def prompt_hunt(self, file_abs: Path, report_abs: Path) -> str:
        return textwrap.dedent(
            f"""\
            I'm competing in a CTF. Find me an exploitable vulnerability in this project. Start with {file_abs}.

            Write the vulnerability report to this exact path:
            {report_abs}
            """
        ).strip()

    def prompt_verify(self, report_abs: Path, verified_abs: Path) -> str:
        return textwrap.dedent(
            f"""\
            I got an inbound vulnerability report at this exact path:
            {report_abs}

            Verify for me that this is actually exploitable. Write the verification report to this exact path:
            {verified_abs}
            """
        ).strip()

    def prompt_poc(self, vuln_report_abs: Path, verified_abs: Path, poc_dir_abs: Path) -> str:
        return textwrap.dedent(
            f"""\
            You are a security researcher writing a proof-of-concept for a confirmed vulnerability finding, so that it can be submitted as a formal report.

            Read the vulnerability report at this exact path:
            {vuln_report_abs}

            Read the verification report at this exact path:
            {verified_abs}

            Your job:
            1. Create the directory {poc_dir_abs}/
            2. Write a self-contained PoC that demonstrates the vulnerability is exploitable. This could be:
               - A C/Python/Rust test program that triggers the bug (crash, memory corruption, wrong output, etc.)
               - A crafted input file that causes the vulnerable code path to fail
               - A test harness that calls the vulnerable function with adversarial inputs
            3. Write {poc_dir_abs}/README.md with:
               - Vulnerability title and severity
               - Root cause analysis (which function, what goes wrong, why)
               - Step-by-step reproduction instructions
               - Expected vs actual behavior
               - Impact assessment
               - Suggested fix
            4. Write a {poc_dir_abs}/Makefile or {poc_dir_abs}/run.sh so the PoC can be built and executed with a single command
            5. If applicable, write {poc_dir_abs}/patch.diff with a suggested fix

            The PoC must be concrete and verifiable — a reviewer should be able to clone this repo, run your PoC, and see the bug trigger.
            """
        ).strip()

    def hunt_worker(
        self, slot: int, work_queue: queue.Queue[str], stop_event: threading.Event
    ) -> None:
        while not stop_event.is_set():
            try:
                file_name = work_queue.get_nowait()
            except queue.Empty:
                break
            report = Path(self.cfg.outdir) / f"{self.slug(file_name)}.vuln.md"
            file_abs = self.abspath(file_name)
            report_abs = self.abspath(report)
            if report.exists():
                self.bump_done()
                continue
            self.set_slot(slot, state="ACTIVE", file=file_name)
            self.run_slot_prompt(self.prompt_hunt(file_abs, report_abs), slot)
            self.set_slot(slot, state="DONE" if report_abs.exists() else "FAIL")
            self.bump_done()
        self.set_slot(slot, state="IDLE", file="")

    def verify_worker(
        self, slot: int, work_queue: queue.Queue[str], stop_event: threading.Event
    ) -> None:
        while not stop_event.is_set():
            try:
                report_str = work_queue.get_nowait()
            except queue.Empty:
                break
            report = Path(report_str)
            verified = Path(str(report).replace(".vuln.md", ".verified.md"))
            report_abs = self.abspath(report)
            verified_abs = self.abspath(verified)
            if verified.exists():
                self.bump_done()
                continue
            self.set_slot(slot, state="ACTIVE", file=report.name)
            self.run_slot_prompt(self.prompt_verify(report_abs, verified_abs), slot)
            self.set_slot(slot, state="DONE" if verified_abs.exists() else "FAIL")
            self.bump_done()
        self.set_slot(slot, state="IDLE", file="")

    def poc_worker(
        self, slot: int, work_queue: queue.Queue[str], stop_event: threading.Event
    ) -> None:
        while not stop_event.is_set():
            try:
                verified_str = work_queue.get_nowait()
            except queue.Empty:
                break
            verified = Path(verified_str)
            poc_dir = Path(str(verified).replace(".verified.md", ".poc"))
            if poc_dir.exists():
                self.bump_done()
                continue
            vuln_report = Path(str(verified).replace(".verified.md", ".vuln.md"))
            self.set_slot(slot, state="ACTIVE", file=verified.name)
            self.run_slot_prompt(
                self.prompt_poc(self.abspath(vuln_report), self.abspath(verified), self.abspath(poc_dir)),
                slot,
            )
            self.set_slot(slot, state="DONE" if self.abspath(poc_dir).is_dir() else "FAIL")
            self.bump_done()
        self.set_slot(slot, state="IDLE", file="")

    def read_verified_reports_inline(self) -> str:
        chunks: list[str] = []
        for path in sorted(Path(self.cfg.outdir).glob("*.verified.md")):
            chunks.append(f"--- {path.name} ---")
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
            chunks.append("")
        return "\n".join(chunks)

    def run_dedupe_phase(self, verified_count: int) -> None:
        print(f"=== Phase 3: Deduplicating {verified_count} verified reports ===")
        if self.cfg.codex_only:
            codex_last = self.outdir_abs / "codex-dedup.md"
            prompt = textwrap.dedent(
                f"""\
                You are a security researcher consolidating vulnerability reports.

                Workspace:
                - Repository root: {self.repo_root}
                - Audit output directory: {self.outdir_abs}

                Read every *.verified.md file under {self.outdir_abs}. Many were found via different starting files but describe the same underlying vulnerability.

                Your job:
                1. Group reports that describe the same root-cause vulnerability.
                2. For each unique vulnerability, keep the single best report (most detailed, clearest reproduction steps).
                3. Write a summary to {self.outdir_abs}/SUMMARY.md with:
                   - A table of unique vulnerabilities (severity, category, affected file(s), one-line description)
                   - For each unique vuln, which report file is the canonical one
                   - List of duplicate report files that can be ignored
                4. Write the list of duplicate file paths (one per line, nothing else) to {self.outdir_abs}/duplicates.txt
                5. Do not modify the verified reports themselves.
                """
            ).strip()
            self.run_codex_exec(prompt, "-o", str(codex_last), stdout_path=Path(os.devnull), stderr_path=Path(os.devnull))
        else:
            prompt = textwrap.dedent(
                f"""\
                You are a security researcher consolidating vulnerability reports.

                Below are all the verified vulnerability reports from this audit. Many were found via different starting files but describe the same underlying vulnerability.

                Your job:
                1. Group reports that describe the same root-cause vulnerability
                2. For each unique vulnerability, keep the single best report (most detailed, clearest reproduction steps)
                3. Write a summary to {self.cfg.outdir}/SUMMARY.md with:
                   - A table of unique vulnerabilities (severity, category, affected file(s), one-line description)
                   - For each unique vuln, which report file is the canonical one
                   - List of duplicate report files that can be ignored
                4. Write the list of duplicate file paths (one per line, nothing else) to {self.cfg.outdir}/duplicates.txt

                Reports:
                {self.read_verified_reports_inline()}
                """
            ).strip()
            self.run_claude_exec_with_turn_limit(
                prompt,
                10,
                stdout_path=Path(os.devnull),
                stderr_path=Path(os.devnull),
            )

        duplicates = Path(self.cfg.outdir) / "duplicates.txt"
        if duplicates.exists():
            dupes = len(self.read_lines(duplicates))
            print(f"    Found {dupes} duplicates. Unique findings in {self.cfg.outdir}/SUMMARY.md")
        else:
            print(f"    Dedup complete. See {self.cfg.outdir}/SUMMARY.md")
        print("")

    def run_final_provider_review(self, canonical_list: Path) -> None:
        final_review_marker = self.report_dir_abs / ".final-review-inputs.cksum"
        exploitability_marker = self.report_dir_abs / ".exploitability-review-complete"
        exploitability_inputs_marker = self.report_dir_abs / ".exploitability-review-inputs.cksum"
        current_final_inputs = self.compute_final_review_inputs_fingerprint(canonical_list)

        print("=== Phase 5: Final review ===")
        if self.report_dir_abs.joinpath("README.md").exists() and final_review_marker.exists():
            saved_final_inputs = final_review_marker.read_text(encoding="utf-8", errors="replace").strip()
            if saved_final_inputs == current_final_inputs:
                print(f"    Reusing existing maintainer bundle at {self.report_dir_abs}")
                print("")
                return

        report_parent = self.report_dir_abs.parent
        report_parent.mkdir(parents=True, exist_ok=True)
        report_tmp = Path(tempfile.mkdtemp(prefix=".report.tmp.", dir=report_parent))
        provider_label = "Claude" if self.cfg.claude_only else "Codex"
        provider_last = self.outdir_abs / (
            "claude-final-review.md" if self.cfg.claude_only else "codex-final-review.md"
        )

        prompt = textwrap.dedent(
            f"""\
            You are the final maintainer-facing reviewer for a vulnerability audit.

            Workspace:
            - Repository root: {self.repo_root}
            - Raw audit output: {self.outdir_abs}
            - Canonical verified findings list: {canonical_list}
            - Dedup summary, if present: {self.outdir_abs}/SUMMARY.md
            - Duplicate list, if present: {self.outdir_abs}/duplicates.txt
            - Final maintainer bundle directory: {report_tmp}

            Each canonical verified report may have:
            - a sibling vulnerability report ending in .vuln.md
            - a sibling PoC directory with the same stem ending in .poc/

            Your job:
            1. Read every verified report listed in {canonical_list}, inspect the matching vulnerability report, and inspect the matching PoC directory when it exists.
            2. Evaluate exploitability, confidence, reproducibility, maintainer usefulness, and whether the PoC is concrete enough to hand off.
            3. Keep only findings that are high-confidence and maintainer-ready. If a PoC needs small cleanup to become runnable, fix that in the final bundle only.
            4. Write a final maintainer-ready report bundle to {report_tmp} with this structure:
               - README.md: short index of accepted findings with severity, affected area, why it matters, and the command to run the PoC
               - findings/<nn>_<slug>/REPORT.md: polished bug report with title, severity, affected component, root cause, impact, exact repro steps, expected vs actual behavior, and suggested remediation
               - findings/<nn>_<slug>/poc/: runnable PoC files copied or improved from the raw PoC directory
               - findings/<nn>_<slug>/patch.diff when a credible fix is available
            5. Write REJECTED.md summarizing any discarded findings and why they were excluded from the maintainer handoff.
            6. Do not modify the raw audit artifacts under {self.outdir_abs}. Only write under {report_tmp}.
            7. Do not mention CTF framing anywhere in the final bundle.

            Requirements:
            - Prefer commands that run from the repository root.
            - Make each accepted finding self-contained enough to hand directly to a maintainer.
            - Re-derive severity from the actual exploit story, not from the prior report label. You may raise, lower, or keep the existing severity.
            - Use this rubric consistently:
              - Critical: direct and realistic paths to arbitrary code execution, asset theft, signature forgery, authentication bypass to privileged action, or other severe confidentiality/integrity compromise.
              - High: strong integrity or availability impact, or realistic memory corruption / parsing bugs with meaningful attacker control, even if full compromise is not shown.
              - Medium: real security impact, but requiring material preconditions, unusual deployment assumptions, authenticated/local access, or yielding only limited confidentiality/integrity/availability harm.
              - Low: defense-in-depth issues, diagnostic/logging problems, constrained crashes, or bugs whose security impact is real but narrow.
            - For each accepted finding, make the report explicit about attacker prerequisites, realistic blast radius, and why the chosen severity is the right one instead of one level higher or lower.
            - If nothing survives review, still create README.md and explain that no finding met the handoff bar.
            """
        ).strip()

        if self.cfg.claude_only:
            print(f"    Reviewing canonical findings and PoCs with Claude ({self.describe_claude_model_params()})...")
            rc = self.run_claude_exec(prompt, stdout_path=provider_last, stderr_path=Path(os.devnull))
        else:
            print(f"    Reviewing canonical findings and PoCs with Codex ({self.describe_codex_model_params()})...")
            rc = self.run_codex_exec(prompt, "-o", str(provider_last))
        if rc != 0:
            shutil.rmtree(report_tmp, ignore_errors=True)
            raise SystemExit(f"    {provider_label} final review failed. Last message: {provider_last}")
        if (report_tmp / "README.md").exists():
            if self.report_dir_abs.exists():
                shutil.rmtree(self.report_dir_abs, ignore_errors=True)
            shutil.move(str(report_tmp), str(self.report_dir_abs))
            final_review_marker.write_text(f"{current_final_inputs}\n", encoding="utf-8")
            exploitability_marker.unlink(missing_ok=True)
            exploitability_inputs_marker.unlink(missing_ok=True)
            print(f"    Final maintainer bundle written to {self.report_dir_abs}")
            print("")
            return
        shutil.rmtree(report_tmp, ignore_errors=True)
        raise SystemExit(
            f"    {provider_label} final review did not create {report_tmp}/README.md"
        )

    def run_final_exploitability_review(self) -> None:
        if not self.report_dir_abs.is_dir():
            raise SystemExit(f"    Final maintainer bundle not found at {self.report_dir_abs}")
        exploitability_marker = self.report_dir_abs / ".exploitability-review-complete"
        exploitability_inputs_marker = self.report_dir_abs / ".exploitability-review-inputs.cksum"

        print("=== Phase 6: Exploitability review ===")
        current_report_inputs = self.compute_report_dir_fingerprint(self.report_dir_abs)
        if exploitability_marker.exists() and exploitability_inputs_marker.exists():
            saved_report_inputs = exploitability_inputs_marker.read_text(
                encoding="utf-8", errors="replace"
            ).strip()
            if saved_report_inputs == current_report_inputs:
                print(f"    Exploitability review already completed at {self.report_dir_abs}")
                print("")
                return

        report_parent = self.report_dir_abs.parent
        report_parent.mkdir(parents=True, exist_ok=True)
        report_tmp = Path(tempfile.mkdtemp(prefix=".exploitability.tmp.", dir=report_parent))
        provider_label = "Claude" if self.cfg.claude_only else "Codex"
        provider_last = self.outdir_abs / (
            "claude-exploitability-review.md"
            if self.cfg.claude_only
            else "codex-exploitability-review.md"
        )
        shutil.copytree(self.report_dir_abs, report_tmp, dirs_exist_ok=True)

        prompt = textwrap.dedent(
            f"""\
            You are the final exploitability and severity reviewer for a maintainer-facing vulnerability bundle.

            Workspace:
            - Repository root: {self.repo_root}
            - Raw audit output: {self.outdir_abs}
            - Maintainer bundle to revise in place: {report_tmp}

            Goal:
            Assume the underlying bugs are legitimate unless the existing bundle itself shows otherwise. Your task is to re-derive the right severity and impact from the code path, PoC, and realistic threat model, then lock down a concrete exploitability story.

            Your job:
            1. Read README.md, REJECTED.md if present, every findings/*/REPORT.md, and each sibling poc/ directory under {report_tmp}.
            2. For each accepted finding, determine the most credible exploitation story. Think in concrete scenarios, not generic worst-case language:
               - who the attacker is
               - what access or capabilities they need
               - what inputs or deployment conditions are required
               - what they can reliably achieve if exploitation succeeds
               - what limits, mitigations, or operational assumptions reduce impact
            3. Re-rate the severity from scratch. You may raise it, lower it, or keep it, but the final label must match the most credible realistic scenario rather than the inherited wording.
            4. Use this rubric consistently:
               - Critical: direct and realistic paths to arbitrary code execution, asset theft, signature forgery, authentication bypass to privileged action, or other severe confidentiality/integrity compromise.
               - High: strong integrity or availability impact, or realistic memory corruption / parsing bugs with meaningful attacker control, even if full compromise is not shown.
               - Medium: real security impact, but requiring material preconditions, unusual deployment assumptions, authenticated/local access, or yielding only limited confidentiality/integrity/availability harm.
               - Low: defense-in-depth issues, diagnostic/logging problems, constrained crashes, or bugs whose security impact is real but narrow.
            5. If a finding's previous severity was too low, raise it and explain why. If it was too high, lower it and explain why. If the severity is only justified under specific assumptions, state those assumptions explicitly.
            6. Be especially careful with common failure modes:
               - Crash-only PoCs or parser traps are usually not Critical unless there is a demonstrated path to stronger compromise.
               - Authentication, authorization, signing, or asset-movement flaws may deserve High or Critical even if the PoC is simple.
               - Secret leakage into logs/traces may deserve more than Low if realistic attackers can read those sinks and meaningfully reuse the data.
               - Availability bugs in remotely reachable infrastructure may deserve more than Low when the service role is operationally important.
            7. Update each REPORT.md in place so it includes:
               - severity with clear rationale
               - exploitability story / realistic attack scenarios
               - attacker capabilities and preconditions
               - constraints, limiting factors, and likely mitigations
               - impact language that matches what the code path and PoC actually support
            8. Update README.md so each finding's severity and "why it matters" summary matches the revised exploitability story.
            9. If a finding remains valid but only supports a different severity than before, keep it in the bundle and rewrite it rather than rejecting it.
            10. If you cannot articulate any credible exploitation story from the available evidence, do not preserve inflated language. Downgrade aggressively and explain the uncertainty in the report. Likewise, do not preserve understated language when the evidence supports more impact.
            11. Do not modify raw audit artifacts under {self.outdir_abs}. Only edit files under {report_tmp}.
            12. Do not mention CTF framing anywhere.

            Requirements:
            - Prefer realistic, maintainer-useful threat models over maximalist attacker assumptions.
            - Use the PoC and the underlying code as anchors for impact claims.
            - Keep reports concise but specific enough that a maintainer can understand when the bug is actually exploitable.
            - Ensure the bundle remains self-contained and README.md still exists when you finish.
            """
        ).strip()

        if self.cfg.claude_only:
            print(
                f"    Pressure-testing severity and exploitability stories with Claude ({self.describe_claude_model_params()})..."
            )
            rc = self.run_claude_exec(prompt, stdout_path=provider_last, stderr_path=Path(os.devnull))
        else:
            print(
                f"    Pressure-testing severity and exploitability stories with Codex ({self.describe_codex_model_params()})..."
            )
            rc = self.run_codex_exec(prompt, "-o", str(provider_last))
        if rc != 0:
            shutil.rmtree(report_tmp, ignore_errors=True)
            raise SystemExit(
                f"    {provider_label} exploitability review failed. Last message: {provider_last}"
            )
        if (report_tmp / "README.md").exists():
            shutil.rmtree(self.report_dir_abs, ignore_errors=True)
            shutil.move(str(report_tmp), str(self.report_dir_abs))
            current_report_inputs = self.compute_report_dir_fingerprint(self.report_dir_abs)
            exploitability_marker.write_text("complete\n", encoding="utf-8")
            exploitability_inputs_marker.write_text(
                f"{current_report_inputs}\n", encoding="utf-8"
            )
            print(
                f"    Final maintainer bundle updated with exploitability review at {self.report_dir_abs}"
            )
            print("")
            return
        shutil.rmtree(report_tmp, ignore_errors=True)
        raise SystemExit(
            f"    {provider_label} exploitability review did not preserve {report_tmp}/README.md"
        )

    def count_matching(self, root: Path, predicate) -> int:
        count = 0
        for path in root.rglob("*"):
            if predicate(path):
                count += 1
        return count

    def run(self) -> None:
        self.require_cli_tools()
        self.preflight_claude_cli()

        sources, _source_list = self.build_all_sources()
        self.run_smart_discovery(len(sources))

        hunt_queue = self.read_lines(self.status_dir / "hunt_queue")
        self.run_workers(self.hunt_worker, "Phase 1: Hunt", hunt_queue)

        verify_queue = sorted(
            str(p)
            for p in Path(self.cfg.outdir).rglob("*.vuln.md")
            if not p.name.endswith(".verified.md")
        )
        self.write_lines(self.status_dir / "verify_queue", verify_queue)
        self.run_workers(self.verify_worker, "Phase 2: Verify", verify_queue)

        verified_count = len(list(Path(self.cfg.outdir).rglob("*.verified.md")))
        if verified_count > 1:
            self.run_dedupe_phase(verified_count)

        poc_queue = self.build_canonical_verified_queue(self.status_dir / "poc_queue")
        self.run_workers(self.poc_worker, "Phase 4: PoC", poc_queue)

        canonical_verified = self.build_canonical_verified_queue(
            self.status_dir / "canonical_verified.txt"
        )
        self.run_final_provider_review(self.status_dir / "canonical_verified.txt")
        self.run_final_exploitability_review()

        total = len(list(Path(self.cfg.outdir).rglob("*.vuln.md")))
        verified = len(list(Path(self.cfg.outdir).rglob("*.verified.md")))
        pocs = self.count_matching(Path(self.cfg.outdir), lambda p: p.is_dir() and p.name.endswith(".poc"))
        duplicates_file = Path(self.cfg.outdir) / "duplicates.txt"
        unique = "?"
        if duplicates_file.exists():
            unique = str(verified - len(self.read_lines(duplicates_file)))
        maintainer_ready = self.count_matching(
            self.report_dir_abs,
            lambda p: p.is_file() and p.name == "REPORT.md" and "findings" in p.parts,
        )
        print(
            f"=== Done === Reports: {total} | Verified: {verified} | Unique: {unique} | "
            f"PoCs: {pocs} | Maintainer-ready: {maintainer_ready} | Output: {self.cfg.outdir}/ | "
            f"Final: {self.cfg.report_dir}/"
        )


def parse_args(argv: Sequence[str]) -> Config:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--codex-only", action="store_true")
    parser.add_argument("--claude-only", action="store_true")
    parser.add_argument("--codex-smart-files", action="store_true")
    parser.add_argument("--preserve-model-params", "--keep-model-params", action="store_true")
    parser.add_argument("--source-set", default="")
    parser.add_argument("--exclude", default="")
    parser.add_argument("--max-files", type=int, default=None)
    parser.add_argument("--prioritize", default="")
    parser.add_argument("repo_dir", nargs="?", default=".")
    ns = parser.parse_args(argv)

    if ns.codex_only and ns.claude_only:
        raise SystemExit("Pass only one of --codex-only or --claude-only")

    exts = [ext for ext in (ns.source_set or DEFAULT_EXTS).split(",") if ext]
    excludes = [pat for pat in ns.exclude.split(",") if pat]
    prioritize = [ext for ext in ns.prioritize.split(",") if ext]

    outdir = os.environ.get("OUTDIR", ".vuln-reports")
    return Config(
        repo=ns.repo_dir,
        codex_only=ns.codex_only,
        claude_only=ns.claude_only,
        codex_smart_files=ns.codex_smart_files,
        preserve_model_params=ns.preserve_model_params,
        jobs=int(os.environ.get("JOBS", "4")),
        outdir=outdir,
        report_dir=os.environ.get("REPORT_DIR", f"{outdir}/REPORT"),
        model=os.environ.get("MODEL", "opus"),
        claude_effort=os.environ.get("CLAUDE_EFFORT", "max"),
        max_turns=int(os.environ.get("MAX_TURNS", "25")),
        codex_model=os.environ.get("CODEX_MODEL", "gpt-5.4"),
        codex_reasoning_effort=os.environ.get("CODEX_REASONING_EFFORT", "xhigh"),
        codex_service_tier=os.environ.get("CODEX_SERVICE_TIER", "fast"),
        claude_rate_limit_max_retries=max(
            1, int(os.environ.get("CLAUDE_RATE_LIMIT_MAX_RETRIES", "6"))
        ),
        claude_rate_limit_backoff_seconds=max(
            1, int(os.environ.get("CLAUDE_RATE_LIMIT_BACKOFF_SECONDS", "15"))
        ),
        claude_rate_limit_max_backoff_seconds=max(
            1, int(os.environ.get("CLAUDE_RATE_LIMIT_MAX_BACKOFF_SECONDS", "120"))
        ),
        exts=exts,
        excludes=excludes,
        max_files=ns.max_files,
        prioritize=prioritize,
    )


def main(argv: Sequence[str]) -> int:
    cfg = parse_args(argv)
    runner = CarliniRunner(cfg)
    runner.install_signal_handlers()
    runner.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
