"""The grader: turn a candidate completion into a verified reward.

Pipeline for one candidate:

1. **Extract** the function source from the model output.
2. **Guard** – static denylist scan; a grader-escape attempt scores 0 here.
3. **Execute** the functional and security probes in an isolated subprocess
   worker with a hard wall-clock timeout, confined to a throwaway sandbox
   directory (see :mod:`cybersec_env._grade_worker`).
4. **Static rubric** – a per-CWE source check (secondary, low weight).
5. **Reward** – shaped or binary, with functionality and security both
   required for full credit.

The class is deliberately framework-free: it has no dependency on TRL, OpenEnv
or torch, so it can be reused from a training reward function, an OpenEnv
server, a CLI, or a unit test.
"""

from __future__ import annotations

import json
import os
import secrets
import select
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from . import guard
from . import sandbox as sandbox_mod
from .extract import extract_code
from .reward import compute_reward
from .tasks import generate, static_secure

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)


@dataclass
class VerificationResult:
    task_id: str
    family: str
    cwe: str
    parsed: bool = False
    guard_ok: bool = True
    guard_reason: str = ""
    format_ok: bool = False
    functional_pass: int = 0
    functional_total: int = 0
    security_pass: int = 0
    security_total: int = 0
    static_ok: bool = False
    solved: bool = False
    reward: float = 0.0
    error: str = ""
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class Verifier:
    """Grades candidate completions for a task. Thread-safe and stateless."""

    def __init__(self, timeout_s: float = 8.0, reward_mode: str = "shaped",
                 python_executable: Optional[str] = None):
        self.timeout_s = timeout_s
        self.reward_mode = reward_mode
        self.python = python_executable or sys.executable

    # -- public API --------------------------------------------------------
    def grade_completion(self, task_id: str, completion: str) -> VerificationResult:
        """Grade a raw model completion (prose + fenced code)."""
        inst = generate(task_id)
        extracted = extract_code(completion, inst.entrypoint)
        res = self.grade_source(task_id, extracted.code)
        res.format_ok = extracted.format_ok
        res.reward = compute_reward(res, self.reward_mode)
        return res

    def grade_source(self, task_id: str, source: str) -> VerificationResult:
        """Grade already-extracted Python source."""
        inst = generate(task_id)
        res = VerificationResult(task_id=task_id, family=inst.family, cwe=inst.cwe)
        res.functional_total = len(inst.functional_probes)
        res.security_total = len(inst.security_probes)

        if not source or not source.strip():
            res.error = "empty_candidate"
            res.reward = compute_reward(res, self.reward_mode)
            return res

        g = guard.scan(source)
        res.guard_ok = g.ok
        res.guard_reason = g.reason
        if not g.ok:
            res.error = g.reason
            res.reward = compute_reward(res, self.reward_mode)
            return res

        worker = self._run_worker(task_id, source)
        func = worker.get("functional", [])
        sec = worker.get("security", [])
        # Defence in depth: the number of outcomes must match the number of
        # probes this (trusted) process built for the task. A forged verdict
        # that sprays "all pass" without knowing the true probe counts trips
        # this and is discarded as a failure.
        if len(func) != res.functional_total or len(sec) != res.security_total:
            res.error = worker.get("error") or "probe_count_mismatch"
            res.reward = compute_reward(res, self.reward_mode)
            return res
        res.parsed = worker.get("ok", False) and not worker.get("error")
        res.error = worker.get("error", "")
        res.functional_pass = sum(1 for x in func if x)
        res.security_pass = sum(1 for x in sec if x)
        res.static_ok = static_secure(inst.family, source)
        res.solved = (
            res.functional_total > 0
            and res.functional_pass == res.functional_total
            and res.security_pass == res.security_total
        )
        res.details = {
            "functional": dict(zip(worker.get("functional_names", []), func)),
            "security": dict(zip(worker.get("security_names", []), sec)),
            "static_ok": res.static_ok,
        }
        res.reward = compute_reward(res, self.reward_mode)
        return res

    # -- internals ---------------------------------------------------------
    def _run_worker(self, task_id: str, source: str) -> dict:
        # Each candidate gets a fresh sandbox dir that is its cwd, its TEMP and
        # the only place it may write (enforced by the OS jail and the worker's
        # audit hook). The dir is deleted afterwards, so nothing a candidate
        # writes can outlive its own grading or influence another candidate's.
        # realpath: on Windows TEMP is often an 8.3 short path (C:\Users\ABCDEF~1\...),
        # and an answer comparing os.path.realpath(full) with the raw base dir
        # would then reject legitimate files here but not on Linux.
        sandbox = os.path.realpath(tempfile.mkdtemp(prefix="cse_cand_"))
        candidate_path = os.path.join(sandbox, "solution.py")
        with open(candidate_path, "w", encoding="utf-8") as fh:
            fh.write(source)

        env = dict(os.environ)
        env["PYTHONPATH"] = _REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
        env["PYTHONHASHSEED"] = "0"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        for var in ("TMPDIR", "TEMP", "TMP"):
            env[var] = sandbox
        # The worker echoes this per-call token in its verdict; output without
        # it (e.g. anything the candidate printed itself) is not trusted.
        nonce = secrets.token_hex(16)
        request = json.dumps({"task_id": task_id, "candidate_path": candidate_path,
                              "nonce": nonce, "sandbox": sandbox,
                              "timeout_s": self.timeout_s})

        # The verdict comes back on a private pipe, not stdout: candidate code
        # cannot reach this fd (the worker's untrusted child closes it before
        # running the candidate), so it cannot forge or pre-empt the verdict.
        read_fd, write_fd = os.pipe()
        inner = [self.python, "-m", "cybersec_env._grade_worker"]
        env["CSE_VERDICT_FD"] = str(write_fd)
        if os.name == "nt":  # fd numbers don't cross processes there; handles do
            import msvcrt
            env["CSE_VERDICT_HANDLE"] = str(msvcrt.get_osfhandle(write_fd))
        argv, popen_kwargs = sandbox_mod.wrap_command(
            inner, sandbox_dir=sandbox, repo_root=_REPO_ROOT, verdict_fd=write_fd)

        proc = None
        job = None
        if os.name == "nt":
            popen_kwargs["creationflags"] = (popen_kwargs.get("creationflags", 0)
                                             | sandbox_mod.CREATE_SUSPENDED)
        try:
            proc = subprocess.Popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, env=env, cwd=sandbox, **popen_kwargs,
            )
            if os.name == "nt":
                job = sandbox_mod.windows_job_attach(proc)
            os.close(write_fd)
            write_fd = -1
            proc.stdin.write(request.encode("utf-8"))
            proc.stdin.close()
            verdict = self._read_verdict(read_fd, nonce, proc)
            return verdict
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "timeout", "functional": [], "security": []}
        finally:
            if job is not None:  # reaps the worker *and* every descendant
                sandbox_mod.windows_job_close(job)
            if write_fd != -1:
                os.close(write_fd)
            os.close(read_fd)
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.wait()
            shutil.rmtree(sandbox, ignore_errors=True)

    def _read_verdict(self, read_fd: int, nonce: str, proc) -> dict:
        """Read the single nonce-tagged verdict line from the private pipe,
        enforcing the wall-clock timeout."""
        deadline = time.monotonic() + self.timeout_s
        buf = bytearray()
        if os.name == "nt":
            # select() only takes sockets on Windows: read on a helper thread
            # and enforce the deadline by joining it.
            def _pump():
                try:
                    while True:
                        chunk = os.read(read_fd, 65536)
                        if not chunk:
                            break
                        buf.extend(chunk)
                except OSError:
                    pass
            reader = threading.Thread(target=_pump, daemon=True)
            reader.start()
            reader.join(self.timeout_s)
            if reader.is_alive():
                proc.kill()
                return {"ok": False, "error": "timeout", "functional": [], "security": []}
        while os.name != "nt":
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                return {"ok": False, "error": "timeout", "functional": [], "security": []}
            r, _, _ = select.select([read_fd], [], [], remaining)
            if not r:
                continue
            chunk = os.read(read_fd, 65536)
            if not chunk:
                break  # writer closed: EOF
            buf.extend(chunk)

        for line in reversed(bytes(buf).decode("utf-8", "replace").splitlines()):
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(msg, dict) and msg.get("nonce") == nonce:
                return msg.get("result", {"ok": False, "error": "bad_output",
                                          "functional": [], "security": []})
        try:
            err = (proc.stderr.read() or b"")[-200:].decode("utf-8", "replace") if proc.stderr else ""
        except Exception:
            err = ""
        return {"ok": False, "error": f"no_verdict: {err}",
                "functional": [], "security": []}
