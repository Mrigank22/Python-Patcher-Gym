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
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from . import guard
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
        res.parsed = worker.get("ok", False) and not worker.get("error")
        res.error = worker.get("error", "")
        func = worker.get("functional", [])
        sec = worker.get("security", [])
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
        # the only place it may write (enforced in the worker). The dir is
        # deleted afterwards, so nothing a candidate writes can outlive its own
        # grading or influence the grading of another candidate.
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
                              "nonce": nonce, "sandbox": sandbox})

        try:
            proc = subprocess.run(
                [self.python, "-m", "cybersec_env._grade_worker"],
                input=request,
                capture_output=True,
                text=True,
                # Not the locale codec: on Windows (cp1252) one unusual byte in
                # the worker's output would lose the whole verdict.
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_s,
                cwd=sandbox,
                env=env,
            )
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "timeout", "functional": [], "security": []}
        finally:
            shutil.rmtree(sandbox, ignore_errors=True)

        for line in reversed((proc.stdout or "").splitlines()):
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
        return {"ok": False, "error": f"no_verdict: {(proc.stderr or '')[-200:]}",
                "functional": [], "security": []}
