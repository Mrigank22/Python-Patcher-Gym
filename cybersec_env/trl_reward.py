"""TRL-compatible reward function for GRPO training.

Training uses the ``reward_funcs`` path rather than tool-calling, because
secure-code repair is single-turn: the policy reads the vulnerable function and
emits the fixed one. GRPO samples a group of completions per prompt and this
function scores each by running the grader.

The grader spawns one subprocess per completion, so a group is graded in
parallel with a thread pool (the work is I/O/subprocess-bound, so threads are
enough and avoid CUDA-fork issues). The function also keeps running aggregate
statistics (functional/security/solved rates, guard blocks) that a callback can
log, so reward-hacking shows up immediately as "reward rising, security flat".
"""

from __future__ import annotations

import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

from .verifier import Verifier


def _completion_text(c) -> str:
    """Normalise a TRL completion (str or list of chat messages) to text."""
    if isinstance(c, str):
        return c
    if isinstance(c, list):  # conversational: [{"role": "assistant", "content": ...}]
        parts = []
        for m in c:
            if isinstance(m, dict):
                parts.append(m.get("content", "") or "")
        return "\n".join(parts)
    return str(c)


class SecureCodeReward:
    """Callable reward function passed to ``GRPOTrainer(reward_funcs=[...])``."""

    __name__ = "secure_code_repair"  # TRL uses this to name the logged column

    def __init__(self, reward_mode: str = "shaped", timeout_s: float = 8.0,
                 max_workers: Optional[int] = None):
        self.verifier = Verifier(timeout_s=timeout_s, reward_mode=reward_mode)
        self.max_workers = max_workers or 8
        self._lock = threading.Lock()
        self.last_stats: dict = {}

    def __call__(self, prompts=None, completions=None, task_id=None, **kwargs) -> List[float]:
        texts = [_completion_text(c) for c in completions]
        ids = list(task_id) if task_id is not None else [None] * len(texts)

        def _grade(i):
            tid = ids[i]
            if tid is None:
                return 0.0, None
            res = self.verifier.grade_completion(tid, texts[i])
            return res.reward, res

        rewards: List[float] = [0.0] * len(texts)
        results = [None] * len(texts)
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            for i, (r, res) in zip(range(len(texts)), pool.map(_grade, range(len(texts)))):
                rewards[i] = float(r)
                results[i] = res

        self._update_stats(results)
        return rewards

    def _update_stats(self, results) -> None:
        agg = defaultdict(float)
        n = 0
        per_cwe = defaultdict(lambda: [0, 0])
        for res in results:
            if res is None:
                continue
            n += 1
            agg["reward"] += res.reward
            agg["solved"] += 1.0 if res.solved else 0.0
            agg["func_rate"] += _ratio(res.functional_pass, res.functional_total)
            agg["sec_rate"] += _ratio(res.security_pass, res.security_total)
            agg["static_ok"] += 1.0 if res.static_ok else 0.0
            agg["guard_blocked"] += 1.0 if not res.guard_ok else 0.0
            per_cwe[res.cwe][0] += 1 if res.solved else 0
            per_cwe[res.cwe][1] += 1
        if n:
            stats = {k: v / n for k, v in agg.items()}
            stats["n"] = n
            stats["solved_by_cwe"] = {k: f"{a}/{b}" for k, (a, b) in per_cwe.items()}
            with self._lock:
                self.last_stats = stats


def _ratio(num: int, den: int) -> float:
    return 1.0 if den == 0 else num / den
