"""The OpenEnv ``Environment`` wrapping the secure-code-repair grader.

Single-turn episode: ``reset`` hands out a task (its prompt), ``step`` grades
the submitted code and returns the reward with ``done=True``. Each client
session gets its own instance (``SUPPORTS_CONCURRENT_SESSIONS = True``); the
grader spawns an isolated subprocess per submission, so sessions never share
mutable state.

The environment is model-agnostic — it speaks plain strings over HTTP — so any
LLM (local, API, any size) can be trained or evaluated against it.
"""

from __future__ import annotations

import random
from typing import List, Optional
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

from .models import SecureCodeAction, SecureCodeObservation
from .tasks import family_names, generate, get_family
from .verifier import Verifier


class SecureCodeEnv(Environment):
    """Serve and grade secure-code-repair tasks over the OpenEnv protocol."""

    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(
        self,
        families: Optional[List[str]] = None,
        difficulties: tuple = (1,),
        seed_pool: int = 1000,
        reward_mode: str = "shaped",
        timeout_s: float = 8.0,
    ):
        super().__init__()
        self.families = families or family_names()
        self.difficulties = tuple(difficulties)
        self.seed_pool = seed_pool
        self.verifier = Verifier(timeout_s=timeout_s, reward_mode=reward_mode)
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._task = None

    # -- OpenEnv API -------------------------------------------------------
    def reset(self, seed: Optional[int] = None, episode_id: Optional[str] = None,
              task_id: Optional[str] = None, **kwargs) -> SecureCodeObservation:
        """Start an episode. Pass ``task_id`` to request a specific task, or
        ``seed`` to sample one deterministically; otherwise one is sampled."""
        rng = random.Random(seed)
        if task_id:
            self._task = generate(task_id)
        else:
            fam = get_family(rng.choice(self.families))
            d = rng.choice(self.difficulties)
            s = rng.randrange(self.seed_pool) if seed is None else seed
            self._task = fam.generate(seed=s, difficulty=d)

        self._state = State(episode_id=episode_id or str(uuid4()), step_count=0)
        self._state.task_id = self._task.task_id  # type: ignore[attr-defined]

        return SecureCodeObservation(
            task_id=self._task.task_id,
            cwe=self._task.cwe,
            family=self._task.family,
            entrypoint=self._task.entrypoint,
            prompt=self._task.user_prompt(),
            done=False,
            reward=0.0,
        )

    def step(self, action: SecureCodeAction, timeout_s: Optional[float] = None,
             **kwargs) -> SecureCodeObservation:
        if self._task is None:
            raise RuntimeError("call reset() before step()")

        self._state.step_count += 1
        res = self.verifier.grade_completion(self._task.task_id, action.code)

        return SecureCodeObservation(
            task_id=res.task_id,
            cwe=res.cwe,
            family=res.family,
            entrypoint=self._task.entrypoint,
            prompt="",
            solved=res.solved,
            functional_pass=res.functional_pass,
            functional_total=res.functional_total,
            security_pass=res.security_pass,
            security_total=res.security_total,
            static_ok=res.static_ok,
            guard_reason=res.guard_reason,
            error=res.error,
            done=True,
            reward=res.reward,
            metadata={"details": res.details},
        )

    @property
    def state(self) -> State:
        return self._state
