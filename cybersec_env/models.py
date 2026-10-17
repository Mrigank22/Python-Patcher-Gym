"""OpenEnv Action/Observation models for the secure-code-repair environment."""

from __future__ import annotations

from openenv.core.env_server.types import Action, Observation
from pydantic import Field


class SecureCodeAction(Action):
    """The agent's attempt: a fixed function (optionally wrapped in prose/fences)."""

    code: str = Field(..., description="The repaired function. May include a ```python fence.")


class SecureCodeObservation(Observation):
    """What the environment returns on reset and after a step.

    On ``reset`` the task fields (``prompt``, ``cwe`` ...) are populated and
    ``reward``/``solved`` are at their defaults. After ``step`` the grading
    fields are filled and ``done`` is True (single-turn episode).
    """

    task_id: str = Field(default="", description="family-difficulty-seed identifier")
    cwe: str = Field(default="", description="CWE id of the vulnerability")
    family: str = Field(default="", description="task family name")
    entrypoint: str = Field(default="", description="required function name")
    prompt: str = Field(default="", description="the task shown to the model (reset only)")

    solved: bool = Field(default=False, description="all functional and security probes passed")
    functional_pass: int = Field(default=0)
    functional_total: int = Field(default=0)
    security_pass: int = Field(default=0)
    security_total: int = Field(default=0)
    static_ok: bool = Field(default=False)
    guard_reason: str = Field(default="", description="non-empty if a grader-escape was blocked")
    error: str = Field(default="", description="grading error, if any")
