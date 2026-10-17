"""Task framework for the CyberSec secure-code-repair environment.

A *task family* is a procedural generator for one vulnerability class (CWE).
Given an integer ``seed`` it deterministically produces a concrete *instance*:

* a short natural-language spec + a vulnerable seed implementation shown to the
  model (``prompt_code``),
* a reference *safe* implementation (the oracle) used only for sanity checks,
* a set of **functional probes** (benign inputs whose output must match the
  reference) and **security probes** (malicious inputs that must be handled
  safely), both of which live inside the grader and are *never* shown to the
  model,
* a small AST/static rubric specific to the CWE.

Everything here is pure, cross-platform Python so a single instance can be
graded on a CPU in milliseconds. The probes are plain picklable data or small
callables executed inside the grader worker (see ``cybersec_env.sandbox``).
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional, Tuple


@dataclass
class Probe:
    """A single functional or security check.

    The grader calls ``fn(candidate_callable)`` inside an isolated worker and
    expects it to return ``True`` (pass) or ``False`` (fail). It must raise
    nothing on expected-safe behaviour; any uncaught exception counts as a
    failure for that probe.
    """

    name: str
    fn: Callable[[Callable[..., Any]], bool]
    kind: str = "functional"  # "functional" | "security"
    description: str = ""


@dataclass
class TaskInstance:
    """A concrete, fully-specified task produced by a :class:`TaskFamily`."""

    task_id: str
    family: str
    cwe: str
    title: str
    entrypoint: str                 # name of the function the model must define
    prompt_code: str                # vulnerable seed shown to the model
    reference_code: str             # safe oracle, hidden from the model
    instruction: str                # natural-language task description
    functional_probes: List[Probe] = field(default_factory=list)
    security_probes: List[Probe] = field(default_factory=list)
    static_checks: List[Probe] = field(default_factory=list)
    difficulty: int = 1             # 1 (easy) .. 3 (hard)
    metadata: dict = field(default_factory=dict)

    # ---- helpers ---------------------------------------------------------
    def user_prompt(self) -> str:
        """The user-visible task text (spec + vulnerable code + instructions)."""
        return (
            f"{self.instruction}\n\n"
            f"The function below has a security vulnerability "
            f"({self.cwe}: {self.title}). Rewrite it so that it is secure "
            f"while preserving its documented behaviour. Return the complete, "
            f"fixed function inside a single ```python code block and nothing "
            f"else.\n\n"
            f"```python\n{self.prompt_code.strip()}\n```"
        )


class TaskFamily:
    """Base class for a procedural vulnerability-task generator.

    Subclasses implement :meth:`build` to turn a seeded ``random.Random`` into a
    :class:`TaskInstance`. Keep ``build`` deterministic in ``rng`` only.
    """

    #: unique, stable short name, e.g. ``"sqli"``.
    name: str = "base"
    #: CWE identifier, e.g. ``"CWE-089"``.
    cwe: str = "CWE-000"
    #: human-readable vulnerability name.
    title: str = "Generic vulnerability"

    def build(self, rng: random.Random, difficulty: int) -> TaskInstance:  # pragma: no cover - abstract
        raise NotImplementedError

    def generate(self, seed: int, difficulty: int = 1) -> TaskInstance:
        """Deterministically generate the instance for ``seed``."""
        rng = random.Random(f"{self.name}:{difficulty}:{seed}")
        inst = self.build(rng, difficulty)
        inst.task_id = f"{self.name}-{difficulty}-{seed}"
        inst.family = self.name
        inst.cwe = self.cwe
        inst.title = self.title
        inst.difficulty = difficulty
        return inst


def load_callable(source: str, entrypoint: str):
    """Compile ``source`` and return the callable named ``entrypoint``.

    Used by the grader worker and by unit tests. Executes in the *current*
    process, so only ever call it on trusted code (the reference oracle) or
    inside the isolated worker.
    """
    namespace: dict = {}
    code = compile(source, "<candidate>", "exec")
    exec(code, namespace)  # noqa: S102 - sandboxed by the caller
    fn = namespace.get(entrypoint)
    if not callable(fn):
        raise ValueError(f"source does not define a callable '{entrypoint}'")
    return fn
