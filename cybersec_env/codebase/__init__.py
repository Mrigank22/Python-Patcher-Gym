"""Codebase (repository-level) security-repair track.

Each task is a real PyPI advisory turned into a SWE-bench-shaped problem: the
model sees a repository at the vulnerable commit plus a regression test that
describes the required secure behaviour, and must patch the *source* so the
test passes without breaking the existing tests. Grading runs the tests inside
a locked-down Docker container, so the candidate's code never shares a process
with the judge — the strongest isolation in this project and the model labs
actually train on.

See :mod:`cybersec_env.codebase.grader`.
"""

from .grader import (
    CodebaseResult,
    CodebaseGrader,
    sanitize_patch,
)

__all__ = ["CodebaseResult", "CodebaseGrader", "sanitize_patch"]
