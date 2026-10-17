"""Reward shaping from a :class:`~cybersec_env.verifier.VerificationResult`.

Two modes:

* ``binary`` – 1.0 iff the candidate is *solved* (every functional **and**
  every security probe passes) and the static rubric is satisfied, else 0.0.
  This is the signal a lab ultimately cares about and the one the research
  literature finds trains most cleanly on capable models.
* ``shaped`` (default) – dense partial credit for small models that would see
  almost no reward under the binary scheme, while still capping any unsolved
  candidate strictly below a solved one.

The reward and all of its components are returned so a consumer can re-weight
them. Critically, functionality and security are *both* required for full
reward: a candidate that deletes the vulnerable behaviour (passing security but
breaking functionality) and one that keeps functionality but stays vulnerable
are both penalised.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid import cycle at runtime
    from .verifier import VerificationResult

# shaped-mode weights (sum to 1.0 before the solved cap)
W_FUNC = 0.45
W_SEC = 0.40
W_STATIC = 0.10
W_FORMAT = 0.05
UNSOLVED_CAP = 0.85  # an unsolved candidate can never exceed this in shaped mode


def compute_reward(result: "VerificationResult", mode: str = "shaped") -> float:
    if not result.guard_ok:
        return 0.0
    if not result.parsed:
        return 0.0

    if mode == "binary":
        return 1.0 if (result.solved and result.static_ok) else 0.0

    func = _ratio(result.functional_pass, result.functional_total)
    sec = _ratio(result.security_pass, result.security_total)
    static = 1.0 if result.static_ok else 0.0
    fmt = 1.0 if result.format_ok else 0.0

    # Security and static credit count only as far as the code works: code
    # that does nothing (or rejects every input) is trivially "secure", and
    # paying for that made "safe but useless" a local optimum that training
    # converged to (code injection: reward up, solve rate stuck at 0%).
    base = W_FUNC * func + (W_SEC * sec + W_STATIC * static) * func + W_FORMAT * fmt
    if result.solved and result.static_ok:
        return 1.0
    return round(min(base, UNSOLVED_CAP), 6)


def _ratio(num: int, den: int) -> float:
    return 1.0 if den == 0 else num / den
