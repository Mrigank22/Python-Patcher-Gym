"""CyberSec Env — an RL environment for training LLMs to repair insecure code.

Public surface:

* :class:`~cybersec_env.verifier.Verifier` / ``VerificationResult`` — the
  framework-free grader.
* :mod:`cybersec_env.tasks` — procedural vulnerability task families + registry.
* :func:`cybersec_env.dataset.build_dataset` — materialise train/test splits.
* :class:`~cybersec_env.environment.SecureCodeEnv` /
  ``SecureCodeAction`` / ``SecureCodeObservation`` — the OpenEnv environment.
"""

from .verifier import VerificationResult, Verifier

__version__ = "0.1.0"
__all__ = ["Verifier", "VerificationResult", "__version__"]
