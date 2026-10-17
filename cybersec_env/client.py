"""Typed OpenEnv client for the secure-code-repair environment."""

from __future__ import annotations

from typing import Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

from .models import SecureCodeAction, SecureCodeObservation


class SecureCodeClient(EnvClient[SecureCodeAction, SecureCodeObservation, State]):
    """Client that holds a WebSocket session to a running ``SecureCodeEnv``.

    Example:
        >>> with SecureCodeClient(base_url="http://localhost:8000").sync() as c:
        ...     r = c.reset()
        ...     print(r.observation.prompt)
        ...     r = c.step(SecureCodeAction(code="```python\\n...\\n```"))
        ...     print(r.reward, r.observation.solved)
    """

    def _step_payload(self, action: SecureCodeAction) -> Dict:
        return {"code": action.code}

    def _parse_result(self, payload: Dict) -> StepResult[SecureCodeObservation]:
        obs_data = payload.get("observation", {})
        observation = SecureCodeObservation(**{
            k: obs_data[k] for k in obs_data if k in SecureCodeObservation.model_fields
        })
        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
            metadata=payload.get("metadata"),
        )

    def _parse_state(self, payload: Dict) -> State:
        return State(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
        )
