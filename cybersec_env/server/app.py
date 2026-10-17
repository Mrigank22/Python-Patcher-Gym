"""FastAPI app exposing ``SecureCodeEnv`` over HTTP/WebSocket (OpenEnv).

Run locally::

    python -m cybersec_env.server.app --port 8000
    # or
    uvicorn cybersec_env.server.app:app --host 0.0.0.0 --port 8000

Configuration via environment variables (all optional):

    CSE_FAMILIES      comma-separated family names (default: all)
    CSE_DIFFICULTIES  comma-separated ints (default: 1)
    CSE_REWARD_MODE   "shaped" | "binary" (default: shaped)
    CSE_TIMEOUT       grader wall-clock seconds (default: 8)
    CSE_SEED_POOL     number of seeds to sample from (default: 1000)
    CSE_MAX_SESSIONS  concurrent websocket sessions (default: 8)
"""

from __future__ import annotations

import os

from openenv.core.env_server.http_server import create_app

from cybersec_env.environment import SecureCodeEnv
from cybersec_env.models import SecureCodeAction, SecureCodeObservation


def _cfg_list(name, default):
    raw = os.environ.get(name, "").strip()
    return [x.strip() for x in raw.split(",") if x.strip()] or default


def make_env() -> SecureCodeEnv:
    families = _cfg_list("CSE_FAMILIES", None)
    difficulties = tuple(int(x) for x in _cfg_list("CSE_DIFFICULTIES", ["1"]))
    return SecureCodeEnv(
        families=families,
        difficulties=difficulties,
        seed_pool=int(os.environ.get("CSE_SEED_POOL", "1000")),
        reward_mode=os.environ.get("CSE_REWARD_MODE", "shaped"),
        timeout_s=float(os.environ.get("CSE_TIMEOUT", "8")),
    )


app = create_app(
    make_env,
    SecureCodeAction,
    SecureCodeObservation,
    env_name="cybersec-secure-code-repair",
    max_concurrent_envs=int(os.environ.get("CSE_MAX_SESSIONS", "8")),
)


def main() -> None:
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(description="CyberSec secure-code-repair environment server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
