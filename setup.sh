#!/usr/bin/env bash
# One-command environment bootstrap for Python-Patcher-Gym.
#
# Recreates the exact environment on any Linux box (CPU for data/grader work,
# GPU for training) so that only the training command is left to run. Safe to
# re-run. Does NOT need the chat history — the repo, REPORT.md and HANDOFF.md
# carry all the state.
#
#   git clone <repo> && cd Python-Patcher-Gym && bash setup.sh
#   # then, on a GPU box:
#   source ~/envs/pgym/bin/activate   # or use ~/envs/pgym/bin/python directly
#   python scripts/train_grpo.py --config configs/final_coder15_mixed.yaml --no-eval
#
set -euo pipefail
ENV_DIR="${PGYM_ENV:-$HOME/envs/pgym}"
PY="${PGYM_PY:-3.12}"
cd "$(dirname "$0")"

echo "== 1. uv (standalone Python/venv manager) =="
if ! command -v uv >/dev/null 2>&1 && [ ! -x "$HOME/.local/bin/uv" ]; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi
UV="$(command -v uv || echo "$HOME/.local/bin/uv")"

echo "== 2. venv at $ENV_DIR (Python $PY) =="
"$UV" venv -p "$PY" "$ENV_DIR"
PYBIN="$ENV_DIR/bin/python"

echo "== 3. runtime + grader + training deps =="
"$UV" pip install -q -p "$PYBIN" \
  "openenv>=0.9.0" pydantic pyyaml fastapi uvicorn pytest lxml PyJWT argon2-cffi \
  bandit matplotlib requests datasets

echo "== 4. GPU check / PyTorch =="
if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; then
  echo "   GPU detected -> installing CUDA PyTorch + training stack"
  "$UV" pip install -q -p "$PYBIN" torch --index-url https://download.pytorch.org/whl/cu124
  "$UV" pip install -q -p "$PYBIN" "trl>=1.16" "transformers>=5" "peft>=0.21" "accelerate>=1"
else
  echo "   No GPU here. Skipping torch/trl (install on the GPU box):"
  echo "     $PYBIN -m pip install torch --index-url https://download.pytorch.org/whl/cu124"
  echo "     $PYBIN -m pip install 'trl>=1.16' 'transformers>=5' 'peft>=0.21' 'accelerate>=1'"
fi

echo "== 5. bubblewrap (grader OS jail; optional but recommended) =="
if command -v bwrap >/dev/null 2>&1; then
  echo "   bwrap present"
elif command -v apt-get >/dev/null 2>&1; then
  sudo apt-get install -y -q bubblewrap || \
    echo "   could not install bwrap (need sudo); grader falls back to process-only"
fi

echo "== 6. smoke test =="
PYTHONPATH="$PWD" "$PYBIN" -c "from cybersec_env import sandbox; print('grader isolation:', sandbox.isolation_level())"
echo "   running the fast reward-hack regression tests ..."
PYTHONPATH="$PWD" "$PYBIN" -m pytest -q tests/test_reward_hacks.py >/dev/null && echo "   reward-hack tests PASS"

cat <<EOF

Setup complete. Interpreter: $PYBIN

Next (on a GPU box):
  PYTHONPATH="$PWD" "$PYBIN" scripts/train_grpo.py --config configs/final_coder15_mixed.yaml --no-eval

Data/grader work needs no GPU:
  PYTHONPATH="$PWD" "$PYBIN" scripts/hack_audit.py --seeds 3
  PYTHONPATH="$PWD" "$PYBIN" scripts/harvest_codebase.py --triage-batch 200   # grow the codebase dataset
EOF
