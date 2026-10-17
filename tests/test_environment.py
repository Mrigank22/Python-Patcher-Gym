"""OpenEnv environment + reward-function integration tests (no network/model)."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cybersec_env.environment import SecureCodeEnv
from cybersec_env.models import SecureCodeAction
from cybersec_env.tasks import get_family
from cybersec_env.trl_reward import SecureCodeReward


def test_env_reset_and_step_oracle():
    env = SecureCodeEnv(reward_mode="shaped", timeout_s=15)
    obs = env.reset(task_id="weak_hash-1-4")
    assert obs.task_id == "weak_hash-1-4"
    assert "function" in obs.prompt
    inst = get_family("weak_hash").generate(seed=4, difficulty=1)
    step = env.step(SecureCodeAction(code="```python\n" + inst.reference_code + "\n```"))
    assert step.done is True
    assert step.solved is True
    assert step.reward == 1.0


def test_env_step_junk_is_safe():
    env = SecureCodeEnv(timeout_s=15)
    env.reset(task_id="sqli-1-1")
    step = env.step(SecureCodeAction(code="this is not python"))
    assert step.reward == 0.0
    assert step.solved is False


def test_trl_reward_batch():
    reward = SecureCodeReward(reward_mode="shaped", timeout_s=15, max_workers=4)
    insts = [get_family(f).generate(seed=2, difficulty=1) for f in ("sqli", "xss")]
    task_ids = [i.task_id for i in insts]
    # one oracle (solved -> 1.0) and one empty (-> 0.0)
    completions = [
        "```python\n" + insts[0].reference_code + "\n```",
        "```python\n\n```",
    ]
    rewards = reward(prompts=None, completions=completions, task_id=task_ids)
    assert rewards[0] == 1.0
    assert rewards[1] == 0.0
    assert reward.last_stats["n"] == 2


def test_trl_reward_handles_chat_completion_format():
    reward = SecureCodeReward(timeout_s=15, max_workers=2)
    inst = get_family("ssrf").generate(seed=2, difficulty=1)
    completions = [[{"role": "assistant", "content": "```python\n" + inst.reference_code + "\n```"}]]
    rewards = reward(prompts=None, completions=completions, task_id=[inst.task_id])
    assert rewards[0] == 1.0
