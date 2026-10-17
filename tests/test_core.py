"""Core grader tests: oracle passes, no-op fails, determinism, extraction."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cybersec_env.extract import extract_code
from cybersec_env.tasks import family_names, generate, get_family
from cybersec_env.verifier import Verifier

VERIFIER = Verifier(timeout_s=15.0, reward_mode="shaped")
FAMILIES = family_names()


@pytest.mark.parametrize("family", FAMILIES)
def test_oracle_solves(family):
    inst = get_family(family).generate(seed=11, difficulty=1)
    res = VERIFIER.grade_source(inst.task_id, inst.reference_code)
    assert res.solved, res.details
    assert res.reward == 1.0
    assert res.static_ok


@pytest.mark.parametrize("family", FAMILIES)
def test_vulnerable_seed_not_solved(family):
    inst = get_family(family).generate(seed=11, difficulty=1)
    res = VERIFIER.grade_source(inst.task_id, inst.prompt_code)
    assert not res.solved
    assert res.security_pass < res.security_total or res.security_total == 0


@pytest.mark.parametrize("family", FAMILIES)
def test_empty_candidate_scores_zero(family):
    inst = get_family(family).generate(seed=5, difficulty=1)
    res = VERIFIER.grade_source(inst.task_id, "")
    assert res.reward == 0.0


def test_determinism_same_seed():
    a = get_family("ssrf").generate(seed=3, difficulty=1)
    b = get_family("ssrf").generate(seed=3, difficulty=1)
    assert a.task_id == b.task_id
    assert a.prompt_code == b.prompt_code
    r1 = VERIFIER.grade_source(a.task_id, a.reference_code)
    r2 = VERIFIER.grade_source(b.task_id, b.reference_code)
    assert (r1.reward, r1.solved) == (r2.reward, r2.solved)


def test_different_seeds_differ():
    a = get_family("sqli").generate(seed=1, difficulty=1)
    b = get_family("sqli").generate(seed=2, difficulty=1)
    assert a.task_id != b.task_id


def test_regenerate_from_task_id():
    inst = get_family("xss").generate(seed=9, difficulty=1)
    again = generate(inst.task_id)
    assert again.task_id == inst.task_id
    assert again.reference_code == inst.reference_code


def test_extract_prefers_python_fence():
    out = extract_code("sure:\n```python\ndef f():\n    return 1\n```\ndone", "f")
    assert out.code.strip().startswith("def f()")
    assert out.format_ok


def test_extract_bare_code():
    out = extract_code("def f():\n    return 1", "f")
    assert "def f" in out.code
    assert not out.format_ok


def test_timeout_is_handled():
    # an infinite loop in the candidate must be killed and scored 0, not hang
    inst = get_family("ssrf").generate(seed=1, difficulty=1)
    src = (
        "def is_allowed_url(url, allowed_hosts):\n"
        "    while True:\n"
        "        pass\n"
    )
    v = Verifier(timeout_s=3.0, reward_mode="shaped")
    res = v.grade_source(inst.task_id, src)
    assert not res.solved
    assert res.reward < 1.0
