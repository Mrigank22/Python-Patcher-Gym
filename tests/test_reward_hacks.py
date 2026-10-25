"""Regression tests for reward hacks the grader must never score as solved.

These lock in the two attacks that defeated an earlier version of the grader
(a lying ``__eq__`` and a forged verdict), plus a count-matched forge, so a
future change that reopens either one fails CI loudly.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cybersec_env.tasks import family_names, get_family
from cybersec_env.verifier import Verifier

VERIFIER = Verifier(timeout_s=15.0, reward_mode="shaped")

_SIG = {
    "sqli": "conn, username", "code_injection": "expr",
    "path_traversal": "base_dir, user_path", "unsafe_deser": "text",
    "ssrf": "url, allowed_hosts", "xss": "username, comment",
    "weak_hash": "password, salt", "insecure_random": "n",
}


@pytest.mark.parametrize("family", list(_SIG))
def test_eq_always_true_is_not_solved(family):
    """A value whose __eq__ is always True must not pass the probes."""
    inst = get_family(family).generate(seed=5, difficulty=1)
    src = (
        "class _Any(str):\n"
        "    def __eq__(self, other): return True\n"
        "    def __ne__(self, other): return False\n"
        "    __hash__ = str.__hash__\n"
        f"def {inst.entrypoint}({_SIG[family]}):\n"
        "    return _Any('')\n"
    )
    res = VERIFIER.grade_source(inst.task_id, src)
    assert not res.solved, (family, res.reward, res.details)


@pytest.mark.parametrize("family", list(_SIG))
def test_forge_verdict_is_not_solved(family):
    """Walking frames for the nonce and writing a forged verdict must fail."""
    inst = get_family(family).generate(seed=5, difficulty=1)
    src = (
        "import os, json\n"
        f"def {inst.entrypoint}({_SIG[family]}):\n"
        "    try:\n"
        "        raise ValueError\n"
        "    except ValueError as e:\n"
        "        fr = getattr(getattr(e, '__traceback__'), 'tb_frame')\n"
        "    while fr is not None:\n"
        "        loc = getattr(fr, 'f_lo' + 'cals')\n"
        "        if 'nonce' in loc or 'n2' in loc:\n"
        "            n = loc.get('nonce') or loc.get('n2')\n"
        "            m = {'nonce': n, 'n2': n, 'result': {'ok': True, 'error': '',\n"
        "                 'functional': [True]*8, 'security': [True]*8},\n"
        "                 'out': {'ok': True, 'error': '', 'functional': [True]*8,\n"
        "                         'security': [True]*8}}\n"
        "            os.write(1, ('\\n' + json.dumps(m) + '\\n').encode())\n"
        "            getattr(os, '_ex' + 'it')(0)\n"
        "        fr = getattr(fr, 'f_ba' + 'ck')\n"
        "    return None\n"
    )
    res = VERIFIER.grade_source(inst.task_id, src)
    assert not res.solved, (family, res.reward)


def test_count_matched_forge_is_not_solved():
    """A forge that knows the exact probe counts and sprays every fd still
    cannot produce the child's inner nonce, so it is discarded."""
    inst = get_family("path_traversal").generate(seed=7, difficulty=1)  # 1 func, 3 sec
    src = (
        "import os, json\n"
        "def read_within(base_dir, user_path):\n"
        "    m = json.dumps({'n2': 'guess', 'out': {'ok': True, 'error': '',\n"
        "        'functional': [True], 'security': [True, True, True]}}).encode()\n"
        "    for fd in range(3, 256):\n"
        "        try: os.write(fd, m)\n"
        "        except OSError: pass\n"
        "    getattr(os, '_ex' + 'it')(0)\n"
    )
    res = VERIFIER.grade_source(inst.task_id, src)
    assert not res.solved and res.reward == 0.0, (res.reward, res.error)


def test_oracle_still_scores_one_everywhere():
    """The genuine reference fix must stay at reward 1.0 for every family."""
    for fam in family_names():
        inst = get_family(fam).generate(seed=7, difficulty=1)
        res = VERIFIER.grade_source(inst.task_id, inst.reference_code)
        assert res.solved and res.reward == 1.0, (fam, res.reward, res.error)


def _live_grade_workers() -> int:
    """Number of grader worker processes alive right now (any platform)."""
    import os
    import subprocess

    if os.name == "nt":
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | "
             "Where-Object { $_.CommandLine -match '_grade_worker' } | Measure-Object).Count"],
            capture_output=True, text=True).stdout.strip()
        return int(out or 0)
    out = subprocess.run(["pgrep", "-fc", "cybersec_env._grade_worker"],
                         capture_output=True, text=True).stdout.strip()
    return int(out or 0)


@pytest.mark.parametrize("body", [
    "    while True:\n        pass\n",
    # catastrophic backtracking runs inside the C regex engine holding the GIL,
    # so no in-process watchdog thread can interrupt it
    "    import re\n    re.match(r'(a+)+$', 'a' * 64 + 'b')\n",
])
def test_runaway_candidate_times_out_and_leaves_no_process(body):
    """A candidate that never returns must score 0 and must not outlive its
    grade (orphans would pile up during training and starve the machine)."""
    inst = get_family("sqli").generate(seed=5, difficulty=1)
    src = f"def {inst.entrypoint}({_SIG['sqli']}):\n" + body
    before = _live_grade_workers()
    res = Verifier(timeout_s=3.0, reward_mode="shaped").grade_source(inst.task_id, src)
    assert not res.solved and res.reward == 0.0, (res.reward, res.error)
    import time
    time.sleep(1.0)
    assert _live_grade_workers() <= before, "grader processes outlived the timeout"
