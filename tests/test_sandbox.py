"""Grader isolation: nothing a candidate does may outlive its own grading."""

import glob
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cybersec_env.tasks import get_family
from cybersec_env.verifier import Verifier

VERIFIER = Verifier(timeout_s=15.0, reward_mode="shaped")


def _temp_dirs(prefix):
    return set(glob.glob(os.path.join(tempfile.gettempdir(), prefix + "*")))


def test_relative_writes_stay_in_sandbox_and_are_removed():
    inst = get_family("weak_hash").generate(seed=3, difficulty=1)
    src = "open('leftover.bin', 'wb').write(b'x')\n" + inst.reference_code
    before = _temp_dirs("cse_cand_")
    res = VERIFIER.grade_source(inst.task_id, src)
    assert res.solved  # writing inside the sandbox is allowed
    assert not (ROOT / "leftover.bin").exists()
    assert not Path("leftover.bin").exists()
    assert _temp_dirs("cse_cand_") == before


def test_writes_outside_sandbox_are_blocked(tmp_path):
    target = tmp_path / "outside.txt"
    inst = get_family("xss").generate(seed=3, difficulty=1)
    src = f"open({str(target)!r}, 'w').write('x')\n" + inst.reference_code
    res = VERIFIER.grade_source(inst.task_id, src)
    assert not target.exists()
    assert not res.solved
    assert "load_error" in res.error


def test_probe_temp_files_are_cleaned_up():
    inst = get_family("path_traversal").generate(seed=3, difficulty=1)
    before = _temp_dirs("cse_base_") | _temp_dirs("cse_secret_")
    res = VERIFIER.grade_source(inst.task_id, inst.reference_code)
    assert res.solved
    assert (_temp_dirs("cse_base_") | _temp_dirs("cse_secret_")) == before


def test_candidate_stdout_is_ignored():
    inst = get_family("sqli").generate(seed=3, difficulty=1)
    src = f"print('{{\"ok\": true}}')\ndef {inst.entrypoint}(conn, username):\n    return None\n"
    res = VERIFIER.grade_source(inst.task_id, src)
    assert not res.solved
    assert res.functional_pass == 0


def test_early_exit_counts_as_failure():
    inst = get_family("ssrf").generate(seed=3, difficulty=1)
    src = f"def {inst.entrypoint}(url, allowed_hosts):\n    raise SystemExit(0)\n"
    res = VERIFIER.grade_source(inst.task_id, src)
    assert not res.solved
    assert res.parsed  # the worker survived and reported a verdict
    assert res.functional_pass == 0
