"""Imported benchmark tasks: every kept record must still validate in the grader."""

import os
import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cybersec_env.dataset import build_dataset
from cybersec_env.tasks import generate
from cybersec_env.tasks.imported import imported_sources, records
from cybersec_env.verifier import Verifier

VERIFIER = Verifier(timeout_s=30.0, reward_mode="shaped")
# Every record was validated at import time; re-check a fixed sample per source
# (set CSE_FULL_IMPORT_TESTS=1 to re-check all of them, ~30 min).
_ALL = [f"{src}-1-{i}" for src in imported_sources() for i in range(len(records(src)))]
TASK_IDS = _ALL if os.environ.get("CSE_FULL_IMPORT_TESTS") else [
    f"{src}-1-{i}" for src in imported_sources()
    for i in sorted(random.Random(src).sample(range(len(records(src))), min(12, len(records(src)))))]

pytestmark = pytest.mark.skipif(not TASK_IDS, reason="no imported benchmark data")


@pytest.mark.parametrize("task_id", TASK_IDS)
def test_imported_reference_solves(task_id):
    inst = generate(task_id)
    res = VERIFIER.grade_source(task_id, inst.reference_code)
    assert res.solved, (inst.metadata["origin_id"], res.error, res.details)


@pytest.mark.parametrize("task_id", TASK_IDS)
def test_imported_vulnerable_seed_not_solved(task_id):
    inst = generate(task_id)
    res = VERIFIER.grade_source(task_id, inst.prompt_code)
    assert not res.solved, inst.metadata["origin_id"]


def test_imported_sources_join_the_dataset():
    src = imported_sources()[0]
    ds = build_dataset(n_train_per_family=0, n_test_per_family=0, families=[], sources=[src])
    n = len(ds["train"]) + len(ds["test"])
    assert n == len(records(src))
    assert set(ds["test"]["family"]) <= {src}
