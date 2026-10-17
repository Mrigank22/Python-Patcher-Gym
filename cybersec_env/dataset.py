"""Build train/test splits of repair tasks as a Hugging Face ``Dataset``.

Each row is model-agnostic and contains everything the trainer and grader need:

* ``prompt`` – conversational messages (system + user) so any chat model's
  template applies; the user turn holds the vulnerable function and the task.
* ``task_id`` – routes the completion to its grader (``family-difficulty-seed``).
* ``family``, ``cwe``, ``difficulty`` – for stratified evaluation.

Train and test use **disjoint seed ranges** per family, so the held-out set is
never seen during training (contamination control). The prompt text is
identical in shape to what the OpenEnv server serves, so a model trained via
the dataset path and one trained via the live environment see the same task.
"""

from __future__ import annotations

from typing import List, Optional

from .tasks import family_names, generate, get_family
from .tasks.imported import imported_sources, records

SYSTEM_PROMPT = (
    "You are a secure-coding assistant. You are given a Python function that "
    "contains a security vulnerability. Rewrite the function so that it is "
    "secure while preserving its documented behaviour. Reply with the complete "
    "fixed function inside a single ```python code block and nothing else."
)


def make_row(task_id_family: str, seed: int, difficulty: int) -> dict:
    return _row(get_family(task_id_family).generate(seed=seed, difficulty=difficulty))


def _row(inst) -> dict:
    return {
        "prompt": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": inst.user_prompt()},
        ],
        "task_id": inst.task_id,
        "family": inst.family,
        "cwe": inst.cwe,
        "difficulty": inst.difficulty,
        "entrypoint": inst.entrypoint,
    }


def _rows(families: List[str], seeds, difficulties) -> List[dict]:
    rows = []
    for fam in families:
        for d in difficulties:
            for s in seeds:
                rows.append(make_row(fam, s, d))
    return rows


def build_dataset(
    n_train_per_family: int = 48,
    n_test_per_family: int = 16,
    difficulties=(1,),
    families: Optional[List[str]] = None,
    seed_offset: int = 0,
    sources: Optional[List[str]] = None,
):
    """Return a ``datasets.DatasetDict`` with ``train`` and ``test`` splits.

    ``families`` selects procedural families (``None`` = all, ``[]`` = none).
    ``sources`` adds validated imported benchmarks (e.g. ``["cweval"]``); each
    record goes to the split its importer assigned.
    """
    from datasets import Dataset, DatasetDict

    families = family_names() if families is None else families
    train_seeds = range(seed_offset, seed_offset + n_train_per_family)
    test_seeds = range(
        seed_offset + 100_000, seed_offset + 100_000 + n_test_per_family
    )  # disjoint, far from train

    train = _rows(families, train_seeds, difficulties)
    test = _rows(families, test_seeds, difficulties)
    for src in sources or []:
        if src not in imported_sources():
            raise KeyError(f"unknown imported source '{src}'. known: {imported_sources()}")
        for i, rec in enumerate(records(src)):
            (train if rec.get("split") == "train" else test).append(_row(generate(f"{src}-1-{i}")))
    return DatasetDict(
        train=Dataset.from_list(train),
        test=Dataset.from_list(test),
    )
