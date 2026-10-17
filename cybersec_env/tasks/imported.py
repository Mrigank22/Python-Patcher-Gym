"""Tasks imported from public secure-coding benchmarks (CWEval, SecCodePLT, ...).

Each source is a JSONL file under ``cybersec_env/data/imported/`` written by an
importer script (``scripts/import_cweval.py``, ...). A record carries the
vulnerable seed shown to the model, the reference fix, and the benchmark's own
pytest module. The grader worker runs that module against the candidate inside
the sandbox, so imported tasks get the same isolation, guard and reward shaping
as the procedural families.

Importers only keep records that pass validation in this grader: the
reference fix solves the task, the vulnerable seed does not, and an empty stub
does not. Task ids follow the procedural scheme, ``<source>-1-<index>``.
"""

from __future__ import annotations

import functools
import json
from pathlib import Path
from typing import List, Tuple

from .base import Probe, TaskInstance

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "imported"


def _never_called(_cand) -> bool:  # pragma: no cover - pytest tasks don't call probes
    raise RuntimeError("imported tasks are graded by their pytest module")


@functools.lru_cache(maxsize=None)
def records(source: str) -> Tuple[dict, ...]:
    path = DATA_DIR / f"{source}.jsonl"
    if not path.is_file():
        return ()
    lines = path.read_text(encoding="utf-8").splitlines()
    return tuple(json.loads(line) for line in lines if line.strip())


def imported_sources() -> List[str]:
    return sorted(p.stem for p in DATA_DIR.glob("*.jsonl")) if DATA_DIR.is_dir() else []


def build(source: str, index: int) -> TaskInstance:
    rec = records(source)[index]
    return TaskInstance(
        task_id=f"{source}-1-{index}",
        family=source,
        cwe=rec["cwe"],
        title=rec["title"],
        entrypoint=rec["entrypoint"],
        prompt_code=rec["prompt_code"],
        reference_code=rec["reference_code"],
        instruction=rec["instruction"],
        # One placeholder probe per pytest case, named by its node id, so the
        # verifier's pass/total bookkeeping works unchanged.
        functional_probes=[Probe(n, _never_called) for n in rec.get("functional_tests", [])],
        security_probes=[Probe(n, _never_called, "security") for n in rec.get("security_tests", [])],
        metadata={
            "pytest": {"module": rec["task_module"], "test_code": rec["test_code"],
                       "test_func": rec["test_func"], "context": rec.get("context_code", "")},
            "source": source,
            "origin_id": rec["origin_id"],
            "license": rec["license"],
            "split": rec.get("split", "test"),
        },
    )
