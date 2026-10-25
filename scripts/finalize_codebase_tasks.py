"""Backfill flakiness re-runs and frozen dependencies for verified tasks.

Tasks verified before ``CodebaseGrader.verify`` gained re-runs and ``pip
freeze`` lack the ``stability`` and ``pip_freeze`` fields. This re-verifies
each such task once (a fresh build, then 3 before/after runs) and:

* still verified -> rewritten with stable ``f2p_tests`` / ``p2p_tests``,
  ``stability`` and ``pip_freeze`` (the ``reference`` field is preserved);
* flaky or no longer fail-to-pass -> moved to ``data/codebase/quarantine/``
  with the verdict recorded, never deleted.

Run it after the main verify pass, not alongside it: both need Docker and RAM.

    python scripts/finalize_codebase_tasks.py --workers 6
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from cybersec_env.codebase.grader import CodebaseGrader  # noqa: E402
from verify_codebase_task import TRACKED, VERIFIED, verify_and_save  # noqa: E402

QUARANTINE = ROOT / "data" / "codebase" / "quarantine"
_NET = ("fetch_failed", "build_net_error")


def finalize(path: Path, grader: CodebaseGrader) -> str:
    spec = json.loads(path.read_text(encoding="utf-8"))
    if spec.get("stability") and spec.get("pip_freeze"):
        return "already_done"
    v = {}
    for _ in range(3):  # network failures say nothing about the task
        v = verify_and_save(spec, grader)
        if v.get("verdict") not in _NET:
            break
    verdict = v.get("verdict", "error")
    if verdict == "verified" or verdict in _NET or verdict.startswith("error"):
        return verdict
    QUARANTINE.mkdir(parents=True, exist_ok=True)
    spec["verified"] = False
    spec["reverify"] = {k: v.get(k) for k in ("verdict", "stability", "n_before_pass",
                                              "n_after_pass", "n_before_run", "n_after_run")}
    (QUARANTINE / path.name).write_text(json.dumps(spec, indent=2, ensure_ascii=False),
                                        encoding="utf-8", newline="\n")
    for d in (TRACKED, VERIFIED):
        if (d / path.name).exists():
            os.remove(d / path.name)
    return verdict


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=6)
    args = ap.parse_args()
    grader = CodebaseGrader()
    paths = sorted(TRACKED.glob("*.json"))
    tally = collections.Counter()
    with ThreadPoolExecutor(args.workers) as ex:
        for path, verdict in zip(paths, ex.map(lambda p: finalize(p, grader), paths)):
            tally[verdict] += 1
            print(f"{verdict:18s} {path.stem}", flush=True)
    print("\n=== finalize tally ===")
    for k, n in tally.most_common():
        print(f"  {k:20s} {n}")


if __name__ == "__main__":
    main()
