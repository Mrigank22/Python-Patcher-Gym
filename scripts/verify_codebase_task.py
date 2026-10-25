"""Stage 3 driver: verify task specs with the production container grader.

Thin wrapper over :class:`cybersec_env.codebase.grader.CodebaseGrader`, which is
the single source of truth for building the image, proving fail-to-pass, and
grading candidate patches (so training, evaluation and dataset-QA all agree).

For each spec it confirms the gold patch is fail-to-pass, captures the exact
fail-to-pass / pass-to-pass test node ids, and — when verified — writes an
enriched spec (with ``f2p_tests``, ``p2p_tests``, ``test_files``, ``python``)
to ``data/codebase/verified/``. Those are the trainable/evaluable tasks.

Usage::

    python scripts/verify_codebase_task.py              # all specs
    python scripts/verify_codebase_task.py --ids GHSA-... --limit 10
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
SPECS = ROOT / "data" / "codebase" / "specs"
VERIFIED = ROOT / "data" / "codebase" / "verified"
# Verified specs are the dataset itself (tens of KB each), so they are also kept
# in a git-tracked folder; everything else under data/ is rebuildable scratch.
TRACKED = ROOT / "cybersec_env" / "data" / "codebase_tasks"

from cybersec_env.codebase.grader import CodebaseGrader  # noqa: E402


def _safe(advisory_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", advisory_id)


def verify_and_save(spec: dict, grader: CodebaseGrader) -> dict:
    v = grader.verify(spec)
    if v.get("verdict") == "verified":
        spec = dict(spec)
        spec.update({
            "verified": True,
            "f2p_tests": v["f2p_tests"],
            "p2p_tests": v["p2p_tests"],
            "test_files": v["test_files"],
            "python": grader._py(spec),
            "n_before_pass": v.get("n_before_pass"),
            "n_after_pass": v.get("n_after_pass"),
            "stability": v.get("stability"),
            "pip_freeze": v.get("pip_freeze"),
        })
        for d in (VERIFIED, TRACKED):
            d.mkdir(parents=True, exist_ok=True)
            path = d / f"{_safe(spec['id'])}.json"
            # Re-verifying must not drop fields other tools added (e.g. the
            # human-written ``reference`` from enrich_codebase_tasks.py).
            if path.exists():
                try:
                    old = json.loads(path.read_text(encoding="utf-8"))
                    for k in ("reference",):
                        if k in old and k not in spec:
                            spec[k] = old[k]
                except (json.JSONDecodeError, OSError):
                    pass
            path.write_text(json.dumps(spec, indent=2, ensure_ascii=False),
                            encoding="utf-8", newline="\n")
    return v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids", default=None)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    paths = sorted(SPECS.glob("*.json"))
    if args.ids:
        want = set(args.ids.split(","))
        paths = [p for p in paths if json.loads(p.read_text())["id"] in want]
    if args.limit:
        paths = paths[: args.limit]

    grader = CodebaseGrader()
    tally = collections.Counter()
    for p in paths:
        spec = json.loads(p.read_text())
        v = verify_and_save(spec, grader)
        tally[v.get("verdict", "error")] += 1
        extra = ""
        if "f2p_tests" in v:
            extra = f"  f2p={len(v['f2p_tests'])} p2p={len(v['p2p_tests'])}"
        print(f"{v.get('verdict','error'):18s} {spec['id']:30s}{extra}")

    print("\n=== verification tally ===")
    for k, n in tally.most_common():
        print(f"  {k:20s} {n}")
    nver = tally["verified"]
    print(f"\nverified: {nver}/{len(paths)} ({nver/max(len(paths),1):.0%}); specs in {VERIFIED}")


if __name__ == "__main__":
    main()
