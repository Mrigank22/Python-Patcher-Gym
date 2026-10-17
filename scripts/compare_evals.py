"""Paired before/after comparison of two ``scripts/evaluate.py`` runs.

Both runs must cover the same held-out prompts. Each prompt contributes its
pass@1 (mean solved rate over its k samples) for base and trained, and the
script reports the paired difference with a bootstrap 95% CI and a two-sided
sign-flip permutation p-value, overall and per CWE.

    python scripts/compare_evals.py results/eval_base.json results/eval_trained.json \\
        --out results/compare.md
"""

from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path


def _load(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data, {r["task_id"]: r for r in data["rows"]}


def _paired_stats(diffs, iters=10_000, seed=0):
    rng = random.Random(seed)
    n = len(diffs)
    mean = sum(diffs) / n
    boots = sorted(sum(rng.choice(diffs) for _ in range(n)) / n for _ in range(iters))
    lo, hi = boots[int(0.025 * iters)], boots[int(0.975 * iters) - 1]
    extreme = 0
    for _ in range(iters):
        m = sum(d if rng.random() < 0.5 else -d for d in diffs) / n
        extreme += abs(m) >= abs(mean) - 1e-12
    return mean, lo, hi, (extreme + 1) / (iters + 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("trained")
    ap.add_argument("--out", default=None, help="write a markdown table here")
    args = ap.parse_args()

    base, brows = _load(args.base)
    trained, trows = _load(args.trained)
    common = sorted(set(brows) & set(trows))
    if not common:
        raise SystemExit("no prompts in common")

    groups = defaultdict(list)
    for tid in common:
        d = trows[tid]["pass@1"] - brows[tid]["pass@1"]
        groups["ALL"].append((brows[tid]["pass@1"], trows[tid]["pass@1"], d))
        groups[brows[tid]["cwe"]].append((brows[tid]["pass@1"], trows[tid]["pass@1"], d))

    lines = [
        f"Paired comparison on {len(common)} held-out prompts "
        f"(k={base.get('k')} samples each)",
        "",
        "| Slice | n | Base pass@1 | Trained pass@1 | Change | 95% CI | p |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    summary = {}
    for name in ["ALL"] + sorted(k for k in groups if k != "ALL"):
        rows = groups[name]
        b = sum(r[0] for r in rows) / len(rows)
        t = sum(r[1] for r in rows) / len(rows)
        mean, lo, hi, p = _paired_stats([r[2] for r in rows])
        summary[name] = {"n": len(rows), "base": b, "trained": t, "diff": mean,
                         "ci95": [lo, hi], "p": p}
        lines.append(f"| {name} | {len(rows)} | {b:.3f} | {t:.3f} | {mean:+.3f} | "
                     f"[{lo:+.3f}, {hi:+.3f}] | {p:.4f} |")

    extra = [
        "",
        f"pass@{base.get('k')}: base {base['pass_at_k']:.3f} -> trained {trained['pass_at_k']:.3f}",
        f"functional rate: base {base['functional_rate']:.3f} -> trained {trained['functional_rate']:.3f}",
        f"security rate:   base {base['security_rate']:.3f} -> trained {trained['security_rate']:.3f}",
        f"guard-block rate: base {base['guard_block_rate']:.3f} -> trained {trained['guard_block_rate']:.3f}",
    ]
    text = "\n".join(lines + extra)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        Path(args.out).with_suffix(".json").write_text(json.dumps(summary, indent=2),
                                                       encoding="utf-8")
        print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
