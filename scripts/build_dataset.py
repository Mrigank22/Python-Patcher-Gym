"""Materialise the task dataset to disk and print a summary.

    python scripts/build_dataset.py --out data/secure_code --train 48 --test 16

Saves a Hugging Face ``DatasetDict`` (``save_to_disk``) you can reload with
``datasets.load_from_disk`` and, optionally, push to the Hub as an
``rl-environment``-tagged dataset repo.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cybersec_env.dataset import build_dataset  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/secure_code")
    ap.add_argument("--train", type=int, default=48, help="train tasks per family")
    ap.add_argument("--test", type=int, default=16, help="test tasks per family")
    ap.add_argument("--difficulties", default="1", help="comma-separated ints")
    ap.add_argument("--families", default=None, help="comma-separated names (default: all)")
    args = ap.parse_args()

    difficulties = tuple(int(x) for x in args.difficulties.split(","))
    families = args.families.split(",") if args.families else None

    ds = build_dataset(
        n_train_per_family=args.train,
        n_test_per_family=args.test,
        difficulties=difficulties,
        families=families,
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    ds.save_to_disk(str(out))

    for split in ("train", "test"):
        c = Counter(ds[split]["cwe"])
        print(f"[{split}] {len(ds[split])} rows | CWE: {dict(sorted(c.items()))}")
    print(f"[done] saved to {out}  (reload: datasets.load_from_disk('{out}'))")
    print("example prompt:\n" + ds["train"][0]["prompt"][1]["content"][:400])


if __name__ == "__main__":
    main()
