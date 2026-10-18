"""Grow the codebase-track dataset: triage + verify in resumable batches.

One command that walks the advisory candidate index, turns each into a spec
(clone + patch split), and verifies fail-to-pass in Docker, keeping a ledger so
re-runs continue where they left off. Designed to run for hours in the
background on a CPU box (no GPU needed) and accumulate verified tasks.

  python scripts/harvest_codebase.py --triage-batch 300 --verify           # a batch
  python scripts/harvest_codebase.py --triage-batch 300 --verify --loop     # keep going

Coverage: candidates are drawn round-robin across eras (legacy / recent /
post_cutoff) and least-covered CWEs first, so the dataset spans the whole
history and the full vulnerability spectrum rather than clustering.

Ledger: ``data/codebase/ledger.json`` records each advisory's last status
(``spec_written`` / ``no_test_in_fix`` / ``verified`` / ``not_fail_to_pass`` /
``build_failed`` / ...), so nothing is reprocessed and progress is visible.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

CAND = ROOT / "cybersec_env" / "data" / "advisories" / "candidates.jsonl"
OUT = ROOT / "data" / "codebase"
SPECS = OUT / "specs"
LEDGER = OUT / "ledger.json"

from build_codebase_tasks import triage_one, _safe  # noqa: E402
from verify_codebase_task import verify_and_save  # noqa: E402
from cybersec_env.codebase.grader import CodebaseGrader  # noqa: E402


def load_ledger() -> dict:
    if LEDGER.exists():
        return json.loads(LEDGER.read_text())
    return {}


def save_ledger(led: dict):
    OUT.mkdir(parents=True, exist_ok=True)
    LEDGER.write_text(json.dumps(led, indent=2), encoding="utf-8")


def order_candidates(cands, ledger):
    """Unprocessed candidates, round-robin across eras, rare CWEs first."""
    done = set(ledger)
    pending = [c for c in cands if c["id"] not in done]
    cwe_count = collections.Counter()
    for cid, rec in ledger.items():
        if rec.get("status") == "verified":
            for c in rec.get("cwes", []):
                cwe_count[c] += 1
    by_era = collections.defaultdict(list)
    for c in pending:
        by_era[c.get("era", "unknown")].append(c)
    for era in by_era:
        by_era[era].sort(key=lambda c: min((cwe_count[x] for x in c.get("cwes", ["unknown"])),
                                           default=0))
    order, eras = [], ["recent", "post_cutoff", "legacy", "unknown"]
    idx = {e: 0 for e in eras}
    while any(idx[e] < len(by_era.get(e, [])) for e in eras):
        for e in eras:
            lst = by_era.get(e, [])
            if idx[e] < len(lst):
                order.append(lst[idx[e]])
                idx[e] += 1
    return order


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--triage-batch", type=int, default=200)
    ap.add_argument("--verify", action="store_true", help="Docker-verify specs written this batch")
    ap.add_argument("--loop", action="store_true", help="keep processing batches until exhausted")
    ap.add_argument("--max-verify", type=int, default=0, help="cap verifications per batch (0 = all)")
    args = ap.parse_args()

    cands = [json.loads(l) for l in open(CAND, encoding="utf-8") if l.strip()]
    grader = CodebaseGrader()

    while True:
        ledger = load_ledger()
        batch = order_candidates(cands, ledger)[: args.triage_batch]
        if not batch:
            print("no more candidates to process."); break
        print(f"\n== batch of {len(batch)} (ledger has {len(ledger)}) ==")
        newly_written = []
        for i, c in enumerate(batch, 1):
            try:
                res = triage_one(c)
            except Exception as exc:
                res = {"id": c["id"], "status": f"error:{type(exc).__name__}"}
            ledger[c["id"]] = {"status": res["status"], "cwes": c.get("cwes", []),
                               "era": c.get("era"), "ts": time.time()}
            if res["status"] == "spec_written":
                newly_written.append(c["id"])
            if i % 25 == 0:
                save_ledger(ledger)
                print(f"  triaged {i}/{len(batch)}")
        save_ledger(ledger)
        st = collections.Counter(v["status"] for v in ledger.values())
        print(f"  triage statuses so far: {dict(st)}")

        if args.verify and newly_written:
            to_verify = newly_written if not args.max_verify else newly_written[: args.max_verify]
            print(f"  verifying {len(to_verify)} new specs in Docker ...")
            for j, cid in enumerate(to_verify, 1):
                sp = SPECS / f"{_safe(cid)}.json"
                if not sp.exists():
                    continue
                v = verify_and_save(json.loads(sp.read_text()), grader)
                ledger[cid] = {**ledger[cid], "status": v.get("verdict", "verify_error")}
                if j % 5 == 0:
                    save_ledger(ledger)
                    print(f"    verified {j}/{len(to_verify)}")
            save_ledger(ledger)

        v_tally = collections.Counter(v["status"] for v in ledger.values())
        n_ver = v_tally.get("verified", 0)
        print(f"  VERIFIED tasks total: {n_ver}")
        if not args.loop:
            break

    ledger = load_ledger()
    final = collections.Counter(v["status"] for v in ledger.values())
    print("\n=== harvest summary ===")
    for k, n in final.most_common():
        print(f"  {k:20s} {n}")
    print(f"verified tasks in {OUT/'verified'}")


if __name__ == "__main__":
    main()
