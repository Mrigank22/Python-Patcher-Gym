"""Score a frontier Claude model on the held-out test sets.

Same tasks, prompts and grader as the 1.5B evaluation, so the numbers line up
with ``results/eval_hardened_{base,trained}_<set>.json`` task by task::

    python scripts/frontier_calibration.py --trial 2              # 2 tasks, standard API
    python scripts/frontier_calibration.py --batch --sets proc,spl,cweval
    python scripts/frontier_calibration.py --sets proc,spl,cweval # summary tables only

Sets: ``proc`` = the 200 procedural tasks (25 per CWE, difficulty 2),
``spl`` = SecCodePLT's 110 held-out tasks, ``cweval`` = CWEval's 16.

Spend is tracked in ``results/frontier/spend.json`` across runs and every call
is refused if it could push the total past ``--budget`` dollars. The API key is
read from ``ANTHROPIC_API_KEY`` (process, then the Windows user/system
environment) and is never printed or written anywhere.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cybersec_env.dataset import build_dataset  # noqa: E402
from cybersec_env.verifier import Verifier  # noqa: E402

MODEL = "claude-opus-5-5"
PRICE_IN, PRICE_OUT = 4.00, 20.00          # $ per million tokens (standard API)
BATCH_DISCOUNT = 0.5
MAX_TOKENS = 8000                          # thinking + answer; a fix needs ~1k
EFFORT = "medium"                          # Opus 5.5's default effort
OUT = ROOT / "results" / "frontier"
SPEND = OUT / "spend.json"


def rows_path(task_set: str) -> Path:
    return OUT / f"opus55_{task_set}_rows.json"


def api_key() -> str:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key and sys.platform == "win32":
        import winreg

        for hive, path in ((winreg.HKEY_CURRENT_USER, r"Environment"),
                           (winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")):
            try:
                with winreg.OpenKey(hive, path) as k:
                    key = winreg.QueryValueEx(k, "ANTHROPIC_API_KEY")[0]
                    break
            except OSError:
                continue
    if not key:
        sys.exit("ANTHROPIC_API_KEY is not set")
    return key


def load_tasks(task_set: str):
    """The exact held-out split each 1.5B eval in results/ was run on."""
    if task_set == "proc":
        ds = build_dataset(n_train_per_family=1, n_test_per_family=25, difficulties=(2,))
    else:
        src = {"spl": "seccodeplt", "cweval": "cweval"}[task_set]
        ds = build_dataset(n_train_per_family=1, n_test_per_family=16, families=[],
                           sources=[src])
    return list(ds["test"])


def cost(usage: dict, batch: bool) -> float:
    c = (usage["input_tokens"] * PRICE_IN + usage["output_tokens"] * PRICE_OUT) / 1e6
    return c * (BATCH_DISCOUNT if batch else 1.0)


def load(path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def save(path, obj):
    OUT.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    tmp.replace(path)


def params(row) -> dict:
    system, user = row["prompt"][0]["content"], row["prompt"][1]["content"]
    return dict(model=MODEL, max_tokens=MAX_TOKENS, system=system,
                messages=[{"role": "user", "content": user}],
                output_config={"effort": EFFORT})


def worst_case(rows, batch: bool) -> float:
    """Upper bound: every call uses all of max_tokens (input ~ 1 token / 3 chars)."""
    total = sum((len(r["prompt"][0]["content"]) + len(r["prompt"][1]["content"])) / 3 * PRICE_IN
                + MAX_TOKENS * PRICE_OUT for r in rows) / 1e6
    return total * (BATCH_DISCOUNT if batch else 1.0)


def record(rows, spend, row, msg, verifier, batch):
    text = "".join(b.text for b in msg.content if b.type == "text")
    usage = {"input_tokens": msg.usage.input_tokens, "output_tokens": msg.usage.output_tokens}
    res = verifier.grade_completion(row["task_id"], text)
    c = cost(usage, batch)
    spend["total_usd"] = round(spend.get("total_usd", 0.0) + c, 6)
    spend.setdefault("calls", []).append({"task_id": row["task_id"], "usd": round(c, 6),
                                          "batch": batch, **usage})
    rows[row["task_id"]] = {
        "task_id": row["task_id"], "cwe": row["cwe"], "solved": bool(res.solved),
        "functional": f"{res.functional_pass}/{res.functional_total}",
        "security": f"{res.security_pass}/{res.security_total}",
        "guard_ok": res.guard_ok, "error": res.error, "stop_reason": msg.stop_reason,
        "usage": usage, "usd": round(c, 6), "completion": text,
    }
    print(f"  {row['task_id']:24s} {row['cwe']:8s} solved={res.solved!s:5s} "
          f"func {res.functional_pass}/{res.functional_total} "
          f"sec {res.security_pass}/{res.security_total}  stop={msg.stop_reason} "
          f"in={usage['input_tokens']} out={usage['output_tokens']}  ${c:.4f}")


def run_trial(client, todo, n, budget, rows, spend, verifier, path):
    # One task from each of the first n CWEs, so the trial is not one CWE.
    seen, pick = set(), []
    for row in todo:
        if row["cwe"] not in seen:
            seen.add(row["cwe"])
            pick.append(row)
        if len(pick) == n:
            break
    if spend.get("total_usd", 0.0) + worst_case(pick, False) > budget:
        sys.exit("refusing: trial could exceed the budget")
    for row in pick:
        msg = client.messages.create(**params(row))
        record(rows, spend, row, msg, verifier, batch=False)
        save(path, rows); save(SPEND, spend)


def run_batch(client, todo, budget, rows, spend, verifier, path, task_set):
    from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
    from anthropic.types.messages.batch_create_params import Request

    # Send in chunks whose worst case fits the remaining budget; the real spend
    # of each chunk is recorded before the next one is sent.
    by_id = {r["task_id"]: r for r in todo}
    while True:
        todo = [r for r in todo if r["task_id"] not in rows]
        batch_id = spend.get("open_batch", {}).get(task_set)
        if not todo and not batch_id:
            print(f"[{task_set}] nothing left to run"); return
        if not batch_id:
            left = budget - spend.get("total_usd", 0.0)
            chunk = []
            for r in todo:
                if worst_case(chunk + [r], True) > left:
                    break
                chunk.append(r)
            if not chunk:
                sys.exit(f"refusing: ${left:.2f} left is not enough for one more call")
            batch = client.messages.batches.create(requests=[
                Request(custom_id=r["task_id"], params=MessageCreateParamsNonStreaming(**params(r)))
                for r in chunk])
            batch_id = batch.id
            spend.setdefault("open_batch", {})[task_set] = batch_id
            save(SPEND, spend)
            print(f"[{task_set}] batch {batch_id}: {len(chunk)} requests "
                  f"(worst case ${worst_case(chunk, True):.2f})", flush=True)
        while True:
            b = client.messages.batches.retrieve(batch_id)
            if b.processing_status == "ended":
                break
            print(f"  {b.processing_status}: {b.request_counts.processing} processing", flush=True)
            time.sleep(60)
        for res in client.messages.batches.results(batch_id):
            row = by_id.get(res.custom_id)
            if row is None or res.custom_id in rows:
                continue
            if res.result.type == "succeeded":
                record(rows, spend, row, res.result.message, verifier, batch=True)
            else:
                print(f"  {res.custom_id}: {res.result.type}")
        spend.get("open_batch", {}).pop(task_set, None)
        save(path, rows); save(SPEND, spend)
        if any(r["task_id"] not in rows for r in todo) and all(
                r["task_id"] not in rows for r in todo[:1]):
            sys.exit(f"[{task_set}] batch returned no results for pending tasks; stopping")


def report(rows, tasks, task_set):
    """Opus vs the 1.5B base/trained on exactly the tasks Opus has answered."""
    def per_task(name):
        p = ROOT / "results" / f"eval_hardened_{name}_{task_set}.json"
        return {r["task_id"]: r["pass@1"] for r in load(p, {"rows": []})["rows"]}

    base, trained = per_task("base"), per_task("trained")
    done = [t for t in tasks if t["task_id"] in rows]
    by = defaultdict(lambda: [0, 0.0, 0.0, 0.0])
    for t in done:
        d = by[t["cwe"]]
        d[0] += 1
        d[1] += base.get(t["task_id"], 0.0)
        d[2] += trained.get(t["task_id"], 0.0)
        d[3] += rows[t["task_id"]]["solved"]
    lines = [f"[{task_set}]",
             "| CWE | n | Qwen 1.5B base | Qwen 1.5B + RL | Claude Opus 5.5 |",
             "| --- | --- | --- | --- | --- |"]
    tot = [0, 0.0, 0.0, 0.0]
    for cwe in sorted(by):
        n, b, tr, o = by[cwe]
        lines.append(f"| {cwe} | {n} | {b/n:.2f} | {tr/n:.2f} | {o/n:.2f} |")
        tot = [tot[0] + n, tot[1] + b, tot[2] + tr, tot[3] + o]
    if tot[0]:
        n = tot[0]
        lines.append(f"| **ALL** | {n} | {tot[1]/n:.3f} | {tot[2]/n:.3f} | {tot[3]/n:.3f} |")
    print("\n".join(lines))
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trial", type=int, default=0, help="run N tasks on the standard API")
    ap.add_argument("--batch", action="store_true", help="run all remaining tasks as one batch")
    ap.add_argument("--sets", default="proc", help="comma list of proc, spl, cweval")
    ap.add_argument("--budget", type=float, default=8.0, help="hard cap on total spend, $")
    args = ap.parse_args()

    spend = load(SPEND, {})
    client = verifier = None
    if args.trial or args.batch:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key(), max_retries=3)
        verifier = Verifier(timeout_s=8.0, reward_mode="shaped")

    for task_set in args.sets.split(","):
        path = rows_path(task_set)
        tasks, rows = load_tasks(task_set), load(path, {})
        todo = [t for t in tasks if t["task_id"] not in rows]
        print(f"[{task_set}] {len(tasks)} tasks, {len(rows)} done, "
              f"spent so far ${spend.get('total_usd', 0):.4f}")
        if args.trial:
            run_trial(client, todo, args.trial, args.budget, rows, spend, verifier, path)
        if args.batch:
            run_batch(client, todo, args.budget, rows, spend, verifier, path, task_set)
        if rows:
            table = report(rows, tasks, task_set)
            (OUT / f"opus55_{task_set}_summary.md").write_text(table + "\n", encoding="utf-8")
    print(f"total spent: ${spend.get('total_usd', 0):.4f} of ${args.budget:.2f}")


if __name__ == "__main__":
    main()
