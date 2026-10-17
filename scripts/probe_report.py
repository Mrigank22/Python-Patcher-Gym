"""Per-probe failure breakdown: *why* does a model fail a task family?

Generates ``k`` answers per held-out task for the chosen families, grades them,
and reports how often each functional / security probe passes, the guard
rejection reasons, and the most common answer shapes. Writes the full answers
to ``results/probes_<tag>.json`` for reading.

    python scripts/probe_report.py --model Qwen/Qwen2.5-Coder-1.5B-Instruct \\
        --families code_injection,ssrf --tag base
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cybersec_env.dataset import build_dataset  # noqa: E402
from cybersec_env.extract import extract_code  # noqa: E402
from cybersec_env.tasks import generate  # noqa: E402
from cybersec_env.verifier import Verifier  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--families", required=True)
    ap.add_argument("--k", type=int, default=8)
    ap.add_argument("--test-per-family", type=int, default=25)
    ap.add_argument("--difficulty", type=int, default=1)
    ap.add_argument("--max-new-tokens", type=int, default=512)
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--tag", default="run")
    ap.add_argument("--batch-size", type=int, default=2,
                    help="prompts per generate call (x k answers); 8 x 8 runs out of memory on 8 GB")
    args = ap.parse_args()

    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    adapter_cfg = Path(args.model) / "adapter_config.json"
    base_id = (json.loads(adapter_cfg.read_text(encoding="utf-8"))["base_model_name_or_path"]
               if adapter_cfg.is_file() else args.model)
    tok = AutoTokenizer.from_pretrained(base_id, padding_side="left")
    model = AutoModelForCausalLM.from_pretrained(base_id, dtype=torch.bfloat16).to("cuda")
    if adapter_cfg.is_file():
        from peft import PeftModel

        model = PeftModel.from_pretrained(model, args.model)
    model.eval()
    torch.manual_seed(0)

    ds = build_dataset(n_train_per_family=0, n_test_per_family=args.test_per_family,
                       difficulties=(args.difficulty,), families=args.families.split(","))["test"]
    jobs = []
    for start in range(0, len(ds), args.batch_size):
        b = ds[start:start + args.batch_size]
        texts = [tok.apply_chat_template(p, tokenize=False, add_generation_prompt=True)
                 for p in b["prompt"]]
        enc = tok(texts, return_tensors="pt", padding=True).to("cuda")
        with torch.no_grad():
            out = model.generate(**enc, max_new_tokens=args.max_new_tokens, do_sample=True,
                                 temperature=args.temperature, top_p=0.95,
                                 num_return_sequences=args.k, pad_token_id=tok.pad_token_id)
        dec = tok.batch_decode(out[:, enc["input_ids"].shape[1]:], skip_special_tokens=True)
        for i, tid in enumerate(b["task_id"]):
            jobs += [(tid, s) for s in dec[i * args.k:(i + 1) * args.k]]

    v = Verifier(timeout_s=8.0)
    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(lambda j: v.grade_completion(*j), jobs))

    by_fam = defaultdict(list)
    for (tid, text), r in zip(jobs, results):
        by_fam[r.family].append((tid, text, r))
    dump = {}
    for fam, rows in by_fam.items():
        n = len(rows)
        probe_pass = Counter()
        for _, _, r in rows:
            for kind in ("functional", "security"):
                for name, ok in r.details.get(kind, {}).items():
                    probe_pass[f"{kind}:{name}"] += bool(ok)
        guard = Counter(r.guard_reason.split(":")[0] for _, _, r in rows if not r.guard_ok)
        print(f"\n=== {fam}: {n} answers | solved {sum(r.solved for *_, r in rows) / n:.1%} | "
              f"mean reward {sum(r.reward for *_, r in rows) / n:.3f}")
        for key, c in sorted(probe_pass.items()):
            print(f"  {key:40s} passes {c / n:6.1%}")
        if guard:
            print("  guard rejections:", dict(guard))
        errs = Counter(r.error.split(":")[0] for *_, r in rows if r.error and r.guard_ok)
        if errs:
            print("  runtime errors:", dict(errs.most_common(5)))
        dump[fam] = [{"task_id": t, "answer": extract_code(x, generate(t).entrypoint).code,
                      "solved": r.solved, "reward": r.reward, "error": r.error,
                      "details": r.details} for t, x, r in rows]
    out = ROOT / "results" / f"probes_{args.tag}.json"
    out.write_text(json.dumps(dump, indent=1), encoding="utf-8")
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
