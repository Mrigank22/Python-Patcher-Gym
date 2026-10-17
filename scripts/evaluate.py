"""Evaluate any causal LM (base or GRPO-trained) on the held-out test split.

    # base model
    python scripts/evaluate.py --model Qwen/Qwen2.5-0.5B-Instruct --k 4
    # a trained LoRA adapter (its base model is read from adapter_config.json)
    python scripts/evaluate.py --model runs/qwen05b --k 4 --tag trained

Writes ``results/eval_<tag>.json`` (summary + per-prompt rows, so two runs can
be compared prompt by prompt with ``scripts/compare_evals.py``) and a per-CWE
bar chart, and prints pass@1 / pass@k plus the no-op and oracle floors so the
numbers are trustworthy.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cybersec_env.dataset import build_dataset  # noqa: E402
from cybersec_env.evaluation import evaluate_model  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="HF model id or local checkpoint dir")
    ap.add_argument("--k", type=int, default=1)
    ap.add_argument("--test-per-family", type=int, default=16)
    ap.add_argument("--families", default=None,
                    help="comma list of procedural families; 'none' for imported tasks only")
    ap.add_argument("--sources", default=None, help="comma list of imported benchmarks, e.g. cweval")
    ap.add_argument("--max-new-tokens", type=int, default=512)
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--dtype", default="bfloat16")
    ap.add_argument("--tag", default="base")
    ap.add_argument("--batch-size", type=int, default=8)
    ap.add_argument("--seed", type=int, default=0, help="sampling seed")
    ap.add_argument("--difficulties", default="1",
                    help="comma list for procedural tasks (code_injection: 1 = hinted, 2 = plain)")
    args = ap.parse_args()

    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    families = None if not args.families else ([] if args.families == "none"
                                               else args.families.split(","))
    sources = args.sources.split(",") if args.sources else None
    ds = build_dataset(n_train_per_family=1, n_test_per_family=args.test_per_family,
                       difficulties=tuple(int(d) for d in args.difficulties.split(",")),
                       families=families, sources=sources)

    adapter_cfg = Path(args.model) / "adapter_config.json"
    base_id = (json.loads(adapter_cfg.read_text(encoding="utf-8"))["base_model_name_or_path"]
               if adapter_cfg.is_file() else args.model)
    tok = AutoTokenizer.from_pretrained(base_id, padding_side="left")
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(
        base_id, dtype=getattr(torch, args.dtype),
        device_map="auto" if torch.cuda.is_available() else None,
    )
    if adapter_cfg.is_file():
        from peft import PeftModel

        model = PeftModel.from_pretrained(model, args.model)
        print(f"[eval] loaded LoRA adapter {args.model} on {base_id}")
    model.eval()
    torch.manual_seed(args.seed)

    report = evaluate_model(
        model, tok, ds["test"], k=args.k,
        max_new_tokens=args.max_new_tokens, temperature=args.temperature,
        batch_size=args.batch_size,
    )
    print("\n" + report.summary() + "\n")

    outdir = ROOT / "results"
    outdir.mkdir(exist_ok=True)
    payload = dict(report.__dict__)
    payload["model"] = args.model
    payload["base_model"] = base_id
    payload["settings"] = {"k": args.k, "test_per_family": args.test_per_family,
                           "difficulties": args.difficulties, "sources": args.sources,
                           "temperature": args.temperature,
                           "max_new_tokens": args.max_new_tokens, "seed": args.seed}
    (outdir / f"eval_{args.tag}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        cwes = sorted(report.by_cwe)
        vals = [report.by_cwe[c]["pass_at_1"] for c in cwes]
        plt.figure(figsize=(8, 4))
        plt.bar(cwes, vals, color="#4C78A8")
        plt.ylabel("pass@1 (solved)"); plt.ylim(0, 1)
        plt.title(f"{args.tag}: secure-repair pass@1 by CWE")
        plt.xticks(rotation=45, ha="right"); plt.tight_layout()
        plt.savefig(outdir / f"eval_{args.tag}_by_cwe.png", dpi=120)
        print(f"wrote {outdir/f'eval_{args.tag}_by_cwe.png'}")
    except Exception as exc:
        print(f"[warn] no chart: {exc}")

    print(f"wrote {outdir/f'eval_{args.tag}.json'}")


if __name__ == "__main__":
    main()
