"""Show one task, a model's attempted fix, and the grade — a quick sanity demo.

    python scripts/demo_rollout.py --model Qwen/Qwen2.5-0.5B-Instruct --family ssrf

With no ``--model`` it just prints a task and grades the reference oracle, so it
runs instantly with no GPU (useful for a screenshot of the environment itself).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cybersec_env.dataset import SYSTEM_PROMPT  # noqa: E402
from cybersec_env.tasks import family_names, get_family  # noqa: E402
from cybersec_env.verifier import Verifier  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=None)
    ap.add_argument("--family", default="ssrf", choices=family_names())
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--max-new-tokens", type=int, default=512)
    args = ap.parse_args()

    inst = get_family(args.family).generate(seed=args.seed, difficulty=1)
    verifier = Verifier(timeout_s=10.0, reward_mode="shaped")

    print("=" * 70)
    print(f"TASK {inst.task_id}  ({inst.cwe}: {inst.title})")
    print("=" * 70)
    print(inst.user_prompt())
    print("=" * 70)

    if args.model is None:
        res = verifier.grade_source(inst.task_id, inst.reference_code)
        print("[no model] grading the reference oracle instead:")
        print(f"solved={res.solved} reward={res.reward} "
              f"func={res.functional_pass}/{res.functional_total} "
              f"sec={res.security_pass}/{res.security_total}")
        return

    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tok = AutoTokenizer.from_pretrained(args.model, padding_side="left")
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(
        args.model, dtype=torch.bfloat16,
        device_map="auto" if torch.cuda.is_available() else None,
    ).eval()

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": inst.user_prompt()},
    ]
    text = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    enc = tok(text, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(**enc, max_new_tokens=args.max_new_tokens, do_sample=False,
                             pad_token_id=tok.pad_token_id)
    completion = tok.decode(out[0, enc["input_ids"].shape[1]:], skip_special_tokens=True)

    print("MODEL COMPLETION:\n" + completion)
    print("=" * 70)
    res = verifier.grade_completion(inst.task_id, completion)
    print(f"GRADE: solved={res.solved} reward={res.reward:.3f} "
          f"func={res.functional_pass}/{res.functional_total} "
          f"sec={res.security_pass}/{res.security_total} "
          f"static_ok={res.static_ok} guard={res.guard_reason or '-'} err={res.error or '-'}")


if __name__ == "__main__":
    main()
