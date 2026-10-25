"""Model-agnostic GRPO training on the CyberSec secure-code-repair environment.

Everything that depends on model/hardware lives in a YAML config, so the same
command trains a 0.5B or 1.5B model on an 8 GB laptop GPU, and a larger model
given a config for it::

    python scripts/train_grpo.py --config configs/laptop_qwen05b.yaml
    python scripts/train_grpo.py --config configs/hardened_coder15_mixed.yaml

It builds the task dataset, evaluates the base model on a held-out split,
trains with GRPO (reward = the environment grader), evaluates again, and writes
``report.json`` + a reward curve so the before/after improvement is reproducible
and CV-ready. The reward function logs functional/security/solved rates each
step, so reward-hacking (reward up, security flat) is visible live.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cybersec_env.dataset import build_dataset  # noqa: E402
from cybersec_env.evaluation import evaluate_model  # noqa: E402
from cybersec_env.trl_reward import SecureCodeReward  # noqa: E402


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def build_model_and_tokenizer(cfg: dict):
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    model_id = cfg["model"]
    dtype = getattr(torch, cfg.get("dtype", "bfloat16"))
    tok = AutoTokenizer.from_pretrained(model_id, padding_side="left")
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    model_kwargs = {"dtype": dtype}
    if cfg.get("load_in_4bit"):
        try:
            from transformers import BitsAndBytesConfig

            model_kwargs["quantization_config"] = BitsAndBytesConfig(
                load_in_4bit=True, bnb_4bit_compute_dtype=dtype,
                bnb_4bit_use_double_quant=True, bnb_4bit_quant_type="nf4",
            )
        except Exception as exc:  # bitsandbytes missing / unsupported
            print(f"[warn] 4-bit requested but unavailable ({exc}); using {dtype}.")

    model = AutoModelForCausalLM.from_pretrained(model_id, **model_kwargs)
    # Move to GPU up front so the *base* evaluation (which runs before the
    # Trainer is built, and therefore before the Trainer would place the model)
    # uses CUDA instead of crawling on CPU. 4-bit models are already placed by
    # bitsandbytes and must not be .to()'d.
    if torch.cuda.is_available() and not cfg.get("load_in_4bit"):
        model.to("cuda")
    return model, tok


def build_peft(cfg: dict):
    lora = cfg.get("lora", {})
    if not lora.get("enabled"):
        return None
    from peft import LoraConfig

    return LoraConfig(
        r=lora.get("r", 16),
        lora_alpha=lora.get("alpha", 32),
        lora_dropout=lora.get("dropout", 0.0),
        target_modules=lora.get("target_modules", "all-linear"),
        task_type="CAUSAL_LM",
    )


class StatsCallback:
    """Injects the reward function's last-batch stats into the trainer logs."""

    def __init__(self, reward_fn):
        self.reward_fn = reward_fn

    def on_log(self, args, state, control, logs=None, **kwargs):  # transformers API
        if logs is not None and self.reward_fn.last_stats:
            s = self.reward_fn.last_stats
            extra = {f"env/{key}": round(float(s[key]), 4)
                     for key in ("solved", "sec_rate", "func_rate", "guard_blocked") if key in s}
            logs.update(extra)
            # The Trainer has already copied ``logs`` into its history; add the
            # env stats there too so they are saved and plotted.
            if state.log_history:
                state.log_history[-1].update(extra)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--max-steps", type=int, default=None, help="override grpo.max_steps")
    ap.add_argument("--model", default=None, help="override the model id")
    ap.add_argument("--no-eval", action="store_true", help="skip before/after eval")
    ap.add_argument("--resume", action="store_true",
                    help="continue from the latest checkpoint in output_dir")
    args = ap.parse_args()

    cfg = load_config(args.config)
    if args.model:
        cfg["model"] = args.model
    if args.max_steps is not None:
        cfg.setdefault("grpo", {})["max_steps"] = args.max_steps

    from transformers import TrainerCallback
    from trl import GRPOConfig, GRPOTrainer

    # ---- data -----------------------------------------------------------
    dcfg = cfg.get("data", {})
    ds = build_dataset(
        n_train_per_family=dcfg.get("n_train_per_family", 48),
        n_test_per_family=dcfg.get("n_test_per_family", 16),
        difficulties=tuple(dcfg.get("difficulties", [1])),
        families=dcfg.get("families"),
        sources=dcfg.get("sources"),
    )
    print(f"[data] train={len(ds['train'])} test={len(ds['test'])} "
          f"families={sorted(set(ds['train']['family']))}")

    # ---- model ----------------------------------------------------------
    model, tok = build_model_and_tokenizer(cfg)
    peft_config = build_peft(cfg)

    # ---- reward ---------------------------------------------------------
    rcfg = cfg.get("reward", {})
    reward_fn = SecureCodeReward(
        reward_mode=rcfg.get("mode", "shaped"),
        timeout_s=rcfg.get("timeout_s", 8.0),
        max_workers=rcfg.get("max_workers", 8),
    )

    # ---- grpo config ----------------------------------------------------
    gcfg = dict(cfg.get("grpo", {}))
    output_dir = gcfg.pop("output_dir", "runs/cybersec")
    grpo_args = GRPOConfig(output_dir=output_dir, **gcfg)

    class _CB(TrainerCallback):
        def on_log(self, a, s, c, logs=None, **k):
            StatsCallback(reward_fn).on_log(a, s, c, logs=logs)

    # ---- before eval ----------------------------------------------------
    report = {"config": cfg}
    if not args.no_eval:
        ecfg = cfg.get("eval", {})
        print("[eval] base model on held-out test split ...")
        before = evaluate_model(
            model, tok, ds["test"], k=ecfg.get("k", 1),
            max_new_tokens=ecfg.get("max_new_tokens", 512),
            temperature=ecfg.get("temperature", 0.0),
        )
        print(before.summary())
        report["before"] = {k: v for k, v in before.__dict__.items() if k != "rows"}

    # ---- train ----------------------------------------------------------
    trainer = GRPOTrainer(
        model=model,
        reward_funcs=[reward_fn],
        args=grpo_args,
        train_dataset=ds["train"],
        peft_config=peft_config,
        callbacks=[_CB()],
    )
    trainer.train(resume_from_checkpoint=True if args.resume else None)
    trainer.save_model(output_dir)
    tok.save_pretrained(output_dir)
    with open(os.path.join(output_dir, "log_history.json"), "w", encoding="utf-8") as fh:
        json.dump(trainer.state.log_history, fh, indent=1)

    # reward curve
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        hist = [h for h in trainer.state.log_history if "reward" in h]
        if hist:
            steps = [h["step"] for h in hist]
            plt.figure(figsize=(7, 4))
            plt.plot(steps, [h["reward"] for h in hist], label="reward")
            sec = [(h["step"], h["env/sec_rate"]) for h in hist if "env/sec_rate" in h]
            if sec:
                plt.plot([s for s, _ in sec], [v for _, v in sec], label="security rate")
            plt.xlabel("step"); plt.ylabel("mean"); plt.legend(); plt.grid(alpha=0.3)
            plt.title("GRPO training — reward vs security rate")
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, "reward_curve.png"), dpi=120)
            print(f"[plot] {output_dir}/reward_curve.png")
    except Exception as exc:
        print(f"[warn] could not plot reward curve: {exc}")

    # ---- after eval -----------------------------------------------------
    if not args.no_eval:
        ecfg = cfg.get("eval", {})
        print("[eval] trained model on held-out test split ...")
        after = evaluate_model(
            trainer.model, tok, ds["test"], k=ecfg.get("k", 1),
            max_new_tokens=ecfg.get("max_new_tokens", 512),
            temperature=ecfg.get("temperature", 0.0),
        )
        print(after.summary())
        report["after"] = {k: v for k, v in after.__dict__.items() if k != "rows"}

    with open(os.path.join(output_dir, "report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"[done] wrote {output_dir}/report.json")


if __name__ == "__main__":
    main()
