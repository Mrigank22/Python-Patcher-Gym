"""Generation + grading utilities for evaluating any causal LM on the env.

Model-agnostic: anything exposing a HF ``generate`` and a tokenizer with a chat
template works. Reports the metric labs actually care about — ``solved`` rate
(functional **and** security), i.e. pass@1 and pass@k — plus functional-only
and security-only rates so you can see *how* a model fails, broken down by CWE.
Includes no-op and oracle floors so a reader can trust the numbers.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .tasks import generate as gen_task
from .verifier import Verifier


@dataclass
class EvalReport:
    n_prompts: int = 0
    k: int = 1
    pass_at_1: float = 0.0
    pass_at_k: float = 0.0
    functional_rate: float = 0.0
    security_rate: float = 0.0
    guard_block_rate: float = 0.0
    by_cwe: Dict[str, dict] = field(default_factory=dict)
    noop_floor: Optional[float] = None
    oracle_ceiling: Optional[float] = None
    rows: List[dict] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"prompts={self.n_prompts}  k={self.k}",
            f"pass@1 (solved)   = {self.pass_at_1:.3f}",
            f"pass@{self.k} (solved) = {self.pass_at_k:.3f}",
            f"functional rate   = {self.functional_rate:.3f}",
            f"security rate     = {self.security_rate:.3f}",
            f"guard-block rate  = {self.guard_block_rate:.3f}",
        ]
        if self.noop_floor is not None:
            lines.append(f"no-op floor       = {self.noop_floor:.3f} (want ~0)")
        if self.oracle_ceiling is not None:
            lines.append(f"oracle ceiling    = {self.oracle_ceiling:.3f} (want 1.0)")
        lines.append("by CWE (pass@1):")
        for cwe, d in sorted(self.by_cwe.items()):
            lines.append(f"  {cwe:10s} {d['pass_at_1']:.2f}  (n={d['n']})")
        return "\n".join(lines)


def _ratio(num, den):
    return 1.0 if den == 0 else num / den


def grade_floors(task_ids: List[str], verifier: Verifier) -> Dict[str, float]:
    """No-op (identity) and oracle (reference) rewards across the given tasks."""
    noop, oracle = [], []
    for tid in task_ids:
        inst = gen_task(tid)
        noop.append(verifier.grade_source(tid, inst.prompt_code).solved)
        oracle.append(verifier.grade_source(tid, inst.reference_code).solved)
    return {
        "noop": sum(noop) / len(noop) if noop else 0.0,
        "oracle": sum(oracle) / len(oracle) if oracle else 0.0,
    }


def evaluate_model(
    model,
    tokenizer,
    dataset,
    k: int = 1,
    max_new_tokens: int = 512,
    temperature: float = 0.7,
    verifier: Optional[Verifier] = None,
    compute_floors: bool = True,
    batch_size: int = 8,
    grade_workers: int = 8,
) -> EvalReport:
    """Generate ``k`` samples per prompt, grade them, and aggregate.

    ``pass_at_1`` is the unbiased estimate (mean solved rate over all ``k``
    samples), ``pass_at_k`` the fraction of prompts with any solved sample.
    Each row keeps the per-sample ``solved`` flags so two models evaluated on
    the same split can be compared prompt by prompt.
    """
    import torch

    verifier = verifier or Verifier(timeout_s=8.0, reward_mode="shaped")
    device = next(model.parameters()).device
    do_sample = k > 1 or temperature > 0

    # Generation must run in inference mode. A model handed over straight from
    # a Trainer is still in train mode with gradient checkpointing on, and in
    # that state ``generate`` emits garbage tokens (every sample then fails to
    # parse). Switch it over here and restore the caller's state afterwards.
    was_training = model.training
    gc_on = bool(getattr(model, "is_gradient_checkpointing", False))
    cfg = getattr(model, "config", None)
    old_cache = getattr(cfg, "use_cache", None)
    model.eval()
    if gc_on:
        model.gradient_checkpointing_disable()
    if cfg is not None:
        cfg.use_cache = True

    jobs = []  # (prompt index, task_id, cwe, completion)
    try:
        for start in range(0, len(dataset), batch_size):
            batch = dataset[start:start + batch_size]
            texts = [
                tokenizer.apply_chat_template(p, tokenize=False, add_generation_prompt=True)
                for p in batch["prompt"]
            ]
            enc = tokenizer(texts, return_tensors="pt", padding=True, truncation=True,
                            max_length=1024).to(device)
            gen_kwargs = dict(max_new_tokens=max_new_tokens, do_sample=do_sample,
                              num_return_sequences=k, pad_token_id=tokenizer.pad_token_id)
            if do_sample:
                gen_kwargs.update(temperature=max(temperature, 1e-5), top_p=0.95)
            with torch.no_grad():
                out = model.generate(**enc, **gen_kwargs)
            decoded = tokenizer.batch_decode(out[:, enc["input_ids"].shape[1]:],
                                             skip_special_tokens=True)
            for i, (tid, cwe) in enumerate(zip(batch["task_id"], batch["cwe"])):
                for s in decoded[i * k:(i + 1) * k]:
                    jobs.append((start + i, tid, cwe, s))
    finally:
        if cfg is not None and old_cache is not None:
            cfg.use_cache = old_cache
        if gc_on:
            model.gradient_checkpointing_enable()
        if was_training:
            model.train()

    # Grading is CPU-bound subprocess work: run it in parallel.
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=grade_workers) as pool:
        results = list(pool.map(lambda j: verifier.grade_completion(j[1], j[3]), jobs))

    report = EvalReport(n_prompts=len(dataset), k=k)
    per_prompt = defaultdict(list)
    for job, res in zip(jobs, results):
        per_prompt[job[0]].append((job, res))

    by_cwe = defaultdict(lambda: {"solved1": 0.0, "solvedk": 0, "n": 0})
    func_sum = sec_sum = guard_sum = 0.0
    pass1_sum = passk_sum = 0.0
    for idx in sorted(per_prompt):
        pairs = per_prompt[idx]
        (_, tid, cwe, first), _ = pairs[0]
        flags = [r.solved for _, r in pairs]
        p1 = sum(flags) / len(flags)
        pk = any(flags)
        pass1_sum += p1
        passk_sum += int(pk)
        for _, r in pairs:
            func_sum += _ratio(r.functional_pass, r.functional_total)
            sec_sum += _ratio(r.security_pass, r.security_total)
            guard_sum += 0 if r.guard_ok else 1
        d = by_cwe[cwe]
        d["solved1"] += p1
        d["solvedk"] += int(pk)
        d["n"] += 1
        report.rows.append({
            "task_id": tid, "cwe": cwe, "solved": flags, "pass@1": p1, "solved@k": pk,
            "best_reward": round(max(r.reward for _, r in pairs), 3),
            "sample": first[:400],
        })

    n = max(report.n_prompts, 1)
    total = max(len(jobs), 1)
    report.pass_at_1 = pass1_sum / n
    report.pass_at_k = passk_sum / n
    report.functional_rate = func_sum / total
    report.security_rate = sec_sum / total
    report.guard_block_rate = guard_sum / total
    report.by_cwe = {
        c: {"pass_at_1": d["solved1"] / d["n"], "pass_at_k": d["solvedk"] / d["n"], "n": d["n"]}
        for c, d in by_cwe.items()
    }

    if compute_floors:
        floors = grade_floors(list(dataset["task_id"]), verifier)
        report.noop_floor = floors["noop"]
        report.oracle_ceiling = floors["oracle"]
    return report
