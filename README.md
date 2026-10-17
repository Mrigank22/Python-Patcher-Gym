# CyberSec Env — an RL environment for teaching LLMs to repair insecure code

**CyberSec Env** is a production-grade [OpenEnv](https://github.com/meta-pytorch/OpenEnv)
reinforcement-learning environment with **verifiable security rewards (RLVR)**.
An LLM is shown a Python function that contains a real vulnerability and must
return a secure version. The reward is computed by **running hidden functional
tests and real exploit probes** — never by an LLM judge — so a high reward
provably means *the bug is fixed and the behaviour is preserved*.

The grader is hardened in depth: candidate code runs inside a **bubblewrap OS
jail** (no network, read-only filesystem except a throwaway per-candidate
directory) and in a **fork trust-split** where the candidate never shares a
process, nonce or output channel with the part of the worker that issues the
verdict; every value the candidate returns is reduced to a trusted primitive
before any probe compares it. An adversarial **reward-hacking audit** and a
**mutation test** (domain-level probe quality) run as part of the suite. See
`REPORT.md` §4 and §8 for the exact threat model and the one residual the
function-level model does not remove (which the roadmap's container track does).

It is **model-agnostic** (train any Hugging Face causal LM — 0.5B on a laptop
GPU or larger on a server), **framework-light** (the grader has no torch/TRL
dependency), and ships with a GRPO training loop, a held-out evaluation harness,
and the audits above.

```
         vulnerable function                      fixed function
   ┌───────────────────────────┐   LLM policy   ┌──────────────────────────┐
   │ def lookup_user(conn, u):  │ ─────────────▶ │ cur.execute(..., (u,))    │
   │   ...WHERE name='%s'%u     │                │ # parameterized           │
   └───────────────────────────┘                └──────────────────────────┘
                 │                                          │
                 ▼                                          ▼
        OpenEnv reset()                            OpenEnv step(code)
                                                            │
                                      ┌─────────────────────▼───────────────────────┐
                                      │  Verifier (isolated subprocess, CPU)         │
                                      │  1. AST guard (block grader-escape)          │
                                      │  2. functional probes  (benign I/O == ref)   │
                                      │  3. security probes    (exploit is blocked)  │
                                      │  4. static rubric      (per-CWE, low weight) │
                                      │  → reward ∈ [0,1];  solved = func ∧ security  │
                                      └──────────────────────────────────────────────┘
```

## Why this environment

Frontier labs and data vendors are buying RL environments, and **security
("find, exploit, and fix real software vulnerabilities")** is one of the
explicitly in-demand, less-saturated domains — Bugcrowd, Mistral and others post
dedicated *RL-environment (cybersecurity)* roles, and buyers' top acceptance
criterion is a **reward that cannot be hacked**. This repo is built around that
criterion: a verifiable grader, an anti-reward-hacking audit, calibrated
difficulty, and reproducible before/after training evidence — the exact
portfolio artifacts hiring managers ask for.

## What's inside

| Component | Path | What it does |
|---|---|---|
| Task families | `cybersec_env/tasks/` | 8 procedural CWE generators → unlimited, contamination-free tasks |
| Imported benchmarks | `cybersec_env/data/imported/` | 708 validated tasks from SecCodePLT (692) and CWEval (16), graded by their own tests |
| Importers | `scripts/import_seccodeplt.py`, `scripts/import_cweval.py` | convert a benchmark, then keep only tasks that validate in this grader |
| Grader | `cybersec_env/verifier.py` | guard → sandboxed exec → functional/security/static → reward |
| Anti-hacking guard | `cybersec_env/guard.py` | AST denylist for grader-escape constructs |
| Sandboxed worker | `cybersec_env/_grade_worker.py` | one subprocess per candidate in a throwaway folder; writes, network and process spawning blocked; verdict tagged with a per-call token |
| OpenEnv env/server | `cybersec_env/environment.py`, `cybersec_env/server/` | HTTP/WebSocket env, Dockerfile, manifest |
| TRL reward | `cybersec_env/trl_reward.py` | drop-in `reward_funcs` for `GRPOTrainer` |
| Dataset | `cybersec_env/dataset.py` | HF `DatasetDict` with disjoint train/test seeds |
| Training | `scripts/train_grpo.py` + `configs/*.yaml` | model-agnostic GRPO, before/after eval, reward curve |
| Evaluation | `scripts/evaluate.py` | pass@1 / pass@k, per-CWE, no-op & oracle floors |
| Paired comparison | `scripts/compare_evals.py` | base vs trained on the same prompts: change, bootstrap 95% CI, p-value |
| Failure analysis | `scripts/probe_report.py` | which functional/security probes a model fails, and why |
| Audit | `scripts/hack_audit.py` | proves reward-hacks score 0 (writes `results/hack_audit.md`) |

### Vulnerability task families

| Family | CWE | Security probes check that… |
|---|---|---|
| `sqli` | CWE-089 | `' OR '1'='1` returns no rows; stacked `DROP TABLE` does nothing |
| `code_injection` | CWE-095 | an `eval`'d payload cannot create a file / run code (difficulty 1 adds a hint) |
| `path_traversal` | CWE-022 | `../`, absolute paths and a same-prefix sibling folder cannot escape the base dir |
| `unsafe_deser` | CWE-502 | a YAML `!!python/object` payload constructs nothing |
| `ssrf` | CWE-918 | subdomain/query-smuggle/scheme tricks are rejected; normal URLs still allowed |
| `xss` | CWE-079 | `<script>`/attribute payloads are HTML-escaped |
| `weak_hash` | CWE-327 | output is no single fast digest and the code uses a password KDF (PBKDF2, scrypt, bcrypt, argon2) |
| `insecure_random` | CWE-330 | tokens are not reproducible after `random.seed()` |

Each instance ships a vulnerable seed (shown to the model), a hidden reference
oracle, hidden functional + security probes, and a per-CWE static rubric. Tasks
are generated from a `family-difficulty-seed` id, so train and test use
**disjoint seed ranges** (no contamination) and the set is effectively infinite.

### Imported benchmark tasks

| Source | Tasks kept | CWEs | Split | Graded by |
|---|---|---|---|---|
| [SecCodePLT](https://huggingface.co/datasets/Virtue-AI-HUB/SecCodePLT) (MIT, gated) | 692 of 819 runnable | 15 | 582 train / 110 test | a pytest module generated from its capability/safety test table |
| [CWEval](https://github.com/Co1lin/CWEval) (Apache-2.0) | 16 of 25 Python | 13 | test only (independent check) | CWEval's own pytest module |

An importer converts each task (vulnerable seed → prompt, patched code →
oracle), then keeps it only if, in this grader, the reference passes every
test, the vulnerable seed fails, an empty stub fails, and the tests don't read
the clock. Every drop is recorded with its reason in
`cybersec_env/data/imported/*_import_report.md`. SecCodePLT's code-injection
tasks are all dropped on purpose: their "secure" references still call
`eval`/`exec`, which the guard bans.

```bash
python scripts/import_seccodeplt.py            # needs approved access + a token that can read gated repos
python scripts/import_cweval.py ../datasets/CWEval
```

## Quickstart

```bash
# 1. install (CPU is enough to build/serve/grade; GPU only needed to train)
python -m venv .venv && . .venv/Scripts/activate      # Windows; use bin/activate on Linux/mac
pip install -e ".[train,audit,dev]"
# install a CUDA torch build for your GPU: https://pytorch.org

# 2. see a task and grade the reference fix (no model, instant)
python scripts/demo_rollout.py --family ssrf

# 3. prove the grader can't be reward-hacked (writes results/hack_audit.md)
python scripts/hack_audit.py

# 4. run the test suite
pytest -q

# 5. train (laptop / RTX 4060, ~0.5B + LoRA)
python scripts/train_grpo.py --config configs/laptop_qwen05b.yaml

# 6. evaluate a base vs trained model on the held-out split
python scripts/evaluate.py --model Qwen/Qwen2.5-0.5B-Instruct --tag base   --k 4
python scripts/evaluate.py --model runs/qwen05b                 --tag trained --k 4
```

### Serve it as a live OpenEnv environment

```bash
# local
python -m cybersec_env.server.app --port 8000
# or Docker
docker build -t cybersec-env -f cybersec_env/server/Dockerfile .
docker run --rm -p 8000:8000 cybersec-env
```

```python
from cybersec_env.client import SecureCodeClient
from cybersec_env.models import SecureCodeAction

with SecureCodeClient(base_url="http://localhost:8000").sync() as c:
    obs = c.reset().observation
    print(obs.prompt)                       # the task
    fix = "```python\n<your fixed function>\n```"
    r = c.step(SecureCodeAction(code=fix))
    print(r.reward, r.observation.solved, r.observation.security_pass)
```

## Reward design

* **`shaped`** (default, good for small models): dense partial credit —
  `0.45·functional + (0.40·security + 0.10·static)·functional + 0.05·format` —
  and an unsolved candidate is capped at **0.85**, strictly below a solved one
  (1.0). Security credit scales with how much of the code works: without that,
  code that does nothing (or rejects every input) is trivially "secure", and
  training converged on it (code injection's reward rose while its solve rate
  stayed at 0%).
* **`binary`** (recommended for capable models, per the RLVR literature):
  `1.0` iff every functional **and** every security probe passes and the static
  rubric holds, else `0.0`.

Functionality and security are **both required** for full reward, so the two
classic shortcuts — *delete the behaviour to pass the exploit test* and *keep
the behaviour but stay vulnerable* — are both penalised.

## Anti-reward-hacking (the part labs care about)

1. **AST guard** rejects grader-escape before any code runs: imports of the
   grader package / `sys` / `subprocess` / `socket` / `importlib`, interpreter
   introspection (`__globals__`, `__subclasses__`, …), `eval`/`exec`/`__import__`,
   process control (`sys.exit`, `os._exit`), and **assignment to an imported
   module's attribute**, aliases included (so a probe helper like
   `os.path.exists` cannot be monkeypatched, while `self.name = name` is fine).
2. **Sandboxed subprocess** per candidate: a fresh throwaway folder is its
   working directory and TEMP and the only place it may write (enforced with a
   Python audit hook), and it is deleted afterwards, so nothing one answer
   writes can affect another's grading. Network access and process spawning
   are blocked, the verdict must carry a per-call token the candidate never
   sees, and an early exit simply fails the probe. An infinite loop is killed
   by a wall-clock timeout and scored 0.
3. **Hidden probes** — the functional/security tests live in the grader and are
   rebuilt from the task id inside the worker; the model never sees them.
4. **No-op and oracle floors** reported on every eval: a do-nothing solution
   must score ≈0 and the reference fix must score 1.0.
5. **`scripts/hack_audit.py`** runs 64 attacks across all families and asserts
   none is `solved` while the oracle still scores 1.0 — see
   [`results/hack_audit.md`](results/hack_audit.md).

**Found by training, then fixed.** RL optimises exactly what the grader checks,
so the first training runs doubled as a grader audit:

| Finding | Fix |
|---|---|
| Model code ran with the repo as its working directory and could write anywhere | per-candidate sandbox folder, write confinement, verdict token |
| A trained model "fixed" weak password hashing with salted SHA-256, and the grader accepted it | the probe now requires a password KDF and rejects any single fast digest |
| Trained answers checked paths with a bare `startswith(base)` | new probe with a same-prefix sibling folder |
| "Secure but broken" code earned 0.55 reward, a trap the model fell into | security credit now scales with functional correctness |
| The code-injection spec said "literal", steering models to `ast.literal_eval` (which cannot do arithmetic) | clearer spec, finer functional probes, a hinted curriculum level |

## Model-agnostic & compute notes

* Training reads a YAML config; swap `model:` for any HF causal LM. Profiles:
  `laptop_qwen05b`, `laptop_qwen25_1_5b`, `laptop_qwen25_coder_1_5b`,
  `final_coder15_mixed` (procedural + SecCodePLT, the final run) and
  `server_a100`. Add imported tasks to any profile with `data.sources`.
* **RTX 4060 (8 GB):** Qwen2.5-Coder-1.5B + LoRA + bf16 + gradient
  checkpointing with micro-batch 1–2 (micro-batch 4 runs out of memory on long
  answers), HF generation (no vLLM), ~20 s per step. The grader runs entirely
  on **CPU**, so grading never competes with the GPU.
* **System RAM matters on Windows:** a run needs several GB free. Launch long
  runs in their own console (`scripts/final_pipeline.ps1` runs baseline evals,
  training with auto-resume from checkpoints, and trained evals end to end).
* **Server:** flip `use_vllm: true`, raise `num_generations`, disable LoRA for
  full fine-tuning, and switch to `reward.mode: binary`.
* Windows: Docker Desktop (WSL2) builds the container; the grader itself is pure
  cross-platform Python and needs no Docker to train or evaluate.

## Results

Final run: Qwen2.5-Coder-1.5B-Instruct + LoRA, 400 GRPO steps on 1,222 tasks
(19 CWEs; `configs/final_coder15_mixed.yaml`), one RTX 4060 laptop GPU, about
2h20m. pass@1 on held-out tasks, base vs trained, paired over the same tasks
(`scripts/compare_evals.py`, files in `results/compare_final_*.md`):

| Held-out test set | Base | Trained | Change (95% CI) |
|---|---|---|---|
| Procedural tasks (200, 8 CWEs, no hints) | 33.9% | 59.8% | +25.9 pts (+21.1, +30.7) |
| SecCodePLT test split (110, 15 CWEs) | 17.5% | 23.4% | +5.9 pts (+0.7, +11.4) |
| CWEval (16, independent tests) | 32.8% | 32.8% | 0.0 pts (−14.8, +16.4) |

What it shows: large gains on the task distribution the model trained on
(insecure randomness 20% → 94%, unsafe deserialization 34% → 99%, SSRF
45% → 79%, SQL injection 70% → 100%), no measurable transfer to an
independently written benchmark, and no progress on categories where the base
model never succeeded (code injection, password hashing). Path traversal
regressed (12% → 4% with the corrected grader) because a Windows short-path
artifact failed legitimate fixes during training; the grader is now fixed.
Reproduce the numbers with `scripts/final_pipeline.ps1`.

## Extending it

Add a vulnerability family by subclassing `TaskFamily` (implement `build()` to
return a `TaskInstance` with a vulnerable seed, a reference oracle, and
functional/security probes) and registering it in
`cybersec_env/tasks/families.py::ALL_FAMILIES`.

Add a benchmark by writing a converter that produces records with a vulnerable
seed, a reference, and a pytest module (see `scripts/import_cweval.py`), then
pass them through `scripts/import_common.validate`, which keeps only tasks
that validate in this grader. Credit the source in `NOTICE`.

## Troubleshooting

* **Model download fails with `TypeError: process() takes no keyword arguments`**
  — a bug in some `huggingface_hub`/`httpx` combinations, not in this repo.
  Work around it by pre-fetching the model once with a CLI and then training
  (the loader reads from the local cache):

  ```bash
  huggingface-cli download Qwen/Qwen2.5-0.5B-Instruct
  # then, if needed, train offline:
  HF_HUB_OFFLINE=1 python scripts/train_grpo.py --config configs/laptop_qwen05b.yaml
  ```

* **`bitsandbytes` errors on Windows** — keep `load_in_4bit: false` (the default)
  and use LoRA + bf16; 4-bit is optional and mainly for larger models on Linux.
* **OOM on 8 GB** — lower `num_generations` and `max_completion_length`, or move
  to the 0.5B profile.

## Project layout

```
cybersec_env/            # the package (framework-light core)
  tasks/                 # procedural CWE task families, imported-task loader, registry, static rubric
  data/imported/         # validated SecCodePLT + CWEval tasks and their import reports
  guard.py               # AST denylist (anti-reward-hacking)
  _grade_worker.py       # sandboxed grading subprocess
  verifier.py            # guard → exec → probes → reward
  reward.py  extract.py  # reward shaping; code extraction
  environment.py models.py client.py   # OpenEnv env/action/observation/client
  server/                # FastAPI app, Dockerfile, serve requirements
  dataset.py evaluation.py trl_reward.py   # HF dataset, eval harness, TRL reward
scripts/                 # train_grpo, evaluate, compare_evals, probe_report, hack_audit,
                         # import_seccodeplt, import_cweval, final_pipeline.ps1, ...
configs/                 # laptop and server profiles, final_coder15_mixed
tests/                   # 103 pytest tests (imported tasks re-checked on a fixed sample)
results/                 # hack_audit.{json,md} and eval artifacts
```

## License & attribution

Apache-2.0 (see `LICENSE`). Third-party components and the security benchmarks
that informed the design are credited in `NOTICE`. CWE identifiers © the MITRE
CWE project.
