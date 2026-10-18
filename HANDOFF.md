# HANDOFF — Python-Patcher-Gym (secure-code-repair RL environment)

> Single source of truth for anyone (human or model) picking this up cold.
> Read it fully before acting. Give honest verdicts and verify numbers rather
> than guessing — that is how the owner wants to work. Last updated 2026-10-18.

---

## 0. TL;DR of current state

- **What this is:** an OpenEnv RL environment with *verifiable* security rewards
  (no LLM judge). A model is shown vulnerable Python code and must return a
  secure version that still works; reward comes from running hidden functional
  and exploit tests.
- **Two tracks:**
  1. **Function-level** (mature, trainable on a small GPU): 8 procedural CWE
     families + 708 imported benchmark tasks. This is what was trained before.
  2. **Codebase-level** (new, the sellable differentiator): real PyPI security
     advisories turned into SWE-bench-style Docker tasks, graded fail-to-pass.
- **This session's work (all committed on branch `harden-grader-and-feasibility`):**
  - The function-level grader was **verified hackable** and then **hardened** so
    both demonstrated hacks score 0; added an adversarial audit, a mutation test
    and 18 regression tests. 121 tests pass.
  - Built the **codebase-track pipeline** (collect → triage → verify) and a
    **production container grader**, validated end-to-end on a real task.
  - Measured feasibility: thousands of candidate advisories exist; the pipeline
    already produces verified tasks.
- **Biggest blocker:** no GPU on the current VM (see §7). Training is the only
  step that needs one; everything else is done or runnable here.

---

## 1. Who the owner is and what they want

- Wants to become an **independent builder of RL environments ("gyms") and sell
  them** to AI labs and data/environment vendors; security is the first domain.
  A strong portfolio piece for RL jobs is the fallback goal. Not seeking a
  research job.
- Background: RL theory (Shiyu Zhao), Hugging Face OpenEnv, GRPO with TRL
  (trained Qwen on reasoning-gym before).
- Working style: plain-language explanations, honest verdicts (no time-wasting),
  numbers verified not guessed.
- Hardware they personally own: a **Windows 11 laptop, RTX 4060 (8 GB VRAM)** —
  this is where the existing model was trained and is a real, free GPU option.

### What buyers of RL environments actually pay for (market research)
- The **verifier above all** (they test hard for reward hacking), then
  frontier-level difficulty (useful pass band ~2–3% up to ~70%), hundreds of
  distinct tasks, realism, real data, maintenance, clean provenance/licensing.
- Prices: ~$200–2,000 per task; small labs spend ~$300–500k/quarter.
- Routes for an indie: Prime Intellect Environments Hub bounties ($100–5k+);
  contracting for environment vendors; direct lab deals later.
- Competitors in security: Bugcrowd (volume), Collinear (CWE-bench), Proximal
  (verifier audits), Datacurve. **Our edge is verifier quality**, not volume.
- Verdict: the function-level env is a strong **portfolio/sample**, not yet a
  sellable product; the **codebase track is the path to a sellable product**.

---

## 2. Repository map

```
cybersec_env/
  verifier.py          function-level grader (orchestration, private verdict pipe)
  _grade_worker.py     isolated worker: OS jail + fork trust-split + canonicalisation
  sandbox.py           bubblewrap OS-jail command builder  [NEW this session]
  guard.py             AST denylist (second line, not the primary boundary)
  reward.py            shaped/binary reward from a VerificationResult
  tasks/
    families.py        8 procedural CWE families (sqli, code_injection, path_traversal,
                       unsafe_deser, ssrf, xss, weak_hash, insecure_random)
    registry.py        task-id routing + static rubric (incl. _yaml_safe)
    imported.py        loader for the 708 benchmark tasks
  data/
    imported/          SecCodePLT (692) + CWEval (16) jsonl  [tracked]
    advisories/        candidates.jsonl: 8,186 advisory recipes  [tracked, NEW]
  codebase/            codebase-track package  [NEW]
    grader.py          CodebaseGrader: build image, verify, grade_patch, sanitize_patch
scripts/
  train_grpo.py        TRL GRPO trainer (YAML config, --resume)
  evaluate.py          pass@1/pass@k per CWE
  compare_evals.py     paired bootstrap CI + p-value
  hack_audit.py        adversarial reward-hacking audit (12 classes)  [REWRITTEN]
  mutation_test.py     domain-level probe-quality test  [NEW]
  collect_advisories.py   stage 1: OSV -> candidate index  [NEW]
  build_codebase_tasks.py stage 2: clone + split patches -> specs  [NEW]
  verify_codebase_task.py stage 3: Docker fail-to-pass verify (uses CodebaseGrader) [NEW]
  harvest_codebase.py  resumable batch runner for stages 2-3  [NEW]
  advisory_feasibility.py  feasibility counting over OSV  [NEW]
tests/                 121 tests incl. test_reward_hacks.py [NEW]
configs/               YAML training configs (final_coder15_mixed.yaml is the proven one)
data/                  [git-ignored] codebase clones, specs, verified tasks, ledger
setup.sh               one-command environment bootstrap  [NEW]
REPORT.md              full technical report (updated this session)
HANDOFF.md             this file
```

---

## 3. The grader (the product's core)

### 3.1 Function-level grader — how it works and why it is hard to hack
Pipeline per candidate: extract code → AST guard → execute probes in a
sandboxed worker → static rubric → shaped/binary reward
(`0.45·func + (0.40·sec + 0.10·static)·func + 0.05·format`, capped 0.85 unless
solved; security credit gated by functionality).

**Two hacks beat the previous version (both now score 0, regression-tested):**
1. Return an object whose `__eq__` is always True → one value passed every
   `cand(x)==expected` probe. **Fixed** by canonicalising every candidate return
   value to a trusted primitive before comparison (`_canonical`).
2. Walk the call stack for the per-call nonce, print a forged "all pass" verdict,
   `os._exit`. **Fixed** by a **fork trust-split**: candidate runs in a child
   that holds neither the nonce nor the verdict fd, inside a worker *thread* so a
   frame walk can't reach the inner nonce; the verdict travels on a private pipe
   (not stdout); a probe-count cross-check + inner nonce defeat even a
   count-matched fd-spray forge.

**Isolation layers:** (a) **bubblewrap OS jail** — no network, read-only fs
except a throwaway per-candidate dir (Linux only; degrades to process-only
elsewhere, reported by `sandbox.isolation_level()`); (b) the fork trust-split;
(c) the AST guard as a logged second line. ~0.4 s/grade under bwrap.

**Audits:** `scripts/hack_audit.py --seeds 3` (12 attack classes, must PASS) and
`scripts/mutation_test.py` (incomplete fixes must fail; alternative correct
fixes must score 1.0). The mutation test found and we fixed two real probe
blind spots (SQLi keyword-blacklist bypass → added a UNION probe; FullLoader
masquerading as safe → added a `!!python/name` probe; static rule now credits
`yaml.load(SafeLoader)`).

**Honest residual:** the innermost child still reports its own probe outcomes
over a pipe, so in-process corruption of its bookkeeping *before* that write
could misreport. The container grader (below) removes this entirely.

### 3.2 Codebase-level container grader (`cybersec_env/codebase/grader.py`)
This is the production grader labs want and the one with no residual.
- A task = a real advisory. We build a Docker image of the repo at the
  **vulnerable** commit with the fix's **regression tests** applied.
- The model returns a **source patch**. Grading, inside a `--network none`
  container with cpu/memory/pids limits: restore frozen tests from a pristine
  snapshot → **sanitise** the model patch down to edits of pre-existing non-test
  source files (no new files, no tests, no `conftest.py`/`sitecustomize.py`) →
  apply it → run the task's **fail-to-pass** tests (must pass) and
  **pass-to-pass** tests (must not regress).
- Verdict computed **outside** the container from JUnit XML — the candidate
  never shares a process with the judge, so there is no in-process forge path.
- **Validated end-to-end** on advisory `GHSA-x2c2-q32w-4w6m` (package `vyper`,
  CWE-754): gold patch → solved/reward 1.0 (2/2 fail-to-pass, pass-to-pass
  intact); empty patch → 0; a patch that edits the test → hunk stripped → 0.

---

## 4. The datasets

### 4.1 Function-level (ready to train)
- 8 procedural families × difficulties × seeds (train/test use disjoint seeds).
- 708 imported tasks: SecCodePLT 692 (15 CWEs, MIT, gated on HF) + CWEval 16
  (Apache-2.0, independent tests). All re-validated under the hardened grader:
  708/708 reference fixes solve, 0 vulnerable seeds wrongly solved.
- **Caveat for selling:** imported tasks are public benchmarks (no resale value,
  likely in frontier training data); procedural tasks are templates (weak
  signal). Fine as a portfolio/eval set.

### 4.2 Codebase-level (the sellable track, in progress)
- `collect_advisories.py` indexed **8,186 PyPI advisories that have a GitHub fix
  commit**, across all eras: **1,678 legacy (<2022), 1,881 recent, 4,627
  post-cutoff (≥2024-06)**; 4,055 GitHub-reviewed. Full CWE spectrum (CWE-22
  337, CWE-79 302, CWE-94 151, CWE-918 151, CWE-502 135, CWE-89 69, …). Index in
  `cybersec_env/data/advisories/candidates.jsonl` (tracked). Re-run with
  `--refresh` to stay current to the latest advisories.
- **Measured yields (real, from git/Docker — not estimates):**
  - triage (fix touched both a test and source file, extractable patch):
    **35%** of a 60-advisory era-balanced sample.
  - end-to-end Docker fail-to-pass on the first 21 triaged specs: a handful
    verify; the rest drop mostly on **environment setup** (`before={0,0,0}` =
    the historical package didn't `pip install`, so no tests ran) or collection
    errors. This is the known hard part and the main yield lever (see §6).
- Honest projection: after environment-robustness work, expect ~10–25% of the
  8,186 to become fully verified = **~800–2,000 tasks** spanning all eras/CWEs.
  No data scarcity; the bottleneck is per-package environment setup, not supply.

### 4.3 Why the dataset is small in git
Tasks are **recipes**, not built images: each verified task is a JSON spec
(repo URL, two commit SHAs, gold source patch, test patch, f2p/p2p test ids,
Python version) — tens of KB. Docker images are rebuilt on demand and never
committed. 1,000 tasks ≈ 20–40 MB of text, pushes/pulls in seconds (this is how
SWE-bench ships). Clones/images/specs live under the git-ignored `data/`.
*Caveat:* reproducibility depends on the upstream GitHub repos staying alive at
those SHAs; a future "freeze" step can tar each base tree into a release
artifact (GB-scale, shipped outside git) for buyers who need permanence.

---

## 5. Results (function-level, from the prior RTX 4060 run; see REPORT.md §7)
Qwen2.5-Coder-1.5B + LoRA, 400 GRPO steps. pass@1 base → trained, paired on
held-out tasks:
- Procedural (200): **33.9% → 59.8%** (+25.9, CI +21.1..+30.7).
  Big gains where the base model already sometimes succeeded (randomness
  20→94%, deserialization 34→99%, SSRF 45→79%, SQLi 70→100%); **0%→0%** for code
  injection and weak hashing (need a supervised warm-start or bigger model).
- SecCodePLT test (110): 17.5% → 23.4%. CWEval (16): no transfer.
- Lesson: RL improved only categories with non-zero base success; it does not
  create a capability from nothing at this model size.
> NOTE: these numbers predate the grader hardening (they were produced on
> Windows, process-only). Re-running on the hardened grader is a to-do (§6); the
> gains are expected to hold but should be re-measured, not assumed.

---

## 6. What to do next (priority order)

1. **Grow the codebase dataset** (no GPU): run the harvester in the background.
   `python scripts/harvest_codebase.py --triage-batch 300 --verify --loop`.
   Watch the verified count in `data/codebase/verified/` and the ledger.
2. **Raise the verification yield** — the highest-leverage engineering:
   - per-task Python version from `python_requires` (done) *and* a fallback
     matrix (try 3.8–3.12) when the first build/install fails;
   - install system build deps for common native packages; honour
     `requirements*/test-requirements` (partly done);
   - detect tasks whose tests need network/evm/db and drop or mark them;
   - this directly converts the `before={0,0,0}` drops into verified tasks.
3. **Frontier calibration** (needs API budget; owner has no paid API now): run
   1–2 strong models on all three test sets per CWE to get the pass-rate table
   buyers ask for. Open-model stand-ins can run on a rented GPU.
4. **Train** (needs a GPU, §7): re-run `final_coder15_mixed.yaml` on the
   hardened grader (3 seeds), add an SFT warm-start for the 0% categories, and —
   once there are enough verified codebase tasks — a patch-generation run on
   them (expensive: Docker per rollout; use a bigger rented GPU).
5. **Package & sell:** Docker image, grader write-up, the reward-hacking +
   mutation audit reports, frontier pass-rate table, provenance/licence sheet,
   a free sample subset, maintenance plan. Rename if desired (check availability),
   push to GitHub, port to Prime Intellect `verifiers`, publish on the Hub, claim
   bounties. Lead with the "found by training and red-teaming, then fixed" story.

---

## 7. Environment & gotchas (critical, read before running anything)

- **This Azure VM (`STANDARD_E4DS_V4`) has NO GPU.** `lspci -d 10de:` is empty,
  `modprobe nvidia` says "No such device". No driver/CUDA install can change
  that — it is a provisioning fact. To train, start a **GPU compute instance**
  (e.g. `Standard_NC4as_T4_v3` = 1× T4 16 GB) and run there; or use the owner's
  **RTX 4060 laptop** (already proven), Colab/Kaggle (free, time-limited), or a
  cheap rental (RunPod/Vast, ~$0.2–0.5/hr). Student free tiers block GPU SKUs.
- **Moving to another box is NOT a migration:** `git clone` + `bash setup.sh`.
  Chat history does not need to move — this file + REPORT.md + memory carry the
  state. Put models and the venv on **local disk**, not a network mount.
- **Python env:** no conda (Anaconda ToS unaccepted). Use uv; interpreter at
  `~/envs/pgym/bin/python`. Always run with `PYTHONPATH=<repo>`.
- **Grader OS jail:** needs Linux user namespaces + `bwrap`
  (`apt install bubblewrap`); else it degrades to process-only (fine for dev,
  not for hostile multi-tenant grading). Check with
  `python -c "from cybersec_env import sandbox; print(sandbox.isolation_level())"`.
- **Git:** repo lives on a mount that trips git's "dubious ownership"; use
  `git -c safe.directory=$PWD ...`. Remote: github.com/Mrigank22/Python-Patcher-Gym.
- **Docker** is available and used for codebase grading; builds are online
  (pip needs network), test runs are `--network none`.
- **Never edit `cybersec_env/` files while a training/eval/verify run is in
  flight** — workers re-import them per answer.
- **Imported SecCodePLT** is gated on Hugging Face; the owner's account has
  access. Download with system Python then run with `HF_HUB_OFFLINE=1` (a venv
  `huggingface_hub` download bug bit before).

---

## 8. Exact commands

```bash
# Setup (any box)
git clone https://github.com/Mrigank22/Python-Patcher-Gym && cd Python-Patcher-Gym
bash setup.sh                      # creates ~/envs/pgym, installs deps, bwrap, smoke test
export PY="PYTHONPATH=$PWD $HOME/envs/pgym/bin/python"

# Verify the grader is honest (no GPU)
$PY -m pytest -q                               # 121 tests
$PY scripts/hack_audit.py --seeds 3            # reward-hacking audit, must PASS
$PY scripts/mutation_test.py                   # probe-quality, must pass

# Codebase dataset (no GPU; long-running)
$PY scripts/collect_advisories.py --refresh    # refresh the 8,186-advisory index
$PY scripts/harvest_codebase.py --triage-batch 300 --verify --loop

# Train (GPU box only) — the one command that needs a GPU
$PY scripts/train_grpo.py --config configs/final_coder15_mixed.yaml --no-eval

# Evaluate + compare (GPU for generation)
$PY scripts/evaluate.py ...   &&   $PY scripts/compare_evals.py <base.json> <trained.json>
```

---

## 9. Changelog of this session (2026-10-18)
- Verified the function-level grader was hackable (2 attacks at reward 1.0),
  then hardened it: `sandbox.py` (bwrap), fork trust-split + canonicalisation in
  `_grade_worker.py`, private verdict pipe + count-check in `verifier.py`, guard
  additions. Rewrote `hack_audit.py`, added `mutation_test.py` and
  `tests/test_reward_hacks.py`. 103→121 tests; 708/708 imported still valid.
- Built the codebase track: `collect_advisories.py` (8,186 candidates),
  `build_codebase_tasks.py` (triage, 35% yield), `cybersec_env/codebase/grader.py`
  (production container grader, validated on vyper), `verify_codebase_task.py`,
  `harvest_codebase.py`, `advisory_feasibility.py`.
- Added `setup.sh`; updated `README.md` and `REPORT.md`; wrote this handoff.
- Open: GPU provisioning (owner action); verification-yield engineering (§6.2);
  frontier calibration (needs API); re-measure training on the hardened grader.
```
