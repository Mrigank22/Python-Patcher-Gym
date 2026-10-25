# HANDOFF — CyberSec Env (secure-code-repair RL environment)

> The single page to read before picking this project up, whether you are a
> person or a model. Give honest verdicts and verify numbers rather than
> guessing; that is how the owner wants to work.
> **Last updated 2026-10-25.** Full technical detail lives in `REPORT.md`.

---

## 0. Status at a glance

| Part | Status | Headline |
|---|---|---|
| **Function-level RL environment** | ✅ Complete | 8 CWE families + 708 benchmark tasks; hardened grader (12 attack strategies, 300+ attempts, all fail) |
| **GRPO training** | ✅ Complete | Qwen2.5-Coder-1.5B + LoRA: held-out **33.4% → 61.0%** (+27.6, p < 0.001); no transfer to CWEval |
| **Frontier comparison** | ✅ Complete (2026-10-25) | Claude Opus 5.5: 100% procedural, 89.1% SecCodePLT, 100% CWEval; cost about $1.50 |
| **Repository-level dataset** | ⏸ Paused | 87 verified tasks, 2,823 queued; paused on disk space (§5) |
| **Report** | ✅ Up to date | `REPORT.md` covers everything above, failures included |

**No more environment work is planned.** Only the dataset is still in progress.

---

## 1. The owner and the goal

- **Goal:** build RL environments ("gyms") to sell to AI labs and environment
  vendors, with security as the first domain. A strong RL portfolio piece is the
  other aim; this project is on the owner's resume.
- **Working style:** plain-language explanations, honest verdicts, numbers
  verified rather than guessed. Commit or publish only when asked.
- **Hardware:** one Windows 11 laptop. RTX 4060 (8 GB VRAM), 15 GB RAM.
  Docker Desktop on WSL2, with its data on `E:\Docker Images`.
- **Budget:** Anthropic API credit is limited ($100 total; the Opus run was
  capped at $8 and used about $1.50). The key is in the machine-scope
  `ANTHROPIC_API_KEY`. Cloud (Azure/AWS) is **not** used; all cloud scripts
  were removed.

**What buyers pay for** (market research, 2026-10): a verifier that resists
reward hacking above all, then frontier-level difficulty (a useful pass band is
about 2–70%), hundreds of distinct tasks, real data, and clean licensing. Our
edge is verifier quality, not volume. The function-level environment is a
strong portfolio and sample piece. The **repository-level dataset is the
sellable part**, because frontier models do not saturate it the way they
saturate the procedural tasks.

---

## 2. What was built

```
cybersec_env/
  tasks/              8 procedural CWE families + loader for 708 imported tasks
  verifier.py         function-level grader (private verdict pipe, probe-count check)
  _grade_worker.py    isolated worker: fork trust-split + return-value canonicalisation
  sandbox.py          bubblewrap OS jail (Linux); Windows Job Object otherwise
  guard.py            AST denylist (a second line of defence)
  codebase/grader.py  repository-level container grader (Docker, --network none)
  data/imported/      SecCodePLT (692) + CWEval (16)
  data/advisories/    8,186 advisory candidates
  data/codebase_tasks/  verified repository-level tasks (90 JSON specs)
scripts/              train, evaluate, compare, audits, frontier calibration, dataset pipeline
configs/              laptop profiles; hardened_coder15_mixed.yaml is the headline run
results/              every eval, comparison, audit, plot, and results/frontier/
runs/                 trained adapters (hardened_coder15, final_coder15, coder15, qwen05b) + logs
REPORT.md             full technical report  ·  README.md  project front page
```

---

## 3. Key results (details: `REPORT.md` §7)

**Training** (hardened grader, 400 steps, 2 h 19 min, RTX 4060):

| Held-out set | Base | Trained | Opus 5.5 |
|---|---|---|---|
| Procedural (200) | 33.4% | **61.0%** (CI +22.6..+32.9) | 100% |
| SecCodePLT (110) | 17.5% | 22.7% (p = 0.051) | 89.1% |
| CWEval (16) | 32.8% | 35.9% (n.s.) | 100% |

**What the results establish:**
- **RL teaches real fixes on the trained distribution:** parameterised SQL,
  `yaml.safe_load`, `secrets`, allow-list URL parsing.
- **Gains appear only where the base model sometimes succeeded.** Code
  injection and password hashing stayed at 0%.
- **Held-out accuracy plateaus after about 250 steps** and never drops, so
  there is no over-fitting.
- **The procedural tasks are saturated by a frontier model.** This is the main
  limitation, found by measurement.

**Grader story (the strongest portfolio point, `REPORT.md` §4):**
- **Training found eight grader flaws.** Three of them were reward hacks the
  model actually used:
  - salted SHA-256 accepted as a password hash;
  - a bare `startswith` path check;
  - "secure but broken" code earning partial reward.
- **Two hand-built attacks beat the earlier grader:** an always-equal return
  object, and a forged verdict via a stack walk. Both now score 0.
- **Opus 5.5 served as a grader check.** No insecure code passed. One false
  negative class was found: the guard's `__getattribute__` ban rejects 6
  correct CWE-200 fixes. It is still open (§6).

**Not done, and why:**
- **Grader red-teaming by a frontier model:** it was stopped by a safety
  classifier while being prepared. The owner asked for it to be bypassed; that
  was declined and must not be attempted.
- **More training seeds:** compute.
- **Evaluating the trained model on repository tasks:** the owner deferred it
  for compute.

---

## 4. The repository-level dataset

**What a task is:** a real PyPI advisory turned into a Docker task.
- **Environment:** the repository at the vulnerable commit.
- **Tests:** hidden tests from the human fix, which fail before it and pass
  after it (fail-to-pass), plus pass-to-pass tests that must not break.
- **Context:** human-written text only (the OSV advisory, related advisories,
  commit message, PR text, with emails redacted). The owner rejected
  LLM-written explanations because of bias.

**Funnel, ledger `data/codebase/ledger.json` (8,186 entries):**

| Status | Count |
|---|---|
| No test in the fix / no source change / clone failed | 3,540 / 895 / 173 |
| **Queued (`spec_written`)** | **2,823** |
| **Verified** | **87** (90 spec files on disk) |
| Not fail-to-pass / timeout / build failed / fetch failed | 565 / 51 / 19 / 25 |

**Verification checks:**
- **Flakiness:** every task is re-run 3 times and flaky tests are dropped.
- **Packages:** each task records `pip freeze`.
- **Backfill pending:** tasks verified before 2026-10-20 still need both (§6).
- **Projection:** roughly 400–500 tasks.
- **Remaining run time:** about 12–15 h of verify, at 200–250 tasks per hour
  with 8 workers.

---

## 5. Current machine state (read before running anything)

- **Everything is stopped:** Docker Desktop, the harvester, the enricher and
  WSL.
- **Disk:**
  - E: has 31.7 GB free;
  - Docker's disk image is 41 GB, of which 32 GB is build cache, deliberately
    kept so builds stay fast;
  - no containers, images or volumes are left.
- **⚠ Before restarting verify, add a cache cap.** With 8 workers the build
  cache grows about **30 GB per hour**. Uncapped, it filled E: to 0 GB on
  2026-10-20 and crashed Docker. Docker's own `daemon.json` limit (30 GB) is
  not enforced promptly. Plan: trim the cache to 30 GB every ~25 tasks (LRU,
  `docker builder prune --keep-storage 30GB`) and pause below 10 GB free. This
  code is **not written yet**.
- **Build-cache rule (owner's):** never delete the build cache outright. Pruning
  it halved throughput once. Trimming with LRU to a cap was approved.
- **Shrinking Docker's disk image** (it only grows on its own), in this order:
  1. Prune the cache.
  2. With Docker running, `wsl -d docker-desktop -u root fstrim -av`.
  3. `docker desktop stop`.
  4. `wsl --shutdown`.
  5. Run an elevated `diskpart` with `compact vdisk` on
     `E:\Docker Images\DockerDesktopWSL\disk\docker_data.vhdx`.

  Without step 2, compaction frees nothing.
- **Never run Docker verify alongside GPU training.** Together they exhausted
  memory, failed training three times with CUDA out-of-memory, and once crashed
  the laptop.
- **`~/.wslconfig`:** memory = 6 GB, swap = 8 GB, `autoMemoryReclaim=dropcache`,
  `sparseVhd=true`.
- **Background jobs** can die with the Claude Code session. Every long job
  resumes from its ledger; re-run the same command.
- **Python:** use `.venv\Scripts\python.exe` in the project folder.
  - The venv needs `brotli>=1.2` for the Anthropic SDK.
  - A venv `huggingface_hub` download bug exists: download with the system
    Python, then run with `HF_HUB_OFFLINE=1`.
- **PowerShell** `*>` writes UTF-16 log files.
- **Git:** this local folder is not a git repository. Earlier work was pushed
  from a since-deleted Azure VM to `github.com/Mrigank22/Python-Patcher-Gym`;
  check that repo's state before relying on it.

---

## 6. What to do next (priority order)

1. **Add the build-cache cap to `scripts/harvest_codebase.py`** (§5), then
   resume the dataset:
   ```
   python scripts/harvest_codebase.py --verify-only --loop --verify-workers 8 --min-free-gb 10
   python scripts/enrich_codebase_tasks.py --loop
   ```
2. **After verify finishes:**
   - run `python scripts/finalize_codebase_tasks.py --workers 6` to backfill
     the 3-run flakiness check and `pip freeze` for early tasks (flaky tasks go
     to `data/codebase/quarantine/`);
   - requeue the 25 `fetch_failed` entries;
   - refresh the funnel numbers in `REPORT.md` §8.3.
3. **Pre-release items:**
   - A pinned-rebuild mode that installs each task's recorded packages.
   - A red-team review of the repository grader. Suspected holes:
     - the candidate runs inside the pytest process that writes the JUnit
       verdict;
     - `PYTEST_CURRENT_TEST` detection;
     - pass-to-pass tests are taken only from the changed test files.
   - Allow the `__getattribute__` proxy pattern in the guard without
     reopening sandbox escapes.
   - A harder procedural tier.
   - Per-task licences, a dataset card, and a fixed held-out split (the
     post-2024 tasks).
4. **Portfolio polish** (owner's call):
   - a public write-up on "reward hacks my RL run found, and how I closed
     them";
   - 2–3 training seeds;
   - publishing on GitHub;
   - reporting the ambiguous SecCodePLT tests upstream (§7.5 of the report).

---

## 7. Exact commands (Windows, from the project folder)

```powershell
$PY = ".venv\Scripts\python.exe"

# Is the grader honest? (no GPU)
& $PY -m pytest -q                                  # 123 tests
& $PY scripts/hack_audit.py --seeds 3               # 300+ attacks, must PASS
& $PY scripts/mutation_test.py                      # incomplete fixes must fail

# Train and evaluate (GPU; never alongside Docker verify)
& $PY scripts/train_grpo.py --config configs/hardened_coder15_mixed.yaml
& $PY scripts/evaluate.py --model runs/hardened_coder15 --tag trained --k 4 --difficulties 2 --test-per-family 25
& $PY scripts/compare_evals.py results/eval_hardened_base_proc.json results/eval_hardened_trained_proc.json
& $PY scripts/plot_training.py

# Frontier comparison (Batch API, hard $8 cap; already done, results in results/frontier/)
& $PY scripts/frontier_calibration.py --sets proc,spl,cweval            # tables only, no API calls

# Repository dataset (add the cache cap first, see section 5)
& $PY scripts/harvest_codebase.py --verify-only --loop --verify-workers 8 --min-free-gb 10
& $PY scripts/enrich_codebase_tasks.py --loop
& $PY scripts/finalize_codebase_tasks.py --workers 6                    # after verify finishes
```

---

## 8. Changelog

**2026-10-25**
- **Opus 5.5 comparison** on all 326 held-out tasks: `REPORT.md` §7.5, script
  `scripts/frontier_calibration.py`, results in `results/frontier/`. Found the
  procedural set saturated and the `__getattribute__` guard false negative.
  Frontier red-teaming was not done.
- **Disk:** E: went from 0 GB to 31.7 GB free. Build cache trimmed 66.6 → 32.2
  GB (approved), fstrim, then compaction (vhdx 72.6 → 41.0 GB).
- **Removed the unused AWS/Azure scripts** (`aws/`, `azure/`).
- **Docs:** README results section and "Results at a glance" rewritten; this
  handoff rewritten.

**2026-10-20 / 21**
- **Verify pipeline:** flakiness re-runs and `pip freeze` per task, a pip
  resolver timeout (`timeout 900`), container clean-up on test timeout, and
  `finalize_codebase_tasks.py`.
- **`REPORT.md` rewritten:** failures, the eight grader flaws, the checkpoint
  curve and the dataset funnel. Mentions of a 7B run were removed (none
  happened).

**2026-10-19**
- **Hardened training run and checkpoint sweep:** 33.4 → 61.0%.

**2026-10-18**
- **Grader hardening:** fork trust-split, private verdict pipe, OS jail, and
  canonicalisation.
- **Audits:** `hack_audit.py` rewritten and `mutation_test.py` added.
- **Repository-level pipeline and container grader built.**
