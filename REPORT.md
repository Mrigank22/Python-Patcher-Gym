# CyberSec Env — technical report

*A verifiable-reward RL environment for training LLMs to repair insecure code.*

**Headline result (final run, 2026-10-17).** GRPO training of
Qwen2.5-Coder-1.5B-Instruct on CyberSec Env raised held-out pass@1 on the
environment's procedural tasks from **33.9% to 59.8%** (+25.9 points, 95% CI
+21.1 to +30.7) and on the SecCodePLT test split from **17.5% to 23.4%**
(+5.9 points, 95% CI +0.7 to +11.4). It did **not** transfer to CWEval, an
independently written benchmark (32.8% → 32.8%). Training also exposed eight
grader flaws, all documented and fixed (§4.2).

## 1. Problem

Security ("find, exploit, and fix real software vulnerabilities") is one of the
in-demand, less-saturated domains for RL environments, and the property buyers
insist on is a **reward that cannot be hacked**: high reward must mean the
vulnerability is actually fixed, not that the grader was fooled. This project is
an end-to-end environment built to that standard for **secure-code repair**.

## 2. Tasks

Single-turn: the policy is shown a Python function containing a real
vulnerability and must return a secure version that preserves the documented
behaviour.

### 2.1 Procedural families (8 CWEs)

Generated from a `family-difficulty-seed` id: an effectively infinite,
contamination-free supply with **disjoint train/test seed ranges**.

| Family | CWE | Security probes check that… |
|---|---|---|
| sqli | 089 | a tautology returns no rows; a stacked `DROP TABLE` does nothing |
| code_injection | 095 | an `eval`'d payload cannot run code (difficulty 1 adds a hint) |
| path_traversal | 022 | `../`, absolute paths and a same-prefix sibling folder cannot escape |
| unsafe_deser | 502 | a YAML `!!python/object` payload constructs nothing |
| ssrf | 918 | subdomain, query-smuggle and scheme tricks are rejected; normal URLs still allowed |
| xss | 079 | `<script>` and attribute-breakout payloads are escaped |
| weak_hash | 327 | the output is no single fast digest and the code uses a password KDF |
| insecure_random | 330 | tokens are not reproducible after `random.seed()` |

### 2.2 Imported benchmark tasks (708 tasks)

| Source | Kept | CWEs | Split | Graded by |
|---|---|---|---|---|
| SecCodePLT (MIT, gated) | 692 of 819 with executable tests | 15 | 582 train / 110 test | a pytest module generated from its capability/safety test table |
| CWEval (Apache-2.0) | 16 of 25 Python tasks | 13 | test only | CWEval's own pytest module |

Importers (`scripts/import_seccodeplt.py`, `scripts/import_cweval.py`) convert
each task (vulnerable seed → prompt, patched code → reference) and keep it only
if, **in this grader**, the reference passes every test, the vulnerable seed
fails, an empty stub fails, and the tests don't read the clock
(`scripts/import_common.py`). Main drop reasons, all recorded in
`cybersec_env/data/imported/*_import_report.md`:

* SecCodePLT code-injection tasks (102): their "secure" references still call
  `eval`/`exec`, which the guard bans by design.
* Tasks that must start processes (SecCodePLT command injection, CWEval
  CWE-078) or whose crypto library loads native code (CWEval CWE-326, 327, 329):
  the sandbox forbids both.
* CWEval tasks tied to Unix behaviour (file permissions), a timeout decorator,
  or the clock.

SecCodePLT test tasks are close siblings of its training tasks (in-distribution);
CWEval is the out-of-distribution check.

Training used 1,222 tasks across **19 CWEs**; all sources together cover 26.

## 3. Grader (verifiable reward)

For each candidate completion:

1. **Extract** the function from the model output (```python fence → bare def).
2. **Guard**: an AST denylist rejects grader-escape constructs before execution
   (§4).
3. **Execute** the probes in a **two-layer sandbox** (`cybersec_env/sandbox.py`,
   `_grade_worker.py`):
   * an **OS jail** — on Linux the worker runs inside bubblewrap with the
     network namespace emptied (no `connect`/`bind`/DNS at all), the filesystem
     read-only except a fresh throwaway per-candidate directory that is its cwd
     and `$TMPDIR`, and pid/ipc/uts unshared. A Python audit hook and POSIX
     rlimits apply underneath as defence in depth. When bubblewrap is absent
     (e.g. Windows) the layer degrades to process-only and the audit reports it;
   * a **fork trust-split** — the worker forks, and candidate code runs in the
     *child*, which closes the verdict descriptor and stdin before executing any
     candidate code, and runs the candidate in a worker *thread* so a stack walk
     cannot reach the child's inner nonce. The *parent* holds the grader nonce
     and the verdict descriptor and never runs candidate code.
   Procedural tasks run Python probe functions; imported tasks run their
   benchmark's pytest module, with the candidate loaded as the module under test.
   A wall-clock timeout kills infinite loops.
4. **Verdict channel**: the verdict travels on a **private pipe** (not stdout) and
   is accepted only if it carries the per-call token the candidate never sees; the
   child's report to the parent carries a second nonce the candidate cannot read.
   Every value the candidate returns is reduced to a **trusted primitive**
   before any probe compares it, so an object with a lying `__eq__` cannot pass.
   An early exit or a forged write fails the grade instead of faking success.
5. **Static rubric**: a per-CWE source check (e.g. "query is parameterized"),
   low weight, never sufficient for `solved`.
6. **Reward**: `solved = all functional ∧ all security probes pass`.
   * `shaped` (default): `0.45·func + (0.40·sec + 0.10·static)·func + 0.05·format`,
     capped at 0.85 unless solved; a solved fix scores 1.0. Security and static
     credit scale with functional correctness (§4.2).
   * `binary`: 1.0 iff solved and the static rubric holds, else 0.0.

The grader is framework-free (no torch/TRL import), so the same code backs the
OpenEnv server, the TRL reward function, the CLI and the tests.

## 4. Anti-reward-hacking

### 4.1 Audit

`python scripts/hack_audit.py [--seeds N]` runs an adversarial battery of **12
attack strategies across all 8 families** (300+ attempts) and asserts that
**none is scored `solved`** while the genuine oracle still scores **1.0**.
Result: **PASSED** ([`results/hack_audit.md`](results/hack_audit.md)). It
includes the two attacks that *defeated an earlier version of this grader* and
drove the redesign in §3 (regression-tested in `tests/test_reward_hacks.py`).

| Attack strategy | How it is stopped |
|---|---|
| **return an object whose `__eq__` is always True** (one value passes every probe) | return values canonicalised to trusted primitives before comparison |
| **walk the call stack for the nonce and write a forged "all pass" verdict, then exit** | fork trust-split: candidate holds no nonce and no verdict fd; thread isolation hides the inner nonce |
| **spray every fd with a count-matched forged verdict, then exit** | verdict nonce + child inner-nonce + probe-count cross-check; a forge without them is discarded |
| keep the vulnerable code | security probes fail; never solved |
| break functionality to pass the exploit | functional probes fail; security credit scales with function |
| import the grader package / network / subprocess | guard `banned_import`; also blocked by the OS jail at runtime |
| monkeypatch a module attribute (aliases included) | guard `attribute_assignment` |
| interpreter introspection / thread-frame reach | guard `banned_attribute` / `banned_import` (`sys`, `threading`, `gc`, …) |
| process control / dynamic exec | guard `banned_import` / `banned_name` |
| infinite loop | wall-clock timeout → 0 |

### 4.1b Mutation test (probe quality)

`python scripts/mutation_test.py` feeds each family realistic *incomplete*
fixes — the kind a weak model writes — and asserts the probes catch them
(`solved == False`), plus alternative correct fixes that must score the full
1.0. Building it found and fixed two real probe blind spots, now covered:

| Family | Blind spot found | Fix |
|---|---|---|
| SQLi | a keyword blacklist (`OR`/`DROP`/`;`/`--`) passed the old two probes | added a `union_injection` probe that no blacklist screens |
| Unsafe deser | `yaml.load(FullLoader)` passed (it blocks the `builtins.open` gadget) | added a `no_python_tag` probe (`!!python/name:…`) that only a true Safe loader rejects; the static rule now also credits `yaml.load(Loader=SafeLoader)` |

### 4.2 Found by training, then fixed

RL optimises exactly what the grader checks, so the training runs doubled as a
grader audit. Every item below was observed, fixed, and covered by tests.

| # | Finding | How it surfaced | Fix |
|---|---|---|---|
| 1 | Model code ran in the repo folder and could write anywhere; files written during one grading could affect later gradings | stray files written by model answers appeared in the repo; confirmed on an isolated copy | per-candidate sandbox folder, write confinement, deletion afterwards |
| 2 | The parent trusted whatever the worker printed, and the worker only caught `Exception` | confirmed on an isolated copy | per-call verdict token; `BaseException` handling |
| 3 | Weak-hash grader accepted a single salted SHA-256 | 23 of 24 trained solves used it | probe requires a password KDF and rejects any single fast digest |
| 4 | Path grader missed a bare `startswith(base)` check | trained answers used it | new same-prefix sibling-folder probe |
| 5 | "Secure but broken" code earned 0.55 reward | code injection: reward rose 0.37 → 0.51 while solves stayed 0% | security/static credit scales with functional correctness |
| 6 | Code-injection spec said "literal", steering models to `ast.literal_eval` (cannot do arithmetic) | per-probe failure report | clearer spec, finer functional probes, hinted curriculum level |
| 7 | Imported-task grading: cp1252 decoding lost verdicts; a socket monkeypatch broke `import ssl`; pytest read parent-folder config; the guard banned `self.x = …` | importing CWEval/SecCodePLT | UTF-8 channel; network blocked via audit hook; sandboxed pytest config; guard narrowed to module attributes |
| 8 | Windows TEMP used an 8.3 short path, so fixes resolving only one side of a path comparison failed on this machine only | trained model left path-traversal code unchanged in 12 of 25 answers | sandbox uses the resolved path |

Finding 8 is the clearest lesson: the model learned the grader artifact.
Path traversal fell from 12% to 4% (measured with the corrected grader) because
the buggy grader made genuine fixes look broken during training.

## 5. Difficulty calibration

In GRPO a group of rollouts carries signal only when rewards vary within the
group. Epoch AI's interviews with environment buyers put the useful band at
roughly a 2–3% minimum pass rate up to about 70%. The results confirm it
sharply:

* Categories where the base model succeeded sometimes improved strongly
  (insecure randomness 20% → 94%, unsafe deserialization 34% → 99%).
* Categories at 0% stayed at 0%. Code injection: even with a hint, neither the
  base nor the trained model ever wrote a working tree-walking evaluator.
  Password hashing: no sampled answer ever used a KDF.

`scripts/evaluate.py` reports pass@1 / pass@k per CWE with no-op and oracle
floors; `scripts/probe_report.py` shows which probes fail and why. Use both to
keep each family inside the learnable band for the model being trained, or
warm-start zero-success categories with supervised examples.

## 6. Training

`scripts/train_grpo.py` + a YAML config train any HF causal LM with TRL GRPO;
the reward is the grader above (`cybersec_env/trl_reward.py`), and
functional/security/solved rates are logged every step.

| Profile | Model | Notes |
|---|---|---|
| `laptop_qwen05b` | Qwen2.5-0.5B + LoRA | first experiments |
| `laptop_qwen25_coder_1_5b` | Qwen2.5-Coder-1.5B + LoRA | first 1.5B run |
| `final_coder15_mixed` | Qwen2.5-Coder-1.5B + LoRA | final run: procedural (difficulties 1–2) + SecCodePLT train split |
| `server_a100` | 7B, vLLM, full FT | `binary` reward |

Final-run settings: learning rate 1e-5, KL β 0.02, LoRA r=16, 8 generations per
prompt, 16 answers per update (micro-batch 1 × 16), completions ≤448 tokens,
400 steps, about 2h20m on an RTX 4060 laptop GPU (peak ~4.6 GB). Training reward
rose from 0.35 to about 0.59–0.61. `scripts/final_pipeline.ps1` runs baseline
evals, training with auto-resume from checkpoints, and trained evals end to end.

Lessons that cost runs:

* **Evaluate in inference mode.** Generating while the model is still in
  training mode with gradient checkpointing produces garbage (8 of 8 answers
  unparseable). Early runs that looked like "policy collapse" were this bug;
  `evaluate_model` now switches modes itself.
* **Learning rate:** 1e-5 learned (0.5B training reward 0.40 → 0.59); 2e-6
  barely moved the policy (KL ≈ 0.001).
* **Memory:** micro-batch 4 ran out of GPU memory on long answers; evaluation
  must generate in small batches. On a 15 GB Windows laptop, long runs need
  their own console and several GB of free RAM.

## 7. Results

All comparisons are paired over the same held-out tasks (`scripts/compare_evals.py`:
bootstrap 95% CI and a sign-flip permutation p-value); pass@1 is the mean
solved rate over k samples. Every evaluation kept a **0% no-op floor** and a
**100% oracle ceiling**.

### 7.1 Final run (400 steps, hardened graders)

| Held-out test set | Metric | Base | Trained |
|---|---|---|---|
| Procedural (200 tasks, 8 CWEs, difficulty 2, k=4) | pass@1 | 33.9% | **59.8%** (+25.9, CI +21.1 to +30.7, p < 0.001) |
| | pass@4 | 55.0% | 65.0% |
| | functional rate | 47.5% | 88.5% |
| | security rate | 64.3% | 76.0% |
| | guard-block rate | 3.1% | 0.0% |
| SecCodePLT test split (110 tasks, 15 CWEs, k=4) | pass@1 | 17.5% | **23.4%** (+5.9, CI +0.7 to +11.4, p = 0.04) |
| | pass@4 | 40.0% | 32.7% |
| | functional rate | 43.2% | 69.5% |
| | security rate | 37.9% | 33.8% |
| CWEval (16 tasks, 13 CWEs, k=8) | pass@1 | 32.8% | **32.8%** (0.0, CI −14.8 to +16.4) |
| | pass@8 | 68.8% | 50.0% |

Procedural pass@1 by family: insecure randomness 20% → 94%, unsafe
deserialization 34% → 99%, SSRF 45% → 79%, SQL injection 70% → 100%, XSS
98% → 100%, path traversal 12% → 4% (corrected grader; see §4.2 #8), code
injection 0% → 0%, weak hashing 0% → 0%. SecCodePLT gains: SSRF 53% → 83%,
mass assignment 45% → 100%, open redirect 29% → 57%, missing authorization
28% → 48%; regressions: XSS 41% → 12%, unsafe deserialization 12% → 2%.

### 7.2 First 1.5B run (100 steps, original graders)

Qwen2.5-Coder-1.5B on procedural tasks only, step-100 checkpoint (low system
RAM stopped the run at step 106): pass@1 38.8% → 66.1% (+27.4, CI +22.4 to
+32.5). Reading answers showed part of the gain came from lenient graders
(salted SHA-256 accepted as a password hash), which led to fixes 3–4 in §4.2.
Independent check on CWEval: 32.8% → 38.3% (CI −5.5 to +17.2, not significant).

### 7.3 What the results establish

* **Established:** the reward teaches real fixes on the trained task
  distribution (parameterized SQL, `yaml.safe_load`, `secrets`, allow-list URL
  parsing), with large, statistically solid gains; the grader is sound and
  hardened.
* **Not established:** transfer to independently written tests (CWEval
  unchanged, pass@8 down); learning categories that start at 0%; security
  gains on SecCodePLT (functionality rose, security fell slightly);
  robustness across seeds (one model, one seed, one run).

Result files: `results/compare_final_{proc,spl,cweval}.md`,
`results/eval_final_*.json`, `results/probes_*.json`.

## 8. Threat model & limits (honest)

* **Isolation is strong but names one residual.** On Linux the candidate runs
  in a bubblewrap OS jail (no network, read-only fs) and in a fork trust-split
  where it shares no process, nonce or verdict channel with the trusted parent;
  return values are canonicalised; the audit battery (§4.1), including a
  count-matched fd-spray forge, is fully defeated. The **one residual**: the
  child still reports *its own* raw probe outcomes to the parent over a pipe, so
  candidate code that corrupted the child's trusted bookkeeping *before* that
  write — without exiting (which already fails) and without the inner nonce
  (which the thread split hides) — could in principle misreport. Removing it
  entirely requires never running candidate code in the same process as any
  probe logic, i.e. the **container / patch-and-run** model of the roadmap's
  codebase track (§10), where tests are driven from outside the container.
* The guard is a **denylist**; it is a second line behind the OS jail and the
  trust-split, not the primary boundary.
* Static rubric checks are gameable in isolation, so they carry low weight and
  are never sufficient for `solved`; the dynamic probes are the authority.
* The weak-hash KDF probe checks that the candidate's code calls a password
  KDF; it does not verify the work factor.
* All tasks are single functions. Whole-repository repair (the §10 Docker track)
  is the planned successor, not yet built.
* The OS jail requires Linux user namespaces; on Windows the grader degrades to
  process-only isolation and `sandbox.isolation_level()` reports it. The results
  in §7 were produced on Windows (process-only); the hardening and audits in §3–4
  were added and verified on Linux with bubblewrap active.

## 9. Reproducibility

```bash
pytest -q                                  # 121 tests (incl. reward-hack regressions)
python scripts/hack_audit.py --seeds 3     # 300+ attacks, must PASS
python scripts/mutation_test.py            # probe quality: incomplete fixes must fail
python scripts/advisory_feasibility.py --since 2024-06-01 --github-sample 150  # §10 track sizing
python scripts/import_seccodeplt.py        # needs gated access + a token that can read gated repos
python scripts/import_cweval.py ../datasets/CWEval
python scripts/compare_evals.py results/eval_final_base_proc.json results/eval_final_trained_proc.json
```

The OS jail needs Linux with user namespaces and `bwrap` (`apt install
bubblewrap`); without it the grader runs process-only. On Linux, run training
and models from local disk, not a network mount.

The test suite covers: oracle solves / vulnerable seed fails / empty scores 0
for every family; determinism and task-id round-trip; timeout handling; guard
block/allow lists; sandbox isolation (nothing persists, writes outside the
sandbox are blocked, candidate stdout is ignored, early exit fails); OpenEnv
reset/step; the TRL reward; and a fixed sample of imported tasks re-validated on
every run (`CSE_FULL_IMPORT_TESTS=1` re-checks all 708).

## 10. Next steps

1. Re-run the final configuration with the fixed grader on 2–3 seeds and report
   mean and spread (path traversal should recover).
2. Warm-start the zero-success categories (code injection, password hashing)
   with a few dozen supervised examples before RL.
3. Push for transfer: more task sources and variants per CWE, with CWEval kept
   strictly held out.
4. Protect exploration (pass@k fell after training): higher sampling temperature
   or an entropy bonus.
5. A repository-level track: recent Python advisories whose fix commit adds a
   test that fails before and passes after the fix, one Docker image per task.
   Feasibility is now measured (`scripts/advisory_feasibility.py`, output
   `results/advisory_feasibility.md`): of 26,379 PyPI advisories in OSV, 13,600
   are post-2024-06 and **4,627 carry a GitHub fix commit** (1,980
   GitHub-reviewed), spanning the same CWEs as the families here (CWE-22 240,
   918 122, 79 114, 502 100, 94 100, 89 44, …). In an anonymous 39-commit
   sample, 69% of fix commits already touch a test file; even at a pessimistic
   15–25% final yield after dependency-install and genuine fail-to-pass
   filtering, that is ~700–1,150 verifiable tasks — no data scarcity. Next
   concrete step: a clone → Docker → verify pipeline on a 20–50-task pilot,
   reusing this grader's reward shape (fail-to-pass = security probes,
   pass-to-pass = functional probes) with tests driven from outside the
   container (which also closes the §8 residual).
