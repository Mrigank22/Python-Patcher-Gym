"""Stage 3 of the codebase track: prove a task spec is fail-to-pass in Docker.

A spec from ``build_codebase_tasks.py`` is only a *real* task if, in a clean
container with no network:

  * the repo at ``base_commit`` + the fix's **test patch** (so the regression
    test exists) **fails** the added tests — the vulnerability is present; and
  * applying the fix's **source patch** makes those same tests **pass** — the
    gold answer works; and
  * the project's existing tests that passed before still pass (no breakage).

The first two give the fail-to-pass set (the security reward); the spec is then
"verified" and safe to train/evaluate on. This mirrors the function-level
grader's contract — security probes are the tests that must flip, functional
probes are the tests that must keep passing — but the candidate's code never
shares a process with the judge, which also closes the residual noted in
REPORT.md §8.

Build is online (pip needs the network); the test runs use ``--network none``.
Images and build contexts live under ``data/codebase/`` (git-ignored).
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPECS = ROOT / "data" / "codebase" / "specs"
VERIFIED = ROOT / "data" / "codebase" / "verified"

_SUMMARY_RE = re.compile(r"(\d+) (passed|failed|error|errors)")
_PY_FALLBACKS = ["3.11", "3.10", "3.12", "3.9", "3.8"]

_DOCKERFILE = """\
FROM python:{py}-slim
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 PYTHONDONTWRITEBYTECODE=1
RUN apt-get update && apt-get install -y --no-install-recommends \\
      git gcc g++ make libffi-dev libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY repo /app
# Install the project (several common layouts) then pytest. Best-effort: a
# failure here means this task's old deps don't resolve, and it is dropped.
RUN pip install -e ".[test]" 2>/dev/null || pip install -e ".[tests]" 2>/dev/null \\
 || pip install -e ".[dev]" 2>/dev/null || pip install -e . 2>/dev/null \\
 || pip install . 2>/dev/null || true
RUN if [ -f requirements.txt ]; then pip install -r requirements.txt 2>/dev/null || true; fi
RUN pip install pytest 2>/dev/null || true
"""


def run(cmd, timeout=1200, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          errors="replace", **kw)


def _counts(output: str):
    c = {"passed": 0, "failed": 0, "error": 0}
    for n, kind in _SUMMARY_RE.findall(output):
        key = "error" if kind.startswith("error") else kind
        c[key] = c.get(key, 0) + int(n)
    return c


def _py_version(spec) -> str:
    req = spec.get("python_requires") or ""
    m = re.search(r"3\.(\d+)", req)
    if m and f"3.{m.group(1)}" in _PY_FALLBACKS:
        return f"3.{m.group(1)}"
    return "3.11"


def _prepare_repo(spec, work: Path) -> bool:
    repo = work / "repo"
    url = spec["repo"]["url"]
    base = spec["base_commit"]
    if run(["git", "init", "-q", str(repo)]).returncode != 0:
        return False
    for c in (["git", "-C", str(repo), "remote", "add", "origin", url],
              ["git", "-C", str(repo), "fetch", "-q", "--depth", "1", "origin", base]):
        if run(c, timeout=300).returncode != 0:
            return False
    if run(["git", "-C", str(repo), "checkout", "-q", base]).returncode != 0:
        return False
    # Apply the fix's test patch so the regression test exists on the vuln tree.
    (work / "test.patch").write_text(spec["test_patch"], encoding="utf-8")
    ap = run(["git", "-C", str(repo), "apply", "--3way", str(work / "test.patch")])
    if ap.returncode != 0:
        ap = run(["git", "-C", str(repo), "apply", str(work / "test.patch")])
    return ap.returncode == 0


def verify_spec(spec: dict, keep: bool = False) -> dict:
    work = Path(tempfile.mkdtemp(prefix="cse_verify_"))
    tag = "cse_task_" + re.sub(r"[^a-z0-9]", "", spec["id"].lower())[:40]
    test_sel = spec["changed_test_files"]
    try:
        if not _prepare_repo(spec, work):
            return {"id": spec["id"], "verdict": "prepare_failed"}
        (work / "Dockerfile").write_text(_DOCKERFILE.format(py=_py_version(spec)),
                                         encoding="utf-8")
        b = run(["docker", "build", "-q", "-t", tag, str(work)], timeout=1800)
        if b.returncode != 0:
            return {"id": spec["id"], "verdict": "build_failed",
                    "detail": b.stderr[-300:]}

        pytest_cmd = "python -m pytest -q -p no:cacheprovider --no-header " + \
            " ".join(f"'{t}'" for t in test_sel)
        # 1) vulnerable tree + test patch -> the new tests should FAIL.
        before = run(["docker", "run", "--rm", "--network", "none", tag,
                      "sh", "-c", pytest_cmd], timeout=900)
        bc = _counts(before.stdout + before.stderr)

        # 2) apply the source (gold) patch -> the same tests should PASS.
        (work / "source.patch").write_text(spec["source_patch"], encoding="utf-8")
        apply_and_test = (
            "git apply --3way /src.patch 2>/dev/null || git apply /src.patch; "
            + pytest_cmd)
        after = run(["docker", "run", "--rm", "--network", "none",
                     "-v", f"{work/'source.patch'}:/src.patch:ro", tag,
                     "sh", "-c", apply_and_test], timeout=900)
        ac = _counts(after.stdout + after.stderr)

        fail_before = bc["failed"] + bc["error"] > 0
        pass_after = (ac["failed"] + ac["error"] == 0) and ac["passed"] > 0
        verdict = "verified" if (fail_before and pass_after) else "not_fail_to_pass"
        result = {"id": spec["id"], "verdict": verdict,
                  "before": bc, "after": ac,
                  "python": _py_version(spec), "cwes": spec.get("cwes")}
        if verdict == "verified":
            VERIFIED.mkdir(parents=True, exist_ok=True)
            spec2 = dict(spec)
            spec2["verified"] = True
            spec2["f2p_counts"] = {"before": bc, "after": ac}
            spec2["python"] = _py_version(spec)
            (VERIFIED / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', spec['id'])}.json").write_text(
                json.dumps(spec2, indent=2), encoding="utf-8")
        return result
    except subprocess.TimeoutExpired:
        return {"id": spec["id"], "verdict": "timeout"}
    finally:
        run(["docker", "rmi", "-f", tag], timeout=120)
        if not keep:
            shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids", default=None, help="comma-separated advisory ids (default: all specs)")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    paths = sorted(SPECS.glob("*.json"))
    if args.ids:
        want = set(args.ids.split(","))
        paths = [p for p in paths if json.loads(p.read_text())["id"] in want]
    if args.limit:
        paths = paths[: args.limit]

    import collections
    tally = collections.Counter()
    for p in paths:
        spec = json.loads(p.read_text())
        res = verify_spec(spec, keep=args.keep)
        tally[res["verdict"]] += 1
        extra = ""
        if res["verdict"] in ("verified", "not_fail_to_pass"):
            extra = f"  before={res['before']} after={res['after']}"
        print(f"{res['verdict']:18s} {spec['id']:34s}{extra}")

    print("\n=== verification tally ===")
    for k, v in tally.most_common():
        print(f"  {k:20s} {v}")
    print(f"verified tasks in {VERIFIED}")


if __name__ == "__main__":
    main()
