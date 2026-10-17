"""Stage 2 of the codebase track: turn candidate advisories into task specs.

For each candidate (from ``collect_advisories.py``) this clones just the fix
commit and its parent, splits the fix into a **source patch** (the gold answer
the model must reproduce) and a **test patch** (the regression test the fix
added), and keeps only advisories where the fix actually touched a test file —
the prerequisite for a fail-to-pass check.

Two modes:

* ``--triage`` (default, fast, no Docker): clone depth-2, classify the diff,
  extract patches, write a task spec. Measures the real "usable test patch"
  rate on whatever sample you point it at.
* ``--verify`` (slow, needs Docker): additionally hand each spec to
  ``verify_codebase_task.py`` to confirm fail-to-pass inside a container.

A task spec (``data/codebase/specs/<id>.json``) is SWE-bench-shaped::

    {"id", "cwes", "package", "repo", "base_commit" (parent), "fix_commit",
     "python_requires", "source_patch", "test_patch",
     "changed_source_files", "changed_test_files", "candidate_f2p_files",
     "instruction", "era", "verified": false}

Specs live under ``data/codebase/`` (git-ignored; large and reproducible).
Run a sample first, e.g. ``--sample 60 --by-era`` to size yield across time.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAND = ROOT / "cybersec_env" / "data" / "advisories" / "candidates.jsonl"
OUT = ROOT / "data" / "codebase"
SPECS = OUT / "specs"

_TEST_RE = re.compile(r"(^|/)(tests?|testing)/|(^|/)test_[^/]*\.py$|[^/]*_test\.py$|conftest\.py$", re.I)
_PYREQ_RE = re.compile(r"""python_requires\s*=\s*['"]([^'"]+)['"]""")
_PYREQ_TOML_RE = re.compile(r"""requires-python\s*=\s*['"]([^'"]+)['"]""")


def run(cmd, cwd=None, timeout=180):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                          timeout=timeout, errors="replace")


def fetch_commit(repo_url: str, sha: str, workdir: str) -> bool:
    """Shallow-fetch ``sha`` and its parent into a fresh repo at ``workdir``."""
    if run(["git", "init", "-q", workdir]).returncode != 0:
        return False
    env_cmds = [
        ["git", "-C", workdir, "remote", "add", "origin", repo_url],
        # depth 2 brings the commit and its first parent, enough for the diff.
        ["git", "-C", workdir, "fetch", "-q", "--depth", "2", "origin", sha],
    ]
    for c in env_cmds:
        if run(c, timeout=240).returncode != 0:
            return False
    return run(["git", "-C", workdir, "checkout", "-q", sha]).returncode == 0


def diff_files(workdir: str, sha: str):
    r = run(["git", "-C", workdir, "diff", "--name-only", f"{sha}^", sha])
    if r.returncode != 0:
        return None
    return [f for f in r.stdout.splitlines() if f.strip()]


def patch_for(workdir: str, sha: str, paths):
    if not paths:
        return ""
    r = run(["git", "-C", workdir, "diff", f"{sha}^", sha, "--"] + paths)
    return r.stdout if r.returncode == 0 else ""


def python_requires(workdir: str) -> str:
    for rel, rx in (("setup.cfg", _PYREQ_RE), ("setup.py", _PYREQ_RE),
                    ("pyproject.toml", _PYREQ_TOML_RE)):
        p = Path(workdir) / rel
        if p.is_file():
            try:
                m = rx.search(p.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                m = None
            if m:
                return m.group(1)
    return ""


def triage_one(cand: dict) -> dict:
    sha = cand["fix_commits"][0]
    repo_url = cand["repo"]["url"]
    work = tempfile.mkdtemp(prefix="cse_build_")
    try:
        if not fetch_commit(repo_url, sha, work):
            return {"id": cand["id"], "status": "clone_failed"}
        files = diff_files(work, sha)
        if files is None:
            return {"id": cand["id"], "status": "diff_failed"}
        test_files = [f for f in files if _TEST_RE.search(f)]
        src_files = [f for f in files if f not in test_files and f.endswith(".py")]
        if not test_files:
            return {"id": cand["id"], "status": "no_test_in_fix",
                    "changed": len(files)}
        if not src_files:
            return {"id": cand["id"], "status": "no_source_change",
                    "changed": len(files)}
        spec = {
            "id": cand["id"],
            "aliases": cand.get("aliases", []),
            "cwes": cand.get("cwes", []),
            "severity": cand.get("severity", ""),
            "package": cand["package"],
            "repo": cand["repo"],
            "base_commit": None,  # resolved below to the parent sha
            "fix_commit": sha,
            "python_requires": python_requires(work),
            "changed_source_files": src_files,
            "changed_test_files": test_files,
            "source_patch": patch_for(work, sha, src_files),
            "test_patch": patch_for(work, sha, test_files),
            "summary": cand.get("summary", ""),
            "era": cand.get("era"),
            "verified": False,
        }
        parent = run(["git", "-C", work, "rev-parse", f"{sha}^"]).stdout.strip()
        spec["base_commit"] = parent or None
        spec["instruction"] = _instruction(cand)
        if not spec["source_patch"].strip():
            return {"id": cand["id"], "status": "empty_source_patch"}
        SPECS.mkdir(parents=True, exist_ok=True)
        (SPECS / f"{_safe(cand['id'])}.json").write_text(json.dumps(spec, indent=2),
                                                         encoding="utf-8")
        return {"id": cand["id"], "status": "spec_written",
                "n_src": len(src_files), "n_test": len(test_files),
                "cwe": (cand.get("cwes") or ["?"])[0]}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _safe(advisory_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", advisory_id)


def _instruction(cand: dict) -> str:
    cwe = ", ".join(cand.get("cwes") or []) or "a security issue"
    pkg = cand["package"]
    return (f"The package `{pkg}` has a security vulnerability ({cwe}). "
            f"A regression test describing the required secure behaviour has been "
            f"added to the repository. Modify the package source so the test "
            f"passes while keeping existing behaviour intact. Do not edit tests.")


def load_candidates():
    with open(CAND, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def pick(cands, args):
    pool = cands
    if args.era:
        pool = [c for c in pool if c.get("era") == args.era]
    if args.cwe:
        pool = [c for c in pool if args.cwe in (c.get("cwes") or [])]
    if args.reviewed:
        pool = [c for c in pool if c.get("github_reviewed")]
    if args.ids:
        want = set(args.ids.split(","))
        return [c for c in cands if c["id"] in want]
    rnd = random.Random(args.seed)
    if args.by_era:
        out = []
        for e in ("legacy", "recent", "post_cutoff"):
            sub = [c for c in pool if c.get("era") == e]
            rnd.shuffle(sub)
            out += sub[: args.sample // 3]
        return out
    rnd.shuffle(pool)
    return pool[: args.sample] if args.sample else pool


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=30)
    ap.add_argument("--by-era", action="store_true", help="balance the sample across eras")
    ap.add_argument("--era", default=None)
    ap.add_argument("--cwe", default=None)
    ap.add_argument("--reviewed", action="store_true", help="only GitHub-reviewed advisories")
    ap.add_argument("--ids", default=None, help="comma-separated advisory ids")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--verify", action="store_true", help="also Docker-verify each spec")
    args = ap.parse_args()

    cands = load_candidates()
    chosen = pick(cands, args)
    print(f"triaging {len(chosen)} candidates ...")
    import collections
    status = collections.Counter()
    written = []
    for i, c in enumerate(chosen, 1):
        try:
            res = triage_one(c)
        except subprocess.TimeoutExpired:
            res = {"id": c["id"], "status": "timeout"}
        except Exception as exc:
            res = {"id": c["id"], "status": f"error:{type(exc).__name__}"}
        status[res["status"]] += 1
        if res["status"] == "spec_written":
            written.append(res)
        if i % 10 == 0 or i == len(chosen):
            print(f"  {i}/{len(chosen)}  {dict(status)}")

    print("\n=== triage result ===")
    for k, v in status.most_common():
        print(f"  {k:20s} {v}")
    n_ok = status["spec_written"]
    print(f"\nusable specs: {n_ok}/{len(chosen)} ({n_ok/max(len(chosen),1):.0%})")
    if written:
        by_cwe = collections.Counter(w["cwe"] for w in written)
        print("spec CWEs:", dict(by_cwe))
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "triage_report.json").write_text(
        json.dumps({"n": len(chosen), "status": dict(status),
                    "written": written}, indent=2), encoding="utf-8")
    print(f"specs in {SPECS}, report in {OUT/'triage_report.json'}")

    if args.verify and written:
        print("\n=== Docker verification ===")
        from verify_codebase_task import verify_spec  # noqa
        ok = 0
        for w in written:
            spec_path = SPECS / f"{_safe(w['id'])}.json"
            v = verify_spec(json.loads(spec_path.read_text()))
            print(f"  {w['id']:30s} {v['verdict']}")
            ok += 1 if v["verdict"] == "verified" else 0
        print(f"verified {ok}/{len(written)}")


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT / "scripts"))
    main()
