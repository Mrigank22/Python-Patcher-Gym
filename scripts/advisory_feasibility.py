"""Feasibility count for a codebase-level (SWE-bench-style) security track.

Before building Docker-per-task fixing tasks from real advisories, we need to
know how many advisories could actually become a *verifiable* task. A task is
only usable if the published fix lets us build a fail-to-pass test: the fix
commit itself has to add or change a test, so we can run it against the
vulnerable code (fails) and the fixed code (passes).

This script answers, from the public OSV PyPI database (no API needed) plus an
optional GitHub pass:

  stage 0  all PyPI advisories
  stage 1    published on/after --since (recent = less likely memorised)
  stage 2    with a GitHub commit reference (the fix commit; GHSA stores these
             as WEB/FIX references pointing at /commit/<sha>)
  stage 2b     and GitHub-reviewed (higher-quality, curated advisories)
  stage 3    whose fix commit touched a test file   [needs GitHub, sampled]

and breaks the counts down by CWE. Stages 0-2 run offline from the OSV zip;
stage 3 samples ``--github-sample`` fix commits via the GitHub API (set
``GITHUB_TOKEN`` to lift the 60/hour anonymous limit).

Usage::

    python scripts/advisory_feasibility.py --osv-zip all.zip --since 2024-06-01 \\
        --github-sample 150
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"

_COMMIT_RE = re.compile(r"https?://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})", re.I)
_TEST_PATH_RE = re.compile(r"(^|/)(tests?|testing)/|(^|/)test_|_test\.py$|conftest\.py$", re.I)


def load_osv(zip_path: str):
    with zipfile.ZipFile(zip_path) as z:
        for name in z.namelist():
            if name.endswith(".json"):
                try:
                    yield json.loads(z.read(name))
                except Exception:
                    continue


def cwes(adv) -> list:
    out = []
    for key in (adv.get("database_specific") or {},):
        c = key.get("cwe_ids") if isinstance(key, dict) else None
        if c:
            out += c
    for aff in adv.get("affected", []):
        ds = aff.get("database_specific") or {}
        if isinstance(ds, dict) and ds.get("cwe_ids"):
            out += ds["cwe_ids"]
    return sorted(set(out)) or ["unknown"]


def fix_commits(adv) -> list:
    # GHSA records usually attach the fix commit as a WEB (sometimes FIX)
    # reference whose url is .../commit/<sha>. We treat any github commit url in
    # any reference as the fix-commit signal, preferring a FIX-typed one.
    typed, other = [], []
    for ref in adv.get("references", []):
        m = _COMMIT_RE.search(ref.get("url", ""))
        if not m:
            continue
        (typed if ref.get("type") == "FIX" else other).append(
            (m.group(1), m.group(2), m.group(3)))
    return typed + other


def is_reviewed(adv) -> bool:
    return bool((adv.get("database_specific") or {}).get("github_reviewed"))


def commit_touches_test(owner, repo, sha, token) -> bool | None:
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "cse-feasibility"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
    except Exception:
        return None
    files = data.get("files") or []
    return any(_TEST_PATH_RE.search(f.get("filename", "")) for f in files)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--osv-zip", default=None, help="path to PyPI all.zip (downloaded if absent)")
    ap.add_argument("--since", default="2024-06-01", help="keep advisories published on/after this date")
    ap.add_argument("--github-sample", type=int, default=0, help="sample N fix commits for the test-touch check")
    ap.add_argument("--out", default=str(ROOT / "results" / "advisory_feasibility.md"))
    args = ap.parse_args()

    zip_path = args.osv_zip
    if not zip_path:
        zip_path = str(ROOT / "all.zip")
        if not os.path.exists(zip_path):
            print("downloading OSV PyPI archive ...")
            urllib.request.urlretrieve(OSV_URL, zip_path)

    since = args.since
    n_all = n_recent = n_fix = n_fix_reviewed = 0
    by_cwe = collections.Counter()           # recent advisories with a fix commit, by CWE
    fix_pool = []                            # (owner, repo, sha, id, cwe) for sampling

    for adv in load_osv(zip_path):
        n_all += 1
        pub = (adv.get("published") or "")[:10]
        if pub < since:
            continue
        n_recent += 1
        fixes = fix_commits(adv)
        if not fixes:
            continue
        n_fix += 1
        if is_reviewed(adv):
            n_fix_reviewed += 1
        cs = cwes(adv)
        for c in cs:
            by_cwe[c] += 1
        owner, repo, sha = fixes[0]
        fix_pool.append((owner, repo, sha, adv.get("id"), cs[0]))

    lines = []
    def p(s=""):
        print(s); lines.append(s)

    p(f"# Advisory feasibility — codebase security track\n")
    p(f"Source: OSV PyPI database ({zip_path}), analysed {time.strftime('%Y-%m-%d')}.\n")
    p(f"| stage | advisories |")
    p(f"|---|---|")
    p(f"| 0. all PyPI advisories | {n_all} |")
    p(f"| 1. published >= {since} | {n_recent} |")
    p(f"| 2. with a GitHub **fix commit** | {n_fix} |")
    p(f"| 2b. and GitHub-reviewed (curated) | {n_fix_reviewed} |")
    p("")
    p("## Stage-2 advisories (recent + fix commit) by CWE — top 20\n")
    p("| CWE | count |")
    p("|---|---|")
    for cwe, n in by_cwe.most_common(20):
        p(f"| {cwe} | {n} |")
    p("")

    # Stage 3: sample fix commits and see whether they touched a test file.
    if args.github_sample and fix_pool:
        import random
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        sample = random.Random(0).sample(fix_pool, min(args.github_sample, len(fix_pool)))
        touched = checked = 0
        limit = 55 if not token else 4900
        p(f"## Stage 3 — fix-commit-touches-test, sampled\n")
        p(f"GitHub auth: {'token' if token else 'anonymous (~60/hr)'}; "
          f"sampling up to {min(len(sample), limit)} of {len(fix_pool)} fix commits.\n")
        for owner, repo, sha, vid, cwe in sample:
            if checked >= limit:
                break
            res = commit_touches_test(owner, repo, sha, token)
            if res is None:
                continue
            checked += 1
            touched += 1 if res else 0
            if not token:
                time.sleep(1.0)  # be gentle with the anonymous limit
        if checked:
            rate = touched / checked
            p(f"- fix commits checked: **{checked}**")
            p(f"- of those, touched a test file: **{touched}** ({rate:.0%})")
            p(f"- → projected usable tasks (stage 2 x rate): "
              f"**~{int(n_fix * rate)}** of {n_fix}\n")
        else:
            p("- no commits could be checked (rate limit or network).\n")
    else:
        p("## Stage 3 — skipped (pass --github-sample N, ideally with GITHUB_TOKEN)\n")

    p("### Reading this\n")
    p("Stage 2 is the ceiling for a quick Docker track; stage 3's rate is the "
      "fraction of those that already ship a fail-to-pass test, i.e. buildable "
      "with little manual test-writing. The rest would need a hand-written "
      "proof-of-vulnerability test, which is slower but higher-value.")

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
