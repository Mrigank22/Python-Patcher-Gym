"""Stage 1 of the codebase track: collect candidate advisories from OSV.

Builds a de-duplicated index of every PyPI advisory that has a usable GitHub
*fix commit*, across the whole date range (oldest → latest) so the dataset
covers the full history of Python vulnerabilities, not only recent ones. Each
row is compact metadata; the heavy work (cloning, Docker, test discovery)
happens later in ``build_codebase_tasks.py`` and reads this index.

The OSV PyPI archive is public (no API, refreshed continuously), so re-running
with ``--refresh`` re-downloads it and picks up advisories published since the
last run — that is how "up to the latest" stays true.

Output: ``cybersec_env/data/advisories/candidates.jsonl`` (one JSON row per
advisory) and a short ``candidates_summary.md``.

Row schema::

    {"id", "aliases", "cwes", "severity", "published", "modified",
     "package", "repo": {"owner","name","url"},
     "fix_commits": [sha, ...], "fixed_versions": [...],
     "introduced_versions": [...], "summary", "era"}

``era`` is a coarse split for later calibration: "legacy" (< 2022),
"recent" (2022..2024-05) or "post_cutoff" (>= 2024-06); it is advisory metadata,
never a filter here.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "cybersec_env" / "data" / "advisories"
OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"

_COMMIT_RE = re.compile(r"github\.com/([^/\s]+)/([^/\s]+?)(?:\.git)?/commit/([0-9a-f]{7,40})", re.I)
_REPO_RE = re.compile(r"github\.com/([^/\s]+)/([^/\s]+?)(?:\.git|/|$)", re.I)


def era(published: str) -> str:
    d = (published or "")[:10]
    if not d:
        return "unknown"
    if d >= "2024-06-01":
        return "post_cutoff"
    if d >= "2022-01-01":
        return "recent"
    return "legacy"


def load_osv(zip_path: str):
    with zipfile.ZipFile(zip_path) as z:
        for name in z.namelist():
            if name.endswith(".json"):
                try:
                    yield json.loads(z.read(name))
                except Exception:
                    continue


def extract(adv) -> dict | None:
    refs = adv.get("references", [])
    fix_commits, repos = [], collections.Counter()
    for ref in refs:
        url = ref.get("url", "")
        m = _COMMIT_RE.search(url)
        if m:
            owner, repo, sha = m.group(1), m.group(2), m.group(3)
            fix_commits.append((owner, repo, sha))
            repos[(owner, repo)] += 1
    if not fix_commits:
        return None
    # The repo most fix-commit references agree on (usually the only one).
    (owner, repo), _ = repos.most_common(1)[0]
    shas = [s for o, r, s in fix_commits if (o, r) == (owner, repo)]

    pkgs, fixed, introduced = set(), set(), set()
    for aff in adv.get("affected", []):
        p = aff.get("package", {})
        if p.get("ecosystem") == "PyPI" and p.get("name"):
            pkgs.add(p["name"])
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if ev.get("fixed"):
                    fixed.add(ev["fixed"])
                if ev.get("introduced") and ev["introduced"] != "0":
                    introduced.add(ev["introduced"])
        for v in aff.get("versions", [])[:1]:
            introduced.add(v)

    ds = adv.get("database_specific") or {}
    sev = ds.get("severity") or (adv.get("severity") or [{}])[0].get("score", "")
    return {
        "id": adv.get("id"),
        "aliases": adv.get("aliases", []),
        "cwes": ds.get("cwe_ids") or ["unknown"],
        "severity": sev,
        "github_reviewed": bool(ds.get("github_reviewed")),
        "published": adv.get("published"),
        "modified": adv.get("modified"),
        "package": sorted(pkgs)[0] if pkgs else None,
        "all_packages": sorted(pkgs),
        "repo": {"owner": owner, "name": repo,
                 "url": f"https://github.com/{owner}/{repo}"},
        "fix_commits": list(dict.fromkeys(shas)),
        "fixed_versions": sorted(fixed),
        "introduced_versions": sorted(introduced),
        "summary": (adv.get("summary") or "").strip(),
        "era": era(adv.get("published")),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--osv-zip", default=str(ROOT / "all.zip"))
    ap.add_argument("--refresh", action="store_true", help="re-download the OSV archive first")
    args = ap.parse_args()

    zip_path = args.osv_zip
    if args.refresh or not os.path.exists(zip_path):
        print("downloading OSV PyPI archive ...")
        urllib.request.urlretrieve(OSV_URL, zip_path)

    rows, seen = [], set()
    n_total = n_withfix = 0
    for adv in load_osv(zip_path):
        n_total += 1
        rec = extract(adv)
        if not rec or not rec["package"]:
            continue
        n_withfix += 1
        key = rec["id"]
        if key in seen:
            continue
        seen.add(key)
        rows.append(rec)

    rows.sort(key=lambda r: r.get("published") or "")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / "candidates.jsonl"
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")

    by_era = collections.Counter(r["era"] for r in rows)
    by_cwe = collections.Counter(c for r in rows for c in r["cwes"])
    multi_commit = sum(1 for r in rows if len(r["fix_commits"]) > 1)
    reviewed = sum(1 for r in rows if r["github_reviewed"])

    lines = ["# Advisory candidate index (codebase track)\n",
             f"Collected from OSV PyPI, {n_total} advisories scanned.\n",
             f"- candidates with a GitHub fix commit + PyPI package: **{len(rows)}**",
             f"- GitHub-reviewed (curated): {reviewed}",
             f"- single fix commit: {len(rows)-multi_commit}; multi-commit: {multi_commit}",
             "", "## By era (coverage across time)", "",
             "| era | advisories |", "|---|---|"]
    for e in ("legacy", "recent", "post_cutoff", "unknown"):
        lines.append(f"| {e} | {by_era.get(e,0)} |")
    lines += ["", "## Top 25 CWEs", "", "| CWE | count |", "|---|---|"]
    for cwe, n in by_cwe.most_common(25):
        lines.append(f"| {cwe} | {n} |")
    (OUT_DIR / "candidates_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")

    print(f"scanned {n_total} advisories; wrote {len(rows)} candidates to {out}")
    print(f"era split: {dict(by_era)}")
    print(f"top CWEs: {by_cwe.most_common(8)}")


if __name__ == "__main__":
    main()
