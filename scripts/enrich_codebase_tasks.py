"""Attach human-written context to verified codebase tasks (no LLM text).

For every task in ``cybersec_env/data/codebase_tasks/`` (and its working copy in
``data/codebase/verified/``) this adds a ``reference`` field with:

* ``advisory``      - the full OSV advisory: the maintainers' / GitHub advisory
                      team's description of the bug and its impact, aliases,
                      dates, severity, affected ranges and reference links;
                      plus ``related_advisories`` (the aliases' own texts) when
                      they say something the primary record does not;
* ``fix_commit``    - the developer's commit message for the fix (fetched with a
                      metadata-only git fetch: no file contents, no API quota);
* ``pull_requests`` - title and description of the PR(s) that carried the fix,
                      from the GitHub REST API (60 requests/hour without a
                      token; set ``GITHUB_TOKEN`` for more). Rate-limited
                      lookups are left ``pending`` and retried on a later pass.

``reference`` is answer-bearing (advisory texts often describe the fix), so it
must never be shown to a model under evaluation: the model-facing text is the
task's ``instruction`` field, which this script does not touch.

The script only rewrites existing task files (atomically), never creates or
deletes them, so it runs safely next to the harvester, which only creates new
ones. ``--loop`` keeps enriching tasks as the harvester verifies them.

    python scripts/enrich_codebase_tasks.py            # one pass
    python scripts/enrich_codebase_tasks.py --loop     # until stopped
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRACKED = ROOT / "cybersec_env" / "data" / "codebase_tasks"
VERIFIED = ROOT / "data" / "codebase" / "verified"
sys.path.insert(0, str(ROOT))
from cybersec_env.codebase.grader import _rmtree  # noqa: E402  (read-only-safe delete)

OSV_URL = "https://api.osv.dev/v1/vulns/{}"
GH_API = "https://api.github.com/repos/{}/{}/pulls/{}"
SCHEMA = 1


class RateLimited(Exception):
    pass


_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def _redact(text: str) -> str:
    """Mask e-mail addresses (Co-authored-by / Signed-off-by trailers, PR
    bodies): the dataset is meant to be published, and the addresses add
    nothing to the security context."""
    return _EMAIL.sub("<email>", text or "")


def _get_json(url: str, headers: dict | None = None, tries: int = 3):
    for i in range(tries):
        req = urllib.request.Request(url, headers={"User-Agent": "cybersec-env-enrich",
                                                   **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code in (403, 429) and "api.github.com" in url:
                raise RateLimited(e.headers.get("x-ratelimit-reset", ""))
            if i == tries - 1:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if i == tries - 1:
                raise
        time.sleep(5 * (i + 1))


def _advisory_record(adv: dict, package: str) -> dict:
    affected = [
        {"package": a.get("package", {}).get("name"),
         "ranges": a.get("ranges", [])}
        for a in adv.get("affected", [])
        if (a.get("package", {}).get("name") or "").lower() == (package or "").lower()
    ]
    return {
        "id": adv.get("id"),
        "summary": adv.get("summary", ""),
        "details": _redact(adv.get("details", "")),
        "aliases": adv.get("aliases", []),
        "published": adv.get("published"),
        "modified": adv.get("modified"),
        "severity": adv.get("database_specific", {}).get("severity"),
        "cwe_ids": adv.get("database_specific", {}).get("cwe_ids", []),
        "affected": affected,
        "references": adv.get("references", []),
        "source": OSV_URL.format(adv.get("id")),
    }


def fetch_advisory(spec: dict) -> dict:
    adv = _get_json(OSV_URL.format(spec["id"]))
    if adv is None:
        return {"status": "not_found"}
    rec = _advisory_record(adv, spec.get("package"))
    # PYSEC / CVE / GHSA records of the same bug are written by different
    # people; keep an alias's text when it adds something the primary lacks.
    related = []
    seen = {rec["details"].strip()}
    for alias in adv.get("aliases", []):
        if not re.match(r"^(GHSA|PYSEC)-", alias):
            continue
        other = _get_json(OSV_URL.format(alias))
        if other and (other.get("details") or "").strip() and other["details"].strip() not in seen:
            seen.add(other["details"].strip())
            related.append({"id": alias, "summary": other.get("summary", ""),
                            "details": _redact(other["details"]), "source": OSV_URL.format(alias)})
    rec["related_advisories"] = related
    rec["status"] = "ok"
    return rec


def _git(args, cwd, timeout=180):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def fetch_commit(spec: dict) -> dict:
    """The fix commit's message, via a fetch that downloads only the commit
    object (``--filter=tree:0``: no trees, no file contents)."""
    url, sha = spec["repo"]["url"], spec["fix_commit"]
    work = tempfile.mkdtemp(prefix="cse_enrich_")
    try:
        _git(["init", "-q"], work)
        _git(["remote", "add", "origin", url], work)
        ok = False
        for extra in (["--filter=tree:0"], []):  # some servers lack filters
            if _git(["fetch", "-q", "--depth", "1", *extra, "origin", sha], work, 300).returncode == 0:
                ok = True
                break
        if not ok:
            return {"status": "fetch_failed", "sha": sha}
        fmt = "%H%x00%aI%x00%cI%x00%B"
        out = _git(["log", "-1", f"--format={fmt}", sha], work).stdout
        full, authored, committed, message = (out.split("\x00") + ["", "", "", ""])[:4]
        return {"status": "ok", "sha": full.strip() or sha, "authored_at": authored,
                "committed_at": committed, "message": _redact(message.strip()),
                "url": f"{url.rstrip('/')}/commit/{sha}"}
    finally:
        _rmtree(work)


def _pr_numbers(spec: dict, advisory: dict, commit: dict) -> list[tuple[str, str, int]]:
    owner, name = spec["repo"]["owner"], spec["repo"]["name"]
    found = []
    for ref in advisory.get("references", []):
        m = re.match(r"https://github\.com/([^/]+)/([^/]+)/pull/(\d+)", ref.get("url", ""))
        if m:
            found.append((m.group(1), m.group(2), int(m.group(3))))
    msg = commit.get("message", "")
    for m in re.finditer(r"(?:\(#(\d+)\)|Merge pull request #(\d+)|pull request #(\d+))", msg):
        num = next(g for g in m.groups() if g)
        found.append((owner, name, int(num)))
    out = []
    for o, n, num in found:
        if (o.lower(), n.lower(), num) not in {(a.lower(), b.lower(), c) for a, b, c in out}:
            out.append((o, n, num))
    return out


def fetch_prs(spec: dict, advisory: dict, commit: dict) -> list[dict]:
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    prs = []
    for owner, name, num in _pr_numbers(spec, advisory, commit):
        url = f"https://github.com/{owner}/{name}/pull/{num}"
        pr = _get_json(GH_API.format(owner, name, num), headers)  # may raise RateLimited
        if pr is None:
            prs.append({"status": "not_found", "url": url})
            continue
        prs.append({"status": "ok", "number": num, "url": url, "title": _redact(pr.get("title", "")),
                    "body": _redact(pr.get("body") or ""), "merged_at": pr.get("merged_at"),
                    "merge_commit_sha": pr.get("merge_commit_sha")})
    return prs


def _write_atomic(path: Path, data: dict) -> None:
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                   encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def _needs(ref: dict) -> set[str]:
    todo = set()
    if not ref or ref.get("schema") != SCHEMA:
        return {"advisory", "fix_commit", "pull_requests"}
    if ref.get("advisory", {}).get("status") not in ("ok", "not_found"):
        todo.add("advisory")
    if ref.get("fix_commit", {}).get("status") != "ok":
        todo.add("fix_commit")
    if ref.get("pull_requests_status") != "ok":
        todo.add("pull_requests")
    return todo


def enrich_one(path: Path, gh_blocked_until: float) -> tuple[str, float]:
    try:
        spec = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return "unreadable", gh_blocked_until  # being written right now: next pass
    ref = dict(spec.get("reference") or {})
    todo = _needs(ref)
    if not todo:
        return "complete", gh_blocked_until
    ref["schema"] = SCHEMA
    if "advisory" in todo:
        try:
            ref["advisory"] = fetch_advisory(spec)
        except Exception as exc:
            ref["advisory"] = {"status": f"error:{type(exc).__name__}"}
    if "fix_commit" in todo:
        try:
            ref["fix_commit"] = fetch_commit(spec)
        except Exception as exc:
            ref["fix_commit"] = {"status": f"error:{type(exc).__name__}", "sha": spec["fix_commit"]}
    if "pull_requests" in todo and ref["fix_commit"].get("status") == "ok" \
            and ref["advisory"].get("status") in ("ok", "not_found"):
        if time.time() < gh_blocked_until:
            ref["pull_requests_status"] = "pending_rate_limit"
        else:
            try:
                ref["pull_requests"] = fetch_prs(spec, ref["advisory"], ref["fix_commit"])
                ref["pull_requests_status"] = "ok"
            except RateLimited as rl:
                reset = float(rl.args[0]) if rl.args and str(rl.args[0]).isdigit() else time.time() + 3600
                gh_blocked_until = reset + 5
                ref["pull_requests_status"] = "pending_rate_limit"
            except Exception as exc:
                ref["pull_requests_status"] = f"error:{type(exc).__name__}"
    ref["enriched_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    ref["note"] = ("Human-written context from OSV and the project's git history. "
                   "Answer-bearing: never include in model prompts.")
    spec["reference"] = ref
    _write_atomic(path, spec)
    mirror = VERIFIED / path.name
    if mirror.exists():
        try:
            other = json.loads(mirror.read_text(encoding="utf-8"))
            other["reference"] = ref
            _write_atomic(mirror, other)
        except (json.JSONDecodeError, OSError):
            pass
    return ("complete" if not _needs(ref) else "partial"), gh_blocked_until


def one_pass(gh_blocked_until: float) -> tuple[dict, float]:
    tally: dict[str, int] = {}
    for path in sorted(TRACKED.glob("*.json")):
        status, gh_blocked_until = enrich_one(path, gh_blocked_until)
        tally[status] = tally.get(status, 0) + 1
    return tally, gh_blocked_until


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true", help="keep enriching new tasks")
    ap.add_argument("--every", type=int, default=600, help="seconds between passes")
    args = ap.parse_args()
    blocked = 0.0
    while True:
        tally, blocked = one_pass(blocked)
        print(f"{datetime.now():%H:%M} {tally}" +
              (f" (GitHub API limited until {datetime.fromtimestamp(blocked):%H:%M})"
               if blocked > time.time() else ""), flush=True)
        if not args.loop:
            break
        time.sleep(args.every)


if __name__ == "__main__":
    sys.exit(main())
