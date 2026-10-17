"""Shared validation for benchmark importers (``import_cweval.py``, ...).

A converted record is kept only if, in this environment's own grader:

1. its tests do not read the clock (a noisy reward),
2. the reference passes every test, and there is at least one functional and
   one security test (discovered from the reference run),
3. the reference is ``solved``, the vulnerable seed is not, and an empty stub
   is not.

Records are validated in parallel (each grading is its own subprocess).
"""

from __future__ import annotations

import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cybersec_env.tasks import imported  # noqa: E402
from cybersec_env.verifier import Verifier  # noqa: E402

_CLOCK = re.compile(r"datetime\.(datetime\.)?now\(|time\.time\(|date\.today\(")


def write_records(source: str, recs) -> Path:
    path = imported.DATA_DIR / f"{source}.jsonl"
    imported.DATA_DIR.mkdir(parents=True, exist_ok=True)
    clean = [{k: v for k, v in r.items() if not k.startswith("_")} for r in recs]
    path.write_text("".join(json.dumps(r) + "\n" for r in clean), encoding="utf-8")
    imported.records.cache_clear()
    return path


def validate(source: str, recs, workers: int = 8, timeout_s: float = 30.0):
    """Return ``(kept_records, report_rows)``; ``report_rows`` = (name, cwe, result)."""
    v = Verifier(timeout_s=timeout_s, reward_mode="shaped")
    write_records(source, recs)

    def discover(i):
        w = v._run_worker(f"{source}-1-{i}", recs[i]["reference_code"])
        return w.get("discovered") or {}, w.get("error", "")

    with ThreadPoolExecutor(workers) as pool:
        found = list(pool.map(discover, range(len(recs))))
    for rec, (disc, err) in zip(recs, found):
        rec["functional_tests"] = [k for k, (kind, _) in disc.items() if kind == "functional"]
        rec["security_tests"] = [k for k, (kind, _) in disc.items() if kind == "security"]
        rec["_ref_ok"] = bool(disc) and all(ok for _, ok in disc.values())
        rec["_err"] = err
    write_records(source, recs)

    def check(i):
        rec = recs[i]
        if _CLOCK.search(rec["test_code"]):
            return "dropped: time-dependent test (non-deterministic reward)"
        if not rec["_ref_ok"] or not rec["functional_tests"] or not rec["security_tests"]:
            return "dropped: " + (rec["_err"][:70] or "reference fails or lacks functional/security tests")
        tid = f"{source}-1-{i}"
        ref = v.grade_source(tid, rec["reference_code"])
        if not ref.solved:
            return f"dropped: reference not solved ({ref.error[:60]})"
        vul = v.grade_source(tid, rec["prompt_code"])
        if vul.solved:
            return "dropped: vulnerable seed passes every test"
        stub = v.grade_source(tid, f"def {rec['entrypoint']}(*args, **kwargs):\n    return None\n")
        if stub.solved:
            return "dropped: empty stub passes"
        return (f"kept: seed func {vul.functional_pass}/{vul.functional_total}, "
                f"sec {vul.security_pass}/{vul.security_total}")

    with ThreadPoolExecutor(workers) as pool:
        verdicts = list(pool.map(check, range(len(recs))))
    kept = [r for r, why in zip(recs, verdicts) if why.startswith("kept")]
    report = [(r["origin_id"].rsplit("/", 1)[-1], r["cwe"], why) for r, why in zip(recs, verdicts)]
    write_records(source, kept)
    return kept, report


def write_report(source: str, header_lines, report, n_total: int, n_kept: int) -> str:
    lines = [f"# {source} import report", ""] + list(header_lines) + [
        f"Kept {n_kept} of {n_total} tasks.", "", "| Task | CWE | Result |", "| --- | --- | --- |"]
    lines += [f"| {n} | {c} | {r} |" for n, c, r in report]
    text = "\n".join(lines) + "\n"
    (imported.DATA_DIR / f"{source}_import_report.md").write_text(text, encoding="utf-8")
    return text
