"""Import SecCodePLT's insecure-coding tasks as validated repair tasks.

SecCodePLT (Yang et al., 2024; MIT, https://huggingface.co/datasets/Virtue-AI-HUB/SecCodePLT,
gated: request access first) gives, per task, a function split into
``code_before`` + body + ``code_after`` with a vulnerable and a patched body,
module ``setup`` code, and a test table ``testcases = {"capability": [...],
"safety": [...]}`` of ``(kwargs, expected)`` pairs, where ``expected`` may be
an exception class. Only tasks with such executable tests are imported (the
``use_rule`` tasks are judged by a written rule instead and are skipped).

Per task: prompt = setup + function with the vulnerable body, oracle = the
patched function, grader = a generated pytest module (capability cases marked
``functionality``, safety cases ``security``). Every task is validated by
``import_common.validate``. A stable 15% of tasks (by id hash) forms the test
split; note these are close siblings of training tasks, so CWEval remains the
out-of-distribution check.

    python scripts/import_seccodeplt.py
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from import_common import validate, write_report  # noqa: E402

SOURCE = "seccodeplt"
REPO = "Virtue-AI-HUB/SecCodePLT"
FILE = "data/insecure_coding-00000-of-00001.parquet"
TEST_FRACTION = 0.15

CWE_TITLES = {
    "74": "Injection into a downstream component", "77": "Command injection",
    "79": "Cross-site scripting", "94": "Code injection", "95": "Eval injection",
    "200": "Exposure of sensitive information", "327": "Broken or risky cryptographic algorithm",
    "347": "Improper verification of a cryptographic signature",
    "352": "Cross-site request forgery", "502": "Deserialization of untrusted data",
    "601": "Open redirect", "770": "Resource allocation without limits",
    "862": "Missing authorization", "863": "Incorrect authorization",
    "915": "Unsafe modification of object attributes (mass assignment)",
    "918": "Server-side request forgery", "1333": "Inefficient regular expression (ReDoS)",
}

TEST_TEMPLATE = '''import pytest
from {module} import *  # noqa: F401,F403 - task context (setup names)
from {module} import {fn}

{testcases}


def _check(kwargs, expected):
    if isinstance(expected, type) and issubclass(expected, BaseException):
        with pytest.raises(expected):
            {fn}(**kwargs)
    else:
        assert {fn}(**kwargs) == expected


@pytest.mark.parametrize("kwargs, expected", [
    pytest.param(a, e, marks=pytest.mark.functionality) for a, e in testcases["capability"]
] + [
    pytest.param(a, e, marks=pytest.mark.security) for a, e in testcases["safety"]
])
def test_{fn}(kwargs, expected):
    _check(kwargs, expected)
'''


def convert(row) -> dict:
    td, gt, ut = row["task_description"], row["ground_truth"], row["unittest"]
    fn = td["function_name"]
    setup = (ut.get("setup") or "").strip()
    before, after = gt["code_before"], gt["code_after"]
    vulnerable = f"{before}{gt['vulnerable_code']}{after}".strip("\n")
    patched = f"{before}{gt['patched_code']}{after}".strip("\n")
    context = setup + "\n\n" if setup else ""
    module = f"spl_{row['id']}"
    in_test = int(hashlib.sha256(row["id"].encode()).hexdigest(), 16) % 1000 < TEST_FRACTION * 1000
    cwe = f"CWE-{int(row['CWE_ID']):03d}"
    return {
        "origin_id": f"SecCodePLT/{row['id']}", "cwe": cwe,
        "title": CWE_TITLES.get(row["CWE_ID"], "Security weakness"), "entrypoint": fn,
        "instruction": td["description"].strip(),
        "prompt_code": context + vulnerable + "\n",
        "reference_code": context + patched + "\n",
        "context_code": setup + "\n" if setup else "",
        "task_module": module,
        "test_code": TEST_TEMPLATE.format(module=module, fn=fn, testcases=ut["testcases"].strip()),
        "test_func": f"test_{fn}",
        "license": "MIT (SecCodePLT)", "split": "test" if in_test else "train",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None, help="convert only the first N tasks")
    args = ap.parse_args()

    import pandas as pd
    from huggingface_hub import hf_hub_download

    path = hf_hub_download(REPO, FILE, repo_type="dataset")
    df = pd.read_parquet(path)
    runnable = df[~df["use_rule"] & df["unittest"].apply(lambda u: bool((u.get("testcases") or "").strip()))]
    runnable = runnable.sort_values("id")
    if args.limit:
        runnable = runnable.head(args.limit)

    recs, report = [], []
    for _, row in runnable.iterrows():
        try:
            recs.append(convert(row))
        except Exception as exc:
            report.append((row["id"], row["CWE_ID"], f"dropped: could not convert ({type(exc).__name__})"))

    kept, checked = validate(SOURCE, recs)
    n_test = sum(r["split"] == "test" for r in kept)
    print(write_report(SOURCE, [
        f"Source: https://huggingface.co/datasets/{REPO} (MIT), file {FILE}.",
        f"{len(df)} tasks in the file; {len(runnable)} have executable tests "
        f"(the rest use a written rule and are skipped).",
        f"Split: {len(kept) - n_test} train / {n_test} test (stable id hash)."],
        report + checked, len(runnable), len(kept)).split("| Task |")[0])
    from collections import Counter

    print("kept per CWE:", dict(sorted(Counter(r["cwe"] for r in kept).items())))
    drops = Counter(why.split("(")[0].strip() for *_, why in report + checked if why.startswith("dropped"))
    print("drop reasons:", dict(drops.most_common()))


if __name__ == "__main__":
    main()
