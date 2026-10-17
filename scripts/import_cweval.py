"""Import CWEval's Python tasks as validated repair tasks.

CWEval (Peng et al., 2025; Apache-2.0, https://github.com/Co1lin/CWEval) ships,
per task, a secure reference (``*_task.py``) and a pytest module with an
``*_unsafe`` variant plus test cases marked ``functionality`` or ``security``.
This script turns each Python task into a repair task for this environment:

* prompt  = the task's signature + docstring with the *unsafe* body,
* oracle  = the task's reference solution,
* grader  = CWEval's own tests for the task function, run in our sandbox.

Every task is then validated in this grader and kept only if the reference
solves it, the vulnerable seed does not, and an empty stub does not. Tasks the
sandbox cannot run (e.g. ones that need to start processes) drop out here.

    python scripts/import_cweval.py ../datasets/CWEval

Writes ``cybersec_env/data/imported/cweval.jsonl`` and an import report.
"""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from import_common import validate, write_report  # noqa: E402

SOURCE = "cweval"
INSTRUCTION = "You maintain the following function in a production Python service."


def _lines(path: Path):
    return path.read_text(encoding="utf-8").splitlines()


def convert(task_path: Path, test_path: Path) -> dict:
    """Build one (unvalidated) record from a CWEval task/test pair."""
    task_lines = _lines(task_path)
    tree = ast.parse("\n".join(task_lines))
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef))
    cut = next(i for i, ln in enumerate(task_lines) if ln.strip() == "# BEGIN SOLUTION")
    prefix = task_lines[:cut]
    reference = "\n".join(prefix + task_lines[cut + 1:]).rstrip() + "\n"
    indent = re.match(r"\s*", task_lines[fn.body[0].lineno - 1]).group(0)

    test_lines = _lines(test_path)
    ttree = ast.parse("\n".join(test_lines))
    unsafe = next(n for n in ttree.body if isinstance(n, ast.FunctionDef)
                  and n.name.startswith(fn.name + "_unsafe"))
    body = unsafe.body
    if isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant):
        body = body[1:]  # drop a docstring
    raw = [ln for ln in test_lines[body[0].lineno - 1:unsafe.end_lineno]
           if ln.strip() != "# BEGIN SOLUTION"]
    unsafe_body = textwrap.indent(textwrap.dedent("\n".join(raw)), indent)

    # Module-level imports of the test file that the unsafe body relies on.
    used = {n.id for n in ast.walk(unsafe) if isinstance(n, ast.Name)}
    have = {a.asname or a.name.split(".")[0] for n in tree.body
            if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
    extra = []
    for node in ttree.body:
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        mod = getattr(node, "module", None) or ""
        if mod.endswith("_task") or mod.startswith(("pytest", "wrapt_timeout_decorator")):
            continue
        names = {a.asname or a.name.split(".")[0] for a in node.names if a.name != "*"}
        if names & used and not names <= have:
            extra.append(ast.get_source_segment("\n".join(test_lines), node))
    # ...and module-level constants it reads (e.g. a lookup table).
    for node in ttree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in used and t.id not in have for t in node.targets):
            extra.append(ast.get_source_segment("\n".join(test_lines), node))
    prompt = "\n".join(extra + ([""] if extra else []) + prefix) + "\n" + unsafe_body.rstrip() + "\n"

    # The CWE comes from the file name; the test header's own CWE label is
    # wrong in at least one upstream file (cwe_400_0 says CWE-377).
    doc = (ast.get_docstring(ttree) or "").strip().splitlines()
    m = re.match(r"CWE-\d+:\s*(.+)", doc[0]) if doc else None
    stem = task_path.name[: -len("_task.py")]
    cwe = "CWE-" + stem.split("_")[1]
    title = m.group(1).strip() if m else "Security weakness"

    test_defs = [n.name for n in ttree.body if isinstance(n, ast.FunctionDef)
                 and n.name.startswith("test_")]
    test_func = f"test_{fn.name}" if f"test_{fn.name}" in test_defs else \
        next(t for t in test_defs if "unsafe" not in t)
    # Our worker enforces its own wall-clock limit; CWEval's timeout decorator
    # would start a helper process, which the sandbox forbids.
    test_code = "\n".join(ln for ln in test_lines
                          if not ln.startswith("from wrapt_timeout_decorator import")
                          and not re.match(r"\s*@timeout\(", ln)) + "\n"

    cwe = f"CWE-{int(cwe.split('-')[1]):03d}"
    return {
        "origin_id": f"CWEval/{task_path.parent.relative_to(task_path.parents[2]).as_posix()}/{stem}",
        "cwe": cwe, "title": title, "entrypoint": fn.name, "instruction": INSTRUCTION,
        "prompt_code": prompt, "reference_code": reference,
        "task_module": task_path.stem, "test_code": test_code, "test_func": test_func,
        "license": "Apache-2.0 (CWEval)", "split": "test",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cweval_repo", help="path to a CWEval checkout")
    args = ap.parse_args()
    repo = Path(args.cweval_repo).resolve()
    commit = subprocess.run(["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
                            capture_output=True, text=True).stdout.strip() or "unknown"
    pairs = sorted((p, p.with_name(p.name.replace("_task.py", "_test.py")))
                   for p in (repo / "benchmark" / "core" / "py").glob("*_task.py"))

    recs, report = [], []
    for task_path, test_path in pairs:
        try:
            recs.append(convert(task_path, test_path))
        except Exception as exc:  # unusual layout
            report.append((task_path.stem, "?", f"dropped: could not convert ({type(exc).__name__})"))

    kept, checked = validate(SOURCE, recs)
    print(write_report(SOURCE, [f"Source: https://github.com/Co1lin/CWEval at commit {commit} "
                                "(Apache-2.0)."], report + checked, len(pairs), len(kept)))


if __name__ == "__main__":
    main()
