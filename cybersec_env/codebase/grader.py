"""Container grader for repository-level security-repair tasks.

Contract (the same shape as the function-level grader, one process-boundary
stronger): a task fixes a real advisory. We build a Docker image of the repo at
the **vulnerable** commit with the fix's **regression tests already applied**.
The model proposes a *source* patch. We grade it by, inside a no-network
container:

1. **re-materialising the frozen tests** from the task's own test patch, so the
   model cannot change what it is graded against;
2. **sanitising the model patch** down to edits of pre-existing, non-test source
   files (no new files, no tests, no ``conftest.py`` / ``sitecustomize.py``
   auto-import tricks), then applying it;
3. running the task's **fail-to-pass** tests (must all pass) and a sample of
   **pass-to-pass** tests (must not regress).

``solved`` iff every fail-to-pass test passes and no pass-to-pass test breaks.
The candidate runs only inside the container; the verdict is computed by this
module *outside* it from the test runner's structured output, so there is no
in-process channel for the candidate to forge — this is what closes the
residual the function-level grader documents.

Why these anti-cheat rules matter: the dangerous moves for a patch-level task
are to weaken the test, or to run code at import time that fakes a pass. Both
reduce to "touch a file that is a test or is auto-imported", which sanitisation
forbids, plus "the tests you run are mine, re-applied after your patch".
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path

# A path is a "test / auto-import" file the model may never touch.
_TEST_RE = re.compile(
    r"(^|/)(tests?|testing)/|(^|/)test_[^/]*\.py$|[^/]*_test\.py$|"
    r"(^|/)conftest\.py$|(^|/)sitecustomize\.py$|(^|/)usercustomize\.py$|"
    r"(^|/)pytest\.ini$|(^|/)tox\.ini$|(^|/)setup\.cfg$|(^|/)pyproject\.toml$|"
    r"(^|/)\.pth$",
    re.I,
)
_SOURCE_EXT = (".py", ".pyx", ".pyi")
_SUMMARY_RE = re.compile(r"(\d+) (passed|failed|error|errors|skipped)")

_DOCKERFILE = """\
FROM python:{py}-slim
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 PYTHONDONTWRITEBYTECODE=1 \\
    MAKEFLAGS=-j4 NPY_NUM_BUILD_JOBS=4 CMAKE_BUILD_PARALLEL_LEVEL=4 MAX_JOBS=4
RUN apt-get update && apt-get install -y --no-install-recommends \\
      git gcc g++ make libffi-dev libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY repo /app
# The pip cache is a BuildKit cache mount shared by every task build: common
# dependencies are downloaded once per machine instead of once per task (on a
# slow link that is most of the build time). It never ends up in the image and
# does not change what gets installed. Unknown extras are only a warning, so
# one install covers the usual test extras; a failed build would fail the same
# way for every extras variant, so there is a single fallback.
RUN --mount=type=cache,target=/root/.cache/pip \\
    timeout 900 pip install -e ".[test,tests,testing]" 2>/dev/null || timeout 900 pip install -e . 2>/dev/null || true
RUN --mount=type=cache,target=/root/.cache/pip \\
    if [ -f requirements.txt ]; then timeout 900 pip install -r requirements.txt 2>/dev/null || true; fi
RUN --mount=type=cache,target=/root/.cache/pip \\
    if [ -f requirements-test.txt ]; then timeout 900 pip install -r requirements-test.txt 2>/dev/null || true; fi
RUN --mount=type=cache,target=/root/.cache/pip \\
    if [ -f test-requirements.txt ]; then timeout 900 pip install -r test-requirements.txt 2>/dev/null || true; fi
RUN --mount=type=cache,target=/root/.cache/pip timeout 900 pip install pytest 2>/dev/null || true
# Each install is capped at 15 min: pip's resolver can backtrack through
# hundreds of versions for old pinned projects, and such builds tie up a
# worker for the whole build timeout without ever becoming verifiable.
# Test-only dependencies that projects declare in other places (or not at all):
# without them the test files fail at import, before and after the fix alike,
# and an otherwise valid task is rejected as not fail-to-pass.
RUN --mount=type=cache,target=/root/.cache/pip \\
    for f in requirements-dev.txt dev-requirements.txt requirements_test.txt \\
             requirements/test.txt requirements/tests.txt requirements/dev.txt; do \\
      if [ -f "$f" ]; then timeout 900 pip install -r "$f" 2>/dev/null || true; fi; done; \\
    timeout 900 pip install responses mock pytest-mock requests-mock freezegun pytest-asyncio nose 2>/dev/null \\
 || for p in responses mock pytest-mock requests-mock freezegun pytest-asyncio nose; do \\
      timeout 900 pip install "$p" 2>/dev/null || true; done
# Snapshot the pristine (vulnerable + frozen-tests) tree so grading can restore
# the exact tests regardless of what a candidate patch tried to do.
RUN cp -a /app /opt/pristine
"""

_PY_FALLBACKS = {"3.8", "3.9", "3.10", "3.11", "3.12"}


@dataclass
class CodebaseResult:
    task_id: str
    cwes: list = field(default_factory=list)
    built: bool = False
    applied: bool = False
    f2p_total: int = 0
    f2p_pass: int = 0
    p2p_total: int = 0
    p2p_pass: int = 0
    solved: bool = False
    reward: float = 0.0
    error: str = ""
    stripped_hunks: int = 0
    details: dict = field(default_factory=dict)

    def to_dict(self):
        from dataclasses import asdict
        return asdict(self)


def _rmtree(path) -> None:
    """``shutil.rmtree`` that also removes read-only files (git marks its pack
    files read-only on Windows, so a plain ``ignore_errors`` delete leaks them)."""
    import os
    import stat

    def _retry(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_retry)
    else:
        shutil.rmtree(path, onerror=_retry)


def _run(cmd, timeout=1800, **kw):
    # Explicit UTF-8: on Windows the locale codec (cp1252) would garble
    # non-ASCII patch/test text.
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          encoding="utf-8", errors="replace", **kw)


def _counts(output: str) -> dict:
    c = {"passed": 0, "failed": 0, "error": 0, "skipped": 0}
    for n, kind in _SUMMARY_RE.findall(output):
        key = "error" if kind.startswith("error") else kind
        c[key] = c.get(key, 0) + int(n)
    return c


def _nodeids(output: str) -> dict:
    """Map test node id -> outcome from ``pytest -rA`` lines."""
    out = {}
    for line in output.splitlines():
        m = re.match(r"(PASSED|FAILED|ERROR)\s+(\S+)", line.strip())
        if m:
            out[m.group(2)] = (m.group(1) == "PASSED")
    return out


def sanitize_patch(patch: str, existing_files: set | None = None) -> tuple[str, int]:
    """Keep only hunks that edit a pre-existing, non-test source file.

    Returns ``(clean_patch, n_stripped)``. A hunk is dropped if its target is a
    test / auto-import file, is not a source file, is a new or deleted file, or
    (when ``existing_files`` is given) did not exist at the base commit. This is
    the anti-cheat boundary: the model may only change real source it was given.
    """
    lines = patch.splitlines(keepends=True)
    blocks, cur = [], []
    for ln in lines:
        if ln.startswith("diff --git ") and cur:
            blocks.append(cur)
            cur = [ln]
        else:
            cur.append(ln)
    if cur:
        blocks.append(cur)

    kept, stripped = [], 0
    for block in blocks:
        text = "".join(block)
        m = re.search(r"^\+\+\+ [ab]/(.+)$", text, re.M)
        old = re.search(r"^--- [ab]?/?(.+)$", text, re.M)
        target = m.group(1).strip() if m else None
        is_new = "/dev/null" in (old.group(0) if old else "") or "\nnew file mode" in text
        is_del = m and m.group(1).strip() == "/dev/null"
        ok = (
            target is not None
            and not is_new and not is_del
            and not _TEST_RE.search(target)
            and target.endswith(_SOURCE_EXT)
            and (existing_files is None or target in existing_files)
        )
        if ok:
            kept.append(text)
        else:
            stripped += 1
    return ("".join(kept), stripped)


class CodebaseGrader:
    """Builds a task image and grades candidate patches against it."""

    def __init__(self, cpus: str = "2", memory: str = "2g", pids: int = 512,
                 test_timeout: int = 600):
        self.cpus, self.memory, self.pids = cpus, memory, pids
        self.test_timeout = test_timeout

    # -- image -------------------------------------------------------------
    def _py(self, spec) -> str:
        m = re.search(r"3\.(\d+)", spec.get("python_requires") or "")
        v = f"3.{m.group(1)}" if m else ""
        return v if v in _PY_FALLBACKS else spec.get("python") or "3.11"

    def _prepare_context(self, spec, work: Path) -> bool:
        repo = work / "repo"
        url, base = spec["repo"]["url"], spec["base_commit"]
        if _run(["git", "init", "-q", str(repo)]).returncode != 0:
            return False
        # The tree is COPY'd into a Linux image, so keep LF endings even on a
        # Windows host whose git defaults to core.autocrlf=true.
        for c in (["git", "-C", str(repo), "config", "core.autocrlf", "false"],
                  ["git", "-C", str(repo), "config", "core.longpaths", "true"],
                  ["git", "-C", str(repo), "remote", "add", "origin", url],
                  ["git", "-C", str(repo), "fetch", "-q", "--depth", "1", "origin", base]):
            if _run(c, timeout=300).returncode != 0:
                return False
        if _run(["git", "-C", str(repo), "checkout", "-q", base]).returncode != 0:
            return False
        (work / "test.patch").write_text(spec["test_patch"], encoding="utf-8", newline="\n")
        ap = _run(["git", "-C", str(repo), "apply", "--3way", str(work / "test.patch")])
        if ap.returncode != 0:
            ap = _run(["git", "-C", str(repo), "apply", str(work / "test.patch")])
        return ap.returncode == 0

    def build_image(self, spec, work: Path) -> str | None:
        return self._build(spec, work)[0]

    # Docker build errors that mean "registry/network trouble", not "this
    # project cannot be built".
    _NET_ERR = re.compile(r"toomanyrequests|failed to resolve|i/o timeout|TLS handshake|"
                          r"connection (reset|refused)|failed to fetch|failed to do request|"
                          r"unexpected EOF|context deadline exceeded|no such host", re.I)

    def _build(self, spec, work: Path) -> tuple[str | None, str]:
        """``(tag, "")`` on success, else ``(None, reason)`` where reason is
        ``fetch_failed`` (could not get the code from the git host),
        ``build_net_error`` (registry/network trouble during the build) or
        ``build_failed`` (the project itself does not build). Only the last is
        a property of the task; the others are worth retrying."""
        if not self._prepare_context(spec, work):
            return None, "fetch_failed"
        (work / "Dockerfile").write_text(_DOCKERFILE.format(py=self._py(spec)),
                                         encoding="utf-8", newline="\n")
        tag = "cse_cb_" + re.sub(r"[^a-z0-9]", "", spec["id"].lower())[:40]
        b = _run(["docker", "build", "-q", "-t", tag, str(work)], timeout=2400)
        if b.returncode == 0:
            return tag, ""
        return None, "build_net_error" if self._NET_ERR.search(b.stderr or "") else "build_failed"

    def _script(self, test_files, pre_sh: str = "") -> str:
        files = " ".join(f"'{p}'" for p in test_files)
        # Restore the frozen test files from the pristine snapshot *by path*
        # after any candidate patch, so the candidate is always graded against
        # the task's own tests (the git tree is at the base commit, so a
        # `git checkout` would instead delete the un-committed frozen tests).
        restore = "; ".join(
            f"cp -a '/opt/pristine/{p}' '/app/{p}' 2>/dev/null" for p in test_files) or "true"
        # JUnit XML is escape-safe for parametrised ids that contain newlines,
        # unlike parsing -rA text; we run whole test files (stable args) and
        # select fail-to-pass tests by key afterwards.
        return (
            "cp -a /opt/pristine/. /app/ 2>/dev/null; cd /app; "
            + (pre_sh + "; " if pre_sh else "")
            + restore + "; "
            + f"python -m pytest -q -p no:cacheprovider --no-header "
            + f"-o junit_logging=no --junit-xml=/tmp/r.xml {files} >/tmp/out 2>&1; "
            + "echo '<<<CSEXML>>>'; cat /tmp/r.xml 2>/dev/null"
        )

    @staticmethod
    def _parse_xml(output: str) -> dict:
        """Map ``classname::name`` -> passed? from the JUnit XML tail."""
        import xml.etree.ElementTree as ET
        marker = output.rfind("<<<CSEXML>>>")
        xml = output[marker + len("<<<CSEXML>>>"):].strip() if marker >= 0 else ""
        if not xml:
            return {}
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return {}
        out = {}
        for tc in root.iter("testcase"):
            key = f"{tc.get('classname', '')}::{tc.get('name', '')}"
            bad = any(c.tag in ("failure", "error", "skipped") for c in tc)
            out[key] = not bad
        return out

    def _run_testfiles(self, tag, test_files, pre_sh="", patch_path=None) -> dict:
        vols = ["-v", f"{patch_path}:/cand.patch:ro"] if patch_path else []
        # Named so a timeout can remove it: killing the docker CLI on timeout
        # leaves the container itself running inside the Docker VM.
        name = f"cse_run_{uuid.uuid4().hex[:12]}"
        try:
            r = _run(["docker", "run", "--rm", "--name", name, "--network", "none",
                      f"--cpus={self.cpus}", f"--memory={self.memory}",
                      f"--pids-limit={self.pids}", *vols, tag, "sh", "-c",
                      self._script(test_files, pre_sh)],
                     timeout=self.test_timeout)
        except subprocess.TimeoutExpired:
            _run(["docker", "rm", "-f", name], timeout=120)
            raise
        return self._parse_xml(r.stdout + r.stderr)

    # -- grading -----------------------------------------------------------
    def grade_patch(self, spec: dict, model_patch: str,
                    tag: str | None = None) -> CodebaseResult:
        res = CodebaseResult(task_id=spec["id"], cwes=spec.get("cwes", []))
        f2p = spec.get("f2p_tests") or []
        p2p = spec.get("p2p_tests") or []
        res.f2p_total, res.p2p_total = len(f2p), len(p2p)
        work = Path(tempfile.mkdtemp(prefix="cse_cbgrade_"))
        own_image = tag is None
        try:
            if tag is None:
                tag = self.build_image(spec, work)
                if tag is None:
                    res.error = "build_failed"
                    return res
            res.built = True
            if not f2p:
                res.error = "no_f2p_tests_in_spec"
                return res
            existing = set(spec.get("base_files") or []) or None
            clean, stripped = sanitize_patch(model_patch or "", existing)
            res.stripped_hunks = stripped
            if not clean.strip():
                res.error = "empty_after_sanitize"
                res.reward = 0.0
                return res
            (work / "cand.patch").write_text(clean, encoding="utf-8", newline="\n")
            pre = ("git apply --3way /cand.patch 2>/dev/null || "
                   "git apply /cand.patch 2>/dev/null || true")
            test_files = spec.get("test_files") or spec["changed_test_files"]
            outcomes = self._run_testfiles(tag, test_files, pre, work / "cand.patch")
            res.applied = True
            res.f2p_pass = sum(1 for t in f2p if outcomes.get(t) is True)
            res.p2p_pass = sum(1 for t in p2p if outcomes.get(t) is True)
            res.solved = (res.f2p_total > 0 and res.f2p_pass == res.f2p_total
                          and res.p2p_pass == res.p2p_total)
            res.reward = self._reward(res)
            res.details = {"f2p": {t: outcomes.get(t) for t in f2p},
                           "p2p_failed": [t for t in p2p if not outcomes.get(t)]}
            return res
        except subprocess.TimeoutExpired:
            res.error = "timeout"
            return res
        finally:
            if own_image and tag:
                _run(["docker", "rmi", "-f", tag], timeout=120)
            _rmtree(work)

    @staticmethod
    def _reward(res: CodebaseResult) -> float:
        if res.f2p_total == 0:
            return 0.0
        f2p = res.f2p_pass / res.f2p_total
        p2p = 1.0 if res.p2p_total == 0 else res.p2p_pass / res.p2p_total
        if res.solved:
            return 1.0
        # security credit (f2p) gated by not regressing existing behaviour (p2p)
        base = 0.7 * f2p * p2p + 0.3 * p2p
        return round(min(base, 0.85), 6)

    # -- dataset QA --------------------------------------------------------
    def verify(self, spec: dict, reruns: int = 2, freeze: bool = True) -> dict:
        """Confirm the gold patch is fail-to-pass; capture the f2p/p2p node ids.

        Returns a dict with ``verdict`` and, when verified, the ``f2p_tests`` and
        ``p2p_tests`` node-id lists to store back into the spec.

        A fail-to-pass candidate is then re-run ``reruns`` more times before and
        after the fix; only tests whose outcome never changes are kept (a flaky
        test is a noisy reward), and a task left with no stable fail-to-pass
        test is ``flaky``. With ``freeze`` the image's exact installed packages
        (``pip freeze``) are returned, so the environment can be rebuilt later
        even after upstream releases move on.
        """
        work = Path(tempfile.mkdtemp(prefix="cse_cbverify_"))
        tag = None
        try:
            tag, why = self._build(spec, work)
            if tag is None:
                return {"verdict": why}
            tf = spec["changed_test_files"]
            before = self._run_testfiles(tag, tf)
            (work / "src.patch").write_text(spec["source_patch"], encoding="utf-8", newline="\n")
            pre = ("git apply --3way /cand.patch 2>/dev/null || "
                   "git apply /cand.patch 2>/dev/null || true")
            after = self._run_testfiles(tag, tf, pre, work / "src.patch")
            # fail-to-pass = passes after the fix but did NOT pass before
            # (covers failed, errored, and not-collected-before cases, exactly
            # like SWE-bench's FAIL_TO_PASS); pass-to-pass = passed both.
            f2p = sorted(t for t, ok in after.items() if ok and before.get(t) is not True)
            p2p = sorted(t for t, ok in after.items() if ok and before.get(t) is True)
            counts = {"n_before_pass": sum(before.values()), "n_after_pass": sum(after.values()),
                      "n_before_run": len(before), "n_after_run": len(after)}
            if not f2p:
                return {"verdict": "not_fail_to_pass", "f2p_tests": [], "p2p_tests": p2p,
                        "test_files": tf, **counts}
            f2p0, p2p0 = len(f2p), len(p2p)
            for _ in range(reruns):
                b = self._run_testfiles(tag, tf)
                a = self._run_testfiles(tag, tf, pre, work / "src.patch")
                f2p = [t for t in f2p if a.get(t) is True and b.get(t) is not True]
                p2p = [t for t in p2p if a.get(t) is True and b.get(t) is True]
            out = {"verdict": "verified" if f2p else "flaky", "f2p_tests": f2p,
                   "p2p_tests": p2p, "test_files": tf, **counts,
                   "stability": {"runs": 1 + reruns, "f2p_dropped": f2p0 - len(f2p),
                                 "p2p_dropped": p2p0 - len(p2p)}}
            if freeze and f2p:
                r = _run(["docker", "run", "--rm", "--network", "none", tag,
                          "pip", "freeze", "--all"], timeout=300)
                if r.returncode == 0:
                    out["pip_freeze"] = [ln for ln in r.stdout.splitlines()
                                         if ln.strip() and not ln.startswith("-e ")]
            return out
        except subprocess.TimeoutExpired:
            return {"verdict": "timeout"}
        finally:
            if tag:
                _run(["docker", "rmi", "-f", tag], timeout=120)
            _rmtree(work)
