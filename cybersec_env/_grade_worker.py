"""Isolated grading worker (one short-lived process per candidate).

Invoked as ``python -m cybersec_env._grade_worker`` with its cwd set to a fresh
sandbox directory. Reads one JSON request on stdin::

    {"task_id": "sqli-1-7", "candidate_path": "/sandbox/solution.py",
     "nonce": "<per-call token>", "sandbox": "/sandbox"}

and writes one JSON line on stdout::

    {"nonce": "<same token>",
     "result": {"ok": true, "error": "", "functional": [true], "security": [true, false],
                "functional_names": [...], "security_names": [...]}}

The parent only accepts a line carrying its token, so anything else on stdout
is ignored.

Running in a separate process gives isolation from the trainer: an infinite
loop is killed by the parent's timeout, a crash cannot take the trainer down,
and resource limits / a disabled network cap what untrusted code can do. File
writes are confined to the sandbox directory (which the parent deletes
afterwards), so a candidate cannot leave anything behind that would affect a
later grading. The probes themselves come from the trusted package and are
rebuilt from ``task_id`` here, never supplied by the candidate.
"""

from __future__ import annotations

import json
import os
import sys

# Audit events (PEP 578) that change the filesystem: event -> indices of the
# path arguments that must lie inside the sandbox.
_FS_EVENTS = {
    "os.mkdir": (0,), "os.remove": (0,), "os.rmdir": (0,), "os.chmod": (0,),
    "os.chown": (0,), "os.utime": (0,), "os.truncate": (0,), "os.chflags": (0,),
    "os.lchflags": (0,), "os.rename": (0, 1), "os.link": (0, 1), "os.symlink": (1,),
    "shutil.rmtree": (0,), "shutil.chown": (0,), "shutil.copyfile": (1,),
    "shutil.copymode": (1,), "shutil.copystat": (1,), "shutil.copytree": (1,),
    "shutil.move": (0, 1),
}
# Never needed by a fix or a probe (the socket events = no network).
_DENY_EVENTS = {"os.system", "os.startfile", "os.fork", "os.forkpty", "os.kill",
                "os.killpg", "sqlite3.enable_load_extension", "sqlite3.load_extension",
                "socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg",
                "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr"}
_DENY_PREFIXES = ("subprocess.", "os.exec", "os.spawn", "os.posix_spawn",
                  "ctypes.", "_winapi.", "winreg.")
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC


def _confine_writes(sandbox: str) -> None:
    root = os.path.normcase(os.path.realpath(sandbox))

    def inside(path) -> bool:
        if isinstance(path, int):  # an already-open fd (its open was checked)
            return True
        try:
            real = os.path.normcase(os.path.realpath(os.fsdecode(path)))
        except (TypeError, ValueError):
            return False
        return real == root or real.startswith(root + os.sep)

    def deny(event: str, path=None):
        where = f" ({os.fsdecode(path)})" if isinstance(path, (str, bytes, os.PathLike)) else ""
        raise PermissionError(f"{event}{where} outside the grader sandbox is not allowed")

    def hook(event: str, args: tuple) -> None:
        if event == "open":
            path, mode, flags = (tuple(args) + (None, None, 0))[:3]
            writes = (isinstance(mode, str) and any(c in mode for c in "wax+")) or \
                bool((flags or 0) & _WRITE_FLAGS)
            if writes and not inside(path):
                deny(event, path)
        elif event in _FS_EVENTS:
            if any(not inside(args[i]) for i in _FS_EVENTS[event] if i < len(args)):
                deny(event)
        elif event == "sqlite3.connect":
            db = os.fsdecode(args[0]) if args and not isinstance(args[0], int) else ""
            if db not in ("", ":memory:") and (db.startswith("file:") or not inside(db)):
                deny(event)
        elif event in _DENY_EVENTS or event.startswith(_DENY_PREFIXES):
            deny(event)

    sys.addaudithook(hook)


def _harden(sandbox: str) -> None:
    # The network is disabled by the audit hook below (connect/bind/DNS are
    # denied). Replacing ``socket.socket`` instead would break every later
    # import that subclasses it, such as ``ssl``.

    # POSIX resource limits (no-op on Windows).
    try:
        import resource  # type: ignore

        cpu = 10
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        mem = 1024 * 1024 * 1024  # 1 GiB
        try:
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
        except (ValueError, OSError):
            pass
    except Exception:
        pass

    # Nothing on the module search path may come from the sandbox.
    here = os.path.normcase(os.path.realpath(sandbox))
    sys.path[:] = [p for p in sys.path
                   if os.path.normcase(os.path.realpath(p or os.curdir)) != here]
    sys.dont_write_bytecode = True
    # pytest's Windows console workarounds would load these through ctypes,
    # which the jail denies: readline is never needed (mark it unavailable),
    # colorama is loaded now, before the jail.
    sys.modules.setdefault("readline", None)
    try:
        import colorama  # noqa: F401
    except Exception:
        pass
    _confine_writes(sandbox)


def _run_pytest(inst, source: str, sandbox: str):
    """Run an imported benchmark's pytest module against the candidate.

    The candidate is loaded as the module the tests import (e.g.
    ``cwe_022_0_task``) and registered in ``sys.modules`` up front;
    ``--import-mode=importlib`` keeps the sandbox off ``sys.path``. Returns
    ``(outcomes, kinds)`` keyed by test id (the node id after ``::``).
    """
    import types

    os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"  # no third-party plugins
    import pytest

    meta = inst.metadata["pytest"]
    module = types.ModuleType(meta["module"])
    module.__file__ = os.path.join(sandbox, meta["module"] + ".py")
    # Trusted task context (constants, sample data) first, so an answer that
    # returns only the function still finds the names it uses.
    if meta.get("context"):
        exec(compile(meta["context"], "<task-context>", "exec"), module.__dict__)  # noqa: S102
    exec(compile(source, "<candidate>", "exec"), module.__dict__)  # noqa: S102 - sandboxed
    if not callable(module.__dict__.get(inst.entrypoint)):
        raise ValueError(f"source does not define a callable '{inst.entrypoint}'")
    sys.modules[meta["module"]] = module

    test_path = os.path.join(sandbox, "test_imported_task.py")
    with open(test_path, "w", encoding="utf-8") as fh:
        fh.write(meta["test_code"])

    class _Collect:
        def __init__(self):
            self.outcomes, self.kinds = {}, {}

        def pytest_collection_modifyitems(self, items):
            for item in items:
                key = item.nodeid.split("::", 1)[-1]
                self.kinds[key] = "security" if item.get_closest_marker("security") else "functional"

        def pytest_runtest_logreport(self, report):
            key = report.nodeid.split("::", 1)[-1]
            if report.failed:
                self.outcomes[key] = False
            elif report.when == "call" and key not in self.outcomes:
                self.outcomes[key] = True

    # An empty config in the sandbox stops pytest from picking up any ini file
    # (and its log_file, addopts, ...) from the folders above it.
    ini_path = os.path.join(sandbox, "pytest.ini")
    with open(ini_path, "w", encoding="utf-8") as fh:
        fh.write("[pytest]\nmarkers =\n    functionality\n    security\n")

    col = _Collect()
    pytest.main([f"{test_path}::{meta['test_func']}", "-c", ini_path, "--rootdir", sandbox,
                 "-qq", "-p", "no:cacheprovider", "-p", "no:logging",
                 "--import-mode=importlib", "--capture=sys", "-W", "ignore"],
                plugins=[col])
    return col.outcomes, col.kinds


def _run(task_id: str, candidate_path: str, sandbox: str) -> dict:
    from cybersec_env.tasks import generate, load_callable

    inst = generate(task_id)

    with open(candidate_path, "r", encoding="utf-8") as fh:
        source = fh.read()

    result = {
        "ok": False,
        "error": "",
        "functional": [],
        "security": [],
        "functional_names": [p.name for p in inst.functional_probes],
        "security_names": [p.name for p in inst.security_probes],
    }

    if "pytest" in inst.metadata:
        try:
            outcomes, kinds = _run_pytest(inst, source, sandbox)
        except BaseException as exc:  # candidate failed to load
            result["error"] = f"load_error: {type(exc).__name__}: {exc}"
            result["functional"] = [False] * len(inst.functional_probes)
            result["security"] = [False] * len(inst.security_probes)
            return result
        result["functional"] = [outcomes.get(p.name, False) for p in inst.functional_probes]
        result["security"] = [outcomes.get(p.name, False) for p in inst.security_probes]
        # Importers discover a task's test ids from the reference run.
        result["discovered"] = {k: [kinds.get(k, "functional"), v] for k, v in outcomes.items()}
        result["ok"] = True
        return result

    # BaseException, not Exception: a candidate that raises SystemExit (or any
    # other non-Exception) while loading or inside a probe simply fails it.
    try:
        fn = load_callable(source, inst.entrypoint)
    except BaseException as exc:  # import/compile error or missing entrypoint
        result["error"] = f"load_error: {type(exc).__name__}: {exc}"
        result["functional"] = [False] * len(inst.functional_probes)
        result["security"] = [False] * len(inst.security_probes)
        return result

    def _safe(probe) -> bool:
        try:
            return bool(probe.fn(fn))
        except BaseException:
            return False

    result["functional"] = [_safe(p) for p in inst.functional_probes]
    result["security"] = [_safe(p) for p in inst.security_probes]
    result["ok"] = True
    return result


def main() -> None:
    # Read the request (and its token) before any candidate code runs, and
    # keep it in locals only.
    request = json.loads(sys.stdin.readline() or "{}")
    nonce = request.get("nonce", "")
    sandbox = request.get("sandbox") or os.getcwd()
    out_stream = sys.stdout
    try:
        _harden(sandbox)
        out = _run(request["task_id"], request["candidate_path"], sandbox)
    except BaseException as exc:  # pragma: no cover - last-resort guard
        out = {"ok": False, "error": f"worker_error: {type(exc).__name__}: {exc}",
               "functional": [], "security": []}
    out_stream.write("\n" + json.dumps({"nonce": nonce, "result": out}) + "\n")
    out_stream.flush()


if __name__ == "__main__":
    main()
