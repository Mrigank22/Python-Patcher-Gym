"""Isolated grading worker (one short-lived process per candidate).

Invoked as ``python -m cybersec_env._grade_worker``. Reads one JSON request on
stdin::

    {"task_id": "sqli-1-7", "candidate_path": "/sandbox/solution.py",
     "nonce": "<per-call token>", "sandbox": "/sandbox"}

and writes one JSON line carrying its token to the **private verdict fd** named
by ``$CSE_VERDICT_FD`` (a pipe the parent set up with ``pass_fds``; it falls
back to stdout only when no fd was passed)::

    {"nonce": "<same token>",
     "result": {"ok": true, "error": "", "functional": [true], "security": [...],
                "functional_names": [...], "security_names": [...]}}

Two layers of isolation, both necessary:

* **OS jail** (:mod:`cybersec_env.sandbox`): the whole worker runs inside a
  bubblewrap namespace with no network and a read-only filesystem except the
  per-candidate sandbox directory.
* **Trust split (this module):** the worker ``fork``\\s. The *child* runs the
  candidate and the probes; the *parent* holds the nonce and the verdict fd and
  writes the verdict. Before the child executes any candidate code it closes
  the verdict fd and stdin, so candidate code shares no process, no token and
  no output channel with the part of the worker the parent trusts. This is what
  defeats the "forge a passing verdict / exit early" class of reward hack: the
  earlier single-process worker kept the nonce in a frame the candidate could
  walk to and printed the verdict on a stream the candidate could pre-empt.

Candidate return values are reduced to canonical primitives
(:func:`_canonical`) before any probe compares them, so a candidate cannot pass
a probe by returning an object whose ``__eq__`` lies.

The residual the two layers do *not* remove: the child still writes the raw
probe outcomes to the parent over a pipe, so candidate code that corrupts the
child's own bookkeeping before that write could still misreport *its own*
results. Removing that last gap requires never running candidate code in the
same process as any trusted probe logic — the container / patch-and-run model
(one image per task, tests driven from outside) that the project's codebase
track uses. It is documented in REPORT.md rather than hidden.
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

# ---------------------------------------------------------------------------
# Canonicalisation of candidate return values
# ---------------------------------------------------------------------------
# A probe checks the candidate's output with ``==`` (``cand(x) == expected``).
# If the candidate returns an object whose ``__eq__`` always answers True it
# passes every probe at once — the single most general reward hack, and one a
# training run can stumble onto. We defuse it by rebuilding every returned value
# out of trusted primitive types before any comparison, using the *base* type's
# own methods so an overridden dunder on a subclass cannot interfere. A value
# that is not reducible to a primitive is replaced by a unique opaque marker,
# which compares equal to nothing a probe expects.
_PRIMITIVE = (bool, int, float, complex, str, bytes, bytearray, type(None))


class _Opaque:
    """Stand-in for a non-primitive return; equal only to itself."""

    __slots__ = ("kind",)

    def __init__(self, kind: str):
        self.kind = kind

    def __repr__(self):
        return f"<non-primitive:{self.kind}>"


def _canonical(value, _depth: int = 0):
    if _depth > 50:
        return _Opaque("too-deep")
    t = type(value)
    # Exact built-in primitives are already trustworthy.
    if t in _PRIMITIVE:
        return value
    # Subclasses of built-ins: rebuild via the base type, bypassing overrides.
    if isinstance(value, bool):
        return bool(int.__index__(value))
    if isinstance(value, int):
        try:
            return int.__index__(value)
        except Exception:
            return _Opaque("int")
    if isinstance(value, float):
        try:
            return float(value.real) if type(value.real) is float else _Opaque("float")
        except Exception:
            return _Opaque("float")
    if isinstance(value, (str, bytes, bytearray)):
        base = type(value).__mro__[-2] if len(type(value).__mro__) > 1 else t
        base = next((b for b in (str, bytes, bytearray) if isinstance(value, b)), None)
        try:
            return base(base.__str__(value)) if base is str else base(value)
        except Exception:
            return _Opaque(base.__name__ if base else "text")
    # Containers: canonicalise members, iterating via the base type's methods.
    if isinstance(value, (list, tuple)):
        items = list.__iter__(value) if isinstance(value, list) else tuple.__iter__(value)
        out = [_canonical(x, _depth + 1) for x in items]
        return out if isinstance(value, list) else tuple(out)
    if isinstance(value, (set, frozenset)):
        try:
            return {_canonical(x, _depth + 1) for x in set.__iter__(set(value))}
        except Exception:
            return _Opaque("set")
    if isinstance(value, dict):
        out = {}
        for k, v in dict.items(value):
            out[_canonical(k, _depth + 1)] = _canonical(v, _depth + 1)
        return out
    # Anything else (custom classes, generators, callables, ...) is not a value
    # a probe here legitimately compares against, so make it match nothing.
    return _Opaque(getattr(t, "__name__", "object"))


def _canonicalizing(fn):
    """Wrap ``fn`` so its return value is canonicalised; keep the real fn for
    the few probes that introspect the candidate's code object."""

    def wrapper(*args, **kwargs):
        return _canonical(fn(*args, **kwargs))

    wrapper._cse_real = fn  # noqa: SLF001 - read by families._candidate_names
    return wrapper


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
    # The network is disabled by the OS jail (empty net namespace) and, as a
    # second line, by the audit hook below. Replacing ``socket.socket`` instead
    # would break every later import that subclasses it, such as ``ssl``.

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
    entry = module.__dict__.get(inst.entrypoint)
    if not callable(entry):
        raise ValueError(f"source does not define a callable '{inst.entrypoint}'")
    # The tests compare the candidate's output with ``==``; canonicalise it so a
    # lying ``__eq__`` cannot satisfy them (see _canonical).
    module.__dict__[inst.entrypoint] = _canonicalizing(entry)
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

    cand = _canonicalizing(fn)

    def _safe(probe) -> bool:
        try:
            return bool(probe.fn(cand))
        except BaseException:
            return False

    result["functional"] = [_safe(p) for p in inst.functional_probes]
    result["security"] = [_safe(p) for p in inst.security_probes]
    result["ok"] = True
    return result


def _grade_in_child(task_id: str, candidate_path: str, sandbox: str,
                    verdict_fd: int) -> dict:
    """Fork; run the candidate + probes in the child; return the child's result
    dict in the parent.

    The child never holds the grader's verdict fd or outer nonce. Two further
    defences stop a candidate from forging the child's *own* report:

    * The candidate runs in a worker **thread**, while the child's inner nonce
      (``n2``) lives only in the main thread's frame. A frame walk
      (``f_back``) from candidate code stays within its own thread's stack and
      never reaches it; the imports that could reach another thread's frames
      (``sys``, ``threading``, ``gc``, ...) are blocked by the guard.
    * The child stamps its pipe message with ``n2``; the parent accepts only a
      message carrying it. A candidate that writes the pipe directly (e.g.
      spraying every fd) and exits cannot produce ``n2``, so its forged message
      is rejected and the grade falls back to failure.
    """
    import secrets
    import threading

    n2 = secrets.token_hex(16)
    r_fd, w_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # ---------------------------------------- untrusted child
        exit_code = 0
        try:
            os.close(r_fd)
            # Sever every channel the parent trusts before any candidate runs:
            # the verdict fd and stdin (which carried the outer nonce).
            for fd in (verdict_fd, 0):
                try:
                    os.close(fd)
                except OSError:
                    pass
            _harden(sandbox)

            box = {}

            def _work():
                try:
                    box["out"] = _run(task_id, candidate_path, sandbox)
                except BaseException as exc:  # pragma: no cover
                    box["out"] = {"ok": False,
                                  "error": f"worker_error: {type(exc).__name__}: {exc}",
                                  "functional": [], "security": []}

            # Candidate code runs here, one thread removed from the frame that
            # holds n2. os._exit from the candidate still kills the whole
            # process -> the parent sees EOF without n2 -> failure (not forge).
            t = threading.Thread(target=_work, daemon=True)
            t.start()
            t.join()
            out = box.get("out", {"ok": False, "error": "no_thread_result",
                                  "functional": [], "security": []})
        except BaseException as exc:  # pragma: no cover - last-resort guard
            out = {"ok": False, "error": f"worker_error: {type(exc).__name__}: {exc}",
                   "functional": [], "security": []}
        try:
            os.write(w_fd, json.dumps({"n2": n2, "out": out}).encode("utf-8"))
        except BaseException:
            exit_code = 1
        finally:
            os._exit(exit_code)
    # ------------------------------------------------------- trusted parent
    os.close(w_fd)
    chunks = []
    try:
        while True:
            b = os.read(r_fd, 65536)
            if not b:
                break
            chunks.append(b)
    finally:
        os.close(r_fd)
        os.waitpid(pid, 0)
    try:
        msg = json.loads((b"".join(chunks)).decode("utf-8") or "{}")
        if not isinstance(msg, dict) or msg.get("n2") != n2:
            raise ValueError("missing or wrong inner nonce")
        out = msg["out"]
        if not isinstance(out, dict):
            raise ValueError("non-dict verdict")
    except Exception:
        out = {"ok": False, "error": "no_child_verdict", "functional": [], "security": []}
    return out


def _grade_in_subprocess(task_id: str, candidate_path: str, sandbox: str,
                         timeout_s: float) -> dict:
    """The trust split for platforms without ``fork`` (Windows): the untrusted
    half runs in a *fresh interpreter* (``--child``) instead of a forked child.

    Same guarantees as :func:`_grade_in_child`: the child inherits no handles
    (so neither the verdict pipe nor this process's stdin, which carried the
    outer nonce), and it stamps its report with an inner nonce ``n2`` that it
    holds only in its main thread while the candidate runs in a worker thread.
    Its stdout is shared with the candidate, which is why ``n2`` is required.
    """
    import secrets
    import subprocess

    n2 = secrets.token_hex(16)
    req = json.dumps({"task_id": task_id, "candidate_path": candidate_path,
                      "sandbox": sandbox, "n2": n2, "timeout_s": timeout_s})
    env = {k: v for k, v in os.environ.items()
           if k not in ("CSE_VERDICT_FD", "CSE_VERDICT_HANDLE")}
    try:
        p = subprocess.run([sys.executable, "-m", "cybersec_env._grade_worker", "--child"],
                           input=req.encode("utf-8"), capture_output=True, cwd=sandbox,
                           env=env, close_fds=True, timeout=timeout_s + 2)
        lines = p.stdout.decode("utf-8", "replace").splitlines()
    except subprocess.TimeoutExpired:
        lines = []
    for line in reversed(lines):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(msg, dict) and msg.get("n2") == n2 and isinstance(msg.get("out"), dict):
            return msg["out"]
    return {"ok": False, "error": "no_child_verdict", "functional": [], "security": []}


def _child_main() -> None:
    """Entry point of the untrusted half spawned by :func:`_grade_in_subprocess`."""
    import threading

    req = json.loads(sys.stdin.readline() or "{}")
    n2 = req.get("n2", "")  # lives only in this (main) thread's frame
    sys.stdin.close()
    # The parent may be killed on timeout without taking this process with it
    # (no process groups on Windows), so never outlive the grading budget.
    watchdog = threading.Timer(float(req.get("timeout_s") or 8) + 1, os._exit, args=(1,))
    watchdog.daemon = True
    watchdog.start()
    _harden(req["sandbox"])
    box = {}

    def _work():
        try:
            box["out"] = _run(req["task_id"], req["candidate_path"], req["sandbox"])
        except BaseException as exc:  # pragma: no cover
            box["out"] = {"ok": False, "error": f"worker_error: {type(exc).__name__}: {exc}",
                          "functional": [], "security": []}

    t = threading.Thread(target=_work, daemon=True)
    t.start()
    t.join()
    out = box.get("out", {"ok": False, "error": "no_thread_result",
                          "functional": [], "security": []})
    sys.stdout.write("\n" + json.dumps({"n2": n2, "out": out}) + "\n")
    sys.stdout.flush()
    os._exit(0)


def _run_no_fork(task_id: str, candidate_path: str, sandbox: str) -> dict:
    """Fallback for platforms without ``os.fork`` (e.g. Windows): run inline.
    The OS jail and audit hook still apply; only the trust split is absent."""
    try:
        _harden(sandbox)
        return _run(task_id, candidate_path, sandbox)
    except BaseException as exc:  # pragma: no cover
        return {"ok": False, "error": f"worker_error: {type(exc).__name__}: {exc}",
                "functional": [], "security": []}


def main() -> None:
    # Read the request (and its token) before any candidate code runs, and keep
    # it only in this trusted process.
    request = json.loads(sys.stdin.readline() or "{}")
    nonce = request.get("nonce", "")
    sandbox = request.get("sandbox") or os.getcwd()

    # The verdict travels on a private pipe the parent passed via pass_fds, so
    # candidate code writing to stdout can never reach the parent. Fall back to
    # stdout only when launched without one (e.g. a direct manual run).
    try:
        verdict_fd = int(os.environ.get("CSE_VERDICT_FD", ""))
    except ValueError:
        verdict_fd = 1
    if os.name == "nt" and os.environ.get("CSE_VERDICT_HANDLE"):
        import msvcrt
        verdict_fd = msvcrt.open_osfhandle(int(os.environ["CSE_VERDICT_HANDLE"]), os.O_WRONLY)

    try:
        if hasattr(os, "fork") and verdict_fd != 1:
            out = _grade_in_child(request["task_id"], request["candidate_path"],
                                  sandbox, verdict_fd)
        elif verdict_fd != 1:
            out = _grade_in_subprocess(request["task_id"], request["candidate_path"],
                                       sandbox, float(request.get("timeout_s") or 8))
        else:
            out = _run_no_fork(request["task_id"], request["candidate_path"], sandbox)
    except BaseException as exc:  # pragma: no cover - last-resort guard
        out = {"ok": False, "error": f"worker_error: {type(exc).__name__}: {exc}",
               "functional": [], "security": []}

    payload = ("\n" + json.dumps({"nonce": nonce, "result": out}) + "\n").encode("utf-8")
    os.write(verdict_fd, payload)
    try:
        os.fsync(verdict_fd)
    except OSError:
        pass


if __name__ == "__main__":
    _child_main() if "--child" in sys.argv[1:] else main()
