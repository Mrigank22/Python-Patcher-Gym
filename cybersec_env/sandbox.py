"""OS-level sandbox for the grading worker (Linux, via bubblewrap).

The Python-level audit hook in :mod:`cybersec_env._grade_worker` confines what a
candidate *library call* can do, but it is not a security boundary on its own:
a sufficiently creative candidate can reach the interpreter in ways a denylist
never fully covers. This module adds the real boundary underneath it.

When ``bwrap`` (bubblewrap, the sandbox Flatpak uses) is available we launch the
worker inside a throwaway namespace jail:

* **no network** — the network namespace is unshared and left empty, so every
  ``connect``/``bind``/DNS attempt fails at the kernel, not at a Python hook;
* **read-only system** — ``/usr`` and the Python install are bind-mounted
  read-only; the *only* writable path is the per-candidate sandbox directory,
  which is also the cwd and ``$TMPDIR``;
* **no shared pids / ipc / uts** — the candidate sees only itself;
* **no new privileges**, **die-with-parent**, and a **fresh session** so it
  cannot re-acquire a controlling terminal.

If ``bwrap`` is missing (e.g. on Windows, or an unprivileged container without
user namespaces) we fall back to running the worker directly and report that
the OS layer is absent, so an operator can see the isolation level in effect.
The process-level protections in the worker (fork split, private verdict fd,
rlimits, audit hook) apply in both cases.
"""

from __future__ import annotations

import functools
import os
import shutil
import sys
from pathlib import Path
from typing import List, Tuple


@functools.lru_cache(maxsize=1)
def bwrap_path() -> str:
    """Return the ``bwrap`` executable path, or ``""`` if it is unusable here."""
    exe = shutil.which("bwrap")
    if not exe:
        return ""
    # A quick functional probe: unprivileged user namespaces are disabled on
    # some hosts, which makes bwrap fail at launch. Detect that once.
    import subprocess

    cmd = [exe, "--ro-bind", "/usr", "/usr"]
    # Recreate the top-level symlinks (merged-/usr systems) so an absolute path
    # like /bin/true resolves inside the jail, exactly as wrap_command does.
    for link in ("/lib", "/lib64", "/bin", "/sbin"):
        if os.path.islink(link):
            cmd += ["--symlink", os.readlink(link), link]
    cmd += ["--unshare-all", "--die-with-parent", "/usr/bin/true"]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=10)
        return exe if proc.returncode == 0 else ""
    except Exception:
        return ""


def isolation_level() -> str:
    """``"bwrap"`` if the OS jail is active, else ``"process-only"``."""
    return "bwrap" if (os.name == "posix" and bwrap_path()) else "process-only"


def _distinct_existing(paths) -> List[str]:
    seen, out = set(), []
    for p in paths:
        if not p:
            continue
        rp = os.path.realpath(p)
        if rp in seen or not os.path.exists(rp):
            continue
        seen.add(rp)
        out.append(rp)
    return out


def windows_inherit_kwargs(fd: int) -> dict:
    """Windows has no ``pass_fds``: mark ``fd``'s OS handle inheritable and give
    it to the child as its *only* inherited handle (plus stdio, which
    ``subprocess`` adds itself). The explicit handle list matters because the
    grader launches workers from several threads at once: without it a worker
    would also inherit whatever handle another thread had just made
    inheritable. The child finds the handle via ``$CSE_VERDICT_HANDLE``."""
    import msvcrt
    import subprocess

    handle = msvcrt.get_osfhandle(fd)
    os.set_handle_inheritable(handle, True)
    si = subprocess.STARTUPINFO()
    si.lpAttributeList = {"handle_list": [handle]}
    return {"startupinfo": si, "close_fds": True}


CREATE_SUSPENDED = 0x00000004


def windows_job_attach(proc):
    """Put a process started with ``CREATE_SUSPENDED`` into a fresh Job Object
    that kills every process in it when the job handle closes, then resume it.

    Windows has no process groups: killing a timed-out worker leaves its
    children (the venv launcher's interpreter, the spawned untrusted half)
    running, and a candidate stuck in C code (e.g. catastrophic regex
    backtracking) holds the GIL, so no in-process watchdog can stop it. Every
    descendant of a job member joins the job automatically, so closing the job
    (:func:`windows_job_close`) reaps the whole tree. Starting suspended means
    the worker cannot spawn anything before it is inside the job.
    """
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
    k32.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int,
                                            wintypes.LPVOID, wintypes.DWORD)
    k32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)

    class _Basic(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                    ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class _Extended(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", _Basic),
                    ("IoInfo", ctypes.c_ulonglong * 6),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    job = k32.CreateJobObjectW(None, None)
    if not job:
        raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
    info = _Extended()
    info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    ok = (k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))  # 9 = extended
          and k32.AssignProcessToJobObject(job, int(proc._handle)))
    # Resume even if the job setup failed, so the worker never hangs suspended.
    ctypes.WinDLL("ntdll").NtResumeProcess(wintypes.HANDLE(int(proc._handle)))
    if not ok:
        k32.CloseHandle(job)
        raise OSError(ctypes.get_last_error(), "job object setup failed")
    return job


def windows_job_close(job) -> None:
    """Kill every process still in ``job`` and release it."""
    import ctypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.TerminateJobObject.argtypes = (ctypes.c_void_p, ctypes.c_uint)
    k32.CloseHandle.argtypes = (ctypes.c_void_p,)
    k32.TerminateJobObject(job, 1)
    k32.CloseHandle(job)


def wrap_command(inner: List[str], *, sandbox_dir: str, repo_root: str,
                 verdict_fd: int) -> Tuple[List[str], dict]:
    """Wrap ``inner`` (the python worker argv) in a bubblewrap jail.

    Returns ``(argv, popen_kwargs)``. ``popen_kwargs`` carries ``pass_fds`` so
    the private verdict pipe survives into the jailed process; bubblewrap keeps
    inherited fds open by default (it is not a shell). If no OS jail is
    available the inner command is returned unchanged.
    """
    if isolation_level() != "bwrap":
        if os.name == "nt":
            return inner, windows_inherit_kwargs(verdict_fd)
        return inner, {"pass_fds": (verdict_fd,)}

    # Execute the interpreter by its fully-resolved real path so the jail does
    # not have to reproduce a venv's symlink chain (bin/python -> ... -> real).
    inner = list(inner)
    if inner:
        inner[0] = os.path.realpath(inner[0])

    exe = bwrap_path()
    # The interpreter is run by its real path (above), which bypasses any venv,
    # so the venv's site-packages must be put on PYTHONPATH and bind-mounted
    # explicitly. sysconfig here reports the *current* (venv) interpreter's.
    import sysconfig

    site_dirs = _distinct_existing([
        sysconfig.get_paths().get("purelib"), sysconfig.get_paths().get("platlib"),
    ])
    # Everything the interpreter needs to import the stdlib, the venv packages
    # and our own package, all read-only. The candidate's sandbox dir is the
    # single writable mount.
    ro_roots = _distinct_existing([
        "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc/ssl", "/etc/alternatives",
        sys.base_prefix, sys.prefix, os.path.dirname(os.path.realpath(sys.executable)),
        repo_root, *site_dirs,
    ])

    argv = [exe]
    for root in ro_roots:
        argv += ["--ro-bind", root, root]
    # Recreate the usual top-level symlinks when they are real symlinks on the
    # host (merged-/usr systems), so absolute loader paths resolve.
    for link in ("/lib", "/lib64", "/bin", "/sbin"):
        if os.path.islink(link):
            argv += ["--symlink", os.readlink(link), link]
    argv += [
        "--bind", sandbox_dir, sandbox_dir,     # the only writable path
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/run",
        "--chdir", sandbox_dir,
        "--unshare-all",                         # net, pid, ipc, uts, cgroup, user
        "--new-session",
        "--die-with-parent",
        "--clearenv",
    ]
    # A minimal, caller-controlled environment inside the jail.
    jail_env = {
        "PATH": "/usr/bin:/bin",
        "HOME": sandbox_dir,
        "TMPDIR": sandbox_dir, "TEMP": sandbox_dir, "TMP": sandbox_dir,
        "PYTHONPATH": os.pathsep.join([repo_root, *site_dirs]),
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
        "CSE_VERDICT_FD": str(verdict_fd),
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }
    for key, val in jail_env.items():
        argv += ["--setenv", key, val]
    argv += inner
    return argv, {"pass_fds": (verdict_fd,)}
