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


def wrap_command(inner: List[str], *, sandbox_dir: str, repo_root: str,
                 verdict_fd: int) -> Tuple[List[str], dict]:
    """Wrap ``inner`` (the python worker argv) in a bubblewrap jail.

    Returns ``(argv, popen_kwargs)``. ``popen_kwargs`` carries ``pass_fds`` so
    the private verdict pipe survives into the jailed process; bubblewrap keeps
    inherited fds open by default (it is not a shell). If no OS jail is
    available the inner command is returned unchanged.
    """
    if isolation_level() != "bwrap":
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
