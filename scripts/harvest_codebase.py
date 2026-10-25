"""Grow the codebase-track dataset: triage + verify in resumable batches.

One command that walks the advisory candidate index, turns each into a spec
(clone + patch split), and verifies fail-to-pass in Docker, keeping a ledger so
re-runs continue where they left off. Designed to run for hours in the
background on a CPU box (no GPU needed) and accumulate verified tasks.

  python scripts/harvest_codebase.py --triage-batch 300 --verify           # a batch
  python scripts/harvest_codebase.py --triage-batch 300 --verify --loop     # keep going

Coverage: candidates are drawn round-robin across eras (legacy / recent /
post_cutoff) and least-covered CWEs first, so the dataset spans the whole
history and the full vulnerability spectrum rather than clustering.

Ledger: ``data/codebase/ledger.json`` records each advisory's last status
(``spec_written`` / ``no_test_in_fix`` / ``verified`` / ``not_fail_to_pass`` /
``build_failed`` / ...), so nothing is reprocessed and progress is visible.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

CAND = ROOT / "cybersec_env" / "data" / "advisories" / "candidates.jsonl"
OUT = ROOT / "data" / "codebase"
SPECS = OUT / "specs"
LEDGER = OUT / "ledger.json"

from build_codebase_tasks import triage_one, _safe  # noqa: E402
from verify_codebase_task import verify_and_save  # noqa: E402
from cybersec_env.codebase.grader import CodebaseGrader  # noqa: E402


_LOCK = threading.Lock()  # guards the ledger dict + file (threads of one process)


@contextlib.contextmanager
def _ledger_file_lock(timeout: float = 120.0):
    """Cross-process lock, so a triage process and a verify process can share
    one ledger: each update re-reads the file and merges a single entry inside
    this lock, instead of writing back a stale in-memory copy."""
    lock = LEDGER.with_suffix(".lock")
    OUT.mkdir(parents=True, exist_ok=True)
    deadline = time.time() + timeout
    while True:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            try:  # a holder killed mid-update leaves the file behind
                if time.time() - lock.stat().st_mtime > 60:
                    lock.unlink()
                    continue
            except FileNotFoundError:
                continue
            if time.time() > deadline:
                raise TimeoutError(f"ledger lock held too long: {lock}")
            time.sleep(0.05)
    try:
        yield
    finally:
        os.close(fd)
        try:
            lock.unlink()
        except FileNotFoundError:
            pass


def update_ledger(cid: str, fields: dict) -> dict:
    """Merge ``fields`` into one advisory's record on disk; returns the record."""
    with _LOCK, _ledger_file_lock():
        led = load_ledger()
        led[cid] = {**led.get(cid, {}), **fields}
        save_ledger(led)
        return led[cid]


def load_ledger() -> dict:
    # Retries: on Windows a read can collide with another process's replace.
    for attempt in range(50):
        try:
            return json.loads(LEDGER.read_text()) if LEDGER.exists() else {}
        except (PermissionError, json.JSONDecodeError):
            time.sleep(0.1)
    return json.loads(LEDGER.read_text())


def save_ledger(led: dict):
    OUT.mkdir(parents=True, exist_ok=True)
    tmp = LEDGER.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(led, indent=2), encoding="utf-8", newline="\n")
    for attempt in range(50):
        try:
            tmp.replace(LEDGER)  # atomic, so a kill mid-write can't corrupt the ledger
            return
        except PermissionError:  # Windows: a reader has the file open right now
            time.sleep(0.1)
    tmp.replace(LEDGER)


# The disk that holds Docker's data; on Docker Desktop for Windows that is the
# drive with the WSL disk image, not the drive this script runs from.
DISK_PATH = "/"


def free_gb(path=None) -> float:
    return shutil.disk_usage(path or DISK_PATH).free / 1e9


def disk_guard(min_gb: float = 8.0):
    """Keep the disk healthy for parallel Docker builds: drop leftover task
    images and stopped containers when space runs low, and pause (rather than
    crash) if it stays low. The build cache is never wiped here: rebuilding it
    re-downloads base images and packages and roughly halves throughput (its
    size is capped by ``trim_build_cache`` and Docker's own gc instead)."""
    if free_gb() >= min_gb:
        return
    # Only leftovers no worker can be using: tagged task images belong to
    # in-flight verifications (the grader removes each one when it is done).
    print(f"  disk low ({free_gb():.1f}GB free): removing stopped containers and untagged images",
          flush=True)
    subprocess.run(["docker", "container", "prune", "-f"], capture_output=True, timeout=300)
    subprocess.run(["docker", "image", "prune", "-f"], capture_output=True, timeout=300)
    waited = 0
    while free_gb() < min_gb and waited < 600:
        time.sleep(20)
        waited += 20


# Triage outcomes that can be caused by the network (or GitHub) rather than by
# the advisory itself; these are retried up to MAX_TRIES before being final.
MAX_TRIES = 3


def _transient(status: str) -> bool:
    return status in ("clone_failed", "diff_failed") or status.startswith("error:")


def _is_done(rec: dict) -> bool:
    return not _transient(rec.get("status", "")) or rec.get("tries", 1) >= MAX_TRIES


def network_up(host: str = "github.com", timeout: float = 5.0) -> bool:
    try:
        socket.create_connection((host, 443), timeout=timeout).close()
        return True
    except OSError:
        return False


class NetMonitor:
    """Background probe of github.com every few seconds, remembering outages.

    A failed fetch, or a ``pip install`` that half-failed mid-build (the task
    Dockerfile tolerates install errors), would otherwise be recorded as a
    permanent verdict about the *advisory*. Any non-success outcome whose run
    overlapped an outage is instead treated as unknown and retried later.
    """

    def __init__(self, every: float = 5.0):
        self._down: list[list[float]] = []  # [start, end or None]
        self._lock = threading.Lock()
        threading.Thread(target=self._loop, args=(every,), daemon=True).start()

    def _loop(self, every):
        while True:
            up = network_up()
            now = time.time()
            with self._lock:
                if not up and (not self._down or self._down[-1][1] is not None):
                    self._down.append([now, None])
                elif up and self._down and self._down[-1][1] is None:
                    self._down[-1][1] = now
            time.sleep(every)

    def outage_between(self, t0: float, t1: float) -> bool:
        with self._lock:
            return any(s <= t1 and (e is None or e >= t0) for s, e in self._down)


def wait_for_network():
    """Block (rather than burn through the index recording failures) while the
    connection is down."""
    warned = False
    while not network_up():
        if not warned:
            print("  network down: pausing until github.com is reachable ...", flush=True)
            warned = True
        time.sleep(15)
    if warned:
        print("  network back: resuming", flush=True)


def docker_up() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=60).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def wait_for_docker():
    """Block while the Docker engine is unreachable (crash, reboot, Desktop
    restarting): every build would otherwise fail instantly and be recorded
    as build_failed."""
    warned = False
    while not docker_up():
        if not warned:
            print("  docker down: pausing until the engine responds ...", flush=True)
            warned = True
        time.sleep(30)
    if warned:
        print("  docker back: resuming", flush=True)


def trim_build_cache(max_gb: int = 30):
    """Routine cleanup after a verify wave: cap BuildKit's cache instead of
    wiping it, so base images, compiler layers and the shared pip cache stay
    warm (re-downloading them is the slow part of a build on a slow link)."""
    subprocess.run(["docker", "builder", "prune", "-f", "--max-used-space", f"{max_gb}gb"],
                   capture_output=True, timeout=300)


def order_candidates(cands, ledger):
    """Unprocessed candidates, round-robin across eras, rare CWEs first."""
    done = {cid for cid, rec in ledger.items() if _is_done(rec)}
    pending = [c for c in cands if c["id"] not in done]
    cwe_count = collections.Counter()
    for cid, rec in ledger.items():
        if rec.get("status") == "verified":
            for c in rec.get("cwes", []):
                cwe_count[c] += 1
    by_era = collections.defaultdict(list)
    for c in pending:
        by_era[c.get("era", "unknown")].append(c)
    for era in by_era:
        by_era[era].sort(key=lambda c: min((cwe_count[x] for x in c.get("cwes", ["unknown"])),
                                           default=0))
    order, eras = [], ["recent", "post_cutoff", "legacy", "unknown"]
    idx = {e: 0 for e in eras}
    while any(idx[e] < len(by_era.get(e, [])) for e in eras):
        for e in eras:
            lst = by_era.get(e, [])
            if idx[e] < len(lst):
                order.append(lst[idx[e]])
                idx[e] += 1
    return order


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--triage-batch", type=int, default=200)
    ap.add_argument("--verify", action="store_true", help="Docker-verify specs written this batch")
    ap.add_argument("--loop", action="store_true", help="keep processing batches until exhausted")
    ap.add_argument("--max-verify", type=int, default=0, help="cap verifications per batch (0 = all)")
    ap.add_argument("--workers", type=int, default=4,
                    help="concurrent tasks (git/docker are I/O-bound, so >#cores still helps)")
    ap.add_argument("--min-free-gb", type=float, default=8.0, help="disk floor before pruning/pausing")
    ap.add_argument("--disk-path", default="/", help="path on the disk holding Docker's data")
    ap.add_argument("--verify-only", action="store_true",
                    help="no triage: verify specs as a separate triage process writes them "
                         "(with --loop, keep polling until triage is finished)")
    ap.add_argument("--verify-workers", type=int, default=0,
                    help="concurrent Docker verifications (default: --workers); Docker "
                         "builds need far fewer than network-bound git fetches")
    args = ap.parse_args()
    vworkers = args.verify_workers or args.workers
    global DISK_PATH
    DISK_PATH = args.disk_path
    # A user-level http.postBuffer (often raised to ~500 MB to fix big pushes)
    # is allocated up front by every git-remote-https; across dozens of
    # parallel fetches that alone exhausts RAM. Fetches never need it, so pin
    # git's default for every git this process starts (env-scoped config,
    # leaves the user's ~/.gitconfig alone).
    os.environ.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.postBuffer",
                       "GIT_CONFIG_VALUE_0": "1048576"})

    cands = [json.loads(l) for l in open(CAND, encoding="utf-8") if l.strip()]
    grader = CodebaseGrader()
    net = NetMonitor()

    def record(cid, fields):
        ledger[cid] = update_ledger(cid, fields)

    def do_triage(c):
        wait_for_network()
        t0 = time.time()
        try:
            res = triage_one(c)
        except Exception as exc:
            res = {"id": c["id"], "status": f"error:{type(exc).__name__}"}
        if _transient(res["status"]) and net.outage_between(t0 - 10, time.time() + 10):
            return None  # the outage, not the advisory: leave it for a later batch
        prev = ledger.get(c["id"], {})
        tries = prev.get("tries", 1) + 1 if _transient(prev.get("status", "")) else 1
        record(c["id"], {"status": res["status"], "cwes": c.get("cwes", []),
                         "era": c.get("era"), "ts": time.time(), "tries": tries})
        return c["id"] if res["status"] == "spec_written" else None

    def do_verify(cid):
        disk_guard(args.min_free_gb)
        sp = SPECS / f"{_safe(cid)}.json"
        if not sp.exists():
            return None
        wait_for_network()
        wait_for_docker()
        t0 = time.time()
        v = {}
        try:
            v = verify_and_save(json.loads(sp.read_text()), grader)
            verdict = v.get("verdict", "verify_error")
        except Exception as exc:
            verdict = f"verify_error:{type(exc).__name__}"
        # "verified" is proven whatever the network or Docker did; any failure
        # that overlapped an outage may be the outage's fault: keep it queued.
        if verdict != "verified" and (net.outage_between(t0 - 10, time.time() + 10)
                                      or not docker_up()):
            return "retry_after_outage"
        # Could not download the code or a base image: GitHub / the registry
        # throttling a busy IP, or a flaky link the TCP probe did not see. Keep
        # the spec queued (back off a little) and only give up after MAX_TRIES.
        if verdict in ("fetch_failed", "build_net_error"):
            vtries = ledger.get(cid, {}).get("vtries", 0) + 1
            if vtries < MAX_TRIES:
                record(cid, {"vtries": vtries})
                time.sleep(60)
                return "retry_after_outage"
        # Test counts tell a genuine reject (tests ran and passed both times)
        # apart from an environment problem (nothing ran), which is fixable.
        counts = {k: v[k] for k in ("n_before_run", "n_before_pass", "n_after_run", "n_after_pass")
                  if k in v}
        record(cid, {"status": verdict, "vts": time.time(), **counts})
        return verdict

    # Specs triaged in an earlier run that was stopped before Docker
    # verification would otherwise stay at "spec_written" forever (the ledger
    # marks them processed); verify those first.
    ledger = load_ledger()
    if args.verify_only:
        while True:
            ledger = load_ledger()
            todo = [cid for cid, v in ledger.items() if v.get("status") == "spec_written"]
            if todo:
                print(f"== verifying {len(todo)} specs on {vworkers} workers "
                      f"(free {free_gb():.0f}GB) ==", flush=True)
                vdone = 0
                with ThreadPoolExecutor(max_workers=vworkers) as pool:
                    for fut in as_completed(pool.submit(do_verify, cid) for cid in todo):
                        vdone += 1
                        if vdone % 5 == 0:
                            n = sum(1 for v in load_ledger().values() if v["status"] == "verified")
                            print(f"    verified {vdone}/{len(todo)} (total verified: {n})", flush=True)
                trim_build_cache()
            elif not args.loop or not order_candidates(cands, ledger):
                break  # nothing left to verify and triage has nothing left to do
            else:
                time.sleep(60)  # wait for the triage process to write more specs
        args.loop = False

    stranded = [cid for cid, v in ledger.items() if v.get("status") == "spec_written"]
    if args.verify and stranded and not args.verify_only:
        print(f"== resuming {len(stranded)} specs left unverified by a previous run ==", flush=True)
        with ThreadPoolExecutor(max_workers=vworkers) as pool:
            list(pool.map(do_verify, stranded))
        trim_build_cache()

    while not args.verify_only:
        ledger = load_ledger()
        batch = order_candidates(cands, ledger)[: args.triage_batch]
        if not batch:
            print("no more candidates to process."); break
        print(f"\n== batch of {len(batch)} on {args.workers} workers "
              f"(ledger {len(ledger)}, free {free_gb():.0f}GB) ==", flush=True)

        newly_written, done = [], 0
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            for fut in as_completed(pool.submit(do_triage, c) for c in batch):
                done += 1
                cid = fut.result()
                if cid:
                    newly_written.append(cid)
                if done % 25 == 0:
                    print(f"  triaged {done}/{len(batch)}", flush=True)
        st = collections.Counter(v["status"] for v in load_ledger().values())
        print(f"  triage statuses so far: {dict(st)}", flush=True)

        if args.verify and newly_written:
            to_verify = newly_written if not args.max_verify else newly_written[: args.max_verify]
            print(f"  verifying {len(to_verify)} new specs on {vworkers} workers ...", flush=True)
            ledger = load_ledger()
            vdone = 0
            with ThreadPoolExecutor(max_workers=vworkers) as pool:
                for fut in as_completed(pool.submit(do_verify, cid) for cid in to_verify):
                    vdone += 1
                    if vdone % 5 == 0:
                        n = sum(1 for v in load_ledger().values() if v["status"] == "verified")
                        print(f"    verified {vdone}/{len(to_verify)} (total verified: {n})", flush=True)
            # reclaim build cache after a verify wave
            trim_build_cache()

        n_ver = sum(1 for v in load_ledger().values() if v["status"] == "verified")
        print(f"  VERIFIED tasks total: {n_ver}  (free {free_gb():.0f}GB)", flush=True)
        if not args.loop:
            break

    ledger = load_ledger()
    final = collections.Counter(v["status"] for v in ledger.values())
    print("\n=== harvest summary ===")
    for k, n in final.most_common():
        print(f"  {k:20s} {n}")
    print(f"verified tasks in {OUT/'verified'}")


if __name__ == "__main__":
    main()
