#!/usr/bin/env python3
"""Tests for the work-lease registry, launch wrapper and completion predicate.

Sections: D1 registry (`tools/leases.py`), D2 wrapper (`tools/lease_run.py`),
D3 predicate/reconciliation. Stdlib only; real child processes, real git fixture.

Run: python3 tools/test_leases.py (exits non-zero on failure).
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import leases  # noqa: E402

passed: list[str] = []
failures: list[str] = []


def check(name: str, cond: bool):
    if cond:
        passed.append(name)
        print(f"ok: {name}")
    else:
        failures.append(name)
        print(f"FAIL: {name}")


def fixture(prefix: str = "leases-") -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix))


ROOTS: list[Path] = []


def root(prefix: str = "leases-") -> Path:
    path = fixture(prefix)
    ROOTS.append(path)
    return path


def raise_check(name: str, fn, expected: type[BaseException]) -> None:
    try:
        fn()
    except expected:
        check(name, True)
        return
    except BaseException as exc:  # noqa: BLE001 - report the wrong exception type
        check(f"{name} (got {type(exc).__name__}: {exc})", False)
        return
    check(name, False)


# ---------------- D1: registry ----------------

# 1. Acquire -> active verdict with lineage, monotonic version and a safe expiry.
r = root()
rec = leases.acquire(r, "s1-demo", owner_label="battery", session="ses_abc",
                     command="python3 -m harness.run", interval_seconds=120.0, now=1000.0)
v = leases.verdict(r, "s1-demo", now=1000.0)
check("acquire records the owner/session lineage and command",
      v["owner"] == {"pid": os.getpid(), "label": "battery", "session": "ses_abc"}
      and v["command"] == "python3 -m harness.run")
check("acquire starts an active, blocked lease at version 1",
      v["state"] == "active" and v["blocked"] is True and v["version"] == 1
      and v["lease_id"] == rec["lease_id"])
check("expiry is strictly greater than 2x the heartbeat interval",
      v["expires_at"] - v["heartbeat_at"] > 2 * v["interval_seconds"]
      and v["expires_at"] == 1000.0 + 120.0 * leases.EXPIRY_MULTIPLIER)

# 2. Heartbeat -> version bump, advanced window, file grows append-only.
hb = leases.heartbeat(r, "s1-demo", now=1030.0)
v2 = leases.verdict(r, "s1-demo", now=1030.0)
check("heartbeat bumps the version and advances the expiry window",
      v2["version"] == 2 and hb["heartbeat_at"] == 1030.0
      and v2["expires_at"] == 1030.0 + 120.0 * leases.EXPIRY_MULTIPLIER
      and v2["record_count"] == 2 and v2["lease_id"] == v["lease_id"])

# 3. Expiry: a missed heartbeat reads as unknown, and the file is never rewritten.
v3 = leases.verdict(r, "s1-demo", now=1030.0 + 120.0 * leases.EXPIRY_MULTIPLIER + 1)
check("a missed heartbeat expires into unknown-recovery-required (blocked)",
      v3["state"] == "unknown-recovery-required" and v3["blocked"] is True
      and "expired" in v3["reason"])
check("expiry never deletes or rewrites the registry (append-only)",
      v3["record_count"] == 2
      and json.loads(leases.lease_path(r, "s1-demo").read_text().splitlines()[-1])["state"] == "active")

# 4. Heartbeat on a non-active lease refuses (fail closed).
raise_check("heartbeat on an expired (unknown) lease refuses",
            lambda: leases.heartbeat(r, "s1-demo", now=2000.0), leases.LeaseError)

# 5. Acquire on a held lease refuses; after expiry it takes over with a new lease id.
raise_check("acquire refuses while a lease is still held",
            lambda: leases.acquire(r, "s1-demo", now=1030.0), leases.LeaseHeld)
rec2 = leases.acquire(r, "s1-demo", owner_label="retry", interval_seconds=60.0, now=2000.0)
v4 = leases.verdict(r, "s1-demo", now=2000.0)
check("acquire after expiry takes over: new lease id, version continues",
      rec2["lease_id"] != rec["lease_id"] and v4["version"] == 3 and v4["state"] == "active")

# 6. Process-exit and release path: awaiting -> released with the commit recorded.
awaiting = leases.mark_awaiting(r, "s1-demo", exit_code=0, now=2010.0)
v5 = leases.verdict(r, "s1-demo", now=2010.0)
check("mark_awaiting records the exit code and stays held",
      awaiting["state"] == "awaiting-reconciliation" and v5["state"] == "awaiting-reconciliation"
      and v5["blocked"] is True and v5["exit_code"] == 0)
raise_check("release refuses a commit that is not a 40-hex sha",
            lambda: leases.release(r, "s1-demo", commit="HEAD"), leases.LeaseError)
sha = "a" * 40
released = leases.release(r, "s1-demo", commit=sha, reason="predicate clear", now=2020.0)
v6 = leases.verdict(r, "s1-demo", now=2020.0)
check("release records the commit and clears the run",
      released["state"] == "released" and v6["state"] == "released" and v6["blocked"] is False
      and v6["commit"] == sha and v6["version"] == 5)
raise_check("release of an already released lease refuses",
            lambda: leases.release(r, "s1-demo", commit=sha), leases.LeaseError)

# 7. Release from unknown requires an explicit reason (manual recovery path).
r2 = root()
leases.acquire(r2, "stale-run", interval_seconds=10.0, now=0.0)
check("a stale lease blocks until explicitly recovered",
      leases.verdict(r2, "stale-run", now=31.0)["state"] == "unknown-recovery-required")
raise_check("release of an unknown lease without a reason refuses",
            lambda: leases.release(r2, "stale-run", commit=sha), leases.LeaseError)
leases.release(r2, "stale-run", commit=sha, reason="operator verified results", now=40.0)
check("release of an unknown lease with a reason clears it",
      leases.verdict(r2, "stale-run", now=40.0)["state"] == "released")

# 8. Missing registry / no lease for the run / unsafe run id.
empty = root()
check("a missing registry is never clear",
      leases.verdict(empty, "any-run")["state"] == "unknown-recovery-required"
      and leases.verdict(empty, "any-run")["blocked"] is True)
leases.registry_dir(empty).mkdir(parents=True)
check("a readable registry without a lease file for the run is clear",
      leases.verdict(empty, "any-run")["state"] == "no-lease"
      and leases.verdict(empty, "any-run")["blocked"] is False)
raise_check("a run id with path separators refuses",
            lambda: leases.verdict(empty, "../escape"), leases.LeaseError)
raise_check("an empty run id refuses", lambda: leases.verdict(empty, ""), leases.LeaseError)

# 9. Corrupt line tolerance: reported, counted, never a crash, never clear.
r3 = root()
leases.acquire(r3, "corrupt-run", now=1.0)
with open(leases.lease_path(r3, "corrupt-run"), "a", encoding="utf-8") as handle:
    handle.write("{not json}\n")
vc = leases.verdict(r3, "corrupt-run", now=2.0)
check("a corrupt line is tolerated but blocks with a count",
      vc["state"] == "unknown-recovery-required" and vc["blocked"] is True
      and vc["corrupt_lines"] == 1 and "corrupt line" in vc["reason"])
raise_check("mutation refuses a registry with a corrupt line",
            lambda: leases.heartbeat(r3, "corrupt-run", now=3.0), leases.LeaseError)

# 10. Unverifiable chains: unknown state string, non-increasing version.
r4 = root()
leases.acquire(r4, "tampered", now=1.0)
with open(leases.lease_path(r4, "tampered"), "a", encoding="utf-8") as handle:
    handle.write(json.dumps({"seq": 2, "version": 2, "state": "sneaky"}) + "\n")
check("an unknown state string is unverifiable (blocked)",
      leases.verdict(r4, "tampered", now=2.0)["state"] == "unknown-recovery-required")
r5 = root()
leases.acquire(r5, "tampered2", now=1.0)
leases.heartbeat(r5, "tampered2", now=2.0)
with open(leases.lease_path(r5, "tampered2"), "a", encoding="utf-8") as handle:
    handle.write(json.dumps({"seq": 3, "version": 1, "state": "released",
                             "commit": "b" * 40}) + "\n")
check("a non-increasing version chain is unverifiable (blocked)",
      leases.verdict(r5, "tampered2", now=3.0)["state"] == "unknown-recovery-required")
r6 = root()
leases.acquire(r6, "empty-file", now=1.0)
leases.lease_path(r6, "empty-file").write_text("")
check("an empty registry file is unverifiable (blocked)",
      leases.verdict(r6, "empty-file", now=2.0)["state"] == "unknown-recovery-required")

# 11. Lock contention: a live holder blocks; a killed holder releases automatically.
HOLD = (
    "import fcntl, os, sys, time\n"
    "fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT, 0o600)\n"
    "fcntl.flock(fd, fcntl.LOCK_EX)\n"
    "print('held', flush=True)\n"
    "time.sleep(float(sys.argv[2]))\n"
)
r7 = root()
lock_file = leases.registry_dir(r7) / ".lock"
leases.registry_dir(r7).mkdir(parents=True, exist_ok=True)
holder = subprocess.Popen([sys.executable, "-c", HOLD, str(lock_file), "30"],
                          stdout=subprocess.PIPE, text=True)
try:
    assert holder.stdout.readline().strip() == "held"
    started = time.monotonic()
    raise_check("a live lock holder blocks a writer (timeout, fail closed)",
                lambda: leases.acquire(r7, "contended", now=1.0), TimeoutError)
    check("the contended writer waited for the timeout, not zero",
          time.monotonic() - started >= 0.5)
    holder.kill()
    holder.wait(timeout=10)
    leases.acquire(r7, "contended", now=2.0)
    check("a killed lock holder releases the lock automatically (flock)",
          leases.verdict(r7, "contended", now=2.0)["state"] == "active")
finally:
    if holder.poll() is None:
        holder.kill()
        holder.wait(timeout=10)

# 12. Workspace-wide verdict: any held lease blocks; all released is clear.
r8 = root()
leases.acquire(r8, "run-a", interval_seconds=1000.0, now=1.0)
leases.acquire(r8, "run-b", interval_seconds=1000.0, now=1.0)
leases.mark_awaiting(r8, "run-b", exit_code=0, now=2.0)
leases.release(r8, "run-b", commit="c" * 40, now=3.0)
wide = leases.verdict_all(r8, now=3.0)
check("workspace-wide verdict blocks while any run holds a lease",
      wide["blocked"] is True and wide["state"] == "active" and len(wide["runs"]) == 2)
leases.mark_awaiting(r8, "run-a", exit_code=0, now=4.0)
leases.release(r8, "run-a", commit="d" * 40, now=5.0)
check("workspace-wide verdict clears when every lease is released",
      leases.verdict_all(r8, now=5.0)["blocked"] is False)
with open(leases.lease_path(r8, "run-a"), "a", encoding="utf-8") as handle:
    handle.write("garbage\n")
check("workspace-wide verdict blocks on a corrupt file anywhere",
      leases.verdict_all(r8, now=6.0)["blocked"] is True)
check("a missing registry blocks the workspace-wide verdict",
      leases.verdict_all(root(), now=1.0)["blocked"] is True)

print(f"\n{len(passed)}/{len(passed) + len(failures)} passed")
for path in ROOTS:
    shutil.rmtree(path, ignore_errors=True)
if failures:
    print("failed: " + "; ".join(failures))
    raise SystemExit(1)
