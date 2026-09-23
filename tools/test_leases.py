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
REPO = TOOLS.parent
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


def git_fixture(r: Path) -> str:
    """A real git work tree with one commit; returns the commit sha."""
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@e", "PATH": os.environ.get("PATH", "")}
    subprocess.run(["git", "init", "-q"], cwd=r, check=True, env=env, capture_output=True)
    subprocess.run(["git", "commit", "-q", "--allow-empty", "-m", "results"], cwd=r, check=True,
                   env=env, capture_output=True)
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=r, check=True, env=env,
                          capture_output=True, text=True).stdout.strip()


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
hb = leases.heartbeat(r, "s1-demo", lease_id=rec["lease_id"], now=1030.0)
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
            lambda: leases.heartbeat(r, "s1-demo", lease_id=rec["lease_id"], now=2000.0),
            leases.LeaseError)

# 5. Acquire on a held lease refuses; an expired lease is recovery-required, never an
# implicit takeover — the explicit recovery lane is release-with-reason first.
raise_check("acquire refuses while a lease is still held",
            lambda: leases.acquire(r, "s1-demo", now=1030.0), leases.LeaseHeld)
raise_check("acquire refuses an expired lease (recovery is explicit, never an implicit takeover)",
            lambda: leases.acquire(r, "s1-demo", now=2000.0), leases.LeaseHeld)
raise_check("release of the expired lease without a reason refuses",
            lambda: leases.release(r, "s1-demo", commit="a" * 40,
                                   lease_id=rec["lease_id"], now=2000.0), leases.LeaseError)
sha = git_fixture(r)
leases.release(r, "s1-demo", commit=sha, reason="operator recovered the expired lease",
               lease_id=rec["lease_id"], now=2000.0)
rec2 = leases.acquire(r, "s1-demo", owner_label="retry", interval_seconds=60.0, now=2001.0)
v4 = leases.verdict(r, "s1-demo", now=2001.0)
check("after explicit recovery a new generation acquires (new lease id, version continues)",
      rec2["lease_id"] != rec["lease_id"] and v4["version"] == 4 and v4["state"] == "active"
      and v4["lease_id"] == rec2["lease_id"])

# 6. Process-exit and release path: awaiting -> released with the commit recorded.
awaiting = leases.mark_awaiting(r, "s1-demo", exit_code=0, lease_id=rec2["lease_id"], now=2010.0)
v5 = leases.verdict(r, "s1-demo", now=2010.0)
check("mark_awaiting records the exit code and stays held",
      awaiting["state"] == "awaiting-reconciliation" and v5["state"] == "awaiting-reconciliation"
      and v5["blocked"] is True and v5["exit_code"] == 0)
raise_check("release refuses a commit that is not a 40-hex sha",
            lambda: leases.release(r, "s1-demo", commit="HEAD", lease_id=rec2["lease_id"]),
            leases.LeaseError)
released = leases.release(r, "s1-demo", commit=sha, reason="predicate clear",
                          lease_id=rec2["lease_id"], now=2020.0)
v6 = leases.verdict(r, "s1-demo", now=2020.0)
check("release records the commit and clears the run",
      released["state"] == "released" and v6["state"] == "released" and v6["blocked"] is False
      and v6["commit"] == sha and v6["version"] == 6)
raise_check("release of an already released lease refuses",
            lambda: leases.release(r, "s1-demo", commit=sha, lease_id=rec2["lease_id"]),
            leases.LeaseError)

# 6b. Writers are generation-bound: a stale wrapper cannot mutate the new generation.
stale = leases.acquire(r, "s1-demo", owner_label="third", interval_seconds=60.0, now=2100.0)
raise_check("a stale-generation heartbeat refuses (generation-bound writers)",
            lambda: leases.heartbeat(r, "s1-demo", lease_id=rec2["lease_id"], now=2101.0),
            leases.LeaseError)
raise_check("a stale-generation mark_awaiting refuses",
            lambda: leases.mark_awaiting(r, "s1-demo", exit_code=137,
                                         lease_id=rec2["lease_id"], now=2101.0), leases.LeaseError)
raise_check("a stale-generation release refuses",
            lambda: leases.release(r, "s1-demo", commit=sha, reason="stale",
                                   lease_id=rec2["lease_id"], now=2101.0), leases.LeaseError)
check("the current generation's writer is accepted",
      leases.mark_awaiting(r, "s1-demo", exit_code=0,
                           lease_id=stale["lease_id"], now=2102.0)["lease_id"] == stale["lease_id"])

# 7. Release from unknown requires an explicit reason (manual recovery path).
r2 = root()
rec_stale = leases.acquire(r2, "stale-run", interval_seconds=10.0, now=0.0)
check("a stale lease blocks until explicitly recovered",
      leases.verdict(r2, "stale-run", now=31.0)["state"] == "unknown-recovery-required")
raise_check("release of an unknown lease without a reason refuses",
            lambda: leases.release(r2, "stale-run", commit=sha, lease_id=rec_stale["lease_id"]),
            leases.LeaseError)
leases.release(r2, "stale-run", commit=sha, reason="operator verified results",
               lease_id=rec_stale["lease_id"], now=40.0)
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
rec3 = leases.acquire(r3, "corrupt-run", now=1.0)
with open(leases.lease_path(r3, "corrupt-run"), "a", encoding="utf-8") as handle:
    handle.write("{not json}\n")
vc = leases.verdict(r3, "corrupt-run", now=2.0)
check("a corrupt line is tolerated but blocks with a count",
      vc["state"] == "unknown-recovery-required" and vc["blocked"] is True
      and vc["corrupt_lines"] == 1 and "corrupt line" in vc["reason"])
raise_check("mutation refuses a registry with a corrupt line",
            lambda: leases.heartbeat(r3, "corrupt-run", lease_id=rec3["lease_id"], now=3.0),
            leases.LeaseError)

# 10. Unverifiable chains: unknown state string, non-increasing version.
r4 = root()
leases.acquire(r4, "tampered", now=1.0)
with open(leases.lease_path(r4, "tampered"), "a", encoding="utf-8") as handle:
    handle.write(json.dumps({"seq": 2, "version": 2, "state": "sneaky"}) + "\n")
check("an unknown state string is unverifiable (blocked)",
      leases.verdict(r4, "tampered", now=2.0)["state"] == "unknown-recovery-required")
r5 = root()
rec5 = leases.acquire(r5, "tampered2", now=1.0)
leases.heartbeat(r5, "tampered2", lease_id=rec5["lease_id"], now=2.0)
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
rec_a = leases.acquire(r8, "run-a", interval_seconds=1000.0, now=1.0)
rec_b = leases.acquire(r8, "run-b", interval_seconds=1000.0, now=1.0)
sha8 = git_fixture(r8)
leases.mark_awaiting(r8, "run-b", exit_code=0, lease_id=rec_b["lease_id"], now=2.0)
leases.release(r8, "run-b", commit=sha8, lease_id=rec_b["lease_id"], now=3.0)
wide = leases.verdict_all(r8, now=3.0)
check("workspace-wide verdict blocks while any run holds a lease",
      wide["blocked"] is True and wide["state"] == "active" and len(wide["runs"]) == 2)
leases.mark_awaiting(r8, "run-a", exit_code=0, lease_id=rec_a["lease_id"], now=4.0)
leases.release(r8, "run-a", commit=sha8, lease_id=rec_a["lease_id"], now=5.0)
check("workspace-wide verdict clears when every lease is released",
      leases.verdict_all(r8, now=5.0)["blocked"] is False)
with open(leases.lease_path(r8, "run-a"), "a", encoding="utf-8") as handle:
    handle.write("garbage\n")
check("workspace-wide verdict blocks on a corrupt file anywhere",
      leases.verdict_all(r8, now=6.0)["blocked"] is True)
check("a missing registry blocks the workspace-wide verdict",
      leases.verdict_all(root(), now=1.0)["blocked"] is True)

# ---------------- D2: launch wrapper ----------------

WRAPPER = TOOLS / "lease_run.py"


def run_wrapper(r: Path, run_id: str, cmd: list[str], *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(WRAPPER), "--root", str(r), "--run", run_id, *args, "--", *cmd],
        capture_output=True, text=True, timeout=120)


# 13. Spawn/sleep/exit: heartbeats while the tree lives, awaiting-reconciliation after.
r9 = root()
started = time.monotonic()
proc = run_wrapper(r9, "w-sleep", ["sleep", "0.6"], "--interval", "0.2")
elapsed = time.monotonic() - started
v7 = leases.verdict(r9, "w-sleep")
check("the wrapper propagates a clean exit code", proc.returncode == 0 and elapsed >= 0.5)
check("process exit leaves the lease held at awaiting-reconciliation (never success)",
      v7["state"] == "awaiting-reconciliation" and v7["blocked"] is True
      and v7["exit_code"] == 0)
check("the wrapper records the child process group", isinstance(v7["pgid"], int)
      and v7["pgid"] > 0 and not leases._pgid_alive(v7["pgid"]))
records = [json.loads(line) for line in
           leases.lease_path(r9, "w-sleep").read_text().splitlines() if line.strip()]
check("the wrapper heartbeats while the tree is live and the versions are monotonic",
      any(rec["event"] == "heartbeat" for rec in records)
      and all(rec["event"] in ("heartbeat", "acquire") or rec["state"] == "awaiting-reconciliation"
              for rec in records)
      and [rec["version"] for rec in records] == list(range(1, len(records) + 1)))

# 14. Non-zero exit is recorded raw, never interpreted.
r10 = root()
proc = run_wrapper(r10, "w-fail", ["sh", "-c", "exit 7"], "--interval", "5")
v8 = leases.verdict(r10, "w-fail")
check("a non-zero exit code propagates and is recorded raw",
      proc.returncode == 7 and v8["state"] == "awaiting-reconciliation"
      and v8["exit_code"] == 7)

# 15. Kill the wrapper: the lease stays active (no silent release) and expiry covers it.
r11 = root()
marker = r11 / "spawned-marker"
wrapper = subprocess.Popen(
    [sys.executable, str(WRAPPER), "--root", str(r11), "--run", "w-killed",
     "--interval", "0.2", "--", "sh", "-c", f"touch {marker}; sleep 30"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
pgid = None
try:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        current = leases.verdict(r11, "w-killed")
        if isinstance(current.get("pgid"), int) and marker.exists():
            pgid = current["pgid"]
            break
        time.sleep(0.05)
    check("the wrapper records the process group before the child does work", pgid is not None)
    wrapper.kill()
    wrapper.wait(timeout=30)
    v9 = leases.verdict(r11, "w-killed")
    check("killing the wrapper leaves the lease active, not released",
          v9["state"] == "active" and v9["blocked"] is True)
    v10 = leases.verdict(r11, "w-killed", now=time.time() + 3600)
    check("expiry covers a killed wrapper (unknown-recovery-required, never success)",
          v10["state"] == "unknown-recovery-required" and v10["blocked"] is True)
finally:
    if pgid:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except OSError:
            pass
    if wrapper.poll() is None:
        wrapper.kill()
        wrapper.wait(timeout=30)

# 16. A held lease refuses before any spawn.
r12 = root()
leases.acquire(r12, "w-held", interval_seconds=1000.0)
marker2 = r12 / "must-not-exist"
proc = run_wrapper(r12, "w-held", ["sh", "-c", f"touch {marker2}"], "--interval", "5")
check("a held lease refuses the launch before spawning",
      proc.returncode != 0 and not marker2.exists()
      and ("refus" in proc.stderr.lower() or "still holds" in proc.stderr))
check("the refused launch names the run and the held state",
      "w-held" in proc.stderr and "lease" in proc.stderr.lower())

# ---------------- D3: completion predicate + reconciliation ----------------

RESEARCHCTL = TOOLS / "researchctl.py"


def dead_pgid() -> int:
    """A pgid whose group has no live members (a reaped child's pid)."""
    proc = subprocess.Popen(["true"])
    pid = proc.pid
    proc.wait()
    return pid


def make_run(r: Path, run: str = "sweep-1", *, cells: tuple[str, ...] = ("cell-a", "cell-b"),
             plan: bool = True, manifests: bool = True,
             manifests_for: tuple[str, ...] | None = None, reports: bool = True,
             reports_newer: bool = True, commit: bool = True, commit_sha: str | None = None,
             repo: bool = True, pgid: int | None = None, record_pgid: bool = True,
             lease: bool = True, state: str = "awaiting") -> Path:
    """A root-relative run fixture; returns the fixture root."""
    (r / "runs" / run).mkdir(parents=True, exist_ok=True)
    if plan:
        (r / "runs" / run / "plan.json").write_text(json.dumps({"cells": list(cells)}))
    with_manifest = cells if manifests_for is None else manifests_for
    for index, cell in enumerate(cells):
        if manifests and cell in with_manifest:
            (r / "runs" / cell).mkdir(parents=True, exist_ok=True)
            (r / "runs" / cell / "manifest.json").write_text(
                json.dumps({"run_id": cell, "order": index}))
    if reports:
        (r / "reports").mkdir(parents=True, exist_ok=True)
        (r / "reports" / "sweep.md").write_text("# sweep\n")
        if not reports_newer:
            old = time.time() - 3600
            os.utime(r / "reports" / "sweep.md", (old, old))
    sha = commit_sha
    if commit and sha is None:
        sha = git_fixture(r) if repo else "f" * 40
    if commit:
        (r / "runs" / run / "results-commit").write_text(sha + "\n")
    elif repo:
        git_fixture(r)
    if lease:
        rec = leases.acquire(r, run, interval_seconds=1000.0)
        if state != "active":
            if pgid is None:
                pgid = dead_pgid()
            if record_pgid:
                leases.heartbeat(r, run, pgid=pgid, lease_id=rec["lease_id"])
            leases.mark_awaiting(r, run, exit_code=0, lease_id=rec["lease_id"])
    return r


# 17. Full set clears and releases with the commit recorded.
r13 = make_run(root())
result = leases.reconcile(r13, "sweep-1")
v11 = leases.verdict(r13, "sweep-1")
check("the full conjunct set clears and releases the lease",
      result["clear"] is True and result["released"] is True and v11["state"] == "released"
      and v11["blocked"] is False and v11["commit"] == result["commit"])
check("a clear reconcile records exactly one attempt",
      result["attempts"] == 1 and result["recovery_required"] is False)

# 18. Every missing conjunct blocks.
cases = [
    ("plan", dict(plan=False)),
    ("a planned cell without a manifest", dict(cells=("cell-a", "cell-gone"),
                                              manifests_for=("cell-a",))),
    ("an empty plan", dict(cells=())),
    ("a missing reports directory", dict(reports=False)),
    ("stale reports", dict(reports_newer=False)),
    ("a missing results commit", dict(commit=False)),
    ("a results commit unknown to git", dict(commit_sha="e" * 40)),
    ("a missing git work tree", dict(repo=False, commit_sha="e" * 40)),
    ("live children in the recorded group", dict(pgid=os.getpgid(os.getpid()))),
    ("no recorded process group", dict(record_pgid=False)),
]
for label, kwargs in cases:
    fixture_root = make_run(root(), **kwargs)
    outcome = leases.reconcile(fixture_root, "sweep-1")
    check(f"blocked: {label}",
          outcome["clear"] is False and outcome["released"] is False
          and outcome["state"] == "awaiting-reconciliation" and bool(outcome["failed"]))
live = leases.reconcile(make_run(root(), pgid=os.getpgid(os.getpid())), "sweep-1")
check("the live-children block names the process group",
      "live members" in live["conjuncts"]["children-dead"]["reason"])
no_pgid = leases.reconcile(make_run(root(), record_pgid=False), "sweep-1")
check("an unrecorded process group blocks with an explicit reason",
      "no process-group id" in no_pgid["conjuncts"]["children-dead"]["reason"])

# 19. No lease recorded -> loop exit is not established; never clear.
r14 = root()
leases.registry_dir(r14).mkdir(parents=True)
make_run(r14, lease=False)
outcome = leases.reconcile(r14, "sweep-1")
check("a run with no lease never clears (loop exit unverifiable)",
      outcome["clear"] is False and outcome["state"] == "no-lease")
r14b = root()
make_run(r14b, lease=False)
outcome = leases.reconcile(r14b, "sweep-1")
check("a missing registry reconciles to recovery-required, never clear",
      outcome["clear"] is False and outcome["recovery_required"] is True
      and outcome["state"] == "unknown-recovery-required")

# 20. Stale/expired -> unknown-recovery-required, one bounded attempt, never success.
r15 = root()
make_run(r15, state="active")
stale = leases.reconcile(r15, "sweep-1", now=time.time() + 3600)
check("a stale lease reconciles to recovery-required, never a success report",
      stale["clear"] is False and stale["released"] is False
      and stale["state"] == "unknown-recovery-required" and stale["recovery_required"] is True
      and stale["attempts"] == 1)

# 21. Already released: idempotent clear, no new records.
r16 = make_run(root())
leases.reconcile(r16, "sweep-1")
records_before = leases.verdict(r16, "sweep-1")["record_count"]
again = leases.reconcile(r16, "sweep-1")
check("reconciling an already released run is an idempotent clear",
      again["clear"] is True and again["already_released"] is True and again["released"] is False
      and leases.verdict(r16, "sweep-1")["record_count"] == records_before)

# 22. The CLI seam: exit 3 while blocked, exit 0 on clear, no 11_runtime side effect.
r17 = make_run(root(), cells=("cell-a", "cell-missing"), manifests_for=("cell-a",))
blocked = subprocess.run([sys.executable, str(RESEARCHCTL), str(r17), "lease-reconcile", "sweep-1"],
                         capture_output=True, text=True, timeout=60)
payload = json.loads(blocked.stdout)
check("researchctl lease-reconcile exits 3 and reports the failed conjuncts",
      blocked.returncode == 3 and payload["clear"] is False
      and "manifests" in payload["failed"] and "BLOCKED" in blocked.stderr)
check("lease-reconcile does not instantiate the control plane (no 11_runtime side effect)",
      not (r17 / "11_runtime").exists())

r18 = make_run(root())
clear = subprocess.run([sys.executable, str(RESEARCHCTL), str(r18), "lease-reconcile", "sweep-1"],
                       capture_output=True, text=True, timeout=60)
payload2 = json.loads(clear.stdout)
check("researchctl lease-reconcile exits 0, releases and records the commit",
      clear.returncode == 0 and payload2["clear"] is True and payload2["released"] is True
      and payload2["commit"] == leases.verdict(r18, "sweep-1")["commit"]
      and "CLEAR" in clear.stderr)

# ---------------- D4: cross-language verdict parity (JS reader vs Python) -------

ADAPTER = REPO / "dsh-plugin" / "goal-deferral" / "index.js"
PARITY_RUNNER = (
    "import {readLeaseVerdict} from " + json.dumps(ADAPTER.as_uri()) + ";"
    "const [root, runId, now] = process.argv.slice(1);"
    "const v = readLeaseVerdict(root, runId === '-' ? null : runId, {now: Number(now)});"
    "process.stdout.write(JSON.stringify({state: v.state, blocked: v.blocked}))"
)


def js_verdict(fixture_root: Path, run_id: str | None, now: float) -> dict:
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", PARITY_RUNNER,
         str(fixture_root), run_id or "-", str(now)],
        capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"node exit {proc.returncode}")
    return json.loads(proc.stdout)


if shutil.which("node") is None:
    print("SKIP (node unavailable) — lease verdict parity NOT verified")
else:
    parity: list[tuple[str, Path, str | None, float]] = []

    def parity_case(label: str, fixture_root: Path, run_id: str | None, now: float):
        parity.append((label, fixture_root, run_id, now))

    p_active = root()
    leases.acquire(p_active, "run", interval_seconds=1000.0, now=100.0)
    parity_case("active", p_active, "run", 200.0)
    parity_case("active expired", p_active, "run", 4000.0)
    p_awaiting = root()
    rec_pa = leases.acquire(p_awaiting, "run", interval_seconds=1000.0, now=100.0)
    leases.mark_awaiting(p_awaiting, "run", exit_code=3, lease_id=rec_pa["lease_id"], now=110.0)
    parity_case("awaiting-reconciliation", p_awaiting, "run", 200.0)
    p_unknown = root()
    rec_pu = leases.acquire(p_unknown, "run", interval_seconds=1000.0, now=100.0)
    leases.mark_unknown(p_unknown, "run", reason="boom", lease_id=rec_pu["lease_id"], now=110.0)
    parity_case("unknown-recovery-required", p_unknown, "run", 200.0)
    p_released = root()
    sha_released = git_fixture(p_released)
    rec_pr = leases.acquire(p_released, "run", interval_seconds=1000.0, now=100.0)
    leases.mark_awaiting(p_released, "run", exit_code=0, lease_id=rec_pr["lease_id"], now=110.0)
    leases.release(p_released, "run", commit=sha_released, lease_id=rec_pr["lease_id"], now=120.0)
    parity_case("released", p_released, "run", 200.0)
    p_no_lease = root()
    leases.registry_dir(p_no_lease).mkdir(parents=True)
    parity_case("no-lease", p_no_lease, "run", 200.0)
    parity_case("missing registry", root(), "run", 200.0)
    p_corrupt = root()
    leases.acquire(p_corrupt, "run", interval_seconds=1000.0, now=100.0)
    with open(leases.lease_path(p_corrupt, "run"), "a", encoding="utf-8") as handle:
        handle.write("{oops}\n")
    parity_case("corrupt line", p_corrupt, "run", 200.0)
    p_empty = root()
    leases.registry_dir(p_empty).mkdir(parents=True)
    leases.lease_path(p_empty, "run").write_text("")
    parity_case("empty file", p_empty, "run", 200.0)
    p_chain = root()
    leases.acquire(p_chain, "run", interval_seconds=1000.0, now=100.0)
    with open(leases.lease_path(p_chain, "run"), "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"seq": 2, "version": 1, "state": "released"}) + "\n")
    parity_case("non-increasing version", p_chain, "run", 200.0)
    p_state = root()
    leases.acquire(p_state, "run", interval_seconds=1000.0, now=100.0)
    with open(leases.lease_path(p_state, "run"), "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"seq": 2, "version": 2, "state": "sneaky"}) + "\n")
    parity_case("unknown state string", p_state, "run", 200.0)
    p_wide = root()
    sha_wide = git_fixture(p_wide)
    leases.acquire(p_wide, "run-a", interval_seconds=1000.0, now=100.0)
    rec_pwb = leases.acquire(p_wide, "run-b", interval_seconds=1000.0, now=100.0)
    leases.mark_awaiting(p_wide, "run-b", exit_code=0, lease_id=rec_pwb["lease_id"], now=110.0)
    leases.release(p_wide, "run-b", commit=sha_wide, lease_id=rec_pwb["lease_id"], now=120.0)
    parity_case("workspace-wide with one held run", p_wide, None, 200.0)
    p_wide_clear = root()
    sha_clear = git_fixture(p_wide_clear)
    rec_pwc = leases.acquire(p_wide_clear, "run-a", interval_seconds=1000.0, now=100.0)
    leases.mark_awaiting(p_wide_clear, "run-a", exit_code=0, lease_id=rec_pwc["lease_id"], now=130.0)
    leases.release(p_wide_clear, "run-a", commit=sha_clear, lease_id=rec_pwc["lease_id"], now=140.0)
    parity_case("workspace-wide all released", p_wide_clear, None, 200.0)
    p_wide_corrupt = root()
    leases.acquire(p_wide_corrupt, "run-a", interval_seconds=1000.0, now=100.0)
    with open(leases.lease_path(p_wide_corrupt, "run-a"), "a", encoding="utf-8") as handle:
        handle.write("junk\n")
    parity_case("workspace-wide with a corrupt file", p_wide_corrupt, None, 200.0)

    for label, fixture_root, run_id, now in parity:
        try:
            js = js_verdict(fixture_root, run_id, now)
        except RuntimeError as exc:
            check(f"parity: {label} (node error: {exc})", False)
            continue
        py = leases.verdict_all(fixture_root, now=now) if run_id is None \
            else leases.verdict(fixture_root, run_id, now=now)
        check(f"parity: {label} (python {py['state']} / node {js['state']})",
              py["state"] == js["state"] and py["blocked"] == js["blocked"])

    raise_check("parity: an unsafe run id is refused by python",
                lambda: leases.verdict(p_active, "../escape"), leases.LeaseError)
    unsafe = js_verdict(p_active, "../escape", 200.0)
    check("parity: an unsafe run id blocks the node reader",
          unsafe["blocked"] is True and unsafe["state"] == "unknown-recovery-required")

print(f"\n{len(passed)}/{len(passed) + len(failures)} passed")
for path in ROOTS:
    shutil.rmtree(path, ignore_errors=True)
if failures:
    print("failed: " + "; ".join(failures))
    raise SystemExit(1)
