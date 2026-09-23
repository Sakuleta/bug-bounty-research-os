#!/usr/bin/env python3
"""Lease-guarded process launcher (goal-deferral sprint D2).

Acquires the run's work lease BEFORE spawning, renews the heartbeat while the
process tree is alive, and records the raw exit code as
`awaiting-reconciliation` on exit — process exit is never interpreted as success.
The lease is released only by `researchctl lease-reconcile` after the completion
predicate clears.

    python3 tools/lease_run.py --root <workspace> --run <run-id> -- <command> [args...]

The child is spawned in its own session/process group (`start_new_session`), so
the recorded pgid is the whole tree and the reconciliation predicate can prove
"zero matching children alive". A wrapper killed with SIGKILL leaves the lease
`active`; expiry (3x the heartbeat interval) turns it into
`unknown-recovery-required`, so a dead wrapper can never orphan a forever-active
lease. A catchable signal (SIGTERM/SIGINT) kills the group and records
`unknown-recovery-required` explicitly.

The child inherits stdout/stderr; this wrapper's own messages go to stderr so
piped output stays the command's output. Exit code: the child's, mapped to
128+signal when the child died on a signal.
"""
from __future__ import annotations

import argparse
import os
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import leases  # noqa: E402


class _WrapperSignal(Exception):
    def __init__(self, signum: int):
        super().__init__(f"signal {signum}")
        self.signum = signum


def _kill_group(proc: subprocess.Popen) -> None:
    """Kill the whole child group; fall back to the direct child when it is gone."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except OSError:
        try:
            proc.kill()
        except OSError:
            pass


def _install_signal_handlers() -> None:
    def handler(signum, _frame):
        raise _WrapperSignal(signum)
    for signum in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(signum, handler)
        except ValueError:
            pass


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="lease_run.py", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".", help="run workspace root holding .leases/ (default: cwd)")
    ap.add_argument("--run", required=True, help="stable run id (becomes .leases/<run>.jsonl)")
    ap.add_argument("--interval", type=float, default=leases.DEFAULT_HEARTBEAT_SECONDS,
                    help=f"heartbeat interval in seconds (default {leases.DEFAULT_HEARTBEAT_SECONDS:g}; "
                         "expiry is 3x this)")
    ap.add_argument("--owner", default="", help="owner label recorded on the lease")
    ap.add_argument("--session", default="", help="session/lineage label recorded on the lease")
    ap.add_argument("cmd", nargs=argparse.REMAINDER,
                    help="command to run (use `--` before it to stop option parsing)")
    ns = ap.parse_args()

    cmd = list(ns.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("lease-run: no command given (usage: lease_run.py --root R --run ID -- <cmd>)",
              file=sys.stderr)
        return 2
    root = Path(ns.root).resolve()
    if ns.interval <= 0:
        print("lease-run: --interval must be positive", file=sys.stderr)
        return 2

    try:
        lease = leases.acquire(root, ns.run, owner_label=ns.owner, session=ns.session,
                               command=shlex.join(cmd), interval_seconds=ns.interval)
    except leases.LeaseError as exc:
        print(f"lease-run: refusing to launch — {exc}", file=sys.stderr)
        return 1
    lease_id = lease["lease_id"]

    _install_signal_handlers()
    try:
        proc = subprocess.Popen(cmd, start_new_session=True)
    except OSError as exc:
        leases.mark_unknown(root, ns.run, reason=f"spawn failed: {exc}", lease_id=lease_id)
        print(f"lease-run: spawn failed: {exc} (lease marked unknown-recovery-required)",
              file=sys.stderr)
        return 127

    # Record the process group as the first heartbeat: the reconcile predicate needs
    # it, and a wrapper crash before this record leaves it unverifiable (fail closed).
    _heartbeat(root, ns.run, proc.pid, lease_id)

    while True:
        try:
            proc.wait(timeout=ns.interval)
            break
        except subprocess.TimeoutExpired:
            _heartbeat(root, ns.run, proc.pid, lease_id)
        except _WrapperSignal as sig:
            _kill_group(proc)
            try:
                leases.mark_unknown(
                    root, ns.run, lease_id=lease_id,
                    reason=f"wrapper received signal {sig.signum}; the process tree was killed "
                           "and the results are unreconciled")
            except leases.LeaseError as exc:
                print(f"lease-run: could not record the signal exit: {exc}", file=sys.stderr)
            print(f"lease-run: run {ns.run} interrupted (signal {sig.signum}) — "
                  "unknown-recovery-required", file=sys.stderr)
            return 128 + sig.signum

    exit_code = proc.returncode if proc.returncode >= 0 else 128 - proc.returncode
    try:
        leases.mark_awaiting(root, ns.run, exit_code=exit_code, lease_id=lease_id)
    except leases.LeaseError as exc:
        # The exit is real but the registry is unverifiable: say so loudly; the lease
        # blocks (unknown) rather than reading as success.
        print(f"lease-run: could not record the exit for run {ns.run}: {exc}", file=sys.stderr)
    print(f"lease-run: run {ns.run} exited (code {exit_code}) — lease held at "
          "awaiting-reconciliation; reconcile before treating this as success", file=sys.stderr)
    return exit_code


def _heartbeat(root: Path, run_id: str, pgid: int, lease_id: str) -> None:
    """Renew the lease; a broken registry warns and keeps supervising.

    A heartbeat that cannot be recorded means the lease will expire into
    `unknown-recovery-required` (blocking both continuation layers), so the run is
    already fail-closed; killing a live measurement here would only lose work.
    """
    try:
        leases.heartbeat(root, run_id, pgid=pgid, lease_id=lease_id)
    except leases.LeaseError as exc:
        print(f"lease-run: heartbeat for run {run_id} could not be recorded ({exc}) — the "
              "lease will expire into unknown-recovery-required", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
