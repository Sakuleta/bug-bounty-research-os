#!/usr/bin/env python3
"""Work leases: the file-based completion registry for long-running runs.

A lease is the process-liveness half of the completion predicate (goal-deferral
sprint D1/D3): it is acquired BEFORE a run's process tree is spawned, renewed while
the tree is live, and released only after `reconcile()` says the run is complete.
The registry lives under the run workspace root (`<root>/.leases/`) so both
continuation layers (OpenCode plugin, DSH adapter) can read the same truth.

On-disk format — `<root>/.leases/<run-id>.jsonl`, append-only, one JSON object per
line, fsynced under a cross-process lock:

    {"seq": 1, "version": 1, "time": 1758600000.0, "run_id": "s1-x",
     "lease_id": "L-1a2b3c4d", "event": "acquire", "state": "active",
     "owner": {"pid": 123, "label": "...", "session": "..."}, "command": "...",
     "pgid": 124, "heartbeat_at": 1758600000.0, "expires_at": 1758600360.0,
     "interval_seconds": 120.0, "exit_code": null, "commit": null, "reason": ""}

States: `active` (tree live, heartbeats expected) -> `awaiting-reconciliation`
(process exit recorded; the lease stays held until the predicate clears) ->
`released` (reconciled, commit recorded). `unknown-recovery-required` is the
fail-closed sink: an expired heartbeat, a corrupt line, a tampered version chain, or
an unreadable registry. It blocks and wakes a bounded reconciliation turn; it is
never deleted silently and never reported as success.

Fail-closed rules (readers):
  - a missing/unreadable registry is never "clear" — it is `unknown-recovery-required`;
  - a corrupt line is tolerated (never a crash) but the run's state is unverifiable
    from that file, so the verdict is `unknown-recovery-required` (a corrupt line
    must never read as a missed heartbeat or as a release);
  - the encoding contract is shared with the JS reader: bytes are decoded strictly
    as UTF-8 and lines are split on `\n` only; an undecodable line or a raw
    U+0085/U+2028/U+2029 (which the writer escapes) is corrupt;
  - a version chain that is not strictly increasing is unverifiable, same verdict;
  - expiry turns a missed heartbeat on an `active` lease into `unknown-recovery-required`
    (`awaiting-reconciliation` has no heartbeat expectation and stays as recorded).

Locking uses `fcntl.flock` on `<root>/.leases/.lock`: it auto-releases when the
holder dies, so a killed writer cannot brick the registry and there is no
stale-lock reclaim race (the ledger's atomic-mkdir lock stays for the ledger).
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import shlex
import shutil
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DEFAULT_HEARTBEAT_SECONDS = 120.0
# Expiry must be strictly greater than 2x the heartbeat interval, else every lease
# self-expires between two heartbeats; pinned by `tools/test_leases.py`.
EXPIRY_MULTIPLIER = 3.0

LEASE_STATES = ("active", "awaiting-reconciliation", "unknown-recovery-required", "released")
# Every state except `released` holds the lease: the lease is held until the commit.
BLOCKING_STATES = ("active", "awaiting-reconciliation", "unknown-recovery-required")

_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# Line separators a conforming writer escapes (`\u0085`/`\u2028`/`\u2029`). A raw
# occurrence on disk means the record was not written by the shared writer (or was
# tampered with): both readers split on `\n` only and count it corrupt.
_RAW_SEPARATORS = ("\u0085", "\u2028", "\u2029")


class LeaseError(ValueError):
    """Base error for lease operations that refuse (fail closed)."""


class LeaseHeld(LeaseError):
    """Acquire refused: a lease for the run is still held."""


@contextmanager
def _lock(root: Path, timeout: float = 10.0):
    """Cross-process registry lock (flock; auto-released when the holder dies)."""
    directory = registry_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
    fd = os.open(directory / ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"lease registry lock timeout: {directory / '.lock'}")
                time.sleep(0.02)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def _now(now: float | None) -> float:
    """Wall-clock epoch seconds. Injectable so expiry is testable without sleeping.

    Wall clock (not `time.monotonic`) because the timestamps must be comparable
    across processes; a laptop sleep can therefore expire a live lease — which
    reads as `unknown-recovery-required` (fail closed), never as success.
    """
    return time.time() if now is None else float(now)


def registry_dir(root: str | os.PathLike[str]) -> Path:
    return Path(root) / ".leases"


def _safe_run_id(run_id: str) -> str:
    if not isinstance(run_id, str) or not _RUN_ID_RE.match(run_id):
        raise LeaseError(
            f"unsafe run id {run_id!r}: expected [A-Za-z0-9][A-Za-z0-9._-]{{0,127}} "
            "(the run id becomes a registry file name)")
    return run_id


def lease_path(root: str | os.PathLike[str], run_id: str) -> Path:
    return registry_dir(root) / f"{_safe_run_id(run_id)}.jsonl"


def _read_records(path: Path) -> tuple[list[dict[str, Any]], int, bool]:
    """Tolerant JSONL read: (records, corrupt_line_count, unreadable).

    Encoding contract (shared with the JS reader in `dsh-plugin/goal-deferral`):
    the file is read as BYTES, each line is decoded strictly as UTF-8, and lines
    are split on `\\n` only. An undecodable line, or a line carrying a raw
    U+0085/U+2028/U+2029 (separators a conforming writer escapes), counts as
    corrupt: it is never dropped, silently repaired or split into fragments, so
    both readers agree. Blank/non-object lines are tolerated and counted.
    `unreadable` marks a file that exists but cannot be read at all.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return [], 0, True
    records: list[dict[str, Any]] = []
    corrupt = 0
    for raw in data.split(b"\n"):
        if not raw.strip():
            continue
        try:
            line = raw.decode("utf-8")
        except UnicodeDecodeError:
            corrupt += 1
            continue
        if any(separator in line for separator in _RAW_SEPARATORS):
            corrupt += 1
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            corrupt += 1
            continue
        if isinstance(record, dict):
            records.append(record)
        else:
            corrupt += 1
    return records, corrupt, False


def _fold(records: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, str]:
    """Fold append-only records into the latest state; verify the version chain."""
    latest: dict[str, Any] | None = None
    for record in records:
        version = record.get("version")
        if not isinstance(version, int) or version < 1:
            return None, f"record without a valid version (got {version!r})"
        if latest is not None and version <= latest["version"]:
            return None, (f"version chain is not strictly increasing "
                          f"({version} after {latest['version']})")
        if record.get("state") not in LEASE_STATES:
            return None, f"unknown lease state {record.get('state')!r}"
        latest = record
    if latest is None:
        return None, "no records"
    return latest, ""


def _expiry_seconds(interval_seconds: float) -> float:
    return float(interval_seconds) * EXPIRY_MULTIPLIER


def _append(root: Path, run_id: str, record: dict[str, Any], path: Path) -> dict[str, Any]:
    """Read-modify-write one record under the registry lock (fsynced O_APPEND).

    U+0085/U+2028/U+2029 are escaped as `\\uXXXX` after the dump: a raw occurrence
    would be a corrupt line for both readers (they split on `\\n` only), so the
    writer never emits one.
    """
    line = json.dumps(record, ensure_ascii=False, sort_keys=True)
    for separator in _RAW_SEPARATORS:
        line = line.replace(separator, f"\\u{ord(separator):04x}")
    line += "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    return record


def _commit_exists(root: Path, commit: str) -> tuple[bool, str]:
    """Is `commit` a commit in `root`'s git work tree? Fail closed on any doubt."""
    if not isinstance(commit, str) or not _SHA_RE.match(commit):
        return False, f"commit must be a 40-hex sha (got {commit!r})"
    try:
        proc = subprocess.run(["git", "-C", str(root), "cat-file", "-e", f"{commit}^{{commit}}"],
                              capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        return False, "git is unavailable — the commit cannot be verified (fail closed)"
    except subprocess.TimeoutExpired:
        return False, "git cat-file timed out — the commit cannot be verified"
    if proc.returncode != 0:
        return False, (f"commit {commit} does not exist in the git work tree at {root} "
                       f"(git cat-file -e: {proc.stderr.strip() or proc.returncode})")
    return True, f"commit {commit} exists"


def _latest_or_error(root: Path, run_id: str) -> tuple[dict[str, Any], str, int, Path]:
    path = lease_path(root, run_id)
    records, corrupt, unreadable = _read_records(path)
    if unreadable:
        raise LeaseError(f"lease registry file is unreadable: {path} (fail closed)")
    if corrupt:
        raise LeaseError(f"lease registry has {corrupt} corrupt line(s): {path} "
                         "(fail closed; repair or archive the file before mutating)")
    latest, error = _fold(records)
    if latest is None:
        raise LeaseError(f"lease registry state is unverifiable ({error}): {path}")
    return latest, error, corrupt, path


def _effective_state(latest: dict[str, Any], now: float) -> str:
    """The state after read-time expiry: an expired `active` lease is `unknown`.

    Writers use this so a late heartbeat/release cannot silently revive an expired
    lease; `verdict()` applies the same rule with a reader-facing reason string.
    """
    if latest.get("state") == "active":
        expires_at = latest.get("expires_at")
        if not isinstance(expires_at, (int, float)) or float(expires_at) <= now:
            return "unknown-recovery-required"
    return str(latest.get("state"))


def _write_transition(root: Path, run_id: str, **kwargs: Any) -> dict[str, Any]:
    """Take the registry lock and write one transition (see `_write_transition_locked`)."""
    with _lock(root):
        return _write_transition_locked(root, run_id, **kwargs)


def _write_transition_locked(root: Path, run_id: str, *, state: str, event: str,
                             now: float, reason: str = "", exit_code: int | None = None,
                             commit: str | None = None, pgid: int | None = None,
                             lease_id: str | None = None,
                             require: tuple[str, ...] | None = None,
                             require_reason_for: tuple[str, ...] = (),
                             require_owner: bool = False) -> dict[str, Any]:
    """One read-modify-write transition; the caller holds the registry lock.

    Every check reads the CURRENT record under that lock, so a state change landing
    just before the write is seen (fail closed) and nothing can interleave between
    a caller's own read and this write.
    """
    latest, _error, _corrupt, path = _latest_or_error(root, run_id)
    if lease_id is None:
        raise LeaseError(
            f"refusing {event} for run {run_id}: the lease generation is required — pass the "
            "lease_id from acquire()/verdict(); unbound writers are refused (fail closed)")
    if lease_id != latest.get("lease_id"):
        raise LeaseError(
            f"refusing {event} for run {run_id}: lease generation mismatch (caller holds "
            f"{lease_id!r}, the current record is {latest.get('lease_id')!r}) — a stale writer "
            "must not mutate the current lease (fail closed)")
    if require_owner:
        owner = latest.get("owner") or {}
        owner_pid = owner.get("pid")
        if not isinstance(owner_pid, int) or isinstance(owner_pid, bool) \
                or owner_pid != os.getpid():
            raise LeaseError(
                f"refusing {event} for run {run_id}: caller pid {os.getpid()} is not the "
                f"recorded owner (pid {owner_pid!r}) — only the owner process may record this "
                "transition (fail closed)")
    effective = _effective_state(latest, now)
    if require is not None and effective not in require:
        detail = ""
        if effective != latest["state"]:
            detail = (f" (expired at {latest.get('expires_at')} — now reads "
                      "unknown-recovery-required)")
        raise LeaseError(
            f"refusing {event} for run {run_id}: lease state is {latest['state']!r}{detail}, "
            f"expected one of {list(require)}")
    if effective in require_reason_for and not reason.strip():
        raise LeaseError(
            f"refusing {event} for run {run_id}: state {effective!r} is the explicit "
            "recovery path and requires a reason")
    interval = float(latest.get("interval_seconds") or DEFAULT_HEARTBEAT_SECONDS)
    record = {
        "seq": int(latest["seq"]) + 1,
        "version": int(latest["version"]) + 1,
        "time": now,
        "run_id": run_id,
        "lease_id": latest["lease_id"],
        "event": event,
        "state": state,
        "owner": latest.get("owner") or {},
        "command": latest.get("command") or "",
        "pgid": latest.get("pgid") if pgid is None else int(pgid),
        "heartbeat_at": latest.get("heartbeat_at"),
        "expires_at": latest.get("expires_at"),
        "interval_seconds": interval,
        "exit_code": latest.get("exit_code") if exit_code is None else int(exit_code),
        "commit": latest.get("commit") if commit is None else commit,
        "reason": reason,
    }
    if state == "active":
        record["heartbeat_at"] = now
        record["expires_at"] = now + _expiry_seconds(interval)
    if state == "released":
        commit_ok, commit_reason = _commit_exists(root, record["commit"])
        if not commit_ok:
            raise LeaseError(
                f"refusing {event} for run {run_id}: {commit_reason} — a release must cite a "
                "commit that exists (fail closed)")
    return _append(root, run_id, record, path)


def acquire(root: str | os.PathLike[str], run_id: str, *, owner_label: str = "",
            session: str = "", command: str = "", pid: int | None = None,
            pgid: int | None = None, interval_seconds: float = DEFAULT_HEARTBEAT_SECONDS,
            now: float | None = None) -> dict[str, Any]:
    """Acquire the run's lease (call BEFORE spawning the process tree).

    Refuses while a previous lease is still held or reads as
    `unknown-recovery-required` (expiry included): recovery is explicit, never an
    implicit takeover — release the old generation with a reason (or reconcile it)
    first.
    """
    root = Path(root)
    timestamp = _now(now)
    if float(interval_seconds) <= 0:
        raise LeaseError(f"interval_seconds must be positive (got {interval_seconds!r})")
    with _lock(root):
        path = lease_path(root, run_id)
        if path.exists():
            latest, error, _corrupt, _path = _latest_or_error(root, run_id)
            effective = _effective_state(latest, timestamp)
            if effective in BLOCKING_STATES:
                detail = ""
                if effective != latest["state"]:
                    detail = (f" (expired at {latest.get('expires_at')} — it reads "
                              "unknown-recovery-required)")
                raise LeaseHeld(
                    f"run {run_id} still holds a {effective} lease "
                    f"(version {latest['version']}){detail}; recovery is explicit — reconcile or "
                    f"release the old generation first (fail closed)")
        else:
            latest = None
        lease_id = f"L-{os.urandom(4).hex()}"
        record = {
            "seq": (int(latest["seq"]) + 1) if latest else 1,
            "version": (int(latest["version"]) + 1) if latest else 1,
            "time": timestamp,
            "run_id": _safe_run_id(run_id),
            "lease_id": lease_id,
            "event": "acquire",
            "state": "active",
            "owner": {"pid": os.getpid() if pid is None else int(pid),
                      "label": owner_label, "session": session},
            "command": command,
            "pgid": None if pgid is None else int(pgid),
            "heartbeat_at": timestamp,
            "expires_at": timestamp + _expiry_seconds(interval_seconds),
            "interval_seconds": float(interval_seconds),
            "exit_code": None,
            "commit": None,
            "reason": "",
        }
        return _append(root, run_id, record, path)


def heartbeat(root: str | os.PathLike[str], run_id: str, *, lease_id: str,
              pgid: int | None = None, now: float | None = None) -> dict[str, Any]:
    """Renew an `active` lease; refuses on any other state or once it has expired.

    A late heartbeat must not silently revive an expired lease: expiry is a
    recorded fact (`unknown-recovery-required`) and recovery is explicit. The
    caller must name the lease generation (`lease_id`) and be the recorded owner
    process, so a stale or foreign wrapper cannot heartbeat the current generation.
    """
    return _write_transition(Path(root), run_id, state="active", event="heartbeat",
                             now=_now(now), pgid=pgid, lease_id=lease_id, require=("active",),
                             require_owner=True)


def mark_awaiting(root: str | os.PathLike[str], run_id: str, *, exit_code: int,
                  lease_id: str, reason: str = "process exited",
                  now: float | None = None) -> dict[str, Any]:
    """Record process exit; the lease stays held until reconciliation.

    Owner-bound like `heartbeat`: only the process that acquired the lease (the
    launch wrapper) may record its tree's exit.
    """
    return _write_transition(Path(root), run_id, state="awaiting-reconciliation",
                             event="awaiting-reconciliation", now=_now(now),
                             exit_code=exit_code, reason=reason, lease_id=lease_id,
                             require=("active", "awaiting-reconciliation"), require_owner=True)


def mark_unknown(root: str | os.PathLike[str], run_id: str, *, reason: str, lease_id: str,
                 now: float | None = None) -> dict[str, Any]:
    """Record an unrecoverable-in-place failure; requires reconciliation."""
    return _write_transition(Path(root), run_id, state="unknown-recovery-required",
                             event="unknown", now=_now(now), reason=reason, lease_id=lease_id,
                             require=("active", "awaiting-reconciliation",
                                      "unknown-recovery-required"))


def release(root: str | os.PathLike[str], run_id: str, *, commit: str, lease_id: str,
            reason: str = "", now: float | None = None) -> dict[str, Any]:
    """Release the lease after the completion predicate cleared, recording the commit.

    Releasing an `unknown-recovery-required` lease is the explicit manual recovery
    path (the automated reconcile path never releases it) and requires a reason.
    """
    if not isinstance(commit, str) or not _SHA_RE.match(commit):
        raise LeaseError(f"release requires a 40-hex results commit (got {commit!r})")
    return _write_transition(Path(root), run_id, state="released", event="release",
                             now=_now(now), commit=commit, reason=reason, lease_id=lease_id,
                             require=("awaiting-reconciliation",
                                      "unknown-recovery-required"),
                             require_reason_for=("unknown-recovery-required",))


def _verdict_from_records(root: Path, run_id: str, records: list[dict[str, Any]], corrupt: int,
                          unreadable: bool, path: Path, now: float) -> dict[str, Any]:
    def out(state: str, blocked: bool, reason: str, **extra: Any) -> dict[str, Any]:
        return {"run_id": run_id, "state": state, "blocked": blocked, "reason": reason,
                "lease_path": str(path), "corrupt_lines": corrupt,
                "record_count": len(records), **extra}

    if unreadable:
        return out("unknown-recovery-required", True,
                   f"lease registry file is unreadable: {path} (fail closed)")
    if corrupt:
        return out("unknown-recovery-required", True,
                   f"lease registry has {corrupt} corrupt line(s): {path} — state cannot be "
                   "established (fail closed; a corrupt line is never a missed heartbeat "
                   "and never a release)")
    latest, error = _fold(records)
    if latest is None:
        return out("unknown-recovery-required", True,
                   f"lease registry state is unverifiable ({error}): {path} (fail closed)")
    common = {
        "version": int(latest["version"]),
        "lease_id": latest.get("lease_id"),
        "owner": latest.get("owner") or {},
        "command": latest.get("command") or "",
        "pgid": latest.get("pgid"),
        "heartbeat_at": latest.get("heartbeat_at"),
        "expires_at": latest.get("expires_at"),
        "interval_seconds": latest.get("interval_seconds"),
        "exit_code": latest.get("exit_code"),
        "commit": latest.get("commit"),
    }
    state = latest["state"]
    if state == "released":
        commit_ok, commit_reason = _commit_exists(root, latest.get("commit"))
        if not commit_ok:
            return out("unknown-recovery-required", True,
                       f"released record cannot be verified: {commit_reason} (fail closed; a "
                       "forged release is never a release — full commit-to-run binding is "
                       "follow-up work)", **common)
        return out("released", False,
                   f"released after reconciliation (commit {latest.get('commit')})", **common)
    if state == "awaiting-reconciliation":
        return out("awaiting-reconciliation", True,
                   f"process exited (exit_code={latest.get('exit_code')}) and the lease is held "
                   "until the completion predicate clears", **common)
    if state == "active":
        expires_at = latest.get("expires_at")
        if not isinstance(expires_at, (int, float)):
            return out("unknown-recovery-required", True,
                       "active lease without a readable expiry — liveness cannot be verified "
                       "(fail closed)", **common)
        if float(expires_at) <= now:
            return out("unknown-recovery-required", True,
                       f"heartbeat expired at {expires_at} (missed heartbeats) — recovery "
                       "required; stale is never success", **common)
        owner = latest.get("owner") or {}
        return out("active", True,
                   f"lease held by pid {owner.get('pid')} (heartbeat {latest.get('heartbeat_at')}, "
                   f"expires {expires_at})", **common)
    return out("unknown-recovery-required", True,
               f"lease state {state!r} requires recovery", **common)


def verdict(root: str | os.PathLike[str], run_id: str, *, now: float | None = None) -> dict[str, Any]:
    """The current verdict for one run; fail closed on any unverifiable input."""
    root = Path(root)
    timestamp = _now(now)
    path = lease_path(root, run_id)
    directory = registry_dir(root)
    if not directory.is_dir():
        return {"run_id": run_id, "state": "unknown-recovery-required", "blocked": True,
                "reason": f"lease registry missing: {directory} (missing is never clear)",
                "lease_path": str(path), "corrupt_lines": 0, "record_count": 0}
    try:
        os.listdir(directory)
    except OSError as exc:
        return {"run_id": run_id, "state": "unknown-recovery-required", "blocked": True,
                "reason": f"lease registry unreadable: {directory} ({exc}) — missing or "
                          "unreadable is never clear",
                "lease_path": str(path), "corrupt_lines": 0, "record_count": 0}
    if not path.exists():
        return {"run_id": run_id, "state": "no-lease", "blocked": False,
                "reason": "no lease recorded for this run (registry readable)",
                "lease_path": str(path), "corrupt_lines": 0, "record_count": 0}
    records, corrupt, unreadable = _read_records(path)
    return _verdict_from_records(root, run_id, records, corrupt, unreadable, path, timestamp)


def verdict_all(root: str | os.PathLike[str], *, now: float | None = None) -> dict[str, Any]:
    """Workspace-wide verdict: blocked while ANY recorded lease is held.

    The DSH adapter's machine-level veto uses this (it has no single run id). A
    corrupt/unreadable file, or a missing registry, blocks the workspace.
    """
    root = Path(root)
    directory = registry_dir(root)
    if not directory.is_dir():
        return {"state": "unknown-recovery-required", "blocked": True,
                "reason": f"lease registry missing: {directory} (missing is never clear)",
                "runs": [], "corrupt_lines": 0}
    try:
        # `os.listdir` establishes that enumeration succeeded: `Path.glob` suppresses
        # the permission error and would report an unreadable registry as empty (clear).
        entries = sorted(directory / name for name in os.listdir(directory)
                         if name.endswith(".jsonl"))
    except OSError as exc:
        return {"state": "unknown-recovery-required", "blocked": True,
                "reason": f"lease registry unreadable: {directory} ({exc}) — missing or "
                          "unreadable is never clear", "runs": [], "corrupt_lines": 0}
    runs: list[dict[str, Any]] = []
    corrupt_total = 0
    for path in entries:
        run_id = path.stem
        records, corrupt, unreadable = _read_records(path)
        corrupt_total += corrupt
        runs.append(_verdict_from_records(root, run_id, records, corrupt, unreadable, path,
                                          _now(now)))
    blocked = [r for r in runs if r["blocked"]]
    if not blocked:
        return {"state": "clear", "blocked": False,
                "reason": f"{len(runs)} lease file(s), none held", "runs": runs,
                "corrupt_lines": corrupt_total}
    # The worst state wins: unknown > awaiting-reconciliation > active.
    order = {"unknown-recovery-required": 3, "awaiting-reconciliation": 2, "active": 1}
    worst = max(blocked, key=lambda r: order.get(r["state"], 4))
    return {"state": worst["state"], "blocked": True,
            "reason": f"run {worst['run_id']}: {worst['reason']}", "runs": runs,
            "corrupt_lines": corrupt_total}


# ---------- completion predicate (D3) ----------

def _pgid_alive(pgid: int) -> bool:
    """Is any process in this group alive? Unknown/permission answers count as alive."""
    try:
        os.killpg(int(pgid), 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


_ERE_SPECIALS = frozenset(".^$*+?()[]{}|\\")


def _command_pattern(command: str) -> str | None:
    """A `pgrep -f` ERE that matches the recorded command line literally, or None.

    The registry records `shlex.join(argv)` (shell-quoted for humans) while the
    process table exposes the raw argv; the executable is dropped from the pattern
    (macOS resolves the exec path, so argv[0] as passed is not what the table shows)
    and the remaining arguments are joined and ERE-escaped for a literal substring
    match. Fragments shorter than 8 characters are not distinctive enough to sweep
    on — such commands rely on the process-group half. An unparseable command or an
    argument-less command yields None.
    """
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    args = tokens[1:]
    joined = " ".join(args)
    if len(joined) < 8:
        return None
    return "".join(("\\" + ch) if ch in _ERE_SPECIALS else ch for ch in joined)


def _run_pgrep(pgrep: str, args: list[str]) -> tuple[int | None, str]:
    """(exit code, stdout); None marks a pgrep that could not be executed at all."""
    try:
        proc = subprocess.run([pgrep, *args], capture_output=True, text=True, timeout=10)
    except OSError:
        return None, ""
    except subprocess.TimeoutExpired:
        return 2, ""
    return proc.returncode, proc.stdout.strip()


_PGREP_UNAVAILABLE = "pgrep is unavailable — stray descendants cannot be ruled out (fail closed)"


def _tree_sweep_alive(pgid: int, command: str, *,
                      pgrep: str | None = None) -> tuple[bool, str]:
    """Process-table sweep for live members of the recorded tree: (alive, reason).

    The recorded process group is checked with `pgrep -g` (a second opinion on
    `killpg`, and the half that survives a dead group leader), and the recorded
    command with `pgrep -f` — a descendant that left the group but kept the argv
    (the common setsid/double-fork detach shape) is still matched. pgrep absent,
    failing (exit != 0/1) or otherwise unverifiable counts as ALIVE (fail closed).

    Proof bound (documented residual): a descendant that both leaves the recorded
    group and re-execs a different argv can still evade this sweep — there is no
    cgroup/job-object containment available on this platform, and the sweep sees
    only what the process table exposes.
    """
    if pgrep is None:
        pgrep = shutil.which("pgrep")
    if pgrep is None:
        return True, _PGREP_UNAVAILABLE
    code, output = _run_pgrep(pgrep, ["-g", str(pgid), "."])
    if code is None:
        return True, _PGREP_UNAVAILABLE
    if code == 0:
        return True, f"pgrep -g {pgid} still matches live process(es): {output}"
    if code != 1:
        return True, (f"pgrep -g {pgid} failed (exit {code}) — child liveness is unverifiable "
                      "(fail closed)")
    pattern = _command_pattern(command)
    if pattern is not None:
        code, output = _run_pgrep(pgrep, ["-f", "--", pattern])
        if code is None:
            return True, _PGREP_UNAVAILABLE
        if code == 0:
            return True, (f"pgrep -f matches live process(es) still carrying the recorded command: "
                          f"{output} (a stray escaped the recorded process group)")
        if code != 1:
            return True, (f"pgrep -f failed (exit {code}) — stray liveness is unverifiable "
                          "(fail closed)")
    return False, "no live group members and no matching strays"


def _manifest_conjunct(root: Path, run_id: str) -> tuple[bool, str]:
    """Every planned cell has a manifest (layout: runs/<cell>/manifest.json)."""
    plan_path = root / "runs" / run_id / "plan.json"
    try:
        plan = json.loads(plan_path.read_text())
    except OSError:
        return False, f"plan is missing or unreadable: {plan_path}"
    except json.JSONDecodeError as exc:
        return False, f"plan is not valid JSON: {plan_path} ({exc})"
    cells = plan.get("cells") if isinstance(plan, dict) else None
    if not isinstance(cells, list) or not cells or not all(isinstance(c, str) for c in cells):
        return False, (f"plan must carry a non-empty string list at `cells` "
                       f"(got {cells!r}) — nothing verifiable to reconcile")
    missing = []
    for cell in cells:
        manifest = root / "runs" / cell / "manifest.json"
        if not manifest.is_file():
            missing.append(cell)
            continue
        try:
            data = json.loads(manifest.read_text())
        except (OSError, json.JSONDecodeError):
            missing.append(f"{cell} (unreadable manifest)")
            continue
        if not isinstance(data, dict):
            missing.append(f"{cell} (manifest is not an object)")
    if missing:
        return False, "planned cells without a manifest: " + ", ".join(sorted(missing))
    return True, f"{len(cells)} planned cell(s), all with a manifest"


def _reports_conjunct(root: Path, run_id: str) -> tuple[bool, str]:
    """Reports regenerated: reports/ is non-empty and no older than the newest manifest."""
    reports_dir = root / "reports"
    if not reports_dir.is_dir():
        return False, f"reports directory is missing: {reports_dir}"
    report_files = [p for p in reports_dir.rglob("*") if p.is_file()]
    if not report_files:
        return False, f"reports directory is empty: {reports_dir}"
    newest_report = max(p.stat().st_mtime for p in report_files)
    manifest_files = [p for p in (root / "runs").rglob("manifest.json") if p.is_file()]
    newest_manifest = max((p.stat().st_mtime for p in manifest_files), default=None)
    if newest_manifest is not None and newest_report < newest_manifest:
        return False, ("reports predate the newest manifest — regenerate reports before "
                       "reconciling")
    return True, f"{len(report_files)} report file(s), newest {newest_report:.0f}"


def _commit_conjunct(root: Path, run_id: str) -> tuple[bool, str, str | None]:
    """The results commit exists in the root's git work tree."""
    commit_file = root / "runs" / run_id / "results-commit"
    try:
        commit = commit_file.read_text().strip().split()[0] if commit_file.is_file() else ""
    except OSError:
        return False, f"results-commit is unreadable: {commit_file}", None
    if not _SHA_RE.match(commit):
        return False, (f"results-commit must hold a 40-hex commit sha "
                       f"(got {commit!r} in {commit_file})"), None
    ok, detail = _commit_exists(root, commit)
    if not ok:
        return False, f"results {detail}", None
    return True, f"results commit {commit} exists", commit


def completion_predicate(root: str | os.PathLike[str], run_id: str, *,
                         now: float | None = None) -> dict[str, Any]:
    """The five-conjunct completion predicate (root-relative documented layout).

    clear == loop exited AND zero matching children alive AND every planned cell has
    a manifest AND reports regenerated AND the results commit exists. "Children" is
    the recorded process group PLUS a process-table sweep (`pgrep -g`/`-f`) for
    strays that escaped it (setsid/double-fork); the sweep fails closed when pgrep
    is absent or unverifiable, and its proof bound is documented on
    `_tree_sweep_alive`. Any missing or unverifiable conjunct blocks; a
    stale/expired lease yields `unknown-recovery-required`, never success.
    """
    root = Path(root)
    return _predicate_from_verdict(root, run_id, verdict(root, run_id, now=now))


def _predicate_from_verdict(root: Path, run_id: str, current: dict[str, Any]) -> dict[str, Any]:
    """Evaluate the conjuncts for an already-read verdict (see `completion_predicate`)."""
    conjuncts: dict[str, dict[str, Any]] = {}

    if current["state"] == "released":
        return {"run_id": run_id, "clear": True, "already_released": True,
                "released": False, "state": current["state"], "commit": current.get("commit"),
                "verdict": current, "conjuncts": conjuncts}

    loop_exited = current["state"] == "awaiting-reconciliation"
    conjuncts["loop-exited"] = {
        "ok": loop_exited,
        "reason": (f"process exit recorded (exit_code={current.get('exit_code')})" if loop_exited
                   else f"lease state is {current['state']!r} — loop exit is not established "
                        f"({current['reason']})"),
    }
    pgid = current.get("pgid")
    if isinstance(pgid, int) and not isinstance(pgid, bool):
        if _pgid_alive(pgid):
            children_dead = False
            children_reason = f"process group {pgid} still has live members"
        else:
            stray_alive, stray_reason = _tree_sweep_alive(pgid, current.get("command") or "")
            children_dead = not stray_alive
            children_reason = (
                f"process group {pgid} has no live members but the process-table sweep still "
                f"sees the run's tree: {stray_reason}" if stray_alive
                else f"process group {pgid} has no live members and no process-table stray "
                     "matches the recorded tree")
        conjuncts["children-dead"] = {"ok": children_dead, "reason": children_reason}
    else:
        conjuncts["children-dead"] = {
            "ok": False,
            "reason": "lease carries no process-group id — child liveness cannot be verified "
                      "(fail closed)",
        }

    for name, (ok, reason) in (("manifests", _manifest_conjunct(root, run_id)),
                               ("reports", _reports_conjunct(root, run_id))):
        conjuncts[name] = {"ok": ok, "reason": reason}
    commit_ok, commit_reason, commit = _commit_conjunct(root, run_id)
    conjuncts["results-commit"] = {"ok": commit_ok, "reason": commit_reason}

    failed = [name for name, value in conjuncts.items() if not value["ok"]]
    return {"run_id": run_id, "clear": not failed, "already_released": False, "released": False,
            "state": current["state"], "commit": commit if commit_ok else None,
            "verdict": current, "conjuncts": conjuncts,
            "failed": failed}


def reconcile(root: str | os.PathLike[str], run_id: str, *, now: float | None = None) -> dict[str, Any]:
    """One bounded reconciliation attempt; releases the lease only when clear.

    The predicate and the release run under ONE registry-lock pass with a fresh
    state check, so a transition landing in between (e.g. the wrapper's SIGTERM
    `mark_unknown`) can never be auto-released: the automated path releases only
    from `awaiting-reconciliation` — never from `unknown-recovery-required`, which
    is the explicit manual-recovery lane. Stale/expired/unknown input leaves the
    state untouched (never a success report) and reports `recovery_required`.
    Exactly one attempt per invocation — the bound is the caller's, and this
    function never loops.
    """
    root = Path(root)
    timestamp = _now(now)
    if not registry_dir(root).is_dir():
        # No registry to lock (and no state to release): report the missing input.
        result = completion_predicate(root, run_id, now=timestamp)
        result["recovery_required"] = result["verdict"]["state"] == "unknown-recovery-required"
        result["attempts"] = 1
        return result
    with _lock(root):
        current = verdict(root, run_id, now=timestamp)
        result = _predicate_from_verdict(root, run_id, current)
        if result["clear"] and not result["already_released"]:
            try:
                record = _write_transition_locked(
                    root, run_id, state="released", event="release", now=timestamp,
                    commit=result["commit"], reason="completion predicate clear",
                    lease_id=current.get("lease_id"), require=("awaiting-reconciliation",))
                result["released"] = True
                result["release"] = record
            except LeaseError:
                # The state changed under the lock (e.g. a wrapper SIGTERM mark_unknown):
                # re-read and report the blocked result — the automated path must never
                # fall back to the reason-required manual-release lane.
                current = verdict(root, run_id, now=timestamp)
                result = _predicate_from_verdict(root, run_id, current)
        result["recovery_required"] = result["verdict"]["state"] == "unknown-recovery-required"
        result["attempts"] = 1
        return result
