#!/usr/bin/env python3
"""Policy broker for the Research OS: policy snapshot, signing key, single-use token
ledger and decision audit live OUTSIDE the agent-writable workspace.

The broker owns what workspace-local files cannot be trusted with: the scope snapshot
(`policies/<wsid>.json`), the HMAC signing key (`key`, 0600, consulted in place by
same-UID OS processes and never copied elsewhere),
the mint/consume ledger (`tokens.jsonl`) and every decision (`audit.log`). An agent
that edits `00_control/engagement.yaml` or `11_runtime/action-tokens.jsonl` cannot
widen the broker policy, forge a signature or replay a consumed nonce.

Protocol: newline-delimited JSON over `<home>/broker.sock`, one request/response per
line (1 MiB bound). Ops: `hello`, `policy.put`, `policy.get`, `token.mint`,
`token.consume`, `status`. Refusals are `{"ok": false, "error": …}` — a malformed frame
or an unknown op never crashes the daemon. Scope matching reuses the canonical
`asset_hosts` / `host_in_scope` helpers from tools/control_plane.py.

Run: python3 tools/broker/broker.py --serve [--home DIR]
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import socket
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))          # tools/broker (client.py)
sys.path.insert(0, str(_HERE.parent))   # tools (control_plane.py)
from client import VOUCHER_SIGNED_FIELDS, broker_home, workspace_key  # noqa: E402
from control_plane import (  # noqa: E402
    _json_dump, asset_hosts, canonical_request_shape, host_in_scope,
)

VERSION = "research-os-broker/0.1"
CAPABILITIES = ["policy.get", "policy.put", "review.consume", "review.issue",
                "scope.check", "status", "token.consume", "token.mint"]
SOCKET_NAME = "broker.sock"
KEY_NAME = "key"
TOKENS_NAME = "tokens.jsonl"
AUDIT_NAME = "audit.log"
POLICIES_DIR = "policies"
MAX_LINE = 1024 * 1024
READ_TIMEOUT_SECONDS = 5
MAX_CONNECTIONS = 32
DEFAULT_TTL_SECONDS = 300
MIN_TTL_SECONDS = 1
MAX_TTL_SECONDS = 3600
BUDGET_KEYS = ("max_actions_per_cycle", "max_actions_per_engagement")
# The fields covered by the token signature, in signing order. Mint and consume MUST
# agree byte-for-byte, so both derive the signed payload from this one tuple.
_SIGNED_FIELDS = ("workspace", "action_id", "nonce", "digest", "tool_family", "expires_at")
_ASSET_REFUSED = re.compile(r"[\s\"'\\#\x00-\x1f\x7f]")


class Refused(Exception):
    """A deliberate refusal the client sees as {"ok": false, "error": …}."""


# Ops that change broker state (policy file, token ledger). handle() journals an
# INTENT record for these before running them; read-only ops (hello, status,
# policy.get, scope.check) only get the outcome line.
STATE_CHANGING_OPS = frozenset({"policy.put", "token.mint", "token.consume",
                                 "review.issue", "review.consume"})


# A scope revision binds one broker policy to one local SCOPE_CHANGED event:
# `EV-<zero-padded ledger sequence>:<64-hex event hash>`. The hash is the identity
# (tamper-evident, equal revisions name the same event); the sequence orders
# concurrent pushes (hashes alone are unordered, and receipt order is not recency).
_SCOPE_REVISION = re.compile(r"^EV-(\d{6}):([0-9a-f]{64})$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _expiry_iso(ttl_seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _host_of(url: str) -> str:
    """Host[:port] of a URL via the canonical asset normalizer (same as the enforcer)."""
    hosts = asset_hosts([str(url or "")])
    return hosts[0] if hosts else ""


def _scope_host_of(url: str) -> str:
    """Host[:port] for a scope decision, mirroring `control_plane.scope_check`.

    The canonical seam only reads a host out of an absolute URL (it requires `://`);
    a scheme-less string is host-less and therefore default-deny. Matching that exactly
    keeps the broker decision byte-identical to the local one for every URL.
    """
    return _host_of(url) if "://" in str(url or "") else ""


def _parse_budget_caps(raw: Any) -> dict[str, int | None]:
    """Validate a policy budget payload: int|None per cap; malformed refuses (fail closed).

    `None`/absent caps mean uncapped (the broker enforces only what the policy records),
    but a cap that is present and not a non-negative integer refuses instead of being
    read as uncapped — a hand-edited policy must never raise the effective limit.
    """
    if raw is None:
        return {key: None for key in BUDGET_KEYS}
    if not isinstance(raw, dict):
        raise Refused(
            "broker policy budget is malformed (not an object) — repair the policy with "
            "`researchctl scope-set`; refusing to mint")
    caps: dict[str, int | None] = {}
    for key in BUDGET_KEYS:
        value = raw.get(key)
        if value is None:
            caps[key] = None
        elif isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise Refused(
                f"broker policy budget {key}={value!r} is malformed — the cap must be a "
                "non-negative integer or null; repair the policy with `researchctl scope-set`; "
                "refusing to mint")
        else:
            caps[key] = value
    return caps


def _encode(obj: Any) -> bytes:
    return (_json_dump(obj) + "\n").encode("utf-8")


class Broker:
    """State + one-request decision logic; the socket loop lives in `serve()`."""

    def __init__(self, home: Path):
        self.home = Path(home).expanduser()
        self.home.mkdir(parents=True, exist_ok=True)
        os.chmod(self.home, 0o700)
        self.policies_dir = self.home / POLICIES_DIR
        self.policies_dir.mkdir(exist_ok=True)
        self.tokens_file = self.home / TOKENS_NAME
        self.audit_file = self.home / AUDIT_NAME
        self.socket_path = self.home / SOCKET_NAME
        self._lock = threading.Lock()
        self._conn_lock = threading.Lock()
        self.active_connections = 0
        self.key()  # the signing key is a broker-home invariant, not a lazy mint artifact

    # ---------- key + files ----------
    def key(self) -> bytes:
        """The 32-byte HMAC key: created once, 0600, consulted in place by same-UID
        OS processes (control plane keying, audit verification) and never copied elsewhere."""
        path = self.home / KEY_NAME
        if not path.exists():
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                return path.read_bytes()
            try:
                os.write(fd, os.urandom(32))
            finally:
                os.close(fd)
        return path.read_bytes()

    def _sign(self, fields: dict[str, Any]) -> str:
        return hmac.new(self.key(), _json_dump(fields).encode("utf-8"), hashlib.sha256).hexdigest()

    def _audit(self, line: str) -> None:
        """Append one decision line, fsynced. OSError propagates: `handle()` refuses a decision it
        cannot log, while frame-level events use `_audit_best_effort` (the frame is
        already refused, so a missing log line cannot let anything through)."""
        fd = os.open(self.audit_file, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, f"{_now_iso()} {line}\n".encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

    def _audit_best_effort(self, line: str) -> None:
        try:
            self._audit(line)
        except OSError:
            pass

    def _append_jsonl(self, path: Path, record: dict[str, Any]) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, (_json_dump(record) + "\n").encode("utf-8"))
        finally:
            os.close(fd)

    def _ledger_lines(self) -> tuple[list[dict[str, Any]], int]:
        """Every ledger record plus the count of unreadable lines (corruption counter)."""
        # ponytail: linear scan per mint/consume; index by nonce if a ledger ever grows
        # large enough for the scan to matter (token volume is budget-capped today).
        if not self.tokens_file.exists():
            return [], 0
        records: list[dict[str, Any]] = []
        decode_errors = 0
        for line in self.tokens_file.read_text(errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                decode_errors += 1
                continue
            if isinstance(record, dict):
                records.append(record)
            else:
                decode_errors += 1
        return records, decode_errors

    def _records(self, kind: str) -> list[dict[str, Any]]:
        records, _ = self._ledger_lines()
        return [record for record in records if record.get("kind") == kind]

    def _policy_file(self, workspace: str) -> Path:
        return self.policies_dir / f"{hashlib.sha256(workspace.encode('utf-8')).hexdigest()}.json"

    def _read_policy(self, workspace: str) -> dict[str, Any] | None:
        path = self._policy_file(workspace)
        if not path.exists():
            return None
        try:
            policy = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        return policy if isinstance(policy, dict) else None

    def _write_policy(self, workspace: str, policy: dict[str, Any]) -> None:
        fd = os.open(self._policy_file(workspace), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, _json_dump(policy).encode("utf-8"))
        finally:
            os.close(fd)

    # ---------- ops ----------
    def _workspace(self, req: dict[str, Any]) -> str:
        workspace = str(req.get("workspace") or "").strip()
        if not workspace:
            raise Refused("request requires workspace (the absolute engagement root)")
        return workspace_key(workspace)

    def op_hello(self, req: dict[str, Any]) -> tuple[dict[str, Any], str]:
        return {"ok": True, "version": VERSION, "capabilities": list(CAPABILITIES)}, ""

    def op_status(self, req: dict[str, Any]) -> tuple[dict[str, Any], str]:
        workspace = self._workspace(req)
        policy = self._read_policy(workspace)
        _, decode_errors = self._ledger_lines()
        return {
            "ok": True, "version": VERSION, "workspace": workspace,
            "policy_present": policy is not None, "policy": policy,
            "key_present": (self.home / KEY_NAME).exists(),
            "socket": str(self.socket_path),
            "ledger_decode_errors": decode_errors,
        }, (f"workspace={workspace} policy_present={policy is not None} "
            f"ledger_decode_errors={decode_errors}")

    def op_policy_put(self, req: dict[str, Any]) -> tuple[dict[str, Any], str]:
        workspace = self._workspace(req)
        gate = str(req.get("gate") or "assets").lower()
        if gate not in {"assets", "none"}:
            raise Refused("policy.put gate must be 'assets' or 'none'")
        assets = req.get("assets")
        if not isinstance(assets, list):
            raise Refused("policy.put assets must be a list of strings")
        items: list[str] = []
        for item in assets:
            if not isinstance(item, str):
                raise Refused(f"policy.put asset {item!r} is not a string")
            if not item or _ASSET_REFUSED.search(item):
                raise Refused(
                    f"policy.put asset {item!r} is not a plain host/URL string — empty items and "
                    "whitespace, quotes, backslash, '#' and control characters are refused")
            items.append(item)
        if gate == "assets" and not items:
            raise Refused("policy.put in assets mode requires a non-empty assets list")
        reference = str(req.get("source_reference") or "").strip()
        if not reference:
            raise Refused(
                "policy.put requires a non-empty source_reference (policy URL/section; never a secret)")
        human = str(req.get("human_reference") or "").strip()
        budget = _parse_budget_caps(req.get("budget"))
        revision = str(req.get("scope_revision") or "").strip()
        with self._lock:
            present = self._policy_file(workspace).exists()
            existing = self._read_policy(workspace)
            if not human and (present or (existing or {}).get("assets")):
                raise Refused(
                    "policy.put requires human_reference (a ticket/message id from the human who "
                    "authorized the change) — this re-records an existing broker policy; only the "
                    "first record may omit it")
            revision_match = _SCOPE_REVISION.fullmatch(revision)
            if not revision_match:
                raise Refused(
                    "policy.put requires scope_revision as EV-<sequence>:<event-hash> (the "
                    "SCOPE_CHANGED event identity from `researchctl scope-set`) — pushes without "
                    "a revision cannot be ordered and are refused")
            revision_seq = int(revision_match.group(1))
            stored = (existing or {}).get("scope_revision")
            stored_match = _SCOPE_REVISION.fullmatch(str(stored or ""))
            stored_seq = int(stored_match.group(1)) if stored_match else 0
            if stored and revision_seq < stored_seq:
                raise Refused(
                    f"policy.put scope_revision {revision} is older than the stored revision "
                    f"{stored} — refusing the stale push; re-read the current scope and push again")
            if stored and revision_seq == stored_seq and revision != stored:
                raise Refused(
                    f"policy.put scope_revision {revision} reuses the stored sequence with a "
                    f"different event hash ({stored}) — refusing the conflicting push")
            if revision == stored:
                # Idempotent retry (e.g. scope-sync re-pushing the current binding):
                # the stored content must be identical, and nothing is rewritten.
                if (items != list(existing.get("assets") or []) or gate != existing.get("gate")
                        or budget != existing.get("budget")):
                    raise Refused(
                        f"policy.put reuses scope_revision {revision} with different content — "
                        "refusing: one revision names exactly one scope record")
                return {"ok": True, "workspace": workspace, "policy": existing}, (
                    f"workspace={workspace} assets={len(items)} gate={gate} seq={existing.get('sequence')} (idempotent)")
            policy = {
                "assets": items, "gate": gate, "source_reference": reference,
                "human_reference": human, "updated_at": _now_iso(),
                "sequence": (int(existing.get("sequence") or 0) + 1) if existing else 1,
                "budget": budget, "scope_revision": revision,
            }
            self._write_policy(workspace, policy)
        return {"ok": True, "workspace": workspace, "policy": policy}, (
            f"workspace={workspace} assets={len(items)} gate={gate} seq={policy['sequence']}")

    def op_policy_get(self, req: dict[str, Any]) -> tuple[dict[str, Any], str]:
        workspace = self._workspace(req)
        policy = self._read_policy(workspace)
        return {"ok": True, "workspace": workspace, "policy": policy}, (
            f"workspace={workspace} present={policy is not None}")

    def op_token_mint(self, req: dict[str, Any]) -> tuple[dict[str, Any], str]:
        workspace = self._workspace(req)
        preflight = req.get("preflight")
        if not isinstance(preflight, dict):
            raise Refused("token.mint requires a preflight object")
        raw_shape = req.get("request_shape")
        if not isinstance(raw_shape, dict) or not raw_shape:
            raise Refused("token.mint requires a non-empty request_shape object")
        try:
            shape = canonical_request_shape(raw_shape)
        except ValueError as exc:
            raise Refused(f"token.mint request_shape is invalid: {exc}") from exc
        family = str(req.get("tool_family") or "http")
        ttl = req.get("ttl_seconds", DEFAULT_TTL_SECONDS)
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not MIN_TTL_SECONDS <= ttl <= MAX_TTL_SECONDS:
            raise Refused(
                f"token.mint ttl_seconds must be an integer in {MIN_TTL_SECONDS}-{MAX_TTL_SECONDS} "
                f"(got {ttl!r}) — the broker does not clamp a token lifetime")
        host = _host_of(shape.get("url", ""))
        target = str(preflight.get("target") or "").strip()
        if not target:
            raise Refused("token.mint preflight.target is required")
        target_host = _host_of(target)
        if target_host != host:
            raise Refused(
                f"token.mint preflight.target host '{target_host or target}' does not match the "
                f"request_shape url host '{host or shape.get('url', '')}' — the preflight must name "
                "the same target it authorizes")
        cycle_id = str(preflight.get("cycle_id") or "").strip()
        with self._lock:
            policy = self._read_policy(workspace)
            if policy is None:
                raise Refused(
                    "no broker policy for this workspace — register the scope with the broker: run "
                    "`researchctl scope-set` (or record an explicit gate none policy for non-target work)")
            if str(policy.get("gate")) != "none":
                assets = policy.get("assets")
                if not isinstance(assets, list) or not assets:
                    raise Refused(
                        "broker policy assets are unenforceable (empty or not a list) — repair the "
                        "policy with `researchctl scope-set`; refusing to mint")
                if not host or not host_in_scope(host, asset_hosts(assets)):
                    raise Refused(
                        f"target host '{host or shape.get('url', '')}' is outside the engagement scope "
                        f"(broker policy assets={assets})")
            limits = _parse_budget_caps(policy.get("budget"))
            mints = self._records("mint")
            cap_cycle = limits["max_actions_per_cycle"]
            if cap_cycle is not None:
                if not cycle_id:
                    raise Refused(
                        "token.mint preflight.cycle_id is required while a per-cycle budget cap is "
                        "configured — the broker cannot count cycle actions without it")
                used_cycle = sum(
                    1 for record in mints
                    if record.get("workspace") == workspace
                    and str((record.get("preflight") or {}).get("cycle_id") or "") == cycle_id)
                if used_cycle >= cap_cycle:
                    raise Refused(
                        f"cycle budget exhausted ({used_cycle}/{cap_cycle}) — record a human-approved "
                        "raise via `researchctl budget set` (then re-run `researchctl scope-set` so the "
                        "broker copy is refreshed)")
            cap_total = limits["max_actions_per_engagement"]
            if cap_total is not None:
                used_total = sum(1 for record in mints if record.get("workspace") == workspace)
                if used_total >= cap_total:
                    raise Refused(
                        f"engagement budget exhausted ({used_total}/{cap_total}) — record a "
                        "human-approved raise via `researchctl budget set` (then re-run "
                        "`researchctl scope-set` so the broker copy is refreshed)")
            action_id = f"B-{len(mints) + 1:06d}"
            nonce = secrets.token_hex(16)
            expires_at = _expiry_iso(ttl)
            digest = hashlib.sha256(_json_dump(shape).encode("utf-8")).hexdigest()
            record = {
                "kind": "mint", "action_id": action_id, "nonce": nonce, "digest": digest,
                "tool_family": family, "expires_at": expires_at, "workspace": workspace,
                "sig": "", "minted_at": _now_iso(), "preflight": preflight,
            }
            record["sig"] = self._sign({key: record[key] for key in _SIGNED_FIELDS})
            self._append_jsonl(self.tokens_file, record)
        token = {key: record[key] for key in
                 ("action_id", "nonce", "digest", "tool_family", "expires_at", "workspace", "sig")}
        return {"ok": True, "token": token, "preflight": preflight}, (
            f"action={action_id} family={family} host={host or '-'} ttl={ttl}")

    def op_scope_check(self, req: dict[str, Any]) -> tuple[dict[str, Any], str]:
        """The runner-facing scope decision, from the broker's own policy copy.

        Mirrors `control_plane.scope_check`: the canonical `asset_hosts` / `host_in_scope`
        helpers decide, an unset or unenforceable policy refuses (never "allow"), and
        `gate: none` is the explicit opt-out. Used by `researchctl scope-check` and the
        BUA runner's per-request seam while the broker socket is present.
        """
        workspace = self._workspace(req)
        url = str(req.get("url") or "")
        host = _scope_host_of(url)
        policy = self._read_policy(workspace)
        if policy is None:
            raise Refused(
                "the broker holds no policy for this workspace — register the scope with the broker: "
                "run `researchctl scope-set` (or record an explicit gate none policy for non-target work)")
        if str(policy.get("gate")) == "none":
            return {"ok": True, "gate": "disabled", "in_scope": True, "host": host, "assets": []}, (
                f"host={host or '-'} in_scope=True gate=disabled")
        assets = policy.get("assets")
        if not isinstance(assets, list) or not assets:
            raise Refused(
                "broker policy assets are unenforceable (empty or not a list) — repair the policy "
                "with `researchctl scope-set`; refusing the scope check")
        in_scope = bool(host) and host_in_scope(host, asset_hosts(assets))
        return {"ok": True, "gate": "assets", "in_scope": in_scope, "host": host, "assets": assets}, (
            f"host={host or '-'} in_scope={in_scope}")

    def op_token_consume(self, req: dict[str, Any]) -> tuple[dict[str, Any], str]:
        workspace = self._workspace(req)
        digest = str(req.get("digest") or "")
        family = str(req.get("tool_family") or "")
        nonce = str(req.get("nonce") or "")
        sig = str(req.get("sig") or "")
        if not digest or not family or not nonce or not sig:
            raise Refused("token.consume requires digest, tool_family, nonce and sig")
        with self._lock:
            record = next((rec for rec in self._records("mint") if rec.get("nonce") == nonce), None)
            if record is None:
                raise Refused(f"unknown nonce {nonce[:12]}… — no preflight token was minted for it")
            if record.get("workspace") != workspace:
                raise Refused(
                    f"nonce {nonce[:12]}… was minted for a different workspace ({record.get('workspace')})")
            if record.get("digest") != digest:
                raise Refused("digest does not match the minted preflight token")
            if record.get("tool_family") != family:
                raise Refused(
                    f"tool_family does not match the minted preflight token ({record.get('tool_family')})")
            expected = self._sign({key: record.get(key) for key in _SIGNED_FIELDS})
            if not hmac.compare_digest(expected, sig):
                raise Refused(
                    "signature does not verify — the token was not minted by this broker or was tampered with")
            if str(record.get("expires_at") or "") <= _now_iso():
                raise Refused(f"token expired at {record.get('expires_at')} — prepare a fresh preflight")
            if any(rec.get("nonce") == nonce for rec in self._records("consume")):
                raise Refused("token already consumed — preflight tokens are single-use")
            self._append_jsonl(self.tokens_file, {
                "kind": "consume", "action_id": record.get("action_id"), "nonce": nonce,
                "workspace": workspace, "consumed_at": _now_iso()})
        return {"ok": True, "action_id": record.get("action_id"),
                "preflight": record.get("preflight")}, f"action={record.get('action_id')}"

    def op_review_issue(self, req: dict[str, Any]) -> tuple[dict[str, Any], str]:
        """Mint a single-use review voucher binding reviewer + run to one packet.

        The voucher is HMAC-signed over the workspace, cycle, hypothesis, axis,
        declared reviewer/run identity and the packet digest, so a voucher cannot
        move across axes, hypotheses, packets or workspaces. The reviewing run
        embeds it as `review.attestation`; `merge_worker` consumes it exactly once.
        """
        workspace = self._workspace(req)
        cycle_id = str(req.get("cycle_id") or "").strip()
        hypothesis_id = str(req.get("hypothesis_id") or "").strip()
        axis = str(req.get("axis") or "").strip().lower()
        reviewer = str(req.get("reviewer") or "").strip()
        run_id = str(req.get("run_id") or "").strip()
        packet_sha256 = str(req.get("packet_sha256") or "").strip().lower()
        if not cycle_id:
            raise Refused("review.issue requires cycle_id")
        if not hypothesis_id:
            raise Refused("review.issue requires hypothesis_id")
        if axis not in {"objective", "method"}:
            raise Refused("review.issue requires axis objective|method")
        if not reviewer or not run_id:
            raise Refused("review.issue requires reviewer and run_id")
        if not re.fullmatch(r"[0-9a-f]{64}", packet_sha256):
            raise Refused("review.issue requires packet_sha256 (64 hex chars)")
        ttl = req.get("ttl_seconds", DEFAULT_TTL_SECONDS)
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not MIN_TTL_SECONDS <= ttl <= MAX_TTL_SECONDS:
            raise Refused(
                f"review.issue ttl_seconds must be an integer in {MIN_TTL_SECONDS}-{MAX_TTL_SECONDS} "
                f"(got {ttl!r}) — the broker does not clamp a voucher lifetime")
        with self._lock:
            nonce = secrets.token_hex(16)
            voucher = {
                "workspace": workspace, "cycle_id": cycle_id, "hypothesis_id": hypothesis_id,
                "axis": axis, "reviewer": reviewer, "run_id": run_id,
                "packet_sha256": packet_sha256, "nonce": nonce,
                "expires_at": _expiry_iso(ttl),
            }
            voucher["sig"] = self._sign({key: voucher[key] for key in VOUCHER_SIGNED_FIELDS})
            self._append_jsonl(self.tokens_file, {
                "kind": "review-issue", **voucher, "issued_at": _now_iso()})
        return {"ok": True, "voucher": voucher}, (
            f"cycle={cycle_id} hypothesis={hypothesis_id} axis={axis} ttl={ttl}")

    def op_review_consume(self, req: dict[str, Any]) -> tuple[dict[str, Any], str]:
        """Consume one review voucher: signature, expiry, workspace and single-use."""
        workspace = self._workspace(req)
        voucher = req.get("voucher")
        if not isinstance(voucher, dict):
            raise Refused("review.consume requires a voucher object")
        nonce = str(voucher.get("nonce") or "")
        sig = str(voucher.get("sig") or "")
        if not nonce or not sig:
            raise Refused("review.consume requires voucher.nonce and voucher.sig")
        with self._lock:
            record = next((rec for rec in self._records("review-issue")
                           if rec.get("nonce") == nonce), None)
            if record is None:
                raise Refused(f"unknown voucher nonce {nonce[:12]}… — no review voucher was issued for it")
            if record.get("workspace") != workspace:
                raise Refused(
                    f"voucher {nonce[:12]}… was issued for a different workspace ({record.get('workspace')})")
            expected = self._sign({key: record.get(key) for key in VOUCHER_SIGNED_FIELDS})
            if not hmac.compare_digest(expected, sig):
                raise Refused(
                    "voucher signature does not verify — the voucher was not issued by this broker or was tampered with")
            presented = {key: voucher.get(key) for key in VOUCHER_SIGNED_FIELDS if key != "sig"}
            issued = {key: record.get(key) for key in VOUCHER_SIGNED_FIELDS if key != "sig"}
            if presented != issued:
                raise Refused("voucher fields do not match the issued voucher — rebound or edited vouchers are refused")
            if str(record.get("expires_at") or "") <= _now_iso():
                raise Refused(f"voucher expired at {record.get('expires_at')} — issue a fresh voucher")
            if any(rec.get("nonce") == nonce for rec in self._records("review-consume")):
                raise Refused("voucher already consumed — review vouchers are single-use")
            self._append_jsonl(self.tokens_file, {
                "kind": "review-consume", "nonce": nonce, "workspace": workspace,
                "cycle": record.get("cycle_id"), "hypothesis": record.get("hypothesis_id"),
                "axis": record.get("axis"), "consumed_at": _now_iso()})
        bound = {key: record[key] for key in
                 ("cycle_id", "hypothesis_id", "axis", "reviewer", "run_id", "packet_sha256", "nonce")}
        return {"ok": True, **bound}, (
            f"cycle={record.get('cycle_id')} hypothesis={record.get('hypothesis_id')} axis={record.get('axis')}")

    _OPS = {
        "hello": op_hello,
        "status": op_status,
        "policy.put": op_policy_put,
        "policy.get": op_policy_get,
        "scope.check": op_scope_check,
        "token.mint": op_token_mint,
        "token.consume": op_token_consume,
        "review.issue": op_review_issue,
        "review.consume": op_review_consume,
    }

    # ---------- frames + connection ----------
    def handle(self, req: Any) -> dict[str, Any]:
        """Run one op and return its response, refusing any decision that cannot be logged.

        Journal-first: a state-changing op (`policy.put`, `token.mint`,
        `token.consume`) durably appends (fsync) an INTENT record BEFORE it runs, then
        the outcome after. The audit log is preflighted (open for append) BEFORE the op
        runs, so an unwritable log refuses the request instead of executing it
        unlogged; the append after the op is checked too. A late failure cannot
        un-apply the state change, so it returns an explicit `applied_but_unlogged`
        shape — never a plain refusal — and the INTENT line is the decision record
        (recovery: every INTENT without a matching outcome line needs review; the
        state files themselves stay authoritative for enforcement).
        """
        op = req.get("op") if isinstance(req, dict) else None
        try:
            fd = os.open(self.audit_file, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            os.close(fd)
        except OSError as exc:
            return {"ok": False, "error": (
                f"the broker audit log is not writable ({exc}) — refusing the request so no "
                f"decision goes unlogged; repair {self.audit_file}")}
        if op in STATE_CHANGING_OPS:
            try:
                workspace = req.get("workspace") if isinstance(req, dict) else None
                self._audit(f"INTENT {op} workspace={str(workspace or '-').strip() or '-'}")
            except OSError as exc:
                return {"ok": False, "error": (
                    f"the broker journal is not writable ({exc}) — refusing the request so no "
                    f"decision goes unlogged; repair {self.audit_file}")}
        applied = False
        try:
            if not isinstance(req, dict):
                raise Refused("request must be a JSON object")
            if not isinstance(op, str) or not op:
                raise Refused("request is missing op")
            fn = self._OPS.get(op)
            if fn is None:
                raise Refused(f"unknown op: {op}")
            response, summary = fn(self, req)
            applied = response.get("ok") is True
        except Refused as exc:
            response, summary = {"ok": False, "error": str(exc)}, f"refuse {exc}"
        except Exception as exc:  # one bad request must never crash the daemon
            # Unknown whether state changed — assume it did (fail closed: reconcile).
            applied = True
            response, summary = (
                {"ok": False, "error": f"internal error: {exc}"},
                f"error {type(exc).__name__}: {exc}")
        try:
            self._audit(f"{op or '?'} {summary}".rstrip())
        except OSError as exc:
            if applied:
                return {"ok": False, "applied_but_unlogged": True, "op": op, "error": (
                    f"the broker audit record could not be appended ({exc}) — the operation WAS "
                    f"applied ({summary}); the INTENT record above is the decision record. Recovery: "
                    "re-read audit.log for INTENT lines without a matching outcome line and reconcile "
                    f"the state files ({TOKENS_NAME}, policies/) against them")}
            return {"ok": False, "applied_but_unlogged": False, "op": op, "error": (
                f"{response.get('error')} (and the refusal audit line could not be appended "
                f"({exc}) — no state was changed; the INTENT record above shows the attempt. "
                f"Recovery: repair {self.audit_file})")}
        return response

    def _response_for_line(self, line: bytes) -> bytes:
        if len(line) > MAX_LINE:
            self._audit_best_effort("frame refuse request line too large")
            return _encode({"ok": False, "error": f"request line too large (limit {MAX_LINE} bytes)"})
        try:
            req = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._audit_best_effort("frame refuse malformed JSON")
            return _encode({"ok": False, "error": "malformed frame: not valid UTF-8 JSON"})
        payload = _encode(self.handle(req))
        if len(payload) > MAX_LINE:
            self._audit_best_effort("frame refuse response line too large")
            return _encode({"ok": False, "error": (
                f"the response exceeds the {MAX_LINE} byte line bound — refusing the request")})
        return payload

    def claim_connection(self) -> bool:
        """Reserve an in-service connection slot; False when the cap is reached."""
        with self._conn_lock:
            if self.active_connections >= MAX_CONNECTIONS:
                return False
            self.active_connections += 1
            return True

    def release_connection(self) -> None:
        with self._conn_lock:
            self.active_connections = max(0, self.active_connections - 1)

    def serve_connection(self, conn: socket.socket) -> None:
        buf = b""
        conn.settimeout(READ_TIMEOUT_SECONDS)
        try:
            while True:
                try:
                    chunk = conn.recv(65536)
                except OSError:
                    # Includes the idle read timeout: an idle connection is dropped.
                    break
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    conn.sendall(self._response_for_line(line))
                if len(buf) > MAX_LINE:
                    conn.sendall(_encode({"ok": False, "error": f"request line too large (limit {MAX_LINE} bytes)"}))
                    self._audit_best_effort("frame refuse request line too large")
                    break
        except OSError:
            pass
        finally:
            self.release_connection()
            try:
                conn.close()
            except OSError:
                pass


def serve(home: Path) -> int:
    broker = Broker(home)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if broker.socket_path.exists():
        try:
            broker.socket_path.unlink()
        except OSError:
            pass
    sock.bind(str(broker.socket_path))
    os.chmod(broker.socket_path, 0o600)
    sock.listen(16)
    print(f"broker: listening on {broker.socket_path}", flush=True)
    stopping = threading.Event()

    def shutdown(signum, frame):
        stopping.set()
        try:
            sock.close()
        except OSError:
            pass

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try:
        while not stopping.is_set():
            try:
                conn, _ = sock.accept()
            except OSError:
                break
            if not broker.claim_connection():
                try:
                    conn.sendall(_encode({"ok": False, "error": (
                        f"too many concurrent connections (cap {MAX_CONNECTIONS}) — retry shortly")}))
                except OSError:
                    pass
                broker._audit_best_effort(f"refuse connection cap reached ({MAX_CONNECTIONS})")
                try:
                    conn.close()
                except OSError:
                    pass
                continue
            threading.Thread(target=broker.serve_connection, args=(conn,), daemon=True).start()
    finally:
        try:
            sock.close()
        except OSError:
            pass
        try:
            broker.socket_path.unlink()
        except OSError:
            pass
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="broker", description=__doc__.splitlines()[0])
    parser.add_argument("--serve", action="store_true", help="run the broker daemon in the foreground")
    parser.add_argument("--home", help="broker home (default: RESEARCH_OS_BROKER_HOME or ~/.dsh/research-os-broker)")
    args = parser.parse_args(argv)
    if not args.serve:
        parser.error("nothing to do — pass --serve to run the daemon")
    return serve(Path(args.home) if args.home else broker_home())


if __name__ == "__main__":
    raise SystemExit(main())
