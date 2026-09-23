#!/usr/bin/env python3
"""Deterministic control plane for the research workspace.

The append-only event ledger is the canonical mutable history. Human-readable YAML/Markdown
files are projections. The model owns research reasoning; this module owns durable invariants,
state transitions, evidence integrity, human-gate bookkeeping and projection rebuilds.
Standard library only.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote

from knowledge_index import (
    index_problem,
    parse_index,
    resolve_ref,
    selection_cap,
    selection_query,
    top_packs,
)
from ts_cost import cost_summary

CYCLE_EDGES = {
    "PLANNED": {"READY", "BLOCKED"},
    "READY": {"RUNNING", "BLOCKED"},
    "RUNNING": {"HUMAN_GATE", "BLOCKED", "NEEDS_PIVOT", "RESULT_READY"},
    "HUMAN_GATE": {"RUNNING", "BLOCKED"},
    "BLOCKED": {"READY"},
    "NEEDS_PIVOT": {"READY"},
    "RESULT_READY": {"REVIEWED", "FALSE_POSITIVE", "NOT_APPLICABLE", "RUNNING", "BLOCKED"},
    "REVIEWED": {"CLOSED"},
    "FALSE_POSITIVE": {"CLOSED"},
    "NOT_APPLICABLE": {"CLOSED"},
    "CLOSED": set(),
}
# Cycle terminal rename (v7.3): a cycle is REVIEWED (both review axes pass + instrument
# validation); VERIFIED is the hypothesis/finding state. Historical ledgers recorded the
# cycle transition as VERIFIED, so every read-side derivation normalizes it to REVIEWED.
CYCLE_LEGACY_STATES = {"VERIFIED": "REVIEWED"}


def normalize_cycle_state(value: Any) -> Any:
    return CYCLE_LEGACY_STATES.get(value, value)


HYP_EDGES = {
    "CANDIDATE": {"QUEUED", "BLOCKED", "NOT_APPLICABLE", "CLOSED"},
    "QUEUED": {"TESTING", "BLOCKED", "NOT_APPLICABLE", "CLOSED"},
    "TESTING": {"SUPPORTED", "VERIFIED", "FALSE_POSITIVE", "BLOCKED", "NOT_APPLICABLE"},
    "SUPPORTED": {"TESTING", "VERIFIED", "FALSE_POSITIVE", "BLOCKED", "CLOSED"},
    "VERIFIED": {"CLOSED"},
    "FALSE_POSITIVE": {"CLOSED"},
    "BLOCKED": {"QUEUED", "NOT_APPLICABLE", "CLOSED"},
    "NOT_APPLICABLE": {"CLOSED"},
    "CLOSED": set(),
}
EVENT_TYPES = {
    "CYCLE_CREATED", "CYCLE_UPDATED", "CYCLE_TRANSITIONED",
    "HYPOTHESIS_CREATED", "HYPOTHESIS_UPDATED", "HYPOTHESIS_TRANSITIONED",
    "EVIDENCE_REGISTERED", "ACTION_RECORDED", "TECHNIQUE_EVALUATED", "WORKER_RESULT",
    "HUMAN_GATE_REQUESTED", "HUMAN_GATE_RESOLVED", "AUDIT_RECORDED", "FRESHNESS_RECORDED",
    "KNOWLEDGE_PROPOSED", "KNOWLEDGE_RESOLVED",
    "STATE_CHANGE", "NOTE", "SCOPE_CHANGED", "BUDGET_CHANGED",
}
HUMAN_GATE_DECISIONS = {"RESUME", "PROVIDED", "APPROVED", "DENIED", "CANCELLED"}
# A human gate authorizes only when the human said GO: DENIED/CANCELLED are refusals
# (`resolve_gate` itself transitions the cycle to BLOCKED on them). One predicate is
# shared by the dispatch-time gate and the audit's scope-violation disposition, so the
# two can never drift apart on what counts as an approval.
GATE_AUTHORIZING_DECISIONS = frozenset({"RESUME", "PROVIDED", "APPROVED"})


def gate_decision_authorizes(decision: Any) -> bool:
    """True when a RESOLVED gate's decision returns the cycle to RUNNING (an approval)."""
    return str(decision or "").strip().upper() in GATE_AUTHORIZING_DECISIONS


def gate_postdates_token(gate_requested_at: Any, issued_at: Any) -> bool:
    """True when the gate was raised strictly after the token it names was minted.

    Action ids are sequential (`A-%06d`) and therefore predictable, so a gate resolved
    before the run on the predicted id must never pre-authorize it. Both timestamps are
    same-machine ISO-8601 Z strings (`now()`), so the lexical compare is the ordering; a
    same-second tie fails closed (the gate cannot be proven to postdate the mint).
    """
    requested = str(gate_requested_at or "")
    issued = str(issued_at or "")
    return bool(requested) and bool(issued) and requested > issued

REQUIRED_AUDIT_CLASSES = {"scope", "coverage", "negative", "open-hypothesis", "novelty-duplicate", "hygiene-cleanup", "method-self-attack"}
METHOD_SELF_ATTACK_ROWS = ("assumed-secure", "weak-negative", "early-close", "skipped-collision", "version-drift", "tool-misread")
EVIDENCE_STORE = "11_runtime/evidence-store"
FRESHNESS_DEFAULT_MAX_AGE_DAYS = 14
CYCLE_TYPES = {"DISCOVERY", "HYPOTHESIS", "VALIDATION", "AUDIT", "RESEARCH"}
TRIAGE_VERDICTS = {"USE", "SKIP"}
# Reviewed promotion path (backlog #28): a pack proposal is a reviewed artifact, not a
# note. The body floor keeps a proposal reviewable; the title reuses the shared sentence
# rule so a placeholder can never stand in for a claim.
KNOWLEDGE_PROPOSAL_BODY_MIN = 80
KNOWLEDGE_RESOLUTIONS = {"APPLIED", "REJECTED"}
# Controlled vocabulary for technique outcomes. Free-text results were the root of the
# "learning never reaches a file" failure; a closed enum can be projected and audited.
TECHNIQUE_RESULTS = {"CONFIRMED", "FALSE_POSITIVE", "NOT_APPLICABLE", "INCONCLUSIVE", "NEGATIVE"}
GENERATED_HEADER = "# GENERATED — do not edit by hand; rebuild via tools/researchctl.py (control plane)"
# High-confidence secret shapes. The ledger must never carry them raw: redact() scrubs on
# write, and audit.py re-scans the ledger so a hand edit cannot smuggle one back in.
# BEGIN-GENERATED-SECRET-PATTERNS
# Source of truth: tools/secret-patterns.json — do not hand-edit; run python3 tools/generate_secret_patterns.py.
_SECRET_PATTERNS = [
    re.compile(r"glpat-[A-Za-z0-9_.-]{16,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\."),
]
# END-GENERATED-SECRET-PATTERNS


def secret_pattern_hits(value: str) -> list[str]:
    return [p.pattern for p in _SECRET_PATTERNS if p.search(value)]


def _leading_ws(line: str) -> str:
    return line[: len(line) - len(line.lstrip(" \t"))]


def _scope_block_end(lines: list[str], start: int) -> int:
    """First non-blank, non-indented line after `start` (the block boundary)."""
    for j in range(start + 1, len(lines)):
        raw = lines[j].rstrip("\r\n")
        if raw.strip() and not raw.startswith((" ", "\t")):
            return j
    return len(lines)


def _scope_child_indent(lines: list[str], start: int, end: int) -> str:
    """Indentation of the block's first real (non-comment) entry = depth 1."""
    for j in range(start + 1, end):
        stripped = lines[j].strip()
        if stripped and not stripped.startswith("#"):
            return _leading_ws(lines[j])
    return "  "


def _assets_block_items(lines: list[str], entry: int, end: int, legacy: bool) -> tuple[list[str], int]:
    """Items of the `assets:` entry at `entry`, scanned within [entry+1, end).

    A depth-1 entry whose value is neither empty, `[]`, nor an inline list counts as
    unparsed (the caller fails closed). A block list ends at the first depth-1 non-item
    line when the entry sits inside the `scope:` block (`legacy=False`); a legacy
    top-level entry keeps the historical rule and ends at the first col-0 line.
    """
    rest = lines[entry].rstrip("\r\n").strip().split(":", 1)[1].strip()
    items: list[str] = []
    unparsed = 0
    if rest in ("", "[]"):
        j = entry + 1
        while j < end:
            raw = lines[j].rstrip("\r\n")
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                j += 1
                continue
            if not raw.startswith((" ", "\t")):
                break
            if not legacy and not stripped.startswith("-"):
                break
            m = re.match(r"^-\s*(.+?)\s*$", stripped)
            if not m:
                j += 1
                continue
            val = m.group(1)
            if val.startswith(("[", "{")):
                unparsed += 1
                j += 1
                continue
            val = val.strip("\"'")
            if val:
                items.append(val)
            j += 1
    elif rest.startswith("[") and rest.endswith("]"):
        for part in rest[1:-1].split(","):
            val = part.strip().strip("\"'")
            if val:
                items.append(val)
    else:
        unparsed += 1
    return items, unparsed


def engagement_assets(root: Path) -> list[str] | None:
    """Parse the engagement's in-scope asset list (simple YAML string list).

    Depth-aware: only a depth-1 `assets:` entry inside the top-level `scope:` block is
    authoritative. A legacy top-level `assets:` block is still accepted, but ONLY when
    no `scope:` block exists (a shadowed legacy block can never override the scope; the
    writer removes such occurrences). Returns None when the file/block is absent or
    empty (no scope gate configured), the parsed items when they are simple strings,
    and [] when the block exists but is not a simple string list — the caller treats
    [] as unenforceable, fail closed.
    """
    path = root / "00_control" / "engagement.yaml"
    if not path.exists():
        return None
    lines = path.read_text(errors="ignore").splitlines()
    scope_at = next((i for i, line in enumerate(lines)
                     if not line.startswith((" ", "\t"))
                     and re.fullmatch(r"scope:\s*(#.*)?", line.strip())), None)
    if scope_at is not None:
        end = _scope_block_end(lines, scope_at)
        indent = _scope_child_indent(lines, scope_at, end)
        entry = next((j for j in range(scope_at + 1, end)
                      if lines[j].strip() and not lines[j].strip().startswith("#")
                      and _leading_ws(lines[j]) == indent
                      and re.match(r"assets:", lines[j].strip())), None)
        items, unparsed = ([], 0) if entry is None else _assets_block_items(lines, entry, end, False)
    else:
        entry = next((i for i, line in enumerate(lines)
                      if not line.startswith((" ", "\t")) and re.match(r"assets:", line.strip())), None)
        items, unparsed = ([], 0) if entry is None else _assets_block_items(lines, entry, len(lines), True)
    if items:
        return items
    if unparsed:
        return []
    return None


def _normalize_host(host: str) -> str:
    """Host normalization shared with the enforcer: strip userinfo and one trailing dot."""
    value = (host or "").rsplit("@", 1)[-1]
    if value.endswith("."):
        value = value[:-1]
    return value.lower()


# A backslash terminates the authority in the WHATWG URL parser (the real fetch
# stack), so `http://127.0.0.1\@example.test/` connects to 127.0.0.1 while a naive
# `/`-split reads `example.test`. Whitespace/control characters and an encoded
# backslash (%5c, either case) are equally ambiguous to one parser or another:
# any authority carrying them fails closed ("").
_AUTHORITY_AMBIGUOUS = re.compile(r"[\\\s\x00-\x1f\x7f]|%5c", re.IGNORECASE)


def _authority_host(authority: str) -> str:
    """Reduce a raw authority (no `/`, `?`, `#`) to host[:port], failing closed.

    Returns "" when the authority is empty or ambiguous, so it can never match a
    scope pattern; callers treat "" as default-deny.
    """
    raw = str(authority or "")
    if not raw or _AUTHORITY_AMBIGUOUS.search(raw):
        return ""
    return _normalize_host(raw)


def _url_host(url: str) -> str:
    """Host[:port] of an absolute URL, failing closed on ambiguity.

    The authority runs to the first of `/`, `?`, `#` (a backslash inside it denies
    rather than terminates, so the derived host can never disagree with the fetch
    stack); userinfo ends at the last `@` before that terminator. A scheme-less
    string is host-less and therefore default-deny, mirroring the previous seam.
    """
    text = str(url or "")
    if "://" not in text:
        return ""
    rest = text.split("://", 1)[1]
    end = len(rest)
    for term in ("/", "?", "#"):
        idx = rest.find(term)
        if idx >= 0:
            end = min(end, idx)
    return _authority_host(rest[:end])


def _asset_hosts(assets: list[str]) -> list[str]:
    hosts: list[str] = []
    for asset in assets:
        raw = str(asset)
        is_url = "://" in raw
        # URL inputs keep surrounding whitespace so the authority parse denies
        # it (fail closed); bare hosts tolerate surrounding spaces.
        value = raw.split("://", 1)[1] if is_url else raw.strip()
        authority = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        # URL authorities keep whitespace so _authority_host denies (fail closed);
        # bare hosts tolerate surrounding spaces (already stripped above).
        host = _authority_host(authority if is_url else authority.strip())
        if host:
            hosts.append(host)
    return hosts


def _host_in_scope(host: str, patterns: list[str]) -> bool:
    host = (host or "").lower()
    for pattern in patterns:
        if pattern.startswith("*."):
            base = pattern[2:]
            if host == base or host.endswith("." + base):
                return True
        elif host == pattern:
            return True
    return False


# Public seam names: audit.py and other harnesses consume these without reaching into
# private helpers. The private aliases stay for backwards compatibility.
asset_hosts = _asset_hosts
host_in_scope = _host_in_scope


def scope_gate_disabled(root: Path) -> bool:
    """True when the engagement carries the explicit `gate: none` opt-out.

    Canonical rule (identical in dsh-plugin/index.js): after a top-level
    (unindented) `scope:` line, scan its indented block until the first non-blank
    line that is not indented; only depth-1 entries count (the first non-comment
    block line fixes that indentation). For each depth-1 line: skip it when its
    trimmed form starts with `#`; otherwise cut any trailing comment with
    split('#', 1)[0] and require the result to fullmatch
    `^gate:\\s*['\\"]?none['\\"]?\\s*$`.
    """
    path = root / "00_control" / "engagement.yaml"
    if not path.exists():
        return False
    in_scope = False
    child_indent: str | None = None
    for line in path.read_text(errors="ignore").splitlines():
        stripped = line.strip()
        if not in_scope:
            if not line.startswith((" ", "\t")) and re.match(r"^scope:\s*(#.*)?$", stripped):
                in_scope = True
            continue
        if not stripped:
            continue
        if not line.startswith((" ", "\t")):
            break
        if stripped.startswith("#"):
            continue
        indent = line[: len(line) - len(line.lstrip(" \t"))]
        if child_indent is None:
            child_indent = indent
        if indent != child_indent:
            continue
        candidate = stripped.split("#", 1)[0].strip()
        if re.fullmatch(r"gate:\s*['\"]?none['\"]?\s*", candidate):
            return True
    return False


def _scope_gate_line_present(root: Path) -> bool:
    """True when the top-level `scope:` block carries an explicit depth-1 `gate:` line.

    Any value counts: the line is deliberate configuration the human put there, so
    `set_scope` must demand a human_reference even when the parsed asset list is empty.
    """
    path = root / "00_control" / "engagement.yaml"
    if not path.exists():
        return False
    in_scope = False
    child_indent: str | None = None
    for line in path.read_text(errors="ignore").splitlines():
        stripped = line.strip()
        if not in_scope:
            if not line.startswith((" ", "\t")) and re.match(r"^scope:\s*(#.*)?$", stripped):
                in_scope = True
            continue
        if not stripped:
            continue
        if not line.startswith((" ", "\t")):
            break
        if stripped.startswith("#"):
            continue
        indent = _leading_ws(line)
        if child_indent is None:
            child_indent = indent
        if indent != child_indent:
            continue
        if re.match(r"gate:", stripped.split("#", 1)[0].strip()):
            return True
    return False


def scope_check(root: Path, url: str) -> dict[str, Any]:
    """Per-host scope decision for a URL from 00_control/engagement.yaml assets.

    Single seam for prepare, the BUA runner and any harness that needs the same
    answer: `gate` is "disabled" for an explicit `gate: none` opt-out, "unset"
    when no asset list is configured (callers default-deny), "unenforceable" when
    the block exists but is not a simple string list (callers fail closed), and
    "assets" otherwise; `in_scope` is the verdict. Hosts compare as
    host[:port] strings, lowercase, with `*.domain` matching the base and any
    subdomain.
    """
    assets = engagement_assets(root)
    host = _url_host(url)
    if scope_gate_disabled(root):
        return {"gate": "disabled", "in_scope": True, "host": host, "assets": assets}
    if assets is None:
        return {"gate": "unset", "in_scope": False, "host": host, "assets": None}
    if assets == []:
        return {"gate": "unenforceable", "in_scope": False, "host": host, "assets": []}
    return {
        "gate": "assets",
        "in_scope": bool(host) and _host_in_scope(host, _asset_hosts(assets)),
        "host": host,
        "assets": assets,
    }
_SECRET_KEYS = {
    "password", "passwd", "secret", "token", "cookie", "session", "authorization",
    "otp", "mfa", "private_key", "private-key", "api_key", "apikey", "access_token",
    "refresh_token", "client_secret",
}


def external_judgment_allowed(root: Path) -> bool:
    """Does the engagement allow external-model judgment (the TypeSafe seams)?

    Reads the top-level `external_judgment` key in 00_control/engagement.yaml (the
    key and its value are matched case-insensitively; `ALLOWED` enables). Default
    DENIED: an absent, unreadable or unrecognized setting denies, so no config gap
    and no CLI flag can route engagement evidence to an external model service
    without the researcher's explicit opt-in key.
    """
    try:
        text = (root / "00_control" / "engagement.yaml").read_text(errors="ignore")
    except OSError:
        return False
    # Horizontal whitespace only between key and value: `external_judgment:\n  ALLOWED`
    # is not a scalar assignment and must stay DENIED (a `\s*` here would read the next
    # line as the value — fail open).
    match = re.search(r"^external_judgment:[^\S\n]*[\"']?([A-Za-z_-]+)", text, re.M | re.I)
    return bool(match) and match.group(1).strip().upper() == "ALLOWED"


BUDGET_MALFORMED = "malformed"
BUDGET_KEYS = ("max_actions_per_cycle", "max_actions_per_engagement")
IDENTITY_BINDING_REL = "00_control/identity-binding.yaml"
IDENTITY_MALFORMED = "malformed"


def _unquote_scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _is_binding_placeholder(value: str) -> bool:
    """`<...>` template values are ABSENT, not literals (mirrors build_context)."""
    return bool(re.fullmatch(r"<[^<>]*>", value.strip()))


def _parse_binding_bool(value: str) -> bool | None:
    text = _unquote_scalar(value).strip().lower()
    if text == "true":
        return True
    if text == "false":
        return False
    return None


def identity_binding(root: Path) -> dict[str, Any] | str | None:
    """Parse the engagement identity binding (`00_control/identity-binding.yaml`).

    Returns None when the file is absent (template workspaces: callers allow and
    the audit warns); a dict with `account_reference` / `browser_profile` (None
    when undeclared — `<placeholder>` values count as absent), plus
    `session_must_match_identity` (default True) and
    `cross_engagement_session_reuse` (default False); and the IDENTITY_MALFORMED
    marker when the file exists but is not a readable binding (callers fail
    closed — a garbled contract must never read as "no binding").
    """
    path = Path(root) / IDENTITY_BINDING_REL
    if not os.path.lexists(path):
        return None
    if not path.is_file():
        # A non-file at the binding path (directory, fifo, dangling symlink) is
        # a garbled contract, not an absent one — fail closed, never warn-and-allow.
        return IDENTITY_MALFORMED
    try:
        lines = path.read_text(errors="strict").splitlines()
    except (OSError, ValueError):
        # ValueError covers undecodable bytes (UnicodeDecodeError): a garbled
        # contract must read as malformed (fail closed), never raise — one place
        # fixes the CLI readout, prepare, the audit and the executor's fail-closed
        # match (which keys on "malformed") simultaneously.
        return IDENTITY_MALFORMED
    section: str | None = None
    fields: dict[str, str] = {}
    for lineno, raw in enumerate(lines, 1):
        line = raw.split("#", 1)[0] if not raw.lstrip().startswith("#") else ""
        # A `#` inside a quoted scalar is data, not a comment — re-take it.
        stripped = raw.strip()
        if stripped and stripped[0] not in {"#"} and "#" in line:
            for quote in ("'", '"'):
                if stripped.count(quote) >= 2:
                    first, last = stripped.find(quote), stripped.rfind(quote)
                    if "#" in stripped[first:last + 1]:
                        line = raw
                        break
        if not line.strip():
            continue
        if "\t" in raw:
            return IDENTITY_MALFORMED
        if not raw[0] in {" ", "\t"}:
            m = re.match(r"^([A-Za-z0-9_.-]+):\s*(.*?)\s*$", line.strip())
            if not m:
                return IDENTITY_MALFORMED
            key, value = m.group(1), m.group(2)
            if value and key in ("expected_identity", "session"):
                # Block form only: `expected_identity: {account_reference: alice}`
                # declares a binding the reader below cannot see — reading it as
                # "no binding" would skip enforcement (fail open).
                return IDENTITY_MALFORMED
            section = key if not value else None
            if value:
                fields[key] = value
        else:
            m = re.match(r"^\s+([A-Za-z0-9_.-]+):\s*(.*?)\s*$", line.rstrip())
            if not m or section is None:
                return IDENTITY_MALFORMED
            fields[f"{section}.{m.group(1)}"] = m.group(2)
    account = _unquote_scalar(fields.get("expected_identity.account_reference", ""))
    profile = _unquote_scalar(fields.get("session.browser_profile", ""))
    must_match_raw = fields.get("session.session_must_match_identity")
    reuse_raw = fields.get("session.cross_engagement_session_reuse")
    must_match = True if must_match_raw is None else _parse_binding_bool(must_match_raw)
    reuse = False if reuse_raw is None else _parse_binding_bool(reuse_raw)
    if must_match is None or reuse is None:
        return IDENTITY_MALFORMED
    return {
        "account_reference": None if (not account or _is_binding_placeholder(account)) else account,
        "browser_profile": None if (not profile or _is_binding_placeholder(profile)) else profile,
        "session_must_match_identity": must_match,
        "cross_engagement_session_reuse": reuse,
    }

# Durable scope-sync marker (11_runtime/.scope-sync-dirty): present while the local
# scope binding was committed but the broker push failed or was refused. Browser
# dispatch refuses while it exists and a broker socket is in force; `researchctl
# scope-sync` (or a successful scope-set push) clears it. Control-plane-owned: the
# enforcer denies direct writes to it like the other runtime files.
SCOPE_SYNC_DIRTY = ".scope-sync-dirty"


def budget_limits(root: Path) -> dict[str, int | None] | str | None:
    """Parse the top-level `budget:` block in 00_control/engagement.yaml.

    Returns None when the block is absent (no cap configured), a dict with one entry
    per known key (None when the key is absent or carries no value) when it parses
    cleanly, and the BUDGET_MALFORMED marker when a col-0 `budget:` entry carries a
    non-comment remainder (flow map, scalar, block scalar — anything that is not the
    supported block form) or when a present key's value is not a plain non-negative
    integer. Callers must treat the marker as fail-closed — refuse the live action and
    demand a human-fixed `researchctl budget set` — never as "no budget": a typo must
    not raise the effective cap to infinity.
    """
    path = root / "00_control" / "engagement.yaml"
    if not path.exists():
        return None
    lines = path.read_text(errors="ignore").splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.startswith((" ", "\t")):
            continue
        header = re.match(r"budget\s*:(.*)$", line)
        if not header:
            continue
        remainder = header.group(1).strip()
        if remainder and not remainder.startswith("#"):
            return BUDGET_MALFORMED
        start = i
        break
    if start is None:
        return None
    end = _scope_block_end(lines, start)
    indent = _scope_child_indent(lines, start, end)
    limits: dict[str, int | None] = {}
    for j in range(start + 1, end):
        raw = lines[j].rstrip("\r\n")
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _leading_ws(raw) != indent or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        key = key.strip()
        if key not in BUDGET_KEYS:
            continue
        value = value.split("#", 1)[0].strip()
        if value == "":
            # An empty scalar is an unset key; a nested mapping/sequence is not.
            look = j + 1
            while look < end and (not lines[look].strip() or lines[look].strip().startswith("#")):
                look += 1
            if look < end and len(_leading_ws(lines[look])) > len(indent):
                return BUDGET_MALFORMED
            limits[key] = None
        elif re.fullmatch(r"[0-9]+", value):
            limits[key] = int(value)
        else:
            return BUDGET_MALFORMED
    return {key: limits.get(key) for key in BUDGET_KEYS}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cycle_id_ok(value: str) -> bool:
    return bool(re.fullmatch(r"C-[0-9]{4,}", value or ""))


def hyp_id_ok(value: str) -> bool:
    return bool(re.fullmatch(r"H-[0-9]{4,}", value or ""))


def gate_id_ok(value: str) -> bool:
    return bool(re.fullmatch(r"G-[0-9]{4,}", value or ""))


def evidence_id_ok(value: str) -> bool:
    return bool(re.fullmatch(r"E-[0-9]{6,}", value or ""))


def sentence_too_thin(value: str) -> bool:
    """The shared sentence rule: >= 20 characters and >= 3 words after stripping.

    Used by audit summaries and by the NOT_APPLICABLE `precondition_absence` guard so
    placeholder text (`n/a`, `none`, `x`, `TODO`, `<...>`) cannot stand in for a real
    statement of what was audited or what precondition was absent.
    """
    stripped = str(value or "").strip()
    return len(stripped) < 20 or len(stripped.split()) < 3


def never_considered_packs(usage: dict[str, Any]) -> list[str]:
    """All-time view: zero use, zero skip, zero cited.

    Shared by `researchctl knowledge usage` and its `--unused` filter, so the CLI and
    the filter cannot drift apart.
    """
    return [name for name, row in usage["packs"].items()
            if not (row["use"] or row["skip"] or row["cited"])]


def never_considered_in_window(usage: dict[str, Any], cycle_ids: list[str],
                               window: int = 10) -> list[str]:
    """Packs with no disposition and no citation in the last `window` cycles.

    The all-time view answers "has this pack ever been considered?"; this windowed
    view answers "is it being considered now?", so the audit can surface a pack that
    was used once and then silently abandoned. Citation cycles come from the
    TECHNIQUE_EVALUATED event's cycle_id.
    """
    recent = set(cycle_ids[-window:]) if window > 0 else set(cycle_ids)
    return [name for name, row in usage["packs"].items()
            if not (set(row["cycles"]) & recent)
            and not (set(row.get("cited_cycles") or []) & recent)]


def review_quote_problem(root: Path, index: dict[str, dict[str, Any]], item: Any, i: int,
                         allowed_refs: list[str] | None = None) -> str | None:
    """Why `evidence_quotes[i]` is not a quote of the registered store copy, or None.

    Shared by the write-side guard (`merge_worker`) and the integrity audit so both
    sides answer the same question; the check reads the content-addressed store copy
    (`11_runtime/evidence-store/<sha256><suffix>`), never the mutable living file.
    `allowed_refs`, when given, is the packet's own `evidence_refs`: a verdict may only
    quote evidence the packet itself cites.
    """
    if not isinstance(item, dict):
        return f"review.evidence_quotes[{i}] must be an object {{evidence_ref, quote}}"
    ref = str(item.get("evidence_ref", "")).strip()
    quote = str(item.get("quote", "")).strip()
    if not evidence_id_ok(ref):
        return f"review.evidence_quotes[{i}].evidence_ref must be a registered E-* id, got {ref!r}"
    meta = index.get(ref)
    if meta is None:
        return f"review.evidence_quotes[{i}].evidence_ref {ref} is not registered evidence"
    if allowed_refs is not None and ref not in allowed_refs:
        cited = ", ".join(str(r) for r in allowed_refs) or "none"
        return (f"review.evidence_quotes[{i}].evidence_ref {ref} is not one of the packet's evidence_refs "
                f"({cited}) — add the artifact to packet.evidence_refs before quoting it, so the verdict's "
                "grounding stays inside the evidence the packet submitted")
    if len(quote) < 20:
        return (f"review.evidence_quotes[{i}].quote is shorter than 20 characters after stripping — "
                "quote a real line of the registered capture")
    store_rel = str(meta.get("store_path") or "")
    store_path = (root / store_rel) if store_rel else None
    if store_path is None or not store_path.is_file():
        text = ""
    else:
        # The store copy is the artifact the verdict is bound to: re-verify its
        # digest and size against the registration record before accepting any
        # quote, so a later edit of the store copy cannot move the evidence under
        # the review (the substring check alone would still pass an append attack).
        try:
            actual_sha256 = sha256_file(store_path)
            actual_size = store_path.stat().st_size
        except OSError:
            return (f"review.evidence_quotes[{i}].evidence_ref {ref} store copy is unreadable "
                    f"({store_rel or 'no stored copy'}) — re-register the artifact")
        recorded_sha256 = str(meta.get("sha256") or "")
        recorded_size = meta.get("bytes")
        if recorded_sha256 and recorded_sha256 != actual_sha256:
            return (f"review.evidence_quotes[{i}].evidence_ref {ref} store copy no longer matches "
                    f"the registered digest ({store_rel}) — the snapshot changed after registration; "
                    "re-register the artifact so the verdict binds the current bytes")
        if isinstance(recorded_size, int) and recorded_size != actual_size:
            return (f"review.evidence_quotes[{i}].evidence_ref {ref} store copy no longer matches "
                    f"the registered size ({store_rel}) — the snapshot changed after registration; "
                    "re-register the artifact so the verdict binds the current bytes")
        text = store_path.read_text(errors="ignore")
    if quote not in text:
        return (f"review.evidence_quotes[{i}].quote not found in the registered store copy of {ref} "
                f"({store_rel or 'no stored copy'}) — quote the registered snapshot, not the living file "
                "(re-register the artifact if it changed)")
    return None


def review_packet_digest(packet: dict[str, Any]) -> str:
    """Canonical sha256 of a review packet, excluding any embedded attestation.

    The reviewing run hashes this exact projection when asking the broker for a
    voucher (`review.issue ... packet_sha256`); `merge_worker` and the audit
    recompute it, so a voucher cannot move to an edited packet. `producer_run_id`
    rides the digest: a post-issue edit or omission of the producer invalidates
    the voucher, so the producer-run self-review refusal cannot be defeated by
    stripping the field after issue. `_json_dump` is the shared canonicalization
    (sorted keys, compact separators).
    """
    review = dict(packet.get("review") or {})
    review.pop("attestation", None)
    projection = {
        "cycle_id": packet.get("cycle_id"),
        "evidence_refs": packet.get("evidence_refs"),
        "next_step": packet.get("next_step"),
        "producer_run_id": packet.get("producer_run_id"),
        "review": review,
    }
    return hashlib.sha256(_json_dump(projection).encode("utf-8")).hexdigest()


def pack_change_problem(root: Path, row: dict[str, Any]) -> str | None:
    """Why the pack named by a knowledge-proposal row shows no proven content change.

    Compares the row's snapshotted `pack_digests` against the current
    INDEX-declared pack files. Shared by the write-side APPLIED guard
    (`knowledge_resolve`) and the integrity audit, so a forged projection row or
    a hand-appended APPLIED cannot pass one side while failing the other.
    Returns the problem, or None when at least one declared file really changed.
    """
    root = Path(root)
    proposal_id = str(row.get("id") or "")
    pack = str(row.get("pack") or "")
    digests = row.get("pack_digests")
    if not isinstance(digests, dict) or not digests:
        return (
            f"proposal {proposal_id} carries no pack_digests — it predates content "
            "verification; re-propose the change so APPLIED can be proven"
        )
    pack_dir = root / "12_knowledge" / pack
    changed: list[str] = []
    problems: list[str] = []
    for ref, recorded in sorted(digests.items()):
        if not isinstance(recorded, str) or not re.fullmatch(r"[0-9a-f]{64}", recorded):
            problems.append(f"{ref} has a malformed recorded digest")
            continue
        target = (pack_dir / str(ref)).resolve()
        try:
            target.relative_to(root)
        except ValueError:
            problems.append(f"{ref} escapes the workspace")
            continue
        if not target.is_file():
            problems.append(f"{ref} is missing")
            continue
        try:
            current = sha256_file(target)
        except OSError as exc:
            problems.append(f"{ref} is unreadable ({exc})")
            continue
        if current != recorded:
            changed.append(str(ref))
    if problems:
        return (
            f"cannot verify the {pack} pack content for proposal {proposal_id}: "
            + "; ".join(problems)
            + f" — restore or repair 12_knowledge/{pack}/ before resolving APPLIED"
        )
    if not changed:
        return (
            f"pack {pack} content is unchanged since proposal {proposal_id} was created "
            "— a timestamp touch is not an edit; edit the INDEX-declared pack file(s) "
            "with real content, then resolve"
        )
    return None


def triage_demands(root: Path, objective: str) -> tuple[list[str], int]:
    """The demanded ranked pack list and effective cap for one cycle objective.

    One seam for the RUNNING guard, the RUNNING snapshot and the audit, so all three
    answer from the same ranking. Callers snapshot the result at RUNNING time; later
    environment or workspace drift must not move the goalposts on past cycles.
    """
    cap = selection_cap()
    ranked = [name for name, _ in top_packs(root, selection_query(root, objective), k=cap)]
    return ranked, cap


def snapshot_demands(snapshot: Any) -> tuple[list[str], int] | None:
    """A stored `knowledge_triage_snapshot` as (ranked, cap), or None when absent."""
    if not isinstance(snapshot, dict):
        return None
    ranked = snapshot.get("ranked")
    cap = snapshot.get("cap")
    if (not isinstance(ranked, list) or not all(isinstance(n, str) for n in ranked)
            or isinstance(cap, bool) or not isinstance(cap, int)):
        return None
    return list(ranked), cap


def canonical_request_shape(shape: dict[str, Any]) -> dict[str, Any]:
    """Normalize a request_shape to the canonical digest form the executor hashes.

    Canonical form (identical to dsh-plugin `shapeFromArgs` / `browserShapeFromArgs`
    and their `canonicalDigest`): `{method (uppercased), url, principal[, headers
    (lowercase keys, values untouched)][, body_sha256]}`; the browser family's
    `{url, principal}` stays exactly that — keys the caller did not supply are not
    invented. When `body` is present and `body_sha256` is absent, the digest input
    computes `body_sha256 = sha256(body.encode("utf-8"))` and drops `body`; an empty or
    null body contributes nothing. Unknown keys are dropped — the canonical form is
    closed, so a typo cannot ride along inside the hashed bytes.
    """
    out: dict[str, Any] = {}
    if "method" in shape:
        out["method"] = str(shape["method"]).upper()
    if "url" in shape:
        out["url"] = str(shape["url"])
    if "principal" in shape:
        out["principal"] = str(shape["principal"])
    headers = shape.get("headers")
    if isinstance(headers, dict):
        out["headers"] = {str(k).lower(): str(v) for k, v in headers.items()}
    body = shape.get("body")
    body_sha = shape.get("body_sha256")
    if body is not None and body_sha is not None:
        raise ValueError("request_shape cannot carry both 'body' and 'body_sha256' — the digest input is ambiguous")
    if body is not None and not isinstance(body, str):
        raise ValueError("request_shape 'body' must be a string (no implicit stringification of numbers/booleans)")
    if body is not None and body != "":
        out["body_sha256"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
    elif body_sha is not None:
        out["body_sha256"] = str(body_sha)
    return out


def _json_dump(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


# Query/fragment parameter names whose VALUE is a credential. Matched as a
# case-insensitive SUBSTRING after percent-decoding (`access_token`, `client_secret`,
# `X-Amz-Signature`, `token2`, `code`, `session_id` all match). Mirrors the enforcer's
# `redactUrlSecrets` (dsh-plugin/index.js) so both sides mask the same values.
_SENSITIVE_QUERY_MARKERS = re.compile(r"token|secret|key|auth|sig|session|code|password|passwd|cookie", re.I)
# A sensitive assignment nested inside ANOTHER component's decoded value: a double-encoded
# `next=/cb%26token%3Dxyz` decodes once to `next=/cb&token=xyz`, so a downstream consumer
# that decodes `next` would see the token. Matched after a `&`/`;` separator or at the
# value's start; the WHOLE component value is masked when it matches.
_NESTED_SENSITIVE_ASSIGNMENT = re.compile(
    r"(^|[&;])\s*[A-Za-z0-9_.-]*(?:token|secret|key|auth|sig|session|code|password|passwd|cookie)"
    r"[A-Za-z0-9_.-]*\s*=",
    re.I,
)
# A query-or-fragment span inside any string: `?…` or `#…` up to whitespace, a quote
# (a URL embedded in JSON/Markdown ends at the quote), the next `?`/`#`, or the end of
# the string. Scheme/host/path bytes are never touched.
_QUERY_OR_FRAGMENT = re.compile(r"[?#][^\s\"'#?]*")


def _redact_query_component(part: str) -> str:
    """Mask one `name=value` component when its decoded name — or a sensitive
    assignment nested in its decoded value — is sensitive."""
    eq = part.find("=")
    name = part if eq < 0 else part[:eq]
    try:
        decoded = unquote(name)
    except ValueError:  # pragma: no cover - unquote is total on str
        decoded = name
    if _SENSITIVE_QUERY_MARKERS.search(decoded):
        return f"{name}=[REDACTED]"
    if eq < 0:
        return part
    value = part[eq + 1:]
    if _NESTED_SENSITIVE_ASSIGNMENT.search(unquote(value)):
        return f"{name}=[REDACTED]"
    return f"{name}={value}"


def _redact_query_span(span: str) -> str:
    """Split a query/fragment span on `&`/`;` (separators preserved) and mask parts."""
    return "".join(
        token if index % 2 else _redact_query_component(token)
        for index, token in enumerate(re.split(r"([&;])", span))
    )


def _scrub_str(value: str) -> str:
    out = value
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub("[REDACTED]", out)
    return _QUERY_OR_FRAGMENT.sub(lambda m: m.group(0)[0] + _redact_query_span(m.group(0)[1:]), out)


def redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if str(k).lower() in _SECRET_KEYS else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    if isinstance(obj, str):
        return _scrub_str(obj)
    return obj


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


_STALE_LOCK_SECONDS = 120.0


@contextmanager
def _lock(root: Path, timeout: float = 10.0, stale_seconds: float | None = None):
    """Cross-process lock implemented with atomic mkdir plus stale-lock recovery.

    A crashed holder must not brick the workspace: the lock records its owner pid.
    A lock whose owner process is still alive is never reclaimed, regardless of
    age; only a lock whose owner is dead (or unreadable, falling back to the
    lock dir mtime) and older than the staleness horizon is reclaimed.
    `stale_seconds` overrides the module default for fast tests.
    """
    horizon = _STALE_LOCK_SECONDS if stale_seconds is None else stale_seconds
    lock = root / "11_runtime" / ".control-plane.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    while True:
        try:
            lock.mkdir()
            try:
                (lock / "owner").write_text(f"{os.getpid()} {time.time()}\n")
            except OSError:
                pass
            break
        except FileExistsError:
            alive = False
            try:
                pid_s, ts_s = (lock / "owner").read_text().split()
                owner_pid = int(pid_s)
                if _pid_alive(owner_pid):
                    alive = True
                else:
                    alive = (time.time() - float(ts_s)) < horizon
            except (OSError, ValueError):
                try:
                    alive = (time.time() - lock.stat().st_mtime) < horizon
                except OSError:
                    alive = False
            if not alive:
                shutil.rmtree(lock, ignore_errors=True)
                continue
            if time.monotonic() - started >= timeout:
                raise TimeoutError(f"control-plane lock timeout: {lock}")
            time.sleep(0.05)
    try:
        yield
    finally:
        shutil.rmtree(lock, ignore_errors=True)


def _broker_dir() -> Path:
    return Path(__file__).resolve().parent / "broker"


def _broker_socket_hint() -> Path | None:
    """Socket discovery that does not need tools/broker/client.py (broken installs).

    Mirrors `broker.client.broker_path()`: RESEARCH_OS_BROKER_SOCKET wins, else the
    socket under RESEARCH_OS_BROKER_HOME (default ~/.dsh/research-os-broker).
    """
    env = os.environ.get("RESEARCH_OS_BROKER_SOCKET")
    if env:
        return Path(env).expanduser()
    home = os.environ.get("RESEARCH_OS_BROKER_HOME")
    base = Path(home).expanduser() if home else Path.home() / ".dsh" / "research-os-broker"
    return base / "broker.sock"


def broker_consumed_nonces() -> set[str]:
    """Nonces the broker consume ledger holds, or empty when unavailable.

    Same discovery as the client (`RESEARCH_OS_BROKER_SOCKET` else the socket under
    `RESEARCH_OS_BROKER_HOME`, default `~/.dsh/research-os-broker`): the ledger file
    sits next to the socket. Unreadable/missing means "unknown", never an error —
    the local token store remains the primary provenance source.
    """
    home: Path | None = None
    sock_env = os.environ.get("RESEARCH_OS_BROKER_SOCKET")
    home_env = os.environ.get("RESEARCH_OS_BROKER_HOME")
    if sock_env:
        home = Path(sock_env).expanduser().parent
    elif home_env:
        home = Path(home_env).expanduser()
    else:
        home = Path.home() / ".dsh" / "research-os-broker"
    try:
        lines = (home / "tokens.jsonl").read_text(errors="ignore").splitlines()
    except OSError:
        return set()
    nonces: set[str] = set()
    for line in lines:
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict) and rec.get("kind") == "consume":
            nonce = str(rec.get("nonce") or "").strip()
            if nonce:
                nonces.add(nonce)
    return nonces


def broker_client():
    """The broker client module when a broker socket is present, else None.

    The broker (`tools/broker/`) holds the policy snapshot, the signing key and the
    single-use token ledger OUTSIDE the workspace. `None` means no socket is present and
    callers keep the workspace-local behavior (advisory mode, `tools/broker/README.md`);
    a present-but-unreachable socket is NOT "no broker" — callers fail closed on
    `BrokerUnavailable`.

    Only a missing `tools/broker/` DIRECTORY may degrade to advisory local mode (a
    partial workspace copy without the broker). A `tools/broker/` directory whose client
    cannot be imported while a broker socket is present is a broken install: this raises
    (fail closed) instead of silently dropping to the workspace-local trust path.
    """
    if not _broker_dir().is_dir():
        return None
    try:
        from broker import client
    except ImportError as exc:
        hint = _broker_socket_hint()
        if hint is not None and hint.exists():
            raise ValueError(
                "tools/broker/ exists but its client cannot be imported — the broker install "
                f"is broken (fail closed; a broker socket is present at {hint}): {exc} — repair "
                "tools/broker/client.py, or remove the tools/broker directory to run in advisory "
                "local mode") from exc
        return None
    return client if client.available() else None


class ControlPlane:
    """Deep module hiding event storage, state machines, integrity checks and projections."""

    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.rt = self.root / "11_runtime"
        self.events = self.rt / "events.jsonl"
        # Version stamp: every event appended by this control plane records the
        # workspace's OS_VERSION, read once here. Audit treats events without the
        # field as legacy (pre-7.3) and grades their findings as warnings instead
        # of errors; write-side guards always apply to new events.
        try:
            self.os_version = (self.root / "OS_VERSION").read_text(errors="ignore").strip() or "unknown"
        except OSError:
            self.os_version = "unknown"
        self.rt.mkdir(parents=True, exist_ok=True)

    # ---------- ledger primitives ----------
    def _read_events(self) -> list[dict[str, Any]]:
        if not self.events.exists():
            return []
        out: list[dict[str, Any]] = []
        for lineno, line in enumerate(self.events.read_text(errors="strict").splitlines(), 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid event JSON at line {lineno}: {exc}") from exc
            if not isinstance(event, dict):
                raise ValueError(f"event line {lineno} is not an object")
            out.append(event)
        return out

    @staticmethod
    def _event_hash(event: dict[str, Any]) -> str:
        body = {k: v for k, v in event.items() if k != "event_hash"}
        return hashlib.sha256(_json_dump(body).encode("utf-8")).hexdigest()

    def _append_locked(
        self,
        event_type: str,
        entity_type: str,
        entity_id: str,
        *,
        actor: str = "controller",
        reason: str = "",
        evidence_refs: Iterable[str] = (),
        payload: Any = None,
        cycle_id: str | None = None,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        if event_type not in EVENT_TYPES:
            raise ValueError(f"unknown event type: {event_type}")
        refs = list(evidence_refs)
        if event_type not in {"NOTE", "HUMAN_GATE_REQUESTED"} and not entity_id:
            raise ValueError("entity_id required")
        events = self._read_events()
        seq = len(events) + 1
        previous_hash = events[-1].get("event_hash", "GENESIS") if events else "GENESIS"
        event = {
            "event_id": f"EV-{seq:06d}",
            "time": now(),
            "actor": actor,
            "os_version": self.os_version,
            "type": event_type,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "cycle_id": cycle_id,
            "causation_id": causation_id,
            "correlation_id": correlation_id,
            "reason": redact(reason),
            "evidence_refs": refs,
            "payload": redact(payload) if payload is not None else {},
            "prev_hash": previous_hash,
        }
        event["event_hash"] = self._event_hash(event)
        line = _json_dump(event) + "\n"
        fd = os.open(self.events, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        return event

    def append(self, event_type: str, entity_type: str, entity_id: str, **kwargs: Any) -> dict[str, Any]:
        with _lock(self.root):
            event = self._append_locked(event_type, entity_type, entity_id, **kwargs)
        self.refresh()
        return event

    def events_for(self, entity_type: str | None = None, entity_id: str | None = None) -> list[dict[str, Any]]:
        items = self._read_events()
        if entity_type:
            items = [e for e in items if e.get("entity_type") == entity_type]
        if entity_id:
            items = [e for e in items if e.get("entity_id") == entity_id]
        return items

    # ---------- cycle ----------
    def cycle_data(self, cid: str) -> dict[str, Any] | None:
        data: dict[str, Any] | None = None
        for e in self.events_for("cycle", cid):
            if e["type"] == "CYCLE_CREATED":
                data = dict(e.get("payload", {}))
            elif e["type"] == "CYCLE_UPDATED" and data is not None:
                data.update(e.get("payload", {}))
        return data

    def create_cycle(self, cid: str, plan: dict[str, Any], actor: str = "controller") -> dict[str, Any]:
        if not cycle_id_ok(cid):
            raise ValueError("invalid cycle id")
        with _lock(self.root):
            if self.cycle_status(cid) is not None:
                raise ValueError(f"cycle exists: {cid}")
            plan = dict(plan)
            if str(plan.get("status", "PLANNED")) != "PLANNED":
                raise ValueError("new cycle must start PLANNED")
            ctype = str(plan.get("type", ""))
            if ctype not in CYCLE_TYPES:
                raise ValueError("cycle type must be one of " + ", ".join(sorted(CYCLE_TYPES)))
            event = self._append_locked("CYCLE_CREATED", "cycle", cid, actor=actor,
                                        reason="cycle created", payload=plan, cycle_id=cid)
        self.refresh()
        return event

    def cycle_status(self, cid: str) -> str | None:
        status = None
        for e in self.events_for("cycle", cid):
            if e["type"] == "CYCLE_CREATED":
                status = "PLANNED"
            elif e["type"] == "CYCLE_TRANSITIONED":
                status = normalize_cycle_state(e.get("payload", {}).get("to"))
        return status

    def update_cycle(self, cid: str, patch: dict[str, Any], actor: str = "controller") -> dict[str, Any]:
        with _lock(self.root):
            status = self.cycle_status(cid)
            if status is None:
                raise ValueError(f"unknown cycle: {cid}")
            patch = dict(patch)
            if "status" in patch or "id" in patch:
                raise ValueError("cycle status/id are immutable; use lifecycle methods")
            current = self.cycle_data(cid) or {}
            current_snapshot = current.get("knowledge_triage_snapshot")
            if ("objective" in patch and current_snapshot is not None
                    and str(patch["objective"]) != str(current.get("objective"))):
                # A deliberate objective change re-demands: the snapshot follows the
                # NEW objective (recorded in this same update), so the coverage guard
                # still answers the question the cycle now asks. Ambient drift —
                # env, unknowns, last-result — never moves a stored snapshot, and a
                # no-op patch (the identical string) re-freezes nothing: re-demanding
                # on identical text would let post-RUNNING INDEX drift move the
                # frozen goalposts through a one-word-identical update.
                ranked, cap = triage_demands(self.root, str(patch["objective"]))
                patch["knowledge_triage_snapshot"] = {"ranked": ranked, "cap": cap}
            elif "knowledge_triage_snapshot" in patch:
                if current_snapshot is not None and patch["knowledge_triage_snapshot"] != current_snapshot:
                    raise ValueError(
                        "knowledge_triage_snapshot is immutable once recorded at RUNNING — "
                        "later drift cannot move the coverage goalposts on a past cycle"
                    )
            primary = patch.get("primary_hypothesis")
            if primary and str(primary).startswith("H-") and self.hypothesis_status(str(primary)) is None:
                raise ValueError(f"cycle references unknown primary hypothesis: {primary}")
            # Past READY the triage was a RUNNING precondition; a later patch that moves
            # the objective or weakens the triage must clear the same coverage guard with
            # the NEW values, or the guard would be trivially bypassable after RUNNING.
            if status not in {"PLANNED", "READY"} and ("objective" in patch or "knowledge_triage" in patch):
                self._require_triage({**(self.cycle_data(cid) or {}), **patch})
            event = self._append_locked("CYCLE_UPDATED", "cycle", cid, actor=actor,
                                        reason="cycle plan updated", payload=patch, cycle_id=cid)
        self.refresh()
        return event

    def _cycle_dir(self, cid: str) -> Path:
        return self.root / "04_cycles" / cid

    @staticmethod
    def _section_text_in(path: Path, heading: str) -> str:
        """Text under a `## <heading>` section; empty when the section is missing or blank."""
        if not path.is_file():
            return ""
        active = False
        lines: list[str] = []
        for line in path.read_text(errors="ignore").splitlines():
            if line.startswith("## "):
                active = line.strip() == f"## {heading}"
                continue
            if active:
                lines.append(line)
        return "\n".join(lines).strip()

    def _section_text(self, cid: str, filename: str, heading: str) -> str:
        return self._section_text_in(self._cycle_dir(cid) / filename, heading)

    def _require_section(self, cid: str, filename: str, heading: str) -> None:
        if not self._section_text(cid, filename, heading):
            raise ValueError(f"cycle guard: {filename} ## {heading} is empty")

    def _results_refs(self, cid: str) -> list[str]:
        return re.findall(r"\bE-[0-9]{4,}\b", self._section_text(cid, "results.md", "Evidence references"))

    @staticmethod
    def _require_usable_objective(plan: dict[str, Any]) -> None:
        objective = str(plan.get("objective", "")).strip()
        if not objective or objective == "<ONE RESEARCH QUESTION>":
            raise ValueError("cycle guard: plan objective is empty or still the template placeholder")

    def _require_triage(self, plan: dict[str, Any]) -> None:
        """The PULL precondition: every auto-ranked pack must be confirmed or overridden.

        Shape checks first (each line carries pack, verdict USE|SKIP and a real reason),
        then coverage: `knowledge_index.selection_query`/`selection_cap` rank the packs
        exactly as `current-context.md` renders KNOWLEDGE_SELECTION, and every ranked
        pack missing from the triage is named in the refusal — silence about a
        plausibly-relevant pack is the failure mode this guard exists for. Without a
        readable INDEX there is no ranking to check, so the guard fails closed instead
        of passing vacuously.

        Once a cycle has reached RUNNING its `knowledge_triage_snapshot` (demanded
        list + effective cap, frozen at RUNNING time) is the coverage contract — later
        environment or workspace drift cannot move the goalposts.
        """
        triage = plan.get("knowledge_triage")
        if not isinstance(triage, list) or not triage:
            raise ValueError("cycle guard: RUNNING requires knowledge_triage (USE/SKIP per plausibly-relevant pack)")
        covered: set[str] = set()
        for i, entry in enumerate(triage, 1):
            if (not isinstance(entry, dict) or not entry.get("pack")
                    or str(entry.get("verdict", "")).upper() not in TRIAGE_VERDICTS
                    or not str(entry.get("reason", "")).strip()):
                raise ValueError(f"cycle guard: knowledge_triage entry {i} needs pack, verdict USE|SKIP, reason")
            if sentence_too_thin(str(entry.get("reason", ""))):
                raise ValueError(
                    f"cycle guard: knowledge_triage entry {i} reason is too thin — state the pack's "
                    "relevance to this cycle in a real sentence (>= 20 characters, >= 3 words)"
                )
            covered.add(str(entry["pack"]).strip())
        problem = index_problem(self.root)
        if problem:
            raise ValueError(
                "cycle guard: knowledge index missing/unparseable — cannot verify triage coverage "
                f"({problem}); restore 12_knowledge/INDEX.yaml before RUNNING"
            )
        frozen = snapshot_demands(plan.get("knowledge_triage_snapshot"))
        if frozen is not None:
            ranked, cap = frozen
        else:
            ranked, cap = triage_demands(self.root, str(plan.get("objective", "")))
        missing = [name for name in ranked if name not in covered]
        if missing:
            raise ValueError(
                f"cycle guard: knowledge_triage misses auto-ranked packs (relevance-ranked, cap {cap}): "
                f"{', '.join(missing)} — confirm or override each in the cycle knowledge_triage "
                f"(USE/SKIP + reason; auto-ranked for this objective: {', '.join(ranked) or 'none'})"
            )

    def _technique_events(self, cid: str) -> list[dict[str, Any]]:
        return [e for e in self.events_for("technique") if e.get("cycle_id") == cid]

    def _review_axes(self, cid: str) -> dict[str, dict[str, Any]]:
        """Latest review packet per axis: verdict, reviewer, run_id, evidence_quotes."""
        axes: dict[str, dict[str, Any]] = {}
        for e in self.events_for("worker_result"):
            if e.get("cycle_id") != cid:
                continue
            review = (e.get("payload") or {}).get("review") or {}
            axis = str(review.get("axis", "")).lower()
            if axis in {"objective", "method"}:
                axes[axis] = {
                    "verdict": str(review.get("verdict", "")).lower(),
                    "reviewer": str(review.get("reviewer", "")).strip(),
                    "run_id": str(review.get("run_id", "")).strip(),
                    "evidence_quotes": review.get("evidence_quotes"),
                    "attestation": review.get("attestation"),
                }
        return axes

    def _require_reviews(self, cid: str) -> None:
        latest = self._review_axes(cid)
        missing = [a for a in ("objective", "method") if latest.get(a, {}).get("verdict") != "pass"]
        if missing:
            current = {a: latest.get(a, {}).get("verdict", "none") for a in ("objective", "method")}
            raise ValueError(
                "cycle guard: REVIEWED requires independent review packets — researchctl worker "
                "with review.axis=objective and review.axis=method, latest verdict=pass "
                f"(current: {current}; missing/not-pass: {', '.join(missing)})"
            )
        reviewers = {a: latest[a]["reviewer"] for a in ("objective", "method")}
        if not all(reviewers.values()):
            raise ValueError(
                "cycle guard: review packets need an explicit review.reviewer identity — "
                f"objective={reviewers['objective'] or 'missing'}, method={reviewers['method'] or 'missing'}"
            )
        folded_reviewers = {a: reviewers[a].strip().casefold() for a in ("objective", "method")}
        if folded_reviewers["objective"] == folded_reviewers["method"]:
            raise ValueError(
                "cycle guard: the two review axes must come from distinct reviewers — "
                f"both came from '{reviewers['objective']}'. Dispatch the second axis as a separate run."
            )
        run_ids = {a: str(latest[a].get("run_id", "")).strip() for a in ("objective", "method")}
        if not all(run_ids.values()):
            raise ValueError(
                "cycle guard: review packets need a review.run_id — the identity of the reviewing run "
                f"(objective={run_ids['objective'] or 'missing'}, method={run_ids['method'] or 'missing'}); "
                "a review by the same run as the work is not independent"
            )
        folded_runs = {a: run_ids[a].casefold() for a in ("objective", "method")}
        if folded_runs["objective"] == folded_runs["method"]:
            raise ValueError(
                "cycle guard: the two review axes must come from distinct runs — "
                f"both carry run_id '{run_ids['objective']}'. Dispatch the second axis in a separate run."
            )
        if broker_client() is not None:
            attestations = {a: latest[a].get("attestation") for a in ("objective", "method")}
            if any(not isinstance(att, dict) for att in attestations.values()):
                missing = sorted(a for a in ("objective", "method")
                                 if not isinstance(attestations[a], dict))
                raise ValueError(
                    "cycle guard: the policy broker is running, so each review axis needs a "
                    f"broker-attested voucher (review.attestation) — missing on: {', '.join(missing)}; "
                    "issue one per axis via `researchctl review-issue packet.json`"
                )
            nonces = {a: str(attestations[a].get("nonce") or "") for a in ("objective", "method")}
            if not all(nonces.values()) or nonces["objective"] == nonces["method"]:
                raise ValueError(
                    "cycle guard: the two review axes must carry distinct single-use broker "
                    "vouchers — the attestations share a nonce, so one voucher was reused"
                )

    def _validate_review_quotes(self, quotes: list[Any], packet_refs: list[str]) -> None:
        """Every quote must be a substring of the registered store copy — never the living file."""
        index = self.evidence_index()
        for i, item in enumerate(quotes, 1):
            problem = review_quote_problem(self.root, index, item, i, allowed_refs=packet_refs)
            if problem:
                raise ValueError(problem)

    def transition_cycle(self, cid: str, to_state: str, *, reason: str,
                         evidence_refs: Iterable[str] = (), actor: str = "controller") -> dict[str, Any]:
        """Canonical cycle transition. Every guard lives here — adapters stay thin.

        Guards previously split between cycle.py and this class were bypassable by any
        caller of the canonical seam; the seam now owns the full contract: plan fields,
        cycle markdown artifacts, knowledge triage, evidence refs and technique
        evaluation. Evidence refs not passed explicitly are resolved from
        results.md ## Evidence references.
        """
        with _lock(self.root):
            cur = self.cycle_status(cid)
            if cur is None:
                raise ValueError(f"unknown cycle: {cid}")
            if to_state == "VERIFIED":
                raise ValueError(
                    "cycle terminal state is REVIEWED (both review axes pass + instrument validation); "
                    "VERIFIED is the hypothesis/finding state — use `researchctl cycle transition "
                    f"{cid} REVIEWED` and leave findings to the hypothesis lifecycle"
                )
            if to_state not in CYCLE_EDGES.get(cur, set()):
                raise ValueError(f"forbidden transition {cur} -> {to_state}")
            plan = self.cycle_data(cid) or {}
            refs = list(evidence_refs) or self._results_refs(cid)
            self._validate_refs(refs)
            if to_state in {"RUNNING", "BLOCKED"} and cur == "RESULT_READY" and not refs:
                raise ValueError(
                    f"RESULT_READY -> {to_state} back-edge requires evidence refs — record what the "
                    "result state missed (cite E-ids in results.md) before resuming or blocking"
                )
            if to_state == "READY":
                self._require_plan(plan, ("objective", "allowed_scope", "stop_conditions"))
                self._require_usable_objective(plan)
                if not plan.get("allowed_scope") or not plan.get("stop_conditions"):
                    raise ValueError("cycle READY requires non-empty allowed_scope and stop_conditions")
                if cur in {"BLOCKED", "NEEDS_PIVOT"} and not refs:
                    raise ValueError("re-entering READY from BLOCKED/NEEDS_PIVOT requires unblock/pivot evidence")
            if to_state == "RUNNING":
                self._require_plan(plan, ("objective", "allowed_scope", "stop_conditions"))
                self._require_usable_objective(plan)
                self._require_triage(plan)
                self._require_section(cid, "objective.md", "Question")
                self._require_section(cid, "objective.md", "Minimal test")
                if snapshot_demands(plan.get("knowledge_triage_snapshot")) is None:
                    ranked, cap = triage_demands(self.root, str(plan.get("objective", "")))
                    self._append_locked("CYCLE_UPDATED", "cycle", cid, actor=actor,
                                        reason="triage demands snapshotted at RUNNING (ranked packs + effective cap)",
                                        payload={"knowledge_triage_snapshot": {"ranked": ranked, "cap": cap}},
                                        cycle_id=cid)
            if to_state == "RESULT_READY":
                if not refs:
                    raise ValueError("RESULT_READY requires evidence refs (cite E-ids in results.md)")
                self._require_section(cid, "results.md", "Disposition")
            if to_state in {"REVIEWED", "FALSE_POSITIVE", "NOT_APPLICABLE"}:
                if not refs:
                    raise ValueError(f"{to_state} requires evidence refs")
                self._require_section(cid, "results.md", "Interpretation")
                if to_state == "REVIEWED":
                    self._require_section(cid, "results.md", "Instrument validation")
                    self._require_reviews(cid)
                if not plan.get("result_summary"):
                    derived = self._section_text(cid, "results.md", "Interpretation")
                    if not derived:
                        raise ValueError(f"{to_state} requires plan.result_summary or a filled Interpretation section")
                    self._append_locked("CYCLE_UPDATED", "cycle", cid, actor=actor,
                                        reason="result_summary derived from results.md Interpretation",
                                        payload={"result_summary": derived}, cycle_id=cid)
            if to_state == "CLOSED":
                if not refs:
                    raise ValueError("CLOSED requires evidence refs")
                self._require_section(cid, "results.md", "New hypotheses")
                self._require_section(cid, "results.md", "Next step")
                if not self._technique_events(cid):
                    raise ValueError("CLOSED requires at least one TECHNIQUE_EVALUATED event for this cycle (researchctl technique evaluate)")
            event = self._append_locked("CYCLE_TRANSITIONED", "cycle", cid, actor=actor, reason=reason,
                                        evidence_refs=refs, payload={"from": cur, "to": to_state}, cycle_id=cid)
        self.refresh()
        return event

    @staticmethod
    def _require_plan(plan: dict[str, Any], keys: Iterable[str]) -> None:
        missing = [k for k in keys if not plan.get(k)]
        if missing:
            raise ValueError("cycle plan missing: " + ", ".join(missing))

    # ---------- hypothesis ----------
    def hypothesis_data(self, hid: str) -> dict[str, Any] | None:
        data: dict[str, Any] | None = None
        for e in self.events_for("hypothesis", hid):
            if e["type"] == "HYPOTHESIS_CREATED":
                data = dict(e.get("payload", {}))
            elif e["type"] == "HYPOTHESIS_UPDATED" and data is not None:
                data.update(e.get("payload", {}))
        return data

    def create_hypothesis(self, hid: str, data: dict[str, Any], actor: str = "controller") -> dict[str, Any]:
        if not hyp_id_ok(hid):
            raise ValueError("invalid hypothesis id")
        with _lock(self.root):
            if self.hypothesis_status(hid) is not None:
                raise ValueError(f"hypothesis exists: {hid}")
            data = dict(data)
            data.setdefault("status", "CANDIDATE")
            if data["status"] != "CANDIDATE":
                raise ValueError("new hypothesis must start CANDIDATE")
            cycle_id = data.get("cycle_id")
            if cycle_id and self.cycle_status(str(cycle_id)) is None:
                raise ValueError(f"hypothesis references unknown cycle: {cycle_id}")
            required = ["observation", "hypothesis", "secure_prediction", "vulnerable_prediction"]
            missing = [k for k in required if not data.get(k)]
            if missing:
                raise ValueError("hypothesis missing: " + ", ".join(missing))
            event = self._append_locked("HYPOTHESIS_CREATED", "hypothesis", hid, actor=actor,
                                        reason="hypothesis created", payload=data, cycle_id=data.get("cycle_id"))
        self.refresh()
        return event

    def hypothesis_status(self, hid: str) -> str | None:
        # Event-sourced like cycle_status: CREATED sets the initial status,
        # TRANSITIONED moves it. (HYPOTHESIS_UPDATED cannot change status.)
        # Previously this read only the CREATED/UPDATED payload, so every
        # transitioned hypothesis still reported its birth status and all
        # post-QUEUED edges were unreachable. Audit and projections already
        # use event-sourced status; this aligns the state machine with them.
        status = None
        created = False
        for e in self.events_for("hypothesis", hid):
            if e["type"] == "HYPOTHESIS_CREATED":
                created = True
                status = str(e.get("payload", {}).get("status", "CANDIDATE"))
            elif e["type"] == "HYPOTHESIS_TRANSITIONED":
                status = e.get("payload", {}).get("to")
        return status if created else None

    def update_hypothesis(self, hid: str, patch: dict[str, Any], actor: str = "controller") -> dict[str, Any]:
        with _lock(self.root):
            if self.hypothesis_status(hid) is None:
                raise ValueError(f"unknown hypothesis: {hid}")
            patch = dict(patch)
            if "status" in patch or "id" in patch:
                raise ValueError("hypothesis status/id are immutable; use lifecycle methods")
            event = self._append_locked("HYPOTHESIS_UPDATED", "hypothesis", hid, actor=actor,
                                        reason="hypothesis updated", payload=patch, cycle_id=self.entity_cycle("hypothesis", hid))
        self.refresh()
        return event

    def transition_hypothesis(self, hid: str, to_state: str, *, reason: str,
                              evidence_refs: Iterable[str] = (), actor: str = "controller") -> dict[str, Any]:
        refs = list(evidence_refs)
        with _lock(self.root):
            cur = self.hypothesis_status(hid)
            if cur is None:
                raise ValueError(f"unknown hypothesis: {hid}")
            if to_state not in HYP_EDGES.get(cur, set()):
                raise ValueError(f"forbidden hypothesis transition {cur} -> {to_state}")
            self._validate_refs(refs)
            data = self.hypothesis_data(hid) or {}
            if to_state == "QUEUED" and not data.get("test_question"):
                raise ValueError("QUEUED hypothesis requires test_question")
            if to_state == "TESTING" and not data.get("test_plan"):
                raise ValueError("TESTING hypothesis requires test_plan")
            if to_state in {"VERIFIED", "FALSE_POSITIVE", "NOT_APPLICABLE"} and not refs:
                raise ValueError(f"{to_state} hypothesis transition requires evidence refs")
            if to_state == "NOT_APPLICABLE":
                absence = str(data.get("precondition_absence", "")).strip()
                if not absence:
                    raise ValueError(
                        "NOT_APPLICABLE requires precondition_absence on the hypothesis — record the absent "
                        "precondition (version/config/protocol state) via update_hypothesis; use BLOCKED for "
                        "budget or instrument stops"
                    )
                if sentence_too_thin(absence):
                    raise ValueError(
                        "NOT_APPLICABLE requires a real precondition_absence sentence (>= 20 characters and "
                        ">= 3 words after stripping, naming the absent version/config/protocol state) — got "
                        f"{absence!r}; placeholders do not name a precondition. Use BLOCKED for budget or "
                        "instrument stops"
                    )
            if to_state == "CLOSED" and not data.get("learning"):
                raise ValueError("CLOSED hypothesis requires learning")
            event = self._append_locked("HYPOTHESIS_TRANSITIONED", "hypothesis", hid, actor=actor, reason=reason,
                                        evidence_refs=refs, payload={"from": cur, "to": to_state},
                                        cycle_id=self.entity_cycle("hypothesis", hid))
        self.refresh()
        return event

    def entity_cycle(self, entity_type: str, entity_id: str) -> str | None:
        for e in reversed(self.events_for(entity_type, entity_id)):
            if e.get("cycle_id"):
                return e["cycle_id"]
        return None

    # ---------- evidence ----------
    def _validate_refs(self, refs: Iterable[str]) -> None:
        refs = list(refs)
        known = self.evidence_index()
        bad = [r for r in refs if not evidence_id_ok(r) or r not in known]
        if bad:
            raise ValueError("unknown evidence refs: " + ", ".join(bad))

    def register_evidence(self, path: str, *, kind: str, source: str, cycle_id: str | None = None,
                          actor: str = "controller") -> dict[str, Any]:
        p = (self.root / path).resolve()
        try:
            p.relative_to(self.root)
        except ValueError as exc:
            raise ValueError("evidence path must be inside engagement root") from exc
        if not p.is_file():
            raise ValueError(f"evidence file missing: {path}")
        if cycle_id and self.cycle_status(str(cycle_id)) is None:
            raise ValueError(f"evidence references unknown cycle: {cycle_id}")
        suffix = "".join(p.suffixes)[:16]
        with _lock(self.root):
            # Snapshot-first registration: the source is copied to a temp file inside
            # the store, fsynced and closed; the COPY is hashed and sized, then
            # atomically renamed onto <digest><suffix>. The recorded digest always
            # describes the stored bytes (a source mutated mid-registration cannot
            # desynchronize them), and an existing destination with different bytes
            # is a tamper signal — refused, never silently kept.
            store_dir = self.root / EVIDENCE_STORE
            store_dir.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(dir=str(store_dir), prefix=".register-", suffix=".tmp")
            try:
                with os.fdopen(fd, "wb") as tmp:
                    with p.open("rb") as src:
                        shutil.copyfileobj(src, tmp)
                    tmp.flush()
                    os.fsync(tmp.fileno())
                digest = sha256_file(Path(tmp_name))
                size = Path(tmp_name).stat().st_size
                store_rel = f"{EVIDENCE_STORE}/{digest}{suffix}"
                store_abs = self.root / store_rel
                if store_abs.exists():
                    if sha256_file(store_abs) != digest:
                        raise ValueError(
                            f"evidence store destination {store_rel} holds different bytes — "
                            "the snapshot was tampered with; remove it after investigation, "
                            "then re-register")
                else:
                    os.replace(tmp_name, store_abs)
            finally:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
            events = self._read_events()
            n = sum(1 for e in events if e.get("type") == "EVIDENCE_REGISTERED") + 1
            ref = f"E-{n:06d}"
            meta = {
                "id": ref,
                "path": p.relative_to(self.root).as_posix(),
                "store_path": store_rel,
                "kind": kind,
                "source": source,
                "sha256": digest,
                "bytes": size,
            }
            event = self._append_locked("EVIDENCE_REGISTERED", "evidence", ref, actor=actor,
                                        reason="evidence registered", payload=meta, cycle_id=cycle_id)
        self.refresh()
        return event

    def evidence_index(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for e in self._read_events():
            if e.get("type") != "EVIDENCE_REGISTERED":
                continue
            payload = e.get("payload", {})
            eid = payload.get("id", e.get("entity_id"))
            if eid:
                out[eid] = payload
        return out

    # ---------- technique evaluation ----------
    def evaluate_technique(self, payload: dict[str, Any], actor: str = "controller") -> dict[str, Any]:
        """Record one technique outcome as a canonical event.

        The OS projects technique-discoveries.md and last-result.md from these events;
        the agent reports the outcome, it does not hand-edit the learning files.

        A payload carrying the `_draft` marker (from the labeling aid, `ts_label`) is
        refused: drafts are reviewed and confirmed by the controller first
        (`researchctl technique confirm <file>`), which strips the marker — a draft can
        never be recorded as-is.
        """
        data = dict(payload)
        if "_draft" in data:
            raise ValueError(
                "technique evaluation payload is a draft (_draft present) — review it and "
                "confirm via `researchctl technique confirm <file>`; drafts are never "
                "recorded as-is"
            )
        cid = str(data.get("cycle_id", ""))
        if self.cycle_status(cid) in {None, "CLOSED"}:
            raise ValueError("technique evaluation must reference an existing non-closed cycle")
        result = str(data.get("result", "")).upper()
        if result not in TECHNIQUE_RESULTS:
            raise ValueError("technique result must be one of " + ", ".join(sorted(TECHNIQUE_RESULTS)))
        for key in ("technique_family", "interpretation", "learning"):
            if not str(data.get(key, "")).strip():
                raise ValueError(f"technique evaluation requires {key}")
        refs = list(data.get("evidence_refs", []))
        if not refs:
            raise ValueError("technique evaluation requires evidence_refs")
        data["result"] = result
        packs = data.get("knowledge_packs")
        if packs is not None:
            if not isinstance(packs, list) or any(not isinstance(p, str) for p in packs):
                raise ValueError("technique evaluation knowledge_packs must be a list of pack names")
            problem = index_problem(self.root)
            if problem:
                raise ValueError(
                    "knowledge index missing/unparseable — cannot validate knowledge_packs "
                    f"({problem})"
                )
            named = [p.strip() for p in packs]
            known = set(self.indexed_packs())
            bad = [p or "<empty>" for p in named if p not in known]
            if bad:
                raise ValueError(
                    f"unknown knowledge pack in knowledge_packs: {', '.join(bad)} — "
                    "cite packs listed in 12_knowledge/INDEX.yaml"
                )
            data["knowledge_packs"] = named
        with _lock(self.root):
            self._validate_refs(refs)
            events = self._read_events()
            n = sum(1 for e in events if e.get("type") == "TECHNIQUE_EVALUATED") + 1
            tid = str(data.get("id") or f"T-{n:06d}")
            if any(e.get("type") == "TECHNIQUE_EVALUATED" and e.get("entity_id") == tid for e in events):
                raise ValueError(f"technique evaluation exists: {tid}")
            data["id"] = tid
            event = self._append_locked("TECHNIQUE_EVALUATED", "technique", tid, actor=actor,
                                        reason=f"technique evaluated: {result}", evidence_refs=refs,
                                        payload=data, cycle_id=cid)
        self.refresh()
        return event

    # ---------- knowledge lifecycle: usage telemetry + reviewed promotion ----------
    def indexed_packs(self) -> list[str]:
        """Pack names listed in 12_knowledge/INDEX.yaml, sorted; [] when unreadable."""
        idx = self.root / "12_knowledge" / "INDEX.yaml"
        if not idx.is_file() or index_problem(self.root):
            return []
        return sorted(parse_index(idx))

    def knowledge_usage(self) -> dict[str, Any]:
        """Per-pack disposition and citation counters derived from the existing ledger.

        One disposition per (cycle, pack): the latest CYCLE_CREATED/CYCLE_UPDATED
        `knowledge_triage` list for a cycle replaces the earlier list (CYCLE_UPDATED can
        rewrite triage) and the latest row for a duplicate pack inside a list wins, so a
        pack counts at most once per cycle. A row counts only when complete: pack a
        non-empty string (a non-string pack is skipped, never stringified), verdict in
        USE/SKIP and a non-empty reason. Citations come from the optional
        `knowledge_packs` list on TECHNIQUE_EVALUATED payloads, deduplicated per event
        (set semantics) and attributed to the event's cycle. Indexed packs with no events
        stay at zero, which is what makes "never considered" visible.
        """
        use: dict[str, int] = {}
        skip: dict[str, int] = {}
        cited: dict[str, int] = {}
        last_used: dict[str, str] = {}
        last_cited: dict[str, str] = {}
        cycles: dict[str, list[str]] = {}
        cited_cycles: dict[str, list[str]] = {}
        per_cycle: dict[str, dict[str, dict[str, Any]]] = {}

        def note(store: dict[str, str], pack: str, when: Any) -> None:
            if when and (pack not in store or str(when) > store[pack]):
                store[pack] = str(when)

        def note_cycle(store: dict[str, list[str]], pack: str, cid: str) -> None:
            if cid and cid not in store.setdefault(pack, []):
                store[pack].append(cid)

        for e in self._read_events():
            etype = e.get("type")
            if etype in {"CYCLE_CREATED", "CYCLE_UPDATED"}:
                triage = (e.get("payload") or {}).get("knowledge_triage")
                if not isinstance(triage, list):
                    continue
                cid = str(e.get("cycle_id") or e.get("entity_id") or "")
                rows: dict[str, dict[str, Any]] = {}
                for entry in triage:
                    if not isinstance(entry, dict):
                        continue
                    pack = entry.get("pack")
                    verdict = entry.get("verdict")
                    reason = entry.get("reason")
                    if not isinstance(pack, str) or not pack.strip():
                        continue
                    if not isinstance(verdict, str) or verdict.strip().upper() not in TRIAGE_VERDICTS:
                        continue
                    if not isinstance(reason, str) or not reason.strip():
                        continue
                    rows[pack.strip()] = {"verdict": verdict.strip().upper(), "time": e.get("time")}
                per_cycle[cid] = rows
            elif etype == "TECHNIQUE_EVALUATED":
                packs = (e.get("payload") or {}).get("knowledge_packs")
                if not isinstance(packs, list):
                    continue
                cid = str(e.get("cycle_id") or "")
                for name in sorted({p.strip() for p in packs
                                    if isinstance(p, str) and p.strip()}):
                    cited[name] = cited.get(name, 0) + 1
                    note(last_cited, name, e.get("time"))
                    note_cycle(cited_cycles, name, cid)

        for cid, rows in per_cycle.items():
            for pack, row in rows.items():
                note_cycle(cycles, pack, cid)
                if row["verdict"] == "USE":
                    use[pack] = use.get(pack, 0) + 1
                    note(last_used, pack, row["time"])
                else:
                    skip[pack] = skip.get(pack, 0) + 1

        names = sorted(set(self.indexed_packs()) | set(use) | set(skip) | set(cited)
                       | set(cycles) | set(cited_cycles))
        packs = {
            name: {
                "use": use.get(name, 0),
                "skip": skip.get(name, 0),
                "cited": cited.get(name, 0),
                "last_used": last_used.get(name),
                "last_cited": last_cited.get(name),
                "cycles": cycles.get(name, []),
                "cited_cycles": cited_cycles.get(name, []),
            }
            for name in names
        }
        return {
            "totals": {"use": sum(use.values()), "skip": sum(skip.values()), "cited": sum(cited.values())},
            "packs": packs,
        }

    def _write_knowledge_usage_projection(self) -> None:
        usage = self.knowledge_usage()
        p = self.root / "10_learning" / "knowledge-usage.yaml"
        p.parent.mkdir(parents=True, exist_ok=True)
        lines = [GENERATED_HEADER, "totals:"]
        for key in ("use", "skip", "cited"):
            lines.append(f"  {key}: {usage['totals'][key]}")
        if not usage["packs"]:
            lines.append("packs: {}")
        else:
            lines.append("packs:")
            for name, row in usage["packs"].items():
                lines.append(f"  {json.dumps(name)}:")
                for key in ("use", "skip", "cited"):
                    lines.append(f"    {key}: {row[key]}")
                lines.append(f"    last_used: {json.dumps(row['last_used'])}")
                lines.append(f"    last_cited: {json.dumps(row['last_cited'])}")
                lines.append(f"    cycles: {json.dumps(row['cycles'])}")
                lines.append(f"    cited_cycles: {json.dumps(row['cited_cycles'])}")
        p.write_text("\n".join(lines) + "\n")

    def knowledge_propose(self, payload: dict[str, Any], actor: str = "controller") -> dict[str, Any]:
        """Write a proposal file and record KNOWLEDGE_PROPOSED.

        The proposal is the reviewable artifact: title and body are redacted before they
        reach disk (the ledger redacts on write, so file and ledger must agree) and must be
        real content, the pack must exist, the optional technique_ref must name a recorded
        technique, and an optional recheck_date must be a future YYYY-MM-DD. The event
        snapshots every INDEX-declared pack file digest plus the artifact digest, so APPLIED
        can later prove a CONTENT change — a timestamp touch is not an edit. Ids run KP-0001
        upward from the recorded count and skip any collision, so a retry after a partial
        failure lands on the same id.
        """
        data = dict(payload)
        problem = index_problem(self.root)
        if problem:
            raise ValueError(
                f"knowledge index missing/unparseable — cannot validate pack ({problem})"
            )
        pack = str(data.get("pack", "")).strip()
        if pack not in self.indexed_packs():
            raise ValueError(
                f"unknown knowledge pack: {pack or '<empty>'} — not listed in 12_knowledge/INDEX.yaml"
            )
        title = redact(str(data.get("title", "")).strip())
        if sentence_too_thin(title):
            raise ValueError(
                "knowledge proposal title must be a real sentence (>= 20 characters, >= 3 words) — "
                "name what the pack should record"
            )
        body = redact(str(data.get("body", "")).strip())
        if len(body) < KNOWLEDGE_PROPOSAL_BODY_MIN:
            raise ValueError(
                f"knowledge proposal body must be at least {KNOWLEDGE_PROPOSAL_BODY_MIN} characters "
                "of real content — the proposal is the reviewable artifact"
            )
        technique_ref = str(data.get("technique_ref") or "").strip()
        if technique_ref and not any(
            e.get("type") == "TECHNIQUE_EVALUATED" and e.get("entity_id") == technique_ref
            for e in self.events_for("technique", technique_ref)
        ):
            raise ValueError(
                f"unknown technique_ref: {technique_ref} — record the technique first with "
                "researchctl technique evaluate"
            )
        refs = [str(r) for r in (data.get("evidence_refs") or [])]
        recheck = str(data.get("recheck_date") or "").strip()
        if recheck:
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", recheck):
                raise ValueError("recheck_date must be YYYY-MM-DD")
            today = datetime.now(timezone.utc).date()
            if datetime.strptime(recheck, "%Y-%m-%d").date() <= today:
                raise ValueError(f"recheck_date must be in the future (today: {today.isoformat()})")
        pack_digests: dict[str, str] = {}
        for declared in parse_index(self.root / "12_knowledge" / "INDEX.yaml").get(pack, ([], []))[1]:
            target = resolve_ref(self.root, pack, declared)
            if target is None:
                raise ValueError(
                    f"pack {pack} declares unreadable/missing file {declared} — repair "
                    f"12_knowledge/{pack}/{declared} before proposing"
                )
            pack_digests[str(declared)] = sha256_file(target)
        if not pack_digests:
            raise ValueError(
                f"pack {pack} declares no files in 12_knowledge/INDEX.yaml — index the pack "
                "content before proposing a change to it"
            )
        slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:60].strip("-") or "proposal"
        with _lock(self.root):
            self._validate_refs(refs)
            events = self._read_events()
            taken = {str(e.get("entity_id")) for e in events if e.get("type") == "KNOWLEDGE_PROPOSED"}
            n = sum(1 for e in events if e.get("type") == "KNOWLEDGE_PROPOSED") + 1
            directory = self.root / "10_learning" / "knowledge-proposals"
            while True:
                kp_id = f"KP-{n:04d}"
                if kp_id not in taken and not list(directory.glob(f"{kp_id}-*.md")):
                    break
                n += 1
            created = now()
            rel = f"10_learning/knowledge-proposals/{kp_id}-{slug}.md"
            front = {
                "id": kp_id, "pack": pack, "title": title, "created": created,
                "status": "PROPOSED", "technique_ref": technique_ref or None,
                "evidence_refs": refs, "recheck_date": recheck or None,
            }
            artifact = "\n".join(
                ["---"] + [f"{k}: {json.dumps(v)}" for k, v in front.items()] + ["---", "", body, ""])
            body_sha256 = hashlib.sha256(artifact.encode("utf-8")).hexdigest()
            directory.mkdir(parents=True, exist_ok=True)
            (self.root / rel).write_text(artifact)
            event = self._append_locked(
                "KNOWLEDGE_PROPOSED", "knowledge_proposal", kp_id, actor=actor,
                reason=f"knowledge proposed for pack {pack}", evidence_refs=refs,
                payload={**front, "proposal_path": rel, "body_sha256": body_sha256,
                         "pack_digests": pack_digests})
        self.refresh()
        return event

    def _knowledge_proposal_rows(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        proposals: dict[str, dict[str, Any]] = {}
        for e in events:
            if e.get("type") == "KNOWLEDGE_PROPOSED":
                p = e.get("payload") or {}
                pid = str(p.get("id") or e.get("entity_id"))
                proposals[pid] = {
                    "id": pid, "pack": p.get("pack"), "title": p.get("title"),
                    "proposal_path": p.get("proposal_path"), "technique_ref": p.get("technique_ref"),
                    "evidence_refs": p.get("evidence_refs") or [], "recheck_date": p.get("recheck_date"),
                    "created": p.get("created") or e.get("time"), "status": "PROPOSED",
                    "body_sha256": p.get("body_sha256"), "pack_digests": p.get("pack_digests"),
                    "reference": None, "resolved": None,
                }
            elif e.get("type") == "KNOWLEDGE_RESOLVED":
                p = e.get("payload") or {}
                pid = str(p.get("id") or e.get("entity_id"))
                if pid in proposals:
                    decision = str(p.get("decision") or "").strip().upper()
                    proposals[pid]["status"] = (
                        decision if decision in KNOWLEDGE_RESOLUTIONS else "INVALID")
                    proposals[pid]["reference"] = p.get("reference")
                    proposals[pid]["resolved"] = e.get("time")
        return [proposals[pid] for pid in sorted(proposals)]

    def _write_knowledge_proposal_projection(self, events: list[dict[str, Any]]) -> None:
        p = self.root / "10_learning" / "knowledge-proposals.yaml"
        p.parent.mkdir(parents=True, exist_ok=True)
        lines = [GENERATED_HEADER]
        rows = self._knowledge_proposal_rows(events)
        if not rows:
            lines.append("proposals: []")
        else:
            lines.append("proposals:")
            lines.extend("  - " + json.dumps(row, ensure_ascii=False) for row in rows)
        p.write_text("\n".join(lines) + "\n")

    def knowledge_proposals(self) -> list[dict[str, Any]]:
        """Read the proposals projection; absent, compute rows in memory — never mutate.

        The read path is used by the audit, so it must not persist anything: the
        projection is rendered by refresh(), and a workspace without projections gets
        the ledger-derived view without side effects. Latest resolution wins.
        """
        p = self.root / "10_learning" / "knowledge-proposals.yaml"
        if p.is_file():
            rows = self._parse_knowledge_proposal_projection(p)
        else:
            rows = self._knowledge_proposal_rows(self._read_events())
        today = datetime.now(timezone.utc).date().isoformat()
        for row in rows:
            recheck = str(row.get("recheck_date") or "")
            row["overdue"] = bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", recheck)
                                  and recheck < today and row.get("status") == "PROPOSED")
        return rows

    @staticmethod
    def _parse_knowledge_proposal_projection(p: Path) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for lineno, line in enumerate(p.read_text(errors="strict").splitlines(), 1):
            body = line.strip()
            if not body.startswith("- "):
                continue
            try:
                rows.append(json.loads(body[2:]))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"knowledge-proposals projection is malformed at line {lineno}: {exc}"
                ) from exc
        return rows

    def _require_pack_changed(self, row: dict[str, Any]) -> None:
        """APPLIED is only legal after an INDEX-declared pack file's CONTENT changed.

        The proposal snapshotted each declared file's sha256; a matching digest means the
        bytes are identical, so an `utime`/touch (any mtime) is refused. Missing or
        unreadable files are errors, never silently skipped.
        """
        problem = pack_change_problem(self.root, row)
        if problem:
            raise ValueError(problem)

    def knowledge_resolve(self, kp_id: str, decision: str, reference: str,
                          actor: str = "human", gate: str | None = None) -> dict[str, Any]:
        """Record a human resolution; APPLIED additionally proves the pack edit happened.

        `reference` is the recorded friction (a human ticket/message id): a provenance
        string, not cryptographic proof. Passing `gate` binds the resolution to an
        existing RESOLVED human gate and records it; without `gate` the resolution is not
        bound to any gate.
        """
        pid = str(kp_id or "").strip()
        decision = str(decision or "").upper()
        if decision not in KNOWLEDGE_RESOLUTIONS:
            raise ValueError("knowledge resolve decision must be APPLIED or REJECTED")
        reference = str(reference or "").strip()
        if not reference:
            raise ValueError(
                "knowledge resolve requires --reference (a human ticket/message id) — "
                "the resolution is a human decision and must name its source"
            )
        gate_id = str(gate or "").strip()
        if gate_id:
            g = self.gate(gate_id)
            if not g:
                raise ValueError(
                    f"unknown gate: {gate_id} — request it with researchctl gate request"
                )
            if g.get("status") != "RESOLVED":
                raise ValueError(
                    f"gate {gate_id} is not RESOLVED (status: {g.get('status') or 'unknown'}) — "
                    "resolve it with researchctl gate resolve before binding it to a knowledge resolution"
                )
        # Enforcement reads the LEDGER, never the hand-editable projection: a forged
        # knowledge-proposals.yaml row cannot buy an APPLIED the pack never earned.
        ledger_rows = self._knowledge_proposal_rows(self._read_events())
        row = next((r for r in ledger_rows if r.get("id") == pid), None)
        if row is None:
            raise ValueError(f"unknown knowledge proposal: {pid}")
        if decision == "APPLIED":
            self._require_pack_changed(row)
        payload: dict[str, Any] = {"id": pid, "decision": decision, "reference": reference}
        if gate_id:
            payload["gate"] = gate_id
        with _lock(self.root):
            event = self._append_locked(
                "KNOWLEDGE_RESOLVED", "knowledge_proposal", pid, actor=actor,
                reason=f"knowledge proposal {decision.lower()} ({reference})", payload=payload)
        self.refresh()
        return event

    # ---------- engagement scope ----------
    def set_scope(self, assets: list[str], source_reference: str, gate: str | None = None,
                  human_reference: str = "", actor: str = "controller") -> dict[str, Any]:
        """Rewrite the engagement scope block and record its provenance.

        The engagement binding is human-owned and is NOT rebuilt by refresh(); the
        SCOPE_CHANGED event records its history, and this method rewrites the depth-1
        `assets:` entry, every depth-1 `gate:` line and any shadowed duplicate/legacy
        `assets:` occurrence — the postcondition is that `engagement_assets()` returns
        exactly the requested list (see `_write_scope_block`). The rewrite is staged in
        a sibling temp file, fsynced and os.replace'd onto engagement.yaml, and the
        event is appended only after the replace (and the re-parse postcondition) succeed,
        both under the lock.

        `human_reference` is required to re-record or widen a scope that already exists:
        a recorded SCOPE_CHANGED, a non-empty parsed asset list, or an explicit depth-1
        `gate:` line (deliberate configuration). The first bootstrap record on a pristine
        template may omit it.

        When a broker socket is present (tools/broker/), the same record is pushed to the
        broker after the local write; a present-but-failing push raises (fail closed)
        because `prepare_action` refuses while the broker holds no policy for this
        workspace. No socket means advisory local mode.
        """
        reference = str(source_reference or "").strip()
        if not reference:
            raise ValueError("scope-set requires a non-empty source_reference (policy URL/section; never a secret)")
        mode = str(gate or "assets").lower()
        if mode not in {"assets", "none"}:
            raise ValueError("scope-set gate must be 'assets' or 'none'")
        if not isinstance(assets, list):
            raise ValueError("scope-set assets must be a list of strings")
        items: list[str] = []
        for item in assets:
            if not isinstance(item, str):
                raise ValueError(f"scope-set asset {item!r} is not a string")
            if not item or re.search(r"[\s\"'\\#\x00-\x1f\x7f]", item):
                raise ValueError(
                    f"scope-set asset {item!r} is not a plain host/URL string — empty items and "
                    "whitespace, quotes, backslash, '#' and control characters are refused so the "
                    "asset can never inject YAML structure"
                )
            items.append(item)
        if mode == "assets" and not items:
            raise ValueError("scope-set in assets mode requires a non-empty assets list")
        human = str(human_reference or "").strip()
        with _lock(self.root):
            previous = engagement_assets(self.root)
            prior = any(e.get("type") == "SCOPE_CHANGED" for e in self._read_events())
            explicit_gate = _scope_gate_line_present(self.root)
            if not human and (prior or previous or explicit_gate):
                raise ValueError(
                    "scope-set requires human_reference (a ticket/message id from the human who authorized "
                    "the change) — this re-records or widens an existing engagement scope; only the first "
                    "bootstrap record on a pristine template may omit it"
                )
            # The postcondition re-parse lives inside this lock too, so the checked state
            # cannot change between the write and the append.
            self._write_scope_block(items, mode)
            event = self._append_locked(
                "SCOPE_CHANGED", "scope", "engagement", actor=actor,
                reason=f"engagement scope set ({mode})",
                payload={
                    "assets": items,
                    "previous_assets": [] if previous is None else list(previous),
                    "gate": mode,
                    "source_reference": reference,
                    "human_reference": human,
                },
            )
            revision = f"{event['event_id']}:{event['event_hash']}"
        try:
            self._push_broker_policy(items, mode, reference, human, revision)
        except ValueError as exc:
            # The local commit stands; the broker copy is now stale (or was never
            # written). Mark scope-sync DIRTY so browser dispatch refuses until a
            # resync, then re-raise so the CLI reports the failed push.
            self._mark_scope_dirty(revision, str(exc))
            raise
        self._clear_scope_dirty()
        self.refresh()
        return event

    def _push_broker_policy(self, items: list[str], mode: str, reference: str, human: str,
                            revision: str) -> None:
        """Push the recorded scope (and the current budget caps) to the broker when its
        socket is present.

        The local record is written first (it remains the human-visible engagement binding
        and the SCOPE_CHANGED event stands); a present-but-failing push raises, because
        `prepare_action` refuses while a broker socket is present without a matching
        policy — keeping the two copies silently apart is the failure this seam prevents.
        The push carries the SCOPE_CHANGED event identity as `scope_revision`
        (`EV-<sequence>:<hash>`); the broker stores it and refuses updates older than
        the stored revision, so concurrent scope-sets cannot land out of order.
        The budget caps are read at push time (`budget_limits`), so re-running scope-set
        refreshes the broker's enforced limits; a malformed local budget block refuses
        the push rather than storing an uncapped policy.
        """
        client = broker_client()
        if client is None:
            return
        limits = budget_limits(self.root)
        if limits == BUDGET_MALFORMED:
            raise ValueError(
                "the engagement budget block is malformed (fail closed) — repair it with "
                "`researchctl budget set` before the broker policy push; the local SCOPE_CHANGED "
                "record stands, but the broker copy was not updated")
        try:
            response = client.call("policy.put", timeout=5, workspace=str(self.root), assets=items,
                                   gate=mode, source_reference=reference, human_reference=human,
                                   budget=limits, scope_revision=revision)
        except client.BrokerUnavailable as exc:
            raise ValueError(
                f"engagement scope was recorded locally, but the broker policy push failed "
                f"(fail closed): {exc} — start the broker (`researchctl broker serve`) or unset "
                "RESEARCH_OS_BROKER_SOCKET before retrying; prepare refuses while a broker socket "
                "is present without a policy") from exc
        if not response.get("ok"):
            raise ValueError(
                f"the broker refused the policy push (fail closed): {response.get('error')} — "
                "the local SCOPE_CHANGED record stands; repair the broker policy before preparing")

    def _scope_dirty_path(self) -> Path:
        return self.rt / SCOPE_SYNC_DIRTY

    def scope_sync_state(self) -> dict[str, Any] | None:
        """The durable scope-sync DIRTY marker, or None when broker and binding agree."""
        try:
            raw = self._scope_dirty_path().read_text(encoding="utf-8")
        except OSError:
            return None
        try:
            state = json.loads(raw)
        except ValueError:
            return {"revision": "", "reason": "unreadable scope-sync marker", "time": ""}
        return state if isinstance(state, dict) else None

    def _mark_scope_dirty(self, revision: str, reason: str) -> None:
        """Record that the local binding was committed but the broker push failed."""
        try:
            self._scope_dirty_path().write_text(
                _json_dump({"revision": revision, "reason": redact(reason)[:300],
                            "time": now()}),
                encoding="utf-8")
        except OSError as exc:
            print(f"control-plane: WARNING scope-sync DIRTY marker could not be written ({exc}); the broker copy is stale", file=sys.stderr)

    def _clear_scope_dirty(self) -> None:
        try:
            self._scope_dirty_path().unlink(missing_ok=True)
        except OSError:
            pass

    def sync_scope(self, actor: str = "controller") -> dict[str, Any]:
        """Re-push the committed scope binding to the broker and clear DIRTY.

        The resync path for a failed push: reads the live engagement binding (assets,
        gate) and budget caps, and pushes them under the LATEST SCOPE_CHANGED event's
        identity — no new event, no new human_reference (this changes nothing, it
        heals the broker copy). Refuses when no scope was ever recorded
        (`researchctl scope-set` first) or when no broker socket is present (nothing
        to sync to — clears a stale marker and reports local mode).
        """
        latest = None
        for event in self._read_events():
            if event.get("type") == "SCOPE_CHANGED":
                latest = event
        if latest is None:
            raise ValueError(
                "no recorded engagement scope to sync — record it first with "
                "`researchctl scope-set`")
        client = broker_client()
        if client is None:
            self._clear_scope_dirty()
            return {"synced": False, "mode": "local",
                    "note": "no broker socket present — local mode governs, DIRTY cleared"}
        payload = latest.get("payload") or {}
        items = engagement_assets(self.root)
        if items is None:
            raise ValueError(
                "no scope configured — record it with `researchctl scope-set` before syncing")
        if items == []:
            raise ValueError(
                "engagement assets are present but not a simple string list — scope is "
                "unenforceable; repair 00_control/engagement.yaml before syncing")
        mode = str(payload.get("gate") or "assets").lower()
        revision = f"{latest.get('event_id')}:{latest.get('event_hash')}"
        self._push_broker_policy(
            items, mode, str(payload.get("source_reference") or ""),
            str(payload.get("human_reference") or ""), revision)
        self._clear_scope_dirty()
        return {"synced": True, "revision": revision, "assets": items, "gate": mode}

    @staticmethod
    def _leading_ws(line: str) -> str:
        return _leading_ws(line)

    @staticmethod
    def _scope_block_end(lines: list[str], start: int) -> int:
        """First non-blank, non-indented line after `start` (the block boundary)."""
        return _scope_block_end(lines, start)

    @staticmethod
    def _scope_child_indent(lines: list[str], start: int, end: int) -> str:
        """Indentation of the block's first real (non-comment) entry = depth 1."""
        return _scope_child_indent(lines, start, end)

    @staticmethod
    def _scope_item_end(lines: list[str], start: int, end: int) -> int:
        """End of a block list: `-` items plus blank/comment runs followed by more items."""
        j = start
        while j < end:
            raw = lines[j].rstrip("\r\n")
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                look = j + 1
                while look < end and (not lines[look].strip() or lines[look].strip().startswith("#")):
                    look += 1
                if (look < end and lines[look].startswith((" ", "\t"))
                        and lines[look].strip().startswith("-")):
                    j = look
                    continue
                return j
            if raw.startswith((" ", "\t")) and stripped.startswith("-"):
                j += 1
                continue
            return j
        return j

    @staticmethod
    def _legacy_block_end(lines: list[str], start: int) -> int:
        """End of a legacy top-level assets block: `-` items, blank/comment runs."""
        j = start
        while j < len(lines):
            raw = lines[j].rstrip("\r\n")
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                look = j + 1
                while look < len(lines) and (not lines[look].strip() or lines[look].strip().startswith("#")):
                    look += 1
                if look < len(lines) and lines[look].strip().startswith("-"):
                    j = look
                    continue
                return j
            if stripped.startswith("-"):
                j += 1
                continue
            return j
        return j

    @classmethod
    def _top_level_assets_ranges(cls, lines: list[str]) -> list[tuple[int, int]]:
        """Line ranges of every col-0 `assets:` entry (legacy/shadowed duplicates)."""
        ranges: list[tuple[int, int]] = []
        for i, line in enumerate(lines):
            if line.startswith((" ", "\t")):
                continue
            stripped = line.rstrip("\r\n").strip()
            m = re.match(r"assets:\s*(.*?)\s*$", stripped)
            if not m:
                continue
            end = i + 1 if m.group(1) else cls._legacy_block_end(lines, i + 1)
            ranges.append((i, end))
        return ranges

    @staticmethod
    def _splice(lines: list[str], removals: list[tuple[int, int]], insert_at: int,
                replacement: list[str]) -> list[str]:
        """Drop every removal range and insert `replacement` before line `insert_at`."""
        drop = [False] * len(lines)
        for start, end in removals:
            for i in range(start, end):
                drop[i] = True
        out: list[str] = []
        for i, line in enumerate(lines):
            if i == insert_at:
                out.extend(replacement)
            if not drop[i]:
                out.append(line)
        return out

    @staticmethod
    def _atomic_replace(target: Path, text: str, mode_bits: int | None) -> None:
        """Stage `text` in a sibling temp file, fsync and os.replace it onto `target`.

        The temp file carries the original mode (when known) before the rename, so a
        replacement never silently widens or narrows the file permissions.
        """
        fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), prefix=".engagement-", suffix=".yaml")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            if mode_bits is not None:
                os.chmod(tmp_name, mode_bits)
            os.replace(tmp_name, target)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    @staticmethod
    def _scope_block_lines(items: list[str], mode: str, indent: str = "  ", nl: str = "\n") -> list[str]:
        block = [f"{indent}assets:{nl}",
                 *[f"{indent}- {json.dumps(item, ensure_ascii=False)}{nl}" for item in items]]
        if mode == "none":
            block.append(f"{indent}gate: none{nl}")
        return block

    def _write_scope_block(self, items: list[str], mode: str) -> None:
        """Depth-aware line surgery on the top-level `scope:` block, with postcondition.

        The depth-1 `assets:` entry is rewritten and EVERY depth-1 `gate:` line is
        removed (then the requested one is written); nested keys (e.g.
        `exclusions:\\n    gate: strict`) and unrelated bytes survive. Every other
        `assets:` occurrence the parser could see is removed too: duplicate depth-1
        entries inside the `scope:` block and shadowed legacy col-0 `assets:` blocks
        before or after it. A legacy top-level `assets:` entry without a `scope:` block
        is rewritten in place as a `scope:` block; otherwise the block is appended at
        EOF. Line endings are preserved; the write goes through a symlinked target (the
        link survives) carrying the original file mode.

        After the atomic replace the scope is re-parsed inside the caller's lock: when
        `engagement_assets()` no longer equals the requested list, or the gate mode does
        not match the request, the pre-write content is restored and ValueError is
        raised — the writer can never leave a fail-open scope behind.
        """
        path = self.root / "00_control" / "engagement.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        real = Path(os.path.realpath(path))
        try:
            real.relative_to(self.root)
        except ValueError as exc:
            raise ValueError(
                "engagement.yaml resolves outside the engagement root — refusing to follow the symlink"
            ) from exc
        real.parent.mkdir(parents=True, exist_ok=True)
        raw = ""
        mode_bits: int | None = None
        if real.exists():
            with real.open("r", encoding="utf-8", newline="") as fh:
                raw = fh.read()
            mode_bits = stat.S_IMODE(real.stat().st_mode)
        nl = "\r\n" if "\r\n" in raw else "\n"
        lines = raw.splitlines(keepends=True)
        scope_at = next((i for i, line in enumerate(lines)
                         if not line.startswith((" ", "\t"))
                         and re.fullmatch(r"scope:\s*(#.*)?", line.rstrip("\r\n"))), None)
        if scope_at is not None:
            end = self._scope_block_end(lines, scope_at)
            indent = self._scope_child_indent(lines, scope_at, end)
            assets_ranges: list[tuple[int, int]] = []
            gate_positions: list[int] = []
            j = scope_at + 1
            while j < end:
                raw_line = lines[j].rstrip("\r\n")
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("#") or self._leading_ws(raw_line) != indent:
                    j += 1
                    continue
                m = re.match(r"assets:\s*(.*?)\s*$", stripped)
                if m:
                    a_end = j + 1 if m.group(1) else self._scope_item_end(lines, j + 1, end)
                    assets_ranges.append((j, a_end))
                    j = a_end
                    continue
                if re.match(r"gate:", stripped):
                    gate_positions.append(j)
                j += 1
            removals = assets_ranges[1:] + [(g, g + 1) for g in gate_positions]
            removals += self._top_level_assets_ranges(lines)
            if assets_ranges:
                insert_at = assets_ranges[0][0]
                removals.append(assets_ranges[0])
            else:
                insert_at = scope_at + 1
            new_lines = self._splice(lines, removals, insert_at,
                                     self._scope_block_lines(items, mode, indent, nl))
        else:
            legacy = self._top_level_assets_ranges(lines)
            if legacy:
                insert_at = legacy[0][0]
                removals = legacy[1:] + [legacy[0]]
                new_lines = self._splice(lines, removals, insert_at,
                                         [f"scope:{nl}", *self._scope_block_lines(items, mode, "  ", nl)])
            else:
                tail = list(lines)
                if tail and not tail[-1].endswith(("\n", "\r")):
                    tail[-1] += nl
                if tail and tail[-1].strip():
                    tail.append(nl)
                new_lines = [*tail, f"scope:{nl}", *self._scope_block_lines(items, mode, "  ", nl)]
        self._atomic_replace(real, "".join(new_lines), mode_bits)
        try:
            parsed = engagement_assets(self.root)
            gate = scope_check(self.root, "https://scope-postcondition.invalid/")["gate"]
            ok = (parsed or []) == items and gate == ("assets" if mode == "assets" else "disabled")
        except Exception:
            ok = False
        if not ok:
            try:
                self._atomic_replace(real, raw, mode_bits)
            except OSError as exc:
                raise ValueError(
                    "scope-set postcondition failed and the previous engagement.yaml could not be "
                    f"restored: {exc} — inspect 00_control/engagement.yaml before retrying"
                ) from exc
            raise ValueError(
                "scope-set postcondition failed: after the rewrite engagement_assets() does not equal "
                "the requested list or the gate mode does not match (a duplicate or shadowed assets: "
                "occurrence escaped the rewrite); the previous file was restored and no event was recorded"
            )

    # ---------- budget governor ----------
    def _outstanding_tokens(self) -> list[dict[str, Any]]:
        """Latest state per token action_id, keeping only unconsumed, unexpired ones."""
        path = self._tokens_file()
        if not path.exists():
            return []
        states: dict[str, dict[str, Any]] = {}
        for line in path.read_text(errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict) and rec.get("action_id"):
                key = str(rec["action_id"])
                states[key] = {**states.get(key, {}), **rec}
        current = now()
        out: list[dict[str, Any]] = []
        for rec in states.values():
            if rec.get("consumed"):
                continue
            expires = str(rec.get("expires_at") or "")
            # Fail closed: an unreadable expiry counts as outstanding.
            if expires and expires < current:
                continue
            out.append(rec)
        return out

    def action_counts(self) -> dict[str, Any]:
        """Recorded actions plus outstanding preflight tokens, per cycle and engagement.

        The governor's single counting seam: an issued-but-unconsumed token is capacity
        already promised, so it counts against the same cap as a recorded action. And
        consumption never restores headroom: a consumed token with no matching
        ACTION_RECORDED (the executor receipt-failure path — the request may have been
        sent while the receipt write failed) still counts as used.
        """
        cycles: dict[str, int] = {}
        total = 0
        recorded_ids: set[str] = set()
        for e in self._read_events():
            if e.get("type") != "ACTION_RECORDED":
                continue
            cid = str(e.get("cycle_id") or "")
            cycles[cid] = cycles.get(cid, 0) + 1
            total += 1
            recorded_ids.add(str(e.get("entity_id") or ""))
        for rec in self._outstanding_tokens():
            cid = str(rec.get("cycle_id") or "")
            cycles[cid] = cycles.get(cid, 0) + 1
            total += 1
        for rec in self._consumed_unrecorded_tokens(recorded_ids):
            cid = str(rec.get("cycle_id") or "")
            cycles[cid] = cycles.get(cid, 0) + 1
            total += 1
        return {"cycles": cycles, "engagement": total}

    def _consumed_unrecorded_tokens(self, recorded_ids: set[str]) -> list[dict[str, Any]]:
        """Latest state per token action_id, keeping only consumed-but-unrecorded ones.

        The receipt join is keyed by `token_nonce`: a consumed token counts as used
        until an ACTION_RECORDED carries its nonce (the action_id match is kept for
        legacy records that predate the nonce). Either link proves the receipt landed.
        """
        path = self._tokens_file()
        if not path.exists():
            return []
        states: dict[str, dict[str, Any]] = {}
        for line in path.read_text(errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict) and rec.get("action_id"):
                key = str(rec["action_id"])
                states[key] = {**states.get(key, {}), **rec}
        recorded_nonces: set[str] = set()
        for e in self._read_events():
            if e.get("type") != "ACTION_RECORDED":
                continue
            nonce = str((e.get("payload") or {}).get("token_nonce") or "").strip()
            if nonce:
                recorded_nonces.add(nonce)
        out = []
        for key, rec in states.items():
            if not rec.get("consumed") or key in recorded_ids:
                continue
            rec_nonce = str(rec.get("nonce") or rec.get("broker_nonce") or "").strip()
            if rec_nonce and rec_nonce in recorded_nonces:
                continue
            out.append(rec)
        return out

    def budget_status(self) -> dict[str, Any]:
        """Limits, counted actions and remaining capacity — the `budget status` seam.

        `spend` is the Jev cost ledger summary, reported BESIDE the action budget and
        deliberately not folded into `remaining`: the caps count actions, and an
        estimated dollar figure must never consume or relax action capacity.
        """
        limits = budget_limits(self.root)
        if isinstance(limits, str):
            raise ValueError(
                "engagement budget block is malformed — max_actions_per_cycle and "
                "max_actions_per_engagement must be plain non-negative integers; repair it with "
                "`researchctl budget set` (a human_reference is required once limits exist)"
            )
        counts = self.action_counts()
        cap_cycle = (limits or {}).get("max_actions_per_cycle")
        cap_total = (limits or {}).get("max_actions_per_engagement")

        def left(limit: int | None, used: int) -> int | None:
            return None if limit is None else limit - used

        return {
            "limits": limits if limits else None,
            "counts": counts,
            "remaining": {
                "cycles": {cid: left(cap_cycle, used) for cid, used in counts["cycles"].items()},
                "engagement": left(cap_total, counts["engagement"]),
            },
            "spend": cost_summary(self.root),
        }

    def set_budget(self, payload: dict[str, Any], actor: str = "controller") -> dict[str, Any]:
        """Rewrite the top-level `budget:` block and record its provenance.

        Mirrors `set_scope`: same splice/atomic-replace helpers, same in-lock postcondition
        re-parse (a failed write restores the previous file and records no event), and a
        human_reference is required once a prior BUDGET_CHANGED exists or the current
        limits are non-empty — a malformed block counts as configured (fail closed).
        A cap below the current recorded action count is legal and recorded with
        `below_current_count: true`; the audit errs on the over-cap actions until a
        human-approved raise (the CLI warns on that event).
        """
        if not isinstance(payload, dict):
            raise ValueError("budget set payload must be an object")
        new: dict[str, int] = {}
        for key in BUDGET_KEYS:
            value = payload.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(
                    f"budget set requires {key} as a non-negative integer (got {value!r}) — "
                    "the caps are machine-enforced, so a typo must never set them"
                )
            new[key] = value
        reference = str(payload.get("source_reference") or "").strip()
        if not reference:
            raise ValueError("budget set requires a non-empty source_reference (policy URL/section; never a secret)")
        human = str(payload.get("human_reference") or "").strip()
        with _lock(self.root):
            previous = budget_limits(self.root)
            prior = any(e.get("type") == "BUDGET_CHANGED" for e in self._read_events())
            configured = isinstance(previous, str) or (
                isinstance(previous, dict) and any(value is not None for value in previous.values()))
            if not human and (prior or configured):
                raise ValueError(
                    "budget set requires human_reference (a ticket/message id from the human who authorized "
                    "the cap change) — this changes limits that already exist or re-records after a prior "
                    "BUDGET_CHANGED; only the first record on a pristine template may omit it"
                )
            # A cap below the recorded count is legal (the audit will error on the
            # over-cap actions until a human-approved raise) but it is recorded on the
            # event so the CLI can warn instead of letting the lower cap pass silently.
            recorded: dict[str, int] = {}
            for e in self._read_events():
                if e.get("type") == "ACTION_RECORDED":
                    key = str(e.get("cycle_id") or "")
                    recorded[key] = recorded.get(key, 0) + 1
            below_current = (
                new["max_actions_per_cycle"] < max(recorded.values(), default=0)
                or new["max_actions_per_engagement"] < sum(recorded.values())
            )
            event_payload: dict[str, Any] = {
                "previous": previous if isinstance(previous, dict) else None,
                "new": new,
                "source_reference": reference,
                "human_reference": human,
            }
            if below_current:
                event_payload["below_current_count"] = True
            # The postcondition re-parse lives inside this lock too, so the checked state
            # cannot change between the write and the append.
            self._write_budget_block(new)
            event = self._append_locked(
                "BUDGET_CHANGED", "budget", "engagement", actor=actor,
                reason="engagement action budget set",
                payload=event_payload,
            )
        self.refresh()
        return event

    def _write_budget_block(self, limits: dict[str, int]) -> None:
        """Line surgery on the top-level `budget:` block, with a re-parse postcondition.

        Only the two cap entries are rewritten; comments inside and around the block
        and every other byte survive. Duplicate top-level `budget:` blocks are removed
        (the parser reads the first). The write is staged and atomically replaced; when
        the post-write parse does not equal the request the previous content is restored
        and ValueError is raised — a failed write can never leave a raised cap behind.
        """
        path = self.root / "00_control" / "engagement.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        real = Path(os.path.realpath(path))
        try:
            real.relative_to(self.root)
        except ValueError as exc:
            raise ValueError(
                "engagement.yaml resolves outside the engagement root — refusing to follow the symlink"
            ) from exc
        real.parent.mkdir(parents=True, exist_ok=True)
        raw = ""
        mode_bits: int | None = None
        if real.exists():
            with real.open("r", encoding="utf-8", newline="") as fh:
                raw = fh.read()
            mode_bits = stat.S_IMODE(real.stat().st_mode)
        nl = "\r\n" if "\r\n" in raw else "\n"
        lines = raw.splitlines(keepends=True)
        starts = [i for i, line in enumerate(lines)
                  if not line.startswith((" ", "\t"))
                  and re.fullmatch(r"budget:\s*(#.*)?", line.rstrip("\r\n"))]
        if starts:
            start = starts[0]
            end = self._scope_block_end(lines, start)
            indent = self._scope_child_indent(lines, start, end)
            entries: list[int] = []
            j = start + 1
            while j < end:
                raw_line = lines[j].rstrip("\r\n")
                stripped = raw_line.strip()
                if (stripped and not stripped.startswith("#")
                        and self._leading_ws(raw_line) == indent
                        and re.match(r"(max_actions_per_cycle|max_actions_per_engagement):", stripped)):
                    entries.append(j)
                j += 1
            insert_at = entries[0] if entries else start + 1
            removals = [(e, e + 1) for e in entries]
            for extra in starts[1:]:
                removals.append((extra, self._scope_block_end(lines, extra)))
            new_lines = self._splice(lines, removals, insert_at,
                                     self._budget_block_lines(limits, indent, nl))
        else:
            tail = list(lines)
            if tail and not tail[-1].endswith(("\n", "\r")):
                tail[-1] += nl
            if tail and tail[-1].strip():
                tail.append(nl)
            new_lines = [*tail, f"budget:{nl}", *self._budget_block_lines(limits, "  ", nl)]
        self._atomic_replace(real, "".join(new_lines), mode_bits)
        try:
            after = budget_limits(self.root)
        except Exception:
            after = None
        if after != limits:
            try:
                self._atomic_replace(real, raw, mode_bits)
            except OSError as exc:
                raise ValueError(
                    "budget-set postcondition failed and the previous engagement.yaml could not be "
                    f"restored: {exc} — inspect 00_control/engagement.yaml before retrying"
                ) from exc
            raise ValueError(
                "budget-set postcondition failed: after the rewrite budget_limits() does not equal "
                "the requested caps (a duplicate or shadowed budget: block escaped the rewrite); "
                "the previous file was restored and no event was recorded"
            )

    @staticmethod
    def _budget_block_lines(limits: dict[str, int], indent: str = "  ", nl: str = "\n") -> list[str]:
        return [f"{indent}max_actions_per_cycle: {limits['max_actions_per_cycle']}{nl}",
                f"{indent}max_actions_per_engagement: {limits['max_actions_per_engagement']}{nl}"]

    # ---------- action + gate ----------
    def record_action(self, action: dict[str, Any], actor: str = "controller") -> dict[str, Any]:
        required = [
            "target", "scope_status", "account", "object_owner", "purpose", "hypothesis",
            "expected_secure", "expected_vulnerable", "side_effect", "stop_condition",
        ]
        missing = [k for k in required if not action.get(k)]
        if missing:
            raise ValueError("action preflight missing: " + ", ".join(missing))
        if str(action.get("scope_status")).upper() != "IN_SCOPE":
            raise ValueError("action preflight requires scope_status=IN_SCOPE")
        cycle_id = action.get("cycle_id")
        if not cycle_id:
            raise ValueError("live-action preflight requires cycle_id")
        cycle_status = self.cycle_status(str(cycle_id))
        if cycle_status != "RUNNING":
            raise ValueError(f"live-action preflight requires cycle RUNNING, got {cycle_status}")
        hyp = str(action.get("hypothesis", ""))
        if hyp.startswith("H-") and self.hypothesis_status(hyp) is None:
            raise ValueError(f"live-action preflight references unknown hypothesis: {hyp}")
        shape = action.get("request_shape")
        refs = list(action.get("evidence_refs", []))
        with _lock(self.root):
            # The scope re-check runs inside the same critical section as the append:
            # the checked state cannot change between check and record.
            if isinstance(shape, dict) and "url" in shape:
                scope = scope_check(self.root, str(shape.get("url", "")))
                if scope["gate"] == "unenforceable":
                    raise ValueError(
                        "engagement assets are present but not a simple string list; keep "
                        "00_control/engagement.yaml assets as host/URL strings — scope is unenforceable otherwise"
                    )
                if scope["gate"] == "unset":
                    raise ValueError(
                        "no scope configured — record the engagement scope with `researchctl scope-set` "
                        "or set an explicit `gate: none` for non-target work"
                    )
                if not scope["in_scope"]:
                    raise ValueError(
                        f"request_shape host '{scope['host']}' is outside the engagement scope "
                        f"(00_control/engagement.yaml assets={scope['assets']})"
                    )
            self._validate_refs(refs)
            existing = self._read_events()
            nonce = str(action.get("token_nonce") or "").strip()
            if action.get("id"):
                aid = str(action["id"])
                if any(e.get("type") == "ACTION_RECORDED" and e.get("entity_id") == aid
                       for e in existing):
                    raise ValueError(
                        f"action id {aid} is already recorded — action ids are unique; "
                        "re-recording the same receipt is refused (a retry after a failed "
                        "receipt lands on the same id only while no record exists)"
                    )
                # A hand-entered id must not steal a prepared token's id: the only
                # record allowed on a minted id is the genuine receipt carrying that
                # token's nonce (the executor's path). Anything else would refuse
                # the real receipt as a duplicate and hide the pending report.
                token_nonces = self.token_action_nonces()
                if aid in token_nonces and nonce not in token_nonces[aid]:
                    raise ValueError(
                        f"action id {aid} collides with a prepared preflight token — "
                        "the genuine receipt carries that token's nonce; record through "
                        "the controlled executors instead of hand-entering the id"
                    )
            else:
                aid = self._next_action_id(existing)
            # Nonce provenance: a presented token_nonce must resolve to a prepared
            # token whenever the store exists — a forged nonce cannot buy a receipt.
            # The gate is store existence, not issued-nonceness: an existing-but-empty
            # (or truncated/garbled-only) store still refuses. An absent nonce stays
            # the legacy path (the audit warns, closure holds versioned actions to
            # the nonce), so template/manual records keep working.
            issued, _consumed = self._known_token_nonces()
            if nonce and nonce not in issued and self._tokens_file().exists():
                raise ValueError(
                    f"action token_nonce {nonce[:12]}… matches no prepared preflight token — "
                    "record actions only through the controlled executors (or prepare first)"
                )
            event = self._append_locked("ACTION_RECORDED", "action", aid, actor=actor,
                                        reason="live-action preflight recorded", payload=action,
                                        cycle_id=action.get("cycle_id"), evidence_refs=refs)
        self.refresh()
        return event

    # ---------- live-action preflight tokens ----------
    def _next_action_id(self, events: list[dict[str, Any]] | None = None) -> str:
        """One allocator for `A-` action ids, shared by record and prepare.

        The next id runs one past the highest `A-<n>` already taken — by a recorded
        action or by a prepared token — so interleaved prepares and records can never
        mint the same id. Broker `B-` ids live in a separate namespace (the broker
        ledger) and are ignored here.
        """
        maxn = 0
        for e in (events if events is not None else self._read_events()):
            if e.get("type") != "ACTION_RECORDED":
                continue
            m = re.fullmatch(r"A-(\d+)", str(e.get("entity_id") or ""))
            if m:
                maxn = max(maxn, int(m.group(1)))
        path = self._tokens_file()
        if path.exists():
            for line in path.read_text(errors="ignore").splitlines():
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(rec, dict):
                    m = re.fullmatch(r"A-(\d+)", str(rec.get("action_id") or ""))
                    if m:
                        maxn = max(maxn, int(m.group(1)))
        return f"A-{maxn + 1:06d}"

    def token_action_nonces(self) -> dict[str, set[str]]:
        """Prepared-token action ids mapped to their known nonces (the audit seam).

        Both the local `nonce` and the broker mirror's `broker_nonce` count: the
        executor records `token.nonce`, which is the broker nonce in broker mode.
        Empty when no token was ever prepared; an id may map to an empty set when
        its store lines carry no nonce (hand-garbled store — matches nothing).
        """
        out: dict[str, set[str]] = {}
        path = self._tokens_file()
        if not path.exists():
            return out
        for line in path.read_text(errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue
            aid = str(rec.get("action_id") or "")
            if not aid:
                continue
            nonces = out.setdefault(aid, set())
            for key in ("nonce", "broker_nonce"):
                value = str(rec.get(key) or "").strip()
                if value:
                    nonces.add(value)
        return out

    def _tokens_file(self) -> Path:
        return self.rt / "action-tokens.jsonl"

    def _known_token_nonces(self) -> tuple[set[str], set[str]]:
        """All vs consumed preflight nonces in the local token store.

        Both the local `nonce` and the broker mirror's `broker_nonce` count: the
        executor records `token.nonce`, which is the broker nonce in broker mode.
        Empty when no token was ever prepared (legacy/template workspaces).
        """
        issued: set[str] = set()
        consumed: set[str] = set()
        path = self._tokens_file()
        if not path.exists():
            return issued, consumed
        for line in path.read_text(errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue
            for key in ("nonce", "broker_nonce"):
                value = str(rec.get(key) or "").strip()
                if value:
                    issued.add(value)
                    if rec.get("consumed"):
                        consumed.add(value)
        return issued, consumed

    def prepare_action(self, action: dict[str, Any], ttl_seconds: int = 300,
                       actor: str = "controller") -> dict[str, Any]:
        """Issue a single-use preflight token bound to one live action.

        The enforcer plugin (DSH) consumes the token when the matching tool call
        arrives; the controlled executor records ACTION_RECORDED after the call.
        Tokens live in a transient store (11_runtime/action-tokens.jsonl), never
        the ledger — the ledger stays append-only lifecycle history.

        `request_shape` is normalized to the canonical digest form BEFORE hashing
        (identical to the executor's `shapeFromArgs`): method uppercased, header keys
        lowercased (values untouched), and a body without `body_sha256` folded into
        `body_sha256 = sha256(body)` with `body` dropped — see
        `canonical_request_shape`. The token's preflight carries the normalized shape,
        so a hand-built prepare and a tool call cannot disagree about the digest bytes.

        When a broker socket is present (tools/broker/), the broker is the token
        authority: the workspace must already hold a broker policy (`researchctl
        scope-set` pushes it), the broker performs its own scope check and signs the
        minted record, and the local store mirrors it with `broker_sig` /
        `broker_nonce` / `broker_workspace` so the enforcer consumes through the
        broker before dispatch. A present-but-unreachable broker, a missing policy or a
        broker refusal raises (fail closed); no socket means advisory local mode.
        """
        required = [
            "target", "scope_status", "account", "object_owner", "purpose", "hypothesis",
            "expected_secure", "expected_vulnerable", "side_effect", "stop_condition",
            "request_shape",
        ]
        missing = [k for k in required if not action.get(k)]
        if missing:
            raise ValueError("action preflight missing: " + ", ".join(missing))
        if str(action.get("scope_status")).upper() != "IN_SCOPE":
            raise ValueError("action preflight requires scope_status=IN_SCOPE")
        cycle_id = str(action.get("cycle_id") or "")
        if not cycle_id:
            raise ValueError("live-action preflight requires cycle_id")
        cycle_status = self.cycle_status(cycle_id)
        if cycle_status != "RUNNING":
            raise ValueError(f"live-action preflight requires cycle RUNNING, got {cycle_status}")
        hyp = str(action.get("hypothesis", ""))
        if hyp.startswith("H-") and self.hypothesis_status(hyp) is None:
            raise ValueError(f"live-action preflight references unknown hypothesis: {hyp}")
        # Identity binding: the workspace declares its one research identity, and a
        # live preflight must carry it. A garbled binding fails closed; an absent
        # (or placeholder-only) binding leaves the account unchecked (template
        # workspaces) while the audit warns.
        binding = identity_binding(self.root)
        if isinstance(binding, str):
            raise ValueError(
                "00_control/identity-binding.yaml is present but malformed — repair the "
                "expected_identity/session contract before any live action (fail closed)"
            )
        if binding is not None and binding["account_reference"] and binding["session_must_match_identity"]:
            account = str(action.get("account") or "").strip()
            if account != binding["account_reference"]:
                raise ValueError(
                    f"preflight account {account!r} does not match the workspace identity binding "
                    f"({binding['account_reference']!r} in 00_control/identity-binding.yaml) — "
                    "live actions run under the bound research identity only"
                )
        shape = action.get("request_shape")
        if not isinstance(shape, dict) or not shape:
            raise ValueError("request_shape must be a non-empty object (canonical digest input)")
        shape = canonical_request_shape(shape)
        scope = scope_check(self.root, str(shape.get("url", "")))
        if scope["gate"] == "unenforceable":
            raise ValueError(
                "engagement assets are present but not a simple string list; keep "
                "00_control/engagement.yaml assets as host/URL strings — scope is unenforceable otherwise"
            )
        if scope["gate"] == "unset":
            raise ValueError(
                "no scope configured — record the engagement scope with `researchctl scope-set` "
                "or set an explicit `gate: none` for non-target work"
            )
        if not scope["in_scope"]:
            raise ValueError(
                f"target host '{scope['host'] or str(shape.get('url', ''))}' is outside the engagement scope "
                f"(00_control/engagement.yaml assets={scope['assets']})"
            )
        digest = hashlib.sha256(_json_dump(shape).encode("utf-8")).hexdigest()
        normalized = {**action, "request_shape": shape}
        client = broker_client()
        if client is not None:
            self._require_broker_policy(client)
        issued = time.time()
        with _lock(self.root):
            # The budget check shares the critical section with the token write: two
            # concurrent prepares cannot both slip past the last available slot.
            limits = budget_limits(self.root)
            if isinstance(limits, str):
                raise ValueError(
                    "engagement budget block is malformed — max_actions_per_cycle and "
                    "max_actions_per_engagement must be plain non-negative integers; repair it with "
                    "`researchctl budget set` before any live action"
                )
            counts = self.action_counts()
            used_cycle = counts["cycles"].get(cycle_id, 0)
            cap_cycle = (limits or {}).get("max_actions_per_cycle")
            cap_total = (limits or {}).get("max_actions_per_engagement")
            if cap_cycle is not None and used_cycle >= cap_cycle:
                raise ValueError(
                    f"cycle budget exhausted ({used_cycle}/{cap_cycle}) — record a human-approved "
                    "raise via `researchctl budget set`"
                )
            if cap_total is not None and counts["engagement"] >= cap_total:
                raise ValueError(
                    f"engagement budget exhausted ({counts['engagement']}/{cap_total}) — record a "
                    "human-approved raise via `researchctl budget set`"
                )
            if client is None:
                existing = self._read_events()
                aid = self._next_action_id(existing)
                family = str(action.get("tool_family", "http"))
                token = {
                    "action_id": aid,
                    "nonce": secrets.token_hex(16),
                    "issued_at": now(),
                    "expires_at": datetime.fromtimestamp(issued + max(30, int(ttl_seconds)),
                                                         tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "tool_family": family,
                    "argument_digest": digest,
                    "cycle_id": cycle_id,
                    "hypothesis": hyp,
                    "target": str(action.get("target", "")),
                    "consumed": False,
                    # The full validated preflight travels with the token so the controlled
                    # executor can write ACTION_RECORDED after the call without re-typing it.
                    "preflight": redact(dict(normalized)),
                }
                if family == "browser":
                    token["browser_profile"] = self._bound_browser_profile()
            else:
                token = self._broker_token(client, normalized, shape, digest, cycle_id, hyp, ttl_seconds)
            # The token store and the prepare output are audit-visible: scrub the same
            # secret shapes and sensitive query/fragment values the ledger uses, so a
            # target URL cannot smuggle a credential into either surface. The digest
            # was computed over the raw shape and is a hex string — unaffected.
            token = redact(token)
            with self._tokens_file().open("a", encoding="utf-8") as fh:
                fh.write(_json_dump(token) + "\n")
        self.refresh()
        return token

    def _token_state(self, action_id: str) -> dict[str, Any] | None:
        """Latest state for one prepared token action id (None when never prepared).

        The store is append-only with latest-state-per-action_id semantics: the consume
        line is a later record for the same id, never a rewrite of the mint line.
        """
        path = self._tokens_file()
        if not path.exists():
            return None
        state: dict[str, Any] | None = None
        for line in path.read_text(errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict) and str(rec.get("action_id") or "") == action_id:
                state = {**(state or {}), **rec}
        return state

    def _broker_consume(self, client, rec: dict[str, Any], digest: str, family: str) -> None:
        """Consume a broker-minted token in the broker ledger first (fail closed).

        The broker is the token authority while its socket is present: a broker refusal
        (replay, signature mismatch, expiry) must stop the local consume, never be
        papered over locally.
        """
        try:
            response = client.call("token.consume", timeout=5, workspace=str(self.root),
                                   digest=digest, tool_family=family,
                                   nonce=str(rec.get("broker_nonce") or ""),
                                   sig=str(rec.get("broker_sig") or ""))
        except client.BrokerUnavailable as exc:
            raise ValueError(
                f"broker socket is present but the consume call failed (fail closed): {exc} — "
                "start the broker (`researchctl broker serve`) and consume again") from exc
        if not response.get("ok"):
            raise ValueError(
                f"the broker refused to consume the preflight token (fail closed): {response.get('error')}")

    def consume_token(self, action_id: str, shape: dict[str, Any], *, family: str = "browser",
                      actor: str = "controller") -> dict[str, Any]:
        """Consume a prepared preflight token exactly once, bound to the exact action shape.

        The single-use gate for a controller-driven arm (no executor plugin consumes its
        tokens): the token must exist, be unconsumed and unexpired, carry the requested
        tool family, and its `argument_digest` must equal the canonical digest of `shape`
        — the same bytes the executor's `shapeFromArgs` hashes, so a token can never
        authorize a different action than the one it was prepared for. The check and the
        append share one critical section (two concurrent consumes cannot both win), the
        consume is a durable append (latest state per action_id wins), and consumption
        never restores budget headroom. With a broker socket present the broker consumes
        first and a broker refusal fails closed. Returns the token record with its
        `preflight`; raises ValueError with the failing reason otherwise.
        """
        aid = str(action_id or "").strip()
        if not aid:
            raise ValueError("token-consume requires an action id")
        if not isinstance(shape, dict) or not shape:
            raise ValueError("token-consume requires a non-empty request_shape")
        canonical = canonical_request_shape(shape)
        digest = hashlib.sha256(_json_dump(canonical).encode("utf-8")).hexdigest()
        with _lock(self.root):
            rec = self._token_state(aid)
            if rec is None:
                raise ValueError(
                    f"no prepared preflight token for {aid} — no token, no dispatch (prepare it first)")
            if rec.get("consumed"):
                raise ValueError(
                    f"preflight token {aid} was already consumed — preflight tokens are single-use")
            expires = str(rec.get("expires_at") or "")
            if expires and expires < now():
                raise ValueError(f"preflight token {aid} expired at {expires} — prepare a fresh one")
            token_family = str(rec.get("tool_family") or "")
            if token_family != str(family):
                raise ValueError(
                    f"preflight token {aid} is bound to tool_family {token_family!r}, not {family!r}")
            if str(rec.get("argument_digest") or "") != digest:
                raise ValueError(
                    f"preflight token {aid} is bound to a different action shape — the token "
                    "authorizes exactly the shape it was prepared for; prepare the action again")
            client = broker_client()
            if client is not None and rec.get("broker_nonce"):
                self._broker_consume(client, rec, digest, family)
            with self._tokens_file().open("a", encoding="utf-8") as fh:
                fh.write(_json_dump({
                    "action_id": aid,
                    "nonce": str(rec.get("nonce") or ""),
                    "consumed": True,
                    "consumed_at": now(),
                    "consumed_by": actor,
                }) + "\n")
        self.refresh()
        return rec

    def gate_for_action(self, action_id: str) -> dict[str, Any]:
        """Is there a RESOLVED human gate that APPROVES this action id (the consequential gate)?

        The dispatch-time twin of the audit's disposition rule: a gate counts only when it
        is RESOLVED on the action's own cycle with an authorizing decision (APPROVED /
        RESUME / PROVIDED — a DENIED or CANCELLED gate is the human saying no), its
        `what_is_needed` names the action id (substring, exactly the audit's
        `aid in what_is_needed` match), and it was RAISED after the token was minted —
        ids are sequential and predictable, so a gate resolved before the run on the
        predicted id must never pre-authorize it. The answer is advisory evidence for the
        runner; the code that dispatches refuses without it. Raises for an action id with
        no prepared token (nothing to gate).
        """
        aid = str(action_id or "").strip()
        if not aid:
            raise ValueError("gate-check requires an action id")
        rec = self._token_state(aid)
        if rec is None:
            raise ValueError(f"no prepared preflight token for {aid} — nothing to gate")
        cycle_id = str(rec.get("cycle_id") or "")
        issued_at = str(rec.get("issued_at") or "")
        for event in self._read_events():
            if event.get("type") != "HUMAN_GATE_RESOLVED":
                continue
            if cycle_id and str(event.get("cycle_id") or "") != cycle_id:
                continue
            gid = str(event.get("entity_id") or "")
            gate = self.gate(gid) or {}
            if not gate_decision_authorizes(gate.get("decision")):
                continue
            if not gate_postdates_token(self._gate_request_time(gid), issued_at):
                continue
            if aid in str(gate.get("what_is_needed") or ""):
                return {"resolved": True, "gate": gid,
                        "decision": gate.get("decision"), "cycle_id": cycle_id,
                        "reason": "a RESOLVED human gate approving this action postdates it"}
        return {"resolved": False, "gate": None, "cycle_id": cycle_id,
                "reason": (f"no RESOLVED human gate on cycle {cycle_id or '<missing>'} approves "
                           f"{aid} (raised after the token, naming it in what_is_needed) — raise one "
                           "(`researchctl gate request`) and resolve it APPROVED/RESUME/PROVIDED "
                           "before dispatching a consequential action")}

    def _gate_request_time(self, gid: str) -> str:
        """The HUMAN_GATE_REQUESTED event time for one gate ('' when never requested).

        The ordering anchor: a gate that was never requested (or whose request predates
        the token) cannot authorize the token, however it was resolved.
        """
        for event in self._read_events():
            if event.get("type") == "HUMAN_GATE_REQUESTED" and str(event.get("entity_id") or "") == gid:
                return str(event.get("time") or "")
        return ""

    def _bound_browser_profile(self) -> str:
        """The dedicated runner profile for a browser preflight, validated.

        The engagement identity binding declares it; an absent (or
        placeholder-only) binding means the lab default — always explicit, never
        a silent runner fallback. A garbled binding or a profile outside the
        workspace root fails closed before any token is minted.
        """
        binding = identity_binding(self.root)
        if isinstance(binding, str):
            raise ValueError(
                "00_control/identity-binding.yaml is present but malformed — repair the "
                "expected_identity/session contract before any live action (fail closed)"
            )
        profile = ((binding or {}).get("browser_profile") or "lab/bua-profile").strip()
        if not profile:
            profile = "lab/bua-profile"
        try:
            (self.root / profile).resolve().relative_to(self.root)
        except ValueError:
            raise ValueError(
                f"the bound browser profile {profile!r} resolves outside the workspace root — "
                "point session.browser_profile at a dedicated profile inside the workspace"
            ) from None
        return profile

    def _require_broker_policy(self, client) -> None:
        """A present broker is the token authority: no policy means no token (fail closed)."""
        try:
            response = client.call("policy.get", timeout=5, workspace=str(self.root))
        except client.BrokerUnavailable as exc:
            raise ValueError(
                f"broker socket is present but unreachable (fail closed): {exc} — start the broker "
                "(`researchctl broker serve`) or unset RESEARCH_OS_BROKER_SOCKET before preparing") from exc
        if not response.get("ok"):
            raise ValueError(
                f"the broker refused to read the workspace policy (fail closed): {response.get('error')}")
        if response.get("policy") is None:
            raise ValueError(
                "the broker holds no policy for this workspace — register the scope with the broker: "
                "run `researchctl scope-set` (the broker is the token authority while its socket is present)")

    def _broker_token(self, client, normalized: dict[str, Any], shape: dict[str, Any], digest: str,
                      cycle_id: str, hyp: str, ttl_seconds: int) -> dict[str, Any]:
        """Mint through the broker; returns the local token-store record.

        The broker performs the scope check from its OWN policy copy and signs the record.
        The local store mirrors the returned fields plus `broker_sig` / `broker_nonce` /
        `broker_workspace`, so the enforcer can consume through the broker before dispatch.
        """
        family = str(normalized.get("tool_family", "http"))
        try:
            response = client.call("token.mint", timeout=5, workspace=str(self.root),
                                   preflight=redact(dict(normalized)), request_shape=shape,
                                   tool_family=family, ttl_seconds=max(30, int(ttl_seconds)))
        except client.BrokerUnavailable as exc:
            raise ValueError(
                f"broker socket is present but the mint call failed (fail closed): {exc} — "
                "start the broker (`researchctl broker serve`) and prepare again") from exc
        if not response.get("ok"):
            raise ValueError(f"the broker refused the preflight token (fail closed): {response.get('error')}")
        minted = response["token"]
        if minted.get("digest") != digest:
            raise ValueError(
                "the broker digest disagrees with the local canonical digest — refusing the token "
                "(canonicalization drift between prepare and the broker)")
        mirror = {
            "action_id": minted["action_id"],
            "nonce": minted["nonce"],
            "broker_nonce": minted["nonce"],
            "broker_sig": minted["sig"],
            "broker_workspace": minted["workspace"],
            "issued_at": now(),
            "expires_at": minted["expires_at"],
            "tool_family": minted["tool_family"],
            "argument_digest": minted["digest"],
            "cycle_id": cycle_id,
            "hypothesis": hyp,
            "target": str(normalized.get("target", "")),
            "consumed": False,
            "preflight": redact(dict(normalized)),
        }
        if family == "browser":
            mirror["browser_profile"] = self._bound_browser_profile()
        return mirror

    def request_gate(self, gid: str, request: dict[str, Any], actor: str = "controller") -> dict[str, Any]:
        if not gate_id_ok(gid):
            raise ValueError("invalid gate id")
        required = ["cycle_id", "what_is_needed", "why_human_only", "resume_after"]
        missing = [k for k in required if not request.get(k)]
        if missing:
            raise ValueError("gate request missing: " + ", ".join(missing))
        cycle_id = str(request["cycle_id"])
        if self.cycle_status(cycle_id) != "RUNNING":
            raise ValueError("human gate must attach to a RUNNING cycle")
        with _lock(self.root):
            if self.gate(gid):
                raise ValueError(f"gate exists: {gid}")
            payload = dict(request)
            payload["status"] = "PENDING"
            event = self._append_locked("HUMAN_GATE_REQUESTED", "human_gate", gid, actor=actor,
                                        reason="human input required", payload=payload,
                                        cycle_id=request.get("cycle_id"))
            cid = request.get("cycle_id")
            if cid and self.cycle_status(cid) == "RUNNING":
                self._append_locked("CYCLE_TRANSITIONED", "cycle", cid, actor="controller",
                                    reason=f"human gate {gid} opened", payload={"from": "RUNNING", "to": "HUMAN_GATE"},
                                    cycle_id=cid, causation_id=event["event_id"])
        self.refresh()
        return event

    def resolve_gate(self, gid: str, *, decision: str, actor: str = "human", reference: str = "") -> dict[str, Any]:
        decision = decision.upper()
        if decision not in HUMAN_GATE_DECISIONS:
            raise ValueError("invalid human gate decision")
        with _lock(self.root):
            gate = self.gate(gid)
            if not gate:
                raise ValueError(f"unknown gate: {gid}")
            if gate.get("status") == "RESOLVED":
                raise ValueError(f"gate already resolved: {gid}")
            if not reference:
                raise ValueError("gate resolution requires a human reference; never store OTP/secret content")
            event = self._append_locked("HUMAN_GATE_RESOLVED", "human_gate", gid, actor=actor,
                                        reason="human gate resolved",
                                        payload={"status": "RESOLVED", "decision": decision, "reference": reference},
                                        cycle_id=gate.get("cycle_id"))
            cid = gate.get("cycle_id")
            if cid and self.cycle_status(cid) == "HUMAN_GATE":
                if decision in {"RESUME", "PROVIDED", "APPROVED"}:
                    to_state = "RUNNING"
                else:
                    to_state = "BLOCKED"
                self._append_locked("CYCLE_TRANSITIONED", "cycle", cid, actor="controller",
                                    reason=f"human gate {gid} resolved", payload={"from": "HUMAN_GATE", "to": to_state},
                                    cycle_id=cid, causation_id=event["event_id"])
        self.refresh()
        return event

    def gate(self, gid: str) -> dict[str, Any] | None:
        current: dict[str, Any] | None = None
        for e in self.events_for("human_gate", gid):
            payload = dict(e.get("payload", {}))
            current = {**(current or {}), **payload, "cycle_id": e.get("cycle_id"), "time": e["time"]}
        return current

    def method_attack_units(self) -> dict[str, dict[str, Any]]:
        """Deterministic coverage units per method-self-attack prompt, derived from the ledger.

        The critic-wave loop's input (`33_METHOD_SELF_ATTACK.md`): each unit names the
        subject (hypothesis / cycle / freshness component) whose row must be answered.
        Rows the ledger cannot derive units for say so with a reason instead of
        pretending completeness. Deterministic: same ledger, same units.
        """
        events = self._read_events()
        units: dict[str, list[dict[str, Any]]] = {row: [] for row in METHOD_SELF_ATTACK_ROWS}

        def add(row: str, subject: str, label: str) -> None:
            units[row].append({"unit": f"MU-{row}-{len(units[row]) + 1}",
                               "subject": subject, "label": label})

        for component in self.freshness_ledger():
            name = str(component.get("target_component") or "").strip()
            if name:
                add("assumed-secure", name,
                    f"freshness component pinned {component.get('pinned_version') or 'UNKNOWN'}")
        for row in self.freshness_report()["components"]:
            reasons = []
            if row.get("stale"):
                reasons.append("stale")
            if row.get("unpinned"):
                reasons.append("unpinned")
            if reasons:
                add("version-drift", str(row.get("target_component")),
                    f"freshness component {'/'.join(reasons)}")
        for hid in self.all_hypothesis_ids():
            status = self.hypothesis_status(hid)
            if status in {"FALSE_POSITIVE", "NOT_APPLICABLE"}:
                add("weak-negative", hid, f"hypothesis closed {status}")
        seen_blocked: set[str] = set()
        for event in events:
            if (event.get("type") != "CYCLE_TRANSITIONED"
                    or str((event.get("payload") or {}).get("to")) != "BLOCKED"):
                continue
            cid = str(event.get("entity_id") or "")
            if cid and cid not in seen_blocked:
                seen_blocked.add(cid)
                add("early-close", cid, "cycle entered BLOCKED")
        notes = {
            "skipped-collision": "no derivable units: boundary pairs are not recorded in the ledger",
            "tool-misread": "no derivable units: tool failures are not their own event type",
        }
        return {
            row: {"units": units[row],
                  "note": notes.get(row) if not units[row] else None}
            for row in METHOD_SELF_ATTACK_ROWS
        }

    def critique_self_attack(self, matrix: dict[str, Any] | None) -> dict[str, Any]:
        """Coverage critic: is every derived unit named in its matrix row?

        A unit counts as covered when its subject id (hypothesis / cycle / component
        name) appears in the row text — naming the thing that was re-opened is what the
        matrix cell promises. Returns `{"complete", "rows", "uncovered", "units_total"}`.
        """
        units = self.method_attack_units()
        rows: dict[str, dict[str, Any]] = {}
        uncovered: list[str] = []
        for row in METHOD_SELF_ATTACK_ROWS:
            text = str((matrix or {}).get(row, ""))
            subjects = [u["subject"] for u in units[row]["units"]]
            missing = [s for s in subjects if s not in text]
            rows[row] = {"units": subjects,
                         "named": [s for s in subjects if s not in missing],
                         "uncovered": missing, "note": units[row]["note"]}
            uncovered.extend(f"{row}:{s}" for s in missing)
        return {"complete": not uncovered, "rows": rows, "uncovered": uncovered,
                "units_total": sum(len(units[r]["units"]) for r in METHOD_SELF_ATTACK_ROWS)}

    def record_audit(self, audit_class: str, status: str, summary: str, *, cycle_id: str | None = None,
                     evidence_refs: Iterable[str] = (), matrix: dict | None = None,
                     actor: str = "controller") -> dict[str, Any]:
        status = status.upper()
        if status not in {"PASS", "FAIL", "WARN"}:
            raise ValueError("audit status must be PASS, FAIL or WARN")
        summary = str(summary).strip()
        if sentence_too_thin(summary):
            raise ValueError(
                "audit summary must be a sentence (>= 20 characters and >= 3 words after stripping) — "
                "name what was audited and what the verdict rests on; the audit ledger is evidence, "
                "not a checkbox"
            )
        refs = list(evidence_refs)
        if audit_class in REQUIRED_AUDIT_CLASSES and not refs:
            raise ValueError(f"audit class {audit_class} requires evidence refs")
        if audit_class == "method-self-attack":
            if not isinstance(matrix, dict):
                raise ValueError(
                    "method-self-attack audit needs the six-row matrix "
                    f"({', '.join(METHOD_SELF_ATTACK_ROWS)}) — every row filled; "
                    "'none — reason' counts as answered"
                )
            missing = [r for r in METHOD_SELF_ATTACK_ROWS if not str(matrix.get(r, "")).strip()]
            extra = [k for k in matrix if k not in METHOD_SELF_ATTACK_ROWS]
            if missing or extra:
                detail = (f"missing/blank rows: {', '.join(missing)}; " if missing else "") + \
                         (f"unknown rows: {', '.join(extra)}" if extra else "")
                raise ValueError(f"method-self-attack matrix invalid — {detail.rstrip('; ')}")
        if cycle_id and self.cycle_status(str(cycle_id)) is None:
            raise ValueError(f"audit references unknown cycle: {cycle_id}")
        coverage = self.critique_self_attack(matrix) if audit_class == "method-self-attack" else None
        with _lock(self.root):
            self._validate_refs(refs)
            payload: dict[str, Any] = {"class": audit_class, "status": status, "summary": summary}
            if matrix is not None:
                payload["matrix"] = {r: str(matrix[r]).strip() for r in METHOD_SELF_ATTACK_ROWS if r in matrix}
            if coverage is not None:
                # Coverage-ledger discipline: the derived units and what the matrix left
                # unnamed ride on the event (advisory to the audit's warning stream; the
                # six-row form check stays the enforcement).
                payload["coverage"] = {"units_total": coverage["units_total"],
                                       "uncovered": coverage["uncovered"],
                                       "complete": coverage["complete"]}
            event = self._append_locked("AUDIT_RECORDED", "audit", audit_class, actor=actor,
                                        reason=summary, payload=payload,
                                        evidence_refs=refs, cycle_id=cycle_id)
        self.refresh()
        return event

    # ---------- freshness watchtower (31_FRESHNESS_WATCHTOWER) ----------
    def freshness_ledger(self) -> list[dict[str, Any]]:
        """Latest recorded component ledger; a later FRESHNESS_RECORDED replaces it."""
        for e in reversed(self._read_events()):
            if e.get("type") == "FRESHNESS_RECORDED":
                return list((e.get("payload") or {}).get("components") or [])
        return []

    def record_freshness(self, payload: dict[str, Any], actor: str = "controller") -> dict[str, Any]:
        components = payload.get("components")
        if not isinstance(components, list) or not components:
            raise ValueError("freshness payload needs a non-empty 'components' list")
        norm: list[dict[str, Any]] = []
        for i, c in enumerate(components, 1):
            if not isinstance(c, dict):
                raise ValueError(f"freshness component {i} must be an object")
            if not str(c.get("target_component", "")).strip():
                raise ValueError(f"freshness component {i} needs target_component")
            last = str(c.get("last_checked", "")).strip()
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", last):
                raise ValueError(f"freshness component {i} needs last_checked as YYYY-MM-DD")
            if "sources" in c and not isinstance(c["sources"], list):
                raise ValueError(f"freshness component {i} sources must be a list")
            if "max_age_days" in c and (not isinstance(c["max_age_days"], int) or c["max_age_days"] < 1):
                raise ValueError(f"freshness component {i} max_age_days must be a positive integer")
            row = {
                "target_component": str(c["target_component"]).strip(),
                "pinned_version": (str(c.get("pinned_version", "")).strip() or "UNKNOWN"),
                "last_checked": last,
                "sources": [str(s) for s in (c.get("sources") or [])],
                "new_primitives": [str(s) for s in (c.get("new_primitives") or [])],
                "action": str(c.get("action", "")).strip(),
            }
            if c.get("max_age_days"):
                row["max_age_days"] = int(c["max_age_days"])
            norm.append(row)
        with _lock(self.root):
            event = self._append_locked("FRESHNESS_RECORDED", "freshness", "ledger", actor=actor,
                                        reason=f"freshness ledger recorded ({len(norm)} components)",
                                        payload={"components": norm})
        self.refresh()
        return event

    def freshness_report(self, now: datetime | None = None) -> dict[str, Any]:
        """Age, staleness and pin status per component (stale = age > max_age_days)."""
        today = (now or datetime.now(timezone.utc)).date()
        rows, stale, unpinned, ages = [], [], [], {}
        for c in self.freshness_ledger():
            name = str(c.get("target_component", ""))
            try:
                checked = datetime.strptime(str(c.get("last_checked")), "%Y-%m-%d").date()
                age = (today - checked).days
            except ValueError:
                age = 10 ** 6
            max_age = int(c.get("max_age_days") or FRESHNESS_DEFAULT_MAX_AGE_DAYS)
            pinned = str(c.get("pinned_version", "")).strip().upper()
            is_stale = age > max_age
            is_unpinned = (not pinned) or pinned == "UNKNOWN"
            rows.append({**c, "age_days": age, "max_age_days": max_age, "stale": is_stale, "unpinned": is_unpinned})
            ages[name] = age
            if is_stale:
                stale.append(name)
            if is_unpinned:
                unpinned.append(name)
        return {"components": rows, "stale": stale, "unpinned": unpinned, "ages": ages, "due": bool(stale)}

    def _write_freshness_projection(self) -> None:
        p = self.root / "10_learning" / "freshness.yaml"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(GENERATED_HEADER + "\ncomponents: " + json.dumps(self.freshness_ledger(), ensure_ascii=False) + "\n")

    # ---------- workers / status / projections ----------
    def next_actions(self) -> dict[str, Any]:
        """Return legal lifecycle moves and blocking conditions without choosing a research decision."""
        cycles = []
        for cid in self.all_cycle_ids():
            status = self.cycle_status(cid)
            cycles.append({"cycle_id": cid, "status": status, "allowed_transitions": sorted(CYCLE_EDGES.get(status or "", set()))})
        hypotheses = []
        for hid in self.all_hypothesis_ids():
            status = self.hypothesis_status(hid)
            hypotheses.append({"hypothesis_id": hid, "status": status, "allowed_transitions": sorted(HYP_EDGES.get(status or "", set()))})
        gates = [gid for gid in self.all_gate_ids() if (self.gate(gid) or {}).get("status") == "PENDING"]
        return {"cycles": cycles, "hypotheses": hypotheses, "pending_human_gates": gates}

    def _consume_review_voucher(self, packet: dict[str, Any], cid: str) -> None:
        """Consume the packet's broker-attested review voucher (broker mode only).

        No broker socket means advisory local mode: the packet is accepted on its
        declared identities (the audit notes voucher-less reviews). While a broker
        socket is present the voucher is mandatory and single-use: the bindings
        (axis, reviewer, run, cycle, hypothesis, exact packet digest) are checked
        before the broker consumes the nonce, so replayed, forged, rebound or
        edited-packet vouchers are refused and nothing is double-consumed.
        """
        review = packet.get("review") or {}
        client = broker_client()
        if client is None:
            return
        attestation = review.get("attestation")
        if not isinstance(attestation, dict):
            raise ValueError(
                "the policy broker is running, so review packets need a broker-attested "
                "voucher (review.attestation) — issue one via `researchctl review-issue packet.json`"
            )
        axis = str(review.get("axis", "")).lower()
        if str(attestation.get("axis", "")).lower() != axis:
            raise ValueError(
                f"review voucher is bound to axis {attestation.get('axis')!r}, not to this "
                f"packet's axis {axis!r} — vouchers cannot move across axes"
            )
        for field in ("reviewer", "run_id"):
            if str(attestation.get(field, "")).strip().casefold() != str(review.get(field, "")).strip().casefold():
                raise ValueError(
                    f"review voucher is bound to {field} {attestation.get(field)!r}, not to this "
                    f"packet's {field} — vouchers cannot move across reviewers or runs"
                )
        if str(attestation.get("cycle_id", "")).strip() != cid:
            raise ValueError("review voucher is bound to a different cycle — vouchers cannot move across cycles")
        hypothesis_id = str(attestation.get("hypothesis_id", "")).strip()
        if self.entity_cycle("hypothesis", hypothesis_id) != cid:
            raise ValueError(
                f"review voucher names hypothesis {hypothesis_id!r}, which does not belong to "
                f"cycle {cid} — vouchers cannot move across hypotheses"
            )
        if str(attestation.get("packet_sha256", "")).lower() != review_packet_digest(packet):
            raise ValueError(
                "review voucher's packet digest does not match this packet — the packet was "
                "edited after the voucher was issued; issue a fresh voucher for the final packet"
            )
        try:
            response = client.call("review.consume", timeout=5, workspace=str(self.root),
                                   voucher={k: attestation.get(k) for k in
                                            ("workspace", "cycle_id", "hypothesis_id", "axis",
                                             "reviewer", "run_id", "packet_sha256", "nonce",
                                             "expires_at", "sig")})
        except client.BrokerUnavailable as exc:
            raise ValueError(
                f"broker socket is present but the voucher consume call failed (fail closed): {exc} — "
                "start the broker (`researchctl broker serve`) or unset RESEARCH_OS_BROKER_SOCKET") from exc
        if not response.get("ok"):
            raise ValueError(f"the broker refused the review voucher (fail closed): {response.get('error')}")

    def merge_worker(self, packet: dict[str, Any], actor: str = "orchestrator") -> dict[str, Any]:
        cid = packet.get("cycle_id")
        refs = packet.get("evidence_refs") or []
        if not cid or not refs:
            raise ValueError("worker packet needs cycle_id and evidence_refs")
        review = packet.get("review")
        quotes: list[Any] = []
        if review is not None:
            if not isinstance(review, dict):
                raise ValueError("review must be an object: {axis, verdict}")
            axis = str(review.get("axis", "")).lower()
            verdict = str(review.get("verdict", "")).lower()
            if axis not in {"objective", "method"} or verdict not in {"pass", "fail"}:
                raise ValueError("review packet needs review.axis objective|method and review.verdict pass|fail")
            if not str(review.get("reviewer", "")).strip():
                raise ValueError(
                    "review packet needs review.reviewer — the identity of the reviewing run; "
                    "the two axes must come from distinct reviewers"
                )
            if not str(review.get("run_id", "")).strip():
                raise ValueError(
                    "review packet needs review.run_id — the identity of the reviewing run/session; "
                    "a review produced by the same run as the work is not independent, and audits "
                    "measure independence from this field, not from prose"
                )
            quotes = review.get("evidence_quotes")
            if not isinstance(quotes, list) or not quotes:
                raise ValueError(
                    "review packet needs review.evidence_quotes — a non-empty list of "
                    "{evidence_ref, quote} objects quoting the registered store copy of each "
                    "artifact the verdict leans on, so a later edit of the living file cannot "
                    "silently move the evidence under the review"
                )
            producer = str(packet.get("producer_run_id") or "").strip()
            if producer and producer.casefold() == str(review.get("run_id", "")).strip().casefold():
                raise ValueError(
                    "review packet's run_id matches the producer run that did the work "
                    f"({producer!r}) — a run cannot review its own output; dispatch the "
                    "review in a separate run"
                )
        with _lock(self.root):
            if self.cycle_status(str(cid)) in {None, "CLOSED"}:
                raise ValueError("worker packet must reference an existing non-closed cycle")
            self._validate_refs(refs)
            if review is not None:
                self._validate_review_quotes(quotes, refs)
                self._consume_review_voucher(packet, str(cid))
            aid = f"WR-{len(self._read_events()) + 1:06d}"
            event = self._append_locked("WORKER_RESULT", "worker_result", aid, actor=actor,
                                        reason=packet.get("next_step", "worker result merged"),
                                        evidence_refs=refs, payload=packet, cycle_id=cid)
        self.refresh()
        return event

    def active_cycle(self) -> str | None:
        """Latest non-closed cycle touched by an event — the run-status `current_cycle` rule.

        The one derivation shared by `refresh()` and the cost-ledger CLI wiring, so
        `current_cycle` cannot mean two things.
        """
        active = {cid for cid in self.all_cycle_ids()
                  if self.cycle_status(cid) not in {None, "CLOSED"}}
        for e in reversed(self._read_events()):
            if e.get("entity_type") == "cycle" and e.get("entity_id") in active:
                return str(e.get("entity_id"))
        return None

    def refresh(self) -> dict[str, Any]:
        events = self._read_events()
        cycle_ids = self.all_cycle_ids()
        active_cycles = [cid for cid in cycle_ids if self.cycle_status(cid) not in {None, "CLOSED"}]
        pending_gates = [gid for gid in self.all_gate_ids() if (self.gate(gid) or {}).get("status") != "RESOLVED"]
        active_h = [hid for hid in self.all_hypothesis_ids()
                    if self.hypothesis_status(hid) not in {None, "CLOSED", "VERIFIED", "FALSE_POSITIVE", "NOT_APPLICABLE"}]
        current = self.active_cycle()
        if active_cycles:
            status = "ACTIVE"
        elif cycle_ids and all(self.cycle_status(cid) == "CLOSED" for cid in cycle_ids):
            status = "CLOSED"
        else:
            status = "BOOTSTRAP"
        existing = self._load_status()
        last_audit_event = next((e for e in reversed(events) if e.get("type") == "AUDIT_RECORDED"), None)
        merged = {
            "engagement_status": status,
            "current_cycle": current,
            "last_state_update": events[-1].get("time") if events else None,
            "last_audit": last_audit_event.get("time") if last_audit_event else existing.get("last_audit"),
            "open_high_value_hypotheses": len(active_h),
            "open_unknowns": self._count_open_unknowns(),
            "pending_human_gate": bool(pending_gates),
            "lab_ready": existing.get("lab_ready", False),
        }
        self.rt.mkdir(parents=True, exist_ok=True)
        lines = []
        for k, v in merged.items():
            if v is None:
                lines.append(f"{k}: null")
            elif isinstance(v, bool):
                lines.append(f"{k}: {str(v).lower()}")
            else:
                lines.append(f'{k}: "{v}"')
        (self.rt / "run-status.yaml").write_text("\n".join(lines) + "\n")
        self._write_active_cycle(current)
        self._write_cycle_projections(events)
        self._write_hypothesis_projections(events)
        self._write_evidence_index(events)
        self._write_gate_projections(events)
        self._write_audit_projection(events)
        self._write_technique_projections(events)
        self._write_freshness_projection()
        self._write_knowledge_usage_projection()
        self._write_knowledge_proposal_projection(events)
        self._rebuild_context()
        return merged

    def _load_status(self) -> dict[str, Any]:
        p = self.rt / "run-status.yaml"
        out: dict[str, Any] = {}
        if not p.exists():
            return out
        for line in p.read_text(errors="ignore").splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            v = v.strip()
            if v in {"true", "false"}:
                v = (v == "true")
            elif v == "null":
                v = None
            elif len(v) >= 2 and v.startswith('"') and v.endswith('"'):
                v = v[1:-1]
            out[k] = v
        return out

    def _count_open_unknowns(self) -> int:
        p = self.root / "10_learning" / "unknowns.yaml"
        if not p.exists():
            return 0
        return len(re.findall(r"status:\s*['\"]?OPEN['\"]?", p.read_text(errors="ignore")))

    def all_cycle_ids(self) -> list[str]:
        return list(dict.fromkeys(e["entity_id"] for e in self._read_events() if e.get("entity_type") == "cycle"))

    def all_hypothesis_ids(self) -> list[str]:
        return list(dict.fromkeys(e["entity_id"] for e in self._read_events() if e.get("entity_type") == "hypothesis"))

    def all_gate_ids(self) -> list[str]:
        return list(dict.fromkeys(e["entity_id"] for e in self._read_events() if e.get("entity_type") == "human_gate"))

    @staticmethod
    def _write_mapping(path: Path, data: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        body = "\n".join(f"{k}: {json.dumps(v, ensure_ascii=False)}" for k, v in data.items())
        path.write_text(GENERATED_HEADER + "\n" + body + "\n")

    def _write_active_cycle(self, current: str | None) -> None:
        p = self.rt / "active-cycle.yaml"
        if current is None:
            p.write_text(GENERATED_HEADER + "\ncycle_id: null\n")
            return
        data = self.cycle_data(current) or {}
        data = {"cycle_id": current, **data, "status": self.cycle_status(current)}
        self._write_mapping(p, data)

    def _write_cycle_projections(self, events: list[dict[str, Any]]) -> None:
        cycles: dict[str, dict[str, Any]] = {}
        for e in events:
            if e.get("entity_type") != "cycle":
                continue
            cid = e["entity_id"]
            if e["type"] == "CYCLE_CREATED":
                cycles[cid] = dict(e.get("payload", {}))
                cycles[cid]["status"] = "PLANNED"
            elif e["type"] == "CYCLE_UPDATED" and cid in cycles:
                cycles[cid].update(e.get("payload", {}))
            elif e["type"] == "CYCLE_TRANSITIONED" and cid in cycles:
                cycles[cid]["status"] = normalize_cycle_state(e.get("payload", {}).get("to"))
        for cid, plan in cycles.items():
            self._write_mapping(self.root / "04_cycles" / cid / "plan.yaml", plan)

    def _write_hypothesis_projections(self, events: list[dict[str, Any]]) -> None:
        hyps: dict[str, dict[str, Any]] = {}
        for e in events:
            if e.get("entity_type") != "hypothesis":
                continue
            hid = e["entity_id"]
            if e["type"] == "HYPOTHESIS_CREATED":
                hyps[hid] = dict(e.get("payload", {}))
                hyps[hid]["id"] = hid
            elif e["type"] == "HYPOTHESIS_UPDATED" and hid in hyps:
                hyps[hid].update(e.get("payload", {}))
            elif e["type"] == "HYPOTHESIS_TRANSITIONED" and hid in hyps:
                hyps[hid]["status"] = e.get("payload", {}).get("to")
        active = self.root / "03_hypotheses" / "active"
        archive = self.root / "03_hypotheses" / "archive"
        active.mkdir(parents=True, exist_ok=True)
        archive.mkdir(parents=True, exist_ok=True)
        for hid, data in hyps.items():
            target = archive if data.get("status") in {"CLOSED", "VERIFIED", "FALSE_POSITIVE", "NOT_APPLICABLE"} else active
            stale = (active if target is archive else archive) / f"{hid}.yaml"
            try:
                if stale.exists():
                    stale.unlink()
            except OSError:
                pass
            self._write_mapping(target / f"{hid}.yaml", data)

    def _write_evidence_index(self, events: list[dict[str, Any]]) -> None:
        p = self.rt / "evidence-index.jsonl"
        rows = [e.get("payload", {}) for e in events if e.get("type") == "EVIDENCE_REGISTERED"]
        p.write_text("".join(_json_dump(r) + "\n" for r in rows))

    def _write_gate_projections(self, events: list[dict[str, Any]]) -> None:
        d = self.rt / "human-gates"
        d.mkdir(parents=True, exist_ok=True)
        states: dict[str, dict[str, Any]] = {}
        for e in events:
            if e.get("entity_type") != "human_gate":
                continue
            gid = e["entity_id"]
            states[gid] = {**states.get(gid, {}), **e.get("payload", {}), "id": gid, "time": e["time"]}
        for gid, state in states.items():
            self._write_mapping(d / f"{gid}.yaml", state)

    def _write_audit_projection(self, events: list[dict[str, Any]]) -> None:
        """Project the latest audit declarations for human inspection; never the source of truth."""
        latest: dict[str, dict[str, Any]] = {}
        for e in events:
            if e.get("type") != "AUDIT_RECORDED":
                continue
            payload = e.get("payload", {})
            cls = payload.get("class", e.get("entity_id"))
            if cls:
                latest[str(cls)] = {"status": payload.get("status"), "time": e.get("time"), "event_id": e.get("event_id")}
        d = self.root / "06_audits"
        d.mkdir(parents=True, exist_ok=True)
        required = sorted(REQUIRED_AUDIT_CLASSES)
        ready = bool(latest) and all(latest.get(k, {}).get("status") == "PASS" for k in required)
        lines = [f"status: {json.dumps('READY' if ready else 'NOT_READY')}", "audits:"]
        for key in sorted(set(required) | set(latest)):
            item = latest.get(key, {"status": "MISSING", "time": None, "event_id": None})
            lines += [f"  - class: {json.dumps(key)}", f"    status: {json.dumps(item.get('status'))}", f"    time: {json.dumps(item.get('time'))}", f"    event_id: {json.dumps(item.get('event_id'))}"]
        (d / "closure-readiness.yaml").write_text("\n".join(lines) + "\n")

    def _write_technique_projections(self, events: list[dict[str, Any]]) -> None:
        """Project TECHNIQUE_EVALUATED events into the learning files.

        These files are evidence-backed views, not agent homework: the ledger is the
        source of truth, so a forgotten note cannot lose a result and a hand edit
        cannot fake one.
        """
        rows = [e for e in events if e.get("type") == "TECHNIQUE_EVALUATED"]
        learn = self.root / "10_learning"
        learn.mkdir(parents=True, exist_ok=True)
        lines = [GENERATED_HEADER, "", "# Technique Discoveries", "",
                 "One entry per TECHNIQUE_EVALUATED event, reconstructed from `11_runtime/events.jsonl`.", ""]
        if not rows:
            lines.append("_No technique evaluations recorded yet._")
        for e in rows:
            p = e.get("payload", {})
            lines += [
                f"## {p.get('id', e.get('entity_id'))} — {p.get('technique_family', '?')} → {p.get('result', '?')}",
                f"- time: {e.get('time')}",
                f"- cycle: {e.get('cycle_id')}",
            ]
            for key in ("target_surface", "source", "preconditions", "expected_oracle", "negative_control"):
                if p.get(key):
                    lines.append(f"- {key}: {p[key]}")
            lines.append(f"- interpretation: {p.get('interpretation', '')}")
            lines.append(f"- learning: {p.get('learning', '')}")
            if p.get("next_hypothesis"):
                lines.append(f"- next_hypothesis: {p['next_hypothesis']}")
            lines.append(f"- evidence: {', '.join(e.get('evidence_refs', []))}")
            lines.append("")
        (learn / "technique-discoveries.md").write_text("\n".join(lines) + "\n")
        if rows:
            last = rows[-1]
            p = last.get("payload", {})
            (self.rt / "last-result.md").write_text("\n".join([
                GENERATED_HEADER, "", "# Last Result", "",
                f"- technique: {p.get('id', last.get('entity_id'))} ({p.get('technique_family', '?')})",
                f"- result: {p.get('result', '?')}",
                f"- cycle: {last.get('cycle_id')}",
                f"- time: {last.get('time')}",
                f"- interpretation: {p.get('interpretation', '')}",
                f"- learning: {p.get('learning', '')}",
                f"- evidence: {', '.join(last.get('evidence_refs', []))}",
            ]) + "\n")

    def _rebuild_context(self) -> None:
        """current-context.md is a projection: rebuilt on every mutation, never hand-edited."""
        from build_context import rebuild
        rebuild(self.root)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
