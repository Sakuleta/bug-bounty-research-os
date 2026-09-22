#!/usr/bin/env python3
"""Stdlib Unix-socket client for the Research OS policy broker (`tools/broker/`).

One newline-delimited JSON request per connection. Discovery: `RESEARCH_OS_BROKER_SOCKET`
wins; otherwise the socket under `RESEARCH_OS_BROKER_HOME` (default
`~/.dsh/research-os-broker`) when it exists. An absent socket is not an error — it means
advisory local mode (see `README.md`); a present-but-unreachable socket is, and callers
must fail closed on `BrokerUnavailable`.
"""
from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from typing import Any

DEFAULT_HOME = Path.home() / ".dsh" / "research-os-broker"
SOCKET_NAME = "broker.sock"
MAX_LINE = 1024 * 1024


class BrokerUnavailable(Exception):
    """The broker socket is absent, unreachable, timed out or answered garbage."""


def broker_home() -> Path:
    env = os.environ.get("RESEARCH_OS_BROKER_HOME")
    return Path(env).expanduser() if env else DEFAULT_HOME


def broker_path() -> Path | None:
    """Env socket override, else the default home's socket when it exists."""
    env = os.environ.get("RESEARCH_OS_BROKER_SOCKET")
    if env:
        return Path(env).expanduser()
    candidate = broker_home() / SOCKET_NAME
    return candidate if candidate.exists() else None


def available() -> bool:
    path = broker_path()
    return path is not None and path.exists()


def workspace_key(workspace: str | Path) -> str:
    """Canonical workspace identity: the symlink-resolved absolute path string.

    The broker signs this string, so both sides must canonicalize identically. The
    enforcer uses `fs.realpathSync` for the same reason (macOS `/var` is a symlink to
    `/private/var`); a lexically resolved path would not match the signature.
    """
    return str(Path(workspace).resolve())


def call(op: str, timeout: float = 3, **payload: Any) -> dict[str, Any]:
    """One request/response round trip. Raises BrokerUnavailable on any transport or
    parse failure; a broker *refusal* is a normal `{"ok": false, "error": …}` return."""
    path = broker_path()
    if path is None:
        raise BrokerUnavailable(
            "no broker socket — start one (researchctl broker serve / "
            "python3 tools/broker/broker.py --serve) or unset RESEARCH_OS_BROKER_SOCKET")
    request = json.dumps({"op": op, **payload}, ensure_ascii=False) + "\n"
    encoded = request.encode("utf-8")
    if len(encoded) > MAX_LINE:
        raise BrokerUnavailable(f"broker request for {op} exceeds the {MAX_LINE} byte line bound")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(str(path))
            sock.sendall(encoded)
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > MAX_LINE:
                    raise BrokerUnavailable(f"{path}: broker response exceeds the {MAX_LINE} byte line bound")
    except BrokerUnavailable:
        raise
    except OSError as exc:
        raise BrokerUnavailable(f"{path}: {exc}") from exc
    line = buf.split(b"\n", 1)[0]
    try:
        response = json.loads(line)
    except (ValueError, UnicodeDecodeError) as exc:
        raise BrokerUnavailable(f"{path}: malformed response ({exc})") from exc
    if not isinstance(response, dict):
        raise BrokerUnavailable(f"{path}: response is not a JSON object")
    return response
