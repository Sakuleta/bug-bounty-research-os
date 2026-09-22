#!/usr/bin/env python3
"""Prove the sandbox-exec egress containment works ON THIS MACHINE.

Builds a real profile with tools/containment/generate_profile.py, then runs a
Python child UNDER `sandbox-exec -f profile -- python3 -c ...` and asserts:

  loopback_tcp      TCP connect to an in-process loopback listener        -> allowed
  local_address_tcp TCP connect to this host's non-loopback address       -> mode-dependent
  off_host_udp      UDP connect to 192.0.2.1 (RFC 5737 TEST-NET-1,        -> denied
                    reserved; connect() sends no packet)
  write_workspace   write inside the --workspace dir                      -> allowed
  write_tmp         write inside the user's temp dir                      -> allowed
  write_denied      write outside every allowed dir                       -> denied

No real egress is attempted: every probe is either in-machine or a zero-packet
reserved-address connect that must be refused at the syscall. Exit 0 on PASS or SKIP
(unsupported platform / missing sandbox-exec), 1 on FAIL — a profile the OS rejects is
a FAIL, never a SKIP; only an absent sandbox-exec or a non-darwin platform skips.
--json emits the full result.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from generate_profile import (  # noqa: E402
    build_profile,
    probe_literal_ip_support,
    repo_os_version,
    tmp_allow_root,
)

OFF_HOST_PROBE = "192.0.2.1:80"  # RFC 5737 TEST-NET-1: reserved, never routed
RESULT_PREFIX = "RO_SELFTEST_RESULT "

CHILD = r'''
import json, os, socket, sys

cfg = json.loads(os.environ["RO_SELFTEST_PROBE"])
out = {}

def connect(name, kind, target, family=socket.AF_INET):
    sock = socket.socket(family, kind)
    sock.settimeout(3)
    try:
        sock.connect(target)
        out[name] = "ok"
    except Exception as exc:
        out[name] = type(exc).__name__
    finally:
        sock.close()

def write(name, path):
    try:
        with open(path, "w") as fh:
            fh.write("probe\n")
        out[name] = "ok"
    except Exception as exc:
        out[name] = type(exc).__name__

connect("loopback_tcp", socket.SOCK_STREAM, ("127.0.0.1", cfg["loopback_port"]))
if cfg.get("local_port"):
    connect("local_address_tcp", socket.SOCK_STREAM, (cfg["local_address"], cfg["local_port"]))
host, port = cfg["off_host"].rsplit(":", 1)
connect("off_host_udp", socket.SOCK_DGRAM, (host, int(port)))
write("write_workspace", os.path.join(cfg["workspace"], "probe.txt"))
write("write_tmp", os.path.join(cfg["tmp"], "ro-selftest-probe.txt"))
write("write_denied", os.path.join(cfg["denied"], "probe.txt"))
print(cfg["prefix"] + json.dumps(out))
'''


def skip_reason(platform: str, sandbox_exec_present: bool, sandbox_exec: str = "") -> str | None:
    """The reason this machine cannot run the containment proof, or None."""
    if platform != "darwin":
        return f"sandbox-exec is a macOS (darwin) API; this platform is {platform!r}"
    if not sandbox_exec_present:
        return (f"sandbox-exec not found at {sandbox_exec or 'the default path'} "
                f"(pass --sandbox-exec PATH on macOS builds that ship it)")
    return None


def _sandbox_exec_exists(path: str) -> bool:
    return bool(shutil.which(path) or Path(path).exists())


def _outside_tmpdir(prefix: str) -> Path:
    """A temp dir that is NOT covered by the profile's temp-dir rule."""
    for base in ("/private/tmp", "/tmp"):
        try:
            return Path(tempfile.mkdtemp(prefix=prefix, dir=base))
        except OSError:
            continue
    raise OSError("no temp directory outside $TMPDIR is writable")


def _local_ipv4_candidates() -> list[str]:
    addresses: list[str] = []
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
    except OSError:
        return addresses
    for info in infos:
        ip = info[4][0]
        if ip and not ip.startswith("127.") and ip not in addresses:
            addresses.append(ip)
    return addresses


class Listener:
    """Minimal in-process TCP listener; accepts and answers 'ok'."""

    def __init__(self, host: str):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, 0))
        self.sock.listen(8)
        self.host, self.port = self.sock.getsockname()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                conn.sendall(b"ok")
            except OSError:
                pass
            finally:
                conn.close()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


def _start_local_listener() -> tuple[Listener | None, str | None]:
    """Bind a listener on a reachable non-loopback local IPv4 address, if one exists.

    Some addresses reported by getaddrinfo sit on interfaces that are down; binding
    succeeds there but a connect fails with EHOSTUNREACH, which would look like a
    containment result. Preflight in the parent (unsandboxed) and try the next one.
    """
    for candidate in _local_ipv4_candidates():
        try:
            listener = Listener(candidate)
        except OSError:
            continue
        try:
            probe = socket.create_connection((candidate, listener.port), timeout=2)
            probe.close()
            return listener, candidate
        except OSError:
            listener.close()
    return None, None


def run(sandbox_exec: str, json_out: bool) -> int:
    literal_ips = probe_literal_ip_support(sandbox_exec)
    result: dict = {
        "status": "FAIL",
        "ok": False,
        "platform": sys.platform,
        "sandbox_exec": sandbox_exec,
        "profile_mode": "literal-ip-pins" if literal_ips else "localhost-host-spec",
        "off_host_probe": OFF_HOST_PROBE,
        "probes": {},
        "notes": [],
    }
    workspace = denied = None
    loopback = local_listener = None
    try:
        try:
            workspace = _outside_tmpdir("ro-selftest-ws-")
            denied = _outside_tmpdir("ro-selftest-denied-")
            tmp_root = tmp_allow_root()
            loopback = Listener("127.0.0.1")
            local_listener, local_address = _start_local_listener()
        except OSError as exc:
            result.update(status="SKIP", ok=True,
                          reason=f"the containment proof cannot run on this machine: {exc}")
            return _emit(result, json_out)
        profile_path = workspace / "egress.sb"
        result.update(profile=str(profile_path), workspace=str(workspace),
                      denied_dir=str(denied), tmp=tmp_root)
        profile = build_profile(workspaces=[str(workspace)], literal_ips=literal_ips,
                                tmp_root=tmp_root, os_version=repo_os_version())
        profile_path.write_text(profile, encoding="utf-8")
        payload = {
            "prefix": RESULT_PREFIX,
            "loopback_port": loopback.port,
            "local_address": local_address,
            "local_port": local_listener.port if local_listener else None,
            "off_host": OFF_HOST_PROBE,
            "workspace": str(workspace),
            "denied": str(denied),
            "tmp": tmp_root,
        }
        env = dict(os.environ)
        env["RO_SELFTEST_PROBE"] = json.dumps(payload)
        env["TMPDIR"] = tmp_root
        proc = subprocess.run(
            [sandbox_exec, "-f", str(profile_path), "--", sys.executable, "-c", CHILD],
            capture_output=True, text=True, timeout=180, env=env)

        child_result = None
        for line in proc.stdout.splitlines():
            if line.startswith(RESULT_PREFIX):
                child_result = json.loads(line[len(RESULT_PREFIX):])
        if child_result is None:
            os_message = next((ln for ln in proc.stderr.splitlines() if ln.startswith("sandbox-exec:")), "")
            if os_message:
                # sandbox-exec is present and the generated profile was rejected: the
                # containment does NOT work here — FAIL, never a SKIP.
                result.update(status="FAIL", ok=False,
                              reason=f"the OS rejected the generated profile: {os_message}")
                return _emit(result, json_out)
            result["reason"] = (f"the sandboxed child produced no result (rc={proc.returncode}): "
                                f"{(proc.stderr or proc.stdout).strip()[:400]}")
            return _emit(result, json_out)

        expected = {
            "loopback_tcp": "ok",
            "local_address_tcp": "PermissionError" if literal_ips else "ok",
            "off_host_udp": "PermissionError",
            "write_workspace": "ok",
            "write_tmp": "ok",
            "write_denied": "PermissionError",
        }
        notes = {
            "loopback_tcp": "TCP connect to a loopback listener",
            "local_address_tcp": ("SBPL \"localhost\" matches every address of this host"
                                  if not literal_ips else
                                  "profile pins 127.0.0.1/[::1] literally"),
            "off_host_udp": f"UDP connect to {OFF_HOST_PROBE} (reserved, zero packets) must be refused",
            "write_workspace": "--workspace dir",
            "write_tmp": "user temp dir",
            "write_denied": "dir outside every allowed path",
        }
        for name, want in expected.items():
            if name == "local_address_tcp" and local_listener is None:
                result["probes"][name] = {
                    "result": "skipped", "outcome": "skipped", "expected": want, "ok": True,
                    "note": "no reachable non-loopback IPv4 address on this machine"}
                continue
            got = child_result.get(name, "missing")
            outcome = {"ok": "allowed", "PermissionError": "denied"}.get(got, "error")
            good = (got == want)
            result["probes"][name] = {
                "result": got, "outcome": outcome, "expected": want, "ok": good, "note": notes[name]}
            if not good:
                result["status"] = "FAIL"
        if denied.joinpath("probe.txt").exists():
            result["probes"]["write_denied"] = {
                **result["probes"]["write_denied"], "ok": False,
                "note": "the denied dir exists on disk after the run"}
        for leftover in (workspace / "probe.txt", denied / "probe.txt",
                         Path(tmp_root) / "ro-selftest-probe.txt"):
            try:
                leftover.unlink()
            except OSError:
                pass
        ok = all(p["ok"] for p in result["probes"].values())
        result.update(status="PASS" if ok else "FAIL", ok=ok)
        if ok:
            result["notes"].append(
                "containment verified: the wrapped child reached loopback and this host only; "
                "off-host connect and out-of-allowlist writes were refused by the kernel")
        return _emit(result, json_out)
    finally:
        if loopback is not None:
            loopback.close()
        if local_listener is not None:
            local_listener.close()
        for directory in (workspace, denied):
            if directory is not None:
                shutil.rmtree(directory, ignore_errors=True)


def _emit(result: dict, json_out: bool) -> int:
    status = result["status"]
    if json_out:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        if status == "SKIP":
            print(f"SKIP: {result['reason']}")
        else:
            for name, probe in result["probes"].items():
                mark = "ok" if probe["ok"] else "FAIL"
                print(f"{mark}: {name}: {probe['outcome']} ({probe['result']}, expected "
                      f"{probe['expected']}) — {probe['note']}")
            if status == "PASS":
                print(f"PASS: sandbox-exec containment verified ({result['profile_mode']}, "
                      f"off-host probe {result['off_host_probe']} refused)")
            else:
                print(f"FAIL: containment proof failed ({result.get('reason', 'probe mismatch')})")
    return 0 if status in ("PASS", "SKIP") else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="selftest.py",
        description="Prove the sandbox-exec egress containment works on this machine "
                    "(in-machine probes only; no real egress).",
        epilog="Exit 0 on PASS or SKIP, 1 on FAIL.")
    parser.add_argument("--json", action="store_true", help="emit the full result as JSON")
    parser.add_argument("--sandbox-exec", default=shutil.which("sandbox-exec") or "/usr/bin/sandbox-exec",
                        metavar="PATH", help="sandbox-exec binary to use (default: %(default)s)")
    args = parser.parse_args(argv)

    reason = skip_reason(sys.platform, _sandbox_exec_exists(args.sandbox_exec), args.sandbox_exec)
    if reason is not None:
        return _emit({"status": "SKIP", "ok": True, "platform": sys.platform,
                      "sandbox_exec": args.sandbox_exec, "reason": reason}, args.json)
    return run(args.sandbox_exec, args.json)


if __name__ == "__main__":
    raise SystemExit(main())
