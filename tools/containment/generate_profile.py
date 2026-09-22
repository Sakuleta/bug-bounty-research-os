#!/usr/bin/env python3
"""Deterministic SBPL (Scheme) egress-containment profile generator for macOS.

Containment BELOW the tool layer: wrap the agent host process tree so the only
reachable network destinations are loopback / this host.

    sandbox-exec -f tools/containment/macos-egress.sb -- <host command>

Network model: `(deny default)` denies everything; the profile then allows
loopback and, when the host's SBPL parser supports literal network hosts, pins
each `--allow IP:PORT` exception to its literal address. DNS names are never
used: SBPL has no resolution step, so a name would either be rejected by the
parser or pin whatever it resolved to when the profile was compiled.

The emitted profile is deterministic: same inputs -> byte-identical output
(the one host-dependent decision — literal-IP support — is probed, not guessed,
and can be forced with --literal-ips / --no-literal-ips).
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

GENERATOR = "tools/containment/generate_profile.py"
DEFAULT_SANDBOX_EXEC = "/usr/bin/sandbox-exec"
TMP_FALLBACK = "/private/var/folders"

# The literal-IP support probe: a minimal profile that denies everything, re-allows the
# exec plumbing the wrapped `/usr/bin/true` needs (process creation, file reads) and then
# tries one literal-IP network rule. With the plumbing allowed, the command's exit code
# reflects the PARSER's verdict on the literal-IP syntax; without them the command fails
# on its own and a literal-capable parser would be misreported as incapable.
PROBE_PROFILE = (
    "(version 1)\n"
    "(deny default)\n"
    "(allow process*)\n"
    "(allow file-read*)\n"
    '(allow network-outbound (remote ip "127.0.0.1:1"))\n'
)

USAGE_NOTES = """\
sandbox-exec is a DEPRECATED macOS API (man sandbox-exec); it still enforces
kernel-level containment but is not a supported interface. This generator is a
containment layer, not a hardened security boundary: it constrains the network
reachable by the wrapped process tree, not the user's other processes.

The profile is pinned to literal IPs (no DNS names, ever) and is meant to wrap
the agent host, so the controlled executors / proxy become the sole egress path:

    python3 tools/containment/generate_profile.py --print --workspace "$PWD" > /tmp/egress.sb
    sandbox-exec -f /tmp/egress.sb -- <host command>

--allow takes IP:PORT only (IPv6 bracketed, e.g. [::1]:8080). A hostname is
rejected: resolve it yourself and pin the literal IP, or route the target
through the controlled executors. On macOS builds whose SBPL parser accepts only
"*" and "localhost" as network hosts (probed at generation time), a non-loopback
--allow cannot be expressed and the generator refuses instead of emitting a
profile the OS would reject wholesale. --workspace is repeatable; when omitted,
file writes stay unrestricted and the header says so.
"""

DNS_HELP = (
    "DNS names are not permitted: this profile pins literal IPs only and never "
    "resolves names. sandbox-exec has no DNS step, so a hostname would either be "
    "rejected by the profile parser or pin whatever it resolved to when the profile "
    "was compiled — not the egress decision you asked for. Resolve the name yourself, "
    "pin the literal IP, or route the target through the controlled executors.")


def parse_allow(spec: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    """Parse an --allow spec (IP:PORT, IPv6 bracketed). Refuses hostnames and DNS."""
    host, sep, port_text = spec.rpartition(":")
    if not sep or not host:
        raise SystemExit(f"generate_profile: --allow expects IP:PORT, got {spec!r}")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    elif ":" in host:
        raise SystemExit(
            f"generate_profile: --allow {spec!r}: IPv6 addresses must be bracketed, "
            f"e.g. [{host}]:{port_text}")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise SystemExit(
            f"generate_profile: --allow {spec!r}: {host!r} is not a literal IP address. "
            f"{DNS_HELP}")
    if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        raise SystemExit(f"generate_profile: --allow {spec!r}: port must be an integer in 1-65535")
    return address, int(port_text)


def probe_literal_ip_support(sandbox_exec: str) -> bool:
    """True when this host's SBPL parser accepts literal-IP network hosts.

    macOS 26 accepts only `*` and `localhost`; older builds accept literal
    addresses. Probing beats guessing: a profile carrying a literal pin is
    rejected wholesale by a parser that cannot read it, and sandbox-exec then
    refuses to execute the command at all. The probe profile allows the exec
    plumbing (see `PROBE_PROFILE`), so the exit code is the parser's verdict on
    the literal-IP rule — not an unrelated sandbox denial of exec or file reads.
    """
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".sb", delete=False) as fh:
            fh.write(PROBE_PROFILE)
            path = fh.name
    except OSError:
        return False
    try:
        result = subprocess.run([sandbox_exec, "-f", path, "--", "/usr/bin/true"],
                                capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return result.returncode == 0


def repo_os_version() -> str | None:
    """The workspace OS_VERSION (repo root two levels above this file), when present."""
    version_file = Path(__file__).resolve().parents[2] / "OS_VERSION"
    try:
        value = version_file.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


def tmp_allow_root() -> str:
    """The user's temp dir as SBPL must see it: a resolved absolute path."""
    candidate = os.environ.get("TMPDIR") or tempfile.gettempdir()
    return os.path.realpath(candidate) if os.path.isdir(candidate) else TMP_FALLBACK


def _header(workspaces: list[str], tmp_root: str, os_version: str | None,
            literal_ips: bool, covered_loopback: list[str]) -> list[str]:
    version_line = f"OS_VERSION: {os_version}" if os_version else "OS_VERSION: unavailable"
    lines = [
        f"; Generated by {GENERATOR} — do not hand-edit.",
        f"; {version_line}",
        ";",
        "; Containment BELOW the tool layer: wrap the agent host process tree with",
        ";   sandbox-exec -f <this file> -- <host command>",
        "; sandbox-exec is a DEPRECATED macOS API; this is a containment layer, not a",
        "; hardened security boundary. It constrains the network reachable by the wrapped",
        "; process tree, not the user's other processes.",
        ";",
        "; Network: (deny default) denies every destination except loopback / this host.",
    ]
    if literal_ips:
        lines += [
            "; This host's SBPL parser accepts literal-IP network hosts (probed): loopback is",
            "; pinned to 127.0.0.1 / [::1] and every --allow entry is pinned to its literal IP",
            "; and port. No DNS is consulted at any point — names are rejected at generation",
            "; time; the only sanctioned egress is loopback, so the controlled executors /",
            "; proxy are the sole path off-host.",
        ]
    else:
        lines += [
            "; This host's SBPL parser accepts only \"*\" and \"localhost\" as network hosts",
            "; (probed with sandbox-exec), so a literal-IP pin is not expressible here.",
            "; \"localhost\" matches every address of this machine: connections that terminate",
            "; on this host (loopback and the host's own interfaces) are allowed, every other",
            "; destination is denied. No DNS is consulted at any point — names are rejected at",
            "; generation time; the only sanctioned egress is loopback, so the controlled",
            "; executors / proxy are the sole path off-host.",
        ]
    if covered_loopback:
        lines.append("; --allow entries covered by the loopback rule (no extra rule needed): "
                     + ", ".join(covered_loopback))
    if workspaces:
        lines += [
            ";",
            "; File writes: restricted to the --workspace directories below, the user's temp",
            f"; dir ({tmp_root}) and the standard /dev streams.",
        ]
    else:
        lines += [
            ";",
            "; File writes: UNRESTRICTED — no --workspace was given, so file-write* is allowed",
            "; everywhere. Pass --workspace DIR to restrict writes to that directory plus the",
            "; user's temp dir.",
        ]
    return lines


def build_profile(*, workspaces=(), allows=(), literal_ips: bool = False,
                  tmp_root: str | None = None, os_version: str | None = None) -> str:
    """Render the SBPL profile. Deterministic for identical inputs."""
    write_dirs = sorted({os.path.realpath(w) for w in workspaces})
    tmp_root = os.path.realpath(tmp_root) if tmp_root is not None else tmp_allow_root()
    os_version = os_version if os_version is not None else repo_os_version()
    allow_pairs = sorted(allows, key=lambda item: (item[0].version, int(item[0]), item[1]))
    if literal_ips:
        covered: list[str] = []
        pinned = allow_pairs
    else:
        if any(not ip.is_loopback for ip, _ in allow_pairs):
            raise ValueError("literal-IP allows cannot be expressed in localhost-only mode")
        covered = [f"{ip}:{port}" for ip, port in allow_pairs if ip.is_loopback]
        pinned = []

    lines = _header(write_dirs, tmp_root, os_version, literal_ips, covered)
    lines += [
        "",
        "(version 1)",
        "(deny default)",
        "",
        "; process + system plumbing an agent host needs",
        "(allow process*)",
        "(allow sysctl-read)",
        "(allow mach-lookup)",
        "(allow file-read*)",
        "",
        "; file writes",
    ]
    if write_dirs:
        lines.append('(allow file-write* (literal "/dev/null"))')
        lines.append('(allow file-write* (literal "/dev/stderr"))')
        lines.append('(allow file-write* (literal "/dev/stdout"))')
        lines.append('(allow file-write* (literal "/dev/tty"))')
        for directory in write_dirs:
            lines.append(f'(allow file-write* (subpath "{directory}"))')
        if tmp_root not in write_dirs:
            lines.append(f'(allow file-write* (subpath "{tmp_root}"))')
    else:
        lines.append("; no --workspace given — file writes are unrestricted (see header)")
        lines.append("(allow file-write*)")
    lines += [
        "",
        "; network: loopback / this host only",
        '(allow network-bind (local ip "localhost:*"))',
        '(allow network-inbound (local ip "localhost:*"))',
        '(allow network-outbound (remote ip "localhost:*"))',
    ]
    if literal_ips:
        lines.append('(allow network-outbound (remote ip "127.0.0.1:*"))')
        lines.append('(allow network-outbound (remote ip "[::1]:*"))')
        for ip, port in pinned:
            lines.append(f'(allow network-outbound (remote ip "{ip}:{port}"))')
    return "\n".join(lines) + "\n"


def write_atomic(path: Path, text: str) -> None:
    """Write via a sibling temp file + os.replace, so readers never see a partial profile."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="generate_profile.py",
        description="Generate a deterministic sandbox-exec (SBPL) egress-containment "
                    "profile for the agent host.",
        epilog=USAGE_NOTES,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--workspace", action="append", default=[], metavar="DIR",
                        help="directory the wrapped process may write to (repeatable); "
                             "when omitted, file writes stay unrestricted and the header says so")
    parser.add_argument("--allow", action="append", default=[], metavar="IP:PORT",
                        help="literal-IP egress exception (repeatable, sorted); "
                             "hostnames are rejected — the profile never uses DNS")
    parser.add_argument("--literal-ips", action="store_true",
                        help="force literal-IP rules (default: probe the host's SBPL parser)")
    parser.add_argument("--no-literal-ips", action="store_true",
                        help="force the localhost-only form (default: probe)")
    parser.add_argument("--sandbox-exec", default=shutil.which("sandbox-exec") or DEFAULT_SANDBOX_EXEC,
                        metavar="PATH", help="sandbox-exec binary to probe (default: %(default)s)")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--out", metavar="PATH", help="write the profile atomically (temp + replace)")
    output.add_argument("--print", dest="to_stdout", action="store_true",
                        help="print the profile to stdout (default when --out is absent)")
    args = parser.parse_args(argv)

    if args.literal_ips and args.no_literal_ips:
        parser.error("--literal-ips and --no-literal-ips are mutually exclusive")
    literal_ips = args.literal_ips or (not args.no_literal_ips
                                       and probe_literal_ip_support(args.sandbox_exec))
    allows = [parse_allow(spec) for spec in args.allow]
    if not literal_ips:
        unexpressible = [f"{ip}:{port}" for ip, port in allows if not ip.is_loopback]
        if unexpressible:
            parser.error(
                f"--allow {', '.join(unexpressible)} cannot be expressed on this host: its "
                f"SBPL parser accepts only \"*\" and \"localhost\" as network hosts (probed "
                f"with {args.sandbox_exec}), so a literal-IP pin would make sandbox-exec "
                f"reject the whole profile. Loopback rules are already emitted; for egress to "
                f"a specific remote IP run the host in a VM/container or route it through the "
                f"controlled executors.")
    text = build_profile(workspaces=args.workspace, allows=allows, literal_ips=literal_ips)
    if args.out:
        write_atomic(Path(args.out), text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
