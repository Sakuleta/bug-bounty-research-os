#!/usr/bin/env python3
"""Tests for tools/containment/ (SBPL egress containment below the tool layer).

Covers the profile generator (determinism, deny-by-default, loopback allow,
literal-IP pins, --allow validation, --print/--out equivalence, workspace write
rules) and the machine selftest (SKIP paths, real containment proof on macOS).

Run: python3 tools/test_containment.py (exits non-zero on failure).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parent
CONTAINMENT = TOOLS / "containment"
GEN = CONTAINMENT / "generate_profile.py"
SELFTEST = CONTAINMENT / "selftest.py"
SANDBOX_EXEC = shutil.which("sandbox-exec") or "/usr/bin/sandbox-exec"

sys.path.insert(0, str(CONTAINMENT))
import selftest as selftest_mod  # noqa: E402
from generate_profile import (  # noqa: E402
    PROBE_PROFILE,
    build_profile,
    parse_allow,
    probe_literal_ip_support,
)

passed: list[str] = []
skipped: list[str] = []


def check(name: str, cond: bool):
    assert cond, f"FAIL: {name}"
    passed.append(name)
    print(f"ok: {name}")


def skip(name: str, reason: str):
    skipped.append(name)
    print(f"skip: {name} ({reason})")


def gen(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(GEN), *argv], capture_output=True, text=True)


def run_selftest(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SELFTEST), *argv], capture_output=True, text=True)


def tmpdir() -> Path:
    return Path(tempfile.mkdtemp(prefix="ro-containment-test-"))


# --- generator: determinism, defaults, loopback ------------------------------

workspace = tmpdir()
runs = [gen("--print", "--workspace", str(workspace)) for _ in range(2)]
check("generator exits 0", runs[0].returncode == 0 and runs[1].returncode == 0)
check("two runs are byte-identical", runs[0].stdout == runs[1].stdout)
profile = runs[0].stdout
check("(deny default) present", "(deny default)" in profile)
check("loopback outbound allow present",
      '(allow network-outbound (remote ip "localhost:*"))' in profile)
check("loopback bind/inbound allows present",
      '(allow network-bind (local ip "localhost:*"))' in profile
      and '(allow network-inbound (local ip "localhost:*"))' in profile)
check("header records the generator", "generate_profile.py" in profile)
check("header records OS_VERSION",
      f"OS_VERSION: {(REPO / 'OS_VERSION').read_text().strip()}" in profile)
check("header documents the deprecated API and the wrap command",
      "DEPRECATED" in profile and "sandbox-exec -f" in profile)
check("header documents that DNS names are never used", "DNS" in profile and "literal" in profile.lower())

# --- generator: workspace write rules ---------------------------------------

check("workspace write rule emitted",
      f'(allow file-write* (subpath "{workspace.resolve()}"))' in profile)
check("temp-dir write rule emitted",
      f'(allow file-write* (subpath "{Path(tempfile.gettempdir()).resolve()}"))' in profile)
check("no unrestricted write rule when --workspace is given",
      "(allow file-write*)\n" not in profile)

free = gen("--print")
check("file writes are unrestricted without --workspace",
      "(allow file-write*)\n" in free.stdout)
check("unrestricted mode is stated in the header", "unrestricted" in free.stdout.lower())

# --- generator: --allow literal IPs (unit-level, host independent) -----------

allows = [parse_allow("203.0.113.7:443"), parse_allow("10.0.0.5:8080")]
literal = build_profile(workspaces=[str(workspace)], allows=allows, literal_ips=True)
check("literal loopback pins emitted when the parser supports them",
      '(allow network-outbound (remote ip "127.0.0.1:*"))' in literal
      and '(allow network-outbound (remote ip "[::1]:*"))' in literal)
check("literal --allow pins appear sorted",
      literal.index('(remote ip "10.0.0.5:8080")') < literal.index('(remote ip "203.0.113.7:443")'))
check("literal pins are network-outbound rules",
      '(allow network-outbound (remote ip "10.0.0.5:8080"))' in literal)

r = gen("--print", "--literal-ips", "--allow", "203.0.113.7:443", "--allow", "10.0.0.5:8080")
check("--allow pins render through the CLI in sorted order",
      r.returncode == 0
      and r.stdout.index("(remote ip \"10.0.0.5:8080\")") < r.stdout.index("(remote ip \"203.0.113.7:443\")"))

loopback_allow = gen("--print", "--literal-ips", "--allow", "127.0.0.1:8080")
check("loopback --allow is accepted",
      loopback_allow.returncode == 0 and '(remote ip "127.0.0.1:8080")' in loopback_allow.stdout)

# --- generator: rejection paths ---------------------------------------------

r = gen("--print", "--allow", "evil.example:443")
check("hostname in --allow is rejected with an actionable error",
      r.returncode != 0 and "not a literal ip" in r.stderr.lower()
      and "dns" in r.stderr.lower() and "evil.example" in r.stderr)

r = gen("--print", "--allow", "10.0.0.5:0")
check("port 0 is rejected", r.returncode != 0 and "port" in r.stderr.lower())

r = gen("--print", "--allow", "::1:8080")
check("unbracketed IPv6 is rejected with the bracket form documented",
      r.returncode != 0 and "[::1]:8080" in r.stderr)

# --- generator: --print / --out equivalence ---------------------------------

out_dir = tmpdir()
out_path = out_dir / "egress.sb"
r = gen("--out", str(out_path), "--workspace", str(workspace))
check("--out writes the profile", r.returncode == 0 and out_path.is_file())
check("--out and --print are byte-identical",
      out_path.read_text() == gen("--print", "--workspace", str(workspace)).stdout)
check("--out leaves no temp file behind",
      sorted(p.name for p in out_dir.iterdir()) == ["egress.sb"])
r = gen("--print", "--out", str(out_dir / "other.sb"))
check("--print and --out are mutually exclusive", r.returncode != 0)

# --- generator: the literal-IP probe measures the PARSER verdict -----------------
#
# A profile is only "accepted" when the parser accepts the literal-IP syntax AND the
# exec plumbing (process, file reads) is allowed — so the probe profile must carry
# `(allow process*)` and `(allow file-read*)` or an accepting parser is misreported as
# literal-IP-incapable. This host's sandbox-exec cannot change behavior, so the two
# parser verdicts are simulated with stub binaries that inspect the probe they receive.

def make_fake_parser(path: Path, literal_exit: int) -> Path:
    script = f"""#!/bin/sh
prof=""
while [ $# -gt 0 ]; do
  case "$1" in
    -f) prof="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$FAKE_SBPL_CAPTURE" ] && cp "$prof" "$FAKE_SBPL_CAPTURE"
grep -q '(allow process\\*)' "$prof" || exit 1
grep -q '(allow file-read\\*)' "$prof" || exit 1
if grep -q 'remote ip "127.0.0.1:1"' "$prof"; then
  exit {literal_exit}
fi
exit {0 if literal_exit == 1 else 1}
"""
    path.write_text(script)
    path.chmod(0o755)
    return path


fake_dir = tmpdir()
fake_capture = fake_dir / "probe.sb"
accept_parser = make_fake_parser(fake_dir / "sandbox-accept", 0)
reject_parser = make_fake_parser(fake_dir / "sandbox-reject", 1)
prev_capture = os.environ.get("FAKE_SBPL_CAPTURE")
os.environ["FAKE_SBPL_CAPTURE"] = str(fake_capture)
try:
    accept_result = probe_literal_ip_support(str(accept_parser))
    accept_captured = fake_capture.read_text()
    reject_result = probe_literal_ip_support(str(reject_parser))
finally:
    if prev_capture is None:
        os.environ.pop("FAKE_SBPL_CAPTURE", None)
    else:
        os.environ["FAKE_SBPL_CAPTURE"] = prev_capture

check("the probe profile carries process* and file-read* allows",
      "(allow process*)" in PROBE_PROFILE and "(allow file-read*)" in PROBE_PROFILE)
check("the probe profile pins a literal loopback address",
      'remote ip "127.0.0.1:1"' in PROBE_PROFILE)
check("the probe reports an accepting parser as literal-capable", accept_result is True)
check("the probe reports a rejecting parser as localhost-only", reject_result is False)
check("the probe hands the allows to the parser",
      "(allow process*)" in accept_captured and "(allow file-read*)" in accept_captured)

accept_run = gen("--print", "--sandbox-exec", str(accept_parser), "--allow", "203.0.113.7:443")
check("an accepting parser yields literal pins and a header that claims them",
      accept_run.returncode == 0 and '(remote ip "203.0.113.7:443")' in accept_run.stdout
      and "accepts literal-IP network hosts (probed)" in accept_run.stdout)
reject_run = gen("--print", "--sandbox-exec", str(reject_parser))
check("a rejecting parser yields localhost-only rules and a header that claims them",
      reject_run.returncode == 0 and '(remote ip "127.0.0.1:*")' not in reject_run.stdout
      and 'accepts only "*" and "localhost" as network hosts' in reject_run.stdout)
reject_allow = gen("--print", "--sandbox-exec", str(reject_parser), "--allow", "203.0.113.7:443")
check("a rejecting parser refuses to pin a remote literal IP",
      reject_allow.returncode != 0 and "cannot be expressed" in reject_allow.stderr)

# --- generator: the emitted profile must be accepted by this host ------------

if shutil.which("sandbox-exec") or Path(SANDBOX_EXEC).exists():
    host_literal = probe_literal_ip_support(SANDBOX_EXEC)
    probe_file = out_dir / "compile.sb"
    gen("--out", str(probe_file), "--workspace", str(workspace))
    c = subprocess.run([SANDBOX_EXEC, "-f", str(probe_file), "--", "/usr/bin/true"],
                       capture_output=True, text=True)
    check("this host's sandbox-exec accepts the generated profile",
          c.returncode == 0)
    if host_literal:
        check("literal-capable host emits literal loopback pins",
              '(remote ip "127.0.0.1:*")' in probe_file.read_text())
    else:
        r = gen("--print", "--allow", "203.0.113.7:443")
        check("host without literal-IP support refuses to pin a remote literal IP",
              r.returncode != 0 and "203.0.113.7" in r.stderr
              and "localhost" in r.stderr)
        r = gen("--print", "--allow", "127.0.0.1:8080")
        check("host without literal-IP support covers a loopback --allow",
              r.returncode == 0)
else:
    skip("host profile compile", "sandbox-exec is not installed")

# --- selftest: SKIP paths ----------------------------------------------------

check("skip_reason is None on darwin with sandbox-exec", selftest_mod.skip_reason("darwin", True) is None)
check("skip_reason names the platform on non-darwin",
      "darwin" in (selftest_mod.skip_reason("linux", True) or ""))
check("skip_reason names the missing binary",
      "sandbox-exec" in (selftest_mod.skip_reason("darwin", False) or ""))

r = run_selftest("--sandbox-exec", str(out_dir / "missing-sandbox-exec"))
check("selftest SKIPs (exit 0) when sandbox-exec is missing",
      r.returncode == 0 and "SKIP" in r.stdout and "missing-sandbox-exec" in r.stdout)

r = run_selftest("--sandbox-exec", str(out_dir / "missing-sandbox-exec"), "--json")
data = json.loads(r.stdout)
check("selftest --json reports the SKIP visibly",
      r.returncode == 0 and data["status"] == "SKIP" and "missing-sandbox-exec" in data["reason"])

# A genuinely present sandbox-exec whose parser REJECTS the generated profile is a
# containment FAILURE (exit non-zero), never a SKIP: only an absent binary or platform
# may skip.
reject_all = fake_dir / "sandbox-rejects-everything"
reject_all.write_text(
    "#!/bin/sh\n"
    "echo 'sandbox-exec: /tmp/x.sb:9:7: syntax error: invalid network host' >&2\n"
    "exit 1\n")
reject_all.chmod(0o755)
r = run_selftest("--sandbox-exec", str(reject_all), "--json")
data = json.loads(r.stdout)
check("an OS-rejected profile is a FAIL (non-zero), not a SKIP",
      r.returncode != 0 and data["status"] == "FAIL"
      and "rejected" in data.get("reason", ""))
r = run_selftest("--sandbox-exec", str(reject_all))
check("the rejected-profile FAIL is visible without --json",
      r.returncode != 0 and "FAIL" in r.stdout and "SKIP" not in r.stdout)

# --- selftest: the real containment proof on this machine -------------------

if not (shutil.which("sandbox-exec") or Path(SANDBOX_EXEC).exists()):
    skip("real selftest", "sandbox-exec is not installed")
else:
    r = run_selftest("--json")
    start = r.stdout.find("{")
    data = json.loads(r.stdout[start:]) if start >= 0 else {}
    status = data.get("status", "FAIL")
    if status == "PASS":
        check("real selftest proves containment under sandbox-exec",
              data["ok"] is True and all(p["ok"] for p in data["probes"].values()))
        for name, p in data["probes"].items():
            if p.get("note"):
                print(f"    probe {name}: {p['result']} ({p['note']})")
    elif status == "SKIP":
        skip("real selftest", data.get("reason", "environment cannot run it"))
    else:
        check(f"real selftest passes (status={status}, rc={r.returncode})", False)

print(f"\n{len(passed)}/{len(passed)} passed" + (f", {len(skipped)} skipped" if skipped else ""))
