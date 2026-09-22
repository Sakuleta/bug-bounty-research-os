#!/usr/bin/env python3
"""Tests for tools/broker/ — the policy broker outside the agent-writable workspace.

Spawns the real daemon on a temp home and exercises the real Unix socket: protocol
(hello/status, malformed frames, unknown ops, line bound), policy put/get incl. the
human_reference rule, token mint scope enforcement, single-use consume, tamper/expiry
refusals, file permissions, the stdlib client, the control-plane integration
(set_scope pushes, prepare mints through the broker, prepare fails closed when the
broker holds no policy or is unreachable) and the broker-down path.

Run: python3 tools/test_broker.py (exits non-zero on failure).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parent
BROKER = TOOLS / "broker" / "broker.py"
RESEARCHCTL = TOOLS / "researchctl.py"

sys.path.insert(0, str(TOOLS))
from broker import client as broker_client  # noqa: E402
from control_plane import ControlPlane  # noqa: E402

passed: list[str] = []


def check(name: str, cond: bool):
    assert cond, f"FAIL: {name}"
    passed.append(name)
    print(f"ok: {name}")


def tmpdir(prefix: str) -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix))


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def set_home(home: Path | None):
    """Point the client (and any spawned broker) at `home`'s socket."""
    if home is None:
        os.environ.pop("RESEARCH_OS_BROKER_HOME", None)
        os.environ.pop("RESEARCH_OS_BROKER_SOCKET", None)
    else:
        os.environ["RESEARCH_OS_BROKER_HOME"] = str(home)
        os.environ.pop("RESEARCH_OS_BROKER_SOCKET", None)


def wait_for_socket(path: Path, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise AssertionError(f"broker socket never appeared: {path}")


def spawn_broker(home: Path) -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, str(BROKER), "--serve", "--home", str(home)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    wait_for_socket(home / "broker.sock")
    return proc


def stop_broker(proc: subprocess.Popen) -> None:
    import signal
    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=10)


def raw_line(sock_path: Path, payload: bytes, threaded: bool = False) -> dict:
    """Send raw bytes on one connection and parse the first response line."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(str(sock_path))
    try:
        if threaded:
            sender = threading.Thread(target=lambda: _safe_sendall(s, payload), daemon=True)
            sender.start()
            data = s.recv(65536)
            s.close()
            sender.join(5)
        else:
            s.sendall(payload)
            data = b""
            while b"\n" not in data:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        return json.loads(data.split(b"\n")[0])
    finally:
        try:
            s.close()
        except OSError:
            pass


def _safe_sendall(s: socket.socket, payload: bytes) -> None:
    try:
        s.sendall(payload)
    except OSError:
        pass


def call(op: str, **payload) -> dict:
    try:
        return broker_client.call(op, timeout=5, **payload)
    except broker_client.BrokerUnavailable as exc:
        raise AssertionError(f"broker call {op} unavailable: {exc}") from exc


def rev(n: int, tag: str = "rev") -> str:
    """A synthetic scope revision (`EV-seq:hash`, the set_scope event identity)."""
    return f"EV-{n:06d}:" + hashlib.sha256(f"{tag}-{n}".encode()).hexdigest()


def next_rev(policy: dict, tag: str = "rev") -> str:
    """The revision after a stored policy's revision (monotonic per workspace)."""
    seq = int(str(policy.get("scope_revision") or "EV-000000:0").split(":")[0].split("-")[1])
    return rev(seq + 1, tag)


def run_scope_check(root: Path, url: str) -> tuple[subprocess.CompletedProcess, dict]:
    """The runner-facing CLI seam: `researchctl <root> scope-check <url>`."""
    run = subprocess.run(
        [sys.executable, str(RESEARCHCTL), str(root), "scope-check", url],
        capture_output=True, text=True, env=dict(os.environ))
    return run, json.loads(run.stdout)


def ttl_seconds_left(expires_at: str) -> float:
    return (datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            - datetime.now(timezone.utc)).total_seconds()


# --- fixture workspace (same shape the control-plane suites use) --------------

def triage_for(root: Path, objective: str) -> list[dict]:
    from knowledge_index import selection_cap, selection_query, top_packs
    ranked = [name for name, _ in top_packs(root, selection_query(root, objective), k=selection_cap())]
    return [{"pack": name, "verdict": "SKIP", "reason": "broker test fixture reason covers this pack"}
            for name in (ranked or ["fixture"])]


def fixture_root() -> tuple[Path, ControlPlane]:
    root = tmpdir("ro-broker-ws-")
    for d in ["00_control", "02_surface", "03_hypotheses/active", "03_hypotheses/archive",
              "04_cycles", "10_learning", "11_runtime", "12_knowledge/fixture"]:
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / "02_surface/endpoints.yaml").write_text("endpoints: []\n")
    (root / "10_learning/freshness.yaml").write_text("components: []\n")
    (root / "10_learning/unknowns.yaml").write_text("unknowns: []\n")
    (root / "10_learning/assumptions.yaml").write_text("assumptions: []\n")
    (root / "11_runtime/events.jsonl").write_text("")
    (root / "12_knowledge/fixture/fixture.md").write_text("# Fixture pack\n")
    (root / "12_knowledge/INDEX.yaml").write_text(
        "packs:\n  fixture:\n    load_when: [broker, fixture]\n    files: [fixture.md]\n")
    cp = ControlPlane(root)
    objective = "does the broker gate the fixture"
    cp.create_cycle("C-0001", {
        "id": "C-0001", "type": "DISCOVERY", "objective": objective,
        "allowed_scope": ["example.test"], "stop_conditions": ["stop"], "controls": [],
        "status": "PLANNED", "knowledge_triage": triage_for(root, objective),
    })
    (root / "04_cycles/C-0001/objective.md").write_text(
        "# Cycle Objective\n\n## Question\nDoes the broker gate the request?\n\n"
        "## Minimal test\nOne prepare against the fixture scope.\n")
    cp.transition_cycle("C-0001", "READY", reason="ready")
    cp.transition_cycle("C-0001", "RUNNING", reason="run")
    cp.create_hypothesis("H-0001", {
        "cycle_id": "C-0001", "observation": "broker fixture", "hypothesis": "broker fixture",
        "secure_prediction": "denied", "vulnerable_prediction": "allowed"})
    return root, cp


def prepare_payload(url: str, family: str = "http") -> dict:
    shape = ({"url": url, "principal": "researcher-A"} if family == "browser"
             else {"method": "GET", "url": url, "principal": "researcher-A"})
    return {
        "cycle_id": "C-0001", "target": url, "scope_status": "IN_SCOPE", "account": "researcher-A",
        "object_owner": "researcher-A", "purpose": "broker integration", "hypothesis": "H-0001",
        "expected_secure": "no traffic", "expected_vulnerable": "n/a", "side_effect": "none",
        "stop_condition": "stop after one prepare", "tool_family": family, "request_shape": shape,
    }


def wsid_of(workspace: str) -> str:
    return hashlib.sha256(str(Path(workspace).resolve()).encode()).hexdigest()


# =============================================================================
# Phase A — a live broker on a temp home: protocol, policy, tokens, client.
# =============================================================================

HOME = tmpdir("ro-broker-home-")
SOCK = HOME / "broker.sock"
set_home(HOME)
broker_proc = spawn_broker(HOME)

check("broker socket exists", SOCK.exists())
check("broker home is 0700", stat.S_IMODE(HOME.stat().st_mode) == 0o700)
check("broker socket is 0600", stat.S_IMODE(SOCK.stat().st_mode) == 0o600)
key = HOME / "key"
check("broker key exists, is 0600 and 32 bytes",
      key.exists() and stat.S_IMODE(key.stat().st_mode) == 0o600 and len(key.read_bytes()) == 32)
KEY_BYTES = key.read_bytes()

# --- hello / status ----------------------------------------------------------

hello = call("hello")
check("hello reports the version", hello["ok"] is True and hello["version"].startswith("research-os-broker/"))
check("hello advertises the capability set",
      set(hello["capabilities"]) == {"policy.get", "policy.put", "scope.check", "token.mint",
                                     "token.consume", "status"})

ws = str(tmpdir("ro-broker-ws-policy-").resolve())
st = call("status", workspace=ws)
check("status reports key presence and version",
      st["ok"] is True and st["key_present"] is True and st["version"] == hello["version"])
check("a fresh workspace has no broker policy", st["policy_present"] is False and st["policy"] is None)
check("status never returns key material", KEY_BYTES.hex() not in json.dumps(st))

# --- policy.put / policy.get -------------------------------------------------

refused = call("policy.put", workspace=ws, assets=["example.test"], gate="assets")
check("policy.put requires source_reference",
      refused["ok"] is False and "source_reference" in refused["error"])

refused = call("policy.put", workspace=ws, assets=["example.test"], gate="dns",
               source_reference="policy://x")
check("policy.put refuses an unknown gate", refused["ok"] is False and "gate" in refused["error"])

for bad in (123, "a b", "a\nb", "a\x00b", ""):
    resp = call("policy.put", workspace=ws, assets=[bad], gate="assets", source_reference="policy://x")
    check(f"policy.put refuses asset {bad!r}", resp["ok"] is False and "asset" in resp["error"])

refused = call("policy.put", workspace=ws, assets=[], gate="assets", source_reference="policy://x")
check("policy.put refuses an empty asset list in assets mode",
      refused["ok"] is False and "assets" in refused["error"])

put = call("policy.put", workspace=ws, assets=["example.test", "*.lab.example"],
           gate="assets", source_reference="policy://program/scope", scope_revision=rev(1))
check("first policy.put needs no human_reference", put["ok"] is True)
check("policy.put stores provenance and a sequence",
      put["policy"]["assets"] == ["example.test", "*.lab.example"]
      and put["policy"]["gate"] == "assets"
      and put["policy"]["source_reference"] == "policy://program/scope"
      and put["policy"]["sequence"] == 1 and "updated_at" in put["policy"])

refused = call("policy.put", workspace=ws, assets=["example.test"], gate="assets",
               source_reference="policy://program/scope")
check("re-recording an existing policy requires human_reference",
      refused["ok"] is False and "human_reference" in refused["error"])

put2 = call("policy.put", workspace=ws, assets=["example.test", "*.lab.example"],
            gate="assets", source_reference="policy://program/scope", human_reference="ticket-42",
            scope_revision=rev(2))
check("human_reference records the re-record and bumps the sequence",
      put2["ok"] is True and put2["policy"]["human_reference"] == "ticket-42"
      and put2["policy"]["sequence"] == 2)

got = call("policy.get", workspace=ws)
check("policy.get returns the stored policy",
      got["ok"] is True and got["policy"]["assets"] == ["example.test", "*.lab.example"])

# --- policy.put scope revisions (stale-push protection) ------------------------

rev_ws = str(tmpdir("ro-broker-rev-").resolve())
refused = call("policy.put", workspace=rev_ws, assets=["example.test"], gate="assets",
               source_reference="policy://x")
check("policy.put requires a scope_revision",
      refused["ok"] is False and "scope_revision" in refused["error"])
refused = call("policy.put", workspace=rev_ws, assets=["example.test"], gate="assets",
               source_reference="policy://x", scope_revision="not-a-revision")
check("policy.put refuses a malformed scope_revision",
      refused["ok"] is False and "scope_revision" in refused["error"])
first = call("policy.put", workspace=rev_ws, assets=["example.test"], gate="assets",
             source_reference="policy://x", scope_revision=rev(1))
check("the first revisioned put is stored",
      first["ok"] is True and first["policy"]["scope_revision"] == rev(1))
same = call("policy.put", workspace=rev_ws, assets=["example.test"], gate="assets",
            source_reference="policy://x", human_reference="ticket-rev",
            scope_revision=rev(1))
check("an identical revision re-put is idempotent",
      same["ok"] is True and same["policy"]["scope_revision"] == rev(1))
conflict = call("policy.put", workspace=rev_ws, assets=["other.example"], gate="assets",
                source_reference="policy://x", human_reference="ticket-rev",
                scope_revision=rev(1))
check("the same revision with different content is refused",
      conflict["ok"] is False and "scope_revision" in conflict["error"])
second = call("policy.put", workspace=rev_ws, assets=["example.test", "more.example"],
              gate="assets", source_reference="policy://x", human_reference="ticket-rev",
              scope_revision=rev(2))
check("a newer revision supersedes",
      second["ok"] is True and second["policy"]["scope_revision"] == rev(2))
stale = call("policy.put", workspace=rev_ws, assets=["example.test"], gate="assets",
             source_reference="policy://x", human_reference="ticket-rev",
             scope_revision=rev(1))
check("an out-of-order (older) revision push is refused",
      stale["ok"] is False and "scope_revision" in stale["error"])

# --- token.mint scope enforcement -------------------------------------------

nopolicy_ws = str(tmpdir("ro-broker-nopolicy-").resolve())
shape_in = {"method": "GET", "url": "https://example.test/x", "principal": "researcher-A"}
preflight = {"cycle_id": "C-0001", "target": shape_in["url"]}

# --- audit journal-first: intent before state, applied_but_unlogged on late failure ---

import importlib.util as _ilu
_broker_spec = _ilu.spec_from_file_location("broker_mod_w14", TOOLS / "broker" / "broker.py")
broker_mod = _ilu.module_from_spec(_broker_spec)
_broker_spec.loader.exec_module(broker_mod)
journal_home = tmpdir("ro-broker-journal-")
br = broker_mod.Broker(journal_home)
prime = br.handle({"op": "policy.put", "workspace": str(journal_home / "ws"),
                   "assets": ["example.test"], "gate": "assets",
                   "source_reference": "policy://x", "scope_revision": rev(9, "journal")})
check("in-process policy.put primes the journal fixture", prime["ok"] is True)
journal_calls = {"n": 0}
orig_audit = broker_mod.Broker._audit


def flaky_audit(self, line):
    journal_calls["n"] += 1
    if journal_calls["n"] == 2:
        raise OSError("injected post-op audit failure")
    return orig_audit(self, line)


broker_mod.Broker._audit = flaky_audit
try:
    late_fail = br.handle({"op": "token.mint", "workspace": str(journal_home / "ws"),
                           "preflight": dict(preflight), "request_shape": dict(shape_in),
                           "tool_family": "http"})
finally:
    broker_mod.Broker._audit = orig_audit
check("a post-op audit failure returns applied_but_unlogged",
      late_fail["ok"] is False and late_fail.get("applied_but_unlogged") is True
      and late_fail.get("op") == "token.mint"
      and "INTENT" in late_fail.get("error", ""))
check("the intent record exists as the decision record",
      "INTENT token.mint" in (journal_home / "audit.log").read_text())
check("the state change was applied (journal-first, honest shape)",
      '"kind":"mint"' in (journal_home / "tokens.jsonl").read_text())

# A refused op with a failing post-op append must NOT claim application.
journal_calls["n"] = 0
broker_mod.Broker._audit = flaky_audit
try:
    refused_late = br.handle({"op": "token.mint", "workspace": str(journal_home / "no-policy-ws"),
                              "preflight": dict(preflight), "request_shape": dict(shape_in),
                              "tool_family": "http"})
finally:
    broker_mod.Broker._audit = orig_audit
check("a refused op with a failing post-op append reports no application",
      refused_late["ok"] is False and refused_late.get("applied_but_unlogged") is False
      and "policy" in refused_late.get("error", ""))


def dead_audit(self, line):
    raise OSError("injected pre-op audit failure")


policies_before = sorted((journal_home / "policies").glob("*.json"))
broker_mod.Broker._audit = dead_audit
try:
    early_fail = br.handle({"op": "policy.put", "workspace": str(journal_home / "ws2"),
                            "assets": ["example.test"], "gate": "assets",
                            "source_reference": "policy://x", "scope_revision": rev(1, "journal2")})
finally:
    broker_mod.Broker._audit = orig_audit
check("a pre-op (intent) audit failure refuses without applying",
      early_fail["ok"] is False and early_fail.get("applied_but_unlogged") is not True
      and sorted((journal_home / "policies").glob("*.json")) == policies_before)
check("policy.get on an unknown workspace returns no policy",
      call("policy.get", workspace=str(tmpdir("ro-broker-unknown-")))["policy"] is None)
check("policy.get never leaks key material", KEY_BYTES.hex() not in json.dumps(got))

mint = call("token.mint", workspace=nopolicy_ws, preflight=preflight, request_shape=shape_in)
check("token.mint refuses when no policy is stored",
      mint["ok"] is False and "policy" in mint["error"].lower() and "scope" in mint["error"].lower())

minted = call("token.mint", workspace=ws, preflight=preflight, request_shape=shape_in)
check("token.mint allows an in-policy host", minted["ok"] is True)
tok = minted.get("token", {})
check("minted token carries the signed record",
      tok.get("action_id", "").startswith("B-")
      and len(tok.get("nonce", "")) == 32
      and len(tok.get("digest", "")) == 64
      and tok.get("tool_family") == "http"
      and tok.get("workspace") == ws
      and len(tok.get("sig", "")) == 64)
check("token.mint returns the preflight", minted.get("preflight") == preflight)
check("token.mint accepts a wildcard subdomain host",
      call("token.mint", workspace=ws,
           preflight={**preflight, "target": "https://api.lab.example/x"},
           request_shape={**shape_in, "url": "https://api.lab.example/x"})["ok"] is True)

browser_shape = {"url": "https://example.test/app", "principal": "researcher-A"}
browser_mint = call("token.mint", workspace=ws, preflight=preflight, request_shape=browser_shape,
                    tool_family="browser")
check("token.mint records the browser family and its own digest",
      browser_mint["ok"] is True and browser_mint["token"]["tool_family"] == "browser"
      and browser_mint["token"]["digest"] != tok["digest"])

out = call("token.mint", workspace=ws,
           preflight={**preflight, "target": "https://evil.example/x"},
           request_shape={**shape_in, "url": "https://evil.example/x"})
check("token.mint refuses an out-of-policy host with the canonical shape",
      out["ok"] is False and "outside the engagement scope" in out["error"]
      and "broker policy assets" in out["error"] and "evil.example" in out["error"])

gate_none_ws = str(tmpdir("ro-broker-none-").resolve())
call("policy.put", workspace=gate_none_ws, assets=[], gate="none", source_reference="policy://none",
     scope_revision=rev(1, "none"))
minted_none = call("token.mint", workspace=gate_none_ws,
                   preflight={**preflight, "target": "https://anywhere.example/x"},
                   request_shape={**shape_in, "url": "https://anywhere.example/x"})
check("an explicit gate none policy allows any host",
      minted_none["ok"] is True and minted_none["token"]["tool_family"] == "http")

unenf_ws = str(tmpdir("ro-broker-unenf-").resolve())
call("policy.put", workspace=unenf_ws, assets=["example.test"], gate="assets", source_reference="policy://x",
     scope_revision=rev(1, "unenf"))
# Rewrite the stored policy to an unenforceable asset list: the broker must fail closed.
(HOME / "policies" / f"{wsid_of(unenf_ws)}.json").write_text(json.dumps(
    {"assets": [], "gate": "assets", "source_reference": "policy://x",
     "human_reference": "", "updated_at": now_iso(), "sequence": 1}))
resp = call("token.mint", workspace=unenf_ws, preflight=preflight, request_shape=shape_in)
check("an unenforceable policy refuses to mint",
      resp["ok"] is False and "unenforceable" in resp["error"])

# --- token.mint ttl bounds (no silent clamping) -------------------------------

ttl_ws = str(tmpdir("ro-broker-ttl-").resolve())
call("policy.put", workspace=ttl_ws, assets=["example.test"], gate="assets", source_reference="policy://x",
     scope_revision=rev(1, "ttl"))
for bad in (0, 3601, -5, "300", 3.5, True, None):
    resp = call("token.mint", workspace=ttl_ws, preflight=preflight, request_shape=shape_in,
                ttl_seconds=bad)
    check(f"token.mint refuses ttl_seconds={bad!r}",
          resp["ok"] is False and "ttl_seconds" in resp["error"])
default_ttl = call("token.mint", workspace=ttl_ws, preflight=preflight, request_shape=shape_in)["token"]
check("a missing ttl_seconds defaults to 300s",
      290 < ttl_seconds_left(default_ttl["expires_at"]) <= 305)
top_ttl = call("token.mint", workspace=ttl_ws, preflight=preflight, request_shape=shape_in,
               ttl_seconds=3600)["token"]
check("ttl_seconds=3600 is accepted",
      3590 < ttl_seconds_left(top_ttl["expires_at"]) <= 3605)

# --- token.mint binds preflight.target to the request shape -------------------

resp = call("token.mint", workspace=ws,
            preflight={**preflight, "target": "https://evil.example/x"}, request_shape=shape_in)
check("token.mint refuses a target host that does not match the shape",
      resp["ok"] is False and "target" in resp["error"] and "evil.example" in resp["error"])
resp = call("token.mint", workspace=ws, preflight={**preflight, "target": ""}, request_shape=shape_in)
check("token.mint refuses a missing target", resp["ok"] is False and "target" in resp["error"])

# --- token.mint budget enforcement (the broker's own mint ledger) -------------

budget_ws = str(tmpdir("ro-broker-budget-").resolve())
put = call("policy.put", workspace=budget_ws, assets=["example.test"], gate="assets",
           source_reference="policy://x", scope_revision=rev(1, "budget"),
           budget={"max_actions_per_cycle": 1, "max_actions_per_engagement": 3})
check("policy.put records the budget caps", put["ok"] is True
      and put["policy"]["budget"] == {"max_actions_per_cycle": 1, "max_actions_per_engagement": 3})
check("policy.put without a budget records it as uncapped",
      put["policy"]["budget"] is not None
      and set(call("policy.get", workspace=ws)["policy"]["budget"].values()) == {None})
resp = call("policy.put", workspace=budget_ws, assets=["example.test"], gate="assets",
            source_reference="policy://x", human_reference="ticket-budget",
            budget={"max_actions_per_cycle": "one", "max_actions_per_engagement": 3})
check("policy.put refuses a malformed budget", resp["ok"] is False and "budget" in resp["error"])


def bmint(cycle: str) -> dict:
    return call("token.mint", workspace=budget_ws, request_shape=shape_in,
                preflight={**preflight, "cycle_id": cycle})


check("budget: the first mint of a cycle is allowed", bmint("C-0001")["ok"] is True)
resp = bmint("C-0001")
check("budget: the per-cycle cap refuses the second mint",
      resp["ok"] is False and "cycle budget exhausted (1/1)" in resp["error"]
      and "researchctl budget set" in resp["error"])
check("budget: another cycle is still allowed", bmint("C-0002")["ok"] is True)
check("budget: the per-cycle cap counts per cycle", bmint("C-0002")["ok"] is False)
check("budget: the third distinct cycle is allowed", bmint("C-0003")["ok"] is True)
resp = bmint("C-0004")
check("budget: the per-engagement cap refuses past its limit",
      resp["ok"] is False and "engagement budget exhausted (3/3)" in resp["error"])
resp = call("token.mint", workspace=budget_ws, request_shape=shape_in,
            preflight={"target": shape_in["url"]})
check("budget: a preflight without cycle_id is refused while caps are set",
      resp["ok"] is False and "cycle_id" in resp["error"])

# A hand-edited policy with malformed caps must refuse, never read as uncapped.
(HOME / "policies" / f"{wsid_of(budget_ws)}.json").write_text(json.dumps(
    {"assets": ["example.test"], "gate": "assets", "source_reference": "policy://x",
     "human_reference": "ticket-budget", "updated_at": now_iso(), "sequence": 2,
     "budget": {"max_actions_per_cycle": "one", "max_actions_per_engagement": None}}))
resp = bmint("C-0009")
check("budget: malformed caps in the stored policy refuse to mint",
      resp["ok"] is False and "malformed" in resp["error"].lower())

# A later policy.put refreshes (here: clears) the caps.
call("policy.put", workspace=budget_ws, assets=["example.test"], gate="assets",
     source_reference="policy://x", human_reference="ticket-budget", budget=None,
     scope_revision=rev(2, "budget"))
check("budget: a later policy.put refreshes the caps", bmint("C-0009")["ok"] is True)

# --- scope.check: the broker-side decision the runner CLI delegates to ---------

sc = call("scope.check", workspace=ws, url="https://example.test/x")
check("scope.check allows an in-policy host",
      sc["ok"] is True and sc["gate"] == "assets" and sc["in_scope"] is True
      and sc["host"] == "example.test")
sc = call("scope.check", workspace=ws, url="https://api.lab.example/x")
check("scope.check matches a wildcard subdomain", sc["ok"] is True and sc["in_scope"] is True)
sc = call("scope.check", workspace=ws, url="https://evil.example/x")
check("scope.check denies an out-of-policy host",
      sc["ok"] is True and sc["in_scope"] is False and sc["host"] == "evil.example")
sc = call("scope.check", workspace=ws, url="example.test/x")
check("scope.check without a scheme stays default-deny (canonical seam parity)",
      sc["ok"] is True and sc["in_scope"] is False and sc["host"] == "")
sc = call("scope.check", workspace=gate_none_ws, url="https://anywhere.example/x")
check("scope.check with gate none is disabled and allows",
      sc["ok"] is True and sc["gate"] == "disabled" and sc["in_scope"] is True)
sc = call("scope.check", workspace=unenf_ws, url="https://example.test/x")
check("scope.check refuses an unenforceable policy",
      sc["ok"] is False and "unenforceable" in sc["error"])
sc = call("scope.check", workspace=str(tmpdir("ro-broker-scope-")), url="https://example.test/x")
check("scope.check refuses when no policy is stored",
      sc["ok"] is False and "scope-set" in sc["error"])
sc = call("scope.check", workspace=ws, url="http://127.0.0.1:9\\@example.test/")
check("scope.check denies a backslash authority the fetch stack would route elsewhere",
      sc["ok"] is True and sc["in_scope"] is False)
sc = call("scope.check", workspace=ws, url="http://example.test%5Cevil/")
check("scope.check denies an encoded-backslash authority",
      sc["ok"] is True and sc["in_scope"] is False)

# --- token.consume: single use, tamper, expiry -------------------------------

consume = call("token.consume", workspace=ws, digest=tok["digest"], tool_family="http",
               nonce=tok["nonce"], sig=tok["sig"])
check("consume accepts a fresh token and returns the preflight",
      consume["ok"] is True and consume["action_id"] == tok["action_id"]
      and consume["preflight"] == preflight)

again = call("token.consume", workspace=ws, digest=tok["digest"], tool_family="http",
             nonce=tok["nonce"], sig=tok["sig"])
check("consume is single-use", again["ok"] is False and "already consumed" in again["error"])

tampered = call("token.mint", workspace=ws, preflight=preflight, request_shape=shape_in)["token"]
tampered_sig = ("0" if tampered["sig"][0] != "0" else "1") + tampered["sig"][1:]
resp = call("token.consume", workspace=ws, digest=tampered["digest"], tool_family="http",
            nonce=tampered["nonce"], sig=tampered_sig)
check("a tampered signature is refused", resp["ok"] is False and "signature" in resp["error"])

resp = call("token.consume", workspace=ws, digest=tampered["digest"], tool_family="http",
            nonce=tampered["nonce"], sig=tampered["sig"])
check("the untampered twin still consumes", resp["ok"] is True)

wrong_ws = str(tmpdir("ro-broker-wrongws-").resolve())
mint_ws = call("token.mint", workspace=ws, preflight=preflight, request_shape=shape_in)["token"]
resp = call("token.consume", workspace=wrong_ws, digest=mint_ws["digest"], tool_family="http",
            nonce=mint_ws["nonce"], sig=mint_ws["sig"])
check("a token minted for another workspace is refused",
      resp["ok"] is False and "workspace" in resp["error"])

resp = call("token.consume", workspace=ws, digest="f" * 64, tool_family="http",
            nonce=mint_ws["nonce"], sig=mint_ws["sig"])
check("a token consumed with a different digest is refused",
      resp["ok"] is False and "digest" in resp["error"])

resp = call("token.consume", workspace=ws, digest=mint_ws["digest"], tool_family="browser",
            nonce=mint_ws["nonce"], sig=mint_ws["sig"])
check("a token consumed with a different tool_family is refused",
      resp["ok"] is False and "tool_family" in resp["error"])

resp = call("token.consume", workspace=ws, digest=mint_ws["digest"], tool_family="http",
            nonce="0" * 32, sig=mint_ws["sig"])
check("an unknown nonce is refused", resp["ok"] is False and "nonce" in resp["error"])

short = call("token.mint", workspace=ws, preflight=preflight, request_shape=shape_in, ttl_seconds=1)["token"]
ttl_left = (datetime.strptime(short["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            - datetime.now(timezone.utc)).total_seconds()
check("mint honors the requested ttl", 0 < ttl_left <= 5)
time.sleep(1.2)
resp = call("token.consume", workspace=ws, digest=short["digest"], tool_family="http",
            nonce=short["nonce"], sig=short["sig"])
check("an expired token is refused", resp["ok"] is False and "expired" in resp["error"])

# --- robustness: malformed frames, unknown ops, line bound -------------------

resp = raw_line(SOCK, b"this is not json\n")
check("a malformed frame is refused without crashing", resp["ok"] is False and "error" in resp)

resp = raw_line(SOCK, json.dumps({"op": "policy.drop"}).encode() + b"\n")
check("an unknown op is refused", resp["ok"] is False and "unknown op" in resp["error"])

resp = raw_line(SOCK, json.dumps({"workspace": ws}).encode() + b"\n")
check("a frame without an op is refused", resp["ok"] is False)

resp = raw_line(SOCK, b"x" * (1024 * 1024 + 1) + b"\n", threaded=True)
check("an oversized frame is refused", resp["ok"] is False and "too large" in resp["error"].lower())

# A response that would exceed the line bound is replaced by a bounded refusal (the
# unknown-op error echoes the op, so a request just under the bound produces a
# response just over it).
big_op = json.dumps({"op": "x" * (1024 * 1024 - 20)}).encode() + b"\n"
resp = raw_line(SOCK, big_op)
check("an oversized response is bounded with a refusal",
      resp["ok"] is False and "bound" in resp["error"].lower())

check("the daemon survives malformed traffic", call("hello")["ok"] is True)

# --- audit log ---------------------------------------------------------------

audit_log = (HOME / "audit.log").read_text()
check("every decision is logged to audit.log",
      "policy.put" in audit_log and "token.mint" in audit_log and "token.consume" in audit_log)
check("the audit log records refusals too", "refuse" in audit_log)
check("the audit log never carries the key bytes", KEY_BYTES.hex() not in audit_log)

# --- client ------------------------------------------------------------------

check("client.broker_path finds the home socket", broker_client.broker_path() == SOCK)
check("client.available is true while the broker runs", broker_client.available() is True)

# =============================================================================
# Phase A2 — connection hardening + audit/ledger failure semantics (own broker).
# =============================================================================

HARD_HOME = tmpdir("ro-broker-hard-")
HARD_SOCK = HARD_HOME / "broker.sock"
set_home(HARD_HOME)
hard_proc = spawn_broker(HARD_HOME)
call("hello")  # creates audit.log through the first logged decision
hard_ws = str(tmpdir("ro-broker-hard-ws-").resolve())

# If the audit log cannot be appended, the operation refuses BEFORE it runs.
audit_path = HARD_HOME / "audit.log"
check("the audit log exists after the first decision", audit_path.exists())
os.chmod(audit_path, 0o400)
try:
    resp = call("policy.put", workspace=hard_ws, assets=["example.test"], gate="assets",
                source_reference="policy://x")
    check("an unwritable audit log refuses policy.put",
          resp["ok"] is False and "audit" in resp["error"].lower())
    check("the refused put stored no policy on disk",
          not (HARD_HOME / "policies" / f"{wsid_of(hard_ws)}.json").exists())
    resp = call("token.mint", workspace=hard_ws, preflight=preflight, request_shape=shape_in)
    check("an unwritable audit log refuses token.mint",
          resp["ok"] is False and "audit" in resp["error"].lower())
    ledger = HARD_HOME / "tokens.jsonl"
    check("the refused mint wrote no ledger record",
          not ledger.exists() or '"kind":"mint"' not in ledger.read_text())
finally:
    os.chmod(audit_path, 0o600)
resp = call("policy.put", workspace=hard_ws, assets=["example.test"], gate="assets",
            source_reference="policy://x", scope_revision=rev(1, "hard"))
check("a repaired audit log lets the broker work again", resp["ok"] is True)

# Ledger decode failures are counted and surfaced in status, never silent.
hard_ledger = HARD_HOME / "tokens.jsonl"
with hard_ledger.open("a", encoding="utf-8") as fh:
    fh.write("this is not json\n")
    fh.write("[1, 2, 3]\n")
st = call("status", workspace=hard_ws)
check("status counts unreadable ledger lines",
      st["ok"] is True and st["ledger_decode_errors"] == 2)
check("a corrupt ledger line does not break minting",
      call("token.mint", workspace=hard_ws, preflight=preflight,
           request_shape=shape_in)["ok"] is True)

# Idle connections are closed by the per-connection read timeout, not held forever.
idle = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
idle.settimeout(9)
idle.connect(str(HARD_SOCK))
idle_start = time.time()
try:
    idle_data = idle.recv(64)
except OSError:
    idle_data = b""
idle_closed_after = time.time() - idle_start
idle.close()
check("an idle connection is closed by the 5s read timeout",
      idle_data == b"" and 3.5 < idle_closed_after < 8.5)
check("the daemon survives an idle connection", call("hello")["ok"] is True)

# A truncated frame (no newline, then EOF) gets no response and no hang.
trunc = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
trunc.settimeout(5)
trunc.connect(str(HARD_SOCK))
trunc.sendall(b'{"op":"hello"')
trunc.shutdown(socket.SHUT_WR)
try:
    trunc_data = trunc.recv(64)
except OSError:
    trunc_data = b""
trunc.close()
check("a truncated frame is closed without a response", trunc_data == b"")
check("the daemon survives a truncated frame", call("hello")["ok"] is True)

# Concurrent-connection cap: the first 32 held connections are served; the next is
# refused with a clear error instead of queueing forever.
held: list[socket.socket] = []
try:
    for _ in range(32):
        held_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        held_sock.settimeout(5)
        held_sock.connect(str(HARD_SOCK))
        held_sock.sendall(b'{"op":"hello"}\n')
        held_buf = b""
        while b"\n" not in held_buf:
            held_buf += held_sock.recv(65536)
        held.append(held_sock)
    alive = 0
    for held_sock in held:
        held_sock.sendall(b'{"op":"hello"}\n')
        held_buf = b""
        while b"\n" not in held_buf:
            held_buf += held_sock.recv(65536)
        if json.loads(held_buf.split(b"\n", 1)[0])["ok"] is True:
            alive += 1
    check("32 held connections are all served", alive == 32)
    extra = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    extra.settimeout(5)
    extra.connect(str(HARD_SOCK))
    extra.sendall(b'{"op":"hello"}\n')
    extra_buf = b""
    while b"\n" not in extra_buf:
        extra_buf += extra.recv(65536)
    extra_resp = json.loads(extra_buf.split(b"\n", 1)[0])
    extra.close()
    check("the connection past the cap is refused with a clear error",
          extra_resp["ok"] is False and "concurrent" in extra_resp["error"].lower())
finally:
    for held_sock in held:
        held_sock.close()
recovered = False
for _ in range(100):
    try:
        if call("hello")["ok"] is True:
            recovered = True
            break
    except AssertionError:
        pass
    time.sleep(0.05)
check("the daemon recovers after the held connections close", recovered)

stop_broker(hard_proc)
set_home(HOME)


# =============================================================================
# Phase B — control-plane integration: scope-set pushes, prepare mints.
# =============================================================================

ws_root, cp = fixture_root()
(ws_root / "00_control/engagement.yaml").write_text(
    "budget:\n  max_actions_per_cycle: 4\n  max_actions_per_engagement: 9\n")
cp.set_scope(["example.test"], "policy://program/scope")
pushed = call("policy.get", workspace=str(ws_root.resolve()))
check("set_scope pushes the policy to the broker",
      pushed["ok"] is True and pushed["policy"]["assets"] == ["example.test"]
      and pushed["policy"]["source_reference"] == "policy://program/scope")
check("set_scope pushes the workspace budget caps with the policy",
      pushed["policy"]["budget"] == {"max_actions_per_cycle": 4, "max_actions_per_engagement": 9})

prepared = cp.prepare_action(prepare_payload("https://example.test/x"))
check("prepare mints a broker-signed token",
      prepared["action_id"].startswith("B-") and len(prepared["broker_sig"]) == 64
      and prepared["broker_nonce"] == prepared["nonce"]
      and prepared["broker_workspace"] == str(ws_root.resolve()))
store = (ws_root / "11_runtime/action-tokens.jsonl").read_text()
check("the broker token is appended to the workspace token store",
      prepared["broker_nonce"] in store and prepared["broker_sig"] in store
      and '"consumed":false' in store)

consumed = call("token.consume", workspace=str(ws_root.resolve()),
                digest=prepared["argument_digest"], tool_family="http",
                nonce=prepared["broker_nonce"], sig=prepared["broker_sig"])
check("the minted token consumes through the broker once",
      consumed["ok"] is True and consumed["action_id"] == prepared["action_id"])
check("the minted token cannot consume twice",
      call("token.consume", workspace=str(ws_root.resolve()), digest=prepared["argument_digest"],
           tool_family="http", nonce=prepared["broker_nonce"], sig=prepared["broker_sig"])["ok"] is False)

prepared_browser = cp.prepare_action(prepare_payload("https://example.test/app", "browser"))
check("prepare mints a browser-family broker token",
      prepared_browser["tool_family"] == "browser"
      and call("token.consume", workspace=str(ws_root.resolve()),
               digest=prepared_browser["argument_digest"], tool_family="browser",
               nonce=prepared_browser["broker_nonce"], sig=prepared_browser["broker_sig"])["ok"] is True)

# Broker present, but this workspace has no broker policy: prepare must refuse
# actionably instead of minting a local-only token.
lonely_root, lonely_cp = fixture_root()
(lonely_root / "00_control/engagement.yaml").write_text('scope:\n  assets: ["example.test"]\n')
try:
    lonely_cp.prepare_action(prepare_payload("https://example.test/x"))
    check("prepare refuses when the broker holds no policy", False)
except ValueError as exc:
    check("prepare refuses when the broker holds no policy",
          "researchctl scope-set" in str(exc) and "broker" in str(exc).lower())

# Broker authority: a broker policy narrower than the workspace file refuses at prepare.
call("policy.put", workspace=str(ws_root.resolve()), assets=["other.example"], gate="assets",
     source_reference="policy://program/scope", human_reference="ticket-9",
     scope_revision=next_rev(call("policy.get", workspace=str(ws_root.resolve()))["policy"]))
try:
    cp.prepare_action(prepare_payload("https://example.test/x"))
    check("the broker policy refuses a workspace-allowed host", False)
except ValueError as exc:
    check("the broker policy refuses a workspace-allowed host",
          "outside the engagement scope" in str(exc) and "broker policy" in str(exc)
          and "other.example" in str(exc))
call("policy.put", workspace=str(ws_root.resolve()), assets=["example.test"], gate="assets",
     source_reference="policy://program/scope", human_reference="ticket-9",
     scope_revision=next_rev(call("policy.get", workspace=str(ws_root.resolve()))["policy"]))

# --- a broken broker install fails closed, never silently local ----------------

broken_root, _ = fixture_root()
(broken_root / "00_control/engagement.yaml").write_text('scope:\n  assets: ["example.test"]\n')
broken_tools = tmpdir("ro-broker-broken-tools-") / "tools"
shutil.copytree(TOOLS, broken_tools, ignore=shutil.ignore_patterns("__pycache__"))
(broken_tools / "broker" / "client.py").unlink()
broken_script = "\n".join([
    "import json, sys",
    "sys.path.insert(0, sys.argv[1])",
    "from pathlib import Path",
    "from control_plane import ControlPlane",
    "cp = ControlPlane(Path(sys.argv[2]))",
    "out = {}",
    "try:",
    "    cp.prepare_action(json.loads(sys.stdin.read()))",
    "    out['prepare'] = 'no-raise'",
    "except ValueError as exc:",
    "    out['prepare'] = str(exc)",
    "try:",
    "    cp.set_scope(['example.test'], 'policy://program/scope', human_reference='ticket-broken')",
    "    out['scope'] = 'no-raise'",
    "except ValueError as exc:",
    "    out['scope'] = str(exc)",
    "print(json.dumps(out))",
])
broken_run = subprocess.run(
    [sys.executable, "-c", broken_script, str(broken_tools), str(broken_root)],
    input=json.dumps(prepare_payload("https://example.test/x")),
    capture_output=True, text=True, env=dict(os.environ), cwd=str(tmpdir("ro-broker-broken-cwd-")))
try:
    broken_out = json.loads(broken_run.stdout)
    check("a broken broker install refuses prepare (fail closed)",
          broken_out.get("prepare") != "no-raise" and "broken" in broken_out.get("prepare", "")
          and "client" in broken_out.get("prepare", ""))
    check("a broken broker install refuses scope-set (fail closed)",
          broken_out.get("scope") != "no-raise" and "broken" in broken_out.get("scope", ""))
except json.JSONDecodeError:
    check("a broken broker install refuses prepare (fail closed)", False)
    check("a broken broker install refuses scope-set (fail closed)", False)

# --- researchctl scope-check is broker-authoritative --------------------------

scope_run, scope_out = run_scope_check(ws_root, "https://example.test/x")
check("scope-check delegates to the broker when its socket is present",
      scope_run.returncode == 0 and scope_out["in_scope"] is True
      and scope_out["authority"] == "broker" and scope_out["gate"] == "assets")

call("policy.put", workspace=str(ws_root.resolve()), assets=["other.example"], gate="assets",
     source_reference="policy://program/scope", human_reference="ticket-cli",
     scope_revision=next_rev(call("policy.get", workspace=str(ws_root.resolve()))["policy"], "cli"))
scope_run, scope_out = run_scope_check(ws_root, "https://example.test/x")
check("the broker policy overrides the local binding in the scope-check CLI",
      scope_run.returncode == 3 and scope_out["in_scope"] is False
      and scope_out["authority"] == "broker"
      and "example.test" in (ws_root / "00_control/engagement.yaml").read_text())
call("policy.put", workspace=str(ws_root.resolve()), assets=["example.test"], gate="assets",
     source_reference="policy://program/scope", human_reference="ticket-cli",
     scope_revision=next_rev(call("policy.get", workspace=str(ws_root.resolve()))["policy"], "cli"))

# Intersection: a narrowed local binding with a stale broader broker policy denies
# the removed host — local AND broker must allow.
(ws_root / "00_control/engagement.yaml").write_text('scope:\n  assets: ["narrowed.example"]\n')
scope_run, scope_out = run_scope_check(ws_root, "https://example.test/x")
check("a narrowed local binding denies despite a broader broker policy (intersection)",
      scope_run.returncode == 3 and scope_out["in_scope"] is False
      and scope_out["authority"] == "broker")
(ws_root / "00_control/engagement.yaml").write_text('scope:\n  assets: ["example.test"]\n')
scope_run, scope_out = run_scope_check(ws_root, "https://example.test/x")
check("the intersection allows again once both agree",
      scope_run.returncode == 0 and scope_out["in_scope"] is True)

# prepare keeps BOTH checks: a broker policy wider than the local binding still refuses
# on the local engagement.yaml scope (the broker mint alone is not the whole gate).
call("policy.put", workspace=str(ws_root.resolve()), assets=["example.test", "other.example"],
     gate="assets", source_reference="policy://program/scope", human_reference="ticket-cli",
     scope_revision=next_rev(call("policy.get", workspace=str(ws_root.resolve()))["policy"], "cli"))
try:
    cp.prepare_action(prepare_payload("https://other.example/x"))
    check("prepare keeps the local binding as a second gate", False)
except ValueError as exc:
    check("prepare keeps the local binding as a second gate",
          "outside the engagement scope" in str(exc) and "engagement.yaml" in str(exc))
call("policy.put", workspace=str(ws_root.resolve()), assets=["example.test"], gate="assets",
     source_reference="policy://program/scope", human_reference="ticket-cli",
     scope_revision=next_rev(call("policy.get", workspace=str(ws_root.resolve()))["policy"], "cli"))

# --- researchctl broker status ----------------------------------------------

status_run = subprocess.run(
    [sys.executable, str(RESEARCHCTL), str(ws_root), "broker", "status"],
    capture_output=True, text=True, env=dict(os.environ))
status_out = json.loads(status_run.stdout)
check("researchctl broker status reports the live broker",
      status_run.returncode == 0 and status_out["socket"] == str(SOCK)
      and status_out["available"] is True and status_out["policy_present"] is True
      and status_out["key_present"] is True and status_out["version"].startswith("research-os-broker/"))

# --- researchctl broker serve delegates to the daemon ------------------------

serve_home = tmpdir("ro-broker-serve-")
serve_sock = serve_home / "broker.sock"
set_home(serve_home)
serve_proc = subprocess.Popen(
    [sys.executable, str(RESEARCHCTL), str(ws_root), "broker", "serve", "--home", str(serve_home)],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    wait_for_socket(serve_sock)
    check("researchctl broker serve starts a working daemon", call("hello")["ok"] is True)
finally:
    stop_broker(serve_proc)
check("a clean shutdown removes the socket file", not serve_sock.exists())
serve_out = serve_proc.stdout.read() if serve_proc.stdout else ""
serve_err = serve_proc.stderr.read() if serve_proc.stderr else ""
check("broker serve prints the socket path", str(serve_sock) in serve_out + serve_err)
set_home(HOME)

# --- client unavailable paths ------------------------------------------------

missing_home = tmpdir("ro-broker-absent-")
set_home(missing_home)
check("client.broker_path is None when no socket exists", broker_client.broker_path() is None)
check("client.available is false when no socket exists", broker_client.available() is False)
try:
    broker_client.call("hello", timeout=1)
    check("client.call raises BrokerUnavailable when no socket exists", False)
except broker_client.BrokerUnavailable:
    check("client.call raises BrokerUnavailable when no socket exists", True)

offline_status = subprocess.run(
    [sys.executable, str(RESEARCHCTL), str(ws_root), "broker", "status"],
    capture_output=True, text=True, env=dict(os.environ))
offline_out = json.loads(offline_status.stdout)
check("researchctl broker status reports an absent broker without failing",
      offline_status.returncode == 0 and offline_out["available"] is False
      and offline_out["policy_present"] is None and offline_out["version"] is None
      and offline_out["key_present"] is False)
set_home(HOME)

# =============================================================================
# Phase C — broker down after a mint: fail closed, never silent.
# =============================================================================

down_root, down_cp = fixture_root()
down_cp.set_scope(["example.test"], "policy://program/scope")
down_token = down_cp.prepare_action(prepare_payload("https://example.test/x"))

stop_broker(broker_proc)
check("SIGTERM removes the broker socket", not SOCK.exists())

try:
    broker_client.call("token.consume", timeout=1, workspace=str(down_root.resolve()),
                       digest=down_token["argument_digest"], tool_family="http",
                       nonce=down_token["broker_nonce"], sig=down_token["broker_sig"])
    check("client.call raises BrokerUnavailable when the broker is gone", False)
except broker_client.BrokerUnavailable:
    check("client.call raises BrokerUnavailable when the broker is gone", True)

# The key is created once and survives a restart: same home, same key bytes.
restarted = spawn_broker(HOME)
check("the signing key is created once and survives a restart",
      (HOME / "key").read_bytes() == KEY_BYTES)
stop_broker(restarted)

# A dead-but-present socket (SIGKILL leaves the file) must fail closed, not fall
# back to the workspace-local scope.
HOME2 = tmpdir("ro-broker-home2-")
SOCK2 = HOME2 / "broker.sock"
broker2 = spawn_broker(HOME2)
set_home(HOME2)
ws2_root, ws2_cp = fixture_root()
ws2_cp.set_scope(["example.test"], "policy://program/scope")
ws2_cp.prepare_action(prepare_payload("https://example.test/x"))
broker2.kill()
broker2.wait(timeout=10)
check("SIGKILL leaves the stale socket file behind", SOCK2.exists())
try:
    ws2_cp.prepare_action(prepare_payload("https://example.test/y"))
    check("a stale socket fails prepare closed", False)
except ValueError as exc:
    check("a stale socket fails prepare closed",
          "broker" in str(exc).lower() and "fail" in str(exc).lower())
try:
    ws2_cp.set_scope(["example.test", "other.test"], "policy://program/scope",
                     human_reference="ticket-7")
    check("a stale socket fails scope-set closed", False)
except ValueError as exc:
    check("a stale socket fails scope-set closed", "broker" in str(exc).lower())
stored_ws2 = []
for policy_file in (HOME2 / "policies").glob("*.json"):
    stored_ws2.append(json.loads(policy_file.read_text())["assets"])
check("the failed scope-set left the broker policy untouched",
      ["example.test", "other.test"] not in stored_ws2)

# The runner-facing CLI seam fails closed on the stale socket too — and keeps the
# local behavior only once no socket exists at all.
stale_run, stale_out = run_scope_check(ws2_root, "https://example.test/x")
check("scope-check fails closed on a stale broker socket",
      stale_run.returncode == 3 and stale_out["in_scope"] is False
      and stale_out["authority"] == "broker"
      and "unreachable" in stale_out["reason"].lower())

set_home(None)
local_run, local_out = run_scope_check(ws_root, "https://example.test/x")
check("scope-check keeps the local behavior when no socket exists",
      local_run.returncode == 0 and local_out["in_scope"] is True
      and local_out["authority"] == "local")

# =============================================================================
# Phase D — scope-sync DIRTY: a failed broker push blocks browser dispatch
# until resync.
# =============================================================================

sync_home = tmpdir("ro-broker-sync-home-")
set_home(sync_home)
sync_proc = spawn_broker(sync_home)
sync_root, sync_cp = fixture_root()
(sync_root / "00_control/engagement.yaml").write_text(
    "budget:\n  max_actions_per_cycle: 4\n  max_actions_per_engagement: 9\n")
sync_cp.set_scope(["example.test"], "policy://program/scope")
check("a clean scope-set leaves no DIRTY marker",
      not (sync_root / "11_runtime" / ".scope-sync-dirty").exists())

# Kill the broker: the socket file stays (stale) so pushes are attempted and fail.
sync_proc.kill()
sync_proc.wait(timeout=10)
try:
    sync_cp.set_scope(["example.test", "other.example"], "policy://program/scope",
                      human_reference="ticket-sync")
    check("a dead broker fails scope-set closed", False)
except ValueError as exc:
    check("a dead broker fails scope-set closed", "broker" in str(exc).lower())
check("the failed push marks scope-sync DIRTY",
      (sync_root / "11_runtime" / ".scope-sync-dirty").exists())
check("the local scope commit stands despite the failed push",
      "other.example" in (sync_root / "00_control/engagement.yaml").read_text())

sync_cli = subprocess.run(
    [sys.executable, str(RESEARCHCTL), str(sync_root), "scope-sync"],
    capture_output=True, text=True, env=dict(os.environ))
check("scope-sync fails while the broker is unreachable",
      sync_cli.returncode != 0
      and (sync_root / "11_runtime" / ".scope-sync-dirty").exists())

sync_proc = spawn_broker(sync_home)
sync_cli = subprocess.run(
    [sys.executable, str(RESEARCHCTL), str(sync_root), "scope-sync"],
    capture_output=True, text=True, env=dict(os.environ))
check("scope-sync re-pushes and clears DIRTY",
      sync_cli.returncode == 0
      and not (sync_root / "11_runtime" / ".scope-sync-dirty").exists())
synced = call("policy.get", workspace=str(sync_root.resolve()))
check("the resynced broker policy matches the committed binding",
      synced["ok"] is True and sorted(synced["policy"]["assets"]) == ["example.test", "other.example"])
stop_broker(sync_proc)
set_home(HOME)
print(f"\n{len(passed)} checks passed")
