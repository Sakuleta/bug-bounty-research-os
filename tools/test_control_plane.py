#!/usr/bin/env python3
"""End-to-end invariants for the canonical control plane and integrity audit."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parent
ROOT_REPO = TOOLS.parent
sys.path.insert(0, str(TOOLS))
import control_plane as _control_plane  # noqa: E402
from control_plane import (ControlPlane, METHOD_SELF_ATTACK_ROWS,  # noqa: E402
                           REQUIRED_AUDIT_CLASSES, asset_hosts, engagement_assets,
                           host_in_scope, scope_check)

passed: list[str] = []


def check(name: str, cond: bool):
    assert cond, f"FAIL: {name}"
    passed.append(name)
    print(f"ok: {name}")


def fresh_root() -> Path:
    root = Path(tempfile.mkdtemp())
    for d in ["00_control", "02_surface", "03_hypotheses/active", "03_hypotheses/archive", "04_cycles", "10_learning", "11_runtime"]:
        (root / d).mkdir(parents=True, exist_ok=True)
    # Fixture honors the enforced contract: research-started workspaces carry the
    # endpoint ledger (audit FAILs without it once cycles exist).
    (root / "02_surface/endpoints.yaml").write_text("endpoints: []\n")
    (root / "10_learning/freshness.yaml").write_text("components: []\n")
    (root / "10_learning/unknowns.yaml").write_text("unknowns: []\n")
    (root / "10_learning/assumptions.yaml").write_text("assumptions: []\n")
    (root / "11_runtime/run-status.yaml").write_text('engagement_status: "BOOTSTRAP"\n')
    (root / "11_runtime/events.jsonl").write_text("")
    (root / "11_runtime/tool-registry.yaml").write_text("tools: []\n")
    (root / "11_runtime/lab-status.yaml").write_text("status: UNKNOWN\n")
    return root


def cycle_fixture(cid: str, objective: str = "test question") -> dict:
    return {
        "id": cid, "type": "DISCOVERY", "objective": objective,
        "allowed_scope": ["example.test"], "stop_conditions": ["stop"], "controls": [],
        "status": "PLANNED",
        "knowledge_triage": [{"pack": "api", "verdict": "SKIP", "reason": "fixture"}],
    }


def write_objective(root: Path, cid: str) -> None:
    d = root / "04_cycles" / cid
    d.mkdir(parents=True, exist_ok=True)
    (d / "objective.md").write_text(
        "# Cycle Objective\n\n## Question\nDoes behavior differ by principal?\n\n"
        "## Minimal test\nTwo-principal differential on a researcher-owned object.\n")


def scope_workspace(assets_yaml: str | None, target: str) -> tuple[Path, ControlPlane]:
    """Fixture workspace with a RUNNING cycle, one hypothesis and one recorded action."""
    r = fresh_root()
    if assets_yaml is not None:
        (r / "00_control/engagement.yaml").write_text(assets_yaml)
    c = ControlPlane(r)
    c.create_cycle("C-0001", cycle_fixture("C-0001"))
    write_objective(r, "C-0001")
    c.transition_cycle("C-0001", "READY", reason="ready")
    c.transition_cycle("C-0001", "RUNNING", reason="run")
    c.create_hypothesis("H-0001", {
        "cycle_id": "C-0001",
        "observation": "scope fixture",
        "hypothesis": "scope fixture",
        "secure_prediction": "denied",
        "vulnerable_prediction": "allowed",
    })
    action = {k: v for k, v in base_action.items() if k != "evidence_refs"}
    action["target"] = target
    c.record_action(action)
    return r, c


def write_results(root: Path, cid: str, eid: str | None = None, disposition: str = "VERIFIED") -> None:
    d = root / "04_cycles" / cid
    d.mkdir(parents=True, exist_ok=True)
    refs = f"{eid}\n" if eid else ""
    (d / "results.md").write_text(
        "# Cycle Results\n\n## Disposition\n" + disposition + "\n\n"
        "## Instrument validation\nControl fires; negative control clean.\n\n"
        "## Interpretation\nBounded impact reproduced twice.\n\n"
        "## Evidence references\n" + refs + "\n"
        "## New hypotheses\nH-0002 filed as the next branch.\n\n## Next step\nEvaluate H-0002.\n")


root = fresh_root()
cp = ControlPlane(root)

# 1. Create + canonical update, without allowing status mutation via update.
ev = cp.create_cycle("C-0001", cycle_fixture("C-0001", "placeholder"))
check("cycle create event", ev["event_id"] == "EV-000001")
ev = cp.update_cycle("C-0001", {"objective": "test question", "allowed_scope": ["example.test"], "stop_conditions": ["stop"]})
check("cycle plan update is canonical", ev["type"] == "CYCLE_UPDATED")
try:
    cp.update_cycle("C-0001", {"status": "RUNNING"})
    check("status update rejected", False)
except ValueError:
    check("status update rejected", True)

# 1b. Cycle type vocabulary is enforced (HUNT/DISCOVERY drift is a defect, not a synonym).
try:
    cp.create_cycle("C-0009", {**cycle_fixture("C-0009"), "type": "HUNT"})
    check("invalid cycle type rejected", False)
except ValueError:
    check("invalid cycle type rejected", True)

# 2. The canonical seam owns the full guard set (formerly split into cycle.py).
cp.transition_cycle("C-0001", "READY", reason="plan complete")
try:
    cp.transition_cycle("C-0001", "RUNNING", reason="begin")
    check("RUNNING without objective artifact rejected", False)
except ValueError as exc:
    check("RUNNING without objective artifact rejected", "objective.md" in str(exc))
write_objective(root, "C-0001")
cp.transition_cycle("C-0001", "RUNNING", reason="begin")
check("cycle lifecycle reaches RUNNING", cp.cycle_status("C-0001") == "RUNNING")

# 2b. knowledge_triage is a precondition for RUNNING, not a post-hoc audit note.
root_nt = fresh_root(); cp_nt = ControlPlane(root_nt)
cp_nt.create_cycle("C-0001", {**cycle_fixture("C-0001"), "knowledge_triage": None})
write_objective(root_nt, "C-0001")
cp_nt.transition_cycle("C-0001", "READY", reason="ready")
try:
    cp_nt.transition_cycle("C-0001", "RUNNING", reason="no triage")
    check("RUNNING without knowledge_triage rejected", False)
except ValueError as exc:
    check("RUNNING without knowledge_triage rejected", "knowledge_triage" in str(exc))

cp.create_hypothesis("H-0001", {
    "cycle_id": "C-0001",
    "observation": "controlled access pattern",
    "hypothesis": "authorization differs by principal",
    "secure_prediction": "foreign object remains denied",
    "vulnerable_prediction": "foreign object is readable",
})

# 3. Evidence is an object with a stable ID + hash; later refs must resolve.
artifact = root / "04_cycles/C-0001/proof.txt"
artifact.write_text("proof-v1\n")
ev = cp.register_evidence("04_cycles/C-0001/proof.txt", kind="raw", source="researcher-owned", cycle_id="C-0001")
eid = ev["payload"]["id"]
check("evidence ID allocated", eid == "E-000001")
check("evidence ref object stored", cp.evidence_index()[eid]["sha256"])

# 4. Action preflight rejects out-of-scope and accepts complete in-scope record.
base_action = {
    "id": "A-TEST", "cycle_id": "C-0001", "target": "https://example.test/api",
    "scope_status": "OUT_OF_SCOPE", "account": "researcher-A", "object_owner": "researcher-A",
    "purpose": "distinguish authorization behavior", "hypothesis": "H-0001",
    "expected_secure": "denied", "expected_vulnerable": "unexpected access",
    "side_effect": "none", "stop_condition": "stop on unsafe behavior", "evidence_refs": [eid]
}
try:
    cp.record_action(base_action)
    check("out-of-scope action rejected", False)
except ValueError:
    check("out-of-scope action rejected", True)
base_action["scope_status"] = "IN_SCOPE"
ev = cp.record_action(base_action)
check("live action preflight recorded", ev["type"] == "ACTION_RECORDED")

# 4b. Preflight tokens: the single-use binding the enforcer plugin consumes.
#     Default-deny first: with no scope recorded, prepare refuses and names the fix.
no_shape = {k: v for k, v in base_action.items() if k != "evidence_refs"}
try:
    cp.prepare_action(no_shape)
    check("prepare requires request_shape", False)
except ValueError as exc:
    check("prepare requires request_shape", "request_shape" in str(exc))
shape = {"method": "GET", "url": "https://example.test/api", "principal": "researcher-A"}
try:
    cp.prepare_action({**base_action, "tool_family": "http", "request_shape": shape})
    check("prepare refuses when scope is unset", False)
except ValueError as exc:
    check("prepare refuses when scope is unset",
          "no scope configured" in str(exc) and "scope-set" in str(exc) and "gate: none" in str(exc))

# 4c. Per-host scope: once assets are listed, prepare enforces them.
(root / "00_control/engagement.yaml").write_text(
    'program:\n  name: "x"\nassets:\n  - "example.test"\n  - "*.wild.example"\nstatus: "configured"\n')
tok = cp.prepare_action({**base_action, "tool_family": "http", "request_shape": shape})
check("preflight token issued with digest",
      tok["action_id"].startswith("A-") and len(tok["argument_digest"]) == 64 and len(tok["nonce"]) == 32)
tok2 = cp.prepare_action({**base_action, "tool_family": "http", "request_shape": shape})
check("digest is canonical over the shape", tok2["argument_digest"] == tok["argument_digest"])
check("token carries the full preflight",
      tok.get("preflight", {}).get("purpose") == base_action["purpose"]
      and tok["preflight"].get("cycle_id") == "C-0001")
check("token store is not the ledger",
      (root / "11_runtime/action-tokens.jsonl").is_file()
      and "action-tokens" not in (root / "11_runtime/events.jsonl").read_text())

try:
    cp.prepare_action({**base_action, "request_shape": {"method": "GET", "url": "https://evil.test/x", "principal": "researcher-A"}})
    check("out-of-scope prepare rejected", False)
except ValueError as exc:
    check("out-of-scope prepare rejected", "outside the engagement scope" in str(exc))
tok3 = cp.prepare_action({**base_action, "request_shape": {"method": "GET", "url": "https://example.test/x", "principal": "researcher-A"}})
check("in-scope prepare passes", tok3["action_id"].startswith("A-"))
tok4 = cp.prepare_action({**base_action, "request_shape": {"method": "GET", "url": "https://sub.wild.example/y", "principal": "researcher-A"}})
check("wildcard asset matches a subdomain", tok4["action_id"].startswith("A-"))

# 4d. scope_check is the single seam the BUA runner and harnesses share.
sc = scope_check(root, "https://sub.wild.example/y")
check("scope_check seam reports in-scope", sc["gate"] == "assets" and sc["in_scope"] is True)
sc = scope_check(root, "https://evil.test/x")
check("scope_check seam reports out-of-scope", sc["in_scope"] is False and sc["host"] == "evil.test")
nogate = Path(tempfile.mkdtemp())
(nogate / "00_control").mkdir(parents=True)
sc = scope_check(nogate, "https://anything.example/x")
check("scope_check seam: absent scope defaults to deny",
      sc["gate"] == "unset" and sc["in_scope"] is False)
(nogate / "00_control/engagement.yaml").write_text("scope:\n  assets:\n    - {host: nested}\n")
sc = scope_check(nogate, "https://anything.example/x")
check("scope_check seam: unparseable assets fail closed",
      sc["gate"] == "unenforceable" and sc["in_scope"] is False)
(nogate / "00_control/engagement.yaml").write_text("scope:\n  gate: none\n")
sc = scope_check(nogate, "https://anything.example/x")
check("scope_check seam: explicit gate none disables the gate",
      sc["gate"] == "disabled" and sc["in_scope"] is True)
(nogate / "00_control/engagement.yaml").write_text("scope:\n  gate: yes\n")
sc = scope_check(nogate, "https://anything.example/x")
check("scope_check seam: other gate values stay default-deny",
      sc["gate"] == "unset" and sc["in_scope"] is False)
(nogate / "00_control/engagement.yaml").write_text("program:\n  gate: none\n")
sc = scope_check(nogate, "https://anything.example/x")
check("scope_check seam: gate outside the scope block does not disable",
      sc["gate"] == "unset" and sc["in_scope"] is False)
(nogate / "00_control/engagement.yaml").write_text("program:\n  scope:\n  gate: none\n")
sc = scope_check(nogate, "https://anything.example/x")
check("scope_check seam: an indented scope block is not top-level",
      sc["gate"] == "unset" and sc["in_scope"] is False)

# 4d-bis. Canonical `gate: none` rule (parity with dsh-plugin scopeReasonFor): depth-1
#         entries only, comment lines skipped, trailing comments cut, fullmatch value.
for label, text, disabled in [
    ("bare", "scope:\n  gate: none\n", True),
    ("double-quoted", 'scope:\n  gate: "none"\n', True),
    ("single-quoted", "scope:\n  gate: 'none'\n", True),
    ("trailing comment", "scope:\n  gate: none  # opt-out\n", True),
    ("tab indent", "scope:\n\tgate: none\n", True),
    ("commented-out gate", "scope:\n  # gate: none\n", False),
    ("other gate value", "scope:\n  gate: nonexistent\n", False),
    ("other key", "scope:\n  mygate: none\n", False),
    ("nested gate under a child key", "scope:\n  exclusions:\n    gate: none\n", False),
    ("flow-style scope (documented limitation)", "scope: {gate: none}\n", False),
]:
    (nogate / "00_control/engagement.yaml").write_text(text)
    sc = scope_check(nogate, "https://anything.example/x")
    check(f"canonical gate: {label} -> {'disabled' if disabled else 'not disabled'}",
          (sc["gate"] == "disabled") is disabled)

# 4d-ter. Host normalization shared with the enforcer: userinfo and one trailing dot.
(nogate / "00_control/engagement.yaml").write_text('scope:\n  assets:\n  - "t.example"\n')
sc = scope_check(nogate, "https://user:pass@t.example/a")
check("scope_check strips userinfo before host comparison",
      sc["in_scope"] is True and sc["host"] == "t.example")
sc = scope_check(nogate, "https://t.example./a")
check("scope_check strips one trailing dot before host comparison",
      sc["in_scope"] is True and sc["host"] == "t.example")
sc = scope_check(nogate, "HTTPS://T.EXAMPLE/a")
check("scope_check lowercases scheme and host", sc["in_scope"] is True)

# 4e. Prepare honors the gate modes end to end: disabled allows, assets enforce.
scope_root = fresh_root(); cp_scope = ControlPlane(scope_root)
cp_scope.create_cycle("C-0001", cycle_fixture("C-0001"))
write_objective(scope_root, "C-0001")
cp_scope.transition_cycle("C-0001", "READY", reason="ready")
cp_scope.transition_cycle("C-0001", "RUNNING", reason="run")
cp_scope.create_hypothesis("H-0001", {
    "cycle_id": "C-0001",
    "observation": "scope fixture",
    "hypothesis": "scope fixture",
    "secure_prediction": "denied",
    "vulnerable_prediction": "allowed",
})
scope_action = {k: v for k, v in base_action.items() if k != "evidence_refs"}
scope_action["request_shape"] = {"method": "GET", "url": "https://off-target.example/x", "principal": "researcher-A"}
(scope_root / "00_control/engagement.yaml").write_text("scope:\n  gate: none\n")
tok = cp_scope.prepare_action(scope_action)
check("prepare allows an explicit gate none opt-out", tok["action_id"].startswith("A-"))
(scope_root / "00_control/engagement.yaml").write_text("scope:\n  assets:\n  - \"example.test\"\n")
try:
    cp_scope.prepare_action(scope_action)
    check("prepare enforces assets mode", False)
except ValueError as exc:
    check("prepare enforces assets mode", "outside the engagement scope" in str(exc))

# 4f. scope-set: provenance-backed mutation that preserves every unrelated byte.
set_root = fresh_root()
(set_root / "00_control/engagement.yaml").write_text(
    'program:\n  name: "x"\n\nscope:\n  assets: []\n  out_of_scope: []\n\n'
    'accounts:\n  researcher_controlled: []\n\nconfidence: "VERIFIED"\n')
cp_set = ControlPlane(set_root)
try:
    cp_set.set_scope(["example.test"], "")
    check("scope-set rejects an empty source_reference", False)
except ValueError as exc:
    check("scope-set rejects an empty source_reference", "source_reference" in str(exc))
try:
    cp_set.set_scope([], "policy#scope")
    check("scope-set rejects empty assets in assets mode", False)
except ValueError as exc:
    check("scope-set rejects empty assets in assets mode", "assets" in str(exc))
ev = cp_set.set_scope(["example.test", "*.sub.example"], "policy#scope")
check("SCOPE_CHANGED recorded on the scope entity",
      ev["type"] == "SCOPE_CHANGED" and ev["entity_type"] == "scope" and ev["entity_id"] == "engagement")
check("SCOPE_CHANGED payload carries previous/new assets, gate and source",
      ev["payload"]["previous_assets"] == [] and ev["payload"]["assets"] == ["example.test", "*.sub.example"]
      and ev["payload"]["gate"] == "assets" and ev["payload"]["source_reference"] == "policy#scope")
text = (set_root / "00_control/engagement.yaml").read_text()
check("scope-set rewrites assets as a quoted block list",
      '  assets:\n  - "example.test"\n  - "*.sub.example"\n' in text)
check("scope-set preserves unrelated blocks and comments",
      '  name: "x"' in text and "  researcher_controlled: []" in text
      and 'confidence: "VERIFIED"' in text and "  out_of_scope: []" in text)
cp_set.set_scope(["example.test", "*.sub.example"], "policy#scope", human_reference="ticket-1")
check("scope-set is idempotent on re-run", (set_root / "00_control/engagement.yaml").read_text() == text)
ev2 = cp_set.set_scope([], "policy#non-target work", gate="none", human_reference="ticket-1")
check("scope-set gap: gate none mode records cleared assets",
      ev2["payload"]["gate"] == "none" and ev2["payload"]["assets"] == []
      and ev2["payload"]["previous_assets"] == ["example.test", "*.sub.example"])
text2 = (set_root / "00_control/engagement.yaml").read_text()
check("scope-set writes the gate line and preserves the rest",
      "  gate: none\n" in text2 and "  out_of_scope: []" in text2 and "  researcher_controlled: []" in text2)
check("scope-set gate none is reachable through scope_check",
      scope_check(set_root, "https://anything.example/x")["gate"] == "disabled")
cp_set.set_scope(["example.test"], "policy#scope", human_reference="ticket-1")
text3 = (set_root / "00_control/engagement.yaml").read_text()
check("scope-set removes the gate line in assets mode",
      "gate:" not in text3 and '  assets:\n  - "example.test"\n' in text3)
comment_root = fresh_root()
(comment_root / "00_control/engagement.yaml").write_text("scope:  # assets live here\n  assets: []\n")
ControlPlane(comment_root).set_scope(["example.test"], "policy#scope")
comment_text = (comment_root / "00_control/engagement.yaml").read_text()
check("scope-set rewrites a commented scope header in place",
      comment_text.count("scope:") == 1 and '  assets:\n  - "example.test"\n' in comment_text)
cli_payload = set_root / "scope-payload.json"
cli_payload.write_text(json.dumps({"assets": ["cli.example"], "source_reference": "policy#cli",
                                   "human_reference": "ticket-cli"}))
sub = subprocess.run([sys.executable, str(TOOLS / "researchctl.py"), str(set_root),
                      "scope-set", str(cli_payload)], capture_output=True, text=True)
check("researchctl scope-set CLI records the change",
      sub.returncode == 0 and '"SCOPE_CHANGED"' in sub.stdout)
check("CLI scope-set is readable back by scope_check",
      scope_check(set_root, "https://cli.example/x")["gate"] == "assets")

# 4f-bis. scope-set input validation: assets are host/URL strings only, so a crafted
#         item can never inject YAML structure. The item is named in the error.
bad_root = fresh_root()
bad_file = bad_root / "00_control/engagement.yaml"
cp_bad = ControlPlane(bad_root)
for bad in ['ok.example"\nmalicious: true', 'embedded"quote', "embedded'quote",
            "back\\slash", "hash#comment", "space in host", "tab\thost",
            "control\x01char", "cr\rreturn", "line\nbreak", "", "   "]:
    try:
        cp_bad.set_scope([bad], "policy#x")
        check(f"scope-set rejects unsafe asset {bad!r}", False)
    except ValueError as exc:
        check(f"scope-set rejects unsafe asset {bad!r}", repr(bad) in str(exc))
check("scope-set rejected input never reaches the file",
      not bad_file.exists() or "malicious" not in bad_file.read_text())
check("scope-set rejected input records no event",
      "SCOPE_CHANGED" not in (bad_root / "11_runtime/events.jsonl").read_text())
ok_root = fresh_root()
ControlPlane(ok_root).set_scope(
    ["api.example.com", "*.wild.example", "127.0.0.1:8443", "https://url.example/path"], "policy#x")
check("scope-set accepts host, wildcard, host:port and URL assets",
      engagement_assets(ok_root) == ["api.example.com", "*.wild.example", "127.0.0.1:8443",
                                     "https://url.example/path"])

# 4f-ter. Writer round-trip: three file shapes + CRLF, depth-aware, idempotent.
shape_a = fresh_root()
(shape_a / "00_control/engagement.yaml").write_text(
    'program:\n  name: "x"\n\nscope:\n  assets:\n  - "old.example"\n  exclusions:\n'
    '    gate: strict\n  gate: none\n\naccounts:\n  researcher_controlled: []\n')
cp_a = ControlPlane(shape_a)
cp_a.set_scope(["new.example"], "policy#round-trip", human_reference="ticket-1")
a_text = (shape_a / "00_control/engagement.yaml").read_text()
check("set_scope shape A: assets parse back exactly", engagement_assets(shape_a) == ["new.example"])
check("set_scope shape A: assets mode round-trips through the gate parser",
      scope_check(shape_a, "https://new.example/x")["gate"] == "assets")
check("set_scope shape A: nested gate survives, depth-1 gate is replaced",
      "    gate: strict" in a_text and "  gate: none" not in a_text and a_text.count("gate:") == 1)
check("set_scope shape A: unrelated blocks survive",
      '  name: "x"' in a_text and "researcher_controlled: []" in a_text)
cp_a.set_scope(["new.example"], "policy#round-trip", human_reference="ticket-1")
check("set_scope shape A: idempotent", (shape_a / "00_control/engagement.yaml").read_text() == a_text)
cp_a.set_scope(["new.example"], "policy#round-trip", gate="none", human_reference="ticket-1")
check("set_scope shape A: gate none round-trips",
      scope_check(shape_a, "https://anything.example/x")["gate"] == "disabled")

shape_b = fresh_root()
(shape_b / "00_control/engagement.yaml").write_text(
    'program:\n  name: "x"\n\nassets:\n  - "old.example"\n\nstatus: "configured"\n')
cp_b = ControlPlane(shape_b)
cp_b.set_scope(["new.example"], "policy#round-trip", human_reference="ticket-1")
b_text = (shape_b / "00_control/engagement.yaml").read_text()
check("set_scope shape B: legacy assets entry becomes a scope block in place",
      "scope:\n  assets:\n  - \"new.example\"\n" in b_text and "old.example" not in b_text)
check("set_scope shape B: assets parse back exactly", engagement_assets(shape_b) == ["new.example"])
check("set_scope shape B: blank line and later entries survive",
      'status: "configured"' in b_text and "program:" in b_text)
check("set_scope shape B: gate mode round-trips",
      scope_check(shape_b, "https://new.example/x")["gate"] == "assets")

shape_b2 = fresh_root()
(shape_b2 / "00_control/engagement.yaml").write_text(
    'program:\n  name: "x"\nassets: [old.example]\nstatus: "configured"\n')
cp_b2 = ControlPlane(shape_b2)
cp_b2.set_scope(["new.example"], "policy#round-trip", human_reference="ticket-1")
b2_text = (shape_b2 / "00_control/engagement.yaml").read_text()
check("set_scope shape B2: legacy inline assets list becomes a scope block",
      'scope:\n  assets:\n  - "new.example"\n' in b2_text and "old.example" not in b2_text
      and engagement_assets(shape_b2) == ["new.example"])

shape_a2 = fresh_root()
(shape_a2 / "00_control/engagement.yaml").write_text('scope:\n  assets: [old.example]\n  gate: strict\n')
cp_a2 = ControlPlane(shape_a2)
cp_a2.set_scope(["new.example"], "policy#round-trip", human_reference="ticket-1")
check("set_scope shape A2: inline assets list inside scope is rewritten as a block",
      engagement_assets(shape_a2) == ["new.example"]
      and '  - "new.example"' in (shape_a2 / "00_control/engagement.yaml").read_text()
      and scope_check(shape_a2, "https://new.example/x")["gate"] == "assets")

shape_a3 = fresh_root()
(shape_a3 / "00_control/engagement.yaml").write_text('scope:\n  gate: none\n  assets:\n  - "old.example"\n')
ControlPlane(shape_a3).set_scope(["new.example"], "policy#round-trip", human_reference="ticket-1")
check("set_scope shape A3: gate line before assets is handled",
      scope_check(shape_a3, "https://new.example/x")["gate"] == "assets"
      and engagement_assets(shape_a3) == ["new.example"])

shape_c = fresh_root()
(shape_c / "00_control/engagement.yaml").write_text('program:\n  name: "x"\n')
cp_c = ControlPlane(shape_c)
cp_c.set_scope(["new.example"], "policy#round-trip")
c_text = (shape_c / "00_control/engagement.yaml").read_text()
check("set_scope shape C: first bootstrap record needs no human_reference",
      c_text.startswith('program:\n  name: "x"'))
check("set_scope shape C: appends a parseable scope block at EOF",
      engagement_assets(shape_c) == ["new.example"])
check("set_scope shape C: gate mode round-trips",
      scope_check(shape_c, "https://new.example/x")["gate"] == "assets")
try:
    cp_c.set_scope(["other.example"], "policy#again")
    check("scope-set requires human_reference once a change is recorded", False)
except ValueError as exc:
    check("scope-set requires human_reference once a change is recorded",
          "human_reference" in str(exc))
ev_c2 = cp_c.set_scope(["other.example"], "policy#again", human_reference="ticket-2")
check("SCOPE_CHANGED carries the human_reference",
      ev_c2["payload"]["human_reference"] == "ticket-2")

hr_root = fresh_root()
(hr_root / "00_control/engagement.yaml").write_text('scope:\n  assets:\n  - "legacy.example"\n')
try:
    ControlPlane(hr_root).set_scope(["new.example"], "policy#x")
    check("scope-set requires human_reference to re-record an existing asset list", False)
except ValueError as exc:
    check("scope-set requires human_reference to re-record an existing asset list",
          "human_reference" in str(exc))

crlf_root = fresh_root()
(crlf_root / "00_control/engagement.yaml").write_bytes(
    'program:\r\n  name: "x"\r\n\r\nscope:\r\n  assets:\r\n  - "old.example"\r\n\r\naccounts: []\r\n'.encode())
cp_crlf = ControlPlane(crlf_root)
cp_crlf.set_scope(["new.example"], "policy#round-trip", human_reference="ticket-1")
crlf_after = (crlf_root / "00_control/engagement.yaml").read_bytes().decode()
check("set_scope CRLF: assets parse back exactly", engagement_assets(crlf_root) == ["new.example"])
check("set_scope CRLF: gate mode round-trips",
      scope_check(crlf_root, "https://new.example/x")["gate"] == "assets")
check("set_scope CRLF: line endings preserved",
      "\r\n" in crlf_after and crlf_after.count("\n") == crlf_after.count("\r\n"))

# 4f-quinquies. CR-only line endings parse identically (the JS mirror splits on
#               /\r\n|\r|\n/, the Python side on splitlines()).
cr_only_root = fresh_root()
(cr_only_root / "00_control/engagement.yaml").write_bytes(b'scope:\r  assets:\r  - "t.example"\r')
check("CR-only engagement.yaml parses the asset list",
      engagement_assets(cr_only_root) == ["t.example"])
check("CR-only engagement.yaml is reachable through scope_check",
      scope_check(cr_only_root, "https://t.example/a")["in_scope"] is True)
check("CR-only engagement.yaml still denies out-of-scope hosts",
      scope_check(cr_only_root, "https://evil.example/x")["in_scope"] is False)

# 4f-sexies. Depth-aware parser: only a depth-1 `assets:` entry inside the top-level
#            `scope:` block is authoritative; a legacy top-level `assets:` block is
#            accepted ONLY when no `scope:` block exists.
depth_root = fresh_root()
depth_file = depth_root / "00_control/engagement.yaml"
depth_cases = [
    ("legacy-only", 'assets:\n  - "legacy.example"\n', ["legacy.example"], "assets"),
    ("scope-wins-over-legacy-before",
     'assets:\n  - "legacy.example"\n\nscope:\n  assets:\n  - "scoped.example"\n',
     ["scoped.example"], "assets"),
    ("scope-wins-over-legacy-after",
     'scope:\n  assets:\n  - "scoped.example"\n\nassets:\n  - "legacy.example"\n',
     ["scoped.example"], "assets"),
    ("nested-assets-under-child-key",
     'scope:\n  exclusions:\n    assets:\n    - "nested.example"\n  assets:\n  - "scoped.example"\n',
     ["scoped.example"], "assets"),
    ("nested-assets-only", 'program:\n  assets:\n  - "nested.example"\n', None, "unset"),
    ("nested-assets-only-inside-scope",
     'scope:\n  exclusions:\n    assets:\n    - "nested.example"\n', None, "unset"),
    ("duplicate-assets-inside-scope",
     'scope:\n  assets:\n  - "first.example"\n  assets:\n  - "second.example"\n',
     ["first.example"], "assets"),
    ("legacy-col0-comment-and-list",
     '# program assets\nassets:\n  - "legacy.example"\n', ["legacy.example"], "assets"),
]
for label, text, expected, gate in depth_cases:
    depth_file.write_text(text)
    check(f"depth-aware parser: {label}", engagement_assets(depth_root) == expected)
    check(f"depth-aware gate: {label}",
          scope_check(depth_root, "https://anything.example/x")["gate"] == gate)

# 4f-septies. Writer postcondition over hostile scope shapes: after set_scope the parser
#             must return exactly the requested list, and the gate mode must match the
#             request (a stale `gate: none` must be impossible).
for label, text in [
    ("legacy-before-scope",
     'assets:\n  - "legacy.example"\n\nscope:\n  assets:\n  - "old.example"\n'),
    ("legacy-after-scope",
     'scope:\n  assets:\n  - "old.example"\n\nassets:\n  - "legacy.example"\n'),
    ("nested-assets-under-child-key",
     'scope:\n  assets:\n  - "old.example"\n  exclusions:\n    assets:\n    - "nested.example"\n'),
    ("duplicate-assets-inside-scope",
     'scope:\n  assets:\n  - "old.example"\n  assets:\n  - "other.example"\n'),
    ("col0-comment-and-legacy-block-list",
     '# program assets\nassets:\n  - "old.example"\n'),
    ("col0-comment-and-scope-block-list",
     '# scope block\nscope:\n  assets:\n  - "old.example"\n'),
]:
    wroot = fresh_root()
    (wroot / "00_control/engagement.yaml").write_text(text)
    ControlPlane(wroot).set_scope(["new.example"], "policy#writer", human_reference="ticket-1")
    check(f"writer postcondition: {label}", engagement_assets(wroot) == ["new.example"])
    check(f"writer gate mode: {label}",
          scope_check(wroot, "https://new.example/x")["gate"] == "assets")
    wtext = (wroot / "00_control/engagement.yaml").read_text()
    if label.startswith("nested"):
        check(f"writer preserves nested bytes: {label}", "nested.example" in wtext)
    if label == "duplicate-assets-inside-scope":
        check("writer collapses duplicate scope assets entries", wtext.count("assets:") == 1)
    if label.startswith("legacy"):
        check(f"writer removes the shadowed legacy block: {label}", "legacy.example" not in wtext)
    if label.startswith("col0"):
        check(f"writer preserves the col-0 comment: {label}", wtext.lstrip().startswith("#"))

# 4f-octies. Duplicate depth-1 gate lines are all removed; a nested gate survives.
dup_gate_root = fresh_root()
(dup_gate_root / "00_control/engagement.yaml").write_text(
    'scope:\n  assets:\n  - "old.example"\n  gate: none\n  exclusions:\n'
    '    gate: strict\n  gate: none\n')
ControlPlane(dup_gate_root).set_scope(["new.example"], "policy#gate", human_reference="ticket-1")
dup_text = (dup_gate_root / "00_control/engagement.yaml").read_text()
check("set_scope removes every depth-1 gate line", dup_text.count("gate: none") == 0)
check("set_scope keeps the nested gate", "    gate: strict" in dup_text)
check("set_scope postcondition asserts the gate mode",
      scope_check(dup_gate_root, "https://new.example/x")["gate"] == "assets")

# 4f-nonies. Postcondition enforcement: a parse mismatch after the atomic replace restores
#            the pre-write content and records no event.
guard_root = fresh_root()
guard_text = 'scope:\n  assets:\n  - "old.example"\n'
(guard_root / "00_control/engagement.yaml").write_text(guard_text)
cp_guard = ControlPlane(guard_root)
ledger_before = (guard_root / "11_runtime/events.jsonl").read_text()
try:
    with mock.patch.object(_control_plane, "engagement_assets", return_value=["tampered.example"]):
        cp_guard.set_scope(["new.example"], "policy#x", human_reference="ticket-1")
    check("scope-set postcondition mismatch is refused", False)
except ValueError as exc:
    check("scope-set postcondition mismatch is refused", "postcondition" in str(exc))
check("postcondition mismatch restores the pre-write file",
      (guard_root / "00_control/engagement.yaml").read_text() == guard_text)
check("postcondition mismatch records no event",
      (guard_root / "11_runtime/events.jsonl").read_text() == ledger_before)

# 4f-decies. Non-ASCII assets round-trip through the writer (ensure_ascii=False).
uni_root = fresh_root()
ControlPlane(uni_root).set_scope(["münich.example", "xn--bcher-kva.example"], "policy#unicode")
uni_text = (uni_root / "00_control/engagement.yaml").read_text()
check("scope-set writes non-ASCII assets raw (no \\uXXXX escapes)",
      "münich.example" in uni_text and "\\u" not in uni_text)
check("non-ASCII assets round-trip",
      engagement_assets(uni_root) == ["münich.example", "xn--bcher-kva.example"])

# 4f-undecies. A symlinked engagement.yaml is written through (the link survives) and the
#              original file mode is preserved on the replacement.
link_root = fresh_root()
real_file = link_root / "00_control" / "engagement-real.yaml"
real_file.write_text('scope:\n  assets:\n  - "old.example"\n')
os.chmod(real_file, 0o640)
link = link_root / "00_control" / "engagement.yaml"
os.symlink(real_file, link)
ControlPlane(link_root).set_scope(["new.example"], "policy#symlink", human_reference="ticket-1")
check("set_scope keeps engagement.yaml a symlink", link.is_symlink())
check("set_scope writes through the symlink", engagement_assets(link_root) == ["new.example"])
check("set_scope preserves the original file mode",
      (os.stat(link).st_mode & 0o777) == 0o640)

# 4f-duodecies. human_reference is required to touch a deliberately configured scope:
#              a prior SCOPE_CHANGED, a non-empty asset list, or an explicit gate: line.
hr_gate_root = fresh_root()
(hr_gate_root / "00_control/engagement.yaml").write_text('scope:\n  assets: []\n  gate: none\n')
try:
    ControlPlane(hr_gate_root).set_scope(["new.example"], "policy#x")
    check("explicit gate line requires human_reference", False)
except ValueError as exc:
    check("explicit gate line requires human_reference", "human_reference" in str(exc))
hr_gate_ev = ControlPlane(hr_gate_root).set_scope(["new.example"], "policy#x",
                                                  human_reference="ticket-1")
check("explicit gate line accepted with human_reference", hr_gate_ev["type"] == "SCOPE_CHANGED")
hr_gate2_root = fresh_root()
(hr_gate2_root / "00_control/engagement.yaml").write_text('scope:\n  assets: []\n  gate: assets\n')
try:
    ControlPlane(hr_gate2_root).set_scope(["new.example"], "policy#x")
    check("explicit non-none gate line requires human_reference", False)
except ValueError as exc:
    check("explicit non-none gate line requires human_reference", "human_reference" in str(exc))
hr_pristine = fresh_root()
(hr_pristine / "00_control/engagement.yaml").write_text('scope:\n  assets: []\n')
check("pristine assets: [] template stays bootstrap-free",
      ControlPlane(hr_pristine).set_scope(["new.example"], "policy#x")["type"] == "SCOPE_CHANGED")

# 4f-terdecies. The host helpers are public seam functions (audit imports them, not the
#               private aliases).
check("asset_hosts reduces a URL to its host",
      asset_hosts(["https://User@T.Example/path"]) == ["t.example"])
check("host_in_scope matches wildcard bases and subdomains",
      host_in_scope("a.wild.example", ["*.wild.example"])
      and host_in_scope("wild.example", ["*.wild.example"])
      and not host_in_scope("evil.example", ["*.wild.example"]))
audit_src = (TOOLS / "audit.py").read_text()
check("audit imports the public host helpers",
      "asset_hosts" in audit_src and "host_in_scope" in audit_src
      and "_asset_hosts" not in audit_src and "_host_in_scope" not in audit_src)

# 4f-quaterdecies. TOCTOU: scope is re-checked inside the lock critical section.
toctou_root, cp_toctou = scope_workspace('scope:\n  assets:\n  - "good.example"\n',
                                         "https://good.example/")
toctou_action = {k: v for k, v in base_action.items() if k != "evidence_refs"}
toctou_action["id"] = "A-TOCTOU"
toctou_action["request_shape"] = {"method": "GET", "url": "https://good.example/x",
                                  "principal": "researcher-A"}
seen_locked = {}
_real_scope_check = _control_plane.scope_check


def _spy_scope_check(root, url):
    seen_locked["locked"] = (root / "11_runtime" / ".control-plane.lock").is_dir()
    return _real_scope_check(root, url)


with mock.patch.object(_control_plane, "scope_check", side_effect=_spy_scope_check):
    cp_toctou.record_action(toctou_action)
check("record_action re-checks scope inside the lock", seen_locked.get("locked") is True)
seen_set_locked = {}


def _spy_set_scope_check(root, url):
    seen_set_locked["locked"] = (root / "11_runtime" / ".control-plane.lock").is_dir()
    return _real_scope_check(root, url)


with mock.patch.object(_control_plane, "scope_check", side_effect=_spy_set_scope_check):
    cp_toctou.set_scope(["good.example"], "policy#toctou", human_reference="ticket-1")
check("set_scope asserts the postcondition inside the lock", seen_set_locked.get("locked") is True)

# 4g. Audit re-checks recorded actions against the CURRENT scope and demands provenance.
#            appended only after the replace succeeds.
atomic_root = fresh_root()
(atomic_root / "00_control/engagement.yaml").write_text('scope:\n  assets:\n  - "keep.example"\n')
cp_atomic = ControlPlane(atomic_root)
ledger_before = (atomic_root / "11_runtime/events.jsonl").read_text()
try:
    with mock.patch.object(_control_plane.os, "replace", side_effect=OSError("simulated rename failure")):
        cp_atomic.set_scope(["new.example"], "policy#x", human_reference="ticket-1")
    check("scope-set aborts when the atomic replace fails", False)
except OSError:
    check("scope-set aborts when the atomic replace fails", True)
check("scope-set replace failure leaves engagement.yaml intact",
      "keep.example" in (atomic_root / "00_control/engagement.yaml").read_text())
check("scope-set replace failure appends no event",
      (atomic_root / "11_runtime/events.jsonl").read_text() == ledger_before)
check("scope-set replace failure cleans up the temp file",
      [p.name for p in (atomic_root / "00_control").iterdir()] == ["engagement.yaml"])
cp_atomic.set_scope(["new.example"], "policy#x", human_reference="ticket-1")
check("scope-set success leaves no staging file behind",
      [p.name for p in (atomic_root / "00_control").iterdir()] == ["engagement.yaml"]
      and engagement_assets(atomic_root) == ["new.example"])

# 4g. Audit re-checks recorded actions against the CURRENT scope and demands provenance.
audit_root, cp_audit = scope_workspace('scope:\n  assets:\n  - "good.example"\n', "https://evil.example/x")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(audit_root)], capture_output=True, text=True)
check("audit errors when a recorded action left the current scope",
      sub.returncode != 0
      and "targets 'evil.example' but the current engagement scope does not include it (gate=assets)" in sub.stdout)
cp_audit.set_scope([], "policy#non-target work", gate="none", human_reference="ticket-1")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(audit_root)], capture_output=True, text=True)
check("audit skips the scope re-check when the gate is disabled", sub.returncode == 0)

audit_root2, cp_audit2 = scope_workspace('scope:\n  assets:\n  - "good.example"\n', "https://good.example/")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(audit_root2)], capture_output=True, text=True)
check("audit warns when the scope has no provenance record",
      sub.returncode == 0 and "no SCOPE_CHANGED provenance record" in sub.stdout)
cp_audit2.set_scope(["good.example"], "policy#scope", human_reference="ticket-2")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(audit_root2)], capture_output=True, text=True)
check("provenance warning clears after scope-set",
      sub.returncode == 0 and "no SCOPE_CHANGED provenance record" not in sub.stdout)
cp_audit2.set_scope(["other.example"], "policy#narrowed", human_reference="ticket-2")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(audit_root2)], capture_output=True, text=True)
check("audit downgrades an action recorded under an earlier scope to a warning",
      sub.returncode == 0 and "was in scope when recorded" in sub.stdout
      and "targets 'good.example' but the current engagement scope does not include it" not in sub.stdout)

# A host that was never in scope (absent from the SCOPE_CHANGED previous_assets) stays an error.
outside_root, cp_outside = scope_workspace('scope:\n  assets:\n  - "good.example"\n', "https://evil.example/x")
cp_outside.set_scope(["other.example"], "policy#narrowed", human_reference="ticket-3")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(outside_root)], capture_output=True, text=True)
check("audit still errors for a host outside both scopes",
      sub.returncode != 0 and "targets 'evil.example'" in sub.stdout)

# request_shape.url is authoritative over payload.target when both are present.
shape_root, cp_shape = scope_workspace('scope:\n  assets:\n  - "good.example"\n', "https://good.example/")
shape_payload = {k: v for k, v in base_action.items() if k != "evidence_refs"}
shape_payload["id"] = "A-SHAPE"
shape_payload["target"] = "https://good.example/"
shape_payload["request_shape"] = {"method": "GET", "url": "https://evil.example/x", "principal": "researcher-A"}
cp_shape.append("ACTION_RECORDED", "action", "A-SHAPE", cycle_id="C-0001", payload=shape_payload)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(shape_root)], capture_output=True, text=True)
check("audit re-checks request_shape.url over payload.target",
      sub.returncode != 0 and "targets 'evil.example'" in sub.stdout
      and "targets 'good.example'" not in sub.stdout)

# Free-text targets are labels, not hosts: the audit re-checks only URL/host-shaped
# targets, so "the provided apk (static review, no network)" cannot fail the workspace.
apk_root, cp_apk = scope_workspace('scope:\n  assets:\n  - "good.example"\n',
                                   "the provided apk (static review, no network)")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(apk_root)], capture_output=True, text=True)
check("audit skips a free-text action target",
      sub.returncode == 0 and "the provided apk" not in sub.stdout)

# Bare host[:port] targets ARE host-shaped and stay re-checked.
bare_root, cp_bare = scope_workspace('scope:\n  assets:\n  - "good.example"\n', "evil.example")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(bare_root)], capture_output=True, text=True)
check("audit still re-checks bare host-shaped targets",
      sub.returncode != 0 and "targets 'evil.example'" in sub.stdout)

# 4h. record_action refuses a request_shape whose url is unset/out-of-scope; gate none passes.
ra_root, cp_ra = scope_workspace('scope:\n  assets:\n  - "good.example"\n', "https://good.example/")
ra_action = {k: v for k, v in base_action.items() if k != "evidence_refs"}
ra_action["id"] = "A-SCOPE-1"
ra_action["request_shape"] = {"method": "GET", "url": "https://evil.example/x", "principal": "researcher-A"}
try:
    cp_ra.record_action(ra_action)
    check("record_action refuses an out-of-scope request_shape url", False)
except ValueError as exc:
    check("record_action refuses an out-of-scope request_shape url",
          "outside the engagement scope" in str(exc))
legacy_action = {k: v for k, v in base_action.items() if k != "evidence_refs"}
legacy_action["id"] = "A-LEGACY"
ev = cp_ra.record_action(legacy_action)
check("record_action without request_shape keeps working (legacy snapshots)",
      ev["type"] == "ACTION_RECORDED")
unset_root, cp_unset = scope_workspace(None, "https://good.example/")
unset_action = {k: v for k, v in base_action.items() if k != "evidence_refs"}
unset_action["id"] = "A-UNSET"
unset_action["request_shape"] = {"method": "GET", "url": "https://good.example/x", "principal": "researcher-A"}
try:
    cp_unset.record_action(unset_action)
    check("record_action refuses an unset scope when request_shape is present", False)
except ValueError as exc:
    check("record_action refuses an unset scope when request_shape is present",
          "no scope configured" in str(exc))
gate_root, cp_gate = scope_workspace('scope:\n  gate: none\n', "https://any.example/")
gate_action = {k: v for k, v in base_action.items() if k != "evidence_refs"}
gate_action["id"] = "A-GATE"
gate_action["request_shape"] = {"method": "GET", "url": "https://off-target.example/x", "principal": "researcher-A"}
ev = cp_gate.record_action(gate_action)
check("record_action passes an explicit gate none", ev["type"] == "ACTION_RECORDED")

# 5. Result transitions validate evidence objects and the results.md artifact contract.
try:
    cp.transition_cycle("C-0001", "RESULT_READY", reason="bad ref", evidence_refs=["results.md"])
    check("path-like evidence ref rejected", False)
except ValueError:
    check("path-like evidence ref rejected", True)
try:
    cp.transition_cycle("C-0001", "RESULT_READY", reason="no disposition yet", evidence_refs=[eid])
    check("RESULT_READY requires filled Disposition", False)
except ValueError as exc:
    check("RESULT_READY requires filled Disposition", "Disposition" in str(exc))
write_results(root, "C-0001", eid)
cp.transition_cycle("C-0001", "RESULT_READY", reason="result recorded", evidence_refs=[eid])
cp.update_cycle("C-0001", {"result_summary": "impact reproduced with clean negative control"})

# 5a. Claim gate: VERIFIED needs independent review packets on both axes.
try:
    cp.transition_cycle("C-0001", "VERIFIED", reason="no reviews", evidence_refs=[eid])
    check("VERIFIED requires review packets", False)
except ValueError as exc:
    check("VERIFIED requires review packets", "review" in str(exc))
try:
    cp.merge_worker({"cycle_id": "C-0001", "evidence_refs": [eid], "review": {"axis": "vibes", "verdict": "pass"}})
    check("invalid review axis rejected", False)
except ValueError:
    check("invalid review axis rejected", True)
try:
    cp.merge_worker({"cycle_id": "C-0001", "evidence_refs": [eid], "review": {"axis": "objective", "verdict": "pass"}})
    check("review packet requires reviewer identity", False)
except ValueError as exc:
    check("review packet requires reviewer identity", "reviewer" in str(exc))
cp.merge_worker({"cycle_id": "C-0001", "evidence_refs": [eid], "next_step": "objective review",
                 "review": {"axis": "objective", "verdict": "pass", "reviewer": "run-objective"}})
try:
    cp.transition_cycle("C-0001", "VERIFIED", reason="one axis only", evidence_refs=[eid])
    check("VERIFIED requires both axes", False)
except ValueError:
    check("VERIFIED requires both axes", True)
cp.merge_worker({"cycle_id": "C-0001", "evidence_refs": [eid], "next_step": "method review",
                 "review": {"axis": "method", "verdict": "fail", "reviewer": "run-method"}})
try:
    cp.transition_cycle("C-0001", "VERIFIED", reason="failing review", evidence_refs=[eid])
    check("failing review blocks VERIFIED", False)
except ValueError:
    check("failing review blocks VERIFIED", True)
cp.merge_worker({"cycle_id": "C-0001", "evidence_refs": [eid], "next_step": "re-review after fixes",
                 "review": {"axis": "method", "verdict": "pass", "reviewer": "run-method"}})
cp.transition_cycle("C-0001", "VERIFIED", reason="verified", evidence_refs=[eid])
check("verified after both reviews pass", cp.cycle_status("C-0001") == "VERIFIED")

# 5a-bis. Two axes from one reviewer identity cannot satisfy the claim gate.
cp.create_cycle("C-0004", cycle_fixture("C-0004", "same-reviewer"))
write_objective(root, "C-0004")
cp.transition_cycle("C-0004", "READY", reason="ready")
cp.transition_cycle("C-0004", "RUNNING", reason="run")
(root / "same-reviewer-proof.txt").write_text("proof\n")
eid4 = cp.register_evidence("same-reviewer-proof.txt", kind="raw", source="researcher-owned",
                            cycle_id="C-0004")["payload"]["id"]
write_results(root, "C-0004", eid4)
cp.transition_cycle("C-0004", "RESULT_READY", reason="result", evidence_refs=[eid4])
cp.update_cycle("C-0004", {"result_summary": "bounded impact reproduced"})
for axis in ("objective", "method"):
    cp.merge_worker({"cycle_id": "C-0004", "evidence_refs": [eid4],
                     "review": {"axis": axis, "verdict": "pass", "reviewer": "same-run"}})
try:
    cp.transition_cycle("C-0004", "VERIFIED", reason="same reviewer", evidence_refs=[eid4])
    check("same reviewer cannot satisfy both axes", False)
except ValueError as exc:
    check("same reviewer cannot satisfy both axes", "distinct reviewers" in str(exc))

# 5b. CLOSED requires a technique evaluation for the cycle; learning files are projections.
try:
    cp.transition_cycle("C-0001", "CLOSED", reason="closed without technique", evidence_refs=[eid])
    check("CLOSED without technique evaluation rejected", False)
except ValueError as exc:
    check("CLOSED without technique evaluation rejected", "TECHNIQUE_EVALUATED" in str(exc))
cp.evaluate_technique({
    "cycle_id": "C-0001", "technique_family": "authz-differential", "result": "CONFIRMED",
    "interpretation": "principal difference reproduced", "learning": "differential oracle holds on this surface",
    "evidence_refs": [eid],
})
td = (root / "10_learning/technique-discoveries.md").read_text()
lr = (root / "11_runtime/last-result.md").read_text()
check("technique projections carry the result", "T-000001" in td and "CONFIRMED" in td and "T-000001" in lr)
cp.transition_cycle("C-0001", "CLOSED", reason="closed", evidence_refs=[eid])
check("terminal lifecycle enforced", cp.cycle_status("C-0001") == "CLOSED")

# 5c. Secret-shaped values are scrubbed on write (the ledger must never carry them raw).
cp.append("NOTE", "note", "N-1", reason="token glpat-ABCDEFGHIJKLMNOPQRST check",
          payload={"blob": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"})
ledger = (root / "11_runtime/events.jsonl").read_text()
check("secret-shaped values scrubbed at write", "glpat-" not in ledger and "ghp_" not in ledger and "[REDACTED]" in ledger)

# 5d. Stale-lock recovery: a dead owner must not brick the workspace.
lock = root / "11_runtime/.control-plane.lock"
lock.mkdir()
(lock / "owner").write_text("99999999 0\n")
ev = cp.append("NOTE", "note", "N-2", reason="after stale lock")
check("stale lock reclaimed", ev["type"] == "NOTE" and not lock.exists())

# 6. Human gate is durable and automatically binds to cycle state, without storing secrets.
root2 = fresh_root(); cp2 = ControlPlane(root2)
cp2.create_cycle("C-0002", cycle_fixture("C-0002", "gate"))
write_objective(root2, "C-0002")
cp2.transition_cycle("C-0002", "READY", reason="ready")
cp2.transition_cycle("C-0002", "RUNNING", reason="run")
cp2.request_gate("G-0001", {"cycle_id": "C-0002", "what_is_needed": "OTP", "why_human_only": "secret held by researcher", "resume_after": "RESUME"})
cp2.resolve_gate("G-0001", decision="RESUME", reference="human-confirmation-1")
raw = (root2 / "11_runtime/events.jsonl").read_text().lower()
check("gate auto-pauses and resumes cycle", cp2.cycle_status("C-0002") == "RUNNING")
check("gate never stores secret value", "human-confirmation-1" in raw and "otp-1234" not in raw)

# A human denial must not strand the cycle in HUMAN_GATE.
root_denied = fresh_root(); cp_denied = ControlPlane(root_denied)
cp_denied.create_cycle("C-0003", cycle_fixture("C-0003", "deny"))
write_objective(root_denied, "C-0003")
cp_denied.transition_cycle("C-0003", "READY", reason="ready")
cp_denied.transition_cycle("C-0003", "RUNNING", reason="run")
cp_denied.request_gate("G-0002", {"cycle_id": "C-0003", "what_is_needed": "CAPTCHA", "why_human_only": "human verification", "resume_after": "resume or pivot"})
cp_denied.resolve_gate("G-0002", decision="DENIED", reference="human-decision-2")
check("denied gate exits HUMAN_GATE", cp_denied.cycle_status("C-0003") == "BLOCKED")

# 7. Hash-chain and projection audit pass, then detect projection tamper and evidence mutation.
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(root2)], capture_output=True, text=True)
check("clean workspace audit passes", sub.returncode == 0)
plan = root2 / "04_cycles/C-0002/plan.yaml"
plan.write_text(plan.read_text().replace('status: "RUNNING"', 'status: "CLOSED"'))
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(root2)], capture_output=True, text=True)
check("audit detects projection drift", sub.returncode != 0 and "projection drift" in sub.stdout)
cp2.refresh()
artifact2 = root2 / "proof.txt"; artifact2.write_text("original\n")
cp2.register_evidence("proof.txt", kind="raw", source="researcher-owned")
artifact2.write_text("mutated\n")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(root2)], capture_output=True, text=True)
check("audit detects evidence hash drift", sub.returncode != 0 and "hash mismatch" in sub.stdout)

# 7b. Evidence must not carry secret-shaped values (29_SECURITY_HYGIENE, machine-checked).
root5 = fresh_root(); cp5 = ControlPlane(root5)
(root5 / "leak.txt").write_text("token glpat-ABCDEFGHIJKLMNOPQRST\n")
cp5.register_evidence("leak.txt", kind="raw", source="researcher-owned")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(root5)], capture_output=True, text=True)
check("audit rejects evidence carrying secrets", sub.returncode != 0 and "secret-shaped value" in sub.stdout)

# 7c. Registration stores a content-addressed copy; the copy is tamper-evident.
root6 = fresh_root(); cp6 = ControlPlane(root6)
(root6 / "snap.txt").write_text("snapshot body\n")
e6 = cp6.register_evidence("snap.txt", kind="raw", source="researcher-owned")["payload"]
store_file = root6 / e6["store_path"]
check("registration stores a content-addressed copy",
      store_file.is_file() and e6["sha256"] in store_file.name and store_file.read_text() == "snapshot body\n")
store_file.write_text("tampered\n")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(root6)], capture_output=True, text=True)
check("audit detects stored-copy tampering", sub.returncode != 0 and "stored copy hash mismatch" in sub.stdout)

# 7d. Freshness watchtower: the ledger is a projection; stale components fail the audit.
root7 = fresh_root(); cp7 = ControlPlane(root7)
cp7.record_freshness({"components": [
    {"target_component": "cdn-terminator", "pinned_version": "vX (header evidence)", "last_checked": "2026-09-20",
     "sources": ["vendor-changelog"], "action": "checked, no new primitives"},
    {"target_component": "chrome", "pinned_version": "UNKNOWN", "last_checked": "2020-01-01",
     "sources": ["release-feed"], "action": "no re-check since pin"},
]})
proj = (root7 / "10_learning/freshness.yaml").read_text()
check("freshness ledger is a projection", "GENERATED" in proj and "cdn-terminator" in proj)
report = cp7.freshness_report()
check("freshness report flags stale and unpinned",
      "chrome" in report["stale"] and "chrome" in report["unpinned"] and "cdn-terminator" not in report["stale"])
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(root7)], capture_output=True, text=True)
check("audit fails on stale freshness", sub.returncode != 0 and "stale" in sub.stdout)
cp7.record_freshness({"components": [
    {"target_component": "chrome", "pinned_version": "v153", "last_checked": "2026-09-21",
     "sources": ["release-feed"], "action": "re-checked after trigger"},
]})
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(root7)], capture_output=True, text=True)
check("audit passes after the re-check (UNKNOWN pin gone)", sub.returncode == 0)

# 8. Closure audit declarations must be evidence-backed and stale after new research events.
root4 = fresh_root(); cp4 = ControlPlane(root4)
cp4.create_cycle("C-0010", cycle_fixture("C-0010", "close"))
write_objective(root4, "C-0010")
cp4.transition_cycle("C-0010", "READY", reason="ready")
cp4.transition_cycle("C-0010", "RUNNING", reason="run")
proof4 = root4 / "scope-proof.txt"; proof4.write_text("audit proof\n")
e4 = cp4.register_evidence("scope-proof.txt", kind="audit", source="researcher-owned", cycle_id="C-0010")["payload"]["id"]
write_results(root4, "C-0010", e4, disposition="FALSE_POSITIVE")
cp4.transition_cycle("C-0010", "RESULT_READY", reason="result", evidence_refs=[e4])
cp4.update_cycle("C-0010", {"result_summary": "clean control reproduced the signal"})
cp4.transition_cycle("C-0010", "FALSE_POSITIVE", reason="fp", evidence_refs=[e4])
cp4.evaluate_technique({"cycle_id": "C-0010", "technique_family": "tls-pinning", "result": "FALSE_POSITIVE",
                        "interpretation": "control reproduced the signal", "learning": "no pinning oracle on this build",
                        "evidence_refs": [e4]})
cp4.transition_cycle("C-0010", "CLOSED", reason="closed", evidence_refs=[e4])
# Method self-attack is machine-checked: six rows, no blanks, or the audit is refused.
try:
    cp4.record_audit("method-self-attack", "PASS", "no matrix", evidence_refs=[e4])
    check("method-self-attack requires the six-row matrix", False)
except ValueError as exc:
    check("method-self-attack requires the six-row matrix", "matrix" in str(exc))
blank = {r: "none — fixture has no closed branches" for r in METHOD_SELF_ATTACK_ROWS}
blank["weak-negative"] = "   "
try:
    cp4.record_audit("method-self-attack", "PASS", "blank row", evidence_refs=[e4], matrix=blank)
    check("method-self-attack matrix rows must all be filled", False)
except ValueError as exc:
    check("method-self-attack matrix rows must all be filled", "weak-negative" in str(exc))
for cls in sorted(REQUIRED_AUDIT_CLASSES):
    if cls == "method-self-attack":
        cp4.record_audit(cls, "PASS", "six prompts answered", evidence_refs=[e4],
                         matrix={r: "none — fixture has no closed branches" for r in METHOD_SELF_ATTACK_ROWS})
    else:
        cp4.record_audit(cls, "PASS", f"{cls} complete", evidence_refs=[e4])
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(root4), "--closure"], capture_output=True, text=True)
check("evidence-backed audit declarations prove closure", sub.returncode == 0)
# Any later material research event invalidates the current audit set.
cp4.append("NOTE", "research", "N-1", reason="new research observation")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(root4), "--closure"], capture_output=True, text=True)
check("new research makes closure audits stale", sub.returncode != 0 and "_audit_current" in sub.stdout)

# 9. Chain tampering is detectable.
root3 = fresh_root(); cp3 = ControlPlane(root3)
cp3.append("NOTE", "note", "N-1", reason="one")
cp3.append("NOTE", "note", "N-2", reason="two")
lines = (root3 / "11_runtime/events.jsonl").read_text().splitlines()
item = json.loads(lines[0]); item["reason"] = "tampered"; lines[0] = json.dumps(item, separators=(",", ":"), sort_keys=True)
(root3 / "11_runtime/events.jsonl").write_text("\n".join(lines) + "\n")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(root3)], capture_output=True, text=True)
check("audit detects event tampering", sub.returncode != 0 and "event_hash mismatch" in sub.stdout)

next_view = cp4.next_actions()
check("next seam exposes legal lifecycle moves", any(x["cycle_id"] == "C-0010" for x in next_view["cycles"]))

print(f"\n{len(passed)} checks passed")
