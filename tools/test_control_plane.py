#!/usr/bin/env python3
"""End-to-end invariants for the canonical control plane and integrity audit."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT_REPO = TOOLS.parent
sys.path.insert(0, str(TOOLS))
from control_plane import (ControlPlane, METHOD_SELF_ATTACK_ROWS,  # noqa: E402
                           REQUIRED_AUDIT_CLASSES, scope_check)

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
no_shape = {k: v for k, v in base_action.items() if k != "evidence_refs"}
try:
    cp.prepare_action(no_shape)
    check("prepare requires request_shape", False)
except ValueError as exc:
    check("prepare requires request_shape", "request_shape" in str(exc))
shape = {"method": "GET", "url": "https://example.test/api", "principal": "researcher-A"}
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

# 4c. Per-host scope: prepare enforces engagement.yaml assets when they are listed.
(root / "00_control/engagement.yaml").write_text(
    'program:\n  name: "x"\nassets:\n  - "example.test"\n  - "*.wild.example"\nstatus: "configured"\n')
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
check("scope_check seam: no asset list -> no gate", sc["gate"] == "none" and sc["in_scope"] is True)
(nogate / "00_control/engagement.yaml").write_text("scope:\n  assets:\n    - {host: nested}\n")
sc = scope_check(nogate, "https://anything.example/x")
check("scope_check seam: unparseable assets fail closed",
      sc["gate"] == "unenforceable" and sc["in_scope"] is False)

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
