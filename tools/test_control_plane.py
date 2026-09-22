#!/usr/bin/env python3
"""End-to-end invariants for the canonical control plane and integrity audit."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parent
ROOT_REPO = TOOLS.parent
sys.path.insert(0, str(TOOLS))
import audit as _audit  # noqa: E402
import control_plane as _control_plane  # noqa: E402
from control_plane import (CYCLE_EDGES, GENERATED_HEADER, ControlPlane,  # noqa: E402
                           METHOD_SELF_ATTACK_ROWS, REQUIRED_AUDIT_CLASSES, asset_hosts,
                           engagement_assets, external_judgment_allowed, host_in_scope,
                           never_considered_packs, redact, scope_check)

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
    # Minimal knowledge index so the triage-coverage guard is exercised by fixtures
    # instead of being vacuous; `triage_for` computes the entries from this index.
    (root / "12_knowledge/fixture").mkdir(parents=True, exist_ok=True)
    (root / "12_knowledge/fixture/fixture.md").write_text("# Fixture pack\n")
    (root / "12_knowledge/INDEX.yaml").write_text(
        "packs:\n"
        "  fixture:\n"
        "    load_when: [test, question, placeholder, review, closure, fixture, same-reviewer, gate, deny, close, budget, scope]\n"
        "    files: [fixture.md]\n")
    return root


def triage_for(root: Path, objective: str) -> list[dict]:
    """Cover the auto-ranked packs exactly as the RUNNING guard computes them."""
    from knowledge_index import selection_cap, selection_query, top_packs
    ranked = [name for name, _ in top_packs(root, selection_query(root, objective), k=selection_cap())]
    return [{"pack": name, "verdict": "SKIP", "reason": "fixture triage reason covers this pack"}
            for name in (ranked or ["fixture"])]


def cycle_fixture(cid: str, objective: str = "test question", root: Path | None = None) -> dict:
    return {
        "id": cid, "type": "DISCOVERY", "objective": objective,
        "allowed_scope": ["example.test"], "stop_conditions": ["stop"], "controls": [],
        "status": "PLANNED",
        "knowledge_triage": triage_for(root, objective) if root is not None
                            else [{"pack": "fixture", "verdict": "SKIP",
                                   "reason": "fixture triage reason covers this pack"}],
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
    c.create_cycle("C-0001", cycle_fixture("C-0001", root=r))
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


def legacyize(root: Path) -> None:
    """Rewrite the ledger as a pre-versioning historical ledger (no os_version, re-hashed).

    Emulates a workspace archived before the version stamp existed: events lack the
    field, the chain is intact, and the audit must tolerate them as legacy records.
    """
    path = root / "11_runtime/events.jsonl"
    events = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    prev = "GENESIS"
    lines = []
    for event in events:
        event.pop("os_version", None)
        event["prev_hash"] = prev
        event.pop("event_hash", None)
        event["event_hash"] = ControlPlane._event_hash(event)
        prev = event["event_hash"]
        lines.append(json.dumps(event, sort_keys=True, separators=(",", ":")))
    path.write_text("\n".join(lines) + "\n")
    ControlPlane(root).refresh()


def downgrade_last_event(root: Path) -> None:
    """Strip `os_version` from only the final ledger event and re-hash it.

    Models a later append that slipped past the version stamp without touching the
    chain of earlier events (their hashes stay valid).
    """
    path = root / "11_runtime/events.jsonl"
    events = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    last = events[-1]
    last.pop("os_version", None)
    last.pop("event_hash", None)
    last["event_hash"] = ControlPlane._event_hash(last)
    path.write_text("\n".join(json.dumps(e, sort_keys=True, separators=(",", ":")) for e in events) + "\n")
    ControlPlane(root).refresh()


def downgrade_events_through(root: Path, entity_id: str) -> None:
    """Strip `os_version` from every event up to and including `entity_id`, re-chaining hashes.

    Keeps the ledger's version stamps monotone (legacy prefix, then versioned suffix) so a
    single legacy record can be emulated inside an otherwise versioned ledger.
    """
    path = root / "11_runtime/events.jsonl"
    events = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    prev = "GENESIS"
    legacy = True
    lines = []
    for event in events:
        if legacy:
            event.pop("os_version", None)
            if event.get("entity_id") == entity_id:
                legacy = False
        event["prev_hash"] = prev
        event.pop("event_hash", None)
        event["event_hash"] = ControlPlane._event_hash(event)
        prev = event["event_hash"]
        lines.append(json.dumps(event, sort_keys=True, separators=(",", ":")))
    path.write_text("\n".join(lines) + "\n")
    ControlPlane(root).refresh()


def recording_workspace(cid: str = "C-0001") -> tuple[Path, ControlPlane, str]:
    """RUNNING cycle with registered evidence and a filled results.md at RESULT_READY."""
    r = fresh_root()
    c = ControlPlane(r)
    c.create_cycle(cid, cycle_fixture(cid, "review binding", root=r))
    write_objective(r, cid)
    c.transition_cycle(cid, "READY", reason="ready")
    c.transition_cycle(cid, "RUNNING", reason="run")
    (r / f"{cid}-capture.txt").write_text("capture: bounded impact reproduced under the recorded control\n")
    eid = c.register_evidence(f"{cid}-capture.txt", kind="raw", source="researcher-owned",
                              cycle_id=cid)["payload"]["id"]
    write_results(r, cid, eid)
    c.transition_cycle(cid, "RESULT_READY", reason="result", evidence_refs=[eid])
    c.update_cycle(cid, {"result_summary": "bounded impact reproduced under review"})
    return r, c, eid


def close_workspace(with_action: bool = False, token_nonce: str | None = None,
                    with_closure_gate: bool = False) -> tuple[Path, ControlPlane, str]:
    """Minimal CLOSED workspace: one false-positive cycle, auditable evidence, no gates."""
    r = fresh_root()
    c = ControlPlane(r)
    c.create_cycle("C-0010", cycle_fixture("C-0010", "closure fixture", root=r))
    write_objective(r, "C-0010")
    c.transition_cycle("C-0010", "READY", reason="ready")
    c.transition_cycle("C-0010", "RUNNING", reason="run")
    if with_closure_gate:
        # The closure-review attestation on the real path: requested while RUNNING,
        # resolved APPROVED with a human reference, then the cycle resumes.
        c.request_gate("G-0001", {"cycle_id": "C-0010",
                                 "what_is_needed": "Closure review: confirm the false-positive disposition and the audit set before closure",
                                 "why_human_only": "Only the researcher can attest that closure was reviewed",
                                 "resume_after": "Gate resolution"})
        c.resolve_gate("G-0001", decision="APPROVED", reference="ticket-closure-1")
    if with_action:
        action = {
            "id": "A-CLOSURE", "cycle_id": "C-0010",
            "target": "the researcher-owned rehearsal target (no network)",
            "scope_status": "IN_SCOPE", "account": "researcher-A", "object_owner": "researcher-A",
            "purpose": "closure provenance check", "hypothesis": "rehearsal (no hypothesis)",
            "expected_secure": "n/a", "expected_vulnerable": "n/a",
            "side_effect": "none", "stop_condition": "stop after the check",
        }
        if token_nonce:
            # An honest executor flow: prepare a real token, consume it, record with
            # its nonce — the audit resolves the nonce against consumed tokens.
            (r / "00_control/engagement.yaml").write_text("scope:\n  gate: none\n")
            tok = c.prepare_action({
                **action, "tool_family": "http",
                "request_shape": {"method": "GET", "url": "https://example.test/api",
                                  "principal": "researcher-A"},
            })
            with (r / "11_runtime/action-tokens.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"action_id": tok["action_id"], "nonce": tok["nonce"],
                                     "consumed": True,
                                     "consumed_at": "2026-09-01T00:00:01Z"}) + "\n")
            action["token_nonce"] = tok["nonce"]
        c.record_action(action)
    (r / "scope-proof.txt").write_text("scope proof: the rehearsal asset stayed inside the recorded boundary\n")
    eid = c.register_evidence("scope-proof.txt", kind="audit", source="researcher-owned",
                              cycle_id="C-0010")["payload"]["id"]
    write_results(r, "C-0010", eid, disposition="FALSE_POSITIVE")
    c.transition_cycle("C-0010", "RESULT_READY", reason="result", evidence_refs=[eid])
    c.update_cycle("C-0010", {"result_summary": "clean control reproduced the signal"})
    c.transition_cycle("C-0010", "FALSE_POSITIVE", reason="fp", evidence_refs=[eid])
    c.evaluate_technique({"cycle_id": "C-0010", "technique_family": "tls-pinning",
                          "result": "FALSE_POSITIVE", "interpretation": "control reproduced the signal",
                          "learning": "no pinning oracle on this build", "evidence_refs": [eid]})
    c.transition_cycle("C-0010", "CLOSED", reason="closed", evidence_refs=[eid])
    return r, c, eid


AUDIT_SUMMARIES = {
    "scope": "scope audit: no assets were declared and none were contacted",
    "coverage": "every applicable matrix cell has a terminal state or a named blocker (C-0010)",
    "negative": "negative conclusions carry validated controls and their capture evidence",
    "open-hypothesis": "no high-value legal hypothesis is left without a disposition (none open)",
    "novelty-duplicate": "the candidate was compared against program history and current public research",
    "hygiene-cleanup": "no credentials, secrets or unrelated artifacts remain in reportable material",
}


def record_all_audits(cp: ControlPlane, eid: str) -> None:
    for cls, summary in AUDIT_SUMMARIES.items():
        cp.record_audit(cls, "PASS", summary, evidence_refs=[eid])
    cp.record_audit("method-self-attack", "PASS", "all six self-attack prompts are answered with no blank rows",
                    evidence_refs=[eid],
                    matrix={row: "none — fixture has no closed branches" for row in METHOD_SELF_ATTACK_ROWS})


def fill_proof(root: Path) -> None:
    """Emit the closure proof and replace every TODO(human) line with rehearsal prose."""
    _audit.emit_closure_proof(root, force=True)
    path = root / "06_audits/CLOSURE-PROOF.md"
    gate_binding = ""
    try:
        cp = ControlPlane(root)
        for gid in cp.all_gate_ids():
            gate = cp.gate(gid) or {}
            if gate.get("status") == "RESOLVED" and gate.get("decision") == "APPROVED" \
                    and str(gate.get("reference") or "").strip():
                gate_binding = (f"Closure-Gate: {gid} "
                                f"(reference: {str(gate['reference']).strip()})")
                break
    except (OSError, ValueError):
        gate_binding = ""
    lines = []
    for line in path.read_text().splitlines():
        if line.startswith("TODO(human):"):
            if "Closure-Gate" in line and gate_binding:
                lines.append(gate_binding)
            else:
                lines.append(f"Rehearsal judgment: {line.split(':', 1)[1].strip()} (satisfied by this fixture)")
        else:
            lines.append(line)
    path.write_text("\n".join(lines) + "\n")


def replace_proof_section(root: Path, name: str, body: str) -> Path:
    """Swap one closure-proof section body for `body`; the rest of the proof is untouched."""
    path = root / "06_audits/CLOSURE-PROOF.md"
    out: list[str] = []
    skip = False
    for line in path.read_text().splitlines():
        if line.startswith("## "):
            if skip:
                skip = False
            elif line[3:].strip() == name:
                out += [line, body]
                skip = True
                continue
        if not skip:
            out.append(line)
    path.write_text("\n".join(out) + "\n")
    return path


root = fresh_root()
cp = ControlPlane(root)

# 1. Create + canonical update, without allowing status mutation via update.
ev = cp.create_cycle("C-0001", cycle_fixture("C-0001", "placeholder", root=root))
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
    cp.create_cycle("C-0009", {**cycle_fixture("C-0009", root=root), "type": "HUNT"})
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
cp_nt.create_cycle("C-0001", {**cycle_fixture("C-0001", root=root_nt), "knowledge_triage": None})
write_objective(root_nt, "C-0001")
cp_nt.transition_cycle("C-0001", "READY", reason="ready")
try:
    cp_nt.transition_cycle("C-0001", "RUNNING", reason="no triage")
    check("RUNNING without knowledge_triage rejected", False)
except ValueError as exc:
    check("RUNNING without knowledge_triage rejected", "knowledge_triage" in str(exc))

# 2c. Triage must cover the auto-ranked packs: the guard refuses RUNNING until each has a
# USE/SKIP line with a reason.
def triage_root() -> Path:
    r = fresh_root()
    for pack, keyword in [("pack-a", "alpha"), ("pack-b", "beta"), ("pack-c", "gamma")]:
        (r / "12_knowledge" / pack).mkdir(parents=True, exist_ok=True)
        (r / "12_knowledge" / pack / f"{pack}.md").write_text(f"# {pack}\n")
    (r / "12_knowledge" / "INDEX.yaml").write_text(
        "packs:\n"
        "  pack-a:\n    load_when: [alpha]\n    files: [pack-a.md]\n"
        "  pack-b:\n    load_when: [beta]\n    files: [pack-b.md]\n"
        "  pack-c:\n    load_when: [gamma]\n    files: [pack-c.md]\n")
    return r


tr_root = triage_root()
cp_tr = ControlPlane(tr_root)
cp_tr.create_cycle("C-0001", cycle_fixture("C-0001", "alpha beta probe", root=tr_root))
write_objective(tr_root, "C-0001")
cp_tr.transition_cycle("C-0001", "READY", reason="ready")
cp_tr.update_cycle("C-0001", {"knowledge_triage": [{"pack": "pack-a", "verdict": "USE",
                                                    "reason": "alpha is covered by this triage line"}]})
try:
    cp_tr.transition_cycle("C-0001", "RUNNING", reason="missing pack-b")
    check("RUNNING refused when an auto-ranked pack is missing", False)
except ValueError as exc:
    check("RUNNING refused when an auto-ranked pack is missing",
          "pack-b" in str(exc) and "confirm or override" in str(exc))
cp_tr.update_cycle("C-0001", {"knowledge_triage": [
    {"pack": "pack-a", "verdict": "USE", "reason": "alpha is the question"},
    {"pack": "pack-b", "verdict": "SKIP", "reason": "beta is not relevant here"},
]})
cp_tr.transition_cycle("C-0001", "RUNNING", reason="covered")
check("RUNNING accepted when every auto-ranked pack is covered", cp_tr.cycle_status("C-0001") == "RUNNING")
# Overriding the auto-ranking in either direction is fine: a reasoned line is the point.
tr2_root = triage_root()
cp_tr2 = ControlPlane(tr2_root)
cp_tr2.create_cycle("C-0001", cycle_fixture("C-0001", "alpha beta probe", root=tr2_root))
write_objective(tr2_root, "C-0001")
cp_tr2.transition_cycle("C-0001", "READY", reason="ready")
cp_tr2.update_cycle("C-0001", {"knowledge_triage": [
    {"pack": "pack-a", "verdict": "SKIP", "reason": "auto-rank overridden: not applicable"},
    {"pack": "pack-b", "verdict": "USE", "reason": "auto-rank overridden: beta it is"},
]})
cp_tr2.transition_cycle("C-0001", "RUNNING", reason="overridden both ways")
check("USE/SKIP overrides of the auto-ranking both pass", cp_tr2.cycle_status("C-0001") == "RUNNING")

# 2c-ter. Post-RUNNING plan edits that touch objective or knowledge_triage re-run the
# coverage guard with the NEW values: a weakening patch is refused, not recorded.
try:
    cp_tr2.update_cycle("C-0001", {"objective": "alpha beta gamma coverage"})
    check("post-RUNNING objective change re-runs the coverage guard", False)
except ValueError as exc:
    check("post-RUNNING objective change re-runs the coverage guard",
          "pack-c" in str(exc) and "confirm or override" in str(exc))
try:
    cp_tr2.update_cycle("C-0001", {"knowledge_triage": [
        {"pack": "pack-a", "verdict": "USE", "reason": "alpha remains the only covered pack"}]})
    check("post-RUNNING triage weakening is refused", False)
except ValueError as exc:
    check("post-RUNNING triage weakening is refused", "pack-b" in str(exc))
ev_cover = cp_tr2.update_cycle("C-0001", {"knowledge_triage": [
    {"pack": "pack-a", "verdict": "USE", "reason": "alpha is the question under test"},
    {"pack": "pack-b", "verdict": "USE", "reason": "beta remains relevant to the probe"},
    {"pack": "pack-c", "verdict": "SKIP", "reason": "gamma is not implicated by this question"},
]})
check("post-RUNNING triage update with full coverage is recorded",
      ev_cover["type"] == "CYCLE_UPDATED")
ev_obj = cp_tr2.update_cycle("C-0001", {"objective": "alpha beta gamma refinement"})
check("post-RUNNING objective update with full coverage is recorded",
      ev_obj["type"] == "CYCLE_UPDATED")

# 2c-quater. Thin placeholder reasons (x / n/a / none) are not triage decisions.
thin_root = triage_root()
cp_thin = ControlPlane(thin_root)
cp_thin.create_cycle("C-0001", {**cycle_fixture("C-0001", "alpha beta probe", root=thin_root),
                                "knowledge_triage": [
                                    {"pack": "pack-a", "verdict": "USE", "reason": "n/a"},
                                    {"pack": "pack-b", "verdict": "SKIP", "reason": "x"}]})
write_objective(thin_root, "C-0001")
cp_thin.transition_cycle("C-0001", "READY", reason="ready")
try:
    cp_thin.transition_cycle("C-0001", "RUNNING", reason="thin reasons")
    check("thin triage reasons are refused", False)
except ValueError as exc:
    check("thin triage reasons are refused",
          "too thin" in str(exc) and "knowledge_triage entry 1" in str(exc))

# 2c-quinquies. Missing or unparseable knowledge INDEX is refused, not vacuously passed:
# without an index there is no auto-ranking to verify coverage against.
def index_guard_root(index_text: str | None) -> ControlPlane:
    r = triage_root()
    path = r / "12_knowledge/INDEX.yaml"
    if index_text is None:
        path.unlink()
    else:
        path.write_text(index_text)
    c = ControlPlane(r)
    c.create_cycle("C-0001", cycle_fixture("C-0001", "alpha beta probe", root=r))
    write_objective(r, "C-0001")
    c.transition_cycle("C-0001", "READY", reason="ready")
    return c


for label, index_text in [("missing", None), ("unparseable", "not a yaml index at all\n"),
                          ("empty pack list", "packs:\n")]:
    cp_idx = index_guard_root(index_text)
    try:
        cp_idx.transition_cycle("C-0001", "RUNNING", reason=f"{label} index")
        check(f"RUNNING refused when the knowledge index is {label}", False)
    except ValueError as exc:
        check(f"RUNNING refused when the knowledge index is {label}",
              "knowledge index missing/unparseable" in str(exc)
              and "cannot verify triage coverage" in str(exc))
# The audit is the backstop: a MODERN workspace with cycles and no readable index errors;
# a legacy ledger keeps only the presence checks.
for label, index_text in [("missing", None), ("unparseable", "not a yaml index at all\n")]:
    idx_root = triage_root()
    idx_path = idx_root / "12_knowledge/INDEX.yaml"
    if index_text is None:
        idx_path.unlink()
    else:
        idx_path.write_text(index_text)
    cp_idx_audit = ControlPlane(idx_root)
    cp_idx_audit.create_cycle("C-0001", cycle_fixture("C-0001", "alpha beta probe", root=idx_root))
    write_objective(idx_root, "C-0001")
    cp_idx_audit.transition_cycle("C-0001", "READY", reason="ready")
    sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(idx_root)],
                         capture_output=True, text=True)
    check(f"audit errors for a modern workspace whose knowledge index is {label}",
          sub.returncode != 0 and "knowledge index missing/unparseable" in sub.stdout)
    downgrade_events_through(idx_root, "C-0001")
    sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(idx_root)],
                         capture_output=True, text=True)
    check(f"audit leaves a legacy workspace's unreadable index as a non-error ({label})",
          sub.returncode == 0 and "knowledge index missing/unparseable" not in sub.stdout)

# 2c-sexies. The audit re-checks coverage for MODERN cycles as an ERROR; legacy ledgers
# stay as written. The write-time guard blocks weakening updates, so the fixture models a
# ledger written by an older tool (the audit is the backstop for exactly that).
cp_tr._append_locked("CYCLE_UPDATED", "cycle", "C-0001", actor="controller",
                     reason="simulated older writer weakening the triage",
                     payload={"knowledge_triage": [{"pack": "pack-a", "verdict": "USE",
                                                    "reason": "alpha covered by the old writer"}]},
                     cycle_id="C-0001")
cp_tr.refresh()
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(tr_root)], capture_output=True, text=True)
check("audit errors when a modern cycle's triage misses an auto-ranked pack",
      sub.returncode != 0 and "pack-b" in sub.stdout and "auto-ranked" in sub.stdout)
downgrade_events_through(tr_root, "C-0001")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(tr_root)], capture_output=True, text=True)
check("audit leaves a legacy cycle's triage coverage as a non-error",
      sub.returncode == 0 and "auto-ranked" in sub.stdout and "ERROR" not in sub.stdout)

# 2c-septies. The context KNOWLEDGE_SELECTION and the RUNNING guard rank through ONE seam:
# the guard's required pack list must equal the set the context renders, including when
# the pack is surfaced by the ledger texts (last-result) rather than the objective, and
# under a KNOWLEDGE_PACK_CAP override.
def selection_root() -> Path:
    r = fresh_root()
    for name in ("pack-a", "pack-b", "pack-c", "pack-d", "pack-e"):
        (r / "12_knowledge" / name).mkdir(parents=True, exist_ok=True)
        (r / "12_knowledge" / name / f"{name}.md").write_text(f"# {name}\n")
    (r / "12_knowledge" / "INDEX.yaml").write_text(
        "packs:\n"
        "  pack-a:\n    load_when: [alpha]\n    files: [pack-a.md]\n"
        "  pack-b:\n    load_when: [beta]\n    files: [pack-b.md]\n"
        "  pack-c:\n    load_when: [gamma]\n    files: [pack-c.md]\n"
        "  pack-d:\n    load_when: [delta]\n    files: [pack-d.md]\n"
        "  pack-e:\n    load_when: [epsilon, zeta]\n    files: [pack-e.md]\n")
    (r / "11_runtime" / "last-result.md").write_text(
        "# Last Result\n- learning: epsilon zeta surfaced by the previous cycle\n")
    return r


def rendered_selection(ctx: str) -> list[str]:
    line = next(l for l in ctx.splitlines() if l.startswith("auto-selected packs"))
    body = line.split("): ", 1)[1].split(" — confirm", 1)[0]
    return [p.strip() for p in body.split(",") if p.strip()]


def guard_ranked(cp: ControlPlane) -> list[str]:
    try:
        cp.transition_cycle("C-0001", "RUNNING", reason="coverage probe")
    except ValueError as exc:
        if "auto-ranked for this objective:" in str(exc):
            body = str(exc).split("auto-ranked for this objective: ", 1)[1]
            return [p.strip() for p in body.rstrip(")").split(",") if p.strip()]
        raise
    raise AssertionError("guard accepted an uncovered triage")


sel_root = selection_root()
cp_sel = ControlPlane(sel_root)
cp_sel.create_cycle("C-0001", {
    **cycle_fixture("C-0001", "alpha beta gamma delta", root=sel_root),
    "knowledge_triage": [{"pack": "pack-a", "verdict": "USE",
                          "reason": "alpha is the question under test"}]})
write_objective(sel_root, "C-0001")
cp_sel.transition_cycle("C-0001", "READY", reason="ready")
ctx_packs = rendered_selection((sel_root / "11_runtime/current-context.md").read_text())
check("context KNOWLEDGE_SELECTION equals the guard's auto-ranked list",
      ctx_packs == guard_ranked(cp_sel) and ctx_packs == ["pack-e", "pack-a", "pack-b", "pack-c"])
with mock.patch.dict(os.environ, {"KNOWLEDGE_PACK_CAP": "6"}):
    cp_sel.refresh()
    ctx_packs6 = rendered_selection((sel_root / "11_runtime/current-context.md").read_text())
    check("KNOWLEDGE_PACK_CAP=6 widens the context selection to every ranked pack",
          len(ctx_packs6) == 5 and "cap 6" in (sel_root / "11_runtime/current-context.md").read_text())
    check("the guard ranks with the same cap override", ctx_packs6 == guard_ranked(cp_sel))

cp.create_hypothesis("H-0001", {
    "cycle_id": "C-0001",
    "observation": "controlled access pattern",
    "hypothesis": "authorization differs by principal",
    "secure_prediction": "foreign object remains denied",
    "vulnerable_prediction": "foreign object is readable",
})

# 3. Evidence is an object with a stable ID + hash; later refs must resolve.
artifact = root / "04_cycles/C-0001/proof.txt"
artifact.write_text("proof-v1: bounded impact reproduced under the recorded control\n")
QUOTE = "bounded impact reproduced under the recorded control"
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

# 4c-bis. Canonical digest: prepare normalizes request_shape to the executor's canonical
# form (method uppercased, header keys lowercased, body -> body_sha256) BEFORE hashing,
# and the token carries the normalized shape. The expected digests are the executor-side
# values (dsh-plugin canonicalDigest over shapeFromArgs) — cross-language parity.
import hashlib as _hashlib  # noqa: E402

mixed_shape = {"method": "get", "url": "https://example.test/h", "principal": "researcher-A",
               "headers": {"X-Custom": "Value-1", "X-Trace-Id": "TRACE-1"}}
tok5 = cp.prepare_action({**base_action, "tool_family": "http", "request_shape": mixed_shape})
mixed_canonical = {"method": "GET", "url": "https://example.test/h", "principal": "researcher-A",
                   "headers": {"x-custom": "Value-1", "x-trace-id": "TRACE-1"}}
check("prepare normalizes a lowercase method and mixed-case header keys",
      tok5["preflight"]["request_shape"] == mixed_canonical)
# Digest parity vector: the executor-side digest over shapeFromArgs for
# {headers: {x-custom: Value-1, authorization: Bearer x}} (dsh-plugin canonicalDigest).
secret_header_shape = {"method": "get", "url": "https://example.test/h", "principal": "researcher-A",
                       "headers": {"X-Custom": "Value-1", "AUTHORIZATION": "Bearer x"}}
tok5b = cp.prepare_action({**base_action, "tool_family": "http", "request_shape": secret_header_shape})
check("prepare digest equals the executor-side digest for method+header normalization",
      tok5b["argument_digest"] == "73582a995dc3e49b19d6f579798cacc7ba1d131f73cb5ac76563cf96a081df3a")

body_text = '{"probe": "x"}'
body_shape = {"method": "POST", "url": "https://example.test/b", "principal": "researcher-A",
              "body": body_text}
tok6 = cp.prepare_action({**base_action, "tool_family": "http", "request_shape": body_shape})
body_canonical = {"method": "POST", "url": "https://example.test/b", "principal": "researcher-A",
                  "body_sha256": _hashlib.sha256(body_text.encode("utf-8")).hexdigest()}
check("prepare folds a body without body_sha256 into body_sha256 and drops body",
      tok6["preflight"]["request_shape"] == body_canonical)
check("prepare digest equals the executor-side digest for a body without body_sha256",
      tok6["argument_digest"] == "9ca3f0956193b433cc35f73b1bd5ff07a07c83abc6ca242797627e34f93c1c0d")
explicit_shape = {**body_canonical}
tok7 = cp.prepare_action({**base_action, "tool_family": "http", "request_shape": explicit_shape})
check("an already-canonical shape digests identically",
      tok7["argument_digest"] == tok6["argument_digest"])

# 4c-quater. Canonical shape strictness: a shape that names the body twice, or a
# non-string body, is rejected instead of silently stringified / double-defined.
for label, bad_shape in [
    ("body and body_sha256 both present",
     {"method": "POST", "url": "https://example.test/b", "principal": "researcher-A",
      "body": "x", "body_sha256": "a" * 64}),
    ("numeric body",
     {"method": "POST", "url": "https://example.test/b", "principal": "researcher-A", "body": 123}),
    ("boolean body",
     {"method": "POST", "url": "https://example.test/b", "principal": "researcher-A", "body": True}),
]:
    try:
        cp.prepare_action({**base_action, "tool_family": "http", "request_shape": bad_shape})
        check(f"canonical shape rejects {label}", False)
    except ValueError as exc:
        check(f"canonical shape rejects {label}", "body" in str(exc))
tok_empty = cp.prepare_action({**base_action, "tool_family": "http", "request_shape":
    {"method": "POST", "url": "https://example.test/e", "principal": "researcher-A", "body": ""}})
check("an empty string body contributes nothing",
      "body_sha256" not in tok_empty["preflight"]["request_shape"])
tok_null = cp.prepare_action({**base_action, "tool_family": "http", "request_shape":
    {"method": "POST", "url": "https://example.test/e", "principal": "researcher-A", "body": None}})
check("a null body contributes nothing",
      "body_sha256" not in tok_null["preflight"]["request_shape"])
browser_shape = {"url": "https://example.test/app", "principal": "researcher-A"}
tok8 = cp.prepare_action({**base_action, "tool_family": "browser", "request_shape": browser_shape})
check("a browser shape keeps the executor's {url,principal} canonical form and digest",
      tok8["preflight"]["request_shape"] == browser_shape
      and tok8["argument_digest"] == "19ceac0be794e368aad5a6d317acae62af51c936797b51d9244f853b25298ecb")

# 4c-ter. Secret hygiene: sensitive query/fragment values and sensitive header values
# never persist — not in the token store, not in the ACTION_RECORDED payload, not in
# the returned prepare object researchctl prints. Redaction runs BEFORE the payload is
# stored; the digest still hashes the same canonical shape (redaction cannot mask it).
secret_url = ("https://example.test/cb?access_token=TOPSECRET&client_secret=ANOTHERSECRET"
              "&page=2#code=FRAGSECRET")
secret_shape = {"method": "GET", "url": secret_url, "principal": "researcher-A",
                "headers": {"Authorization": "Bearer PREPAREHEADERSECRET"}}
tok_secret = cp.prepare_action({**base_action, "tool_family": "http", "target": secret_url,
                                "request_shape": secret_shape})
store_text = (root / "11_runtime/action-tokens.jsonl").read_text()
check("token store masks query and fragment secrets",
      "TOPSECRET" not in store_text and "ANOTHERSECRET" not in store_text
      and "FRAGSECRET" not in store_text
      and "access_token=[REDACTED]" in store_text and "code=[REDACTED]" in store_text)
check("token store masks sensitive header values",
      "PREPAREHEADERSECRET" not in store_text and '"authorization":"[REDACTED]"' in store_text)
check("a benign query parameter and the path survive in the token store",
      "page=2" in store_text and "https://example.test/cb" in store_text)
check("prepare output (the returned token) is masked too",
      "TOPSECRET" not in json.dumps(tok_secret) and "PREPAREHEADERSECRET" not in json.dumps(tok_secret))
check("the digest still covers the raw canonical shape",
      tok_secret["argument_digest"] == _hashlib.sha256(
          _control_plane._json_dump(_control_plane.canonical_request_shape(secret_shape)).encode()).hexdigest())

secret_action = {k: v for k, v in base_action.items() if k != "evidence_refs"}
secret_action["target"] = secret_url
secret_action["request_shape"] = {"method": "GET", "url": secret_url, "principal": "researcher-A"}
del secret_action["id"]  # v8.2 W8: action ids are unique — the allocator assigns this receipt
cp.record_action(secret_action)
ledger_text = (root / "11_runtime/events.jsonl").read_text()
check("ACTION_RECORDED payload masks query secrets in url and target",
      "TOPSECRET" not in ledger_text and "FRAGSECRET" not in ledger_text
      and "access_token=[REDACTED]" in ledger_text and "code=[REDACTED]" in ledger_text
      and '"target":"https://example.test/cb?access_token=[REDACTED]' in ledger_text)

# Direct scrubber vectors: sensitive SUBSTRINGS, percent-decoding, separators.
check("redact masks a substring parameter name",
      redact({"u": "https://t.example/x?X-Amz-Signature=abc123"})["u"]
      == "https://t.example/x?X-Amz-Signature=[REDACTED]")
check("redact masks a percent-encoded parameter name",
      redact({"u": "https://t.example/x?t%6Fken=abc"})["u"] == "https://t.example/x?t%6Fken=[REDACTED]")
check("redact handles semicolons and fragments",
      redact("GET https://t.example/x?token=a;page=2#client_secret=b")
      == "GET https://t.example/x?token=[REDACTED];page=2#client_secret=[REDACTED]")
check("redact leaves non-sensitive query values and the path alone",
      redact("https://t.example/secret-looking/path?page=2&sort=name")
      == "https://t.example/secret-looking/path?page=2&sort=name")
check("redact masks a URL embedded in JSON without swallowing the rest of the string",
      redact('{"u":"https://t.example/x?token=abc","ok":true}')
      == '{"u":"https://t.example/x?token=[REDACTED]","ok":true}')
check("redact masks a URL embedded in prose",
      redact("see https://t.example/x?access_token=abc now")
      == "see https://t.example/x?access_token=[REDACTED] now")

# Nested (double-encoded) sensitive assignments inside a component value: a value that
# decodes once to `next=/cb&token=xyz` leaks the token to a downstream consumer that
# decodes `next`, so the WHOLE component value is masked. Malformed escapes never throw.
check("redact masks a nested sensitive assignment in a component value",
      redact("https://t.example/reset/abc?next=/cb%26token%3Dxyz")
      == "https://t.example/reset/abc?next=[REDACTED]")
check("redact leaves a nested non-sensitive assignment readable",
      redact("https://t.example/reset/abc?next=/cb%26page%3D2")
      == "https://t.example/reset/abc?next=/cb%26page%3D2")
check("redact masks a nested sensitive assignment in a fragment value",
      redact("https://t.example/a#frag=a%26client_secret%3Dx")
      == "https://t.example/a#frag=[REDACTED]")
check("redact masks the whole value when a nested assignment is followed by benign pairs",
      redact("https://t.example/a?next=a%26token%3Dx%26b=1")
      == "https://t.example/a?next=[REDACTED]")
check("redact tolerates malformed percent escapes without hiding a nested assignment",
      redact("https://t.example/a?next=%zz%26token%3Dx")
      == "https://t.example/a?next=[REDACTED]")
nested_shape = {"method": "GET", "url": "https://example.test/reset?next=/cb%26token%3Dxyz",
                "principal": "researcher-A"}
nested_digest = _hashlib.sha256(
    _control_plane._json_dump(_control_plane.canonical_request_shape(nested_shape)).encode()).hexdigest()
tok_nested = cp.prepare_action({**base_action, "tool_family": "http",
                                "target": nested_shape["url"], "request_shape": nested_shape})
check("the digest covers the unmasked nested URL while the stored token is masked",
      tok_nested["argument_digest"] == nested_digest
      and "next=[REDACTED]" in json.dumps(tok_nested)
      and "token%3Dxyz" not in json.dumps(tok_nested))

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
(nogate / "00_control/engagement.yaml").write_text('scope:\n  assets:\n    - "https://example.test /x"\n')
sc = scope_check(nogate, "https://example.test/x")
check("scope_check seam: whitespace in a URL authority denies instead of stripping",
      sc["in_scope"] is False)
check("asset_hosts drops a whitespace URL authority (fail closed)",
      asset_hosts(["https://example.test /x"]) == [])
check("asset_hosts drops a trailing-space URL with no path (fail closed)",
      asset_hosts(["https://t.example "]) == [])
check("scope_check denies a trailing-space URL with no path (local seam parity)",
      scope_check(nogate, "https://example.test ")["in_scope"] is False)
check("asset_hosts keeps a clean URL authority",
      asset_hosts(["https://example.test/x"]) == ["example.test"])
cp_dirty = ControlPlane(nogate)
with mock.patch.object(type(cp_dirty), "_scope_dirty_path", return_value=nogate / "11_runtime" / ".scope-sync-dirty"):
    with mock.patch.object(Path, "write_text", side_effect=OSError("injected dirty failure")):
        saved_err = sys.stderr
        class _Buf:
            def __init__(self): self.text = ""
            def write(self, s): self.text += str(s)
            def flush(self): pass
        buf = _Buf()
        sys.stderr = buf
        try:
            cp_dirty._mark_scope_dirty("REV-1", "push failed")
        finally:
            sys.stderr = saved_err
        check("a DIRTY-marker write failure is logged instead of swallowed",
              "DIRTY" in buf.text and "stale" in buf.text)
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

# 4d-quater. URL authority canonicalization (WHATWG parity, fail closed): a backslash
#            terminates the authority for the real fetch stack, so any authority carrying
#            a backslash, whitespace/control characters or an encoded backslash denies.
sc = scope_check(nogate, "http://127.0.0.1:9\\@t.example/")
check("scope_check denies a backslash authority the fetch stack would route elsewhere",
      sc["in_scope"] is False)
sc = scope_check(nogate, "http://t.example%5cevil/")
check("scope_check denies a lowercase-encoded backslash authority",
      sc["in_scope"] is False)
sc = scope_check(nogate, "http://t.example%5Cevil/")
check("scope_check denies an uppercase-encoded backslash authority",
      sc["in_scope"] is False)
sc = scope_check(nogate, "http://t.example\\evil/")
check("scope_check denies a raw backslash in the authority", sc["in_scope"] is False)
sc = scope_check(nogate, "https://user@t.example/a")
check("scope_check still strips userinfo ending at the last @",
      sc["in_scope"] is True and sc["host"] == "t.example")

# 4e. Prepare honors the gate modes end to end: disabled allows, assets enforce.
scope_root = fresh_root(); cp_scope = ControlPlane(scope_root)
cp_scope.create_cycle("C-0001", cycle_fixture("C-0001", root=scope_root))
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

# 4e-bis. External-judgment policy: top-level key, case-insensitive value, default DENIED.
jroot = Path(tempfile.mkdtemp())
(jroot / "00_control").mkdir(parents=True)
check("external judgment defaults to denied when the key is absent",
      external_judgment_allowed(jroot) is False)
check("external judgment defaults to denied when engagement.yaml is missing",
      external_judgment_allowed(Path(tempfile.mkdtemp())) is False)
(jroot / "00_control/engagement.yaml").write_text('external_judgment: "ALLOWED"\n')
check("explicit ALLOWED enables external judgment", external_judgment_allowed(jroot) is True)
(jroot / "00_control/engagement.yaml").write_text('external_judgment: allowed  # researcher opt-in\n')
check("value match is case-insensitive with a trailing comment",
      external_judgment_allowed(jroot) is True)
(jroot / "00_control/engagement.yaml").write_text('external_judgment: "DENIED"\n')
check("explicit DENIED denies external judgment", external_judgment_allowed(jroot) is False)
(jroot / "00_control/engagement.yaml").write_text('program:\n  external_judgment: "ALLOWED"\n')
check("a nested key does not enable external judgment", external_judgment_allowed(jroot) is False)
# The value must sit on the SAME line as the key: a newline after the colon is not a
# scalar, and no other line may be read as the value (fail closed, not fail open).
for label, text in [
    ("value on the next line", 'external_judgment:\n  ALLOWED\n'),
    ("value after a blank line", 'external_judgment:\n\nALLOWED\n'),
    ("commented value, next line ALLOWED", 'external_judgment:  # pending\nALLOWED\n'),
    ("value nested under the key", 'external_judgment:\n  mode: ALLOWED\n'),
    ("quoted value on the next line", 'external_judgment:\n  "ALLOWED"\n'),
]:
    (jroot / "00_control/engagement.yaml").write_text(text)
    check(f"external judgment: {label} stays denied", external_judgment_allowed(jroot) is False)
(jroot / "00_control/engagement.yaml").write_text('external_judgment:    "ALLOWED"\n')
check("horizontal whitespace between key and value is fine", external_judgment_allowed(jroot) is True)
(jroot / "00_control/engagement.yaml").write_text('external_judgment: "ALLOWED"  # researcher opt-in\n')
check("an inline comment after the value stays fine", external_judgment_allowed(jroot) is True)
(jroot / "00_control/engagement.yaml").unlink()
(jroot / "00_control/engagement.yaml").mkdir()
check("unreadable engagement.yaml (a directory) defaults to denied",
      external_judgment_allowed(jroot) is False)

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

# 4i. Budget governor: machine-enforced caps on live-action capacity. The block is
# top-level `budget:` with two integer keys; malformed values fail closed.
from control_plane import BUDGET_MALFORMED, budget_limits  # noqa: E402

budget_root = fresh_root()
check("budget_limits: absent block -> None (no budget configured)", budget_limits(budget_root) is None)
(budget_root / "00_control/engagement.yaml").write_text(
    '# Runtime-only engagement configuration.\n'
    'budget:\n  max_actions_per_cycle: 5\n  max_actions_per_engagement: 40\n')
check("budget_limits: valid block parses both ints",
      budget_limits(budget_root) == {"max_actions_per_cycle": 5, "max_actions_per_engagement": 40})
(budget_root / "00_control/engagement.yaml").write_text("budget:\n  max_actions_per_cycle: 5\n")
check("budget_limits: absent key -> None",
      budget_limits(budget_root) == {"max_actions_per_cycle": 5, "max_actions_per_engagement": None})
(budget_root / "00_control/engagement.yaml").write_text("budget:\n  max_actions_per_cycle: 5  # cap\n")
check("budget_limits: trailing comment is fine",
      budget_limits(budget_root) == {"max_actions_per_cycle": 5, "max_actions_per_engagement": None})
for label, yaml_text in [
    ("non-integer value", "budget:\n  max_actions_per_cycle: twenty\n"),
    ("quoted integer", 'budget:\n  max_actions_per_cycle: "5"\n'),
    ("negative value", "budget:\n  max_actions_per_engagement: -1\n"),
    ("nested value", "budget:\n  max_actions_per_cycle:\n    value: 5\n"),
    ("flow map scalar", "budget: {max_actions_per_cycle: 5, max_actions_per_engagement: 40}\n"),
    ("plain scalar", "budget: 5\n"),
    ("block scalar", "budget: |\n  max_actions_per_cycle: 5\n"),
]:
    (budget_root / "00_control/engagement.yaml").write_text(yaml_text)
    check(f"budget_limits: malformed block ({label})",
          budget_limits(budget_root) == BUDGET_MALFORMED)
(budget_root / "00_control/engagement.yaml").write_text(
    "budget:  # caps\n  max_actions_per_cycle: 5\n")
check("budget_limits: a commented col-0 header still opens the block",
      budget_limits(budget_root) == {"max_actions_per_cycle": 5, "max_actions_per_engagement": None})


def budget_workspace(budget_block: str, recorded: int = 0, cid: str = "C-0001") -> tuple[Path, ControlPlane]:
    """RUNNING cycle fixture with the requested budget block and N recorded actions."""
    r = fresh_root()
    (r / "00_control/engagement.yaml").write_text(
        'scope:\n  assets:\n  - "example.test"\n' + budget_block)
    c = ControlPlane(r)
    c.create_cycle(cid, cycle_fixture(cid, root=r))
    write_objective(r, cid)
    c.transition_cycle(cid, "READY", reason="ready")
    c.transition_cycle(cid, "RUNNING", reason="run")
    c.create_hypothesis("H-0001", {
        "cycle_id": cid,
        "observation": "budget fixture",
        "hypothesis": "budget fixture",
        "secure_prediction": "denied",
        "vulnerable_prediction": "allowed",
    })
    shape = {"method": "GET", "url": "https://example.test/api", "principal": "researcher-A"}
    for i in range(recorded):
        payload = {k: v for k, v in base_action.items() if k != "evidence_refs"}
        payload.update({"id": f"A-R{i:04d}", "cycle_id": cid, "request_shape": shape})
        c.append("ACTION_RECORDED", "action", f"A-R{i:04d}", cycle_id=cid, payload=payload)
    return r, c


bw_root, bw_cp = budget_workspace("budget:\n  max_actions_per_cycle: 2\n  max_actions_per_engagement: 100\n",
                                  recorded=2)
try:
    bw_cp.prepare_action({**base_action, "tool_family": "http", "request_shape": shape,
                          "cycle_id": "C-0001"})
    check("prepare refuses at the cycle cap", False)
except ValueError as exc:
    check("prepare refuses at the cycle cap",
          "cycle budget exhausted (2/2)" in str(exc) and "researchctl budget set" in str(exc))

bo_root, bo_cp = budget_workspace("budget:\n  max_actions_per_cycle: 2\n  max_actions_per_engagement: 100\n")
bo_cp.prepare_action({**base_action, "tool_family": "http", "request_shape": shape, "cycle_id": "C-0001"})
bo_cp.prepare_action({**base_action, "tool_family": "http", "request_shape": shape, "cycle_id": "C-0001"})
try:
    bo_cp.prepare_action({**base_action, "tool_family": "http", "request_shape": shape, "cycle_id": "C-0001"})
    check("outstanding unconsumed tokens count against the cycle cap", False)
except ValueError as exc:
    check("outstanding unconsumed tokens count against the cycle cap",
          "cycle budget exhausted (2/2)" in str(exc))

be_root, be_cp = budget_workspace("budget:\n  max_actions_per_cycle: 10\n  max_actions_per_engagement: 2\n",
                                  recorded=1)
be_cp.prepare_action({**base_action, "tool_family": "http", "request_shape": shape, "cycle_id": "C-0001"})
try:
    be_cp.prepare_action({**base_action, "tool_family": "http", "request_shape": shape, "cycle_id": "C-0001"})
    check("outstanding tokens count against the engagement cap", False)
except ValueError as exc:
    check("outstanding tokens count against the engagement cap",
          "engagement budget exhausted (2/2)" in str(exc))

bm_root, bm_cp = budget_workspace("budget:\n  max_actions_per_cycle: nope\n", recorded=0)
try:
    bm_cp.prepare_action({**base_action, "tool_family": "http", "request_shape": shape, "cycle_id": "C-0001"})
    check("a malformed budget block fails prepare closed", False)
except ValueError as exc:
    check("a malformed budget block fails prepare closed", "malformed" in str(exc))

bn_root, bn_cp = budget_workspace("budget:\n  max_actions_per_cycle: 2\n  max_actions_per_engagement: 100\n",
                                  recorded=1)
tok_bn = bn_cp.prepare_action({**base_action, "tool_family": "http", "request_shape": shape, "cycle_id": "C-0001"})
check("a prepare under the cap still issues a token", tok_bn["action_id"].startswith("A-"))

bs_root, bs_cp = budget_workspace("budget:\n  max_actions_per_cycle: 3\n  max_actions_per_engagement: 30\n",
                                  recorded=1)
bs_cp.prepare_action({**base_action, "tool_family": "http", "request_shape": shape, "cycle_id": "C-0001"})
status = bs_cp.budget_status()
check("budget status reports limits, counts and remaining",
      status["limits"] == {"max_actions_per_cycle": 3, "max_actions_per_engagement": 30}
      and status["counts"]["cycles"] == {"C-0001": 2}
      and status["counts"]["engagement"] == 2
      and status["remaining"]["cycles"] == {"C-0001": 1}
      and status["remaining"]["engagement"] == 28)
sub = subprocess.run([sys.executable, str(TOOLS / "researchctl.py"), str(bs_root), "budget", "status"],
                     capture_output=True, text=True)
cli_status = json.loads(sub.stdout)
check("researchctl budget status prints the same facts",
      sub.returncode == 0 and cli_status["limits"] == status["limits"]
      and cli_status["counts"]["engagement"] == 2)
bstatus = budget_workspace("", recorded=1)[1].budget_status()
check("budget status with no configured block reports null limits/remaining",
      bstatus["limits"] is None and bstatus["remaining"]["engagement"] is None
      and bstatus["counts"]["engagement"] == 1)

# Budget monotonicity: a consumed-but-unrecorded token (the executor receipt-failure
# path) still counts as used — consumption can never restore headroom.
mono_root, mono_cp = budget_workspace(
    "budget:\n  max_actions_per_cycle: 1\n  max_actions_per_engagement: 10\n")
tok_mono = mono_cp.prepare_action({**base_action, "tool_family": "http",
                                   "request_shape": shape, "cycle_id": "C-0001"})
with (mono_root / "11_runtime/action-tokens.jsonl").open("a", encoding="utf-8") as fh:
    fh.write(json.dumps({"action_id": tok_mono["action_id"], "consumed": True,
                         "consumed_at": "2026-01-01T00:00:00Z"}) + "\n")
st_mono = mono_cp.budget_status()
check("a consumed-but-unrecorded token still counts as used",
      st_mono["counts"]["engagement"] == 1 and st_mono["remaining"]["engagement"] == 9)
try:
    mono_cp.prepare_action({**base_action, "tool_family": "http",
                            "request_shape": shape, "cycle_id": "C-0001"})
    check("consumption never restores headroom", False)
except ValueError as exc:
    check("consumption never restores headroom", "cycle budget exhausted (1/1)" in str(exc))

set_budget_root = fresh_root()
(set_budget_root / "00_control/engagement.yaml").write_text(
    'program:\n  name: "x"\n\nscope:\n  assets: []\n  out_of_scope: []\n\n'
    'accounts:\n  researcher_controlled: []\n\nconfidence: "VERIFIED"\n')
cp_budget = ControlPlane(set_budget_root)
budget_before = (set_budget_root / "00_control/engagement.yaml").read_text()
try:
    cp_budget.set_budget({"max_actions_per_cycle": 10, "max_actions_per_engagement": 100})
    check("budget set rejects an empty source_reference", False)
except ValueError as exc:
    check("budget set rejects an empty source_reference", "source_reference" in str(exc))
for label, payload in [
    ("non-integer cap", {"max_actions_per_cycle": "10", "max_actions_per_engagement": 100}),
    ("negative cap", {"max_actions_per_cycle": -1, "max_actions_per_engagement": 100}),
    ("boolean cap", {"max_actions_per_cycle": True, "max_actions_per_engagement": 100}),
    ("missing key", {"max_actions_per_cycle": 10}),
]:
    try:
        cp_budget.set_budget({**payload, "source_reference": "policy#budget"})
        check(f"budget set rejects {label}", False)
    except ValueError:
        check(f"budget set rejects {label}", True)
ev = cp_budget.set_budget({"max_actions_per_cycle": 10, "max_actions_per_engagement": 100,
                           "source_reference": "policy#budget"})
check("BUDGET_CHANGED recorded on the engagement entity",
      ev["type"] == "BUDGET_CHANGED" and ev["entity_type"] == "budget" and ev["entity_id"] == "engagement")
check("BUDGET_CHANGED carries previous/new/source/human",
      ev["payload"] == {"previous": None, "new": {"max_actions_per_cycle": 10, "max_actions_per_engagement": 100},
                        "source_reference": "policy#budget", "human_reference": ""})
budget_text = (set_budget_root / "00_control/engagement.yaml").read_text()
check("budget set writes the block and preserves every unrelated byte",
      budget_text.startswith(budget_before)
      and "accounts:\n  researcher_controlled: []\n" in budget_text
      and budget_limits(set_budget_root) == {"max_actions_per_cycle": 10, "max_actions_per_engagement": 100})
try:
    cp_budget.set_budget({"max_actions_per_cycle": 11, "max_actions_per_engagement": 100,
                          "source_reference": "policy#budget"})
    check("budget set requires human_reference once limits are recorded", False)
except ValueError as exc:
    check("budget set requires human_reference once limits are recorded", "human_reference" in str(exc))
ev2 = cp_budget.set_budget({"max_actions_per_cycle": 10, "max_actions_per_engagement": 100,
                            "source_reference": "policy#budget", "human_reference": "ticket-1"})
check("BUDGET_CHANGED carries the human_reference and the previous limits",
      ev2["payload"]["human_reference"] == "ticket-1"
      and ev2["payload"]["previous"] == {"max_actions_per_cycle": 10, "max_actions_per_engagement": 100})
check("budget set is idempotent on re-run",
      (set_budget_root / "00_control/engagement.yaml").read_text() == budget_text)
# A shipped template budget block is deliberate configuration: changing it needs a human.
tpl_root = fresh_root()
(tpl_root / "00_control/engagement.yaml").write_text(
    "budget:\n  max_actions_per_cycle: 20\n  max_actions_per_engagement: 200\n")
try:
    ControlPlane(tpl_root).set_budget({"max_actions_per_cycle": 5, "max_actions_per_engagement": 50,
                                       "source_reference": "policy#budget"})
    check("budget set requires human_reference when a budget block already exists", False)
except ValueError as exc:
    check("budget set requires human_reference when a budget block already exists",
          "human_reference" in str(exc))
ControlPlane(tpl_root).set_budget({"max_actions_per_cycle": 5, "max_actions_per_engagement": 50,
                                   "source_reference": "policy#budget", "human_reference": "ticket-2"})
check("budget set rewrites the shipped block in place",
      budget_limits(tpl_root) == {"max_actions_per_cycle": 5, "max_actions_per_engagement": 50}
      and (tpl_root / "00_control/engagement.yaml").read_text().count("budget:") == 1)
sub = subprocess.run([sys.executable, str(TOOLS / "researchctl.py"), str(tpl_root), "budget", "set",
                      str(Path(tempfile.mkdtemp()) / "payload.json")], capture_output=True, text=True)
check("researchctl budget set surfaces a readable error", sub.returncode == 1 and "error:" in sub.stderr)

# Audit: over-cap recorded actions are an error; a missing block warns.
over_root = budget_workspace("budget:\n  max_actions_per_cycle: 1\n  max_actions_per_engagement: 100\n",
                             recorded=2)[0]
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(over_root)], capture_output=True, text=True)
check("audit errors when a cycle's recorded actions exceed the configured cap",
      sub.returncode != 0 and "budget" in sub.stdout and "C-0001" in sub.stdout)
under_root = budget_workspace("budget:\n  max_actions_per_cycle: 5\n  max_actions_per_engagement: 100\n",
                              recorded=2)[0]
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(under_root)], capture_output=True, text=True)
check("audit is silent about a cycle inside its budget cap",
      "budget" not in sub.stdout and "no `budget:` block" not in sub.stdout)
nob_root = budget_workspace("", recorded=1)[0]
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(nob_root)], capture_output=True, text=True)
check("audit warns when recorded actions exist with no budget block",
      sub.returncode == 0 and "no `budget:` block" in sub.stdout)

# 4j. Lowering a cap below the current recorded count is allowed but flagged: the event
# carries below_current_count, the CLI warns, and the audit errors until a raise.
below_root, below_cp = budget_workspace("", recorded=3)
ev_below = below_cp.set_budget({"max_actions_per_cycle": 2, "max_actions_per_engagement": 100,
                                "source_reference": "policy#budget"})
check("budget set records below_current_count when the cap is under the recorded count",
      ev_below["payload"].get("below_current_count") is True)
ev_above = below_cp.set_budget({"max_actions_per_cycle": 4, "max_actions_per_engagement": 100,
                                "source_reference": "policy#budget", "human_reference": "ticket-3"})
check("budget set omits below_current_count when the cap covers the recorded count",
      "below_current_count" not in ev_above["payload"])
below_payload = Path(tempfile.mkdtemp()) / "budget.json"
below_payload.write_text(json.dumps({"max_actions_per_cycle": 1, "max_actions_per_engagement": 50,
                                     "source_reference": "policy#budget", "human_reference": "ticket-4"}))
sub = subprocess.run([sys.executable, str(TOOLS / "researchctl.py"), str(below_root), "budget", "set",
                      str(below_payload)], capture_output=True, text=True)
check("researchctl budget set warns when the new caps are below the recorded count",
      sub.returncode == 0 and "below the current recorded" in sub.stderr
      and json.loads(sub.stdout)["payload"]["below_current_count"] is True)

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

# 5a. Claim gate: REVIEWED needs independent review packets on both axes.
try:
    cp.transition_cycle("C-0001", "REVIEWED", reason="no reviews", evidence_refs=[eid])
    check("REVIEWED requires review packets", False)
except ValueError as exc:
    check("REVIEWED requires review packets", "review" in str(exc))
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
try:
    cp.merge_worker({"cycle_id": "C-0001", "evidence_refs": [eid],
                     "review": {"axis": "objective", "verdict": "pass", "reviewer": "run-objective",
                                "evidence_quotes": [{"evidence_ref": eid, "quote": QUOTE}]}})
    check("review packet requires run_id", False)
except ValueError as exc:
    check("review packet requires run_id", "run_id" in str(exc))
def _quote_packet(axis: str, **review_extra: object) -> dict:
    review = {"axis": axis, "verdict": "pass", "reviewer": f"run-{axis}",
              "run_id": f"session-{axis}-1",
              "evidence_quotes": [{"evidence_ref": eid, "quote": QUOTE}]}
    review.update(review_extra)
    return {"cycle_id": "C-0001", "evidence_refs": [eid], "next_step": f"{axis} review", "review": review}
try:
    cp.merge_worker({**_quote_packet("objective"), "review": {"axis": "objective", "verdict": "pass",
                     "reviewer": "run-objective", "run_id": "session-objective-1", "evidence_quotes": []}})
    check("review packet requires evidence quotes", False)
except ValueError as exc:
    check("review packet requires evidence quotes", "evidence_quotes" in str(exc))
try:
    cp.merge_worker({**_quote_packet("objective"),
                     "review": {"axis": "objective", "verdict": "pass", "reviewer": "run-objective",
                                "run_id": "session-objective-1",
                                "evidence_quotes": [{"evidence_ref": eid, "quote": "no such line anywhere"}]}})
    check("review quote must be a registered-capture substring", False)
except ValueError as exc:
    check("review quote must be a registered-capture substring", "not found" in str(exc))
cp.merge_worker(_quote_packet("objective"))
try:
    cp.transition_cycle("C-0001", "REVIEWED", reason="one axis only", evidence_refs=[eid])
    check("REVIEWED requires both axes", False)
except ValueError:
    check("REVIEWED requires both axes", True)
cp.merge_worker({**_quote_packet("method"), "review": {"axis": "method", "verdict": "fail",
                 "reviewer": "run-method", "run_id": "session-method-1",
                 "evidence_quotes": [{"evidence_ref": eid, "quote": QUOTE}]}})
try:
    cp.transition_cycle("C-0001", "REVIEWED", reason="failing review", evidence_refs=[eid])
    check("failing review blocks REVIEWED", False)
except ValueError:
    check("failing review blocks REVIEWED", True)
cp.merge_worker(_quote_packet("method"))
cp.transition_cycle("C-0001", "REVIEWED", reason="both reviews pass", evidence_refs=[eid])
check("reviewed after both reviews pass", cp.cycle_status("C-0001") == "REVIEWED")

# 5a-bis. Two axes from one reviewer identity cannot satisfy the claim gate.
cp.create_cycle("C-0004", cycle_fixture("C-0004", "same-reviewer", root=root))
write_objective(root, "C-0004")
cp.transition_cycle("C-0004", "READY", reason="ready")
cp.transition_cycle("C-0004", "RUNNING", reason="run")
(root / "same-reviewer-proof.txt").write_text("same reviewer proof: bounded impact reproduced\n")
eid4 = cp.register_evidence("same-reviewer-proof.txt", kind="raw", source="researcher-owned",
                            cycle_id="C-0004")["payload"]["id"]
write_results(root, "C-0004", eid4)
cp.transition_cycle("C-0004", "RESULT_READY", reason="result", evidence_refs=[eid4])
cp.update_cycle("C-0004", {"result_summary": "bounded impact reproduced"})
def _same_reviewer_packet(axis: str, run_id: str) -> dict:
    return {"cycle_id": "C-0004", "evidence_refs": [eid4],
            "review": {"axis": axis, "verdict": "pass", "reviewer": "same-run", "run_id": run_id,
                       "evidence_quotes": [{"evidence_ref": eid4,
                                            "quote": "bounded impact reproduced"}]}}
for axis in ("objective", "method"):
    cp.merge_worker(_same_reviewer_packet(axis, f"session-{axis}-1"))
try:
    cp.transition_cycle("C-0004", "REVIEWED", reason="same reviewer", evidence_refs=[eid4])
    check("same reviewer cannot satisfy both axes", False)
except ValueError as exc:
    check("same reviewer cannot satisfy both axes", "distinct reviewers" in str(exc))

# 5a-ter. Two axes from one reviewing run (same run_id) cannot satisfy the claim gate either.
def _same_run_packet(axis: str, run_id: str) -> dict:
    return {"cycle_id": "C-0004", "evidence_refs": [eid4],
            "review": {"axis": axis, "verdict": "pass", "reviewer": f"run-{axis}", "run_id": run_id,
                       "evidence_quotes": [{"evidence_ref": eid4,
                                            "quote": "bounded impact reproduced"}]}}
cp.merge_worker(_same_run_packet("objective", "session-shared"))
cp.merge_worker(_same_run_packet("method", "session-shared"))
try:
    cp.transition_cycle("C-0004", "REVIEWED", reason="same run", evidence_refs=[eid4])
    check("same run_id cannot satisfy both axes", False)
except ValueError as exc:
    check("same run_id cannot satisfy both axes", "run_id" in str(exc) and "distinct" in str(exc))
# A packet merged without a run_id (e.g. a legacy hand-merged ledger) cannot prove REVIEWED.
cp.append("WORKER_RESULT", "worker_result", "WR-LEGACY", cycle_id="C-0004", evidence_refs=[eid4],
          payload={"review": {"axis": "objective", "verdict": "pass", "reviewer": "legacy-run"}})
try:
    cp.transition_cycle("C-0004", "REVIEWED", reason="legacy packet without run_id", evidence_refs=[eid4])
    check("missing run_id blocks REVIEWED", False)
except ValueError as exc:
    check("missing run_id blocks REVIEWED", "run_id" in str(exc))

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
cp2.create_cycle("C-0002", cycle_fixture("C-0002", "gate", root=root2))
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
cp_denied.create_cycle("C-0003", cycle_fixture("C-0003", "deny", root=root_denied))
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
cp4.create_cycle("C-0010", cycle_fixture("C-0010", "close", root=root4))
write_objective(root4, "C-0010")
cp4.transition_cycle("C-0010", "READY", reason="ready")
cp4.transition_cycle("C-0010", "RUNNING", reason="run")
cp4.request_gate("G-0001", {"cycle_id": "C-0010",
                            "what_is_needed": "Closure review: confirm the false-positive disposition and the audit set before closure",
                            "why_human_only": "Only the researcher can attest that closure was reviewed",
                            "resume_after": "Gate resolution"})
cp4.resolve_gate("G-0001", decision="APPROVED", reference="ticket-closure-8")
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
    cp4.record_audit("method-self-attack", "PASS", "no matrix provided for the self-attack audit",
                     evidence_refs=[e4])
    check("method-self-attack requires the six-row matrix", False)
except ValueError as exc:
    check("method-self-attack requires the six-row matrix", "matrix" in str(exc))
blank = {r: "none — fixture has no closed branches" for r in METHOD_SELF_ATTACK_ROWS}
blank["weak-negative"] = "   "
try:
    cp4.record_audit("method-self-attack", "PASS", "matrix with a blank row", evidence_refs=[e4], matrix=blank)
    check("method-self-attack matrix rows must all be filled", False)
except ValueError as exc:
    check("method-self-attack matrix rows must all be filled", "weak-negative" in str(exc))
record_all_audits(cp4, e4)
fill_proof(root4)
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

# 10. Version-stamped events: the envelope records the workspace OS_VERSION; legacy ledgers stay clean.
ver_root = fresh_root()
(ver_root / "OS_VERSION").write_text("7.3\n")
ev = ControlPlane(ver_root).append("NOTE", "note", "N-1", reason="version stamp probe")
check("new events carry the workspace os_version", ev.get("os_version") == "7.3")
check("new events carry a placeholder stamp without an OS_VERSION file",
      ControlPlane(fresh_root()).append("NOTE", "note", "N-2", reason="no version file").get("os_version") == "unknown")
leg_root, leg_cp, leg_eid = recording_workspace("C-0002")
legacyize(leg_root)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(leg_root)], capture_output=True, text=True)
check("audit tolerates a legacy ledger without os_version", sub.returncode == 0)

# 11. Cycle terminal rename: REVIEWED replaces VERIFIED; legacy ledgers replay as REVIEWED.
check("cycle edges carry REVIEWED and no cycle VERIFIED",
      "VERIFIED" not in CYCLE_EDGES and "REVIEWED" in CYCLE_EDGES["RESULT_READY"]
      and CYCLE_EDGES["REVIEWED"] == {"CLOSED"})
ren_root, ren_cp, ren_eid = recording_workspace("C-0001")
try:
    ren_cp.transition_cycle("C-0001", "VERIFIED", reason="old terminal name", evidence_refs=[ren_eid])
    check("cycle VERIFIED transition rejected", False)
except ValueError as exc:
    check("cycle VERIFIED transition rejected with a REVIEWED hint",
          "REVIEWED" in str(exc) and "hypothesis" in str(exc))
write_results(ren_root, "C-0001")
try:
    ren_cp.transition_cycle("C-0001", "RUNNING", reason="back to running without evidence")
    check("RESULT_READY back-edge requires evidence", False)
except ValueError as exc:
    check("RESULT_READY back-edge requires evidence", "evidence" in str(exc))
try:
    ren_cp.transition_cycle("C-0001", "BLOCKED", reason="blocked without evidence")
    check("RESULT_READY -> BLOCKED back-edge requires evidence", False)
except ValueError as exc:
    check("RESULT_READY -> BLOCKED back-edge requires evidence", "evidence" in str(exc))
ren_cp.transition_cycle("C-0001", "RUNNING", reason="back to running for a follow-up", evidence_refs=[ren_eid])
check("RESULT_READY back-edge works with evidence", ren_cp.cycle_status("C-0001") == "RUNNING")

# 11b. NOT_APPLICABLE hypothesis requires a recorded absent precondition.
na_root = fresh_root(); na_cp = ControlPlane(na_root)
na_cp.create_hypothesis("H-0001", {
    "observation": "o", "hypothesis": "h", "secure_prediction": "s", "vulnerable_prediction": "v",
    "test_question": "q", "test_plan": "p"})
(na_root / "na-capture.txt").write_text("fingerprint capture: the parser is absent on this build\n")
na_eid = na_cp.register_evidence("na-capture.txt", kind="raw", source="researcher-owned")["payload"]["id"]
na_cp.transition_hypothesis("H-0001", "QUEUED", reason="queued")
na_cp.transition_hypothesis("H-0001", "TESTING", reason="testing")
try:
    na_cp.transition_hypothesis("H-0001", "NOT_APPLICABLE", reason="absent", evidence_refs=[na_eid])
    check("NOT_APPLICABLE requires a recorded absent precondition", False)
except ValueError as exc:
    check("NOT_APPLICABLE requires a recorded absent precondition",
          "precondition_absence" in str(exc) and "BLOCKED" in str(exc))
na_cp.update_hypothesis("H-0001", {"precondition_absence": "no XML parser on the target build"})
na_cp.transition_hypothesis("H-0001", "NOT_APPLICABLE", reason="absent", evidence_refs=[na_eid])
check("NOT_APPLICABLE recorded once the absent precondition is on the hypothesis",
      na_cp.hypothesis_status("H-0001") == "NOT_APPLICABLE")

# 12. Review binding: the audit re-verifies reviews against the registered store copy.
leg_cp.append("CYCLE_TRANSITIONED", "cycle", "C-0002",
              payload={"from": "RESULT_READY", "to": "VERIFIED"}, evidence_refs=[leg_eid], cycle_id="C-0002")
leg_cp.append("WORKER_RESULT", "worker_result", "WR-L1", cycle_id="C-0002", evidence_refs=[leg_eid],
              payload={"review": {"axis": "objective", "verdict": "pass", "reviewer": "run-1"}})
leg_cp.append("WORKER_RESULT", "worker_result", "WR-L2", cycle_id="C-0002", evidence_refs=[leg_eid],
              payload={"review": {"axis": "method", "verdict": "pass", "reviewer": "run-2"}})
leg_cp.refresh()
check("legacy cycle VERIFIED replays as REVIEWED", leg_cp.cycle_status("C-0002") == "REVIEWED")
check("cycle projection normalizes the legacy status to REVIEWED",
      '"REVIEWED"' in (leg_root / "04_cycles/C-0002/plan.yaml").read_text())
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(leg_root)], capture_output=True, text=True)
check("versioned review packets without run_id/quotes fail the audit",
      sub.returncode != 0 and "run_id" in sub.stdout and "evidence_quotes" in sub.stdout)
legacyize(leg_root)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(leg_root)], capture_output=True, text=True)
check("legacy review packets warn instead of failing the audit",
      sub.returncode == 0 and "WARN" in sub.stdout and "run_id" in sub.stdout)
check("legacy normalization leaves no projection drift", "projection drift" not in sub.stdout)
live_root, live_cp, live_eid = recording_workspace("C-0006")
live_path = live_root / "C-0006-capture.txt"
live_path.write_text(live_path.read_text()
                     + "appended after registration: impact reproduced again\n")
try:
    live_cp.merge_worker({"cycle_id": "C-0006", "evidence_refs": [live_eid],
                          "review": {"axis": "objective", "verdict": "pass", "reviewer": "run-live",
                                     "run_id": "session-live-1",
                                     "evidence_quotes": [{"evidence_ref": live_eid,
                                                          "quote": "appended after registration: impact reproduced again"}]}})
    check("a quote that exists only in the changed living file is rejected", False)
except ValueError as exc:
    check("a quote that exists only in the changed living file is rejected",
          "not found" in str(exc) and "store copy" in str(exc))
leg_cp.evaluate_technique({"cycle_id": "C-0002", "technique_family": "cache-key-differential",
                           "result": "INCONCLUSIVE", "interpretation": "single GET cannot decide the key",
                           "learning": "variant pair needed", "evidence_refs": [leg_eid]})
leg_cp.transition_cycle("C-0002", "CLOSED", reason="close after legacy replay", evidence_refs=[leg_eid])
check("legacy-reviewed cycle closes via REVIEWED", leg_cp.cycle_status("C-0002") == "CLOSED")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(leg_root)], capture_output=True, text=True)
check("legacy ledger still audits after closing", sub.returncode == 0)

# 13. Audit content: evidence refs, sentence summaries, named entities (versioned ERROR / legacy WARNING).
s3_bad_root, s3_bad, s3_bad_eid = recording_workspace("C-0003")
s3_bad.append("AUDIT_RECORDED", "audit", "scope", evidence_refs=[],
              payload={"class": "scope", "status": "PASS", "summary": "thin"})
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(s3_bad_root)], capture_output=True, text=True)
check("audit rejects an audit event without evidence refs",
      sub.returncode != 0 and "no evidence_refs" in sub.stdout)
check("audit rejects a summary shorter than 20 chars / 3 words",
      sub.returncode != 0 and "summary too thin" in sub.stdout)
s3_ent_root, s3_ent, s3_ent_eid = recording_workspace("C-0004")
(s3_ent_root / "00_control/engagement.yaml").write_text('scope:\n  assets:\n  - "example.test"\n')
for cls, summary in [("scope", "the scope was reviewed in this rehearsal"),
                     ("coverage", "coverage was reviewed in this rehearsal"),
                     ("open-hypothesis", "the hypotheses were reviewed in this rehearsal")]:
    s3_ent.append("AUDIT_RECORDED", "audit", cls, evidence_refs=[s3_ent_eid],
                  payload={"class": cls, "status": "PASS", "summary": summary})
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(s3_ent_root)], capture_output=True, text=True)
check("scope summary must name a current asset",
      sub.returncode != 0 and "scope summary names no current asset" in sub.stdout)
check("coverage summary must name a cycle",
      sub.returncode != 0 and "coverage summary names no cycle" in sub.stdout)
check("open-hypothesis summary must name a hypothesis or none",
      sub.returncode != 0 and "open-hypothesis summary names no hypothesis" in sub.stdout)
legacyize(s3_ent_root)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(s3_ent_root)], capture_output=True, text=True)
check("named-entity lite rules warn (not fail) on legacy audit events",
      sub.returncode == 0 and "WARN" in sub.stdout)
s3_ok_root, s3_ok, s3_ok_eid = recording_workspace("C-0005")
(s3_ok_root / "00_control/engagement.yaml").write_text('scope:\n  assets:\n  - "example.test"\n')
for cls, summary in [("scope", "the scope covered example.test during this rehearsal"),
                     ("coverage", "coverage includes C-0005 with a terminal state"),
                     ("open-hypothesis", "no open high-value hypotheses remain (H-0001 closed)")]:
    s3_ok.append("AUDIT_RECORDED", "audit", cls, evidence_refs=[s3_ok_eid],
                 payload={"class": cls, "status": "PASS", "summary": summary})
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(s3_ok_root)], capture_output=True, text=True)
check("named-entity lite rules pass on conforming summaries", sub.returncode == 0)
try:
    s3_ok.record_audit("scope", "PASS", "too thin", evidence_refs=[s3_ok_eid])
    check("record_audit mirrors the summary rule at write time", False)
except ValueError as exc:
    check("record_audit mirrors the summary rule at write time", "summary" in str(exc))

# 14. Closure proof: machine-checked sections, TODO(human) markers, emit/refresh flow.
pr_root, pr_cp, pr_eid = close_workspace(with_closure_gate=True)
record_all_audits(pr_cp, pr_eid)
proof_path = pr_root / "06_audits/CLOSURE-PROOF.md"
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(pr_root), "--closure"], capture_output=True, text=True)
check("closure fails before the proof exists",
      sub.returncode != 0 and "CLOSURE-PROOF.md" in sub.stdout)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(pr_root), "--emit-proof"], capture_output=True, text=True)
check("emit-proof exits cleanly", sub.returncode == 0 and proof_path.is_file())
text = proof_path.read_text()
check("emit-proof writes every required section",
      all(f"## {name}" in text for name in _audit.CLOSURE_PROOF_SECTIONS))
check("emit-proof leaves TODO(human) markers in the judgment sections", "TODO(human):" in text)
check("emit-proof fills mechanical cycle and technique facts",
      "C-0010" in text and "T-000001" in text)
check("emit-proof fills the evidence inventory", f"{pr_eid}" in text and "kind=audit" in text)
before = proof_path.read_text()
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(pr_root), "--emit-proof"], capture_output=True, text=True)
check("emit-proof refreshes a TODO-bearing proof deterministically",
      sub.returncode == 0 and proof_path.read_text() == before)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(pr_root), "--closure"], capture_output=True, text=True)
check("unanswered TODOs fail closure", sub.returncode != 0 and "TODO(human)" in sub.stdout)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(pr_root), "--emit-proof"], capture_output=True, text=True)
check("emit-proof refreshes (does not refuse) while TODOs remain",
      sub.returncode == 0 and "TODO(human):" in proof_path.read_text())
fill_proof(pr_root)
check("filled proof has no TODO markers left", "TODO(human)" not in proof_path.read_text())
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(pr_root), "--closure"], capture_output=True, text=True)
check("a fully filled proof passes closure", sub.returncode == 0 and "closure=READY" in sub.stdout)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(pr_root), "--emit-proof"], capture_output=True, text=True)
check("emit-proof refuses to overwrite a filled proof",
      sub.returncode != 0 and "force" in sub.stdout)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(pr_root), "--emit-proof", "--force"],
                     capture_output=True, text=True)
check("emit-proof --force rewrites a filled proof",
      sub.returncode == 0 and "TODO(human):" in proof_path.read_text())
fill_proof(pr_root)
text = proof_path.read_text()
start = text.index("## NEGATIVE_EVIDENCE")
end = text.index("\n## ", start + 1)
proof_path.write_text(text[:start] + "## NEGATIVE_EVIDENCE\n\n" + text[end + 1:])
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(pr_root), "--closure"], capture_output=True, text=True)
check("an empty required section fails closure",
      sub.returncode != 0 and "NEGATIVE_EVIDENCE" in sub.stdout)
fill_proof(pr_root)
proof_path.write_text(proof_path.read_text().replace("## BLOCKERS\n", "## BLOCKERS\nTODO(human): still unresolved\n", 1))
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(pr_root), "--closure"], capture_output=True, text=True)
check("a TODO(human) body fails closure",
      sub.returncode != 0 and "TODO(human)" in sub.stdout and "BLOCKERS" in sub.stdout)
fill_proof(pr_root)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(pr_root), "--closure"], capture_output=True, text=True)
check("closure recovers once the proof is filled again", sub.returncode == 0)

# 14b. --emit-proof prints the recorded audit event id and marks non-current facts stale.
proof_root, proof_cp, proof_eid2 = close_workspace()
record_all_audits(proof_cp, proof_eid2)
proof_file = proof_root / "06_audits/CLOSURE-PROOF.md"
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(proof_root), "--emit-proof"],
                     capture_output=True, text=True)
text = proof_file.read_text()
check("emit-proof prints the recorded audit event id", sub.returncode == 0 and "scope: PASS (EV-" in text)
check("emit-proof prints no stale marker while the audits are current", "stale — re-record" not in text)
proof_cp.append("NOTE", "research", "N-STALE", reason="a later material event invalidates the audit set")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(proof_root), "--emit-proof"],
                     capture_output=True, text=True)
text = proof_file.read_text()
check("emit-proof marks non-current audit facts stale",
      sub.returncode == 0 and "scope: PASS (EV-" in text and "stale — re-record" in text)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(proof_root), "--emit-proof"],
                     capture_output=True, text=True)
check("stale emit-proof output is deterministic", sub.returncode == 0 and proof_file.read_text() == text)

# 15. Action ↔ token provenance: controlled-executor actions carry the preflight nonce.
tok_root, tok_cp, tok_eid = close_workspace(with_action=True, with_closure_gate=True)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(tok_root)], capture_output=True, text=True)
check("versioned action without token_nonce warns",
      sub.returncode == 0 and "WARN" in sub.stdout and "token_nonce" in sub.stdout)
record_all_audits(tok_cp, tok_eid)
fill_proof(tok_root)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(tok_root), "--closure"], capture_output=True, text=True)
check("closure requires token provenance for versioned actions",
      sub.returncode != 0 and "actions_have_token_provenance" in sub.stdout)
legacyize(tok_root)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(tok_root), "--closure"], capture_output=True, text=True)
check("legacy actions without token_nonce are tolerated at closure", sub.returncode == 0)
ok_root, ok_cp, ok_eid = close_workspace(with_action=True, token_nonce="a" * 32, with_closure_gate=True)
record_all_audits(ok_cp, ok_eid)
fill_proof(ok_root)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(ok_root), "--closure"], capture_output=True, text=True)
check("a versioned action carrying the nonce closes cleanly",
      sub.returncode == 0 and "token_nonce" not in sub.stdout)

# 16. Closure readiness projection requires all seven audit classes.
ready_root, ready_cp, ready_eid = close_workspace()
record_all_audits(ready_cp, ready_eid)
ready_proj = (ready_root / "06_audits/closure-readiness.yaml").read_text()
check("closure readiness is READY with all seven classes", 'status: "READY"' in ready_proj)
check("the required audit class set has seven classes", len(REQUIRED_AUDIT_CLASSES) == 7)
six_root, six_cp, six_eid = close_workspace()
for cls, summary in AUDIT_SUMMARIES.items():
    six_cp.record_audit(cls, "PASS", summary, evidence_refs=[six_eid])
six_proj = (six_root / "06_audits/closure-readiness.yaml").read_text()
check("closure readiness is NOT_READY without method-self-attack", 'status: "NOT_READY"' in six_proj)

# 17. Closure-proof bodies must carry real content: case/space-insensitive TODO
# detection, an invisible-stripped minimum, and a word/letter requirement.
pr2_root, pr2_cp, pr2_eid = close_workspace(with_closure_gate=True)
record_all_audits(pr2_cp, pr2_eid)
fill_proof(pr2_root)
for label, body in [
    ("TODO(HUMAN) case variant", "TODO(HUMAN): map every applicable surface cell to a terminal state or a named blocker (cite ids)"),
    ("spaced TODO ( human ) variant", "TODO ( human ) : map every applicable surface cell to a terminal state or a named blocker"),
    ("zero-width only", "\u200b\ufeff\u2060" * 10),
    ("single punctuation mark", "."),
    ("single word", "done"),
    ("single letter", "x"),
    ("repeated skeleton prompts", "TODO(human): map every applicable surface cell\nTODO(human): map every applicable surface cell"),
    ("punctuation and digits only", "1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3"),
]:
    replace_proof_section(pr2_root, "BLOCKERS", body)
    sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(pr2_root), "--closure"],
                         capture_output=True, text=True)
    check(f"closure proof rejects a thin body: {label}",
          sub.returncode != 0 and "BLOCKERS" in sub.stdout)
fill_proof(pr2_root)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(pr2_root), "--closure"],
                     capture_output=True, text=True)
check("closure proof accepts the filled rehearsal bodies", sub.returncode == 0)

# v8.2 W11: closure needs a resolved human gate (filler cannot substitute), and a
# recorded PASS contradicting a fresh check fails closure.
_ng_root, _ng_cp, _ng_eid = close_workspace()
record_all_audits(_ng_cp, _ng_eid)
fill_proof(_ng_root)
_ng_sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(_ng_root), "--closure"],
                         capture_output=True, text=True)
check("v8.2 W11: a gateless filled proof is refused at closure",
      _ng_sub.returncode != 0 and "Closure-Gate" in (_ng_sub.stdout + _ng_sub.stderr))
_cd_root, _cd_cp, _cd_eid = close_workspace(with_closure_gate=True)
_cd_cp.set_scope(["example.test"], "policy://closure-scope")
record_all_audits(_cd_cp, _cd_eid)
fill_proof(_cd_root)
_cd_ok = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(_cd_root), "--closure"],
                        capture_output=True, text=True)
check("v8.2 W11: attested closure with fresh agreement is READY",
      _cd_ok.returncode == 0 and "closure=READY" in _cd_ok.stdout)
(_cd_root / "00_control/engagement.yaml").write_text(
    'scope:\n  assets:\n  - "example.test"\n  - "evil.example"\n')
_cd_bad = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(_cd_root), "--closure"],
                         capture_output=True, text=True)
check("v8.2 W11: a recorded PASS contradicting a fresh check fails closure",
      _cd_bad.returncode != 0
      and "closure contradiction: scope" in (_cd_bad.stdout + _cd_bad.stderr))

# 18. Version stamps are monotone: once an event carries os_version, every later event must.
vs_root = fresh_root(); vs_cp = ControlPlane(vs_root)
vs_cp.append("NOTE", "note", "N-1", reason="the first versioned event in this workspace")
vs_cp.append("NOTE", "note", "N-2", reason="this event will lose its stamp")
downgrade_last_event(vs_root)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(vs_root)], capture_output=True, text=True)
check("audit rejects a versioned-then-unversioned ledger",
      sub.returncode != 0 and "version stamp regression at event 2" in sub.stdout)
leg2_root = fresh_root(); leg2_cp = ControlPlane(leg2_root)
leg2_cp.append("NOTE", "note", "N-1", reason="legacy ledger event one")
leg2_cp.append("NOTE", "note", "N-2", reason="legacy ledger event two")
legacyize(leg2_root)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(leg2_root)], capture_output=True, text=True)
check("a ledger with only unversioned events still audits cleanly",
      sub.returncode == 0 and "version stamp regression" not in sub.stdout)
leg3_root = fresh_root(); leg3_cp = ControlPlane(leg3_root)
leg3_cp.append("NOTE", "note", "N-1", reason="legacy first event")
downgrade_last_event(leg3_root)
leg3_cp.append("NOTE", "note", "N-2", reason="a later event re-establishes the stamp")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(leg3_root)], capture_output=True, text=True)
check("an unversioned event before the first versioned event is tolerated",
      sub.returncode == 0 and "version stamp regression" not in sub.stdout)

# 19. Quote binding: a review quote may only cite evidence the packet itself lists.
qb_root, qb_cp, qb_eid = recording_workspace("C-0007")
(qb_root / "C-0007-extra.txt").write_text("second capture: the control stayed clean under repetition\n")
qb_eid2 = qb_cp.register_evidence("C-0007-extra.txt", kind="raw", source="researcher-owned",
                                  cycle_id="C-0007")["payload"]["id"]

def _qbound_packet(axis: str, reviewer: str, quote_ref: str, quote: str) -> dict:
    return {"cycle_id": "C-0007", "evidence_refs": [qb_eid],
            "review": {"axis": axis, "verdict": "pass", "reviewer": reviewer,
                       "run_id": f"session-{reviewer}",
                       "evidence_quotes": [{"evidence_ref": quote_ref, "quote": quote}]}}

qb_cp.merge_worker(_qbound_packet("objective", "run-a", qb_eid, QUOTE))
qb_cp.merge_worker(_qbound_packet("method", "run-b", qb_eid, QUOTE))
qb_cp.transition_cycle("C-0007", "REVIEWED", reason="both axes quote the packet evidence", evidence_refs=[qb_eid])
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(qb_root)], capture_output=True, text=True)
check("quoted evidence inside the packet refs audits cleanly", sub.returncode == 0)
try:
    qb_cp.merge_worker(_qbound_packet("objective", "run-c", qb_eid2, "the control stayed clean under repetition"))
    check("merge_worker rejects a quote outside the packet evidence_refs", False)
except ValueError as exc:
    check("merge_worker rejects a quote outside the packet evidence_refs",
          "evidence_refs" in str(exc) and qb_eid2 in str(exc))
qb_cp.append("WORKER_RESULT", "worker_result", "WR-BOUND", cycle_id="C-0007", evidence_refs=[qb_eid],
             payload={"review": {"axis": "objective", "verdict": "pass", "reviewer": "run-d",
                                 "run_id": "session-run-d",
                                 "evidence_quotes": [{"evidence_ref": qb_eid2,
                                                      "quote": "the control stayed clean under repetition"}]}})
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(qb_root)], capture_output=True, text=True)
check("audit rejects a quote citing evidence outside the packet refs",
      sub.returncode != 0 and "evidence_refs" in sub.stdout)

# 20. NOT_APPLICABLE precondition_absence must pass the audit-summary sentence rule.
na2_root = fresh_root(); na2_cp = ControlPlane(na2_root)
(na2_root / "na2-capture.txt").write_text("precondition capture: the probe shows the parser is gone\n")
na2_eid = na2_cp.register_evidence("na2-capture.txt", kind="raw", source="researcher-owned")["payload"]["id"]
na2_cp.create_hypothesis("H-0001", {
    "observation": "o", "hypothesis": "h", "secure_prediction": "s", "vulnerable_prediction": "v",
    "test_question": "q", "test_plan": "p"})
na2_cp.transition_hypothesis("H-0001", "QUEUED", reason="queued")
na2_cp.transition_hypothesis("H-0001", "TESTING", reason="testing")
for placeholder in ("n/a", "none", "x", "TODO", "<...>", "not applicable"):
    na2_cp.update_hypothesis("H-0001", {"precondition_absence": placeholder})
    try:
        na2_cp.transition_hypothesis("H-0001", "NOT_APPLICABLE", reason="placeholder", evidence_refs=[na2_eid])
        check(f"NOT_APPLICABLE rejects placeholder precondition_absence {placeholder!r}", False)
    except ValueError as exc:
        check(f"NOT_APPLICABLE rejects placeholder precondition_absence {placeholder!r}",
              "precondition_absence" in str(exc) and "BLOCKED" in str(exc))
na2_cp.update_hypothesis("H-0001", {"precondition_absence": "the XML parser is absent on the target build"})
na2_cp.transition_hypothesis("H-0001", "NOT_APPLICABLE", reason="absent", evidence_refs=[na2_eid])
check("NOT_APPLICABLE accepts a real precondition sentence",
      na2_cp.hypothesis_status("H-0001") == "NOT_APPLICABLE")

# 21. --emit-proof on a path that is not a regular file fails actionably, not with a traceback.
fk_root = fresh_root()
(fk_root / "06_audits/CLOSURE-PROOF.md").mkdir(parents=True)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(fk_root), "--emit-proof"],
                     capture_output=True, text=True)
check("emit-proof on a non-regular path fails without a traceback",
      sub.returncode == 1 and "Traceback" not in sub.stderr
      and "CLOSURE-PROOF.md" in sub.stdout and "regular file" in sub.stdout)

# 22. Per-axis review grading: each axis's missing run_id is graded with its OWN
# versioned flag — a legacy packet warns even when the sibling axis is versioned.
def reviewed_missing_run_id(cid: str, order: tuple[str, ...] = ("objective", "method"),
                            with_run_id: tuple[str, ...] = ()) -> tuple[Path, ControlPlane, str]:
    root, cp, eid = recording_workspace(cid)
    for axis in order:
        review: dict = {"axis": axis, "verdict": "pass", "reviewer": f"run-{axis}",
                        "evidence_quotes": [{"evidence_ref": eid, "quote": QUOTE}]}
        if axis in with_run_id:
            review["run_id"] = f"session-{axis}"
        cp.append("WORKER_RESULT", "worker_result", f"WR-{axis}", cycle_id=cid, evidence_refs=[eid],
                  payload={"review": review})
    cp.append("CYCLE_TRANSITIONED", "cycle", cid, payload={"from": "RESULT_READY", "to": "REVIEWED"},
              evidence_refs=[eid], cycle_id=cid)
    return root, cp, eid

qa_root, qa_cp, qa_eid = reviewed_missing_run_id("C-0008", with_run_id=("method",))
downgrade_events_through(qa_root, "WR-objective")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(qa_root)], capture_output=True, text=True)
check("a legacy axis without run_id only warns when the sibling axis is versioned",
      sub.returncode == 0 and "objective review lacks run_id" in sub.stdout
      and "ERROR" not in sub.stdout)
qb2_root, qb2_cp, qb2_eid = reviewed_missing_run_id("C-0009", order=("method", "objective"),
                                                   with_run_id=("method",))
downgrade_events_through(qb2_root, "WR-method")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(qb2_root)], capture_output=True, text=True)
check("a versioned axis without run_id errors when the sibling axis is legacy",
      sub.returncode != 0 and "objective review lacks run_id" in sub.stdout
      and "method review lacks run_id" not in sub.stdout)
qc_root, qc_cp, qc_eid = reviewed_missing_run_id("C-0011")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(qc_root)], capture_output=True, text=True)
check("both versioned axes missing run_id produce per-axis errors",
      sub.returncode != 0 and "objective review lacks run_id" in sub.stdout
      and "method review lacks run_id" in sub.stdout)

# 23. Closure-proof parser: fences are opaque, unknown subheadings stay body text,
# duplicate required headings fail.
pp_root, pp_cp, pp_eid = close_workspace(with_closure_gate=True)
record_all_audits(pp_cp, pp_eid)
fill_proof(pp_root)
pp_proof = pp_root / "06_audits/CLOSURE-PROOF.md"
filled_text = pp_proof.read_text()
pp_proof.write_text("```\n# Closure Proof\n## SCOPE_PROOF\n- a fenced heading with a fenced body long enough to look real\n```\n")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(pp_root), "--closure"],
                     capture_output=True, text=True)
check("a fence-only proof collects no sections", sub.returncode != 0 and "SCOPE_PROOF" in sub.stdout)
pp_proof.write_text(filled_text)
pp_proof.write_text(filled_text.replace(
    "## BLOCKERS\n",
    "## BLOCKERS\nA real blocker note that is long enough to count as a judgment.\n```\nTODO(human)\n```\n", 1))
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(pp_root), "--closure"],
                     capture_output=True, text=True)
check("a fenced TODO(human) does not block closure", sub.returncode == 0)
pp_proof.write_text(filled_text + "\n```\n## BLOCKERS\nfenced duplicate heading must stay opaque\n```\n")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(pp_root), "--closure"],
                     capture_output=True, text=True)
check("a fenced duplicate heading is ignored", sub.returncode == 0)
pp_proof.write_text(filled_text.replace(
    "## NOVELTY_CHECK\n",
    "## NOVELTY_CHECK\nThe novelty judgment covers the program history and this rehearsal.\n"
    "## Supporting notes\nTODO(human): still owe a real note\n", 1))
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(pp_root), "--closure"],
                     capture_output=True, text=True)
check("a real TODO after an unlisted subheading blocks closure",
      sub.returncode != 0 and "NOVELTY_CHECK" in sub.stdout and "TODO(human)" in sub.stdout)
pp_proof.write_text(filled_text + "\n## BLOCKERS\nA second BLOCKERS section with a real sentence is still a duplicate.\n")
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(pp_root), "--closure"],
                     capture_output=True, text=True)
check("a duplicate required heading fails closure",
      sub.returncode != 0 and "duplicate" in sub.stdout and "BLOCKERS" in sub.stdout)
pp_proof.write_text(filled_text)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(pp_root), "--closure"],
                     capture_output=True, text=True)
check("the pristine filled proof still passes after parser surgery", sub.returncode == 0)


# Replay capture-integrity harness: the workspace gate and the no-leak failure output.
def run_replay(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(TOOLS / "test_replay.py"), *args],
                          capture_output=True, text=True)


def replay_workspace(capture_text: str | None = None,
                     markers: bool = True) -> Path:
    r = Path(tempfile.mkdtemp())
    if markers:
        (r / "OS_VERSION").write_text("7.5\n")
        (r / "11_runtime").mkdir(parents=True)
        (r / "11_runtime/events.jsonl").write_text("")
        (r / "08_artifacts/raw").mkdir(parents=True)
    elif capture_text is not None:
        (r / "08_artifacts/raw").mkdir(parents=True)
    if capture_text is not None:
        (r / "08_artifacts/raw/capture.http").write_text(capture_text)
    return r


CAPTURE = (
    "# research_os_request — GET https://example.test/api\n"
    "# action: A-0001 | cycle: C-0001\n\n"
    "--- request\n"
    "GET https://example.test/api HTTP/1.1\n\n"
    "--- response\n"
    "HTTP 200\n"
    "content-type: application/json\n\n"
    '{"ok":true}\n')


def capture_with(request_line: str) -> str:
    return CAPTURE.replace("GET https://example.test/api HTTP/1.1", request_line)


missing = Path(tempfile.mkdtemp()) / "does-not-exist"
sub = run_replay(str(missing))
check("integrity mode refuses a nonexistent path",
      sub.returncode != 0 and "not a research workspace" in sub.stdout
      and "OS_VERSION" in sub.stdout)
plain_dir = Path(tempfile.mkdtemp())
(plain_dir / "notes").mkdir()
sub = run_replay(str(plain_dir))
check("integrity mode refuses a directory without research-workspace markers",
      sub.returncode != 0 and "not a research workspace" in sub.stdout)
sub = run_replay(str(replay_workspace(CAPTURE)))
check("integrity mode accepts a workspace holding a clean capture", sub.returncode == 0)
secret_value = "glpat-ABCDEFGHIJKLMNOPQRSTUV"
sub = run_replay(str(replay_workspace(capture_with(f"GET https://example.test/api?x={secret_value} HTTP/1.1"))))
check("a dirty capture with a secret-shaped value fails",
      sub.returncode != 0 and "secret-shaped value" in sub.stdout)
check("the secret-hit failure output never repeats the raw secret",
      secret_value not in sub.stdout and secret_value not in sub.stderr
      and "glpat-[A-Za-z0-9_.-]{16,}" in sub.stdout and "line 5" in sub.stdout)
raw_token = "s3cr3tvalue"
sub = run_replay(str(replay_workspace(capture_with(
    f"GET https://example.test/api?token={raw_token} HTTP/1.1"))))
check("an unmasked token capture fails the idempotence check",
      sub.returncode != 0 and "not idempotent" in sub.stdout)
check("the idempotence diff prints the masked form, never the raw token",
      raw_token not in sub.stdout and raw_token not in sub.stderr and "[REDACTED]" in sub.stdout)


# 24. Knowledge lifecycle telemetry: per-pack USE/SKIP counters and technique citations
# derive from the existing ledger into 10_learning/knowledge-usage.yaml; the CLI renders
# them; the audit warns when a modern workspace never considered an indexed pack.
def usage_root() -> tuple[Path, ControlPlane]:
    """Workspace indexing two packs: `fixture` gets dispositions, `extra` stays untouched."""
    r = fresh_root()
    for name in ("fixture", "extra"):
        (r / "12_knowledge" / name).mkdir(parents=True, exist_ok=True)
        (r / f"12_knowledge/{name}/{name}.md").write_text(f"# {name} pack\n")
    (r / "12_knowledge/INDEX.yaml").write_text(
        "packs:\n"
        "  fixture:\n"
        "    load_when: [test, question, placeholder, review, closure, fixture]\n"
        "    files: [fixture.md]\n"
        "  extra:\n"
        "    load_when: [telemetry, unused, ranking]\n"
        "    files: [extra.md]\n")
    return r, ControlPlane(r)


def usage_cycle(cid: str, triage: list) -> dict:
    return {"id": cid, "type": "DISCOVERY", "objective": f"usage question {cid}",
            "allowed_scope": ["example.test"], "stop_conditions": ["stop"], "controls": [],
            "status": "PLANNED", "knowledge_triage": triage}


def usage_reason(pack: str) -> str:
    return f"the {pack} pack relevance to this cycle was reviewed for telemetry"


def run_researchctl(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(TOOLS / "researchctl.py"), str(root), *args],
                          capture_output=True, text=True)


ur, ucp = usage_root()
with mock.patch.object(_control_plane, "now", return_value="2026-09-01T00:00:01Z"):
    ucp.create_cycle("C-0001", usage_cycle("C-0001", [
        {"pack": "fixture", "verdict": "USE", "reason": usage_reason("fixture")}]))
with mock.patch.object(_control_plane, "now", return_value="2026-09-01T00:00:02Z"):
    ucp.create_cycle("C-0002", usage_cycle("C-0002", [
        {"pack": "fixture", "verdict": "SKIP", "reason": usage_reason("fixture")}]))
with mock.patch.object(_control_plane, "now", return_value="2026-09-01T00:00:03Z"):
    ucp.create_cycle("C-0003", usage_cycle("C-0003", [
        {"pack": "fixture", "verdict": "USE", "reason": usage_reason("fixture")}]))
(ur / "usage-capture.txt").write_text("usage probe capture: the fixture oracle fired under the control\n")
ueid = ucp.register_evidence("usage-capture.txt", kind="raw", source="researcher-owned")["payload"]["id"]


def usage_technique(**over) -> dict:
    payload = {"cycle_id": "C-0001", "result": "CONFIRMED", "technique_family": "oracle-probe",
               "interpretation": "the fixture oracle fired under the clean control",
               "learning": "the fixture pack oracle note should cite the repetition requirement",
               "evidence_refs": [ueid]}
    payload.update(over)
    return payload


try:
    ucp.evaluate_technique(usage_technique(knowledge_packs=["nope-pack"]))
    check("technique knowledge_packs rejects an unknown pack by name", False)
except ValueError as exc:
    check("technique knowledge_packs rejects an unknown pack by name", "nope-pack" in str(exc))
try:
    ucp.evaluate_technique(usage_technique(knowledge_packs="fixture"))
    check("technique knowledge_packs must be a list of names", False)
except ValueError as exc:
    check("technique knowledge_packs must be a list of names", "knowledge_packs" in str(exc))
with mock.patch.object(_control_plane, "now", return_value="2026-09-01T00:00:04Z"):
    ucp.evaluate_technique(usage_technique(knowledge_packs=["fixture"]))

usage = ucp.knowledge_usage()
check("knowledge usage counts USE and SKIP dispositions per pack",
      usage["packs"]["fixture"]["use"] == 2 and usage["packs"]["fixture"]["skip"] == 1)
check("knowledge usage leaves a never-disposed indexed pack at zero",
      usage["packs"]["extra"] == {"use": 0, "skip": 0, "cited": 0,
                                  "last_used": None, "last_cited": None,
                                  "cycles": [], "cited_cycles": []})
check("knowledge usage keeps last_used from the latest USE disposition",
      usage["packs"]["fixture"]["last_used"] == "2026-09-01T00:00:03Z")
check("knowledge usage counts technique knowledge_packs citations",
      usage["packs"]["fixture"]["cited"] == 1
      and usage["packs"]["fixture"]["last_cited"] == "2026-09-01T00:00:04Z")
check("knowledge usage tracks the cycles that disposed the pack",
      usage["packs"]["fixture"]["cycles"] == ["C-0001", "C-0002", "C-0003"])
check("knowledge usage tracks the cycles that cited the pack",
      usage["packs"]["fixture"]["cited_cycles"] == ["C-0001"])
check("knowledge usage aggregates totals", usage["totals"] == {"use": 2, "skip": 1, "cited": 1})

ucp.create_cycle("C-0004", usage_cycle("C-0004", [
    "junk", {"pack": ""}, {"pack": "fixture", "verdict": "MAYBE", "reason": "not a verdict"}]))
ucp.update_cycle("C-0004", {"knowledge_triage": [
    {"pack": "fixture", "verdict": "SKIP", "reason": usage_reason("fixture")}]})
usage = ucp.knowledge_usage()
check("malformed triage entries are skipped while later updates still count",
      usage["packs"]["fixture"]["use"] == 2 and usage["packs"]["fixture"]["skip"] == 2
      and usage["totals"] == {"use": 2, "skip": 2, "cited": 1})

ucp.create_cycle("C-0005", usage_cycle("C-0005", [
    {"pack": "fixture", "verdict": "USE", "reason": usage_reason("fixture")},
    {"pack": "fixture", "verdict": "SKIP", "reason": usage_reason("fixture")}]))
usage = ucp.knowledge_usage()
check("a pack counts once per cycle and the latest row in its list wins",
      usage["packs"]["fixture"]["skip"] == 3 and usage["packs"]["fixture"]["use"] == 2
      and usage["packs"]["fixture"]["cycles"].count("C-0005") == 1)

ucp.create_cycle("C-0006", usage_cycle("C-0006", [
    {"pack": "fixture", "verdict": "USE", "reason": usage_reason("fixture")}]))
ucp.update_cycle("C-0006", {"knowledge_triage": [
    {"pack": "fixture", "verdict": "SKIP", "reason": usage_reason("fixture")}]})
usage = ucp.knowledge_usage()
check("CYCLE_UPDATED rewrites the cycle disposition (latest event wins)",
      usage["packs"]["fixture"]["skip"] == 4 and usage["packs"]["fixture"]["use"] == 2
      and usage["packs"]["fixture"]["cycles"].count("C-0006") == 1)

ucp.create_cycle("C-0007", usage_cycle("C-0007", [
    {"pack": "extra", "verdict": "USE", "reason": usage_reason("extra")}]))
ucp.update_cycle("C-0007", {"knowledge_triage": [
    {"pack": "fixture", "verdict": "SKIP", "reason": usage_reason("fixture")}]})
usage = ucp.knowledge_usage()
check("a rewritten triage list replaces the earlier cycle disposition entirely",
      usage["packs"]["extra"]["use"] == 0 and "C-0007" not in usage["packs"]["extra"]["cycles"]
      and usage["packs"]["fixture"]["skip"] == 5
      and "C-0007" in usage["packs"]["fixture"]["cycles"])

ucp.create_cycle("C-0008", usage_cycle("C-0008", [
    {"pack": 12345, "verdict": "USE", "reason": usage_reason("fixture")},
    {"pack": "fixture", "verdict": "USE"},
    {"pack": "fixture", "verdict": 7, "reason": usage_reason("fixture")},
    {"pack": "fixture", "verdict": "USE", "reason": "   "}]))
usage = ucp.knowledge_usage()
check("incomplete dispositions are ignored (non-string pack never stringified, missing reason)",
      "12345" not in usage["packs"] and usage["packs"]["fixture"]["use"] == 2
      and "C-0008" not in usage["packs"]["fixture"]["cycles"])

with mock.patch.object(_control_plane, "now", return_value="2026-09-01T00:00:05Z"):
    ucp.evaluate_technique(usage_technique(knowledge_packs=["fixture", "fixture"]))
usage = ucp.knowledge_usage()
check("technique knowledge_packs dedupes per event (set semantics)",
      usage["packs"]["fixture"]["cited"] == 2
      and usage["packs"]["fixture"]["last_cited"] == "2026-09-01T00:00:05Z")

usage_projection = ur / "10_learning/knowledge-usage.yaml"
rendered = usage_projection.read_text()
check("knowledge usage projection is a generated per-pack view",
      rendered.startswith(GENERATED_HEADER) and "packs:" in rendered
      and "last_cited" in rendered and '"fixture":' in rendered)
ucp.refresh()
check("knowledge usage projection rebuild is idempotent",
      usage_projection.read_text() == rendered)

sub = run_researchctl(ur, "knowledge", "usage")
out = json.loads(sub.stdout)
check("researchctl knowledge usage prints JSON counters plus a human summary",
      sub.returncode == 0 and out["packs"]["fixture"]["cited"] == 2
      and "never_considered=1" in sub.stderr)
sub = run_researchctl(ur, "knowledge", "usage", "--unused")
out = json.loads(sub.stdout)
check("researchctl knowledge usage --unused lists never-considered packs only",
      list(out["packs"]) == ["extra"] and "unused packs: extra" in sub.stderr)

sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(ur)], capture_output=True, text=True)
check("audit warns when a modern workspace never considered an indexed pack",
      "not considered in the last 10 cycles" in sub.stdout and "extra" in sub.stdout
      and "ERROR" not in sub.stdout and sub.returncode == 0)
legacyize(ur)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(ur)], capture_output=True, text=True)
check("the never-considered warning stays silent for a legacy workspace",
      "not considered" not in sub.stdout and sub.returncode == 0)

# 24b. The audit warning is windowed to the last 10 cycles: a pack disposed only in the
# first cycles of a long ledger is drifting again, while a recently considered pack is
# not nagged about. `--unused` stays the all-time view.
wr, wcp = usage_root()
for i in range(1, 13):
    triage = ([{"pack": "fixture", "verdict": "USE", "reason": usage_reason("fixture")}] if i <= 2
              else [{"pack": "extra", "verdict": "SKIP", "reason": usage_reason("extra")}])
    wcp.create_cycle(f"C-{i:04d}", usage_cycle(f"C-{i:04d}", triage))
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(wr)], capture_output=True, text=True)
warning = next((line for line in sub.stdout.splitlines()
                if line.startswith("WARN: knowledge packs not considered")), "")
check("the audit never-considered warning names the 10-cycle window and flags stale packs",
      "not considered in the last 10 cycles" in warning and "fixture" in warning
      and "extra" not in warning and "ERROR" not in sub.stdout)
usage = wcp.knowledge_usage()
check("the windowed warning is not the all-time view (both packs have history)",
      usage["packs"]["fixture"]["use"] == 2 and usage["packs"]["extra"]["skip"] == 10
      and "fixture" not in never_considered_packs(usage)
      and "extra" not in never_considered_packs(usage))

# 25. Reviewed promotion path: an engagement learning is proposed against a pack,
# reviewed, and only then resolved; APPLIED requires the pack edit to exist.
PROPOSAL_TITLE = "Fixture pack needs the repetition oracle note"
PROPOSAL_BODY = (
    "The fixture pack's oracle list needs the negative-control note observed in this "
    "engagement: with the control clean the oracle fired twice in a row, so the pack "
    "should record the repetition requirement and the stop condition it implies.")


def proposal_root() -> tuple[Path, ControlPlane]:
    r, cp = usage_root()
    cp.create_cycle("C-0001", usage_cycle("C-0001", [
        {"pack": "fixture", "verdict": "USE", "reason": usage_reason("fixture")}]))
    (r / "promotion-capture.txt").write_text("promotion capture: the fixture oracle fired under a clean control\n")
    eid = cp.register_evidence("promotion-capture.txt", kind="raw", source="researcher-owned",
                               cycle_id="C-0001")["payload"]["id"]
    cp.evaluate_technique(usage_technique(evidence_refs=[eid]))
    return r, cp


pr, pcp = proposal_root()
pr_eid = next(iter(pcp.evidence_index()))
proposal = pcp.knowledge_propose({
    "pack": "fixture", "title": PROPOSAL_TITLE, "body": PROPOSAL_BODY,
    "technique_ref": "T-000001", "evidence_refs": [pr_eid], "recheck_date": "2999-12-31"})
check("knowledge propose writes the proposal file and event with a KP id",
      proposal["payload"]["id"] == "KP-0001"
      and (pr / proposal["payload"]["proposal_path"]).is_file())
proposal_text = (pr / proposal["payload"]["proposal_path"]).read_text()
pack_target = pr / "12_knowledge/fixture/fixture.md"
check("the proposal front matter carries the review fields",
      all(marker in proposal_text for marker in (
          'id: "KP-0001"', 'pack: "fixture"', 'status: "PROPOSED"',
          'technique_ref: "T-000001"', 'recheck_date: "2999-12-31"'))
      and PROPOSAL_BODY in proposal_text)
check("the proposal payload snapshots a sha256 per INDEX-declared pack file",
      proposal["payload"]["pack_digests"]
      == {"fixture.md": hashlib.sha256(pack_target.read_bytes()).hexdigest()})
check("the proposal payload carries the digest of the written artifact",
      proposal["payload"]["body_sha256"] == hashlib.sha256(proposal_text.encode()).hexdigest())
second = pcp.knowledge_propose({"pack": "fixture", "title": "Second promotion candidate note",
                                "body": PROPOSAL_BODY})
check("knowledge propose ids increment from the recorded count",
      second["payload"]["id"] == "KP-0002"
      and second["payload"]["recheck_date"] is None
      and second["payload"]["technique_ref"] is None)


def propose_error(payload: dict) -> str:
    try:
        pcp.knowledge_propose(payload)
    except ValueError as exc:
        return str(exc)
    return ""


check("knowledge propose rejects an unknown pack by name",
      "nope-pack" in propose_error({"pack": "nope-pack", "title": PROPOSAL_TITLE, "body": PROPOSAL_BODY}))
check("knowledge propose rejects a thin title",
      "title" in propose_error({"pack": "fixture", "title": "ok", "body": PROPOSAL_BODY}))
check("knowledge propose rejects a short body",
      "body" in propose_error({"pack": "fixture", "title": PROPOSAL_TITLE, "body": "too short"}))
check("knowledge propose rejects a malformed recheck_date",
      "recheck_date" in propose_error({"pack": "fixture", "title": PROPOSAL_TITLE,
                                       "body": PROPOSAL_BODY, "recheck_date": "31-12-2999"}))
check("knowledge propose rejects a past recheck_date",
      "future" in propose_error({"pack": "fixture", "title": PROPOSAL_TITLE,
                                 "body": PROPOSAL_BODY, "recheck_date": "2020-01-01"}))
check("knowledge propose rejects an unknown technique_ref",
      "T-9999" in propose_error({"pack": "fixture", "title": PROPOSAL_TITLE,
                                 "body": PROPOSAL_BODY, "technique_ref": "T-9999"}))
check("knowledge propose validates evidence_refs like every other ref list",
      "E-999999" in propose_error({"pack": "fixture", "title": PROPOSAL_TITLE,
                                   "body": PROPOSAL_BODY, "evidence_refs": ["E-999999"]}))

created = next(e for e in pcp.events_for("knowledge_proposal", "KP-0001")
               if e["type"] == "KNOWLEDGE_PROPOSED")["time"]
created_epoch = datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ").replace(
    tzinfo=timezone.utc).timestamp()
os.utime(pack_target, (created_epoch - 120, created_epoch - 120))
try:
    pcp.knowledge_resolve("KP-0001", "APPLIED", "ticket-42")
    check("resolve APPLIED refuses a backdated but byte-identical pack", False)
except ValueError as exc:
    check("resolve APPLIED refuses a backdated but byte-identical pack",
          "timestamp touch is not an edit" in str(exc))
os.utime(pack_target, (created_epoch + 120, created_epoch + 120))
try:
    pcp.knowledge_resolve("KP-0001", "APPLIED", "ticket-42")
    check("resolve APPLIED refuses utime-only (mtime moved forward, bytes identical)", False)
except ValueError as exc:
    check("resolve APPLIED refuses utime-only (mtime moved forward, bytes identical)",
          "unchanged since proposal KP-0001" in str(exc))
try:
    pcp.knowledge_resolve("KP-0001", "APPLIED", "")
    check("resolve requires a human reference", False)
except ValueError as exc:
    check("resolve requires a human reference", "reference" in str(exc))
try:
    pcp.knowledge_resolve("KP-9999", "REJECTED", "ticket-42")
    check("resolve refuses an unknown proposal", False)
except ValueError as exc:
    check("resolve refuses an unknown proposal", "KP-9999" in str(exc))
pack_backup = pack_target.read_bytes()
pack_target.rename(pack_target.with_suffix(".md.bak"))
try:
    pcp.knowledge_resolve("KP-0002", "APPLIED", "ticket-42")
    check("resolve APPLIED refuses when an INDEX-declared pack file is missing", False)
except ValueError as exc:
    check("resolve APPLIED refuses when an INDEX-declared pack file is missing",
          "fixture.md is missing" in str(exc) and "repair" in str(exc))
pack_target.write_bytes(pack_backup)
os.chmod(pack_target, 0o000)
try:
    if os.geteuid() != 0:
        try:
            pcp.knowledge_resolve("KP-0002", "APPLIED", "ticket-42")
            check("resolve APPLIED refuses an unreadable INDEX-declared pack file", False)
        except ValueError as exc:
            check("resolve APPLIED refuses an unreadable INDEX-declared pack file",
                  "unreadable" in str(exc))
finally:
    os.chmod(pack_target, 0o644)
pack_target.write_text(pack_target.read_text()
                       + "\n- Repetition requirement: control fires twice before trusting the oracle.\n")
resolved = pcp.knowledge_resolve("KP-0001", "APPLIED", "ticket-42")
check("resolve APPLIED records the resolution after a real content edit",
      resolved["payload"] == {"id": "KP-0001", "decision": "APPLIED", "reference": "ticket-42"}
      and proposal["payload"]["pack_digests"]["fixture.md"]
      != hashlib.sha256(pack_target.read_bytes()).hexdigest())
rejected = pcp.knowledge_resolve("KP-0002", "REJECTED", "ticket-43")
check("resolve REJECTED needs no pack edit",
      rejected["payload"]["decision"] == "REJECTED")
pcp.knowledge_resolve("KP-0001", "REJECTED", "ticket-45")
pcp.knowledge_resolve("KP-0001", "APPLIED", "ticket-46")
rows = pcp.knowledge_proposals()
row = next(r for r in rows if r["id"] == "KP-0001")
check("the proposals projection keeps the latest resolution",
      row["status"] == "APPLIED" and row["reference"] == "ticket-46")
check("knowledge proposals rows carry the review fields and overdue flag",
      {"id", "pack", "title", "status", "created", "recheck_date", "overdue"} <= set(row)
      and row["pack"] == "fixture" and row["title"] == PROPOSAL_TITLE and row["overdue"] is False)
check("knowledge proposals projection is a generated view",
      (pr / "10_learning/knowledge-proposals.yaml").read_text().startswith(GENERATED_HEADER))

payload_file = pr / "proposal-payload.json"
payload_file.write_text(json.dumps({"pack": "fixture", "title": "Third promotion candidate note",
                                    "body": PROPOSAL_BODY}))
sub = run_researchctl(pr, "knowledge", "propose", str(payload_file))
check("researchctl knowledge propose wires through the canonical seam",
      sub.returncode == 0 and json.loads(sub.stdout)["payload"]["id"] == "KP-0003"
      and "KP-0003" in sub.stderr)
sub = run_researchctl(pr, "knowledge", "proposals")
out = json.loads(sub.stdout)
check("researchctl knowledge proposals prints the JSON list plus a human summary",
      sub.returncode == 0 and [r["id"] for r in out] == ["KP-0001", "KP-0002", "KP-0003"]
      and "proposals" in sub.stderr)
sub = run_researchctl(pr, "knowledge", "resolve", "KP-0003", "REJECTED", "--reference", "ticket-47")
check("researchctl knowledge resolve wires through the canonical seam",
      sub.returncode == 0 and json.loads(sub.stdout)["payload"]["decision"] == "REJECTED"
      and "KP-0003" in sub.stderr)
kp5 = pr / "10_learning/knowledge-proposals/KP-0004-forged-digest.md"
kp5.write_text("---\nid: \"KP-0004\"\n---\n\nForged digest fixture body recorded for the malformed digest check.\n")
pcp._append_locked("KNOWLEDGE_PROPOSED", "knowledge_proposal", "KP-0004",
                   payload={"id": "KP-0004", "pack": "fixture",
                            "title": "Forged digest candidate note",
                            "proposal_path": "10_learning/knowledge-proposals/KP-0004-forged-digest.md",
                            "body_sha256": hashlib.sha256(kp5.read_bytes()).hexdigest(),
                            "pack_digests": {"fixture.md": "not-a-digest"},
                            "technique_ref": None, "evidence_refs": [], "recheck_date": None})
pcp.refresh()
try:
    pcp.knowledge_resolve("KP-0004", "APPLIED", "ticket-60")
    check("resolve APPLIED refuses a malformed recorded digest", False)
except ValueError as exc:
    check("resolve APPLIED refuses a malformed recorded digest", "malformed" in str(exc))
REDACT_TITLE = ("Fixture pack records the exposed ghp_ABCDEFGHIJKLMNOPQRSTUVWX handling rule")
REDACT_BODY = ("The promotion capture proves the exposed ghp_ABCDEFGHIJKLMNOPQRSTUVWX value must "
               "never enter a pack: record only the shape and the remediation, never the credential "
               "itself, so the library cannot become a secret store.")
redacted = pcp.knowledge_propose({"pack": "fixture", "title": REDACT_TITLE, "body": REDACT_BODY})
redacted_text = (pr / redacted["payload"]["proposal_path"]).read_text()
check("knowledge propose redacts secret-shaped title and body before writing the artifact",
      "ghp_ABCDEFGHIJKLMNOPQRSTUVWX" not in redacted_text and "[REDACTED]" in redacted_text)
check("the artifact front matter mirrors the redacted title and payload",
      redacted["payload"]["title"] == redact(REDACT_TITLE)
      and f'title: {json.dumps(redact(REDACT_TITLE))}' in redacted_text
      and redacted["payload"]["body_sha256"] == hashlib.sha256(redacted_text.encode()).hexdigest())

kp99_rel = "10_learning/knowledge-proposals/KP-0099-aged-promotion-candidate-note.md"
kp99 = pr / kp99_rel
kp99.parent.mkdir(parents=True, exist_ok=True)
kp99.write_text("---\nid: \"KP-0099\"\n---\n\nAged promotion candidate note body recorded for the overdue fixture.\n")
pcp.append("KNOWLEDGE_PROPOSED", "knowledge_proposal", "KP-0099",
           payload={"id": "KP-0099", "pack": "fixture", "title": "Aged promotion candidate note",
                    "proposal_path": kp99_rel,
                    "body_sha256": hashlib.sha256(kp99.read_bytes()).hexdigest(),
                    "technique_ref": None, "evidence_refs": [],
                    "recheck_date": "2020-01-01"})
rows = pcp.knowledge_proposals()
check("the proposals projection flags an overdue PROPOSED recheck date",
      next(r for r in rows if r["id"] == "KP-0099")["overdue"] is True)
sub = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(pr)], capture_output=True, text=True)
check("audit warns on an overdue proposal",
      "overdue" in sub.stdout and "KP-0099" in sub.stdout and "ERROR" not in sub.stdout)


def run_audit(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(root)],
                          capture_output=True, text=True)


# 26. The read path used by the audit never mutates: knowledge_proposals() reads the
# projection when present and otherwise computes in memory, with or without events.
ro = fresh_root()
rocp = ControlPlane(ro)
before = sorted(str(p.relative_to(ro)) for p in ro.rglob("*"))
rows = rocp.knowledge_proposals()
after = sorted(str(p.relative_to(ro)) for p in ro.rglob("*"))
check("knowledge_proposals on a projection-less workspace creates no files",
      rows == [] and before == after)
ap = "10_learning/knowledge-proposals/KP-0001-read-only-fixture-proposal.md"
rocp._append_locked("KNOWLEDGE_PROPOSED", "knowledge_proposal", "KP-0001",
                    payload={"id": "KP-0001", "pack": "fixture",
                             "title": "Read-only fixture proposal note", "proposal_path": ap,
                             "body_sha256": "0" * 64, "pack_digests": {"fixture.md": "1" * 64},
                             "technique_ref": None, "evidence_refs": [], "recheck_date": None})
before = sorted(str(p.relative_to(ro)) for p in ro.rglob("*"))
rows = rocp.knowledge_proposals()
after = sorted(str(p.relative_to(ro)) for p in ro.rglob("*"))
check("knowledge_proposals computes event rows in memory without persisting a projection",
      [r["id"] for r in rows] == ["KP-0001"] and rows[0]["status"] == "PROPOSED"
      and before == after and not (ro / "10_learning/knowledge-proposals.yaml").exists())

# 27. The audit re-validates knowledge events a hand edit or raw append could smuggle in.
ar, acp = usage_root()
acp.create_cycle("C-0001", usage_cycle("C-0001", [
    {"pack": "fixture", "verdict": "USE", "reason": usage_reason("fixture")}]))
(ar / "audit-capture.txt").write_text("audit capture: the fixture oracle fired under the control\n")
aeid = acp.register_evidence("audit-capture.txt", kind="raw", source="researcher-owned")["payload"]["id"]
acp._append_locked(
    "TECHNIQUE_EVALUATED", "technique", "T-000001", evidence_refs=[aeid], cycle_id="C-0001",
    payload={"id": "T-000001", "cycle_id": "C-0001", "result": "CONFIRMED",
             "technique_family": "oracle-probe",
             "interpretation": "the fixture oracle fired under the clean control",
             "learning": "the fixture pack oracle note should cite the repetition requirement",
             "knowledge_packs": ["nope-pack"]})
sub = run_audit(ar)
check("audit flags knowledge_packs naming an unknown pack (versioned: ERROR)",
      sub.returncode == 1 and "nope-pack" in sub.stdout)
legacyize(ar)
sub = run_audit(ar)
check("the knowledge_packs backstop degrades to WARNING for a legacy ledger",
      sub.returncode == 0 and "nope-pack" in sub.stdout and "ERROR" not in sub.stdout)

br, bcp = proposal_root()
bprop = bcp.knowledge_propose({"pack": "fixture", "title": PROPOSAL_TITLE, "body": PROPOSAL_BODY})
bcp._append_locked("KNOWLEDGE_RESOLVED", "knowledge_proposal", bprop["payload"]["id"],
                   payload={"id": bprop["payload"]["id"], "decision": "MAYBE",
                            "reference": "hand-edit"})
bcp.refresh()
brow = next(r for r in bcp.knowledge_proposals() if r["id"] == bprop["payload"]["id"])
check("an unknown resolution decision projects as an explicit INVALID marker",
      brow["status"] == "INVALID")
sub = run_audit(br)
check("audit flags an unknown KNOWLEDGE_RESOLVED decision (versioned: ERROR)",
      sub.returncode == 1 and "MAYBE" in sub.stdout)
legacyize(br)
sub = run_audit(br)
check("the decision backstop degrades to WARNING for a legacy ledger",
      sub.returncode == 0 and "MAYBE" in sub.stdout and "ERROR" not in sub.stdout)

cr, ccp = proposal_root()
cprop = ccp.knowledge_propose({"pack": "fixture", "title": PROPOSAL_TITLE, "body": PROPOSAL_BODY})
cartifact = cr / cprop["payload"]["proposal_path"]
cartifact.write_text(cartifact.read_text() + "tampered after proposal\n")
sub = run_audit(cr)
check("audit flags a tampered proposal artifact (digest mismatch, versioned: ERROR)",
      sub.returncode == 1 and "sha256 mismatch" in sub.stdout)
legacyize(cr)
sub = run_audit(cr)
check("the proposal digest backstop degrades to WARNING for a legacy ledger",
      sub.returncode == 0 and "sha256 mismatch" in sub.stdout and "ERROR" not in sub.stdout)

dr, dcp = proposal_root()
dcp._append_locked("KNOWLEDGE_PROPOSED", "knowledge_proposal", "KP-0002",
                   payload={"id": "KP-0002", "pack": "fixture",
                            "title": "A proposal missing its artifact evidence"})
sub = run_audit(dr)
check("audit requires the KNOWLEDGE_PROPOSED artifact fields (versioned: ERROR)",
      sub.returncode == 1 and "proposal_path" in sub.stdout and "body_sha256" in sub.stdout)

# 28. Resolution provenance: an optional --gate binds the resolution to a resolved human
# gate; without it the free-text reference is the recorded friction, not cryptographic proof.
gr, gcp = usage_root()
gcp.create_cycle("C-0001", usage_cycle("C-0001", [
    {"pack": "fixture", "verdict": "USE", "reason": usage_reason("fixture")},
    {"pack": "extra", "verdict": "SKIP", "reason": usage_reason("extra")}]))
gcp.transition_cycle("C-0001", "READY", reason="gate fixture ready")
write_objective(gr, "C-0001")
gcp.transition_cycle("C-0001", "RUNNING", reason="gate fixture running")
gcp.request_gate("G-0001", {"cycle_id": "C-0001", "what_is_needed": "Review the promotion",
                            "why_human_only": "Only the researcher can approve promotion",
                            "resume_after": "Promotion resolved"})
gprop = gcp.knowledge_propose({"pack": "fixture", "title": PROPOSAL_TITLE, "body": PROPOSAL_BODY})
try:
    gcp.knowledge_resolve(gprop["payload"]["id"], "REJECTED", "ticket-50", gate="G-9999")
    check("resolve --gate refuses an unknown gate", False)
except ValueError as exc:
    check("resolve --gate refuses an unknown gate", "G-9999" in str(exc) and "gate" in str(exc))
try:
    gcp.knowledge_resolve(gprop["payload"]["id"], "REJECTED", "ticket-50", gate="G-0001")
    check("resolve --gate refuses a gate that is not RESOLVED", False)
except ValueError as exc:
    check("resolve --gate refuses a gate that is not RESOLVED", "not RESOLVED" in str(exc))
gcp.resolve_gate("G-0001", decision="APPROVED", reference="ticket-50")
gated = gcp.knowledge_resolve(gprop["payload"]["id"], "REJECTED", "ticket-50", gate="G-0001")
check("resolve --gate records the gate on the resolution once it is RESOLVED",
      gated["payload"]["gate"] == "G-0001"
      and gated["payload"]["reference"] == "ticket-50")
gsecond = gcp.knowledge_propose({"pack": "fixture", "title": "Second gate candidate note",
                                 "body": PROPOSAL_BODY})
sub = run_researchctl(gr, "knowledge", "resolve", gsecond["payload"]["id"], "REJECTED",
                      "--reference", "ticket-51", "--gate", "G-0001")
check("researchctl knowledge resolve --gate wires through the canonical seam",
      sub.returncode == 0 and json.loads(sub.stdout)["payload"]["gate"] == "G-0001")


# v8.2 W3: lock truthfulness — a live holder is never reclaimed, dead owners are.
import os as _os, time as _time
from control_plane import _lock as _w3_lock
_w3_root = fresh_root()
_w3_lockdir = _w3_root / "11_runtime" / ".control-plane.lock"
_w3_lockdir.mkdir()
(_w3_lockdir / "owner").write_text(f"{_os.getpid()} {_time.time() - 10000}\n")
try:
    with _w3_lock(_w3_root, timeout=0.3):
        check("v8.2 W3: live holder past the horizon is not reclaimed", False)
except TimeoutError:
    check("v8.2 W3: live holder past the horizon is not reclaimed", True)
import shutil as _shutil
_shutil.rmtree(_w3_lockdir, ignore_errors=True)
_w3_lockdir.mkdir()
(_w3_lockdir / "owner").write_text(f"99999999 {_time.time() - 10000}\n")
with _w3_lock(_w3_root, timeout=2.0, stale_seconds=0.0):
    check("v8.2 W3: dead owner is reclaimed", True)


# v8.2 W1: review independence — trim+casefold identities, producer-run refusal,
# local-mode (voucher-less) acceptance.
def _w1_root() -> tuple:
    r = fresh_root()
    c = ControlPlane(r)
    c.create_cycle("C-0001", cycle_fixture("C-0001", "review casefold probe", root=r))
    write_objective(r, "C-0001")
    c.transition_cycle("C-0001", "READY", reason="ready")
    c.transition_cycle("C-0001", "RUNNING", reason="run")
    proof = r / "proof.txt"
    proof.write_text(f"probe observation: {QUOTE}\n")
    e = c.register_evidence("proof.txt", kind="raw", source="researcher-owned",
                            cycle_id="C-0001")["payload"]["id"]
    write_results(r, "C-0001", e)
    c.update_cycle("C-0001", {"result_summary": "bounded impact reproduced"})
    c.transition_cycle("C-0001", "RESULT_READY", reason="result", evidence_refs=[e])
    return r, c, e


def _w1_packet(e: str, axis: str, reviewer: str, run_id: str, **extra: object) -> dict:
    pkt: dict = {"cycle_id": "C-0001", "evidence_refs": [e], "next_step": f"{axis} review",
                 "review": {"axis": axis, "verdict": "pass", "reviewer": reviewer,
                            "run_id": run_id,
                            "evidence_quotes": [{"evidence_ref": e, "quote": QUOTE}]}}
    pkt.update(extra)
    return pkt


_wr, _wc, _we = _w1_root()
_wc.merge_worker(_w1_packet(_we, "objective", "Run-A", "Session-A"))
_wc.merge_worker(_w1_packet(_we, "method", "run-a", "session-a"))
try:
    _wc.transition_cycle("C-0001", "REVIEWED", reason="case variants", evidence_refs=[_we])
    check("v8.2 W1: case-variant reviewer/run_id pair is refused", False)
except ValueError as exc:
    check("v8.2 W1: case-variant reviewer/run_id pair is refused", "distinct" in str(exc))

_wr2, _wc2, _we2 = _w1_root()
_wc2.merge_worker(_w1_packet(_we2, "objective", "rev-a", "Session-A"))
_wc2.merge_worker(_w1_packet(_we2, "method", "rev-b", "session-a"))
try:
    _wc2.transition_cycle("C-0001", "REVIEWED", reason="run case variant", evidence_refs=[_we2])
    check("v8.2 W1: run_id differing only by case is refused", False)
except ValueError as exc:
    check("v8.2 W1: run_id differing only by case is refused", "distinct runs" in str(exc))

_wr3, _wc3, _we3 = _w1_root()
try:
    _wc3.merge_worker(_w1_packet(_we3, "objective", "rev-a", "run-1", producer_run_id="RUN-1"))
    check("v8.2 W1: review by the producer run is refused", False)
except ValueError as exc:
    check("v8.2 W1: review by the producer run is refused", "producer run" in str(exc))
_wc3.merge_worker(_w1_packet(_we3, "objective", "rev-a", "run-1", producer_run_id="run-9"))
_wc3.merge_worker(_w1_packet(_we3, "method", "rev-b", "run-2", producer_run_id="run-9"))
_wc3.transition_cycle("C-0001", "REVIEWED", reason="local voucher-less", evidence_refs=[_we3])
check("v8.2 W1: local mode accepts voucher-less reviews from distinct runs",
      _wc3.cycle_status("C-0001") == "REVIEWED")

# v8.2 W4: snapshot-first registration + review-gate digest re-verification.
_wr4, _wc4, _we4 = _w1_root()
_store4 = _wr4 / _wc4.evidence_index()[_we4]["store_path"]
import hashlib as _hashlib
check("v8.2 W4: the store copy matches the recorded digest",
      _hashlib.sha256(_store4.read_bytes()).hexdigest()
      == _wc4.evidence_index()[_we4]["sha256"])
with _store4.open("a") as _fh:
    _fh.write("forged appendix: nothing was ever validated\n")
try:
    _wc4.merge_worker(_w1_packet(_we4, "objective", "rev-a", "run-1"))
    check("v8.2 W4: quote against a digest-mismatched store is refused", False)
except ValueError as exc:
    check("v8.2 W4: quote against a digest-mismatched store is refused",
          "no longer matches the registered digest" in str(exc))

# v8.2 W6: APPLIED backstop — ledger-derived enforcement, audit re-verification,
# orphan resolutions.
def _w6_root() -> tuple:
    r = fresh_root()
    (r / "OS_VERSION").write_text("8.1\n")
    c = ControlPlane(r)
    return r, c


PROPOSAL_TITLE = "Fixture pack records the probe behavior under test"
PROPOSAL_BODY = ("The probe body explains what the pack should record and why the change "
                 "matters for review.")
_kr6, _kc6 = _w6_root()
_kp6 = _kc6.knowledge_propose({"pack": "fixture", "title": PROPOSAL_TITLE, "body": PROPOSAL_BODY})
_prop_path = _kr6 / "10_learning" / "knowledge-proposals.yaml"
_rows6 = [l for l in _prop_path.read_text().splitlines() if l.strip().startswith("- ")]
_row6 = json.loads(_rows6[0].strip()[2:])
_row6["pack_digests"] = {"fixture.md": "0" * 64}
_prop_path.write_text("- " + json.dumps(_row6) + "\n")
try:
    _kc6.knowledge_resolve("KP-0001", "APPLIED", "ticket-123")
    check("v8.2 W6: forged projection row cannot buy APPLIED", False)
except ValueError as exc:
    check("v8.2 W6: forged projection row cannot buy APPLIED", "unchanged" in str(exc))
_kr6b, _kc6b = _w6_root()
_kc6b.append("KNOWLEDGE_RESOLVED", "knowledge_proposal", "KP-9999", actor="human",
             reason="orphan fixture",
             payload={"id": "KP-9999", "decision": "APPLIED", "reference": "ticket-999"})
_sub6 = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(_kr6b)],
                       capture_output=True, text=True)
check("v8.2 W6: orphan KNOWLEDGE_RESOLVED fails the audit",
      _sub6.returncode != 0 and "KP-9999" in (_sub6.stdout + _sub6.stderr))
_kr6c, _kc6c = _w6_root()
_kc6c.knowledge_propose({"pack": "fixture", "title": PROPOSAL_TITLE, "body": PROPOSAL_BODY})
_kc6c.append("KNOWLEDGE_RESOLVED", "knowledge_proposal", "KP-0001", actor="human",
             reason="forged applied", payload={"id": "KP-0001", "decision": "APPLIED",
                                               "reference": "ticket-123"})
_sub6c = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(_kr6c)],
                        capture_output=True, text=True)
check("v8.2 W6: forged APPLIED on an untouched pack fails the audit",
      _sub6c.returncode != 0 and "APPLIED" in (_sub6c.stdout + _sub6c.stderr))
(_kr6c / "12_knowledge" / "fixture" / "fixture.md").write_text("# Fixture pack\n\nReal new content.\n")
_kc6c.knowledge_resolve("KP-0001", "APPLIED", "ticket-124")
_sub6d = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(_kr6c)],
                        capture_output=True, text=True)
check("v8.2 W6: legit APPLIED after a real pack edit audits clean", _sub6d.returncode == 0)

# v8.2 W7: token_nonce provenance — write-side refusal, audit resolution against
# consumed records, and consumed-but-unrecorded budget accounting keyed by nonce.
def _w7_root(cap_cycle: int = 50, cap_total: int = 50) -> tuple:
    r = fresh_root()
    (r / "00_control/engagement.yaml").write_text(
        'scope:\n  assets:\n  - "example.test"\n'
        f"budget:\n  max_actions_per_cycle: {cap_cycle}\n  max_actions_per_engagement: {cap_total}\n")
    c = ControlPlane(r)
    c.create_cycle("C-0001", cycle_fixture("C-0001", "nonce probe", root=r))
    write_objective(r, "C-0001")
    c.transition_cycle("C-0001", "READY", reason="ready")
    c.transition_cycle("C-0001", "RUNNING", reason="run")
    c.create_hypothesis("H-0001", {"cycle_id": "C-0001", "observation": "probe",
                                   "hypothesis": "probe", "secure_prediction": "denied",
                                   "vulnerable_prediction": "allowed"})
    return r, c


def _w7_action() -> dict:
    return {"cycle_id": "C-0001", "target": "https://example.test/api", "scope_status": "IN_SCOPE",
            "account": "researcher-A", "object_owner": "researcher-A",
            "purpose": "distinguish authorization behavior", "hypothesis": "H-0001",
            "expected_secure": "denied", "expected_vulnerable": "unexpected access",
            "side_effect": "none", "stop_condition": "stop on unsafe behavior", "tool_family": "http",
            "request_shape": {"method": "GET", "url": "https://example.test/api",
                              "principal": "researcher-A"}}


_nr7, _nc7 = _w7_root()
_tok7 = _nc7.prepare_action(_w7_action())
try:
    _nc7.record_action({**_w7_action(), "token_nonce": "forged-nonce-not-a-real-token"})
    check("v8.2 W7: record_action refuses a forged token_nonce", False)
except ValueError as exc:
    check("v8.2 W7: record_action refuses a forged token_nonce", "token_nonce" in str(exc))
with (_nr7 / "11_runtime/action-tokens.jsonl").open("a", encoding="utf-8") as _fh:
    _fh.write(json.dumps({"action_id": _tok7["action_id"], "nonce": _tok7["nonce"],
                          "consumed": True, "consumed_at": "2026-09-01T00:00:01Z"}) + "\n")
_nc7.record_action({**_w7_action(), "token_nonce": _tok7["nonce"]})
check("v8.2 W7: record_action accepts the consumed token nonce",
      any(e.get("type") == "ACTION_RECORDED" for e in _nc7._read_events()))
_nr7f, _nc7f = _w7_root()
_tok7f = _nc7f.prepare_action(_w7_action())
_nc7f.append("ACTION_RECORDED", "action", _tok7f["action_id"], cycle_id="C-0001",
             reason="forged receipt fixture",
             payload={**_w7_action(), "token_nonce": "forged-nonce-not-a-real-token"})
_sub7 = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(_nr7f)],
                       capture_output=True, text=True)
check("v8.2 W7: the audit errors on a forged token_nonce",
      _sub7.returncode != 0 and "token_nonce" in (_sub7.stdout + _sub7.stderr))
# Consumed-but-unrecorded capacity (reviewer D PROBE 1): the receipt-failure path
# must not reopen budget headroom.
_nr7b, _nc7b = _w7_root(cap_cycle=1, cap_total=10)
_tok7b = _nc7b.prepare_action(_w7_action())
try:
    _nc7b.prepare_action(_w7_action())
    check("v8.2 W7: second prepare refused while the token is outstanding", False)
except ValueError:
    check("v8.2 W7: second prepare refused while the token is outstanding", True)
with (_nr7b / "11_runtime/action-tokens.jsonl").open("a", encoding="utf-8") as _fh:
    _fh.write(json.dumps({"action_id": _tok7b["action_id"], "nonce": _tok7b["nonce"],
                          "consumed": True, "consumed_at": "2026-09-01T00:00:01Z"}) + "\n")
check("v8.2 W7: consumed-but-unrecorded still counts against the cap",
      _nc7b.budget_status()["counts"]["engagement"] == 1)
try:
    _nc7b.prepare_action(_w7_action())
    check("v8.2 W7: receipt failure does not reopen budget headroom", False)
except ValueError:
    check("v8.2 W7: receipt failure does not reopen budget headroom", True)

# v8.2 W8: one allocator for A- ids across record and prepare; duplicates refused
# at the seam and flagged by the audit.
_nr8, _nc8 = _w7_root()
_t8a = _nc8.prepare_action(_w7_action())
_r8a = _nc8.record_action({k: v for k, v in _w7_action().items()})
_t8b = _nc8.prepare_action(_w7_action())
check("v8.2 W8: interleaved prepares and records never share an id",
      len({_t8a["action_id"], _r8a["entity_id"], _t8b["action_id"]}) == 3)
_nc8.record_action({**_w7_action(), "id": "A-000004"})
try:
    _nc8.record_action({**_w7_action(), "id": "A-000004"})
    check("v8.2 W8: a duplicate explicit action id is refused", False)
except ValueError as exc:
    check("v8.2 W8: a duplicate explicit action id is refused", "already recorded" in str(exc))
_nr8b, _nc8b = _w7_root()
_nc8b.record_action({**_w7_action(), "id": "A-000004"})
_nc8b.append("ACTION_RECORDED", "action", "A-000004", cycle_id="C-0001", reason="dup fixture",
             payload=_w7_action())
_sub8 = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(_nr8b)],
                       capture_output=True, text=True)
check("v8.2 W8: the audit errors on duplicate action ids",
      _sub8.returncode != 0 and "duplicate action id A-000004" in (_sub8.stdout + _sub8.stderr))

# v8.2 W5: provenance drift — hand edits behind the ledger fail the audit until
# re-recorded; hop entries carry the seam's real reason (node-side, run.test.mjs).
_dr5 = fresh_root()
_dc5 = ControlPlane(_dr5)
_dc5.set_scope(["example.test"], "policy://scope")
_dc5.set_budget({"max_actions_per_cycle": 5, "max_actions_per_engagement": 50,
                 "source_reference": "policy://budget"})
_sub5 = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(_dr5)],
                       capture_output=True, text=True)
check("v8.2 W5: recorded scope and budget audit clean", _sub5.returncode == 0)
(_dr5 / "00_control/engagement.yaml").write_text(
    'scope:\n  assets:\n  - "example.test"\n  - "evil.example"\n'
    'budget:\n  max_actions_per_cycle: 5\n  max_actions_per_engagement: 50\n')
_sub5w = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(_dr5)],
                        capture_output=True, text=True)
check("v8.2 W5: hand-widened scope fails the audit until re-recorded",
      _sub5w.returncode != 0 and "scope drifted" in (_sub5w.stdout + _sub5w.stderr)
      and "researchctl scope-set" in (_sub5w.stdout + _sub5w.stderr))
_dc5.set_scope(["example.test", "evil.example"], "policy://scope-v2", human_reference="ticket-1")
_sub5r = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(_dr5)],
                        capture_output=True, text=True)
check("v8.2 W5: re-recorded scope audits clean", _sub5r.returncode == 0)
(_dr5 / "00_control/engagement.yaml").write_text(
    'scope:\n  assets:\n  - "example.test"\n  - "evil.example"\n'
    'budget:\n  max_actions_per_cycle: 1\n  max_actions_per_engagement: 50\n')
_sub5b = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(_dr5)],
                        capture_output=True, text=True)
check("v8.2 W5: hand-lowered budget fails the audit until re-recorded",
      _sub5b.returncode != 0 and "budget caps drifted" in (_sub5b.stdout + _sub5b.stderr)
      and "researchctl budget set" in (_sub5b.stdout + _sub5b.stderr))

# v8.2 W9: triage snapshot — RUNNING freezes the demanded list + cap; later env
# and workspace drift cannot move the goalposts on past cycles.
def _w9_root() -> Path:
    r = fresh_root()
    for pk in ["alpha", "bravo", "charlie", "delta", "echo"]:
        (r / "12_knowledge" / pk).mkdir(parents=True, exist_ok=True)
        (r / "12_knowledge" / pk / f"{pk}.md").write_text(f"# {pk} pack\n")
    (r / "12_knowledge/INDEX.yaml").write_text(
        "packs:\n" + "".join(f"  {pk}:\n    load_when: [test]\n    files: [{pk}.md]\n"
                              for pk in ["alpha", "bravo", "charlie", "delta", "echo"]))
    return r


_wr9 = _w9_root()
_wc9 = ControlPlane(_wr9)
from knowledge_index import selection_cap as _cap9, selection_query as _q9, top_packs as _top9
_ranked9 = [n for n, _ in _top9(_wr9, _q9(_wr9, "test question"), k=_cap9())]
assert len(_ranked9) > 1, "w9 fixture needs several ranked packs"
_wc9.create_cycle("C-0001", cycle_fixture("C-0001", "test question", root=_wr9))
_wc9.update_cycle("C-0001", {"knowledge_triage": [
    {"pack": n, "verdict": "SKIP", "reason": "snapshot probe reason covers this pack"}
    for n in _ranked9]})
write_objective(_wr9, "C-0001")
_wc9.transition_cycle("C-0001", "READY", reason="ready")
_wc9.transition_cycle("C-0001", "RUNNING", reason="run")
_snap9 = _wc9.cycle_data("C-0001").get("knowledge_triage_snapshot") or {}
check("v8.2 W9: RUNNING snapshots the demanded list and the effective cap",
      _snap9.get("ranked") == _ranked9 and _snap9.get("cap") == _cap9())
_sub9 = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(_wr9)],
                       capture_output=True, text=True)
check("v8.2 W9: the snapshotted cycle audits clean", _sub9.returncode == 0)
_flipped = dict(os.environ, KNOWLEDGE_PACK_CAP="6")
_sub9f = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(_wr9)],
                        capture_output=True, text=True, env=_flipped)
check("v8.2 W9: a cap flip after RUNNING adds no audit errors on past cycles",
      _sub9f.returncode == 0 and "knowledge_triage" not in (_sub9f.stdout + _sub9f.stderr))
(_wr9 / "10_learning/unknowns.yaml").write_text(
    "unknowns: [alpha, bravo, charlie, delta, echo, extra]\n")
_sub9u = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(_wr9)],
                        capture_output=True, text=True)
check("v8.2 W9: an unknowns edit after RUNNING adds no audit errors on past cycles",
      _sub9u.returncode == 0 and "knowledge_triage" not in (_sub9u.stdout + _sub9u.stderr))
try:
    _wc9.update_cycle("C-0001", {"knowledge_triage_snapshot": {"ranked": [], "cap": 1}})
    check("v8.2 W9: the snapshot is immutable", False)
except ValueError as exc:
    check("v8.2 W9: the snapshot is immutable", "immutable" in str(exc))

# v8.2 W2: identity binding — declared accounts enforced at prepare, malformed
# fails closed, absent/placeholder allows with an audit warning; the browser
# profile rides the token explicitly and outside-root profiles are refused.
_BINDING = (
    "binding_version: 1\nengagement: probe\nplatform: DIRECT\nprogram: Probe\n"
    "expected_identity:\n  public_handle: researcher-x\n  account_reference: acct-binding-1\n"
    "session:\n  browser_profile: lab/bua-prog\n  session_must_match_identity: true\n"
    "  cross_engagement_session_reuse: false\n")


def _w2_root(binding: str | None = _BINDING) -> tuple:
    r, c = _w7_root()
    if binding is not None:
        (r / "00_control/identity-binding.yaml").write_text(binding)
    return r, c


_nr2, _nc2 = _w2_root()
try:
    _nc2.prepare_action({**_w7_action(), "account": "intruder-acct"})
    check("v8.2 W2: prepare refuses an account outside the binding", False)
except ValueError as exc:
    check("v8.2 W2: prepare refuses an account outside the binding", "identity binding" in str(exc))
_tok2 = _nc2.prepare_action({**_w7_action(), "account": "acct-binding-1"})
check("v8.2 W2: prepare allows the bound account", _tok2["action_id"].startswith("A-"))
_browser_payload = {**_w7_action(), "account": "acct-binding-1", "tool_family": "browser",
                    "request_shape": {"url": "https://example.test/app", "principal": "researcher-A"}}
_tok2b = _nc2.prepare_action(_browser_payload)
check("v8.2 W2: browser prepare binds the declared profile",
      _tok2b.get("browser_profile") == "lab/bua-prog")
_nr2m, _nc2m = _w2_root("expected_identity:\n\taccount_reference: x\n")
try:
    _nc2m.prepare_action({**_w7_action(), "account": "acct-binding-1"})
    check("v8.2 W2: malformed binding fails prepare closed", False)
except ValueError as exc:
    check("v8.2 W2: malformed binding fails prepare closed", "malformed" in str(exc))
_nr2a, _nc2a = _w2_root(None)
_tok2a = _nc2a.prepare_action(_w7_action())
check("v8.2 W2: absent binding allows prepare (template workspaces)",
      _tok2a["action_id"].startswith("A-"))
_nr2p, _nc2p = _w2_root(
    "binding_version: 1\nexpected_identity:\n  account_reference: <NON_SECRET_ACCOUNT_REFERENCE>\n"
    "session:\n  browser_profile: <DEDICATED_BROWSER_PROFILE>\n")
_tok2p = _nc2p.prepare_action(_w7_action())
check("v8.2 W2: placeholder-only binding allows prepare",
      _tok2p["action_id"].startswith("A-")
      and _nc2p.prepare_action({**_browser_payload, "account": "researcher-A"}).get("browser_profile") == "lab/bua-profile")
_nr2o, _nc2o = _w2_root(_BINDING.replace("lab/bua-prog", "../outside"))
try:
    _nc2o.prepare_action(_browser_payload)
    check("v8.2 W2: outside-root profiles are refused", False)
except ValueError as exc:
    check("v8.2 W2: outside-root profiles are refused", "outside the workspace" in str(exc))
_sub2 = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(_nr2a)],
                       capture_output=True, text=True)
check("v8.2 W2: missing binding warns the audit",
      _sub2.returncode == 0 and "identity binding" in (_sub2.stdout + _sub2.stderr))
_nc2.record_action({**_w7_action(), "account": "intruder-acct"})
_sub2m = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(_nr2)],
                        capture_output=True, text=True)
check("v8.2 W2: the audit errors on an action outside the binding",
      _sub2m.returncode != 0 and "identity binding" in (_sub2m.stdout + _sub2m.stderr))


print(f"\n{len(passed)} checks passed")
