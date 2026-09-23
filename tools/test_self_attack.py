#!/usr/bin/env python3
"""v8.3 V1a: coverage-ledger discipline for the method self-attack matrix.

Deterministic coverage units derived from the ledger + a critic-wave loop over the
six-row matrix: every derived unit must be named in its row, and the coverage result
rides on the audit event (advisory to the audit's warning stream — the six-row form
check stays the enforcement).
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import audit as _audit  # noqa: E402
from control_plane import ControlPlane, METHOD_SELF_ATTACK_ROWS  # noqa: E402

passed: list[str] = []


def check(name: str, cond: bool):
    assert cond, f"FAIL: {name}"
    passed.append(name)
    print(f"ok: {name}")


def fresh_root() -> Path:
    root = Path(tempfile.mkdtemp())
    for d in ["00_control", "02_surface", "03_hypotheses/active", "03_hypotheses/archive",
              "04_cycles", "10_learning", "11_runtime", "12_knowledge/fixture"]:
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / "02_surface/endpoints.yaml").write_text("endpoints: []\n")
    (root / "10_learning/freshness.yaml").write_text("components: []\n")
    (root / "10_learning/unknowns.yaml").write_text("unknowns: []\n")
    (root / "10_learning/assumptions.yaml").write_text("assumptions: []\n")
    (root / "11_runtime/events.jsonl").write_text("")
    (root / "11_runtime/run-status.yaml").write_text('engagement_status: "BOOTSTRAP"\n')
    (root / "11_runtime/tool-registry.yaml").write_text("tools: []\n")
    (root / "11_runtime/lab-status.yaml").write_text("status: UNKNOWN\n")
    (root / "12_knowledge/fixture/fixture.md").write_text("# Fixture pack\n")
    (root / "12_knowledge/INDEX.yaml").write_text(
        "packs:\n  fixture:\n    load_when: [coverage, fixture, self-attack]\n    files: [fixture.md]\n")
    return root


root = fresh_root()
(root / "00_control/engagement.yaml").write_text(
    'external_judgment: "DENIED"\nscope:\n  assets:\n  - "example.test"\n')
(root / "proof.txt").write_text("HTTP 200 observed with title Example Domain\n")
cp = ControlPlane(root)
cp.register_evidence("proof.txt", kind="raw", source="test")
cp.create_cycle("C-0001", {
    "id": "C-0001", "type": "DISCOVERY", "objective": "self-attack coverage fixture",
    "allowed_scope": ["example.test"], "stop_conditions": ["stop"], "controls": [],
    "status": "PLANNED",
    "knowledge_triage": [{"pack": "fixture", "verdict": "SKIP",
                          "reason": "fixture covers the self-attack coverage seam"}]})
cycle_dir = root / "04_cycles" / "C-0001"
(cycle_dir / "objective.md").write_text(
    "# Cycle Objective\n\n## Question\nDoes the fixture hold?\n\n"
    "## Minimal test\nOne controlled request.\n")
cp.transition_cycle("C-0001", "READY", reason="ready")
cp.transition_cycle("C-0001", "RUNNING", reason="run")
cp.transition_cycle("C-0001", "BLOCKED", reason="instrument stop for the coverage fixture")
cp.create_hypothesis("H-0001", {
    "cycle_id": "C-0001", "observation": "the fixture flipped", "hypothesis": "fixture flipped",
    "secure_prediction": "denied", "vulnerable_prediction": "allowed",
    "test_question": "does the fixture flip?", "test_plan": "one differential"})
cp.transition_hypothesis("H-0001", "QUEUED", reason="queued")
cp.transition_hypothesis("H-0001", "TESTING", reason="testing")
cp.transition_hypothesis("H-0001", "FALSE_POSITIVE", reason="the signal was the lab stub",
                         evidence_refs=["E-000001"])
cp.record_freshness({"components": [
    {"target_component": "edge-proxy", "pinned_version": "1.2.3", "last_checked": "2026-09-22",
     "sources": ["vendor changelog"], "action": "none"},
    {"target_component": "legacy-auth", "pinned_version": "UNKNOWN", "last_checked": "2026-01-05",
     "sources": [], "action": "pin the version"},
]})

# 1. Deterministic units per row, derived from the ledger.
units = cp.method_attack_units()
check("units cover the six rows (empty rows carry their reason)",
      set(units) == set(METHOD_SELF_ATTACK_ROWS))
check("a FALSE_POSITIVE hypothesis is a weak-negative unit",
      [u["subject"] for u in units["weak-negative"]["units"]] == ["H-0001"])
check("a cycle that entered BLOCKED is an early-close unit",
      [u["subject"] for u in units["early-close"]["units"]] == ["C-0001"])
check("freshness components are assumed-secure units",
      sorted(u["subject"] for u in units["assumed-secure"]["units"]) == ["edge-proxy", "legacy-auth"])
check("an unpinned/stale component is a version-drift unit",
      [u["subject"] for u in units["version-drift"]["units"]] == ["legacy-auth"])
check("rows the ledger cannot derive units for say so with a reason",
      units["skipped-collision"]["units"] == [] and units["skipped-collision"]["note"]
      and units["tool-misread"]["units"] == [] and units["tool-misread"]["note"])

# 2. The critic: every derived unit must be named in its row.
missing_matrix = {row: "none — no miss recorded for this fixture" for row in METHOD_SELF_ATTACK_ROWS}
critique = cp.critique_self_attack(missing_matrix)
check("the critic reports every uncovered unit with its row",
      critique["complete"] is False
      and {"weak-negative:H-0001", "early-close:C-0001", "assumed-secure:edge-proxy",
           "version-drift:legacy-auth"} <= set(critique["uncovered"]))
named_matrix = dict(missing_matrix)
named_matrix["weak-negative"] = "re-opened H-0001 (lab stub); re-run clean"
named_matrix["early-close"] = "C-0001 instrument stop replayed"
named_matrix["assumed-secure"] = "edge-proxy and legacy-auth trusted without evidence; one probe each"
named_matrix["version-drift"] = "legacy-auth pinned version unknown; drift re-opened"
complete = cp.critique_self_attack(named_matrix)
check("a matrix naming every derived unit is complete", complete["complete"] is True
      and complete["uncovered"] == [])

# 3. record_audit carries the coverage result on the event (ledger-visible).
event = cp.record_audit("method-self-attack", "PASS",
                        "six rows answered; coverage critic run against derived units",
                        evidence_refs=["E-000001"], matrix=missing_matrix)
coverage = (event.get("payload") or {}).get("coverage")
check("the audit event carries the derived coverage (units + uncovered)",
      isinstance(coverage, dict) and coverage["units_total"] >= 4
      and "weak-negative:H-0001" in coverage["uncovered"]
      and coverage["complete"] is False)
check("a matrix that does not name the units is still accepted (advisory, not a gate)",
      event["type"] == "AUDIT_RECORDED")

# 4. The audit surfaces uncovered units as a warning, never an error.
ok, result = _audit.audit(root)
coverage_warnings = [w for w in result["warnings"] if "coverage unit" in w]
check("the audit warns about uncovered units without erroring on them",
      coverage_warnings and any("H-0001" in w for w in coverage_warnings)
      and not any("coverage unit" in e for e in result["errors"]))

print(f"\n{len(passed)}/{len(passed)} passed")
