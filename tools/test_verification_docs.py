#!/usr/bin/env python3
"""v8.3 V1 (b/c/d): the adapted skill and the docs must say what the tools do.

The fresh-verifier skill is adapted (not imported): refute-don't-confirm, fingerprint
stability, material-replacement re-verification, and live-target routing through
`researchctl prepare` + the controlled executors (never a default `needs_validation`).
Severity anchors carry a boundary-defeat discriminator; the coverage ledger is
documented as advisory (warn, never a closure gate). No guard code is asserted here —
that is the point: these are prompt/doc contracts, and the tests pin their presence and
their consistency with the enforcement wording.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
from knowledge_index import validate_index  # noqa: E402
from ts_triage import pack_cards  # noqa: E402

passed: list[str] = []


def check(name: str, cond: bool):
    assert cond, f"FAIL: {name}"
    passed.append(name)
    print(f"ok: {name}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text()


# 1. The adapted skill: present, parseable, and not a knowledge pack.
skill_path = ROOT / ".dsh" / "skills" / "fresh-verifier" / "SKILL.md"
check("the fresh-verifier skill exists under .dsh/skills/", skill_path.is_file())
skill = skill_path.read_text()
check("the skill carries the front-matter description pack_cards parses",
      bool(re.search(r'^description:\s*"?.*\S', skill, re.M))
      and "fresh-verifier" not in pack_cards(ROOT))
errors, _warnings = validate_index(ROOT)
check("the new skill dir does not break the knowledge index consistency",
      errors == [])

# 2. Verifier prompt blocks: refute-don't-confirm + fingerprint stability +
#    material-replacement re-verification.
check("the skill says refute, don't confirm (a pass is a failed refutation)",
      "refute" in skill.lower() and "falsify" in skill.lower()
      and "failed" in skill.lower())
check("the skill requires fingerprint stability with the packet digest",
      "fingerprint" in skill.lower() and "packet digest" in skill.lower()
      and "run_id" in skill)
check("the skill states material-replacement re-verification",
      "material-replacement" in skill.lower() and "invalidates" in skill.lower()
      and "re-verify" in skill.lower())

# 3. Live-target routing: prepare + controlled executors, never a default blocker.
check("the skill routes decisive checks through researchctl prepare + the executors",
      "researchctl prepare" in skill and "research_os_request" in skill
      and "research_os_browser" in skill and "controlled executor" in skill.lower())
check("the skill forbids defaulting an authorized live target to needs_validation",
      "needs_validation" in skill and "never default" in skill.lower()
      and "BLOCKED" in skill and "what_is_needed" in skill)
check("the closure doc binds the verifier instructions to the skill",
      ".dsh/skills/fresh-verifier/SKILL.md" in read("07_AUDIT_CLOSURE.md"))
check("the evidence doc carries the live-target validation section",
      "## Live-target validation" in read("06_EVIDENCE_VALIDATION.md")
      and "researchctl prepare" in read("06_EVIDENCE_VALIDATION.md")
      and "needs_validation" in read("06_EVIDENCE_VALIDATION.md"))

# 4. Severity anchors with the boundary-defeat discriminator.
protocol = read("12_REPORT_PROTOCOL.md")
check("the report protocol carries the five severity anchors",
      all(anchor in protocol for anchor in ("critical", "high", "medium", "low",
                                            "informational")))
check("the anchors use the boundary-defeat discriminator",
      "boundary defeat" in protocol and "checklist deviation" in protocol
      and "should have prevented" in protocol)
template = read("templates/finding/report.md")
check("the report template prompts the discriminator in Severity Rationale",
      "Severity Rationale" in template and "boundary defeat" in template
      and "checklist deviation" in template and "hardening note" in template)

# 5. Docs match behavior: the coverage ledger is documented as advisory.
check("the self-attack doc documents the coverage ledger as a critic, not a gate",
      "coverage ledger" in read("33_METHOD_SELF_ATTACK.md").lower()
      and "warns (never errors)" in read("33_METHOD_SELF_ATTACK.md"))
check("the closure doc says the coverage critic is never a closure gate",
      "coverage" in read("07_AUDIT_CLOSURE.md")
      and "never a closure gate" in read("07_AUDIT_CLOSURE.md"))

print(f"\n{len(passed)}/{len(passed)} passed")
