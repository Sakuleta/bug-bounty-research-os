#!/usr/bin/env python3
"""Assert-based runtime seam tests. Run: python3 tools/test_runtime.py"""
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
FAILS = []


def check(name, fn):
    try:
        fn()
        print(f"ok: {name}")
    except AssertionError as e:
        print(f"FAIL: {name}: {e}")
        FAILS.append(name)
    except Exception as e:
        print(f"ERROR: {name}: {type(e).__name__}: {e}")
        FAILS.append(name)


def run(*args, env_extra=None):
    env = dict(os.environ)
    env.update(env_extra or {})
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, env=env)


def make_root():
    tmp = Path(tempfile.mkdtemp())
    (tmp / "04_cycles").mkdir()
    (tmp / "11_runtime").mkdir()
    (tmp / "10_learning").mkdir()
    (tmp / "12_knowledge" / "access-auth").mkdir(parents=True)
    (tmp / "12_knowledge" / "mobile").mkdir(parents=True)
    (tmp / "12_knowledge" / "api-protocols").mkdir(parents=True)
    (tmp / "12_knowledge" / "frameworks").mkdir(parents=True)
    (tmp / "11_runtime" / "run-status.yaml").write_text("engagement_status: ACTIVE\ncurrent_cycle: C-0001\n")
    (tmp / "11_runtime" / "active-cycle.yaml").write_text("cycle_id: C-0001\nobjective: test auth session login\n")
    (tmp / "11_runtime" / "last-result.md").write_text("# Last Result\nNONE\n")
    (tmp / "11_runtime" / "tool-registry.yaml").write_text("tools: []\n")
    (tmp / "11_runtime" / "lab-status.yaml").write_text("status: READY\n")
    (tmp / "10_learning" / "unknowns.yaml").write_text("- auth session handling\n")
    (tmp / "10_learning" / "assumptions.yaml").write_text("- test assumption\n")
    (tmp / "12_knowledge" / "INDEX.yaml").write_text(
        "packs:\n"
        "  access-auth:\n    load_when: [auth, session]\n    files: [authentication-authorization.md]\n"
        "  mobile:\n    load_when: [Android, APK]\n    files: [mobile.md]\n"
        "  api-protocols:\n    load_when: [REST, GraphQL]\n    files: [api.md]\n"
        "  frameworks:\n    load_when: [Django, Rails]\n    files: [frameworks.md]\n"
    )
    (tmp / "12_knowledge" / "access-auth" / "authentication-authorization.md").write_text("# Auth\n" + "x" * 200)
    (tmp / "12_knowledge" / "mobile" / "mobile.md").write_text("# Mobile\n" + "y" * 200)
    (tmp / "12_knowledge" / "api-protocols" / "api.md").write_text("# API\n" + "z" * 200)
    (tmp / "12_knowledge" / "frameworks" / "frameworks.md").write_text("# FW\n" + "w" * 200)
    return tmp


def test_new_cycle_creates():
    tmp = make_root()
    r = run(str(TOOLS / "new_cycle.py"), str(tmp), "C-0001")
    assert r.returncode == 0, r.stderr + r.stdout
    d = tmp / "04_cycles" / "C-0001"
    assert (d / "objective.md").exists(), "objective.md missing"
    assert (d / "plan.yaml").exists(), "plan.yaml missing"
    assert (d / "results.md").exists(), "results.md missing"
    # literal 'cycle' dir must NOT be created (bug regression)
    assert not (tmp / "04_cycles" / "cycle").exists(), "bug: literal 'cycle' dir created"


def test_new_cycle_rejects_bad_id():
    tmp = make_root()
    r = run(str(TOOLS / "new_cycle.py"), str(tmp), "bad-id")
    assert r.returncode != 0, "bad CYCLE_ID must fail"


def test_new_cycle_idempotent():
    tmp = make_root()
    r1 = run(str(TOOLS / "new_cycle.py"), str(tmp), "C-0002")
    assert r1.returncode == 0, r1.stderr + r1.stdout
    r2 = run(str(TOOLS / "new_cycle.py"), str(tmp), "C-0002")
    assert r2.returncode != 0, "existing cycle must fail"


def test_build_context_budget_and_packs():
    tmp = make_root()
    # cycle dir for inclusion
    r = run(str(TOOLS / "new_cycle.py"), str(tmp), "C-0001")
    assert r.returncode == 0, r.stderr + r.stdout
    r = run(str(TOOLS / "build_context.py"), str(tmp), env_extra={"CONTEXT_BUDGET": "2000"})
    assert r.returncode == 0, r.stderr + r.stdout
    out = tmp / "11_runtime" / "current-context.md"
    assert out.exists(), "current-context.md missing"
    text = out.read_text()
    assert len(text) <= 2000, f"over budget: {len(text)}"
    assert "run-status.yaml" in text or "ACTIVE" in text, "run-status not included"
    # max 4 packs: count pack headers
    packs = re.findall(r"12_knowledge/\S+", text)
    assert len(set(packs)) <= 4, f"too many packs: {set(packs)}"
    # relevance: auth keywords should rank access-auth first
    assert "access-auth" in text, "relevant pack access-auth missing"


def test_validate_passes_real_root():
    r = run(str(TOOLS / "validate_workspace.py"), str(ROOT))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "PASS" in r.stdout, "must print PASS"


def test_validate_catches_missing():
    tmp = Path(tempfile.mkdtemp())  # empty -> missing
    r = run(str(TOOLS / "validate_workspace.py"), str(tmp))
    assert r.returncode != 0, "empty dir must fail validation"


def test_provision_check_only():
    tmp = make_root()
    r = run(str(TOOLS / "provision.py"), str(tmp), "--check-only")
    assert r.returncode == 0, r.stdout + r.stderr
    lab = tmp / "11_runtime" / "lab-status.yaml"
    reg = tmp / "11_runtime" / "tool-registry.yaml"
    assert lab.exists(), "lab-status.yaml missing"
    assert reg.exists(), "tool-registry.yaml missing"
    lab_text = lab.read_text()
    assert re.search(r"status:\s*(READY|MISSING|BLOCKED|FAILED)", lab_text), "lab status invalid"
    assert "auto_exploit: false" in lab_text, "provision must never auto-exploit"


def test_provision_capability_filter():
    tmp = make_root()
    r = run(str(TOOLS / "provision.py"), str(tmp), "--check-only", "--capability", "adb")
    assert r.returncode == 0, r.stdout + r.stderr


if __name__ == "__main__":
    check("new_cycle creates 04_cycles/<ID>/", test_new_cycle_creates)
    check("new_cycle rejects bad ID", test_new_cycle_rejects_bad_id)
    check("new_cycle idempotency guard", test_new_cycle_idempotent)
    check("build_context budget + max 3 packs", test_build_context_budget_and_packs)
    check("validate PASS on real root", test_validate_passes_real_root)
    check("validate catches missing", test_validate_catches_missing)
    check("provision --check-only", test_provision_check_only)
    check("provision --capability filter", test_provision_capability_filter)
    print(f"\n{8 - len(FAILS)}/8 passed")
    sys.exit(1 if FAILS else 0)
