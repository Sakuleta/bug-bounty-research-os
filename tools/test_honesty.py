#!/usr/bin/env python3
"""v8.3 V6d (T6): knowledge-use honesty check — one Noul per pack a cycle CITES,
advisory warning only, never a fail (the audit gains no error and the exit code is
unchanged), and never a state mutation.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from control_plane import ControlPlane  # noqa: E402
from ts_cost import cost_rows  # noqa: E402
from ts_honesty import cited_packs, check_knowledge_use  # noqa: E402

passed: list[str] = []


def check(name: str, cond: bool):
    assert cond, f"FAIL: {name}"
    passed.append(name)
    print(f"ok: {name}")


def workspace(policy: str = 'external_judgment: "ALLOWED"\n') -> tuple[Path, ControlPlane]:
    root = Path(tempfile.mkdtemp())
    for d in ["00_control", "02_surface", "04_cycles", "10_learning", "11_runtime",
              "12_knowledge/fixture", ".dsh/skills/fixture"]:
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / "00_control/engagement.yaml").write_text(policy)
    (root / "02_surface/endpoints.yaml").write_text("endpoints: []\n")
    (root / "11_runtime/events.jsonl").write_text("")
    (root / "12_knowledge/fixture/fixture.md").write_text("# Fixture pack\n")
    (root / "12_knowledge/INDEX.yaml").write_text(
        "packs:\n  fixture:\n    load_when: [honesty, fixture]\n    files: [fixture.md]\n")
    (root / ".dsh/skills/fixture/SKILL.md").write_text(
        '---\nname: fixture\ndescription: "Fixture pack: header parsing and cache semantics."\n---\n'
        "# Fixture pack\n\n## When to use\nParsing quirks and cache-key mismatches.\n")
    (root / "proof.txt").write_text("HTTP 200 observed with title Example Domain\n")
    cp = ControlPlane(root)
    cp.register_evidence("proof.txt", kind="raw", source="test")
    cp.create_cycle("C-0001", {
        "id": "C-0001", "type": "DISCOVERY", "objective": "header parsing behavior",
        "allowed_scope": ["example.test"], "stop_conditions": ["stop"], "controls": [],
        "status": "PLANNED",
        "knowledge_triage": [{"pack": "fixture", "verdict": "USE",
                              "reason": "fixture pack covers the honesty seam"}]})
    cdir = root / "04_cycles" / "C-0001"
    (cdir / "results.md").write_text(
        "# Cycle Results\n\n## Disposition\nNEGATIVE\n\n"
        "## Instrument validation\nControl fires; negative control clean.\n\n"
        "## Interpretation\nThe malformed header was rejected with a generic error; the "
        "cache key ignores the header, so no poisoning primitive was observed.\n\n"
        "## Evidence references\nE-000001\n")
    cp.evaluate_technique({
        "cycle_id": "C-0001", "result": "NEGATIVE",
        "technique_family": "fixture", "interpretation": "header parsing rejected",
        "learning": "cache key ignores the header", "evidence_refs": ["E-000001"],
        "knowledge_packs": ["fixture"],
    })
    return root, cp


ALLOWED, cp = workspace()
DENIED, _ = workspace('external_judgment: "DENIED"\n')

check("cited_packs reads the cycle's TECHNIQUE_EVALUATED knowledge_packs",
      cited_packs(ALLOWED, "C-0001") == ["fixture"]
      and cited_packs(ALLOWED, "C-9999") == [])

# 1. Gate.
denied_calls: list = []
denied = check_knowledge_use(DENIED, "C-0001", client=lambda s, q: denied_calls.append(s) or {})
check("the DENIED policy returns unavailable and never calls the client",
      denied["source"] == "unavailable" and denied["warnings"] == []
      and denied_calls == [])
check("live=False returns unavailable",
      check_knowledge_use(ALLOWED, "C-0001", live=False,
                          client=lambda s, q: {})["source"] == "unavailable")

# 2. Per-pack question; low score warns, high score stays quiet.
calls: list = []


def honesty_client(score: float):
    def client(state, questions):
        calls.append((state, questions))
        return {"model": "stub-honesty",
                "answers": {name: {"type": "noul", "noul": score} for name in questions},
                "usage": {"input_tokens": 25, "output_tokens": 2}}
    return client


decorative = check_knowledge_use(ALLOWED, "C-0001", client=honesty_client(0.2))
check("a below-threshold use score is an advisory warning naming the pack",
      decorative["source"] == "typesafe" and decorative["warnings"]
      and decorative["warnings"][0]["pack"] == "fixture"
      and decorative["warnings"][0]["score"] == 0.2
      and decorative["advisory"] is True)
check("the question carries the cycle outputs and the pack guide",
      calls and "cache key" in calls[0][0]["cycle_outputs"]
      and "cache semantics" in calls[0][0]["pack_guide_fixture"]
      and set(calls[0][1]) == {"use_fixture"})
honest = check_knowledge_use(ALLOWED, "C-0001", client=honesty_client(0.9))
check("a high use score produces no warning", honest["warnings"] == []
      and honest["checked"][0]["pack"] == "fixture")
egress: dict = {}


def redaction_client(state, questions):
    egress.update(state)
    return honesty_client(0.9)(state, questions)


check_knowledge_use(ALLOWED, "C-0001", client=redaction_client,
                    cycle_outputs="the token glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
                                  "appeared in the response header",
                    packs=["fixture"], guides={"fixture": "cache semantics"})
check("cycle outputs are redacted before egress",
      "[REDACTED]" in egress["cycle_outputs"] and "glpat-" not in egress["cycle_outputs"])

# 3. Never a fail: the audit's exit code and error count are unchanged by the check.
def audit_run() -> tuple[int, int]:
    proc = subprocess.run([sys.executable, str(TOOLS / "audit.py"), str(ALLOWED)],
                          capture_output=True, text=True)
    errors = sum(1 for line in (proc.stdout + proc.stderr).splitlines()
                 if line.strip().lower().startswith("error"))
    return proc.returncode, errors


before_exit, before_errors = audit_run()
check_knowledge_use(ALLOWED, "C-0001", client=honesty_client(0.1))
after_exit, after_errors = audit_run()
check("the advisory adds no audit error and never changes the audit verdict",
      (before_exit, before_errors) == (after_exit, after_errors))

# 4. Advisory only + cost ledger.
events_before = len(ControlPlane(ALLOWED)._read_events())
check_knowledge_use(ALLOWED, "C-0001", client=honesty_client(0.1))
check("the check writes no lifecycle event (advisory only)",
      len(ControlPlane(ALLOWED)._read_events()) == events_before)
check("the check ledgers its usage as an estimated cost row",
      any(r["decision"] == "honesty" and r["estimated"] for r in cost_rows(ALLOWED)))

# 6. v8.3 fix: each pack judgment is a replayable record (input snapshot + digest,
#    endpoint, posture); replay re-runs the use question offline.
from ts_claims import read_judgments  # noqa: E402
from ts_honesty import replay_honesty  # noqa: E402

rp_root, rp_cp = workspace()
rp_out = check_knowledge_use(rp_root, "C-0001", client=honesty_client(0.2))
rp_rows = read_judgments(rp_root, seam="honesty")
check("the pack judgment is recorded with input digest, endpoint and posture",
      len(rp_rows) == 1 and len(rp_rows[0]["input_digest"]) == 64
      and rp_rows[0]["endpoint"] == "https://api.typesafe.ai/v1/systemone"
      and rp_rows[0]["posture"] == "on" and rp_rows[0]["verdict"] == "warning"
      and rp_rows[0]["input"]["pack"] == "fixture"
      and "cache key" in rp_rows[0]["input"]["cycle_outputs"])
check("the honesty result carries the posture and the endpoint",
      rp_out["posture"] == "on"
      and rp_out["endpoint"] == "https://api.typesafe.ai/v1/systemone")
rp_replay = replay_honesty(rp_root, client=honesty_client(0.2))
check("replay reproduces the honesty warning decision deterministically",
      rp_replay["replayed"] == 1 and rp_replay["matched"] == 1
      and rp_replay["mismatched"] == 0 and rp_replay["drifted"] == 0)
check("replay with a flipped score argues the mismatch",
      replay_honesty(rp_root, client=honesty_client(0.9))["mismatched"] == 1)
rp_denied, _ = workspace('external_judgment: "DENIED"\n')
check_knowledge_use(rp_denied, "C-0001", client=honesty_client(0.2))
check("a DENIED seam writes no judgment record (nothing was judged)",
      read_judgments(rp_denied, seam="honesty") == [])

# 5. CLI wiring: `researchctl knowledge honesty --cycle C-0001`.
import contextlib  # noqa: E402
import io  # noqa: E402
from researchctl import main as ctl_main  # noqa: E402


def cli_post(payload, **kwargs):
    return {"model": "stub-honesty",
            "answers": {name: {"type": "noul", "noul": 0.3} for name in payload["questions"]},
            "usage": {"input_tokens": 6, "output_tokens": 1}}


with mock.patch("ts_honesty.post_json", cli_post), \
        mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "k"}):
    buf = io.StringIO()
    err = io.StringIO()
    with mock.patch.object(sys, "argv", [str(TOOLS / "researchctl.py"), str(ALLOWED),
                                         "knowledge", "honesty", "--cycle", "C-0001"]), \
            contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
        rc_honesty = ctl_main()
cli_out = json.loads(buf.getvalue())
check("researchctl knowledge honesty prints the advisory warnings",
      rc_honesty == 0 and cli_out["warnings"][0]["pack"] == "fixture"
      and "warning" in err.getvalue().lower())

print(f"\n{len(passed)}/{len(passed)} passed")
