#!/usr/bin/env python3
"""v8.3 V6c (T5): technique-outcome labeling — per-field questions compile the
technique-result schema over the cycle transcript into a payload DRAFT; the controller
confirms before recording (a draft can never reach `evaluate_technique`), and the human
still closes the cycle.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from control_plane import ControlPlane  # noqa: E402
from ts_cost import cost_rows  # noqa: E402
from ts_label import DRAFT_MARKER, draft_technique_payload  # noqa: E402

passed: list[str] = []


def check(name: str, cond: bool):
    assert cond, f"FAIL: {name}"
    passed.append(name)
    print(f"ok: {name}")


def workspace(policy: str = 'external_judgment: "ALLOWED"\n') -> tuple[Path, ControlPlane]:
    root = Path(tempfile.mkdtemp())
    for d in ["00_control", "02_surface", "04_cycles", "10_learning", "11_runtime",
              "12_knowledge/fixture"]:
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / "00_control/engagement.yaml").write_text(policy)
    (root / "02_surface/endpoints.yaml").write_text("endpoints: []\n")
    (root / "11_runtime/events.jsonl").write_text("")
    (root / "12_knowledge/fixture/fixture.md").write_text("# Fixture pack\n")
    (root / "12_knowledge/INDEX.yaml").write_text(
        "packs:\n  fixture:\n    load_when: [label, fixture]\n    files: [fixture.md]\n")
    (root / "proof.txt").write_text("HTTP 200 observed with title Example Domain\n")
    cp = ControlPlane(root)
    cp.register_evidence("proof.txt", kind="raw", source="test")
    cp.create_cycle("C-0001", {
        "id": "C-0001", "type": "VALIDATION", "objective": "does the filter hold",
        "allowed_scope": ["example.test"], "stop_conditions": ["stop"], "controls": [],
        "status": "PLANNED",
        "knowledge_triage": [{"pack": "fixture", "verdict": "USE",
                              "reason": "fixture pack covers the labeling seam"}]})
    cdir = root / "04_cycles" / "C-0001"
    (cdir / "results.md").write_text(
        "# Cycle Results\n\n## Disposition\nFALSE_POSITIVE\n\n"
        "## Instrument validation\nControl fires; negative control clean.\n\n"
        "## Interpretation\nThe 403 was a WAF block, not an authorization oracle; "
        "the same request with a different header succeeded, so the filter holds.\n\n"
        "## Evidence references\nE-000001\n")
    return root, cp


ALLOWED, cp = workspace()
DENIED, _ = workspace('external_judgment: "DENIED"\n')

# 1. Gate.
denied_calls: list = []
denied = draft_technique_payload(DENIED, "C-0001",
                                 client=lambda s, q: denied_calls.append(s) or {})
check("the DENIED policy returns unavailable and never calls the client",
      denied["source"] == "unavailable" and denied[DRAFT_MARKER] is None
      and denied_calls == [])
check("live=False returns unavailable",
      draft_technique_payload(ALLOWED, "C-0001", live=False,
                              client=lambda s, q: {})["source"] == "unavailable")

# 2. The draft compiles the schema from per-field questions over the transcript.
calls: list = []


def label_client(state, questions):
    calls.append((state, questions))
    answers = {}
    for name in questions:
        if name == "result":
            answers[name] = {"type": "choice", "choice": "FALSE_POSITIVE", "confidence": 0.93,
                             "probabilities": {"FALSE_POSITIVE": 0.93, "CONFIRMED": 0.04,
                                               "INCONCLUSIVE": 0.03}}
        elif name == "technique_family":
            answers[name] = {"type": "choice", "choice": "fixture", "confidence": 0.9,
                             "probabilities": {"fixture": 0.9, "other": 0.1}}
        else:
            answers[name] = {"type": "noul", "noul": 0.8}
    return {"model": "stub-label", "answers": answers,
            "usage": {"input_tokens": 40, "output_tokens": 4}}


draft = draft_technique_payload(ALLOWED, "C-0001", client=label_client)
check("the draft carries the schema fields compiled from the transcript",
      draft["cycle_id"] == "C-0001" and draft["result"] == "FALSE_POSITIVE"
      and draft["technique_family"] == "fixture" and draft["evidence_refs"] == ["E-000001"])
check("interpretation/learning quote the transcript verbatim (the controller rewrites them)",
      "WAF block" in draft["interpretation"] and draft["learning"]
      and draft[DRAFT_MARKER]["source"] == "cycle transcript")
check("the draft marker says the controller must confirm before recording",
      "confirm" in draft[DRAFT_MARKER]["note"].lower() and DRAFT_MARKER in draft)
check("the per-field questions cover result, technique_family and the learning check",
      set(calls[0][1]) == {"result", "technique_family", "has_learning"}
      and "transcript" in calls[0][0])

# 3. A draft can never be recorded: evaluate_technique refuses it.
try:
    cp.evaluate_technique(dict(draft))
    refused = None
except ValueError as exc:
    refused = str(exc)
check("evaluate_technique refuses a draft payload (confirm step required)",
      refused is not None and "draft" in refused.lower() and "confirm" in refused.lower())

# 4. The confirm step records it: strip the marker, record, human still closes.
import contextlib  # noqa: E402
import io  # noqa: E402
from researchctl import main as ctl_main  # noqa: E402

draft_file = ALLOWED / "draft.json"
draft_file.write_text(json.dumps(draft))
with mock.patch.object(sys, "argv", [str(TOOLS / "researchctl.py"), str(ALLOWED),
                                     "technique", "confirm", str(draft_file)]), \
        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
    rc_confirm = ctl_main()
events = [e for e in cp._read_events() if e.get("type") == "TECHNIQUE_EVALUATED"]
check("researchctl technique confirm records the confirmed payload exactly once",
      rc_confirm == 0 and len(events) == 1
      and events[0]["payload"]["result"] == "FALSE_POSITIVE"
      and DRAFT_MARKER not in events[0]["payload"])
check("the cycle is not closed by the confirmation (the human still closes)",
      cp.cycle_status("C-0001") == "PLANNED")
check("the draft ran as an aid and ledgered its usage",
      any(r["decision"] == "label" and r["estimated"] for r in cost_rows(ALLOWED)))

# 5. An invalid result choice is rejected, never surfaced as a field value.
def bad_client(state, questions):
    answers = {}
    for name in questions:
        if name == "result":
            answers[name] = {"type": "choice", "choice": "MAYBE", "confidence": 0.99,
                             "probabilities": {"MAYBE": 0.99}}
        elif name == "technique_family":
            answers[name] = {"type": "choice", "choice": "fixture", "confidence": 0.9,
                             "probabilities": {"fixture": 0.9, "other": 0.1}}
        else:
            answers[name] = {"type": "noul", "noul": 0.5}
    return {"model": "stub-label", "answers": answers, "usage": {}}


bad = draft_technique_payload(ALLOWED, "C-0001", client=bad_client)
check("an invalid result choice leaves the field unset with the reason in the draft",
      bad["result"] is None and "rejected" in bad[DRAFT_MARKER]["notes"]["result"])

print(f"\n{len(passed)}/{len(passed)} passed")
