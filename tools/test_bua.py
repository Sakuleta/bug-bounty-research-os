#!/usr/bin/env python3
"""B5: the interactive-plan seam — one Jev fan-out per step, every answer validated.

The interactive arm cannot pick operations itself, so the plan seam is a guard, not a
service: it posts ONE System One call carrying the executor-built Choice space
(operation + per-operation target/text/file/flow/reason labels), validates EVERY answer
through `validate_choice` (simplex ≈ 1, argmax), and returns a typed operation built from
validated labels only. An invalid, missing or policy-denied answer is a re-plan, never a
dispatch. Caps are enforced in code beside the action budgets: per-action and per-cycle
model-call budgets (`RESEARCH_OS_BUA_MAX_MODEL_CALLS_PER_ACTION` /
`_PER_CYCLE`), and every real call lands one `bua-plan` row in the cost ledger.
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
from ts_bua import (DEFAULT_MAX_CALLS_PER_ACTION, PLAN_STATE_REL,  # noqa: E402
                    plan_actions)
from ts_cost import COSTS_REL, cost_rows  # noqa: E402

passed: list[str] = []


def check(name: str, cond: bool):
    assert cond, f"FAIL: {name}"
    passed.append(name)
    print(f"ok: {name}")


def plan_root(*, policy: str = "ALLOWED", budget: bool = True) -> Path:
    root = Path(tempfile.mkdtemp())
    for d in ["00_control", "11_runtime"]:
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / "00_control/engagement.yaml").write_text(
        (f'external_judgment: "{policy}"\n' if policy is not None else "")
        + 'scope:\n  assets:\n  - "example.test"\n'
        + ("budget:\n  max_actions_per_cycle: 20\n  max_actions_per_engagement: 200\n" if budget else ""))
    (root / "11_runtime/events.jsonl").write_text("")
    return root


def plan_request(step: int = 1, action_id: str = "A-000001", cycle_id: str = "C-0001",
                 extra_questions: dict | None = None) -> dict:
    questions = {
        "bua_operation": {"choices": ["CLICK", "TYPE", "NAVIGATE", "DONE", "BLOCKED"],
                          "instructions": "Which single next operation advances the objective?"},
        "bua_target:CLICK": {"choices": ["e1", "e3"]},
        "bua_target:TYPE": {"choices": ["e2"]},
        "bua_target:NAVIGATE": {"choices": ["u0", "u1"]},
        "bua_text": {"choices": ["t1"]},
        "bua_block": {"choices": ["b1", "b2"]},
    }
    questions.update(extra_questions or {})
    return {
        "step": step, "action_id": action_id, "cycle_id": cycle_id,
        "state": {"url": "https://example.test/app", "title": "App", "step": step,
                  "history": [], "elements": [{"handle": "e1", "text": "Sign in"}]},
        "questions": questions,
    }


def choice(name: str, value: str, *, probabilities: dict | None = None) -> dict:
    answer = {"type": "choice", "choice": value, "confidence": 0.9}
    if probabilities is not None:
        answer["probabilities"] = probabilities
    return answer


def simplex(choices: list[str], chosen: str) -> dict:
    """A valid simplex over `choices` with `chosen` at the argmax."""
    others = [c for c in choices if c != chosen]
    rest = round(0.4 / len(others), 6) if others else 0.0
    probs = {c: rest for c in choices}
    probs[chosen] = round(1.0 - rest * len(others), 6)
    return probs


def valid_answers(op: str = "CLICK", target: str | None = None) -> dict:
    """A full answer set for every declared question (the fan-out answers all of them)."""
    targets = {"CLICK": "e1", "TYPE": "e2", "NAVIGATE": "u0"}
    if target is not None and op in targets:
        targets[op] = target
    return {
        "bua_operation": choice("bua_operation", op,
                                probabilities=simplex(
                                    ["CLICK", "TYPE", "NAVIGATE", "DONE", "BLOCKED"], op)),
        "bua_target:CLICK": choice("bua_target:CLICK", targets["CLICK"],
                                   probabilities=simplex(["e1", "e3"], targets["CLICK"])),
        "bua_target:TYPE": choice("bua_target:TYPE", targets["TYPE"],
                                  probabilities=simplex(["e2"], targets["TYPE"])),
        "bua_target:NAVIGATE": choice("bua_target:NAVIGATE", targets["NAVIGATE"],
                                      probabilities=simplex(["u0", "u1"], targets["NAVIGATE"])),
        "bua_text": choice("bua_text", "t1", probabilities={"t1": 1.0}),
        "bua_block": choice("bua_block", "b1", probabilities=simplex(["b1", "b2"], "b1")),
    }


def stub_client(answers: dict, usage: dict | None = None):
    calls = []

    def call(state, questions):
        calls.append({"state": state, "questions": questions})
        return {"model": "stub-bua", "answers": answers,
                "usage": usage or {"input_tokens": 100, "output_tokens": 20}}
    call.calls = calls
    return call


# ---- the gate: policy DENIED (default) means no call and no dispatch -----------------
root = plan_root(policy=None)
client = stub_client(valid_answers())
out = plan_actions(root, plan_request(), client=client)
check("B5 gate: a policy-less engagement denies the plan (no network call)",
      out["source"] == "denied" and out["operation"] is None and len(client.calls) == 0)
check("B5 gate: the denial names the policy", "external judgment denied" in out["note"])
check("B5 gate: a denied plan ledgers no cost row", cost_rows(root) == [])
check("B5 gate: a denied plan never reports a dispatchable operation", out["ok"] is False)

root = plan_root()
out = plan_actions(root, plan_request(), live=False)
check("B5 gate: live=False reports unavailable without a call",
      out["source"] == "unavailable" and out["operation"] is None)

# ---- one fan-out round trip, every answer validated ---------------------------------
root = plan_root()
client = stub_client(valid_answers())
with mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "test-key"}):
    out = plan_actions(root, plan_request(), client=client)
check("B5 fan-out: one call carries every question of the step",
      len(client.calls) == 1 and len(client.calls[0]["questions"]) == 6)
check("B5 fan-out: every question is a Choice over the executor's labels",
      all(q["type"] == "choice" and q["choices"] for q in client.calls[0]["questions"].values()))
check("B5 fan-out: the validated operation is returned as labels (no selectors, no URLs)",
      out["ok"] is True and out["operation"] == {"op": "CLICK", "labels": {"target": "e1"}})
check("B5 fan-out: the model is named on the result", out["model"] == "stub-bua")
check("B5 fan-out: the usage rides the result for the cost ledger",
      out["usage"]["input_tokens"] == 100)
rows = cost_rows(root)
check("B5 cost: one bua-plan row lands with usd/estimated/source",
      len(rows) == 1 and rows[0]["decision"] == "bua-plan" and rows[0]["estimated"] is True
      and rows[0]["usd"] > 0 and "estimated" in rows[0]["source"])
check("B5 cost: the row keeps estimated and measured apart", rows[0]["estimated"] is True)

# A TYPE plan carries both the target and the text label.
root = plan_root()
client = stub_client(valid_answers(op="TYPE", target="e2"))
with mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "test-key"}):
    out = plan_actions(root, plan_request(), client=client)
check("B5 fan-out: a TYPE plan resolves target + text labels",
      out["operation"] == {"op": "TYPE", "labels": {"target": "e2", "text": "t1"}})

# ---- invalid answers are re-plans, never dispatches ---------------------------------
root = plan_root()
client = stub_client({**valid_answers(), "bua_operation": choice("bua_operation", "EVALUATE")})
with mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "test-key"}):
    out = plan_actions(root, plan_request(), client=client)
check("B5 validate: an operation outside the offered choices is rejected",
      out["ok"] is False and out["source"] == "invalid_choice"
      and "not one of" in out["reason"])
check("B5 validate: the rejected answer is never returned as an operation", out["operation"] is None)
check("B5 validate: the spent call still lands a cost row (the tokens were real)",
      len(cost_rows(root)) == 1)

root = plan_root()
bad_target = valid_answers()
bad_target["bua_target:CLICK"] = choice("bua_target:CLICK", "e3",
                                        probabilities={"e1": 0.9, "e3": 0.1})
client = stub_client(bad_target)
with mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "test-key"}):
    out = plan_actions(root, plan_request(), client=client)
check("B5 validate: a target that is not the argmax is rejected",
      out["ok"] is False and out["source"] == "invalid_choice" and "argmax" in out["reason"])

root = plan_root()
bad_simplex = valid_answers()
bad_simplex["bua_target:CLICK"] = choice("bua_target:CLICK", "e3",
                                         probabilities={"e1": 0.2, "e3": 0.3})
client = stub_client(bad_simplex)
with mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "test-key"}):
    out = plan_actions(root, plan_request(), client=client)
check("B5 validate: a probability simplex that does not sum to 1 is rejected",
      out["ok"] is False and "simplex" in out["reason"])

root = plan_root()
partial = valid_answers()
partial.pop("bua_target:NAVIGATE")
client = stub_client(partial)
with mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "test-key"}):
    out = plan_actions(root, plan_request(), client=client)
check("B5 validate: a missing answer for a declared question is rejected (never assumed)",
      out["ok"] is False and out["source"] == "invalid_choice"
      and "no answer" in out["reason"])

root = plan_root()
client = stub_client(valid_answers())
client_missing = stub_client(None)
with mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "test-key"}):
    out = plan_actions(root, plan_request(), client=client_missing)
check("B5 validate: a response without answers is rejected, never dispatched",
      out["ok"] is False and out["source"] == "invalid_choice")

# ---- caps: per-action and per-cycle model-call budgets ------------------------------
root = plan_root()
client = stub_client(valid_answers())
with mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "test-key",
                                  "RESEARCH_OS_BUA_MAX_MODEL_CALLS_PER_ACTION": "2"}):
    first = plan_actions(root, plan_request(step=1), client=client)
    second = plan_actions(root, plan_request(step=2), client=client)
    third = plan_actions(root, plan_request(step=3), client=client)
check("B5 cap: calls up to the per-action cap are allowed",
      first["ok"] and second["ok"] and len(client.calls) == 2)
check("B5 cap: the call past the per-action cap is refused without a network call",
      third["ok"] is False and third["source"] == "cap_reached"
      and len(client.calls) == 2 and "per-action" in third["reason"])
check("B5 cap: the cap state is durable across calls",
      json.loads((root / PLAN_STATE_REL).read_text())["actions"]["A-000001"]["calls"] == 2)
check("B5 cap: the default per-action cap is a named constant", DEFAULT_MAX_CALLS_PER_ACTION >= 1)

root = plan_root()
client = stub_client(valid_answers())
with mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "test-key",
                                  "RESEARCH_OS_BUA_MAX_MODEL_CALLS_PER_CYCLE": "2"}):
    plan_actions(root, plan_request(step=1, action_id="A-000001"), client=client)
    plan_actions(root, plan_request(step=2, action_id="A-000002"), client=client)
    capped = plan_actions(root, plan_request(step=3, action_id="A-000003"), client=client)
check("B5 cap: the per-cycle cap refuses the third call across actions",
      capped["source"] == "cap_reached" and len(client.calls) == 2
      and "per-cycle" in capped["reason"])

# ---- the request the executor sends is the whole model space ------------------------
root = plan_root()
client = stub_client(valid_answers())
with mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "test-key"}):
    plan_actions(root, plan_request(), client=client)
sent = json.dumps(client.calls[0]["state"])
check("B5 request: the state carries the snapshot elements, not selectors or coordinates",
      "elements" in sent and "Sign in" in sent and "selector" not in sent)

root = plan_root()
secret_state = plan_request()
secret_state["state"]["title"] = "token glpat-ABCDEFGHIJKLMNOPQRST"
client = stub_client(valid_answers())
with mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "test-key"}):
    plan_actions(root, secret_state, client=client)
check("B5 request: a secret-shaped value in the state never reaches the model",
      "glpat-ABCDEFGHIJKLMNOPQRST" not in json.dumps(client.calls[0]["state"]))

root = plan_root()
client = stub_client(valid_answers())
with mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "test-key"}):
    bad_request = plan_actions(root, {**plan_request(), "questions": {}}, client=client)
check("B5 request: a request without an operation question is refused, never called",
      bad_request["source"] == "invalid_request" and len(client.calls) == 0)

root = plan_root()
client = stub_client(valid_answers())
with mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "test-key"}):
    bad_labels = plan_actions(root, plan_request(extra_questions={
        "bua_target:CLICK": {"choices": ["#submit", "javascript:alert(1)"]},
    }), client=client)
check("B5 request: a choice label that is not an executor label is refused, never called",
      bad_labels["source"] == "invalid_request" and len(client.calls) == 0)

root = plan_root()
client = stub_client(valid_answers())
with mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "test-key"}):
    too_many = plan_actions(root, plan_request(extra_questions={
        "bua_target:CLICK": {"choices": [f"e{i}" for i in range(1, 200)]},
    }), client=client)
check("B5 request: an over-wide choice space is refused, never called",
      too_many["source"] == "invalid_request" and len(client.calls) == 0)

# ---- the CLI seam the interactive arm calls ----------------------------------------
root = plan_root(policy=None)
(req_file := root / "plan-request.json").write_text(json.dumps(plan_request()))
sub = subprocess.run([sys.executable, str(TOOLS / "researchctl.py"), str(root),
                      "bua-plan", str(req_file)], capture_output=True, text=True,
                     env={**os.environ, "TYPESAFE_API_KEY": ""})
out = json.loads(sub.stdout)
check("B5 CLI: bua-plan answers JSON and denies without a policy (exit 0, no dispatch)",
      sub.returncode == 0 and out["source"] == "denied" and out["operation"] is None)

print(f"\n{len(passed)} checks passed")
