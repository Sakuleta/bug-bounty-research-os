#!/usr/bin/env python3
"""Interactive-plan seam: ONE Jev fan-out per step, every answer validated.

The interactive arm (`tools/bua/interactive.mjs`) never lets a model choose an element
directly. It sends this seam an executor-built Choice space — one `bua_operation`
question plus, per operation, the target/text/file/flow/reason labels the executor is
willing to act on — and this seam:

- consults the engagement's `external_judgment` policy first (DENIED default: no network
  call, no dispatch);
- posts ONE System One call carrying every question (the documented fan-out shape, the
  same one `ts_ground` uses) and nothing the executor did not build;
- validates EVERY answer through `validate_choice` (simplex ≈ 1, argmax, v8.3 strict) and
  requires a strict probability simplex on every answer in this seam (an answer without
  one is a re-plan — `ts_http`'s global contract is untouched), then maps the validated
  labels to a typed operation — an invalid, missing or extra answer is a re-plan, never a
  dispatch;
- enforces per-action and per-cycle model-call caps in code, beside the action budgets
  (dollars never relax action capacity), from a small state file;
- ledgers one `bua-plan` cost row per real call (`{usd, estimated, source}`).

Nothing here records lifecycle state, names a finding or decides a test outcome.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from control_plane import external_judgment_allowed, redact  # noqa: E402
from ts_cost import record_seam_cost  # noqa: E402
from ts_http import API, model_name, post_json, validate_choice  # noqa: E402

PLAN_STATE_REL = "11_runtime/bua-plan-state.json"
POLICY_NOTE = "external judgment denied by engagement policy"
NO_KEY_NOTE = "no TYPESAFE_API_KEY (or live=False): no plan was produced"
DEFAULT_MAX_CALLS_PER_ACTION = 3
DEFAULT_MAX_CALLS_PER_CYCLE = 48
OPERATIONS = ("CLICK", "TYPE", "SELECT", "NAVIGATE", "UPLOAD", "LOGIN", "DONE", "BLOCKED")
TARGET_QUESTION = {"CLICK": "bua_target:CLICK", "TYPE": "bua_target:TYPE",
                   "SELECT": "bua_target:SELECT", "NAVIGATE": "bua_target:NAVIGATE",
                   "UPLOAD": "bua_target:UPLOAD"}
REQUIRED_LABELS = {"CLICK": ("target",), "TYPE": ("target", "text"),
                   "SELECT": ("target",), "NAVIGATE": ("target",),
                   "UPLOAD": ("target", "file"), "LOGIN": ("flow",), "BLOCKED": ("reason",),
                   "DONE": ()}
ROLE_QUESTION = {"text": "bua_text", "file": "bua_file", "flow": "bua_flow",
                 "reason": "bua_block"}
# The model space is executor-built: question names and labels are closed vocabularies, so
# a request can never smuggle a selector, URL, coordinate or free text into the questions.
QUESTION_RE = re.compile(r"^bua_(operation|target:[A-Z]+|text|file|flow|block)$")
LABEL_RE = re.compile(r"^[A-Za-z0-9_:.=-]{1,64}$")
MAX_QUESTIONS = 12
MAX_CHOICES = 64
MAX_STATE_CHARS = 24000
MAX_HISTORY = 20
MAX_ELEMENTS = 60
MAX_QUESTION_INSTRUCTIONS = 600


def _cap(env: str, default: int) -> int:
    raw = os.environ.get(env, "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return value if value >= 0 else default


def _load_state(root: Path) -> dict[str, Any]:
    path = root / PLAN_STATE_REL
    state: dict[str, Any] = {"actions": {}, "cycles": {}}
    if not path.is_file():
        return state
    try:
        loaded = json.loads(path.read_text(errors="ignore"))
    except (OSError, json.JSONDecodeError):
        # A garbled counter must not fail open: it reads as no calls made, which only ever
        # means MORE headroom — so refuse instead of guessing.
        return {"actions": {}, "cycles": {}, "garbled": True}
    if not isinstance(loaded, dict):
        return {"actions": {}, "cycles": {}, "garbled": True}
    for key in ("actions", "cycles"):
        bucket = loaded.get(key)
        if isinstance(bucket, dict):
            state[key] = {str(k): v for k, v in bucket.items() if isinstance(v, dict)}
    return state


def _save_state(root: Path, state: dict[str, Any]) -> None:
    path = root / PLAN_STATE_REL
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, ensure_ascii=False, sort_keys=True) + "\n")


def _calls(state: dict[str, Any], bucket: str, key: str) -> int:
    record = state.get(bucket, {}).get(key) or {}
    value = record.get("calls")
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _clean_questions(raw: Any) -> tuple[dict[str, dict[str, Any]] | None, str]:
    """The declared question space, or the reason the request is not one."""
    if not isinstance(raw, dict) or not raw:
        return None, "the plan request carries no questions"
    if len(raw) > MAX_QUESTIONS:
        return None, f"the plan request carries more than {MAX_QUESTIONS} questions"
    if "bua_operation" not in raw:
        return None, "the plan request needs a bua_operation question"
    cleaned: dict[str, dict[str, Any]] = {}
    for name, spec in raw.items():
        name = str(name)
        if not QUESTION_RE.match(name):
            return None, f"question {name!r} is not an executor question name"
        if not isinstance(spec, dict):
            return None, f"question {name!r} is not an object"
        choices = spec.get("choices")
        if (not isinstance(choices, list) or not choices or len(choices) > MAX_CHOICES
                or not all(isinstance(c, str) and LABEL_RE.match(c) for c in choices)
                or len(set(choices)) != len(choices)):
            return None, (f"question {name!r} needs 1..{MAX_CHOICES} unique executor "
                          "labels (letters, digits, _ : . = -)")
        instructions = spec.get("instructions")
        cleaned[name] = {
            "choices": [str(c) for c in choices],
            "instructions": (str(instructions)[:MAX_QUESTION_INSTRUCTIONS]
                             if isinstance(instructions, str) else ""),
        }
    op_choices = cleaned["bua_operation"]["choices"]
    unknown = [op for op in op_choices if op not in OPERATIONS]
    if unknown:
        return None, f"bua_operation offers unknown operations: {', '.join(unknown)}"
    for op, question in TARGET_QUESTION.items():
        if question in cleaned and op not in op_choices:
            return None, f"question {question!r} is offered for an operation that is not offered"
    return cleaned, ""


def _model_state(raw: Any) -> dict[str, Any]:
    """The state the model may see: redacted, bounded, closed to unknown keys."""
    state = raw if isinstance(raw, dict) else {}
    history = state.get("history")
    elements = state.get("elements")
    payload = {
        "url": str(state.get("url") or ""),
        "title": str(state.get("title") or "")[:200],
        "step": state.get("step"),
        "history": (history[-MAX_HISTORY:] if isinstance(history, list) else []),
        "elements": (elements[:MAX_ELEMENTS] if isinstance(elements, list) else []),
    }
    redacted = redact(payload)
    text = json.dumps(redacted, ensure_ascii=False, sort_keys=True)
    if len(text) > MAX_STATE_CHARS:
        # Bounded, never truncated mid-structure: drop the history first, then the tail of
        # the element list, and say so.
        redacted["history"] = []
        redacted["elements"] = redacted["elements"][:MAX_ELEMENTS // 2]
        redacted["truncated"] = True
    return redacted


def _plan_from_answers(answers: Any, questions: dict[str, dict[str, Any]]
                       ) -> tuple[dict[str, Any] | None, str]:
    """Map validated answers to a typed operation; (None, reason) when anything is off.

    The bua-plan seam requires STRICT simplex answers: `validate_choice` alone accepts
    an answer that carries no probability map (the IDF/unavailable shape), but this seam
    only ever talks to the System One fan-out, which must supply a simplex over the
    offered choices — an answer without one is a re-plan, never a dispatch. This is
    deliberately seam-scoped: `ts_http.validate_choice` keeps its global contract (v8.3
    shapes depend on it).
    """
    if not isinstance(answers, dict):
        return None, "the model returned no answers"
    for name, spec in questions.items():
        answer = answers.get(name)
        if answer is None:
            return None, f"question {name!r} has no answer — a partial answer set is not a plan"
        problem = validate_choice(answer, spec["choices"])
        if problem:
            return None, f"question {name!r}: {problem}"
        probabilities = answer.get("probabilities") if isinstance(answer, dict) else None
        if not isinstance(probabilities, dict) or not probabilities:
            return None, (f"question {name!r}: the bua-plan seam requires a strict probability "
                          "simplex over the offered choices — an answer without probabilities "
                          "is not evidence, so it is a re-plan")
    op = str(answers["bua_operation"]["choice"])
    labels: dict[str, str] = {}
    for role in REQUIRED_LABELS[op]:
        question = (TARGET_QUESTION[op] if role == "target" else ROLE_QUESTION[role])
        if question not in questions:
            return None, f"operation {op} needs question {question!r}, which the executor did not offer"
        labels[role] = str(answers[question]["choice"])
    return {"op": op, "labels": labels}, ""


def _unavailable(note: str, source: str, posture: str) -> dict[str, Any]:
    return {"ok": False, "source": source, "operation": None, "reason": note, "note": note,
            "model": None, "usage": {}, "posture": posture, "endpoint": API}


def plan_actions(root: Path, request: Any, *, client=None, live: bool = True,
                 timeout: int = 60) -> dict[str, Any]:
    """One validated plan for one interactive step (see the module docstring).

    `client` injects a callable (state, questions) -> response for tests; `live=False`
    forces the unavailable posture. Every refusal shape carries `ok: false` and no
    operation, so the caller re-plans or blocks — it can never dispatch on a refusal.
    """
    root = Path(root)
    request = request if isinstance(request, dict) else {}
    questions, problem = _clean_questions(request.get("questions"))
    if questions is None:
        return {"ok": False, "source": "invalid_request", "operation": None, "reason": problem,
                "note": problem, "model": None, "usage": {}, "posture": "invalid",
                "endpoint": API}
    if not live:
        return _unavailable(NO_KEY_NOTE, "unavailable", "off: live=False")
    if not external_judgment_allowed(root):
        return _unavailable(POLICY_NOTE, "denied", "off: external judgment denied")
    if client is None and not os.environ.get("TYPESAFE_API_KEY"):
        return _unavailable(NO_KEY_NOTE, "unavailable", "off: no key")

    action_id = str(request.get("action_id") or "")
    cycle_id = str(request.get("cycle_id") or "")
    state = _load_state(root)
    if state.get("garbled"):
        return {"ok": False, "source": "cap_reached", "operation": None,
                "reason": f"{PLAN_STATE_REL} is unreadable — refusing to plan with an "
                          "unknown model-call count",
                "note": "garbled cap state", "model": None, "usage": {}, "posture": "allowed",
                "endpoint": API}
    cap_action = _cap("RESEARCH_OS_BUA_MAX_MODEL_CALLS_PER_ACTION", DEFAULT_MAX_CALLS_PER_ACTION)
    cap_cycle = _cap("RESEARCH_OS_BUA_MAX_MODEL_CALLS_PER_CYCLE", DEFAULT_MAX_CALLS_PER_CYCLE)
    if action_id and _calls(state, "actions", action_id) >= cap_action:
        return {"ok": False, "source": "cap_reached", "operation": None,
                "reason": (f"per-action model-call cap reached for {action_id} "
                           f"({cap_action}) — re-plan is refused, no dispatch"),
                "note": "per-action cap", "model": None, "usage": {}, "posture": "allowed",
                "endpoint": API}
    if cycle_id and _calls(state, "cycles", cycle_id) >= cap_cycle:
        return {"ok": False, "source": "cap_reached", "operation": None,
                "reason": (f"per-cycle model-call cap reached for {cycle_id} ({cap_cycle}) — "
                           "raise RESEARCH_OS_BUA_MAX_MODEL_CALLS_PER_CYCLE or start a new cycle"),
                "note": "per-cycle cap", "model": None, "usage": {}, "posture": "allowed",
                "endpoint": API}
    # Count the attempt before the call: a crash mid-call still spent the model call.
    if action_id:
        state["actions"].setdefault(action_id, {})["calls"] = _calls(state, "actions", action_id) + 1
    if cycle_id:
        state["cycles"].setdefault(cycle_id, {})["calls"] = _calls(state, "cycles", cycle_id) + 1
    _save_state(root, state)

    call = client or (lambda s, q: post_json(
        {"state": s, "model": model_name(), "questions": q},
        api_key=os.environ.get("TYPESAFE_API_KEY", ""), timeout=timeout))
    response = call(_model_state(request.get("state")), {
        name: {"type": "choice", "instructions": spec["instructions"], "choices": spec["choices"]}
        for name, spec in questions.items()
    })
    response = response if isinstance(response, dict) else {}
    answers = response.get("answers")
    operation, problem = _plan_from_answers(answers, questions)
    out: dict[str, Any] = {
        "ok": operation is not None,
        "source": "typesafe" if operation is not None else "invalid_choice",
        "operation": operation,
        "reason": problem or None,
        "model": response.get("model"),
        "usage": response.get("usage") if isinstance(response.get("usage"), dict) else {},
        "posture": "allowed", "endpoint": API, "step": request.get("step"),
    }
    # Tokens were really spent whether or not the answer survived validation.
    record_seam_cost(root, decision="bua-plan", out=out, cycle_id=cycle_id or None)
    return out
