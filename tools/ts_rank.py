#!/usr/bin/env python3
"""Hypothesis ranking / next-test selection (T4): the SELECT step, mechanized.

One Noul per open hypothesis over the cycle's question ("how much information would
testing this add?"), then code — never the model — applies the safety veto and picks
the highest-information SAFE test. A vetoed hypothesis can never be the pick: the veto
reads the hypothesis payload's `side_effect_risk` and a small destructive-keyword list.
Low-confidence rankings escalate (top score below threshold, or a narrow top-two
margin) instead of pretending to choose; a tie resolves deterministically by id.

Advisory only: this seam writes no lifecycle event and moves no hypothesis — the
controller still selects, and the audit still owns every gate.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from control_plane import ControlPlane, external_judgment_allowed, redact  # noqa: E402
from ts_cost import record_seam_cost  # noqa: E402
from ts_http import model_name, post_json  # noqa: E402

INFO_THRESHOLD = 0.6
ESCALATE_MARGIN = 0.15
POLICY_NOTE = "external judgment denied by engagement policy"
NO_KEY_NOTE = "no TYPESAFE_API_KEY (or live=False): no ranking was produced"
UNSAFE_RISK_VALUES = {"high", "destructive", "critical"}
# The deterministic safety net: a test that would touch these in an engagement context
# is vetoed regardless of its information value (the model never decides safety).
UNSAFE_KEYWORDS = ("delete", "drop table", "wipe", "rm -rf", "format disk", "dos ",
                   "flood", "ransom", "destructive write", "overwrite production")
TERMINAL_STATUSES = {"CLOSED", "VERIFIED", "FALSE_POSITIVE", "NOT_APPLICABLE", "BLOCKED"}
ADVISORY_NOTE = ("advisory: the controller selects; the safety veto and thresholds are "
                 "code, and every escalation stays a human decision")


def open_hypotheses(root: Path) -> list[dict[str, Any]]:
    """Non-terminal hypotheses as `[{id, text, status, payload}]`, in ledger order."""
    cp = ControlPlane(root)
    out: list[dict[str, Any]] = []
    for hid in cp.all_hypothesis_ids():
        status = cp.hypothesis_status(hid)
        if status in TERMINAL_STATUSES or status is None:
            continue
        data = cp.hypothesis_data(hid) or {}
        text = " ".join(str(data.get(key) or "") for key in ("observation", "hypothesis")).strip()
        out.append({"id": hid, "text": text, "status": status, "payload": data})
    return out


def veto_reason(entry: dict[str, Any]) -> str | None:
    """Why this hypothesis is unsafe to run, or None. Deterministic, code-only."""
    risk = str((entry.get("payload") or {}).get("side_effect_risk") or "").strip().lower()
    if risk in UNSAFE_RISK_VALUES:
        return f"side_effect_risk={risk!r} declared on the hypothesis"
    lowered = str(entry.get("text") or "").lower()
    for keyword in UNSAFE_KEYWORDS:
        if keyword in lowered:
            return f"destructive keyword {keyword!r} in the hypothesis text"
    return None


def _unavailable(note: str) -> dict[str, Any]:
    return {"source": "unavailable", "ranking": [], "pick": None, "escalate": True,
            "reason": note, "vetoed": [], "vetoed_reasons": {}, "advisory": True,
            "model": None, "usage": {}, "note": note}


def rank_hypotheses(root: Path, *, client=None, live: bool = True, timeout: int = 60,
                    cycle_id: str | None = None,
                    hypotheses: list[dict[str, Any]] | None = None,
                    question: str | None = None) -> dict[str, Any]:
    """Rank open hypotheses by information value; code picks the safe maximum.

    Returns `{"source", "ranking": [{id, info, safe, status}], "pick", "escalate",
    "reason", "vetoed", "vetoed_reasons", "advisory", "model", "usage"}`. `pick` is
    None whenever the ranking escalates (no safe candidate above `INFO_THRESHOLD`, a
    narrow top-two margin, or an unavailable seam). A caller may pass `hypotheses`
    and/or `question` to rank a scenario without ledger state (the paired eval does).
    """
    root = Path(root)
    if not live or not external_judgment_allowed(root):
        return _unavailable(POLICY_NOTE if live else NO_KEY_NOTE)
    if client is None and not os.environ.get("TYPESAFE_API_KEY"):
        return _unavailable(NO_KEY_NOTE)
    if hypotheses is not None:
        entries = [{"id": str(h.get("id")), "text": str(h.get("text") or ""),
                    "status": str(h.get("status") or "CANDIDATE"),
                    "payload": dict(h.get("payload") or h)}
                   for h in hypotheses]
    else:
        entries = open_hypotheses(root)
    if not entries:
        return {**_unavailable("no open hypotheses to rank"), "escalate": False}
    cycle = ControlPlane(root)
    resolved_question = question
    if resolved_question is None and cycle_id:
        resolved_question = str((cycle.cycle_data(cycle_id) or {}).get("objective") or "")
    state = {"question": resolved_question or "the current cycle question",
             "hypotheses": {f"hypothesis_{i}": {"id": e["id"], "text": redact(str(e["text"]))}
                            for i, e in enumerate(entries, 1)}}
    questions = {
        f"info_{i}": {
            "type": "noul",
            "instructions": (f"How much information would testing `hypothesis_{i}` add for "
                             "`question`? Answer by expected information gain (does the test "
                             "decide something open?), not by how interesting the topic is."),
            "criteria": {
                "true": "Testing it would resolve a real open question with clear signal.",
                "false": "Low information: already answered, cosmetic, or unconnected.",
            },
        }
        for i in range(1, len(entries) + 1)
    }
    call = client or (lambda s, q: post_json(
        {"state": s, "model": model_name(), "questions": q},
        api_key=os.environ.get("TYPESAFE_API_KEY", ""), timeout=timeout))
    started = time.monotonic()
    resp = call(state, questions)
    answers = resp.get("answers") if isinstance(resp.get("answers"), dict) else {}
    ranking: list[dict[str, Any]] = []
    vetoed: list[str] = []
    vetoed_reasons: dict[str, str] = {}
    for i, entry in enumerate(entries, 1):
        reason = veto_reason(entry)
        if reason:
            vetoed.append(entry["id"])
            vetoed_reasons[entry["id"]] = reason
        raw = answers.get(f"info_{i}")
        value = raw.get("noul") if isinstance(raw, dict) else None
        info: float | None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            info = None
        else:
            info = float(value)
            if info != info or info < 0.0 or info > 1.0:
                info = None
        ranking.append({"id": entry["id"], "info": info, "safe": reason is None,
                        "status": entry["status"]})
    ranking.sort(key=lambda row: (-(row["info"] if row["info"] is not None else -1.0),
                                  row["id"]))
    safe_scored = [row for row in ranking if row["safe"] and row["info"] is not None]
    pick: str | None = None
    escalate = False
    reason: str | None = None
    if not safe_scored:
        escalate = True
        reason = ("no safe hypothesis carries a valid score — escalating instead of "
                  "picking a test")
    else:
        top = safe_scored[0]
        if top["info"] < INFO_THRESHOLD:
            escalate = True
            reason = (f"top safe score {top['info']:.2f} below threshold {INFO_THRESHOLD} "
                      "— escalating instead of picking")
        elif len(safe_scored) > 1 and (top["info"] - safe_scored[1]["info"]) < ESCALATE_MARGIN:
            escalate = True
            reason = (f"top-two margin {top['info'] - safe_scored[1]['info']:.2f} below "
                      f"{ESCALATE_MARGIN} — escalating instead of picking")
        else:
            pick = top["id"]
    out = {"source": "typesafe", "ranking": ranking, "pick": pick, "escalate": escalate,
           "reason": reason, "vetoed": vetoed, "vetoed_reasons": vetoed_reasons,
           "advisory": True, "threshold": INFO_THRESHOLD, "margin": ESCALATE_MARGIN,
           "model": resp.get("model"), "usage": resp.get("usage", {}),
           "note": ADVISORY_NOTE}
    record_seam_cost(root, decision="rank", out=out, cycle_id=cycle_id,
                     latency_ms=int((time.monotonic() - started) * 1000))
    return out


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="ts_rank")
    ap.add_argument("root")
    ap.add_argument("--cycle", default=None)
    ns = ap.parse_args()
    print(json.dumps(rank_hypotheses(Path(ns.root), cycle_id=ns.cycle),
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
