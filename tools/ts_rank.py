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
from ts_claims import (API, judgment_posture, judgment_record,  # noqa: E402
                       try_record_judgments, verified_records)
from ts_cost import record_seam_cost  # noqa: E402
from ts_http import model_name, post_json  # noqa: E402

INFO_THRESHOLD = 0.6
ESCALATE_MARGIN = 0.15
TEXT_CAP = 6000
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


def _unavailable(note: str, posture: str) -> dict[str, Any]:
    """The unavailable shape carries the endpoint and posture too (never a silent
    default), so a reader can tell what was attempted."""
    return {"source": "unavailable", "ranking": [], "pick": None, "escalate": True,
            "reason": note, "vetoed": [], "vetoed_reasons": {}, "advisory": True,
            "model": None, "usage": {}, "note": note,
            "posture": posture, "endpoint": API}


def _bounded(text: Any) -> str:
    """The egress/record copy of a hypothesis text: redacted, then capped (the same
    minimization discipline as the other seams)."""
    safe = redact(str(text or ""))
    if len(safe) > TEXT_CAP:
        safe = safe[:TEXT_CAP] + f"\n…[truncated {len(safe) - TEXT_CAP} chars]"
    return safe


def _rank_questions(count: int) -> dict[str, dict]:
    """The one info battery shape over `hypothesis_1..N` (shared with the replay)."""
    return {
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
        for i in range(1, count + 1)
    }


def _rank_decision(answers: Any, entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Code-side ranking decision — the veto, the validated scores and the deterministic
    pick/escalate rules. Shared by the seam and its replay so both apply one guard."""
    answers = answers if isinstance(answers, dict) else {}
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
    return {"ranking": ranking, "pick": pick, "escalate": escalate, "reason": reason,
            "vetoed": vetoed, "vetoed_reasons": vetoed_reasons}


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
    if not live:
        return _unavailable(NO_KEY_NOTE, "off: live=False")
    if not external_judgment_allowed(root):
        return _unavailable(POLICY_NOTE, "off: external judgment denied")
    if client is None and not os.environ.get("TYPESAFE_API_KEY"):
        return _unavailable(NO_KEY_NOTE, judgment_posture(root))
    if hypotheses is not None:
        entries = [{"id": str(h.get("id")), "text": str(h.get("text") or ""),
                    "status": str(h.get("status") or "CANDIDATE"),
                    "payload": dict(h.get("payload") or h)}
                   for h in hypotheses]
    else:
        entries = open_hypotheses(root)
    if not entries:
        return {**_unavailable("no open hypotheses to rank", judgment_posture(root)),
                "escalate": False}
    cycle = ControlPlane(root)
    resolved_question = question
    if resolved_question is None and cycle_id:
        resolved_question = str((cycle.cycle_data(cycle_id) or {}).get("objective") or "")
    # One egress/record copy per hypothesis: redacted + capped, used by the model state
    # and the replayable judgment record alike.
    recorded_hypotheses = [
        {"id": entry["id"], "text": _bounded(entry["text"]),
         "status": entry["status"],
         "side_effect_risk": str((entry.get("payload") or {}).get("side_effect_risk") or "")}
        for entry in entries]
    state = {"question": resolved_question or "the current cycle question",
             "hypotheses": {f"hypothesis_{i}": {"id": h["id"], "text": h["text"]}
                            for i, h in enumerate(recorded_hypotheses, 1)}}
    questions = _rank_questions(len(entries))
    call = client or (lambda s, q: post_json(
        {"state": s, "model": model_name(), "questions": q},
        api_key=os.environ.get("TYPESAFE_API_KEY", ""), timeout=timeout))
    posture = judgment_posture(root, live=live)
    started = time.monotonic()
    resp = call(state, questions)
    decision = _rank_decision(
        (resp.get("answers") if isinstance(resp, dict) else None), entries)
    ranking = decision["ranking"]
    top_info = ranking[0]["info"] if ranking and ranking[0]["safe"] else None
    out = {"source": "typesafe", "ranking": ranking, "pick": decision["pick"],
           "escalate": decision["escalate"], "reason": decision["reason"],
           "vetoed": decision["vetoed"], "vetoed_reasons": decision["vetoed_reasons"],
           "advisory": True, "threshold": INFO_THRESHOLD, "margin": ESCALATE_MARGIN,
           "model": resp.get("model") if isinstance(resp, dict) else None,
           "usage": (resp.get("usage") if isinstance(resp, dict) else None) or {},
           "posture": posture, "endpoint": API, "note": ADVISORY_NOTE}
    out.update(try_record_judgments(root, [judgment_record(
        seam="rank",
        input_payload={"question": resolved_question or "the current cycle question",
                       "hypotheses": recorded_hypotheses,
                       "threshold": INFO_THRESHOLD, "margin": ESCALATE_MARGIN},
        model=out["model"], verdict=out["pick"], confidence=top_info,
        escalate=out["escalate"], posture=posture, cycle_id=cycle_id,
        vetoed=out["vetoed"])]))
    record_seam_cost(root, decision="rank", out=out, cycle_id=cycle_id,
                     latency_ms=int((time.monotonic() - started) * 1000))
    return out


def replay_rank(root: Path, *, client, path: str | Path | None = None) -> dict[str, Any]:
    """Re-run stored ranking judgments offline and compare the pick decision.

    Digest-verified records rebuild the same hypotheses (id, redacted text and
    side-effect risk — the veto inputs) and the same info battery; the mocked answer is
    re-scored through `_rank_decision` and the recomputed pick/escalate is compared with
    the stored ones. Returns {"replayed", "matched", "drifted", "mismatched",
    "mismatches"}.
    """
    records, drifted = verified_records(root, seam="rank", path=path)
    replayed = matched = mismatched = 0
    mismatches: list[dict[str, Any]] = []
    for record in records:
        replayed += 1
        input_payload = record["input"]
        entries = [{"id": str(h.get("id")), "text": str(h.get("text") or ""),
                    "status": str(h.get("status") or "CANDIDATE"),
                    "payload": {"side_effect_risk": h.get("side_effect_risk")}}
                   for h in (input_payload.get("hypotheses") or [])]
        if not entries:
            mismatched += 1
            mismatches.append({"stored": [record.get("verdict"), record.get("escalate")],
                               "replayed": [None, None], "reason": "empty stored input"})
            continue
        state = {"question": input_payload.get("question"),
                 "hypotheses": {f"hypothesis_{i}": {"id": h["id"], "text": h["text"]}
                                for i, h in enumerate(entries, 1)}}
        resp = client(state, _rank_questions(len(entries)))
        decision = _rank_decision(
            (resp.get("answers") if isinstance(resp, dict) else None), entries)
        if (decision["pick"] == record.get("verdict")
                and decision["escalate"] == record.get("escalate")):
            matched += 1
        else:
            mismatched += 1
            mismatches.append({
                "stored": [record.get("verdict"), record.get("escalate")],
                "replayed": [decision["pick"], decision["escalate"]],
            })
    return {"replayed": replayed, "matched": matched, "drifted": drifted,
            "mismatched": mismatched, "mismatches": mismatches}


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
