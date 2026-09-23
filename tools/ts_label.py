#!/usr/bin/env python3
"""Technique-outcome labeling (T5): compile the technique-result schema into a DRAFT.

Per-field questions over the cycle transcript (capped and redacted) compile a
`TECHNIQUE_EVALUATED` payload draft: a `result` Choice over the canonical outcomes, a
`technique_family` Choice over the cycle's own candidate packs, and a Noul check for a
reusable learning. The draft quotes the transcript verbatim for
`interpretation`/`learning` — the controller rewrites those — and carries a `_draft`
marker that `evaluate_technique` refuses, so a draft can never be recorded as-is: the
explicit confirm step (`researchctl technique confirm`) is the only way in, and the
human still closes the cycle.
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
from control_plane import TECHNIQUE_RESULTS, ControlPlane, external_judgment_allowed, redact  # noqa: E402
from ts_claims import (API, judgment_posture, judgment_record,  # noqa: E402
                       try_record_judgments, verified_records)
from ts_cost import record_seam_cost  # noqa: E402
from ts_http import model_name, post_json, validate_choice  # noqa: E402

DRAFT_MARKER = "_draft"
TRANSCRIPT_CAP = 6000
POLICY_NOTE = "external judgment denied by engagement policy"
NO_KEY_NOTE = "no TYPESAFE_API_KEY (or live=False): no draft was produced"
OTHER_FAMILY = "other"
EVIDENCE_ID = re.compile(r"\bE-\d{6,}\b")


def cycle_transcript(root: Path, cycle_id: str, cap: int = TRANSCRIPT_CAP) -> str:
    """The cycle's objective + results text, redacted and capped, verbatim otherwise."""
    cycle_dir = Path(root) / "04_cycles" / cycle_id
    parts: list[str] = []
    for name in ("objective.md", "results.md"):
        path = cycle_dir / name
        if path.is_file():
            parts.append(f"--- {name}\n{path.read_text(errors='ignore').strip()}")
    text = "\n\n".join(parts)
    if len(text) > cap:
        text = text[:cap] + f"\n…[truncated {len(text) - cap} chars]"
    return redact(text)


def _evidence_refs(root: Path, cycle_id: str) -> list[str]:
    path = Path(root) / "04_cycles" / cycle_id / "results.md"
    if not path.is_file():
        return []
    section = re.search(r"^##\s*Evidence references\s*$(.*?)(^##\s|\Z)", path.read_text(errors="ignore"),
                        re.M | re.S)
    if not section:
        return []
    return list(dict.fromkeys(EVIDENCE_ID.findall(section.group(1))))


def _family_candidates(root: Path, cycle_id: str) -> list[str]:
    """Candidate families: the cycle's own triage packs, plus `other`."""
    plan = ControlPlane(root).cycle_data(cycle_id) or {}
    names = [str(entry.get("pack")) for entry in (plan.get("knowledge_triage") or [])
             if isinstance(entry, dict) and str(entry.get("pack") or "").strip()]
    declared = str(plan.get("technique_family") or "").strip()
    if declared:
        names.insert(0, declared)
    return list(dict.fromkeys(names + [OTHER_FAMILY]))


def _unavailable(note: str, cycle_id: str, posture: str = "off") -> dict[str, Any]:
    """The unavailable shape carries the endpoint and posture too (never a silent
    default)."""
    return {"source": "unavailable", "cycle_id": cycle_id, "result": None,
            "technique_family": None, "interpretation": "", "learning": "",
            "evidence_refs": [], DRAFT_MARKER: None, "note": note,
            "model": None, "usage": {}, "posture": posture, "endpoint": API}


def _label_questions(families: list[str]) -> dict[str, dict]:
    """The one per-field question set (result / technique_family / has_learning),
    shared by the seam and its offline replay."""
    return {
        "result": {
            "type": "choice",
            "instructions": ("Which single result best describes this cycle's outcome? "
                             "Pick by what the transcript shows was observed, not by what "
                             "was hoped for."),
            "criteria": {
                "CONFIRMED": "The transcript shows the hypothesized behavior with a control.",
                "FALSE_POSITIVE": "The observed signal turned out to be noise or an artifact.",
                "NOT_APPLICABLE": "The precondition was absent; the test could not apply.",
                "INCONCLUSIVE": "The run did not decide the question either way.",
                "NEGATIVE": "The secure behavior held under a clean control.",
            },
        },
        "technique_family": {
            "type": "choice",
            "instructions": ("Which technique family did this cycle actually exercise? Pick "
                             "`other` when none of the candidates fits."),
            "criteria": {name: (f"The cycle used the {name} family."
                                if name != OTHER_FAMILY else "No candidate family fits.")
                         for name in families},
        },
        "has_learning": {
            "type": "noul",
            "instructions": ("Does `transcript` state a reusable learning (or a clear "
                             "negative result) that belongs in the technique ledger?"),
            "criteria": {
                "true": "The transcript states what was learned and why it matters.",
                "false": "Only raw observations; the controller must write the learning.",
            },
        },
    }


def _label_decision(answers: Any, families: list[str]) -> dict[str, Any]:
    """Code-side per-field decision: rejected answers leave the field unset with the
    reason recorded (never surfaced as a value). Shared by the seam and its replay."""
    answers = answers if isinstance(answers, dict) else {}
    notes: dict[str, str] = {}
    ranswer = answers.get("result") or {}
    rproblem = validate_choice(ranswer, sorted(TECHNIQUE_RESULTS))
    result = str(ranswer.get("choice")) if rproblem is None else None
    if rproblem:
        notes["result"] = f"result answer rejected: {rproblem}"
    try:
        confidence = float(ranswer.get("confidence", 0.0) or 0.0)
    except (TypeError, ValueError, AttributeError):
        confidence = 0.0
    fanswer = answers.get("technique_family") or {}
    fproblem = validate_choice(fanswer, families)
    family = str(fanswer.get("choice")) if fproblem is None else None
    if fproblem:
        notes["technique_family"] = f"technique_family answer rejected: {fproblem}"
    lanswer = answers.get("has_learning")
    learning_score = lanswer.get("noul") if isinstance(lanswer, dict) else None
    if not isinstance(learning_score, (int, float)) or isinstance(learning_score, bool):
        learning_score = None
        notes["has_learning"] = "has_learning answer missing or invalid"
    return {"result": result, "technique_family": family, "confidence": confidence,
            "has_learning": learning_score, "notes": notes}


def draft_technique_payload(root: Path, cycle_id: str, *, client=None, live: bool = True,
                            timeout: int = 60, transcript: str | None = None,
                            evidence_refs: list[str] | None = None) -> dict[str, Any]:
    """Compile a `TECHNIQUE_EVALUATED` draft from per-field questions over the transcript.

    `transcript` and `evidence_refs` override the cycle artifacts (the paired eval uses
    committed fixtures). Nothing is recorded here: the returned payload carries
    `_draft` and must be reviewed and confirmed by the controller.
    """
    root = Path(root)
    if not live:
        return _unavailable(NO_KEY_NOTE, cycle_id, "off: live=False")
    if not external_judgment_allowed(root):
        return _unavailable(POLICY_NOTE, cycle_id, "off: external judgment denied")
    if client is None and not os.environ.get("TYPESAFE_API_KEY"):
        return _unavailable(NO_KEY_NOTE, cycle_id, judgment_posture(root))
    text = transcript if transcript is not None else cycle_transcript(root, cycle_id)
    refs = list(evidence_refs) if evidence_refs is not None else _evidence_refs(root, cycle_id)
    families = _family_candidates(root, cycle_id)
    input_payload = {"cycle_id": cycle_id, "transcript": text, "families": families,
                     "evidence_refs": refs}
    state = {"cycle_id": cycle_id, "transcript": text,
             "technique_family_candidates": families, "evidence_refs": refs}
    questions = _label_questions(families)
    call = client or (lambda s, q: post_json(
        {"state": s, "model": model_name(), "questions": q},
        api_key=os.environ.get("TYPESAFE_API_KEY", ""), timeout=timeout))
    posture = judgment_posture(root, live=live)
    started = time.monotonic()
    resp = call(state, questions)
    decision = _label_decision((resp.get("answers") if isinstance(resp, dict) else None),
                               families)
    result = decision["result"]
    family = decision["technique_family"]
    learning_score = decision["has_learning"]
    notes = decision["notes"]
    model = resp.get("model") if isinstance(resp, dict) else None
    record = judgment_record(
        seam="label", input_payload=input_payload, model=model, verdict=result,
        confidence=decision["confidence"], posture=posture, cycle_id=cycle_id,
        technique_family=family, has_learning=learning_score, notes=notes)
    out = {
        "source": "typesafe",
        "cycle_id": cycle_id,
        "result": result,
        "technique_family": family,
        "interpretation": text,
        "learning": text,
        "evidence_refs": refs,
        DRAFT_MARKER: {
            "source": "cycle transcript",
            "model": model,
            "usage": (resp.get("usage") if isinstance(resp, dict) else None) or {},
            "has_learning": learning_score,
            "notes": notes,
            # Provenance for the confirm step: the recorded TECHNIQUE_EVALUATED payload
            # keeps the model + confidence whose draft the controller confirmed.
            "confidence": decision["confidence"],
            "input_digest": record["input_digest"],
            "posture": posture,
            "endpoint": API,
            "note": ("draft only — review and edit interpretation/learning, then confirm "
                     "via `researchctl technique confirm <file>`; nothing was recorded"),
        },
    }
    out.update(try_record_judgments(root, [record]))
    record_seam_cost(root, decision="label",
                     out={"usage": (resp.get("usage") if isinstance(resp, dict) else None) or {},
                          "model": model},
                     cycle_id=cycle_id, latency_ms=int((time.monotonic() - started) * 1000))
    return out


def replay_label(root: Path, *, client, path: str | Path | None = None) -> dict[str, Any]:
    """Re-run stored technique-labeling judgments offline and compare the field picks.

    Digest-verified records rebuild the same per-field questions over the recorded
    transcript/families and re-run them through `client`; the recomputed result and
    technique_family are compared with the stored ones. Returns {"replayed", "matched",
    "drifted", "mismatched", "mismatches"}.
    """
    records, drifted = verified_records(root, seam="label", path=path)
    replayed = matched = mismatched = 0
    mismatches: list[dict[str, Any]] = []
    for record in records:
        replayed += 1
        input_payload = record["input"]
        families = list(input_payload.get("families") or [])
        state = {"cycle_id": input_payload.get("cycle_id"),
                 "transcript": input_payload.get("transcript") or "",
                 "technique_family_candidates": families,
                 "evidence_refs": list(input_payload.get("evidence_refs") or [])}
        resp = client(state, _label_questions(families))
        decision = _label_decision((resp.get("answers") if isinstance(resp, dict) else None),
                                   families)
        if (decision["result"] == record.get("verdict")
                and decision["technique_family"] == record.get("technique_family")):
            matched += 1
        else:
            mismatched += 1
            mismatches.append({
                "stored": [record.get("verdict"), record.get("technique_family")],
                "replayed": [decision["result"], decision["technique_family"]],
            })
    return {"replayed": replayed, "matched": matched, "drifted": drifted,
            "mismatched": mismatched, "mismatches": mismatches}


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="ts_label")
    ap.add_argument("root")
    ap.add_argument("cycle_id")
    ns = ap.parse_args()
    print(json.dumps(draft_technique_payload(Path(ns.root), ns.cycle_id),
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
