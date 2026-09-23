#!/usr/bin/env python3
"""Novelty/duplicate aid (T3): pairwise entity resolution over blocked candidates.

Strictly advisory to the deterministic `novelty-duplicate` audit: this seam proposes
same/different/unclear relations between a candidate and the archived hypotheses, code
applies the confidence threshold, and `unclear` (or a rejected answer) routes to the
human lane. It never records an audit, never names or withdraws a finding, and never
touches the ledger — the audit's PASS still comes only from `record_audit`.

Cheap deterministic blocking runs first (normalized-hash equality plus keyword
overlap), so judged pairs stay small and a model call is only spent where a relation
is plausible. Gate: the engagement's `external_judgment` policy (DENIED default).
Egress discipline: candidate and archived texts are redacted and capped once; both the
model state and the question instructions quote that same copy, so a secret-shaped value
cannot ride an unredacted channel.
"""
from __future__ import annotations

import hashlib
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
from ts_http import model_name, post_json, validate_choice  # noqa: E402
from ts_screen import SCREEN_CAP  # noqa: E402

PAIR_CHOICES = ("same", "different", "unclear")
CONFIDENCE_THRESHOLD = 0.8
# Blocking is a recall-oriented prefilter (the model judges precision afterwards), so it
# uses an overlap coefficient with light plural folding, not a strict Jaccard.
BLOCK_MIN_OVERLAP = 0.4
POLICY_NOTE = "external judgment denied by engagement policy"
NO_KEY_NOTE = "no TYPESAFE_API_KEY (or live=False): no novelty verdicts were produced"
ADVISORY_NOTE = ("advisory to the deterministic novelty-duplicate audit — it never sets "
                 "PASS, never names a finding, and unclear always goes to the human lane")
STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "into", "when", "then", "than",
    "are", "was", "were", "has", "have", "had", "not", "but", "its", "his", "her", "their",
    "they", "them", "you", "your", "our", "all", "any", "can", "could", "should", "would",
    "will", "must", "may", "via", "per", "also", "only", "more", "most", "less", "least",
    "each", "every", "some", "such", "same", "other", "another", "because", "after",
    "before", "while", "where", "which", "who", "whom", "how", "why", "what", "does",
    "did", "done", "being", "been", "over", "under", "between", "within", "without",
    "upon", "onto", "off", "out", "own", "one", "two",
}


def _normalize(text: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", str(text or "").lower()))


def _tokens(text: str) -> set[str]:
    tokens: set[str] = set()
    for token in _normalize(text).split():
        if len(token) < 3 or token in STOPWORDS:
            continue
        # Light plural folding only (recall-oriented prefilter, never a stemmer).
        if len(token) > 4 and token.endswith("s") and not token.endswith("ss"):
            token = token[:-1]
        tokens.add(token)
    return tokens


def _digest(text: str) -> str:
    return hashlib.sha256(_normalize(text).encode("utf-8")).hexdigest()


def block_candidates(candidate: dict[str, Any], pool: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Cheap deterministic prefilter: exact normalized-hash match or keyword overlap.

    Returns `[{id, text, exact, overlap}]` sorted by (exact desc, overlap desc, id) so
    the judged set is small and stable.
    """
    cand_text = str(candidate.get("text") or "")
    cand_digest = _digest(cand_text)
    cand_tokens = _tokens(cand_text)
    out: list[dict[str, Any]] = []
    for item in pool:
        if str(item.get("id")) == str(candidate.get("id")):
            continue
        text = str(item.get("text") or "")
        if not text:
            continue
        exact = _digest(text) == cand_digest
        other = _tokens(text)
        denominator = min(len(cand_tokens), len(other))
        overlap = len(cand_tokens & other) / denominator if denominator else 0.0
        if exact or overlap >= BLOCK_MIN_OVERLAP:
            out.append({"id": str(item.get("id")), "text": text,
                        "exact": exact, "overlap": round(overlap, 4)})
    out.sort(key=lambda row: (not row["exact"], -row["overlap"], row["id"]))
    return out


def hypothesis_pool(root: Path) -> list[dict[str, Any]]:
    """Open hypotheses from the ledger as `[{id, text, status}]` (the archived pool)."""
    cp = ControlPlane(root)
    pool: list[dict[str, Any]] = []
    for hid in cp.all_hypothesis_ids():
        data = cp.hypothesis_data(hid) or {}
        text = " ".join(str(data.get(key) or "") for key in ("observation", "hypothesis")).strip()
        pool.append({"id": hid, "text": text, "status": cp.hypothesis_status(hid)})
    return pool


def _unavailable(note: str) -> dict[str, Any]:
    return {"source": "unavailable", "proposals": [], "human_lane": [], "blocked": [],
            "advisory": True, "model": None, "usage": {}, "note": note}


def _egress_text(text: Any) -> str:
    """The one canonical egress copy for candidate/archived text: redact, then cap.

    Both the `state` snippets and the `questions.instructions` copy come from this
    string, so a secret-shaped value can never ride one channel while the other is
    redacted. Redaction runs before the cap: a token straddling the truncation point
    is redacted whole instead of leaving a bare prefix. The cap is the screening
    convention (`ts_screen.SCREEN_CAP`).
    """
    safe = redact(str(text or ""))
    if len(safe) > SCREEN_CAP:
        safe = safe[:SCREEN_CAP] + f"\n…[truncated {len(safe) - SCREEN_CAP} chars]"
    return safe


def check_novelty(root: Path, candidate: dict[str, Any], pool: list[dict[str, Any]] | None = None,
                  *, client=None, live: bool = True, timeout: int = 60,
                  threshold: float = CONFIDENCE_THRESHOLD,
                  cycle_id: str | None = None) -> dict[str, Any]:
    """Judge blocked candidate pairs; returns advisory proposals + the human lane.

    `candidate` is `{id, text}`; `pool` defaults to the ledger's hypotheses. A `same`
    verdict below the threshold degrades to `unclear` (never an auto-`same`), and any
    `unclear` (model or threshold) lands in `human_lane`.
    """
    root = Path(root)
    if not live:
        return _unavailable(NO_KEY_NOTE)
    if not external_judgment_allowed(root):
        return _unavailable(POLICY_NOTE)
    if client is None and not os.environ.get("TYPESAFE_API_KEY"):
        return _unavailable(NO_KEY_NOTE)
    pool = pool if pool is not None else hypothesis_pool(root)
    blocked = block_candidates(candidate, pool)
    candidate_text = _egress_text(candidate.get("text"))
    call = client or (lambda s, q: post_json(
        {"state": s, "model": model_name(), "questions": q},
        api_key=os.environ.get("TYPESAFE_API_KEY", ""), timeout=timeout))
    questions = {"pair": {
        "type": "choice",
        "instructions": {
            "candidate": {"id": candidate.get("id"), "text": candidate_text},
            "question": ("Do `candidate` and `archived` describe the same finding (same root "
                         "cause and primitive), different findings, or is it unclear?"),
        },
        "criteria": {
            "same": "Same root cause and primitive; the wording differs at most.",
            "different": "A different root cause or primitive.",
            "unclear": "Cannot be decided from the texts alone.",
        },
    }}
    proposals: list[dict[str, Any]] = []
    human_lane: list[str] = []
    started = time.monotonic()
    model = None
    usage_total: dict[str, int] = {}
    for entry in blocked:
        state = {"candidate": {"id": candidate.get("id"), "text": candidate_text},
                 "archived": {"id": entry["id"], "text": _egress_text(entry["text"])}}
        resp = call(state, questions)
        model = resp.get("model") or model
        usage = resp.get("usage")
        if isinstance(usage, dict):
            for key in ("input_tokens", "output_tokens"):
                value = usage.get(key)
                if isinstance(value, int) and not isinstance(value, bool):
                    usage_total[key] = usage_total.get(key, 0) + value
        answer = (resp.get("answers") or {}).get("pair") or {}
        problem = validate_choice(answer, PAIR_CHOICES)
        try:
            confidence = float(answer.get("confidence", 0.0) or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        verdict = str(answer.get("choice", "")) if problem is None else "unclear"
        note = None
        if problem is not None:
            note = f"answer rejected ({problem}) — routed to the human lane"
        elif verdict == "same" and confidence < threshold:
            note = (f"same verdict below threshold {threshold} (confidence {confidence:.2f}) "
                    "— routed to the human lane as unclear")
            verdict = "unclear"
        auto = verdict in ("same", "different") and confidence >= threshold
        if verdict == "unclear":
            human_lane.append(entry["id"])
        proposals.append({"id": entry["id"], "verdict": verdict, "confidence": confidence,
                          "auto": auto, "note": note,
                          "evidence": {"exact_hash": entry["exact"],
                                       "keyword_overlap": entry["overlap"]}})
    out = {"source": "typesafe", "proposals": proposals, "human_lane": human_lane,
           "blocked": [b["id"] for b in blocked], "advisory": True,
           "threshold": threshold, "model": model, "usage": usage_total,
           "note": ADVISORY_NOTE}
    record_seam_cost(root, decision="novelty", out=out, cycle_id=cycle_id,
                     latency_ms=int((time.monotonic() - started) * 1000))
    return out


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="ts_novelty")
    ap.add_argument("root")
    ap.add_argument("candidate_json")
    ns = ap.parse_args()
    candidate = json.loads(Path(ns.candidate_json).read_text())
    print(json.dumps(check_novelty(Path(ns.root), candidate), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
