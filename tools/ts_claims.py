#!/usr/bin/env python3
"""TypeSafe (Jev) claim/evidence seam: does the evidence support the claim?

One `Choice` question per claim — supports / contradicts / says_nothing — with a
calibrated confidence; below `auto_accept` (default 0.8) the verdict is flagged for
a reasoning model or human. Pattern: citation_check cookbook. Falsifiable in code:
without `TYPESAFE_API_KEY` (or with `live=False`) the seam reports `unavailable`
and never invents a verdict.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from control_plane import ControlPlane  # noqa: E402

API = "https://api.typesafe.ai/v1/systemone"
MODEL = "jev-latest"
AUTO_ACCEPT = 0.8
EXCERPT_CAP = 6000


def evidence_excerpt(root: Path, ref: str, cap: int = EXCERPT_CAP) -> str:
    """Registered evidence text, bounded. Never guesses a path from a filename."""
    index = ControlPlane(root).evidence_index()
    meta = index.get(ref)
    if not meta:
        raise ValueError(f"unknown evidence ref: {ref}")
    path = root / str(meta.get("path", ""))
    if not path.is_file():
        raise ValueError(f"evidence file missing: {meta.get('path')}")
    blob = path.read_bytes()
    if b"\x00" in blob[:4096]:
        return f"[binary evidence {ref}, {len(blob)} bytes]"
    text = blob.decode("utf-8", errors="ignore")
    if len(text) > cap:
        return text[:cap] + f"\n…[truncated {len(text) - cap} chars]"
    return text


def _http_call(state: dict, questions: dict, timeout: int) -> dict:
    body = json.dumps({"state": state, "model": MODEL, "questions": questions}).encode()
    req = urllib.request.Request(API, data=body, headers={
        "Authorization": f"Bearer {os.environ.get('TYPESAFE_API_KEY', '')}",
        "Content-Type": "application/json",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def check_claims(root: Path, packet: dict, *, client=None, live: bool = True,
                 auto_accept: float = AUTO_ACCEPT, timeout: int = 60) -> dict:
    """Check each {id, claim, evidence_ref} against its registered evidence.

    Returns {"source": "typesafe"|"unavailable", "auto_accept": float, "results": [...],
    "summary": {...}, "model": ..., "usage": {...}}. Each result carries verdict,
    confidence and `auto` (confidence >= auto_accept).
    """
    claims = packet.get("claims") or []
    if not isinstance(claims, list) or not claims:
        raise ValueError("claims packet needs a non-empty 'claims' list")
    key = os.environ.get("TYPESAFE_API_KEY", "")
    if not live or (client is None and not key):
        return {"source": "unavailable", "auto_accept": auto_accept, "results": [],
                "summary": {"checked": 0, "flagged": 0},
                "model": None, "usage": {},
                "note": "no TYPESAFE_API_KEY (or live=False): no verdicts were produced"}
    call = client or (lambda s, q: _http_call(s, q, timeout))
    results = []
    usage_in = usage_out = 0
    for i, item in enumerate(claims, 1):
        cid = str(item.get("id") or f"C-{i}")
        claim = str(item.get("claim", "")).strip()
        ref = str(item.get("evidence_ref", "")).strip()
        if not claim or not ref:
            raise ValueError(f"claim {cid} needs both 'claim' and 'evidence_ref'")
        excerpt = evidence_excerpt(root, ref)
        questions = {"relation": {
            "type": "choice",
            "instructions": {"claim": claim, "evidence": excerpt,
                             "question": "How does the evidence relate to `claim`?"},
            "criteria": {
                "supports": "The evidence states the claim or directly implies that it is true.",
                "contradicts": "The evidence states the opposite of the claim or implies it is false.",
                "says_nothing": "The evidence does not address what the claim asserts, either way.",
            },
        }}
        resp = call({"claim": claim, "evidence": excerpt}, questions)
        usage = resp.get("usage", {})
        usage_in += int(usage.get("input_tokens", 0) or 0)
        usage_out += int(usage.get("output_tokens", 0) or 0)
        answer = resp["answers"]["relation"]
        confidence = float(answer.get("confidence", 0.0) or 0.0)
        results.append({
            "id": cid, "claim": claim, "evidence_ref": ref,
            "verdict": answer.get("choice"), "confidence": confidence,
            "auto": confidence >= auto_accept,
            "probabilities": answer.get("probabilities", {}),
        })
    flagged = sum(1 for r in results if not r["auto"])
    return {"source": "typesafe", "auto_accept": auto_accept, "results": results,
            "summary": {"checked": len(results), "flagged": flagged,
                        "supports": sum(1 for r in results if r["verdict"] == "supports"),
                        "contradicts": sum(1 for r in results if r["verdict"] == "contradicts"),
                        "says_nothing": sum(1 for r in results if r["verdict"] == "says_nothing")},
            "model": resp.get("model"), "usage": {"input_tokens": usage_in, "output_tokens": usage_out}}


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="ts_claims")
    ap.add_argument("root")
    ap.add_argument("packet_json")
    ns = ap.parse_args()
    out = check_claims(Path(ns.root), json.loads(Path(ns.packet_json).read_text()))
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
