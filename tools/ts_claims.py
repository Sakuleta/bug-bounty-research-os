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
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from control_plane import ControlPlane, external_judgment_allowed  # noqa: E402
from ts_http import model_name, post_json  # noqa: E402

AUTO_ACCEPT = 0.8
EXCERPT_CAP = 6000
POLICY_NOTE = "external judgment denied by engagement policy"
NO_KEY_NOTE = "no TYPESAFE_API_KEY (or live=False): no verdicts were produced"

CITATION = re.compile(r"`?\b(E-\d{6,})\b`?")
SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")
BULLET = re.compile(r"^(?:[-*+]|\d+\.)\s+")
MIN_CLAIM_CHARS = 40
SHORT_CLAIM_NOTE = f"sentence shorter than {MIN_CLAIM_CHARS} chars after citations"
NO_CLAIMS_NOTE = "no checkable claims in the draft"
NONE = "none"
TRIAGE_NOTE = "triage: no relevant passage"
# The relation question's answer space. Anything else is a model/reporting error, never
# a verdict: it is flagged and counted under `invalid_choice`.
VALID_CHOICES = ("supports", "contradicts", "says_nothing")
INVALID_CHOICE = "invalid_choice"
# The verify-clause answer space: does the cited evidence support the verdict the
# relation just gave? Anything else is flagged like an invalid choice.
VERIFY_CHOICES = ("supported", "unsupported")
VERIFY_MAX_RELATION_ATTEMPTS = 2
JUDGMENTS_REL = "11_runtime/jev-judgments.jsonl"
PASSAGE_MIN = 400
PASSAGE_MAX = 1500
PASSAGE_CAP = 12


def _unavailable(note: str, auto_accept: float) -> dict:
    """The one shape of an `unavailable` seam result: no verdicts, no model, a reason."""
    return {"source": "unavailable", "auto_accept": auto_accept, "results": [],
            "summary": {"checked": 0, "flagged": 0},
            "model": None, "usage": {}, "note": note}


def evidence_excerpt(root: Path, ref: str, cap: int = EXCERPT_CAP) -> str:
    """Registered evidence text, bounded, read from the content-addressed store copy.

    The store copy under 11_runtime/evidence-store/ is the registered artifact (audits
    verify it; review quotes must match it); the living path is mutable and must never
    be what the seam reasons over. A legacy record without a store_path falls back to
    its readable living path, never a guessed filename.
    """
    index = ControlPlane(root).evidence_index()
    meta = index.get(ref)
    if not meta:
        raise ValueError(f"unknown evidence ref: {ref}")
    store_rel = str(meta.get("store_path") or "")
    path = (root / store_rel) if store_rel else (root / str(meta.get("path", "")))
    if not path.is_file():
        raise ValueError(f"evidence store copy missing: {store_rel or meta.get('path')}")
    blob = path.read_bytes()
    if b"\x00" in blob[:4096]:
        return f"[binary evidence {ref}, {len(blob)} bytes]"
    text = blob.decode("utf-8", errors="ignore")
    if len(text) > cap:
        return text[:cap] + f"\n…[truncated {len(text) - cap} chars]"
    return text


def extract_draft_claims(text: str) -> dict:
    """Cited sentences of a report draft as {id, claim, evidence_ref} checks.

    Fenced code blocks (``` or ~~~) and 4-space/tab-indented code lines are skipped;
    headings are skipped; blockquote `>` markers are stripped and the sentence is kept;
    each table row (`|`-prefixed) is its own sentence. Sentences without a citation token
    (`E-\\d{6,}`) are dropped; a cited sentence whose text (citations removed) is shorter
    than MIN_CLAIM_CHARS is skipped with a note instead of being checked. One claim per
    (sentence, cited ref) pair; `id` is `<line>-<ref>` where `<line>` is the line the
    paragraph/bullet/row starts on (a repeat of the same pair on that line gets a `-N`
    suffix from a per-(line, ref) counter — linear, never a rescan). The evidence index is
    NOT consulted here: unknown refs come back as claims and the caller reports them, so
    extraction never crashes on a stale citation.
    """
    claims: list[dict] = []
    skipped: list[dict] = []
    counts: dict[tuple[int, str], int] = {}
    block: list[str] = []
    start = 0
    fence = ""

    def flush() -> None:
        if not block:
            return
        for sentence in SENTENCE_SPLIT.split(" ".join(block).strip()):
            refs = list(dict.fromkeys(CITATION.findall(sentence)))
            if not refs:
                continue
            claim = " ".join(CITATION.sub(" ", sentence).split())
            if len(claim) < MIN_CLAIM_CHARS:
                skipped.append({"line": start, "reason": SHORT_CLAIM_NOTE})
                continue
            for ref in refs:
                key = (start, ref)
                counts[key] = counts.get(key, 0) + 1
                suffix = "" if counts[key] == 1 else f"-{counts[key]}"
                claims.append({"id": f"{start}-{ref}{suffix}", "claim": claim, "evidence_ref": ref})
        block.clear()

    for lineno, raw in enumerate(text.splitlines(), 1):
        if raw.startswith(("    ", "\t")):
            flush()
            continue
        line = raw.strip()
        if fence:
            if line.startswith(fence):
                fence = ""
            continue
        if line.startswith("```") or line.startswith("~~~"):
            flush()
            fence = line[:3]
            continue
        line = re.sub(r"^(?:>\s*)+", "", line).strip()
        if not line or line.startswith("#"):
            flush()
            continue
        if line.startswith("|"):
            flush()
            start = lineno
            block.append(line)
            flush()
            continue
        if BULLET.match(line):
            flush()
            block.append(BULLET.sub("", line))
            start = lineno
            flush()
            continue
        if not block:
            start = lineno
        block.append(line)
    flush()
    return {"claims": claims, "skipped": skipped}


def evidence_passages(text: str, max_chars: int = PASSAGE_MAX, min_chars: int = PASSAGE_MIN,
                      cap: int = PASSAGE_CAP, report: dict | None = None) -> list[str]:
    """Bound the evidence (or capture) text into triage-sized passages.

    Blank lines are the primary boundary; runs of small chunks are merged and a trailing
    fragment shorter than `min_chars` is folded into the previous passage whenever it
    fits, so a fragment is never triaged alone; an oversized chunk is hard-split at
    `max_chars`, and at most `cap` passages are offered. With `report` given it receives
    `{"total": <passages before the cap>, "dropped": <passages the cap cut>}`, so a caller
    can say how much evidence the cap hid. Deterministic: same text, same passages.
    """
    pieces: list[str] = []
    for chunk in re.split(r"\n\s*\n", text):
        chunk = chunk.strip()
        while len(chunk) > max_chars:
            pieces.append(chunk[:max_chars])
            chunk = chunk[max_chars:].lstrip()
        if chunk:
            pieces.append(chunk)
    passages: list[str] = []
    for piece in pieces:
        if (passages
                and len(passages[-1]) + 2 + len(piece) <= max_chars
                and (len(piece) < min_chars or len(passages[-1]) < min_chars)):
            passages[-1] += "\n\n" + piece
        else:
            passages.append(piece)
    if report is not None:
        report["total"] = len(passages)
        report["dropped"] = max(0, len(passages) - cap)
    return passages[:cap]


def _passage_question(claim: str, passages: list[str]) -> dict:
    """One Choice question over the candidate passages plus `none`."""
    criteria = {str(i): f"Passage {i}: {p[:300]}" for i, p in enumerate(passages, 1)}
    criteria[NONE] = "No passage addresses what the claim asserts."
    return {"passage": {
        "type": "choice",
        "instructions": ("Which single passage is most relevant to `claim`? Pick by how "
                         "directly it addresses what the claim asserts; pick none when no "
                         "passage does."),
        "criteria": criteria,
    }}


def _http_call(state: dict, questions: dict, timeout: int) -> dict:
    return post_json({"state": state, "model": model_name(), "questions": questions},
                     api_key=os.environ.get("TYPESAFE_API_KEY", ""), timeout=timeout)


def _verify_question(claim: str, verdict: str, evidence: str) -> dict:
    """One Choice question: do the cited evidence quotes support this verdict?"""
    return {"verify": {
        "type": "choice",
        "instructions": {"claim": claim, "verdict": verdict, "evidence": evidence,
                         "question": "Do the cited evidence quotes support this verdict on `claim`?"},
        "criteria": {
            "supported": "The quoted evidence states the verdict or directly implies it.",
            "unsupported": "The quoted evidence does not support the verdict, or it cuts against it.",
        },
    }}


def _judgment_digest(claim: str, evidence: str) -> str:
    """Canonical input digest for one judgment (replay compares it first)."""
    import hashlib
    return hashlib.sha256(json.dumps({"claim": claim, "evidence": evidence},
                                     ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def record_judgments(root: Path, records: list[dict]) -> Path:
    """Append judgment records for replay; returns the ledger path."""
    path = Path(root) / JUDGMENTS_REL
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    return path


def replay_judgments(root: Path, *, client, path: str | Path | None = None) -> dict:
    """Re-run stored judgments offline and compare guard decisions deterministically.

    For each stored record the evidence excerpt is re-read and its digest compared
    first (drifted evidence replays as `drifted`, never as a false match); then the
    relation question — and, when the stored judgment verified, the verify-clause
    question on the replayed verdict — re-run through `client` (a mocked provider
    in tests), and the recomputed verdict, verify outcome and auto decision are
    compared to the stored ones. Returns {"replayed", "matched", "drifted",
    "mismatched", "mismatches": [...]}.
    """
    root = Path(root)
    ledger = Path(path) if path is not None else root / JUDGMENTS_REL
    replayed = matched = drifted = mismatched = 0
    mismatches: list[dict] = []
    if ledger.is_file():
        for line in ledger.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            replayed += 1
            ref = str(record.get("evidence_ref") or "")
            try:
                evidence = evidence_excerpt(root, ref)
            except ValueError:
                evidence = None
            if evidence is None or _judgment_digest(str(record.get("claim") or ""), evidence) != record.get("input_digest"):
                drifted += 1
                continue
            questions = {"relation": {
                "type": "choice",
                "instructions": {"claim": record.get("claim"), "evidence": evidence,
                                 "question": "How does the evidence relate to `claim`?"},
                "criteria": {
                    "supports": "The evidence states the claim or directly implies that it is true.",
                    "contradicts": "The evidence states the opposite of the claim or implies it is false.",
                    "says_nothing": "The evidence does not address what the claim asserts, either way.",
                },
            }}
            resp = client({"claim": record.get("claim"), "evidence": evidence}, questions)
            answer = (resp.get("answers") or {}).get("relation") or {}
            verdict = str(answer.get("choice", ""))
            try:
                confidence = float(answer.get("confidence", 0.0) or 0.0)
            except (TypeError, ValueError):
                confidence = 0.0
            stored_verify = record.get("verify_supported")
            replayed_verify: bool | None = None
            if stored_verify is not None and verdict in VALID_CHOICES:
                vresp = client({"claim": record.get("claim"), "verdict": verdict,
                                "evidence": evidence},
                               _verify_question(str(record.get("claim") or ""), verdict, evidence))
                vanswer = (vresp.get("answers") or {}).get("verify") or {}
                replayed_verify = str(vanswer.get("choice", "")) == "supported"
            auto = (verdict in VALID_CHOICES and confidence >= float(record.get("auto_accept", AUTO_ACCEPT))
                    and (replayed_verify if stored_verify is not None else True))
            if (verdict == record.get("verdict") and auto == record.get("auto")
                    and replayed_verify == stored_verify):
                matched += 1
            else:
                mismatched += 1
                mismatches.append({"claim_id": record.get("claim_id"),
                                   "stored": [record.get("verdict"), record.get("auto"),
                                              stored_verify],
                                   "replayed": [verdict, auto, replayed_verify]})
    return {"replayed": replayed, "matched": matched, "drifted": drifted,
            "mismatched": mismatched, "mismatches": mismatches}


def check_claims(root: Path, packet: dict, *, client=None, live: bool = True,
                 auto_accept: float = AUTO_ACCEPT, timeout: int = 60, triage: bool = False,
                 verify: bool = False) -> dict:
    """Check each {id, claim, evidence_ref} against its registered evidence.

    Returns {"source": "typesafe"|"unavailable", "auto_accept": float, "results": [...],
    "summary": {...}, "model": ..., "usage": {...}, "judgments_recorded": bool,
    "judgments_error": str (only when the ledger write failed)}. Each result carries verdict,
    confidence and `auto` (confidence >= auto_accept). With `triage=True` a passage
    selection question runs first (skipped when the evidence is a single passage); a
    `none` selection yields `says_nothing` with TRIAGE_NOTE and no relation call, a
    selection runs the relation question on that passage only and records
    `passage_index` / `triage_confidence`; both confidences must clear auto_accept.
    With `verify=True` (the `researchctl claims-check` step) each relation verdict is
    then judged supportable-or-not against the cited evidence by a second Choice
    question; an `unsupported` verdict retries the relation once (bounded), and a
    verdict that never verifies is kept but flagged (`auto` False with a
    verify-clause note). Live judgments are appended to 11_runtime/jev-judgments.jsonl
    (input digest, model, verdict, confidence, timestamp) for offline replay.
    """
    claims = packet.get("claims") or []
    if not isinstance(claims, list) or not claims:
        raise ValueError("claims packet needs a non-empty 'claims' list")
    key = os.environ.get("TYPESAFE_API_KEY", "")
    if not live:
        return _unavailable(NO_KEY_NOTE, auto_accept)
    if not external_judgment_allowed(root):
        return _unavailable(POLICY_NOTE, auto_accept)
    if client is None and not key:
        return _unavailable(NO_KEY_NOTE, auto_accept)
    call = client or (lambda s, q: _http_call(s, q, timeout))
    results = []
    judgments: list[dict] = []
    usage_in = usage_out = 0
    resp = None
    for i, item in enumerate(claims, 1):
        cid = str(item.get("id") or f"C-{i}")
        claim = str(item.get("claim", "")).strip()
        ref = str(item.get("evidence_ref", "")).strip()
        if not claim or not ref:
            raise ValueError(f"claim {cid} needs both 'claim' and 'evidence_ref'")
        excerpt = evidence_excerpt(root, ref)
        evidence = excerpt
        extra: dict = {}
        if triage:
            report: dict = {}
            passages = evidence_passages(excerpt, cap=PASSAGE_CAP, report=report)
            if report["dropped"]:
                extra["dropped_passages"] = report["dropped"]
            if len(passages) > 1:
                tresp = call({"claim": claim, "passages": passages},
                             _passage_question(claim, passages))
                usage = tresp.get("usage", {})
                usage_in += int(usage.get("input_tokens", 0) or 0)
                usage_out += int(usage.get("output_tokens", 0) or 0)
                t_answer = tresp["answers"]["passage"]
                t_conf = float(t_answer.get("confidence", 0.0) or 0.0)
                choice = str(t_answer.get("choice", ""))
                if choice == NONE:
                    results.append({
                        "id": cid, "claim": claim, "evidence_ref": ref,
                        "verdict": "says_nothing", "confidence": t_conf,
                        "auto": t_conf >= auto_accept,
                        "probabilities": t_answer.get("probabilities", {}),
                        "note": TRIAGE_NOTE, "triage_confidence": t_conf, **extra,
                    })
                    resp = tresp
                    continue
                if choice.isdigit() and 1 <= int(choice) <= len(passages):
                    evidence = passages[int(choice) - 1]
                    extra.update(passage_index=int(choice), triage_confidence=t_conf,
                                 triage_auto=t_conf >= auto_accept)
                else:
                    extra["note"] = (f"triage: unrecognized selection {choice!r}; "
                                     "the relation ran on the full excerpt")
        questions = {"relation": {
            "type": "choice",
            "instructions": {"claim": claim, "evidence": evidence,
                             "question": "How does the evidence relate to `claim`?"},
            "criteria": {
                "supports": "The evidence states the claim or directly implies that it is true.",
                "contradicts": "The evidence states the opposite of the claim or implies it is false.",
                "says_nothing": "The evidence does not address what the claim asserts, either way.",
            },
        }}
        verify_state: dict = {}
        attempts = 0
        while True:
            attempts += 1
            resp = call({"claim": claim, "evidence": evidence}, questions)
            usage = resp.get("usage", {})
            usage_in += int(usage.get("input_tokens", 0) or 0)
            usage_out += int(usage.get("output_tokens", 0) or 0)
            answer = resp["answers"]["relation"]
            confidence = float(answer.get("confidence", 0.0) or 0.0)
            choice = str(answer.get("choice", ""))
            valid = choice in VALID_CHOICES
            if not verify or not valid:
                break
            vresp = call({"claim": claim, "verdict": choice, "evidence": evidence},
                         _verify_question(claim, choice, evidence))
            vusage = vresp.get("usage", {})
            usage_in += int(vusage.get("input_tokens", 0) or 0)
            usage_out += int(vusage.get("output_tokens", 0) or 0)
            vanswer = (vresp.get("answers") or {}).get("verify") or {}
            try:
                vconfidence = float(vanswer.get("confidence", 0.0) or 0.0)
            except (TypeError, ValueError):
                vconfidence = 0.0
            supported = str(vanswer.get("choice", "")) == "supported"
            verify_state = {"supported": supported, "confidence": vconfidence,
                            "attempts": attempts}
            if supported or attempts >= VERIFY_MAX_RELATION_ATTEMPTS:
                break
        result = {
            "id": cid, "claim": claim, "evidence_ref": ref,
            "verdict": choice if valid else INVALID_CHOICE, "confidence": confidence,
            "auto": valid and confidence >= auto_accept and extra.pop("triage_auto", True)
                    and (verify_state.get("supported", True) if verify else True),
            "probabilities": answer.get("probabilities", {}),
        }
        if verify and valid:
            result["verify"] = verify_state
            if not verify_state.get("supported"):
                result["note"] = ("verify-clause: the cited evidence does not support "
                                  f"the {choice} verdict after {attempts} attempts; flagged for review")
        if not valid:
            result["note"] = f"unrecognized relation choice {choice!r}; flagged for review"
        result.update(extra)
        results.append(result)
        judgments.append({
            "claim_id": cid, "claim": claim, "evidence_ref": ref,
            "input_digest": _judgment_digest(claim, evidence),
            "model": resp.get("model"), "verdict": result["verdict"],
            "confidence": confidence, "auto": result["auto"],
            "auto_accept": auto_accept,
            "verify_supported": (verify_state.get("supported") if verify and valid else None),
            "verify_confidence": (verify_state.get("confidence") if verify and valid else None),
            "timestamp": _now_iso(),
        })
    flagged = sum(1 for r in results if not r["auto"])
    out = {"source": "typesafe", "auto_accept": auto_accept, "results": results,
           "summary": {"checked": len(results), "flagged": flagged,
                       "supports": sum(1 for r in results if r["verdict"] == "supports"),
                       "contradicts": sum(1 for r in results if r["verdict"] == "contradicts"),
                       "says_nothing": sum(1 for r in results if r["verdict"] == "says_nothing"),
                       "invalid_choice": sum(1 for r in results if r["verdict"] == INVALID_CHOICE)},
           "model": resp.get("model"), "usage": {"input_tokens": usage_in, "output_tokens": usage_out}}
    try:
        record_judgments(root, judgments)
    except OSError as exc:
        # Replay coverage must never be lost silently: the judgments still return,
        # but the output says the ledger write failed so the gap is visible.
        out["judgments_recorded"] = False
        out["judgments_error"] = f"judgment ledger write failed ({exc}) — replay coverage lost"
    else:
        out["judgments_recorded"] = True
    return out


def check_draft(root: Path, draft_path, *, triage: bool = False, client=None, live: bool = True,
                auto_accept: float = AUTO_ACCEPT, timeout: int = 60) -> dict:
    """Audit a report draft: extract its cited sentences and check the registered ones.

    Refs absent from the evidence index are reported under `errors` (never checked, never
    a crash) — in the policy-ALLOWED live path only: when the seam is unavailable
    (external judgment denied, `live=False` or no key) nothing is routed and `errors`
    stays empty. Extraction notes land under `skipped`. Same policy gate, thresholds and
    transport as `check_claims`; the result also carries `draft` counts. An aid, never a
    gate: a flagged or contradicted result does not fail the run by itself.
    """
    draft_path = Path(draft_path)
    extracted = extract_draft_claims(draft_path.read_text(errors="ignore"))
    if not live:
        out = _unavailable(NO_KEY_NOTE, auto_accept)
    elif not external_judgment_allowed(root):
        out = _unavailable(POLICY_NOTE, auto_accept)
    else:
        index = ControlPlane(root).evidence_index()
        known = [c for c in extracted["claims"] if c["evidence_ref"] in index]
        unknown = [c for c in extracted["claims"] if c["evidence_ref"] not in index]
        if client is None and not os.environ.get("TYPESAFE_API_KEY", ""):
            out = _unavailable(NO_KEY_NOTE, auto_accept)
        elif known:
            out = check_claims(root, {"claims": known}, client=client, live=live,
                               auto_accept=auto_accept, timeout=timeout, triage=triage)
        else:
            out = _unavailable(NO_CLAIMS_NOTE, auto_accept)
        out["errors"] = [{"id": c["id"], "claim": c["claim"], "evidence_ref": c["evidence_ref"],
                          "error": f"unknown evidence ref: {c['evidence_ref']}"} for c in unknown]
    out["draft"] = {"path": str(draft_path), "claims": len(extracted["claims"]),
                    "checked": len(out.get("results", []))}
    out["skipped"] = extracted["skipped"]
    out.setdefault("errors", [])
    return out


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
