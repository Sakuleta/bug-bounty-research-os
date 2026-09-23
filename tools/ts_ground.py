#!/usr/bin/env python3
"""Grounded-judgment seam: retrieval-backed Jev judgments (the console's recipe).

The console demo's mechanism, rebuilt on the OS's own seams: a pluggable retrieval
provider (env-keyed adapters, default off — the OS's path, never an agent's MCP keys),
snippets inserted **verbatim** into `state.search_results` with `source` and `date`
(no model in between), then one support/relevance question per candidate plus the
target verdict. Code applies the thresholds and decides: a verdict is only accepted
when at least one candidate cleared the relevance threshold AND the verdict confidence
cleared its own; otherwise it stays a flagged proposal. Retrieved snippets are external
content, so each one runs through the V2 screening battery first and a flagged snippet
never enters `search_results` (it stays visible under `excluded` with the reason).

Eval-integrity: grounding is default off. It needs BOTH the engagement's
`external_judgment: "ALLOWED"` (the DENIED-default gate) and its own explicit
`grounding: "ALLOWED"` key; during scored eval runs it stays off and the posture is
part of every result and every ledger row. Per-cycle cache and an explicit per-cycle
call cap bound the loop (no unbounded retrieval). The operator question is redacted
once at the boundary and that copy is what the provider, the model state, the ledger
and the cycle cache carry; snippet text stays verbatim (retrieved web content) while
source/date metadata is redacted too. Stdlib only.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from control_plane import cycle_id_ok, external_judgment_allowed, redact  # noqa: E402
from ts_claims import judgment_digest  # noqa: E402
from ts_cost import record_seam_cost  # noqa: E402
from ts_http import API, model_name, post_json, validate_choice  # noqa: E402
from ts_screen import screen_text  # noqa: E402

RELEVANCE_THRESHOLD = 0.6
VERDICT_CONFIDENCE_THRESHOLD = 0.8
VERDICT_CHOICES = ("yes", "no", "unclear")
GROUND_MAX_CALLS_PER_CYCLE = 12
SNIPPET_CAP = 2000
GROUNDING_REL = "11_runtime/grounding.jsonl"
CACHE_REL = "11_runtime/grounding-cache"
POLICY_NOTE = "external judgment denied by engagement policy"
OPTOUT_NOTE = "grounding not ALLOWED (default off; eval-integrity posture)"
NO_PROVIDER_NOTE = "no retrieval provider configured (env-keyed adapters, default off)"
NO_KEY_NOTE = "no TYPESAFE_API_KEY (or live=False): no grounded judgment was produced"


def grounding_allowed(root: Path) -> bool:
    """Grounding needs the external-judgment gate AND its own explicit opt-in key."""
    if not external_judgment_allowed(root):
        return False
    try:
        text = (Path(root) / "00_control" / "engagement.yaml").read_text(errors="ignore")
    except OSError:
        return False
    match = re.search(r"^grounding:[^\S\n]*[\"']?([A-Za-z_-]+)", text, re.M | re.I)
    return bool(match) and match.group(1).strip().upper() == "ALLOWED"


def grounding_posture(root: Path) -> str:
    """The recorded posture: `on`, or `off: <why>` — never a silent default."""
    if not external_judgment_allowed(root):
        return "off: external judgment denied"
    if not grounding_allowed(root):
        return "off: grounding not ALLOWED"
    return "on"


def _max_calls() -> int:
    try:
        value = int(os.environ.get("GROUND_MAX_CALLS_PER_CYCLE", ""))
    except (TypeError, ValueError):
        return GROUND_MAX_CALLS_PER_CYCLE
    return value if value >= 0 else GROUND_MAX_CALLS_PER_CYCLE


class Provider:
    """Retrieval adapter interface: fetch(query, limit, timeout, opener) -> snippets.

    A snippet is `{"text", "source", "date"}`; `text` is the provider's returned
    snippet verbatim (bounded, never rewritten), `source` the URL, `date` the
    provider's date (None when it reports none).
    """

    name = "base"
    env_key = ""

    def available(self) -> bool:
        return bool(os.environ.get(self.env_key))

    def fetch(self, query: str, *, limit: int = 5, timeout: int = 30,
              opener=None) -> list[dict[str, Any]]:  # pragma: no cover - interface
        raise NotImplementedError


def _clean_snippets(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in items:
        text = str(item.get("text") or "").strip()
        # Source/date are metadata this seam persists (ledger + cache): redact them like
        # every other egress/ledger copy (a token-shaped query value never lands raw).
        source = redact(str(item.get("source") or "").strip())
        if not text or not source:
            continue
        if len(text) > SNIPPET_CAP:
            text = text[:SNIPPET_CAP] + f"\n…[truncated {len(text) - SNIPPET_CAP} chars]"
        out.append({"text": text, "source": source,
                    "date": (redact(str(item["date"]).strip()) if item.get("date") else None)})
    return out


class FakeProvider(Provider):
    """Committed-snippet provider (tests and the paired eval's after-web arm)."""

    name = "fake"

    def __init__(self, snippets: list[dict[str, Any]]):
        self._snippets = [dict(s) for s in snippets]

    def available(self) -> bool:
        return True

    def fetch(self, query: str, *, limit: int = 5, timeout: int = 30, opener=None):
        return [dict(s) for s in self._snippets[:limit]]


class BraveProvider(Provider):
    """Brave Search API adapter (BRAVE_API_KEY; GET /res/v1/web/search)."""

    name = "brave"
    env_key = "BRAVE_API_KEY"
    url = "https://api.search.brave.com/res/v1/web/search"

    def fetch(self, query: str, *, limit: int = 5, timeout: int = 30, opener=None):
        opener = opener or urllib.request.urlopen
        url = f"{self.url}?q={urllib.parse.quote_plus(query)}&count={max(1, limit)}"
        request = urllib.request.Request(url, headers={
            "Accept": "application/json",
            "X-Subscription-Token": os.environ.get(self.env_key, ""),
        })
        with opener(request, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        results = ((data.get("web") or {}).get("results")) or []
        return _clean_snippets([
            {"text": r.get("description"), "source": r.get("url"),
             "date": r.get("page_age") or r.get("age")}
            for r in results if isinstance(r, dict)
        ])


class TavilyProvider(Provider):
    """Tavily Search API adapter (TAVILY_API_KEY; POST /search)."""

    name = "tavily"
    env_key = "TAVILY_API_KEY"
    url = "https://api.tavily.com/search"

    def fetch(self, query: str, *, limit: int = 5, timeout: int = 30, opener=None):
        opener = opener or urllib.request.urlopen
        body = json.dumps({"api_key": os.environ.get(self.env_key, ""), "query": query,
                           "max_results": max(1, limit)}).encode()
        request = urllib.request.Request(self.url, data=body, headers={
            "Content-Type": "application/json", "Accept": "application/json"})
        with opener(request, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        results = data.get("results") or []
        return _clean_snippets([
            {"text": r.get("content"), "source": r.get("url"),
             "date": r.get("published_date")}
            for r in results if isinstance(r, dict)
        ])


PROVIDER_CLASSES = (BraveProvider, TavilyProvider)


def provider_from_env() -> Provider | None:
    """First env-configured provider, or None (default off — never a silent fallback)."""
    for cls in PROVIDER_CLASSES:
        provider = cls()
        if provider.available():
            return provider
    return None


def retrieve(root: Path, question: str, *, provider: Provider | None = None,
             limit: int = 5, timeout: int = 30) -> dict[str, Any]:
    """One retrieval step: provider snippets, verbatim, with source and date."""
    provider = provider or provider_from_env()
    if provider is None:
        return {"source": "unavailable", "provider": None, "results": [],
                "note": NO_PROVIDER_NOTE}
    results = provider.fetch(question, limit=limit, timeout=timeout)
    return {"source": "provider", "provider": provider.name, "results": results}


def _cache_path(root: Path, cycle_id: str | None) -> Path:
    """Cache file for one cycle. The cycle id is an allowlist value, never a path.

    Only `C-<4+ digits>` or None (the shared `adhoc` entry) are accepted: an absolute or
    traversing id fails closed before any read or write, so the grounding cache can never
    escape the workspace (Security M1). The resolved path is additionally checked against
    the cache directory as defense in depth.
    """
    key = cycle_id or "adhoc"
    if key != "adhoc" and not cycle_id_ok(str(key)):
        raise ValueError(
            f"invalid grounding cache key {key!r}: a cycle id must match C-<digits> "
            "(or be omitted) — arbitrary paths are refused, the cache stays in the "
            "workspace")
    base = (Path(root) / CACHE_REL).resolve()
    path = (base / f"{key}.json").resolve()
    if base != path.parent:
        raise ValueError(f"grounding cache path escapes the cache directory: {path}")
    return path


def _load_cache(root: Path, cycle_id: str | None) -> dict[str, Any]:
    path = _cache_path(root, cycle_id)
    if not path.is_file():
        return {"calls": 0, "entries": {}}
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"calls": 0, "entries": {}}
    if not isinstance(data, dict):
        return {"calls": 0, "entries": {}}
    data.setdefault("calls", 0)
    data.setdefault("entries", {})
    return data


def _save_cache(root: Path, cycle_id: str | None, cache: dict[str, Any]) -> None:
    path = _cache_path(root, cycle_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache, ensure_ascii=False, sort_keys=True) + "\n")


def _question_key(question: str) -> str:
    return hashlib.sha256(question.encode("utf-8")).hexdigest()[:16]


def _unavailable(note: str, root: Path, question: str) -> dict[str, Any]:
    return {"source": "unavailable", "question": question, "verdict": None,
            "confidence": None, "auto": False, "relevant": [], "excluded": [],
            "state": {"question": question, "search_results": []},
            "model": None, "usage": {}, "posture": grounding_posture(root),
            "endpoint": API, "cached": False, "note": note}


def _support_questions(count: int) -> dict[str, dict]:
    return {
        f"support_{i}": {
            "type": "noul",
            "instructions": (f"Does `search_results[{i - 1}]` support or directly address "
                             "`question`? Answer by how directly the snippet bears on the "
                             "question's claim, not by whether it agrees with it."),
            "criteria": {
                "true": "The snippet states or directly bears on the question's claim.",
                "false": "Off-topic, too vague, or about a different subject.",
            },
        }
        for i in range(1, count + 1)
    }


def _verdict_question() -> dict[str, dict]:
    return {"verdict": {
        "type": "choice",
        "instructions": ("Based only on `question` and `search_results`, what is the "
                         "answer? Pick unclear when the evidence is missing, conflicting "
                         "or does not decide it."),
        "criteria": {
            "yes": "The evidence shows the claim/answer is true.",
            "no": "The evidence shows the claim/answer is false.",
            "unclear": "The evidence does not decide the claim/answer.",
        },
    }}


def _noul(answer: Any) -> float | None:
    if not isinstance(answer, dict):
        return None
    value = answer.get("noul")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if number != number or number < 0.0 or number > 1.0:
        return None
    return number


def _usage_add(total: dict[str, int], usage: Any) -> None:
    if not isinstance(usage, dict):
        return
    for key in ("input_tokens", "output_tokens"):
        value = usage.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            total[key] = total.get(key, 0) + value


def _apply_ground_answers(answers: Any, kept: list[dict[str, Any]]) -> dict[str, Any]:
    """Code-side decisions over one grounded judgment response.

    Shared by `ground_state` and `replay_grounding` so both apply exactly the same
    guard: the per-candidate relevance threshold, verdict validation, the verdict
    confidence threshold and the resulting `auto`. Returns relevant/excluded/verdict/
    confidence/auto/note/problem.
    """
    answers = answers if isinstance(answers, dict) else {}
    relevant: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for i, snippet in enumerate(kept, 1):
        score = _noul(answers.get(f"support_{i}"))
        if score is None:
            excluded.append({"source": snippet["source"], "date": snippet["date"],
                             "reason": "support score invalid — not counted as relevant",
                             "screening": None})
            continue
        if score >= RELEVANCE_THRESHOLD:
            relevant.append({"source": snippet["source"], "date": snippet["date"],
                             "score": score})
    vanswer = answers.get("verdict") or {}
    problem = validate_choice(vanswer, VERDICT_CHOICES)
    verdict = str(vanswer.get("choice", "")) if problem is None else None
    try:
        confidence = float(vanswer.get("confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    note = None
    if problem is not None:
        verdict, confidence = None, None
        note = f"verdict rejected: {problem}"
    elif not relevant:
        note = ("no relevant evidence above the threshold — verdict not accepted "
                "(the model's answer stays a proposal)")
    elif confidence is not None and confidence < VERDICT_CONFIDENCE_THRESHOLD:
        note = (f"verdict confidence {confidence:.2f} below threshold "
                f"{VERDICT_CONFIDENCE_THRESHOLD} — flagged for review")
    auto = bool(verdict and relevant and confidence is not None
                and confidence >= VERDICT_CONFIDENCE_THRESHOLD)
    return {"relevant": relevant, "excluded": excluded, "verdict": verdict,
            "confidence": confidence, "auto": auto, "note": note, "problem": problem}


def ground_state(root: Path, question: str, *, provider: Provider | None = None,
                 client=None, live: bool = True, cycle_id: str | None = None,
                 limit: int = 5, timeout: int = 60) -> dict[str, Any]:
    """Retrieve, insert verbatim, ask per-candidate support + the target verdict.

    Code decides: `auto` is True only when at least one candidate cleared
    `RELEVANCE_THRESHOLD` and the (validated) verdict cleared
    `VERDICT_CONFIDENCE_THRESHOLD`. Flagged snippets are excluded with their screening
    reason; a per-cycle cache serves repeats and an explicit call cap refuses the step
    (without any model call) when it would exceed the cycle's budget.
    """
    root = Path(root)
    # Egress/ledger minimization (Security M2): the operator's question is redacted once
    # at the boundary, and that copy is what the retrieval provider, the model state, the
    # ledger row and the cycle cache see. A secret-shaped string is never a legitimate
    # ranking term, and the redaction runs before any hash-keyed caching.
    question = redact(str(question or ""))
    posture = grounding_posture(root)
    if not live:
        return _unavailable(NO_KEY_NOTE, root, question)
    if posture != "on":
        return _unavailable(posture, root, question)
    if client is None and not os.environ.get("TYPESAFE_API_KEY"):
        return _unavailable(NO_KEY_NOTE, root, question)
    provider = provider or provider_from_env()
    if provider is None:
        return _unavailable(NO_PROVIDER_NOTE, root, question)
    cache = _load_cache(root, cycle_id)
    key = _question_key(question)
    if key in cache["entries"]:
        return {**cache["entries"][key], "cached": True}
    results = provider.fetch(question, limit=limit, timeout=timeout)
    snippets = _clean_snippets([{k: v for k, v in s.items() if k in ("text", "source", "date")}
                                for s in results])
    cap = _max_calls()
    needed = len(snippets) + 1  # one screening call per candidate, plus the judgment call
    if cache["calls"] + needed > cap:
        return {"source": "cap_reached", "question": question, "verdict": None,
                "confidence": None, "auto": False, "relevant": [], "excluded": [],
                "state": {"question": question, "search_results": []},
                "model": None, "usage": {}, "posture": posture, "endpoint": API,
                "cached": False,
                "note": (f"grounding call cap reached for this cycle "
                         f"({cache['calls']}+{needed} > {cap}) — no retrieval-backed "
                         "judgment was produced; raise GROUND_MAX_CALLS_PER_CYCLE or "
                         "start a new cycle")}
    usage_total: dict[str, int] = {}
    # The spend ledger must not double count: `screen_text` already ledgers one `screen`
    # row per screening call, so the `ground` row prices the judgment call only, while
    # `usage_total` (the result/manifest figure) still reports the true total spend.
    judgment_usage: dict[str, int] = {}
    excluded: list[dict[str, Any]] = []
    kept: list[dict[str, Any]] = []
    screening_client = client
    for snippet in snippets:
        screening = screen_text(root, snippet["text"], client=screening_client,
                                live=live, timeout=timeout)
        _usage_add(usage_total, screening.get("usage"))
        if screening["flagged"]:
            excluded.append({
                "source": snippet["source"], "date": snippet["date"],
                "reason": ("screening: " + (", ".join(screening["flagged_questions"])
                                            or screening.get("error") or "invalid scores")),
                "screening": {"scores": screening["scores"],
                              "invalid_scores": screening["invalid_scores"],
                              "error": screening.get("error")},
            })
            continue
        kept.append({"text": snippet["text"], "source": snippet["source"],
                     "date": snippet["date"],
                     "truncated": "[truncated" in snippet["text"]})
    state = {"question": question,
             "search_results": [{"text": s["text"], "source": s["source"], "date": s["date"]}
                                for s in kept]}
    call = client or (lambda s, q: post_json(
        {"state": s, "model": model_name(), "questions": q},
        api_key=os.environ.get("TYPESAFE_API_KEY", ""), timeout=timeout))
    model = None
    if kept:
        # One call: every per-candidate support question plus the target verdict, all
        # against the same grounded state (the documented fan-out shape).
        questions = {**_support_questions(len(kept)), **_verdict_question()}
        resp = call(state, questions)
        _usage_add(usage_total, resp.get("usage"))
        _usage_add(judgment_usage, resp.get("usage"))
        model = resp.get("model") if isinstance(resp, dict) else None
        decision = _apply_ground_answers(
            (resp.get("answers") if isinstance(resp, dict) else None), kept)
        excluded.extend(decision["excluded"])
    else:
        decision = _apply_ground_answers(None, [])
    relevant = decision["relevant"]
    verdict = decision["verdict"]
    confidence = decision["confidence"]
    problem = decision["problem"]
    note = decision["note"]
    auto = decision["auto"]
    input_payload = {"question": question, "search_results": list(state["search_results"])}
    input_digest = judgment_digest(input_payload)
    out: dict[str, Any] = {
        "source": "typesafe", "question": question, "verdict": verdict,
        "confidence": confidence, "auto": auto, "relevant": relevant,
        "excluded": excluded, "state": state, "model": model,
        "usage": usage_total, "posture": posture, "endpoint": API, "cached": False,
        "input_digest": input_digest, "note": note,
    }
    calls_used = len(snippets) + 1 if kept else len(snippets)
    cache["calls"] = cache["calls"] + calls_used
    cache["entries"][key] = {k: v for k, v in out.items() if k != "cached"}
    _save_cache(root, cycle_id, cache)
    row = {
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "question": question, "cycle_id": cycle_id, "provider": provider.name,
        "sources": [{"source": s["source"], "date": s["date"]} for s in kept],
        "excluded": excluded, "relevant": relevant, "verdict": verdict,
        "confidence": confidence, "auto": auto, "model": model,
        "usage": usage_total, "judgment_usage": judgment_usage,
        "input": input_payload, "input_digest": input_digest,
        "posture": posture, "endpoint": API,
        "calls": calls_used,
    }
    ledger = root / GROUNDING_REL
    ledger.parent.mkdir(parents=True, exist_ok=True)
    with ledger.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    record_seam_cost(root, decision="ground", out={**out, "usage": judgment_usage},
                     cycle_id=cycle_id)
    return out



def replay_grounding(root: Path, *, client, path: str | Path | None = None) -> dict[str, Any]:
    """Re-run stored grounding judgments offline and compare guard decisions.

    For each ledger row carrying an input snapshot the digest is checked first (a
    tampered row replays as `drifted`, never as a false match); the same support +
    verdict questions are then rebuilt over the snapshot and re-run through `client`,
    and the code-computed verdict, confidence and `auto` decision are compared with the
    stored ones. Rows without an input snapshot (cap refusals, unavailable postures)
    are skipped — nothing was judged. Returns {"replayed", "matched", "drifted",
    "mismatched", "mismatches"}.
    """
    root = Path(root)
    ledger = Path(path) if path is not None else root / GROUNDING_REL
    replayed = matched = drifted = mismatched = 0
    mismatches: list[dict[str, Any]] = []
    if ledger.is_file():
        for line in ledger.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict) or not isinstance(record.get("input"), dict):
                continue
            replayed += 1
            input_payload = record["input"]
            if judgment_digest(input_payload) != record.get("input_digest"):
                drifted += 1
                continue
            search_results = input_payload.get("search_results") or []
            kept = [{"text": str(s.get("text") or ""), "source": str(s.get("source") or ""),
                     "date": s.get("date")} for s in search_results if isinstance(s, dict)]
            state = {"question": input_payload.get("question"),
                     "search_results": list(search_results)}
            if kept:
                resp = client(state, {**_support_questions(len(kept)), **_verdict_question()})
                decision = _apply_ground_answers(
                    (resp.get("answers") if isinstance(resp, dict) else None), kept)
            else:
                decision = _apply_ground_answers(None, [])
            if (decision["verdict"] == record.get("verdict")
                    and decision["confidence"] == record.get("confidence")
                    and decision["auto"] == record.get("auto")):
                matched += 1
            else:
                mismatched += 1
                mismatches.append({
                    "question": str(input_payload.get("question") or "")[:120],
                    "stored": [record.get("verdict"), record.get("confidence"), record.get("auto")],
                    "replayed": [decision["verdict"], decision["confidence"], decision["auto"]],
                })
    return {"replayed": replayed, "matched": matched, "drifted": drifted,
            "mismatched": mismatched, "mismatches": mismatches}


def judge_question(root: Path, question: str, *, search_results: list[dict[str, Any]] | None = None,
                   client=None, live: bool = True, timeout: int = 60) -> dict[str, Any]:
    """One verdict question over a caller-supplied state (no retrieval).

    The plain judgment primitive: gated by `external_judgment` only (it is not
    grounding), used by the paired eval's before-web arm and available to any seam
    that already holds evidence. Code-side thresholding stays with the caller.
    """
    root = Path(root)
    # Same boundary redaction as `ground_state`: nothing carries the raw question.
    question = redact(str(question or ""))
    posture = grounding_posture(root)
    if not live or not external_judgment_allowed(root):
        out = _unavailable(POLICY_NOTE, root, question)
        out["posture"] = posture
        return out
    if client is None and not os.environ.get("TYPESAFE_API_KEY"):
        return _unavailable(NO_KEY_NOTE, root, question)
    state = {"question": question, "search_results": list(search_results or [])}
    call = client or (lambda s, q: post_json(
        {"state": s, "model": model_name(), "questions": q},
        api_key=os.environ.get("TYPESAFE_API_KEY", ""), timeout=timeout))
    resp = call(state, _verdict_question())
    vanswer = (resp.get("answers") or {}).get("verdict") or {}
    problem = validate_choice(vanswer, VERDICT_CHOICES)
    verdict = str(vanswer.get("choice", "")) if problem is None else None
    try:
        confidence = float(vanswer.get("confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    return {"source": "typesafe", "question": question, "verdict": verdict,
            "confidence": confidence if problem is None else None,
            "auto": False, "relevant": [], "excluded": [], "state": state,
            "model": resp.get("model"), "usage": resp.get("usage", {}),
            "posture": posture, "endpoint": API, "cached": False,
            "note": (f"verdict rejected: {problem}" if problem else None)}


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="ts_ground")
    ap.add_argument("root")
    ap.add_argument("question")
    ap.add_argument("--cycle", default=None)
    ns = ap.parse_args()
    print(json.dumps(ground_state(Path(ns.root), ns.question, cycle_id=ns.cycle),
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
