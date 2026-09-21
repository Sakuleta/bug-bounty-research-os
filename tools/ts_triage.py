#!/usr/bin/env python3
"""TypeSafe (Jev) triage seam: rank knowledge packs for a research question.

Design chosen by the 2026-09-21 experiment over a 20-question labeled set
(committed: tools/ts-eval/): one Choice question over ALL packs plus a `none` option
(skill_suggestion pattern) scored top-1 20/20 vs the IDF baseline 17/20, with
no regressions. The naive per-pack Noul rerank lost (7/20) and is not used.

`TYPESAFE_API_KEY` comes from the environment. Without a key (or with
`live=False`) the seam falls back to the deterministic knowledge_index IDF
ranking, so triage never hard-depends on an external service. The engagement's
top-level `external_judgment` key (default DENIED) gates the external call: when
it is not "ALLOWED" the seam falls back to IDF with a policy note.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from control_plane import external_judgment_allowed  # noqa: E402
from knowledge_index import parse_index, rank_packs  # noqa: E402
from ts_http import model_name, post_json  # noqa: E402

NONE = "none"
POLICY_NOTE = "external judgment denied by engagement policy"


def pack_cards(root: Path) -> dict[str, dict]:
    """Compact candidate card per pack: skill description + first research families."""
    packs = parse_index(root / "12_knowledge" / "INDEX.yaml")
    cards: dict[str, dict] = {}
    for name, (_load_when, files) in packs.items():
        description = ""
        skill = root / ".dsh" / "skills" / name / "SKILL.md"
        if skill.exists():
            m = re.search(r'^description:\s*"?(.*?)"?\s*$', skill.read_text(), re.M)
            description = (m.group(1) if m else "").strip()
        families: list[str] = []
        for f in files:
            p = (root / "12_knowledge" / name / f).resolve()
            if not p.is_file():
                continue
            m = re.search(r"## Research families\n(.*?)(\n## |\Z)", p.read_text(errors="ignore"), re.S)
            if not m:
                continue
            for line in m.group(1).splitlines():
                if line.strip().startswith("- "):
                    families.append(line.strip()[2:].strip())
            if len(families) >= 8:
                break
        cards[name] = {"name": name, "description": description, "research_families": families[:8]}
    return cards


def idf_order(root: Path, question: str) -> list[str]:
    """Deterministic fallback order: IDF-scored packs first, then the rest by name."""
    packs = parse_index(root / "12_knowledge" / "INDEX.yaml")
    ranked = [name for _, name, _ in rank_packs(packs, question)]
    return ranked + [n for n in sorted(packs) if n not in ranked]


def _http_call(state: dict, questions: dict, timeout: int) -> dict:
    return post_json({"state": state, "model": model_name(), "questions": questions},
                     api_key=os.environ.get("TYPESAFE_API_KEY", ""), timeout=timeout)


def suggest(root: Path, question: str, *, client=None, live: bool = True, timeout: int = 60) -> dict:
    """Rank packs for a research question.

    Returns {"source": "typesafe"|"idf", "suggested": pack|None, "ranked": [...],
    "probabilities": {...}, "confidence": float|None, "model": str|None, "usage": {...}}.
    `client` injects a callable (state, questions) -> response for tests; `live=False`
    forces the deterministic IDF fallback.
    """
    order = idf_order(root, question)
    if not live or not external_judgment_allowed(root):
        result = {"source": "idf", "suggested": order[0] if order else None, "ranked": order,
                  "probabilities": {}, "confidence": None, "model": None, "usage": {}}
        if live:
            result["note"] = POLICY_NOTE
        return result
    if client is None and not os.environ.get("TYPESAFE_API_KEY"):
        return {"source": "idf", "suggested": order[0] if order else None, "ranked": order,
                "probabilities": {}, "confidence": None, "model": None, "usage": {}}
    cards = pack_cards(root)
    names = sorted(cards)
    criteria = {n: (cards[n]["description"] or n) for n in names}
    criteria[NONE] = "No pack covers this technology and failure class; research from primary sources first."
    questions = {"first_pack": {
        "type": "choice",
        "instructions": ("Which single candidate_pack should be loaded FIRST to research `research_question`? "
                         "Pick by how directly the pack domain and its research families cover the technology "
                         "and the failure class in the question; pick none when no pack covers it."),
        "criteria": criteria,
    }}
    call = client or (lambda s, q: _http_call(s, q, timeout))
    resp = call({"research_question": question, "candidate_pack": cards}, questions)
    answer = resp["answers"]["first_pack"]
    probs = answer.get("probabilities", {})
    ranked = sorted(names, key=lambda n: -probs.get(n, 0.0))
    choice = answer.get("choice")
    return {
        "source": "typesafe",
        "suggested": None if choice == NONE else choice,
        "choice": choice,
        "ranked": ranked,
        "probabilities": probs,
        "confidence": answer.get("confidence"),
        "model": resp.get("model"),
        "usage": resp.get("usage", {}),
    }


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="ts_triage")
    ap.add_argument("root")
    ap.add_argument("question")
    ns = ap.parse_args()
    out = suggest(Path(ns.root), ns.question)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
