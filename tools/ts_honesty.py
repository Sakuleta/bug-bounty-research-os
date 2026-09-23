#!/usr/bin/env python3
"""Knowledge-use honesty check (T6): did the cycle actually use the pack it cited?

One Noul per pack the cycle CITES (`TECHNIQUE_EVALUATED.knowledge_packs`), over the
cycle's outputs plus the pack's own guide: "is the citation load-bearing, or
decorative?". A below-threshold score is an ADVISORY WARNING only — never a fail:
nothing here records an audit, adds an audit error, or mutates state. The audit's
presence heuristic ("not considered in the last 10 cycles") remains the deterministic
signal; this seam closes the gap between coverage and genuine use without punishing
legitimate tacit use.
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
from control_plane import ControlPlane, external_judgment_allowed  # noqa: E402
from ts_cost import record_seam_cost  # noqa: E402
from ts_http import model_name, post_json  # noqa: E402
from ts_label import cycle_transcript  # noqa: E402

USE_THRESHOLD = 0.5
GUIDE_CAP = 1200
POLICY_NOTE = "external judgment denied by engagement policy"
NO_KEY_NOTE = "no TYPESAFE_API_KEY (or live=False): no honesty verdicts were produced"
ADVISORY_NOTE = ("advisory warning only — the audit's presence heuristic and the human "
                 "remain the deciding layer; this check never fails a cycle")
DESCRIPTION_RE = re.compile(r'^description:\s*"?(.*?)"?\s*$', re.M)


def cited_packs(root: Path, cycle_id: str) -> list[str]:
    """Packs cited by the cycle's TECHNIQUE_EVALUATED events, deduplicated in order."""
    out: list[str] = []
    for event in ControlPlane(root).events_for("technique"):
        if str(event.get("cycle_id") or "") != str(cycle_id):
            continue
        packs = (event.get("payload") or {}).get("knowledge_packs")
        if not isinstance(packs, list):
            continue
        for name in packs:
            if isinstance(name, str) and name.strip() and name.strip() not in out:
                out.append(name.strip())
    return out


def pack_guide(root: Path, pack: str, cap: int = GUIDE_CAP) -> str:
    """The pack's skill description + guide head, bounded (what the pack covers)."""
    skill = Path(root) / ".dsh" / "skills" / pack / "SKILL.md"
    text = ""
    if skill.is_file():
        raw = skill.read_text(errors="ignore")
        match = DESCRIPTION_RE.search(raw)
        text = (match.group(1).strip() if match else "")
    if not text:
        text = pack
    if len(text) > cap:
        text = text[:cap] + f"\n…[truncated {len(text) - cap} chars]"
    return text


def _unavailable(note: str, cycle_id: str) -> dict[str, Any]:
    return {"source": "unavailable", "cycle_id": cycle_id, "warnings": [],
            "checked": [], "advisory": True, "threshold": USE_THRESHOLD,
            "model": None, "usage": {}, "note": note}


def check_knowledge_use(root: Path, cycle_id: str, *, client=None, live: bool = True,
                        timeout: int = 60, threshold: float = USE_THRESHOLD,
                        cycle_outputs: str | None = None,
                        packs: list[str] | None = None,
                        guides: dict[str, str] | None = None) -> dict[str, Any]:
    """Judge each cited pack's genuine use; below the threshold is a warning.

    `cycle_outputs` / `packs` / `guides` override the workspace artifacts (the paired
    eval uses committed fixtures). Nothing is recorded beyond the cost ledger.
    """
    root = Path(root)
    if not live or not external_judgment_allowed(root):
        return _unavailable(POLICY_NOTE if live else NO_KEY_NOTE, cycle_id)
    if client is None and not os.environ.get("TYPESAFE_API_KEY"):
        return _unavailable(NO_KEY_NOTE, cycle_id)
    outputs = cycle_outputs if cycle_outputs is not None else cycle_transcript(root, cycle_id)
    names = list(packs) if packs is not None else cited_packs(root, cycle_id)
    if not names:
        return {**_unavailable("the cycle cites no knowledge packs", cycle_id),
                "note": "no citations to check"}
    questions = {
        f"use_{name}": {
            "type": "noul",
            "instructions": (f"Does `cycle_outputs` actually USE `pack_guide_{name}` for "
                             f"`pack_{name}` — did the cycle apply this pack's material, "
                             "or is the citation decorative?"),
            "criteria": {
                "true": "The outputs show the pack's concepts or checks applied to this cycle.",
                "false": "The pack is cited but its material is absent from the work.",
            },
        }
        for name in names
    }
    state = {"cycle_id": cycle_id, "cycle_outputs": outputs,
             **{f"pack_{name}": name for name in names},
             **{f"pack_guide_{name}": ((guides or {}).get(name) or pack_guide(root, name))
                for name in names}}
    call = client or (lambda s, q: post_json(
        {"state": s, "model": model_name(), "questions": q},
        api_key=os.environ.get("TYPESAFE_API_KEY", ""), timeout=timeout))
    started = time.monotonic()
    resp = call(state, questions)
    answers = resp.get("answers") if isinstance(resp.get("answers"), dict) else {}
    checked: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    for name in names:
        raw = answers.get(f"use_{name}")
        value = raw.get("noul") if isinstance(raw, dict) else None
        score: float | None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            score = None
        else:
            score = float(value)
            if score != score or score < 0.0 or score > 1.0:
                score = None
        row = {"pack": name, "score": score, "warning": False}
        if score is None:
            row["warning"] = True
            row["note"] = "use score missing or invalid — surfaced as a warning, never a fail"
        elif score < threshold:
            row["warning"] = True
            row["note"] = (f"use score {score:.2f} below {threshold}: the citation may be "
                           "decorative (advisory)")
        checked.append(row)
        if row["warning"]:
            warnings.append(dict(row))
    out = {"source": "typesafe", "cycle_id": cycle_id, "warnings": warnings,
           "checked": checked, "advisory": True, "threshold": threshold,
           "model": resp.get("model"), "usage": resp.get("usage", {}), "note": ADVISORY_NOTE}
    record_seam_cost(root, decision="honesty", out=out, cycle_id=cycle_id,
                     latency_ms=int((time.monotonic() - started) * 1000))
    return out


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="ts_honesty")
    ap.add_argument("root")
    ap.add_argument("cycle_id")
    ns = ap.parse_args()
    print(json.dumps(check_knowledge_use(Path(ns.root), ns.cycle_id),
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
