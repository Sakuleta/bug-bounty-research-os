#!/usr/bin/env python3
"""Paired eval: the same labeled freshness questions before-web vs after-web.

Before-web: one verdict question over `{"question": q}` with no search_results.
After-web: the shipped grounded seam (`ts_ground.ground_state`) with the item's
committed, dated snippets inserted verbatim (a `FakeProvider` — the after-web arm is
reproducible by construction; the live provider adapters are exercised by the unit
tests with mocked transports, no network in this eval beyond TypeSafe itself).

Metric: confidently-wrong verdicts (verdict != truth and confidence >= the seam's
verdict threshold) before vs after. Ship criterion: grounding measurably reduces them.

Eval integrity: the scored system under test runs with grounding OFF unless the
engagement explicitly allows it; this eval needs the explicit opt-in for its after-web
arm, and the posture is recorded in the committed payload (the run-manifest row).

Guarded live runner, same chain as the other ts-eval scripts (`--force`, ALLOWED
policy, `TYPESAFE_API_KEY`, atomic write, never overwrite without `--force`).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # tools/
from control_plane import external_judgment_allowed  # noqa: E402
from ts_ground import (VERDICT_CONFIDENCE_THRESHOLD, FakeProvider, ground_state,  # noqa: E402
                       grounding_allowed, judge_question)

SCRATCH = Path(__file__).resolve().parent


def guard_live(force: bool, root: Path) -> None:
    """Refuse a live run without --force and without an explicit policy opt-in."""
    if not force:
        raise SystemExit("grounding_eval: refusing a live TypeSafe run without --force "
                         "(it calls the external API and rewrites the committed eval artifact)")
    if not external_judgment_allowed(root):
        raise SystemExit(f"grounding_eval: external judgment denied by engagement policy "
                         f"({root / '00_control' / 'engagement.yaml'}); set "
                         f"external_judgment: \"ALLOWED\" in the workspace passed as --root")
    if not os.environ.get("TYPESAFE_API_KEY"):
        raise SystemExit("TYPESAFE_API_KEY missing")
    if not grounding_allowed(root):
        raise SystemExit("grounding_eval: this eval measures the grounded arm, so the workspace "
                         "needs its own explicit `grounding: \"ALLOWED\"` opt-in (scored OS runs "
                         "keep grounding off unless the engagement allows it)")


def write_results(path: Path, data, *, force: bool) -> bool:
    """Write `data` as JSON via temp file + os.replace, never overwriting without --force."""
    if path.exists() and not force:
        print(f"refusing to overwrite committed results without --force: {path}")
        return False
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(data, indent=2) + "\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return True


def confident_wrong(verdict: str | None, confidence: float | None, truth: str) -> bool:
    return (verdict is not None and verdict != truth and confidence is not None
            and confidence >= VERDICT_CONFIDENCE_THRESHOLD)


def main(*, root: Path | None = None, force: bool = False) -> None:
    root = root or REPO_ROOT
    guard_live(force, root)
    items = json.loads((SCRATCH / "grounding_eval_set.json").read_text())
    rows: list[dict] = []
    for item in items:
        before = judge_question(root, item["question"])
        after = ground_state(root, item["question"],
                             provider=FakeProvider(item["snippets"]),
                             cycle_id=f"eval-{item['id']}")
        rows.append({
            "id": item["id"], "question": item["question"], "truth": item["truth"],
            "before_verdict": before["verdict"], "before_confidence": before["confidence"],
            "before_confident_wrong": confident_wrong(before["verdict"], before["confidence"],
                                                      item["truth"]),
            "after_verdict": after["verdict"], "after_confidence": after["confidence"],
            "after_confident_wrong": confident_wrong(after["verdict"], after["confidence"],
                                                     item["truth"]),
            "after_auto": after["auto"], "after_relevant": len(after["relevant"]),
            "after_excluded": len(after["excluded"]),
            "after_sources": [s["source"] for s in after["state"]["search_results"]],
            "before_model": before["model"], "after_model": after["model"],
            "before_usage": before["usage"], "after_usage": after["usage"],
        })
        print(f"{item['id']:<28} truth={item['truth']:<4} "
              f"before={str(before['verdict']):<8}@{before['confidence']} "
              f"after={str(after['verdict']):<8}@{after['confidence']} "
              f"auto={after['auto']} relevant={len(after['relevant'])}")
    before_wrong = sum(1 for r in rows if r["before_confident_wrong"])
    after_wrong = sum(1 for r in rows if r["after_confident_wrong"])
    before_yesno_wrong = sum(1 for r in rows if r["before_verdict"] in ("yes", "no")
                             and r["before_verdict"] != r["truth"]
                             and (r["before_confidence"] or 0) >= VERDICT_CONFIDENCE_THRESHOLD)
    after_yesno_wrong = sum(1 for r in rows if r["after_verdict"] in ("yes", "no")
                            and r["after_verdict"] != r["truth"]
                            and (r["after_confidence"] or 0) >= VERDICT_CONFIDENCE_THRESHOLD)
    before_correct = sum(1 for r in rows if r["before_verdict"] == r["truth"])
    after_correct = sum(1 for r in rows if r["after_verdict"] == r["truth"])
    ship = after_wrong < before_wrong
    print(f"\nconfidently wrong: before {before_wrong}/{len(rows)} -> after {after_wrong}/{len(rows)}")
    print(f"confident yes/no answers that are wrong: before {before_yesno_wrong} -> after {after_yesno_wrong}")
    print(f"correct: before {before_correct}/{len(rows)} -> after {after_correct}/{len(rows)}")
    print(f"ship (grounding measurably reduces confidently-wrong verdicts): {ship}")
    payload = {
        "eval": "grounded-judgment", "threshold": VERDICT_CONFIDENCE_THRESHOLD,
        "metric": ("confidently wrong = verdict != truth with confidence >= threshold; a "
                   "confident `unclear` counts as a confident non-answer (reported "
                   "separately as the yes/no-wrong count)"),
        "before_confident_wrong": before_wrong, "after_confident_wrong": after_wrong,
        "before_confident_yesno_wrong": before_yesno_wrong,
        "after_confident_yesno_wrong": after_yesno_wrong,
        "before_correct": before_correct, "after_correct": after_correct,
        "ship": ship, "rows": rows,
        "posture": {
            "before_arm": "off (no search_results)",
            "after_arm": "on (committed fixture retrieval, verbatim insertion)",
            "grounding_opt_in": True,
            "scored_system_runs": ("grounding stays off unless the engagement explicitly "
                                   "allows it; the posture is recorded in the run manifest"),
        },
    }
    write_results(SCRATCH / "grounding_results.json", payload, force=force)


def cli(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="grounding_eval",
        description="Live paired eval: before-web vs after-web on labeled freshness "
                    "questions (guarded: needs --force, an ALLOWED policy and the "
                    "grounding opt-in).")
    ap.add_argument("--force", action="store_true",
                    help="required: call the external API and replace the committed result artifact")
    ap.add_argument("--root", default=None,
                    help="workspace whose external_judgment + grounding policy gates this run")
    ns = ap.parse_args(argv)
    main(root=Path(ns.root) if ns.root else None, force=ns.force)
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
