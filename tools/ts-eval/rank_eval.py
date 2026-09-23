#!/usr/bin/env python3
"""Paired eval: current priority order (baseline) vs the hypothesis-ranking aid.

Same labeled scenarios (`rank_eval_set.json`: five cycles' worth of open hypotheses,
each with one high-information SAFE test, a cosmetic decoy listed first, an unsafe
temptation, and a low-value option). Baseline: the current priority order — the first
hypothesis in creation order. Seam: `ts_rank.rank_hypotheses` (one Noul per open
hypothesis, safety veto and thresholds in code; a low-confidence ranking escalates and
counts as no pick).

Metric: pick accuracy against the labeled correct test. Ship criterion: the seam beats
the baseline.

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
from ts_rank import rank_hypotheses  # noqa: E402

SCRATCH = Path(__file__).resolve().parent


def guard_live(force: bool, root: Path) -> None:
    if not force:
        raise SystemExit("rank_eval: refusing a live TypeSafe run without --force "
                         "(it calls the external API and rewrites the committed eval artifact)")
    if not external_judgment_allowed(root):
        raise SystemExit(f"rank_eval: external judgment denied by engagement policy "
                         f"({root / '00_control' / 'engagement.yaml'}); set "
                         f"external_judgment: \"ALLOWED\" in the workspace passed as --root")
    if not os.environ.get("TYPESAFE_API_KEY"):
        raise SystemExit("TYPESAFE_API_KEY missing")


def write_results(path: Path, data, *, force: bool) -> bool:
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


def main(*, root: Path | None = None, force: bool = False) -> None:
    root = root or REPO_ROOT
    guard_live(force, root)
    scenarios = json.loads((SCRATCH / "rank_eval_set.json").read_text())
    rows: list[dict] = []
    for scenario in scenarios:
        baseline_pick = scenario["hypotheses"][0]["id"]
        result = rank_hypotheses(root, hypotheses=scenario["hypotheses"],
                                 question=scenario["question"],
                                 cycle_id=f"eval-{scenario['id']}")
        rows.append({
            "id": scenario["id"], "question": scenario["question"],
            "correct_pick": scenario["correct_pick"],
            "baseline_pick": baseline_pick,
            "baseline_correct": baseline_pick == scenario["correct_pick"],
            "seam_pick": result["pick"], "seam_correct": result["pick"] == scenario["correct_pick"],
            "seam_escalate": result["escalate"], "seam_reason": result["reason"],
            "seam_vetoed": result["vetoed"],
            "seam_scores": {r["id"]: r["info"] for r in result["ranking"]},
            "model": result["model"], "usage": result["usage"],
        })
        print(f"{scenario['id']:<24} correct={scenario['correct_pick']} "
              f"baseline={baseline_pick} seam={result['pick']} "
              f"escalate={result['escalate']} vetoed={result['vetoed']}")
    base_correct = sum(1 for r in rows if r["baseline_correct"])
    seam_correct = sum(1 for r in rows if r["seam_correct"])
    escalations = sum(1 for r in rows if r["seam_escalate"])
    ship = seam_correct > base_correct
    print(f"\npick accuracy: baseline {base_correct}/{len(rows)} -> seam {seam_correct}/{len(rows)} "
          f"(escalations: {escalations})")
    print(f"ship (seam beats the deterministic baseline): {ship}")
    payload = {
        "eval": "hypothesis-ranking", "baseline_correct": base_correct,
        "seam_correct": seam_correct, "escalations": escalations,
        "ship": ship, "rows": rows,
    }
    write_results(SCRATCH / "rank_results.json", payload, force=force)


def cli(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="rank_eval",
        description="Live paired eval: priority order vs the hypothesis-ranking aid "
                    "(guarded: needs --force and an ALLOWED policy).")
    ap.add_argument("--force", action="store_true",
                    help="required: call the external API and replace the committed result artifact")
    ap.add_argument("--root", default=None,
                    help="workspace whose external_judgment policy gates this run")
    ns = ap.parse_args(argv)
    main(root=Path(ns.root) if ns.root else None, force=ns.force)
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
