#!/usr/bin/env python3
"""Paired eval: keyword-overlap baseline vs the shipped novelty/duplicate aid.

Same labeled pair set (`novelty_eval_set.json`: same / different / unclear pairs over
finding-shaped texts). Baseline: Jaccard keyword overlap >= the seam's blocking
threshold means `same`, otherwise `different` (a deterministic similarity heuristic
that cannot express `unclear`). Seam: `ts_novelty.check_novelty` (cheap blocking first,
then one pairwise Choice per blocked candidate; `unclear` routes to the human lane).
An empty proposal list maps to `different` — no plausible pair means no duplicate.

Metric: relation accuracy over the labeled pairs. Ship criterion: the seam beats the
baseline.

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
from ts_novelty import BLOCK_MIN_OVERLAP, block_candidates, check_novelty  # noqa: E402

SCRATCH = Path(__file__).resolve().parent


def baseline_verdict(candidate: dict, archived: dict) -> str:
    blocked = block_candidates(candidate, [archived])
    if blocked and blocked[0]["overlap"] >= BLOCK_MIN_OVERLAP:
        return "same"
    return "different"


def guard_live(force: bool, root: Path) -> None:
    if not force:
        raise SystemExit("novelty_eval: refusing a live TypeSafe run without --force "
                         "(it calls the external API and rewrites the committed eval artifact)")
    if not external_judgment_allowed(root):
        raise SystemExit(f"novelty_eval: external judgment denied by engagement policy "
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
    items = json.loads((SCRATCH / "novelty_eval_set.json").read_text())
    rows: list[dict] = []
    for item in items:
        result = check_novelty(root, item["candidate"], pool=[item["archived"]],
                               cycle_id=f"eval-{item['id']}")
        proposal = result["proposals"][0] if result["proposals"] else None
        seam_verdict = proposal["verdict"] if proposal else "different"
        base_verdict = baseline_verdict(item["candidate"], item["archived"])
        rows.append({
            "id": item["id"], "truth": item["truth"],
            "baseline_verdict": base_verdict, "baseline_correct": base_verdict == item["truth"],
            "seam_verdict": seam_verdict, "seam_correct": seam_verdict == item["truth"],
            "seam_confidence": proposal["confidence"] if proposal else None,
            "seam_auto": proposal["auto"] if proposal else None,
            "seam_human_lane": result["human_lane"],
            "seam_blocked": result["blocked"],
            "model": result["model"], "usage": result["usage"],
        })
        print(f"{item['id']:<24} truth={item['truth']:<9} baseline={base_verdict:<9} "
              f"seam={seam_verdict:<9} conf={rows[-1]['seam_confidence']} "
              f"human={result['human_lane']}")
    base_correct = sum(1 for r in rows if r["baseline_correct"])
    seam_correct = sum(1 for r in rows if r["seam_correct"])
    ship = seam_correct > base_correct
    print(f"\naccuracy: baseline {base_correct}/{len(rows)} -> seam {seam_correct}/{len(rows)}")
    print(f"ship (seam beats the deterministic baseline): {ship}")
    payload = {
        "eval": "novelty-duplicate-aid", "block_threshold": BLOCK_MIN_OVERLAP,
        "baseline_correct": base_correct, "seam_correct": seam_correct,
        "ship": ship, "rows": rows,
    }
    write_results(SCRATCH / "novelty_results.json", payload, force=force)


def cli(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="novelty_eval",
        description="Live paired eval: keyword-overlap baseline vs the novelty aid "
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
