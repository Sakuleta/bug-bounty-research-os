#!/usr/bin/env python3
"""Paired eval: program-triage keyword heuristic vs the technique-outcome labeling aid.

Same labeled cycle transcripts (`label_eval_set.json`: four outcomes with known truth).
Baseline: an ordered keyword scan over the transcript (the kind of program-triage text
matching that reads "succeeded" as CONFIRMED and misses negations). Seam:
`ts_label.draft_technique_payload` (per-field Choice/Noul questions over the
transcript; the draft's `result` field is the label under test).

Metric: result-label accuracy. Ship criterion: the seam beats the baseline.

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
from ts_label import draft_technique_payload  # noqa: E402

SCRATCH = Path(__file__).resolve().parent

# The deterministic baseline: first match wins, negations are invisible to it.
BASELINE_RULES = (
    ("CONFIRMED", ("confirmed", "reproduced", "returned another", "succeeded", "bypass")),
    ("FALSE_POSITIVE", ("false positive", "noise", "waf", "challenge")),
    ("NEGATIVE", ("held", "denied", "no bypass")),
)


def baseline_label(transcript: str) -> str:
    lowered = transcript.lower()
    for label, keywords in BASELINE_RULES:
        if any(keyword in lowered for keyword in keywords):
            return label
    return "INCONCLUSIVE"


def guard_live(force: bool, root: Path) -> None:
    if not force:
        raise SystemExit("label_eval: refusing a live TypeSafe run without --force "
                         "(it calls the external API and rewrites the committed eval artifact)")
    if not external_judgment_allowed(root):
        raise SystemExit(f"label_eval: external judgment denied by engagement policy "
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
    items = json.loads((SCRATCH / "label_eval_set.json").read_text())
    rows: list[dict] = []
    for item in items:
        draft = draft_technique_payload(root, f"eval-{item['id']}",
                                        transcript=item["transcript"], evidence_refs=[])
        base = baseline_label(item["transcript"])
        rows.append({
            "id": item["id"], "truth": item["truth"],
            "baseline_label": base, "baseline_correct": base == item["truth"],
            "seam_label": draft["result"], "seam_correct": draft["result"] == item["truth"],
            "seam_family": draft["technique_family"],
            "seam_has_learning": draft["_draft"]["has_learning"],
            "seam_notes": draft["_draft"]["notes"],
            "model": draft["_draft"]["model"], "usage": draft["_draft"]["usage"],
        })
        print(f"{item['id']:<28} truth={item['truth']:<14} baseline={base:<14} "
              f"seam={draft['result']} learning={draft['_draft']['has_learning']}")
    base_correct = sum(1 for r in rows if r["baseline_correct"])
    seam_correct = sum(1 for r in rows if r["seam_correct"])
    ship = seam_correct > base_correct
    print(f"\nlabel accuracy: baseline {base_correct}/{len(rows)} -> seam {seam_correct}/{len(rows)}")
    print(f"ship (seam beats the deterministic baseline): {ship}")
    payload = {
        "eval": "technique-labeling", "baseline_rules": [list(r) for r in BASELINE_RULES],
        "baseline_correct": base_correct, "seam_correct": seam_correct,
        "ship": ship, "rows": rows,
    }
    write_results(SCRATCH / "label_results.json", payload, force=force)


def cli(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="label_eval",
        description="Live paired eval: keyword heuristic vs the technique-labeling aid "
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
