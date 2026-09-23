#!/usr/bin/env python3
"""Paired eval: presence heuristic vs the knowledge-use honesty check.

Same labeled rows (`honesty_eval_set.json`: genuine uses and decorative citations of a
pack over cycle outputs). Baseline: the audit-style presence heuristic — a distinctive
guide keyword appearing in the outputs means "used". Seam:
`ts_honesty.check_knowledge_use` (one Noul per cited pack: is the citation
load-bearing?). Advisory both ways; the metric is use/decorative accuracy.

Ship criterion: the seam beats the baseline.

Guarded live runner, same chain as the other ts-eval scripts (`--force`, ALLOWED
policy, `TYPESAFE_API_KEY`, atomic write, never overwrite without `--force`).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # tools/
from control_plane import external_judgment_allowed  # noqa: E402
from ts_honesty import check_knowledge_use  # noqa: E402

SCRATCH = Path(__file__).resolve().parent


def presence_verdict(cycle_outputs: str, pack_guide: str) -> str:
    """The presence heuristic: any distinctive guide keyword in the outputs = used."""
    keywords = {w for w in re.findall(r"[a-z]{4,}", pack_guide.lower())}
    lowered = cycle_outputs.lower()
    return "used" if any(word in lowered for word in keywords) else "decorative"


def guard_live(force: bool, root: Path) -> None:
    if not force:
        raise SystemExit("honesty_eval: refusing a live TypeSafe run without --force "
                         "(it calls the external API and rewrites the committed eval artifact)")
    if not external_judgment_allowed(root):
        raise SystemExit(f"honesty_eval: external judgment denied by engagement policy "
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
    items = json.loads((SCRATCH / "honesty_eval_set.json").read_text())
    rows: list[dict] = []
    for item in items:
        result = check_knowledge_use(root, f"eval-{item['id']}",
                                     cycle_outputs=item["cycle_outputs"],
                                     packs=[item["pack"]],
                                     guides={item["pack"]: item["pack_guide"]})
        checked = result["checked"][0] if result["checked"] else {}
        seam_verdict = "used" if (checked.get("score") is not None
                                  and checked["score"] >= result["threshold"]) else "decorative"
        base = presence_verdict(item["cycle_outputs"], item["pack_guide"])
        rows.append({
            "id": item["id"], "truth": item["truth"], "pack": item["pack"],
            "baseline_verdict": base, "baseline_correct": base == item["truth"],
            "seam_verdict": seam_verdict, "seam_correct": seam_verdict == item["truth"],
            "seam_score": checked.get("score"), "seam_warning": checked.get("warning"),
            "model": result["model"], "usage": result["usage"],
        })
        print(f"{item['id']:<28} truth={item['truth']:<11} baseline={base:<11} "
              f"seam={seam_verdict:<11} score={checked.get('score')}")
    base_correct = sum(1 for r in rows if r["baseline_correct"])
    seam_correct = sum(1 for r in rows if r["seam_correct"])
    ship = seam_correct > base_correct
    print(f"\naccuracy: baseline {base_correct}/{len(rows)} -> seam {seam_correct}/{len(rows)}")
    print(f"ship (seam beats the deterministic baseline): {ship}")
    payload = {
        "eval": "knowledge-use-honesty", "baseline_correct": base_correct,
        "seam_correct": seam_correct, "ship": ship, "rows": rows,
        "advisory_note": "warnings only; the audit's presence heuristic and the human remain deciding",
    }
    write_results(SCRATCH / "honesty_results.json", payload, force=force)


def cli(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="honesty_eval",
        description="Live paired eval: presence heuristic vs the knowledge-use honesty "
                    "check (guarded: needs --force and an ALLOWED policy).")
    ap.add_argument("--force", action="store_true",
                    help="required: call the external API and replace the committed result artifact")
    ap.add_argument("--root", default=None,
                    help="workspace whose external_judgment policy gates this run")
    ns = ap.parse_args(argv)
    main(root=Path(ns.root) if ns.root else None, force=ns.force)
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
