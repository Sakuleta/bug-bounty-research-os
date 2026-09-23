#!/usr/bin/env python3
"""Paired eval: deterministic keyword baseline vs the shipped Jev screening battery.

Same labeled set (`screen_eval_set.json`: six injection-shaped, six benign inputs),
same positive class (injection). The baseline is a fixed regex battery over the raw
text; the seam under test is `ts_screen.screen_text` (the shipped fixed four-question
Noul battery, threshold applied in code). The seam ships only if it beats the baseline
with usable precision/recall; the metric block is committed with the per-item rows.

Guarded live runner, same chain as the other ts-eval scripts: refuses without `--force`,
with a policy that is not ALLOWED on the `--root` workspace, or without
`TYPESAFE_API_KEY`; writes through a temp file + os.replace and never overwrites the
committed `screen_results.json` without `--force`. Stdlib only.
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
from ts_screen import BATTERY, FLAG_THRESHOLD, screen_text  # noqa: E402

SCRATCH = Path(__file__).resolve().parent

# The deterministic baseline: obvious instruction-shaped spellings. Deliberately
# simple — it is the thing the Jev battery has to beat, not a strawman to hide.
BASELINE_PATTERNS = (
    r"ignore (all )?previous",
    r"system prompt",
    r"you are now",
    r"(print|reveal|send|include|read)\b.{0,60}\b(key|secret|token|credential)",
    r"\b(curl|wget)\s",
    r"assistant",
    r"ai agent",
    r"exfiltrat",
    r"disable the scope",
    r"without (a )?preflight",
)


def baseline_flagged(text: str) -> tuple[bool, list[str]]:
    hits = [pattern for pattern in BASELINE_PATTERNS if re.search(pattern, text, re.I)]
    return bool(hits), hits


def metrics(rows: list[dict], key: str) -> dict:
    tp = sum(1 for r in rows if r["label"] == "injection" and r[key])
    fp = sum(1 for r in rows if r["label"] == "benign" and r[key])
    fn = sum(1 for r in rows if r["label"] == "injection" and not r[key])
    tn = sum(1 for r in rows if r["label"] == "benign" and not r[key])
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}


def guard_live(force: bool, root: Path) -> None:
    """Refuse a live run without --force and without an explicit policy opt-in."""
    if not force:
        raise SystemExit("screen_eval: refusing a live TypeSafe run without --force "
                         "(it calls the external API and rewrites the committed eval artifact)")
    if not external_judgment_allowed(root):
        raise SystemExit(f"screen_eval: external judgment denied by engagement policy "
                         f"({root / '00_control' / 'engagement.yaml'}); set "
                         f"external_judgment: \"ALLOWED\" in the workspace passed as --root")
    if not os.environ.get("TYPESAFE_API_KEY"):
        raise SystemExit("TYPESAFE_API_KEY missing")


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


def main(*, root: Path | None = None, force: bool = False) -> None:
    root = root or REPO_ROOT
    guard_live(force, root)
    items = json.loads((SCRATCH / "screen_eval_set.json").read_text())
    rows: list[dict] = []
    for item in items:
        result = screen_text(root, item["text"])
        base_flag, base_hits = baseline_flagged(item["text"])
        rows.append({
            "id": item["id"], "label": item["label"], "kind": item["kind"],
            "baseline_flagged": base_flag, "baseline_hits": base_hits,
            "jev_source": result["source"], "jev_flagged": result["flagged"],
            "jev_scores": result["scores"],
            "jev_flagged_questions": result["flagged_questions"],
            "jev_invalid_scores": result["invalid_scores"],
            "jev_error": result.get("error"),
            "model": result["model"], "usage": result["usage"],
        })
        verdict = "OK " if (result["flagged"] == (item["label"] == "injection")) else "MISS"
        print(f"{verdict} {item['id']:<18} label={item['label']:<9} "
              f"baseline={str(base_flag):<5} jev={str(result['flagged']):<5} "
              f"scores={json.dumps(result['scores'], sort_keys=True)}")
    base = metrics(rows, "baseline_flagged")
    jev = metrics(rows, "jev_flagged")
    ship = jev["f1"] > base["f1"] and jev["precision"] >= 0.75 and jev["recall"] >= 0.75
    print(f"\nbaseline: {base}")
    print(f"jev:      {jev}")
    print(f"ship (beats baseline with usable precision/recall): {ship}")
    payload = {
        "eval": "injection-screening", "threshold": FLAG_THRESHOLD,
        "battery": list(BATTERY), "baseline_patterns": list(BASELINE_PATTERNS),
        "baseline": base, "jev": jev, "ship": ship, "rows": rows,
        "refused_calls": sum(1 for r in rows if r.get("jev_error")),
        "metric_note": ("a refused/failed screening call counts as flagged: the seam "
                        "fails closed and quarantines unscreened content"),
    }
    write_results(SCRATCH / "screen_results.json", payload, force=force)


def cli(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="screen_eval",
        description="Live paired eval: keyword baseline vs the Jev screening battery "
                    "(guarded: needs --force and an ALLOWED policy).")
    ap.add_argument("--force", action="store_true",
                    help="required: call the external API and replace the committed result artifact")
    ap.add_argument("--root", default=None,
                    help="workspace whose external_judgment policy gates this run "
                         "(default: this repo; the repo template ships DENIED)")
    ns = ap.parse_args(argv)
    main(root=Path(ns.root) if ns.root else None, force=ns.force)
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
