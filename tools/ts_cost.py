#!/usr/bin/env python3
"""Jev cost ledger: per-decision spend rows with estimated-vs-measured separation.

The TypeSafe System One API returns token usage only — there is no USD field and no
official rate card — so every figure this module computes is `estimated: true` and
names its source (`tokens×<rate>`); a `measured` figure can only arrive from an
explicit measured source (a provider invoice, a metered proxy). Estimated and measured
totals are reported separately and are never summed into one number, and nothing here
feeds the action-budget caps (`budget_status` / `prepare_action` count actions, never
dollars — the regression is pinned in tools/test_cost.py).

Rows live in `11_runtime/jev-costs.jsonl`, append-only, mirroring the judgment ledger
(`11_runtime/jev-judgments.jsonl`). Stdlib only.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

COSTS_REL = "11_runtime/jev-costs.jsonl"
# The one documented rate the repo already used in its eval runs (rerank_eval printed
# `tin/1_000_000*42`). No official rate card exists; override with the env var.
DEFAULT_USD_PER_MTOK = 42.0
ESTIMATE_SOURCE = "tokens×{rate:.2f}USD/1Mtok rate (estimated; no measured source)"


def usd_per_mtok() -> float:
    """Token rate used for estimates: TYPESAFE_USD_PER_MTOK, else the repo default."""
    raw = os.environ.get("TYPESAFE_USD_PER_MTOK", "")
    try:
        rate = float(raw)
    except (TypeError, ValueError):
        return DEFAULT_USD_PER_MTOK
    return rate if rate >= 0 else DEFAULT_USD_PER_MTOK


def _tokens(value: Any) -> int:
    """Non-negative int tokens; malformed usage counts as zero, never raises."""
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, value)


def estimate_usd(usage: dict | None) -> float:
    """Estimated USD for a usage dict at the documented token rate."""
    usage = usage if isinstance(usage, dict) else {}
    total = _tokens(usage.get("input_tokens")) + _tokens(usage.get("output_tokens"))
    return total * usd_per_mtok() / 1_000_000


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def record_cost(root: Path, *, decision: str, usage: dict | None = None,
                model: str | None = None, cycle_id: str | None = None,
                latency_ms: int | None = None, measured_usd: float | None = None,
                source: str | None = None, actor: str = "controller") -> dict[str, Any]:
    """Append one per-decision cost row and return it.

    `measured_usd` given -> `estimated: false` with the caller's `source` (the measured
    origin); otherwise the row is `estimated: true` with the computed figure and its
    rate named. The two kinds never blend: a row is one or the other.
    """
    if not str(decision or "").strip():
        raise ValueError("cost row needs a decision name")
    if measured_usd is not None and (isinstance(measured_usd, bool)
                                     or not isinstance(measured_usd, (int, float))
                                     or measured_usd < 0):
        raise ValueError("measured_usd must be a non-negative number")
    if measured_usd is not None and not str(source or "").strip():
        raise ValueError("a measured cost row needs its measured source (where the figure came from)")
    usage = usage if isinstance(usage, dict) else {}
    rate = usd_per_mtok()
    row: dict[str, Any] = {
        "time": _now_iso(),
        "decision": str(decision).strip(),
        "model": model,
        "cycle_id": str(cycle_id) if cycle_id else None,
        "input_tokens": _tokens(usage.get("input_tokens")),
        "output_tokens": _tokens(usage.get("output_tokens")),
        "usd": round(float(measured_usd), 6) if measured_usd is not None
               else round(estimate_usd(usage), 6),
        "estimated": measured_usd is None,
        "source": str(source).strip() if measured_usd is not None
                  else ESTIMATE_SOURCE.format(rate=rate),
        "latency_ms": max(0, int(latency_ms)) if latency_ms is not None else None,
        "actor": actor,
    }
    path = Path(root) / COSTS_REL
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    return row


def record_seam_cost(root: Path, *, decision: str, out: Any, cycle_id: str | None = None,
                     latency_ms: int | None = None) -> dict[str, Any] | None:
    """Ledger a seam result's usage; a no-spend result records nothing.

    Policy-denied, no-key and `live=False` shapes carry an empty usage — no model was
    called, so there is no decision to price. Everything else lands as one estimated
    row (`model` from the seam result) for the per-decision/per-cycle summaries.
    """
    if not isinstance(out, dict):
        return None
    usage = out.get("usage") if isinstance(out.get("usage"), dict) else {}
    if not (_tokens(usage.get("input_tokens")) or _tokens(usage.get("output_tokens"))):
        return None
    return record_cost(root, decision=decision, usage=usage, model=out.get("model"),
                       cycle_id=cycle_id, latency_ms=latency_ms)


def cost_rows(root: Path, *, cycle_id: str | None = None) -> list[dict[str, Any]]:
    """All ledger rows (optionally filtered to one cycle); malformed lines are skipped."""
    path = Path(root) / COSTS_REL
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line in path.read_text(errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        if cycle_id is not None and str(row.get("cycle_id") or "") != str(cycle_id):
            continue
        rows.append(row)
    return rows


def _bucket() -> dict[str, float | int]:
    return {"rows": 0, "estimated_rows": 0, "measured_rows": 0,
            "estimated_usd": 0.0, "measured_usd": 0.0}


def _add(bucket: dict[str, float | int], row: dict[str, Any]) -> None:
    bucket["rows"] += 1
    if row.get("estimated"):
        bucket["estimated_rows"] += 1
        bucket["estimated_usd"] += float(row.get("usd") or 0.0)
    else:
        bucket["measured_rows"] += 1
        bucket["measured_usd"] += float(row.get("usd") or 0.0)


def cost_summary(root: Path, *, cycle_id: str | None = None) -> dict[str, Any]:
    """Spend totals with estimated and measured kept apart, per decision and per cycle.

    There is deliberately no combined `total_usd`: an estimated figure must never be
    read as a measured one (mirrors the harness manifest's `cost_estimated` semantics).
    """
    rows = cost_rows(root, cycle_id=cycle_id)
    total = _bucket()
    by_decision: dict[str, dict[str, float | int]] = {}
    by_cycle: dict[str, dict[str, float | int]] = {}
    for row in rows:
        _add(total, row)
        _add(by_decision.setdefault(str(row.get("decision") or "unknown"), _bucket()), row)
        if row.get("cycle_id"):
            _add(by_cycle.setdefault(str(row["cycle_id"]), _bucket()), row)
    for bucket in list(by_decision.values()) + list(by_cycle.values()):
        bucket["estimated_usd"] = round(float(bucket["estimated_usd"]), 6)
        bucket["measured_usd"] = round(float(bucket["measured_usd"]), 6)
    total["estimated_usd"] = round(float(total["estimated_usd"]), 6)
    total["measured_usd"] = round(float(total["measured_usd"]), 6)
    return {
        "rows": total["rows"],
        "estimated_rows": total["estimated_rows"],
        "measured_rows": total["measured_rows"],
        "estimated_usd": total["estimated_usd"],
        "measured_usd": total["measured_usd"],
        "by_decision": by_decision,
        "by_cycle": by_cycle,
    }
