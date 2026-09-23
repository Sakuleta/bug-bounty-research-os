#!/usr/bin/env python3
"""v8.3 V5: the Jev cost ledger — estimated vs measured separation, per-decision rows
and the regression that no cap logic consumes an estimated figure as measured.

The TypeSafe API returns token usage only (no USD), so every computed figure is
`estimated: true` with its source named; a measured figure can only arrive from an
explicit measured source. The action budget (`budget_status`/`prepare_action`) counts
actions and must be byte-for-byte unaffected by any spend row.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from control_plane import ControlPlane  # noqa: E402
from ts_cost import COSTS_REL, cost_rows, cost_summary, estimate_usd, record_cost  # noqa: E402

passed: list[str] = []


def check(name: str, cond: bool):
    assert cond, f"FAIL: {name}"
    passed.append(name)
    print(f"ok: {name}")


def cost_root() -> Path:
    root = Path(tempfile.mkdtemp())
    for d in ["00_control", "11_runtime"]:
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / "00_control/engagement.yaml").write_text(
        'external_judgment: "ALLOWED"\n'
        'scope:\n  assets:\n  - "example.test"\n'
        "budget:\n  max_actions_per_cycle: 5\n  max_actions_per_engagement: 40\n")
    (root / "11_runtime/events.jsonl").write_text("")
    (root / "12_knowledge/fixture").mkdir(parents=True, exist_ok=True)
    (root / "12_knowledge/fixture/fixture.md").write_text("# Fixture pack\n")
    (root / "12_knowledge/INDEX.yaml").write_text(
        "packs:\n  fixture:\n    load_when: [test, realtime, socket, leak]\n    files: [fixture.md]\n")
    (root / "proof.txt").write_text("HTTP 200 observed with title Example Domain\n")
    return root


root = cost_root()
ControlPlane(root).register_evidence("proof.txt", kind="raw", source="test")

# 1. Estimation: tokens x the documented rate; env-overridable; garbage never raises.
with mock.patch.dict(os.environ, {"TYPESAFE_USD_PER_MTOK": "42"}):
    check("estimate_usd prices input+output tokens at the documented rate",
          estimate_usd({"input_tokens": 1000, "output_tokens": 500}) == 1500 * 42.0 / 1_000_000)
with mock.patch.dict(os.environ, {"TYPESAFE_USD_PER_MTOK": "10"}):
    check("TYPESAFE_USD_PER_MTOK overrides the rate",
          estimate_usd({"input_tokens": 1_000_000}) == 10.0)
check("estimate_usd treats malformed usage as zero, never raises",
      estimate_usd({"input_tokens": "many", "output_tokens": None}) == 0.0
      and estimate_usd({}) == 0.0)

# 2. Rows: every computed figure is flagged estimated and names its source.
row = record_cost(root, decision="triage", usage={"input_tokens": 1000, "output_tokens": 500},
                  model="jev-latest", latency_ms=812)
check("record_cost appends one per-decision row with usd/estimated/source",
      row["decision"] == "triage" and row["usd"] > 0 and row["estimated"] is True
      and "rate" in row["source"] and row["latency_ms"] == 812 and row["model"] == "jev-latest")
check("the ledger is the documented append-only JSONL",
      [r["decision"] for r in cost_rows(root)] == ["triage"]
      and (root / COSTS_REL).read_text().strip().count("\n") == 0)

measured = record_cost(root, decision="technique-label", usage={"input_tokens": 10},
                       measured_usd=0.004, source="provider invoice 2026-09-23", cycle_id="C-0001")
check("a measured row is not estimated and carries its measured source",
      measured["estimated"] is False and measured["usd"] == 0.004
      and measured["source"] == "provider invoice 2026-09-23")
record_cost(root, decision="claims-check", usage={"input_tokens": 2000, "output_tokens": 100},
            cycle_id="C-0001")

# 3. Summary: estimated and measured totals are separate, never one blended total.
summary = cost_summary(root)
check("cost_summary separates estimated and measured totals",
      summary["estimated_usd"] > 0 and summary["measured_usd"] == 0.004
      and summary["estimated_rows"] == 2 and summary["measured_rows"] == 1
      and "total_usd" not in summary)
check("cost_summary groups spend per decision",
      summary["by_decision"]["triage"]["estimated_usd"] > 0
      and summary["by_decision"]["technique-label"]["measured_usd"] == 0.004
      and summary["by_decision"]["technique-label"]["estimated_usd"] == 0.0)
check("cost_summary groups spend per cycle",
      summary["by_cycle"]["C-0001"]["rows"] == 2
      and summary["by_cycle"]["C-0001"]["measured_usd"] == 0.004)
check("cost_summary filters by cycle",
      cost_summary(root, cycle_id="C-0001")["rows"] == 2
      and cost_summary(root, cycle_id="C-9999")["rows"] == 0)

# 4. Regression: no cap logic consumes an estimated figure as measured.
cp = ControlPlane(root)
before = cp.budget_status()
record_cost(root, decision="claims-draft", usage={"input_tokens": 9_000_000, "output_tokens": 0})
after = cp.budget_status()
check("a huge estimated spend never moves the action-budget remaining",
      after["remaining"] == before["remaining"] and after["counts"] == before["counts"])
check("the spend rides beside the action budget, visibly estimated",
      after["spend"]["estimated_usd"] > 300 and after["spend"]["measured_usd"] == 0.004)

malformed = cost_root()
(malformed / "00_control/engagement.yaml").write_text("budget: 5\n")
record_cost(malformed, decision="triage", usage={"input_tokens": 10})
try:
    ControlPlane(malformed).budget_status()
    refused = False
except ValueError as exc:
    refused = "malformed" in str(exc)
check("budget_status still refuses a malformed block with spend present", refused)

# 5. CLI surfaces: budget status shows spend; triage/claims-check record their usage.
proc = subprocess.run([sys.executable, str(TOOLS / "researchctl.py"), str(root), "budget", "status"],
                      capture_output=True, text=True)
cli_status = json.loads(proc.stdout)
check("researchctl budget status carries the spend block",
      proc.returncode == 0 and cli_status["spend"]["estimated_usd"] > 0
      and cli_status["spend"]["measured_usd"] == 0.004
      and cli_status["remaining"] == before["remaining"])

triage_payloads: list = []


def fake_triage_post(payload, **kwargs):
    triage_payloads.append(payload)
    return {"model": "jev-test-2",
            "answers": {"first_pack": {"choice": "fixture", "confidence": 0.9,
                                       "probabilities": {"fixture": 0.9, "none": 0.1}}},
            "usage": {"input_tokens": 300, "output_tokens": 30}}


from researchctl import main as ctl_main  # noqa: E402  (import-time wiring check)

import contextlib  # noqa: E402
import io  # noqa: E402


def run_cli(argv: list[str]):
    buf = io.StringIO()
    with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(buf):
        rc = ctl_main()
    return rc, buf.getvalue()


with mock.patch("ts_triage.post_json", fake_triage_post), \
        mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "k"}):
    rc_triage, triage_stdout = run_cli([str(TOOLS / "researchctl.py"), str(root),
                                        "triage", "realtime socket leak"])
triage_rows = [r for r in cost_rows(root) if r["decision"] == "triage"]
check("researchctl triage ledgers its usage as an estimated row",
      rc_triage == 0 and json.loads(triage_stdout)["source"] == "typesafe"
      and len(triage_rows) == 2 and len(triage_payloads) == 1
      and triage_rows[-1]["input_tokens"] == 300 and triage_rows[-1]["estimated"] is True
      and triage_rows[-1]["latency_ms"] >= 0)


def fake_claims_post(payload, **kwargs):
    return {"model": "jev-test-2",
            "answers": {"relation": {"choice": "supports", "confidence": 0.9,
                                     "probabilities": {"supports": 0.9, "contradicts": 0.05,
                                                       "says_nothing": 0.05}},
                        "verify": {"choice": "supported", "confidence": 0.9}},
            "usage": {"input_tokens": 40, "output_tokens": 4}}


packet = root / "packet.json"
packet.write_text(json.dumps({"claims": [{"id": "c1", "claim": "HTTP 200 was observed",
                                          "evidence_ref": "E-000001"}]}))
with mock.patch("ts_claims.post_json", fake_claims_post), \
        mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "k"}):
    rc_claims, _ = run_cli([str(TOOLS / "researchctl.py"), str(root),
                            "claims-check", str(packet)])
claims_rows = [r for r in cost_rows(root) if r["decision"] == "claims-check"]
check("researchctl claims-check ledgers the verify-chain usage",
      rc_claims == 0 and claims_rows and claims_rows[-1]["input_tokens"] == 80
      and claims_rows[-1]["estimated"] is True)

print(f"\n{len(passed)}/{len(passed)} passed")
