#!/usr/bin/env python3
"""v8.3 V6a (T3): entity-resolution novelty/duplicate aid — pairwise Choice over
blocked candidates, `unclear` routed to the human lane, strictly advisory to the
deterministic novelty-duplicate audit (it never records an audit, never names a
finding, never closes anything).
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from control_plane import ControlPlane  # noqa: E402
from ts_cost import cost_rows  # noqa: E402
from ts_novelty import (CONFIDENCE_THRESHOLD, block_candidates, check_novelty,  # noqa: E402
                        hypothesis_pool)

passed: list[str] = []


def check(name: str, cond: bool):
    assert cond, f"FAIL: {name}"
    passed.append(name)
    print(f"ok: {name}")


def workspace(policy: str = 'external_judgment: "ALLOWED"\n') -> Path:
    root = Path(tempfile.mkdtemp())
    for d in ["00_control", "11_runtime"]:
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / "00_control/engagement.yaml").write_text(policy)
    (root / "11_runtime/events.jsonl").write_text("")
    return root


ALLOWED = workspace()
DENIED = workspace('external_judgment: "DENIED"\n')

CANDIDATE = {"id": "H-0099",
             "text": "The export endpoint returns other tenants' rows when the tenant "
                     "header is omitted; the ORM scope is skipped on the raw query path."}
SAME = {"id": "H-0007",
        "text": "Raw export query bypasses the tenant ORM scope when the header is "
                "missing, leaking cross-tenant rows."}
DIFFERENT = {"id": "H-0008",
             "text": "The password reset token is not rotated after use, so a captured "
                     "link stays valid until expiry."}
UNRELATED = {"id": "H-0009",
             "text": "CDN cache poisoning via unkeyed X-Forwarded-Host on the marketing site."}

# 1. Cheap deterministic blocking runs before any model call.
blocked = block_candidates(CANDIDATE, [SAME, DIFFERENT, UNRELATED])
check("blocking keeps the keyword-overlap candidate and drops the unrelated one",
      [b["id"] for b in blocked] == ["H-0007"] and blocked[0]["overlap"] >= 0.3)
exact = block_candidates({"id": "c", "text": SAME["text"]}, [SAME, DIFFERENT])
check("blocking shortlists an exact normalized-hash duplicate first",
      exact[0]["id"] == "H-0007" and exact[0]["exact"] is True)
check("blocking returns nothing for a pool with no plausible pair",
      block_candidates(CANDIDATE, [UNRELATED]) == [])

# 2. The gate: DENIED / live=False never call the client.
denied_calls: list = []
denied = check_novelty(DENIED, CANDIDATE, pool=[SAME],
                       client=lambda s, q: denied_calls.append(s) or {})
check("the DENIED policy returns unavailable and never calls the client",
      denied["source"] == "unavailable" and denied["proposals"] == []
      and denied["note"] == "external judgment denied by engagement policy"
      and denied_calls == [])
check("live=False returns unavailable",
      check_novelty(ALLOWED, CANDIDATE, pool=[SAME], live=False,
                    client=lambda s, q: {})["source"] == "unavailable")


def pair_client(choice: str, confidence: float):
    def client(state, questions):
        assert set(questions) == {"pair"}, "one pair question per judged candidate"
        return {"model": "stub-novelty",
                "answers": {"pair": {"type": "choice", "choice": choice,
                                     "confidence": confidence,
                                     "probabilities": {choice: 0.9}}},
                "usage": {"input_tokens": 20, "output_tokens": 3}}
    return client


# 3. Same/different proposals; unclear routes to the human lane.
same_out = check_novelty(ALLOWED, CANDIDATE, pool=[SAME], client=pair_client("same", 0.92))
check("a confident same verdict is a proposal, not a decision",
      same_out["source"] == "typesafe" and same_out["proposals"][0]["verdict"] == "same"
      and same_out["proposals"][0]["auto"] is True and same_out["human_lane"] == []
      and same_out["advisory"] is True)
diff_out = check_novelty(ALLOWED, CANDIDATE, pool=[SAME], client=pair_client("different", 0.9))
check("a different verdict is advisory and does not touch the human lane",
      diff_out["proposals"][0]["verdict"] == "different"
      and diff_out["proposals"][0]["auto"] is True and diff_out["human_lane"] == [])
unclear_out = check_novelty(ALLOWED, CANDIDATE, pool=[SAME], client=pair_client("unclear", 0.9))
check("an unclear verdict routes to the human lane",
      unclear_out["proposals"][0]["verdict"] == "unclear"
      and unclear_out["proposals"][0]["auto"] is False
      and unclear_out["human_lane"] == ["H-0007"])

# 4. Thresholds are code: below-threshold confidence becomes unclear + human lane.
low = check_novelty(ALLOWED, CANDIDATE, pool=[SAME],
                    client=pair_client("same", CONFIDENCE_THRESHOLD - 0.1))
check("a below-threshold same verdict degrades to unclear in the human lane",
      low["proposals"][0]["verdict"] == "unclear" and low["human_lane"] == ["H-0007"]
      and "threshold" in low["proposals"][0]["note"])
bad = check_novelty(ALLOWED, CANDIDATE, pool=[SAME],
                    client=lambda s, q: {"model": "stub", "answers": {"pair": {
                        "type": "choice", "choice": "probably", "confidence": 0.99}},
                        "usage": {}})
check("an invalid choice is flagged and routed to the human lane, never surfaced",
      bad["proposals"][0]["verdict"] == "unclear" and bad["human_lane"] == ["H-0007"]
      and "rejected" in bad["proposals"][0]["note"])

# 5. Strictly advisory: no ledger events, no audit records, no state mutation.
cp = ControlPlane(ALLOWED)
check("the aid writes no control-plane events (advisory only)",
      cp._read_events() == [] and cp.evidence_index() == {})
check("the aid ledgers its usage as an estimated cost row",
      any(r["decision"] == "novelty" and r["estimated"] for r in cost_rows(ALLOWED)))

# 6. The pool comes from the ledger's hypotheses when none is given.
pool_root = workspace()
pcp = ControlPlane(pool_root)
pcp.create_cycle("C-0001", {"id": "C-0001", "type": "DISCOVERY", "objective": "novelty pool",
                            "allowed_scope": ["example.test"], "stop_conditions": ["stop"],
                            "controls": [], "status": "PLANNED",
                            "knowledge_triage": [{"pack": "fixture", "verdict": "SKIP",
                                                  "reason": "fixture covers the pool"}]})
for hid, data in (("H-0001", {"cycle_id": "C-0001", "observation": SAME["text"],
                              "hypothesis": SAME["text"], "secure_prediction": "denied",
                              "vulnerable_prediction": "allowed"}),
                  ("H-0002", {"cycle_id": "C-0001", "observation": UNRELATED["text"],
                              "hypothesis": UNRELATED["text"], "secure_prediction": "denied",
                              "vulnerable_prediction": "allowed"})):
    pcp.create_hypothesis(hid, data)
pool = hypothesis_pool(pool_root)
check("the default pool reads open hypotheses from the ledger",
      {p["id"] for p in pool} == {"H-0001", "H-0002"}
      and any("tenant" in p["text"] for p in pool))
ledger_out = check_novelty(pool_root, CANDIDATE, client=pair_client("same", 0.9))
check("the aid judges only the blocked pairs from the ledger pool",
      [p["id"] for p in ledger_out["proposals"]] == ["H-0001"])

# 7. CLI wiring: `researchctl novelty candidate.json`.
import contextlib  # noqa: E402
import io  # noqa: E402
from researchctl import main as ctl_main  # noqa: E402

cand_file = pool_root / "candidate.json"
cand_file.write_text(json.dumps(CANDIDATE))


def cli_post(payload, **kwargs):
    return {"model": "stub-novelty",
            "answers": {"pair": {"type": "choice", "choice": "different", "confidence": 0.95,
                                 "probabilities": {"different": 0.95}}},
            "usage": {"input_tokens": 5, "output_tokens": 1}}


with mock.patch("ts_novelty.post_json", cli_post), \
        mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "k"}):
    buf = io.StringIO()
    with mock.patch.object(sys, "argv", [str(TOOLS / "researchctl.py"), str(pool_root),
                                         "novelty", str(cand_file)]), \
            contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        rc_novelty = ctl_main()
cli_out = json.loads(buf.getvalue())
check("researchctl novelty prints the advisory proposals",
      rc_novelty == 0 and cli_out["advisory"] is True
      and cli_out["proposals"][0]["verdict"] == "different"
      and cli_out["proposals"][0]["id"] == "H-0001")

print(f"\n{len(passed)}/{len(passed)} passed")
