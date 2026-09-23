#!/usr/bin/env python3
"""v8.3 V6b (T4): hypothesis ranking / next-test selection — one Noul per open
hypothesis over the cycle question, the safety veto in code (never the model), the
highest-information SAFE test as the pick, and an escalation lane for low-confidence
or narrow-margin rankings. Advisory only: the controller still selects.
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
from ts_rank import (ESCALATE_MARGIN, INFO_THRESHOLD, open_hypotheses,  # noqa: E402
                     rank_hypotheses)

passed: list[str] = []


def check(name: str, cond: bool):
    assert cond, f"FAIL: {name}"
    passed.append(name)
    print(f"ok: {name}")


def workspace(policy: str = 'external_judgment: "ALLOWED"\n') -> Path:
    root = Path(tempfile.mkdtemp())
    for d in ["00_control", "11_runtime", "12_knowledge/fixture"]:
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / "00_control/engagement.yaml").write_text(policy)
    (root / "11_runtime/events.jsonl").write_text("")
    (root / "12_knowledge/fixture/fixture.md").write_text("# Fixture pack\n")
    (root / "12_knowledge/INDEX.yaml").write_text(
        "packs:\n  fixture:\n    load_when: [rank, fixture]\n    files: [fixture.md]\n")
    return root


ALLOWED = workspace()
DENIED = workspace('external_judgment: "DENIED"\n')


def add_cycle(root: Path, cid: str = "C-0001") -> None:
    ControlPlane(root).create_cycle(cid, {
        "id": cid, "type": "HYPOTHESIS", "objective": "which export weakness is real",
        "allowed_scope": ["example.test"], "stop_conditions": ["stop"], "controls": [],
        "status": "PLANNED",
        "knowledge_triage": [{"pack": "fixture", "verdict": "SKIP",
                              "reason": "fixture covers the ranking seam"}]})


def add_hyp(root: Path, hid: str, text: str, **extra) -> None:
    data = {"cycle_id": "C-0001", "observation": text, "hypothesis": text,
            "secure_prediction": "denied", "vulnerable_prediction": "allowed", **extra}
    ControlPlane(root).create_hypothesis(hid, data)


add_cycle(ALLOWED)
add_hyp(ALLOWED, "H-0001", "Does the export endpoint enforce the tenant filter for API keys?",
        information_gain="high")
add_hyp(ALLOWED, "H-0002", "Does the export endpoint's pagination limit hold under load?")
add_hyp(ALLOWED, "H-0003", "Retest the already-verified login banner.",
        side_effect_risk="high")

check("open_hypotheses reads non-terminal hypotheses with their text and risk",
      {h["id"] for h in open_hypotheses(ALLOWED)} == {"H-0001", "H-0002", "H-0003"}
      and open_hypotheses(ALLOWED)[0]["text"].startswith("Does the export endpoint enforce"))

# 1. Gate.
denied_calls: list = []
denied = rank_hypotheses(DENIED, client=lambda s, q: denied_calls.append(s) or {})
check("the DENIED policy returns unavailable and never calls the client",
      denied["source"] == "unavailable" and denied["ranking"] == [] and denied["pick"] is None
      and denied_calls == [])
check("live=False returns unavailable",
      rank_hypotheses(ALLOWED, live=False, client=lambda s, q: {})["source"] == "unavailable")

# 2. One call, one Noul per open hypothesis; code picks the max among SAFE hypotheses.
calls: list = []


def rank_client(scores: dict[str, float]):
    def client(state, questions):
        calls.append((state, questions))
        return {"model": "stub-rank",
                "answers": {name: {"type": "noul", "noul": scores[name]}
                            for name in questions},
                "usage": {"input_tokens": 30, "output_tokens": 3}}
    return client


HIGH = {"info_1": 0.95, "info_2": 0.5, "info_3": 0.99}
picked = rank_hypotheses(ALLOWED, client=rank_client(HIGH), cycle_id="C-0001")
check("one call asks one info question per open hypothesis",
      len(calls) == 1 and set(calls[0][1]) == {"info_1", "info_2", "info_3"}
      and calls[0][0]["question"] == "which export weakness is real")
check("the code picks the highest-information SAFE test, not the model's top score",
      picked["pick"] == "H-0001" and picked["escalate"] is False
      and next(r for r in picked["ranking"] if r["safe"])["id"] == "H-0001"
      and picked["vetoed"] == ["H-0003"] and "high" in picked["vetoed_reasons"]["H-0003"])
check("the safety veto is code: the unsafe hypothesis is never the pick",
      all(row["id"] != "H-0003" or row["safe"] is False for row in picked["ranking"]))

# 3. Escalation lanes: all unsafe, below threshold, narrow margin.
all_unsafe = rank_hypotheses(ALLOWED, client=rank_client({"info_1": 0.1, "info_2": 0.1,
                                                          "info_3": 0.99}),
                             cycle_id="C-0001")
check("no safe candidate above the threshold escalates instead of picking",
      all_unsafe["pick"] is None and all_unsafe["escalate"] is True
      and "safe" in all_unsafe["reason"])
low = rank_hypotheses(ALLOWED, client=rank_client({"info_1": INFO_THRESHOLD - 0.2,
                                                   "info_2": 0.1, "info_3": 0.1}),
                      cycle_id="C-0001")
check("a below-threshold top score escalates",
      low["pick"] is None and low["escalate"] is True and "threshold" in low["reason"])
narrow = rank_hypotheses(ALLOWED, client=rank_client({"info_1": 0.80,
                                                      "info_2": 0.80 - ESCALATE_MARGIN / 2,
                                                      "info_3": 0.1}), cycle_id="C-0001")
check("a narrow top-two margin escalates",
      narrow["pick"] is None and narrow["escalate"] is True and "margin" in narrow["reason"])
clear = rank_hypotheses(ALLOWED, client=rank_client({"info_1": 0.90, "info_2": 0.5,
                                                     "info_3": 0.1}), cycle_id="C-0001")
check("a clear margin picks without escalation",
      clear["pick"] == "H-0001" and clear["escalate"] is False)

# 4. A tie is a zero margin: it escalates deterministically with ids in stable order.
tie = rank_hypotheses(ALLOWED, client=rank_client({"info_1": 0.9, "info_2": 0.9,
                                                   "info_3": 0.1}), cycle_id="C-0001")
check("a tie escalates deterministically with the ids in stable order",
      tie["escalate"] is True and tie["pick"] is None
      and [r["id"] for r in tie["ranking"] if r["safe"]] == ["H-0001", "H-0002"])
override = rank_hypotheses(ALLOWED, client=rank_client({"info_1": 0.9}),
                           hypotheses=[{"id": "H-9000", "text": "caller-supplied scenario text"}],
                           question="a caller-supplied question")
check("a caller-supplied hypothesis list and question are honored",
      override["pick"] == "H-9000" and calls[-1][0]["question"] == "a caller-supplied question")
secret = rank_hypotheses(ALLOWED, client=rank_client({"info_1": 0.9}),
                         hypotheses=[{"id": "H-9001",
                                      "text": "Does the token glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
                                              "reach the client?"}],
                         question="q")
check("hypothesis text is redacted before egress",
      "[REDACTED]" in calls[-1][0]["hypotheses"]["hypothesis_1"]["text"]
      and "glpat-" not in calls[-1][0]["hypotheses"]["hypothesis_1"]["text"])

# 5. Invalid scores fail closed: they cannot win the pick.
def invalid_client(state, questions):
    answers = {name: {"type": "noul", "noul": 0.99} for name in questions}
    answers["info_1"] = {"type": "noul", "noul": "very high"}
    return {"model": "stub-rank", "answers": answers, "usage": {}}


invalid = rank_hypotheses(ALLOWED, client=invalid_client, cycle_id="C-0001")
check("an invalid score is excluded, never treated as the highest",
      invalid["pick"] != "H-0001" and any(row["id"] == "H-0001" and row["info"] is None
                                          for row in invalid["ranking"]))

# 6. Advisory only + cost ledger.
cp = ControlPlane(ALLOWED)
check("the ranking writes no lifecycle events (advisory only)",
      not any(e.get("type") in {"HYPOTHESIS_TRANSITIONED", "AUDIT_RECORDED", "TECHNIQUE_EVALUATED"}
              for e in cp._read_events()))
check("the ranking ledgers its usage as an estimated cost row",
      any(r["decision"] == "rank" and r["estimated"] for r in cost_rows(ALLOWED)))

# 6b. v8.3 fix: the ranking call is a replayable record (input snapshot + digest,
#     endpoint, posture); replay re-runs the info battery offline against it.
from ts_claims import read_judgments  # noqa: E402
from ts_rank import replay_rank  # noqa: E402

rp_root = workspace()
add_cycle(rp_root)
add_hyp(rp_root, "H-0001", "Does the export endpoint enforce the tenant filter for API keys?")
add_hyp(rp_root, "H-0002", "Does the export endpoint's pagination limit hold under load?")
rp_out = rank_hypotheses(rp_root, client=rank_client({"info_1": 0.95, "info_2": 0.2}),
                         cycle_id="C-0001")
rp_rows = read_judgments(rp_root, seam="rank")
check("the ranking is recorded with input digest, endpoint and posture",
      len(rp_rows) == 1 and len(rp_rows[0]["input_digest"]) == 64
      and rp_rows[0]["endpoint"] == "https://api.typesafe.ai/v1/systemone"
      and rp_rows[0]["posture"] == "on" and rp_rows[0]["verdict"] == rp_out["pick"]
      and [h["id"] for h in rp_rows[0]["input"]["hypotheses"]] == ["H-0001", "H-0002"])
check("the ranking result carries the posture and the endpoint",
      rp_out["posture"] == "on"
      and rp_out["endpoint"] == "https://api.typesafe.ai/v1/systemone")
rp_replay = replay_rank(rp_root, client=rank_client({"info_1": 0.95, "info_2": 0.2}))
check("replay reproduces the pick and escalation decision deterministically",
      rp_replay["replayed"] == 1 and rp_replay["matched"] == 1
      and rp_replay["mismatched"] == 0 and rp_replay["drifted"] == 0)
check("replay with a flipped score argues the mismatch",
      replay_rank(rp_root, client=rank_client({"info_1": 0.2, "info_2": 0.95}))["mismatched"] == 1)
rp_denied = workspace('external_judgment: "DENIED"\n')
rank_hypotheses(rp_denied, client=rank_client({"info_1": 0.95}), cycle_id="C-0001")
check("a DENIED seam writes no judgment record (nothing was judged)",
      read_judgments(rp_denied, seam="rank") == [])

# 7. CLI wiring: `researchctl rank --cycle C-0001`.
import contextlib  # noqa: E402
import io  # noqa: E402
from researchctl import main as ctl_main  # noqa: E402


def cli_post(payload, **kwargs):
    return {"model": "stub-rank",
            "answers": {name: {"type": "noul", "noul": 0.9 if name == "info_1" else 0.2}
                        for name in payload["questions"]},
            "usage": {"input_tokens": 4, "output_tokens": 1}}


with mock.patch("ts_rank.post_json", cli_post), \
        mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "k"}):
    buf = io.StringIO()
    with mock.patch.object(sys, "argv", [str(TOOLS / "researchctl.py"), str(ALLOWED),
                                         "rank", "--cycle", "C-0001"]), \
            contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        rc_rank = ctl_main()
cli_out = json.loads(buf.getvalue())
check("researchctl rank prints the advisory pick and escalation state",
      rc_rank == 0 and cli_out["pick"] == "H-0001" and cli_out["escalate"] is False
      and cli_out["advisory"] is True)

print(f"\n{len(passed)}/{len(passed)} passed")
