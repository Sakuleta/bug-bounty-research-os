#!/usr/bin/env python3
"""Small, deterministic CLI seam for the Research OS control plane."""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from broker import client as broker_client  # noqa: E402
except ImportError:
    # A partial workspace copy (the replay fixture carries only the tool files it
    # needs) keeps every non-broker command working; `broker` commands then refuse.
    broker_client = None
from control_plane import (  # noqa: E402
    ControlPlane, broker_client as load_broker_client, never_considered_packs, scope_check,
)
try:
    # `leases` is stdlib-only; a partial workspace copy (the replay fixture carries only
    # the tool files it needs) keeps every other command working and refuses only
    # `lease-reconcile`, mirroring the tolerant broker import above.
    from leases import reconcile as lease_reconcile  # noqa: E402
except ImportError:
    lease_reconcile = None
from ts_triage import suggest as triage_suggest  # noqa: E402
from ts_claims import check_claims, check_draft  # noqa: E402
from ts_cost import record_seam_cost  # noqa: E402

BROKER_SCRIPT = Path(__file__).resolve().parent / "broker" / "broker.py"


def load_json(path: str):
    return json.loads(Path(path).read_text())


def scope_verdict(root: Path, url: str) -> dict:
    """The authoritative per-URL scope decision for the CLI/runner seam.

    While a broker socket is present the decision is the INTERSECTION of the broker's
    `scope.check` and the workspace-local `scope_check`: both must allow, so a stale
    broader broker policy can never widen a narrowed local binding (and a narrowed
    broker policy still gates a wider file). An unreachable broker or a broker refusal
    is a DENY — never a silent fallback to the workspace-local scope. With no socket
    the local `scope_check` behavior is unchanged. The returned shape mirrors
    `scope_check` (`gate`, `in_scope`, `host`, `assets`) plus an `authority` marker.
    """
    client = load_broker_client()
    if client is None:
        return {**scope_check(root, url), "authority": "local"}
    path = client.broker_path()
    try:
        response = client.call("scope.check", timeout=3,
                               workspace=client.workspace_key(root), url=url)
    except client.BrokerUnavailable as exc:
        return {
            "gate": "broker-unreachable", "in_scope": False, "host": "", "assets": None,
            "authority": "broker",
            "reason": (f"the broker socket {path} is present but unreachable (fail closed): {exc} — "
                       "start the broker (`researchctl broker serve`) or remove the stale socket"),
        }
    if not response.get("ok"):
        return {
            "gate": "broker-refused", "in_scope": False, "host": "", "assets": None,
            "authority": "broker",
            "reason": f"the broker refused the scope check (fail closed): {response.get('error')}",
        }
    if response.get("in_scope") is not True:
        return {
            "gate": response.get("gate"), "in_scope": False,
            "host": response.get("host") or "", "assets": response.get("assets"),
            "authority": "broker",
        }
    local = scope_check(root, url)
    if local["in_scope"] is not True:
        return {
            "gate": local["gate"], "in_scope": False, "host": local["host"],
            "assets": local["assets"], "authority": "broker",
            "reason": ("the workspace-local scope denies this target while the broker copy "
                       "allows it (stale broader broker policy?) — refusing (fail closed); "
                       "resync with `researchctl scope-sync` after repairing the scope via "
                       "`researchctl scope-set`"),
        }
    return {
        "gate": response.get("gate"), "in_scope": True,
        "host": response.get("host") or "", "assets": response.get("assets"),
        "authority": "broker",
    }


def broker_status(root: Path) -> dict:
    """Socket, availability, policy/key presence and version — fail closed on a stale socket."""
    if broker_client is None:
        raise ValueError("tools/broker/ is not present in this workspace copy — the broker is unavailable")
    path = broker_client.broker_path()
    home = broker_client.broker_home()
    out = {
        "socket": str(path) if path else str(home / broker_client.SOCKET_NAME),
        "home": str(home),
        "available": broker_client.available(),
        "key_present": (home / "key").exists(),
        "version": None,
        "policy_present": None,
        "policy": None,
    }
    if not out["available"]:
        return out
    try:
        response = broker_client.call("status", timeout=3, workspace=broker_client.workspace_key(root))
    except broker_client.BrokerUnavailable as exc:
        raise ValueError(
            f"broker socket {path} is present but unreachable (fail closed): {exc} — start the "
            "broker (`researchctl broker serve`) or remove the stale socket") from exc
    if not response.get("ok"):
        raise ValueError(f"broker status failed: {response.get('error')}")
    out["version"] = response.get("version")
    out["policy_present"] = response.get("policy_present")
    out["policy"] = response.get("policy")
    out["key_present"] = bool(response.get("key_present", out["key_present"]))
    return out


def refs(ns):
    return getattr(ns, "evidence", []) or []


def main() -> int:
    ap = argparse.ArgumentParser(prog="researchctl")
    ap.add_argument("root")
    sub = ap.add_subparsers(dest="command", required=True)

    s = sub.add_parser("status")
    s.set_defaults(fn="status")
    r = sub.add_parser("refresh")
    r.set_defaults(fn="status")
    n = sub.add_parser("next")
    n.set_defaults(fn="next")

    c = sub.add_parser("cycle")
    cs = c.add_subparsers(dest="op", required=True)
    x = cs.add_parser("create"); x.add_argument("id"); x.add_argument("plan_json"); x.set_defaults(fn="cycle-create")
    x = cs.add_parser("update"); x.add_argument("id"); x.add_argument("patch_json"); x.set_defaults(fn="cycle-update")
    x = cs.add_parser("transition"); x.add_argument("id"); x.add_argument("to"); x.add_argument("reason"); x.add_argument("--evidence", action="append", default=[]); x.set_defaults(fn="cycle-transition")

    h = sub.add_parser("hypothesis")
    hs = h.add_subparsers(dest="op", required=True)
    x = hs.add_parser("create"); x.add_argument("id"); x.add_argument("json"); x.set_defaults(fn="hyp-create")
    x = hs.add_parser("update"); x.add_argument("id"); x.add_argument("patch_json"); x.set_defaults(fn="hyp-update")
    x = hs.add_parser("transition"); x.add_argument("id"); x.add_argument("to"); x.add_argument("reason"); x.add_argument("--evidence", action="append", default=[]); x.set_defaults(fn="hyp-transition")

    e = sub.add_parser("evidence")
    es = e.add_subparsers(dest="op", required=True)
    x = es.add_parser("register"); x.add_argument("path"); x.add_argument("kind"); x.add_argument("source"); x.add_argument("--cycle"); x.set_defaults(fn="evidence")

    t = sub.add_parser("technique")
    ts = t.add_subparsers(dest="op", required=True)
    x = ts.add_parser("evaluate"); x.add_argument("json"); x.set_defaults(fn="technique-evaluate")
    x = ts.add_parser("draft", help="compile a TECHNIQUE_EVALUATED payload draft from per-field "
                                    "questions over the cycle transcript (nothing is recorded; "
                                    "the controller confirms with `technique confirm`)")
    x.add_argument("cycle_id")
    x.set_defaults(fn="technique-draft")
    x = ts.add_parser("confirm", help="confirm a reviewed technique draft: strip the _draft "
                                      "marker and record it via the canonical seam")
    x.add_argument("draft_json")
    x.set_defaults(fn="technique-confirm")

    k = sub.add_parser("knowledge")
    ks = k.add_subparsers(dest="op", required=True)
    x = ks.add_parser("usage", help="per-pack dispositions and citations derived from the ledger; "
                                    "--unused lists indexed packs never considered")
    x.add_argument("--unused", action="store_true")
    x.set_defaults(fn="knowledge-usage")
    x = ks.add_parser("honesty", help="advisory honesty check: one Noul per pack a cycle cites "
                                      "(warning only, never a fail)")
    x.add_argument("--cycle", required=True, help="cycle whose cited packs are checked")
    x.set_defaults(fn="knowledge-honesty")
    x = ks.add_parser("propose", help="{pack, title, body, technique_ref?, evidence_refs?, "
                                       "recheck_date?} — writes a reviewed proposal artifact")
    x.add_argument("json")
    x.set_defaults(fn="knowledge-propose")
    x = ks.add_parser("proposals", help="proposal status projection (latest resolution wins)")
    x.set_defaults(fn="knowledge-proposals")
    x = ks.add_parser("resolve", help="record a human resolution; APPLIED requires the pack "
                                      "file content to have changed first")
    x.add_argument("id")
    x.add_argument("decision", choices=["APPLIED", "REJECTED"])
    x.add_argument("--reference", default="", help="human ticket/message id (required; the "
                                                   "recorded friction, not cryptographic proof)")
    x.add_argument("--gate", default="", help="optional G-xxxx gate that must exist and be "
                                              "RESOLVED; binds the resolution to that gate")
    x.set_defaults(fn="knowledge-resolve")

    g = sub.add_parser("gate")
    gs = g.add_subparsers(dest="op", required=True)
    x = gs.add_parser("request"); x.add_argument("id"); x.add_argument("json"); x.set_defaults(fn="gate-request")
    x = gs.add_parser("resolve"); x.add_argument("id"); x.add_argument("decision"); x.add_argument("reference"); x.set_defaults(fn="gate-resolve")

    a = sub.add_parser("action")
    a.add_argument("json")
    a.set_defaults(fn="action")
    p = sub.add_parser("prepare")
    p.add_argument("json")
    p.set_defaults(fn="prepare")
    tc = sub.add_parser("token-consume", help="consume a prepared preflight token exactly "
                                              "once, bound to the exact action shape "
                                              "(controller-driven arms; no token, no dispatch)")
    tc.add_argument("action_id")
    tc.add_argument("shape_json")
    tc.set_defaults(fn="token-consume")
    gc = sub.add_parser("gate-check", help="does a RESOLVED human gate name this action id? "
                                           "(the dispatch-time gate for consequential actions)")
    gc.add_argument("action_id")
    gc.set_defaults(fn="gate-check")
    bp = sub.add_parser("bua-plan", help="one validated interactive plan: the executor-built "
                                         "Choice space goes out as ONE Jev fan-out, every "
                                         "answer through validate_choice; policy DENIED or an "
                                         "invalid answer means no operation to dispatch")
    bp.add_argument("request_json")
    bp.set_defaults(fn="bua-plan")
    sc = sub.add_parser("scope-check")
    sc.add_argument("url")
    sc.set_defaults(fn="scope-check")
    ss = sub.add_parser("scope-set")
    ss.add_argument("json", help='{"assets": [...], "source_reference": "...", "gate": "assets"|"none", '
                                 '"human_reference": "ticket-id (required to re-record an existing scope)"}')
    ss.set_defaults(fn="scope-set")
    sy = sub.add_parser("scope-sync", help="re-push the committed scope binding to the broker "
                                           "and clear a scope-sync DIRTY marker (no new event, "
                                           "no human_reference — a heal, not a re-record)")
    sy.set_defaults(fn="scope-sync")
    tr = sub.add_parser("triage")
    tr.add_argument("question")
    tr.set_defaults(fn="triage")
    cc = sub.add_parser("claims-check")
    cc.add_argument("packet_json")
    cc.set_defaults(fn="claims-check")
    cd = sub.add_parser("claims-draft")
    cd.add_argument("draft", help="report draft markdown; cited sentences are audited against "
                                  "registered evidence (an aid, never a gate)")
    cd.add_argument("--triage", action="store_true",
                    help="ask which evidence passage is most relevant before the relation question")
    cd.add_argument("--fail-on-flag", action="store_true",
                    help="exit 1 only when any verdict is flagged; unknown refs (reported "
                         "under `errors`), an unavailable seam (no key or policy denied) and "
                         "a draft with no cited claims always exit 0; a missing/unreadable "
                         "draft file is an error and exits 1 regardless of this flag")
    cd.set_defaults(fn="claims-draft")
    fr = sub.add_parser("freshness")
    frs = fr.add_subparsers(dest="op", required=True)
    x = frs.add_parser("record"); x.add_argument("json"); x.set_defaults(fn="freshness-record")
    x = frs.add_parser("status"); x.set_defaults(fn="freshness-status")
    gr = sub.add_parser("ground", help="retrieval-backed Jev judgment: provider snippets "
                                       "go verbatim into state.search_results; code "
                                       "thresholds decide; default off (needs "
                                       "external_judgment ALLOWED + grounding: ALLOWED)")
    gr.add_argument("question")
    gr.add_argument("--cycle", default=None)
    gr.set_defaults(fn="ground")
    nv = sub.add_parser("novelty", help="advisory novelty/duplicate aid: pairwise Choice over "
                                        "blocked candidates (unclear routes to the human lane; "
                                        "the deterministic audit stays the only PASS)")
    nv.add_argument("candidate_json", help='{"id": "...", "text": "..."} candidate')
    nv.set_defaults(fn="novelty")
    rk = sub.add_parser("rank", help="advisory hypothesis ranking / next-test selection: one "
                                     "Noul per open hypothesis, safety veto + thresholds in "
                                     "code, low-confidence rankings escalate")
    rk.add_argument("--cycle", default=None, help="cycle whose objective anchors the ranking")
    rk.set_defaults(fn="rank")
    scr = sub.add_parser("screen", help="run the fixed injection battery over a registered "
                                        "evidence artifact's store copy; a flagged verdict "
                                        "quarantines a review copy and withholds the text "
                                        "from external judgment (never dropped)")
    scr.add_argument("evidence_ref", help="registered E-* id (screen web-fetch output, BUA "
                                          "captures and excerpts by registering them first)")
    scr.set_defaults(fn="screen")
    bu = sub.add_parser("budget")
    bus = bu.add_subparsers(dest="op", required=True)
    x = bus.add_parser("status", help="limits, counted actions (recorded + outstanding tokens) and remaining")
    x.set_defaults(fn="budget-status")
    x = bus.add_parser("set", help='{"max_actions_per_cycle": N, "max_actions_per_engagement": N, '
                                   '"source_reference": "...", "human_reference": "ticket-id (required once limits exist)"}; '
                                   "a cap below the current recorded action count is recorded as below_current_count "
                                   "and tools/audit.py errors on the over-cap actions until a human-approved raise")
    x.add_argument("json")
    x.set_defaults(fn="budget-set")
    w = sub.add_parser("worker")
    w.add_argument("json")
    w.set_defaults(fn="worker")
    ib = sub.add_parser("identity-binding", help="print the parsed engagement identity binding "
                                                 "(account reference, browser profile, session flags)")
    ib.set_defaults(fn="identity-binding")
    ri = sub.add_parser("review-issue", help="issue a broker-attested review voucher for a "
                                             "review packet and embed it as review.attestation "
                                             "(one voucher per axis; the broker must be running)")
    ri.add_argument("json", help="review packet file (cycle_id, evidence_refs, review{axis, "
                                 "verdict, reviewer, run_id, evidence_quotes}); updated in place")
    ri.add_argument("hypothesis_id", help="hypothesis under review (must belong to the packet's cycle)")
    ri.add_argument("--ttl", type=int, default=300, help="voucher lifetime in seconds (1-3600)")
    ri.set_defaults(fn="review-issue")
    br = sub.add_parser("broker")
    brs = br.add_subparsers(dest="op", required=True)
    x = brs.add_parser("status", help="broker socket, availability, policy/key presence and version")
    x.set_defaults(fn="broker-status")
    x = brs.add_parser("serve", help="run the policy broker in the foreground "
                                     "(delegates to tools/broker/broker.py --serve)")
    x.add_argument("--home", default=None, help="broker home override (default RESEARCH_OS_BROKER_HOME "
                                                "or ~/.dsh/research-os-broker)")
    x.set_defaults(fn="broker-serve")

    au = sub.add_parser("audit-record")
    au.add_argument("audit_class")
    au.add_argument("status", choices=["PASS", "FAIL", "WARN"])
    au.add_argument("summary")
    au.add_argument("--cycle")
    au.add_argument("--evidence", action="append", default=[])
    au.add_argument("--matrix", help="six-row method-self-attack matrix JSON (required for that class)")
    au.set_defaults(fn="audit-record")

    lr = sub.add_parser("lease-reconcile", help="the run-completion predicate: releases the work "
                                                "lease only when the loop exited, zero matching "
                                                "children are alive, every planned cell has a "
                                                "manifest, reports were regenerated and the results "
                                                "commit exists; otherwise blocked (exit 3) and the "
                                                "lease stays held (stale => recovery required)")
    lr.add_argument("run", help="run id (the .leases/<run>.jsonl registry file)")
    lr.set_defaults(fn="lease-reconcile")

    ns = ap.parse_args()
    # lease-reconcile reads the run workspace's `.leases/` registry directly; it must not
    # instantiate the control plane, whose constructor mkdirs 11_runtime/ on every call.
    cp = None if ns.fn == "lease-reconcile" else ControlPlane(Path(ns.root))
    try:
        if ns.fn == "status":
            out = cp.refresh()
        elif ns.fn == "next":
            out = cp.next_actions()
        elif ns.fn == "cycle-create":
            out = cp.create_cycle(ns.id, load_json(ns.plan_json))
        elif ns.fn == "cycle-update":
            out = cp.update_cycle(ns.id, load_json(ns.patch_json))
        elif ns.fn == "cycle-transition":
            out = cp.transition_cycle(ns.id, ns.to, reason=ns.reason, evidence_refs=refs(ns))
        elif ns.fn == "hyp-create":
            out = cp.create_hypothesis(ns.id, load_json(ns.json))
        elif ns.fn == "hyp-update":
            out = cp.update_hypothesis(ns.id, load_json(ns.patch_json))
        elif ns.fn == "hyp-transition":
            out = cp.transition_hypothesis(ns.id, ns.to, reason=ns.reason, evidence_refs=refs(ns))
        elif ns.fn == "evidence":
            out = cp.register_evidence(ns.path, kind=ns.kind, source=ns.source, cycle_id=ns.cycle)
        elif ns.fn == "technique-evaluate":
            out = cp.evaluate_technique(load_json(ns.json))
        elif ns.fn == "technique-draft":
            from ts_label import draft_technique_payload
            out = draft_technique_payload(Path(ns.root), ns.cycle_id)
        elif ns.fn == "technique-confirm":
            from ts_label import DRAFT_MARKER
            payload = load_json(ns.draft_json)
            if not isinstance(payload, dict) or DRAFT_MARKER not in payload:
                raise ValueError(
                    f"{ns.draft_json} is not a technique draft (no {DRAFT_MARKER} marker) — "
                    "confirm only drafts produced by `researchctl technique draft`")
            draft_meta = payload.pop(DRAFT_MARKER)
            if isinstance(draft_meta, dict):
                # Keep the replayable provenance on the confirmed record: the model and
                # confidence whose draft the controller confirmed, plus the input digest,
                # endpoint and posture (the _draft marker itself is never recorded).
                payload["label_provenance"] = {
                    key: draft_meta.get(key) for key in
                    ("model", "confidence", "input_digest", "endpoint", "posture",
                     "has_learning", "notes")}
            out = cp.evaluate_technique(payload)
        elif ns.fn == "knowledge-usage":
            out = cp.knowledge_usage()
            if ns.unused:
                out = {"totals": out["totals"],
                       "packs": {name: out["packs"][name] for name in never_considered_packs(out)}}
        elif ns.fn == "knowledge-honesty":
            from ts_honesty import check_knowledge_use
            out = check_knowledge_use(Path(ns.root), ns.cycle)
        elif ns.fn == "knowledge-propose":
            out = cp.knowledge_propose(load_json(ns.json))
        elif ns.fn == "knowledge-proposals":
            out = cp.knowledge_proposals()
        elif ns.fn == "knowledge-resolve":
            out = cp.knowledge_resolve(ns.id, ns.decision, ns.reference, gate=ns.gate)
        elif ns.fn == "gate-request":
            out = cp.request_gate(ns.id, load_json(ns.json))
        elif ns.fn == "gate-resolve":
            out = cp.resolve_gate(ns.id, decision=ns.decision, reference=ns.reference)
        elif ns.fn == "action":
            out = cp.record_action(load_json(ns.json))
        elif ns.fn == "prepare":
            out = cp.prepare_action(load_json(ns.json))
        elif ns.fn == "token-consume":
            out = cp.consume_token(ns.action_id, load_json(ns.shape_json))
        elif ns.fn == "gate-check":
            out = cp.gate_for_action(ns.action_id)
        elif ns.fn == "bua-plan":
            from ts_bua import plan_actions
            out = plan_actions(cp.root, load_json(ns.request_json))
        elif ns.fn == "scope-check":
            out = scope_verdict(Path(ns.root), ns.url)
        elif ns.fn == "scope-set":
            data = load_json(ns.json)
            out = cp.set_scope(data.get("assets", []), data.get("source_reference", ""),
                               gate=data.get("gate"), human_reference=data.get("human_reference", ""))
        elif ns.fn == "scope-sync":
            out = cp.sync_scope()
        elif ns.fn == "triage":
            started = time.monotonic()
            out = triage_suggest(Path(ns.root), ns.question)
            record_seam_cost(cp.root, decision="triage", out=out, cycle_id=cp.active_cycle(),
                             latency_ms=int((time.monotonic() - started) * 1000))
        elif ns.fn == "claims-check":
            started = time.monotonic()
            out = check_claims(Path(ns.root), load_json(ns.packet_json), verify=True)
            record_seam_cost(cp.root, decision="claims-check", out=out, cycle_id=cp.active_cycle(),
                             latency_ms=int((time.monotonic() - started) * 1000))
        elif ns.fn == "claims-draft":
            started = time.monotonic()
            out = check_draft(Path(ns.root), ns.draft, triage=ns.triage)
            record_seam_cost(cp.root, decision="claims-draft", out=out, cycle_id=cp.active_cycle(),
                             latency_ms=int((time.monotonic() - started) * 1000))
        elif ns.fn == "freshness-record":
            out = cp.record_freshness(load_json(ns.json))
        elif ns.fn == "freshness-status":
            out = cp.freshness_report()
        elif ns.fn == "screen":
            from ts_screen import screen_evidence
            out = screen_evidence(Path(ns.root), ns.evidence_ref)
        elif ns.fn == "ground":
            from ts_ground import ground_state
            out = ground_state(Path(ns.root), ns.question, cycle_id=ns.cycle)
        elif ns.fn == "novelty":
            from ts_novelty import check_novelty
            out = check_novelty(Path(ns.root), load_json(ns.candidate_json))
        elif ns.fn == "rank":
            from ts_rank import rank_hypotheses
            out = rank_hypotheses(Path(ns.root), cycle_id=ns.cycle)
        elif ns.fn == "budget-status":
            out = cp.budget_status()
        elif ns.fn == "budget-set":
            out = cp.set_budget(load_json(ns.json))
        elif ns.fn == "worker":
            out = cp.merge_worker(load_json(ns.json))
        elif ns.fn == "identity-binding":
            from control_plane import identity_binding as _binding
            binding = _binding(Path(ns.root))
            if isinstance(binding, str):
                raise ValueError(
                    "00_control/identity-binding.yaml is present but malformed — repair the "
                    "expected_identity/session contract (fail closed)")
            out = {"binding_present": binding is not None, **(binding or {})}
        elif ns.fn == "review-issue":
            from control_plane import review_packet_digest as _packet_digest
            packet = load_json(ns.json)
            review = packet.get("review") or {}
            client = load_broker_client()
            if client is None:
                raise ValueError("no broker socket — review vouchers need a running broker "
                                 "(`researchctl broker serve`); without one, review packets merge "
                                 "on declared identities (local mode)")
            response = client.call(
                "review.issue", timeout=5, workspace=str(Path(ns.root).resolve()),
                cycle_id=str(packet.get("cycle_id") or ""),
                hypothesis_id=str(ns.hypothesis_id or ""),
                axis=str(review.get("axis", "")).lower(),
                reviewer=str(review.get("reviewer", "")).strip(),
                run_id=str(review.get("run_id", "")).strip(),
                packet_sha256=_packet_digest(packet), ttl_seconds=ns.ttl)
            if not response.get("ok"):
                raise ValueError(f"the broker refused the review voucher: {response.get('error')}")
            packet["review"] = {**review, "attestation": response["voucher"]}
            Path(ns.json).write_text(json.dumps(packet, ensure_ascii=False, indent=2) + "\n")
            out = {"voucher": response["voucher"], "packet": ns.json}
        elif ns.fn == "broker-status":
            out = broker_status(cp.root)
        elif ns.fn == "broker-serve":
            if not BROKER_SCRIPT.exists():
                raise ValueError(f"tools/broker/broker.py is missing from this workspace copy ({BROKER_SCRIPT})")
            argv = [sys.executable, str(BROKER_SCRIPT), "--serve"]
            if ns.home:
                argv += ["--home", ns.home]
            os.execv(sys.executable, argv)
        elif ns.fn == "audit-record":
            out = cp.record_audit(ns.audit_class, ns.status, ns.summary, cycle_id=ns.cycle,
                                  evidence_refs=ns.evidence,
                                  matrix=load_json(ns.matrix) if ns.matrix else None)
        elif ns.fn == "lease-reconcile":
            if lease_reconcile is None:
                raise ValueError("tools/leases.py is missing from this workspace copy — "
                                 "lease-reconcile is unavailable")
            out = lease_reconcile(Path(ns.root), ns.run)
        else:
            raise ValueError(ns.fn)
        print(json.dumps(out, ensure_ascii=False, indent=2))
        if ns.fn == "claims-draft":
            s = out["summary"]
            print(f"claims-draft: checked={s['checked']} flagged={s['flagged']} "
                  f"supports={s.get('supports', 0)} contradicts={s.get('contradicts', 0)} "
                  f"says_nothing={s.get('says_nothing', 0)} invalid={s.get('invalid_choice', 0)} "
                  f"unscreened={s.get('unscreened', 0)} "
                  f"skipped={len(out.get('skipped', []))} "
                  f"errors={len(out.get('errors', []))} (aid, not a gate)", file=sys.stderr)
            if ns.fail_on_flag and s["flagged"]:
                return 1
        if ns.fn == "screen":
            verdict = ("FLAGGED" if out.get("flagged") else
                       ("clean" if out.get("flagged") is False else "unavailable"))
            print(f"screen {ns.evidence_ref}: {verdict} "
                  f"(flagged_questions={out.get('flagged_questions') or []}, "
                  f"quarantine={out.get('quarantine_path')})", file=sys.stderr)
        if ns.fn == "ground":
            print(f"ground: posture={out.get('posture')} verdict={out.get('verdict')} "
                  f"auto={out.get('auto')} relevant={len(out.get('relevant') or [])} "
                  f"excluded={len(out.get('excluded') or [])} (aid, not a decision)",
                  file=sys.stderr)
        if (ns.fn == "budget-set" and isinstance(out, dict)
                and out.get("payload", {}).get("below_current_count")):
            print("warning: the new caps are below the current recorded action counts — "
                  "tools/audit.py errors on the over-cap actions until a human-approved raise "
                  "(`researchctl budget set` with human_reference)", file=sys.stderr)
        if ns.fn == "knowledge-usage":
            totals = out["totals"]
            never = never_considered_packs(out)
            print(f"knowledge usage: use={totals['use']} skip={totals['skip']} cited={totals['cited']} "
                  f"packs={len(out['packs'])} never_considered={len(never)}", file=sys.stderr)
            if ns.unused:
                print("unused packs: " + (", ".join(never) or "none"), file=sys.stderr)
        if ns.fn == "knowledge-honesty":
            print(f"knowledge honesty: checked={len(out.get('checked', []))} "
                  f"warnings={len(out.get('warnings', []))} "
                  "(advisory warning only, never a fail)", file=sys.stderr)
        elif ns.fn == "knowledge-propose":
            print(f"knowledge propose: {out['payload']['id']} -> "
                  f"{out['payload']['proposal_path']}", file=sys.stderr)
        elif ns.fn == "knowledge-proposals":
            print(f"knowledge proposals: total={len(out)} "
                  f"proposed={sum(1 for r in out if r['status'] == 'PROPOSED')} "
                  f"applied={sum(1 for r in out if r['status'] == 'APPLIED')} "
                  f"rejected={sum(1 for r in out if r['status'] == 'REJECTED')} "
                  f"overdue={sum(1 for r in out if r['overdue'])}", file=sys.stderr)
        elif ns.fn == "knowledge-resolve":
            print(f"knowledge resolve: {out['payload']['id']} {out['payload']['decision']} "
                  f"(reference: {out['payload']['reference']})", file=sys.stderr)
        if ns.fn == "lease-reconcile":
            if out["clear"]:
                print(f"lease-reconcile {ns.run}: CLEAR (released={out['released']}, "
                      f"commit={out['commit']})", file=sys.stderr)
            else:
                failed = ",".join(out.get("failed") or []) or "none"
                print(f"lease-reconcile {ns.run}: BLOCKED ({out['state']}; failed={failed})"
                      + (" — recovery required" if out.get("recovery_required") else ""),
                      file=sys.stderr)
        if ns.fn == "scope-check" and not out["in_scope"]:
            return 3
        if ns.fn == "lease-reconcile" and not out["clear"]:
            return 3
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
