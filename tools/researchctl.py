#!/usr/bin/env python3
"""Small, deterministic CLI seam for the Research OS control plane."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from control_plane import ControlPlane, never_considered_packs, scope_check  # noqa: E402
from ts_triage import suggest as triage_suggest  # noqa: E402
from ts_claims import check_claims, check_draft  # noqa: E402


def load_json(path: str):
    return json.loads(Path(path).read_text())


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

    k = sub.add_parser("knowledge")
    ks = k.add_subparsers(dest="op", required=True)
    x = ks.add_parser("usage", help="per-pack dispositions and citations derived from the ledger; "
                                    "--unused lists indexed packs never considered")
    x.add_argument("--unused", action="store_true")
    x.set_defaults(fn="knowledge-usage")
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
    sc = sub.add_parser("scope-check")
    sc.add_argument("url")
    sc.set_defaults(fn="scope-check")
    ss = sub.add_parser("scope-set")
    ss.add_argument("json", help='{"assets": [...], "source_reference": "...", "gate": "assets"|"none", '
                                 '"human_reference": "ticket-id (required to re-record an existing scope)"}')
    ss.set_defaults(fn="scope-set")
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

    au = sub.add_parser("audit-record")
    au.add_argument("audit_class")
    au.add_argument("status", choices=["PASS", "FAIL", "WARN"])
    au.add_argument("summary")
    au.add_argument("--cycle")
    au.add_argument("--evidence", action="append", default=[])
    au.add_argument("--matrix", help="six-row method-self-attack matrix JSON (required for that class)")
    au.set_defaults(fn="audit-record")

    ns = ap.parse_args()
    cp = ControlPlane(Path(ns.root))
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
        elif ns.fn == "knowledge-usage":
            out = cp.knowledge_usage()
            if ns.unused:
                out = {"totals": out["totals"],
                       "packs": {name: out["packs"][name] for name in never_considered_packs(out)}}
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
        elif ns.fn == "scope-check":
            out = scope_check(Path(ns.root), ns.url)
        elif ns.fn == "scope-set":
            data = load_json(ns.json)
            out = cp.set_scope(data.get("assets", []), data.get("source_reference", ""),
                               gate=data.get("gate"), human_reference=data.get("human_reference", ""))
        elif ns.fn == "triage":
            out = triage_suggest(Path(ns.root), ns.question)
        elif ns.fn == "claims-check":
            out = check_claims(Path(ns.root), load_json(ns.packet_json))
        elif ns.fn == "claims-draft":
            out = check_draft(Path(ns.root), ns.draft, triage=ns.triage)
        elif ns.fn == "freshness-record":
            out = cp.record_freshness(load_json(ns.json))
        elif ns.fn == "freshness-status":
            out = cp.freshness_report()
        elif ns.fn == "budget-status":
            out = cp.budget_status()
        elif ns.fn == "budget-set":
            out = cp.set_budget(load_json(ns.json))
        elif ns.fn == "worker":
            out = cp.merge_worker(load_json(ns.json))
        elif ns.fn == "audit-record":
            out = cp.record_audit(ns.audit_class, ns.status, ns.summary, cycle_id=ns.cycle,
                                  evidence_refs=ns.evidence,
                                  matrix=load_json(ns.matrix) if ns.matrix else None)
        else:
            raise ValueError(ns.fn)
        print(json.dumps(out, ensure_ascii=False, indent=2))
        if ns.fn == "claims-draft":
            s = out["summary"]
            print(f"claims-draft: checked={s['checked']} flagged={s['flagged']} "
                  f"supports={s.get('supports', 0)} contradicts={s.get('contradicts', 0)} "
                  f"says_nothing={s.get('says_nothing', 0)} invalid={s.get('invalid_choice', 0)} "
                  f"skipped={len(out.get('skipped', []))} "
                  f"errors={len(out.get('errors', []))} (aid, not a gate)", file=sys.stderr)
            if ns.fail_on_flag and s["flagged"]:
                return 1
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
        if ns.fn == "scope-check" and not out["in_scope"]:
            return 3
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
