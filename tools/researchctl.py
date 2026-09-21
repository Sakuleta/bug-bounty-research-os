#!/usr/bin/env python3
"""Small, deterministic CLI seam for the Research OS control plane."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from control_plane import ControlPlane, scope_check  # noqa: E402
from ts_triage import suggest as triage_suggest  # noqa: E402
from ts_claims import check_claims  # noqa: E402


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
    tr = sub.add_parser("triage")
    tr.add_argument("question")
    tr.set_defaults(fn="triage")
    cc = sub.add_parser("claims-check")
    cc.add_argument("packet_json")
    cc.set_defaults(fn="claims-check")
    fr = sub.add_parser("freshness")
    frs = fr.add_subparsers(dest="op", required=True)
    x = frs.add_parser("record"); x.add_argument("json"); x.set_defaults(fn="freshness-record")
    x = frs.add_parser("status"); x.set_defaults(fn="freshness-status")
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
        elif ns.fn == "triage":
            out = triage_suggest(Path(ns.root), ns.question)
        elif ns.fn == "claims-check":
            out = check_claims(Path(ns.root), load_json(ns.packet_json))
        elif ns.fn == "freshness-record":
            out = cp.record_freshness(load_json(ns.json))
        elif ns.fn == "freshness-status":
            out = cp.freshness_report()
        elif ns.fn == "worker":
            out = cp.merge_worker(load_json(ns.json))
        elif ns.fn == "audit-record":
            out = cp.record_audit(ns.audit_class, ns.status, ns.summary, cycle_id=ns.cycle,
                                  evidence_refs=ns.evidence,
                                  matrix=load_json(ns.matrix) if ns.matrix else None)
        else:
            raise ValueError(ns.fn)
        print(json.dumps(out, ensure_ascii=False, indent=2))
        if ns.fn == "scope-check" and not out["in_scope"]:
            return 3
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
