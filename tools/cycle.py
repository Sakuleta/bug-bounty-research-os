#!/usr/bin/env python3
"""Thin cycle adapter over the canonical control plane.

Every lifecycle guard lives in tools/control_plane.py (the single canonical seam);
this adapter only shapes the CLI, creates the working documents and calls the seam.
"""
from __future__ import annotations
import json, re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from control_plane import ControlPlane, CYCLE_EDGES  # noqa: E402

ID_RE = re.compile(r'C-[0-9]{4,}$')
RESULTS_TMPL = '''# Cycle Results

## What was tested

## What was observed

## Instrument validation

## Interpretation

## Disposition

## Evidence references

## New hypotheses

## Next step
'''
OBJ_TMPL = '''# Cycle Objective

## Question

## Why this matters

## Primary hypothesis

## Secure prediction

## Vulnerable prediction

## Control

## Minimal test

## Stop condition

## Expected evidence
'''

PLAN_TMPL = {
    'type': 'DISCOVERY',
    'objective': '<ONE RESEARCH QUESTION>',
    'primary_hypothesis': None,
    'priority_reason': '',
    'allowed_scope': [],
    'accounts': [],
    'knowledge_packs': [],
    'knowledge_triage': [],
    'preconditions': [],
    'controls': [],
    'stop_conditions': [],
    'evidence_expected': [],
    'result_summary': '',
    'status': 'PLANNED',
}


def die(msg, code=1):
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def _create(root: Path, cid: str):
    cp = ControlPlane(root)
    cdir = root / '04_cycles' / cid
    if cp.cycle_status(cid) is not None or cdir.exists():
        die(f'cycle exists: {cid}')
    cdir.mkdir(parents=True)
    (cdir / 'objective.md').write_text(OBJ_TMPL)
    (cdir / 'results.md').write_text(RESULTS_TMPL)
    plan = {'id': cid, **PLAN_TMPL}
    (cdir / 'plan.yaml').write_text('\n'.join(f'{k}: {json.dumps(v)}' for k, v in plan.items()) + '\n')
    return cp.create_cycle(cid, plan)


def cmd_create(root, cid):
    """Compatibility entry point used by tools/new_cycle.py."""
    if not ID_RE.fullmatch(cid):
        die(f"invalid CYCLE_ID {cid!r}", 2)
    _create(Path(root), cid)
    print(Path(root) / "04_cycles" / cid)


def main():
    if len(sys.argv) < 4:
        print('usage: cycle.py <ROOT> create|update|begin|submit|transition|close <CYCLE_ID> [TO/TERMINAL]')
        return 2
    root = Path(sys.argv[1]).resolve()
    verb = sys.argv[2]
    cid = sys.argv[3]
    cp = ControlPlane(root)
    try:
        if verb == 'create':
            if not ID_RE.fullmatch(cid):
                die(f'invalid CYCLE_ID {cid!r}', 2)
            _create(root, cid)
            print(f'{cid}: created')
            return 0
        if cp.cycle_status(cid) is None:
            die(f'unknown cycle: {cid}')
        if verb == 'begin':
            cur = cp.cycle_status(cid)
            changed = False
            for nxt in ('READY', 'RUNNING'):
                if cur in CYCLE_EDGES and nxt in CYCLE_EDGES[cur]:
                    cp.transition_cycle(cid, nxt, reason=f'cycle begin: {cur}->{nxt}')
                    cur = nxt
                    changed = True
            print(f'{cid}: {cur}' + ('' if changed else ' (already in current state)'))
            return 0
        if verb == 'update':
            if len(sys.argv) < 5:
                return 2
            patch = json.loads(Path(sys.argv[4]).read_text())
            ev = cp.update_cycle(cid, patch)
            print(f'{cid}: updated ({ev["event_id"]})')
            return 0
        if verb == 'submit':
            cp.transition_cycle(cid, 'RESULT_READY', reason='cycle result recorded')
            print(f'{cid}: RESULT_READY')
            return 0
        if verb == 'transition':
            if len(sys.argv) < 5:
                return 2
            to = sys.argv[4]
            cp.transition_cycle(cid, to, reason=f'manual guarded transition to {to}')
            print(f'{cid}: {to}')
            return 0
        if verb == 'close':
            if len(sys.argv) < 5:
                return 2
            terminal = sys.argv[4]
            cp.transition_cycle(cid, terminal, reason=f'close cycle as {terminal}')
            if terminal != 'CLOSED':
                cp.transition_cycle(cid, 'CLOSED', reason='terminal disposition accepted; cycle archived')
            print(f'{cid}: {terminal}')
            return 0
        print('unknown verb')
        return 2
    except (ValueError, OSError, TimeoutError) as e:
        print(f'error: {e}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
