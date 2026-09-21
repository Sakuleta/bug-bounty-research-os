#!/usr/bin/env python3
"""Tests for tools/state.py (Deep State + event log). No dependencies."""
import json
import sys
import tempfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from state import merge, merge_result, propose, read_status, refresh  # noqa: E402
from control_plane import ControlPlane

passed = []


def check(name, cond):
    assert cond, f'FAIL: {name}'
    passed.append(name)
    print(f'ok: {name}')


def fresh_root():
    tmp = Path(tempfile.mkdtemp())
    (tmp / '11_runtime').mkdir()
    (tmp / '11_runtime' / 'run-status.yaml').write_text(
        'engagement_status: ACTIVE\ncurrent_cycle: null\nlast_state_update: null\n'
        'last_audit: null\nopen_high_value_hypotheses: 0\nopen_unknowns: 0\n'
        'pending_human_gate: false\nlab_ready: false\n')
    (tmp / '11_runtime' / 'active-cycle.yaml').write_text('cycle_id: "C-0003"\n')
    (tmp / '11_runtime' / 'events.jsonl').write_text('')
    ControlPlane(tmp).create_cycle('C-0003', {'id':'C-0003','type':'DISCOVERY','objective':'compat','allowed_scope':['example.test'],'stop_conditions':['stop'],'status':'PLANNED'})
    return tmp


root = fresh_root()

# 1. STATE_CHANGE without evidence rejected, nothing appended
try:
    merge(root, propose(entity='H-1', from_='QUEUED', to='TESTING',
                        reason='x', actor='c', evidence_refs=[]))
    check('evidenceless merge rejected', False)
except ValueError:
    check('evidenceless merge rejected', True)
check('nothing appended on reject',
      len((root / '11_runtime' / 'events.jsonl').read_text().strip().splitlines()) == 1)

# 2. register an evidence object, then merge appends EV-0002 with UTC time
proof = root / 'proof.txt'; proof.write_text('evidence\n')
eid = ControlPlane(root).register_evidence('proof.txt', kind='test', source='researcher-owned')['payload']['id']
ev = merge(root, propose(entity='H-1', from_='QUEUED', to='TESTING', reason='x',
                         actor='c', evidence_refs=[eid]))
check('EV-0003 assigned after evidence', ev['event_id'] == 'EV-000003' and ev['time'].endswith('Z'))
st = read_status(root)
check('current_cycle derived', st['current_cycle'] == 'C-0003')
check('engagement_status preserved', st['engagement_status'] == 'ACTIVE')

# 3. ids sequential
ev2 = merge(root, propose(entity='H-1', from_='TESTING', to='DONE', reason='y',
                          actor='c', evidence_refs=[eid]))
check('ids sequential', ev2['event_id'] == 'EV-000004')

# 4. merge_result rejects packet without evidence
try:
    merge_result({'cycle_id': 'C-0003', 'evidence_refs': []}, root=root)
    check('packet without evidence rejected', False)
except ValueError:
    check('packet without evidence rejected', True)

# 5. merge_result appends WORKER_RESULT with packet refs
ev3 = merge_result({'cycle_id': 'C-0003', 'evidence_refs': [eid],
                    'next_step': 'pivot'}, root=root)
check('worker merge recorded',
      ev3['type'] == 'WORKER_RESULT' and ev3['evidence_refs'] == [eid])
lines = (root / '11_runtime' / 'events.jsonl').read_text().strip().splitlines()
check('log has 5 events', len(lines) == 5 and all(json.loads(l)['event_id'] for l in lines))

print(f'\n{len(passed)}/{len(passed)} passed')
