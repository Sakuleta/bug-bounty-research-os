#!/usr/bin/env python3
"""Tests for tools/cycle.py (thin adapter) against the canonical seam guards. No dependencies."""
import subprocess
import sys
import tempfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
CYCLE = TOOLS / 'cycle.py'
sys.path.insert(0, str(TOOLS))
from control_plane import ControlPlane
passed = []


def run(*args):
    return subprocess.run([sys.executable, str(CYCLE), *args],
                          capture_output=True, text=True)


def check(name, cond):
    assert cond, f'FAIL: {name}'
    passed.append(name)
    print(f'ok: {name}')


def fresh_root():
    tmp = Path(tempfile.mkdtemp())
    (tmp / '04_cycles').mkdir()
    return tmp


def prep(root, cid):
    """Fill plan fields + triage + the objective artifact — the documented RUNNING preconditions."""
    cp = ControlPlane(root)
    cp.update_cycle(cid, {'objective': 'test question', 'allowed_scope': ['example.test'],
                          'stop_conditions': ['stop'],
                          'knowledge_triage': [{'pack': 'access-auth', 'verdict': 'USE', 'reason': 'auth test'}]})
    obj = root / '04_cycles' / cid / 'objective.md'
    obj.write_text(obj.read_text().replace('## Question\n', '## Question\nTest question\n')
                                        .replace('## Minimal test\n', '## Minimal test\nMinimal safe test\n'))


def fill_results(root, cid, disposition=True, instrument=True, tail=True, evidence=True):
    p = root / '04_cycles' / cid / 'results.md'
    text = p.read_text()
    if disposition:
        text = text.replace('## Disposition\n', '## Disposition\nVERIFIED on researcher account A.\n')
    if instrument:
        text = text.replace('## Instrument validation\n', '## Instrument validation\nControl works.\n')
        text = text.replace('## Interpretation\n', '## Interpretation\nBounded result.\n')
    if tail:
        text = text.replace('## New hypotheses\n', '## New hypotheses\nH-0002 filed.\n')
        text = text.replace('## Next step\n', '## Next step\nEvaluate H-0002.\n')
    eid = None
    if evidence:
        evp = root / '04_cycles' / cid / 'evidence.txt'
        evp.write_text('cycle evidence\n')
        ev = ControlPlane(root).register_evidence(evp.relative_to(root).as_posix(), kind='raw',
                                                  source='researcher-owned', cycle_id=cid)
        eid = ev['payload']['id']
        text = text.replace('## Evidence references\n', f'## Evidence references\n{eid}\n')
    p.write_text(text)
    return eid


# 1. bad ID rejected
r = run(str(fresh_root()), 'create', 'nope')
check('rejects bad ID', r.returncode == 2)

# 2. create ok + plan.yaml canonical shape (15 fields incl. triage + result_summary)
root = fresh_root()
r = run(str(root), 'create', 'C-0001')
check('creates cycle', r.returncode == 0 and (root / '04_cycles' / 'C-0001' / 'plan.yaml').exists())
plan = (root / '04_cycles' / 'C-0001' / 'plan.yaml').read_text()
fields = ['id:', 'type:', 'objective:', 'primary_hypothesis:', 'priority_reason:', 'allowed_scope:', 'accounts:',
          'knowledge_packs:', 'knowledge_triage:', 'preconditions:', 'controls:', 'stop_conditions:',
          'evidence_expected:', 'result_summary:', 'status:']
check('plan.yaml canonical shape', all(f in plan for f in fields))

# 3. idempotent create rejected
r = run(str(root), 'create', 'C-0001')
check('idempotency guard', r.returncode == 1)

# 4. forbidden transition rejected (PLANNED -> CLOSED skips the machine)
r = run(str(root), 'transition', 'C-0001', 'CLOSED')
check('rejects forbidden transition', r.returncode == 1)

# 5. RUNNING preconditions live in the canonical seam: plan + triage + objective artifact.
cp = ControlPlane(root)
cp.update_cycle('C-0001', {'objective': 'test question', 'allowed_scope': ['example.test'], 'stop_conditions': ['stop']})
r = run(str(root), 'transition', 'C-0001', 'READY')
check('READY after plan fields', r.returncode == 0)
r = run(str(root), 'transition', 'C-0001', 'RUNNING')
check('RUNNING blocked without triage/objective', r.returncode == 1)
prep(root, 'C-0001')
r = run(str(root), 'transition', 'C-0001', 'RUNNING')
check('RUNNING after plan+triage+objective', r.returncode == 0)

# 6. RESULT_READY needs Disposition + registered evidence.
r = run(str(root), 'submit', 'C-0001')
check('guard blocks empty Disposition', r.returncode == 1)
fill_results(root, 'C-0001', disposition=True, instrument=False, tail=False, evidence=False)
r = run(str(root), 'submit', 'C-0001')
check('guard still requires registered evidence', r.returncode == 1)
eid = fill_results(root, 'C-0001', disposition=True, instrument=False, tail=False, evidence=True)
r = run(str(root), 'submit', 'C-0001')
check('submit passes with disposition + evidence', r.returncode == 0)

# 7. Terminal + CLOSED with the technique-evaluation gate and the claim-review gate.
fill_results(root, 'C-0001', evidence=True)
for axis in ('objective', 'method'):
    ControlPlane(root).merge_worker({'cycle_id': 'C-0001', 'evidence_refs': [eid],
                                     'next_step': f'{axis} review',
                                     'review': {'axis': axis, 'verdict': 'pass', 'reviewer': f'{axis}-run'}})
r = run(str(root), 'transition', 'C-0001', 'VERIFIED')
check('terminal transition VERIFIED', r.returncode == 0)
r = run(str(root), 'transition', 'C-0001', 'CLOSED')
check('CLOSED blocked before technique evaluation', r.returncode == 1)
ControlPlane(root).evaluate_technique({'cycle_id': 'C-0001', 'technique_family': 'authz-differential',
                                       'result': 'CONFIRMED', 'interpretation': 'reproduced',
                                       'learning': 'oracle holds', 'evidence_refs': [eid]})
r = run(str(root), 'transition', 'C-0001', 'CLOSED')
check('CLOSED after technique evaluation', r.returncode == 0)

# 8. begin sugar walks PLANNED -> READY -> RUNNING, idempotent.
root2 = fresh_root()
r = run(str(root2), 'create', 'C-0002')
check('creates second cycle', r.returncode == 0)
prep(root2, 'C-0002')
r = run(str(root2), 'begin', 'C-0002')
check('begin walks to RUNNING', r.returncode == 0 and 'RUNNING' in r.stdout)
r = run(str(root2), 'begin', 'C-0002')
check('begin idempotent', r.returncode == 0 and 'already in current state' in r.stdout)

# 9. submit sugar enforces the Disposition guard.
r = run(str(root2), 'submit', 'C-0002')
check('submit guards Disposition', r.returncode == 1)

# 10. close sugar: full terminal flow including the technique gate.
eid2 = fill_results(root2, 'C-0002', evidence=True)
r = run(str(root2), 'submit', 'C-0002')
check('submit after results', r.returncode == 0)
ControlPlane(root2).evaluate_technique({'cycle_id': 'C-0002', 'technique_family': 'fixture',
                                        'result': 'NEGATIVE', 'interpretation': 'no oracle delta',
                                        'learning': 'clean denial path', 'evidence_refs': [eid2]})
r = run(str(root2), 'close', 'C-0002', 'FALSE_POSITIVE')
check('close sugar reaches CLOSED',
      r.returncode == 0 and ControlPlane(root2).cycle_status('C-0002') == 'CLOSED')

print(f'\n{len(passed)}/{len(passed)} passed')
