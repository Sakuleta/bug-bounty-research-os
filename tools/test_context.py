#!/usr/bin/env python3
"""Tests for build_context ranking seam + 27 fixture (order/budget)."""
import sys
import tempfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from knowledge_index import rank_packs, top_packs, validate_index  # noqa: E402
from build_context import assemble  # noqa: E402

passed = []


def check(name, cond):
    assert cond, f'FAIL: {name}'
    passed.append(name)
    print(f'ok: {name}')


LONG = [f'kw{i}' for i in range(16)] + ['shared-term']
SHORT = ['niche-a', 'niche-b', 'shared-term']
packs = {'long-pack': (LONG, ['a.md']), 'short-pack': (SHORT, ['b.md'])}

# 1. length bias fixed: one shared match each -> focused pack wins
ranked = rank_packs(packs, 'this mentions shared-term once')
check('focused pack beats keyword-stuffed pack', ranked[0][1] == 'short-pack')

# 2. determinism: same input, same order, twice
r1 = [(s, n) for s, n, _ in rank_packs(packs, 'shared-term niche-a')]
r2 = [(s, n) for s, n, _ in rank_packs(packs, 'shared-term niche-a')]
check('ranking deterministic', r1 == r2)

# 3. index consistency: missing ref = error, orphan md = warning
mini = Path(tempfile.mkdtemp()) / '12_knowledge'
(mini / 'demo').mkdir(parents=True)
(mini / 'INDEX.yaml').write_text('packs:\n  demo:\n    load_when: [demo]\n    files: [real.md, ghost.md]\n')
(mini / 'demo' / 'real.md').write_text('# real\n')
(mini / 'demo' / 'orphan.md').write_text('# orphan\n')
errors, warnings = validate_index(mini.parent)
check('missing ref is error', any('ghost.md' in e for e in errors))
check('orphan md is warning', any('orphan.md' in w for w in warnings))

# 4. top_packs: one call returns resolved files, at most 3
V6ROOT = TOOLS.parent
got = top_packs(V6ROOT, 'desync cache proxy smuggling')
check('top_packs resolved', 0 < len(got) <= 3 and all(p.is_file() for _, ps in got for p in ps))
tmp = Path(tempfile.mkdtemp())
(tmp / 'START.md').write_text('# START — entry contract\n')
(rt := tmp / '11_runtime').mkdir()
(rt / 'run-status.yaml').write_text('engagement_status: "ACTIVE"\n')
(rt / 'active-cycle.yaml').write_text('cycle_id: "C-0001"\nobjective: "realtime socket test"\n')
(rt / 'tool-registry.yaml').write_text('tools: []\n')
(rt / 'lab-status.yaml').write_text('status: MISSING\n')
(tmp / '12_knowledge').mkdir()
(tmp / '10_learning').mkdir(exist_ok=True)
(tmp / '10_learning/freshness.yaml').write_text('components: []\n')
out = assemble(tmp, 8000)
check('assemble pure', isinstance(out, str))
check('contract before knowledge', out.index('## ENTRY CONTRACT') < out.index('## KNOWLEDGE/') if '## KNOWLEDGE/' in out else True)
check('within budget', len(out) <= 8000)
check('context carries the freshness ledger', '## FRESHNESS' in out)

# 5. TypeSafe triage seam: ranked choice via an injected client, deterministic fallback.
from ts_triage import suggest as triage_suggest  # noqa: E402
stub = lambda state, questions: {  # noqa: E731
    'model': 'stub-1',
    'answers': {'first_pack': {'type': 'choice', 'choice': 'realtime', 'confidence': 0.91,
                               'probabilities': {'realtime': 0.7, 'api-protocols': 0.25, 'none': 0.05}}},
    'usage': {'input_tokens': 10, 'output_tokens': 2},
}
ranked = triage_suggest(V6ROOT, 'realtime socket subscription leak', client=stub)
check('triage ranks via the client', ranked['source'] == 'typesafe' and ranked['suggested'] == 'realtime'
      and ranked['ranked'][0] == 'realtime' and ranked['probabilities']['api-protocols'] == 0.25)
none_stub = lambda state, questions: {  # noqa: E731
    'model': 'stub-1',
    'answers': {'first_pack': {'type': 'choice', 'choice': 'none', 'confidence': 0.8,
                               'probabilities': {'realtime': 0.4, 'none': 0.6}}},
    'usage': {},
}
check('triage none means no pack', triage_suggest(V6ROOT, 'unknown thing', client=none_stub)['suggested'] is None)
fallback = triage_suggest(V6ROOT, 'realtime socket subscription leak', live=False)
check('triage falls back to IDF without live',
      fallback['source'] == 'idf' and len(fallback['ranked']) == 17 and fallback['suggested'] == fallback['ranked'][0])

# 6. TypeSafe claims seam: evidence-grounded verdicts via an injected client; no invented verdicts.
import tempfile  # noqa: E402
from control_plane import ControlPlane  # noqa: E402
from ts_claims import check_claims  # noqa: E402
croot = Path(tempfile.mkdtemp())
for d in ['00_control', '02_surface', '03_hypotheses/active', '03_hypotheses/archive', '04_cycles',
          '10_learning', '11_runtime']:
    (croot / d).mkdir(parents=True, exist_ok=True)
(croot / '02_surface/endpoints.yaml').write_text('endpoints: []\n')
(croot / '11_runtime/events.jsonl').write_text('')
(croot / '11_runtime/run-status.yaml').write_text('engagement_status: "BOOTSTRAP"\n')
(croot / '11_runtime/tool-registry.yaml').write_text('tools: []\n')
(croot / '11_runtime/lab-status.yaml').write_text('status: UNKNOWN\n')
(croot / '10_learning/freshness.yaml').write_text('components: []\n')
(croot / '10_learning/unknowns.yaml').write_text('unknowns: []\n')
(croot / '10_learning/assumptions.yaml').write_text('assumptions: []\n')
(croot / 'proof.txt').write_text('HTTP 200 observed with title Example Domain\n')
ControlPlane(croot).register_evidence('proof.txt', kind='raw', source='test')
stub_claims = lambda state, questions: {  # noqa: E731
    'model': 'stub-1',
    'answers': {'relation': {'type': 'choice', 'choice': 'supports', 'confidence': 0.9,
                             'probabilities': {'supports': 0.9, 'contradicts': 0.05, 'says_nothing': 0.05}}},
    'usage': {'input_tokens': 5, 'output_tokens': 1},
}
claims_out = check_claims(croot, {'claims': [
    {'id': 'c1', 'claim': 'HTTP 200 was observed', 'evidence_ref': 'E-000001'},
    {'id': 'c2', 'claim': 'the title was Login', 'evidence_ref': 'E-000001'},
]}, client=stub_claims)
check('claims seam returns evidence-grounded verdicts',
      claims_out['source'] == 'typesafe' and len(claims_out['results']) == 2
      and claims_out['results'][0]['verdict'] == 'supports' and claims_out['results'][0]['auto'] is True)
low_claims = lambda state, questions: {  # noqa: E731
    'model': 'stub-1',
    'answers': {'relation': {'type': 'choice', 'choice': 'says_nothing', 'confidence': 0.4, 'probabilities': {}}},
    'usage': {},
}
low_out = check_claims(croot, {'claims': [{'id': 'c3', 'claim': 'x', 'evidence_ref': 'E-000001'}]}, client=low_claims)
check('low-confidence verdicts are flagged for review',
      low_out['results'][0]['auto'] is False and low_out['summary']['flagged'] == 1)
no_key = check_claims(croot, {'claims': [{'id': 'c4', 'claim': 'x', 'evidence_ref': 'E-000001'}]}, live=False)
check('claims seam never invents verdicts without a key',
      no_key['source'] == 'unavailable' and no_key['results'] == [])

print(f'\n{len(passed)}/{len(passed)} passed')
