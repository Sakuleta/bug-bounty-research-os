#!/usr/bin/env python3
"""Tests for build_context ranking seam + 27 fixture (order/budget)."""
import email.message
import json
import os
import sys
import tempfile
import urllib.error
from pathlib import Path
from unittest import mock

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

# 4a. The shared selection seam: one query composer and one cap for the context
# projection AND the RUNNING coverage guard, so the two can never rank apart.
from knowledge_index import selection_cap, selection_query  # noqa: E402

sroot = Path(tempfile.mkdtemp())
(sroot / '11_runtime').mkdir(parents=True)
(sroot / '10_learning').mkdir()
(sroot / '11_runtime/active-cycle.yaml').write_text('cycle_id: "C-0001"\n')
(sroot / '11_runtime/last-result.md').write_text('# Last Result\n')
(sroot / '10_learning/unknowns.yaml').write_text('unknowns: []\n')
sq = selection_query(sroot, 'objective-first text')
check('selection_query puts the objective first', sq.startswith('objective-first text'))
check('selection_query carries the ledger texts after the objective',
      sq.index('cycle_id') > 0 and 'Last Result' in sq and 'unknowns' in sq)
check('selection_query tolerates a missing objective and missing ledgers',
      selection_query(Path(tempfile.mkdtemp())) == '')
with mock.patch.dict(os.environ, {'KNOWLEDGE_PACK_CAP': '6'}):
    check('selection_cap reads the env override', selection_cap() == 6)
with mock.patch.dict(os.environ, {'KNOWLEDGE_PACK_CAP': 'garbage'}):
    check('selection_cap falls back to 4 on a non-integer', selection_cap() == 4)
with mock.patch.dict(os.environ, {}, clear=False):
    os.environ.pop('KNOWLEDGE_PACK_CAP', None)
    check('selection_cap defaults to 4', selection_cap() == 4)
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

# 4b. SAFETY KERNEL: first section, complete, and never truncated.
kroot = Path(tempfile.mkdtemp())
(kroot / '00_control').mkdir(parents=True)
(kroot / '04_cycles' / 'C-0001').mkdir(parents=True)
(kroot / '10_learning').mkdir()
(kroot / '12_knowledge').mkdir()
(kroot / 'START.md').write_text('# START — entry contract\n' + 'truncation filler line\n' * 40)
krt = kroot / '11_runtime'
krt.mkdir()
(krt / 'run-status.yaml').write_text(
    'engagement_status: "ACTIVE"\ncurrent_cycle: "C-0001"\npending_human_gate: false\n')
(krt / 'active-cycle.yaml').write_text('cycle_id: "C-0001"\n')
(kroot / '00_control/engagement.yaml').write_text(
    'external_judgment: "DENIED"\nscope:\n  assets:\n  - "example.test"\n')
(kroot / '00_control/identity-binding.yaml').write_text(
    'expected_identity:\n  public_handle: "researcher-A"\n  account_reference: "acct-7"\n')
(kroot / '04_cycles/C-0001/plan.yaml').write_text(
    'id: "C-0001"\nstatus: "RUNNING"\nstop_conditions: ["one controlled GET", "stop on 500"]\n')
kout = assemble(kroot, 8000)
check('safety kernel is the first section',
      kout.startswith('# Current Context') and kout.index('## SAFETY KERNEL') < kout.index('## ENTRY CONTRACT'))
check('safety kernel carries status, scope gate, assets, policy, stop conditions and identity',
      'engagement: ACTIVE' in kout and 'gate: assets' in kout and 'assets: example.test' in kout
      and 'external judgment: DENIED' in kout and 'one controlled GET' in kout and 'stop on 500' in kout
      and 'researcher-A' in kout and 'acct-7' in kout)
check('safety kernel reports no pending human gate', 'human gate: none pending' in kout)

(krt / 'run-status.yaml').write_text(
    'engagement_status: "ACTIVE"\ncurrent_cycle: "C-0001"\npending_human_gate: true\n')
check('safety kernel flags a pending human gate', 'human gate: PENDING' in assemble(kroot, 8000))

(krt / 'run-status.yaml').write_text('engagement_status: "BOOTSTRAP"\ncurrent_cycle: null\n')
(kroot / '00_control/engagement.yaml').write_text('scope:\n  gate: none\n')
kout_none = assemble(kroot, 8000)
check('safety kernel states no active cycle and the disabled gate',
      'active cycle: none' in kout_none and 'gate: none' in kout_none and 'external judgment: DENIED' in kout_none)

(kroot / '00_control/engagement.yaml').write_text('external_judgment: "ALLOWED"\nscope:\n  assets: []\n')
check('safety kernel shows unset scope as default deny and ALLOWED policy',
      'gate: unset' in assemble(kroot, 8000) and 'external judgment: ALLOWED' in assemble(kroot, 8000))

tiny = assemble(kroot, 600)
check('tiny budget keeps the full kernel intact',
      all(marker in tiny for marker in ['## SAFETY KERNEL', 'engagement: BOOTSTRAP', 'gate: unset',
                                        'external judgment: ALLOWED', 'active cycle: none',
                                        'human gate: none pending', 'handle=researcher-A', 'reference=acct-7']))
check('tiny budget truncates only after the kernel',
      '[CONTEXT_TRUNCATED]' in tiny and tiny.index('[CONTEXT_TRUNCATED]') > tiny.index('reference=acct-7')
      and len(tiny) <= 600)

# 4b-bis. Placeholder values are absent, not literals: `<...>` in identity-binding.yaml
# falls through to the engagement's identity_reference, else UNKNOWN.
(kroot / '00_control/identity-binding.yaml').write_text(
    'expected_identity:\n  public_handle: "<RESEARCHER_HANDLE>"\n  account_reference: "<NON_SECRET_ACCOUNT_REFERENCE>"\n')
(kroot / '00_control/engagement.yaml').write_text(
    'external_judgment: "ALLOWED"\nresearcher:\n  identity_reference: "acct-9"\n')
kout_ph = assemble(kroot, 8000)
check('placeholder identity values fall through to the engagement reference',
      'handle=UNKNOWN' in kout_ph and 'reference=acct-9' in kout_ph and '<RESEARCHER_HANDLE>' not in kout_ph)
(kroot / '00_control/engagement.yaml').write_text(
    'external_judgment: "ALLOWED"\nresearcher:\n  identity_reference: "<SECURE_IDENTITY_REFERENCE>"\n')
check('placeholder engagement references resolve to UNKNOWN',
      'reference=UNKNOWN' in assemble(kroot, 8000))

# 4b-ter. The kernel (with its heading) outranks the budget: a budget that would cut
# into it emits the whole kernel instead of a silently truncated identity line.
from build_context import safety_kernel, section  # noqa: E402

ksec = section('SAFETY KERNEL', safety_kernel(kroot))
prefixed = len('# Current Context\n\n') + len(ksec)
check('budget 270 keeps the identity line', 'reference=UNKNOWN' in assemble(kroot, 270))
check('a budget inside the kernel window still emits the whole kernel',
      'reference=UNKNOWN' in assemble(kroot, prefixed - 10) and '## SAFETY KERNEL' in assemble(kroot, prefixed - 10))
runt = assemble(kroot, prefixed - 10)
check('the kernel window result is never cut mid-line',
      runt.endswith('\n') and runt.count('identity:') == 1)

# 5. TypeSafe triage seam: ranked choice via an injected client, deterministic fallback.
from ts_triage import suggest as triage_suggest  # noqa: E402


def policy_root(engagement_text=None, unreadable=False):
    """Workspace root for external-judgment tests; the knowledge library is symlinked."""
    proot = Path(tempfile.mkdtemp())
    os.symlink(V6ROOT / '12_knowledge', proot / '12_knowledge')
    os.symlink(V6ROOT / '.dsh', proot / '.dsh')
    (proot / '00_control').mkdir()
    path = proot / '00_control/engagement.yaml'
    if unreadable:
        path.mkdir()
    elif engagement_text is not None:
        path.write_text(engagement_text)
    return proot


POLICY_ALLOW = policy_root('external_judgment: "ALLOWED"\n')
POLICY_DENY = policy_root('external_judgment: "DENIED"  # default posture\n')
POLICY_UNREADABLE = policy_root(unreadable=True)

stub = lambda state, questions: {  # noqa: E731
    'model': 'stub-1',
    'answers': {'first_pack': {'type': 'choice', 'choice': 'realtime', 'confidence': 0.91,
                               'probabilities': {'realtime': 0.7, 'api-protocols': 0.25, 'none': 0.05}}},
    'usage': {'input_tokens': 10, 'output_tokens': 2},
}
ranked = triage_suggest(POLICY_ALLOW, 'realtime socket subscription leak', client=stub)
check('triage ranks via the client', ranked['source'] == 'typesafe' and ranked['suggested'] == 'realtime'
      and ranked['ranked'][0] == 'realtime' and ranked['probabilities']['api-protocols'] == 0.25)
none_stub = lambda state, questions: {  # noqa: E731
    'model': 'stub-1',
    'answers': {'first_pack': {'type': 'choice', 'choice': 'none', 'confidence': 0.8,
                               'probabilities': {'realtime': 0.4, 'none': 0.6}}},
    'usage': {},
}
check('triage none means no pack', triage_suggest(POLICY_ALLOW, 'unknown thing', client=none_stub)['suggested'] is None)
fallback = triage_suggest(V6ROOT, 'realtime socket subscription leak', live=False)
check('triage falls back to IDF without live',
      fallback['source'] == 'idf' and len(fallback['ranked']) == 17 and fallback['suggested'] == fallback['ranked'][0])
denied = triage_suggest(POLICY_DENY, 'realtime socket subscription leak', client=stub)
check('triage denied by engagement policy falls back to IDF with the note',
      denied['source'] == 'idf' and denied['model'] is None and len(denied['ranked']) == 17
      and denied['note'] == 'external judgment denied by engagement policy')
unreadable = triage_suggest(POLICY_UNREADABLE, 'realtime socket subscription leak', client=stub)
check('triage unreadable policy defaults to denied and never calls the client',
      unreadable['source'] == 'idf'
      and unreadable['note'] == 'external judgment denied by engagement policy')

# 6. TypeSafe claims seam: evidence-grounded verdicts via an injected client; no invented verdicts.
import tempfile  # noqa: E402
from control_plane import ControlPlane  # noqa: E402
from ts_claims import check_claims, evidence_excerpt  # noqa: E402
croot = Path(tempfile.mkdtemp())
for d in ['00_control', '02_surface', '03_hypotheses/active', '03_hypotheses/archive', '04_cycles',
          '10_learning', '11_runtime']:
    (croot / d).mkdir(parents=True, exist_ok=True)
(croot / '00_control/engagement.yaml').write_text('external_judgment: "ALLOWED"\n')
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

# 6b. Evidence excerpts come from the content-addressed store copy (the registered
#     artifact), never the mutable living file — the same rule review quotes follow.
(croot / 'proof.txt').write_text('MUTATED living file content\n')
excerpt = evidence_excerpt(croot, 'E-000001')
check('excerpt reads the registered store copy, not the living file',
      'HTTP 200 observed with title Example Domain' in excerpt and 'MUTATED' not in excerpt)
sent: dict = {}


def spy(state, questions):
    sent['evidence'] = state['evidence']
    return stub_claims(state, questions)


check_claims(croot, {'claims': [{'id': 'c5', 'claim': 'x', 'evidence_ref': 'E-000001'}]}, client=spy)
check('the store copy is what gets sent to the seam',
      'HTTP 200 observed with title Example Domain' in sent.get('evidence', '')
      and 'MUTATED' not in sent.get('evidence', ''))

# 6c. External-judgment policy: claims denies before any network/client call.
denied_claims = check_claims(POLICY_DENY, {'claims': [{'id': 'c9', 'claim': 'x', 'evidence_ref': 'E-000001'}]},
                             client=stub_claims)
check('claims denied by engagement policy returns unavailable with the note',
      denied_claims['source'] == 'unavailable' and denied_claims['results'] == []
      and denied_claims['model'] is None
      and denied_claims['note'] == 'external judgment denied by engagement policy')
unreadable_claims = check_claims(POLICY_UNREADABLE, {'claims': [{'id': 'c9', 'claim': 'x', 'evidence_ref': 'E-000001'}]},
                                 client=stub_claims)
check('claims unreadable policy defaults to denied',
      unreadable_claims['source'] == 'unavailable'
      and unreadable_claims['note'] == 'external judgment denied by engagement policy')

# 6d. Report-draft claim audit extraction: only cited sentences (>= 40 chars after the
#     citation tokens are removed) become claims; fenced code, headings and short
#     sentences never do; unknown refs are data, not a crash.
draft = Path(tempfile.mkdtemp()) / 'draft.md'
draft.write_text(
    "# Report draft\n"
    "\n"
    "The service returned HTTP 200 on an unauthenticated request, as seen in capture `E-000001`.\n"
    "\n"
    "```\n"
    "curl -s https://example.test/admin | grep E-000002\n"
    "```\n"
    "\n"
    "- Too short E-000003.\n"
    "\n"
    "- The admin route leaked the build string in `E-000001` and also echoed `E-000002`.\n"
    "\n"
    "- A stale citation E-000099 is reported as an unknown ref, never a crash.\n"
)
from ts_claims import extract_draft_claims  # noqa: E402

findings = extract_draft_claims(draft.read_text())
check('draft extraction keeps one claim per cited sentence',
      [c['id'] for c in findings['claims']]
      == ['3-E-000001', '11-E-000001', '11-E-000002', '13-E-000099'])
check('draft extraction skips fenced code blocks',
      not any(c['id'].startswith('6-') for c in findings['claims']))
check('draft extraction notes the short cited sentence',
      len(findings['skipped']) == 1 and findings['skipped'][0]['line'] == 9
      and '40' in findings['skipped'][0]['reason'])
check('draft extraction strips citation tokens from the claim text',
      'HTTP 200' in findings['claims'][0]['claim'] and 'E-000001' not in findings['claims'][0]['claim'])
check('draft extraction yields one claim per cited ref with a shared sentence',
      findings['claims'][1]['claim'] == findings['claims'][2]['claim']
      and {findings['claims'][1]['evidence_ref'], findings['claims'][2]['evidence_ref']}
      == {'E-000001', 'E-000002'})

# 6e. The draft audit routes unknown refs to `errors`, keeps known ones checkable, and
#     stays fail-closed under a DENIED policy without ever calling the client.
from ts_claims import check_draft  # noqa: E402

draft_mixed = Path(tempfile.mkdtemp()) / 'mixed.md'
draft_mixed.write_text(
    "The panel accepted an unauthenticated GET and returned the build banner in `E-000001`.\n"
    "\n"
    "- A stale citation E-000099 is reported as an unknown ref, never checked.\n"
)
mixed = check_draft(croot, draft_mixed, client=stub_claims)
check('draft audit checks known refs and reports unknown ones as errors',
      mixed['source'] == 'typesafe' and [r['evidence_ref'] for r in mixed['results']] == ['E-000001']
      and [e['evidence_ref'] for e in mixed['errors']] == ['E-000099']
      and mixed['draft']['claims'] == 2 and mixed['draft']['checked'] == 1)

denied_calls: list = []


def denied_client(state, questions):
    denied_calls.append(state)
    return stub_claims(state, questions)


denied_draft = check_draft(POLICY_DENY, draft_mixed, client=denied_client)
check('draft audit denied by engagement policy returns unavailable and never calls the client',
      denied_draft['source'] == 'unavailable' and denied_draft['results'] == []
      and denied_draft['note'] == 'external judgment denied by engagement policy'
      and denied_calls == [])

# 6f. Capture triage (opt-in): passages split on blank lines, one passage-selection
#     question first, the relation question runs on the SELECTED passage only.
from ts_claims import evidence_passages  # noqa: E402

para1 = ' '.join(['The session cookie set on the login response was scoped to the parent domain, '
                  'so every subdomain received it on the first request.'] * 4)
para2 = ' '.join(['The admin console accepted the anonymous request and rendered the build banner '
                  'without any authentication challenge.'] * 4)
(croot / 'paragraphs.txt').write_text(para1 + '\n\n' + para2 + '\n')
ControlPlane(croot).register_evidence('paragraphs.txt', kind='raw', source='test')

small = 'alpha beta gamma delta epsilon zeta eta theta iota kappa'
oversized = 'B' * 1600
split = evidence_passages(small + '\n\n' + small + '\n\n' + oversized)
check('passages merge small chunks and split oversized ones',
      split[0] == small + '\n\n' + small and all(len(p) <= 1500 for p in split)
      and split[1] == 'B' * 1500 and split[2] == 'B' * 100)
check('passages cap at 12',
      len(evidence_passages('\n\n'.join(['paragraph-%d ' % i + 'x' * 450 for i in range(15)]))) == 12)

draft_multi = Path(tempfile.mkdtemp()) / 'triage.md'
draft_multi.write_text(
    "The admin console accepted the anonymous request and returned the build banner `E-000002`.\n")
triage_calls: list = []


def triage_client(state, questions):
    triage_calls.append((state, questions))
    if 'passage' in questions:
        return {'model': 'stub-1',
                'answers': {'passage': {'choice': '2', 'confidence': 0.95,
                                        'probabilities': {'1': 0.03, '2': 0.95, 'none': 0.02}}},
                'usage': {'input_tokens': 7, 'output_tokens': 1}}
    return stub_claims(state, questions)


triaged = check_draft(croot, draft_multi, triage=True, client=triage_client)
check('triage sees every passage and the relation runs on exactly the selected one',
      len(triage_calls) == 2 and triage_calls[0][0]['passages'] == [para1, para2]
      and triage_calls[1][0]['evidence'] == para2
      and triaged['results'][0]['passage_index'] == 2
      and triaged['results'][0]['triage_confidence'] == 0.95
      and triaged['results'][0]['verdict'] == 'supports')
check('triage and relation usage both count',
      triaged['usage'] == {'input_tokens': 12, 'output_tokens': 2})

none_calls: list = []


def none_triage_client(state, questions):
    none_calls.append(state)
    if 'passage' in questions:
        return {'model': 'stub-1',
                'answers': {'passage': {'choice': 'none', 'confidence': 0.88,
                                        'probabilities': {'none': 0.88}}},
                'usage': {}}
    raise AssertionError('the relation question must not run after a none triage')


none_out = check_draft(croot, draft_multi, triage=True, client=none_triage_client)
check('a none triage verdict skips the relation call and says nothing',
      len(none_calls) == 1 and none_out['results'][0]['verdict'] == 'says_nothing'
      and none_out['results'][0]['note'] == 'triage: no relevant passage'
      and none_out['results'][0]['auto'] is True and none_out['summary']['says_nothing'] == 1)

low_triage_out = check_draft(
    croot, draft_multi, triage=True,
    client=lambda state, questions: {'model': 'stub-1',
                                     'answers': {'passage': {'choice': 'none', 'confidence': 0.4,
                                                             'probabilities': {}}}, 'usage': {}})
check('a below-threshold triage verdict is flagged',
      low_triage_out['results'][0]['auto'] is False and low_triage_out['summary']['flagged'] == 1)

stray_calls: list = []


def stray_client(state, questions):
    stray_calls.append((state, questions))
    if 'passage' in questions:
        return {'model': 'stub-1',
                'answers': {'passage': {'choice': '9', 'confidence': 0.9, 'probabilities': {}}},
                'usage': {}}
    return stub_claims(state, questions)


stray_out = check_draft(croot, draft_multi, triage=True, client=stray_client)
check('an out-of-range triage selection falls back to the full excerpt with a note',
      len(stray_calls) == 2 and 'passage' in stray_calls[0][1] and 'relation' in stray_calls[1][1]
      and para1 in stray_calls[1][0]['evidence'] and para2 in stray_calls[1][0]['evidence']
      and 'unrecognized' in stray_out['results'][0]['note'])

single_calls: list = []


def single_client(state, questions):
    single_calls.append((state, questions))
    assert 'passage' not in questions, 'single-passage evidence must skip triage'
    return stub_claims(state, questions)


draft_single = Path(tempfile.mkdtemp()) / 'single.md'
draft_single.write_text("The capture observed an HTTP 200 on the unauthenticated request `E-000001`.\n")
single_out = check_draft(croot, draft_single, triage=True, client=single_client)
check('single-passage evidence skips triage and runs one relation call',
      len(single_calls) == 1 and 'passage_index' not in single_out['results'][0])

plain_calls: list = []


def plain_client(state, questions):
    plain_calls.append((state, questions))
    assert 'passage' not in questions, 'without --triage no passage question may be asked'
    return stub_claims(state, questions)


plain_out = check_draft(croot, draft_multi, client=plain_client)
check('without triage the relation sees the whole excerpt in one call',
      len(plain_calls) == 1 and para1 in plain_calls[0][0]['evidence']
      and para2 in plain_calls[0][0]['evidence']
      and 'passage_index' not in plain_out['results'][0])

# 6g. CLI wiring: `researchctl claims-draft` runs the audit, prints JSON, exits 0 even
#     with flags (aid, not gate); --fail-on-flag is the explicit opt-in exit code.
import contextlib  # noqa: E402
import io  # noqa: E402
import subprocess  # noqa: E402

wroot = Path(tempfile.mkdtemp())
for d in ['00_control', '02_surface', '03_hypotheses/active', '03_hypotheses/archive', '04_cycles',
          '10_learning', '11_runtime']:
    (wroot / d).mkdir(parents=True, exist_ok=True)
(wroot / '00_control/engagement.yaml').write_text('external_judgment: "ALLOWED"\n')
(wroot / '02_surface/endpoints.yaml').write_text('endpoints: []\n')
(wroot / '11_runtime/events.jsonl').write_text('')
(wroot / '11_runtime/run-status.yaml').write_text('engagement_status: "BOOTSTRAP"\n')
(wroot / '11_runtime/tool-registry.yaml').write_text('tools: []\n')
(wroot / '11_runtime/lab-status.yaml').write_text('status: UNKNOWN\n')
(wroot / '10_learning/freshness.yaml').write_text('components: []\n')
(wroot / '10_learning/unknowns.yaml').write_text('unknowns: []\n')
(wroot / '10_learning/assumptions.yaml').write_text('assumptions: []\n')
(wroot / 'proof.txt').write_text('HTTP 200 observed with title Example Domain\n')
ControlPlane(wroot).register_evidence('proof.txt', kind='raw', source='test')
cli_draft = wroot / 'draft-cli.md'
cli_draft.write_text("The capture recorded an unauthenticated HTTP 200 for the endpoint `E-000001`.\n")
proc = subprocess.run(
    [sys.executable, str(TOOLS / 'researchctl.py'), str(wroot), 'claims-draft', str(cli_draft)],
    capture_output=True, text=True, env={**os.environ, 'TYPESAFE_API_KEY': ''})
cli_out = json.loads(proc.stdout)
check('claims-draft CLI prints JSON, exits 0 and matches the registered ref',
      proc.returncode == 0 and cli_out['source'] == 'unavailable'
      and cli_out['draft']['claims'] == 1 and cli_out['errors'] == []
      and 'checked=0' in proc.stderr)

import researchctl  # noqa: E402


def run_cli(argv):
    with mock.patch.object(sys, 'argv', argv):
        return researchctl.main()


flag_payloads: list = []


def fake_flag_post(payload, **kwargs):
    flag_payloads.append(payload)
    return {'model': 'jev-test-2',
            'answers': {'relation': {'type': 'choice', 'choice': 'says_nothing',
                                     'confidence': 0.4, 'probabilities': {}}},
            'usage': {'input_tokens': 1, 'output_tokens': 1}}


with mock.patch('ts_claims.post_json', fake_flag_post), \
        mock.patch.dict(os.environ, {'TYPESAFE_API_KEY': 'k'}):
    buf, errbuf = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(errbuf):
        rc_plain = run_cli([str(TOOLS / 'researchctl.py'), str(croot), 'claims-draft', str(draft_multi)])
    cli_flagged = json.loads(buf.getvalue())
check('claims-draft exits 0 with a flagged verdict by default (aid, not a gate)',
      rc_plain == 0 and cli_flagged['summary']['flagged'] == 1 and 'flagged=1' in errbuf.getvalue())

with mock.patch('ts_claims.post_json', fake_flag_post), \
        mock.patch.dict(os.environ, {'TYPESAFE_API_KEY': 'k'}):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc_fail = run_cli([str(TOOLS / 'researchctl.py'), str(croot), 'claims-draft',
                           str(draft_multi), '--fail-on-flag'])
check('claims-draft --fail-on-flag turns a flag into exit 1', rc_fail == 1)

triage_payloads: list = []


def fake_triage_post(payload, **kwargs):
    triage_payloads.append(payload)
    if 'passage' in payload['questions']:
        return {'model': 'jev-test-2',
                'answers': {'passage': {'choice': '2', 'confidence': 0.9, 'probabilities': {}}},
                'usage': {'input_tokens': 2, 'output_tokens': 1}}
    return {'model': 'jev-test-2',
            'answers': {'relation': {'choice': 'supports', 'confidence': 0.9, 'probabilities': {}}},
            'usage': {'input_tokens': 3, 'output_tokens': 1}}


with mock.patch('ts_claims.post_json', fake_triage_post), \
        mock.patch.dict(os.environ, {'TYPESAFE_API_KEY': 'k'}):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc_triage = run_cli([str(TOOLS / 'researchctl.py'), str(croot), 'claims-draft',
                             str(draft_multi), '--triage'])
    cli_triage = json.loads(buf.getvalue())
check('claims-draft --triage asks the passage question then the relation question',
      rc_triage == 0 and len(triage_payloads) == 2
      and 'passage' in triage_payloads[0]['questions']
      and 'relation' in triage_payloads[1]['questions']
      and triage_payloads[1]['state']['evidence'] == para2
      and cli_triage['results'][0]['passage_index'] == 2)

# 7. TypeSafe transport: pinned model + bounded retry/backoff (HTTP 429/5xx only).
import ts_http  # noqa: E402
from ts_triage import model_name as triage_model  # noqa: E402
from ts_claims import model_name as claims_model  # noqa: E402


class FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return json.dumps(self._payload).encode()


def http_error(code, retry_after=None):
    headers = email.message.Message()
    if retry_after is not None:
        headers['Retry-After'] = str(retry_after)
    return urllib.error.HTTPError(ts_http.API, code, 'error', headers, None)


def opener_factory(steps, payload=None, retry_after=None):
    calls: list = []

    def opener(request, timeout=None):
        calls.append(json.loads(request.data.decode()))
        code = steps.pop(0)
        if code is None:
            return FakeResp(payload if payload is not None else {'model': 'stub-model'})
        raise http_error(code, retry_after)
    return opener, calls


with mock.patch.dict(os.environ, {'TYPESAFE_MODEL': ''}):
    check('default model is jev-latest', triage_model() == 'jev-latest' and claims_model() == 'jev-latest')
with mock.patch.dict(os.environ, {'TYPESAFE_MODEL': 'jev-test-2'}):
    check('TYPESAFE_MODEL overrides the pinned model in both seams',
          triage_model() == 'jev-test-2' and claims_model() == 'jev-test-2')

sleeps: list = []
opener, calls = opener_factory([429, None])
out = ts_http.post_json({'x': 1}, api_key='k', opener=opener, sleep=sleeps.append)
check('retry succeeds after a 429', out['model'] == 'stub-model' and len(calls) == 2)
check('backoff falls back to 1s when Retry-After is absent', sleeps == [1.0])

sleeps = []
opener, calls = opener_factory([503, None], retry_after=2.5)
out = ts_http.post_json({'x': 1}, api_key='k', opener=opener, sleep=sleeps.append)
check('Retry-After is honored when present', sleeps == [2.5] and len(calls) == 2)

# Retry-After is clamped: never faster than the default backoff, never longer than 60s;
# a past HTTP-date falls back to the default, nonsense never speeds retries up.
def retry_headers(value):
    h = email.message.Message()
    h['Retry-After'] = str(value)
    return h


import time as _time  # noqa: E402
from email.utils import formatdate as _formatdate  # noqa: E402

check('huge Retry-After clamps to 60s', ts_http.retry_delay(retry_headers(999999999), 1) == 60.0)
check('a past HTTP-date falls back to the default backoff',
      ts_http.retry_delay(retry_headers(_formatdate(_time.time() - 3600, usegmt=True)), 1) == 1.0)
check('a far-future HTTP-date clamps to 60s',
      ts_http.retry_delay(retry_headers(_formatdate(_time.time() + 3600, usegmt=True)), 1) == 60.0)
check('nonsense Retry-After falls back to the default',
      ts_http.retry_delay(retry_headers('soon'), 1) == 1.0)
check('a tiny Retry-After never retries faster than the default',
      ts_http.retry_delay(retry_headers(0.25), 1) == 1.0)
check('attempt 2 keeps its 2s default floor', ts_http.retry_delay(retry_headers(0.5), 2) == 2.0)
check('a 3s Retry-After is honored on attempt 1', ts_http.retry_delay(retry_headers(3), 1) == 3.0)
check('a missing header falls back to the default', ts_http.retry_delay(None, 2) == 2.0)

sleeps = []
opener, calls = opener_factory([502, 503, 504])
try:
    ts_http.post_json({'x': 1}, api_key='k', opener=opener, sleep=sleeps.append)
    gave_up = False
except urllib.error.HTTPError as exc:
    gave_up = exc.code == 504
check('gives up after three attempts with 1s/2s backoff',
      gave_up and len(calls) == 3 and sleeps == [1.0, 2.0])

sleeps = []
opener, calls = opener_factory([400])
try:
    ts_http.post_json({'x': 1}, api_key='k', opener=opener, sleep=sleeps.append)
    raised = None
except urllib.error.HTTPError as exc:
    raised = exc.code
check('a 400 is never retried', raised == 400 and len(calls) == 1 and sleeps == [])

sleeps = []
opener, calls = opener_factory([401])
try:
    ts_http.post_json({'x': 1}, api_key='k', opener=opener, sleep=sleeps.append)
    raised = None
except urllib.error.HTTPError as exc:
    raised = exc.code
check('other 4xx are never retried either', raised == 401 and len(calls) == 1 and sleeps == [])

# The seam's real transport sends the pinned model and returns the reported one.
captured: dict = {}


def fake_post(payload, **kwargs):
    captured.update(payload)
    return {'model': 'jev-test-2',
            'answers': {'first_pack': {'type': 'choice', 'choice': 'realtime', 'confidence': 0.9,
                                       'probabilities': {'realtime': 0.9, 'none': 0.1}}},
            'usage': {'input_tokens': 1, 'output_tokens': 1}}


with mock.patch('ts_triage.post_json', fake_post):
    with mock.patch.dict(os.environ, {'TYPESAFE_MODEL': 'jev-test-2', 'TYPESAFE_API_KEY': 'k'}):
        live_out = triage_suggest(POLICY_ALLOW, 'realtime socket subscription leak')
check('triage sends the pinned model and records the reported model',
      captured.get('model') == 'jev-test-2' and live_out['model'] == 'jev-test-2')

captured.clear()


def fake_claims_post(payload, **kwargs):
    captured.update(payload)
    return {'model': 'jev-test-2',
            'answers': {'relation': {'type': 'choice', 'choice': 'supports', 'confidence': 0.9,
                                     'probabilities': {'supports': 0.9}}},
            'usage': {'input_tokens': 1, 'output_tokens': 1}}


with mock.patch('ts_claims.post_json', fake_claims_post):
    with mock.patch.dict(os.environ, {'TYPESAFE_MODEL': 'jev-test-2', 'TYPESAFE_API_KEY': 'k'}):
        live_claims = check_claims(croot, {'claims': [{'id': 'c1', 'claim': 'x', 'evidence_ref': 'E-000001'}]})
check('claims sends the pinned model and records the reported model',
      captured.get('model') == 'jev-test-2' and live_claims['model'] == 'jev-test-2')

# 6h. Extraction robustness: `~~~` fences, 4-space-indented code blocks, blockquote
#     markers and table rows each follow their own rule (fences/code skip, quotes strip,
#     each table row is its own sentence).
import ts_claims  # noqa: E402  (module handle for the PASSAGE_CAP patch below)
draft_blocks = Path(tempfile.mkdtemp()) / 'blocks.md'
draft_blocks.write_text(
    "~~~\n"
    "A tilde-fenced sample carries a citation E-000777 and must be skipped entirely.\n"
    "~~~\n"
    "\n"
    "    An indented code sample carries a citation E-000778 and must be skipped too.\n"
    "\n"
    "> A blockquoted sentence carries a citation E-000001 and loses its marker.\n"
    "\n"
    "| Table row one carries a citation E-000002 and is its own sentence. |\n"
    "| Table row two carries a citation E-000003 and is its own sentence. |\n"
    "\n"
    "After the table, a normal paragraph carries a citation E-000004.\n"
)
blocks = extract_draft_claims(draft_blocks.read_text())
block_ids = [c['id'] for c in blocks['claims']]
check('extraction skips ~~~ fenced blocks',
      not any(c['evidence_ref'] == 'E-000777' for c in blocks['claims']))
check('extraction skips 4-space-indented code blocks',
      not any(c['evidence_ref'] == 'E-000778' for c in blocks['claims']))
check('extraction strips blockquote markers and keeps the sentence',
      block_ids[0] == '7-E-000001' and blocks['claims'][0]['claim'].startswith('A blockquoted')
      and '>' not in blocks['claims'][0]['claim'])
check('each table row is its own sentence',
      block_ids[1:3] == ['9-E-000002', '10-E-000003']
      and 'Table row two' not in blocks['claims'][1]['claim']
      and 'Table row one' not in blocks['claims'][2]['claim'])
check('extraction resumes after the table', block_ids[3] == '12-E-000004')

# 6i. Passage building: a trailing fragment merges into the previous passage, and a cap
#     truncation reports how many passages were dropped.
long_para = 'L' * 900
small_frag = 'S' * 120
passage_report: dict = {}
merged = evidence_passages(long_para + '\n\n' + small_frag, report=passage_report)
check('a trailing fragment merges into the previous passage',
      len(merged) == 1 and long_para in merged[0] and small_frag in merged[0]
      and passage_report == {'total': 1, 'dropped': 0})
passage_report = {}
capped = evidence_passages('\n\n'.join(['para-%d ' % i + 'x' * 450 for i in range(15)]),
                           cap=12, report=passage_report)
check('the cap reports the dropped-passage count',
      len(capped) == 12 and passage_report == {'total': 15, 'dropped': 3})

# 6j. The triage path surfaces the dropped-passage count on the result, so a claim is
#     never triaged against a silently truncated evidence set.
paras4 = '\n\n'.join(['Paragraph %d ' % i + 'y' * 489 for i in range(4)])
(croot / 'passages4.txt').write_text(paras4 + '\n')
ControlPlane(croot).register_evidence('passages4.txt', kind='raw', source='test')
draft_capped = Path(tempfile.mkdtemp()) / 'capped.md'
draft_capped.write_text("The four paragraphs each state an observation `E-000003`.\n")
capped_calls: list = []


def capped_client(state, questions):
    capped_calls.append((state, questions))
    if 'passage' in questions:
        return {'model': 'stub-1',
                'answers': {'passage': {'choice': '1', 'confidence': 0.9, 'probabilities': {}}},
                'usage': {}}
    return stub_claims(state, questions)


with mock.patch.object(ts_claims, 'PASSAGE_CAP', 2):
    capped_out = check_draft(croot, draft_capped, triage=True, client=capped_client)
check('the triage result reports the passages dropped by the cap',
      capped_out['results'][0].get('dropped_passages') == 2
      and len(capped_calls[0][0]['passages']) == 2)
check('an untruncated evidence set reports no dropped passages',
      plain_out['results'][0].get('dropped_passages') is None)

# 6k. The relation answer's choice is validated: an unknown choice is never auto-accepted
#     and is counted as its own summary bucket so the buckets always sum to `checked`.
bogus_client = lambda state, questions: {  # noqa: E731
    'model': 'stub-1',
    'answers': {'relation': {'type': 'choice', 'choice': 'maybe', 'confidence': 0.99,
                             'probabilities': {}}},
    'usage': {'input_tokens': 1, 'output_tokens': 1},
}
bogus_out = check_claims(croot, {'claims': [{'id': 'c7', 'claim': 'x', 'evidence_ref': 'E-000001'}]},
                         client=bogus_client)
check('an unrecognized relation choice is flagged, never auto-accepted',
      bogus_out['results'][0]['verdict'] == 'invalid_choice'
      and bogus_out['results'][0]['auto'] is False
      and 'unrecognized' in bogus_out['results'][0]['note']
      and bogus_out['summary']['flagged'] == 1)
check('the summary counts an invalid choice as its own bucket',
      bogus_out['summary']['invalid_choice'] == 1
      and (bogus_out['summary']['supports'] + bogus_out['summary']['contradicts']
           + bogus_out['summary']['says_nothing'] + bogus_out['summary']['invalid_choice'])
      == bogus_out['summary']['checked'])

# 6l. Extraction is linear in the number of cited sentences (the id-collision counter
#     replaced a rescanning `while cid in used` loop).
import time  # noqa: E402

big_draft = ' '.join(f'Sentence {i} states a verifiable observation in `E-000001`.'
                     for i in range(8000))
big_start = time.perf_counter()
big_out = extract_draft_claims(big_draft)
big_elapsed = time.perf_counter() - big_start
check('8k cited sentences extract in well under a second',
      len(big_out['claims']) == 8000 and big_elapsed < 1.0)
print(f'    (8k extraction: {big_elapsed:.3f}s)')
check('the 8k claim ids stay unique',
      len({c['id'] for c in big_out['claims']}) == 8000
      and big_out['claims'][0]['id'] == '1-E-000001'
      and big_out['claims'][1]['id'] == '1-E-000001-2')

# 6m. The documented exit contract of `claims-draft`: `--fail-on-flag` only reacts to a
#     flagged verdict (never to `unavailable`, unknown refs or a no-claim draft), while a
#     missing draft file is a hard error.
with mock.patch.dict(os.environ, {'TYPESAFE_API_KEY': ''}):
    proc_skip_flag = subprocess.run(
        [sys.executable, str(TOOLS / 'researchctl.py'), str(wroot), 'claims-draft',
         str(cli_draft), '--fail-on-flag'],
        capture_output=True, text=True, env={**os.environ, 'TYPESAFE_API_KEY': ''})
check('claims-draft --fail-on-flag exits 0 when the seam is unavailable (not a flag)',
      proc_skip_flag.returncode == 0)
missing_proc = subprocess.run(
    [sys.executable, str(TOOLS / 'researchctl.py'), str(wroot), 'claims-draft',
     str(wroot / 'no-such-draft.md')],
    capture_output=True, text=True, env={**os.environ, 'TYPESAFE_API_KEY': ''})
check('claims-draft on a missing draft file is an error (exit 1)',
      missing_proc.returncode == 1 and 'error:' in missing_proc.stderr)
help_proc = subprocess.run(
    [sys.executable, str(TOOLS / 'researchctl.py'), 'x', 'claims-draft', '--help'],
    capture_output=True, text=True)
check('claims-draft --fail-on-flag help states the exact trigger',
      'only when any verdict is flagged' in help_proc.stdout
      and 'unavailable' in help_proc.stdout and 'missing' in help_proc.stdout)

# 6f. v8.2 W14: verify-clause — each relation verdict must be supportable by the
# cited evidence (bounded retry), judgments are stored for replay, and replay with a
# mocked provider reproduces guard decisions deterministically.
from ts_claims import check_claims as _w14_check, replay_judgments as _w14_replay  # noqa: E402
_w14root = Path(tempfile.mkdtemp())
for d in ['00_control', '02_surface', '03_hypotheses/active', '03_hypotheses/archive', '04_cycles',
          '10_learning', '11_runtime']:
    (_w14root / d).mkdir(parents=True, exist_ok=True)
(_w14root / '00_control/engagement.yaml').write_text('external_judgment: "ALLOWED"\n')
(_w14root / '02_surface/endpoints.yaml').write_text('endpoints: []\n')
(_w14root / '11_runtime/events.jsonl').write_text('')
(_w14root / '11_runtime/run-status.yaml').write_text('engagement_status: "BOOTSTRAP"\n')
(_w14root / '11_runtime/tool-registry.yaml').write_text('tools: []\n')
(_w14root / '11_runtime/lab-status.yaml').write_text('status: UNKNOWN\n')
(_w14root / '10_learning/freshness.yaml').write_text('components: []\n')
(_w14root / '10_learning/unknowns.yaml').write_text('unknowns: []\n')
(_w14root / '10_learning/assumptions.yaml').write_text('assumptions: []\n')
(_w14root / 'proof.txt').write_text('HTTP 200 observed with title Example Domain\n')
ControlPlane(_w14root).register_evidence('proof.txt', kind='raw', source='test')
_w14_calls: list = []


def _w14_support_stub(state, questions):
    _w14_calls.append(set(questions))
    if 'verify' in questions:
        return {'model': 'stub-verify', 'answers': {'verify': {'type': 'choice', 'choice': 'supported',
                  'confidence': 0.88, 'probabilities': {}}}, 'usage': {}}
    return {'model': 'stub-verify', 'answers': {'relation': {'type': 'choice', 'choice': 'supports',
              'confidence': 0.9, 'probabilities': {}}}, 'usage': {}}


_w14_out = _w14_check(_w14root, {'claims': [{'id': 'v1', 'claim': 'HTTP 200 was observed',
                                             'evidence_ref': 'E-000001'},
                                            {'id': 'v1b', 'claim': 'the title was Example Domain',
                                             'evidence_ref': 'E-000001'}]},
                      client=_w14_support_stub, verify=True)
_w14_res = _w14_out['results'][0]
check('v8.2 W14: a supported verdict verifies and stays auto',
      _w14_res['auto'] is True and _w14_res.get('verify', {}).get('supported') is True
      and _w14_res['verify']['attempts'] == 1)
check('v8.2 W14: verify costs one extra judge call per claim',
      sum(1 for c in _w14_calls if c == {'relation'}) == 2
      and sum(1 for c in _w14_calls if c == {'verify'}) == 2)
_w14_reject_calls: list = []


def _w14_reject_stub(state, questions):
    _w14_reject_calls.append(set(questions))
    if 'verify' in questions:
        return {'model': 'stub-verify', 'answers': {'verify': {'type': 'choice', 'choice': 'unsupported',
                  'confidence': 0.85, 'probabilities': {}}}, 'usage': {}}
    return {'model': 'stub-verify', 'answers': {'relation': {'type': 'choice', 'choice': 'supports',
              'confidence': 0.9, 'probabilities': {}}}, 'usage': {}}


import shutil as _w14_shutil
_w14rej = Path(tempfile.mkdtemp())
for d in ['00_control', '11_runtime']:
    (_w14rej / d).mkdir(parents=True, exist_ok=True)
(_w14rej / '00_control/engagement.yaml').write_text('external_judgment: "ALLOWED"\n')
(_w14rej / '11_runtime/events.jsonl').write_text('')
(_w14rej / 'proof.txt').write_text('HTTP 200 observed with title Example Domain\n')
ControlPlane(_w14rej).register_evidence('proof.txt', kind='raw', source='test')
_w14_reject = _w14_check(_w14rej, {'claims': [{'id': 'v2', 'claim': 'HTTP 200 was observed',
                                              'evidence_ref': 'E-000001'}]},
                         client=_w14_reject_stub, verify=True)
_w14_rres = _w14_reject['results'][0]
check('v8.2 W14: an unsupported verdict retries boundedly then flags',
      _w14_rres['auto'] is False and _w14_rres.get('verify', {}).get('supported') is False
      and _w14_rres['verify']['attempts'] == 2 and 'verify-clause' in _w14_rres.get('note', '')
      and sum(1 for c in _w14_reject_calls if c == {'relation'}) == 2
      and sum(1 for c in _w14_reject_calls if c == {'verify'}) == 2)
import json as _w14_json
_w14_rows = [ _w14_json.loads(line) for line in
              (_w14root / '11_runtime/jev-judgments.jsonl').read_text().splitlines() if line.strip()]
check('v8.2 W14: judgments store digest, model, verdict, confidence and timestamp',
      all(set(('input_digest', 'model', 'verdict', 'confidence', 'timestamp')) <= set(r)
          and len(r['input_digest']) == 64 for r in _w14_rows) and len(_w14_rows) >= 2)
def _w14_match_mock(state, questions):
    if 'verify' in questions:
        return {'answers': {'verify': {'type': 'choice', 'choice': 'supported', 'confidence': 0.88}},
                'usage': {}}
    return {'answers': {'relation': {'type': 'choice', 'choice': 'supports', 'confidence': 0.9}},
            'usage': {}}


_w14_replay_ok = _w14_replay(_w14root, client=_w14_match_mock)
check('v8.2 W14: replay with a matching mock reproduces guard decisions',
      _w14_replay_ok['matched'] == _w14_replay_ok['replayed'] >= 2
      and _w14_replay_ok['mismatched'] == 0)
def _w14_flip_mock(state, questions):
    if 'verify' in questions:
        return {'answers': {'verify': {'type': 'choice', 'choice': 'unsupported', 'confidence': 0.9}},
                'usage': {}}
    return {'answers': {'relation': {'type': 'choice', 'choice': 'contradicts', 'confidence': 0.9}},
            'usage': {}}


_w14_replay_flip = _w14_replay(_w14root, client=_w14_flip_mock)
check('v8.2 W14: replay with a flipped mock reports mismatches',
      _w14_replay_flip['mismatched'] >= 2 and _w14_replay_flip['matched'] == 0)
_w14_denied = _w14_check(POLICY_DENY, {'claims': [{'id': 'v9', 'claim': 'x', 'evidence_ref': 'E-000001'}]},
                         client=_w14_support_stub, verify=True)
check('v8.2 W14: verify stays gated by external_judgment ALLOWED',
      _w14_denied['source'] == 'unavailable' and _w14_denied['results'] == [])
with mock.patch.object(ts_claims, "record_judgments", side_effect=OSError("injected ledger failure")):
    _w14_lost = _w14_check(_w14root, {'claims': [{'id': 'vL', 'claim': 'HTTP 200 was observed',
                                                  'evidence_ref': 'E-000001'}]},
                           client=_w14_support_stub, verify=True)
check('backlog B10: a judgment-ledger write failure is surfaced, not swallowed',
      bool(_w14_lost['results']) and _w14_lost.get('judgments_recorded') is False
      and 'judgment' in str(_w14_lost.get('judgments_error', '')).lower())
check('backlog B10: the happy path reports recorded judgments',
      _w14_out.get('judgments_recorded') is True)

# 8. v8.3 V4: validate_choice — a model answer is validated before it becomes a value.
#    Rejection is never coercion: callers fall back or flag, they never take the bad value.
from ts_http import validate_choice  # noqa: E402

CHOICES3 = ('supports', 'contradicts', 'says_nothing')
check('validate_choice accepts a full simplex whose choice is the argmax',
      validate_choice({'choice': 'supports',
                       'probabilities': {'supports': 0.9, 'contradicts': 0.05, 'says_nothing': 0.05}},
                      CHOICES3) is None)
check('validate_choice accepts a partial probability map (legacy/IDF-adjacent shapes)',
      validate_choice({'choice': 'supports', 'probabilities': {'supports': 0.9}}, CHOICES3) is None)
check('validate_choice accepts absent probabilities and the none option',
      validate_choice({'choice': 'none'}, ('none', 'pack-a')) is None)
check('validate_choice rejects a choice outside the answer space',
      'not one of' in str(validate_choice({'choice': 'maybe'}, CHOICES3)))
check('validate_choice rejects a simplex violation',
      'simplex' in str(validate_choice({'choice': 'supports',
                                        'probabilities': {'supports': 0.5, 'contradicts': 0.2,
                                                          'says_nothing': 0.1}}, CHOICES3)))
check('validate_choice rejects an argmax mismatch',
      'argmax' in str(validate_choice({'choice': 'contradicts',
                                       'probabilities': {'supports': 0.8, 'contradicts': 0.15,
                                                         'says_nothing': 0.05}}, CHOICES3)))
check('validate_choice tolerates float noise around the simplex',
      validate_choice({'choice': 'supports', 'probabilities': {'supports': 0.6,
                                                               'contradicts': 0.2000000001,
                                                               'says_nothing': 0.1999999999}},
                      CHOICES3) is None)
check('validate_choice tolerates ties at the argmax',
      validate_choice({'choice': 'contradicts', 'probabilities': {'supports': 0.5, 'contradicts': 0.5}},
                      CHOICES3) is None)
check('validate_choice rejects negative, NaN and non-numeric probabilities',
      validate_choice({'choice': 'supports', 'probabilities': {'supports': -0.5, 'contradicts': 1.5}},
                      CHOICES3) is not None
      and validate_choice({'choice': 'supports', 'probabilities': {'supports': float('nan')}},
                          CHOICES3) is not None
      and validate_choice({'choice': 'supports', 'probabilities': {'supports': 'high'}},
                          CHOICES3) is not None)
check('validate_choice rejects a non-object answer',
      validate_choice(None, CHOICES3) is not None and validate_choice('supports', CHOICES3) is not None)
check('validate_choice rejects a choice missing from its own probability map',
      validate_choice({'choice': 'supports', 'probabilities': {'contradicts': 0.9}}, CHOICES3) is not None)

# The triage seam rejects an invalid response to the deterministic IDF fallback with a
# visible reason; usage is still real (tokens were spent) and never a value.
bad_triage = lambda state, questions: {  # noqa: E731
    'model': 'stub-bad',
    'answers': {'first_pack': {'choice': 'not-a-pack', 'confidence': 0.99,
                               'probabilities': {'not-a-pack': 1.0}}},
    'usage': {'input_tokens': 3, 'output_tokens': 1},
}
rejected_triage = triage_suggest(POLICY_ALLOW, 'realtime socket subscription leak', client=bad_triage)
check('triage rejects an invalid model response to the IDF fallback with the reason',
      rejected_triage['source'] == 'idf' and rejected_triage['suggested'] == rejected_triage['ranked'][0]
      and 'rejected' in rejected_triage.get('note', '')
      and rejected_triage['usage'] == {'input_tokens': 3, 'output_tokens': 1})
check('triage rejects a response with no answers instead of raising',
      triage_suggest(POLICY_ALLOW, 'realtime socket subscription leak',
                     client=lambda state, questions: {'model': 'stub-bad', 'usage': {}})['source'] == 'idf')

# The claims seam flags an argmax-mismatched relation answer as invalid_choice.
mismatch_client = lambda state, questions: {  # noqa: E731
    'model': 'stub-1',
    'answers': {'relation': {'type': 'choice', 'choice': 'contradicts', 'confidence': 0.99,
                             'probabilities': {'supports': 0.9, 'contradicts': 0.05,
                                               'says_nothing': 0.05}}},
    'usage': {},
}
mismatch_out = check_claims(croot, {'claims': [{'id': 'c8', 'claim': 'x', 'evidence_ref': 'E-000001'}]},
                            client=mismatch_client)
check('an argmax-mismatched relation answer is flagged invalid_choice, never surfaced',
      mismatch_out['results'][0]['verdict'] == 'invalid_choice'
      and mismatch_out['results'][0]['auto'] is False
      and 'argmax' in mismatch_out['results'][0].get('note', ''))

# Replay normalizes a rejected answer to invalid_choice too, so an invalid stored record
# replays deterministically instead of reporting a spurious drift/mismatch.
invroot = Path(tempfile.mkdtemp())
for d in ['00_control', '11_runtime']:
    (invroot / d).mkdir(parents=True, exist_ok=True)
(invroot / '00_control/engagement.yaml').write_text('external_judgment: "ALLOWED"\n')
(invroot / '11_runtime/events.jsonl').write_text('')
(invroot / 'proof.txt').write_text('HTTP 200 observed with title Example Domain\n')
ControlPlane(invroot).register_evidence('proof.txt', kind='raw', source='test')
_w14_check(invroot, {'claims': [{'id': 'inv1', 'claim': 'HTTP 200 was observed',
                                 'evidence_ref': 'E-000001'}]}, client=mismatch_client)
_replay_inv = _w14_replay(invroot, client=mismatch_client)
check('replay reproduces an invalid_choice guard decision deterministically',
      _replay_inv['replayed'] == 1 and _replay_inv['matched'] == 1
      and _replay_inv['mismatched'] == 0)

# 6m. Fix (Standards M1): a verify answer that `validate_choice` rejects is NOT a
# supported verdict — the raw choice never feeds `supported`/`auto` and the stored
# judgment records the fail-closed decision (which replay reproduces).
_foroot = Path(tempfile.mkdtemp())
for d in ['00_control', '11_runtime']:
    (_foroot / d).mkdir(parents=True, exist_ok=True)
(_foroot / '00_control/engagement.yaml').write_text('external_judgment: "ALLOWED"\n')
(_foroot / '11_runtime/events.jsonl').write_text('')
(_foroot / 'proof.txt').write_text('HTTP 200 observed with title Example Domain\n')
ControlPlane(_foroot).register_evidence('proof.txt', kind='raw', source='test')
_fo_calls: list = []


def _failopen_client(state, questions):
    _fo_calls.append(sorted(questions))
    if 'verify' in questions:
        return {'model': 'jev-fo',
                'answers': {'verify': {'type': 'choice', 'choice': 'supported',
                                       'confidence': 0.95,
                                       'probabilities': {'supported': 0.9, 'unsupported': 0.9}}},
                'usage': {}}
    return {'model': 'jev-fo', 'answers': {'relation': {'type': 'choice', 'choice': 'supports',
              'confidence': 0.9, 'probabilities': {'supports': 0.9, 'contradicts': 0.05,
                                                   'says_nothing': 0.05}}}, 'usage': {}}


_fo_out = check_claims(_foroot, {'claims': [{'id': 'fo1', 'claim': 'HTTP 200 was observed',
                                             'evidence_ref': 'E-000001'}]},
                       client=_failopen_client, verify=True)
_fo_res = _fo_out['results'][0]
check('an invalid verify answer is not-supported: the rejected choice never decides',
      _fo_res['verify']['supported'] is False and _fo_res['auto'] is False
      and 'invalid_choice' in _fo_res['verify'] and 'simplex' in _fo_res['verify']['invalid_choice']
      and sum(1 for c in _fo_calls if c == ['relation']) == 2
      and sum(1 for c in _fo_calls if c == ['verify']) == 2)
_fo_rows = [json.loads(line) for line in
            (_foroot / '11_runtime/jev-judgments.jsonl').read_text().splitlines() if line.strip()]
_fo_row = [r for r in _fo_rows if r.get('claim_id') == 'fo1'][-1]
check('the judgment ledger records the fail-closed verify decision',
      _fo_row['verify_supported'] is False and _fo_row['auto'] is False)
_replay_fo = _w14_replay(_foroot, client=_failopen_client)
check('replay reproduces the fail-closed verify decision deterministically',
      _replay_fo['replayed'] == 1 and _replay_fo['matched'] == 1
      and _replay_fo['mismatched'] == 0)

# 9. v8.3 V7: already-covered proof — the v8.2 W14 verify-clause + replay are green
#    end to end through the CLI seam too (claims-check runs the verify judge, records
#    the judgment ledger, and the stored records replay deterministically).
_v7root = Path(tempfile.mkdtemp())
for d in ['00_control', '02_surface', '03_hypotheses/active', '03_hypotheses/archive', '04_cycles',
          '10_learning', '11_runtime']:
    (_v7root / d).mkdir(parents=True, exist_ok=True)
(_v7root / '00_control/engagement.yaml').write_text('external_judgment: "ALLOWED"\n')
(_v7root / '02_surface/endpoints.yaml').write_text('endpoints: []\n')
(_v7root / '11_runtime/events.jsonl').write_text('')
(_v7root / '11_runtime/run-status.yaml').write_text('engagement_status: "BOOTSTRAP"\n')
(_v7root / '11_runtime/tool-registry.yaml').write_text('tools: []\n')
(_v7root / '11_runtime/lab-status.yaml').write_text('status: UNKNOWN\n')
(_v7root / '10_learning/freshness.yaml').write_text('components: []\n')
(_v7root / '10_learning/unknowns.yaml').write_text('unknowns: []\n')
(_v7root / '10_learning/assumptions.yaml').write_text('assumptions: []\n')
(_v7root / 'proof.txt').write_text('HTTP 200 observed with title Example Domain\n')
ControlPlane(_v7root).register_evidence('proof.txt', kind='raw', source='test')
_v7packet = _v7root / 'packet.json'
_v7packet.write_text(json.dumps({'claims': [{'id': 'v7', 'claim': 'HTTP 200 was observed',
                                             'evidence_ref': 'E-000001'}]}))
_v7_calls: list = []


def _v7_post(payload, **kwargs):
    _v7_calls.append(sorted(payload['questions']))
    if 'verify' in payload['questions']:
        return {'model': 'jev-v7', 'answers': {'verify': {'choice': 'supported', 'confidence': 0.9}},
                'usage': {'input_tokens': 3, 'output_tokens': 1}}
    return {'model': 'jev-v7', 'answers': {'relation': {'choice': 'supports', 'confidence': 0.92,
              'probabilities': {'supports': 0.92, 'contradicts': 0.04, 'says_nothing': 0.04}}},
            'usage': {'input_tokens': 4, 'output_tokens': 1}}


with mock.patch('ts_claims.post_json', _v7_post), \
        mock.patch.dict(os.environ, {'TYPESAFE_API_KEY': 'k'}):
    _v7buf = io.StringIO()
    with contextlib.redirect_stdout(_v7buf):
        _v7rc = run_cli([str(TOOLS / 'researchctl.py'), str(_v7root), 'claims-check',
                         str(_v7packet)])
_v7out = json.loads(_v7buf.getvalue())
check('v8.3 V7: claims-check CLI runs the verify judge and records the judgments',
      _v7rc == 0 and _v7_calls == [['relation'], ['verify']]
      and _v7out['results'][0]['verify']['supported'] is True
      and _v7out['results'][0]['auto'] is True
      and (_v7root / '11_runtime/jev-judgments.jsonl').is_file())
def _v7_client(state, questions):
    """Client-shaped mock (state, questions) for the offline replay path."""
    if 'verify' in questions:
        return {'model': 'jev-v7', 'answers': {'verify': {'choice': 'supported', 'confidence': 0.9}},
                'usage': {}}
    return {'model': 'jev-v7', 'answers': {'relation': {'choice': 'supports', 'confidence': 0.92}},
            'usage': {}}


check('v8.3 V7: the stored judgment replays deterministically with a mocked provider',
      _w14_replay(_v7root, client=_v7_client)['matched'] == 1
      and _w14_replay(_v7root, client=_v7_client)['mismatched'] == 0)
with mock.patch.dict(os.environ, {'TYPESAFE_API_KEY': 'k'}), \
        mock.patch('ts_claims.post_json', _v7_post):
    _v7deny = check_claims(POLICY_DENY, {'claims': [{'id': 'v7d', 'claim': 'x',
                                                     'evidence_ref': 'E-000001'}]}, verify=True)
check('v8.3 V7: the DENIED-default gate still short-circuits claims-check before any call',
      _v7deny['source'] == 'unavailable' and _v7deny['results'] == [])

print(f'\n{len(passed)}/{len(passed)} passed')
