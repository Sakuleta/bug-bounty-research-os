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

print(f'\n{len(passed)}/{len(passed)} passed')
