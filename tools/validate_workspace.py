#!/usr/bin/env python3
"""Validate workspace existence + content quality. Usage: validate_workspace.py [ROOT]

Contract (explicit): an OS checkout root (tools/control_plane.py present) gets the
full check below; an engagement snapshot (no tools/, but 00_control/ + 11_runtime/)
gets the engagement subset only — required engagement files plus the leak/junk
scans. Anything else fails. `tools/audit.py`, not this script, is the engagement
integrity check.
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from knowledge_index import parse_index, validate_index  # noqa: E402

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
IS_CHECKOUT = (ROOT / 'tools' / 'control_plane.py').is_file()
IS_SNAPSHOT = (not IS_CHECKOUT
               and ((ROOT / '00_control' / 'engagement.yaml').is_file()
                    or (ROOT / '11_runtime' / 'events.jsonl').is_file()))
if IS_SNAPSHOT:
    print('engagement snapshot: validating the engagement subset '
          '(validate_workspace targets an OS checkout root; tools/audit.py is the integrity check)')
REQUIRED = [
    'OS_VERSION',
    'START.md', 'AGENTS.md', 'ARCHITECTURE.md',
    '00_control/engagement.yaml', '00_control/research-contract.md', '00_control/identity-binding.yaml',
    '02_WORKFLOW.md', '03_ORCHESTRATOR.md', '04_CYCLE_PROTOCOL.md',
    '05_HYPOTHESIS_ENGINE.md', '06_EVIDENCE_VALIDATION.md', '07_AUDIT_CLOSURE.md',
    '08_human_gates.md', '09_RESEARCH_PROTOCOL.md', '10_STATE_MODEL.md',
    '11_WORKER_PROTOCOL.md', '12_REPORT_PROTOCOL.md', '13_RUNTIME.md',
    '17_DYNAMIC_TECHNIQUE_ENGINE.md',
    'REAL_ENGAGEMENT_TEMPLATE.md',
    'tools/new_cycle.py', 'tools/build_context.py', 'tools/control_plane.py',
    'tools/researchctl.py', 'tools/audit.py', 'tools/provision.py', 'tools/cycle.py',
    'tools/knowledge_index.py', 'tools/state.py',
    'tools/test_runtime.py', 'tools/test_cycle.py', 'tools/test_context.py',
    'tools/test_state.py', 'tools/test_control_plane.py',
    'schemas/cycle.yaml', 'schemas/event.json', 'schemas/hypothesis.yaml', 'schemas/technique.yaml',
    '12_knowledge/INDEX.yaml',
    '11_runtime/run-status.yaml', '11_runtime/active-cycle.yaml',
    '11_runtime/tool-registry.yaml', '11_runtime/lab-status.yaml',
    '11_runtime/last-result.md', '11_runtime/current-context.md',
    '11_runtime/events.jsonl', '11_runtime/evidence-index.jsonl',
    '11_runtime/human-gates', '10_learning/freshness.yaml',
    '10_learning/unknowns.yaml', '10_learning/assumptions.yaml',
]
REQUIRED_SNAPSHOT = [
    '00_control/engagement.yaml',
    '11_runtime/run-status.yaml',
    '11_runtime/events.jsonl',
]
if IS_SNAPSHOT:
    REQUIRED = REQUIRED_SNAPSHOT
LEAK = re.compile(r'turn\d+\S*search|cite.?turn', re.IGNORECASE)
issues = []
missing = [p for p in REQUIRED if not (ROOT / p).exists()]
if missing:
    issues.append('Missing: ' + ', '.join(missing))

idx_errors, idx_warnings = ([], []) if IS_SNAPSHOT else validate_index(ROOT)
issues.extend(idx_errors)
for w in idx_warnings:
    print(f'warning: {w}')

# Knowledge <-> skills binding: every indexed pack ships its skill entry point, so
# the agent's on-demand reach (the skill) and the triage/lookup layer never drift apart.
# OS checkouts only — engagement snapshots carry no packs or skills.
if not IS_SNAPSHOT and (ROOT / '12_knowledge' / 'INDEX.yaml').exists():
    for pack in sorted(parse_index(ROOT / '12_knowledge' / 'INDEX.yaml')):
        if not (ROOT / '.dsh' / 'skills' / pack / 'SKILL.md').is_file():
            issues.append(f'knowledge pack without a skill entry point: .dsh/skills/{pack}/SKILL.md missing')

for s in ['schemas/cycle.yaml', 'schemas/event.json', 'schemas/hypothesis.yaml', 'schemas/technique.yaml']:
    p = ROOT / s
    if p.exists() and p.stat().st_size == 0:
        issues.append(f'schema empty: {s}')
ev = ROOT / 'schemas/event.json'
if ev.exists() and ev.stat().st_size:
    try:
        json.loads(ev.read_text(errors='ignore'))
    except json.JSONDecodeError as e:
        issues.append(f'schemas/event.json: invalid JSON: {e}')

for rel in ['11_runtime/run-status.yaml', '11_runtime/active-cycle.yaml',
            '11_runtime/tool-registry.yaml', '11_runtime/lab-status.yaml',
            '11_runtime/last-result.md', '11_runtime/current-context.md']:
    p = ROOT / rel
    if p.exists() and p.stat().st_size == 0 and not IS_SNAPSHOT:
        issues.append(f'11_runtime template empty: {rel}')

for p in ROOT.rglob('*'):
    if not p.is_file() or p.suffix not in ('.md', '.yaml', '.yml'):
        continue
    if '.git' in p.parts or 'node_modules' in p.parts:
        continue
    try:
        for i, line in enumerate(p.read_text(errors='ignore').splitlines(), 1):
            if LEAK.search(line):
                issues.append(f'cite-artifact leakage: {p.relative_to(ROOT)}:{i}')
                break
    except OSError:
        pass

junk = [p for p in ROOT.rglob('*') if p.is_file() and p.name == '.DS_Store']
stray_pyc = [p for p in ROOT.rglob('*.pyc') if '__pycache__' not in p.parts]
if stray_pyc:
    junk.extend(stray_pyc)
if junk:
    issues.append('Generated/junk files: ' + ', '.join(str(x.relative_to(ROOT)) for x in junk[:10]))

if issues:
    print('\n'.join(issues))
    raise SystemExit(1)
print('Workspace validation: PASS')
