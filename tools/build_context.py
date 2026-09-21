#!/usr/bin/env python3
"""Build the smallest useful runtime context with provenance and adaptive knowledge selection."""
from __future__ import annotations
import json, os, re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from control_plane import external_judgment_allowed, scope_check
from knowledge_index import selection_cap, selection_query, top_packs

DEFAULT_BUDGET=10000

def read(p:Path, limit:int|None=None)->str:
    try:
        s=p.read_text(errors='ignore')
        return s if limit is None else s[:limit]
    except OSError: return ''

def section(title, body):
    b=body.strip()
    return f'## {title}\n\n{b}\n' if b else ''

def cycle_id(rt):
    m=re.search(r'cycle_id:\s*"?([A-Za-z0-9-]+)"?',read(rt/'active-cycle.yaml',500))
    return m.group(1) if m and m.group(1) not in ('null','None') else None

def _unquote(value:str)->str:
    return value.strip().strip('"\'').strip()

def _is_placeholder(value:str)->bool:
    """`<...>` template values are ABSENT, not literals: they must never be presented
    as a resolved identity fact."""
    return bool(re.fullmatch(r'<[^<>]*>',value.strip()))

def _yaml_scalar(path:Path, key:str)->str:
    m=re.search(rf'^\s*{key}:\s*(.+?)\s*$',read(path,4000),re.M)
    return _unquote(m.group(1)) if m else ''

def _identity_scalar(path:Path, key:str)->str:
    """A YAML scalar for identity display; `<placeholder>` values count as absent."""
    value=_yaml_scalar(path,key)
    return '' if _is_placeholder(value) else value

def _stop_conditions(plan:str)->list[str]:
    """Stop conditions from either a YAML flow list or an indented block list."""
    m=re.search(r'^stop_conditions:\s*(.+)$',plan,re.M)
    if m:
        try:
            value=json.loads(m.group(1))
            if isinstance(value,list): return [str(v) for v in value]
        except (json.JSONDecodeError,TypeError): pass
        return [_unquote(m.group(1))]
    m=re.search(r'^stop_conditions:\s*$\n((?:[ \t]+-.*\n?)+)',plan,re.M)
    if not m: return []
    return [_unquote(line.split('-',1)[1]) for line in m.group(1).splitlines() if '-' in line]

def safety_kernel(root:Path)->str:
    """Small, complete safety facts: status, scope gate, external-judgment policy,
    active-cycle stop conditions, pending human gate, non-secret identity binding.

    The kernel is the first section and is never truncated; a tiny budget shrinks the
    sections after it, never this one.
    """
    rt=root/'11_runtime'
    status=re.search(r'^engagement_status:\s*"?([A-Z_]+)"?',read(rt/'run-status.yaml',1000),re.M)
    gate=scope_check(root,'https://scope-probe.invalid/')
    if gate['gate']=='assets':
        scope=f"gate: assets — assets: {', '.join(str(a) for a in gate['assets'])}"
    elif gate['gate']=='disabled':
        scope='gate: none (explicit human opt-out)'
    elif gate['gate']=='unenforceable':
        scope='gate: unenforceable — assets are not a simple string list (fail closed)'
    else:
        scope='gate: unset — target traffic denied until scope-set (default deny)'
    policy='ALLOWED' if external_judgment_allowed(root) else 'DENIED'
    pointer=re.search(r'^current_cycle:\s*"?([A-Za-z0-9-]+|null)"?',read(rt/'run-status.yaml',1000),re.M)
    if pointer:
        cid=None if pointer.group(1)=='null' else pointer.group(1)
    else:
        cid=cycle_id(rt)  # no status pointer: fall back to the cycle projection
    if cid:
        stops=_stop_conditions(read(root/'04_cycles'/cid/'plan.yaml',4000))
        cycle=f"active cycle: {cid} — stop conditions: {'; '.join(stops) if stops else 'none recorded'}"
    else:
        cycle='active cycle: none'
    pending=bool(re.search(r'^pending_human_gate:\s*true\s*$',read(rt/'run-status.yaml',1000),re.M|re.I))
    binding=root/'00_control/identity-binding.yaml'
    handle=_identity_scalar(binding,'public_handle')
    reference=_identity_scalar(binding,'account_reference')
    if not reference:
        reference=_identity_scalar(root/'00_control/engagement.yaml','identity_reference')
    identity=f"identity: handle={handle or 'UNKNOWN'} — reference={reference or 'UNKNOWN'}"
    return '\n'.join([
        f"engagement: {status.group(1) if status else 'UNKNOWN'}",
        f"scope: {scope}",
        f"external judgment: {policy}",
        cycle,
        f"human gate: {'PENDING' if pending else 'none pending'}",
        identity,
    ])

def assemble(root:Path,budget:int=DEFAULT_BUDGET,pack_cap:int|None=None)->str:
    rt=root/'11_runtime'; out='# Current Context\n\n'
    pack_cap=max(1,pack_cap) if pack_cap is not None else selection_cap()
    kernel=section('SAFETY KERNEL',safety_kernel(root))
    if kernel: out+=kernel+'\n'
    # The safety kernel is the floor: it outranks the budget. When the budget cannot
    # hold the prefixed kernel, emit the whole kernel (documented: the result may exceed
    # the budget) rather than silently cutting a safety fact mid-line.
    if kernel and len(out)>=budget: return out
    parts=[]
    parts.append(section('ENTRY CONTRACT',read(root/'START.md',1800)))
    parts.append(section('ENGAGEMENT POLICY',read(root/'00_control/engagement.yaml',2200)))
    parts.append(section('RUN STATUS',read(rt/'run-status.yaml',1000)))
    parts.append(section('FRESHNESS',read(root/'10_learning/freshness.yaml',1200)))
    # The shared seam: the RUNNING knowledge-triage guard ranks with the same query and
    # cap, so the coverage it demands is exactly this rendered set.
    ranked = top_packs(root,selection_query(root),k=pack_cap)
    # Decision log, placed FIRST so it survives budget truncation: the controller sees
    # WHAT was auto-selected so it can confirm or override per cycle (knowledge triage
    # is enforced by audit.py — this line is its input).
    parts.append(section('KNOWLEDGE_SELECTION', f"auto-selected packs (relevance-ranked, cap {pack_cap}): {', '.join(n for n,_ in ranked) or 'none'} — confirm or override in the cycle knowledge_triage"))
    parts.append(section('ACTIVE CYCLE',read(rt/'active-cycle.yaml',1400)))
    cid=cycle_id(rt)
    if cid:
        c=root/'04_cycles'/cid
        parts.append(section(f'CYCLE {cid}', '\n\n'.join(read(p,2200) for p in sorted(c.glob('*')) if p.is_file())))
    parts.append(section('LAST RESULT',read(rt/'last-result.md',1800)))
    parts.append(section('UNKNOWN / ASSUMPTION LEDGERS',read(root/'10_learning/unknowns.yaml',1500)+'\n'+read(root/'10_learning/assumptions.yaml',1200)))
    parts.append(section('ACTIVE HYPOTHESIS','\n\n'.join(read(p,2200) for p in sorted((root/'03_hypotheses'/'active').glob('*.yaml'))[:2])))
    parts.append(section('TOOL / LAB',read(rt/'tool-registry.yaml',1400)+'\n'+read(rt/'lab-status.yaml',1000)))
    for name,paths in ranked:
        body='\n\n'.join(read(p,1800) for p in paths)
        parts.append(section(f'KNOWLEDGE/{name}',body))
    for part in parts:
        room=budget-len(out)
        if room<=0: break
        if len(part)<=room:
            out+=part+'\n'
            continue
        # Reserve room for the marker so the final budget slice cannot cut it.
        marker='\n\n[CONTEXT_TRUNCATED]\n'
        out+=part[:max(0,room-len(marker)-1)]+marker
        break
    return out[:budget]

GENERATED_HEADER = "# GENERATED — do not edit by hand; rebuilt by the control plane on every mutation (tools/build_context.py)"

def rebuild(root, budget=None, pack_cap=None):
    """Rebuild 11_runtime/current-context.md as a deterministic projection of workspace state."""
    if budget is None:
        try: budget=int(os.getenv('CONTEXT_BUDGET',DEFAULT_BUDGET))
        except ValueError: budget=DEFAULT_BUDGET
    p=root/'11_runtime'; p.mkdir(parents=True,exist_ok=True)
    body_budget=max(1,budget-len(GENERATED_HEADER)-2)
    out=assemble(root,body_budget,pack_cap)
    text=GENERATED_HEADER+'\n\n'+out
    (p/'current-context.md').write_text(text)
    return len(text)

def main():
    root=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else Path.cwd()
    n=rebuild(root)
    print(root/'11_runtime'/'current-context.md',n); return 0
if __name__=='__main__': raise SystemExit(main())
