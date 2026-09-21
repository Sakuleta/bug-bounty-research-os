#!/usr/bin/env python3
"""Build the smallest useful runtime context with provenance and adaptive knowledge selection."""
from __future__ import annotations
import os, re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from knowledge_index import top_packs

DEFAULT_BUDGET=10000
DEFAULT_PACK_CAP=4

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

def assemble(root:Path,budget:int=DEFAULT_BUDGET,pack_cap:int=DEFAULT_PACK_CAP)->str:
    rt=root/'11_runtime'; out='# Current Context\n\n'
    parts=[]
    parts.append(section('ENTRY CONTRACT',read(root/'START.md',1800)))
    parts.append(section('ENGAGEMENT POLICY',read(root/'00_control/engagement.yaml',2200)))
    parts.append(section('RUN STATUS',read(rt/'run-status.yaml',1000)))
    parts.append(section('FRESHNESS',read(root/'10_learning/freshness.yaml',1200)))
    query='\n'.join([p for p in [read(rt/'active-cycle.yaml',2500),read(rt/'last-result.md',1800),read(root/'10_learning/unknowns.yaml',1800)] if p])
    ranked = top_packs(root,query,k=pack_cap)
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
        clipped=part[:room]
        if len(clipped)<len(part): clipped += '\n\n[CONTEXT_TRUNCATED]\n'
        out+=clipped+'\n'
    return out[:budget]

GENERATED_HEADER = "# GENERATED — do not edit by hand; rebuilt by the control plane on every mutation (tools/build_context.py)"

def rebuild(root, budget=None, pack_cap=None):
    """Rebuild 11_runtime/current-context.md as a deterministic projection of workspace state."""
    if budget is None:
        try: budget=int(os.getenv('CONTEXT_BUDGET',DEFAULT_BUDGET))
        except ValueError: budget=DEFAULT_BUDGET
    if pack_cap is None:
        try: pack_cap=int(os.getenv('KNOWLEDGE_PACK_CAP',DEFAULT_PACK_CAP))
        except ValueError: pack_cap=DEFAULT_PACK_CAP
    p=root/'11_runtime'; p.mkdir(parents=True,exist_ok=True)
    body_budget=max(1,budget-len(GENERATED_HEADER)-2)
    out=assemble(root,body_budget,max(1,pack_cap))
    text=GENERATED_HEADER+'\n\n'+out
    (p/'current-context.md').write_text(text)
    return len(text)

def main():
    root=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else Path.cwd()
    n=rebuild(root)
    print(root/'11_runtime'/'current-context.md',n); return 0
if __name__=='__main__': raise SystemExit(main())
