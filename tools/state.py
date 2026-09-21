#!/usr/bin/env python3
"""Compatibility adapter: all mutable research state goes through control_plane.py."""
from __future__ import annotations
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from control_plane import ControlPlane  # noqa: E402

TYPES=('STATE_CHANGE','NOTE','WORKER_RESULT')

def propose(entity='', from_='', to='', reason='', actor='controller', evidence_refs=(), type='STATE_CHANGE'):
    if type not in TYPES: raise ValueError(f'unknown type {type!r}')
    if not entity or not reason: raise ValueError('proposal needs entity/reason')
    if type=='STATE_CHANGE' and not evidence_refs: raise ValueError('STATE_CHANGE needs evidence_refs')
    return {'entity':entity,'from':from_,'to':to,'reason':reason,'actor':actor,'evidence_refs':list(evidence_refs),'type':type}

def append_event(root, proposal):
    cp=ControlPlane(Path(root)); kind=proposal.get('type','NOTE')
    return cp.append(kind,'legacy',proposal['entity'],actor=proposal.get('actor','controller'),reason=proposal.get('reason',''),
                     evidence_refs=proposal.get('evidence_refs',[]),payload=proposal)

def refresh(root): return ControlPlane(Path(root)).refresh()
def read_status(root): return refresh(root)

def merge(root, proposal):
    p=dict(proposal)
    p.pop('root', None)
    return append_event(root, p)

def merge_result(packet, actor='orchestrator', root=Path.cwd()): return ControlPlane(Path(root)).merge_worker(packet,actor=actor)
def record(entity,to,reason,from_='',evidence_refs=(),actor='controller',root=Path.cwd()):
    cp=ControlPlane(Path(root))
    if from_:
        return cp.append('NOTE','legacy',entity,actor=actor,reason=reason,evidence_refs=evidence_refs,payload={'from':from_,'to':to})
    return cp.append('NOTE','legacy',entity,actor=actor,reason=reason,evidence_refs=evidence_refs,payload={'to':to})

def main():
    if len(sys.argv)<3: print('usage: state.py <ROOT> refresh | merge-result --packet FILE | record ...'); return 2
    root=Path(sys.argv[1]).resolve(); verb=sys.argv[2]
    try:
        if verb=='refresh': print(json.dumps(read_status(root),indent=1)); return 0
        if verb=='merge-result' and len(sys.argv)==5 and sys.argv[3]=='--packet': print(json.dumps(merge_result(json.loads(Path(sys.argv[4]).read_text()),root=root))); return 0
        print('record compatibility path is deprecated; use researchctl'); return 2
    except Exception as e: print(f'error: {e}',file=sys.stderr); return 1
if __name__=='__main__': raise SystemExit(main())
