#!/usr/bin/env python3
"""Experiment: IDF knowledge triage (baseline) vs TypeSafe Noul rerank.

Shortlist = the OS's own knowledge_index.rank_packs (IDF over load_when), top K.
Rerank    = one Jev call per question asking, per shortlisted pack, whether that
            field guide would materially help answer the question.
Metrics   = top-1 / top-3 accuracy of the gold pack, baseline vs reranked.

Guarded live runner: refuses to call the external API unless `--force` is passed AND
the `external_judgment` policy of the `--root` workspace (default: this repo, or
RESEARCH_OS_ROOT) is ALLOWED; output is written to a temp file and atomically replaces
the committed artifact, and the committed artifact is never overwritten without
`--force`. The committed results.json / results_choice.json are the authoritative
records; the original scratch directory no longer exists.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from control_plane import external_judgment_allowed  # noqa: E402
from knowledge_index import parse_index, rank_packs  # noqa: E402

API = 'https://api.typesafe.ai/v1/systemone'
KEY = os.environ.get('TYPESAFE_API_KEY', '')
K = 5
SCRATCH = Path(__file__).resolve().parent


def workspace_root() -> Path:
    """The workspace whose policy and knowledge packs this run reads."""
    return Path(os.environ.get('RESEARCH_OS_ROOT') or REPO_ROOT)


def guard_live(force: bool, root: Path) -> None:
    """Refuse a live run without --force and without an explicit policy opt-in."""
    if not force:
        raise SystemExit('rerank_eval: refusing a live TypeSafe run without --force '
                         '(it calls the external API and rewrites the committed eval artifacts)')
    if not external_judgment_allowed(root):
        raise SystemExit(f'rerank_eval: external judgment denied by engagement policy '
                         f'({root / "00_control" / "engagement.yaml"}); set '
                         f'external_judgment: "ALLOWED" in the workspace passed as --root')
    if not os.environ.get('TYPESAFE_API_KEY'):
        raise SystemExit('TYPESAFE_API_KEY missing')


def write_results(path: Path, data, *, force: bool) -> bool:
    """Write `data` as JSON to `path` via temp file + os.replace, never overwriting the
    committed artifact without `--force`."""
    if path.exists() and not force:
        print(f'refusing to overwrite committed results without --force: {path}')
        return False
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + '.', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w') as fh:
            fh.write(json.dumps(data, indent=2) + '\n')
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return True


def pack_cards(root: Path) -> dict[str, dict]:
    """Compact candidate card per pack: skill description + first families."""
    packs = parse_index(root / '12_knowledge' / 'INDEX.yaml')
    cards = {}
    for name, (load_when, files) in packs.items():
        desc = ''
        skill = root / '.dsh' / 'skills' / name / 'SKILL.md'
        if skill.exists():
            m = re.search(r'^description:\s*"?(.*?)"?\s*$', skill.read_text(), re.M)
            desc = (m.group(1) if m else '').strip()
        families = []
        for f in files:
            p = (root / '12_knowledge' / name / f).resolve()
            if not p.is_file():
                continue
            text = p.read_text(errors='ignore')
            m = re.search(r'## Research families\n(.*?)(\n## |\Z)', text, re.S)
            if not m:
                continue
            for line in m.group(1).splitlines():
                if line.strip().startswith('- '):
                    families.append(line.strip()[2:].strip())
            if len(families) >= 8:
                break
        cards[name] = {'name': name, 'description': desc, 'research_families': families[:8]}
    return cards


def call_typesafe(state: dict, questions: dict, retries: int = 4) -> dict:
    body = json.dumps({'state': state, 'model': 'jev-latest', 'questions': questions}).encode()
    req = urllib.request.Request(API, data=body, headers={
        'Authorization': f'Bearer {KEY}', 'Content-Type': 'application/json'})
    delay = 1.0
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors='ignore')[:800]
            if e.code in (429, 529) and attempt < retries:
                time.sleep(delay); delay *= 2; continue
            raise RuntimeError(f'HTTP {e.code}: {detail}') from e
    raise RuntimeError('unreachable')


def score_query(root: Path, cards: dict, item: dict) -> dict:
    question = item['question']
    packs = parse_index(root / '12_knowledge' / 'INDEX.yaml')
    # Full-field triage: the agent chooses among all packs, so evaluate all of them.
    ranked = [name for _, name, _ in rank_packs(packs, question)]
    shortlist = ranked + [n for n in sorted(packs) if n not in ranked]
    questions = {
        name: {
            'type': 'noul',
            'instructions': (
                'Would loading `candidate_pack` materially help answer `research_question`? '
                'Answer yes when the pack domain AND its research families cover the technology '
                'and the failure class the question is about; answer no when the relation is loose '
                'or the pack covers a different layer.'
            ),
            'criteria': {
                'true': 'The pack families directly cover the technology and failure class in the question.',
                'false': 'Only loosely related, or a different layer of the stack.',
            },
        }
        for name in shortlist
    }
    resp = call_typesafe({'research_question': question,
                          'candidate_pack': {n: cards[n] for n in shortlist}}, questions)
    scores = {n: resp['answers'][n]['noul'] for n in shortlist}
    reranked = sorted(shortlist, key=lambda n: -scores[n])
    return {
        'id': item['id'], 'gold': item['gold'], 'shortlist': shortlist,
        'scores': scores, 'reranked': reranked,
        'baseline_top1': shortlist[0] == item['gold'],
        'baseline_top3': item['gold'] in shortlist[:3],
        'rerank_top1': reranked[0] == item['gold'],
        'rerank_top3': item['gold'] in reranked[:3],
        'gold_in_shortlist': item['gold'] in shortlist,
        'baseline_rank': shortlist.index(item['gold']) + 1 if item['gold'] in shortlist else None,
        'usage': resp.get('usage', {}),
    }


def main(*, root: Path | None = None, force: bool = False) -> None:
    root = root or workspace_root()
    guard_live(force, root)
    cards = pack_cards(root)
    items = json.loads((SCRATCH / 'eval_set.json').read_text())
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda it: score_query(root, cards, it), items))
    base1 = sum(r['baseline_top1'] for r in results)
    base3 = sum(r['baseline_top3'] for r in results)
    re1 = sum(r['rerank_top1'] for r in results)
    re3 = sum(r['rerank_top3'] for r in results)
    in_short = sum(r['gold_in_shortlist'] for r in results)
    n = len(results)
    tin = sum(r['usage'].get('input_tokens', 0) for r in results)
    tout = sum(r['usage'].get('output_tokens', 0) for r in results)
    print(f'K={K}, n={n}; gold in shortlist: {in_short}/{n}')
    print(f'top-1  baseline {base1}/{n}  ->  rerank {re1}/{n}')
    print(f'top-3  baseline {base3}/{n}  ->  rerank {re3}/{n}')
    print(f'tokens: {tin} in / {tout} out (~${tin/1_000_000*42:.4f})')
    print()
    for r in results:
        flag = 'FIX' if r['rerank_top1'] and not r['baseline_top1'] else ('OK ' if r['rerank_top1'] else 'MISS')
        gold_rank = (r['reranked'].index(r['gold']) + 1) if r['gold'] in r['reranked'] else '-'
        print(f"{flag} {r['id']} gold={r['gold']:<18} baseline#1={r['shortlist'][0]:<18} rerank#1={r['reranked'][0]:<18} gold_rank={gold_rank} "
              f"noul={r['scores'].get(r['gold'], 0):.2f}")
    write_results(SCRATCH / 'results.json', results, force=force)




def score_query_choice(root: Path, cards: dict, item: dict) -> dict:
    """B variant: one Choice question over ALL packs (+ none) ranks the whole field."""
    question = item['question']
    packs = parse_index(root / '12_knowledge' / 'INDEX.yaml')
    ranked = [name for _, name, _ in rank_packs(packs, question)]
    baseline = ranked + [n for n in sorted(packs) if n not in ranked]
    names = sorted(packs)
    criteria = {n: (cards[n]['description'] or n) for n in names}
    criteria['none'] = 'No pack covers this technology and failure class; research from primary sources first.'
    questions = {'first_pack': {
        'type': 'choice',
        'instructions': ('Which single candidate_pack should be loaded FIRST to research `research_question`? '
                         'Pick by how directly the pack domain and its research families cover the technology '
                         'and the failure class in the question; pick none when no pack covers it.'),
        'criteria': criteria,
    }}
    resp = call_typesafe({'research_question': question, 'candidate_pack': {n: cards[n] for n in names}}, questions)
    answer = resp['answers']['first_pack']
    probs = answer['probabilities']
    order = sorted(names, key=lambda n: -probs.get(n, 0.0))
    gold = item['gold']
    return {
        'id': item['id'], 'gold': gold, 'choice': answer['choice'], 'confidence': answer['confidence'],
        'order': order, 'baseline_order': baseline,
        'baseline_top1': baseline[0] == gold, 'baseline_top3': gold in baseline[:3],
        'rerank_top1': order[0] == gold, 'rerank_top3': gold in order[:3],
        'gold_prob': probs.get(gold, 0.0),
        'usage': resp.get('usage', {}),
    }


def main_choice(*, root: Path | None = None, force: bool = False) -> None:
    root = root or workspace_root()
    guard_live(force, root)
    cards = pack_cards(root)
    items = json.loads((SCRATCH / 'eval_set.json').read_text())
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda it: score_query_choice(root, cards, it), items))
    n = len(results)
    b1 = sum(r['baseline_top1'] for r in results); b3 = sum(r['baseline_top3'] for r in results)
    r1 = sum(r['rerank_top1'] for r in results); r3 = sum(r['rerank_top3'] for r in results)
    tin = sum(r['usage'].get('input_tokens', 0) for r in results)
    tout = sum(r['usage'].get('output_tokens', 0) for r in results)
    print(f'CHOICE variant: n={n}')
    print(f'top-1  baseline {b1}/{n}  ->  choice {r1}/{n}')
    print(f'top-3  baseline {b3}/{n}  ->  choice {r3}/{n}')
    print(f'tokens: {tin} in / {tout} out (~${tin/1_000_000*42:.4f})')
    print()
    for r in results:
        flag = 'FIX' if r['rerank_top1'] and not r['baseline_top1'] else ('OK ' if r['rerank_top1'] else 'MISS')
        print(f"{flag} {r['id']} gold={r['gold']:<18} picked={str(r['choice']):<18} conf={r['confidence']:.2f} gold_p={r['gold_prob']:.2f} "
              f"baseline#1={r['baseline_order'][0]:<18} gold_rank={(r['order'].index(r['gold'])+1) if r['gold'] in r['order'] else '-'}")
    write_results(SCRATCH / 'results_choice.json', results, force=force)


def cli(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog='rerank_eval',
        description='Live TypeSafe triage-design evaluation (guarded: needs --force and an ALLOWED policy).')
    ap.add_argument('--force', action='store_true',
                    help='required: call the external API and replace the committed result artifacts')
    ap.add_argument('--root', default=None,
                    help='workspace root whose external_judgment policy and knowledge packs this run uses '
                         '(default: RESEARCH_OS_ROOT or this repo)')
    ap.add_argument('--variant', choices=('a', 'b'), default='b',
                    help='a = per-pack Noul rerank (historical, results.json), b = one Choice over all packs (shipped design, results_choice.json)')
    ns = ap.parse_args(argv)
    root = Path(ns.root) if ns.root else workspace_root()
    if ns.variant == 'a':
        main(root=root, force=ns.force)
    else:
        main_choice(root=root, force=ns.force)
    return 0


if __name__ == '__main__':
    raise SystemExit(cli())
