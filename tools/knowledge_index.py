#!/usr/bin/env python3
"""Deep Knowledge index: single seam for parse + validate + rank + resolve.

Both tools/build_context.py and tools/validate_workspace.py are thin adapters
over this module. See 12_knowledge/README.md for the pack contract.
"""
import math
import os
import re
from pathlib import Path

DEFAULT_PACK_CAP = 4


def selection_query(root: Path, objective: str | None = None) -> str:
    """The ONE query the knowledge ranking runs on: the cycle objective first, then the
    same active-cycle / last-result / unknowns texts `build_context.py` renders.

    Both the agent-facing KNOWLEDGE_SELECTION block and the RUNNING triage-coverage
    guard consume this, so the guard demands exactly the set the context shows.
    Limits mirror the context projection so the two cannot rank different text."""
    parts = [objective or ""]
    for rel, limit in (("11_runtime/active-cycle.yaml", 2500),
                       ("11_runtime/last-result.md", 1800),
                       ("10_learning/unknowns.yaml", 1800)):
        try:
            parts.append((root / rel).read_text(errors="ignore")[:limit])
        except OSError:
            parts.append("")
    return "\n".join(p for p in parts if p)


def selection_cap() -> int:
    """The auto-selection cap both consumers apply: KNOWLEDGE_PACK_CAP env, default 4."""
    try:
        return max(1, int(os.getenv("KNOWLEDGE_PACK_CAP", DEFAULT_PACK_CAP)))
    except ValueError:
        return DEFAULT_PACK_CAP


def index_problem(root: Path) -> str | None:
    """Why 12_knowledge/INDEX.yaml cannot be parsed for ranking, or None when it is
    readable and holds at least one pack. Callers fail closed: without an index there
    is no auto-ranking and a coverage guard would pass vacuously."""
    idx = root / "12_knowledge" / "INDEX.yaml"
    if not idx.exists():
        return "12_knowledge/INDEX.yaml is missing"
    text = idx.read_text(errors="ignore")
    if "\t" in text or "packs:" not in text:
        return "12_knowledge/INDEX.yaml is unparseable (invalid YAML shape)"
    if not parse_index(idx):
        return "12_knowledge/INDEX.yaml is unparseable (no packs found)"
    return None


def parse_index(idx: Path):
    """Parse 12_knowledge/INDEX.yaml pack shape. Returns {pack: (load_when, files)}."""
    packs, cur = {}, None
    for line in idx.read_text(errors='ignore').splitlines():
        m = re.match(r'  ([\w-]+):\s*$', line)
        if m:
            cur = m.group(1)
            packs[cur] = ([], [])
        elif cur:
            m2 = re.match(r'    (load_when|files):\s*\[(.*)\]\s*$', line)
            if m2:
                vals = [v.strip().strip('"\'') for v in m2.group(2).split(',') if v.strip()]
                packs[cur][0 if m2.group(1) == 'load_when' else 1].extend(vals)
    return packs


def resolve_ref(root: Path, pack: str, ref: str):
    """Resolve an INDEX `files:` entry (incl. `../` cross-refs) under root.

    Returns the Path if it is a non-empty file inside root, else None."""
    cand = (root / '12_knowledge' / pack / ref).resolve()
    try:
        cand.relative_to(root.resolve())
    except ValueError:
        return None
    if cand.is_file():
        try:
            if cand.stat().st_size > 0:
                return cand
        except OSError:
            return None
    return None


def rank_packs(packs, query):
    """IDF-weighted keyword overlap, length-normalized. Returns
    [(score, name, files)] sorted by (-score, name). Deterministic."""
    query = query.lower()
    names = sorted(packs)
    doc_freq: dict = {}
    for name in names:
        for k in set(x.lower() for x in packs[name][0]):
            doc_freq[k] = doc_freq.get(k, 0) + 1
    scored = []
    for name in names:
        keywords, files = packs[name]
        if not keywords:
            continue
        weight = 0.0
        for k in keywords:
            if k.lower() in query:
                weight += math.log(len(names) / doc_freq[k.lower()]) + 1.0
        if weight:
            scored.append((weight / math.sqrt(len(keywords)), name, files))
    scored.sort(key=lambda t: (-t[0], t[1]))
    return scored


def top_packs(root: Path, query: str, k: int = 3):
    """One call per consumer: parse -> rank -> resolve (+ empty-pack fallback).

    Returns [(name, [resolved Paths])], at most k entries. Callers must not
    reimplement this ordering."""
    idx = root / '12_knowledge' / 'INDEX.yaml'
    packs = parse_index(idx) if idx.exists() else {}
    out = []
    for _, name, files in rank_packs(packs, query)[:k]:
        paths = [p for f in files if (p := resolve_ref(root, name, f)) is not None]
        if not paths:  # fallback: any md in pack dir
            for p in sorted((root / '12_knowledge' / name).glob('*.md')):
                paths.append(p)
                break
        if paths:
            out.append((name, paths))
    return out


def validate_index(root: Path):
    """Check INDEX.yaml <-> pack-directory consistency.

    Returns (errors, warnings). Missing/empty refs are errors; *.md files
    present but unreferenced are warnings (READMEs and cross-ref targets
    like novelty-research.md are legitimate orphans only at 12_knowledge/
    root — inside a pack dir every md must be referenced)."""
    errors, warnings = [], []
    idx = root / '12_knowledge' / 'INDEX.yaml'
    if not idx.exists():
        return ['12_knowledge/INDEX.yaml: missing'], warnings
    text = idx.read_text(errors='ignore')
    if '\t' in text or 'packs:' not in text:
        return ['12_knowledge/INDEX.yaml: invalid YAML shape'], warnings
    packs = parse_index(idx)
    if not packs:
        return ['12_knowledge/INDEX.yaml: no packs found'], warnings
    referenced: set = set()
    for pack, (_, files) in packs.items():
        for f in files:
            resolved = resolve_ref(root, pack, f)
            if resolved is None:
                errors.append(f'knowledge pack broken ref: 12_knowledge/{pack}/{f}')
            else:
                referenced.add(resolved)
    for pack in packs:
        d = root / '12_knowledge' / pack
        if not d.is_dir():
            continue
        for p in sorted(d.glob('*.md')):
            if p.resolve() not in {r.resolve() for r in referenced}:
                warnings.append(f'knowledge pack orphan md (unreferenced): {p.relative_to(root)}')
    return errors, warnings
