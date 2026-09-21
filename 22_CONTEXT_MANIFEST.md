# Context Manifest

`tools/build_context.py` is the context projection implementation. The event ledger/control plane remains the canonical lifecycle source; this file documents the context builder contract.

Budget: `CONTEXT_BUDGET` chars, default 10000. Pack cap: max 4, ranked by
`rank_packs` (IDF-weighted keyword overlap, length-normalized, ties by name).

Section order (fixed first, then cycle/evidence state, then tool/lab context, then knowledge):

```text
START.md (entry contract, 1800)
00_control/engagement.yaml (policy, 2200)
11_runtime/run-status.yaml (state, 1000)
10_learning/freshness.yaml (watchtower ledger, 1200)
11_runtime/active-cycle.yaml (objective, 1400)
04_cycles/<CURRENT>/* (objective/results/plan, 2200 each)
11_runtime/last-result.md (state, 1800)
10_learning/unknowns.yaml + assumptions.yaml (2700 combined)
03_hypotheses/active/* (active reasoning, 4400 combined)
11_runtime/tool-registry.yaml + lab-status.yaml (tool/lab, 2400 combined)
12_knowledge/<TOP-4-PACKS> (1800 each)
```

Greedy fit in that order; truncate at budget. Never attach the whole library.
Regenerate with `python3 tools/build_context.py <ROOT>`.
