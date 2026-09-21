# Knowledge Library

These files are loaded by relevance, not all at once.

Single seam: `tools/knowledge_index.py` owns parse + validate + rank + resolve
for `INDEX.yaml`. Tools are thin adapters over it; do not re-parse the index
anywhere else.

A deep knowledge pack uses 7 sections:

1. Research families (when to load)
2. Preconditions (architectural conditions that must hold)
3. Oracles (black-box observables distinguishing vuln vs secure)
4. Minimal safe proof (smallest reversible test + stop conditions)
5. False positives (benign explanations + how to rule out)
6. Version/implementation notes (where behavior differs)
7. References (named sources, no fake URLs)

## Skills layer (DSH)

Each pack also ships a skill at `.dsh/skills/<pack>/SKILL.md` (model-invoked). The skill is
the entry point the agent reaches on its own: trigger-rich description, the operational
ladder, checkable completion criteria, stop conditions — and a pointer back into the pack
file here for depth (oracles, false positives, version notes). The skill carries the
process; this library carries the evidence. Written per `writing-for-agents`
(mattpocock/skills): descriptions are always-loaded pointers, so they front-load the
leading word and list one trigger per branch.
