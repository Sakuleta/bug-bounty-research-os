# Worked example — shadow rehearsal (example.com)

What this is: one complete cycle of the OS against `example.com` (IANA-reserved,
harmless GETs), kept as the archival snapshot of the end-to-end chain:
scope check → preflight token → controlled executor → evidence → technique
evaluation → two independent reviews → seven closure audit classes.

Read in this order:

1. `11_runtime/events.jsonl` — the canonical ledger, 27 events, hash-chained
   (`event_hash`/`prev_hash`); every projection below is derived from it.
2. `04_cycles/C-0001/` — `objective.md`, `plan.yaml` (incl. `knowledge_triage`),
   `results.md`: projected cycle state.
3. `03_hypotheses/archive/H-0001.yaml` — the closed hypothesis with
   `test_question` / `test_plan` / `learning`.
4. `06_audits/closure-readiness.yaml` — the seven required audit classes, all
   PASS, each pointing at its `AUDIT_RECORDED` event id.
5. `11_runtime/current-context.md` — the smallest useful state, rebuilt by
   `tools/build_context.py` (never hand-edited).
6. `10_learning/` — `technique-discoveries.md`, `freshness.yaml`,
   `PROGRAM-KNOWLEDGE.md`, `unknowns.yaml`, `assumptions.yaml`, `corrections.md`.
7. `08_artifacts/raw/` and `11_runtime/evidence-store/` — the capture and its
   content-addressed copy (same sha256: `8310a964…`).

What it demonstrates: the full loop ran end to end on a harmless target; the
registered evidence is a byte-identical snapshot; audit classes carry evidence;
the cycle closed with a named learning instead of a claim.

What it does not demonstrate: a real program, real vulnerabilities, adversarial
conditions, or multi-cycle state. `06_audits/CLOSURE-PROOF.md` keeps its template
layout — the free-text closure proof was not written in this rehearsal.

State dirs that are empty in a live workspace (`01_intelligence/`,
`05_findings/`, `07_reports/`, `09_workers/`, `lab/`) hold no files and are
therefore absent from this snapshot.
