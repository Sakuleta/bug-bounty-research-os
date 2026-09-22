# Worked example — shadow rehearsal (example.com)

What this is: one complete cycle of the OS against `example.com` (IANA-reserved,
harmless GETs), kept as the archival snapshot of the end-to-end chain:
scope check → preflight token → controlled executor → evidence → technique
evaluation → two independent reviews → seven closure audit classes. The cycle
terminal is `REVIEWED` in the current machine (this snapshot predates the rename
and records the legacy `VERIFIED` transition, which the audit normalizes on read).

Read in this order:

1. `11_runtime/events.jsonl` — the canonical ledger, 36 events, hash-chained
   (`event_hash`/`prev_hash`); every projection below is derived from it. (27
   archival events plus the v8.2 closure-review gate pair `G-0001` and the
   re-recorded current audit declarations.)
2. `04_cycles/C-0001/` — `objective.md`, `plan.yaml` (incl. `knowledge_triage`),
   `results.md`: projected cycle state.
3. `03_hypotheses/archive/H-0001.yaml` — the closed hypothesis with
   `test_question` / `test_plan` / `learning`.
4. `06_audits/closure-readiness.yaml` — the seven required audit classes, all
   PASS, each pointing at its `AUDIT_RECORDED` event id.
5. `06_audits/CLOSURE-PROOF.md` — the filled, machine-checked closure proof:
   `python3 tools/audit.py examples/shadow-engagement --closure` exits 0 (the
   proof was emitted with `--emit-proof` and its judgment prompts completed from
   the ledger). The proof binds closure-review gate `G-0001` (`reference:
   shadow-closure-review`), resolved APPROVED — filler prose alone cannot close.
6. `11_runtime/current-context.md` — the smallest useful state, rebuilt by
   `tools/build_context.py` (never hand-edited).
7. `10_learning/` — `technique-discoveries.md`, `freshness.yaml`,
   `PROGRAM-KNOWLEDGE.md`, `unknowns.yaml`, `assumptions.yaml`, `corrections.md`.
8. `08_artifacts/raw/` and `11_runtime/evidence-store/` — the capture and its
   content-addressed copy (same sha256: `8310a964…`).

What it demonstrates: the full loop ran end to end on a harmless target; the
registered evidence is a byte-identical snapshot; audit classes carry evidence;
the closure proof passes the machine check; the cycle closed with a named learning
instead of a claim.

What it does not demonstrate: a real program, real vulnerabilities, adversarial
conditions, or multi-cycle state. The proof's coverage/novelty/duplicate sections
are honestly vacuous — no finding was claimed.

Legacy warnings are expected and legitimate: this ledger predates the v7.3
version stamp, so its events carry no `os_version`. The two archived review
packets lack `run_id`/`evidence_quotes`, and action `A-000001` lacks
`token_nonce`, so the audit reports them as legacy warnings instead of errors.
The snapshot also predates the budget governor, so its one recorded action
produces the `recorded actions exist (1) with no budget: block` warning. New
events on a 7.3 workspace are held to the full rules; re-recording reviews,
actions or audit declarations here would produce versioned records.

State dirs that are empty in a live workspace (`01_intelligence/`,
`05_findings/`, `07_reports/`, `09_workers/`, `lab/`) hold no files and are
therefore absent from this snapshot.
