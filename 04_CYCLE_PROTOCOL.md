# Cycle Protocol — Deep Cycle Module

A cycle is the atomic unit of research. This file owns the cycle interface:
header shape, lifecycle, result packet contract, and adapter contract.
The canonical lifecycle state lives in `tools/control_plane.py`; cycle documents are projections and working artifacts.
State machine guards live in `28_CYCLE_STATE_MACHINE.md`; worker packet
fields live in `11_WORKER_PROTOCOL.md`; both are part of this module.

## Cycle header (canonical, see `schemas/cycle.yaml`)

```yaml
id: "C-0001"
type: "DISCOVERY|HYPOTHESIS|VALIDATION|AUDIT|RESEARCH"
objective: "<ONE QUESTION>"
primary_hypothesis: "H-0001"
priority_reason: "<WHY NOW>"
allowed_scope: []
accounts: []
knowledge_packs: []
preconditions: []
controls: []
stop_conditions: []
evidence_expected: []
status: "PLANNED"
```

## Adapter contract (`tools/cycle.py`)

```text
researchctl <ROOT> cycle create <CYCLE_ID> <PLAN_JSON>
cycle.py <ROOT> create <CYCLE_ID>              # PLANNED dir + header + templates
cycle.py <ROOT> begin <CYCLE_ID>               # sugar: PLANNED -> READY -> RUNNING
cycle.py <ROOT> submit <CYCLE_ID>              # sugar: RUNNING -> RESULT_READY
cycle.py <ROOT> transition <CYCLE_ID> <TO>     # guarded edge, exit 1 on violation
cycle.py <ROOT> update <CYCLE_ID> <PATCH_JSON>        # canonical plan update
cycle.py <ROOT> close <CYCLE_ID> <TERMINAL>    # RESULT_READY -> REVIEWED|FALSE_POSITIVE|NOT_APPLICABLE -> CLOSED
```

Code-enforced guards (all in `tools/control_plane.py`, the canonical seam; `tools/cycle.py` and `tools/researchctl.py` are thin adapters with no private enforcement): `READY` needs a usable objective + non-empty scope/stop conditions; `RUNNING` additionally needs `objective.md` (## Question + ## Minimal test) and per-pack `knowledge_triage` (USE/SKIP + reason); `RESULT_READY` needs `results.md` ## Disposition + registered E-* refs; terminal states need ## Interpretation (+ ## Instrument validation and both review axes for `REVIEWED`); back-edges `RESULT_READY -> RUNNING|BLOCKED` need at least one evidence ref; `CLOSED` needs ## New hypotheses + ## Next step + at least one `TECHNIQUE_EVALUATED` event for the cycle. Cycle `VERIFIED` is rejected with a pointer to `REVIEWED` (finding-level `VERIFIED` belongs to the hypothesis lifecycle). Lifecycle edges outside `28_CYCLE_STATE_MACHINE.md` are rejected. Canonical plan fields are updated through the control plane, not by editing `plan.yaml`. `tools/new_cycle.py` is a thin wrapper over `create`.

## Mandatory cycle questions

1. What exact security question are we answering?
2. What observation caused this question?
3. What is the strongest plausible secure behavior?
4. What is the strongest plausible vulnerable behavior?
5. What is the smallest test that distinguishes them?
6. What control proves the instrument works?
7. What side effect can occur?
8. What ends the cycle?
9. What evidence will be written?
10. What new branch could this result create?

## Cycle execution

```text
READ
→ FRAME
→ RESEARCH IF NEEDED
→ TEST
→ FALSIFY TEST
→ CLASSIFY RESULT
→ WRITE EVIDENCE
→ UPDATE STATE
→ GENERATE NEXT STEP
```

## Pivot rule

After repeated attempts that do not change the information state, stop repeating the same method and create a different hypothesis.

Do not confuse persistence with progress.

## Worked examples

- `25_MINIMUM_MODEL_OUTPUT.md`
