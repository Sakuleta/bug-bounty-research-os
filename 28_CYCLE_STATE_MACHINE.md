# Cycle State Machine

Enforced by `tools/control_plane.py`, the canonical seam; `tools/cycle.py` and `tools/researchctl.py` are thin adapters (see `04_CYCLE_PROTOCOL.md` for the module doc).

```text
PLANNED
  ↓
READY
  ↓
RUNNING
  ├──→ HUMAN_GATE
  ├──→ BLOCKED
  ├──→ NEEDS_PIVOT
  └──→ RESULT_READY
           ↓
   REVIEWED | FALSE_POSITIVE | NOT_APPLICABLE
           ↓
         CLOSED
```

Cycle `VERIFIED` was renamed to `REVIEWED` in v7.3: `REVIEWED` means both review axes
pass and the instrument validation section is filled. `VERIFIED` is the
hypothesis/finding state (impact reproduced + clean negative control), not a cycle
state; `tools/control_plane.py` rejects a cycle transition to `VERIFIED` with a pointer
to `REVIEWED`, and archived ledgers that recorded the old transition are normalized on
read.

A cycle cannot become CLOSED solely because an endpoint returned a denial. Evidence, branch disposition and state update are required.

## Transition guards

| FROM -> TO | Guard | Who | Evidence required |
|---|---|---|---|
| PLANNED -> READY | research question + allowed scope + stop conditions defined | agent | plan update / scope proof |
| READY -> RUNNING | question + minimal safe test prepared, preconditions checked, `knowledge_triage` recorded (USE/SKIP per pack) | agent | objective.md Question+Minimal test filled + triage in plan |
| RUNNING -> HUMAN_GATE | action crosses auth, data, or irreversibility boundary | agent | pending-action description |
| HUMAN_GATE -> RUNNING | explicit human decision allows resume | human | approval/provisioning reference |
| RUNNING -> BLOCKED | progress impossible (scope wall, tool gap, rate limit) | agent | blocker + attempted alternatives |
| BLOCKED -> READY | blocker cleared or pivot hypothesis filed | agent/human | unblock/pivot evidence required |
| RUNNING -> NEEDS_PIVOT | oracle disproved, adjacent branch viable | agent | negative result + pivot target |
| NEEDS_PIVOT -> READY | new hypothesis filed | agent | new hypothesis ID |
| RUNNING -> RESULT_READY | oracle observed, positive or negative | agent | raw request/response pair |
| RESULT_READY -> REVIEWED | both review axes pass + instrument validation filled | agent | review packets (objective + method: run_id + evidence quotes) + results.md Instrument validation |
| RESULT_READY -> FALSE_POSITIVE | negative control shows same effect | agent | control evidence |
| RESULT_READY -> NOT_APPLICABLE | precondition proven absent on target | agent | fingerprint proof |
| RESULT_READY -> RUNNING/BLOCKED | back-edge: the result state missed something (follow-up work or a blocker) | agent | ≥1 evidence ref naming what was missed |
| REVIEWED/FALSE_POSITIVE/NOT_APPLICABLE -> CLOSED | learning recorded, state updated | agent | ≥1 TECHNIQUE_EVALUATED event + results.md New hypotheses/Next step |

Forbidden: RUNNING -> CLOSED (must pass through RESULT_READY), BLOCKED -> CLOSED (must exit via protocol below), any cycle -> VERIFIED (use REVIEWED; VERIFIED is the hypothesis/finding state), a REVIEWED terminal without passing reviews on both axes.

## NEEDS_PIVOT rules

Pivot only on oracle failure with a named adjacent branch (sibling endpoint, alternate encoding, downgraded protocol, second principal). Carry over the negative result as the pivot's baseline. Max two pivots per hypothesis before filing a fresh hypothesis — endless pivoting is thrash, not coverage. [PROCEDURAL — counted by discipline, not by a tool.]

## BLOCKED exit protocol

1. Record blocker, timestamp, and every attempted alternative.
2. If a human can clear it (scope question, credential, approval): route to HUMAN_GATE, do not idle in BLOCKED.
3. If research can clear it: file pivot hypothesis, move NEEDS_PIVOT -> READY.
4. If neither: record learning, close branch as NOT_APPLICABLE with reason. BLOCKED is never a terminal state.

## HUMAN_GATE entry / exit

- Entry: any step that touches other users' data, writes persistent state, bypasses auth, spends money/quota, or is irreversible. Agent halts and posts the exact pending action.
- Exit: only on explicit recorded human approval (reference + conditions). Denial routes to NEEDS_PIVOT or graceful close, never silent retry.

## Terminal criteria

- REVIEWED: both review axes pass (independent reviewer + run_id + evidence quotes bound to the registered capture) and `results.md` ## Instrument validation is filled. The claim is reviewed; the impact-level criteria (impact reproduced twice or once + independent second oracle AND negative control clean) are the **hypothesis VERIFIED** criteria recorded through the hypothesis lifecycle, and they feed `05_findings/`.
- FALSE_POSITIVE: control run reproduces the "success" signal without the cause. Record signature to avoid re-testing.
- NOT_APPLICABLE: architectural precondition absent (version, config, protocol state). Cite fingerprint evidence, and record the absent precondition in the hypothesis's `precondition_absence` field — it must satisfy the audit-summary sentence rule (>= 20 characters and >= 3 words after stripping, naming the absent version/config/protocol state), so `n/a`, `none`, `x`, `TODO` and `<...>` are refused as placeholders. Budget/instrument stops are BLOCKED, not NOT_APPLICABLE.
- CLOSED: one terminal disposition is complete, ≥1 `TECHNIQUE_EVALUATED` event exists for the cycle, learning/next-step state is recorded, and integrity audits are clean. `plan.yaml` remains a projection.

## Walkthrough

H-14 (dangling suffix): PLANNED -> READY (oracle: second-response reflection) -> RUNNING (fresh-connection control first) -> RESULT_READY (reflection seen) -> REVIEWED (repeat + clean control + both review axes) -> CLOSED (learning entry L-09). If control also reflects: -> FALSE_POSITIVE with echo signature. If no keep-alive reuse exists: -> NOT_APPLICABLE with header evidence.
