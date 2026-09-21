# Runtime

`11_runtime/` contains current execution state.

Canonical runtime files:

```text
events.jsonl              # canonical hash-chained event ledger
action-tokens.jsonl       # transient single-use preflight tokens (consumed by the enforcer plugin)
tool-registry.yaml        # capability probe result
lab-status.yaml           # lab/provisioning reality; never a fake success state
```

Everything else under `11_runtime/` (`run-status.yaml`, `active-cycle.yaml`,
`current-context.md`, `evidence-index.jsonl`, `human-gates/`, `last-result.md`) and the
`10_learning/` projections (`technique-discoveries.md`, `freshness.yaml`) are rebuildable
views: their list and rebuild rules live in `10_STATE_MODEL.md` — never hand-edit them.
Canonical mutation entry point: `tools/researchctl.py`; deterministic audit: `tools/audit.py`.

Methodology index: novelty `17_DYNAMIC_TECHNIQUE_ENGINE.md`, freshness `31_FRESHNESS_WATCHTOWER.md`, agentic `32_AGENTIC_PARADIGM.md`, self-attack `33_METHOD_SELF_ATTACK.md`, guards `28_CYCLE_STATE_MACHINE.md`.

## Run status

```yaml
engagement_status: "BOOTSTRAP|ACTIVE|AUDIT|CLOSURE_CANDIDATE|CLOSED|BLOCKED"
current_cycle: "C-0001"
last_state_update: "<TIMESTAMP>"
last_audit: "<TIMESTAMP>"
open_high_value_hypotheses: 0
open_unknowns: 0
pending_human_gate: false
lab_ready: false
```

## Context assembly

Construct each model call from only what is needed:

```text
ENTRY CONTRACT
+ ENGAGEMENT POLICY
+ CURRENT OBJECTIVE
+ RELEVANT STATE
+ RELEVANT EVIDENCE
+ 1–3 RELEVANT KNOWLEDGE PACKS
+ REQUIRED TOOL / LAB CONTEXT
+ REQUIRED OUTPUT FORMAT
```

Never load the whole knowledge base merely because it exists.

## Autonomy invariant

The runtime must assume:

```text
THE AI IS RESPONSIBLE FOR ROUTINE TECHNICAL EXECUTION.
THE HUMAN IS A LAST-MILE INPUT / DECISION SOURCE.
```

The absence of a preconfigured emulator, browser profile, proxy, analyzer or package is a provisioning task, not automatically a human task.
