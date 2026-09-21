# Bug Bounty Research OS — Architecture

## The system has six layers

```text
1. CONTROL
   authorization, scope, identity, human gates

2. MODEL
   hosts, applications, endpoints, objects, workflows, trust boundaries

3. HYPOTHESIS
   observations, assumptions, attack ideas, competing explanations

4. EXECUTION
   cycles, workers, tools, evidence capture

5. VERIFICATION
   proof, adversarial review, negative validation, duplicate/novelty analysis

6. LEARNING
   corrections, program behavior, new techniques, research patterns
```

## Runtime context principle

The AI does not receive the entire repository for every turn.
The controller builds the smallest context that can answer the current question.

```text
stable contract
+ current state
+ current cycle
+ relevant evidence
+ relevant research
= model context
```

## Recommended topology

```text
                    CONTROLLER
                        │
        ┌───────────────┼────────────────┐
        ▼               ▼                ▼
     MAPPER          HUNTER           RESEARCHER
        │               │                │
        └───────────────┼────────────────┘
                        ▼
                    VERIFIER
                        │
                        ▼
                  STATE / EVIDENCE
                        │
                        ▼
                   NEXT CYCLE
```

The workers are not the source of truth. The control plane and registered evidence are.

## Canonical seam

`tools/control_plane.py` is the only lifecycle mutation seam. It owns state-machine legality, event sequencing, locking, evidence references, human-gate bookkeeping and projection rebuilds. `tools/researchctl.py` is the normal CLI entry point; `cycle.py` and `state.py` are compatibility adapters.

```text
MODEL
  ↓
CONTROL PLANE
  ├─ canonical event ledger (hash chained)
  ├─ cycle / hypothesis transitions
  ├─ evidence registry + SHA-256 identity
  ├─ live-action preflight
  └─ human-gate lifecycle
  ↓
REBUILDABLE PROJECTIONS
  ├─ run-status / active-cycle
  ├─ cycle plans / hypothesis views
  ├─ evidence index / gate views
  └─ current context / audit reports
```

A projection may be edited accidentally or damaged; correctness is restored by `refresh()` and verified by `tools/audit.py`. A projection is never allowed to mutate lifecycle truth.

## Three research portfolios

```text
CORE      = directly supported by observed architecture
ADJACENT  = created from second-order observations
FRONTIER  = novel/current-research hypotheses
```

The controller keeps these portfolios alive when the engagement is broad enough to support them.

## Why the architecture is modular

Rules change slowly.
Knowledge changes frequently.
State changes every cycle.
Research tasks expire quickly.

A single monolithic prompt forces all four into the same context budget.
The OS separates them so the model can reason with fresh, narrow information.
