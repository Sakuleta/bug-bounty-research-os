# Hypothesis Engine

## Hypothesis states

New hypotheses start `CANDIDATE`. Terminal states are `VERIFIED`, `FALSE_POSITIVE`,
`NOT_APPLICABLE` and `CLOSED`; `SUPPORTED` is a live signal awaiting verification and
still counts as open. The legal transitions are the single source of truth in
`HYP_EDGES` (`tools/control_plane.py`) — ask `researchctl next` rather than trusting a
remembered flow.

## Hypothesis schema

```yaml
id: "H-0001"
surface: "<SURFACE>"
asset: "<ASSET>"
object: "<OBJECT_OR_NONE>"
class: "<CLASS>"
observation: "<FACT>"
hypothesis: "<CLAIM>"
secure_prediction: "<PREDICTION>"
vulnerable_prediction: "<PREDICTION>"
novelty_angle: "<ANGLE>"
duplicate_risk: "LOW|MEDIUM|HIGH|UNKNOWN"
information_gain: "LOW|MEDIUM|HIGH"
testability: "LOW|MEDIUM|HIGH"
side_effect_risk: "LOW|MEDIUM|HIGH"
priority: "LOW|MEDIUM|HIGH|URGENT"
status: "CANDIDATE"
test_question: "<QUESTION>"   # enforced: required before QUEUED
test_plan: "<PLAN>"           # enforced: required before TESTING
learning: "<LESSON>"          # enforced: required before CLOSED
precondition_absence: "<ABSENT_PRECONDITION>"  # enforced: required before NOT_APPLICABLE;
                                               # >= 20 chars and >= 3 words after stripping,
                                               # naming the absent version/config/protocol state
                                               # (placeholders like "n/a" or "TODO" are refused)
```

## Generation sources

Create hypotheses from:

- invariant violations
- state transitions
- alternate representations
- linked-object boundaries
- parser disagreements
- tenant / brand / role boundaries
- lifecycle artifacts
- implementation differences
- current public research
- unusual error or timing oracles
- client/server discrepancies
- cache and serialization boundaries
- cross-protocol translation
- tool-observed anomalies

## Quality filter

A good hypothesis predicts an observable difference.
A weak hypothesis is merely “this endpoint might be vulnerable”.
