# Research Workflow

## Phase 0 — Bootstrap

Create the engagement directory, load policy, identity references and runtime controls.

Outputs:

- engagement configuration
- policy snapshot
- scope map
- run status

## Phase 1 — Intelligence

Collect the smallest useful set of facts:

- in-scope hosts and applications
- exposed entry points
- client surfaces
- authentication model
- obvious trust boundaries
- technologies and versions where safely observable
- program history and disclosure signals

Do not turn intelligence gathering into unfocused enumeration.

## Phase 2 — Architecture Model

Build:

```text
HOST GRAPH
APPLICATION GRAPH
ENDPOINT GRAPH
OBJECT GRAPH
AUTHORIZATION GRAPH
WORKFLOW GRAPH
TRUST-BOUNDARY GRAPH
DATA-FLOW GRAPH
```

Record uncertainty explicitly.

## Phase 3 — Hypothesis Generation

Generate hypotheses from:

1. observed architecture,
2. violated or suspicious invariants,
3. cross-surface inconsistencies,
4. lifecycle behavior,
5. current research,
6. known framework/protocol primitives,
7. unusual errors and state changes,
8. gaps in the current coverage matrix.

## Phase 4 — Hunt Cycles

Each cycle contains one primary question and at most a small number of tightly related tests.

A cycle should maximize information gain while minimizing side effects.

## Phase 5 — Verification

Interesting behavior is not yet a finding.
Reproduce from a clean baseline, prove the security boundary crossing, and verify the instrument.

## Phase 6 — Adversarial Review

A separate review pass must try to falsify:

- the finding,
- the impact,
- the root cause,
- the novelty claim,
- the duplicate assessment,
- and the negative conclusion if no finding exists.

## Phase 7 — Reporting

Prepare a concise, reproducible, evidence-backed report. Submission remains human-gated.

## Phase 8 — Closure

Run:

```text
STATE AUDIT
COVERAGE AUDIT
NEGATIVE-EVIDENCE AUDIT
NOVELTY / DUPLICATE AUDIT
HYGIENE AUDIT
OPEN-HYPOTHESIS AUDIT
CAPABILITY / TOOL LIMITATION AUDIT
```

Then create the closure proof.

## Phase 9 — Institutional Learning

After the engagement, preserve:

- verified architecture facts
- program-specific acceptance patterns
- false-positive lessons
- unusual primitives
- novel techniques discovered
- triage calibration
- reusable research heuristics

Do not store secrets.
