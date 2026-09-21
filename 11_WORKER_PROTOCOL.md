# Worker Protocol

Part of the Deep Cycle module (`04_CYCLE_PROTOCOL.md` owns the lifecycle;
this file owns the packet fields, unchanged).

Workers may be separate agent runs, processes, or human collaborators. The workflow does not assume multiple AI models or any specific model provider.

## Worker charter

A worker receives:

```text
CURRENT OBJECTIVE
SCOPE SLICE
RELEVANT STATE
RELEVANT EVIDENCE
RELEVANT KNOWLEDGE PACKS
EXPECTED OUTPUT FORMAT
```

Do not give every worker the entire repository by default.

## Result packet

```yaml
worker_id: "W-001"
cycle_id: "C-0001"
objective: "<QUESTION>"
work_performed: []
observations: []
hypotheses_supported: []
hypotheses_rejected: []
new_hypotheses: []
evidence_refs: []
limitations: []
state_changes_proposed: []
next_step: "<NEXT>"
confidence: "LOW|MEDIUM|HIGH"
```

## Review packets (claim gate)

A claim (a cycle heading to `VERIFIED`) is independently reviewed on two axes by two
separate worker packets — never merged, never reranked. Each packet carries the identity
of the reviewing run; the control plane refuses `VERIFIED` when the two axes share one
`reviewer` (and `tools/audit.py` re-checks the ledger), so independence is mechanical,
not a promise:

```yaml
review:
  axis: "objective"   # Does the result answer the cycle's question and meet its stop/acceptance conditions?
  verdict: "pass"     # pass | fail
  reviewer: "review-run-1"   # identity of this reviewing run; must differ from the other axis
```

```yaml
review:
  axis: "method"      # Instrument validated, positive/negative controls present, capture integrity
  verdict: "pass"
  reviewer: "review-run-2"
```

Record with `researchctl worker packet.json` (the packet still needs `cycle_id` +
`evidence_refs`). The **latest** verdict per axis is what counts: a `fail` blocks
`VERIFIED` until a later `pass` lands on the same axis. Dispatch the two reviews as
independent runs — ideally separate subagents — because agreement is not evidence.

## Canonical-state rule

Workers never rewrite canonical lifecycle state directly. They emit result packets; the orchestrator merges them through the control plane after validation.

## Independent challenge

At least one worker or pass should be allowed to disagree with the primary hypothesis.
Agreement is not evidence.

## When to delegate (controller rule)

The controller fans out — it does not do everything inline. Delegate when:

```text
(a) PARALLEL BRANCHES — two or more work items with no shared state
    (static mapping + web sweep + live probes proceed together)
(b) BACKGROUNDABLE LONG TASKS — builds, pulls, boots, sweeps, polls that run
    while the controller progresses elsewhere (never busy-poll; collect on notice)
(c) INDEPENDENT VERIFICATION — a VERIFIED claim gets a second pair of eyes tasked
    to break it, plus novelty pressure against public prior art
(d) SEPARABLE RESEARCH — web/API-doc sweeps detachable from live testing
```

Inline-by-default with no parallel branch is a smell, not a virtue. Worker packets
merge through the control plane after validation; workers never touch canonical state.
