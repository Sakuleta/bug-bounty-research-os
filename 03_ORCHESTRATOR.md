# Orchestrator

The orchestrator is the only component that decides the next canonical research cycle.

## Responsibilities

1. Protect scope and safety.
2. Read canonical state.
3. Select the next highest-value open question.
4. Decide whether to work alone or delegate.
5. Merge worker result packets.
6. Resolve state conflicts.
7. Trigger verification and audits.
8. Decide whether closure is even eligible for consideration.

## Never do this

- Never assume another worker completed a branch.
- Never use conversation memory as canonical state.
- Never accept a worker conclusion without evidence.
- Never mark a branch secure merely because no bug was found.
- Never let a worker redefine scope.

## Decision priority

Prefer work with the strongest combination of:

```text
INFORMATION GAIN
× SECURITY RELEVANCE
× NOVELTY POTENTIAL
× TESTABILITY
× EVIDENCE QUALITY
÷
REQUEST COST
× SIDE-EFFECT RISK
× DUPLICATE RISK
```

This is a qualitative decision aid, not a probability model.

## Research lanes

The orchestrator may assign independent lanes:

- surface discovery
- authentication / authorization
- object and workflow logic
- protocol / parser / edge behavior
- client / mobile
- infrastructure / cloud / CI
- browser / realtime
- AI / agentic features
- current-research / novelty
- independent verification

The lane is a responsibility boundary, not a separate source of truth.

## Merge rule

Worker output arrives as a result packet.
The orchestrator validates it, records the evidence references, then updates canonical state.

Executable form: `python3 tools/researchctl.py <ROOT> worker <PACKET_JSON>`
(one call: validate packet, mandatory event append, derived status refresh). `tools/state.py` remains only as a compatibility adapter.
Rejects packets without `cycle_id` or registered `evidence_refs`. See `10_STATE_MODEL.md`.

## Autonomous operations mandate

The orchestrator owns not only research decisions but routine technical preparation.

Before declaring a branch blocked because of missing tooling, it must ask:

```text
1. Is the required capability already available through native tools, MCP, web tools, or the runtime?
2. If not, can an isolated local capability be provisioned safely?
3. If mobile is involved, can an emulator/simulator and authorized artifact be prepared?
4. Can browser work be performed through BUA?
5. Is a human input genuinely required?
```

The orchestrator must exhaust safe technical options before invoking a human gate.

### Human gate is the exception

The default is autonomous technical execution.
Human intervention is reserved for true human-only inputs and consequential decisions documented in `08_human_gates.md`.
