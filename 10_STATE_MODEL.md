# State Model — Deep State Module

Single seam: `tools/control_plane.py`. `tools/researchctl.py` is the normal caller; `tools/cycle.py` and `tools/state.py` are compatibility adapters. Every material lifecycle mutation is represented by an event.

## Canonical state

The event ledger is the canonical mutable lifecycle history:

```text
11_runtime/events.jsonl
```

The following are rebuildable projections or research artifacts:

```text
run-status.yaml
active-cycle.yaml
04_cycles/*/plan.yaml
03_hypotheses/{active,archive}/*.yaml
11_runtime/evidence-index.jsonl
11_runtime/human-gates/*.yaml
11_runtime/current-context.md
10_learning/freshness.yaml
10_learning/technique-discoveries.md
11_runtime/last-result.md
06_audits/closure-readiness.yaml
```

Lifecycle status and closure-readiness declarations must never be edited directly in those projection files. Use the control plane.

## Event integrity

Each event has a sequential ID plus `prev_hash` and `event_hash`. The chain makes accidental reorder, deletion or in-place mutation detectable. Writes use an atomic lock, append-only file mode and `fsync`.

## Update semantics

Plans and hypotheses have explicit `CYCLE_UPDATED` / `HYPOTHESIS_UPDATED` events. This prevents the false choice between editable documents and immutable state: reasoning data may evolve, but every evolution is recorded.

## Evidence identity

Evidence is an object, not a path string. A registered evidence object contains `E-*` identity, relative path, kind, source, byte count and SHA-256, plus a content-addressed copy under `11_runtime/evidence-store/<sha256>` — the registered artifact. Consumers reference the object ID; audits verify the stored copy still matches (and flag legacy records without one).

## Technique evaluation

A technique outcome is a canonical event, not a Markdown chore:

```text
python3 tools/researchctl.py <ROOT> technique evaluate payload.json
```

Payload: `technique_family`, `result` (`CONFIRMED|FALSE_POSITIVE|NOT_APPLICABLE|INCONCLUSIVE|NEGATIVE`), `interpretation`, `learning`, `evidence_refs`; optional `target_surface`, `preconditions`, `expected_oracle`, `negative_control`, `next_hypothesis`. The control plane allocates the `T-*` id. `10_learning/technique-discoveries.md` and `11_runtime/last-result.md` are rebuilt from these events, and a cycle cannot reach `CLOSED` without at least one evaluation. Free-text learning notes are not the mechanism; the event is.

## Live-action preflight tokens

`researchctl prepare payload.json` issues a single-use token binding one preflight to one
live action: `action_id`, `nonce`, `expires_at`, `tool_family`, `argument_digest`
(canonical SHA-256 over `request_shape`), cycle and hypothesis. The DSH enforcer plugin
consumes the token when the matching tool call arrives; the controlled executor records
`ACTION_RECORDED` after the call. Tokens live in the transient store
`11_runtime/action-tokens.jsonl`, never the ledger — a recorded preflight alone cannot
authorize thirty follow-up actions. When `00_control/engagement.yaml` carries a non-empty
`assets` list (simple host/URL strings), `prepare` refuses any target whose host is outside
it (`*.domain` wildcards allowed); an assets block that is not a simple string list fails
closed as unenforceable.

## Unknowns ledger

Maintain `10_learning/unknowns.yaml`.
An unknown is valuable state, not a failure.
Each unknown should say:

```yaml
id: "U-0001"
question: "<UNKNOWN>"
why_it_matters: "<IMPACT>"
possible_resolution: []
blocked_by: "<IF_ANY>"
status: "OPEN|BLOCKED|RESOLVED"
```

## Assumption ledger

Maintain `10_learning/assumptions.yaml`.
Every assumption that could alter a security conclusion should be recorded and either verified or retired.

## Canonical-state rule

The append-only event ledger is the only canonical mutable lifecycle history. `plan.yaml`, active/archive hypothesis files, run status, evidence index and human-gate files are projections. They may be regenerated from the ledger; lifecycle mutations must not bypass `tools/control_plane.py`.

Every evidence ID is a registered object with a content hash. Every human gate is resumable state without storing the human-only secret itself.
