# Closure Proof

Machine-emitted skeleton (`tools/audit.py --emit-proof`); the judgment sections below were filled from the ledger for this rehearsal. `python3 tools/audit.py examples/shadow-engagement --closure` passes.

Closure-Gate: G-0001 (reference: shadow-closure-review)

## SCOPE_PROOF

- gate: assets
- assets: ["example.com"]

## SURFACE_COVERAGE

One surface cell was exercised in this rehearsal: `GET https://example.com/` under
action `A-000001` (capture `E-000001`). No other path, method, header or parameter was
probed. The cell is terminal for the rehearsal: the cycle closed INCONCLUSIVE after a
single baseline request, so no coverage is claimed beyond the executor chain itself.

## AUTHORIZATION_COVERAGE

The request was anonymous (no `Cookie`/`Authorization` in the capture) from the
executor principal label `researcher-A`; `00_control/engagement.yaml` declares no
researcher-controlled accounts and no roles, and the rehearsal created none. The
principal label records the executor's `request_shape.principal`, not an authenticated
identity. No authenticated or cross-principal path was tested.

## WORKFLOW_COVERAGE

The workflow exercised was the OS chain: scope check → preflight token → controlled
executor → registered capture → technique evaluation → two review packets → seven
closure audit classes (`EV-000001`–`EV-000027`). The target's own behavior (raw vs
normalized cache-key variants) was not exercised: only the baseline request was sent.

## TECHNIQUE_COVERAGE

- T-000001: http-edge-differential -> INCONCLUSIVE

`T-000001` is the only technique evaluation and it is explicitly inconclusive: a single
GET cannot distinguish cache keys. No technique on this surface is marked CONFIRMED.

## NEGATIVE_EVIDENCE

There is no validated negative to report. `T-000001` (INCONCLUSIVE) states that the
variant pair was never sent, so nothing about cache-key behavior is proven — neither
positive nor negative. No negative-control claim is made.

## VERIFIED_FINDINGS

- H-0001: CLOSED

No hypothesis reached VERIFIED and no `05_findings/` record exists. `H-0001` closed with
learning: an edge cache-key differential needs the variant pair; a single GET cannot
decide it.

## FALSE_POSITIVES

None recorded. `H-0001` closed as NOT_APPLICABLE/CLOSED, not FALSE_POSITIVE, and no
control signature was needed because no "success" signal was claimed.

## BLOCKERS

No blocker prevented closure of this rehearsal. The variant-pair test was outside the
rehearsal's single-request budget and was recorded as INCONCLUSIVE plus a learning
rather than pursued to a claim; under a real authorization it would be an open branch,
not a closure blocker.

## NOVELTY_CHECK

Vacuous by construction: no finding is claimed, so no candidate was compared against
program history or public research. The rehearsal's only artifact is the executor
capture; nothing was offered as novel.

## DUPLICATE_CHECK

Vacuous by construction: no finding is claimed, so there is nothing to compare on root
cause, primitive, representation, direction or impact.

## STATE_INTEGRITY

- cycle C-0001: CLOSED
- coverage: PASS (EV-000022)
- hygiene-cleanup: PASS (EV-000026)
- method-self-attack: PASS (EV-000027)
- negative: PASS (EV-000023)
- novelty-duplicate: PASS (EV-000025)
- open-hypothesis: PASS (EV-000024)
- scope: PASS (EV-000021)

All projections rebuild from the hash-chained ledger (`11_runtime/events.jsonl`, 27
events). Cycle `C-0001` is CLOSED, hypothesis `H-0001` is CLOSED, and all seven audit
classes report PASS with current event ids. The audit reports legacy warnings for the
two pre-7.3 review packets and the pre-7.3 action, plus the advisory provenance note for
the scope block; those records predate the version stamp and are tolerated by design
(see the README).

## TOOL_LIMITATIONS

The controlled executor itself completed cleanly: exit 0, HTTP 200 read back from the
capture, no tool failure mislabelled as target behavior. The limitation was test design,
not instrumentation: one baseline request cannot distinguish raw from normalized cache
keys, and the rehearsal did not extend the executor to send the variant pair.

## HYGIENE

- E-000001: kind=raw path=08_artifacts/raw/A-000001-2026-09-21T17-50-54-684Z.http

Only `E-000001` is registered (`kind=raw`, the `.http` capture in `08_artifacts/raw/`);
its content-addressed store copy matches. The capture is an anonymous GET and carries no
credentials, cookies or PII; the audit's secret scan is clean and `lab/` holds no
credential files in this snapshot.

## CLEANUP

Nothing was provisioned to clean up: no lab credentials, no browser profile, no
temporary containers, no state-changing requests. `08_artifacts/sanitized/` and
`08_artifacts/screenshots/` are empty; the raw capture is retained only as the
registered rehearsal evidence.

## REMAINING_UNKNOWNS

`10_learning/unknowns.yaml` and `10_learning/assumptions.yaml` are empty projections.
The rehearsal's open question — whether raw and normalized paths share a cache key on
this edge — remains open and is recorded in `T-000001` / `H-0001` learning instead of as
a formal unknown. Closure is justified for this rehearsal because it claims nothing and
the executor chain is fully evidenced.

## FINAL_OPEN-HYPOTHESIS_AUDIT

`H-0001` is CLOSED with its learning recorded; no high-value legal hypothesis remains
open, matching the `open-hypothesis` audit PASS. No further legal next step is claimed
under this rehearsal's boundary.
