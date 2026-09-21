---
name: business-logic
description: "Multi-step workflow and state testing — replay and skip, one-time action reuse, state resurrection, price and balance invariants, races and TOCTOU, account linking confusion."
---

# Business Logic & State

Every finding here is a **violated invariant** — write it down before testing ("coupon is single-use", "price is non-negative", "approval precedes activation", "refund requires return"). The bug is the state change that contradicts the invariant, and the proof is the **ledger read-back**: baseline → action → observed state, reconciled in both accounts.

## Run this

1. **Write the invariant and the forbidden transition first**, then record baseline state (balances, coupon status, order status) with timestamps. Done when the expected-vs-observed outcome is predictable in advance.
2. **Single-actor, minimum-value tests** — smallest denominations, researcher-owned instruments, one repetition beyond the allowed count.
3. **Replay once, race with two** — reuse the exact original request once for replay; start races with exactly 2 parallel requests and scale to 5/10 only if the 2-request signal is clean.
4. **Probe expiry with a just-expired researcher entitlement** (seconds past the window) before older states — it keeps clock-skew disputes off the finding.
5. **Reconcile in both accounts** — actor and counterparty read-back, expected vs observed, request/response pairs preserved.
6. **Clean up** — cancel test orders, void test coupons, unlink test identities, leave balances as close to baseline as the platform allows.

## Done when

- Every tested invariant has: written prediction, baseline capture, action, read-back in both accounts, ledger reconciliation.
- Every race candidate has a sequential control (2 sequential requests → one success) beside the 2-parallel result.
- Each oracle class carries one negative control from the false-positive list (server recalculates at charge time, second use rejected, dedupe holds).

## Stop conditions

Real funds move; third-party entitlements change; an irreversible terminal state is reached on a non-test record; rate-limit or fraud-control intervention. Halt, document, revert, report.

## Depth

Field guide: `12_knowledge/business-logic/state.md` — families, oracle catalog, false positives, race-synchronization and idempotency implementation notes.
