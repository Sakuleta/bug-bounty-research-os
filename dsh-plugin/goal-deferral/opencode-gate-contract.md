# OpenCode goal-plugin pre-continuation gate — normative patch contract

**Status: specification only.** This repo does not fork the upstream plugin, never patches
`~/.npm` or the OpenCode package cache, and does not vendor upstream code. The fork/PR
happens in the upstream MIT repo (`prevalentWare/opencode-goal-plugin`); this document is
the normative text that change must implement, plus the executable block/allow matrix
(`gate.matrix.test.mjs`) that pins the semantics against a local harness seam.

## Target

- Plugin: `@prevalentware/opencode-goal-plugin`, V2 path (`setupV2`).
- Pinned sources: **v0.1.45** (the locally cached bundle; `dist/server.js` — in-memory
  `TaskTracker`, `session.status` busy/idle gate, no transcript hydration) and
  **v0.1.50** (upstream `src/server.ts` at commit
  `300044954cb41cd91dda85fb916343766b3a458a`; `timeoutMillisecondsFromSeconds` L276,
  `taskBlockExpired` L541, option wiring L1106 — transcript recovery, `0` = no ceiling).
- Insertion point: the V2 pre-continuation gate — `taskBlockStatus` as consulted by
  `runAutoContinue`, immediately before a continuation is reserved and delivered. That
  gate must additionally consult the shared work-lease registry.

## Semantics (normative)

1. **Blockers are additive.** A continuation may be sent only when BOTH (a) no tracked
   Task blocks (the existing rule, unchanged) AND (b) no work lease for the run is held.
   Neither condition may substitute for the other.

2. **Lease verdict.** The gate reads the shared registry (`<run root>/.leases/<run>.jsonl`,
   format and verdict rules owned by `tools/leases.py`; the dependency-free reader is
   `dsh-plugin/goal-deferral/index.js:readLeaseVerdict`). It **blocks** on:
   `active`, `awaiting-reconciliation`, `unknown-recovery-required`, an expired `active`
   lease, a missing or unreadable registry, a corrupt line, and an unverifiable version
   chain. It **allows** on: `released` (reconciled, commit recorded) and `no-lease`
   (a readable registry with no record for this run).

3. **No Task-success shortcut.** A terminal Task — even one the parent assistant message
   reconciled — is not process exit, not output reconciliation and not a commit
   acknowledgement. It must never release the lease block, and it must never authorize a
   continuation while a lease is held. This is the incident this contract exists for: a
   detached measurement process outlived its Task session, and the gate continued anyway.

4. **Reconcile-then-recheck.** On any blocker-state transition the gate re-reads the
   registry (subscribe-then-reread against the monotonic record version — never a cached
   verdict, never a delta) and rechecks the complete predicate. A transition to clear must
   re-run the full predicate before the continuation is reserved; there is no
   "clear once, continue later" path.

5. **Sole emitter.** The OpenCode plugin is the single continuation emitter for a run.
   The DSH layer is veto-only (`dsh-plugin/goal-deferral/`): it may block on its own
   signals but never emits a competing continuation for the same run. Both layers read the
   same registry; neither pauses or resumes the other's durable goal state.

6. **Timeouts do not release leases.** `max_task_block_seconds: 0` means *no ceiling*
   (v0.1.50 `timeoutMillisecondsFromSeconds(0) === null`), not "disable deferral"; and a
   task-block timeout never expires a lease block. A lease is released only by
   `researchctl lease-reconcile <run>` after the completion predicate clears.

7. **Activation boundary, fail closed inside it.** A run is lease-managed when the plugin
   is configured with its root (`RESEARCH_OS_LEASE_ROOT`, or a run id via
   `RESEARCH_OS_LEASE_RUN`) or discovers an ancestor directory containing `.leases/`.
   Inside a lease-managed run, an unreadable or missing registry blocks (never clear). A
   workspace that is not lease-managed is not deferred — otherwise every OpenCode session
   outside the battery workflow would deadlock.

8. **Stale is never success.** An expired lease reads as `unknown-recovery-required`,
   wakes exactly one bounded reconciliation turn (`researchctl lease-reconcile`, one
   attempt per transition), and is never reported as completed work.

## Patch shape (reference, not code to copy)

```text
taskBlockStatus(tracker, ...)            # existing Task fold
  + leaseBlockStatus(root, runId)        # new: readLeaseVerdict(...).blocked
runAutoContinue(...)
  before reserving a continuation:
    if taskBlockStatus(...).blocked -> defer (existing behavior)
    if leaseBlockStatus(...).blocked -> defer (new; reason names the state and the run)
    else -> reserve and send the continuation (sole emitter)
```

Both `blocked` reads must happen in the same serialized `runAutoContinue` pass (the
existing serialization is what makes "exactly one continuation" hold); the lease read is
cheap (one small JSONL file) and happens at idle/round boundaries, not per token.

## Out of scope here

- Applying the patch (fork/PR in the upstream repo; nothing under `~/.npm` or the
  OpenCode cache is touched by this repo).
- Upstream DSH `goal-round-driver` readiness-hook changes: the adapter in
  `dsh-plugin/goal-deferral/` owns the predicate and its integration coverage; the
  driver hook belongs upstream or in a deliberately maintained local overlay.

## Executable matrix

`gate.matrix.test.mjs` mirrors the gate's inputs (a tracked-Task fold plus the real
registry reader) and asserts the block/allow matrix, including the no-Task-success
shortcut and the timeout rules. It is dependency-free and runs with
`node dsh-plugin/goal-deferral/gate.matrix.test.mjs`.
