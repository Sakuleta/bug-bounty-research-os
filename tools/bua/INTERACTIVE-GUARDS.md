# Write-capable BUA extension — executor guard requirements

Status: **in force**. The read-only runner (`run.mjs`) is still read-only
(navigate + screenshot + masked capture) and is still the default arm wired into the
executor; there is no click/fill/type/evaluate path in it. A write-capable task script
now exists BESIDE it — `tools/bua/interactive.mjs` — carrying its documented
precondition, its own guard suite (`tools/bua/interactive.test.mjs`) and the human gate
for consequential actions. `run.test.mjs` scans every `tools/bua/*.mjs` file: interaction
APIs in any file fail unless that guard suite exists and passes, and the read-only runner
itself stays interaction-free. Every requirement below is encoded in code and pinned by
the guard suite.

Adapted from the `browser-use/jev-ultrafast` executor discipline
(`INTEGRATION-RESEARCH.md` §4.4): *the model proposes an action; the executor decides
what that action actually is against the live DOM.*

## 1. Node identity is re-resolved at dispatch — never by the model

A model answer may name an element only as an opaque, run-scoped handle (an index into
a snapshot the executor produced). The executor must, at dispatch time, re-resolve that
handle against the live DOM and verify the node is the same node it showed the model:

- **freshness**: the handle's snapshot generation must still be current; a stale
  generation is re-snapshotted and the action re-planned, never dispatched on stale
  coordinates;
- **occlusion**: the node must be the actual hit target (elementFromPoint-style check);
  an element covered by an overlay is reported as blocked, not clicked through;
- **geometry**: the node's bounding box must be inside the viewport and unchanged
  beyond tolerance; scrolled-away or moved nodes fail the check.

## 2. Model output never becomes selectors, coordinates, shell, or JavaScript

- The model may never emit a CSS/XPath **selector**, a raw **coordinate** pair, a
  **shell** command, or **JavaScript** to evaluate; only typed operations over
  executor-issued handles (e.g. `CLICK(handle)`, `TYPE(handle, text)`). Model output
  must never become selectors, coordinates, shell, or JavaScript.
- Text values are the only free-form payload, bounded in length, and never personal
  data (the harness `TYPE_TEXT` rule: strict `{"text": ...}` JSON, ≤ 2000 chars).
- No `page.evaluate`, no `page.$eval`, no string interpolation into a script context.

## 3. Every write passes the existing gates, exactly once

- A single-use **preflight** token (`researchctl prepare`, `tool_family` "browser")
  bound to the exact `request_shape`; no token, no dispatch.
- The per-request **scope** route handler stays installed for the whole run; a write to
  an out-of-scope host is aborted and recorded, never followed.
- Page-initiated writes (a form the page submits, an XHR the page fires) are inside the
  same scope guard; runner-initiated writes need their own authorization model and
  their own capture + evidence registration, per action.

## 4. The read-only default stays the default

- The read-only runner remains the only arm wired into the executor
  (`dsh-plugin/index.js` spawns `tools/bua/run.mjs` and nothing else); the interactive
  task script is controller-driven and carries its documented precondition
  (`tools/bua/interactive.mjs` header: scope verdict, explicit workspace profile, a
  consumed single-use entry token, the per-action preflight template).
- `run.test.mjs` scans every `tools/bua/*.mjs` file for interaction APIs and fails when
  one appears in a file without the guard suite (`tools/bua/interactive.test.mjs`) — and
  it runs that suite, so "exists" is never enough; it must pass. `run.mjs` itself stays
  interaction-free. This doc is the checklist the suite encodes.

## 5. Failure is a first-class outcome

- `DONE` is never independent evidence of success: a completed write must be verified
  by a fresh observation (state re-read, capture registered as evidence) before it is
  reported as confirmed.
- `BLOCKED` is recorded with the failing guard (freshness/occlusion/geometry/scope),
  never retried blindly past the step cap.
