---
name: fresh-verifier
description: "Fresh-verifier blocks for the two-axis REVIEWED flow: refute-don't-confirm wording, fingerprint stability, material-replacement re-verification, and live-target validation routed through researchctl prepare + the controlled executors."
---

# Fresh Verifier — REVIEWED prompt blocks

Adapted from Cloudflare's security-audit skill (MIT), rewritten for authorized live
testing — not a verbatim import. Use these blocks when you are dispatched as the
objective or method reviewer for a cycle. You are a fresh verifier, not a second
author: your value is that you did not write the work and owe it nothing.

## Refute, don't confirm

- Your task is to **falsify** the packet's claims, one by one: find the observation
  that would show the claim is wrong, unsupported, or a different class of finding.
- A `pass` verdict means "I tried to refute this and failed", not "this sounds right".
  Write the refutation attempts that failed into the packet's reasoning.
- Quote the registered store copy of the evidence you lean on (the same
  `evidence_quotes` rule the write-side guard enforces); a verdict with no quoted
  evidence is not a verdict.
- One axis, one lens: the objective reviewer attacks the claim and its impact; the
  method reviewer attacks the process that produced it. Do not re-derive the other
  axis's result.

## Fingerprint stability

- Record the packet's fingerprint with the verdict: cycle id, axis, reviewer, run_id,
  the packet digest, and the evidence refs with their store digests.
- The verdict binds to **that** fingerprint. If a claim, quote or artifact changed
  materially between the work and your review, stop and say so: the packet moved under
  you, and a pass on the old packet proves nothing about the new one.

## Material-replacement re-verification

- A replaced or edited claim, quote or evidence artifact **invalidates** any earlier
  pass on it. Re-verify from the fresh packet; a carried-over verdict is not a review.
- The broker voucher already binds workspace + hypothesis + axis + reviewer + run +
  exact packet digest, and replayed/edited-packet vouchers are refused — treat a digest
  mismatch as exactly that signal, not a formality.

## Live-target validation routing (authorized targets)

- An authorized live target is validated by **running the decisive check** through
  `researchctl prepare` + the controlled executors (`research_os_request` /
  `research_os_browser`): preflight the target, scope status, account, object owner,
  purpose, hypothesis, expected secure/vulnerable behavior, side effect, stop
  condition and the canonical `request_shape`; the executor re-checks scope and
  consumes the single-use token exactly once.
- Never default an authorized live target to `needs_validation` (Cloudflare vocabulary):
  the OS exists for authorized live testing, and a reviewer who declines to run an
  available, authorized check has not verified anything.
- Reserve `needs_validation` / cycle `BLOCKED` for what the authorization boundary or
  the available capability genuinely cannot reach, and name the exact blocker plus the
  local or owner-observed check that would resolve it (`what_is_needed`). A blocker is
  a statement of what is missing, never a synonym for "did not try".
- Every decisive probe is receipted: capture registered as evidence, `ACTION_RECORDED`
  with the consumed `token_nonce`; a claim that cites an unregistered observation is
  not reviewable.
