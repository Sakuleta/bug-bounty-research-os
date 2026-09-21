---
name: access-auth
description: "Authorization and identity testing — BOLA/BFLA, mass assignment, JWT/OAuth/SAML, MFA and recovery chains, session lifecycle, passwordless, cross-tenant boundaries."
---

# Authentication & Authorization

Every authorization bug answers one of three questions at one boundary: **does A reach B's object** (BOLA), **does A reach a higher function** (BFLA), **does the token or flow bind the wrong subject** (JWT/OAuth/SAML/session). Ask all three of every object and every role you hold. The proof is the **read-back**: the victim-context account's own view of the record.

## Run this

1. **Build the account matrix first** — unauthenticated, A, B, plus every higher role the program grants (premium, admin, collaborator, service). Done when a table of each principal and its observed access policy (UI and docs) is written down.
2. **Walk one object through every representation** — primary read, write methods, sub-resources, bulk, export/preview/download, versions, share/restore, history. Done when each representation has an observed result for B acting on A's object.
3. **Prove with read-back** — re-read the affected record as the victim-context account and compare against the pre-test baseline; the re-read is the evidence, a status code is a hint.
4. **Perturb exactly one token or flow element per request** — one header, one claim, one parameter — against a fresh valid baseline. Done when each validation step (signature, audience, issuer, expiry, binding) has one controlled perturbation and its response recorded.
5. **Walk recovery and lifecycle chains end-to-end** with researcher-owned mailboxes: reset, email change, MFA enrol/disable, linking, revoke.
6. **Test bulk endpoints item by item** — compare a multi-ID request against single-ID calls, looking for per-item authorization checked only on the first ID.

## Done when

- Every (principal × representation) cell has an observed, read-back-confirmed result.
- Every token and flow validation step has one recorded perturbation.
- Each oracle class carries one negative control (same request, valid context, clean result).

## Stop conditions

Third-party data returned; another account's email or phone changed; another user's session invalidated; MFA disabled; a bulk endpoint mass-mutated state. Halt, revert your researcher-side changes, report the differential.

## Depth

Field guide: `12_knowledge/access-auth/authentication-authorization.md` — research families, oracle catalog, false-positive disambiguation, JWT/OAuth/WebAuthn version notes.
