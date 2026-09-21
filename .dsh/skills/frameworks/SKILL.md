---
name: frameworks
description: "Web framework surface testing — Next.js, Nuxt, SvelteKit, Remix, Astro data routes and actions; Django, Rails, Spring, Laravel, Express debug, schema, actuator, manifest gaps."
---

# Frameworks

Framework testing asks whether a fingerprinted framework's **generated surface** — data route, action, middleware, proxy, actuator, manifest — makes a **different authorization decision** than the page the developer wrote.
Fingerprint from converging signals, work the **Next.js**, **Nuxt**, **SvelteKit**, **Remix**, **Astro**, **Django**, **Rails**, **Spring**, **Laravel**, and **Express** families against the router generation you actually observe, and treat deployment configuration as unknown until observed.

## Run this

1. **Fingerprint** — record two independent framework signals plus the observed version hint. Done when two independent signals agree on framework and version hint.

2. **Enumerate generated surfaces** — list data routes, manifests, schema and docs paths, and dashboard-shaped paths without fetching them yet. Done when the route list is derived from the live bundle rather than from memory.

3. **Baseline** — request the page and its data or action counterpart from owner, second-account, and anonymous sessions; record status, body hash, and redirect-versus-data behavior. Done when each (session × representation) cell has an observed result.

4. **Single-path bypass probe** — replay the data, action, or direct-API variant with exactly one variable changed (session removed, path rewritten, method swapped) and diff against baseline. Done when each probe differs from baseline by exactly one variable.

5. **Proxy and manifest read-only check** — request one manifest or proxy URL with a benign researcher-controlled target. Done when the response is classified as refused or as fetched researcher-collaborator bytes, with no pivoting.

6. **Debug-path read-only check** — request one suspected debug, schema, or actuator index without credentials and capture the redacted shape only. Done when no exposed operation was invoked.

7. **Method and content-type differential** — replay one route under an alternate method, override header, or parser that the documented path denies. Done when the outcome is recorded as denial-consistent or as a state change on researcher-owned objects only.

## Done when

- Every fingerprinted surface (page versus data route, page versus action, manifest, proxy, debug path, method variant) has a baseline and a one-variable diff.

- Two independent signals confirm framework and version before any behavior-specific conclusion.

- Each observed state change stays on researcher-owned objects, and every bypass candidate carries its consistent-denial control.

## Stop conditions

Stack trace with secrets, unrelated user record, state change outside researcher scope, or dashboard action surface.
Halt, preserve minimal evidence, clean up researcher artifacts, and report.

## Depth

Manifest + router: `12_knowledge/frameworks/frameworks.md` — scope, shared model, the family router, cross-cutting oracles, minimal safe proof, false-positive and version notes, plus companion pointers to browser, parsers, and edge-cache detail. Route to the fingerprinted family for depth: `js-nextjs.md`, `js-nuxt.md`, `js-sveltekit.md`, `js-remix.md`, `js-astro.md`, `backend-django.md`, `backend-rails.md`, `backend-spring.md`, `backend-laravel.md`, `backend-express.md` (each with its generated-surface map, router-generation/version exposure, oracles, false positives, and references).
