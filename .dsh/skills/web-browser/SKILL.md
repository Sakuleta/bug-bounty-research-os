---
name: web-browser
description: "Browser-enforced behavior — XSS and mXSS, DOM clobbering, postMessage, Service Workers, CORS impact, XS-Leaks, CSS injection, open-redirect chains, modern CSRF and SameSite shapes."
---

# Browser Security

Attacker bytes reach a sink the browser executes, or a cross-origin difference the browser exposes. Trace the **sink first**, then source reachability; confirm with a canary, then escalate exactly one step: from "canary landed in an executable context" to one benign execution proof in your own session.

## Run this

1. **Map sinks before payloads** — enumerate `message` listeners, `innerHTML`/`document.write`/`eval`/`location` assignments, and SW registrations from shipped JS. Done when each sink has a source-reachability note.
2. **Canary in every context** — an inert unique token in attribute, JS-string, HTML, URL, and postMessage positions; observe the reflection context without executing.
3. **Escalate one step** — one confirmed context becomes one benign proof (custom event, collaborator fetch) inside your own session; stored payloads stay within your own views.
4. **mXSS needs the round-trip** — payload inert after the sanitizer but executable after one `<template>`/innerHTML re-serialization; verify per browser and record versions.
5. **XS-Leaks: 10+ samples plus a logged-out control** — a consistent cross-state difference (frame count, timing bucket, error-vs-load) with a control distribution.
6. **CORS counts with credentials and non-public data** — header reflection alone is inert; `null`-origin acceptance needs a practical null-origin primitive (sandboxed iframe, redirect).
7. **postMessage: record the branch, not the receipt** — attacker-origin iframe canary messages reach a dangerous sink (location write, HTML sink, privileged fetch) with no origin check; stop before state changes.

## Done when

- Every sink has its context, canary reflection, breakout attempts per context, and one escalation decision.
- Every XS-Leak candidate has 10+ samples, a logged-out control, and a named embedding primitive.
- Each oracle class carries one negative control from the false-positive list (framework auto-escape, origin allowlist, narrow SW scope).

## Stop conditions

A stored payload becomes visible to other accounts; an SW update affects other sessions; a CORS or XS-Leak proof touches another user's data. Halt and report the oracle using your own accounts only.

## Depth

Field guide: `12_knowledge/web-browser/browser.md` — families, oracle catalog, false-positive disambiguation, mXSS/CORB/Trusted-Types version notes.
