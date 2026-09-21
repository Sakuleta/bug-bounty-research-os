# Advanced Research Tradecraft

This file teaches the controller how to think about security research, not how to spray payloads.

## Boundary inversion
For every trust boundary ask both directions and then test alternate representations of the same identity or object.

## Invariant inversion
```text
INVARIANT
→ WHERE IS IT ENFORCED?
→ WHERE IS IT ASSUMED?
→ WHERE IS IT RE-IMPLEMENTED?
→ WHICH PATH BYPASSES THE ORIGINAL CHECK?
```

## Representation lattice
Treat one logical object as a family: list, detail, preview, export, search result, notification, cache entry, signed artifact, realtime event, mobile representation.

## State-time matrix
Cross security artifacts with ACTIVE / REVOKED / EXPIRED / ROTATED / DOWNGRADED / DELETED / RESTORED.

## Assumption attack
For every major component record developer, framework, infrastructure and client assumptions, then target mismatches between them.

## Second-order hunting
A verified weakness is also architectural evidence. Search for the same policy, serializer, middleware, object family, lifecycle and boundary elsewhere.

## Secure-behavior challenge
Ask why the system appears secure, what control made it secure, whether the control is centralized or duplicated, and whether every representation uses it.

## Oracle triangulation
Prefer independent observables: status, response shape, read-back, cache effect, timing, UI effect, audit event and second-account view.

## Frontier lane
Always keep a small branch asking what could be true that is not represented in the current model.

## Uncertainty-driven effort
Spend effort where uncertainty and security consequence overlap. Do not confuse persistence with progress.
