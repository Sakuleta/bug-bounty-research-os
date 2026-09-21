---
name: api-protocols
description: "API surface testing across representations — REST version drift, method and parameter precedence, GraphQL batching and authz gaps, gRPC metadata, SSE, gateway bypass."
---

# API / Protocol Research

One capability, many representations — v1/v2, REST/GraphQL, gateway/origin, web/mobile. The systematic bug is authorization applied unevenly across representations; hunt the pair that disagrees.

## Run this

1. **Inventory from shipped artifacts** — routes, versions, and parameter names out of JS bundles, mobile traffic, manifests, OpenAPI, error messages. Done when a representation table (capability × representation × observed authz) exists.
2. **Run pairwise differentials** — the same operation through both representations, two researcher-owned accounts, both responses recorded. Done when each candidate has a disagreement or a match on record.
3. **Confirm with read-back** — the victim-context account's view of the object is the evidence.
4. **GraphQL: depth 3, batch 2** — start small; stop at the first policy signal (error, throttle). Test mutation-vs-query and nested-field authorization against the REST equivalent, in both directions.
5. **gRPC: one stream, two messages** — metadata presence, casing, emptying; per-message authorization (act as A on an authorized stream, reference B's object mid-stream); close the stream right after the decision.
6. **Gateway bypass shape** — direct origin (IP, alternate host, port) or trusted client headers (`X-Original-URL`, `X-Forwarded-*`) changing routing or authorization; probe with a canary.
7. **Webhooks deliver to your collaborator** — observe delivery headers, secret inclusion, source IP.

## Done when

- Every candidate has both representations' responses recorded under two accounts.
- Each oracle class carries one negative control (random-path 404 control, clean-baseline request).
- The hop path tested (which gateway or proxy) is named per result.

## Stop conditions

Another user's data returned; a rate-limit or WAF intervention; a bypass path confirmed that would encourage scanning — halt and report the differential instead.

## Depth

Field guide: `12_knowledge/api-protocols/api.md` — families, oracle catalog, false positives, GraphQL/gRPC/SSE/gateway implementation notes.
