---
name: data-layer
description: "Data-layer record exposure through search, pagination, aggregation, and export surfaces; ORM scoping leaks, nested traversal, raw-query and NoSQL operators, resolver and cache mismatches."
---

# Data Layer

A record the second account cannot see must stay invisible through **every representation** of the same data: list, search, facet, total count, export, and resolver. Every probe is one **single-variable** change against a recorded **baseline**, and the second-account **canary** in the returned bytes is what makes it a finding.

## Run this

1. **Seed canaries and baseline first** — one record per researcher account with unique canary strings; record list, search, count, and export responses per account. Done when every account has a written baseline of row sets, totals, and facet buckets.

2. **Probe one parameter at a time** — operator, sort key, null versus absent, array versus scalar — and diff row sets and totals against that baseline. Done when each changed parameter has its own recorded differential.

3. **Cross-check resolvers and representations** — request the same records through REST and GraphQL paths, and through list versus export, from both sessions. Done when each representation has an observed authorization decision for the hidden record.

4. **Attribute aggregation deltas to your own canary** — record counts and facet buckets before and after creating one hidden canary record, then attribute only the canary-driven delta.

5. **Re-check after revocation** — downgrade or revoke access on one researcher record, then re-request list, aggregate, and export from the downgraded session and a clean session. Done when both post-change responses are recorded.

6. **Confirm the oracle with hidden-record bytes** — a count shift or reordering is a hint; the second-account canary present in returned rows is the proof.

## Done when

- Every (representation × session) cell has a recorded response diffed against baseline.

- Every hidden-record claim carries second-account canary bytes, not a status or total change.

- Every changed parameter, resolver pair, and revocation event has its own single-variable record.

## Stop conditions

- A non-researcher record, production table name, or stack trace with secrets appears — halt, record the oracle, and report the class without enumerating or extracting rows.

- A probe brings heavy-query slowdown or scan pressure — stop at the signal, record the oracle, and report the differential instead of pulling rows.

- An export or aggregation returns third-party data — halt immediately, discard the artifact, and report the class of oracle only.

## Depth

Field guide: `12_knowledge/data-layer/data.md` — research families, oracle catalog, false-positive disambiguation, and ORM, NoSQL, GraphQL, and cache version notes.
