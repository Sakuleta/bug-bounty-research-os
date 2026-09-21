---
name: emerging
description: "Emerging behavior triage — fingerprinting an unfamiliar stack or version, mapping primitives to one observable, then promotion, novelty escalation, or non-applicable closure."
---

# Emerging & Unfamiliar Behavior Triage

An unfamiliar stack is a routing problem before it is a vulnerability: the invariant is that every unknown behavior ends with an owner — a dedicated pack, the dynamic technique engine, or a written non-applicable closure. Anchor each cycle on one observed behavior (header, response shape, timing, error text), pin the version, and map at most three primitives to target observables before external research drives any probing.

## Run this

1. **Fingerprint with two independent signals** — banners, headers, version strings, SDK markers, error shapes, documentation links. Done when two signals are recorded for the unfamiliar component.

2. **Pin the version and read that range only** — resolve the exact version or commit range, then check vendor advisories, changelogs, and current research for it. Done when every checked source carries a date.

3. **Map at most three primitives** — a parser, a boundary, or a state assumption — each to one observed target behavior with a one-line relevance argument. Done when each primitive has exactly one mapped behavior.

4. **Confirm the dedicated packs decline ownership** — browser, edge, api, parsers, auth, logic, mobile, cloud, supply-chain, and agentic checks run first. Done when the decline is recorded per pack.

5. **Run one benign differential per primitive** — case, encoding, ordering, or version-field variant from the researcher session. Done when per-hop handling is recorded for each variant.

6. **Validate the technique against the checklist** — fingerprint, current research links, preconditions, false positives, black-box observable, smallest safe proof, hypothesis in `03_hypotheses/`, record in `10_learning/`. Done when all eight steps are discharged.

7. **Promote or close** — a divergent oracle promotes to the owning pack or the dynamic engine with precondition plus oracle; convergence closes as non-applicable with neutralized-input evidence. Done when the cycle holds one of those two outcomes.

## Done when

- Every unfamiliar component has two independent fingerprint signals plus a version or commit range with dated sources.

- Each candidate primitive has one mapped observable, one benign differential, and its per-hop handling recorded.

- The cycle ends promoted (precondition plus oracle) or closed non-applicable with neutralized-input evidence, and the `10_learning/freshness.yaml` ledger entry is written.

## Stop conditions

- Destructive action, other-user effect, or production state change — halt, record, and report the triage boundary.

- A probe the version research flags as unsafe — halt and report the oracle boundary before sending it.

- A staged rollout or cohort flag in the suspected path — fix the flag, repeat, and report the result rather than claiming a new primitive.

- Version-string age without a version-matched primitive — close as non-applicable and report the mismatch.

## Depth

Field guides: `12_knowledge/emerging/emerging.md` — triage scope, research families, oracles, minimal safe proof, and false positives for unfamiliar stacks; `12_knowledge/novelty-research.md` — the 8-step per-technique validation checklist, source triage order, precondition/false-positive/oracle extraction, and the minimal proof template.
