---
name: supply-chain
description: "Supply chain and CI-CD testing — dependency confusion, lockfile integrity, fork-build trust, webhook verification, artifact provenance, build secrets, runner cache poisoning."
---

# Supply Chain / CI-CD

Supply chain and CI-CD testing asks one question of every in-scope pipeline asset: can a researcher-controlled contribution reach a **protected secret, branch, artifact, or environment** that the legitimate release flow keeps closed? Work the **dependency confusion**, **lockfile integrity**, **build trigger trust**, **webhook verification**, and **artifact provenance** families, plus **build-secret residue**, **IaC state** exposure, and **runner-cache poisoning**, from a recorded baseline — treating every secret-shaped string as a lead until it yields an authorization oracle on researcher-owned scope.

## Run this

1. **Baseline first** — record the legitimate dependency resolution, build trigger matrix, approval chain, and artifact digest for a researcher-owned change. Done when each has a recorded secure-baseline value.

2. **Confusion check, read-only** — publish a canary under a researcher-owned namespace only, and infer feed priority from resolver output and error text. Done when the resolver's chosen source and error text are recorded, with no private package name claimed in a public feed.

3. **Trigger matrix** — open one fork PR and one branch PR with one variable changed; record which steps execute, which secrets are masked, and which writes are attempted. Done when both PRs carry a step list and every protected-write attempt is aborted on the spot.

4. **Webhook replay** — capture one legitimate delivery to a researcher endpoint, then replay it once unsigned and once with an expired timestamp. Done when accept-versus-reject is recorded for both replays against the signature-plus-timestamp-plus-nonce baseline.

5. **Provenance check** — pull the artifact by tag across two authorized builds and compare digests plus signature presence. Done when mutable-tag drift is recorded without overwriting anything.

6. **Build-secret residue** — inspect image layers, build cache, and logs from a researcher build for secret-shaped values. Done when each hit is classified as fixture placeholder or live-format value validated against researcher scope.

7. **IaC state and plan** — read state or plan output and compare the secrets and resource addresses it exposes against the authorized reader set. Done when disclosure to an unauthorized researcher session is either observed or ruled out.

## Done when

- Every family tested (confusion, lockfile, trigger, webhook, provenance, residue, IaC) carries an observed result diffed against the recorded baseline.

- Every oracle candidate names its secure-baseline counterpart — the flow that does enforce.

- Every secret-shaped string resolves to fixture data or to a researcher-scope-validated live value.

## Stop conditions

Production artifact overwrite, real secret disclosure, cross-tenant pipeline effect, or protected-branch write. Halt, preserve the oracle output, clean up researcher artifacts, and report without further interaction.

## Depth

Field guide: `12_knowledge/supply-chain/supply-chain.md` — research families, preconditions, oracle catalog, false-positive disambiguation, and per-ecosystem registry, CI-platform, provenance, container-builder, and IaC-backend version notes.
