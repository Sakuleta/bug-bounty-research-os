---
name: web3-emerging
description: "Web3 authorization surfaces — wallet-to-session binding, transaction authorization stages, EIP-712 domain and replay checks, bridge verification, contract role reachability, and off-chain drift."
---

# Web3 / Emerging Protocol Surfaces

A web3 surface becomes a finding only as a broken authorization boundary on researcher accounts: the invariant is that a signed address, a transaction stage, a bridge event, or a contract role gates exactly the action the app trusts it to gate. Lead with the legitimate sign-then-execute baseline — what is signed, what is verified, where state changes — then move one field or one stage at a time.

## Run this

1. **Baseline the legitimate flow twice** — connect, sign, and execute with two researcher wallets, recording signed messages, domain fields, nonces, expiries, transaction hashes, and allow-versus-deny decisions. Done when both runs carry the full field set.

2. **Replay one researcher signature with one field changed** — chain ID, domain, nonce, or expiry, against the researcher session only. Done when each tested field has a result diffed against the baseline decision.

3. **Probe transaction-stage trust** — submit one researcher transaction and query app-gated benefits at the submitted and confirmed stages. Done when both stages carry an observed benefit decision.

4. **Check bridge acceptance** — emit one researcher source event and one fabricated source event, then compare destination-chain acceptance. Done when both events have a recorded destination result.

5. **Probe role reachability** — attempt one privileged app action from the unprivileged researcher wallet and one from the privileged researcher wallet, with the direct contract call as control. Done when app-side and contract-side results are both recorded.

6. **Diff the indexer against the chain** — compare the backend allowlist or balance with the on-chain read for the same researcher address at the same block height. Done when both reads and the governing decision are written down.

## Done when

- Every signature and transaction field (domain, chain ID, nonce, expiry, stage) has a baseline value and a single-variable result.

- Each oracle in play — binding, premature trust, domain reuse, nonce or expiry, bridge acceptance, role reachability, off-chain drift, sequencing — carries a decision flip on researcher accounts plus one negative control.

- Any halt-triggering observation is preserved as raw hashes and signed messages.

## Stop conditions

- Any other user's funds, assets, or access affected — halt, preserve hashes and messages, and report the boundary failure without further interaction.

- Mainnet value movement beyond researcher dust, or a bridge or contract pause triggered — halt and report.

- Another user's signature or transaction offered for replay — decline, substitute a researcher key, and report.

- Wallet UX confusion with no server or contract state change on researcher data — record as non-applicable, not a finding.

## Depth

Field guide: `12_knowledge/web3-emerging/emerging.md` — wallet, transaction, signature-domain, bridge, contract-role, and off-chain drift families with their oracles, minimal safe proof, false positives, and version notes; session and tenant binding is referenced from `12_knowledge/access-auth/authentication-authorization.md`.
