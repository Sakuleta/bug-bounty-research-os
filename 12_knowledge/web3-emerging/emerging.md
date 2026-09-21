# Web3 / Emerging Protocol Surfaces

> SCOPE: Load only when a wallet, transaction, bridge, or contract-mediated authorization path is explicitly in scope; on-chain curiosity alone is not a finding — a broken authorization boundary on researcher accounts is.

## Research families

- Wallet and account binding (address to session, session to tenant, disconnect semantics)
- Transaction authorization state (pending, signed, submitted, confirmed, reverted — what the app trusts at each stage)
- Signature domain separation (EIP-712 domain, chain ID, nonce, expiry, replay across domains)
- Cross-chain and cross-domain replay (same signature honored in two contexts)
- Bridge and messenger verification (source-chain event to destination-chain action)
- Smart-contract role boundaries (owner, minter, pauser, upgrader reached via app flows)
- Off-chain versus on-chain authorization mismatches (backend allows what the contract denies and vice versa)
- Price, oracle, and sequencing assumptions exposed through app endpoints
- New protocol parsers (address, transaction, metadata decoding differentials)
- Consensus-adjacent implementation issues only where the app is the trust consumer
- Off-chain signature standards: `permit` / `eth_signTypedData` approval paths vs `approve`
- Smart-account and delegation surfaces (ERC-4337 user operations, EIP-7702 delegated accounts)
- Contract wallets and multisig signature validation (ERC-1271 `isValidSignature`)
- Signature-malleability acceptance (non-canonical `s`/`v`) that bypasses a "used" check
- Relayer/bundler trust (a submitted `UserOperation`/`permit` is not the same trust level as an on-chain check)
- Backend indexer finality assumptions feeding app-gated benefits
- Wallet-connection library variance (wagmi / ethers / web3.js) changing what is actually signed
- L2/sequencer-specific finality or blob assumptions the app trusts
- On-chain event signature / ABI drift between the indexer and the contract
- Sign-in session origin binding (EIP-4361 SIWE `domain`/`uri`/`nonce` fields versus the origin that actually requested the signature)
- Standing vs one-shot signed approvals (ERC-2612 and Permit2 `AllowanceTransfer` vs Permit2 `SignatureTransfer` and ERC-3009)
- Permit2 witness payloads (arbitrary extra data bound to the signature by a witness hash and EIP-712 witness type string)
- Counterfactual / predeploy account signatures (ERC-6492 wrapper) and the verifier's check ordering
- Meta-transaction forwarder trust (ERC-2771 `_msgSender()` extraction, `isTrustedForwarder`)
- RPC endpoint trust (provider-executed `eth_call`/`eth_getLogs` versus pinned-block or proof-verified reads)
- Signing-UI integrity (compromised front-end resources replacing the transaction the signer believes they approved)

## Preconditions

- The wallet, contract, or bridge flow under test is in scope with researcher-controlled accounts and test assets only.
- Baseline of the legitimate sign-then-execute flow (what is signed, what is verified, where state changes) before claiming a binding gap.
- Every signature test uses researcher keys and researcher sessions; never replay another user's signature or transaction.
- Bridge and oracle hypotheses tied to an observed verifier, relayer, or backend check — not a speculative chain.
- Server or contract state change on researcher data required; wallet UX confusion alone never becomes a finding in this pack.
- For signature-replay claims: the exact `EIP712Domain` struct used by the deployment is captured (name, version, chainId, verifyingContract, salt) — a missing `chainId` is the precondition for cross-chain replay.
- For `permit`-style claims: whether the token implements ERC-2612 (or a `dai`-style variant) and whether the app's flow depends on the signed approval being single-use.
- For smart-account claims: the account's validation entry point is identified (`validateUserOp` for ERC-4337, `isValidSignature` for ERC-1271, or an EIP-7702 delegate) before testing it.
- For malleability claims: the verifier is reachable with a raw `r,s,v` payload (not only a wallet UI) so a non-canonical `s` can be supplied.
- For relayer/bundler claims: the off-chain validation path (simulation, sponsorship) is distinct from the on-chain `msg.sender`-gated path.
- For `verifyingContract` claims: the domain struct is captured and the verifying contract is confirmed to be the one actually checking the signature.
- For EIP-191 claims: the exact version byte a verifier hashes is compared against the byte the signer produced.
- For SIWE-shaped logins: the full field set (`domain`, `uri`, `version`, `chain-id`, `nonce`, `issued-at`, optional `expiration-time`/`not-before`/`request-id`/`resources`) and which of those the backend actually validates on this path.
- For Permit2 claims: which module is in play (`AllowanceTransfer` standing permit vs `SignatureTransfer` one-time transfer), the witness type string if a witness is used, and the nonce model (packed per owner/token/spender vs unordered bitmap).
- For ERC-3009 claims: whether the token exposes `transferWithAuthorization`/`receiveWithAuthorization` and whether the app's wrap checks `to == address(this)` and caller identity.
- For ERC-6492 claims: whether the verifier implements the wrapper order (6492 suffix check, then ERC-1271 when contract code exists, then `ecrecover` last) before treating an accepted signature as authorization.
- For forwarder claims (ERC-2771): the recipient's `isTrustedForwarder` set and whether membership is mutable or upgradeable; a malicious or upgradeable forwarder can forge `_msgSender()`.
- For RPC/provider claims: which block tag the app reads (`latest` vs `safe` vs `finalized`), whether reads are pinned by block hash (EIP-1898), and whether any read is verified against a proof rather than trusted from the provider.
- For off-chain drift claims: the app decision, the provider's `eth_call` result, and the on-chain state at the same block height are captured together, with the provider endpoint identified.

## Oracles

- Binding gap: signed address A operates on account or tenant B, or a disconnected wallet session still executes privileged researcher actions.
- Premature-trust differential: app treats a submitted or pending transaction as confirmed and unlocks a researcher benefit the confirmed-only baseline withholds.
- Domain-reuse confirmation: signature minted for domain or chain X is accepted in domain or chain Y without re-signing.
- Nonce or expiry bypass: replayed researcher signature executes twice, or an expired signature executes after its stated deadline.
- Bridge-acceptance gap: destination action executes for a researcher payload the source chain never emitted or already reverted.
- Role-reachability signal: researcher account invokes an owner or minter function through the app where the direct contract call and the documented flow both deny.
- Off-chain drift: backend allowlist or balance differs from the on-chain read for the same researcher address at the same block height, and the backend decision governs.
- Sequencing inversion: reordered researcher transactions within one block or batch produce a different privileged outcome than the documented order.
- Approval-path gap: a signed `permit` / `eth_signTypedData` approval is accepted by the backend or another contract for a `spender`, `value`, or `deadline` the signer did not intend.
- Signature-validator divergence: an ERC-1271 account (or 4337 account) accepts a signature that a plain `ecrecover` check would reject — or vice versa — and the two paths gate the same privileged action.
- Delegate-hijack signal: an EIP-7702 delegated account executes an initialization or authorization path that was not bound to the signer.
- Malleability replay: a second, differently-encoded signature (flipped `v`, `s` outside the lower half-order) recovers the same signer and is accepted where a canonical signature was already consumed.
- Nonce-channel confusion: an ERC-4337 operation signed under one nonce `key` is accepted (or rejected) inconsistently versus the sequential expectation — the 192-bit key / 64-bit sequence split is mis-scoped.
- Envelope confusion: a signature is accepted by a verifier that hashes a different EIP-191 version byte than the signer used, so the recovered principal is not the intended one.
- `verifyingContract` binding gap: an ERC-2612 `permit` valid for contract X is accepted by contract Y because the domain omitted `verifyingContract`.
- Origin-binding gap: a SIWE message whose `domain`/`uri` does not match the requesting origin is still accepted (wallet signs it, or backend provisions a session) — the phishing precondition.
- Permit2 standing-permit gap: an `AllowanceTransfer` permit signed for a one-off swap is later consumed repeatedly for a different spender/token while within `expiration`.
- Witness confusion: a Permit2 `permitWitnessTransferFrom` signature is accepted for a witness object whose type string or value differs from what the signer approved.
- Unordered-nonce reuse: a `SignatureTransfer` nonce is accepted twice, or a bitmap nonce is marked spent for a different signer/domain.
- 6492 ordering inversion: a verifier that checks `ecrecover` before ERC-1271 accepts a predeploy/account signature for an EOA principal, or vice versa.
- Forwarder spoofing: a recipient that reads the last 20 bytes of calldata without checking `isTrustedForwarder` accepts an attacker-appended address as `_msgSender()`.
- RPC divergence: the app's provider returns an `eth_call`/`eth_getLogs` result that a second independent provider (or an `eth_getProof` verification at the same pinned block hash) contradicts, and the app acts on the first result.
- Confirmation-tag abuse: the same log/read is visible under `latest` but absent under `finalized` (or marked `removed: true` after a reorg), yet the app used the non-final view for a security decision.
- Signing-UI substitution: the payload the signer reviewed (displayed values) differs from the bytes actually signed/submitted (e.g. Safe `operation`/`delegatecall` payload), with both the display artifact and the raw transaction captured.

Oracle → what actually proves a crossing:

| Oracle | Evidence to capture |
|---|---|
| Domain replay | same `r,s,v` accepted with a different `chainId`/`verifyingContract`; record both domain structs |
| Permit abuse | `allowance[owner][attacker]` changed to a value the signer never authorized; record tx + event |
| ERC-1271 divergence | the magic value `0x1626ba7e` returned for a signature the app treats as privileged |
| 6492 wrapper | signature ending in the 32-byte `0x6492…6492` suffix accepted from a counterfactual account, with verifier order recorded |
| Permit2 witness | `permitWitnessTransferFrom` calldata with a witness type string/value the signer did not approve, plus the resulting `transferFrom` |
| SIWE origin | signed message with `domain`/`uri` ≠ requesting origin, plus the backend session issued |
| Premature trust | benefit unlocked while the tx hash is still pending/unconfirmed, with block number at decision time |
| Role reach | privileged function selectors executed from an unprivileged researcher wallet, with calldata |
| Malleability | two distinct signatures recovered to one signer, both accepted for the same one-time action |
| Forwarder spoof | calldata with a 20-byte sender suffix accepted by a recipient whose `isTrustedForwarder(msg.sender)` is false |
| RPC lie | second provider / `eth_getProof` disagree with the first at a pinned block hash; both responses retained |

## Minimal safe proof

1. Baseline: complete the legitimate connect, sign, and execute flow twice with two researcher wallets; record messages signed, domain fields, nonces, expiries, transaction hashes, and allow versus deny decisions.
2. Single-variable replay: replay one researcher signature with one field changed (chain ID, domain, nonce, expiry) against the researcher session only; diff against the baseline decision.
3. State-stage check: submit one researcher transaction and probe app-gated benefits at submitted versus confirmed stages; record which stage the app trusts.
4. Bridge check: emit one researcher source event and one fabricated source event; compare destination-chain acceptance — halt on any destination execution of the fabricated event and report the oracle.
5. Role probe: attempt one privileged app action from the unprivileged researcher wallet and one from the privileged researcher wallet; compare — never touch another user's assets.
6. Signature-standard probe: for a `permit`/1271/4337 surface, replay the canonical test vector with one domain or nonce field changed and diff `ecrecover` vs the account's `isValidSignature`/`validateUserOp` result.
7. SIWE/origin probe: request a sign-in with a message whose `domain`/`uri` differs from the requesting origin (researcher session only); record whether wallet and backend each accept, and whether a session is issued.
8. Read-path probe: take one app decision that depends on an RPC read, then re-issue the same read pinned to a block hash with a second provider and compare; for a storage read, verify with `eth_getProof` against the block's state root rather than trusting `eth_call` alone.
9. Stop conditions: any other user's funds, assets, or access affected, any mainnet value movement beyond researcher dust, any bridge or contract pause triggered — halt, preserve hashes and messages, and report the boundary failure without further interaction.

## False positives

- Wallet address visible to any visitor — public identifier by design; require cross-account action, not address display.
- Transaction pending display before confirmation — UX optimism; require the app to unlock a benefit before confirmation, not merely display pending state.
- Signature valid in two test domains that intentionally share a domain separator — documented composability; require acceptance beyond the documented domain set.
- Reverted transaction still visible in history — expected transparency; require a state change that survives the revert.
- Contract role function reverting with an authorization error — the control working; require successful execution or an app-side bypass of the revert.
- Off-chain cache lagging the chain by a few blocks — expected indexing delay; require a security decision made on stale data with a demonstrable privilege effect.
- Testnet token value movement — valueless by design; findings need mainnet-equivalent authorization logic, demonstrated on researcher scope.
- Address-checksum or casing variation accepted — encoding tolerance; require a different account or privilege, not a formatting acceptance.
- `permit` is front-run by another party but produces the same signer-intended effect — the EIP itself states the end result is the same for the signer; require a *different* spender/value/effect.
- `ecrecover` returning the zero address on a malformed signature where the contract also checks `owner != address(0)` — the guard is present; require the missing check to enable an effective approval.
- Backend indexer confirmation lag with no privilege consequence — expected finality behavior; require a decision differential.
- A delegated EIP-7702 account re-running its initializer where the implementation correctly rejects the second call — the guard held; require a state change on the re-run.
- A validator `query` that expires a signature earlier than `deadline` but never later than it — the deadline is an upper bound; require execution past the stated deadline.
- An EOA signature rejected by an ERC-1271 verifier because that account is not the signer — correct principal separation; require the account's own validator to return the magic value.
- Two chains that intentionally share a `chainId`-less domain separator for a documented cross-chain flow — require acceptance outside the documented domain set.
- An envelope mismatch that simply fails signature recovery — a rejected signature is the control working; require one that is *accepted* for the wrong principal.
- SIWE `port`/`scheme` defaulting differences (implicit `https:`, implicit 443) — the spec treats port mismatch as a warning, not a rejection; require a genuinely different host/domain accepted.
- Permit2 `AllowanceTransfer` nonces that differ because the nonce is packed per owner/token/spender — expected model; require reuse of the identical nonce with identical token and spender.
- A provider returning `null` or dropping a log after a reorg — expected cleanup; require the app to have granted or withheld a privilege from the removed view.
- `eth_call` succeeding in simulation but reverting at inclusion because state changed between the two — TOCTOU in the app's read path; benign unless the app treats the simulation result as committed authorization.
- A Permit2 `SignatureTransfer` signature that reverts because the nonce bitmap entry was already spent — single-use enforcement working; require double-spend or cross-signer acceptance.
- A contract wallet whose `isValidSignature` reads mutable state (owner rotation, key revocation) — ERC-1271 is explicitly allowed to be state-dependent; require the app to keep the stale session/privilege after revocation.
- A Wormhole VAA valid on several chains — multicast is the documented default; require an application action the VAA does not bind (missing destination app/chain check), not mere cross-chain authenticity.
- A bridge message replaying after a legitimate reorg on an unfinalized source block — expected until the configured finality level; require replay after the source reached the level the protocol defines.

## Version/implementation notes

### EIP-712 mechanics and what a verifier must check

- **EIP-712** is the typed-data scheme the rest of the ecosystem builds on. The signed digest is `keccak256("\x19\x01" ‖ domainSeparator ‖ hashStruct(message))`, which is ERC-191-compliant with version byte `0x01`; a plain-bytestring message instead uses the `"\x19Ethereum Signed Message:\n" ‖ len ‖ message` form. The `EIP712Domain` struct carries a subset of `name`, `version`, `chainId`, `verifyingContract`, `salt` in that order (absent fields skipped).
- `hashStruct(s) = keccak256(typeHash ‖ encodeData(s))` with `typeHash = keccak256(encodeType(typeOf(s)))`; `encodeType` is `Name(type member,...)` with referenced structs appended sorted by name, and `encodeData` is each member encoded 32 bytes wide (dynamic `bytes`/`string` as their keccak256, arrays as the hash of concatenated elements, nested structs as `hashStruct`). `domainSeparator = hashStruct(eip712Domain)`.
- `chainId` is what makes a signature non-portable across chains; the EIP itself says the user-agent *should* refuse signing when `chainId` does not match the active chain — a wallet that does not enforce this is the gadget for a cross-chain replay.
- EIP-712 explicitly **does not** include replay protection: "make sure the application behaves correctly when it sees the same signed message twice" is the implementer's job (reject or be idempotent), and front-running of a broadcast signature is likewise out of scope. Those two sentences are the basis of the replay and premature-trust oracles.
- The RPC surface to fingerprint is `eth_signTypedData` (and `personal_signTypedData`); the returned signature is a 65-byte `r‖s‖v` where `v` encodes the EIP-155 chain id. Compare what the wallet *displays* against the raw `TypedData` JSON — the display is not the commitment.
- Field order and version: `EIP712Domain` fields are emitted in the fixed order above, absent fields skipped, and future additions must come after them alphabetically; `version` is the signing-domain version, so a dApp that bumps `version` from `1` to `2` invalidates every previously signed digest rather than repurposing it.
- **ERC-5267** adds `eip712Domain()` discovery: a `fields` bitmap (bit `i` set means domain field `i` present, indexed in EIP-712 order), the values `name`/`version`/`chainId`/`verifyingContract`/`salt`, and an `extensions` list of EIP numbers. Contract authors MAY change the domain, but SHOULD do so rarely, SHOULD track the EIP-155 `chainId` of the underlying chain, and MAY emit `EIP712DomainChanged`. The spec's own security note: a contract can declare a `verifyingContract` other than itself and a `chainId` other than the current chain, so an integrator must validate those against the contract and chain it actually intends to sign for.
- Signature encodings differ: **ERC-2098** packs `yParity` into the top bit of `s` as a 64-byte `(r, yParityAndS)` value, relying on the canonical-`s` constraint that keeps the top bit zero. A verifier or parser that assumes 65-byte `r‖s‖v` and a 64-byte compact form is the same object can mis-slice calldata; `v`/`yParity` normalization (27/28 vs 0/1) is likewise a per-implementation choice.
- **EIP-155** is the transaction-level analog: the signing payload becomes `(nonce, gasprice, startgas, to, value, data, chainId, 0, 0)` and `v = {0,1} + CHAIN_ID * 2 + 35`, while legacy `v = 27/28` signatures remain valid recoverable inputs. Hand-rolled verifiers over transaction-like payloads that ignore `chainId` reproduce pre-EIP-155 replay across a chain split.

### Off-chain signing RPC surface and wallet display

- `eth_signTypedData_v4` is the recommended typed-data method; it carries the full domain (including `verifyingContract`) so the wallet can render and bind the request. Older `v1` shapes and raw `eth_sign` do not provide the same binding guarantees — MetaMask documents `eth_sign` as deprecated (MIP-3) and recommends `personal_sign` (ERC-191 prefixed) only for off-chain authentication-style messages.
- `personal_sign` prepends `\x19Ethereum Signed Message:\n<length>` before hashing; an app that verifies `personal_sign` output while the user signed EIP-712 typed data (or vice versa) is comparing across envelopes — the recovered signer differs or the check silently fails.
- MetaMask's own guidance for `personal_sign` challenges matches the pack's oracle: include the domain or a timestamp in the challenge text so a phisher cannot reuse the same challenge string; a challenge with no origin/expiry binding is an origin-binding gap candidate.
- What the wallet displays is a rendering of the typed data, not a cryptographic commitment: user-visible fields (top-level struct name, `domain.name`, member names) are part of the security interface, and any contract that derives authorization from fields it does not display invites a display/substance mismatch.

### ERC-2612 `permit` — the most exposed off-chain approval path

- `permit(owner, spender, value, deadline, v, r, s)` sets `allowance[owner][spender] = value`, increments `nonces[owner]`, and emits `Approval`, **iff** `block.timestamp <= deadline`, `owner != address(0)`, `nonces[owner]` equals the signed `nonce`, and `(r,s,v)` is a valid secp256k1 signature over the EIP-712 `Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)` struct. The caller of `permit` can be **any address**, so the signer is decoupled from the submitter.
- The domain separator is the ACL: the EIP requires it "should be unique to the contract and chain to prevent replay attacks from other domains". Two live misconfigurations are worth probing — a `DOMAIN_SEPARATOR` computed once at deployment (replayable across a chain split) versus reconstructed per-signature with the current `chainId`.
- Security notes that become oracles: `ecrecover` **fails silently and returns the zero address** on malformed input, hence the `owner != address(0)` requirement (without it, `permit` can create an approval over "zombie funds" owned by `0x0`); `deadline = uint(-1)` creates a never-expiring permit; the standard ERC-20 approve race condition (SWC-114) applies.
- The `dai`-style variant differs: a `bool allowed` (0 or `uint(-1)`) instead of `value`, and `expiry` instead of `deadline` — so the signed struct differs and a copy-pasted verifier that expects one shape can accept the wrong struct.
- Relayer economics are an oracle too: the submitting party holds a free option to submit or withhold, and the signer can render a pending permit invalid by submitting it themselves — "signed but never used" is expected behavior, not a bug.

### Permit2 — standing and one-time signed approvals for any ERC-20

- Permit2 is a singleton union of `AllowanceTransfer` (standing, time-bound allowance) and `SignatureTransfer` (one-time, transaction-scoped transfer). Deployed at the same address on every supported chain except zkSync: `0x000000000022D473030F116dDEE9F6B43aC78BA3`; on zkSync `0x0000000000225e31D15943971F47aD3022F714Fa`. Same `verifyingContract` across chains means `chainId` is the only domain field separating chains — a Permit2-domain replay is a `chainId` bug by construction.
- Nonce models differ and are the primary oracle differentiator. `AllowanceTransfer` packs an incrementing nonce per owner/token/spender next to amount and `expiration`; two permits with the same nonce do not cancel each other when the token or spender differs. `SignatureTransfer` uses unordered bitmap nonces, each single-use, order-independent.
- Both modules carry a signature deadline; `AllowanceTransfer` allowances additionally carry their own `expiration`. Approvals can be batch-revoked, and expiring approvals are revocable by expiry rather than a transaction.
- Witness support: integrations may bind arbitrary extra data via a witness hash and witness type string, and "the type string must follow the EIP-712 standard" — the classic failure is a witness type string that does not exactly match the struct the integrator hashes, so the signature's meaning diverges from the displayed intent.
- Integration risk to keep in frame: using Permit2 requires a one-time ERC-20 approval of the Permit2 contract itself, commonly `type(uint256).max` of every token the user touches — the standing exposure is concentrated in one contract address, not the dApp.

### ERC-3009 — transfer authorizations with an in-band validity window

- `transferWithAuthorization(from,to,value,validAfter,validBefore,bytes32 nonce,...)` moves tokens on a signed EIP-712 authorization with a random 32-byte nonce, an explicit validity window, `AuthorizationUsed` event, and an optional `cancelAuthorization`.
- `receiveWithAuthorization` adds a caller-equals-`to` check to stop mempool front-running of a wrapper contract that expected to receive the tokens first; a wrapper that decodes and forwards a `transferWithAuthorization` for its own benefit is the documented antipattern.
- The spec recommends including both `verifyingContract` and `chainId` in the domain; its security section restates the zero-address `ecrecover` hazard. The random-nonce model (vs ERC-2612's sequential nonces) means "unused nonce" cannot be predicted from chain state — an integration that assumes strict ordering is wrong.

### ERC-1271 — contract signature validation

- A contract wallet cannot hold a private key, so it exposes `isValidSignature(bytes32 _hash, bytes _signature)` returning the 4-byte magic value **`0x1626ba7e`** on success (`0xffffffff` otherwise). It is a `view` function (MUST NOT modify state, so it can be queried off-chain), and the reason for a magic value rather than `bool` is stricter verification.
- Any app that lets a contract be the signer must branch: `ecrecover` for EOAs, `isValidSignature` for contracts. A verifier that only calls `ecrecover` will mis-handle contract wallets; a verifier that calls `isValidSignature` must not hard-code a gas limit (implementations may consume a lot of gas), and the callee is fully responsible for validating the signature — a permissive contract wallet collapses the boundary.
- Signature-malleability detail that also applies to hand-rolled `ecrecover`: valid `s` is in `0 < s < secp256k1n/2` and `v ∈ {27, 28}`; a verifier that skips the `s`-range check accepts malleable signatures (a distinct-looking signature that recovers the same signer), which can bypass a "signature already used" check.

### ERC-6492 — signatures from accounts that do not exist yet

- A counterfactual contract wallet can sign before deployment by appending the 32-byte magic suffix `0x6492649264926492649264926492649264926492649264926492649264926492` to `abi.encode((create2Factory, factoryCalldata, originalERC1271Signature))`. The verifier MUST: detect the suffix and deploy/prepare via the factory, then call `isValidSignature`; if there is code and no suffix, do ERC-1271; only if there is no code fall back to `ecrecover`.
- Order matters and is normative: the 6492 suffix check MUST run before the ERC-1271 check (so signatures survive later deployment) and before `ecrecover`; `ecrecover` MUST NOT run before ERC-1271, because a wallet contract may use a signature format that is also a valid `ecrecover` signature for a different EOA address.
- Replay dimension stated by the spec: a signature rendered invalid by key rotation can still validate on another network where the wallet deploys from the same factory/bytecode — "valid at deploy time" is not "valid now" or "valid here". Deploy-then-verify runs a CALL, not a STATICCALL, so off-chain verifiers must constrain side effects (the reference implementation reverts to capture the result when side effects are disallowed).

### Meta-transactions and forwarder trust (ERC-2771)

- A trusted forwarder appends the 20-byte transaction-signer address to the end of calldata; the recipient extracts it from the last 20 bytes as `_msgSender()`. The recipient **MUST** check `isTrustedForwarder(msg.sender)` first — otherwise it "could result in a forged address" from any caller that appends 20 bytes.
- Threat model in the spec: a malicious forwarder can forge `_msgSender()` for any address; an upgradeable forwarder is trusted to not be maliciously upgraded; and the trusted-forwarder list must be immutable or owner-restricted, since an attacker who can add their own forwarder can forge any sender.
- Discovery is `isTrustedForwarder(address)` (MUST NOT revert, SHOULD stay under 50k gas); a recipient with an empty or misconfigured set rejects legitimate meta-transactions — control working — while a recipient that trusts `msg.sender`-appended data without the check is the finding.

### ERC-4337 / EIP-7702 — account abstraction and delegation

- ERC-4337 introduces a `UserOperation` pseudo-transaction; `userOpHash` is an EIP-712 hash over the op (except `signature`) **plus `entryPoint` and `chainId`** — to prevent replay across chains or between EntryPoint versions the spec requires the signature to depend on both. A smart account's `validateUserOp` **MUST** verify the caller is the trusted `EntryPoint` and return `SIG_VALIDATION_FAILED` (1), not revert, on a bad signature.
- Nonces are semi-abstracted: a single `uint256` is treated as a **192-bit `key` and a 64-bit `sequence`** (`getNonce(sender, key)`). The sequence increments monotonically per key; a new key starts at `0`. An account can therefore run an "admin" channel in parallel with normal operations — a mis-scoped key check is the nonce-channel oracle above.
- Paymasters can sponsor fees (`paymasterAndData`), and bundlers run validation **three times** (on receipt, per-op at bundling, on the whole bundle) with an opcode/storage sandbox to resist DoS — so "the bundler validated it" is not the same assurance as on-chain validation. The account itself is the trust consumer here.
- EIP-7702 lets an EOA delegate to contract code via an authorization tuple executed in a `SET_CODE_TX_TYPE` transaction; the delegation cost `PER_EMPTY_ACCOUNT_COST = 25000` is not observable on-chain by the EntryPoint and must be priced into `preVerificationGas`. Delegated accounts **MUST** gate initialization to `entryPoint.senderCreator()`, and their initializer can be called repeatedly through the EntryPoint — "init ran twice" is the oracle; account code is supposed to allow it once.

### EIP-191 version bytes — which signed-message form is in play

- ERC-191 defines the outer envelope `0x19 ‖ <1-byte version> ‖ <version-specific data> ‖ <data to sign>`. The leading `0x19` guarantees the payload is not valid RLP, so a signed message can never be replayed as an Ethereum transaction. The registry of version bytes tells you which scheme a verifier expects:
  - `0x00` (EIP-191) — data with an intended validator; the version-specific data is the validating address (multisig/presigned flows). Mis-binding or omitting this address is exactly the cross-wallet presigned-transaction replay the EIP was written to stop.
  - `0x01` (EIP-712) — structured data; version-specific data is the 32-byte `domainSeparator`.
  - `0x45` (`E`, personal_sign) — version-specific data is `thereum Signed Message:\n` + decimal length; the `E` is the version byte `0x45`.
- Practical consequence: an app that verifies `personal_sign` output while the user signed EIP-712 typed data (or vice versa) is comparing across envelopes — the recovered signer differs or the check silently fails. Confirm which envelope a verifier hashes before claiming a signature-acceptance bug.

### Signature verification decision tree

| Signer is a… | Correct check | Common bug to look for |
|---|---|---|
| EOA (private key) | `ecrecover(hash, v, r, s)` with canonical `s`/`v` and a non-zero signer | missing `s`-range check → malleable replay |
| Contract wallet | `isValidSignature(hash, sig) == 0x1626ba7e` (ERC-1271) | verifier only calls `ecrecover`, so contract principals are rejected or confused |
| Predeploy / counterfactual wallet | ERC-6492 suffix → deploy/prepare → `isValidSignature`; `ecrecover` only when no code | `ecrecover` tried before ERC-1271, or the 6492 suffix ignored so counterfactual signatures are mishandled |
| Smart account (ERC-4337) | `validateUserOp` via the trusted `EntryPoint`; `userOpHash` binds `chainId` + `entryPoint` | trusting an off-chain/bundler validation as final |
| Delegated EOA (EIP-7702) | authorization tuple binds the signer; init gated to `senderCreator()` | init re-runs, or the delegate is swapped after hashing |
| Meta-transaction signer (ERC-2771) | recipient checks `isTrustedForwarder(msg.sender)` before reading the calldata suffix | suffix read without the forwarder check → forged `_msgSender()` |

### Sign-In with Ethereum (EIP-4361) — origin binding for wallet sessions

- The SIWE message is an ERC-191 signed plaintext with required fields `domain`, `address`, `uri`, `version` (`1`), `chain-id` (EIP-155), `nonce` (at least 8 alphanumeric), `issued-at`, and optional `statement`, `expiration-time`, `not-before`, `request-id`, `resources`. The `domain` and (when present) `scheme` MUST correspond to the origin that requested the signature — the spec explicitly covers the cross-origin-iframe case and requires conforming wallets to enforce the match.
- Wallet-side origin verification is normative and is the anti-phishing control: reject when scheme is not in the allowed list, reject on host mismatch, reject or warn on subdomain mismatch, warn on port mismatch; the origin should be read from a trusted source (browser window, or WalletConnect/ERC-1328 session metadata) and compared against the message fields.
- Relying-party rules: parse against the ABNF, check expected values (expiry, nonce, request URI), verify the signature per ERC-191 for EOAs and per ERC-1271 for contract accounts resolved from the declared `chain-id`, and bind the session to the address only. Sessions MUST be invalidated when ERC-1271-relevant state changes — the spec notes `isValidSignature` is not required to be pure and can change with blockchain state.
- Nonce and replay: nonce is per session-initiation and chosen by the relying party (or a privacy-preserving substitute such as a recent block hash/timestamp); "signature valid, nonce already consumed" must be rejected. A backend that verifies the signature but skips `domain`/`uri`/`nonce` checks has an origin-binding gap even though the crypto verifies.

### Wallet connection, providers, and the injected-object surface

- **EIP-1193** is the provider API: `request({method, params})` returning a promise, events `connect`, `disconnect`, `chainChanged`, `accountsChanged`, `message`, and error codes `4001` (user rejected), `4100` (unauthorized), `4200` (unsupported method), `4900`/`4901` (disconnected / chain disconnected). `window.ethereum` is a convention, not part of the standard, and accounts should not be exposed by default — access is requested via `eth_requestAccounts` (EIP-1102) or `wallet_requestPermissions` (EIP-2255).
- The provider object lives in an untrusted environment: the spec says to treat it as though it is controlled by an adversary, keep private user data out of it, isolate wallet from provider, rate-limit requests, and validate all data that arrives from the provider side. An app that trusts a provider-injected account or chain value without a second source is trusting the page's own code path.
- **EIP-6963** addresses provider discovery when several wallet extensions inject into `window.ethereum`: providers announce via the `eip6963:announceProvider` event with a frozen `EIP6963ProviderDetail` (`uuid` UUIDv4, `name`, icon, rdns), and dApps request announcements via `eip6963:requestProvider`. The motivation is explicit: extension load order is a race and "the last wallet to load usually wins" — a dApp that reads `window.ethereum` instead of announced providers is choosing an arbitrary, page-controlled wallet.
- Connection libraries (wagmi/viem/ethers/web3.js) normalize chain IDs, account lists, and signature formats differently, and a wallet's rendered confirmation is a UI artifact. Bind the session to the address and verify every signature against the *raw* message plus the *expected* domain, not against the library's normalized object.

### Bridging and cross-domain message verification

- **OP Stack `CrossDomainMessenger`**: `sendMessage` on the source side and `relayMessage` on the destination side; successful messages are recorded by `msgHash` in `successfulMessages` (replay guard) and failures in `failedMessages`. Messages are versioned by the first two bytes of the nonce (version 0 `relayMessage(address,address,bytes,uint256)`, version 1 `relayMessage(uint256,address,address,uint256,uint256,bytes)`), so a destination that hard-codes one ABI version mis-decodes the other; `L2CrossDomainMessenger` is a predeploy at `0x4200000000000000000000000000000000000007`. An app that trusts `relayMessage` calldata without checking `msg.sender == messenger` expands the trust boundary to any caller.
- Ancillary mechanisms are not security controls: the spec records that `blockedMessages` was removed because "a smart attacker could get around any message blocking attempts", and the `relayedMessages` relay-id mapping was removed because it could not know whether a relayed message actually succeeded. Findings should not rest on those mechanisms existing.
- **Wormhole**: guardians sign `keccak256` of the message body; once a 2/3 supermajority (13 of 19) signs, the signatures are combined into a VAA. VAAs are indexed by `(emitter_chain, emitter_address, sequence)`, and the Core Contract on the target chain verifies guardian signatures before executing. `consistencyLevel` is the source-chain finality the Guardians wait for before attesting — the explicit defense against source reorgs/rollbacks. VAAs are multicast by default (authentic on any chain where relayed), so destination binding (expected emitter, chain, recipient app, sequence) is application code, not the VAA.
- **Nomad (counterexample)**: a routine proxy upgrade initialized `confirmAt[0x00] = 1`, and `process()` checked `acceptableRoot(messages[messageHash])`; since any unused mapping key reads as `0x00`, every previously unseen message was "proven" against the zero root. Anyone could edit the recipient in the message and replay — the exploit was permissionless and repeated by copycats. The durable lesson for this pack: message verification must be positive (an expected root/attestation exists and is bound to this message) and a default/zero state must never satisfy an authentication check.

### RPC providers, `eth_call`, block tags, and indexer drift

- `eth_call` "executes a new message call immediately without creating a transaction on the blockchain"; it is answered by the provider's own node and takes a block parameter. It is a simulation convenience, not a proof: a malicious or misconfigured provider can return any result, and the environment differs from the eventual mined transaction (block number, timestamp, prior state).
- Default block parameter semantics (EIP-1474/ethereum.org): `HEX` number, `"earliest"`, `"latest"` (latest proposed block), `"safe"`, `"finalized"`, `"pending"`. `eth_getLogs` entries carry `removed: true` "when the log was removed, due to a chain reorganization" — an indexer or app that ignores `removed` replayed an orphaned event into a decision.
- **EIP-1898** lets the block parameter be `{blockNumber | blockHash, requireCanonical?}` so a read can be pinned to an exact block even across reorgs; with `requireCanonical: true` the node must error if that hash is not canonical. Pinning by hash (and re-reading at the same hash) is the minimum reproducible baseline for a drift claim.
- **EIP-1186** `eth_getProof` returns the account and requested storage values with Merkle proofs against the block's `stateRoot`, so a client can verify a provider's answers offline given a trusted blockhash instead of trusting `eth_call`/`eth_getBalance` output. Absent a proof or a second independent provider, an app's "on-chain read" is only as trustworthy as its endpoint.
- Finality: on Ethereum PoS a checkpoint pair backed by a 2/3 stake supermajority link becomes justified, then finalized; reverting a finalized block would cost at least a third of staked ETH. Apps deciding on `latest` (which can be reorged) while claiming "confirmed on-chain" is the confirmation-tag oracle; a genuine security decision should use `finalized` (or a chain-specific finality the protocol defines) and record the block number/hash it used.
- Bridge-side finality is per-protocol and per-chain: Wormhole's `consistencyLevel` and OP's withdrawal finalization window are the source-chain assumptions; the destination app often repeats the check. Where a destination trusts an off-chain relayer's word rather than the verifier contract's event, the trust seam is the relayer, not the chain.
- Deployment-domain nuance to keep in the seam section: signature standards differ (personal-sign, EIP-712 typed data, chain-specific prefixes); domain separator, version, chain ID, and nonce handling are per-integration observations. Wallets differ on what they display versus what is signed; always compare displayed text against the raw signed payload.

### Signing-UI integrity: the front-end is inside the trust boundary

- The February 2025 Bybit/`Safe{Wallet}` incident is the worked example: attackers modified the S3-hosted JavaScript of `app.safe.global` (activation gated to the Bybit cold wallet), so the interface displayed a legitimate transfer while the signed payload replaced the implementation via a `delegatecall` (`operation = 1`) to a pre-deployed contract exposing `sweepETH`/`sweepERC20`, draining the cold wallet without further multisig approvals. WazirX and Radiant Capital reported the same display-versus-signature mismatch pattern.
- Consequence for this pack: "the UI showed X" is not evidence of what was signed; capture the raw transaction/hash and the displayed artifact separately, and treat third-party wallet front-ends, browser extensions, and RPC endpoints as part of the authorization path when the app's assurance story depends on them.

### Bridging, indexing, and the app trust seam (framing)

- Chains and L2s differ on confirmation depth, reorg behavior, and event finality; bridge acceptance assumptions are per-bridge observations.
- Contracts differ on upgradeability, pausability, and role granularity; proxy versus implementation semantics govern the role surface.
- Backend indexers differ on confirmation thresholds and reorg handling; premature-trust bugs live in the indexer-to-app handoff, not the chain itself.
- The **OWASP Smart Contract Top 10 (2025)** is the taxonomy to map on-chain findings onto: `SC01` Access Control, `SC02` Price Oracle Manipulation, `SC03` Logic Errors, `SC04` Lack of Input Validation, `SC05` Reentrancy, `SC06` Unchecked External Calls, `SC07` Flash Loan Attacks, `SC08` Integer Overflow/Underflow, `SC09` Insecure Randomness, `SC10` Denial of Service. Keep the app-boundary framing: this pack reports the authorization boundary, not contract internals.

## References

- [T0 standard] EIP-712 typed structured data hashing and signing (`hashStruct`, `encodeType`, `encodeData`, `domainSeparator`, `eth_signTypedData`, chainId/user-agent rule, replay/frontrunning caveats): https://eips.ethereum.org/EIPS/eip-712
- [T0 standard] ERC-2612, Permit extension for EIP-20 signed approvals (deadline, nonces, `DOMAIN_SEPARATOR`, zero-address risk): https://eips.ethereum.org/EIPS/eip-2612
- [T0 standard] ERC-1271, standard signature validation for contracts (`isValidSignature`, magic value `0x1626ba7e`, s/v malleability): https://eips.ethereum.org/EIPS/eip-1271
- [T0 standard] ERC-4337, account abstraction using alt mempool (`UserOperation`, `userOpHash`, `validateUserOp`, nonce key/sequence, paymasters, EIP-7702 delegation): https://eips.ethereum.org/EIPS/eip-4337
- [T0 standard] ERC-191, Signed Data Standard (envelope `0x19`, version-byte registry `0x00`/`0x01`/`0x45`, personal_sign construction): https://eips.ethereum.org/EIPS/eip-191
- [T0 standard] ERC-4361, Sign-In with Ethereum (required/optional fields, nonce, origin verification rules, ERC-1271 session invalidation): https://eips.ethereum.org/EIPS/eip-4361
- [T0 standard] ERC-5267, retrieval of EIP-712 domain (`eip712Domain()` fields bitmap, extensions, domain-change guidance, verifyingContract/chainId caution): https://eips.ethereum.org/EIPS/eip-5267
- [T0 standard] ERC-6492, signature validation for predeploy contracts (magic suffix, verifier ordering, cross-network replay note): https://eips.ethereum.org/EIPS/eip-6492
- [T0 standard] ERC-2098, compact signature representation (`r` + `yParityAndS`, canonical-`s` top-bit assumption): https://eips.ethereum.org/EIPS/eip-2098
- [T0 standard] EIP-155, simple replay attack protection (nine-element signing payload, `v = chainId*2+35`): https://eips.ethereum.org/EIPS/eip-155
- [T0 standard] ERC-3009, transfer with authorization (random 32-byte nonce, `validAfter`/`validBefore`, `receiveWithAuthorization` front-run guard, domain recommendation): https://eips.ethereum.org/EIPS/eip-3009
- [T0 standard] ERC-2771, secure protocol for native meta transactions (calldata suffix `_msgSender()` extraction, `isTrustedForwarder` requirement, malicious/upgradeable forwarder risks): https://eips.ethereum.org/EIPS/eip-2771
- [T0 standard] EIP-1193, Ethereum provider JavaScript API (request/events, error codes 4100/4900/4901, provider-as-adversary guidance, EIP-1102/EIP-2255 account exposure): https://eips.ethereum.org/EIPS/eip-1193
- [T0 standard] EIP-6963, multi-injected provider discovery (`eip6963:announceProvider`/`requestProvider`, provider detail and load-order race): https://eips.ethereum.org/EIPS/eip-6963
- [T0 standard] EIP-1898, block parameter as `{blockNumber|blockHash, requireCanonical}` for reads across reorgs: https://eips.ethereum.org/EIPS/eip-1898
- [T0 standard] EIP-1186, `eth_getProof` account/storage Merkle proofs against `stateRoot`: https://eips.ethereum.org/EIPS/eip-1186
- [T0 standard] EIP-1474, JSON-RPC specification (default block parameter list for `eth_call` and state methods): https://eips.ethereum.org/EIPS/eip-1474
- [T1 vendor] Uniswap Permit2 overview (module split, nonce schemes, canonical addresses, one-time approval): https://developers.uniswap.org/docs/protocols/permit2/overview ; Permit2 repository README (witness hash/type string, EIP-1271 support, batch revoke): https://github.com/Uniswap/permit2
- [T1 vendor] OP Stack specification, cross domain messengers (`successfulMessages`/`failedMessages`, message versions, removed blocked-message mechanism): https://specs.optimism.io/protocol/messengers.html
- [T1 vendor] Wormhole VAA documentation (guardian keccak256 signing, 13/19 supermajority, `(emitter_chain, emitter_address, sequence)` indexing): https://wormhole.com/docs/protocol/infrastructure/vaas/ ; Core Contract documentation (`consistencyLevel` finality, target-chain signature verification, multicast default): https://wormhole.com/docs/protocol/infrastructure/core-contracts/
- [T1 vendor] MetaMask sign-data guide (`eth_signTypedData_v4` domain metadata, `personal_sign` prefix and phishing advice, `eth_sign` deprecation/MIP-3): https://docs.metamask.io/metamask-connect/evm/guides/sign-data/
- [T1 vendor] ethereum.org JSON-RPC API (`eth_call`, block tags `latest`/`safe`/`finalized`, `eth_getLogs` `removed` flag on reorg): https://ethereum.org/en/developers/docs/apis/json-rpc/
- [T1 vendor] ethereum.org proof-of-stake finality (justified/finalized checkpoints, 1/3-stake cost to revert): https://ethereum.org/en/developers/docs/consensus-mechanisms/pos/
- [T2 research] OWASP Smart Contract Top 10 (2025), SC01–SC10: https://owasp.org/www-project-smart-contract-top-10/
- [T2 research] Immunefi hack analysis of the Nomad bridge (trusted zero root initialized, `acceptableRoot` on unused mapping keys, permissionless replay): https://immunefi.com/blog/bug-fix-reviews/hack-analysis-nomad-bridge-august-2022/
- [T2 research] Sygnia investigation of the Bybit hack (modified Safe{Wallet} S3 JavaScript, `delegatecall` payload substitution, WazirX/Radiant parallels): https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/
- [T1 vendor] EIP-712 signing explainer: https://eco.com/support/en/articles/15483230-what-is-eip-712-typed-structured-data-signing-on-ethereum ; auditor-oriented EIP-712 risk write-up: https://medium.com/@chinmayf/auditors-digest-the-risks-of-eip712-5a0fc57e3837
- [T2 research] Bridge/security lesson on EIP-712 use in bridges: https://updraft.cyfrin.io/courses/security/bridges/eip-712
- access-auth/authentication-authorization.md for session and tenant binding reused from the auth surface
