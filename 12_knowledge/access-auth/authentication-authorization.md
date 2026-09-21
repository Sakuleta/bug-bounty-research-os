# Authentication & Authorization

> SCOPE: Load when testing identity, sessions, roles, tenants, objects, or any lifecycle transition (register, recover, link, revoke). Covers BOLA/BFLA, mass assignment, JWT/OAuth/OIDC/SAML, MFA, passkeys/WebAuthn, session lifecycle, recovery chains, and tenant/object authorization.

## Research families

- BOLA/IDOR across the full representation matrix (sub-resources, export, preview, history, share, restore)
- BFLA: role-gated functions reachable by lower roles (admin endpoints, method variants, internal/legacy API versions)
- Mass assignment of protected fields with read-back confirmation (property-level read + write)
- JWT validation failures (alg confusion, kid/jku injection, claim enforcement, key-type confusion)
- JWT key-source lifecycle (JWKS rotation overlap, `kid`-less trial verification, cache staleness)
- OAuth/OIDC redirect, state, PKCE, and account-linking flaws
- OAuth consent-screen and incremental-scope escalation (second, weaker client upgrades the grant)
- OAuth 2.1 / RFC 9700 deltas (PKCE downgrade, exact redirect matching, refresh rotation/replay detection, DPoP binding)
- SAML signature wrapping and assertion confusion (XSW variants, parser differentials, comment injection)
- Password reset and recovery authorization chains
- Account pre-hijacking (classic-federated merge, unexpired session, trojan identifier, unexpired email change, non-verifying IdP)
- MFA enrollment, replay, and channel-downgrade bypasses
- Session fixation, persistence across credential change, and scope confusion
- IDOR-to-ATO chains (email, phone, API key, credential-ID takeover)
- Cross-tenant and cross-brand boundary leakage
- WebAuthn/passkey ceremony and credential-binding gaps (platform vs roaming vs synced)
- Magic-link and passwordless token lifecycle flaws
- Bulk and batch authorization on multi-object operations
- Recovery-chain composition (email → phone → TOTP → API key) where any single leg authorizes the next
- Token lifecycle: refresh rotation/reuse detection, revocation, and introspection gaps

## Preconditions

- Two or more identities under researcher control (A and B, plus unauthenticated) to test every direction of every boundary.
- Object references (IDs, UUIDs, short forms, hashes) that are enumerable or guessable, or disclosed through legitimate flows.
- Role-differentiated accounts where the program provides them (user, premium, admin, collaborator, service account); hidden UI alone never proves server-side enforcement.
- For token attacks: a JWT/OAuth/SAML flow whose validation steps (signature, audience, issuer, expiry, binding) can each be individually perturbed.
- For recovery attacks: control of at least the attacker-side mailbox/phone plus visibility into reset-link structure (host header, token format, parameter binding).
- For session attacks: observable session issuance, refresh, and invalidation events (login, logout, password change, MFA change), plus two parallel session surfaces (web, mobile, API key) to compare invalidation fan-out.
- For passkey/magic-link attacks: enrollment and ceremony endpoints reachable such that challenge binding, origin checking, and single-use can each be tested.
- For bulk-operation gaps: a multi-ID endpoint where per-item authorization is plausibly checked only once (first ID, count limit, or response truncation).
- For token-family testing: the signing key material is reachable (`/.well-known/jwks.json`, an `x5c` chain, or a public key the app already trusts) so a forgery can be built from source, not guessed.
- For OIDC: the deployment issues `id_token`s (or a hybrid response) so `nonce`, `c_hash`, `at_hash`, and `azp` become individually testable claims.
- For recovery composition: at least two recovery legs exist (e.g. email reset + phone reset) so the weaker leg's token can be fed into the stronger leg's flow.
- For JWKS rotation tests: a tenant/AS under researcher control (or docs/knowledge of the rotation schedule) so old-key acceptance can be tested without touching production key material.
- For pre-hijacking tests: a researcher-controlled identifier (mailbox) plus the ability to create an account through at least two routes (classic password and federated) and to observe merge/link behavior.
- For MFA policy tests: knowledge of the stated policy (AAL/target level, session lifetime, "remember this device") against which the observed session lifetime and factor behavior can be compared.

## Oracles

- Cross-account read-back: object created by A is readable, writable, or deletable by B (or unauthenticated) through at least one representation — confirmed by reading B's view of A's record, not by status code.
- Write/read asymmetry: GET correctly 403s but PUT, DELETE, export, preview, share, or history on the same ID succeeds — the forgotten-representation pattern.
- Mass-assignment persistence: injected field (`role`, `is_admin`, `tenant_id`, `balance`) survives a re-GET of the object as the low-privilege user.
- Property-level read leak: an endpoint echoes sensitive properties of a related object (e.g. a "report user" mutation returning the reported user's email/location) — property-level authorization applies to reads and writes, not only writes. [T1 OWASP API3]
- JWT acceptance differential: `alg:none` variant, RS256-token-verified-as-HS256, `kid` traversal, or `jku`/`x5u` to attacker JWKS accepted where the baseline valid token is the control.
- JWT claim-enforcement differential: one claim mutated per request against a valid baseline — `exp` far future, `nbf` cleared, `iat` back-dated, `aud` swapped for another service, `iss` swapped, `sub` swapped for B's identifier. A token still accepted after `sub`/`aud` mutation is the finding; a 401 on every variant is a hardened validator (see false positives).
- Key-type confusion oracle: a token signed with a symmetric algorithm verified against an asymmetric public key (RSA/EC/OpenSSH format) still validates — the shape behind CVE-2022-23541 (node), CVE-2024-33663 (python-jose) and CVE-2022-29217 (PyJWT).
- `kid`/key-source injection: `kid` used as a file path (`../../dev/null`), as a URL, or as an SQL/lookup key returns or selects attacker-influenced key material; `jku`/`x5u`/`jwk` header pointing at a researcher-hosted JWKS is fetched and trusted.
- `kid`-less trial verification: a token with no `kid` (or an unknown `kid`) is verified by trying every key in the published JWKS — on a researcher-owned tenant, sign with a key that has been revoked and see if verification still succeeds.
- JWKS rotation overlap: after rotation/revocation on a tenant under researcher control, tokens signed with the previous key are still accepted; discovery also publishes the [next] key before it signs anything, so acceptance of a token claiming a future/unknown `kid` is a policy bypass. [T1 Auth0]
- JWE bomb: a compact JWE with a high compression ratio (`zip`) or an oversized PBES2 iteration count (`p2c`) causes unbounded CPU/memory during decryption; if the endpoint stays up, submission size limits alone are not protecting it.
- OAuth binding failure: authorization code, `state`, or `code_verifier` omitted, replayed, or substituted across clients/sessions still completes the flow.
- PKCE downgrade oracle: a token request carrying `code_verifier` is accepted although the authorization request carried no `code_challenge` (RFC 9700 requires rejection); or the `plain` method (forbidden in OAuth 2.1) is accepted. [T0 RFC 9700; T0 OAuth 2.1]
- PKCE/nonce constancy oracle: the same `code_challenge` or `nonce` value is accepted across separate sessions/transactions (RFC 9700 warns AS to detect constant values), so the verifier is a fixed secret rather than a per-transaction binding. Check the AS metadata (`code_challenge_methods_supported`) to see whether PKCE is detectable at all. [T0 RFC 9700]
- OAuth mix-up oracle: with two authorization servers configured, the client accepts a code/`id_token` minted by the *other* AS — check whether the `iss` parameter (RFC 9207) is present and validated, and whether PKCE is bound across AS boundaries.
- Redirect matching oracle: `redirect_uri` prefix/regex/`@host`/path-append variants complete the flow where exact string matching is required; localhost port flexibility is the only RFC 9700 exception. [T0 RFC 9700]
- Bearer-in-query oracle: a resource server returns data for `?access_token=…`; OAuth 2.1 requires resource servers to *ignore* query-parameter tokens. [T0 OAuth 2.1]
- Refresh-replay oracle: an already-rotated refresh token still succeeds, or reuse of the predecessor leaves the successor/family alive (RFC 9700 expects predecessor invalidation plus revocation of the active token on replay). [T0 RFC 9700]
- Sender-constraining oracle: a DPoP/mTLS-bound token replayed **without** its proof-of-possession, or with a proof whose `htu`/`htm`/`jti` are replayed, still succeeds — the binding is decorative.
- OIDC id_token oracle: `nonce` absent from the token, `azp` missing on a multi-audience token, or `c_hash`/`at_hash` not matching the returned code/access token — the token is still accepted, proving the check is skipped. `nonce` is REQUIRED in implicit/hybrid responses and, if sent in the request, MUST be compared. [T0 OIDC Core]
- Cross-issuer `sub` collision: a `sub` value from a second issuer is accepted as the same local principal — `sub` is only locally unique and never reassigned *within its issuer*. [T0 OIDC Core]
- Reset-token confusion: token issued for A usable with B's identifier, reusable after use, or surviving password change; reset link host controlled via `Host`/`X-Forwarded-Host` in the test mailbox.
- Recovery-chain escalation: a weaker leg's artifact (email reset token, OTP) unsatisfied at its own step but accepted at a stronger step (phone change, MFA disable, email change) — cross-leg authorization leak.
- Pre-hijack persistence: after the victim recovers an account, an attacker-side leg survives — an unexpired session created before the reset, a pending email-change nonce, a linked trojan identifier (attacker email/phone/federated identity), or a classic/federated merge that keeps attacker access. [T2 USENIX 2022; T1 MSRC]
- MFA/session gap: direct navigation past the MFA step, OTP reuse or parallel-accept, session surviving password/MFA change or logout on one brand but alive on another.
- MFA-downgrade shape: a pre-auth session (post-password, pre-MFA) that already carries a usable cookie, refresh token, or API scope — the "authenticated but not verified" state treated as authenticated by another component.
- OTP hygiene oracle: the same OTP verifies twice, an old OTP stays valid after a resend, or the code is not invalidated on success (OWASP: short TTL, single-use, strict attempt limits, invalidate on success, resend overwrites the old record). [T1 OWASP MFA]
- MFA factor-replacement oracle: adding/removing/replacing an MFA factor succeeds with only the active session (no re-auth with an existing factor, no out-of-band notification). [T1 OWASP MFA]
- Step-up claim oracle: the token/session records `acr`/`amr` (or the app's equivalent) but a component consumes it without checking that the value satisfies the required authentication context — `acr` "0" explicitly means no specific context class was met, so accepting it for a step-up decision is a downgrade. [T0 OIDC Core]
- Phone-binding oracle: changing the pre-registered telephone number (adding/replacing an SMS factor) completes without re-authentication — NIST treats number binding as binding a *new authenticator*, which must follow the authenticator-binding rules. [T0 NIST 800-63B-4]
- MFA coverage oracle: *all* authentication paths enforce MFA — a mobile app, an API login, a legacy endpoint, or a "sign in with" path that authenticates the same principal without the second factor is the bypass; OWASP calls the separate-API/mobile path the commonly missed one. [T1 OWASP MFA]
- Reset-request side-effect oracle: requesting a reset (no valid token yet) changes account state — locks the account, invalidates the current password/OTP, or reveals whether the account exists. OWASP: do not make changes to the account until a valid token is presented. [T1 OWASP Forgot Password]
- Transport oracle: any OAuth/OIDC/SAML endpoint reachable over `http` (or with live TLS validation disabled) is a downgrade; OAuth 2.1 requires `https` for all protocol URLs with a loopback exception, and TLS certificate validation per RFC 9110 §4.3.4. [T0 OAuth 2.1]
- Session-policy oracle: a session or refresh token outlives the stated re-authentication policy (NIST 800-63B-4 reference points: AAL1 30 days overall; AAL2 24 hours overall or 1 hour inactivity; AAL3 12 hours overall or 15 minutes inactivity; rev 3 used 12h/30min for AAL2). [T0 NIST]
- Passkey/passwordless gap: ceremony completing with wrong-origin or replayed challenge, credential ID from A accepted under B's session, magic link usable twice or across accounts.
- Passkey flag oracle: a credential whose `BE=1` (backup-eligible, synced) is treated by the RP as if device-bound for step-up decisions, or `BS`/`BE` ignored when policy requires a hardware-bound key (`BE=0`, `BS=0`). See version notes for bit values and the verification steps. [T0 WebAuthn L3; T1 MDN]
- Attestation-policy oracle: registration accepts any authenticator with no attestation check even where the deployment claims hardware-backed assurance (TPM/Secure Enclave/StrongBox); OWASP's remediation for device-binding bypass is exactly non-exportable keys plus attestation where policy demands it. [T1 OWASP MFA]
- Passkey step-up oracle: `userVerification:"required"` accepted with the UV bit unset, or a `crossOrigin=true` ceremony accepted where the RP never checks `topOrigin`/`crossOrigin`. [T0 WebAuthn L3]
- Session-regeneration oracle: session identifier unchanged across login, or across a privilege change (anonymous → authenticated, user → admin) — the pre-auth ID stays valid, enabling fixation.
- Sensitive-change re-auth oracle: password, email, or MFA-factor change completes without the current password/second factor (OWASP expects current-credential verification, not just an active session). [T1 OWASP AuthN]
- Tenant isolation failure: tenant-A session listing, searching, or exporting tenant-B records through list, search, aggregate, or export endpoints.
- Bulk-operation gap: multi-ID request (`ids=1,2,3`) authorized on the first ID only while returning or mutating all requested objects.
- Linked-object traversal: attachment, comment, or share record of A's object reachable by B through the child endpoint even where the parent is correctly guarded.
- BFLA oracle: a regular user reaches an administrative or privileged *function* (not just another user's object) — e.g. `DELETE /admin/user/{id}`, an internal API version, or a guessable admin route with no server-side role gate. [T1 OWASP API5]
- Quotas: object IDs in headers/payload (not only path/query) are treated as trusted identifiers; comparing the session user ID to the ID parameter is explicitly insufficient protection. [T1 OWASP API1]

## Minimal safe proof

1. Build the account matrix first (unauth, A, B, plus any higher role available) and record the intended access policy from observed UI and docs before sending adversarial requests.
2. Test every representation of one object before moving to the next object: primary, write methods, sub-resources, bulk, export/preview/download, versions, share/restore, history/audit.
3. Prove with read-back: after each candidate bypass, re-read the affected record as the victim-context account and compare against the pre-test baseline.
4. Token and flow tests perturb exactly one element per request (one header, one claim, one parameter) against a fresh valid baseline; never brute-force OTPs or tokens beyond the program's stated rate limits.
5. Reset and email-change chains use researcher-owned mailboxes end to end; never route reset links for real users or third-party addresses.
6. For JWT forgery, mint the adversarial token offline from key material the app itself publishes (JWKS, `x5c`); never exercise a private key you do not own.
7. For recovery-chain probes, advance one leg at a time and read back the next leg's precondition as the victim-context account before touching the following leg.
8. For JWKS rotation and key-lifecycle tests, use a tenant/AS under researcher control; rotate, then replay a token signed with the retired key and record acceptance. Never test rotation against a production tenant whose private keys you do not own.
9. For pre-hijacking probes, use two researcher mailboxes only: create with mailbox A, recover via mailbox B, then check whether any A-side session, pending email change, or linked identifier still authenticates.
10. For MFA/OTP tests, capture the OTP with the researcher's authenticator, then replay it (sequential and parallel) and issue one resend; do not run guessing loops. Stop if a third-party account is affected.
11. Stop conditions: real third-party data returned, another account's email/phone changed, session of another user invalidated, MFA disabled on a non-test account, or mass state change (bulk endpoint affecting many rows) — halt, revert researcher-side changes, report.

## False positives

- Object ID of your own account accessible to yourself through alternate representations — same-principal access; require cross-principal read-back.
- Error-message difference (403 vs 404) without data return or state effect — enumeration aid at most; require the read-back.
- Admin UI hidden but every admin API returns 403/404 for the low role with no representation gap — hidden is not vulnerable; require an enforced-decision failure.
- JWT tampering rejected identically across all variants (signature, audience, expiry enforced) — hardened validator; require one accepted forgery.
- `alg:none` rejected but the library *only* rejects it when the app passes an explicit algorithm list; a separate endpoint that omits the list still accepting `none` is the real finding — test each token-consuming service, not just one.
- Key-type confusion rejected (modern library) — e.g. jsonwebtoken ≥9.0.0 validates key/algorithm combinations, so an RSA-key-as-HMAC-secret attempt failing is the expected hardened behavior, not a finding.
- JWE bomb mitigated by request-size limits or `zip` rejected outright — correct; require an actually consumed resource (latency, memory growth, worker restart).
- OAuth `redirect_uri` mismatch correctly rejected, or `state` enforced — require a completed confused-flow, not a suspicious parameter reflection.
- `iss` parameter absent but mix-up structurally impossible (single AS per client) — absence alone is not a finding; require two-AS confusion to succeed.
- OIDC `nonce` missing from the request but `state`/PKCE already bind the session — require the token-substitution path to actually complete under a second AS.
- PKCE `plain` accepted is a finding only if the AS actually offers/enables the method; an AS that only ships S256 and rejects plain is compliant.
- Bearer token in a query working against an *application* endpoint may be a frontend design artifact; require the resource server itself (the API that validates the token) to accept it — proxies and CDNs may pass it through regardless.
- OTP rate-limited with single-use enforced and session correctly gated behind MFA completion — require the actual skip, reuse, or pre-MFA session.
- A resend generating a *new* valid code is correct; the finding is the *old* code remaining valid after the resend.
- A constant `code_challenge`/`nonce` is only a finding when the flow can actually be crossed between sessions; a server that stores and compares it per transaction has binding even if the value looks static in one capture.
- Risk-based authentication is allowed to skip MFA on a trusted signal; the finding is a *fallback* that is weaker than the primary factor (e.g. device cookie that can be replayed cross-device) — require the risk signal to be attacker-forgeable and the downgrade observable.
- Session surviving logout on a purely client-side cache (stale local copy, server rejects) — require a server-accepted request with the old session.
- Session ID not regenerated but the old ID is independently invalidated server-side — require the fixation takeover to succeed, not just the static ID.
- Session living longer than a NIST interval is a policy deviation, not automatically a vulnerability: NIST applies to federal/gov contexts and "recommended" targets; require the program's stated policy or a concrete takeover step.
- Tenant-scoped search returning only own-tenant rows with correct counts — working isolation; require cross-tenant rows or counts.
- Bulk endpoint returning partial results limited to owned objects with per-item denial — correct enforcement; require the unowned items included or mutated.
- Child endpoint (attachment, comment) denying B where B holds a legitimate share grant — intended sharing, not leakage; require access outside any grant.
- Email change requiring confirmation from *both* the old and the new address is the secure design (OWASP recommends exactly this); a working "change" that needs only the new address is the finding.
- Pre-hijack observations are only findings when a leg survives account recovery by the victim; an unverified abandoned account is the designed precondition, not the bug.
- Passkey `BE=1` credential flagged as "insecure" where RP policy explicitly permits synced passkeys — policy choice, not a bypass; require the RP to *intend* device-bound and fail to enforce it.
- UV=0 accepted where the RP set `userVerification:"preferred"` — spec-compliant; require `"required"` in the ceremony options and a still-accepted UV=0 assertion.
- Mass-assignment field echoed in an error or response but not persisted — require the read-back to show the stored value.

## Version/implementation notes

### JWT — library behavior matrix (per-language)

- Node `jsonwebtoken` before 4.2.2 did not enforce the signing algorithm, so a caller-chosen `alg` could verify an HS-signed token against an RS/ES public key (CVE-2015-9235). Modern releases enforce this only when the app passes an explicit `algorithms` list to `verify()` — fingerprint which call site omits it.
- Node `jsonwebtoken` ≤ 8.5.1 carries three related 2022 CVEs, all fixed in 9.0.0: CVE-2022-23539 (unrestricted key type — e.g. a DSA key accepted with RS256; fixed by key/algorithm combination validation, with an `allowInvalidAsymmetricKeyTypes` escape hatch), CVE-2022-23540 (`jwt.verify()` with no `algorithms` and a falsy key defaults to `none` for unsigned tokens), and CVE-2022-23541 (a poorly implemented key-retrieval function lets an RSA public key verify as an HS256 secret). [T3]
- PyJWT `< 2.4.0` allowed key confusion through non-blocklisted public-key formats (SSH-format Ed25519 keys tested as HMAC secrets, CVE-2022-29217); the fix blocklists such formats. PyJWT, like most libraries, only rejects `alg:none` when algorithms are pinned.
- Python `python-jose` < 3.4.0: CVE-2024-33663 (algorithm confusion with OpenSSH ECDSA keys and other key formats — same class as PyJWT's advisory) and CVE-2024-33664 (JWE "token bomb" via high compression ratio, patch in PR #345). [T3]
- Node `jose` 3.0.0–4.15.4 (and < 2.0.7): CVE-2024-28176 — compressed JWE plaintext expands after decryption, so application-level size limits measured on the encrypted token are bypassed; patches cap decompression at 250 kB, and v5 removed JWE compression entirely. Test by sending a `zip`-compressed JWE and measuring decryption cost. [T3]
- Go `golang-jwt`: CVE-2025-30204 — `parse.ParseUnverified` splits the untrusted token on `.` and allocates ~16× the input, so `Authorization: Bearer .......` (many periods) amplifies memory; fixed in v4.5.2 and v5.2.2, v3.2.0–3.2.2 has no patch. [T3]
- Java `nimbus-jose-jwt` < 9.37.2: CVE-2023-52428 — attacker-supplied JWE `p2c` (PBKDF2 iteration count) forces unbounded CPU in `PasswordBasedDecrypter`. [T3]
- .NET `Microsoft.IdentityModel.JsonWebTokens` / `System.IdentityModel.Tokens.Jwt`: CVE-2024-21319 (JWE with high compression ratio → unbounded memory; unauthenticated). Affected < 5.7.0, 6.5.0–< 6.34.0, 7.0.0-preview–< 7.1.2; the ASP.NET Core templates were the usual deployment path. [T3]
- ECDSA verification in Java 15–18 (SunEC provider) accepted all-zero signatures (**Psychic Signatures**, CVE-2022-21449) — a JWT signed with a blank `r=s=0` ECDSA signature validates against any public key on an affected JDK. Fingerprint JVM/JDK versions behind a signed-token service.
- `kid` is application-interpreted, so its handling is per-deployment: a filesystem path (path traversal to a known key or `/dev/null`), a database lookup (SQL injection or unknown-kid fallback to a default key), or a key-ID to JWKS map. The classic bypass is an unknown/degenerate `kid` that falls back to a key the attacker can supply.
- Key-source headers (`jku`, `x5u`, `jwk`, `x5c`) are only as safe as the allowlist: if the validator fetches `jku`/`x5u` URLs or trusts an embedded `jwk`, host a JWKS on a researcher-controlled origin and point the header at it.
- Claim enforcement is per-claim and per-service: `exp`, `nbf`, `iat`, `aud` (type and value), `iss`, `sub`, and for OIDC `azp`/`nonce`/`c_hash`/`at_hash`. RFC 8725 recommends explicitly rejecting `none`, validating `alg`/`typ`/`cty`, and requiring the app to pin expected algorithms — deviations are the test surface.
- Cross-service confusion: an internal service that verifies only the signature (not `aud`/`iss`) accepts a token minted for a different audience or a sibling brand. Enumerate every token consumer, then replay a low-value token against high-value consumers.
- Temporal edges: clock skew tolerance, `exp` absent (some libraries treat missing `exp` as non-expiring), and long-lived `iat`-only tokens are policy failures rather than parser bugs — confirm the token's acceptance across a simulated expiry boundary.

Library behavior matrix (fingerprint the resolver before choosing a payload):

| Library / family | `alg` handling | `kid` / key-source | Claim enforcement | Black-box tell |
|---|---|---|---|---|
| node `jsonwebtoken` (< 4.2.2) | alg not enforced; caller-chosen `alg` verifies HS token against RS/ES public key (CVE-2015-9235) | `kid` handed to an app resolver (path/DB/JWKS) | `exp`/`nbf`/`aud`/`iss` only if options passed to `verify()` | swapped-`alg` token accepted where baseline valid token is the control |
| node `jsonwebtoken` (≤ 8.5.1) | key type not validated; HS verification against RSA public key possible (CVE-2022-23541); `none` default with falsy key and no `algorithms` (CVE-2022-23540) | key retrieval function is app-supplied and easily mixed symmetric/asymmetric | app-driven | forged HS256 token built from the service's RSA public key |
| PyJWT (< 2.4.0) | `none` rejected only when `algorithms` is pinned; key confusion via non-blocklisted key formats (CVE-2022-29217) | `kid` via app callback | `exp`/`nbf`/`aud`/`iss` app-driven | SSH-format public key string accepted as HMAC secret |
| PyJWT default-algorithm mode | `jwt.algorithms.get_default_algorithms()` enables all algorithms — the documented foot-gun named in CVE-2022-29217 | as above | as above | any-alg token verifies |
| python-jose (< 3.4.0) | OpenSSH/ECDSA public keys accepted as HMAC secrets (CVE-2024-33663) | `kid` via app | claims via `options` | OpenSSH `ecdsa-sha2-...` key string used as HS256 secret |
| node `jose` (3.0.0–4.15.4) | signature validation solid; risk is JWE not JWS | n/a | app-driven | `zip`-compressed JWE accepted and decrypted (CVE-2024-28176) |
| Go `golang-jwt` (< 4.5.2, v5 < 5.2.2) | method pinned by the `SigningMethod` passed to ParseWithClaims | keyfunc is app-supplied and `jwt.ParseUnverified` is unauthenticated | claims via `WithClaims` validators | long period runs in `Authorization` cause memory amplification (CVE-2025-30204) |
| Java nimbus-jose-jwt (< 9.37.2) | JWS verification solid; JWE `p2c` unbounded (CVE-2023-52428) | key selector via app | app-driven | PBES2 JWE with huge iteration count stalls a worker |
| .NET IdentityModel (< 5.7.0 / 6.5.0–6.34.0 / 7.x < 7.1.2) | JWS solid; JWE compression bomb (CVE-2024-21319) | `kid` via `TokenValidationParameters` | per-parameter, app-driven | compressed JWE exhausts memory on decrypt |
| JDK SunEC (Java 15–18) | ECDSA verification accepts all-zero signature (CVE-2022-21449) | n/a (JVM-level) | n/a | blank `r=s=0` ES256/384/512 signature validates for any key |
| Generic validator | pinning is per call-site, per service (RFC 8725 §3.1) | `jku`/`x5u`/`jwk` fetched or trusted | per-claim, per-consumer | one service enforces, a sibling does not |

Claim → failure → oracle (each perturbed alone against a valid baseline):

| Claim | Binds | Skipped-check failure | Oracle |
|---|---|---|---|
| `alg` / `typ` | signature algorithm & token type | attacker chooses HMAC over an asymmetric key; `none` accepted | forged token validates |
| `kid` | which key verifies | traversal/URL/SQL selects attacker-influenced key; unknown-`kid` fallback key | key substitution succeeds |
| `iss` / `aud` | issuer & intended resource server | token for service X accepted by service Y | cross-audience replay |
| `sub` (+`iss`) | the principal | `sub` compared without `iss` → cross-issuer account collision | login resolves to another principal |
| `exp`/`nbf`/`iat` | validity window | expiry/nbf ignored; missing `exp` treated as non-expiring | expired token still accepted |
| `nonce`/`azp`/`c_hash`/`at_hash` | OIDC request & token binding | replayed or substituted id_token accepted | token substitution completes |
| JWE `zip`/`p2c` | decryption cost budget | no compression/iteration cap | latency/memory spike or worker death |

### JWT — key sources and JWKS rotation

- A JWKS-backed deployment publishes more than one key on purpose: Auth0's discovery document always contains the current and the next signing key, and may retain the previous key until it is revoked; tokens signed with the previous key stay valid until revocation. So "the JWKS has several keys" is not a finding — the finding is a retired `kid` still verifying, or an unknown `kid` accepted. [T1 Auth0]
- Rotation windows are the test surface: middleware caches JWKS "at a certain interval" or pins a `.cer` file manually, so a key revoked on the AS may remain trusted by the RP for the length of its cache TTL; conversely an aggressively cached JWKS can cause outages during rotation (a reliability hint that a stale cache exists).
- On a tenant/AS under researcher control, the full oracle set is: (1) sign with the previous key after revocation → accepted? (2) send `kid` values absent from the JWKS → does the verifier try all keys or reject? (3) rotate and immediately check whether both keys are accepted during the overlap.
- OIDC discovery (`jwks_uri`) is also an SSRF/DoS seam: fetching the endpoint from the RP side is a server-side request, and a JWKS containing an `oct`/symmetric key alongside RSA keys invites HMAC confusion if the verifier selects by `kid` alone.

### OAuth 2.1 / RFC 9700 deltas

- RFC 9700 (OAuth 2.0 Security BCP) is the normative anchor. Its verified requirements: AS MUST exact-string match redirect URIs (localhost port numbers excepted for native apps); public clients MUST use PKCE, confidential clients are RECOMMENDED to (an OIDC client MAY instead use `nonce` with the §4.5.3.2 precautions); AS MUST support PKCE; AS MUST enforce `code_verifier` whenever a `code_challenge` was sent; AS MUST mitigate PKCE downgrade by accepting a `code_verifier` only if a challenge was present; S256 is called out as the only challenge method that does not expose the verifier; clients SHOULD NOT use the implicit grant; sender-constrained tokens are SHOULD for access tokens; refresh tokens for public clients MUST be sender-constrained or rotated. [T0 RFC 9700]
- Correction to the older text: PKCE is **MUST** for public clients and **RECOMMENDED** for confidential clients in RFC 9700; the "PKCE for all clients" mandate is the OAuth 2.1 draft, not RFC 9700. Test both shapes: a confidential client that omits PKCE is a deviation from best practice, not necessarily from a MUST.
- RFC 9700 refresh-token rotation semantics: a new refresh token on every refresh, the previous token invalidated, the relationship retained; if a replayed/invalidated token is presented, the AS cannot tell attacker from victim and must revoke the active token (the family dies). Rotation without predecessor invalidation, or a static reusable refresh token for a public client, is the finding. Refresh tokens MUST be bound to the consented scope and resource servers, MAY be revoked on password change/logout, and SHOULD expire on inactivity. [T0 RFC 9700]
- OAuth 2.1 (draft-ietf-oauth-v2-1-16 at fetch time) replaces and obsoletes RFC 6749 and RFC 6750 and folds in the BCP. Verified deltas beyond RFC 9700: PKCE `plain` is explicitly forbidden; clients MUST use `code_challenge`/`code_verifier` and AS MUST enforce them (limited exception path for OIDC `nonce`); AS MUST require complete redirect URI registration and reject non-exact matches; clients MUST NOT send access tokens in the URI query and resource servers MUST ignore query tokens; a client MUST NOT use more than one token transmission method per request; the Implicit and Resource Owner Password grants are not specified. [T0 OAuth 2.1]
- Response-mode and parameter hygiene: fragment-delivered tokens leak via referrer/history where code flow does not; `state` must be bound to the user agent's session (a value that round-trips to a *different* session is a binding failure, not just CSRF).
- Mix-up defense (RFC 9207): with more than one AS, the client should validate the `iss` in the authorization response against the AS it intended. Absence of `iss` validation plus a second AS reachable is the classic multi-IdP client-side confusion.
- Probe order for a code-flow client: (1) send `code_verifier` without a prior `code_challenge`; (2) reuse a code; (3) reuse a verifier across two codes; (4) swap a confidential client's `client_secret` for none; (5) replay a rotated refresh token and then the successor.

OAuth 2.0 → RFC 9700 / 2.1 delta table:

| Element | 2.0 baseline | RFC 9700 / 2.1 requirement | Bypass shape to test |
|---|---|---|---|
| PKCE | optional, public clients | public MUST (9700); all clients MUST (2.1 draft); `plain` forbidden (2.1) | missing/blank `code_verifier`; verifier not bound to code/`state` |
| PKCE downgrade | n/a | AS accepts `code_verifier` only if `code_challenge` was sent (§4.8.2) | verifier-only token request succeeds |
| Implicit grant | allowed (`response_type=token`) | 9700 clients SHOULD NOT; 2.1 omits it | legacy client still minting a fragment token |
| ROPC (password) grant | allowed | not specified in 2.1 | legacy token endpoint still accepting the grant |
| Bearer in query | allowed (RFC 6750) | 2.1: clients MUST NOT send, RS MUST ignore | `?access_token=` still accepted by the RS |
| `redirect_uri` match | minimal | exact string match (9700); complete registration + rejection (2.1) | prefix/regex/`@`/`../`/append |
| Refresh (public client) | opaque, reusable | sender-constrained or rotated single-use + reuse detection | static reuse; rotation without predecessor invalidation |
| `iss` in authz response | N/A | RFC 9207 issue + validate | absent/ignored → multi-AS mix-up |
| Sender-constrained access token | N/A | SHOULD (DPoP RFC 9449 / mTLS RFC 8705) | bound token replayed without proof |

### OIDC — id_token and hybrid flows

- `id_token` validation is a superset of JWT validation: `iss`, `aud` (the client_id must be among the audiences), `azp` (if present it MUST be the client_id; absent `azp` with multiple audiences is the audit target), `exp`/`iat`, `nonce` (if sent in the request it MUST be in the token and equal; required in implicit/hybrid responses), and `sub` which is "locally unique and never reassigned **within the Issuer**" — compare `(iss, sub)` pairs, never `sub` alone, or an attacker-controlled second issuer collides accounts. Pairwise identifiers + sector identifier are the anti-correlation control. [T0 OIDC Core]
- The validation sections to name in a report: §3.1.3.7 (code flow, token endpoint), §3.2.2.11 (implicit), §3.3.2.12 (hybrid, authorization endpoint), §3.3.3.7 (hybrid, token endpoint). ID Tokens MUST be signed with JWS; `alg:none` has no place in OIDC.
- Hybrid responses (`code id_token`, `code token`, `code id_token token`) add `c_hash` (binds the authorization code to the id_token) and `at_hash` (binds the access token). The definitions are exact: `at_hash` is the base64url encoding of the left-most half of the hash of the octets of the ASCII access-token value, using the hash named by the id_token's `alg` header (RS256 → SHA-256, take the left 128 bits); `c_hash` is computed the same way over the code. A client that receives the id_token via the front channel but ignores `c_hash` can be fed an attacker's code paired with a victim's id_token. [T0 OIDC Core]
- Probe order: strip `nonce` from the request and see if the token still validates; use a token whose `aud` is a *sibling* client; send an id_token with two audiences and no `azp`; mismatch `c_hash`/`at_hash`; re-parse the token with a second issuer's keys. Each accepted variant is one skipped check.
- Token substitution across deployments: the same `sub` string across two issuers, or an id_token minted for client X replayed to client Y that shares the AS, are the account-confusion classes. Confirm by proving the session resolves to the *other* principal.
- `redirect_uri` in OIDC requires exact match with Simple String Comparison (RFC 3986 §6.2.1) — a deployment that behaves like a prefix match is non-conformant even if the flow completes normally in the happy path. [T0 OIDC Core]
- `acr` is the Authentication Context Class Reference: an OPTIONAL string claim describing the context the authentication satisfied, with "0" meaning the IdP did not apply any specific context class; `auth_time` records when the end-user authentication occurred. They are only meaningful if a downstream consumer enforces them — treat "claim present, never checked" as the finding shape. [T0 OIDC Core]

### SAML — wrapping and assertion confusion

- XML Signature Wrapping (XSW) has ~8 documented variants (XSW1–8): the signed element is relocated, duplicated, comment-split, or wrapped so the signature verifies over one node while the application consumes a *different* (attacker) assertion. The reference attack is Somorovsky et al., "On Breaking SAML: Be Whoever You Want to Be" (USENIX 2012); SAML Raider automates the variants.
- CVE-2024-45409 (ruby-saml) is a document-global XPath (`//`) vs context-relative (`.//`) bug in `validate_signature`, enabling an XSW-style bypass that also affected GitLab via OmniAuth-SAML. Verified affected ranges: ruby-saml ≤ 1.12.2 or 1.13.0–1.16.0 (patched 1.17.0 and 1.12.3); omniauth-saml ≤ 2.1.0 (patched 2.2.0) and ≤ 1.10.3 (patched 1.10.5). (Correction: earlier notes wrote "≤ 12.2", meaning 1.12.2.) [T3]
- CVE-2025-25291 + CVE-2025-25292 (ruby-saml ≤ 1.17.0, fixed 1.18.0): the signature path parses the document with both REXML and Nokogiri, and the two parsers can disagree about which `Signature`/`SignedInfo`/element-with-ID they see. The hash check and the signature check each pass, but over *different* elements — so one valid signature from any assertion (or, in some cases, publicly available signed IdP metadata) lets an attacker fabricate assertions for any user. Lesson: per-library XML parser behavior and element-ID resolution, not "SAML is broken". GitLab shipped fixes in the same window. [T2 GitHub blog]
- NameID XML-comment injection: an attacker who can alter the assertion but not the signature can inject a comment that truncates the parsed NameID to a prefix, authenticating as another user (e.g. authentik GHSA-9wj8-xv4r-qwrp). Test comment/entity handling inside identity attributes, not only response structure.
- Assertion-consumption checks to perturb individually: `Destination` (must equal the ACS URL), `Recipient`, `InResponseTo` (must match the issued request id), `NotBefore`/`NotOnOrAfter`, `Audience`, and `SubjectConfirmationData`. A validator checking signature only accepts replayed or re-targeted assertions.
- Encrypted assertions are their own class (GitHub's own SAML implementation had CVE-2024-9487 around encrypted assertions before it moved to ruby-saml); if the IdP encrypts assertions, test whether the SP validates the signature *after* decryption and whether it accepts an unencrypted attacker assertion alongside an encrypted one. [T2 GitHub blog]

### Passkeys / WebAuthn — platform vs roaming, synced credentials

- Authenticators split by transport and trust: **platform** (Touch ID/Windows Hello — built into the device) vs **roaming** (a USB/NFC key) vs **synced/multi-device** (iCloud Keychain, Google Password Manager). The RP sees them through the same API and must decide policy per authenticator type.
- WebAuthn Level 3 authenticator-data flags: **UP** bit 0, **UV** bit 2, **BE** (Backup Eligibility) bit 3 = `0x08`, **BS** (Backup State) bit 4 = `0x10`, **AT** bit 6, **ED** bit 7. BE is decided at credential creation and is permanent — a backup-eligible credential is a **multi-device credential**, a non-eligible one a **single-device credential**; BS reflects the credential's current backup status and can change over the credential's life. [T1 MDN; T0 WebAuthn L3]
- RP verification steps that matter (assertion ceremony): verify `rpIdHash` = SHA-256 of the expected RP ID; verify the challenge matches the server-issued value; verify `type` is `webauthn.get` (a registration response uses `webauthn.create` and must not be replayable as an assertion); **if the BE bit is not set, verify the BS bit is not set**; if the RP's policy uses backup state, read `currentBe`/`currentBs` and enforce; require UV only if `userVerification` was set to `required` in the ceremony options, and then verify the UV bit. [T0 WebAuthn L3]
- Synced-credential policy trap: an RP that *intends* device-bound step-up but never checks BE/BS accepts a synced (cloud-restorable) credential where a hardware key was expected. The converse is also testable: UV=0 accepted where the app's UX implies a biometric/PIN step-up, or `crossOrigin=true` accepted where the RP never checks `topOrigin`.
- `CollectedClientData` carries `origin`, `crossOrigin` (inverse of `sameOriginWithAncestors`), and `topOrigin` (top-level origin when framed cross-origin). Verification for framed ceremonies must compare `C.topOrigin` against an expected parent origin; the spec formalizes this in the topOrigin verification step (§13.4.9 guidance). [T0 WebAuthn L3]
- Related Origin Requests (ROR): an RP can allow additional origins to use its `rpId` via `https://{rpId}/.well-known/webauthn`. An over-broad or mis-served ROR list widens the origin attack surface; a shared/`eTLD+1` `rpId` lets a sibling subdomain's XSS forge ceremonies for the whole domain — check the `rpId` scope, not just the per-page origin check.
- WebAuthn L3 adds `signalUnknownCredential`, `signalAllAcceptedCredentials`, and `signalCurrentUserDetails` so the RP can tell the platform's credential manager that a credential is gone. Worth testing after account recovery / credential deletion: if the platform still offers a deleted credential and the RP re-registers it, credential lifecycle is broken end to end. [T0 WebAuthn L3]
- Sign-counter handling: some authenticators (and all synced credentials) do not maintain a reliable counter, so strict counter-regression rejection breaks legitimately — the useful test is whether a *cloned* credential is detected, not whether counters are compared. NIST requires replay resistance at AAL2+ and forbids key export at AAL3, so synced (exportable) credentials cannot satisfy AAL3 device-binding claims. [T0 NIST 800-63B-4]

Authenticator / credential model table:

| Authenticator | Transport | BE/BS (L3) | Attacker-relevant property |
|---|---|---|---|
| Platform (Touch ID, Windows Hello) | built-in, no external key | BE=1 for synced platform passkeys (iCloud/Google), BE=0 for device-bound platform keys | ceremony bound to the platform enclave; origin check is client-side |
| Roaming hardware key | USB/NFC/BLE | BE=0 (device-bound) | the "hardware step-up" assumption; counter usually present for clone detection |
| Synced multi-device credential | cloud-backed, portable | BE=1, BS toggles with backup state | survives device loss; an RP intending device-bound step-up must require `BE=0` |
| Cloned credential | — | — | detectable via signature-counter regression where a counter is reliable |

### MFA — enrollment, replay, downgrade

- Enrollment gap: the second factor can be *added* to an account without re-authenticating the first factor (an attacker with a stolen session enrolls their own TOTP and locks out the owner), or removed without re-auth. OWASP's MFA guidance is explicit: factor replacement must require re-authentication with an existing enrolled factor, must not rely solely on the active session, and should notify out-of-band. Test enroll/disable/replace as a privileged action. [T1 OWASP MFA]
- OTP hygiene expectations (the oracle set): short TTL, single use, strict attempt limits, invalidation on successful verification, and resend generates a *new* code that overwrites the old record. The failure shapes are the same OTP twice, old OTP alive after resend, and codes logged or stored plaintext. [T1 OWASP MFA]
- Replay shapes: TOTP/HOTP reuse within the same window, a code accepted twice on parallel requests (race), or a backup-code that does not single-use. An "already used" OTP still accepted is the oracle.
- Downgrade shapes: a component that treats a *pre-MFA* session as authenticated (the "authenticated but not verified" cookie, a refresh token issued before MFA completion, an API scope minted at password step); a second service that reads the same session without re-checking `amr`/`acr`. Enumerate every consumer of the post-password credential.
- Channel/formula downgrade: offering a "remember this device" cookie that bypasses MFA without binding to the device, a legacy endpoint that cannot enforce MFA, or a password-only path that resets the MFA state. Recovery of MFA (lost-device flow) is often weaker than first-factor recovery — test it as its own family. SMS/PSTN factors are a restricted authenticator class in NIST 800-63B-4 (SS7 interception, SIM swap, porting); a deployment that offers SMS as the *only* second factor for a high-value account is a policy finding. [T1 OWASP MFA; T0 NIST]
- Phishing/MFA-fatigue shapes relevant to testing: real-time reverse-proxy phishing (Evilginx/Modlishka/Muraena) captures the post-MFA session rather than the OTP, so session-binding and origin-bound (WebAuthn) factors are the differentiator; push bombing is mitigated by number-matching challenge-response. NIST adds a rate/total cap on push notifications since the last successful authentication, which is directly observable. [T1 OWASP MFA; T0 NIST]
- Assurance levels carry factor requirements, not just session times: AAL2 requires two distinct factors plus replay resistance; AAL3 requires a hardware-based authenticator with verifier impersonation resistance (phishing-resistant) and prohibits key export. A "passkey" rollout that is entirely synced credentials therefore cannot be claimed as AAL3-grade device binding. [T0 NIST 800-63B-4]
- Session-lifetime reference points (NIST 800-63B-4): AAL1 30-day overall reauth; AAL2 24-hour overall or 1-hour inactivity; AAL3 12-hour overall or 15-minute inactivity (rev 3 used 12h overall / 30-min inactivity for AAL2). Compare observed refresh-token/session lifetime against the program's stated assurance level; a session that survives the inactivity window with a usable refresh token is the testable deviation. [T0 NIST]

### Session lifecycle — fixation, regeneration, cross-brand, device binding

- Session ID must be regenerated on authentication (anonymous → authenticated) and on any privilege-level change; OWASP's Session Management Cheat Sheet makes regeneration mandatory at those transitions. A static ID across the login boundary is the fixation precondition.
- Cookie-scope defaults are the cross-brand lever: a cookie set on a shared parent `Domain` (`.brand-a.example` and `.brand-b.example`) travels across brands; `__Host-` prefix rules (no `Domain` attribute, `Path=/`, `Secure`) exist precisely to stop subdomain/domain-scope overwrite — a session cookie *without* the prefix on a shared domain is a cross-brand fixation surface.
- `SameSite` default and `Domain` handling differ by framework and browser generation; the server-side invalidation behavior (does logout, password change, or MFA change kill *all* sessions or just the current one?) is what matters — test each transition against every parallel session (web, mobile, API key).
- Logout/session-revocation gaps: a refresh token that survives logout, a mobile token that survives a web password change, or "log out all devices" that only clears the current row. Confirm by making a request with the supposedly-revoked credential.
- Sensitive-change gating: OWASP expects the *current* password or an existing factor for password change, email change, and factor management — otherwise an XSS/CSRF or an unlocked browser turns into account takeover. Pair this oracle with the re-auth-after-risk-events guidance: invalidate sessions and rotate tokens after recovery/reset. [T1 OWASP AuthN]
- Device binding is a distinct control from MFA: a "trusted device" cookie or a bound credential must key off a hardware-backed, non-exportable key (TPM/Secure Enclave/StrongBox) to survive review; a device token that is a plain cookie, or one that is issued without attestation where policy claims hardware assurance, collapses on a cloned/exportable credential. [T1 OWASP MFA]
- Pre-hijacking defenses define what a *secure* session lifecycle looks like — and therefore the gaps to look for: on password reset, sign out all other sessions and invalidate tokens, cancel pending email-change actions, and force review of linked identifiers (email, phone, federated identity). If any of these survive a reset on the target, the unexpired-session / unexpired-email-change pre-hijack shapes are live. [T2 USENIX 2022; T1 MSRC]

### Account recovery, email change, and pre-hijacking

- Reset-token properties to perturb: entropy/predictability, binding to a user identifier (does a token for A work with B's `user_id`?), single-use, expiry, and invalidation on password change. A token that survives its own success is the finding.
- Host-header poisoning: the reset-link origin is often built from `Host`/`X-Forwarded-Host`; pointing the link at a researcher-controlled origin (observed in the test mailbox) proves it without touching a real user. OWASP's guidance is to hard-code the URL origin or validate it against a trusted-domain allowlist, use HTTPS, add `Referrer-Policy: noreferrer` on the reset page, and rate-limit per account (never lock the account on a reset request). [T1 OWASP Forgot Password]
- Reset completion details worth checking: tokens must be single-use and expire; do not auto-login after reset (it adds session complexity); invalidate all existing sessions (or explicitly ask the user). PIN-based flows use 6–12 digit codes delivered out-of-band and create a restricted session that can only set a new password. [T1 OWASP Forgot Password]
- Email-change flow: the OWASP-recommended design is a *pending* change confirmed by time-limited nonces from **both** the old address (notification with a report-activity link) and the new address (confirmation); with MFA, the factor substitutes for the current password; without MFA, the current password is required. A flow that completes with only the new address (or only the session) is the finding, and the reverse direction — old address confirms but the change can be triggered by the attacker — is the same seam. [T1 OWASP AuthN]
- Cross-leg composition: the identifier verified by one leg is often trusted by the next. Test whether an email-reset token can drive a phone change, whether a verified email is enough to enroll MFA, and whether an unverified-but-set attribute (phone/email) short-circuits verification at another step.
- Pre-hijacking, the five documented types (all testable with researcher mailboxes; ~35 of 75 popular services were vulnerable in the 2022 study): (1) **classic-federated merge** — attacker creates a classic account with the victim's email, victim later signs up via SSO, service merges both and keeps attacker access; (2) **unexpired session identifier** — attacker keeps a session alive across the victim's password reset; (3) **trojan identifier** — attacker binds their own email/phone/federated identity, then uses it to recover; (4) **unexpired email change** — attacker leaves a pending change-of-email capability unconfirmed, victim recovers, attacker completes it later; (5) **non-verifying IdP** — attacker uses an IdP that does not verify email ownership and the SP merges by email. [T2 USENIX 2022; T1 MSRC]
- Pre-hijacking root cause: the service lets an account be *used* with an unverified identifier. Prevention (and the checklist to test): require verification before any account action; on merge, require proof of control of both routes; minimize email-change capability lifetime and cap re-requests for unverified identifiers; prune unverified accounts; invalidate pre-MFA sessions when MFA is enabled. [T2 USENIX 2022; T1 MSRC]
- Enumeration and timing: differential responses (or response time) on "unknown account" vs "known account" in reset, registration, and MFA-enrollment flows are account-oracle bugs — verify with two confirmed accounts before claiming. OWASP notes the "quick exit" implementation pattern as the usual timing leak. [T1 OWASP AuthN]

### Magic-link and passwordless token lifecycle

- A magic link is a bearer capability in a URL, so its properties to perturb are: single-use (does a second GET still log in?), short expiry, binding to the requesting browser/session (an unbound link works from any client the attacker controls after intercepting it), and binding to the identifier (does a link requested for `a@x` authenticate `b@x`?).
- Leakage surfaces: token in `Referer` to third-party resources the landing page loads, in server/proxy logs, in email-preview prefetch (link scanners that consume the single use before the user), and in the url after redirect. Prefetch consumption is a real availability/takeover aid — verify by replaying a fetched link. OWASP's control for reset/confirm pages is `Referrer-Policy: noreferrer`, so a missing header plus third-party assets is the reproduction path. [T1 OWASP Forgot Password]
- Token format risk: long random is fine; predictable/sequential or short tokens are enumerable; a token that is the hash of the email is offline-forgeable.
- Passwordless enrollment is the same pre-hijack surface as federated linking: whoever controls the email address first can create the account, so test verification-before-use and the recovery routes attached to the identifier. [T2 USENIX 2022]

### Account linking and consent

- Linking an external identity to a local account is a high-value seam: test whether linking requires proof of control of *both* sides, whether an unverified email from the IdP is trusted for linking (pre-hijack: attacker links before the victim registers), and whether unlinking/re-linking rotates the recovery identity.
- Consent and incremental authorization: a second, less-trusted client requesting added scopes can upgrade a grant; check whether the consent screen is bound to the client and whether "already consented" state skips re-approval for new scopes. RFC 9700 treats scope/consent as an authorization decision, not just UX.
- Open-redirect at the post-consent redirect and `prompt=none` silent re-auth are the shapes that turn consent into a token delivered to an attacker-controlled `redirect_uri`.
- Merge/link semantics are where pre-hijacking lands: when a classic account and a federated login share an email, the correct control is proof of control of *both*; a merge that silently keeps the older (attacker-created) session, trojan email, or pending email-change capability is the vulnerability. [T2 USENIX 2022; T1 MSRC]

### Tenant and object authorization (BOLA/BFLA/mass assignment)

- BOLA: object IDs appear in path, query, headers, and payload, and can be sequential integers, UUIDs, or opaque strings — the API1:2023 guidance is that comparing the session user ID (e.g. from the JWT) with the ID parameter is *not* sufficient; each function that uses a client-supplied record reference needs its own authorization check. [T1 OWASP API1]
- The representation matrix is the test plan: list/search/filter/export/preview/download/history/share/restore, plus batch endpoints, all acting on the same ID. A Guarded primary GET is meaningless if the export or preview path skips the check.
- BFLA: attackers send legitimate-looking calls to functions they should not reach (admin REST routes, internal API versions, GraphQL mutations, gRPC methods). Roles can be layered (sub-users, multi-role users), and services often re-check only at the gateway — probe the function directly with a low-privilege token. [T1 OWASP API5]
- Property-level (mass assignment): the endpoint is vulnerable if it exposes properties the caller should not read (excessive data exposure) *or* lets the caller change/delete properties they should not (mass assignment, the older name). Realistic shapes: a GraphQL mutation returning richer related-object fields, and a client-writable `blocked`/`role`/`is_verified` flag that unlocks other features. [T1 OWASP API3]
- Cross-tenant controls to test: tenant/org ID taken from a client-supplied header or body rather than from the session; list/search/aggregate endpoints that filter in the UI but not in the query; exports and background jobs that re-read objects without the caller's tenant context.
- Multi-object endpoints need per-item checks: compare a multi-ID request against the equivalent single-ID calls; look for authorization computed from the first ID, the count, or the response truncation limit.
- Identifier design matters: sequential/predictable object IDs make an authorization gap trivially exploitable, so prefer random, unpredictable GUIDs as a defense-in-depth control — a program using random IDs is not immune, it just raises the cost of enumeration. [T1 OWASP API1]

### Deployment fingerprinting (do this before choosing a payload)

1. Identify the token format and consumer count: decode a real token's header (`alg`, `kid`, `typ`), list every endpoint/service that accepts it, and note which reject identity but not signature.
2. Read the key material the app publishes (`/.well-known/jwks.json`, `x5c`, a public key in JS) — that is the base for `alg`-confusion and `kid`/`jku` forgery without touching private keys. Record how many keys are published and whether symmetric (`oct`) keys are mixed in.
3. Fingerprint the library from error strings, `WWW-Authenticate` detail, and timing; map it to the behavior matrix above, then test the one call site that omits algorithm pinning.
4. For OIDC, capture the authorization response and mark which of `iss`, `nonce`, `azp`, `c_hash`, `at_hash` are present — absent bindings are the skippable checks.
5. For SAML, decode both the Response and the Assertion, locate the signed node, and check whether identity attributes (`NameID`, `SubjectConfirmation`) live *inside* the signed node; note every element with an `ID` attribute that a signature reference could resolve to.
6. Record the framework/session defaults (regeneration, cookie scope, logout fan-out) once, then apply uniformly — most session bugs are deviations from the framework's own default.
7. Map the lifecycle: registration routes (classic/federated), verification-before-use or not, email-change nonces, MFA enroll/disable gates, and what a password reset invalidates — that map is the pre-hijacking and recovery-chain test plan. [T2 USENIX 2022]

### Cross-family ATO chains (compose verified primitives, do not stack guesses)

| Chain | Leg 1 (entry) | Leg 2 (escalation) | Leg 3 (persistence) | Oracle per leg |
|---|---|---|---|---|
| Email-reset → email change | reset token for A | change email after reset | enroll MFA as A | read-back of B's profile fields |
| Pre-MFA session → API scope | cookie minted post-password | call API with that cookie | refresh token issued pre-MFA | request that skips the MFA gate |
| IDOR → credential takeover | read A's object as B | leak A's reset/API-key ID | rotate A's key via B's session | victim-context re-read |
| SAML XSW → SSO persistence | forged assertion for target | consume `NotOnOrAfter`-valid assertion | bind attacker IdP to target | session resolves to the target identity |
| Passkey enroll → lockout | enroll attacker credential on A | remove A's existing factor | no MFA left | A's own login fails afterwards |
| Pre-hijack → post-recovery | unverified account/trojan identifier | victim registers and recovers | pending email-change or session completes | attacker-side leg authenticates after recovery |
| JWE bomb → availability | compressed JWE / huge `p2c` to token endpoint | worker stalled | retry loop | latency/memory delta with a valid control token |

## References

- [T0 standards] RFC 9700, Best Current Practice for OAuth 2.0 Security (exact redirect matching, PKCE role per client type, PKCE downgrade, refresh rotation/replay, sender-constrained tokens): https://www.rfc-editor.org/rfc/rfc9700.html
- [T0 standards] OAuth 2.1, draft-ietf-oauth-v2-1-16 (obsoletes RFC 6749/6750; PKCE for all clients, `plain` forbidden, exact redirect registration, no bearer tokens in query): https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/
- [T0 standards] RFC 9207, OAuth 2.0 Authorization Server Issuer Identification (mix-up defense): https://www.rfc-editor.org/rfc/rfc9207.html
- [T0 standards] RFC 8725, JSON Web Token Best Current Practices: https://www.rfc-editor.org/rfc/rfc8725.html
- [T0 standards] RFC 9449, OAuth 2.0 Demonstrating Proof of Possession (DPoP): https://www.rfc-editor.org/rfc/rfc9449.html
- [T0 standards] RFC 8705, OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Tokens: https://www.rfc-editor.org/rfc/rfc8705.html
- [T0 standards] RFC 7519 (JWT), RFC 6749 (OAuth 2.0), RFC 7636 (PKCE), RFC 6750 (Bearer)
- [T0 standards] OpenID Connect Core 1.0 incorporating errata set 2 (`azp`, `nonce`, `at_hash`/`c_hash`, `sub` uniqueness, ID Token validation sections 3.1.3.7 / 3.2.2.11 / 3.3.2.12 / 3.3.3.7): https://openid.net/specs/openid-connect-core-1_0.html
- [T0 standards] Web Authentication Level 3 (authenticator data flags, BE/BS verification steps, topOrigin/crossOrigin, rpId/origin binding, related-origin requests, signalUnknownCredential): https://www.w3.org/TR/webauthn-3/
- [T0 standards] NIST SP 800-63B rev 3 (AAL reauth: AAL2 12h/30min) and SP 800-63B-4 (AAL1 30d; AAL2 24h/1h; AAL3 12h/15min; replay resistance; key export permitted AAL1–2, prohibited AAL3; PSTN restricted): https://pages.nist.gov/800-63-3/sp800-63b.html ; https://pages.nist.gov/800-63-4/sp800-63b.html
- [T1 vendor] FIDO Alliance, WebAuthn Level 3 is a W3C Recommendation (BE/BS synced-vs-device-bound): https://fidoalliance.org/webauthn-level-3-is-now-a-w3c-recommendation/
- [T1 vendor] MDN, Authenticator data (flag bit numbers: UP 0, UV 2, BE 3, BS 4, AT 6, ED 7): https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data
- [T1 vendor] passkeys.dev, Related Origin Requests: https://passkeys.dev/docs/advanced/related-origins/
- [T1 vendor] OWASP Session Management Cheat Sheet (regeneration on privilege change): https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- [T1 vendor] OWASP OAuth2 Cheat Sheet (sender-constrained/rotating refresh tokens): https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
- [T1 vendor] OWASP Authentication Cheat Sheet (re-auth for sensitive features, re-auth after risk events, registered email change process, enumeration timing): https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- [T1 vendor] OWASP Multifactor Authentication Cheat Sheet (OTP single-use/TTL/resend, factor replacement re-auth, MFA fatigue, reverse-proxy phishing, SMS restriction): https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
- [T1 vendor] OWASP Forgot Password Cheat Sheet (host-header-safe links, token properties, no auto-login, session invalidation, PIN flows): https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
- [T1 vendor] OWASP API Security Top 10 2023: API1 BOLA (ID in path/query/headers/payload; session-ID comparison insufficient): https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- [T1 vendor] OWASP API Security Top 10 2023: API3 Broken Object Property Level Authorization (excessive data exposure + mass assignment): https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- [T1 vendor] OWASP API Security Top 10 2023: API5 BFLA (regular users reaching privileged functions): https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
- [T1 vendor] OWASP Cheat Sheet Series (authentication, authorization, identity management)
- [T1 vendor] MDN Set-Cookie (cookie prefixes `__Host-`/`__Secure-`, Domain/Path scope): https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie
- [T1 vendor] Auth0, Rotate Signing Keys (discovery always publishes current + next key, previous key valid until revoked, JWKS cache interval): https://auth0.com/docs/get-started/tenant-settings/signing-keys/rotate-signing-keys
- [T1 vendor] Microsoft MSRC, Pre-hijacking attacks on web user accounts (five attack types, prevention checklist): https://www.microsoft.com/en-us/msrc/blog/2022/05/pre-hijacking-attacks
- [T1 vendor] IBM, What is XML Signature wrapping (XSW): https://www.ibm.com/think/topics/xml-signature-wrapping
- [T2 research] Sudhodanan & Paverd, "Pre-hijacked accounts: An Empirical Study of Security Failures in User Account Creation on the Web", USENIX Security 2022: https://www.usenix.org/conference/usenixsecurity22/presentation/sudhodanan
- [T2 research] GitHub Security Lab, "Sign in as anyone: Bypassing SAML SSO authentication with parser differentials" (CVE-2025-25291/25292, REXML vs Nokogiri): https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/
- [T2 research] PortSwigger Web Security Academy: access control (BOLA/BFLA), JWT attacks, OAuth/OIDC, SAML, MFA and session handling: https://portswigger.net/web-security/jwt
- [T2 research] Somorovsky et al., "On Breaking SAML: Be Whoever You Want to Be", USENIX Security 2012: https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf
- [T3 vuln intel] CVE-2015-9235 (jsonwebtoken alg-confusion verification bypass < 4.2.2): https://nvd.nist.gov/vuln/detail/CVE-2015-9235
- [T3 vuln intel] CVE-2022-23539 / CVE-2022-23540 / CVE-2022-23541 (jsonwebtoken ≤ 8.5.1: key-type confusion, `none` default, RSA→HMAC; fixed 9.0.0): https://github.com/advisories/GHSA-8cf7-32gw-wr33 ; https://security.snyk.io/vuln/SNYK-JS-JSONWEBTOKEN-3180022 ; https://github.com/advisories/GHSA-hjrf-2m68-5959
- [T3 vuln intel] CVE-2022-29217 (PyJWT key confusion through non-blocklisted public-key formats): https://github.com/advisories/GHSA-ffqj-6fqr-9h24
- [T3 vuln intel] CVE-2024-33663 (python-jose < 3.4.0 algorithm confusion with OpenSSH ECDSA keys): https://github.com/advisories/GHSA-6c5p-j8vq-pqhj
- [T3 vuln intel] CVE-2024-33664 (python-jose JWE "token bomb" via high compression ratio): https://nvd.nist.gov/vuln/detail/CVE-2024-33664
- [T3 vuln intel] CVE-2024-28176 (node `jose` ≤ 4.15.4 JWE decompression resource exhaustion; fixed 4.15.5/2.0.7; v5 removed compression): https://github.com/advisories/GHSA-hhhv-q57g-882q
- [T3 vuln intel] CVE-2025-30204 (golang-jwt ParseUnverified memory amplification; fixed v4.5.2/v5.2.2): https://github.com/advisories/GHSA-mh63-6h87-95cp
- [T3 vuln intel] CVE-2023-52428 (nimbus-jose-jwt < 9.37.2 JWE `p2c` iteration-count DoS): https://nvd.nist.gov/vuln/detail/CVE-2023-52428
- [T3 vuln intel] CVE-2024-21319 (.NET IdentityModel JWE compression DoS; fixed 5.7.0/6.34.0/7.1.2): https://github.com/advisories/GHSA-59j7-ghrg-fj52
- [T3 vuln intel] CVE-2022-21449 "Psychic Signatures" (Java 15–18 ECDSA blank-signature verification): https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/
- [T3 vuln intel] CVE-2024-45409 (ruby-saml ≤ 1.12.2 / 1.13.0–1.16.0 SAML response verification bypass; patched 1.17.0 and 1.12.3; omniauth-saml ≤ 2.1.0 → 2.2.0): https://github.com/SAML-Toolkits/ruby-saml/security/advisories/GHSA-jw9c-mfg7-9rx2
- [T3 vuln intel] CVE-2025-25291 / CVE-2025-25292 (ruby-saml ≤ 1.17.0 XML parser differential authentication bypass; fixed 1.18.0): https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/
- [T3 vuln intel] authentik SAML NameID XML-comment injection authentication bypass: https://github.com/goauthentik/authentik/security/advisories/GHSA-9wj8-xv4r-qwrp
