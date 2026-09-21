# Business Logic & State

> SCOPE: Load when testing multi-step workflows (order, payment, coupon, referral, approval, linking) or any one-time, time-bound, or permission-gated transition.

## Research families

Workflow and gate families:

- Workflow step skip, repeat, replay, and cross-flow substitution
- One-time action reuse (coupon, invite, verify, redeem, trial)
- State resurrection (expired, consumed, deleted, or revoked state reused)
- Status rollback and downgrade races
- Alternate routes to the same terminal state
- Permission transitions mid-workflow (role change during approval)
- Time-bound offer and trial windows (expiry enforced server-side or client-side only)
- Hidden sub-states and state-machine skips (a single request that internally walks check → act → commit; a terminal endpoint that an earlier step was supposed to gate)

Money and entitlement families:

- Price, quantity, discount, and currency invariant violations
- Referral, loyalty, and gift-card balance abuse
- Order, cart, payment, refund, and return lifecycle gaps
- Refund / chargeback invariants (refund must not exceed the captured amount; a refund must correspond to a captured charge; a return must precede a refund)
- Numeric and currency-exponent abuse (minor-unit confusion, split-order rounding, negative or zero amounts, float-money drift)

Idempotency and event families:

- Idempotency-key reuse on retries and webhooks; gateway-level vs backend-level enforcement mismatch
- Payment-provider webhook semantics — signed vs unsigned, replayable, and unordered event delivery used as an alternate state driver
- Double-credit / double-spend via webhook redelivery racing the client-side confirmation path
- Provider-event trust split — unsigned, signed-but-unverified, verified-but-replayable, or bound to only one endpoint/tenant
- Provider-event ordering conflicts (a stale event applied after a terminal one because the handler applies by arrival order)

Identity-linking families:

- Account linking, unlinking, and merge confusion (OAuth, email, phone, device; merge/unlink ordering)
- Re-registration and identity overwrite (case variants, unverified-address reuse, unlink → re-register with the same identifier)

Concurrency families:

- Race and TOCTOU on redeem, transfer, apply, withdraw, approve, and linking
- Partial-construction races (object persisted before its security fields are initialized)
- Session-serialized processing masking or hiding races
- Multi-endpoint races (two endpoints mutating the same record inside one parallel group)
- Chargeback / dispute abuse (refund a disputed charge, then re-refund after funds are reinstated)
- Coupon / code enumeration (brute-forcing codes; timing or response differences between valid and invalid codes)
- Gift-card / store-credit laundering (transfer between research accounts, split tender, credit-to-cash)
- Fee / tax / currency invariants (fee computed once not per retry; tax on the discounted total; rounding not gameable by splitting an order)
- Subscription lifecycle (trial-only abuse, proration minting, cancel-then-resume windows)
- Onboarding / verification abuse (repeat signup bonuses, device-dedupe bypass)
- Webhook-as-state-machine (using provider events, signed or otherwise, to force transitions the UI forbids)

## Preconditions

- A modeled invariant exists before testing (e.g. "coupon single-use", "price non-negative", "approval precedes activation", "refund requires return") — the finding is the violated invariant, not odd behavior.
- Researcher control of all participating accounts, payment instruments (test cards, zero-value flows), and state transitions end to end.
- For race findings: a check-then-act window (balance check before debit, coupon validation before apply, counter increment after action) reachable with parallel requests.
- For resurrection: a terminal state (consumed, expired, refunded, deleted) whose identifier remains accepted by at least one endpoint.
- For linking confusion: two linkable identities (OAuth, email, phone, device) where link/unlink ordering can be manipulated, and a merge path that keeps one side's entitlements while dropping the other's checks.
- For expiry gaps: a time-bound entitlement (trial, offer, coupon window) whose expiry is displayed client-side but may not be re-checked on the redemption endpoint.
- Program policy permits the commerce surface under test — price/quantity logic is tested only where the policy allows, and never with real funds movement.
- For TOCTOU classification: record whether the window sits between check and act inside one service (code fix) or across services/webhooks (ordering and idempotency fix) — the remediation differs.
- For webhook-driven findings: the platform must be observable end to end (you can see the provider dashboard or API events *and* the resulting app state), and you can obtain or replay a signed event from a test-mode provider without affecting a third party.
- For webhook handlers, know the ack/process order: Adyen's documented sequence is verify → store in a queue → ack → process. A handler that processes synchronously and then fails its ack is retried, so "duplicate processing" can be the provider reacting to your own failed acknowledgement.
- For webhook trust specifically: treat "unsigned", "signed-but-unverified", and "verified-but-replayable" as three distinct hypotheses; the raw-body-vs-parsed-body mismatch (a JSON body-parser running before the HMAC check) is the most common enforcement gap.
- For idempotency findings: the gateway contract must be distinguishable from the backend effect — send the same key twice and read the *ledger*, not the response body, because many gateways echo the first response regardless.
- For race-window shape: know which synchronisation primitive the stack supports before starting — H2 multiplexing (single-packet), H1 keep-alive (last-byte sync), or neither.
- For provider-specific claims: know the key's retention/scope before designing the retry test — Stripe prunes keys once ≥24 h old, Adyen keys are company-scoped and valid 7–14 days, PayPal retention is per-API and not every API supports the header; a "duplicate" after the documented window is expected behavior.
- For refund/dispute testing: distinguish authorization, capture, refund, and dispute states in *both* the app model and the provider's model, and read the provider's status as the source of truth; test-mode disputes only.
- For currency/rounding tests: know the ISO minor-unit exponent for the currency pair in play (Stripe amounts are integers in the minor unit; zero-decimal currencies differ) and whether the app stores money as a float (decimal/float drift becomes a finding only if systematic).
- For re-registration tests: control the address in several spellings (case variants, plus/dot aliases where the platform treats them as one identity) and an unverified first account to compare verified vs unverified paths.
- For state-skip tests: a direct-reachable terminal endpoint whose guard is client-side; capture a legitimate step token first so the test can replay a believable flow.
- For partial-construction races: a registration/creation flow that writes the record and its security attribute in more than one step, and an input primitive that can match an uninitialized value (empty array, `null`, empty string).

## Oracles

Core invariant oracles:

- Invariant ledger: starting balance/entitlement recorded, action executed, ending state differs from the policy-predicted state by a measurable amount (double credit, negative price accepted, spent coupon reusable).
- Replay acceptance: identical one-time request (same idempotency key, token, or coupon) succeeds twice with cumulative effect — verify via read-back of both resulting states.
- Skip differential: omitted-step flow reaches the terminal state (activated, approved, shipped, paid) with the skipped gate never enforced server-side.
- Resurrection: terminal-state identifier (used coupon, refunded order, deleted invite) accepted again for full effect.
- Race confirmation: 2 parallel identical requests both succeed where 2 sequential ones produce one success plus one rejection — scale to 5/10 only if the 2-request signal is clean.
- Link confusion: unlink/relink ordering moves entitlements, sessions, or verified identifiers between researcher accounts in a way the UI denies.
- Alternate route: disallowed transition (downgrade without approval, refund without return, admin activation via support flow) reaches the same terminal state as the guarded path.
- Idempotency failure: retried request with the same idempotency key executes the effect twice — verify via ledger read-back, not response text.
- Expiry bypass: redemption accepted after the displayed window closed, with the entitlement granted and ledger moved.

Per-family oracles (new depth):

- Webhook replay / forgery: a captured provider event (or a hand-crafted one, if the endpoint does not verify the signature) can be re-sent later and still moves state — observe a second order marked paid, or a second credit, from a single provider event.
- Webhook ordering: send the provider's *later* event before its *earlier* event (or rely on the provider's own out-of-order delivery) and observe a terminal state ("refunded") being overwritten by a stale state ("captured") because the handler applies events blindly by arrival order.
- Idempotency enforcement split: the gateway returns the cached first response while the backend still wrote a second row/ledger entry — the two disagree, so the effect doubled even though the HTTP response looked idempotent.
- Idempotency conflict signals per gateway (use these to localize where enforcement lives): Adyen returns 422/409 with error code 704 "request already processed or in progress" and a `transient-error: true` header on the racing request; Stripe does not save a result when the request conflicts with a concurrent one, so a retry may legitimately reprocess; PayPal "processes the first request and might fail the second request" when the same `PayPal-Request-Id` arrives simultaneously.
- Idempotency-echo oracle: Adyen returns the `idempotency-key` header on the response when it processed the request idempotently — a missing echo means the request was treated as new. Adyen also does not check keys across regional endpoints, so the same key sent to two regions can legitimately produce the effect twice (documented scope limit, still app-visible).
- Stale-snapshot oracle: Braintree notifications carry a snapshot of the entity at trigger time and may arrive out of order — replaying an older notification over a newer one must not roll the app's record back; the signed payload's timestamp is the comparison point.
- Replay-window shape per provider (what must be checked to call an accepted replay a finding): Stripe signature carries a timestamp and libraries default to a 5-minute tolerance (a tolerance of `0` disables the recency check entirely — a config bug, not a provider property); Square signs `notification URL + raw body` with no timestamp or nonce; GitHub signs the body with no timestamp. For the last two, a captured event is replayable indefinitely *unless the app dedupes by event id* — the finding is the state movement, not the absence of a timestamp (derived from the documented signing inputs).
- Refund state-machine oracle: a refund is not a 1-bit "done" — Stripe refunds move through `pending` → `succeeded`, can stall in `requires_action` (customer must supply bank details before an expiry), or end `failed`/`canceled` with a `failure_reason` (`charge_for_pending_refund_disputed` means the customer disputed the charge while the refund was pending; Stripe recommends accepting/challenging the dispute instead, to avoid a duplicate reimbursement). An app that marks only `refund.created` as "refunded" diverges from the provider's terminal state.
- Double-refund via bank-debit race: for SEPA/Bacs/ACH-style debits, a proactive app refund plus a customer-initiated dispute can both credit the customer ("risk of double refund" per Stripe) — test-mode branch only.
- Chargeback lifecycle oracle: a dispute immediately reverses the payment and debits the balance plus network fees; it is not the same as a refund. Stripe notifies `charge.dispute.created`; an inquiry is a *pre-dispute* stage, and if it escalates the merchant must respond again. Resolution closes as `won` (debited amount returned to you) or `lost` (permanent). `charge.dispute.funds_reinstated` fires when funds are reinstated after closure — an app that also fires its own refund path can double-credit.
- Rounding / minor-unit oracle: fractional amounts created by proration, coupons, or taxes are rounded by the provider for some currencies (UGX invoices round to the nearest value divisible by 100, with the difference credited or debited to the customer balance) — if the app rounds differently, the balance delta becomes visible. Split one order into N small ones and compare total charged/tax against N=1 (line-level vs document-level tax rounding is a documented vendor-behavior explanation — see false positives).
- Currency-exponent oracle: the API integer means different money per currency (`100` is 1.00 USD but 100 JPY, because JPY is zero-decimal) — put the same integer into a zero-decimal flow and a two-decimal flow and read the charged amount; a backend that treats every amount as cents gives a 100× error class.
- State-skip oracle: submit the terminal action (activate, confirm, ship, approve) directly with the step-1 token or none; read the resulting object's server state, not the redirect or the toast. Flip the step order, resubmit an old step after the terminal step, and repeat the terminal step once more.
- Partial-construction oracle: during a create race, a second request reads the record while its key/flag is uninitialized and passes a guard (e.g. an empty-array API key matches the unset value; a `nil`/null value compares equal). PortSwigger's PHP/Rails array syntaxes (`param[]`, `param[key]` with no value) are the classic inputs.
- Session-serialization check (also a false-positive filter): if all parallel responses arrive sequentially, the framework (e.g. PHP's native session handler) may process one request per session at a time — retry the same group with a distinct session token per request before concluding "no race".
- Single-endpoint race oracle: one endpoint, two values, one shared slot — e.g. two parallel password-reset requests from one session with different usernames can leave the *victim's* user id with the *attacker's* token in the session. Email-sending flows are prime targets because mail often runs after the response.
- Re-registration takeover oracle: a case-variant or alias of an address that the identity layer treats as the same, used to (a) create a second account over an unverified first one, or (b) receive the first account's reset mail — the observable is which account the reset link authenticates (Vine: the overwritten, unverified account became unreachable because resets then targeted the new account).
- Merge/unlink entitlement transfer: after a merge, the surviving account keeps both identities' currencies/credits, or after an unlink a verified identifier still grants access to the other account's data.
- Trial/offer window: redemption accepted with the offer removed from the catalog, or with a client-only countdown that the redemption endpoint never re-checks.
- Return / subscription double-dip: one return issues both store credit and a card refund (or two refunds), or a rapid upgrade→downgrade cycle leaves account credit exceeding the paid plan value.
- Signature bypass: a captured event with a modified body/amount is acted on (signature not enforced), or a valid event bound to one endpoint/tenant is accepted at another (shared secret, no endpoint binding).
- Signature-input oracle: recompute the signature over the documented input and diff against the header — Adyen signs a colon-joined field string (`pspReference:originalReference:merchantAccountCode:merchantReference:value:currency:eventCode:success`, empty fields as empty strings), Square signs `notification URL + body`, Shopify signs the raw body with the app secret, GitHub signs the body with the webhook secret and prefixes `sha256=`. A handler that verifies a different input (parsed body, re-serialized JSON) fails the tamper test.
- Fee / currency oracle: splitting one order into many small ones lowers the total fee/tax in your favor, or a cart-vs-charge currency mismatch changes the effective price — reconcile against the captured charge, not the cart total.
- Code-enumeration oracle: a significant difference (status, body, or latency) between valid and invalid codes over a small bounded sample reveals a brute-forceable code space — stop at the smallest sample that shows the signal.
- Mid-flight privilege change: start an approval as role X, revoke the approver's role mid-flow, and check whether the already-issued approval still activates the target (permission transition applied after the gate).

## Minimal safe proof

1. Write the invariant and the forbidden transition explicitly before testing; record baseline state (balances, coupon status, order status) with timestamps.
2. Single-actor, minimum-value tests: use smallest denominations, researcher-owned instruments, and one repetition beyond the allowed count — never scale a working exploit for effect size.
3. Replay tests reuse the exact original request once; race tests start with exactly 2 parallel requests (single-packet or last-byte sync only if the 2-request signal needs disambiguation) — never sustained parallel floods.
4. Confirm by read-back in both accounts (actor and counterparty) and reconcile the ledger: expected vs observed, with request/response pairs preserved.
5. Expiry probes use a just-expired researcher entitlement first (seconds past the window) before testing older states — minimizes dispute about clock skew.
6. Webhook probes use a provider test-mode event re-sent to your own endpoint (or a self-signed event created with a test secret); never replay a real customer event and never target another tenant's endpoint. Mint test-mode events with provider tooling (Stripe CLI `stripe trigger` / `stripe listen`, PayPal's webhook simulator, Square API Explorer, a Shopify dev tunnel) so the event is test-mode by construction.
7. Race priming: warm the connection first, choose the correct primitive for the stack (H2 single-packet vs H1 last-byte sync), and keep the concurrency to the smallest count that shows the signal — a working 2-request race is the finding, a flood is not.
8. Race controls: send the same group *sequentially* first to benchmark normal behavior, then in parallel; if every response looks sequential, switch to a different session token per request before calling it a non-race.
9. Idempotency tests: same key + same payload (should be inert) versus same key + changed payload (should be rejected) versus a *new* key after a timeout (the realistic duplicate) — and one delayed retry just inside vs just outside the provider's documented retention (Stripe ≥24 h, Adyen 7–14 days).
10. State-skip tests: capture a legitimate step-1 token, call the step-3/terminal endpoint directly, and read the resulting object; do not confuse a redirect with a state change.
11. Currency/rounding tests: charge the smallest allowed amount once, then split the same basket into small units and compare the total against the one-shot control; read the provider ledger and the app's balance ledger separately.
12. Linking/re-registration tests: link A→B, unlink, re-link, then register a case-variant/alias of B's identifier and observe which account resets and which sessions survive.
13. Clean up: cancel test orders, void test coupons where possible, unlink test identities, and leave balances as close to baseline as the platform allows.
14. Stop conditions: real funds move, third-party entitlements change, irreversible terminal state reached on a non-test record, rate-limit or fraud-control intervention, or any signal the parallel load affects shared infrastructure — halt, document, revert, report.

## False positives

- Client-side price or quantity display glitch where the server recalculates correctly at charge time — rule out by checking the server-side ledger, not the UI.
- Coupon rejected on second use with identical error and no state change — single-use enforced; require cumulative effect on read-back.
- Parallel requests where the second correctly fails (one success, one rejection) — race mitigated via atomic check; require dual success.
- Test-mode or sandbox balances that reset automatically and are documented as non-persistent — environment behavior; require the violation in the assessed environment.
- Skipped UI step that the server still enforces on submit (server rejects the incomplete flow) — client-only gating; require terminal-state reachability.
- Expired-state identifier returning cached success text without state effect (stale client cache, no ledger change) — require ledger movement.
- Referral self-credit blocked by device, payment, or identity deduplication that actually holds on read-back — require the credited ledger entry.
- Retry that the server deduplicates correctly under the same idempotency key (single ledger effect) — require the double effect on read-back.
- Expiry correctly enforced server-side where only the client display lagged (server rejects, no ledger movement) — require the granted entitlement.
- Optimistic UI that self-corrects on refresh with no server state change — require the ledger movement, not the transient display.
- Browser back/forward and bfcache: the browser can restore a full in-memory snapshot of the page (including the JS heap) without any request, so old balances/statuses can reappear on Back — confirm with a fresh load or a fresh session before treating the rendering as server state.
- A provider webhook that is *signed but correctly verified* — the endpoint rejects a tampered body; the finding requires the endpoint to act on an unauthenticated or unverified event, not merely to receive one.
- A duplicate webhook that the handler correctly deduplicates by the provider's event id (single ledger effect) — the fix is present; require the second effect.
- Multiple deliveries of one logical event that are *expected*: Shopify sends one delivery per subscription (distinct `X-Shopify-Webhook-Id` but the same `X-Shopify-Event-Id`), Adyen redelivers with the same `eventCode`/`pspReference` and a later `eventDate` (use the latest), and every provider's retry loop re-sends the original event id — none of these are replay vulnerabilities by themselves.
- Gateway "idempotency" that only de-duplicates the HTTP response while the backend is naturally idempotent — no double effect, so no finding.
- A refund over-run that is actually the provider's documented authorization hold behavior (hold released then re-authorized) — check the provider dashboard, not just the app ledger.
- Clock-skew grace windows: a seconds-late acceptance inside a documented skew/tolerance window is not an expiry bypass; require effect beyond the plausible margin.
- Event ordering that looks wrong in the app but is self-healing (a reconciliation job corrects the ledger within its run interval) — require the wrong state to persist past the reconciliation window.
- Provider sandbox that auto-refunds / resets test balances — environment behavior; require the violation in a persistent environment.
- Idempotency "failure" measured after the key-retention window (Stripe prunes keys once ≥24 h old; Adyen keys last 7–14 days) — a new request is expected there; demonstrate the double effect *within* the retention window to call it a finding.
- Fee/rounding drift within one minor unit of the documented policy — not a finding unless the gain is systematic and repeatable.
- Documented rounding-mode differences: line-level rounding rounds each line before summing, document-level rounding sums then rounds (Avalara's documented switch explains cents-level tax drift; align the two systems before calling it a bug). Note that this is a *benign explanation*, not a defense for a repeatable split-order gain.
- Zero-decimal display confusion: `amount: 1000` for JPY is ¥1000, not ¥10.00 — a developer's cents-assumption is a bug only if it changes the money actually moved; verify against the provider's amount, not the app's formatted string.
- Refund states that are waiting, not failing: `requires_action` means the customer must supply bank details before an expiry; a refund that later transitions is not a lost-funds bug.
- Provider retries with an interval: Braintree retries hourly (up to 3 h sandbox / 24 h production) and PayPal retries up to 25 times over 3 days; a "duplicate" inside the retry window with the same event id is expected.
- PayPal mock events (`WEBHOOK_ID`) cannot be validated via the postback endpoint — a failed postback verification against a mock is a test artifact, not a signature bypass.
- Re-registration with the same address on a platform that intentionally allows 1:N account-to-email mapping (Reddit triaged exactly this as Informative) — check the platform's stated identity model; the finding exists only where the second registration overwrites or captures the first identity (Vine-style case-variant overwrite), or where the reset flow routes to the wrong account.
- Coupon-code timing difference that is noise — require a signal that survives against interleaved known-valid and known-invalid controls.
- An "unverified webhook" endpoint that nonetheless dedupes by event id and therefore never double-applies — the trust gap is real but the impact needs the second effect (report as hardening, not as a critical finding).

## Version/implementation notes

Webhook trust: signature *present* vs signature *enforced* (three separate hypotheses):

- **No signature** — the endpoint accepts any `POST`; the finding is any state change from a hand-crafted event. Test one unsigned event against your own account.
- **Signature present but not verified** — the provider sends a signature header, but the handler ignores it, or verifies the *parsed* body instead of the raw bytes (the classic bug: `express.json()` runs before the HMAC check). Re-send a captured event with a modified amount/status and see whether it is acted on.
- **Verified but replayable** — no timestamp/anti-replay check, so a captured event is accepted indefinitely; or the signing secret is shared across endpoints/tenants, so a valid signature from one endpoint passes at another.
- IP allowlisting is defense-in-depth, not verification: an endpoint that trusts the source IP without a signature is only as strong as the provider's egress path (and can be defeated if the app trusts `X-Forwarded-For` upstream).

Signing schemes per provider (what the signature covers, and its replay edges):

- Stripe: `Stripe-Signature` header, HMAC over the raw body with the endpoint's `whsec_` secret; the header includes a timestamp that is part of the signed payload, and official libraries default to a **5-minute** tolerance (a tolerance of `0` disables the recency check). Timestamp and signature are regenerated for every retry delivery, so a re-delivered event carries a fresh valid signature. Secrets are per endpoint, and rolling a secret keeps both old and new active for up to 24 hours (one signature per secret until expiry).
- Adyen: HMAC signature over a colon-joined field string of the event item (`pspReference:originalReference:merchantAccountCode:merchantReference:value:currency:eventCode:success`, empty fields as empty strings), key is a hex secret converted to binary, HMAC-SHA256, Base64. Standard webhooks carry it in `additionalData.hmacSignature`; other webhook types carry it in the `hmacsignature` header with a `protocol: HmacSHA256` header and must not deserialize the body before verification. One key per endpoint and a new key for test→live; a rotated key can take time to propagate, so accept the previous key for a while.
- PayPal: self-verification builds `transmissionId | timeStamp | webhookId | crc32` from `paypal-transmission-id`, `paypal-transmission-time`, the webhook id, and the decimal CRC32 of the **raw** body (never re-serialize parsed JSON), then verifies the `paypal-transmission-sig` signature with the public key in the certificate named by the `paypal-cert-url` header. The postback alternative (`verify-webhook-signature`) is not available for mock events. A receiver that downloads the header-supplied cert URL without pinning it to PayPal's domain trusts attacker-supplied key material — prefer postback or pin the host (derived from PayPal's documented flow and the Standard Webhooks warning against trusting headers for keys).
- Square: `x-square-hmacsha256-signature` = HMAC-SHA256(signature key, `notification URL + raw body`); constant-time comparison is explicitly recommended. Because the signed input contains no timestamp or nonce, replay protection must come from event-id dedupe, not from the signature (derived from the documented construction).
- Shopify: `X-Shopify-Hmac-SHA256` = Base64 HMAC-SHA256 of the **raw** body with the app's client secret; middleware order matters (a JSON body-parser before verification breaks it), and after a secret rotation the old digest can persist for up to an hour. Dedupe deliveries by `X-Shopify-Webhook-Id`; correlate multi-subscription deliveries by `X-Shopify-Event-Id`.
- GitHub: `X-Hub-Signature-256` = `sha256=` + hex HMAC-SHA256 of the payload with the webhook secret (legacy `X-Hub-Signature` = SHA1); constant-time compare; the signed material is the body only.
- Braintree: notifications arrive `x-www-form-urlencoded` with `bt_signature` + `bt_payload`; the payload is signed and the SDK parse raises an *invalid signature* exception. Notifications "may not be delivered sequentially" — the payload carries a timestamp to order by.
- Standard Webhooks (community spec, v1.0.0): headers `webhook-id`, `webhook-timestamp`, `webhook-signature`; the signed content is `msg_id.timestamp.payload`; symmetric `v1` (HMAC-SHA256, `whsec_` secret) and asymmetric `v1a` (ed25519, `whpk_`/`whsk_`) are both defined, with multiple space-delimited signatures for zero-downtime rotation. Listeners must verify the timestamp within tolerance, use constant-time comparison, treat `webhook-id` as the idempotency key, and must not trust a public key supplied in a request header.
- Generic test: recompute the signature over the provider's documented input with a test secret and confirm it matches; then flip one byte of the body and confirm the endpoint rejects it. Match acceptance proves the input construction, rejection proves enforcement.

Signature-input matrix (synthesis of the cited provider docs; pick the replay test from the guard column):

| Provider | Signed input | Replay guard | Dedupe key |
|---|---|---|---|
| Stripe | raw body + `t=` timestamp, `whsec_` secret | 300 s default tolerance; `0` disables | event `id` |
| Adyen | colon-joined event fields, hex key → Base64 | none in signature; order by `eventDate` | `eventCode` + `pspReference` (apply latest) |
| PayPal | `transmissionId\|timeStamp\|webhookId\|crc32` | signature only; no tolerance documented | event envelope `id` |
| Square | `notification URL + raw body` | none (no timestamp/nonce in input — derived) | event id |
| Shopify | raw body, app client secret (Base64) | none in signature | `X-Shopify-Webhook-Id` (correlate `X-Shopify-Event-Id`) |
| Braintree | form fields `bt_signature` + `bt_payload` | none in signature; payload timestamp | notification id |
| GitHub | body, webhook secret, `sha256=` hex | none in signed input (derived) | — (dedupe on your side) |

Webhook delivery, ordering, and retry semantics per provider:

- Stripe: up to 16 endpoints; delivery retried up to three days with exponential backoff in live mode (three attempts over hours in sandbox); manual resend for 15 days in the Dashboard and 30 days via CLI. Endpoints must be public HTTPS URLs (TLS 1.2+ in live mode). Ordering is **not** guaranteed; snapshot events record `created` in seconds so distinct events can share a timestamp — use the event ID (not `created`) for dedupe, and retrieve objects from the API when an event arrives first. If two separate Event objects are generated for one logical change, they are distinguished by `data.object.id` + `event.type`.
- Adyen: ack with 200/202 (three terminal webhook types accept only 200) within 10 seconds or the webhook is marked Failing and queued for retry; check the event timestamp (and `sequenceNumber` where present) to order events; duplicates share `eventCode` + `pspReference` with possibly-different `eventDate` — apply the latest.
- PayPal: listener must be HTTPS on port 443; non-2xx/no response triggers up to 25 retries over 3 days; the event envelope includes `id`, `event_type`, `resource`, and a `resend` link.
- Shopify: 200 required (3xx counts as error); 1 s connect and 5 s total request timeouts; webhook connections use HTTP keep-alive; failures retried 8 times over 4 hours, after which Admin-API-configured subscriptions can be auto-deleted.
- Braintree: a response taking longer than 30 seconds is a timeout; retries are hourly for up to 3 hours in sandbox or 24 hours in production until a 2xx.
- Square: event delivery order is not guaranteed (treat handlers as unordered and idempotent) — same operational rule as Stripe: dedupe on event id, never on arrival order.

Idempotency key lifecycle: three failure shapes to probe per gateway:

1. **New key on retry** — the client (or SDK) generates a fresh key per attempt, so the backend correctly processes two requests; the *finding* is the persisted double effect.
2. **Key reused too late** — the provider prunes keys after a retention window (Stripe: keys can be removed once at least 24 h old, and a reused key then starts a new request; Adyen: 7–14 days), so a retry after that window silently creates a second operation. Test a delayed retry, and test a retry just inside vs just outside the window.
3. **Same key, different payload** — a gateway that caches only the response and not the payload hash lets a changed amount pass under the *same* key. Stripe compares the incoming parameters to the original request and errors if they differ; Square returns an error for a changed request under a reused key ("this behavior might vary depending on the API"); a home-grown gateway often does neither.

Idempotency-key enforcement per gateway vs backend (per provider, verified):

- Stripe: the client sends `Idempotency-Key` (up to 255 characters); a repeat with the same key returns the same result — including a stored `500` — and keys are pruned once ≥24 h old, after which a reused key makes a **new** request. Only `POST` accepts keys (`GET`/`DELETE` ignore them). A result is saved only after endpoint execution begins: a request that fails validation or conflicts with a concurrent request is not saved, so retrying it is legitimate. A finding here is the *backend* writing twice despite the gateway replay, or keys pruned before the client's retry window (client retries past 24 h → duplicate charge).
- Adyen: `idempotency-key` header (max 64 characters) on `POST`; other verbs are idempotent by definition. Keys are stored at the **company account** level and are valid 7–14 days after first submission; keys are *not* checked for duplicates across regional endpoints. Racing duplicates get 422 or 409 with error code 704; a `transient-error: true` response header means retry with the same key, and if the idempotency store itself is unavailable the API returns 503 with error code 703 (retry later, or fall back to submitting without the header). Adyen's platform accounting rules already cap captures at the authorized amount and total refunds at the captured amount.
- PayPal: `PayPal-Request-Id` header enforces idempotency on `POST`; not all APIs support it and the retention period is documented per API. The value must be unique per request *and* per API call type (and is limited to 38 single-byte characters per the reference). Omitting the header duplicates the request; sending it twice simultaneously means the first is processed and the second *might* fail. Retrying with a fresh key after a timeout is the classic double-effect cause.
- Square: an idempotency key is required to be unique; the same key with the *same* request returns the original response without a second effect, but the same key with a *changed* request is rejected (may vary by API). That asymmetry is a useful test: change the amount while holding the key and observe whether the backend still creates a second charge.
- General pattern to probe: gateways that enforce exactly-once (key stored + response cached) vs gateways that pass a key through to a backend that ignores it. Send the same key with two *different* payloads and with the same payload twice; the divergent responses localize where enforcement lives.
- Key placement is not uniform: Square and Google Standard Payments put the key in a request-body property, PayPal uses `PayPal-Request-Id`, Stripe/Adyen use `Idempotency-Key`, Twilio uses `I-Twilio-Idempotency-Token` on webhooks, Chargebee uses `chargebee-idempotency-key`, OpenBanking uses `x-idempotency-key` (per the IETF draft's implementation-status list). A replay test that only copies a header misses body-keyed implementations — replay the whole captured request.
- There is no ratified standard to lean on: the IETF `Idempotency-Key` draft (draft-ietf-httpapi-idempotency-key-header-07, intended Standards Track) expired 18 April 2026 with no RFC status. It defines the shapes worth testing against any home-grown implementation: 422 for the same key with a different payload, 409 for a retry while the original is still processing, 400 for a missing key where required, an optional key/payload fingerprint, and a documented expiry policy; its security section warns that low-entropy keys let attackers guess cache entries and recommends a composite cache key that includes server-known client attributes.

Race-window shape per stack (match the primitive to the observation):

- Single-packet attack (HTTP/2): one TCP packet completes 20–30 requests simultaneously, neutralizing network jitter; the natural fit for H2 multiplexed targets and the default for discovery. It is **incompatible with HTTP/1** — Burp's tooling and Turbo Intruder switch technique automatically by server HTTP version.
- Last-byte synchronization (HTTP/1.1): hold all but the final byte of each request and release them together on the same reused connection; needs HTTP/1.1 connection reuse to be reliable.
- First Sequence Sync (HTTP/2): expands the single-packet technique past the 65,535-byte limit by synchronizing the first frame sequence — useful when the exploit needs voluminous requests.
- Connection warming: complete a benign request first so TLS/TCP setup does not consume the race window.
- Hidden sub-states: a single HTTP request can internally transition through states the UI never exposes (e.g. authenticate → set session → enforce MFA). Send the sensitive follow-up request in the same parallel group as the first so it lands inside the sub-state.
- Multi-endpoint alignment: two different endpoints mutate the same record; endpoint-specific processing time and front-end→back-end connection setup skew the windows, so warm the connection and retry the group before concluding the WAF or a guard stopped you.
- Server-side delay injection: when the exploit needs one request to run later, a burst of dummy requests that trips rate/resource limits can induce a usable server-side delay (keeps the single-packet property for the real requests).
- Session locking: some frameworks process only one request per session at a time (PHP's native session handler is the canonical case) — all-parallel requests that come back strictly sequential are a signal to use a distinct session token per request.
- Partial construction: object created and secured in separate steps leaves a window where a guard compares against an uninitialized value; input shapes that produce `null`/empty collections (`param[]=`, key-with-no-value) match it.
- Time-sensitive token generation: tokens seeded only by a high-resolution timestamp collide when two requests land in the same tick — the same precision-timing tooling finds it.

Payment-provider webhook semantics (per provider, verified):

- Stripe signs every event in the `Stripe-Signature` header and requires verification with the official libraries (or manual steps); it also recommends IP allowlisting of its senders. Its libraries default to a **5-minute (300 s)** timestamp tolerance, checked against the `t=` value to blunt replay. Stripe does **not** guarantee that events arrive in the order they were generated, retries deliveries automatically, and allows manual resend for up to 15 days (Dashboard) / 30 days (CLI); the same event can therefore arrive more than once. Handler must dedupe by event id and treat ordering as unordered.
- Adyen places the HMAC signature in `additionalData.hmacSignature` for Standard webhooks (some webhook types carry it in a header instead, which needs a different verification routine); one HMAC key is bound per endpoint and a new key is required when moving test→live. Duplicate events share the `eventCode` and `pspReference` values while `eventDate` can differ — the receiver is told to use the details from the **latest** event.
- PayPal supports self-verification (form the string `transmissionId | timeStamp | webhookId | crc32` from the `PAYPAL-TRANSMISSION-*` headers and compute the signature locally) or deferring verification by POSTing the event back to PayPal's verify-webhook-signature endpoint; self-verification is preferred for latency and to avoid the extra dependency. For the postback, the `webhook_event` object must be sent back exactly as received — re-serializing parsed JSON can fail verification.
- Square: webhooks must be verified before acting; event delivery order is not guaranteed (treat handlers as unordered and idempotent).
- Shopify: verify the HMAC before trusting the payload and use the delivery-id header to ignore duplicates; HTTPS deliveries only (Pub/Sub and EventBridge deliveries do not carry the HMAC header).
- Braintree: signed form-encoded payload; parse with the SDK and let it raise on a bad signature; order by the timestamp inside the signed payload.
- GitHub: sign the body with the webhook secret; if the secret is not configured the signature header is simply absent — an implementation that only verifies *when the header is present* is bypassable by omitting it.

Coupon / loyalty / refund invariant catalog (write these as explicit invariants before testing):

- Coupon: single-use per user; single-use globally; not stackable; not applicable to sale items; expiry not extended by cart persistence; redemption count == ledger decrements.
- Loyalty / gift card: balance non-negative; balance never exceeds face value + earned; points cannot be earned on a refunded order; points cannot be spent twice on concurrent redemptions; gift-card split payments cannot exceed the order total.
- Refund: total refunded ≤ captured; refund requires a prior capture; refund requires a linked return where the flow says so; partial refunds cannot be chained to exceed the total; a refunded order cannot be re-refunded by reusing the refund id; a refund returns only to the original instrument.
- Referral: inviter and invitee cannot be the same identity (device/payment/email dedupe); credit is granted once per qualifying conversion.
- Return / RMA: returned quantity ≤ purchased quantity; a return requires a prior delivery; store credit issued for a return cannot exceed the item value; a single return cannot be processed twice; a returned item cannot also be refunded outside the policy window.
- Subscription: proration on upgrade/downgrade; cancel-then-resume; seat/quantity changes cannot double-bill; a rapid up→down cycle cannot mint credit larger than the paid plan value.
- Wallet / top-up / gift balance: balance non-negative; top-up caps and velocity limits hold; no currency mixing across one wallet; promotional credit cannot be withdrawn as cash; a rounded-off remainder is credited/debited once, not twice.

Refund / chargeback lifecycle semantics (per provider):

- Stripe emits `refund.created`, `refund.updated`, and `refund.failed` for the refund object, and `charge.refunded` for the charge (emitted for partial refunds too). A handler that listens only to `charge.refunded` can miss a failed refund; one that listens only to `refund.created` can mark money returned before it settles — probe handlers that act on the wrong event. (Deprecated: `charge.refund.updated` — listen to `refund.updated` instead.) `review.closed` also fires with `reason` one of `approved`, `disputed`, `canceled`, `refunded`, `refunded_as_fraud`.
- Refund invariants to write down and try to violate: total refunded ≤ captured; a refund must reference a real, captured charge; a partial refund cannot be chained past the total; a refunded (or disputed) charge cannot be refunded again; when the authorization was only partly captured, refunds cannot exceed the *captured* amount.
- Stripe refund failure taxonomy (each is a documented state, not automatically a bug): `charge_for_pending_refund_disputed` (customer disputed while the refund was pending), `declined`, `expired_or_canceled_card`, `insufficient_funds`, `lost_or_stolen_card`, `merchant_request`, `unknown`; a refund can also be `canceled` (Dashboards-only for card refunds in some cases) or wait in `requires_action` for customer bank details until an expiry.
- Chargeback/dispute events (`charge.dispute.*`, `charge.dispute.funds_reinstated`) arrive asynchronously and can race the app's own refund flow — an app refund issued while the provider already refunded produces a double outflow. Disputes debit the balance plus network dispute fees at creation; Stripe gives a response window of "usually 7 to 21 days" per network, and the outcome arrives as `charge.dispute.closed` with status `won` or `lost` (an inquiry is only a pre-dispute stage and requires a fresh response if it escalates).
- Authorization hold vs capture: a hold is not a capture. A handler that treats a hold as money taken can refund funds that were never captured, or miss a real capture — verify against the provider's charge status, never the app's own status field.
- Adyen's accounting rules do part of the work for you: partial captures cannot exceed the authorized amount, and by default total refunds cannot exceed the captured amount — a violation means the app bypassed or duplicated Adyen's modification flow, so record which flow the request used.

Chargeback / dispute invariant catalog (for test-mode reasoning):

- A dispute presupposes a captured charge; on a merely authorized charge the flow is a cancel/void, not a chargeback.
- Funds are withdrawn at dispute creation (amount + network fee), once per dispute; multiple disputes can attach to a single payment, so sum them before concluding "double refund".
- An open dispute and an app refund must not both return the money (Stripe's `charge_for_pending_refund_disputed` guidance says accept or challenge the dispute rather than refunding) — the double outflow is the finding.
- Reinstatement happens only when the dispute closes in your favor (`won`) or is withdrawn; `charge.dispute.funds_reinstated` is an inbound state the app must reconcile, not a second capture.
- An inquiry is not a chargeback and needs a fresh response if it escalates; a workflow that maps both to one state can skip a required response.
- The provider's dispute status is authoritative for "is this money gone"; an app order status must not be the only source.

Numeric / currency / rounding notes:

- Stripe amounts are integers in the currency's minor unit: `1000` is 10 USD in a two-decimal currency but `10` is 10 JPY in a zero-decimal currency (zero-decimal list: BIF, CLP, DJF, GNF, JPY, KMF, KRW, MGA, PYG, RWF, UGX, VND, VUV, XAF, XOF, XPF). Backward-compat quirks: ISK and UGX are represented as two-decimal values whose last two digits must be `00`. HUF and TWD are chargeable with two decimals but manual payouts must be whole 100s. Fractional invoice amounts in UGX are auto-rounded by Stripe to the nearest 100 and the difference is credited or debited to the customer balance — a second ledger to reconcile.
- Stripe enforces minimum charge amounts per settlement currency (e.g. 0.50 USD/EUR, 0.30 GBP, 50 JPY, 175 HUF, 10 THB); subscription charges may be zero (coupons, trials) but any non-zero amount is subject to the minimum. Card amounts support up to 12 digits in minor units (9 for AmEx in most currencies) — "large number" boundary tests belong to the provider's limits, not the app's.
- Currency-mixing bugs happen when the app reuses one integer across currencies or computes fees/tax in a different currency from the charge; always reconcile the *charged* currency+amount from the provider, not the cart's display currency.

Account-linking merge/unlink ordering:

- Merge direction matters: merging A into B then unlinking should not leave B holding A's verified identifiers or LTV/credits. Probe both merge orders and the unlink-after-merge sequence.
- Re-verify after unlink: unlinking a verified provider should revoke the entitlement it granted; test whether the old session/identifier still authenticates or still carries role/plan.
- TOCTOU on link: start a second link operation while the first is mid-flight (client-side-step window) to see whether duplicate links to the same identity can be created and one skipped.

State-resurrection identifier catalog (where to look for a reusable terminal id):

- Coupons / promo codes (single-use, expired, or removed from the catalog).
- Invite / referral codes after acceptance or revocation.
- Email/phone verification tokens and magic links after first use.
- Deleted or revoked sessions, API keys, and device tokens — does the old token still authenticate?
- Refunded/cancelled order ids accepted by a "re-send confirmation", "re-download", or "re-order" endpoint.
- Trial ids / entitlement keys re-applied after expiry.

Account-linking merge/unlink specifics:

- Email-based linking: link via an unverified email, then take over the second identity by verifying it — a two-step confusion the UI never shows.
- IdP-initiated merge: an OAuth/OIDC login that silently merges into an existing account by matching email, granting the new IdP's roles to the old account.
- Carry-over: merge a premium identity into a basic one (and the reverse) and see which entitlements survive; unlink must *revoke*, not merely hide.
- Ordering race: unlink then immediately re-link the same provider and check whether the old session survives the unlink window.
- Re-registration takeover: if the platform lets you register again with the same address (case variant, alias, or an unverified original), test which account the reset flow targets — Vine's case-variant duplicate signup overwrote the unverified account's password, and subsequent resets then targeted the *new* account, making the original unrecoverable.

Optimistic-UI and caching false positives (the most common trap):

- SPAs render success before the server confirms; always reconcile against a server read-back (list endpoint, provider dashboard, ledger export) rather than the toast/badge in the DOM.
- bfcache restores a full page snapshot (JS heap included) without a request on Back/Forward, so a stale balance or "success" screen can reappear; hard-reload or open a fresh session before calling it a state bug.

### State-machine skip specifics

- Reachability test: enumerate the terminal actions (activate, confirm, approve, ship, mark-paid, downgrade) and call each directly with the lowest-privilege session that owns the object; the guard must be server-side and per-transition, not attached to the previous step's page.
- Token choreography: keep the step-1 token, skip step 2, replay step 1 after step 3, and re-submit step 3 a second time — look for state that only advances (or only pays) once.
- API vs UI divergence: the UI may hide a state the API still accepts; test the raw enum values (`status: "approved"` supplied directly, unknown enum values stored without validation) — mass assignment and hidden enum members are the usual entry points.
- Webhook-as-state-driver: a provider event (or a support/tooling endpoint) that can be triggered by you to move the app state the UI forbids is a skip with a legitimate-looking request log.

### Per-family test recipes (concrete)

- Coupon reuse: record the baseline price → apply the coupon → apply it again in a second request; read the order total *and* the coupon's redemption count.
- Race on redeem: 2 parallel identical redeem requests on one warmed H2 connection (or H1 last-byte sync); compare against a 2-sequential control (one success, one rejection).
- Skip: capture the step-1 token, submit step 3 directly; read the resulting object's state, not the redirect.
- Idempotency: same key + same payload (should be inert) vs same key + different amount (should be rejected) vs a new key after a timeout (the realistic double-charge); repeat the pair just inside and just outside the provider's retention window.
- Webhook: re-send one captured test event; if the endpoint acts, escalate to a *modified* body to separate "unverified" from "unsigned"; then check whether the app deduped by event id.
- Linking: link A→B, unlink, re-link, and check both accounts' entitlements and sessions after each step; then attempt a case-variant re-registration of B's address and follow the reset flow.
- Refund: partial-refund once, then a second partial refund that together exceeds the capture; read the provider dashboard, not just the app.
- Dispute: in test mode, create a dispute and watch which events the app consumes; confirm whether an app-initiated refund in the same window double-credits.
- Rounding: charge a one-item basket, then split the same basket into small units; diff the totals and the tax lines against the one-shot control, then check the provider's rounding mode before reporting.
- Race controls: send the group sequentially first (benchmark), then in parallel; if responses serialize, re-run with a fresh session token per request.

### What a defensible report contains

- The written invariant and the forbidden transition (one sentence each).
- Baseline and post-action ledger values in *both* accounts, with timestamps.
- The exact request(s) plus the idempotency key / coupon / order / provider event identifiers involved.
- The sequential control beside the parallel result (races), or the clean-key / clean-cache control (replay and poisoning).
- The remediation class: a per-request atomic check (application code) vs cross-service ordering/idempotency (architecture).
- For provider-mediated findings: the event id, delivery/retry timestamps, and the provider dashboard state showing the divergence.

## References

- Stripe webhooks — signature verification (`Stripe-Signature`), 5-minute default timestamp tolerance (and `0` disabling the recency check), raw-body requirement, per-endpoint secrets and 24 h secret-roll overlap, no delivery-order guarantee, retries (3 days live / 3 attempts sandbox), resend windows (15 days Dashboard / 30 days CLI), dedupe by event id: https://docs.stripe.com/webhooks ; signature error guide: https://docs.stripe.com/webhooks/signature [T1 vendor]
- Stripe idempotent requests — `Idempotency-Key`, 255-char limit, same result incl. `500`, keys pruned once ≥24 h old, payload comparison, concurrent-request result not saved, POST-only: https://docs.stripe.com/api/idempotent_requests [T1 vendor]
- Stripe refunds — event catalog (`refund.created` / `refund.updated` / `refund.failed` on the refund, `charge.refunded` incl. partials), refund statuses (`pending`, `failed`, `canceled`, `requires_action`) and failure reasons (`charge_for_pending_refund_disputed`, …), cumulative refund cap, refund-to-original-instrument, bank-debit double-refund risk: https://docs.stripe.com/refunds [T1 vendor]
- Stripe disputes — dispute immediately reverses payment and debits balance plus network fees; response window "usually 7 to 21 days"; inquiries as pre-dispute stage; `charge.dispute.closed` statuses `won`/`lost`: https://docs.stripe.com/disputes/responding [T1 vendor]
- Stripe currencies — amounts in minor units, zero-decimal currency list, ISK/UGX backward-compat `00`, HUF/TWD payout divisibility by 100, UGX invoice rounding to the nearest 100 with difference credited/debited to the customer balance, minimum charge amounts, digit limits: https://docs.stripe.com/currencies [T1 vendor]
- Stripe disputes (overview) — balance debit and dispute-fee mechanics: https://docs.stripe.com/disputes [T1 vendor]
- Adyen — verify HMAC signatures (`additionalData.hmacSignature` for Standard webhooks, `hmacsignature`+`protocol` headers for other types, colon-joined field string, hex key, Base64 output, per-endpoint key, test→live key change and propagation): https://docs.adyen.com/development-resources/webhooks/secure-webhooks/verify-hmac-signatures — CORRECTION: the previously cited URL `.../webhooks/verify-hmac-signatures/` now returns 404 (verified this session); the canonical path moved under `secure-webhooks/` [T1 vendor]
- Adyen — handle webhook events (10 s ack window, Failing + retry queue, 200/202; duplicates share `eventCode`/`pspReference` and the latest `eventDate` wins; timestamp/`sequenceNumber` ordering): https://docs.adyen.com/development-resources/webhooks/handle-webhook-events [T1 vendor]
- Adyen — API idempotency (`idempotency-key`, max 64 chars, POST only, company-account key scope, keys valid 7–14 days, not cross-checked across regional endpoints, 422/409 error code 704, `transient-error` header, 503 error code 703, captures ≤ authorized and refunds ≤ captured by default): https://docs.adyen.com/development-resources/api-idempotency [T1 vendor]
- PayPal — webhook verification (self-verification string `transmissionId | timeStamp | webhookId | crc32` with raw-body CRC32, cert from `paypal-cert-url`, postback via `verify-webhook-signature` unavailable for mock events, HTTPS 443, retries up to 25× over 3 days): https://developer.paypal.com/api/rest/webhooks/rest/ [T1 vendor]
- PayPal — idempotency (`PayPal-Request-Id`, not all APIs support it, retention per API, omitting duplicates, simultaneous second request "might fail", unique per request and per API call type, 38 single-byte characters): https://developer.paypal.com/api/rest/reference/idempotency [T1 vendor]
- Square — verify webhook notifications (`x-square-hmacsha256-signature` = HMAC-SHA256 over `notification URL + raw body`, constant-time comparison): https://developer.squareup.com/docs/webhooks/step3validate [T1 vendor]
- Square — idempotency key semantics (same key+request returns original response; same key+different request rejected; behavior may vary by API): https://developer.squareup.com/docs/build-basics/common-api-patterns/idempotency [T1 vendor]
- Shopify — verify webhook deliveries (`X-Shopify-Hmac-SHA256` Base64 HMAC of the raw body, `X-Shopify-Webhook-Id` vs `X-Shopify-Event-Id`, raw-body/middleware ordering, 8 retries over 4 h, 1 s/5 s timeouts, keep-alive, 1 h secret-rotation lag): https://shopify.dev/docs/apps/build/webhooks/verify-deliveries [T1 vendor]
- GitHub — validating webhook deliveries (`X-Hub-Signature-256` with `sha256=` hex HMAC, legacy SHA1 header, UTF-8 handling, constant-time compare, test vector): https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries [T1 vendor]
- Braintree — webhook parse (`bt_signature` + `bt_payload` form fields, signed payload, invalid-signature exception, non-sequential delivery/order by timestamp, hourly retries up to 3 h sandbox / 24 h production, 30 s timeout): https://developer.paypal.com/braintree/docs/guides/webhooks/parse/ruby/ [T1 vendor]
- Standard Webhooks specification v1.0.0 — `webhook-id` / `webhook-timestamp` / `webhook-signature`, signed content `msg_id.timestamp.payload`, `v1` HMAC-SHA256 vs `v1a` ed25519, multi-signature rotation, constant-time comparison, use `webhook-id` as idempotency key, retry schedule and status-code handling, do not trust header-supplied keys: https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md [T1 vendor/community spec]
- IETF Idempotency-Key draft — 422 (same key, different payload), 409 (retry while processing), 400 (missing key), fingerprint concept, documented expiry policy, low-entropy-key security considerations, composite cache key: https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-idempotency-key-header-07 — STATUS: expired 18 April 2026, no RFC; semantics are vendor-defined, do not treat as normative [T0 standards (expired draft)]
- PortSwigger race conditions academy — single-packet attack (H2 only, 20–30 requests in one TCP packet), last-byte synchronization (H1), hidden sub-states, sequential benchmarking, connection warming, rate-limit-induced delays, PHP session serialization, partial-construction races (PHP/Rails null-input shapes), time-sensitive token collisions: https://portswigger.net/web-security/race-conditions ; single-packet background: https://www.clear-gate.com/blog/race-condition-single-packet-attack/ [T2 research]
- First Sequence Sync — expanding the single-packet race past the 65,535-byte limit: https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/ [T2 research]
- Avalara — line-level vs document-level tax rounding (each line rounded before summing, vs sum-then-round; mismatched systems explain cents drift): https://knowledge.avalara.com/bundle/dqa1657870670369_dqa1657870670369/page/rwv1666091993209.html [T1 vendor]
- MDN — `bfcache` (back/forward cache restores a full in-memory page snapshot, JS heap included, without repeating network requests): https://developer.mozilla.org/en-US/docs/Glossary/bfcache [T1 vendor]
- HackerOne disclosed report 187714 — Vine: case-variant duplicate signup overwrote the password of an unverified account; resets then targeted the new account: https://hackerone.com/reports/187714 [T3 vuln intel]
- HackerOne disclosed report 785833 — Reddit: multiple registrations on one email plus email-routed resets; triaged Informative because the platform intentionally allows 1:N account-to-email mapping (false-positive lesson): https://hackerone.com/reports/785833 [T3 vuln intel]
- HackerOne disclosed report 157996 — race condition allows redeeming the same coupon multiple times: https://hackerone.com/reports/157996 [T3 vuln intel]
- HackerOne blog — business-logic vulnerability leading to unlimited discount redemption: https://www.hackerone.com/blog/how-business-logic-vulnerability-led-unlimited-discount-redemption [T3 vuln intel]
- OWASP business-logic abuse: https://owasp.org/www-project-top-10-for-business-logic-abuse/ ; race-condition reference: https://hacktricks.wiki/en/pentesting-web/race-condition.html ; TOCTOU: https://deepstrike.io/blog/what-is-time-of-check-time-of-use-toctou [T0/T2 reference]
- OWASP Testing Guide: business logic and workflow testing chapters; OWASP API Security Top 10 (Unrestricted Access to Sensitive Business Flows) [T0 standards]
- Program policy and payment-flow documentation for the assessed environment's permitted commerce testing bounds [T1 vendor]
- Concurrency-control references for the observed stack (database isolation levels, atomic operations, distributed locks) to ground the remediation recommendation [T0/T1 reference]
- Tier tags: `[T0 standards]` RFC/OWASP normative; `[T1 vendor]` official product/API docs; `[T2 research]` published security research; `[T3 vuln intel]` advisories, CVE records, and secondary reporting.
