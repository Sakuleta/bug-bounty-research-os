# Frameworks — SvelteKit

> SCOPE: Load when SvelteKit is fingerprinted (typically the `__sveltekit_*` inline script and `/_app/immutable/` asset paths, `Vary: Accept`) and `load` functions, form actions, `+server.js` endpoints, hooks, remote functions, or adapter-node settings are the research surface.

## Research families

- Server `load` functions: `+page.server.js` / `+layout.server.js` export `load` that runs only on the server; `+page.js` / `+layout.js` run on server and client. Returned data is serialized (devalue) into the page and into the data response for client navigation.
- Data representations: `__data.json` requests for a route during client-side navigation; the `__sveltekit_*` inline hydration script in the HTML.
- `+server.js` endpoints ("API routes"): export `GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD` (and a `fallback` handler); return raw `Response` objects.
- Form actions: `actions` exported from `+page.server.js`, invoked by `<form>` POST to the same URL; default action plus named actions selected by `?/name`.
- Remote functions (`experimental.remoteFunctions`, `.remote.ts` files): `query`, `form`, `command`, `prerender` functions — the `form` function deserializes binary form data (devalue) and is the entry point for the 2026 DoS CVEs.
- Hooks: `handle` in `hooks.server.js` (runs for every request), `handleFetch`, `handleError`; sequence helpers.
- Content negotiation: `PUT/PATCH/DELETE/OPTIONS` always go to `+server.js`; `GET/POST/HEAD` go to `+server.js` unless `Accept` prioritizes `text/html`; `GET` responses carry `Vary: Accept`.
- Layout/guard scoping: `+layout.server.js` load guards its subtree's pages, but has no effect on `+server.js` files.
- Parent/child data flow: a child `load` receives `parent()` data; when the parent enforces auth by returning a redirect, the child still runs in the same request — a child `load` that returns private fields is reachable through the child route's `__data.json` even though the parent would have redirected the page.
- adapter-node runtime knobs: `ORIGIN` (absolute-URL base for prerendering) and `BODY_SIZE_LIMIT` (request-body cap), plus the `HOST`/`PORT`/`PROTOCOL_HEADER`/`HOST_HEADER` family.

## Preconditions

- A route exists where the page is guarded (in `handle` or a `+layout.server.js` load) but the data path is not: a sibling `+server.js`, a `+page.server.js` `load` reachable as `__data.json`, or a form `action`.
- The authorization decision sits at the page/layout layer while the data-producing function does not repeat it — SvelteKit docs warn `params`/`url` in a remote-function request are request-controlled and must not drive authorization.
- `adapter-node` deployments for the `ORIGIN`/`BODY_SIZE_LIMIT` families (other adapters behave differently).
- Around `experimental.remoteFunctions` (and the `form` remote function) for the deserialization/DoS families.
- Two independent fingerprint signals (immutable asset hashing, `__sveltekit_` global, `Vary: Accept` on GET) before applying any version note.
- For the `ORIGIN` SSRF family: at least one prerendered route, `adapter-node`, no `ORIGIN` env var, and no reverse proxy performing Host-header validation.
- For the `BODY_SIZE_LIMIT` family: only the SvelteKit layer limit is at issue — WAF/gateway/platform limits still apply and must be observed separately.
- For the remote-form `files` array family (CVE-2026-82259): the app's `form` handler processes `files` without validating `files.length` or individual file sizes; the payload is small on the wire but expands server-side.
- For the devalue `parse` family (CVE-2026-22774/22775): user input reaches `devalue.parse` — in SvelteKit that means remote functions are enabled; a plain non-remote app is not exposed through these two CVEs.

## Oracles

- Data-route bypass: `GET /<guarded-route>/__data.json` returns the private `load` payload to an anonymous session while the HTML page redirects to login.
- Endpoint-vs-page divergence: `/x` (page) is guarded but `/x` as `+server.js` (or `Accept: application/json`) returns data — the guard was in the layout/page and does not cover `+server.js`.
- Action invocation gap: anonymous `POST` to a form action URL (optionally `?/actionName`) mutates researcher-owned state without a token; SvelteKit actions rely on SameSite cookies, not CSRF tokens.
- `ORIGIN`-unset SSRF: with `adapter-node`, a prerendered route, and no `ORIGIN` env var (and no Host-validating proxy), a forged Host/absolute-URL request makes the server fetch internal resources (CVE-2025-67647 SSRF component); the same misconfiguration can die on a single request (DoS component).
- `BODY_SIZE_LIMIT` bypass: an oversized body reaches the handler despite a configured `BODY_SIZE_LIMIT` (CVE-2026-40073) — oracle is memory pressure/acceptance, not a data leak; do not send real oversized bodies.
- Remote-form deserialization amplification: with `experimental.remoteFunctions` and the `form` function, malformed form data expands during `devalue.parse`/binary deserialization into memory/CPU exhaustion (CVE-2026-22803, CVE-2026-82259, CVE-2026-82260) — single small benign probe, never amplification.
- Hydration-script reflection: the `__sveltekit_*` script echoing attacker-influenced keys (`hydratable`) is XSS-shaped (CVE-2025-15265) — confirm the same key reaches a second user.
- `handle` runs for every request, including `+server.js` endpoints: when a guard lives in `handle` it covers both pages and endpoints; when it lives in a layout `load` it covers neither endpoints nor the data representation alone.
- Named-action control: an unknown action name (`?/does-not-exist`) returns the framework's action error rather than executing — use it as the negative control for a suspected action invocation gap.
- Remote-form expansion shape: a small `multipart/form-data` body naming the same file field repeatedly expands into a large `files` array during `form` deserialization (CVE-2026-82259) — oracle is processing time/memory on one benign body, not a data leak.

## Minimal safe proof

1. Fingerprint: confirm SvelteKit from immutable asset hashing plus the `__sveltekit_` hydration global; note adapter (node vs serverless) and whether remote functions are in use from `/_app/` assets and action/remote endpoints.
2. Baseline: request the guarded page and its data representation (`__data.json`, or `Accept: application/json`) from owner and anonymous sessions; record status/body/redirect.
3. Data probe (single variable): request `__data.json` anonymously for one guarded route; if it returns private fields, capture shape only.
4. Endpoint probe: request the `+server.js` variant of a guarded path anonymously; diff against the page.
5. Action probe: submit one form action from an anonymous session that affects only researcher-owned state; keep the same action with a wrong/named-action control.
6. Version probe: read the `@sveltejs/kit`/`devalue`/`svelte` versions from the bundle or lockfile signal and map them to the CVE ranges below before probing `ORIGIN`, `BODY_SIZE_LIMIT`, or remote-function behavior.
7. Stop conditions: any other-user data, any state change outside researcher scope, fatal memory pressure, any amplification payload, or reflected attacker script — halt and report.

## False positives

- `__data.json` returning the same redirect/login payload as the page — consistent denial.
- `+server.js` `OPTIONS` returning CORS headers Vite injected in dev — those are absent in production unless added; not a bypass.
- `Vary: Accept` present on a normal HTML response — expected negotiation, not a finding.
- A 404/`fallback` handler returning generic text — no data exposure.
- `hydratable` key confirmation only when the same attacker key cannot reach a second user — reflected/self-only is not XSS.
- Dev-only `ORIGIN` warnings without an actual internal fetch — require the SSRF oracle (internal/collaborator response).
- `BODY_SIZE_LIMIT` accepted a large body but a WAF/gateway limit rejected or logged it first — the outer layer is the control; confirm which layer observed the body.
- Remote functions not enabled (`experimental.remoteFunctions` off) — the 2026 remote-form CVEs are not applicable even on an affected kit version.

## Version/implementation notes

- CVE-2025-67647 (DoS + possible SSRF when prerendering): `@sveltejs/kit` DoS `2.44.0`–`2.49.4` with a prerendered route; SSRF `2.19.0`–`2.49.4` with `adapter-node` and no `ORIGIN` and no Host-validating proxy; can chain to cache-poisoned XSS via a CDN. Fixed by the January 2026 patched set.
- CVE-2026-40073 (`BODY_SIZE_LIMIT` bypass, `@sveltejs/adapter-node`): affected `<= 2.57.0`, patched `2.57.1` (High; CWE-770; CVSS 4.0 `VA:H`); only the SvelteKit-layer limit is affected — WAF/gateway limits still apply.
- Remote-functions / devalue DoS set (all require `experimental.remoteFunctions`; the devalue ones require parsing user-controlled input, which remote functions do): CVE-2026-22775 (`devalue` `5.1.0`–`5.6.1`, `devalue.parse` memory/CPU), CVE-2026-22774 (`devalue` `5.3.0`–`5.6.1`, memory exhaustion), CVE-2026-22803 (`@sveltejs/kit` `2.49.0`–`2.49.4`, binary `form` deserializer memory amplification).
- CVE-2026-82260: `@sveltejs/kit >=2.49.0 <=2.52.1`, patched `2.52.2`; malformed form data causes excessive memory allocation during remote-form deserialization, crashing the server (CWE-400; CVSS 4.0 8.7). GHSA-vrhm-gvg7-fpcf.
- CVE-2026-82259: `@sveltejs/kit` `2.49.0`–`2.53.2`, patched `2.53.3`; the `form` remote function expands attacker-controlled `files` arrays (no `files.length` or file-size validation) into expensive processing (CWE-502; CVSS 4.0 8.7). GHSA-fpg4-jhqr-589c.
- CVE-2025-15265: XSS via `hydratable` (`svelte` `5.46.0`–`5.46.3`) when unsanitized user keys are returned to another user.
- January 2026 patched set: `devalue 5.6.2`, `svelte 5.46.4`, `@sveltejs/kit 2.49.5`, `@sveltejs/adapter-node 5.5.1` — useful for fingerprint-to-exposure mapping.
- `+layout` files never protect `+server.js` routes; auth must live in `handle` or be repeated in each endpoint. This is the single highest-value SvelteKit design fact.
- `handle` is the only hook that sees every request; `handleFetch` rewrites server-side `event.fetch` calls made inside endpoints, `load`, `action`, `handle`, `handleError`, or `reroute` (not only `load`), so an internal-fetch SSRF policy belongs there.
- Actions carry no framework CSRF token; the session cookie is the only credential — SameSite/`Secure`/origin-check configuration decides cross-site reachability. Remote functions add their own trust rule: request-controlled `params`/`url` must never drive authorization.
- Adapter versions matter independently of kit: the `adapter-node` deployment path carried the `BODY_SIZE_LIMIT` bypass (CVE-2026-40073, fixed kit `2.57.1`); `@sveltejs/adapter-node 5.5.1` was the adapter pin in the January 2026 patched set for the earlier CVE cluster — read the adapter line as well as the kit line.
- Dependency depth matters: `svelte` and `@sveltejs/kit` depend on `devalue`, and the patched releases bundle the fixed `devalue` (`5.6.2`) — a lockfile that pins an older transitive `devalue` keeps the `devalue.parse` CVEs even on a patched kit.
- `+server.js` may export a `fallback` handler for methods without an explicit export; authorization written only in the named method handlers leaves the fallback path uncovered on a route that accepts other verbs.
- Remote functions run through `devalue.parse`; treat any endpoint that accepts a serialized remote-function payload as an input parser and test its size/shape limits rather than its business logic.
- Negotiation differential: request the same route with `Accept: application/json` and `Accept: text/html` under one session; `Vary: Accept` is expected, but a different authorization decision between the two representations is the finding.
- Baseline control for actions: an unknown named action (`?/nope`) returning the framework's error confirms actions are routed; the same action with the owner session confirms the happy path — the anonymous replay is the one-variable test.
- Adapter choice changes what exists: `@sveltejs/adapter-node` exposes `ORIGIN`/`BODY_SIZE_LIMIT`; Cloudflare/Vercel adapters enforce platform limits instead, so the two DoS families are Node-only.

## References

- [T1] SvelteKit routing (server `load`, `+server.js`, actions, "+layout files have no effect on +server.js", `Vary: Accept`, request-controlled `params`/`url` warning): https://svelte.dev/docs/kit/routing
- [T1] Svelte team, CVEs affecting the Svelte ecosystem (Jan 2026 patched versions and conditions for 22774/22775/22803/67647/15265): https://svelte.dev/blog/cves-affecting-the-svelte-ecosystem
- [T1] CVE-2026-40073 advisory GHSA-2crg-3p73-43xp (affected `<=2.57.0`, patched `2.57.1`): https://github.com/advisories/GHSA-2crg-3p73-43xp
- [T1] CVE-2026-82260 record (affected `>=2.49.0 <=2.52.1`, patched `2.52.2`, remote form deserialization; GHSA-vrhm-gvg7-fpcf): https://osv.dev/vulnerability/CVE-2026-82260
- [T1] CVE-2026-82259 record (affected `2.49.0`–`2.53.2`, patched `2.53.3`, `form` files-array expansion; GHSA-fpg4-jhqr-589c): https://osv.dev/vulnerability/CVE-2026-82259
- [T1] NVD/CVE record CVE-2026-40073 (`BODY_SIZE_LIMIT` bypass, `adapter-node`): https://nvd.nist.gov/vuln/detail/cve-2026-40073 ; GitLab advisory mirror: https://advisories.gitlab.com/npm/@sveltejs/kit/CVE-2026-40073/
- [T1] GHSA-j62c-4x62-9r35 (CVE-2025-67647, prerender DoS/SSRF), GHSA-j2f3-wq62-6q46 (CVE-2026-22803), GHSA-6738-r8g5-qwp3 (CVE-2025-15265): via the Svelte blog above
- [T2] VulnCheck, SvelteKit remote form deserialization CPU exhaustion (fixed 2.52.2): https://www.vulncheck.com/advisories/sveltekit-before-2.52.2-cpu-exhaustion-via-remote-form-deserialization
- frameworks.md (this pack's manifest) for cross-cutting oracles and deployment-config discipline
