# Frameworks — Astro

> SCOPE: Load when Astro is fingerprinted (`/_astro/` hashed asset paths, `astro-island` custom elements, `data-astro-*` attributes, `X-Astro`/adapter headers) and endpoints, Server Islands, server actions, SSR error pages, or SSR/client-prop exposure are the research surface.

## Research families

- Endpoints (`src/pages/**/*.ts|.js`): export `GET`/`POST`/`PUT`/`PATCH`/`DELETE`/`OPTIONS`/`ALL` returning a `Response`. In a static build they are evaluated at build time to produce static files; under SSR (`output: 'server'`/`'hybrid'` or per-route `export const prerender = false`) they become live request handlers.
- Server Islands (`server:defer`): each island is split into its own special route fetched at runtime, `/_server-islands/[name]`, registered for all SSR apps using the Node standalone adapter — independent of whether the page itself is static. Encrypted `props`/`slots` parameters are replayed to the endpoint.
- Server actions: form/action POSTs handled by the SSR adapter at the generated `POST /_actions/<name>` endpoint (JSON or FormData); action names are discoverable from HTML form attributes on public pages, and the standalone Node adapter historically buffered the body with no size limit (CVE-2026-27729).
- Client-visible props: props serialized into `astro-island` custom elements and island hydration scripts; server-only data placed in a component prop is client-visible.
- Dynamic routes and `getStaticPaths` (`[param].astro`, rest params `[...slug]`) — prerendered vs on-demand changes the attack surface.
- Middleware (`src/middleware.js|ts`): `onRequest(context, next)` runs for on-demand pages and endpoints, stores request state in `context.locals`, supports `sequence()` chaining and `context.rewrite()` (which re-runs middleware and breaks `Request.body` consumption, a known interaction with form-based Astro actions).
- `prerender` export and the `output` config (`static` vs `server` vs `hybrid`) determine per-route render mode.
- SSR error rendering: custom prerendered `404.astro`/`500.astro` pages are fetched internally by the server (`prerenderedErrorPageFetch`), which trusts the request URL built from the `Host` header (CVE-2026-25545).
- Adapter behavior (`@astrojs/node` standalone/middleware, Vercel, Netlify, Cloudflare) decides which internal routes exist, which body limits apply, and which `security.*` settings are enforced.
- Build paths: `/_astro/<hash>.js|css`, `astro.config.mjs` integrations, `dist/` output layout.

## Preconditions

- SSR or hybrid output (or Server Islands present on an otherwise static site) for any live request handler to exist; a pure `output: 'static'` site with no `server:defer` has build-time-only endpoints.
- For the Server Islands surface: an SSR app using the Node standalone adapter (or an equivalent that mounts `/_server-islands/[name]`) — the route is registered regardless of whether any component uses `server:defer`.
- For the Host-header SSRF family: SSR mode, at least one custom prerendered `404.astro`/`500.astro` (or a custom error route), the `Host` header unsanitized by the edge (may require reaching the origin IP directly), and versions below `astro 5.17.2` / `@astrojs/node 9.5.3`.
- For the island-replay family: server islands in use on `astro < 6.1.10`, two different island components sharing a key name for one `props` and one `slots` parameter, a dynamically rendered page, and attacker control of the overlapping prop value.
- A page is auth-guarded while a sibling endpoint or Server Island handler for the same data is not — guards on `.astro` pages do not cover `src/pages/**/*.ts` endpoints or island handlers.
- Middleware coverage resolved before relying on it: middleware runs at build time for prerendered pages (no request context), runs on demand for SSR pages, and the adapter decides whether it runs for unmatched 404s; `handle`-layer auth in other frameworks has no direct Astro equivalent, so guards must be repeated or enforced in middleware that actually runs for the target route type.
- Body-size handling not enforced at a reverse proxy in front (for the missing-limit families); note the framework `security.serverIslandBodySizeLimit` default of `1048576` bytes (1 MB), added in `astro@5.18.0`, and that adapter versions decide enforcement.
- For the server-action body-limit family: on-demand rendered site with server actions defined (`src/actions/*`), `@astrojs/node` `9.0.0`–`9.5.3`, and at least one public page exposing a form action name; no authentication is required because action names are discoverable from HTML.
- Two independent fingerprint signals before applying a version note (adapter and Astro major both matter).

## Oracles

- Server-island route reachable: `POST /_server-islands/<name>` responds (200/valid JSON error/name validation) without authentication on an app that never intended to expose islands.
- Missing body limit: an unauthenticated oversized JSON `POST` to `/_server-islands/<name>` is buffered/parsed before the island name is validated, causing heap/memory exhaustion (CVE-2026-29772) — oracle is process memory pressure, not a data leak; test with a small benign payload first. The same shape applies to server actions on unpatched `@astrojs/node` (CVE-2026-27729): a single oversized `POST /_actions/<name>` is buffered before validation.
- Action endpoint exposure: `POST /_actions/<name>` with an `Accept: application/json` header returns the action result (or a validation error) without authentication when the action itself performs no auth check — the endpoint is generated, discoverable, and easy to miss in route reviews.
- Host-header SSRF: a request to any 404-triggering path with a forged `Host: <collaborator>` makes the SSR server fetch `http://<collaborator>/404.html`; if the collaborator 302-redirects to an internal URL, the internal body is returned (CVE-2026-25545). Control: the same request without the forged Host.
- Encrypted-parameter replay: an island's encrypted `p` (props) value replayed as another island's `s` (slots) value renders attacker-influenced raw HTML → XSS (CVE-2026-45028); requires the shared-key-name precondition, so treat as a construct to test only in scope.
- Replay control: a replayed ciphertext that fails decryption returns an error/bind failure instead of rendered HTML — that error is the patched behavior and a valid control.
- Island parameter shape: `astro-island` elements and their hydration fetch carry the encrypted `p`/`s` values; a site that renders islands but never forwards attacker-controlled props is reachable but not exploitable.
- Adapter matrix: `@astrojs/node` standalone, Vercel, Netlify, and Cloudflare adapters mount different internal paths and body limits — re-derive `/_server-islands/`, `/_actions`, and error-page behavior for the observed adapter instead of assuming the Node layout.
- Baseline for islands: request the island URL with a missing/invalid encrypted parameter first; the error shape (400 vs 500 vs rendered fragment) tells you whether the endpoint is reachable before you craft props.
- Static/prebuilt pages: when `output: 'static'`, endpoint files are build-time artifacts and `/_actions`/island routes may not exist at runtime — confirm from a 404/405 rather than assuming SSR.
- Endpoint-vs-page bypass: `/api/foo` (or any endpoint path) returns private data anonymously while the page rendering the same data is guarded.
- Client-prop disclosure: server-side-only values passed as component props appear in the `astro-island` element's serialized props or hydration script.
- Prerender confusion: a route expected to be dynamic is served as a stale prerendered file (or vice versa) because `prerender`/`output` differs from expectation — map by observing mutation vs static behavior.
- Middleware rewrite differential: `context.rewrite()` re-runs middleware and can throw on `Request.body` consumption with form actions — a 500/behavioral difference on a rewritten action route is worth classifying (framework correctness, not automatically a security finding).

## Minimal safe proof

1. Fingerprint: confirm Astro from `/_astro/` hashed assets and `astro-island` elements; determine output mode (static vs server vs hybrid) and adapter from behavior; record the Astro and adapter versions.
2. Baseline: request one guarded page and its data endpoint from owner and anonymous sessions; record status/body/redirect.
3. Endpoint probe (single variable): request the endpoint anonymously and diff against the guarded page.
4. Server-island probe: send one small, benign `POST` to `/_server-islands/<name>` (a valid JSON object, no size amplification) and classify the response shape; do not send amplification payloads.
5. Client-prop check: view the rendered HTML for one island and confirm whether server-only values are serialized into props (record field names only).
6. Host-header check: one 404-triggering request with a collaborator `Host` header; classify whether the server fetched the collaborator (a hit on your canary) — do not redirect to internal targets from the canary.
7. Stop conditions: any memory-pressure/crash signal, any other-user data, any state change, any code-execution attempt, or any request that risks DoS beyond a single benign probe — halt and report.

## False positives

- Endpoint returning 404 for an unregistered island name — absence is the control.
- `/_server-islands/` refusing oversized bodies (patched behavior with `security.serverIslandBodySizeLimit`) — the limit is the control.
- Client-visible props containing only public/non-sensitive data already rendered in HTML — no boundary crossed.
- Prerendered endpoint output being static — expected for `prerender`/static output, not an auth bypass.
- `astro-island` attributes echoing framework metadata — fingerprint, not disclosure.
- Dev-only verbose adapter errors — require production mode.
- Host header reflected in HTML/meta tags without a server-side fetch — require collaborator or internal bytes, or a followed redirect.
- Encrypted params that decode but do not reach a raw-HTML sink — the replay condition requires a shared key name and a slots sink; absent that, no XSS.
- Static (`output: 'static'`) site with server islands disabled — no `/_server-islands/` route to probe.

## Version/implementation notes

- CVE-2026-29772: Astro Server Islands missing request-body size limit (memory-exhaustion DoS). Advisory package `@astrojs/node < 10.0.0`, patched `10.0.0`; the vulnerable path is `/_server-islands/[name]`, registered for all SSR apps on the Node standalone adapter, with the body parsed before the island name is validated. `JSON.parse()` amplification is ~15x (wire bytes to heap); a ~8.6 MB body of empty objects crashed a 128 MB heap in the published PoC (astro 5.18.0, `@astrojs/node` 9.5.4). Fix adds/uses `security.serverIslandBodySizeLimit` (config reference: default `1048576` bytes, added `astro@5.18.0`).
- CVE-2026-27729: Astro server actions had no default request body size limit; a single large POST to a valid action endpoint crashed memory-constrained servers. Affected `@astrojs/node` `9.0.0`–`9.5.3`, patched `>= 9.5.4` (GHSA-jm64-8m5q-4qh8, PR #15564, commit `522f880b07a4ea7d69a19b5507fb53a5ed6c87f8`; CWE-770, Moderate, CVSS `AV:N/AC:H`). Action names are exposed in the HTML of pages that use them; no auth is needed to reach the parser. A 125 MB JSON body against a 128 MB heap reproduced the crash in the advisory PoC (astro 5.17.2, `@astrojs/node` 9.5.3).
- CVE-2026-25545: Host-header injection → SSR error-page fetch → SSRF with redirect following. Fixed in `astro 5.17.2`, `astro 6.0.0-beta.11`, `@astrojs/node 9.5.3`; the fix reads `/404.html`/`/500.html` from disk, validates `Host`, and only fetches elsewhere when `options.experimentalErrorPageHost` is explicitly set. Requirements: SSR mode, custom error page, unsanitized Host (often requires the origin IP behind a validating proxy).
- CVE-2026-45028: server-island encrypted parameters were not bound to their component or parameter type (`< 6.1.10`), allowing a props value to be replayed as a slots value (raw HTML) → XSS under the documented conditions; CWE-323.
- CVE-2026-45028 testing order: enumerate island components and their prop/slot key names from rendered HTML first; without an overlapping key name and an attacker-controlled value the replay construct cannot fire, so stop at enumeration.
- Patched-behavior checks for the island and action families: a size-limit rejection (413/400), an invalid-name validation error, and a Host-validation refusal all indicate a gated build — record the exact error shape as the control.
- For fixed-version confirmation under CVE-2026-29772, the `security.serverIslandBodySizeLimit` setting and the adapter version must both be present; a config alone on an old adapter does not enforce the limit.
- Recommended interim mitigation for unpatched SSR apps: cap body size at the reverse proxy/WAF and block `/_server-islands/*` from untrusted networks; keep custom error pages from being fetched by Host (validate Host at the edge).
- `output` semantics changed across Astro majors (`hybrid` merged/renamed, per-route `prerender` becomes the main switch); always resolve the major from behavior, not from memory.
- Server Islands exist as a first-class feature since Astro 5; older versions lack `/_server-islands/` entirely. Island props serialization format is version- and framework-adapter-specific; inspect the live element for the observed build.

## References

- [T1] Astro Server Islands guide (`server:defer`, per-island route fetched at runtime): https://docs.astro.build/en/guides/server-islands/
- [T1] Astro Endpoints guide (static vs SSR endpoint behavior): https://docs.astro.build/en/guides/endpoints/
- [T1] Astro configuration reference (`security.serverIslandBodySizeLimit`, default `1048576`, added `astro@5.18.0`): https://docs.astro.build/en/reference/configuration-reference/
- [T1] GHSA-3rmj-9m5h-8fpv / CVE-2026-29772 (Server Islands body-size DoS, route registered regardless of use, patched `@astrojs/node 10.0.0`; 15x amplification, 8.6 MB PoC): https://github.com/advisories/GHSA-3rmj-9m5h-8fpv
- [T1] CVE-2026-27729 advisory GHSA-jm64-8m5q-4qh8 (server actions body-size DoS; affected `@astrojs/node 9.0.0`–`9.5.3`, patched `>=9.5.4`; action names discoverable from HTML): https://github.com/withastro/astro/security/advisories/GHSA-jm64-8m5q-4qh8 ; GitLab mirror: https://advisories.gitlab.com/npm/@astrojs/node/CVE-2026-27729/
- [T1] CVE-2026-45028 (server-island encrypted-parameter replay; `< 6.1.10`; conditions): https://advisories.gitlab.com/npm/astro/CVE-2026-45028/
- [T2] Aikido, CVE-2026-25545 Astro Host-header SSRF (mechanics, patched versions, requirements): https://www.aikido.dev/blog/astro-full-read-ssrf-via-host-header-injection
- [T2] CVE-2026-29772 analysis (patch adds `security.serverIslandBodySizeLimit`, PR #15755): https://cvereports.com/reports/CVE-2026-29772 ; SentinelOne: https://www.sentinelone.com/vulnerability-database/cve-2026-29772/
- [T2] Miggo database entry (route registered on all SSR apps with the Node standalone adapter; body parsed before name validation): https://www.miggo.io/vulnerability-database/cve/CVE-2026-29772
- [T1] Astro Middleware guide (`src/middleware.ts`, `onRequest`, `locals`, `sequence()`, `context.rewrite()`, error-page behavior, adapter caveat): https://docs.astro.build/en/guides/middleware/
- [T2] Astro "Future of Astro: Server Islands" (architecture intent): https://astro.build/blog/future-of-astro-server-islands/
- frameworks.md (this pack's manifest) for cross-cutting oracles and deployment-config discipline
