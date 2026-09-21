# Frameworks — Nuxt

> SCOPE: Load when Nuxt / Nitro is fingerprinted (`x-powered-by: Nuxt`, `/_nuxt/` asset paths, `/__nuxt`, `useFetch` payloads, Nitro server routes) and SSR payload exposure, server routes, route rules, server islands, or payload caching are the research surface.

## Research families

- SSR payload / hydration state: `useFetch` and `useAsyncData` serialize server-side state into the page and into per-route `_payload.json`; server-only composables can leak private records into hydrated state.
- Runtime payload caching (route rules): `routeRules` with `swr`, `isr`, or cache directives plus the runtime payload cache (`cache:nuxt:payload`) — Nuxt 4.4.0+ runtime payload extraction (CVE-2026-71316).
- Server islands: `server:defer`-style islands fetched through `/__nuxt_island/<Name>_<hash>.json`; props are attacker-supplyable JSON, the URL hash is a deterministic unsalted content hash, not an authentication token (CVE-2026-71320).
- Payload extraction: `experimental.payloadExtraction` controls whether `/<route>/_payload.json` is emitted separately; when disabled the endpoint 404s and the page carries an inline payload instead — the documented interim mitigation for the payload-cache CVE.
- Nitro server routes: `server/api/**` (`/api/*`), `server/routes/**` (arbitrary path), `defineEventHandler`, catching-all routes `[...slug].ts`.
- Middleware: route middleware (`defineNuxtRouteMiddleware`), `routeRules.appMiddleware` gates, and server middleware (`server/middleware/**`) — the layer that may or may not run before a data/payload/island response.
- Nitro error handling and dev pages: `__nuxt_error`, verbose dev error responses, stack/`.output/` server bundle disclosure.
- Build/static paths: `/_nuxt/<hash>.js`, `/_nuxt/builds/meta/<buildId>.json`, `/_ipx/` image handler, `/__nuxt_error`, `/__nuxt_island/`.
- Client-visible props from `useState`/`useFetch` that never should have been serialized to the browser.

## Preconditions

- SSR (not fully static export) with at least one route fetching user-specific data via `useFetch`/`useAsyncData`; pure client-side fetch after hydration carries no SSR payload.
- Payload-cache family: Nuxt `>=4.4.0` and `<4.5.1` with `payloadExtraction` enabled and a route using SWR/ISR/hybrid caching that handles private data.
- Route-rule guard-skip family: `routeRules` with `appMiddleware` used as an authorization gate and a rule key containing an uppercase character (e.g. `'/Admin'` or `pages/Admin.vue`) on an unpatched `4.4.7`–`4.5.0` / `3.21.7`–`3.21.9` line.
- Server-island family: component islands active (a `.server.vue` component is registered) and a Node server deployment where `vue` is externalized — SSG deployments are largely unreachable, and island names are constrained to the build-time component registry.
- For island RCE: an island forwards attacker-influenced values into dynamic component resolution (`<component :is>`, `resolveDynamicComponent`, `h()`) or a polymorphic `as`/`asChild` prop (e.g. `@nuxt/ui`/`reka-ui`), including implicit attribute fallthrough onto such a root. An attacker who knows the component name and desired props can compute a valid island URL hash offline — the hash is integrity, not a secret.
- For the island DoS family: component islands active on an unpatched line; the endpoint parses/hashes the submitted body before validation, so oversized or `v-for`-expanding props are the pressure vector.
- The route-level guard (route middleware) is the only access control on the page — if authorization also runs inside the data fetcher or server route, the payload/cache differential is neutralized.
- Server routes reachable in scope; the guard on the page does not automatically cover `server/api` or `server/routes` handlers.
- CDN/reverse-proxy layer observed: payload responses may additionally be cached by path, amplifying exposure, and a leaked payload can persist upstream after upgrading.

## Oracles

- Payload guard bypass: `GET /<private-path>/_payload.json` from an anonymous session returns the hydrated SSR state (tokens, emails, records) that the page guard would have blocked in HTML (CVE-2026-71316).
- Payload cache cross-user: after an authenticated user loads a cached route, an anonymous request to the same `_payload.json` returns that user's serialized state because the cache key is path-only (no cookie, `authorization`, or `cache.varies` dimension) and the read resolves before route middleware.
- Shared-state leakage: `useState` values rendered into the SSR payload expose data fetched for a different request if state is not request-scoped.
- Server-route bypass: a Nitro `server/api/*` or `server/routes/*` handler returns private data while the corresponding page is auth-guarded — the guard was on the page, not the handler.
- Route-rule guard skip: `GET /Admin` (case variant) renders the guarded page while the `routeRules.appMiddleware` guard only matched `/admin` (GHSA-hxvh-4h3w-prp9).
- Island endpoint reachable: `POST/GET /__nuxt_island/<Name>_<hash>.json` with attacker-shaped `props` returns a rendered island fragment without the page's session guard; a `template` key inside forwarded props reaches Vue's runtime template compiler (CVE-2026-71320) — classify, never execute code.
- Island polymorphic-instantiation: without `vue.runtimeCompiler`, an undeclared prop forwarded onto a polymorphic `as` root (e.g. `{ "as": "iframe" }`) instantiates an arbitrary HTML element or globally registered component (GHSA-48hr-524c-v5w3) — no code execution, but a DOM/clickjacking-shaped primitive worth classifying.
- Island endpoint on a static build: an SSG/static deployment has no Nitro process to exploit and generally no `__nuxt_island` handler; confirm SSR before testing the family.
- Island DoS shape: an island prop that expands through `v-for`, or an oversized body parsed/hashed before rejection, consumes CPU/memory before any validation (GHSA-hxcr-hm88-mpq6 / GHSA-9pgf-384g-p7mv) — oracle is process pressure on a single benign probe, not a crash loop.
- Image handler differential (`/_ipx/`): remote-fetch-shaped parameter returns collaborator/internal bytes or a size/format error implying an upstream fetch.
- Dev/error verbosity: Nitro error output in dev exposes stack traces, module paths, or `.env`-shaped values; confirm production mode.

## Minimal safe proof

1. Fingerprint: confirm Nuxt from two signals (`x-powered-by`, `/_nuxt/` hashed assets, `__NUXT__` / payload shape) and record the version hint and route rules.
2. Baseline: request one private route's HTML from owner and anonymous sessions; record guard behavior.
3. Payload probe (single variable): request `/<same-path>/_payload.json` anonymously; if it returns hydrated state, capture only field names/shape, not the record contents.
4. Cache confirmation: load the route from the authenticated session, then re-request the payload anonymously; a changed-but-valid payload confirms shared-key caching without reading another user's PII.
5. Route-rule probe: request the ordinary path and one case variant of a guarded route; a 200 on the variant with the middleware skipped is the oracle (control: the correctly cased path is denied).
6. Server-route and island probe: request one `server/api` route anonymously and one `/__nuxt_island/` name with a benign JSON body; diff against the guarded page; do not send `template` keys, `v-for` expansion payloads, or oversized bodies.
7. Stop conditions: any other-user PII in the payload, any token/cookie value, any state change, any code execution attempt, or any CDN-poisoned response visible to a third party — halt and report.

## False positives

- `_payload.json` returning an empty/`null` payload or the same login redirect as the page — consistent denial.
- `_payload.json` 404 when payload extraction is disabled or the route is not cached — absence is the control (also the documented workaround behavior for CVE-2026-71316).
- Payload containing only public, non-user data already rendered in HTML — no confidentiality boundary crossed; require a session-scoped field (token, email, tenant).
- Dev-only verbose errors or source paths — require production mode.
- `/_ipx/` refusing an external host — refusal is the control.
- Route-rule caching present but keyed per session (custom cache keys) — confirm two sessions get distinct payloads before claiming shared-key exposure.
- Island endpoint 404 for an unknown component name or 400 for a blocked `template` key — patched behavior; require a 200 render of attacker-influenced props on an unpatched build.
- `render` keys inside island props — inert (props arrive as JSON, so a `render` value is a string Vue ignores); only `template` reaches the runtime compiler.
- Case-variant path returning the unguarded *public* page — no authorization boundary crossed; require a guarded page body.
- A route-rule key that case-matches but whose guard is also enforced inside the page/loader — the outer control passed.
- Dev-only issues (`nuxi dev --host` path disclosure, `@nuxt/devtools` RPC) — confirm a dev server is reachable and in scope before treating them as production findings.

## Version/implementation notes

- CVE-2026-71316: Nuxt `>=4.4.0, <=4.5.0` (fixed 4.5.1). Runtime payload caching activated in 4.4.0 stored SSR payloads under a path-only `cache:nuxt:payload` key and served them before route middleware; `cache.varies` does not mitigate because the payload cache ignores it. HTML stays correctly varied — only the extracted payload leaks. The fix re-gates runtime payload-cache reads/writes behind `import.meta.prerender`; `main`/v5 and the `3.x` line always kept the gate and are not affected. Advisory references: runtime payload extraction PR #34410 (commit `e1dade2175`). Interim mitigation: `experimental.payloadExtraction: false` (standalone endpoint 404s; page still serves a 200 with an inline payload), do not cache authenticated pages, require auth for `/**/_payload.json` at the CDN, and purge CDN caches after upgrading.
- CVE-2026-71320 (server-island RCE via runtime template injection): affected `>=4.0.0 <4.5.1` and `>=3.4.0 <3.21.10`; fixed `4.5.1`/`3.21.10`. Attack: `POST /__nuxt_island/<Name>_<hash>.json` with props like `{ "as": { "template": "<attacker-controlled>" } }` when the island forwards props into Vue dynamic-component resolution, explicitly or via attribute fallthrough onto a polymorphic root. Patch rejects decoded props containing a `template` key at any depth with HTTP 400 when `vue.runtimeCompiler` is enabled (on Node with externalized `vue` the vector still applies). Island names are registry-constrained; Nuxt 2 has no server islands.
- Nuxt 4.5.1 + 3.21.10 (2026-07-27 patch release) also fixed: route-rule authorization bypass with uppercase rule keys — a regression introduced by the CVE-2026-53721 fix, so `4.4.7+`/`3.21.7+` do not imply safety; route rules now match case-insensitively (`router.options.sensitive: true` restores case-sensitive matching); server-component DoS via the `/__nuxt_island` endpoint (`v-for` prop expansion and oversized body parsing); and `@nuxt/devtools@3.3.1` closes an unauthenticated RPC command-execution path over the Vite HMR socket (dev only). Lockfile refresh is required for the devtools fix.
- The island RCE patch rejects decoded props containing a `template` key at any depth with HTTP 400 (with a diagnostic suggesting a prop rename), and only when `vue.runtimeCompiler` is enabled — the default compiler-off configuration still renders legitimate props that merely contain a `template` field (e.g. CMS content). The advisory's earlier claim that `vue.runtimeCompiler` was required was corrected: with `vue` externalized (the default on Nuxt 4.x/3.x Node servers) the vector applies regardless.
- WAF/interim guidance for the island endpoint: a rule that URL-decodes and JSON-parses the `props` value and blocks `template`/`render` keys covers browser-originated island requests only — initial-SSR internal island renders do not transit the edge, so a clean WAF log does not prove the vector closed. Declaring island props explicitly or setting `inheritAttrs: false` also removes the fallthrough path.
- Upgrade hygiene: the recommended command is `npx nuxt upgrade --dedupe` so the lockfile actually pulls `@nuxt/devtools@3.3.1`; pinned release lines can use Socket's Certified Patches for Nuxt as an interim, but upgrading remains the recommended fix. For the payload CVE, upgrading alone does not evict an already-cached `_payload.json` — purge the CDN/edge cache too.
- Historically payload read/write was limited to static generation/prerender; the CVE-2026-71316 regression is specific to the 4.4.x runtime line — older Nuxt 3 static builds are not in that CVE's range but still serialize SSR state into the page body.
- Version-line rule: `3.21.10` is the backport for the island RCE/DoS and route-rule fixes, while the payload-cache CVE is 4.x-only (`>=4.4.0`); Nuxt 2 is unaffected by the island family (no server islands) but still serializes SSR state into the page.
- Server middleware (`server/middleware/**`) runs for every Nitro request, including `server/api`/`server/routes` handlers; when auth lives there, page-level payload/cache differentials usually close — verify where the guard actually runs before treating a payload read as a bypass.
- `/__nuxt_error` and the payload script are the two document-level reachability checks: view-source the page and look for serialized state; if private fields appear in the inline payload, the exposure exists even where `_payload.json` is disabled.
- Route-rule cache flags (`cache`, `swr`, `isr`) print in server response headers as cache-control/age variants — record the observed cache headers alongside each route so the payload probe targets a cacheable path.
- Baseline for the payload family: request `/<route>/_payload.json` with the owner session and anonymously; a difference in body hash (not just a redirect) is the minimum signal, then map which fields are session-scoped.
- Nitro server-routes mounting, the `/__nuxt_island/` endpoint, and the image handler (`/_ipx/`) exposure vary by preset/adapter (node, vercel, netlify, cloudflare); the deployed preset determines which internal paths exist.
- Route-rule names (`swr`, `isr`, `prerender`, `cache`), their case-matching semantics, and their interaction with payload extraction change across minor versions — pin the version from `/_nuxt/builds/meta/<buildId>.json` or the server banner.

## References

- [T1] Nuxt advisory GHSA-wm8w-6qjm-cv43 / CVE-2026-71316 (payload-cache disclosure, affected `>=4.4.0 <=4.5.0`, fixed 4.5.1, workarounds): https://github.com/nuxt/nuxt/security/advisories/GHSA-wm8w-6qjm-cv43
- [T1] Nuxt advisory GHSA-9473-5f9j-94wq / CVE-2026-71320 (`/__nuxt_island/` template-injection RCE, patch guard, WAF guidance): https://github.com/nuxt/nuxt/security/advisories/GHSA-9473-5f9j-94wq
- [T1] Nuxt Security Patch Releases (4.5.1 + 3.21.10; GHSAs for route-rule bypass, island DoS, devtools; `@nuxt/devtools@3.3.1`): https://nuxt.com/blog/v4-5-security
- [T1] Nuxt data fetching (`useFetch`/`useAsyncData`, SSR payload forwarding): https://nuxt.com/docs/4.x/getting-started/data-fetching
- [T2] Nuxt payload system overview (payload serialization, `_payload.json`): https://deepwiki.com/nuxt/nuxt/6.2-payload-system
- [T2] CVE-2026-71316 analysis (root cause, patch commit, affected `<4.5.1`): https://cvereports.com/reports/CVE-2026-71316 ; patch commit: https://github.com/nuxt/nuxt/commit/ac9b41a36b62296a117862254ee7d2b21a2a5203
- [T2] Nuxt 3 security hardening (SSR shared-state leakage, Nitro server routes): https://safeguard.sh/resources/blog/nuxt3-security-hardening-guide
- [T3] Payload file behavior on static sites (`_payload.json` per route): https://jsschools.com/nuxt/payload/
- frameworks.md (this pack's manifest) for cross-cutting oracles and deployment-config discipline
