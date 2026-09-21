# Frameworks — Next.js

> SCOPE: Load when Next.js is fingerprinted (`x-powered-by`, `__NEXT_DATA__`, `/_next/` asset paths, `x-nextjs-cache`, `vary: RSC, Next-Router-State-Tree`) and its router generation, data routes, Server Actions, middleware, or image/rewrite proxy are the research surface.

## Research families

- Pages Router data routes: `getServerSideProps` / `getStaticProps` JSON exposed through the page URL and `__NEXT_DATA__`; `/_next/data/<buildId>/<route>.json` for `getStaticProps` pages.
- App Router data routes: React Server Component (RSC) flight payloads — `?_rsc=` query, `RSC: 1` request header, `Next-Router-State-Tree` — returning serialized server data without the page shell.
- Server Actions (`"use server"`): `POST` to the page/action URL carrying the `Next-Action` header with an action ID; action IDs and `use cache` endpoint IDs can be globally disclosed (CVE-2026-64643).
- Middleware / proxy: `middleware.ts` at project root with optional `config.matcher`; the internal `x-middleware-subrequest` header used for recursion tracking (CVE-2025-29927); App Router + Turbopack + single-locale i18n bypass (CVE-2026-64642).
- Image Optimization API: `/_next/image?url=&w=&q=` with `images.remotePatterns` allowlist; redirect-following and SVG handling have shipped SSRF/DoS; AVIF handling through `sharp`/libheif shipped unauthenticated RCE in Aug 2026.
- Rewrites/redirects/headers (`next.config.js`): external destinations built from request-controlled host input (CVE-2026-64645).
- Build manifests and static paths: `/_next/static/<buildId>/_buildManifest.js`, `_ssgManifest.js`, page/route chunk paths, `/_next/static/media/`.
- Header-forwarding on custom servers: Server Action forward/redirect plus attacker-controlled Host-associated headers (CVE-2026-64649); the pre-14.1.1 equivalent is CVE-2024-34351.
- Self-hosted Node server: WebSocket upgrade proxying (CVE-2026-44578) and Windows-filesystem path traversal (CVE-2026-75604) — both absent on Vercel-hosted deployments.
- Server-side `fetch` response cache: body-keyed cache confusion (CVE-2026-64647/64648) on routes that fetch with request bodies.

## Preconditions

- Router generation resolved first: Pages Router (`__NEXT_DATA__`, `/_next/data/`) vs App Router (`RSC: 1`, `/_rsc=`, `Next-Router-State-Tree`), and bundler (webpack vs Turbopack) for the middleware-bypass family.
- For middleware bypass: the target relies on `middleware.ts` (not per-route/route-handler checks) for the auth decision; middleware absent or already enforcing inside the route handler closes this surface.
- For CVE-2026-64642: App Router built with Turbopack and exactly one entry in `config.i18n.locales`.
- For Server Actions: at least one `"use server"` action exists and is reachable; the request is `POST` (actions are POST-only) with a resolvable action ID.
- For the image proxy: `images.remotePatterns` (or legacy `domains`) is configured for remote hosts — the optimization API does not fetch arbitrary upstreams by default.
- For rewrite SSRF: a `rewrites()`/`redirects()` rule builds its external destination hostname from request-controlled input.
- For cache confusion (CVE-2026-64647/64648): a route performs a server-side `fetch` with a request body; two researcher-controlled requests to the same URL with different bodies are enough to observe the cache returning the other body.
- For the AVIF image-optimizer family (GHSA-2xp9-vwfh-vxw4 / GHSA-g89c-p67h-r497): self-hosting with the default image loader and remote images configured, on a `sharp`/libheif line below the patched release; patched releases disable AVIF optimization entirely.
- For the WebSocket family: self-hosted Node server (`next start` / custom server) reachable directly, not behind a host-validating proxy or Vercel routing.
- For the Windows RCE family: server runs on a Windows filesystem and the app uses both Pages Router and App Router without Cache Components.
- Build ID observed from the live bundle; never reuse a remembered build ID (paths are build-scoped).
- Custom-server deployments (not `next start`) for the Host-header Server Action SSRF family.

## Oracles

- Middleware bypass: a protected page/route returns 200 with data when the version-appropriate `x-middleware-subrequest` value is supplied; the same request without the header redirects or 403s. The value mirrors the middleware module path for that generation and must be derived from the observed bundle, not from memory.
- i18n middleware bypass (App Router + Turbopack, single locale): a request variant carrying the configured locale prefix reaches the route handler while the middleware/proxy check is skipped; control is the same request without the i18n prefix, which is denied.
- Data-route bypass: `__NEXT_DATA__` / `/_next/data/<buildId>/<route>.json` / `?_rsc=` for a page that hides auth both in the browser and server-side returns the private `props`/RSC tree to an anonymous session.
- Server Action invocation gap: `POST` to the action URL with `Next-Action: <id>` and no prior token mutates researcher-owned state; control is the same POST with a wrong/absent action ID.
- Action-ID disclosure: RSC/manifest responses enumerate `use server` action IDs and `use cache` endpoint IDs for reconnaissance (CVE-2026-64643) — disclosure alone is reconnaissance, not yet a finding.
- Image proxy fetch: `/_next/image?url=<researcher-collaborator or metadata URL>&w=64&q=75` returns fetched bytes (or a size/format error that implies a fetch) instead of refusing; an allowlisted host that 301/302-redirects to a forbidden host is the redirect-bypass oracle.
- Rewrite SSRF / open redirect: a `rewrites()` rule whose hostname is attacker-influenced reaches an arbitrary host despite the rule's hostname suffix; the `redirects()` twin yields a 3xx to the attacker host.
- WebSocket-upgrade SSRF (self-hosted, <15.5.16 / <16.2.5): an upgrade request with an attacker-influenced target is proxied, and the response carries collaborator- or internal-shaped bytes; control is a plain HTTP request to the same target, which is refused.
- Windows path/RCE family: on Windows-hosted apps, a crafted request path reaches the RCE primitive (CVE-2026-75604) — version fingerprint first; do not exercise the primitive outside an authorized lab.
- Fetch-cache confusion: a server-side `fetch(new Request(init), aDifferentInit)` or an invalid-UTF-8 body returns another request's cached body (CVE-2026-64647/64648); oracle is the second researcher request returning the first researcher request's body — a cache-integrity finding, not an authz bypass.
- Data-route representation (RSC): `GET /<route>` with `RSC: 1` and `Next-Router-State-Tree` returns the flight payload for the tree; a guarded page whose flight payload renders private data anonymously is the App Router equivalent of the Pages `__NEXT_DATA__` oracle.
- Source/manifest disclosure: `_buildManifest.js` / route lists expose admin or debug routes that reproduce as reachable endpoints.

## Minimal safe proof

1. Fingerprint + generation: confirm Pages vs App Router from two signals (`__NEXT_DATA__` vs `RSC: 1` / `Next-Router-State-Tree`), capture the `buildId`, and list generated routes without fetching each.
2. Baseline: request one page and its data counterpart (`__NEXT_DATA__`, `/_next/data/<buildId>/...json`, or `?_rsc=`) from owner and anonymous sessions; record status, body hash, redirect-vs-data.
3. Middleware probe (single variable): replay the anonymous protected request adding only `x-middleware-subrequest` with the observed value; diff against baseline; keep the no-header control.
4. Action probe (single variable): replay the accepted action `POST` from an anonymous session; stop at the first mutation on researcher-owned state.
5. Proxy/manifest read-only: request one `/_next/image` URL pointed at a collaborator you control, and request the manifest; do not pivot or fetch internal metadata beyond classification.
6. Release-line check: map the observed version to the Active/Maintenance LTS advisory tables and note which 2026 CVE applies before concluding; AVIF/Windows/WebSocket families are fingerprints, not to be exercised.
7. Stop conditions: any leaked secret in an error payload, any other-user record, any mutation outside researcher scope, any action reaching a dashboard, or any attempt to trigger the RCE/DoS primitives — halt and report.

## False positives

- `_buildManifest.js` / RSC payload listing only public routes — enumeration without a newly reachable restricted route is not a bypass.
- Data route returning the same redirect/login JSON as the page — consistent denial is the control passing.
- `x-middleware-subrequest` echoed or accepted without changing routing — the patched builds ignore/strip it externally; require an authorization decision flip backed by the no-header control.
- `/_next/image` returning a 400 for a non-allowlisted host — refusal is the control; require fetched collaborator bytes.
- `NEXT_PUBLIC_*` values in the bundle — intentionally client-inlined, not a secret leak.
- Dev-only verbose errors — confirm production mode before treating a stack as disclosure.
- Rewrite/redirect hostname the attacker cannot actually control (static suffix honored) — require the host-suffix boundary to be crossed.
- Action IDs disclosed without a reachable action invocation — reconnaissance only; the POST must mutate researcher-owned state.
- RSC flight payload returning the same public data as the HTML — representation difference without a confidentiality delta.
- Cache-confusion response body differing but containing only public data — integrity/cache-poisoning context, not data disclosure; require another user's or a privileged body.
- WebSocket upgrade returning a normal HTTP error instead of proxying — the patched behavior; require collaborator bytes.
- AVIF/WASM paths returning errors on patched builds — patched releases disable AVIF optimization until the upstream fix, so absence of a crash is the control.

## Version/implementation notes

- CVE-2025-29927 (middleware authorization bypass via `x-middleware-subrequest`): affects `>=11.1.4` and `<12.3.5`, `<13.5.9`, `<14.2.25`, `<15.2.3`; patched builds removed external trust of the header. Present only when the authz decision lives in middleware.
- July 2026 security release (2026-07-20; patched in `v16.2.11` Active LTS and `v15.5.21` Maintenance LTS; also in `16.3.0-canary.92` / `16.3.0-preview.7`): CVE-2026-64641 CPU-exhaustion DoS via Server Actions (App Router), CVE-2026-64642 middleware/proxy bypass (App Router + Turbopack + a single `config.i18n.locales` entry), CVE-2026-64643 unauthenticated disclosure of internal Server Function and `use cache` endpoint IDs, CVE-2026-64644 SVG CPU-exhaustion DoS in `/_next/image`, CVE-2026-64645 SSRF in `rewrites()` / open redirect in `redirects()` via attacker-controlled destination hostname, CVE-2026-64646 unbounded Server Action payload memory consumption (Edge runtime), CVE-2026-64647 cache confusion for bodies containing invalid UTF-8, CVE-2026-64648 cache confusion for `fetch(new Request(init), aDifferentInit)`, CVE-2026-64649 SSRF in Server Actions on custom servers via Host-associated headers.
- August 2026 security release (2026-08-25; patched in `v16.3.3` Active LTS and `v15.5.24` Maintenance LTS): GHSA-2xp9-vwfh-vxw4 / GHSA-g89c-p67h-r497 — unauthenticated RCE through `sharp`/libheif when optimizing attacker-controlled AVIF images (patched releases disable AVIF optimization until the upstream fix propagates); CVE-2026-75604 / GHSA-p293-qw3h-jr36 — unauthenticated RCE on Windows-hosted servers using Pages and App Router without Cache Components; Linux/macOS unaffected; no workaround. Next.js moved to a preannounced monthly security-release model starting July 2026.
- CVE-2026-64647/64648 mechanics: 64647 triggers when request bodies contain invalid UTF-8 byte sequences (the advisory's example: the UTF-16 byte sequences for `삃삃` and `섄섄` share the same cache entry); 64648 triggers only for the `fetch(new Request(init), aDifferentInit)` shape. Both return a different request's cached response body for the same URL.
- CVE-2026-44578: pre-auth SSRF in the self-hosted Node WebSocket upgrade handler — a crafted `GET`/upgrade request makes the server proxy to arbitrary internal or external destinations (secondary reporting cites `localhost:80`), exposing internal services and cloud metadata. Affected `>=13.4.13 <15.5.16` and `>=16.0.0 <16.2.5`; patched `15.5.16`/`16.2.5`; Vercel-hosted deployments unaffected. Workaround: block WebSocket upgrades at the proxy and restrict origin egress.
- Image optimizer SSRF lineage separates from Server Action SSRF: CVE-2024-34351 (`next >=13.4.0, <14.1.1`, patched `14.1.1`) is SSRF in **Server Actions** when a self-hosted action redirects to a relative path and the `Host` header is attacker-controlled (Assetnote) — not the image optimizer. The image-endpoint lineage is the redirect re-check bypass for `remotePatterns` and CVE-2026-5120 (image-endpoint SSRF plus downstream edge cache poisoning). (Correction: earlier revisions of this pack grouped CVE-2024-34351 under the image-optimizer lineage.)
- Server Action anti-CSRF is an `Origin` vs Host comparison, tunable via `serverActions.allowedOrigins`; a too-broad or misconfigured origin list widens the action surface. App Router actions are POST-only with `bodySizeLimit` (default 1 MB) — the Edge-runtime limit bypass is CVE-2026-64646.
- `buildId` is set by `generateBuildId`; consistent IDs across containers are common, so `/_next/data/<buildId>/` paths are guessable and stable.
- LTS labels are part of the version note: `15.5.x` is the Maintenance LTS line and `16.x` the Active LTS line at the time of the July/August 2026 releases; a `14.2.x` deployment is outside the patched lines entirely even if it is "still Next.js".
- Middleware matcher scope matters for every bypass family: a `config.matcher` that excludes a path means the middleware never ran there, so a 200 is not a bypass but an unguarded route by design — read the matcher from the build before interpreting a result.
- Server Actions on a self-hosted custom server are the intersection of three families (Host-header SSRF, origin-check CSRF, body limits): resolve which server is in front (`next start` vs custom Node server vs Vercel routing) before choosing the probe.

## References

- [T1] Next.js, July 2026 Security Release (primary; CVE list, patched versions): https://nextjs.org/blog/july-2026-security-release
- [T1] Next.js, August 2026 Security Release (AVIF/libheif RCE, CVE-2026-75604, patched `v16.3.3`/`v15.5.24`): https://nextjs.org/blog/august-2026-security-release
- [T1] Vercel advisory GHSA-c4j6-fc7j-m34r / CVE-2026-44578 (WebSocket upgrade SSRF, affected `>=13.4.13 <15.5.16`, `>=16.0.0 <16.2.5`): https://github.com/vercel/next.js/security/advisories/GHSA-c4j6-fc7j-m34r
- [T1] GHSA-fr5h-rqp8-mj6g / CVE-2024-34351 (Server Actions SSRF via Host + relative redirect; patched 14.1.1): https://github.com/advisories/GHSA-fr5h-rqp8-mj6g
- [T1] Next.js config: `serverActions` (allowedOrigins, Origin/Host CSRF model): https://nextjs.org/docs/app/api-reference/config/next-config-js/serverActions
- [T1] Next.js config: `generateBuildId`: https://nextjs.org/docs/app/api-reference/config/next-config-js/generateBuildId
- [T1] NVD, CVE-2025-29927 (affected/fixed version ranges): https://nvd.nist.gov/vuln/detail/cve-2025-29927
- [T2] ProjectDiscovery, CVE-2025-29927 middleware authorization bypass (header mechanics): https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass ; OffSec: https://www.offsec.com/blog/cve-2025-29927/
- [T2] CVE-2026-44578 secondary analyses (absolute-form/upgrade mechanics): https://strapi.io/blog/cve-2026-44578-nextjs-websocket-ssrf-vulnerability ; https://hadrian.io/blog/next-js-websocket-ssrf-unauthenticated-access-to-internal-resources-cve-2026-44578-2
- [T2] CVE-2026-44578 PoC repository: https://github.com/dinosn/CVE-2026-44578
- [T3] CVE-2026-5120 (image-endpoint SSRF + cache poisoning): https://www.zinruss.com/nextjs-image-optimization-vulnerability-ssrf-cache-poisoning-cve-2026-5120/
- [T3] Redirect-bypass PoC for the image optimizer (`/_next/image`): https://github.com/shuvonsec/nextjs-ssrf-poc
- [T3] HackTricks, Next.js surface map: https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/nextjs.html
- frameworks.md (this pack's manifest) for cross-cutting oracles and deployment-config discipline
