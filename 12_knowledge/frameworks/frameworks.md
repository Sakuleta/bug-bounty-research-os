# Frameworks — Manifest

> SCOPE: Load when a framework, version, or generated surface is fingerprinted (headers, manifests, errors, bundles) and its specific routing, middleware, or serialization behavior is the research surface. This is the MANIFEST: shared model, family router, and cross-cutting oracles. Per-family depth lives in the sibling files listed below.

## Research families

This pack is hierarchical. Route to the family whose framework you fingerprinted; each sibling file carries the generated-surface map, router-generation/version exposure, oracles, false positives, and implementation notes for that framework.

- **Next.js** — `js-nextjs.md`: App/Pages router data routes (RSC, `?_rsc=`, `getServerSideProps`), Server Actions (`POST` + `Next-Action`), `middleware.ts` matcher vs API routes, `/_next/image` proxy, `_buildManifest.js`, rewrites/redirects, and the preannounced monthly security releases (`v16.2.11`/`v15.5.21` July 2026; `v16.3.3`/`v15.5.24` Aug 2026).
- **Nuxt** — `js-nuxt.md`: Nitro server routes, `_payload.json` payload caching (`cache:nuxt:payload`), `routeRules` SWR/ISR case matching, `useFetch`/`useAsyncData` SSR state, `/_nuxt/` assets, and the `/__nuxt_island/` server-island endpoint.
- **SvelteKit** — `js-sveltekit.md`: `+page.server.js` server `load`, `+server.js` endpoints, form `actions`, `hooks.server.js` `handle`, `__data.json`, `Vary: Accept` negotiation, `adapter-node` `ORIGIN`/`BODY_SIZE_LIMIT`, and `experimental.remoteFunctions`.
- **Remix** — `js-remix.md`: `loader` reads vs `action` writes, resource routes, `?_data=` / `.data` single-fetch representations, `?_routes=`, deferred data, and React Router v7 Framework/Data/RSC modes.
- **Astro** — `js-astro.md`: `src/pages` endpoints (static vs SSR), `server:defer` Server Islands (`/_server-islands/[name]`), server actions, `/_astro/` build paths, `prerender` export, and SSR error-page rendering.
- **Django** — `backend-django.md`: `/admin/`, DRF schema (`/api/schema/`, drf-spectacular), `DEBUG` tracebacks, Debug Toolbar, CORS, `SECRET_KEY` signing, and cache middleware (`UpdateCacheMiddleware`, `cache_page`).
- **Rails** — `backend-rails.md`: `/rails/info/routes|properties`, detailed exception page, Strong Parameters, `_method` tunneling, signed/encrypted cookies via `secret_key_base`, and Active Storage/libvips variant processing.
- **Spring** — `backend-spring.md`: `/actuator` discovery + `env|heapdump|mappings|gateway/routes`, `/error` Whitelabel, SpEL in gateway routes, management-port isolation, and health-group additional paths.
- **Laravel** — `backend-laravel.md`: `/telescope`, `/horizon`, `/_ignition/*`, `APP_DEBUG`, `/storage/*`, CSRF `$except` bypass, and the email validation rule.
- **Express** — `backend-express.md`: middleware ordering, `method-override`, `cookie-parser` signed cookies, `express-session`, `trust proxy`, CORS, and the multer/morgan/path-to-regexp companion middleware.

Cross-cutting (this file): middleware-versus-route enforcement, proxy/BFF header translation, manifest/source-map disclosure, method/content-type differentials, cache-key authorization gaps, Host-header trust in SSR paths, and deployment-config-unknown discipline.

## Preconditions

- Fingerprinted framework and plausible version from converging signals (headers, manifests, errors, static paths, bundles) — never a single string.
- Observed route, generated endpoint, or server boundary (data route, action, actuator, schema, docs) reachable in scope.
- Researcher-controlled sessions and objects for every authorization differential; generated-route reads stay read-only.
- Middleware, guard, or permission hypothesis stated before probing (which layer should deny, which layer might forget).
- Canonical XSS, SSTI, deserialization, and desync detail lives in web-browser/browser.md, parsers-injection/parsers.md, and http-edge-cache/http-desync-cache.md and is referenced here.
- Deployment configuration treated as unknown until observed; framework defaults are leads, not conclusions.
- The router generation (App vs Pages, Turbopack vs webpack, static vs SSR, adapter) resolved before applying any version note — the same advisory rarely covers every generation.
- The advisory release line resolved: Active/Maintenance LTS, current vs legacy major, package vs framework version (many 2026 advisories pin an adapter or companion package, not the framework itself).
- Any CDN/edge cache in front of the framework observed before judging a cache-key family; cross-user exposure can live in the framework cache, the CDN, or both.
- Request-body limits and Host-header validation at the edge observed before claiming an in-framework body-limit or Host-spoofing oracle.
- Generated endpoint paths re-derived from the live bundle/manifest each time; stale build-scoped URLs produce false negatives.

## Oracles

Cross-cutting oracles; each family file adds framework-specific ones.

- Data-route bypass: page requires auth in a browser but its data, payload, or JSON route returns researcher-record bodies without the session cookie.
- Middleware bypass: page path denies but the direct API, server-route, action, or rewritten internal path with the same session state allows.
- Proxy fetch confirmation: image, fetch, or SSR-shaped proxy parameter returns internal, metadata-shaped, or researcher-collaborator content instead of refusing.
- Action invocation gap: direct server-action, form-action, or mutation call with attacker-shaped parameters mutates researcher state despite client-side denial or missing token.
- Manifest disclosure: build, route, or schema manifest enumerates hidden, admin, or debug routes that reproduce as reachable endpoints.
- Debug and dashboard exposure: debug, actuator, schema, docs, console, or queue-dashboard path returns stack, mapping, environment-shaped, or queue data without auth.
- Source-map disclosure: map file for a production bundle returns original sources with endpoints, secrets-shaped strings, or internal hosts.
- Method and content-type differential: same framework route allows a state change under an alternate method, override header, or parser that the documented path denies.
- Cross-representation divergence: two representations of one route (HTML vs data/JSON, page vs endpoint, RSC vs SSR) return different authorization decisions for the same session state.
- Cache-key authorization gap: the HTML response is varied per session but the cached data/payload/JSON representation is keyed by path only, so a second session receives the first session's body (Nuxt `cache:nuxt:payload`; Django cache middleware `Vary` omissions).
- Host-header SSR fetch: an SSR error page, island, or rewrite builds an internal fetch URL from the client `Host` header and returns the fetched (or redirect-followed) internal body (Astro CVE-2026-25545; the Next.js custom-server family).
- Island endpoint exposure: `/_server-islands/[name]` or `/__nuxt_island/[name]_[hash]` answers without auth, accepts a `template` key, or lets encrypted props be replayed as slots.
- Route-rule guard skip: authorization middleware bound to a route rule is skipped for a case-variant path that still renders the guarded page (Nuxt `GHSA-hxvh-4h3w-prp9` family).
- Body-limit absence: an unauthenticated oversized JSON/multipart POST to an island, action, or upload endpoint is parsed before any name/authorization check (Astro `/_server-islands`, Astro server actions, multer).
- Release-line mismatch: observed framework generation falls in an advisory range but a later patch on the same minor line is installed — confirm the exact patched version, not just the major.

## Minimal safe proof

1. Fingerprint and generation: record two independent framework signals plus the observed version hint; resolve the router generation, the deployed adapter, and the advisory release line; list generated routes, manifests, and dashboard-shaped paths from the live bundle without fetching them yet.
2. Baseline: request the page and its data or action counterpart from owner, second-account, and anonymous sessions; record status, body hash, and redirect versus data behavior.
3. Single-path bypass probe: replay the data, action, or direct-API variant with exactly one variable changed (session removed, path rewritten, method swapped) and diff against baseline.
4. Proxy and manifest read-only check: request one manifest or proxy URL with a benign researcher-controlled target; treat collaborator or internal-shaped response as the oracle and stop before pivoting.
5. Debug-path read-only check: request one suspected debug, schema, or actuator index without credentials; record redacted shape only and halt before executing any exposed operation.
6. Body-limit and cache-family probes: never send amplification payloads; verify a cache-key gap by warming with the owner session and reading the payload/JSON anonymously, capturing field shape only.
7. Stop conditions: any stack trace with secrets, unrelated user record, successful state change outside researcher scope, memory-pressure/crash signal, or dashboard action surface — halt, preserve minimal evidence, clean up, and report.

## False positives

Cross-cutting; each family file carries its own disambiguation.

- Data route returning the same redirect or login JSON as the page — consistent denial across representations is the control passing, not bypass.
- Manifest listing only public routes already reachable from navigation — enumeration without a newly reachable restricted route is reconnaissance, not access control failure.
- Schema, docs, or actuator index visible with only health or version strings — metadata alone without mappings, environment values, or reachable operations is hardening context.
- Source map returning minified code without original sources or secrets-shaped strings — build artifact presence without source disclosure is not source disclosure.
- Image or fetch proxy that strictly allowlists domains and refuses researcher external URLs — refusal is the control; require fetched researcher-collaborator bytes.
- Debug toolbar marker in HTML without an enabled debug endpoint — framework fingerprint, not debug-mode exposure; require the executable debug response.
- Method-override header echoed but ignored by the backend — header reflection without a state change is not method confusion.
- CORS wildcard on a public asset route without credentialed researcher-data access — require cross-origin read of non-public researcher bytes.
- Cache warm that returns the same public fields for anonymous and owner — no confidentiality boundary crossed; require a cross-session body difference or a session-scoped field (token, email, tenant).
- Island endpoint answering 404/400 for an unknown or blocked name after patching — the control is the error; require a 200 render of attacker-influenced content on an unpatched build.
- Host-header reflection without a server-side fetch — require collaborator or internal bytes in the response, or a redirect chain the server followed.
- Encrypted-parameter replay that cannot satisfy the overlap conditions (shared key name, attacker-controlled value, dynamic render) — theoretical construct, not a finding.

## Version/implementation notes

- Next.js moved to a preannounced monthly security-release model in July 2026: nine CVEs fixed in `v16.2.11` (Active LTS) and `v15.5.21` (Maintenance LTS) on 2026-07-20; two critical RCEs fixed in `v16.3.3` and `v15.5.24` on 2026-08-25. Map a fingerprint by release line, not by the newest number alone.
- Nuxt patch lines: `4.5.1` + `3.21.10` on 2026-07-27 fixed island-prop RCE and island DoS alongside the payload-cache CVE (4.x only); the route-rule case-matching bug is a regression from the `CVE-2026-53721` fix, so `4.4.7+`/`3.21.7+` do not imply safety.
- Nuxt, SvelteKit, Remix, and Astro each separate load or loader reads from action or mutation writes; the write path is the higher-yield differential when reads look secure.
- Django, Rails, Spring, Laravel, and Express exposures cluster around debug flags, admin dashboards, schema endpoints, actuator or console paths, and companion middleware (multer/morgan/path-to-regexp) that differ per minor version.
- Gateway and BFF translation can add, strip, or rename auth headers between edge and framework; confirm which hop makes the authz decision before concluding bypass.
- Static-asset and chunk paths change per build; stale chunk or map URLs from memory produce false negatives — re-derive paths from the live bundle.
- Error-page verbosity and header fingerprints vary by environment setting; production versus development mode must be confirmed from live behavior.
- Framework security releases are batched and back-ported (e.g. Next.js LTS lines, Nuxt `3.x` backports, SvelteKit patch lines): pin the exact patched version when mapping a fingerprint to an exposure.
- Advisories increasingly pin the companion package rather than the framework: `@astrojs/node` (10.0.0), `@sveltejs/adapter-node` (2.57.1 for the `BODY_SIZE_LIMIT` bypass), `@nuxt/devtools` (3.3.1), `path-to-regexp`/`multer`/`morgan` for Express — fingerprint the dependency versions, not just the framework banner.
- Cache middleware and route rules are authorization surfaces in modern frameworks: always ask which request dimensions (cookie, `Authorization`, locale, host) are part of the cache key.

## References

- [T1] Next.js July 2026 security release (CVE-2026-64641..64649, patched versions): https://nextjs.org/blog/july-2026-security-release
- [T1] Next.js August 2026 security release (AVIF/libheif RCE, CVE-2026-75604 Windows RCE): https://nextjs.org/blog/august-2026-security-release
- [T1] Next.js CVE-2026-44578 WebSocket-upgrade SSRF (affected ranges, patched 15.5.16/16.2.5): https://github.com/vercel/next.js/security/advisories/GHSA-c4j6-fc7j-m34r
- [T1] Nuxt CVE-2026-71316 payload-cache disclosure advisory: https://github.com/nuxt/nuxt/security/advisories/GHSA-wm8w-6qjm-cv43 ; Nuxt patch-release blog: https://nuxt.com/blog/v4-5-security
- [T1] Nuxt CVE-2026-71320 server-island RCE advisory: https://github.com/nuxt/nuxt/security/advisories/GHSA-9473-5f9j-94wq
- [T1] Svelte ecosystem CVEs, January 2026 patched set: https://svelte.dev/blog/cves-affecting-the-svelte-ecosystem
- [T1] SvelteKit CVE-2026-40073 `BODY_SIZE_LIMIT` bypass advisory: https://github.com/advisories/GHSA-2crg-3p73-43xp ; CVE-2026-82259/82260 records: https://osv.dev/vulnerability/CVE-2026-82259 , https://osv.dev/vulnerability/CVE-2026-82260
- [T1] React Router CVE-2026-22030 CSRF advisory: https://nvd.nist.gov/vuln/detail/cve-2026-22030 ; CVE-2026-22029 open-redirect XSS: https://osv.dev/vulnerability/CVE-2026-22029 ; CVE-2026-53666 hydration constructor injection: https://github.com/remix-run/react-router/security/advisories/GHSA-337j-9hxr-rhxg
- [T1] Astro CVE-2026-29772 Server Islands body-size DoS advisory: https://github.com/advisories/GHSA-3rmj-9m5h-8fpv
- [T1] Django security releases July 2026 (6.0.7 / 5.2.16; cache, GDALRaster, DomainNameValidator CVEs): https://www.djangoproject.com/weblog/2026/jul/07/security-releases/ ; CVE-2026-35193: https://nvd.nist.gov/vuln/detail/CVE-2026-35193
- [T1] Rails Active Storage/libvips CVE-2026-66066 advisory: https://discuss.rubyonrails.org/t/cve-2026-66066-possible-arbitrary-file-read-and-remote-code-execution-in-active-storage-variant-processing/91432
- [T1] Spring advisories: CVE-2026-40976 https://spring.io/security/cve-2026-40976/ ; CVE-2026-22731 https://spring.io/security/cve-2026-22731 ; CVE-2026-22732 https://spring.io/security/cve-2026-22732
- [T1] Laravel CVE-2026-48019 CRLF-in-email-rule advisory: https://github.com/laravel/framework/security/advisories/GHSA-5vg9-5847-vvmq
- [T1] Express security releases: March 2026 `path-to-regexp` https://expressjs.com/en/blog/2026-03-30-security-releases/ ; June 2026 `multer`/`morgan` https://expressjs.com/en/blog/2026-06-30-security-releases/
- [T1] Next.js CVE-2024-34351 Server Actions SSRF (fixed 14.1.1): https://github.com/advisories/GHSA-fr5h-rqp8-mj6g
- Correction (this revision): the CVE-2026-44578 case study URL previously cited here and in `js-nextjs.md` (pasqualepillitteri.it) did not resolve this session; the primary Vercel advisory above (with the secondary analyses listed in `js-nextjs.md`) replaced it. CVE-2024-34351 was corrected from "image optimizer lineage" to the Server Actions SSRF lineage.
- [T1] Next.js config: `serverActions` (allowedOrigins, Origin/Host CSRF model): https://nextjs.org/docs/app/api-reference/config/next-config-js/serverActions
- [T1] Next.js config: `generateBuildId`: https://nextjs.org/docs/app/api-reference/config/next-config-js/generateBuildId
- [T1] NVD, CVE-2025-29927 (affected/fixed version ranges): https://nvd.nist.gov/vuln/detail/cve-2025-29927
- [T2] ProjectDiscovery, CVE-2025-29927 middleware authorization bypass (header mechanics): https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass ; OffSec: https://www.offsec.com/blog/cve-2025-29927/
- [T2] Astro CVE-2026-25545 Host-header SSRF research: https://www.aikido.dev/blog/astro-full-read-ssrf-via-host-header-injection ; CVE-2026-45028 island encrypted-parameter replay: https://advisories.gitlab.com/npm/astro/CVE-2026-45028/ ; CVE-2026-27729 server-action body limit: https://advisories.gitlab.com/npm/@astrojs/node/CVE-2026-27729/
- [T2] Ethiack, "Abusing Remix Routing Discrepancies" (`.data` requests bypass page guards): https://ethiack.com/info-hub/research/abusing-remix-routing-discrepancies
- [T2] OWASP Django Security Cheat Sheet (`DEBUG`, `SECRET_KEY`, admin URL, `check --deploy`): https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html
- [T2] Wiz, Spring Boot Actuator misconfigurations: https://www.wiz.io/blog/spring-boot-actuator-misconfigurations
- [T2] PortSwigger Web Security Academy: access-control, SSRF-proxy, and information-disclosure oracles reused per framework surface
- [T3] CVE-2026-5120 image-endpoint SSRF + cache poisoning writeup: https://www.zinruss.com/nextjs-image-optimization-vulnerability-ssrf-cache-poisoning-cve-2026-5120/ ; redirect-bypass PoC: https://github.com/shuvonsec/nextjs-ssrf-poc
- [T3] HackTricks Next.js surface map: https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/nextjs.html
- Companion packs: web-browser/browser.md for canonical XSS detail; parsers-injection/parsers.md for canonical SSTI and deserialization detail; http-edge-cache/http-desync-cache.md for edge-versus-origin normalization differentials that mimic framework routing bugs
- Family files in this directory: js-nextjs.md, js-nuxt.md, js-sveltekit.md, js-remix.md, js-astro.md, backend-django.md, backend-rails.md, backend-spring.md, backend-laravel.md, backend-express.md
