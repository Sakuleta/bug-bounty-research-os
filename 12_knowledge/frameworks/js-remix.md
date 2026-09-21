# Frameworks — Remix

> SCOPE: Load when Remix (now React Router v7 framework mode) is fingerprinted (`_data`/`.data` responses, `__remixContext`, `/_build/` asset paths, `X-Remix-*`, turbo-stream bodies) and loader/action boundaries, route representations, or resource routes are the research surface.

## Research families

- `loader` functions (GET/read) and `action` functions (POST/mutation) per route file; the same route URL serves both HTML and a data representation.
- Legacy data representation: `?_data=` query parameter (and index route form) returning the loader's JSON for a route without the page shell.
- Single Fetch data representation (Remix `v2.9.0` flag, `v2.13.0` stable as `future.v3_singleFetch`; default in React Router v7): `GET /<route>.data` (and `.data?_routes=routes/a,routes/b`) returning loader/action data as `turbo-stream`, executable code path.
- Nested-route data: a single fetch runs the loaders of all matching routes, including child loaders that a page-level guard never called.
- Resource routes: route modules with a `loader`/`action` and no default export, hit directly as JSON — expected to be API-shaped.
- Server-rendered secrets: `__remixContext` / the single-fetch inline stream embedded in the initial document.
- `headers()` export: now applies to both document and data requests under Single Fetch, affecting cache behavior of data responses.
- React Router v7 "framework mode" inherits this model; "data mode"/SPA mode changes what exists, and unstable RSC modes add server actions with their own CSRF surface.
- Serialization boundary: legacy `?_data=` returns JSON, Single Fetch returns `turbo-stream` (an executable representation); a client that trusts the decoded stream is the sink for the XSS/constructor-injection advisories below.
- Document POSTs: Framework mode routes with server-side `action` handlers accept cross-site document POSTs unless the app adds its own origin check (CVE-2026-22030).

## Preconditions

- Authorization is applied in the rendered page component, the URL path shape, or a parent route/`shouldRevalidate` gate rather than inside the data-producing `loader`/`action` that emits the data.
- The route has both a UI representation and a data representation (`.data` or `?_data=`); a resource route is data-only by design.
- For the child-loader family: a nested route whose parent checks auth while a child `loader` returns private data — the single fetch executes the child loader.
- Single Fetch enabled (default in RR7, `future.v3_singleFetch` in v2) for the `.data` representation; older Remix uses `?_data=`.
- Cookies are same-site so actions carry the session; actions have no framework CSRF token of their own (the CVE-2026-22030 family).
- For the document-POST CSRF family: RR7 `7.0.0`–`7.11.0` or `@remix-run/server-runtime` `<2.17.3` and server-side action handlers on UI routes.
- For the XSS family: a loader/action builds a redirect target from untrusted input on `@remix-run/router` `<1.23.2` or `react-router` `7.0.0`–`7.11.0`; a redirect from a hard-coded path is the control.
- For the hydration-constructor family: Framework/Data mode with manual SSR/hydration on `react-router >=6.4.0 <7.18.0` and application code that lets attacker input overwrite SSR-caught error fields.
- Mode resolved before any probe: Framework mode (server loaders exist), Data mode, Declarative mode, or SPA — the advisories apply only to specific modes; the CSRF advisory also covers the unstable RSC server-action modes.

## Oracles

- Data representation bypass: `GET /<guarded-route>.data` (or `?_data=routes/<route>`) from an anonymous session returns the private loader payload while the HTML page redirects.
- Child-loader leak: `GET /a/b/c.data` returns data from a child/nested loader even though the guard ran only on the parent page component (Ethiack routing-discrepancy class).
- Fine-grained revalidation surface: `.data?_routes=<list>` executes exactly the named loaders — enumerate routes and request each data representation directly.
- Action invocation gap: anonymous `POST` to an action URL mutates researcher-owned state because actions rely on SameSite cookies rather than a CSRF token.
- Document-POST CSRF (CVE-2026-22030): a cross-site document POST to a UI route with a server-side action handler performs the state change; control is the same request against Declarative/Data mode, which is not affected.
- Open-redirect XSS (CVE-2026-22029): a loader/action redirect built from untrusted input resolves to a `javascript:`-shaped target and executes client-side; control is a redirect built from a constant path.
- Resource-route disclosure: a resource route with a `loader` but no default export returns JSON to an unauthenticated client and was never covered by any page guard.
- Document-source leak: `__remixContext` / the streamed single-fetch payload in the initial HTML contains server-only data serialized for hydration.
- Hydration constructor injection (CVE-2026-53666): attacker input that overwrites SSR-caught error fields causes unexpected client-side constructor execution with outbound network — requires the specific app-layer code, so classify from source/behavior, not by payload fuzzing.

## Minimal safe proof

1. Fingerprint + mode: confirm Remix/RR7 from `__remixContext`/`_build/` assets and detect Single Fetch (`.data` works) vs legacy (`?_data=` works); note the route tree from the build manifest; record the router package version.
2. Baseline: request a guarded page and its data representation from owner and anonymous sessions; record status/body/redirect.
3. Data probe (single variable): request `/<route>.data` (or `?_data=`) anonymously; if it returns private fields, record shape only, never contents.
4. Child-loader probe: request the deepest nested route's `.data` anonymously to test whether only the parent guard ran.
5. Action probe: submit one action from an anonymous session that changes only researcher-owned state; keep the control with an invalid intent.
6. Representation matrix: for one route, compare HTML, `.data`, `?_data=`, and `?_routes=` responses under the same session — a divergence in authorization between representations is the finding.
7. Stop conditions: any other-user record, any mutation outside researcher scope, any leaked session token in the context, or any client-side code execution attempt — halt and report.

## False positives

- `.data` / `?_data=` returning the same redirect/login payload as the page — consistent denial.
- Resource route returning public, non-user data — by design, no boundary crossed.
- Single-Fetch `.data` returning `turbo-stream` that decodes to the same public fields as HTML — no private data.
- A 405/404 for an unrecognized method on the data route — the route declined, not bypassed.
- Dev-mode `__remixContext` verbosity — require production mode.
- `.data?_routes=` restricting to public routes only — enumeration without a restricted route reachable.
- Redirect to an external absolute URL that is not a `javascript:`-shaped target — open redirect impact depends on the client routing sink; require execution or a policy-boundary crossing.
- Redirect target that is fixed or server-mapped (e.g. `redirect('/dashboard')`) — no attacker influence over the URL, no CVE-2026-22029 sink.
- CSRF-shaped cross-site POST that the app already rejects via origin/Referer checks or SameSite cookies — the outer control passed; require the state change.

## Version/implementation notes

- Single Fetch (`future.unstable_singleFetch` in `v2.9.0` → `future.v3_singleFetch` in `v2.13.0` → default in React Router v7) replaces per-loader HTTP calls with one `.data` call using `turbo-stream`; this changed caching, serialization, and default revalidation, and it is the representation that makes child loaders reachable without the page.
- With Single Fetch, multi-route fetches use `GET /<path>.data?_routes=root,routes/a,routes/c`; a `clientLoader` calling `serverLoader()` issues its own `.<route>.data` call. Enumerate and request these directly.
- Default revalidation flipped from opt-in to opt-out on GET navigations; an `action` returning `4xx/5xx` no longer revalidates by default. These change which loader data a request will actually execute.
- Legacy Remix (pre-Single-Fetch) still exposes `?_data=` for loaders; both representations may exist during migration.
- React Router v7 framework mode keeps the loader/action model; data mode and SPA mode do not expose server loaders at all — confirm the mode before probing.
- Actions rely on same-site cookies; there is no per-form CSRF token, so cross-site-friendliness and cookie `SameSite`/`Secure` settings are the control to inspect. CVE-2026-22030 (CSRF on document POSTs to UI-route server actions; fixed `@remix-run/server-runtime 2.17.3` / `react-router 7.12.0`) and CVE-2026-22029 (XSS via loader/action open redirects; fixed `@remix-run/router 1.23.2` / `react-router 7.12.0`) both landed on the `7.0.0`–`7.11.0` line.
- CVE-2026-53666 (arbitrary client-side constructor injection via SSR hydration) affects `react-router >=6.4.0 <7.18.0`, patched `>=7.18.0`; Framework/Data mode doing manual SSR/hydration only, and requires app code that lets attacker input overwrite SSR-error fields. Declarative mode is unaffected.
- Fix-line mapping: `react-router 7.12.0` closed both CVE-2026-22029 and CVE-2026-22030; `@remix-run/router 1.23.2` and `@remix-run/server-runtime 2.17.3` are the v2 backports. Remix v1/v2 and RR7 therefore need separate checks when both package names appear in a migration.
- Resource routes and `.data` both bypass the document render path; a guard written in the root route's component (or a layout component) does not run for either. Only loader/action-level or server-middleware checks survive.
- Single Fetch moved `headers()` into data responses; when a private loader result is cacheable because the app never set `Vary`/`Cache-Control` there, the `.data` URL is the shared-key artifact to test.
- If both `?_data=` and `.data` answer on the same route, probe both under the same session: a migration can leave the legacy representation with weaker handling than the new one.
- Route inventory for this family: enumerate routes with a `loader` from the build manifest, then request each `.data` URL anonymously — routes with a default export (UI pages) are the highest-yield targets because developers put guards in the component.
- Baseline control: `.data` returning 200 with `null`/empty loader data is a reachable route with nothing to leak; require a body difference between owner and anonymous before claiming a bypass.
- Record the exact `.data` URL and any `?_routes=` list in evidence: the representation is content-negotiated, so a wrong suffix silently returns HTML and looks like a denial — verify the response media type before concluding the route is guarded.
- Application-layer guards that only run in the rendered component, or in a `shouldRevalidate`/navigation hook, are not invoked by a direct `.data` request — map which layer denies before probing, then make the data route the one-variable test.
- A `headers()` export now governs caching of data responses under Single Fetch; if the app does not vary or no-cache private loader data there, the data representation can become a shared-cache artifact even when the HTML is protected.
- The `?_routes=` list is a routing primitive, not an authorization boundary: requesting exactly the private route IDs executes exactly those loaders — enumerate IDs from the manifest, never fuzz paths blindly.
- Remix v1/v2 (`@remix-run/router`/`server-runtime`) are covered by the CVE-2026-22029/22030 ranges alongside RR7 — check both package names when fingerprinting a migrated app.

## References

- [T1] Remix `loader` docs: https://remix.run/docs/en/main/route/loader
- [T1] Remix Single Fetch guide (`.data`, `?_routes=`, turbo-stream, revalidation, resource routes): https://remix.run/docs/en/main/guides/single-fetch
- [T1] NVD CVE-2026-22030 (CSRF on document POST; fixed 2.17.3 / 7.12.0): https://nvd.nist.gov/vuln/detail/cve-2026-22030
- [T1] OSV CVE-2026-22029 (XSS via open redirects from loaders/actions; fixed `@remix-run/router 1.23.2` / `react-router 7.12.0`): https://osv.dev/vulnerability/CVE-2026-22029
- [T1] GHSA-337j-9hxr-rhxg / CVE-2026-53666 (SSR-hydration constructor injection; `>=6.4.0 <7.18.0`, patched `7.18.0`): https://github.com/remix-run/react-router/security/advisories/GHSA-337j-9hxr-rhxg
- [T2] Ethiack, "Abusing Remix Routing Discrepancies" (`.data` requests bypass page guards, child loaders still execute): https://ethiack.com/info-hub/research/abusing-remix-routing-discrepancies
- [T2] Secondary summary of the Ethiack finding (authorization belongs on the loader, not the page wrapper): https://nhimg.org/articles/remix-routing-discrepancies-can-bypass-page-guards-and-leak-data/
- [T2] Remix security field notes (loader/action auth, session, CSRF absence): https://ironimo.online/blog/remix-security-testing-loader-action-authentication-session-management-csrf
- [T3] Remix `?_data=` handling discussion (the parameter is framework-managed): https://github.com/remix-run/remix/discussions/9354
- frameworks.md (this pack's manifest) for cross-cutting oracles and deployment-config discipline
