# Frameworks — Express / Node middleware

> SCOPE: Load when Express (or Node middleware) is fingerprinted (`X-Powered-By: Express`, `connect.sid`, `etag` shape, `Express` error template) and middleware ordering, method tunneling, proxy trust, signed cookies, sessions, CORS, or the multer/morgan/path-to-regexp middlewares are the research surface.

## Research families

- Middleware ordering: `app.use()` runs in registration order; a route registered before the auth middleware, or `app.use` after `res.send`, leaves the guarded path reachable.
- Router mounting: `express.Router()` with `router.use(auth)` vs per-route middleware; a router mounted without the guard, or a route defined before the guard, decides the outcome.
- `method-override`: `_method` query string / body field or `X-HTTP-Method-Override` header (default getter `X-HTTP-Method-Override`, default allowed original methods `['POST']`).
- `cookie-parser` signed cookies: `cookieParser(secret)` sets `req.secret` and lets `res.cookie(..., {signed:true})` / `req.signedCookies` be verified with HMAC — signature is tamper detection, not confidentiality.
- `express-session`: `req.session`, cookie name `connect.sid` by default, `secret` option, `cookie.sameSite`/`secure`, store choice.
- `trust proxy` setting: `X-Forwarded-For` for `req.ip`, `X-Forwarded-Host` for `req.hostname`, `X-Forwarded-Proto` for `req.protocol`.
- CORS: the `cors` middleware with `origin: true`/`*` and `credentials: true`.
- Static/URL parsing: `express.static` mount order, `express.urlencoded({extended:true})`, path normalization.
- `body-parser` (bundled as `express.json`/`express.urlencoded`): URL-encoded bodies with very large numbers of parameters are handled inefficiently (CVE-2025-13466, `2.2.0`); the 100 KB default body limit does not prevent the CPU/memory cost.
- Companion middlewares: `multer` (multipart, `diskStorage`), `morgan` (`:remote-user` token, access logs), `path-to-regexp` (route-pattern compilation) — each with its own 2026 advisory line.

## Preconditions

- The auth/guard middleware is registered after the route it is meant to protect, or the guarded logic lives in a router mounted without the guard — the oracle is a reachability outcome, not a code read.
- `method-override` is enabled and the target route has a destructive handler reachable by the tunneled verb.
- `trust proxy` is set to `true` (or a hop count) AND the front-most trusted proxy does not overwrite `X-Forwarded-*` — otherwise the client can supply `X-Forwarded-Host`/`X-Forwarded-For`.
- Signed cookies or `express-session` are in use with a weak/known/guessable `secret` (or the secret is exposed elsewhere), for the forgery family.
- CORS configured with a reflected/wildcard origin plus `credentials: true`.
- Two independent fingerprint signals; note Express major (`X-Powered-By` is often removed) from behavior.
- For the multer family: a multer-parsed multipart endpoint reachable, `diskStorage` for the disk-exhaustion variant, and `append-field` field-name parsing for the nested-name variant.
- For the morgan family: access logs use a format containing `:remote-user` (including the built-in `combined`/`common`/`default`/`short` formats) on `morgan >= 1.2.0 <= 1.10.1`.
- For the path-to-regexp family: routes compiled from user-influenced patterns, or a dependency line older than the patched versions below (three-plus parameters in one segment; sequential optional groups; multiple wildcards).
- For the body-parser family: `body-parser` `2.2.0` (or a framework bundling it) parsing `application/x-www-form-urlencoded` on a route reachable without auth.

## Oracles

- Ordering bypass: a protected path returns data/status to an anonymous session because its handler was registered before the auth middleware (control: a sibling route registered after the guard denies).
- Method-tunnel bypass: `POST` with `_method=DELETE` (query or body) or `X-HTTP-Method-Override: DELETE` reaches a destructive handler that a plain `GET`/`POST` refused.
- Proxy-trust spoofing: with `trust proxy: true`, a client-supplied `X-Forwarded-Host` changes `req.hostname` (password-reset link poisoning / cache key), or `X-Forwarded-For` bypasses IP-based rate limits/allowlists.
- Signed-cookie forgery: a cookie rewritten with a guessable/known secret is accepted as a valid signed cookie; control is the same tampered cookie rejecting under an unknown secret.
- Session fixation: the session ID is not rotated on login, so an attacker-set `connect.sid` is adopted post-authentication.
- CORS credentialed read: the server reflects the attacker `Origin` with `Access-Control-Allow-Credentials: true` on a private route.
- Error verbosity: the default Express error handler returns stack traces when `NODE_ENV` is not production.
- Multipart nested-name DoS: a multipart body whose field names use deep bracket notation (`a[b][c]...`) forces allocation of deeply nested objects during parsing (CVE-2026-5079) — single small probe, never a deep-nesting payload.
- Upload-cleanup DoS: aborted multipart uploads through `multer.diskStorage` leave orphaned partial files that accumulate on disk (CVE-2026-5038) — observe with one aborted upload only.
- Log forging: a `Basic` `Authorization` header containing CR/LF injects forged lines into the access log through morgan's `:remote-user` token (CVE-2026-5078).
- Route-pattern ReDoS: request patterns that trigger catastrophic backtracking in the installed `path-to-regexp` line (CVE-2026-4867/4926/4923) — timing oracle, single request.
- Parameter-count pressure: a URL-encoded body with thousands of distinct parameter names inflates CPU/memory inside the default 100 KB limit (CVE-2025-13466) — timing oracle on one researcher request, never a sustained flood.

## Minimal safe proof

1. Fingerprint: confirm an Express-shaped stack from two signals (header shape, `connect.sid`, error template) and record the Express major plus the installed `multer`/`morgan`/`path-to-regexp`/`cookie-parser`/`express-session` lines.
2. Baseline: request a protected path and a sibling path from owner and anonymous sessions; record status/body.
3. Ordering probe: request one protected path anonymously; the sibling-after-guard route is the control.
4. Tunnel probe: on a researcher-owned object, one `_method`/`X-HTTP-Method-Override` request to a denial-only path; stop at the first state change.
5. Proxy probe: add only `X-Forwarded-Host`/`X-Forwarded-For` to a benign request and observe whether `req.hostname`/rate-limit behavior changes (control: same request without the header).
6. Cookie probe: tamper one byte of your own signed cookie and confirm rejection before any forgery attempt; never forge against another account.
7. Middleware-version probe: map the installed companion versions against the advisories below before testing multipart/log/route-pattern behavior; use one benign request per family.
8. Stop conditions: any other-user record, any destructive action beyond researcher scope, any real session secret, any file-upload abuse beyond a single aborted request, or any sustained ReDoS timing — halt and report.

## False positives

- `X-Powered-By: Express` present/absent — fingerprint only, not a vulnerability.
- `X-HTTP-Method-Override` echoed but the route still denies — require actual re-dispatch.
- `trust proxy` set but the reverse proxy overwrites `X-Forwarded-*` — the header cannot be spoofed.
- CORS `*` without `credentials: true` on a public route — no credentialed read.
- Dev-only stack traces with `NODE_ENV=development` in a non-deployed environment.
- Signed cookie with a strong, unknown secret rejecting tampering — expected.
- Session ID unchanged on login because the app is stateless (JWT-shaped) — no server session to fixate.
- Deep nested field names rejected by a body/field-count limit at the app or proxy — the outer control is working.
- Log line separation intact because morgan is patched (`>= 1.11.0`) or `:remote-user` is not in the format — no forging sink.
- Route-pattern timing caused by the network or a WAF rather than the compiled regex — require a repeatable local-style differential.

## Version/implementation notes

- `method-override` v3: default getter is the `X-HTTP-Method-Override` header, `options.methods` defaults to `['POST']`; string getters starting `X-` are headers, others are query-string keys; the module must be used before anything that reads `req.method`. Allowing non-POST originals "may introduce security issues" per the docs.
- `trust proxy` semantics (Express 5.x): `true` trusts the left-most `X-Forwarded-For` entry (requires the last trusted proxy to overwrite `X-Forwarded-For`/`X-Forwarded-Host`/`X-Forwarded-Proto`); an IP/subnet or hop count is the precise form; `false` (default) derives the client from `req.socket.remoteAddress`. Implemented via `proxy-addr`.
- `cookie-parser` signs with HMAC and only verifies integrity; it does not encrypt. `express-session` signs its own `connect.sid` with its `secret` — running both on overlapping cookies with different secrets causes signature mismatches, and the session `secret` (not `cookie-parser`'s) governs session forgery.
- Express 5 automatically forwards rejected promises from async handlers to the error middleware (a change from Express 4); error-handler behavior and stack exposure depend on `NODE_ENV`.
- Default session cookie is `connect.sid`; `cookie.sameSite`/`cookie.secure` settings decide cross-site exposure.
- Express 5 routes compile through the `path-to-regexp` v8 line, so the 2026 ReDoS advisories apply directly to Express 5 route patterns; Express 4 applications depend on the old `0.1.x` line and inherit CVE-2026-4867 instead.
- CORS preflight (`OPTIONS`) is answered by the `cors` middleware before route auth runs by design — a 204 preflight is not an authorization bypass; test the credentialed actual request.
- `express.static` ignores dotfiles by default and normalizes paths; a mount order that places `static` before the auth middleware can serve a file the auth layer would have guarded.
- Error-handler placement: the 4-argument error middleware must be registered after all routes; a handler registered early never sees downstream errors, and `NODE_ENV` decides whether the default handler exposes the stack.
- When both `X-Powered-By` and `Server` are stripped, fingerprint from behavior: `connect.sid`, `etag` shape, `X-Request-Id`/`X-RateLimit-*` conventions, and the default JSON error body shape.
- Rate limiting after `trust proxy` misconfiguration is a two-for-one: spoofed `X-Forwarded-For` values can both evade limits and poison logs/metrics that record `req.ip`.
- Safe ceiling for the DoS families: one request plus a timing comparison against a normal request is enough to classify; never send sustained or sized-to-crash payloads.
- Dependency-version-first: the 2026 companion advisories are version-precise (`multer`, `morgan`, `path-to-regexp`, `body-parser`), so read `package.json`/lockfile when any file disclosure exists, then confirm from behavior.
- The `express.json` 100 KB default limit bounds JSON bodies but does not bound the parameter-count cost of URL-encoded parsing (CVE-2025-13466) — the two limits are independent controls.
- March 2026 `path-to-regexp` releases: CVE-2026-4867 (High) affects `<= 0.1.12`, patched `>= 0.1.13` (three or more parameters in one segment, e.g. `/:a-:b-:c`, defeat the v0.1.12 backtrack protection); CVE-2026-4926 (High) affects `>= 8.0.0`, patched `>= 8.4.0` (sequential optional groups, e.g. `{a}{b}{c}:z`); CVE-2026-4923 (Medium) affects `>= 8.0.0 <= 8.3.0`, patched `>= 8.4.0` (multiple wildcards with at least one parameter). GHSAs: GHSA-37ch-88jc-xwx2, GHSA-j3q9-mxjg-w52f, GHSA-27v5-c462-wpq7.
- CVE-2025-13466 (body-parser DoS when URL encoding is used): `body-parser` `2.2.0` only, patched `2.2.1`; thousands of parameters within the default 100 KB limit cause elevated CPU/memory (CWE-400, Moderate, CVSS `AV:N/AC:L/.../A:L`). `express.json`/`express.urlencoded` inherit the bundled line.
- June 2026 `multer`/`morgan` releases: CVE-2026-5079 (High) — deep nested multipart field names via `append-field`; affected `>= 1.0.0 < 2.2.0` and `>= 3.0.0-alpha.1 < 3.0.0-alpha.2`, patched `>= 2.2.0` / `>= 3.0.0-alpha.2` (GHSA-72gw-mp4g-v24j). CVE-2026-5038 (Medium) — aborted uploads leave orphaned partial files with `diskStorage`; affected `>= 2.0.0-alpha.1 < 2.2.0` and the alpha line, patched likewise (GHSA-3p4h-7m6x-2hcm). CVE-2026-5078 (Medium) — morgan `:remote-user` log forging; affected `>= 1.2.0 <= 1.10.1`, patched `>= 1.11.0` (GHSA-4vj7-5mj6-jm8m).

## References

- [T1] Express `method-override` middleware (default getter, `options.methods`, security note, ordering requirement): https://expressjs.com/en/resources/middleware/method-override/
- [T1] Express behind proxies (`trust proxy` values and the header-spoofing warning): https://expressjs.com/en/guide/behind-proxies.html
- [T1] Express `session` middleware (server-side session, `connect.sid`, secret): https://expressjs.com/en/resources/middleware/session/
- [T1] Express March 2026 security releases (`path-to-regexp` CVE-2026-4867/4926/4923, patched versions, GHSAs): https://expressjs.com/en/blog/2026-03-30-security-releases/
- [T1] `body-parser` advisory GHSA-wqch-xfxh-vrr4 / CVE-2025-13466 (URL-encoded parameter-count DoS; `2.2.0` affected, `2.2.1` patched): https://github.com/expressjs/body-parser/security/advisories/GHSA-wqch-xfxh-vrr4
- [T1] Express June 2026 security releases (`multer` CVE-2026-5079/5038, `morgan` CVE-2026-5078, patched versions, GHSAs): https://expressjs.com/en/blog/2026-06-30-security-releases/
- [T1] Express security-updates index (dependency advisory history): https://expressjs.com/en/advanced/security-updates/
- [T2] `cookie-parser` signed-cookie security mechanics: https://deepwiki.com/expressjs/cookie-parser/4.1-signed-cookie-security
- [T2] HackTricks, NodeJS Express (middleware chain, proxy trust, session handling, cookie signature testing): https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/nodejs-express.html
- frameworks.md (this pack's manifest) for cross-cutting oracles and deployment-config discipline
