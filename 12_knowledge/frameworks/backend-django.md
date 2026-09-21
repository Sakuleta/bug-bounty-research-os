# Frameworks — Django

> SCOPE: Load when Django (or Django REST Framework) is fingerprinted (`csrftoken`/`sessionid` cookies, `X-Frame-Options: DENY`, `/admin/` login, DRF browsable API) and debug mode, admin, schema endpoints, permission classes, CORS, or cache middleware are the research surface.

## Research families

- Debug mode: `DEBUG=True` tracebacks (the "yellow page") leak `settings` modules, environment variables, `SECRET_KEY`, DB credentials, and the URL map.
- Django admin: `/admin/` (path configurable in `urls.py`), `admin/login`, model list/change forms; `admin/docs`, `admin/<app>/<model>/`; admin actions.
- DRF schema endpoints: `get_schema_view()` mounted by convention at `/api/schema/` with `public=` (default `False`) and `permission_classes`/`authentication_classes`; `drf-spectacular` Swagger/Redoc UIs (commonly `/api/schema/swagger-ui/`, `/api/schema/redoc/`), plus `generateschema` offline output.
- DRF browsable API: `?format=api` rendering of endpoints, serializer fields, and allowed methods.
- Permission and authentication classes: `DEFAULT_PERMISSION_CLASSES` (e.g. `AllowAny` vs `IsAuthenticated`), per-view `permission_classes`, `DEFAULT_AUTHENTICATION_CLASSES`, `DEFAULT_SCHEMA_CLASS`.
- Cache middleware: `django.middleware.cache.UpdateCacheMiddleware` + `django.views.decorators.cache.cache_page` — caching decisions depend on `Vary` handling for `Cookie` and `Authorization` (CVE-2026-48588, CVE-2026-35193).
- CORS: `django-cors-headers` with `CORS_ALLOW_ALL_ORIGINS` / `CORS_ALLOW_CREDENTIALS`, `CORS_ALLOWED_ORIGINS`.
- Signing: `SECRET_KEY` signs sessions, password-reset tokens, and signed cookies; middleware order in `MIDDLEWARE` decides which layer enforces CSRF/auth.
- GIS/validator edges: `django.contrib.gis.gdal.GDALRaster` buffer handling (CVE-2026-53877) and `DomainNameValidator` newline acceptance (CVE-2026-53878).

## Preconditions

- `DEBUG=True` in the deployed environment (confirm from live behavior — production mode disables the verbose page).
- A DRF schema route mounted and reachable, and `public=True` or missing effective permissions on the schema view, for endpoint-map/schema disclosure.
- `DEFAULT_PERMISSION_CLASSES` resolving to `AllowAny` (or a view lacking `permission_classes`) for an API endpoint that should be authenticated.
- `django-cors-headers` configured to reflect arbitrary origins with credentials for the CORS-read family.
- Admin reachable and not fronted by additional SSO — for the admin enumeration family.
- Observed `SECRET_KEY` value (e.g. from a traceback) before any signing/forgery conclusion.
- For the cache-privacy family: `UpdateCacheMiddleware`/`cache_page` active on a view that reads identity from `Cookie` or `Authorization`, and either a shared cache backend or a CDN that honors the response's `Vary`/`Cache-Control`.
- For the `Vary`-omission shape: the incoming request carries `Authorization` without `Cache-Control: public`, and the view's response is cacheable — that is the exact CVE-2026-35193 configuration.
- For the Set-Cookie shape: the incoming request already carries an unrelated cookie (locale/theme) while the response sets a session or sensitive cookie — the exact CVE-2026-48588 configuration.
- For the GDALRaster family: GIS enabled and a code path that instantiates `GDALRaster` from a bytes object in GDAL's virtual filesystem — information disclosure, not authz.

## Oracles

- Debug traceback: a request that raises a server exception returns the Django yellow page including `SECRET_KEY`, `DATABASES`, environment values, and installed apps — reproduces with one deliberate 500-triggering request in scope.
- Schema disclosure: `GET /api/schema/` (or the drf-spectacular UI paths) returns the full OpenAPI document — every route, method, parameter, and sometimes permission hints — without authentication.
- Browsable API disclosure: `?format=api` on an endpoint shows serializer fields and the HTML form, exposing write fields even when JSON GET is guarded.
- CORS credentialed read: an endpoint responds with `Access-Control-Allow-Origin: <attacker origin>` plus `Access-Control-Allow-Credentials: true`, letting a cross-origin page read researcher-private data.
- Admin enumeration: `/admin/` returns the login, and `/admin/<app>/<model>/` reveals model structure; a weak/green admin session gives model CRUD.
- Signing forgery: with the exposed `SECRET_KEY`, a signed session cookie or password-reset token can be forged and validated by the target.
- Cache-key privacy (Authorization): a view cached with `cache_page`/`UpdateCacheMiddleware` returns an authenticated user's body to an anonymous request when the first request bore `Authorization` without `Cache-Control: public`, because `Authorization` is not added to `Vary` (CVE-2026-35193) — oracle is an anonymous request receiving the owner's private fields.
- Cache-key privacy (Cookie): a response that sets a session/sensitive cookie is stored in the shared cache when the incoming request already carried an unrelated cookie (e.g. theme/locale), because the Cookie-varying protection only applied to cookie-less requests (CVE-2026-48588).
- `Vary` inspection (control): read the response's `Vary` header before and after the probe — a patched or correctly configured view varies on `Cookie`/`Authorization`, which is the control that closes both cache CVEs.
- GDALRaster over-read: a `vsi_buffer`-backed `GDALRaster` returns ~32 bytes of adjacent heap — adjacent-memory disclosure only in a GIS code path; treat as low-value and lab-only.

## Minimal safe proof

1. Fingerprint: confirm Django from two signals (`csrftoken`/`sessionid` cookie names, `X-Frame-Options`, `/admin/`, DRF `?format=api`) and whether DRF is present.
2. Baseline: request one protected page/endpoint from owner and anonymous sessions; record status/body/redirect.
3. Schema probe (read-only): request the suspected schema path anonymously and record only the top-level operation list, not secrets.
4. Debug probe: request one path expected to error and confirm whether a verbose page (vs the generic 500) appears; capture field names only, never dump secrets.
5. CORS probe: send an `Origin: https://<researcher-canary>` request with credentials and read back the ACAO/ACAC headers.
6. Cache probe (read-only): warm a cache-eligible private view with the owner session (including an `Authorization` header where relevant), then request it anonymously and diff bodies; record field shape only, never another user's values.
7. Stop conditions: any real secret value, any other-user record, any admin write, any forged-session use against another account, or any cache-poisoned response visible to a third party — halt, preserve minimal evidence, and report.

## False positives

- `/admin/login` returning 200 — a login page is hardened by default; enumerating it is not access control failure.
- Schema endpoint returning an error/redirect because `public=False` and auth is enforced — the control is working.
- `?format=api` rendering only public fields — no write-field disclosure.
- CORS wildcard with `Access-Control-Allow-Credentials: false` or on a public asset — no credentialed read possible.
- Dev-only tracebacks behind a local-only `ALLOWED_HOSTS` — require the deployed environment to reproduce.
- `SECRET_KEY` prefixed `django-insecure-` seen in a repo, but not the deployed value — repo default is not the live signing key.
- Cached response that is identical for anonymous and owner sessions, or contains no session-scoped fields — no confidentiality boundary crossed.
- `Vary: Authorization` present (patched behavior) — the cache key includes identity; not the CVE-2026-35193 shape.
- CDN stripping/not honoring `Vary` is an edge finding, not a Django finding — attribute the layer.

## Version/implementation notes

- Cache middleware CVEs: CVE-2026-35193 — `UpdateCacheMiddleware` did not add `Authorization` to `Vary` for requests bearing that header without `Cache-Control: public`, allowing unauthenticated reads of private cached responses (Django `5.2 < 5.2.15`, `6.0 < 6.0.6`; CVSS-B 2.3, CWE-524; reported by Shai Berger). CVE-2026-48588 — responses that set a cookie while varying on `Cookie` were cached whenever the request carried an unrelated cookie (fixed `6.0.7` / `5.2.16`; low severity; reported by Chris Whyland). Both make cache middleware part of the authorization surface.
- July 2026 security release (`6.0.7`, `5.2.16`; 2026-07-07) also fixed CVE-2026-53877 (`GDALRaster` `vsi_buffer` heap over-read of ~32 bytes; low; Bence Nagy) and CVE-2026-53878 (`DomainNameValidator` accepted newlines, header injection only when used outside Django form fields; low; Bence Nagy). Supported branches at that date: `main`, `6.1` (beta), `6.0`, `5.2`.
- DRF's built-in OpenAPI schema generation is deprecated in favor of third-party packages (notably `drf-spectacular`); `DEFAULT_SCHEMA_CLASS` selects the `AutoSchema` subclass and the schema route's permissions come from `get_schema_view()` (`public`, `authentication_classes`, `permission_classes`).
- `get_schema_view(..., public=True)` makes the schema bypass per-view permission checks — a common misconfiguration that turns `/api/schema/` into a full endpoint map.
- `manage.py check --deploy` enumerates the exact misconfigurations (W004 HSTS, W008 SSL redirect, W009 short/insecure `SECRET_KEY`, W012/W016 cookie-secure, W018 `DEBUG=True`, W020 empty `ALLOWED_HOSTS`) — use it as the version-agnostic checklist.
- Django majors shift defaults (e.g. `SECURE_*` settings, `STORAGES`, `CSRF_TRUSTED_ORIGINS`); resolve the major from behavior before applying a setting note. Security fixes are back-ported only to supported branches — pin the observed minor.
- Middleware order matters: `SecurityMiddleware` early, `CsrfViewMiddleware` and `AuthenticationMiddleware` after session middleware; reordering can silently disable CSRF for a path, and `UpdateCacheMiddleware` must remain first when used.
- Security fixes are back-ported only to supported branches; at the July 2026 release that meant `main`, `6.1` (beta), `6.0`, `5.2`. An EOL branch (e.g. `5.0`, `4.2` after support ends) can remain vulnerable to the same CVEs with no fixed release — map the observed minor to a supported branch before concluding.
- `sessionid` + `csrftoken` are the core fingerprint pair; `SESSION_COOKIE_SECURE`/`SESSION_COOKIE_SAMESITE`/`CSRF_COOKIE_*` settings decide whether a cross-site request can carry them, which is the control for the CSRF families.
- The DRF schema path is a convention, not a default: an app may mount `get_schema_view()` anywhere, and `DEFAULT_SCHEMA_CLASS` selects the generator — enumerate from the URL map (when visible) rather than assuming `/api/schema/`.
- Admin flow details worth one benign pass: loading `/admin/` while logged out shows whether the login is the only gate; per-model URLs redirect back to login, which confirms per-model checks are active. Record only status/redirect, never attempt credentials.
- Sessions: `sessionid` is signed with `SECRET_KEY` and served by `SessionMiddleware`; the signing disclosure path (debug traceback) is what turns a cookie into a forgery primitive — observed key first, forgery conclusion second.
- `/api/schema/` returning a Swagger UI HTML shell while the JSON schema endpoint is guarded is a partial-disclosure pattern; classify each representation separately (HTML UI vs JSON document).
- A debug traceback also prints the URL map: use that single 500 to enumerate generated schema/admin/debug paths, then probe each read-only and stop — do not trigger repeated 500s for the same information.
- When `DEBUG` is on, treat `SECRET_KEY` as observed: the follow-on work is session-forgery proof on the researcher's own account, never another user's.
- Schema-scope discipline: the OpenAPI document may include write operations with security schemes; record the operation list only, and test at most one read-only endpoint from it.
- Cache-family evidence hygiene: capture the cold/warm response pair, the `Vary` header, and the cache-control value; the pair plus header is what distinguishes the CVE shape from normal caching.
- Baseline control for CORS: send the same `Origin` request to a public endpoint; if the app reflects every origin credentialied there too, record it as a configuration posture, not a single-endpoint finding.
- Session fixation/rotation is framework-default behavior in modern Django; probe it only if a custom auth backend is observed, and keep the test on the researcher's own session.

## References

- [T1] Django security releases 6.0.7 and 5.2.16 (CVE-2026-48588 cache Set-Cookie; CVE-2026-53877 GDALRaster; CVE-2026-53878 DomainNameValidator; supported branches): https://www.djangoproject.com/weblog/2026/jul/07/security-releases/
- [T1] NVD CVE-2026-35193 (`Vary: Authorization` omission; `5.2 < 5.2.15`, `6.0 < 6.0.6`): https://nvd.nist.gov/vuln/detail/CVE-2026-35193
- [T1] Django REST Framework, Schemas (`get_schema_view`, `public`, `DEFAULT_SCHEMA_CLASS`, `AutoSchema`): https://www.django-rest-framework.org/api-guide/schemas/
- [T1] drf-spectacular docs (schema generation, settings): https://drf-spectacular.readthedocs.io/en/latest/readme.html ; settings: https://drf-spectacular.readthedocs.io/en/latest/settings.html
- [T1] Django security topics (CSRF, XSS, clickjacking): https://docs.djangoproject.com/en/stable/topics/security/
- [T2] OWASP Django Security Cheat Sheet (DEBUG, SECRET_KEY, admin URL, `check --deploy`): https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html
- [T2] Django debug-mode escalation research (endpoint extraction, RCE/SSRF/SQLi chaining): https://blog.vidocsecurity.com/blog/escalation-of-debug-mode-in-django
- [T2] Django debug-mode exposure writeup: https://blogs.jsmon.sh/what-is-django-debug-mode-exposure-ways-to-exploit-examples-and-impact/
- frameworks.md (this pack's manifest) for cross-cutting oracles and deployment-config discipline
