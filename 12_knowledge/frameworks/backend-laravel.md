# Frameworks — Laravel

> SCOPE: Load when Laravel is fingerprinted (`laravel_session`/`XSRF-TOKEN` cookies, `X-Powered-By: PHP`, `/storage/`+`/vendor/` paths, Ignition error page, `APP_DEBUG` traces) and debug mode, dashboards, storage paths, Ignition, mail validation, or CSRF exclusions are the research surface.

## Research families

- Debug mode: `APP_DEBUG=true` renders the Ignition error page with environment variables, stack traces, and `APP_KEY`; `/_ignition/*` routes exist only with Ignition installed.
- Ignition RCE: `/_ignition/execute-solution` with `APP_DEBUG=true` (CVE-2021-3129) — Phar deserialization + log-poisoning chain to code execution.
- Telescope dashboard: `/telescope` (gate `viewTelescope`, local-env default, `TELESCOPE_ENABLED`); records requests/headers/sessions/env/queries.
- Horizon dashboard: `/horizon` (queue metrics/jobs; `Horizon::auth` gate).
- Debugbar: `/_debugbar/*` and the `phpdebugbar` HTML marker; open only when `APP_DEBUG` and the package are active.
- Exposed storage/config paths: `/storage/logs/laravel.log`, `/storage/framework/*`, `/vendor/**`, and `/.env` when the webroot is misconfigured.
- CSRF exclusions: `ValidateCsrfToken` (Laravel 11+) configured via `validateCsrfTokens(except: [...])` in `bootstrap/app.php`, or the legacy `VerifyCsrfToken::$except` (Laravel ≤10); over-broad globs (e.g. `'*'`) disable CSRF.
- Signing/encryption: `APP_KEY` signs cookies and signed URLs and encrypts session/payload data; disclosure enables forgery.
- Mail-validation rule: the default `email` rule accepted CRLF-bearing input that reaches Symfony Mailer/Mime (CVE-2026-48019).
- Mail stack: `Mail`/`Notification` flows hand user-supplied addresses to Symfony Mailer; the transport then decides whether injected headers become separate MIME headers or recipients.

## Preconditions

- `APP_DEBUG=true` in the deployed environment for Ignition/debugbar/verbose traces; production sets it false.
- Ignition package present on Laravel ≤8 (`facade/ignition`) for the `/_ignition/execute-solution` route; modern Laravel uses `spatie/laravel-ignition` with the endpoint disabled in production.
- Telescope/Horizon installed and `APP_ENV` not `production`, or the dashboard gate left permissive, for dashboard access.
- A route excluded from CSRF (glob/wildcard in `validateCsrfTokens(except:)` or `$except`) that performs a state change, for the CSRF-bypass family.
- An observed `APP_KEY` value (e.g. from a debug page) before any cookie/signed-URL forgery conclusion.
- Debugbar present with `APP_DEBUG=true` for the `/_debugbar` surface.
- For the mail-CRLF family (CVE-2026-48019): the app sends mail to user-supplied addresses (auth flows, contact forms) on `laravel/framework <= 13.9.0` or `< 12.60.0`, and the mail transport processes the address before adequate sanitization.
- A route-level CSRF exclusion is not the same as an absent session: confirm the endpoint actually changes state for the researcher's account.

## Oracles

- Debug-page disclosure: a request that raises an exception returns the Ignition page including `.env` values and `APP_KEY` — reproduces with one deliberate error in scope.
- Ignition RCE: `POST /_ignition/execute-solution` with a crafted solution executes code when `APP_DEBUG=true` (lab/authorized only) — classify by behavior, never by running arbitrary commands on a live program.
- Telescope exposure: `GET /telescope` from an anonymous session returns the dashboard (requests, sessions, env, queries) when the environment is not production or the gate is open.
- Horizon exposure: `GET /horizon` returns queue/job data and controls when `Horizon::auth` is not restrictive.
- Storage disclosure: `GET /storage/logs/laravel.log` or `/storage/framework/*` returns logs/caches with credentials or tokens.
- CSRF-bypass state change: a cross-site-shaped `POST` to an excluded route succeeds without a token.
- Debugbar surface: `/_debugbar/*` endpoints return collected messages/queries while `APP_DEBUG=true`.
- Mail-header injection: an address containing CRLF-shaped sequences passes the `email` rule and influences outbound message content/recipients (CVE-2026-48019) — verify by observing validation/transport behavior for a researcher-owned address only, never by relaying to third parties.
- Signed-URL/cookie forgery: with an observed `APP_KEY`, a `laravel_session`/signed-URL artifact can be forged and accepted — never exercise against another account.

## Minimal safe proof

1. Fingerprint: confirm Laravel from two signals (cookie names, Ignition/debug page shape, `/storage/`+`/vendor/` paths) and whether Telescope/Horizon are installed; record the framework major (`12.x`/`13.x`).
2. Baseline: request one protected page/action from owner and anonymous sessions; record status/body/redirect.
3. Debug probe: request one path expected to error and classify Ignition page vs generic error; capture field names only, not secrets.
4. Dashboard probe (read-only): `GET /telescope` and `/horizon` anonymously; record the landing shape only, do not drive queue/job controls.
5. Storage probe: request one log path; record whether it returns log lines (field names only).
6. CSRF probe: attempt one token-less `POST` to an excluded route affecting only researcher-owned state.
7. Mail probe: submit one CRLF-shaped address to a researcher-owned mail flow (or a local mail catcher) and inspect the generated message for injected headers; never target a third-party mailbox and never use the app as a relay.
8. Stop conditions: any real secret/`APP_KEY`, any other-user session from Telescope, any queue job control, any mail delivered to a non-researcher recipient, or any Ignition code execution beyond the authorized lab — halt and report.

## False positives

- `/_ignition/execute-solution` returning 404 — the endpoint is absent/disabled in production; that is the control.
- `/telescope` or `/horizon` returning 403 — the gate is working.
- `laravel_session` cookie alone — transparent framework fingerprint.
- Debugbar marker in HTML without `/_debugbar/*` responding — not debug exposure.
- `/storage/logs/laravel.log` returning 403/404 or a static stub — no log disclosure.
- CSRF token echoed in the page — normal; require a state change without a token.
- `XSRF-TOKEN` cookie present — it is an encrypted convenience token; without `APP_KEY` it is not forgeable.
- Email address rejected by validation, normalized, or rejected by the MTA — the control is working; require a crafted message to actually differ.
- Mail flow that never uses the address in the transport (e.g. logs only) — no CRLF sink.

## Version/implementation notes

- CVE-2026-48019 (High; CWE-93): CRLF injection in Laravel's default `email` validation rule, combined with Symfony Mailer/Symfony Mime character handling, may let an unauthenticated attacker influence outbound mail (content, unintended recipients, relay abuse). Affected: `laravel/framework <= 13.9.0` and `< 12.60.0`; patched `>= 13.10.0` and `>= 12.60.0`. CVSS `AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:L`. Reported by OmarXtream. Treat any app that mails user-supplied addresses as in scope for the check.
- Laravel 11 removed the `App\Http\Middleware\VerifyCsrfToken` class from the skeleton; exclusions moved to `validateCsrfTokens(except: [...])` inside `bootstrap/app.php`'s `withMiddleware()` (Laravel ≤10 used the `$except` array property). The middleware is `Illuminate\Foundation\Http\Middleware\ValidateCsrfToken`; it also accepts `X-CSRF-TOKEN` and `X-XSRF-TOKEN`, and CSRF is auto-disabled under tests.
- Telescope is accessible at `/telescope`; by default only in `local`, and the `viewTelescope` gate (in `TelescopeServiceProvider`) governs non-local access. Set `APP_ENV=production` or the dashboard is public. `TELESCOPE_ENABLED` toggles collection entirely.
- CVE-2021-3129 (Ignition unauthenticated RCE via `/_ignition/execute-solution`) requires `APP_DEBUG=true`; affects Laravel ≤8 with `facade/ignition`; mitigated by `APP_DEBUG=false` and a patched Ignition (2.5.2+).
- Debug mode page content and paths track the Laravel/Ignition major; verify the observable behavior rather than assuming a specific error template.
- `APP_KEY` is the signing/encryption key for cookies, encrypted casts, and signed URLs — treat its disclosure as full session/payload forgery capability. Signed routes (`URL::signedRoute`/`temporarySignedRoute`) and the encrypted `XSRF-TOKEN` are the same key's outputs.
- Storage exposure: `php artisan storage:link` publishes `storage/app/public` at `/storage`; a misconfigured symlink or webroot can expose `storage/logs`/`storage/framework` instead. Check the webroot, not the framework default.
- Telescope records request payloads, headers (including `Authorization`/cookies), session data, and env values when configured — any successful Telescope read should be treated as credential exposure and trigger rotation, not just a dashboard-exposure finding.
- Laravel 11+ `bootstrap/app.php` also registers middleware aliases and per-route middleware; an app migrated from ≤10 may keep dead `VerifyCsrfToken` config while the effective middleware is `ValidateCsrfToken` — confirm behavior from the live responses, not the skeleton.
- Ignition page classification: the debug page exposes env values in its stack/context panes; capture only the presence of `APP_KEY` as a field name, never the value. Ignition registers several routes and the executor is the sensitive one — classify each route separately and treat any code-execution route as lab-only.
- Horizon jobs can be retried/failed from the dashboard; an open Horizon is a state-change surface, so the safe proof is a single GET that records the landing page and then stops.
- When both `APP_DEBUG` and Telescope are open, the finding is credential exposure with a path to session forgery — treat `APP_KEY` as the pivot and follow the rotate-everything guidance rather than chaining further.
- Storage baseline: request one known-public asset under `/storage/` first; if that 404s, the publish path is not active and the log-path probe is moot.
- Queue-dashboard data is operationally sensitive (`/horizon` jobs include payloads); record job class names only, never payload bodies, and never retry a failed job.
- Telescope's dashboard is backed by JSON API routes served by the package; classify one JSON representation and the HTML dashboard separately, and stop after the landing shape.
- Debugbar collection can include SQL bindings and session values; if `_debugbar` responds, treat the response as credential-adjacent and capture field names only.
- The `email` rule is one of many validators that feed mail/headers; when patched behavior is uncertain, compare the validation error for a CRLF-bearing address against a plain invalid address — a differential in acceptance is the signal.
- Framework fix lines move fast (`12.x` and `13.x` maintained in parallel at the time of CVE-2026-48019); check the exact `laravel/framework` constraint, not just the app's Laravel "version" marketing label.
- Removed classes still matter when fingerprinting: a Laravel 11/12 app can carry legacy `VerifyCsrfToken` references from old middleware code, while the effective middleware is `ValidateCsrfToken` — verify which one the running app uses before concluding CSRF is absent.

## References

- [T1] Laravel advisory GHSA-5vg9-5847-vvmq / CVE-2026-48019 (CRLF in default email rule; affected `<=13.9.0`/`<12.60.0`, patched `>=13.10.0`/`>=12.60.0`): https://github.com/laravel/framework/security/advisories/GHSA-5vg9-5847-vvmq
- [T1] Laravel Telescope (route `/telescope`, local-only default, `viewTelescope` gate, `APP_ENV=production` requirement, `TELESCOPE_ENABLED`): https://laravel.com/framework/docs/12.x/telescope
- [T1] Laravel CSRF protection (`ValidateCsrfToken`, `validateCsrfTokens(except:)` in `bootstrap/app.php`, `X-CSRF-TOKEN`/`X-XSRF-TOKEN`): https://laravel.com/framework/docs/12.x/csrf
- [T1] CVE-2021-3129 (Ignition `/_ignition/execute-solution` RCE requiring `APP_DEBUG=true`): https://nvd.nist.gov/vuln/detail/cve-2021-3129 ; analysis: https://www.modracx.com/blog/cve-laravel-ignition-unauth-rce/
- [T2] Laravel debug-mode exposure and impact: https://blogs.jsmon.sh/what-is-laravel-debug-mode-exposure-ways-to-exploit-examples-and-impact/
- [T2] Telescope data-exposure risk on production servers: https://www.cosmiclearn.com/laravel/telescope.php
- [T3] Laravel 11 CSRF exclusion migration (`VerifyCsrfToken` removed, `validateCsrfTokens` added): https://stackoverflow.com/questions/78279024/laravel-11-disable-csrf-for-a-route
- frameworks.md (this pack's manifest) for cross-cutting oracles and deployment-config discipline
