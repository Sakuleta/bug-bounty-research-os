# Frameworks — Spring Boot / Spring Cloud

> SCOPE: Load when Spring Boot is fingerprinted (`Whitelabel Error Page`, `/actuator` discovery, `X-Application-Context`, JSESSIONID, Spring Security headers) and Actuator, gateway routes, error pages, SpEL evaluation, or security-header behavior are the research surface.

## Research families

- Actuator discovery page: `/actuator` links to all exposed endpoints; moves to the management context root when `management.endpoints.web.base-path`/`management.server.port` is customized.
- Read endpoints with high impact: `/actuator/env`, `/actuator/configprops`, `/actuator/beans`, `/actuator/mappings`, `/actuator/conditions`, `/actuator/threaddump`, `/actuator/httpexchanges`, `/actuator/loggers`, `/actuator/sessions`, `/actuator/scheduledtasks`, `/actuator/quartz`, `/actuator/sbom`.
- Artifact endpoints: `/actuator/heapdump` (HPROF/PHD file), `/actuator/logfile` (supports HTTP `Range`), `/actuator/prometheus` where micrometer is present.
- Write/impact endpoints: `/actuator/shutdown` (disabled by default), `/actuator/loggers` (`POST` to change levels), custom `@WriteOperation`/`@DeleteOperation`.
- Spring Cloud Gateway: `/actuator/gateway/routes` (list) and `POST .../refresh` (rebuild) — SpEL in route filters (CVE-2022-22947).
- Error surface: `/error` Whitelabel page, error attributes (`message`, `trace`, `path`, `bindingErrors`), `${...}` in log/message patterns.
- Security filter chain: the default chain's authorization rules, `management.endpoints.access.default`, and health-group additional paths (CVE-2026-40976, CVE-2026-22731).
- Actuator access model: `management.endpoints.access.default` (`none` vs `unrestricted`), per-endpoint `access`, and `management.endpoint.<id>.enabled` — three independent switches that decide whether an endpoint is reachable at all.
- Security headers: Spring Security's `HeaderWriterFilter` writes `X-Frame-Options`, `Cache-Control`, HSTS, etc. — suppressed under certain lazy-write conditions (CVE-2026-22732).
- Console/aux: `/h2-console`, `/jolokia`, dev tools restart endpoints.

## Preconditions

- Actuator on the classpath and exposed (at minimum `management.endpoints.web.exposure.include` covering the endpoint, or the vulnerable default-filter-chain states in the CVEs below).
- A decision point: either the endpoint is exposed over the main web port, or a management port/context is network-reachable despite assumed isolation.
- For CVE-2026-40976: Spring Boot `4.0.0`–`4.0.5` servlet app with no user-defined `SecurityFilterChain`, `spring-boot-actuator-autoconfigure` on the classpath, and `spring-boot-health` absent.
- For CVE-2026-22731: an application endpoint requiring authentication declared under a path already configured as a Health Group additional path, e.g. `management.endpoint.health.group.mygroup.additional-path=server:/healthz` plus an endpoint mapped at `/healthz/admin`.
- For SpEL/gateway RCE: Spring Cloud Gateway Actuator endpoint enabled, exposed, and without adequate authorization (CVE-2022-22947).
- For env/configprops disclosure: `show-values` not `never` (or a custom `SanitizingFunction` absent) so values are not masked as `******`.
- For heapdump: endpoint access permitted (defaults restrict access to `shutdown` and `heapdump` in the modern access model; older exposure configs may not).
- For the header-suppression family: Spring Security servlet app using lazy (default) header writing on an affected line (`5.7.21`, `5.8.23`, `6.3.14`, `6.4.14`, `6.5.8`, `7.0.3`).
- Fingerprint the Spring Boot major (2.x vs 3.x vs 4.x) and Spring Security major before applying autoconfiguration notes.

## Oracles

- Discovery enumeration: `GET /actuator` returns a JSON index (or HTML) listing available endpoint links — establishes which endpoints exist without invoking them.
- Secret disclosure: `/actuator/env` and `/actuator/configprops` return unsanitized property values (DB passwords, API keys, JWT secrets); the oracle is a non-`******` value, not just a key name.
- Full-memory disclosure: `/actuator/heapdump` returns a downloadable dump; download once and grep offline for secrets — do not repeatedly pull it.
- Route/architecture map: `/actuator/mappings` returns every `@RequestMapping` path (including internal/admin routes).
- Log-level manipulation: `POST /actuator/loggers/<logger>` with `{"configuredLevel":"..."}` changes runtime logging — a state change; test only on a logger you own operationally.
- Gateway SpEL RCE: `POST /actuator/gateway/routes/<id>` with a filter whose SpEL expression executes a command, then trigger and `refresh` (CVE-2022-22947) — only in an authorized lab/program.
- Auth-bypass default chain: with the vulnerable Boot 4.0 dependency state (below), every `/actuator/*` endpoint answers anonymously.
- Health-group path bypass: an authenticated endpoint declared under a health-group additional path answers anonymously (CVE-2026-22731) — control is the same endpoint under a normal path, which is denied.
- Header suppression: responses from authenticated routes are missing the framework's `X-Frame-Options`/`Cache-Control`/HSTS headers under the affected lazy-write line (CVE-2026-22732) — oracle is header absence plus an actual consequence (framing or cacheability), not the absence alone.

## Minimal safe proof

1. Fingerprint: confirm Spring Boot from two signals (Whitelabel error page, `X-Application-Context`, actuator shape, JSESSIONID) and the major version.
2. Discovery (read-only): `GET /actuator`; record the endpoint list only.
3. Sanitization check: `GET /actuator/env` once; record whether values are `******` or real secrets — do not enumerate every property.
4. Mapping check: `GET /actuator/mappings` once; record the count/top-level paths only.
5. Health-path check: if a health group additional path is visible in config/discovery, request one such path anonymously and diff against a normal guarded path; keep the non-health control.
6. Header check: request one authenticated-shaped route and note whether the documented security headers are absent; only escalate if framing or caching is actually possible in scope.
7. Heapdump: only if access is permitted, download once and analyze offline; never share the raw dump.
8. Stop conditions: any real credential value, any other-user session from `/actuator/sessions`, any `/actuator/shutdown`/loggers state change, or any gateway RCE beyond the authorized lab — halt immediately and report.

## False positives

- `/actuator/health` returning `{"status":"UP"}` only — health metadata is expected; without `show-details: always`/`when-authorized` it is not a leak.
- Health endpoint returning component details because `show-details: always` is configured — configuration disclosure, not an authorization bypass; require the CVE-2026-22731 shape (an authenticated non-health endpoint reachable under a health path).
- Endpoint returning 404 because it is inactive or not exposed — absence is the control.
- `/actuator/env` showing `******` for secrets — sanitization is working.
- Whitelabel Error Page — a generic error, not a stack/secret disclosure.
- `/actuator/mappings` present but the app is internal-only and not in scope — reachability, not exposure.
- Gateway routes listed but the Actuator is properly authorized — enumeration only.
- Health-group path returning 200 for a public/health endpoint by design — require the endpoint itself to require authentication.
- Missing security headers without a demonstrable framing/caching consequence — hardening observation, not a vulnerability.

## Version/implementation notes

- Defaults: only `health` is exposed over HTTP by default; `shutdown` is disabled by default and (with `heapdump`) access-restricted by default in the modern model. `management.endpoints.web.exposure.include=*` is the classic misconfiguration; `management.endpoints.access.default=none` + per-endpoint opt-in is the hardened model.
- Sanitization: `/env`, `/configprops`, `/quartz` values are fully replaced by `******` unless `show-values` is `always`/`when-authorized` (and no `SanitizingFunction` applies). `management.endpoint.env.show-values=when-authorized` + `roles=admin` is the safe setting.
- CVE-2026-40976 (Critical, CVSS 9.1): Spring Boot `4.0.0`–`4.0.5`, fixed `4.0.6`. A servlet app with no user `SecurityFilterChain`, `spring-boot-actuator-autoconfigure` present, and `spring-boot-health` absent gets a default filter chain with no authorization rule for the Actuator path → `/actuator/env`, `/actuator/heapdump`, `/actuator/configprops`, etc. are anonymous. Interim fix: add the `spring-boot-health` dependency.
- CVE-2026-22731 (High, March 2026): authentication bypass when an authenticated endpoint is declared under a path already configured as a Health Group additional path. Fixed in Spring Boot `4.0.4`, `3.5.12` (`3.4.15` Enterprise Support Only). Clarification of an earlier pack note: the fix line is Boot `4.0.4`/`3.5.12`/`3.4.15`, not "3.x and earlier" generally. Reported by Gyu-hyeok Lee (g2h); similar but not equivalent to CVE-2026-22733.
- CVE-2026-22732: Spring Security servlet HTTP response headers are silently not written when applications set their own cache-related headers under lazy (default) writing. Affected `5.7.21`, `5.8.23`, `6.3.14`, `6.4.14`, `6.5.8`, `7.0.3`; fixed `5.7.22`, `5.8.24`, `6.3.15`, `6.4.15`, `6.5.9`, `7.0.4` (older lines Enterprise Support Only; `6.5.9`/`7.0.4` OSS). Workaround: `HeaderWriterFilter.shouldWriteHeadersEagerly=true` via `ObjectPostProcessor`/`BeanPostProcessor` — changes application behavior. Reported by Wyfrel.
- CVE-2022-22947 (Spring Cloud Gateway Actuator RCE via SpEL in route filters): versions prior to `3.1.1` and `3.0.7` (including `3.1.0`, `3.0.6`).
- A separate `management.server.port` isolates Actuator from the app port but is not an authorization control; a network-reachable management port is still in scope. Health-group additional paths are matched independently of the normal request-mapping chain, which is what created CVE-2026-22731.
- When `management.endpoints.web.base-path` or the management port is customized, re-derive the base path before probing (`/actuator` may live at `/manage`, `/management`, or on another port); `GET /actuator` returning 404 means either not exposed or wrong base path.
- `/actuator/sessions` returning an empty list confirms the endpoint is open without exposing another user; a non-empty list is an immediate stop condition.
- Actuator responses may differ by `Accept` header (JSON index vs HTML); record both shapes once rather than fuzzing endpoint names.
- Artifact-endpoint classification: `/actuator/heapdump` returns a binary body with `Content-Type: application/octet-stream` and a large `Content-Length`; confirm metadata once, download at most once, and never in a loop.
- `/actuator/logfile` honors `Range` requests, so a partial read of the first lines classifies the endpoint without downloading the whole log; stop at classification and do not grep for secrets inline.
- If both an app port and a management port answer, fingerprint the management context separately: Actuator endpoints there can be outside the app's security filter chain while still inside scope.
- `/actuator/env` property-source names can reveal config-server, Git, or vault URLs even when values are masked; record source names as architecture intel and stop there.
- Baseline for the default-chain CVE: request `/actuator/mappings` anonymously; a 200 with a full mapping list in the CVE-2026-40976 dependency state means every Actuator endpoint is open, so classify from the index and halt.
- Do not test `/actuator/shutdown` even when it answers: the endpoint is a state-change surface with no safe reversible proof outside an authorized lab.
- When the app is Boot 4.0.x, check the `spring-boot-health` dependency presence indirectly: if `/actuator/health` exists but a custom `SecurityFilterChain` is absent, the CVE-2026-40976 state is plausible — confirm with the anonymous index request only.
- Health-group bypass probe ordering: discover the group path from config/response headers, request that path anonymously once, and immediately request the same logical endpoint under its normal path as the control.

## References

- [T1] Spring Boot Actuator endpoints (primary: exposure/access properties, sanitization, discovery page, health): https://docs.spring.io/spring-boot/reference/actuator/endpoints.html
- [T1] Spring Security advisory CVE-2026-40976 (fixed `4.0.6`): https://spring.io/security/cve-2026-40976/ ; analysis: https://www.herodevs.com/blog-posts/cve-2026-40976-spring-boot-4-0-actuator-authorization-bypass
- [T1] Spring advisory CVE-2026-22731 (Health Group additional-path bypass; fixed `4.0.4`/`3.5.12`/`3.4.15`): https://spring.io/security/cve-2026-22731
- [T1] Spring advisory CVE-2026-22732 (headers not written; affected/fixed versions, `shouldWriteHeadersEagerly` workaround): https://spring.io/security/cve-2026-22732
- [T1] CVE-2022-22947 (Spring Cloud Gateway Actuator SpEL RCE): https://nvd.nist.gov/vuln/detail/cve-2022-22947
- [T2] Wiz, Spring Boot Actuator misconfigurations (`/heapdump`, `/env`, `/gateway/routes`, `/metrics`): https://www.wiz.io/blog/spring-boot-actuator-misconfigurations
- [T2] CVE-2022-22947 summary: https://safeguard.sh/resources/blog/spring-cloud-gateway-actuator-rce-cve-2022-22947 ; PoC: https://www.exploit-db.com/exploits/50799
- [T3] `/heapdump` credential-exposure walkthrough: https://dev.to/roxdavirox/exposed-spring-boot-actuator-heapdump-delivers-credentials-in-production-354p
- frameworks.md (this pack's manifest) for cross-cutting oracles and deployment-config discipline
