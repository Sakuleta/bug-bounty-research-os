# Frameworks — Ruby on Rails

> SCOPE: Load when Rails is fingerprinted (`X-Powered-By`/server banner, `_session_id`/`_<app>_session` cookie, `csrf-token` meta tag, `X-Request-Id`, `X-Runtime`, `/assets/` digested paths, `authenticity_token`) and info routes, mass assignment, cookie signing, method tunneling, detailed exceptions, or Active Storage processing are the research surface.

## Research families

- Info routes: `/rails/info/routes` (full route table with a search/filter, matched top-to-bottom) and `/rails/info/properties` (framework runtime properties: Rails, Ruby, Rack versions). Provided by `Rails::InfoController` / `Rails::Info`.
- Detailed exception pages: the development error page with stack trace, source snippets, params, and cookies; controlled by `config.consider_all_requests_local` (there is also `config.action_dispatch.show_exceptions`).
- Mass assignment / Strong Parameters: `params.require(:x).permit(:a, :b)`, `permit!` (allows everything), and legacy `attr_accessible`/`protected_attributes`.
- Method tunneling: `_method` hidden field/query param and `X-HTTP-Method-Override` header on `POST` (Rack::MethodOverride) re-dispatch to `PUT`/`PATCH`/`DELETE`.
- Signed/encrypted cookies: `secret_key_base` (from `config/master.key`/credentials) signs and encrypts the session cookie and `cookies.signed`/`cookies.encrypted`; `config.action_dispatch.cookies_serializer` chooses the serializer (`:json` modern, `:marshal`/`:hybrid` legacy).
- Active Storage + variant processing: `config.active_storage.variant_processor` (Vips by default under `load_defaults 7.0`), the direct-upload route, signed `variation_key`s, and libvips "unfuzzed"/untrusted operations (CVE-2026-66066).
- Variant URLs: `/rails/active_storage/representations/...` responses are signed by the app's signing key; a leaked/forged `variation_key` is the second half of the CVE-2026-66066 chain when combined with a crafted upload.
- CORS: `rack-cors` in `config/initializers/cors.rb`.
- Admin/dashboard gems (ActiveAdmin, Administrate, Sidekiq web) with their own mounted paths.

## Preconditions

- Rails in development mode (`consider_all_requests_local` true) for the info routes/detailed exception page to be exposed; production sets it false.
- A route/controller accepting mass assignment without filtering (`permit!`, or an unfiltered `Model.new(params[:model])` in legacy apps) for the mass-assignment family.
- The session cookie signed/encrypted with a `secret_key_base` that is exposed or weak, for the forgery family.
- Legacy `cookies_serializer` set to `:marshal` (or a cookie produced under it) for the deserialization family.
- A route where GET is denied but the verb can be tunneled to write, for the `_method` family.
- For the Active Storage family (`CVE-2026-66066`): `variant_processor = :vips` (implied by `load_defaults 7.0`+), the app accepts image uploads from untrusted users, and the Active Storage direct-upload route is reachable — it is present by default whenever Active Storage routes are mounted, even if the app's own UI never uses direct uploads. Generating image variants is **not** a separate precondition for the known chain.
- libvips presence and version: `< 8.13` cannot disable untrusted operations at all; `>= 8.13` supports `VIPS_BLOCK_UNTRUSTED` / `Vips.block_untrusted(true)`.
- Two independent fingerprint signals (cookie name + `csrf-token` + digested asset paths) and the Rails major.

## Oracles

- Info-route disclosure: `GET /rails/info/routes` returns the full route table (including unlinked/admin routes) and `/rails/info/properties` returns Rails/Ruby/Rack versions — 200 on a misconfigured deployment.
- Detailed exception page: a server error returns the Rails debug page with stack, params, and cookies instead of the generic 500.
- Mass-assignment escalation: a request that sets a normally server-controlled attribute (e.g. `role`, `admin`, `owner_id`) on a researcher-owned record succeeds because it was not `permit`ed against.
- Verb-tunneling bypass: `POST` with `_method=DELETE` (or `X-HTTP-Method-Override` header) reaches a destructive action that a direct `GET`/`POST` would have refused.
- Cookie forgery/deserialization: a modified signed cookie is accepted (weak/known `secret_key_base`), or a `:marshal`-serialized cookie is deserialized into an object gadget.
- CORS credentialed read: `rack-cors` reflects an arbitrary origin with credentials for a private endpoint.
- Active Storage variant file-read (CVE-2026-66066): a crafted upload whose variant is rendered returns file bytes in the image representation instead of image data — the known chain abuses the MATLAB-loader/HDF5 external-file-list path with a genuine signed `variation_key` obtained from a page that renders a representation. Lab/authorized scope only; classify by the returned representation, do not enumerate filesystem paths.
- Secrets-in-variant oracle: if a variant response yields environment-shaped content, treat the process environment (and therefore `secret_key_base`) as compromised; escalate to the advisory's rotation guidance.

## Minimal safe proof

1. Fingerprint + mode: confirm Rails from two signals and determine development vs production (info routes, error verbosity); note the Rails/Active Storage version and whether Vips is the variant processor.
2. Baseline: request one protected page from owner and anonymous sessions; record the routing and cookie behavior.
3. Info-route probe (read-only): `GET /rails/info/routes` and `/rails/info/properties`; if 200, record only the route-name list, not secrets.
4. Exception probe: request one path expected to error and classify generic-500 vs detailed-page.
5. Tunneling probe: on a researcher-owned object, one `_method`/`X-HTTP-Method-Override` request to a denial-only path; stop at the first state change.
6. Cookie probe: modify one byte of the researcher's own session cookie and observe rejection (control) before any forgery attempt; never use a forged cookie against another account.
7. Active Storage probe (only in an authorized program that accepts the risk, and never against production data): upload one researcher-owned file through the documented direct-upload flow, obtain a genuine signed variation key from a researcher-owned representation page, request exactly one crafted variant, and stop at the first non-image byte. Do not brute-force paths or read files outside researcher scope.
8. Stop conditions: any other-user record, any destructive action beyond researcher scope, any real `secret_key_base`/credential value, or any arbitrary file content beyond the single proof byte — halt and report; if secrets were exposed, follow the rotate-everything guidance.

## False positives

- `/rails/info/routes` returning 403/404 in production — the control is working.
- Route table containing only public routes — enumeration without a reachable restricted route.
- Generic 500 page — no source/secret disclosure.
- `permit!` present in code but the controller is unreachable or already authorized — require a live state change.
- `_method` echoed/ignored — require actual re-dispatch to a denied action.
- Cookie signature error on a modified cookie — expected tamper detection, not a finding.
- `X-Powered-By`/`Server` banner alone — fingerprint only.
- Variant response that is a normal image or a processing error — no file disclosure; require non-image bytes from a crafted upload.
- Magick (`mini_magick`) deployments — not affected through the reported CVE-2026-66066 vector, which is Vips-specific.

## Version/implementation notes

- CVE-2026-66066 ("KindaRails2Shell", critical, CVSSv4 9.5, CWE-1188): Active Storage did not disable libvips' unfuzzed/untrusted operations before processing user-supplied files. Affected: `activestorage < 7.2.3.2`, `>= 8.0 < 8.0.5.1`, `>= 8.1 < 8.1.3.1`; fixed `7.2.3.2` / `8.0.5.1` / `8.1.3.1`. libvips must be `>= 8.13`; when `ruby-vips` is installed, patched versions refuse to boot if the local libvips/ruby-vips cannot support blocking untrusted operations. Workarounds: `VIPS_BLOCK_UNTRUSTED` env var, or `Vips.block_untrusted(true)` from an initializer with `ruby-vips >= 2.2.1`; on libvips `< 8.13` the only workaround is removing libvips. Rails 6.0–6.1.7.10 may be affected under non-default Vips configuration but have no fixed releases — migrate or work around.
- CVE-2026-66066 exploitation notes: the published chain uses the direct-upload endpoint with a false image content type, then a crafted file that libvips reads as MATLAB level 5 (matload) while libmatio/`libhdf5` treats it as a MAT 7.3 HDF5 container whose External File List reads an attacker-selected path; the bytes are returned as image pixels. RCE escalation reuses recovered Rails signing material to forge an ImageProcessing 1.x variation (no Marshal deserialization needed). Rails published technical details and forensic tooling early after researcher reverse-engineering; scheduled cleanup of unattached blobs can destroy evidence, so forensic assessment must start promptly.
- Forking deployments (Puma/Unicorn) matter for the family: `VIPS_BLOCK_UNTRUSTED` must be present in every worker environment, and `load_defaults` version determines the default variant processor — Rails 7.0+ apps that never configured `variant_processor` still use Vips.
- If affected, treat every secret readable by the app process as exposed: rotate `secret_key_base`, the Rails master key (`config/master.key` or `RAILS_MASTER_KEY`) and everything in `config/credentials.yml.enc`, storage credentials (S3/GCS/Azure), database credentials, and third-party tokens. Rotating `secret_key_base` expires sessions and invalidates encrypted/signed cookies, signed global IDs, and Active Storage URLs.
- Fixed-version confirmation: the patched Active Storage requires libvips `>= 8.13` and (when `ruby-vips` is installed) `ruby-vips >= 2.2.1`; Rails refuses to boot when the local libraries cannot block untrusted operations, so a booting patched app is itself the control.
- Workaround ordering: `VIPS_BLOCK_UNTRUSTED` is read while libvips initializes, so it must be present in the process environment before boot; setting it at runtime is too late.
- `config.consider_all_requests_local = true` exposes both the detailed exception page and the `/rails/info/*` routes in development; production (`false`) hides them. `config.action_dispatch.show_exceptions` separately controls whether exceptions are rescued.
- `_method` and `X-HTTP-Method-Override` tunneling is `Rack::MethodOverride` (default only `POST`, `_method` param default; the base Rack middleware also honors the header) — the exact accepted combinations depend on the Rack middleware configuration.
- Cookie serialization: Rails 5+ defaults to `:json` for cookies; Rails 4.x used `:marshal`, and `:marshal`/`:hybrid` remain configurable — a `:marshal` cookie is the deserialization risk. `secret_key_base` is the signing key and lives in credentials/`master.key` or `ENV`.
- Strong Parameters replaced `attr_accessible`/`protected_attributes` (removed as a core gem after Rails 4); older codebases may still expose mass assignment.
- `/rails/info/properties` output set is defined by `Rails::Info` (Rails, Ruby, Rack versions and app-specific properties) and can be extended — treat its content as version-specific.
- Cookie fingerprints: signed cookies are base64 with a `--` separator; encrypted cookies also carry a purpose/version prefix. A cookie that decodes to JSON under a `:json` serializer is the modern shape; Marshal magic bytes (`\x04\x08`) indicate a legacy `:marshal` cookie.
- The development exception page decision can be observed with one controlled error: `consider_all_requests_local` controls the page while `action_dispatch.show_exceptions` controls whether the exception is rescued at all — a generic 500 can mean either, so classify both.
- Credentials layout matters operationally: `config/master.key` (or `RAILS_MASTER_KEY`) decrypts `config/credentials.yml.enc`; a leaked master key is equivalent to leaked `secret_key_base` plus every stored third-party credential, which is why CVE-2026-66066's response requires rotating the whole set.
- Mounted engines widen the route table: Active Storage (`/rails/active_storage/*`), Action Mailbox, Action Cable, and admin gems register their own routes — enumerate engine routes from `/rails/info/routes` or the config, and treat each as a separate authorization surface.
- A 200 on `/rails/info/routes` is a disclosure finding only when the table contains a route that is otherwise unreachable; compare the visible table against the app's public navigation before reporting enumeration alone.
- Mass-assignment surface includes nested attributes (`accepts_nested_attributes_for`) and `permit` lists that omit a sensitive key while permitting the parent object — read the controller's permit chain, then test one researcher-owned record.
- Variant-processing baseline: request one representation URL for a researcher-owned file first; the response should be an image content type. A `text/plain`/`binary` body is the anomaly, not a processing error.
- The `secret_key_base`/credentials family is high-impact but fragile evidence: never print a recovered key, hash it for the report, and stop as soon as the exposure is demonstrated.

## References

- [T1] Rails security advisory CVE-2026-66066 (Active Storage/libvips; affected and patched versions; workarounds; secret rotation; disclosure timeline): https://discuss.rubyonrails.org/t/cve-2026-66066-possible-arbitrary-file-read-and-remote-code-execution-in-active-storage-variant-processing/91432
- [T2] Rapid7, "KindaRails2Shell" analysis (CVSSv4 9.5, direct-upload + signed variation-key chain, libvips >= 8.13 requirement, forensic tooling): https://www.rapid7.com/blog/post/etr-kindarails2shell-cve-2026-66066-critical-arbitrary-file-read-and-possible-remote-code-execution-in-ruby-on-rails/
- [T1] Ruby on Rails API, `Rails::Info` (runtime properties shown by the info controller): https://api.rubyonrails.org/classes/Rails/Info.html
- [T1] Rails Configuration guide (`consider_all_requests_local`, `show_exceptions`, middleware stack): https://guides.rubyonrails.org/configuring.html
- [T1] Rails Security guide (mass assignment/Strong Parameters, sessions, CSRF): https://guides.rubyonrails.org/security.html
- [T1] Rails Routing guide (`_method`/`X-HTTP-Method-Override` form tunneling, `match`): https://guides.rubyonrails.org/routing.html
- [T1] Rack `Rack::MethodOverride` source (default `_method`, POST-only behavior): https://github.com/rack/rack/blob/main/lib/rack/method_override.rb
- [T1] Active Storage guide (`variant_processor`, `load_defaults` defaults, direct uploads): https://guides.rubyonrails.org/active_storage_overview.html
- [T3] `/rails/info/routes` behavior in development (route table with search filter): https://goalkicker.com/RubyOnRailsBook/RubyOnRailsNotesForProfessionals.pdf
- frameworks.md (this pack's manifest) for cross-cutting oracles and deployment-config discipline
