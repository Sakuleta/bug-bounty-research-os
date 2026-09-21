# Browser Security

> SCOPE: Load when testing anything rendered, executed, or enforced by the browser: XSS/mXSS, sanitizers and Trusted Types, navigation and redirects, cross-origin access (CORS/CORP/COOP/COEP), workers, storage partitioning, CSS injection, XS-Leaks, or client-side trust decisions.

## Research families

### Injection and parsing

- Reflected, stored, and DOM XSS (sinks over sources; canonical XSS detail lives here)
- Mutation XSS (mXSS): sanitizer output re-parsed differently by the browser
- Parser-context differentials: `<template>`, raw-text wrappers (`script`, `xmp`, `iframe`, `noembed`, `noframes`, `noscript`), and SVG/MathML foreign-content transitions
- Sanitizer-implementation research: DOMPurify bypasses, browser-native Sanitizer API (`Element.setHTML`/`setHTMLUnsafe`, `Document.parseHTMLUnsafe`) config differentials
- DOM clobbering via id/name attribute injection, and the underlying named-access-on-`Window` mechanism
- Trusted Types policy analysis: `require-trusted-types-for 'script'` coverage, default-policy bypass, sink-group gaps
- Client-side navigation sinks: `Location`/`location.href` setters, `window.open`, `javascript:`/`data:` scheme handling
- CSP policy analysis: `'strict-dynamic'` trust propagation, nonce/hash surface, `meta`-vs-header divergence, report-only leakage
- CSP reporting as a covert channel: `SecurityPolicyViolationEvent` and `report-to`/`report-uri` endpoints

### Messaging, workers, and document lifetime

- postMessage sender and receiver validation
- Service Worker scope, cache, update-race, and message-handler trust
- Service Worker lifecycle abuse: response rewrite, XSS persistence, local DoS, phishing/defacement, self-XSS escalation
- Reverse-tabnabbing / `opener`-reference abuse via `window.open` without `noopener`
- The cross-origin-accessible `Window`/`Location` surface as an explicit attack surface (`window`, `location` href get/set + `replace`, `postMessage`, array-index window access)

### Cross-origin access and isolation

- CORS response-class differentials (not just reflection)
- CORB/ORB, COOP/COEP/CORP, and Fetch Metadata enforcement gaps
- Cross-origin isolation posture: COOP browsing-context-group severing, COEP `require-corp`/`credentialless`, `crossOriginIsolated`
- Storage partitioning: double-keyed third-party storage, CHIPS `Partitioned` cookies, Storage Access API, cookie prefixes
- Referrer-Policy and its effect on the `Origin` header (`null`-origin shape)
- Open redirect and navigation-behavior chains (scheme rejection, redirect caps, method preservation)
- Modern CSRF and SameSite bypass shapes
- Storage, token, and WebView bridge exposure

### Oracles and exfiltration

- XS-Leak classes: framability, fetch-dedupe, timing, cache-probing, error oracles
- XS-Leak error oracles (CSP violation reports, CORB-blocked vs allowed, redirect-count limits)
- XS-Leak browser-API classes with concrete primitives: frame counting (`window.frames.length`), error events (`onload` vs `onerror`), `performance` timing buckets, connection-pool timing
- Historical/implementation-detail leaks: content-type sniffing (`typeMustMatch`), Scroll-to-Text-Fragment, redirect-count limits
- CSS injection and style-constrained exfiltration (attribute selectors, `:has()`, `@import` chaining, font/ligature tricks)

## Preconditions

- Attacker-controlled bytes reach an HTML, JS, CSS, URL, or postMessage sink — trace the sink first, then the source reachability.
- For mXSS: a server- or client-side sanitizer whose output is re-serialized through `<template>`, `innerHTML`, or SVG/MathML namespace transitions — or concatenated into a raw-text wrapper before the second parse.
- For DOM clobbering: attacker HTML with `id`/`name` attributes rendered in the same document as security-relevant JS globals (`config`, `settings`, `user`). Reachability depends on the HTML named-access rules (below), which are broader than most developers assume.
- For postMessage issues: a `message` listener reachable cross-origin (receiver) or a sender using `targetOrigin: '*'` with sensitive payload (sender).
- For SW issues: SW registration or update path influenced by attacker content, or a fetch handler performing privileged fetches. The SW script must be served with a JavaScript MIME type and be reachable under the intended scope.
- For XS-Leaks: a state-dependent cross-origin response difference (status, length, timing, error type) plus an embedding primitive (`<iframe>`, `<img>`, `fetch no-cors`, `window.open`).
- For CORS impact: credentialed cross-origin read of non-public data, not mere header reflection.
- For navigation impact: the redirect or scheme target must be attacker-influenced and reachable from a realistic entry point (parameter, path, postMessage-driven location write). The `Location` header itself only navigates to HTTP(S) URLs (Fetch).
- For CSP gaps: a policy is present, so the question flips from "is there XSS" to "what does this policy actually permit" — `'strict-dynamic'`, `'unsafe-hashes'`, a nonce/hash list, or a `meta`-delivered policy are each their own trust model. A missing `base-uri` leaves `<base href>` unrestricted.
- For Trusted Types: enforcement is on (`require-trusted-types-for 'script'`), so the attack surface is the policy callback body and the `trusted-types` name allowlist, not the sink call sites.
- For XS-Leak error events: a cross-origin endpoint whose existence under the victim's cookies is observable through load-vs-error of a `<script>`/`<img>` load, or through a cache-hit vs network fetch.
- For CSS-injection exfiltration: an injection point inside a stylesheet or `style` attribute, plus an attribute value derived from secret data — and styles still render when script is blocked by CSP or a sanitizer.
- For cross-origin window abuse: a page that stores secrets in `window.name`, relies on `w.location.href` being non-readable cross-origin, or assumes only `postMessage` crosses the boundary.
- For storage-partitioning findings: the target reads state set in a third-party context; under partitioning the third party only sees `(top-level site, own origin)`-scoped state unless Storage Access API access was granted.
- For COOP/COEP impact: the leak uses a window reference (defeated by COOP) or a cross-origin subresource (defeated by CORP/COEP) — the opt-in headers on the *victim* decide which oracles survive.
- For redirect-chain oracles: the chain length, method, and cross-origin hops are attacker-influenced, and the observable is a navigation outcome (error, download, `history.length`, CSP violation).

## Oracles

- Sink execution: unique canary (alphanumeric token, never `alert(1)` against production UI) fires in the target origin context — confirm via collaborator callback or DOM marker, not screenshots of dialogs.
- Sanitizer differential: payload inert immediately after sanitization but executable after one `innerHTML` round-trip through a detached `<template>` node (mXSS confirmed client-side, no server round-trip needed).
- Sanitizer context-switch differential: sanitized output that is re-wrapped (`<script>`, `<xmp>`, `<iframe>`, `<noembed>`, `<noframes>`, `<noscript>`) and reparsed releases markup the sanitizer already passed — the second parse context, not the sanitizer, is the bug.
- Sanitizer config differential: the same markup survives `Element.setHTML()` (safe default) but passes through `setHTMLUnsafe()`/`parseHTMLUnsafe()` unchanged — an "unsafe" call site trusted with attacker input is the bug, not the sanitizer.
- Clobbering: injected `<img name="config">` or `<form id="x">` shadows the expected JS global — verify with `typeof`/`instanceof` probes in console on your own session.
- postMessage receiver: attacker iframe message with a canary object reaches a dangerous sink (location assignment, HTML sink, fetch to sensitive endpoint) without origin check — log the handler's branch, not just receipt.
- postMessage sender: `targetOrigin` resolves to `*` (explicit, or required for `data:`/`file:` targets) while the payload carries a secret or a token-bearing URL.
- SW overreach: registered SW scope (`/`) broader than its script path (`/sub/sw.js`) and its fetch handler attaches credentials to attacker-chosen URLs.
- SW lifecycle abuse: a SW that rewrites a login page, persists an XSS across navigations, or exfiltrates cache URLs — observable as changed responses inside its scope, not as a script error.
- SW inventory signal: browsers send a `Service-Worker` request header when registering, and the registration request must return a JS MIME type — both are cheap black-box fingerprints for a SW surface and for upload-to-SW chains.
- CORS impact: `Origin: https://attacker.example` reflected with `Access-Control-Allow-Credentials: true` on an endpoint returning non-public data; `null`-origin acceptance only counts with a practical null-origin primitive (sandboxed iframe, redirect).
- CORS wildcard check: `Access-Control-Allow-Origin: *` never satisfies a credentialed CORS check — the literal `Origin` value (which may be `null`) must be returned instead.
- XS-Leak: consistent cross-state difference over 10+ samples (frame count, `performance` timing bucket, error vs load event) distinguishing logged-in victim state from logged-out.
- Navigation chain: redirect parameter reaches `location` or `<a href>` with `javascript:`/`data:` scheme executable, or `//evil.example` treated as same-origin path. Note the browser never follows a `javascript:`/`data:` `Location` header (Fetch rejects non-HTTP(S) redirect targets).
- Fetch Metadata signal: `Sec-Fetch-Site: cross-site` requests reaching state-changing endpoints that ignore fetch metadata confirm missing defense-in-depth even where tokens exist.
- CSP report oracle: a `report-uri`/`report-to` endpoint or `SecurityPolicyViolationEvent` listener reveals `blockedURI`, `effectiveDirective`, and (with `'report-sample'`) the first 40 chars of the blocked inline script — an out-of-band oracle for otherwise-blind injections.
- CSP cross-origin redirect oracle: with `connect-src` (or `form-action` after a GET form submission) pinned to one origin, a `SecurityPolicyViolationEvent` fires exactly when the request follows a redirect off that origin.
- Trusted Types oracle: with enforcement on, assigning a raw string to a guarded sink throws a `TypeError` and fires a `trusted-types-sink` CSP violation — the *absence* of that error at a sink proves the sink is outside the guarded group.
- CSP directive-precedence oracle: a duplicate directive in one policy is ignored after the first (first-wins), and multiple policies are combined (most restrictive wins) — a permissive duplicate does not loosen a strict earlier one.
- CSP trust-propagation oracle: under `'strict-dynamic'`, host allowlists and `'self'` no longer load scripts — only nonce/hash-trusted and dynamic-insertion paths do, so a working allowlisted `<script src>` proves `'strict-dynamic'` is not effective.
- Frame-counting oracle: `w.frames.length` / `w.length` read across origins reveals the number of child frames in the victim page — a binary oracle that changes with authenticated state; sample it on a timer (e.g. every 60 ms) when both states have the same steady-state count.
- Error-event oracle: loading `victim/search?q=SECRET` as a `<script>`/`<img>` fires `onload` on a hit and `onerror` on a miss, giving a binary oracle over authenticated responses (the XS-Search pattern). Behavior varies by tag, `Content-Type`, and `X-Content-Type-Options`.
- Cache/timing oracle: per-resource cache probing (does a `fetch`/`<img>` return instantly from cache?) or network-timing buckets distinguish state without any response being readable.
- Cache-probing error oracle: when a resource was cached with a reflected `Access-Control-Allow-Origin` from another origin, a `fetch(..., {mode:"cors"})` from your origin fails on the cached copy — error vs success becomes a cache-state oracle.
- Cache-invalidation oracle: `cache: "reload"` plus `AbortController.abort()` before the body arrives probes (and purges) cache entries without leaving new content behind; a `no-cors` POST or a form POST can purge by the top-level key, bypassing partitioned HTTP caches.
- Navigation oracle: an `<iframe>`'s load events, `history.length` (read after navigating a window reference away and back), and `Content-Disposition: attachment` detection (a download produces no navigation, so the window stays on the attacker origin) all reveal whether a cross-origin navigation happened.
- Redirect-count oracle: browsers stop a chain after 20 redirects (Fetch: redirect count 20 → network error), so the number of redirects taken by a cross-origin endpoint is measurable with error events — top-level navigations included.
- Connection-pool oracle: browsers cap global sockets (Chrome historically 256 TCP / 6000 UDP); block N-1 sockets against hanging hosts, then time the target request to bucket its network duration. Connection reuse is also readable directly: `performance.getEntries()` exposes `connectStart === startTime` (reused) and `nextHopProtocol`.
- CSS-injection oracle: a rule whose URL (`background:`, `@import`, `@font-face src`) embeds a secret attribute value generates a distinct collaborator request per leaked character; `html:has(input[value^="x"])` works even for hidden inputs and unknown page structure.
- CSS variable on/off oracle: `input[value="1337"] { --v: url(/collect?1337); } input { background: var(--v, none); }` — the `none` fallback is what prevents an invalid assignment and makes the request conditional.
- CSP sample oracle detail: with `'report-sample'`, the violation `sample` carries the first 40 characters of the blocked inline script/handler — a partial-content leak with no execution.
- Cross-origin `Window` surface: cross-origin code may only read the safelisted names (`closed`, `length`, `top`, `frames`, array indices) and may *set* `location`; a design that exposes anything else across origins is already outside spec-provided guarantees.
- CSP hash-report oracle: a page using `'report-sha256'` (or `384`/`512`) emits a `csp-hash` report containing the loaded subresource URL and its computed hash — an integrity/asset oracle delivered to the report collector.
- COEP/COOP report oracle: a blocked cross-origin embed yields a `coep` report (`blockedURL`, `destination`, `type: "corp"`, `disposition`), and a severed window yields `coop` reports (`navigation-from-response`, `access-from-coop-page-to-openee`, `effectivePolicy`) — an out-of-band confirmation that isolation is actually enforced.
- Storage Access API oracle: `Permissions.query({name:"storage-access"})` and whether `requestStorageAccess()` resolves tell you if a third party can still see unpartitioned state under the user's browser policy.
- `crossOriginIsolated` oracle: `self.crossOriginIsolated` is a single boolean that reports whether COOP+COEP (plus Permissions-Policy) actually produced an isolated document — check it before predicting timer/SAB behavior.

## Minimal safe proof

1. Map sinks first: enumerate `message` listeners, `innerHTML`/`document.write`/`eval`/`location` assignments, and SW registration calls from shipped JS before crafting any payload.
2. Prove with canaries: use inert unique tokens (`bbcanary-<rand>`) in attribute, JS-string, HTML, URL, and postMessage positions; observe reflection context without executing anything.
3. Escalate one step only: turn exactly one confirmed canary context into a benign execution proof (console-logging custom event or collaborator fetch from *your own* session); never auto-spread stored payloads to other users' views.
4. postMessage: send structured canary messages from an attacker-origin iframe you control; record which handler branches execute and stop before triggering state changes.
5. SW: register or update only a SW you serve on your own test path with narrowest scope; never overwrite a production SW or broaden scope on a shared origin. Prove the fetch handler with a canary response inside your own session.
6. CSP analysis is read-only first: parse the policy, name which source expression decides the outcome (`'strict-dynamic'`, nonce, hash, host), and confirm with a report-only/report-collector probe before attempting a bypass.
7. Stop conditions: stored payload visible to other accounts, SW update affecting other sessions, CORS proof touching another user's data, or any XS-Leak enumeration of real victim state — halt and report the oracle with your own accounts only.
8. CSS-injection and report-based proofs leak only canary characters from your own session; never target another user's secret attribute values.
9. Error-event / XS-Search proofs need a logged-out control and 10+ samples per state; stop before enumerating real victim data, and prefer frame-count/`length` oracles over search-term enumeration.
10. Redirect probes: use your own collaborator target and a single benign hop; never chain through third-party redirectors you do not own, and stop before any stored redirect or open-redirect chain reaches real users.
11. Storage-partitioning checks are read-only: `crossOriginIsolated`, `Permissions.query({name:"storage-access"})`, and cookie presence from your own third-party frame; register an observation, do not attempt to break out of the partition.
12. CSS exfiltration proofs run against your own session data only, hosted on an HTTP/2 endpoint (avoids preflight), and stop after the canary field is recovered — never enumerate another user's values.
13. Cache-probing proofs use `cache: "reload"` + `AbortController` on resources you own; do not purge or poison caches that other sessions depend on.

### Detection methodology

1. Enumerate sinks from shipped JS: `innerHTML`/`outerHTML`/`insertAdjacentHTML`, `document.write`, `eval`/`setTimeout(string)`, `location`/`location.href` writes, `postMessage` senders, `new Worker`, and `navigator.serviceWorker.register` — then pair each with its source (URL params, hash, `document.referrer`, postMessage, storage).
2. Parse the CSP exactly as the browser would: split on `;`, ASCII-lowercase directive names, first-wins on duplicates; identify the expression that decides `script-src`, and whether a `<meta>` policy silently drops `frame-ancestors`/`report-uri`/`sandbox`. Note that any nonce or hash source disables `'unsafe-inline'` in the same directive.
3. Detect Trusted Types enforcement empirically: a raw-string assignment to a guarded sink throws `TypeError`; if it does not, name which sink group is unguarded.
4. Fingerprint client dependencies (DOMPurify version, sanitizer library, framework build) from bundler output/provenance before attempting any bypass; treat the DOMPurify advisories index as the version oracle.
5. Pick the XS-Leak oracle by embedding primitive first: `<iframe>` → frame counting/framability; `<img>`/`<script>` → error events/CORB; `fetch no-cors` → cache/timing; `window.open` → window-reference timing (defeated by COOP); `history.length`/download detection → navigation outcomes.
6. Record browser generation and origin-isolation headers (COOP/COEP/CORP) once — most "leaks" are decided by which opt-in headers are present. Check them on every document and worker in the chain: COEP with duplicate headers or multiple tokens is equivalent to `unsafe-none`.
7. Inventory Service Workers before testing: check `navigator.serviceWorker.getRegistrations()`, the scope/script paths, and whether registration requests were served with a JavaScript MIME type; a SW's fetch handler also sees cross-origin subresources referenced by pages in scope.
8. Read the cookie and storage posture in one pass: `SameSite` values and age, `Partitioned`/`__Host-`/`__Http-` prefixes, `Referrer-Policy`, and whether `<base>` is constrained by `base-uri`.

## False positives

- Reflected input inside a correctly-encoded attribute or text node with no executable context — rule out by attempting breakouts per context (`"`, `'`, `</tag>`, backtick, URL scheme) and confirming inertness.
- `Access-Control-Allow-Origin: *` without credentials on public data — no confidentiality impact; require credentialed read of non-public data.
- `postMessage` listener that validates `event.origin` against an exact allowlist before any sink — receipt of the message alone is not a finding; require sink reachability.
- SW file served from a subdirectory with default (narrow) scope — scoping is working as designed; require overbroad scope plus privileged fetch behavior.
- XS-Leak timing differences under 10 samples or without a logged-out control — network jitter; require statistically separated distributions with controls.
- `javascript:` string present in JS source but never assigned to a URL sink (dead code, string literal) — require sink reachability in shipped code.
- Sanitizer stripping the payload on first pass where no re-parse primitive exists on the page — inert without a round-trip sink; require the re-serialization step (a `<template>` round-trip, or a raw-text wrapper concatenated around the sanitized string).
- Framework auto-escaping (React children, Vue interpolation, Angular binding) rendering the payload as text — correct default; require a genuine escape hatch (`dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrustHtml` — see frameworks pack).
- `postMessage` origin check present but using substring or regex match (`evil-target.example` passing a `target.example` check) — verify with exact-match negative controls, not just honest-origin positives.
- COOP/COEP headers present on the main document but missing on the data-serving endpoint — window-reference and timing leaks stay viable; require consistent policy on both sides before calling it mitigated.
- Redirect allowlist validated after decoding exactly once while the browser decodes twice (`%252f` becoming `/` post-check) — verify with double-encoding controls before declaring the check effective.
- A CSP with `'unsafe-inline'` *and* a nonce/hash: the browser ignores `'unsafe-inline'` (the nonce/hash wins), so the policy is *stronger* than it looks — do not report it as "looks hardened but admits any inline script". **Correction to prior revision of this pack, which stated the inverse.**
- Newlines/whitespace around a directive token (`script-SRC 'none'` vs `script-src 'none'`) are normalized (case-insensitive, ASCII-whitespace-split) — a "bypass" that only differs in casing is not a bypass.
- `Content-Security-Policy-Report-Only` treated as an enforced block — report-only never blocks; require the enforced header to reproduce the block.
- A `frame-ancestors`/`report-uri`/`sandbox` directive delivered via `<meta>` — those directives are ignored in `meta`; the page is *not* protected by them (a finding about the page, not a bypass). `Content-Security-Policy-Report-Only` is not supported in `meta` at all.
- Named access: a `window[name]` collision that resolves to an `HTMLCollection` rather than a single element — the clobbering impact depends on the code's read path (`config.value` vs `config[0]`); require the shadowed read to change a decision.
- A single `w.length` or timing difference without repeated-sample separation — measure jitter first; require a stable per-state distribution. Frame counts can differ for unrelated reasons (ads, extension frames, A/B layout), so require the difference to track the state variable.
- Cross-origin reads of `closed`/`length`/`location` that carry no state-dependent value — normal cross-origin behavior, not a leak.
- A `report-only` CSP producing violations but no enforced policy — monitoring is not blocking; require the enforced header.
- A `postMessage` call using the options form without `targetOrigin` (which defaults to `/`, the sender's own origin) — check the resolved value; a literal `*` is the risk. `*` is also the only workable target for `data:`/`file:` documents, so a `*` to an opaque-origin frame is not automatically a finding.
- `Origin: null` on a state-changing request: the null may be produced by the page's own `Referrer-Policy` (`no-referrer`, or a downgrade/`same-origin` rule) rather than by an opaque origin — check the policy before claiming a sandbox/`data:` primitive.
- CORB/ORB "blocked" responses are empty, not errors: a blocked `<img>` may still fire `onload`, and a blocked `<script>` produces no syntax error — do not treat load-vs-error alone as proof the body was readable.
- `Cross-Origin-Resource-Policy: cross-origin` is the default behavior if the header is absent — an explicit `cross-origin` is not "missing protection"; require absence *and* an embeddability expectation that depends on it.
- `Content-Disposition: attachment` responses ignore `X-Frame-Options`/`frame-ancestors` — that is browser behavior, not a framing misconfiguration; the finding, if any, is the information leak through download-vs-navigate.
- A `SameSite=Lax` cookie being sent on a top-level cross-site GET navigation is by design, not a CSRF bug — require a non-idempotent method or a state change on GET. The Chrome `Lax+POST` 2-minute window applies only to cookies *without* an explicit `SameSite` attribute; do not generalize it to other browsers.
- Service Worker registered but with no privileged fetch handler and default scope — no capability gain; require response rewriting, credential attachment, or scope overreach.
- COEP set twice, or with multiple tokens: browsers treat the header as `unsafe-none` — an isolation claim based on such a header is wrong in both directions.
- `document.domain` assignment succeeding is not itself a finding on modern Chrome (deprecated/no-op in isolated contexts); require an actual same-origin reachability gain.
- A cross-origin redirect that changes only the path on the same origin — not cross-origin; check scheme+host+port before reporting a redirect oracle.

## Version/implementation notes

### Parsing and sanitizers — mXSS is a moving target

- mXSS payloads are namespace- and parser-sensitive: SVG/MathML confusion shapes that fire in Chrome may be inert in Firefox or Safari; verify per browser and record versions.
- DOMPurify advisories define the exploitable window: CVE-2024-45801 / GHSA-mmhx-hmjr-r674 — malicious HTML using special nesting bypassed the depth check (and prototype pollution could weaken it), affecting `<2.5.4` and `<3.1.3`, fixed in `2.5.4`/`3.1.3`; the fix commits are `1e52026` (3.x) and `26e1d69` (2.x). Treat DOMPurify version as a first-class fingerprint — an old bundled copy is the bug, not "DOMPurify is broken".
- DOMPurify 3.x advisory tail (each is a separate small window, all default-config XSS unless noted): CVE-2026-3126 / GHSA-h8r8-wccr-v5f2 — mXSS via re-contextualization, sanitized output concatenated into `<script>`/`<xmp>`/`<iframe>`/`<noembed>`/`<noframes>`/`<noscript>` wrappers and reparsed; affects `3.3.1`, patched `3.3.2`. CVE-2026-47423 / GHSA-87xg-pxx2-7hvx — `<selectedcontent>` re-clone: the browser refreshes the sanitized clone from the original `<option>` after DOMPurify has moved on; affects `3.4.4`, patched `3.4.5`, reproduced in Chromium 148/WebKit 625 but not Firefox. The 2026 index also shows a hook/`IN_PLACE` cluster: `IN_PLACE` hook removal leaving detached subtrees executable (GHSA-55q2-fjhq-7xh7), `CUSTOM_ELEMENT_HANDLING` bypassing `afterSanitizeElements` (GHSA-c2j3-45gr-mqc4), `ALLOWED_ATTR` pollution via `setConfig()` (GHSA-cmwh-pvxp-8882), Trusted Types policy surviving `clearConfig()` (GHSA-vxr8-fq34-vvx9), `SAFE_FOR_TEMPLATES` expressions surviving inside `<template>` content (GHSA-gvmj-g25r-r7wr), and `IN_PLACE` issues with attacker-controlled root nodes/nodeName/shadow roots (GHSA-x4vx-rjvf-j5p4, GHSA-rp9w-3fw7-7cwq, GHSA-hpcv-96wg-7vj8, GHSA-r47g-fvhr-h676). Prefer the GHSA index over memorized version numbers; the current patch level is the version oracle.
- The browser-native Sanitizer API (now in WHATWG HTML; `setHTMLUnsafe` Baseline 2025) differs by method: `setHTML()` has a restrictive safe default and runs `removeUnsafe()` on the config, while `setHTMLUnsafe()`/`parseHTMLUnsafe()` are **unrestricted by default**. The built-in safe baseline removes `script`/`embed`/`frame`/`iframe`/`object` (HTML namespace) and SVG `script`/`use`, plus all `on*` event-handler content attributes. A call site that uses the "unsafe" variant on user input is the finding.
- Sanitizer API config surface details: the default config removes XSS-unsafe elements/attributes plus clickjacking/spoofing vectors; safe methods apply that default automatically and still strip XSS-unsafe items from a caller-supplied sanitizer (without mutating the passed config); unsafe methods sanitize nothing by default; a global allow-list and remove-list for the same name is an invalid config and throws; `"default"` is accepted as a sanitizer string; `setHTMLUnsafe()` parses declarative shadow roots (only the first per host); a string input to a TT-guarded method without a default policy throws `TypeError`.
- Trusted Types (W3C WD) guards the DOM XSS sink group named `script` — setters for URL/code attributes, `eval`, `javascript:` navigation, and HTML-parsing sinks (`innerHTML`/`outerHTML`/`ShadowRoot.innerHTML`, `document.write`, `DOMParser.parseFromString`). Production enforcement is opt-in via CSP (`require-trusted-types-for 'script'` plus a `trusted-types` name allowlist); almost every app leaves the DOM-XSS sink group enabled. `createPolicy` is name-gated by the `trusted-types` directive (and `'allow-duplicates'` controls re-registration), so a policy name absent from the allowlist throws.
- `document.domain` relaxation is deprecated and disabled by default in modern Chrome; historical subdomain-XSS chains assuming it need revalidation.
- `document.domain` details that change old chains: the setter can only go to the same or a parent domain, it **removes the port component from the origin** (so a different-port site on the same host becomes same-origin), it throws `SecurityError` on sandboxed/opaque-origin documents, and it does nothing on a cross-origin-isolated (COOP+COEP) page or one using `Origin-Agent-Cluster`. It also does not affect origin checks for `localStorage`, `IndexedDB`, `BroadcastChannel`, or `SharedWorker`.

### Cookies, isolation, and navigation

- SameSite default (`Lax`) and cookie `Secure` requirements change CSRF viability per browser generation; test top-level navigation vs subrequest paths separately. Chromium enforcement timeline: announced for Chrome 80, limited rollout from 2020-02-17, paused during COVID, resumed 2020-07-14, 100% of Chrome 80+ by 2020-08-11; flags removed in Chrome 91; Android WebView gets modern SameSite only for apps targeting Android 12+; Chrome iOS unaffected.
- The Chrome `Lax+POST` intervention: cookies with **no explicit** `SameSite` attribute are sent on top-level cross-site POST if at most 2 minutes old; "normal" Lax cookies (and non-idempotent methods like PUT) are never sent cross-site. Test with `--enable-features=SameSiteDefaultChecksMethodRigorously` (removes the mitigation) or `ShortLaxAllowUnsafeThreshold` (10 s window) instead of waiting 2 minutes. `SameSite=None` without `Secure` is rejected, and "Schemeful Same-Site" means `http`/`https` variants of a host are cross-site to each other.
- Cookie prefixes are a defense to check for in takeover/CSRF chains: `__Secure-` (Secure), `__Host-` (Secure, no `Domain`, `Path=/`), and the newer `__Http-`/`__Host-Http-` (must carry `HttpOnly`, proving Set-Cookie provenance). `Partitioned` cookies must be `Secure`.
- CORB/ORB blocking of cross-origin JSON (the Chromium CORB explainer's `plasma` corpus) changes XSSI viability: a `text/html`-sniffed JSON endpoint readable via `<script>` in legacy browsers may be neutered in current Chrome; record the blocking behavior observed. CORB protects JSON/HTML/XML, is exempt for `iframe`/`object`/`embed` and downloads, and blocks before the body reaches a renderer; responses blocked by CORB/ORB have an empty body, so "load vs error" signals change shape.
- ORB (CORB++, being upstreamed to Fetch) generalizes this with MIME sets instead of sniffing heuristics: opaque-safelisted (`text/css`, `image/svg+xml`, JavaScript MIME types) are always allowed, opaque-blocklisted (HTML/JSON/XML) are blocked, a large never-sniffed list (PDF, ZIP, CSV, `text/event-stream`, office formats, `multipart/*`) is blocked outright, `nosniff` + blocklisted (or `text/plain`) blocks, then media/image patterns are sniffed from the first 1024 bytes, and the last resort is a full-body JavaScript/JSON parse. XSSI-defeating prefixes (`)]}'`, `{} &&`, `for(;;);`) are a strong signal to protect, with `text/css` an explicit exception. CORB's `nosniff`/206 handling is in Fetch; confirmation sniffing is not standardized.
- Trusted Types (if enforced) convert many HTML sinks into throw-on-string — treat enforcement as a mitigation to bypass via policy analysis, not as absence of sinks.
- `window.name` is reset when a navigable is navigated to another origin, so cross-origin `window.name` persistence is not a general-purpose channel on modern engines; verify the observed behavior rather than assuming.
- HTML named access makes a `Window` property resolve from: same-origin document-tree child navigables' target names; the `name` content attribute of `embed`/`form`/`img`/`object`; and any element's `id`. Ordering is tree order with duplicates ignored, and equal-name collisions return an `HTMLCollection` — that ordering is what a clobbering payload must respect.
- Storage partitioning (launched in Chrome 115) double-keys third-party storage and communication APIs by top-level site + own origin; Firefox partitions third-party cookie storage by default (state partitioning). CHIPS (`Partitioned`) is the opt-in cookie mechanism: the partition key is the top-level **site including scheme**, so re-embedding under another top-level site gets a separate jar, while subdomains of the same site still share it. Access to unpartitioned state from an embedded frame requires the Storage Access API: `requestStorageAccess()` needs transient activation (unless already granted), is per own-origin, is blocked by a `storage-access` Permissions Policy, and a sandboxed iframe needs `allow-storage-access-by-user-activation`; `types` can additionally request `localStorage`/`indexedDB`/`caches`/`SharedWorker`/`BroadcastChannel` handles.
- Referrer policy shapes CSRF/CORS evidence: the default is `strict-origin-when-cross-origin` (origin only on cross-origin requests, nothing on HTTPS→HTTP). For non-CORS-mode requests (form submissions, `mode:"same-origin"/"no-cors"`), `no-referrer`, a downgrade under `no-referrer-when-downgrade`/`strict-origin`, or `same-origin` cross-origin sends make the browser set `Origin: null`. A same-origin `fetch()` POST still sends the real origin because `fetch` defaults to `mode:"cors"`. `Referrer-Policy: unsafe-url` leaks full URLs including query strings.

### CSP semantics (Level 3) that decide outcomes

- Duplicate directives: the *first* occurrence wins and later duplicates are ignored. Multiple policies combine (intersection/most-restrictive). A permissive directive cannot loosen a stricter earlier one.
- `'strict-dynamic'` changes trust propagation: script that runs on the page may load more script via **non-parser-inserted** `script` elements, which is why nonce/hash-based `'strict-dynamic'` deployments can be bypassed only via an already-running trusted script, not a plain injected `<script src>`. When `'strict-dynamic'` is present, allowlists, `'self'`, and `'unsafe-inline'` are ignored; host allowlists therefore stop being a bypass surface.
- `'unsafe-inline'` is ignored whenever the same directive also contains a nonce-source or hash-source — the strict source wins, so the common "unsafe-inline plus nonce" deployment is nonce-only for inline scripts. Nonce and hash sources only apply to `<script>`/`<style>` elements (use `'unsafe-hashes'` for event handlers/style attributes).
- `'unsafe-hashes'` lets event handlers, `style` attributes, and `javascript:` navigation match hashes — a policy that lists these is a different (weaker) model than a nonce-only `script-src`. MDN notes the sharp edge: the same handler body injected as an inline `<script>` also matches its hash, so hashed handlers become injectable script content.
- Hash sources may match external scripts only when the `script` element also carries matching `integrity` metadata, and every *valid* hash in `integrity` must appear in the CSP; unrecognized hash tokens are ignored; base64 and base64url forms are equivalent. `'wasm-unsafe-eval'` gates WebAssembly, `'trusted-types-eval'` gates TT-mediated `eval`/`Function`, and `'unsafe-eval'` overrides `'wasm-unsafe-eval'`.
- `meta`-delivered CSP cannot enforce `report-uri`, `frame-ancestors`, or `sandbox`, and `Content-Security-Policy-Report-Only` is not supported in `meta` at all; resources fetched before an early `<meta>` policy are not covered.
- `base-uri` has **no `default-src` fallback**: if it is absent, any URL may set the document's base URI, so a single injected `<base href="//attacker">` retargets every relative script/URL on the page. `base-uri 'none'` is the strict form.
- Worker CSP is per-request, not inherited: a worker is governed by the CSP of the response that served the worker script, except when the worker URL is a `data:`/`blob:` (opaque-origin) URL, in which case it inherits the creating document's policy. `worker-src` (or `child-src`/`default-src` fallback) restricts which worker scripts load.

### Fetch Metadata and Service Workers

- Fetch Metadata (`Sec-Fetch-Site`/`Sec-Fetch-Mode`/`Sec-Fetch-Dest`/`Sec-Fetch-User`) is spec'd by W3C; shipping baseline is Chrome 76+ / Firefox 90+ / Safari 16.4+ for `Sec-Fetch-Site`, Chrome 80+ for `Sec-Fetch-Dest`. The `Sec-` prefix makes them forbidden response-header names (unforgeable from JS). Values shift along a redirect chain (a chain that passes through a cross-site URL yields `cross-site` even if it returns same-origin), and a response that depends on them must `Vary` on them.
- Service Worker registration: default scope is the script's directory (resolved against the script URL), broadenable only with a `Service-Worker-Allowed` response header (otherwise registration fails); `scriptURL` and scope must be same-origin and use `http(s)`; path segments containing case-insensitive `%2F`/`%5C` are rejected. `updateViaCache` is `'all' | 'imports' | 'none'` (default `'imports'`: main script always revalidated from network, imports may come from HTTP cache). `worker-src`/`script-src`/`default-src` CSP restricts allowed script URLs, and `TrustedScriptURL` is required where Trusted Types are enforced.
- Service Worker lifecycle: one worker controls a scope at a time; a second registration under the same scope replaces the first, and when scopes overlap the more specific scope wins. `importScripts()` must be same-origin. A new version installs in the background and stays `waiting` until every client controlled by the old version is gone; `skipWaiting()` activates immediately and `clients.claim()` adopts already-open pages (the two calls that turn a narrow bug into an event). The fetch handler covers all requests inside scope, including cross-origin subresources referenced by controlled pages, and `event.respondWith()` can rewrite body, status, and headers; `navigationPreload` fetches navigations in parallel. SWs persist across browser restarts until unregistered or storage cleared.
- SW abuse shapes (Akamai): persisted XSS that appends a payload to every page in scope; response rewrite for phishing/defacement (login page rerouted through an attacker server); local DoS by answering 404; exfiltration of "sandboxed" upload-domain URLs when an upload endpoint serves attacker JavaScript with a JS MIME type and the attacker can trigger XSS there; escalation of a self-XSS into a persistent cross-user issue via login/logout CSRF. Practical constraints are scope depth and the JS MIME type requirement.

### COOP/COEP/CORP and cross-origin isolation

- COOP has four values: `unsafe-none` (default), `same-origin`, `same-origin-allow-popups`, and `noopener-allow-popups`. On navigations, documents share a browsing context group only when policies "match" (both `unsafe-none`, or same policy + same origin); with `window.open()`, a `noopener-allow-popups` document always opens into a new BCG and reports `window.closed === true` to the opener, and `unsafe-none` can still be opened into the opener's BCG by a `same-origin-allow-popups`/`noopener-allow-popups` opener. COOP severs window references used by XS-Leaks but does nothing against iframe-based oracles (framing protections govern those).
- COEP values are `unsafe-none` (default), `require-corp`, and `credentialless`; `credentialless` loads cross-origin `no-cors` subresources without credentials and ignores credential-bearing responses. The header should carry exactly one token: setting it more than once or with multiple tokens is equivalent to `unsafe-none`. COEP does not override CORP/CORS — a resource CORP'd `same-origin` stays blocked regardless. Violations are `coep` reports (`blockedURL`, `destination`, `type:"corp"`, `disposition`) sent via `report-to`/`Reporting-Endpoints`, and COOP reports use types `navigation-from-response` and `access-from-coop-page-to-openee`.
- `Cross-Origin-Resource-Policy` is `same-site | same-origin | cross-origin` and applies to `no-cors` cross-origin loads; absent CORP behaves as `cross-origin`. CORP is the per-resource opt-in that COEP `require-corp` requires, and it is the header that actually stops most XS-Leak embedding oracles.
- Cross-origin isolation is the combination `COOP: same-origin` + `COEP: require-corp|credentialless` (+ `Permissions-Policy` not blocking `cross-origin-isolated`); verify with `self.crossOriginIsolated`. Milestones: `crossOriginIsolated` from Chrome 87, SharedArrayBuffer restricted to isolated pages on desktop from Chrome 92 / Android Chrome 88, and `document.domain` becomes immutable in isolated documents. Iframes need `allow="cross-origin-isolated"` and the whole ancestor chain isolated.

### Cross-origin window and location surface (HTML spec)

- The cross-origin-accessible `Window` names are a fixed safelist: `window`, `self`, `location`, `close`, `closed`, `focus`, `blur`, `frames`, `length`, `top`, `opener`, `parent`, `postMessage`, plus array indices. A cross-origin `Location` exposes only `href` (get and set) and `replace`. Everything else throws `SecurityError` or resolves via the fallback.
- The `Location.href` setter "intentionally has no security check" — navigation to `javascript:`/`data:` is therefore governed by the *target context's* rules and by CSP (`script-src` inline checks for `javascript:` navigation), not by the setter's origin. This is why "attacker writes `location`" and "payload executes" are separate questions.
- `frameElement` returns null in cross-origin situations, and `opener`/`top`/`parent` return `WindowProxy` (null when the browsing context has been discarded), so a stale reference read after the frame is removed is not a leak.
- `window.name` is reset when a navigable is navigated to another origin; `window.open` defaults `target="_blank"` and, unless `noopener`/`noreferrer` is set, leaves an `opener` reference the opened page can navigate — the reverse-tabnabbing precondition.
- `postMessage` semantics that decide findings: `targetOrigin` defaults to `"/"` (the sender's own origin), so the risk is an explicit `*`; `data:` targets require `"*"`, `file:` targets require `"*"`, and extension senders have `source === null`. `event.origin` is the sender's origin *at send time* — it is not the window's current origin (the frame may have navigated), it is unaffected by `document.domain`, and for IDN hosts it may appear as Unicode or punycode, so content checks should accept both.

### XS-Leak taxonomy (from the xsleaks wiki)

- Root cause is composability: the browser lets sites load each other's resources and observe side effects, so an "oracle" answers a binary YES/NO about the victim (e.g. "does `?query=secret` return 200?" detectable via the `onload`/`onerror` events). This is CSRF's sibling: CSRF performs an action, XS-Leaks infer information.
- Source classes to enumerate: **browser APIs** (frame counting, timing), **implementation details/bugs** (connection pooling, `typeMustMatch` content-type), and **hardware** (Spectre-class speculative execution). Timing attacks on browsing activity are documented since 2000; "Cross-Site Search Attacks" (2015) turned them into high-impact XS-Search.
- Defenses are opt-in and header-driven: e.g. `Cross-Origin-Opener-Policy: same-origin` severs the window reference that enables many timing/oracle classes. Treat a missing opt-in header as the precondition, and confirm the leak empirically rather than assuming it.
- Defense mapping matters per primitive: `SameSite=Lax` cookies and framing protections cover iframe oracles but not window-reference oracles; COOP covers windows but not iframes. Connection-pool timing is covered by none of them (browsers are considering randomized capacity / partitioned socket pools).
- Frame counting: `win.length` on a `window.open`/iframe reference; sample at an interval (60 ms) to build a load-time pattern when steady states collide; real-world leaks include Facebook profile attributes and GitHub private repositories.
- Error events: `onload`/`onerror` availability varies by element, `Content-Type`, `X-Content-Type-Options`, and status; use them for auth-state oracles and as the readable half of cache probing. Classic reports: Twitter API endpoint error vs success to deanonymize a user; image-auth flaw in private messages.
- Cache probing: detect cache hits by timing, by error events after forced invalidation, by a cached CORS response whose reflected `Access-Control-Allow-Origin` no longer matches, or by `window.stop()` racing a navigation to a same-site cached URL. Purge/invalidate with `cache:"reload"` + `AbortController`, a `no-cors` POST, a form POST (uses the top-level-site key, bypassing partitioned caches), a failed request with unusual headers, or by exceeding the cache limit. HTTP cache partitioning by top-level eTLD+1 (since ~Sept 2021) blocks the cross-site version but is ineffective for subdomains and window navigations; `Vary: Sec-Fetch-Site`, `Cache-Control: no-store`, and unpredictable URL tokens are the app-side mitigations. Real-world: YouTube thumbnail cache check revealed whether a video had been watched.
- Navigations: `history.length` (navigate a reference to the target, then back to same-origin, then read), iframe `onload` counts, and `Content-Disposition: attachment` detection (a download does not navigate, so the window stays on your origin; XFO/CSP framing headers are ignored for attachment responses). Redirect-chain length is measurable via the 20-redirect cap (Fetch: 20 → network error) and via URL-length inflation (server-side error or Chrome's ~2 MB abort to `about:blank`); fragments are preserved across server redirects, which makes inflation controllable. Cross-origin redirect leaks use CSP `connect-src`/`form-action` violations (note: Firefox does not block post-form-submission redirects with `form-action`). Real-world: Twitter private-tweet XS-Search.
- Connection pool: block N-1 of the browser's global sockets (Chrome historically 256 TCP / 6000 UDP) against hanging hosts, then time the target; connection reuse is readable from `performance.getEntries()` (`connectStart === startTime`, `nextHopProtocol`), with `Timing-Allow-Origin` needed for full timing detail. HTTP/2 connection coalescing (keyed by whether credentials are included) and HPACK/stream priority create further buckets, and HTTP/3 connections idle out (~30 s).

### CSS exfiltration mechanics (PortSwigger blind-CSS technique)

- Confirm styles render with `"><style>@import'//collab'</style>` — `@import` fires a collaborator request without any script; serve the exfiltrator over HTTP/2 to avoid preflights on cross-protocol requests.
- Attribute selectors are the leak primitive: `[value^="a"]`, `[value$="f"]`, `[value*="x"]` (starts/ends/contains). Combine with a CSS variable as a condition and a `none` fallback so the `background` assignment stays valid: `input[value="1337"]{--v:url(/c?1337)} input{background:var(--v,none)}`.
- `:has()` removes the need to know sibling structure and works when the matching element cannot itself load a URL (hidden inputs): `div:has(input[value="1337"]){background:url(/c?1337)}`. Anchor the request on `html:has(...)` because page CSS rarely sets the `html` background — otherwise cascade order can overwrite your rule.
- Use `:not()` to advance after enumerating a value (`html:has(input[name^="m"]):not(input[name="mytoken"])`) and `@import` chaining (Pepe Vila / d0nut technique) for throughput. The published exfiltrator recovers input names/values, textarea names, form actions, and anchor links — CSS only, so it survives a CSP that blocks script but allows styles or a sanitizer that permits style content.

### Redirect and navigation mechanics

- Fetch caps a redirect chain at 20 (`redirect count is 20` → network error) and rejects any `Location` whose scheme is not HTTP(S) — `javascript:`/`data:` in a `Location` header never becomes a navigation.
- Method preservation (MDN Location): `303` always becomes GET; `307`/`308` preserve the method; `301`/`302` should preserve it but older agents may not.
- The full URL (including fragment) is reattached on server redirects, and client-side URL length limits (~2 MB in Chrome) turn an over-long inflated navigation into `about:blank`, which is itself observable.
- Redirect-chain oracles are among the few that work in a top-level window with SameSite=Lax cookies: the chain length, the final origin, and the CSP `connect-src`/`form-action` violation are all readable without a window reference.

### CSP `'self'` and scheme matching (CSP3 quirks)

- Insecure schemes and ports now match their secure variants: the source `http://example.com:80` matches both `http://example.com:80` and `https://example.com:443`, and `'self'` matches the `https:`/`wss:` forms of the page origin *even on an `http:` page* — a policy that looks origin-locked may still admit the secure sibling.
- Hash sources may match external scripts only when the `script` element also carries matching `integrity` metadata; `'report-sample'` adds the first 40 characters of the blocked inline source to the violation.
- `report-uri` is only used when `report-to` is absent (browsers that support `report-to` ignore it); `csp-violation` reports are visible to `ReportingObserver`s while `csp-hash` reports (emitted by `'report-sha256'`/`384`/`512`) are not.

### Trusted Types and Sanitizer config surface

- Trusted Types guards "over 60 different injection sinks" in the `script` sink group (`Element.innerHTML`, `Location.href`, `eval`, `DOMParser.parseFromString`, …) and is exposed on both `Window` and `Worker`. Trusted values can only be produced by named policies, so `createPolicy` is the injected-security-review surface; `isHTML`/`isScript`/`isScriptURL` are the introspection hooks.
- Sanitizer API config is a programmatic object with `allowElement`/`removeElement`/`allowAttribute`/`removeAttribute`/`setComments`/`setDataAttributes`/`removeUnsafe`; global allow- and remove-lists cannot coexist for the same name (invalid config), and `parseHTML`/`parseHTMLUnsafe` build a document with scripting disabled, so script execution there is a non-issue while DOM-XSS on insertion is not.
- CSP reporting (CSP3): `report-uri` is deprecated in favor of `report-to` and is only used when `report-to` is absent. `csp-violation` reports are visible to `ReportingObserver`s while `csp-hash` reports (emitted by `'report-sha256'`/`384`/`512`) are not. Nonces are strict string matches; hash sources accept base64 or base64url and treat them as equivalent.
- Reverse tabnabbing: `window.open(url, target)` defaults `target="_blank"` and, unless `noopener`/`noreferrer` is set, leaves an `opener` reference the opened page can use to navigate the opener (`window.opener.location = …`).

### Oracle selection by sink class

| Sink class | Prerequisite | Cheapest safe oracle |
|---|---|---|
| HTML sink (`innerHTML`, `insertAdjacentHTML`, `document.write`) | attacker HTML reaches the sink | canary token confirmed in target origin, then one benign exec |
| DOM URL sink (`location`, `javascript:`) | attacker controls the value assigned | scheme probe + CSP inline check for `javascript:` navigation |
| postMessage | cross-origin listener, or sender with `targetOrigin:"*"` | structured canary from an attacker-origin frame; log the branch taken |
| Service Worker | registration/update path attacker-influenced | own-path SW, narrowest scope; observe the fetch handler; inventory via registration requests |
| CORS | credentialed read of non-public data | `Origin` reflection + `ACAC:true` + non-public body read |
| XS-Leak | state-dependent cross-origin difference + embed primitive | 10+ samples per state vs a logged-out control |
| CSP gap | an enforced policy is present | parse + report-only probe; name the deciding source expression |
| CSS injection | styles render, script does not | `@import` collaborator proof, then `:has()` + CSS-variable canary on your own session |
| Redirect/navigation | attacker-influenced chain, HTTP(S) targets | error events + `history.length` on a window you own; 20-redirect / inflation probes |
| Storage partition | third-party frame under partitioning | `Permissions.query({name:"storage-access"})` + cookie presence on your own frames |
| Isolation posture | COOP/COEP/CORP present or absent | `self.crossOriginIsolated` + `coop`/`coep` reports to your collector |

## References

- PortSwigger Web Security Academy: XSS, DOM XSS, mXSS, DOM clobbering, postMessage, CORS, CSRF, XS-Leaks, Service Workers [T2 research]
- OWASP Testing Guide: client-side testing, browser storage, cross-origin sections [T1 vendor]
- HTML Standard (WHATWG) and Fetch Standard for parsing, navigation, and CORS normative behavior [T0 standards]
- WHATWG HTML — named access on the Window object (supported property names, ordering, HTMLCollection): https://html.spec.whatwg.org/multipage/window-object.html#named-access-on-the-window-object [T0 standards]
- WHATWG HTML — `window.name` (reset on cross-origin navigation), `WindowProxy`, cross-origin property access: https://html.spec.whatwg.org/multipage/nav-history-apis.html [T0 standards]
- Google / Chromium XS-Leak wiki for leak-class taxonomy and mitigation mapping [T2 research]
- COSI attack class paper (XS-Leak systematization): https://arxiv.org/pdf/1908.02204 [T2 research]
- XS-Leak techniques and COOP defenses: https://safeguard.sh/resources/blog/xs-leaks-explained-and-defenses [T2 research]
- DOM clobbering attack techniques and defenses (ACM CCS 2023): https://dl.acm.org/doi/10.1145/3576915.3616598 [T2 research]
- DOM-based XSS sinks and sources: https://payloadplayground.com/blog/xss-dom-based-exploitation [T2 research]
- XS-Leaks Wiki (oracles, frame-count/error/timing classes, defense mechanisms): https://xsleaks.dev/ [T2 research]
- W3C Fetch Metadata Request Headers (Sec-Fetch-Site/Dest/Mode/User, redirect value shifts, `Vary` guidance, browser support): https://www.w3.org/TR/fetch-metadata/ [T0 standards]
- W3C Content Security Policy Level 3 (`'strict-dynamic'`, `'unsafe-hashes'`, `'wasm-unsafe-eval'`, duplicate-directive and meta-delivery rules): https://www.w3.org/TR/CSP3/ [T0 standards]
- W3C Trusted Types (injection-sink groups, `require-trusted-types-for`, `trusted-types` policy allowlist, DOM XSS sink group): https://www.w3.org/TR/trusted-types/ [T0 standards]
- MDN — `Document: domain` (deprecated; port removal; COOP/Origin-Agent-Cluster no-ops; unaffected storage APIs): https://developer.mozilla.org/en-US/docs/Web/API/Document/domain [T1 vendor]
- MDN — `ServiceWorkerContainer.register()` (default scope, `Service-Worker-Allowed`, `updateViaCache`, `worker-src`/TrustedScriptURL): https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorkerContainer/register [T1 vendor]
- WICG HTML Sanitizer API (setHTML vs setHTMLUnsafe defaults, safe baseline element/attribute lists): https://wicg.github.io/sanitizer-api/ [T1 vendor]
- DOMPurify advisory GHSA-mmhx-hmjr-r674 / CVE-2024-45801 (nesting-based depth-check bypass + prototype pollution; fixed 2.5.4 / 3.1.3): https://github.com/cure53/DOMPurify/security/advisories/GHSA-mmhx-hmjr-r674 [T3 vuln intel]
- DOMPurify advisory GHSA-h8r8-wccr-v5f2 / CVE-2026-3126 (mXSS via re-contextualization in `script`/`xmp`/`iframe`/`noembed`/`noframes`/`noscript` wrappers; 3.3.1 → 3.3.2): https://github.com/cure53/DOMPurify/security/advisories/GHSA-h8r8-wccr-v5f2 [T3 vuln intel]
- DOMPurify advisory GHSA-87xg-pxx2-7hvx / CVE-2026-47423 (`selectedcontent` re-clone; 3.4.4 → 3.4.5; Chromium/WebKit reproduced): https://github.com/cure53/DOMPurify/security/advisories/GHSA-87xg-pxx2-7hvx [T3 vuln intel]
- DOMPurify advisory index (version fingerprint incl. the 2026 hook/`IN_PLACE` cluster): https://github.com/cure53/DOMPurify/security/advisories [T3 vuln intel]
- WHATWG Fetch Standard (`HTTP-redirect fetch`: 20-redirect cap and non-HTTP(S) location failure; CORS protocol headers incl. `Origin`/`null` and case-sensitive `ACAC`): https://fetch.spec.whatwg.org/ [T0 standards]
- MDN — `Content-Security-Policy` header (`unsafe-inline` ignored with nonce/hash, `script-src` fallbacks, worker CSP inheritance, report-sample length, report-uri vs report-to, multi-policy intersection): https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy [T1 vendor]
- MDN — CSP `script-src` (strict-dynamic ignore list, integrity requirement for external hashes, unsafe-hashes, wasm-unsafe-eval): https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src [T1 vendor]
- MDN — CSP `base-uri` (no default-src fallback; absent = any URL): https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/base-uri [T1 vendor]
- MDN — `Set-Cookie` (Lax+POST two-minute grace, `SameSite=None` requires `Secure`, `__Host-`/`__Secure-`/`__Http-` prefixes, `Partitioned` requires `Secure`): https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie [T1 vendor]
- MDN — Cross-Origin-Opener-Policy (four values, BCG matching tables, `noopener-allow-popups`, isolation requirements): https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy [T1 vendor]
- MDN — Cross-Origin-Embedder-Policy (single-token rule, `credentialless`, COEP reports, CORP interaction): https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy [T1 vendor]
- MDN — Cross-Origin-Resource-Policy (`same-site`/`same-origin`/`cross-origin`; `no-cors` loads): https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Resource-Policy [T1 vendor]
- MDN — `Element.setHTMLUnsafe()` (no sanitization by default, declarative shadow roots, TrustedHTML/`TypeError`, invalid config): https://developer.mozilla.org/en-US/docs/Web/API/Element/setHTMLUnsafe [T1 vendor]
- MDN — `Sanitizer` (default config, safe vs unsafe methods, `removeUnsafe`, config validity): https://developer.mozilla.org/en-US/docs/Web/API/Sanitizer [T1 vendor]
- MDN — `Window.postMessage()` (targetOrigin default `/`, `data:`/`file:` need `*`, event.origin/IDN caveats, transferables): https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage [T1 vendor]
- MDN — `Document.requestStorageAccess()` (transient activation, per-origin grants, `storage-access` Permissions Policy, sandbox token, `types` handles): https://developer.mozilla.org/en-US/docs/Web/API/Document/requestStorageAccess [T1 vendor]
- MDN — Partitioned cookies / CHIPS (partition key = top-level site incl. scheme, Secure required, subdomain scope, Firefox state partitioning): https://developer.mozilla.org/en-US/docs/Web/Privacy/Guides/Third-party_cookies/Partitioned_cookies [T1 vendor]
- MDN — `Referrer-Policy` (default `strict-origin-when-cross-origin`; `Origin: null` rules for non-CORS-mode requests): https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy [T1 vendor]
- MDN — `Service-Worker-Allowed` (scope broadening; registration fails without it): https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Service-Worker-Allowed [T1 vendor]
- MDN — Using Service Workers (install/waiting/activate, `skipWaiting`, `clients.claim`, navigation preload): https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API/Using_Service_Workers [T1 vendor]
- MDN — `Location` header (303 → GET; 307/308 preserve method; 301/302 should): https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Location [T1 vendor]
- Chromium — SameSite Updates (Chrome 80 Lax-by-default timeline, Lax+POST 2-minute intervention and testing flags, Chrome 91 flag removal, Android WebView): https://www.chromium.org/updates/same-site/ [T1 vendor]
- web.dev — Make your website "cross-origin isolated" using COOP and COEP (Chrome 87/88/92 milestones, `crossOriginIsolated`, COOP/COEP report shapes, iframe `allow="cross-origin-isolated"`): https://web.dev/articles/coop-coep [T1 vendor]
- web.dev — SameSite cookies explained (Lax/Strict/None semantics, "Incrementally Better Cookies" defaults): https://web.dev/articles/samesite-cookies-explained [T1 vendor]
- chromestatus — Partitioning Storage, Service Workers, and Communication APIs (third-party storage partitioning launched in Chrome 115): https://chromestatus.com/feature/5723617717387264 [T1 vendor]
- annevk/orb — Opaque Response Blocking (CORB++) README (opaque-safelisted/blocklisted/never-sniffed MIME sets, 1024-byte sniffing, JS/JSON parse step; upstreaming into Fetch PR #1442): https://github.com/annevk/orb [T2 research]
- Chromium — Cross-Origin Read Blocking (CORB) explainer (protected types JSON/HTML/XML, exemptions, `nosniff`/206 rules, XSSI prefixes `)]}'`/`{} &&`/`for(;;);`, empty-body substitution): https://chromium.googlesource.com/chromium/src/+/HEAD/services/network/cross_origin_read_blocking_explainer.md [T2 research]
- PortSwigger — Blind CSS Exfiltration (attribute selectors, CSS variables with `none` fallback, `:has()`/`:not()`, `@import` chaining, H2 requirement): https://portswigger.net/research/blind-css-exfiltration [T2 research]
- Akamai — Abusing the Service Workers API (persistence, response modification, XSS persistence, DoS, phishing, sandboxed-domain leakage, scope/MIME caveats, `Service-Worker` header detection): https://www.akamai.com/blog/security/abusing-the-service-workers-api [T2 research]
- xsleaks.dev — Frame Counting: https://xsleaks.dev/docs/attacks/frame-counting/ [T2 research]
- xsleaks.dev — Error Events: https://xsleaks.dev/docs/attacks/error-events/ [T2 research]
- xsleaks.dev — Cache Probing: https://xsleaks.dev/docs/attacks/cache-probing/ [T2 research]
- xsleaks.dev — Navigations (history.length, download detection, 20-redirect cap, inflation, CSP violation redirect oracle, partitioned-cache bypass): https://xsleaks.dev/docs/attacks/navigations/ [T2 research]
- xsleaks.dev — Connection Pool (256 TCP / 6000 UDP sockets, `performance.getEntries()` connection-reuse detection, HPACK/coalescing, defense mapping): https://xsleaks.dev/docs/attacks/timing-attacks/connection-pool/ [T2 research]
- Tier tags: `[T0 standards]` W3C/WHATWG/RFC normative; `[T1 vendor]` official product/API docs; `[T2 research]` published security research; `[T3 vuln intel]` advisories, CVE/GHSA records, and secondary reporting.
