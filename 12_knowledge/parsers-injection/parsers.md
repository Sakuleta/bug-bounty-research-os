# Parser / Injection Research

> SCOPE: Load when attacker-controlled values cross component, encoding, or language boundaries: URLs, Unicode, structured bodies, templates, queries, or serialized objects.

## Research families

- Same bytes, two parsers: framing and syntax decisions that differ between an edge/WAF/validator and the origin/app interpreter (the parser-differential family that contains request smuggling, WAF bypass, and validation bypass).
- URL and hostname canonicalization differentials (including IDN/punycode, label-separator handling, and backslash-vs-slash for special schemes)
- Unicode normalization, control characters, and overlong encodings
- Unicode confusables and mixed-script identifiers (homoglyph allowlist bypass)
- Duplicate JSON keys and parameter precedence; JSON number-precision and key-truncation differentials
- YAML scalar-resolution differentials (1.1 vs 1.2 booleans/null) and duplicate keys
- Signed-token claim parsing (JWT/JWS duplicate Claim Names, claim replication across header/payload)
- Multipart and MIME boundary confusion (malformed framing, quoting, `filename` vs `filename*`)
- HTTP message framing: `Transfer-Encoding` vs `Content-Length`, obs-fold, HTTP/2→HTTP/1 downgrade
- XML parser differentials (XXE, XInclude, SVG-embedded XML, office/feed envelopes)
- Template and expression-language injection (SSTI), per engine and per sandbox
- SQL, ORM-raw, and query-builder injection, including second-order (stored) SQLi
- NoSQL operator injection and server-side JavaScript (`$where`, `$function`, `$accumulator`)
- Prototype pollution with gadget reachability (merge/deep-extend/path-set utilities, query parsers)
- Deserialization across Java, PHP, Python, Ruby, .NET, and Node runtimes (native modules and JSON type-name handlers)
- PHP `phar://` metadata deserialization reached through file-operation functions
- Header, email, and SMTP parser discrepancies (CRLF injection, SMTP end-of-data smuggling)
- Normalization-before-validation versus validation-before-normalization ordering
- Stored-payload routing: upload, filename, or metadata paths that deliver attacker bytes to a backend parser
- Archive extraction traversal (zip slip) and symlink handling on server-side unpacking
- Second-order (stored) SQLi: a value inert on write but concatenated into a raw query on read
- Encoding-layer differentials: decode-count mismatches, base64 intermediate hops, charset/collation confusion (latin1 vs UTF-8) across a boundary
- XML parameter-entity and external-DTD paths for blind/out-of-band XXE, and XInclude file-read/SSRF

## Preconditions

- Two components interpret the same value with different rules (validator vs executor, edge vs origin, parser vs renderer) — the canonical question is whether the difference changes a security decision.
- Attacker bytes survive to a dangerous interpreter: SQL engine, template engine, XML external-entity resolver, deserializer, or shell-adjacent sink.
- For SSTI: template syntax reflected or stored into a server-rendered template, not merely echoed into HTML (that is XSS — see the browser pack). Highest-yield when user input is *concatenated into the template string* rather than passed as data.
- For XXE: XML accepted from the attacker, including SVG uploads, office documents, SOAP/SAML envelopes, and feeds.
- For prototype pollution: recursive merge, deep-extend, or path-set utility fed by attacker JSON, query keys (`__proto__`, `constructor[prototype]`), or postMessage data, plus a gadget reading the polluted property.
- For deserialization: a serialized-object sink (`pickle`, `unserialize`, `BinaryFormatter`, `Marshal`, `node-serialize`, unsafe YAML) reachable with attacker bytes. For PHP the relevant knob is `allowed_classes` (absent = every class may instantiate); for Json.NET it is a non-`None` `TypeNameHandling`.
- For PHP `phar://`: a writable/uploadable file that can be addressed as `phar://…` and any file function called on that path (`file_exists`, `getimagesize`, `file_get_contents`) — the phar manifest metadata is stored in `serialize()` format and deserializes on access.
- For NoSQL: the app passes attacker-supplied operator objects (`$ne`, `$gt`, `$regex`) into a query without type-checking, or server-side JavaScript is enabled so `$where`/`$function` bodies can run.
- For stored routing: a file, filename, archive entry, or metadata field whose bytes are parsed server-side (image library, document converter, archive extractor) after upload validation passes.
- For traversal via archives: an unpacking step that resolves entry names against the filesystem without sanitizing `../` segments or symlinks.
- For CRLF/header injection: a value is copied into an HTTP header, an SMTP message, or a log line without neutralizing `\r\n` (bare `\n` frequently suffices).
- For SMTP smuggling: the message path crosses an *outbound* SMTP server and an *inbound* one that disagree about which newline/dot sequences end `DATA`, and the sender can place `<LF>` bytes inside the body.
- For HTTP framing differentials: the same byte stream is framed by two HTTP implementations (reverse proxy vs origin, h2 edge vs h1 origin); a `Transfer-Encoding`/`Content-Length` conflict, obs-fold, or illegal h2 field value is resolved differently on the two ends.
- For multipart differentials: a WAF/validator parses the `Content-Type` boundary and part headers differently from the application's multipart parser (framing, quotes, charset, duplicate names).
- For JSON interop differentials: two JSON parsers sit in the path (WAF/broker/app, issuer/consumer) and disagree on duplicate keys, key truncation, number precision, or extensions (comments, quoteless strings).
- For signed tokens: verifier and consumer disagree on duplicate Claim Names, or a claim is replicated between JOSE header and payload and only one copy is checked.
- For YAML scalar differentials: one side uses a 1.1-era resolver (`yes`/`on`/`no` → boolean) while the other treats the same scalar as a string (or vice versa), and the value feeds a decision.
- For blind/OOB XXE: the parser resolves an external DTD or parameter entity out-of-band, so no in-response echo is required — a collaborator fetch alone confirms it.
- For second-order SQLi: a stored value (profile field, filename, saved search) is later concatenated into a raw query on a different code path than the write.

## Oracles

- Polyglot SSTI probe (`${{<%[%'"}}%\`) changes engine behavior: arithmetic evaluation (`{{7*7}}` returning 49), error-class change, or timing shift (blind `sleep`) — distinguish engine evaluation from plain reflection.
- SSTI engine fingerprint: `{{7*'7'}}` returns `49` under Twig and `7777777` under Jinja2 — the render result (or the error text, e.g. ERB's `undefined local variable or method`) names the engine before payload selection.
- SQL boolean/time differential: `AND 1=1` vs `AND 1=2` response divergence, or `SLEEP`/`pg_sleep` delay correlated with injection position — median over repeated samples with a benign control.
- XXE confirmation via collaborator DNS/HTTP callback on external-entity or XInclude fetch, or `php://filter` base64 exfiltration of a researcher-planted canary file — never read real secrets; prove the read primitive on a canary path.
- NoSQL operator oracle: changing `{"user":"x","pass":"y"}` to `{"user":"x","pass":{"$ne":null}}` (or `$gt:""`, `$regex`) authenticates without the password — a boolean/behavior differential proves operator injection, distinct from a plain wrong-password response.
- NoSQL blind JS oracle: a `$where`/`$function` body with a `sleep()`/busy-loop or a truthy/falsy condition produces a timing or result-set differential only if server-side JS executes.
- Prototype pollution: `Object.prototype` canary property (`__proto__[bbcanary]`) observable in a fresh object afterward, plus a gadget (template output, admin flag, HTML sink) consuming it.
- Deserialization: class-resolution or magic-bytes sensitivity (reflection change, error oracle, collaborator callback from XXE-in-serialized-XML or gadget chain trigger) without executing destructive chains. Distinguishing tells include an unknown-class error, an autoload attempt (PHP `unserialize_callback_func`), or a `__PHP_Incomplete_Class` object.
- Json.NET type-name oracle: an injected `"$type"` property resolves to an attacker-chosen .NET type when `TypeNameHandling` is not `None`; a binder-rejected or ignored `$type` is the safe behavior.
- Normalization gap: value rejected-or-accepted differently before and after NFC/NFKC, case folding, slash/backslash, or dot-segment normalization (e.g. `..%c0%af` vs `../`) with the post-normalization form reaching the sink.
- IDN/label-separator differential: input using fullwidth/ideographic dots (`U+FF0E`, `U+3002`, `U+FF61`) or deviation characters (`ß`, final sigma, ZWJ/ZWNJ) normalizes to a different ASCII/punycode host than the validator reasoned about.
- Duplicate-key precedence: first-wins vs last-wins differs between validator and executor (`{"role":"user","role":"admin"}`), changing the enforced decision.
- Header/email injection: CRLF or bare-LF bytes in name/email fields produce additional `Bcc:`/`Cc:` delivery or SMTP-command confusion observable in test-mailbox delivery.
- Zip-slip confirmation: archive entry named with `../` segments or a symlink that, on server-side extraction, writes outside the destination — prove with a canary filename in a researcher-owned workspace, never production paths.
- Second-order SQLi oracle: store a benign boolean/error payload that is inert on write, then observe a boolean/time differential on the *read* path that consumes the stored value — the write response proves nothing.
- Decode-count oracle: `%2527` vs `%27` (or a raw `'`) reach the SQL parser differently depending on how many decode passes sit between edge and origin; a charset mismatch (bytes valid in latin1 but invalid UTF-8) can likewise flip which branch executes.
- Blind-XXE oracle: a researcher-hosted external DTD with a parameter entity triggers a collaborator fetch, and a `php://filter`/entity chain leaks a canary file's bytes through DNS/HTTP — no in-band echo needed.
- HTTP framing oracle (CL.TE/TE.CL): with a single researcher-controlled connection, send a request whose body boundary sits at the conflicting length and observe whether the front end waits (timeout) while the origin has already answered (CL.TE) or the front end answers 400 while the origin waits (TE.CL). A duplicate/conflicting header that both ends resolve identically is inert.
- h2→h1 downgrade oracle: an h2 field value containing CR/LF/NUL is *rejected as malformed* by a compliant edge; if it is forwarded and re-emitted as separate header lines downstream, the same bytes decode as header injection at the origin (RFC 9113 §8.2.1).
- SMTP end-of-data oracle: send a message with `<LF>.<LF>` (or `<LF>.<CR><LF>`) inside the body to a target MX from a researcher-controlled sender; a second, spoofed message arriving in a researcher-owned mailbox proves inbound/outbound disagreement. Control: the standard `<CRLF>.<CRLF>`.
- Multipart framing oracle: malform the part boundary or the header/body separator (drop one CR from `CRLFCRLF`, change quoting) so a WAF/validator skips inspection while the app parser still extracts the field/file — the differential is "validator saw nothing / app stored the payload".
- JSON interop oracle: submit the same value as an exact duplicate key, a key with an unrepresentable character (`"test\x0d"`, `"test\ud800"`, `"te\st"`), or an out-of-range number (`1E400`, > 2^53 integer) and observe which value the decision layer actually used vs what the validating layer parsed.
- JWT duplicate-claim oracle: craft `{"role":"user","role":"admin"}` (or duplicate `sub`) in the payload; RFC 7519 requires uniqueness or last-member semantics — a mismatch between what the signature check parses and what the authorization check consumes is the bug.
- YAML scalar oracle: feed `yes`/`no`/`on`/`off` (and `NO`, `0o7`, `0x3A`) where the field is compared to a string or a boolean; behavior flip between a 1.1-era loader (PyYAML) and a 1.2 consumer names the differential.
- Query-parser pollution oracle: `?__proto__[bbcanary]=1` vs `?constructor[prototype][bbcanary]=1` against a filtered endpoint — the second shape survives naive `__proto__` stripping; confirm on a fresh object, not the shared one.

## Minimal safe proof

1. Detect before exploiting: run one polyglot/error-probe per interpreter class and classify (reflected text vs evaluated vs error) before any payload escalation.
2. Time-based confirmation uses short delays (single seconds, few repetitions) with interleaved benign controls; stop if the backend shows load sensitivity.
3. XXE/deserialization proofs use collaborator callbacks and canary files only; never exfiltrate `/etc/passwd`, cloud credentials, or real key material, and never trigger RCE gadget chains against production.
4. SQL probing prefers boolean/error oracles over UNION column enumeration; enumerate only to the minimum (column count) needed to demonstrate injectability.
5. Pollution and template tests run in your own session objects; never pollute shared prototypes or stored templates visible to other users.
6. NoSQL probes change one comparator at a time (a single operator or one `$where` predicate) against a captured valid query; never run an unbounded server-side JS loop on shared infrastructure.
7. Archive-traversal probes use researcher-owned workspaces and canary filenames; never extract toward system paths or overwrite existing files.
8. Framing/smuggling probes stay on one researcher-owned socket: no shared caches, no shared connections, no queued victim request. Demonstrate the disagreement with a self-contained request pair (control vs probe) and stop at the first successful desync proof; never leave a poisoned connection open.
9. SMTP-smuggling proofs use a researcher-owned domain/sender and a researcher-owned recipient mailbox; never spoof a third party. Minimize to the single variant that demonstrates end-of-data disagreement.
10. Stop conditions: backend errors spike, WAF blocks engage, state-changing evaluation occurs (email sent, file written, command executed), or pooled-parser behavior suggests shared-infrastructure impact — halt and report the oracle.
11. Second-order and OOB probes store/write only researcher-planted canaries; never leave payloads visible to other users or trigger background re-parsers on shared queues.

### Detection / fingerprinting order

1. Fingerprint the language and engine from error text, headers (`Server`, `X-Powered-By`), and build artifacts **before** payload selection — engine choice decides the whole payload space.
2. For each boundary, name the pair (validator vs executor) and the exact value that crosses it; a target with only one parser in the path has no differential to exploit.
3. Order probes by cost: reflection/error probe → boolean differential → time differential → collaborator callback; never jump to RCE-shaped payloads first.
4. Version the sink: record the loader/flag in use (`safe_load` vs `load`, `allowed_classes`, `TypeNameHandling`, `--noscripting`) because the default is frequently the safe one.
5. Run store-then-read for second-order bugs: write the benign payload, then trigger the read path and compare against a control.
6. Keep the per-runtime deserialization table handy so a found sink maps to a known gadget family only when the classpath/runtime actually supports it.

## False positives

- Polyglot string reflected verbatim with correct output encoding and no evaluation — inert reflection; require engine evaluation or decision change.
- SQL-like error text from input validation (generic 400/422) without boolean or timing divergence — validator rejection; require the differential.
- XML parsed with external entities disabled (no callback, no canary read) — hardened parser; require the fetch or read primitive.
- XML that triggers a *local* entity-expansion (billion laughs) DoS but no external fetch — resource-exhaustion, not XXE file read; classify separately and only test if DoS is in scope.
- `__proto__` key stored as a plain own-property by a safe parser without prototype effect — require `Object.prototype` contamination plus gadget reachability. (`JSON.parse` creating an own `__proto__` key is expected, not pollution; a literal object/merge utility is where the prototype write happens.)
- Deserializer accepting bytes but resolving to inert types with no gadget path — hardened endpoint; require a decision or callback change.
- PHP `unserialize()` returning `false`/`__PHP_Incomplete_Class` because the class is not autoloadable — no object graph is instantiated; require a real class/magic-method path, not just a parse error.
- YAML using a restricted loader (`safe_load`/`SafeLoader`, Psych ≥ 4 `load`) rejects `!!python/object*` tags — hardened; require the unsafe loader to be the one in use.
- NoSQL `$ne`/`$gt` object rejected by type validation, or server-side JS disabled (`--noscripting`/`security.javascriptEnabled:false`) — hardened; require the operator to reach the query or JS to execute.
- Normalization differences that converge before the security check (both layers normalize identically at decision time) — cosmetic; require the post-check divergence.
- Duplicate JSON keys where both layers agree on precedence — consistent handling; require validator/executor disagreement with decision impact. (RFC 8259 explicitly leaves duplicate-name behavior unpredictable, so "we differ from them" is not by itself a bug — the *decision* must change.)
- Duplicate JWT claims that the verifier rejects or consistently resolves last-per-ECMAScript — RFC 7519 permits either; the bug is a *split* between signature-time and authorization-time parsing.
- YAML `yes`/`on` that stays a string under the YAML 1.2 core/JSON schema — correct behavior, not the Norway problem; require a 1.1-era resolver on the consuming side.
- Uploaded file parsed by a hardened converter that strips active content (no callback, no script execution, metadata dropped) — require the parsing primitive, not the upload alone.
- Archive extractor that rejects `../` entries and symlinks (verified by a blocked canary extraction) — require the out-of-destination write, not the upload acceptance.
- SMTP newline bytes stripped or encoded by the mailer before transmission — neutralized; require actual extra-header delivery to the test mailbox.
- Conflicting `Transfer-Encoding`/`Content-Length` that the edge rejects (400) or normalizes before forwarding, with no observable desync — compliant handling; require a framing divergence between the two ends.
- Malformed multipart that both the WAF and the app reject, or that the app parser also refuses to extract — no differential; require the app to accept what the validator ignored.
- HTTP/2 request with a bare-LF header value getting a 400/stream error — that is the compliant response (RFC 9113 §8.2.1), not a finding; the finding is the edge *forwarding* it.
- A library *string* that contains `eval`/`unserialize` but is never reached with attacker bytes — dead path; require sink reachability in shipped code.
- Second-order candidate whose stored value is safely parameterized on the read path (no differential) — the write-side encoding is irrelevant; require the read-path divergence.

## Version/implementation notes

### Parser differentials — HTTP framing and down-conversion

- RFC 9112 §6.3 precedence: `Transfer-Encoding` overrides `Content-Length`; a message with both "might indicate an attempt to perform request smuggling"; an intermediary that forwards MUST first remove the received `Content-Length`; a request whose `Transfer-Encoding` does not end in `chunked` MUST get 400 + connection close; malformed `Content-Length` is unrecoverable (400; proxy → 502).
- RFC 9112 §6.1: chunked MUST NOT be applied more than once; if any other coding is applied to a request, chunked MUST be the final coding (else no reliable framing). RFC 9112 §5.2: a receiver of obs-fold MUST either 400 the request or replace each obs-fold with one or more SP before interpreting (proxy: 502 or replace) — two ends choosing differently is a desync primitive.
- RFC 9113 §8.2.1 (HTTP/2): a field value MUST NOT contain NUL/LF/CR anywhere and MUST NOT start/end with SP/HTAB; field names forbid colon (except pseudo-headers), uppercase, and 0x00-0x20/0x7f-0xff. Violations MUST be treated as malformed — "failure to validate fields can be exploited for request smuggling attacks" when h2 is converted to h1 downstream.
- RFC 9113 §8.2.2: `Connection`, `Proxy-Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade` are connection-specific and MUST NOT appear in h2; the only exception is `TE`, which may be present only with value `trailers`. An h1→h2 intermediary MUST strip them or its messages are malformed downstream.

### SMTP framing and header parsing

- RFC 5321 §4.1.1.4: mail data ends at `<CRLF>.<CRLF>`; servers "MUST NOT" treat `<LF>.<LF>` as equivalent, and accepting bare LF "has proven to cause more interoperability problems than it solves".
- SMTP smuggling (SEC Consult / Timo Longin, Dec 2023): outbound and inbound servers interpret end-of-data differently, so `<LF>.<LF>` or `<LF>.<CR><LF>` inside the body can terminate the message early on one side and start a new, attacker-controlled message on the other — while still passing SPF alignment because it is sent from the vulnerable outbound host. Microsoft (Outlook/Exchange Online) and GMX issues were fixed; the researchers flagged Cisco Secure Email's default configuration.
- Concrete disagreement example: Outlook rejects `<LF>.<LF>` (`550 5.6.11 SMTPSEND.BareLinefeedsAreIllegal`) but does not filter `<LF>.<CR><LF>`; Outlook's use of `BDAT` blocks some, not all, receiver combinations.
- Postfix: `smtpd_forbid_bare_newline = normalize` (the old `yes` is now an alias) is the default in 3.9+; for 3.8.4/3.7.9/3.6.13/3.5.23 the long-term setting is `smtpd_forbid_bare_newline = yes`. `reject` is stricter (rejects instead of normalizing); `smtpd_forbid_bare_newline_exclusions = $mynetworks` is the compatibility escape hatch.
- RFC 5322 §2.2.3: header folding inserts CRLF before WSP; unfolding removes CRLF only when immediately followed by WSP, and unfolded fields have no length limit. Body CR/LF must appear only as CRLF. A consumer that unfolds differently from the validator (or accepts bare LF) is a header-injection seam.
- CRLF injection (CWE-93) is the shared root cause across HTTP response splitting, SMTP header injection, and log forging: any component that treats CR/LF as a structural separator but fails to neutralize it in input is the sink; the classic mail case is an attacker-controlled name/address adding extra headers.

### Multipart and Content-Disposition

- RFC 2046 §5.1.1: a boundary delimiter line is exactly `--` + boundary value + optional linear whitespace + CRLF; boundary values containing specials (e.g. `:`) must be quoted in the `Content-Type` — unquoted/quoted parsing is a common parser split.
- RFC 7578 §4.1: the boundary MUST NOT appear inside any encapsulated part; §4.2: do not use `filename` blindly and do not use path information; the RFC 5987 `filename*` parameter MUST NOT be used in `multipart/form-data` (note the contrast with RFC 6266 for HTTP `Content-Disposition`); §4.7 `Content-Transfer-Encoding` is deprecated; §5.2 parts with identical field names MUST NOT be coalesced (duplicate names are a precedence seam).
- RFC 6266 §4.3 (HTTP `Content-Disposition`): when both are present, recipients SHOULD pick `filename*` over `filename`; strip path segments using **both** `\` and `/`; a server-provided extension is advisory (`.exe`-style escalation).
- Sicura Next's multipart-parser survey found every tested parser (PHP, Node.js, Python) deviates from the RFC; one concrete bypass class is removing a single `\r` from the `CRLFCRLF` header/body separator so a WAF skips inspection while PHP still parses the part.
- WAFFLED (arXiv 2503.10846): fuzzing parsing discrepancies in `multipart/form-data`, `application/json`, and `application/xml` found 1,207 WAF bypasses across AWS, Azure, Cloud Armor, Cloudflare, and ModSecurity; >90% of tested sites accepted `application/x-www-form-urlencoded` and `multipart/form-data` interchangeably.
- Archive extraction (zip-slip) affects `tar`, `jar`, `war`, `cpio`, `apk`, `rar`, and `7z`, and was especially prevalent in Java where no central high-level archive library enforced path checks; the vulnerable pattern is `new File(destDir, entry.getName())` with no `../` validation (CVE-2018-1002203 unzipper, CVE-2018-1002207 mholt/archiver).

### JSON / JWT / YAML differentials

- JSON carries its own differentials regardless of library: RFC 8259 says names within an object SHOULD be unique, that duplicate-name behavior is unpredictable (many implementations last-wins, some error, some keep all), and that lone/unpaired UTF-16 surrogates make string behavior unpredictable — both are usable validator-vs-executor seams.
- RFC 7519 §4 (JWT): Claim Names within a JWT Claims Set MUST be unique; parsers MUST either reject duplicates or use a parser that returns only the lexically last duplicate member (ECMAScript 5.1 §15.12). §5.3: when claims are replicated as JOSE header parameters, the application SHOULD verify the copies match — a verifier that checks the header copy while authorization reads the payload copy is the split.
- Go `encoding/json`: v1 permits duplicate object names while v2 makes them an error (`jsontext.AllowDuplicateNames` controls it); v1 silently replaces invalid UTF-8 while v2 errors (`jsontext.AllowInvalidUTF8`). One Go upgrade can flip the parser differential without any app code change.
- PostgreSQL: `json` preserves duplicate keys (processing functions consider the last value operative); `jsonb` keeps only the last duplicate. Writing `json`, reading through `jsonb` (or vice versa) is a built-in precedence differential.
- Bishop Fox's JSON interoperability taxonomy: inconsistent duplicate-key precedence; key collision by character truncation/comments (`{"test":1,"test\x0d":2}`, `{"test":1,"test\ud800":2}`, `{"test":1,"te\st":2}` — parsers that truncate the odd character see a duplicate, others see two keys); serialization quirks; float/integer representation (`1E400`, > 2^53); permissive parsing (JSON5/HJSON comments, quoteless strings, trailing commas) leaking into "JSON" parsers.
- YAML 1.2 core schema resolves only `true|True|TRUE|false|False|FALSE` (the JSON schema only lowercase); YAML 1.1 additionally treats `y|Y|yes|Yes|YES|n|N|no|No|NO|on|On|ON|off|Off|OFF` as booleans — the "Norway problem": the country code `NO` becomes `false` on a 1.1-era resolver.
- `yaml.load` is explicitly "as powerful as `pickle.load`" and can call any Python function; `yaml.safe_load` recognizes only standard tags — the loader choice, not the YAML, is the vulnerability.

### Template engines — syntax, sandboxing, and evaluation are engine-specific

- Template syntax is engine-specific (Jinja2 `{{7*7}}`, Twig, Freemarker `${7*7}`, Velocity `#set`, Smarty `{7*7}`, ERB `<%= %>`, Thymeleaf `[[${}]]`, Handlebars prototype paths) — identify the engine from error text or stack behavior before payload selection.
- Ambiguity is the trap: `{{7*'7'}}` yields `49` in Twig but `7777777` in Jinja2, so a single successful evaluation does not identify the engine; treat detection as a decision tree and confirm before escalation.
- Sandbox presence is a first-class fingerprint: Jinja2's `SandboxedEnvironment` raises `SecurityError` on unsafe attribute access (e.g. `func.__code__`), but its own docs say "the sandbox alone is not a solution for perfect security" and warn about CPU/memory exhaustion from small templates — resource limits are part of the control.
- FreeMarker class resolution is configurable: `Configuration.setNewBuiltinClassResolver` accepts `TemplateClassResolver.SAFER_RESOLVER` (blocks `ObjectConstructor`, `Execute`, `JythonRuntime`), `ALLOWS_NOTHING_RESOLVER` (denies all), or `UNRESTRICTED_RESOLVER` (plain `ClassUtil.forName`) — pre-2.3.17 code has no such knob.
- Twig's `{% sandbox %}` tag is deprecated as of Twig 3.15 (use `Twig\Sandbox\Sandbox`); the sandbox extension's security policy decides which tags/filters/methods a template may use.
- Client-side template injection (Angular/Vue/React) belongs to the browser pack; keep server-executed template findings here.

### SQL / NoSQL engines

- Database functions differ per engine (MySQL `SLEEP`/`LOAD_FILE`, Postgres `pg_sleep`/`COPY`, MSSQL `WAITFOR`/`xp_dirtree`, Oracle `UTL_HTTP`) — match probes to the fingerprinted backend.
- Parameterization covers *values*, not identifiers: Django's own docs state querysets are safe because SQL text is defined separately from parameters, and raw queries are safe only when the placeholder is unquoted and passed via `params` ("if you use string interpolation or quote the placeholder, you're at risk"); table/column names and `ORDER BY` targets still need allow-listing by the developer.
- MongoDB server-side JavaScript is version- and configuration-dependent: `$where`/`$function`/`$accumulator` require server-side scripting (default on, `--noscripting`/`security.javascriptEnabled:false` disables it), and MongoDB 6.0 upgraded the JS engine from MozJS-60 to MozJS-91, removing deprecated non-standard array/string helpers that older payloads relied on. Starting in MongoDB 8.0, `$where`/`$function`/`$accumulator` are deprecated and log a warning when used. `$expr` with non-JS operators is preferred and executes no JavaScript.
- MySQL `NO_BACKSLASH_ESCAPES` disables `\` as an escape character inside strings and identifiers (and removes the default LIKE escape) — an app-side escaping layer that assumes backslash-escaping silently loses its defense when this sql_mode is enabled.
- ORM/raw-query surfaces re-enable injection behind "safe" stacks: Prisma `$queryRawUnsafe`/`$executeRawUnsafe` are documented as "at significant risk of making your code vulnerable to SQL injection", while `$queryRaw`/`$executeRaw` are safe only with a simple template tag, no string building, and no concatenation; Prisma also allows only one statement per call, so stacked queries are not part of that surface. Verify per framework: Sequelize `literal`, Django `.raw()`/`.extra()`, SQLAlchemy `text()` — cross-read the frameworks pack.

### Deserialization — one bug class, many runtimes

| Runtime | Sink / flag | Attacker-visible tell | Safe hardening to look for |
|---|---|---|---|
| Java | `ObjectInputStream`/`readObject`; gadget chains (CommonsCollections 3.1/4.0, Spring, Groovy, BeanShell, Jdk7u21) | unknown-class error, collaborator callback from a chain, reflection change | JEP 290 `ObjectInputFilter`/`jdk.serialFilter`; no untrusted `readObject` |
| PHP | `unserialize()` (absent `allowed_classes` = all classes); `__wakeup`/`__unserialize` POP chains; `phar://` metadata | `__PHP_Incomplete_Class`, autoload/`unserialize_callback_func` firing, object injection from a file function | `['allowed_classes' => false]`, `max_depth`, JSON instead; avoid phar on attacker-controlled paths |
| Python | `pickle.load`, `yaml.load`, `Marshal` | arbitrary object/`!!python/object/apply` execution under an unsafe loader | `yaml.safe_load`, no `pickle` of untrusted data |
| .NET | `BinaryFormatter`, Json.NET with `TypeNameHandling != None` (`$type`) | `$type` resolving to a chosen type; `SerializationBinder` rejection; .NET 9 throws on any BinaryFormatter use | `TypeNameHandling.None`, custom binder, no `BinaryFormatter` |
| Ruby | `Marshal.load`, unsafe `YAML.load` | object-graph resolution, magic-method side effects | `YAML.safe_load`; Ruby 3.1 / Psych 4 `load` is safe by default |
| Node | `node-serialize` (CVE-2017-5941), unsafe `eval`-based revivers | a reviver executes a function-valued string; IIFE payload | schema validation before revive |

- `yaml.load` is explicitly "as powerful as `pickle.load`" and can call any Python function; `yaml.safe_load` recognizes only standard tags — the loader choice, not the YAML, is the vulnerability. Python's pickle docs are blunt: "The pickle module is not secure. Only unpickle data you trust... Never unpickle data that could have come from an untrusted source."
- Json.NET's own guidance: `TypeNameHandling` should be used with caution when deserializing from an external source, and incoming types must be validated with a custom `SerializationBinder` whenever it is not `None`.
- Java gadget availability is not itself the bug: the vulnerability is the application performing unsafe deserialization; the classpath only supplies the chain. JEP 290 adds process-wide filtering via the `jdk.serialFilter` system property (which supersedes the `conf/security/java.security` value) and per-stream filtering via `ObjectInputStream.setObjectInputFilter`; patterns are `;`-separated class/package names or limits `maxdepth`, `maxrefs`, `maxbytes`, `maxarray`, and a rejection returns `Status.REJECTED`.
- PHP `unserialize()` has no object-safety by default: `max_depth` (default 4096) only caps nesting, and absent `allowed_classes` it will attempt to instantiate **any** class — so the only durable control is an allowlist or not calling `unserialize()` on input at all (prefer JSON). The Phar manifest stores "Serialized Phar Meta-data, stored in `serialize()` format", so a file function applied to a `phar://` path deserializes attacker-chosen metadata — the same POP-chain exposure reachable from `file_exists()`/`getimagesize()`.
- .NET: Microsoft states `BinaryFormatter` is "insecure and can't be made secure"; starting in .NET 9 the in-box implementation throws exceptions on use even with the settings that previously enabled it, and those settings are removed.
- Ruby: Psych 4.0 (Ruby 3.1) changed `Psych.load` to use `safe_load` by default — older code that relied on `YAML.load` instantiating arbitrary objects loses that behavior on upgrade, and code pinned to older Ruby keeps it.
- Node: `node-serialize` 0.0.4 (CVE-2017-5941) executes an IIFE when untrusted data reaches `unserialize()`.
- The loader choice is the whole mitigation for YAML/Python too: `safe_load` "recognizes only standard YAML tags and cannot construct an arbitrary Python object," while `yaml.load` is documented as powerful as `pickle.load`.

### Prototype pollution — utility and runtime controls

- Node's runtime guard: `--disable-proto=delete` removes `Object.prototype.__proto__` entirely; `--disable-proto=throw` throws `ERR_PROTO_ACCESS` on access (added v13.12.0/v12.17.0). Presence of this flag is strong evidence of a hardened deployment; its absence proves nothing.
- Pollution is a parser-utility bug, not just a language quirk: `lodash.defaultsDeep` before 4.17.12 allowed `{constructor:{prototype:{…}}}` to modify `Object.prototype` (CVE-2019-10744); the sibling packages had their own fixed versions (`lodash-amd` 4.17.13, `lodash-es` 4.17.14, `lodash.defaultsdeep` 4.6.1). Fingerprint the utility version, not the app.
- `__proto__` is only one route: `constructor.prototype` survives filters that strip the literal string `__proto__`, and query-string parsers that build nested objects (`a[b][c]=…`) can reach the same gadget without JSON at all.

### XXE — parser defaults dominate

- Modern defaults are usually safe, so verify rather than assume: libxml2 ≥ 2.9 disables XXE by default; PHP ≥ 8.0 prevents XXE with the default (libxml2-based) parser; .NET `XDocument`/`XmlDocument`/`XmlTextReader`/`XPathNavigator` are safe at framework ≥ 4.5.2 (and ASP.NET must set `<httpRuntime targetFramework="4.5.2+"/>`).
- Java parsers are the common exception — most enable DTD/external entities by default. Harden with `disallow-doctype-decl`, disable `external-general-entities`/`external-parameter-entities`, `nonvalidating/load-external-dtd`, set `XMLConstants.ACCESS_EXTERNAL_DTD`/`ACCESS_EXTERNAL_SCHEMA` to `""`, and disable XInclude (`setXIncludeAware(false)`).
- `java.beans.XMLDecoder` is fundamentally unsafe: it is both an XXE sink and an arbitrary-object-construction primitive with no safe configuration — flag any use outright.
- Distinct impact classes to separate: blind XXE (external DTD / out-of-band), XInclude-based file read, billion-laughs (expansion DoS), and SSRF via an external entity reference.
- OWASP's strongest single rule: disable DTDs entirely — per OWASP this also removes the Billion Laughs DoS class. XInclude is a *separate* switch from entity handling: W3C XInclude `parse="text"` includes the `href` resource as text (with an `encoding` attribute for the included text), so a processor with XInclude enabled can read `file://` and fetch `http://` targets even when entities are disabled.

### Normalization, IDN, confusables, and CRLF

- Unicode normalization matters before a security decision: UAX #15 defines NFC as canonical decomposition followed by canonical composition, and NFKC as compatibility decomposition followed by canonical composition — NFKC folds compatibility variants (halfwidth/fullwidth katakana, Roman numerals and their letter equivalents, ligatures) that NFC keeps distinct, so "normalize then compare" and "compare then normalize" disagree on a whole class of inputs.
- IDNA processing requires the label be in **NFC**, and fullwidth/ideographic dots (`U+FF0E`, `U+3002`, `U+FF61`) all map to `.` — so `a。b` and `a.b` can normalize to the same host, or differently between a strict validator and a lenient executor.
- IDNA2003 vs IDNA2008 divergence is a live parser differential: the deviation characters `ß` and final sigma `ς` (and ZWJ/ZWNJ) resolve to different punycode under the two schemes (e.g. `faß.de` → `fass.de` vs `xn--fa-hia.de`); the industry has moved to nontransitional (IDNA2008) processing, so map which side of a boundary uses which.
- Confusables are the visual sibling of normalization: UTS #39 defines single-script, mixed-script, and whole-script confusable detection functions — an allowlist that only checks ASCII/length/charset can be satisfied by a homoglyph identifier that a human reviewer reads as the trusted name.
- WHATWG URL parsing has its own differentials: a URL with a special scheme (http/https/ws/wss/ftp/file) that contains `\` instead of `/` is reported as `invalid-reverse-solidus`, and the parser has named failure classes (`invalid-credentials`, `host-missing`, `port-out-of-range`) — two URL parsers (browser vs backend, validator vs fetcher) disagree on which of these are fatal.
- YAML and pickle sinks are language-version sensitive (`yaml.load` vs `safe_load`, Ruby `YAML.load` behavior); framework ORM raw-query surfaces need per-framework verification — cross-read the frameworks pack.
- Path-traversal defenses vary (canonicalize-then-check vs check-then-canonicalize, symlink resolution timing) — map the order per endpoint before selecting bypass shapes.
- CRLF injection (CWE-93) spans HTTP response splitting, SMTP header injection, and log forging (see the SMTP section above for the mail-specific framing rules).

### XXE control matrix — what a missing setting buys an attacker

| Missing control | Resulting capability |
|---|---|
| DOCTYPE not disabled | classic in-band XXE (entity expansion reaches the response) |
| External entities enabled | SSRF, file exfiltration, internal port scanning |
| External DTD loading allowed | blind XXE / hidden SSRF (no in-band echo needed) |
| Parameter entities not disabled | advanced/OOB payloads via `%entity;` survive simple mitigations |
| No entity-expansion limit | Billion Laughs / memory-exhaustion DoS |
| XInclude enabled | local file disclosure (`file://`) and SSRF |
| Secure Processing disabled | resource/network protections bypassed |
| Schema validation fetches external URLs | silent outbound requests during validation |

- Minimal hardening to check for: disable DOCTYPE, external entities, external DTD loading; enable Secure Processing; disable XInclude; limit entity expansion; avoid legacy parsers; never parse untrusted XML with defaults.
- Split the finding by class — standard in-band XXE vs blind/OOB XXE (external DTD + parameter entity) vs XInclude file read vs Billion Laughs DoS — because each needs a different oracle and a different partner triage note.

### Normalization / decoding decision table

| Boundary | Rule / behavior | Differential to test |
|---|---|---|
| IDNA label | must be NFC; `U+FF0E`/`U+3002`/`U+FF61` map to `.` | `a。b` vs `a.b` resolving to the same or different host |
| IDNA deviation chars | `ß`, `ς`, ZWJ/ZWNJ differ IDNA2003 vs IDNA2008 | `faß.de` → `fass.de` vs `xn--fa-hia.de` |
| Unicode normalization | NFC vs NFKC differ on compatibility chars | halfwidth/fullwidth, ligatures, Roman numerals |
| WHATWG URL | special scheme + `\` = `invalid-reverse-solidus` | `http://host\path` across validator vs fetcher |
| URL decoding | per-hop, count-dependent | `%2527` vs `%27` reaching the parser |
| Charset/collation | latin1-valid bytes may be invalid UTF-8 | which branch executes per encoding |
| JSON object names | duplicate keys: unpredictable (often last-wins); Go v1 allows / v2 errors | validator vs executor precedence; key truncation (`\x0d`, `\ud800`) |
| YAML scalars | 1.1 `yes/on/NO` = bool; 1.2 core = only true/false | value type flip across loader generations |
| JWT claims | names MUST be unique or lexically-last | signature-time vs authorization-time split |
| YAML/PHP/Java type tags | loader/`allowed_classes`/filter decides | whether an object is instantiated at all |

### Oracle selection by boundary

| Boundary | Prerequisite | Cheapest safe oracle |
|---|---|---|
| SSTI | input concatenated into a template string | polyglot/`{{7*7}}` evaluation after engine fingerprint |
| SQLi (in-band) | input reaches a query string/ORM raw call | boolean differential (`1=1` vs `1=2`) first, timing second |
| SQLi (second-order) | stored value reused on a read path | store benign payload, diff the read path |
| XXE | XML from the attacker | collaborator callback or canary-file read |
| NoSQL | operator object or server-side JS enabled | `$ne`/`$gt` differential; JS timing only if enabled |
| Prototype pollution | recursive merge utility + a gadget | `Object.prototype` canary in a fresh object |
| Deserialization | serialized-object sink | class-resolution/error + callback, no RCE chain |
| HTTP framing | two HTTP parsers in the path | CL.TE/TE.CL timing pair on one researcher socket |
| SMTP end-of-data | outbound + inbound SMTP disagree | `<LF>.<LF>` variant delivered to a researcher mailbox |
| Multipart | WAF/validator + app parser | malformed framing that the app still extracts |
| JSON interop | two JSON parsers in the path | duplicate/truncated key with divergent decisions |
| JWT duplicate claim | verifier + consumer parse separately | `{"role":"user","role":"admin"}` split |
| Zip slip | server-side extraction | canary file written outside the destination |
| CRLF | value into a header, mail, or log | extra header delivered to the test mailbox |

## References

- PortSwigger Web Security Academy: SQL injection, SSTI, XXE, prototype pollution, deserialization [T2 research]
- PortSwigger Web Security Academy — server-side template injection (detection, engine identification, `{{7*'7'}}` Twig/Jinja2 divergence): https://portswigger.net/web-security/server-side-template-injection [T2 research]
- PortSwigger Web Security Academy — request smuggling (framing attacks, TE/CL): https://portswigger.net/web-security/request-smuggling [T2 research]
- XXE via file-upload lab: https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload ; XXE reference: https://hacktricks.wiki/en/pentesting-web/xxe-xee-xml-external-entity.html [T2 research]
- Upload and XXE payloads (PayloadsAllTheThings): https://swisskyrepo.github.io/PayloadsAllTheThings/Upload%20Insecure%20Files/ and https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md [T2 research]
- OWASP Testing Guide: injection testing chapters for SQL, NoSQL, XML, and template injection [T1 vendor]
- OWASP XML External Entity Prevention Cheat Sheet (libxml2 ≥2.9 default, PHP ≥8.0 default, .NET 4.5.2 defaults, Java DTD features, XInclude, `java.beans.XMLDecoder`, DTD-off removes Billion Laughs): https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html [T1 vendor]
- RFC 8259, JSON (duplicate names unpredictable/last-wins, lone surrogates, UTF-8 requirement, `eval` risk): https://www.rfc-editor.org/rfc/rfc8259 [T0 standards]
- PyYAML documentation (`yaml.load` as powerful as `pickle.load`; `safe_load`/`SafeLoader`; `!!python/object*` tags): https://pyyaml.org/wiki/PyYAMLDocumentation [T1 vendor]
- MongoDB `$function` aggregation operator (server-side JS enablement/disable, MozJS-60→91 in 6.0, deprecation in 8.0, `$expr` preference): https://www.mongodb.com/docs/manual/reference/operator/aggregation/function/ [T1 vendor]
- MongoDB `$where` query operator (JS expression; `--noscripting`/`security.javascriptEnabled` control): https://www.mongodb.com/docs/manual/reference/operator/query/where/ [T1 vendor]
- lodash prototype pollution advisory GHSA-jf85-cpcp-j695 / CVE-2019-10744 (`defaultsDeep`, fixed 4.17.12 and sibling versions): https://github.com/advisories/GHSA-jf85-cpcp-j695 [T3 vuln intel]
- Snyk — Zip Slip (tar/jar/war/cpio/apk/rar/7z; vulnerable `new File(dest, entry.getName())`; CVE-2018-1002203/1002207): https://security.snyk.io/research/zip-slip-vulnerability [T2 research]
- ysoserial — Java deserialization gadget chains and the "vulnerability is in the app, not the classpath" note: https://github.com/frohoff/ysoserial [T1 tool]
- PHP `unserialize()` manual (`allowed_classes`, `max_depth` default 4096, `__wakeup`/`__unserialize`, `__PHP_Incomplete_Class`): https://www.php.net/manual/en/function.unserialize.php [T1 vendor]
- PHP manual — Phar file format ("Serialized Phar Meta-data, stored in `serialize()` format"): https://www.php.net/manual/en/phar.fileformat.phar.php [T1 vendor]
- Json.NET `TypeNameHandling` enumeration (`None`/`Objects`/`Arrays`/`All`/`Auto`; caution + `SerializationBinder` guidance): https://www.newtonsoft.com/json/help/html/T_Newtonsoft_Json_TypeNameHandling.htm [T1 vendor]
- CWE-93, Improper Neutralization of CRLF Sequences (HTTP response splitting, SMTP header injection, log forging; CVE-2002-1771 mail-header injection): https://cwe.mitre.org/data/definitions/93.html [T1 vendor]
- UTS #46, Unicode IDNA Compatibility Processing (NFC validity, U+FF0E/U+3002/U+FF61 label separators, ß/ς deviation characters, IDNA2003↔IDNA2008 divergence): https://www.unicode.org/reports/tr46/ [T0 standards]
- UAX #15, Unicode Normalization Forms (NFC = canonical decomposition + canonical composition; NFKC adds compatibility folding of halfwidth/fullwidth, Roman numerals, ligatures): https://www.unicode.org/reports/tr15/ [T0 standards]
- UTS #39, Unicode Security Mechanisms (single-script, mixed-script, and whole-script confusable detection): https://www.unicode.org/reports/tr39/ [T0 standards]
- WHATWG URL Standard (`invalid-reverse-solidus` for special schemes using `\`, `invalid-credentials`, `host-missing`, `port-out-of-range`): https://url.spec.whatwg.org/ [T0 standards]
- YAML 1.2.2 Specification (core schema `true|True|TRUE|false|False|FALSE`; JSON schema lowercase-only): https://yaml.org/spec/1.2.2/ [T0 standards]
- YAML 1.1 bool type (`y|yes|n|no|on|off|true|false` variants): https://yaml.org/type/bool.html [T0 standards]
- RFC 9112, HTTP/1.1 (TE overrides CL and signals smuggling, intermediary MUST strip CL, non-final chunked → 400, obs-fold 400-or-SP): https://www.rfc-editor.org/rfc/rfc9112 [T0 standards]
- RFC 9113, HTTP/2 (field validity: no NUL/LF/CR in values, no uppercase/colon in names; connection-specific headers forbidden; TE only `trailers`): https://www.rfc-editor.org/rfc/rfc9113 [T0 standards]
- RFC 2046, MIME Part Two (§5.1.1 boundary delimiter line syntax, optional LWSP, quoting requirement): https://www.rfc-editor.org/rfc/rfc2046 [T0 standards]
- RFC 7578, multipart/form-data (§4.1 boundary MUST NOT appear in parts; §4.2 filename path handling, RFC 5987 `filename*` MUST NOT be used; §5.2 duplicate names MUST NOT be coalesced): https://www.rfc-editor.org/rfc/rfc7578 [T0 standards]
- RFC 6266, Content-Disposition in HTTP (§4.3 prefer `filename*`, strip `\` and `/` path segments, extensions advisory): https://www.rfc-editor.org/rfc/rfc6266 [T0 standards]
- RFC 5321, SMTP (§4.1.1.4 end-of-data `<CRLF>.<CRLF>`; `<LF>.<LF>` MUST NOT be accepted): https://www.rfc-editor.org/rfc/rfc5321 [T0 standards]
- RFC 5322, Internet Message Format (§2.2.3 folding/unfolding; body CR/LF only as CRLF): https://www.rfc-editor.org/rfc/rfc5322 [T0 standards]
- RFC 7519, JWT (§4 duplicate Claim Names MUST be unique or lexically-last; §5.3 replicated claims SHOULD be verified; §7.3 string comparison rules): https://www.rfc-editor.org/rfc/rfc7519 [T0 standards]
- W3C XInclude (1.0) — `parse="text"` inclusion and `encoding` attribute: https://www.w3.org/TR/xinclude/ [T0 standards]
- SEC Consult — SMTP Smuggling: Spoofing E-Mails Worldwide (outbound/inbound end-of-data disagreement; Microsoft/GMX fixes; Cisco default config; Outlook `<LF>.<CR><LF>` behavior): https://sec-consult.com/blog/detail/smtp-smuggling-spoofing-e-mails-worldwide/ [T2 research]
- Postfix — SMTP smuggling mitigations (`smtpd_forbid_bare_newline = normalize|reject`, aliases, version matrix, exclusions): https://www.postfix.org/smtp-smuggling.html [T1 vendor]
- Bishop Fox — JSON Interoperability Vulnerabilities (duplicate-key precedence, truncation/comments key collisions, float/integer representation, permissive parsing): https://bishopfox.com/blog/json-interoperability-vulnerabilities [T2 research]
- Sicura Next — Breaking Down Multipart Parsers (parser/RFC deviations; WAF-vs-PHP framing bypass): https://blog.sicuranext.com/breaking-down-multipart-parsers-validation-bypass/ [T2 research]
- WAFFLED: Exploiting Parsing Discrepancies to Bypass WAFs (1,207 bypasses across AWS/Azure/Cloud Armor/Cloudflare/ModSecurity; content-type interchangeability): https://arxiv.org/html/2503.10846v4 [T2 research]
- Go `encoding/json` (v1 duplicate names permitted vs v2 error with `jsontext.AllowDuplicateNames`; invalid UTF-8 handling with `AllowInvalidUTF8`): https://pkg.go.dev/encoding/json [T1 vendor]
- PostgreSQL JSON types (`json` keeps duplicate keys, processing functions use the last; `jsonb` keeps only the last): https://www.postgresql.org/docs/current/datatype-json.html [T1 vendor]
- MySQL `sql_mode` — `NO_BACKSLASH_ESCAPES` (backslash stops being an escape in strings/identifiers; LIKE escape changes): https://dev.mysql.com/doc/refman/8.4/en/sql-mode.html [T1 vendor]
- Django security docs (querysets are parameterized; raw SQL requires `params` and unquoted placeholders): https://docs.djangoproject.com/en/5.2/topics/security/ ; raw queries warning: https://docs.djangoproject.com/en/5.2/topics/db/sql/ [T1 vendor]
- Prisma raw queries (`$queryRawUnsafe`/`$executeRawUnsafe` risk; tagged-template caveats; one statement per call): https://www.prisma.io/docs/orm/prisma-client/using-raw-sql/raw-queries [T1 vendor]
- Jinja2 sandbox (`SecurityError`, "the sandbox alone is not a solution for perfect security", resource-exhaustion warning): https://jinja.palletsprojects.com/en/stable/sandbox/ [T1 vendor]
- FreeMarker `TemplateClassResolver` (`SAFER_RESOLVER` blocks ObjectConstructor/Execute/JythonRuntime; `ALLOWS_NOTHING_RESOLVER`; `setNewBuiltinClassResolver`): https://freemarker.apache.org/docs/api/freemarker/core/TemplateClassResolver.html [T1 vendor]
- Twig sandbox tag (deprecated as of 3.15; `Twig\Sandbox\Sandbox`): https://twig.symfony.com/doc/3.x/tags/sandbox.html [T1 vendor]
- JEP 290, Filter Incoming Serialization Data (`jdk.serialFilter`, `ObjectInputFilter`, per-stream filter, `maxdepth`/`maxrefs`/`maxbytes`/`maxarray`): https://openjdk.org/jeps/290 [T1 vendor]
- Python `pickle` documentation ("not secure", arbitrary code during unpickling, prefer JSON): https://docs.python.org/3/library/pickle.html [T1 vendor]
- Microsoft — BinaryFormatter security guide ("insecure and can't be made secure"; .NET 9 throws on use, enabling settings removed): https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide [T1 vendor]
- Ruby 3.1 release notes (Psych 4.0: `Psych.load` uses `safe_load` by default): https://www.ruby-lang.org/en/news/2021/12/25/ruby-3-1-0-released/ [T1 vendor]
- NVD CVE-2017-5941 (node-serialize 0.0.4: untrusted data into `unserialize()` executes an IIFE): https://nvd.nist.gov/vuln/detail/CVE-2017-5941 [T3 vuln intel]
- Node.js CLI docs — `--disable-proto=mode` (`delete` removes `Object.prototype.__proto__`; `throw` yields `ERR_PROTO_ACCESS`; added v13.12.0/v12.17.0): https://nodejs.org/api/cli.html#--disable-protomode [T1 vendor]
- Engine and database vendor documentation for the fingerprinted stack (template syntax, function availability) [T1 vendor]
- Tier tags: `[T0 standards]` W3C/WHATWG/RFC/Unicode; `[T1 vendor]` official product/API docs and tool docs; `[T2 research]` published security research; `[T3 vuln intel]` advisories and CVE/GHSA records.
