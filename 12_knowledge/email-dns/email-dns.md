# Email / DNS / Identity Infrastructure

> SCOPE: Load when account recovery, email ingestion, DNS ownership, mailbox-identity handling, or certificate and hostname signals are the research surface, and program scope permits infrastructure observations.

## Research families

- SPF, DKIM, and DMARC posture and alignment gaps enabling spoofing context
- SMTP smuggling and line-ending differentials between hops
- Email header injection beyond simple line breaks (copy fields, MIME, boundaries)
- Mail template and variable injection rendering into webmail or ticket UI
- Inbound email parsing (support, ticket, webhook ingestion) as injection entry
- Unsubscribe, notification, and bombing primitives (token, enumeration, rate)
- DNS rebinding where an internal or same-origin trust decision is reachable
- Subdomain ownership and dangling-record takeover validation
- Zone-transfer, CAA, and DNSSEC posture as supporting context
- CDN and origin exposure via DNS, certificate, header, and error signals
- Transport-security policy for mail (MTA-STS, TLS-RPT, DANE) as its own downgrade surface
- ARC chain manipulation / replay where an intermediary rewrites mail
- DMARC policy-discovery manipulation (records planted at a delegated subdomain or PSD)
- Provider local-part alias differentials (dots, plus tags, hyphen aliases, case) as account-identity seams
- Password-reset and magic-link delivery, rewriting, and scanner consumption per mailbox provider
- Dangling DKIM selectors, dangling/poisoned SPF includes, and dangling MX/NS records that re-point mail authentication at attacker-controlled infrastructure

### Mail-auth record map (what each record actually controls)

| Record | Name | Controls | Productive differential |
|---|---|---|---|
| SPF | `example.com TXT "v=spf1 ..."` | path authorization of MAIL FROM/HELO | `-all` vs `~all` vs missing `all` |
| DKIM | `<sel>._domainkey.example.com TXT` | signature validity for `d=` | selector reachable/parkable, key length/alg |
| DMARC | `_dmarc.example.com TXT` | alignment + disposition + reporting | `p`/`sp`/`np`, `adkim`/`aspf` strict vs relaxed |
| MTA-STS | `_mta-sts.example.com TXT` | HTTPS policy discovery + version | `mode` enforce/testing/none, `id` |
| CAA | `example.com CAA` | which CAs may issue certs | `issue` vs `issuewild` precedence |
| DNSSEC | `example.com RRSIG`/`DS` | authenticated denial/records | signed-empty vs bogus, zone-cut delegation |

## Preconditions

- Program scope explicitly decides whether DNS, email, or infrastructure findings are reportable; confirm before testing.
- Researcher-controlled mailbox, domain, and (for takeover) claimant account available; never use victim addresses.
- Fingerprinted mail and DNS posture (TXT records, nameservers, CDN edge headers) before hypothesis selection.
- For inbound parsing: an engagement-visible ingestion address (support, ticket, webhook) and researcher-sent messages only.
- For rebinding: a plausible internal or same-origin trust decision reachable through the browser or SSRF sink, tested at low rate.
- For takeover: a dangling DNS record pointing at an unclaimed external service, verified read-only before any claim attempt.
- For SMTP-smuggling claims: an *authenticated* sending position at service A (your own account) and a destination B whose behavior you can observe on a researcher mailbox — never craft against a third party's mailbox.
- For DMARC/SPF posture claims: the security-relevant flow (recovery, notification, billing) identified first, not just bulk marketing mail.
- For local-part differentials: a researcher-owned mailbox at the target provider (or a provider with the same dialect) plus control of every spelling tested; never probe another person's mailbox.
- For reset/magic-link claims: a researcher-owned app account and the researcher inbox that receives the message; capture the delivered payload before comparing generated vs delivered link.
- For selector/include takeover: read-only resolution first, then a researcher-controlled registration or record only where program scope and the service's terms permit benign proof.

### Fingerprinting checklist

1. Enumerate `_dmarc`, `spf`, DKIM selectors (common + product-specific), `_mta-sts`, CAA, DNSKEY/DS, nameservers, and MX with TTLs recorded.
2. Confirm whether the domain is a PSD / where the Organizational Domain sits (`psd` tag, `publicsuffix` semantics under DMARCbis).
3. Identify the receiving stack by `Authentication-Results` / `Received` header dialect; the receiver governs enforcement.
4. Identify the origin/CDN by edge headers, cert issuer, and historical DNS; mark one signal as a lead until a second confirms it.
5. For inbound-parse hypotheses: fingerprint the ticket/helpdesk product and version from UI, email templates, and headers.
6. Resolve alias-equivalent spellings of your own researcher address at the target provider, then record which variants the app accepts, stores, or normalizes.
7. Check whether inbound links are rewritten (Safe Links, ESP click tracking) or prefetched (Mail Privacy Protection) before treating any delivered-link observation as ground truth.
8. Note whether the zone is NSEC- or NSEC3-signed (and whether opt-out is in use) before using enumeration results.

## Oracles

- Authentication-result gap: missing, permissive, or non-enforcing SPF, DKIM, or DMARC records combined with an accepted spoof-shaped test to the researcher mailbox.
- Header-injection reflection: researcher-supplied copy, reply-to, content-type, or boundary value persists as a structured header in the delivered researcher message.
- Template-execution signal: benign arithmetic or identifier probe in a profile field renders evaluated (not literal) inside the researcher-delivered email or ticket view.
- Inbound-execution signal: crafted researcher email produces script-shaped or template-shaped rendering in the ticket or web UI visible to the researcher session only.
- Rebinding confirmation: short-TTL researcher domain resolves first to a public IP then to a loopback or internal value from the test vantage point, with Host-validation behavior recorded.
- Takeover confirmation: dangling record plus successful researcher-account claim of the referenced resource, or vendor-documented claimable fingerprint without destructive claim.
- Zone-transfer disclosure: single AXFR or IXFR query returns full zone contents from an authorized nameserver target.
- Origin disclosure: error, header, certificate, or historical-DNS signal converges on one consistent origin IP or hostname across two independent signals.

### SMTP-transport oracles
- END-OF-DATA differential: service A accepts a non-standard end-of-DATA (`<LF>.<LF>` or `<LF>.<CR><LF>`) and forwards it verbatim, while service B treats it as a real end-of-DATA — observed as two messages delivered from one send.
- Smuggled-message oracle: the injected `MAIL FROM`/`RCPT`/`DATA` produces a second message in the researcher mailbox whose `Received` chain does not match the send; the injected `From:` need not align.
- SPF/DMARC-pass oracle: the smuggled message passes SPF at B because its `MAIL FROM` belongs to A and it arrives from A's IP — pass, not fail, is the interesting signal.
- Pipelining/BDAT oracle: unauthorized command pipelining or `BDAT` (CHUNKING) acceptance is the enabling condition and is itself a finding worth recording.
- BDAT desync oracle: a chunk size larger than the bytes actually sent makes the receiver read the next command as message data; a size smaller than the bytes sent makes the tail parse as commands (RFC 3030) — observable as spurious `500`/`503` replies or a delivered second message.

### Mail-auth / DNS oracles
- Alignment differential: strict vs relaxed `adkim`/`aspf` decides whether a subdomain signature/path passes — perturb the `d=`/MAIL FROM between the two modes and record which flows flip.
- DMARC policy-discovery oracle: a record at a delegated subdomain or PSD node is selected (or ignored) in a way the operator did not intend — the DNS Tree Walk result is the oracle.
- MTA-STS downgrade oracle: `mode: testing`/absence of a live policy lets a STARTTLS-stripped connection deliver, where `mode: enforce` refuses; `id` mismatch is the "stale cached policy" signal.
- CAA gap oracle: an `issue`-restricted domain still receives a cert from a non-authorized CA because the relevant RRset was suppressed or tree-climbed past (wildcard/`issuewild` precedence).
- ARC oracle: an added/removed ARC set changes the receiver's disposition (`arc=pass` vs `arc=fail`); the `cv` value and `oldest-pass` are the observables.
- Dangling-include oracle: an SPF `include:` (or `a:`/`mx:`/`redirect=`) target is NXDOMAIN, expired, or squatted; when the researcher's replacement publishes `v=spf1 +all` (or any matching mechanism), the victim's SPF evaluates `pass` for the researcher's sending IP. Verify with the receiver's `Authentication-Results`, not by re-reading the record.
- Selector-reclaim oracle: `d=`/`s=` resolve to an absent, empty, or parkable `_domainkey` record; a researcher-published replacement key verifies a researcher-signed test signature for that pair. Verify offline with a DKIM verifier — never send forged third-party mail. Under relaxed DMARC alignment the same signature can carry a `From:` at the parent domain.
- Duplicate-policy oracle: more than one DMARC policy record at the same target causes evaluation to discard all of them (RFC 9989), so a receiver treats a domain with published records as having none.
- Poisoned-include oracle: the researcher's SPF tree contains the researcher's mail IPs as a nested include, so the victim domain's mail that transits the researcher's infrastructure returns `spf=pass` at the receiver.

### Header / template / inbound-parse oracles
- Copy-field reflection: a value supplied in `Reply-To`, `Content-Type`, `Boundary`, or a custom `X-` field persists as its own structured header in the delivered researcher message (distinguishes a real header injection from body text).
- Envelope/header divergence: the `Return-Path`/`Envelope-From` and the displayed `From:` differ in a way the receiving app trusts — the app resolving the identity from the wrong one is the bug.
- CRLF/encoding-boundary survival: the injected content survives encoding, quoted-printable, or a MIME multipart boundary rather than being normalized away — that survival is the oracle.
- Template-eval signal: benign arithmetic (`{{7*7}}`, `${7*7}`) renders evaluated in the *delivered* message or the ticket view, not literal.
- Inbound-parse action signal: a crafted attachment filename, MIME boundary, or `mailto:` in the body triggers an action (ticket creation, link unfurl, external fetch) that a benign message does not.
- Markup-render signal: HTML/script-shaped content from the inbound mail renders in the ticket/agent UI only for the researcher session (a self-XSS-shaped probe is not a finding without cross-user rendering).

### Local-part / identity oracles
- Alias-equivalence oracle: the same action for `r@`, `r+tag@`, `r.tag@` (provider-dependent) yields two accounts, two rows, or two reset artifacts — the app treats one mailbox as two identities.
- Normalization-asymmetry oracle: registration normalizes (strips `+tag`, dots, or case) while login or reset matches the raw string, or vice versa — observable as the address stored differing from the address that receives mail.
- Enumeration oracle: `forgot-password` for a plus/dot variant returns "sent" while an unknown base address returns "no such user", or the timing of the two differs keyed by mailbox existence.
- Case differential oracle: SMTP requires local-part case to be preserved, but most providers are case-insensitive (see version notes) — an app that changes case between register and reset is the seam.
- EAI/IDN oracle: a non-ASCII local-part or a U-label/A-label domain pair reaches the app as different byte strings (RFC 6531/5890) — record how the app stores it versus how the mail system delivers it.

### Reset-link / magic-link oracles
- Host-shape oracle: the reset link's host is derived from `Host`, `X-Forwarded-Host`, `X-Forwarded-Server`, or a forwarded scheme — the delivered link host differs from the app's canonical host.
- Wrapper-vs-original oracle: the delivered link is wrapped by the mailbox provider (Safe Links) or the ESP (click tracking) — unwrap it and compare the underlying host and token, never the surface string.
- Token-leak oracle: the token appears in a URL from which an attacker-controlled host or third-party resource receives it (Referer, poisoned link host); the leak is the finding, not the token's presence.
- Consumption oracle: a first fetch (by the researcher, a link scanner, or a mail-client prefetch) invalidates the token — record who consumed it, and whether one-time use is the control passing or the flaw.
- Identity-binding oracle: reset requests for `r+tag1@` and `r+tag2@` produce tokens that reset each other's accounts, or a reset claims to target the requested address while the account bound to the token is a different one.

### DNS rebinding / same-origin oracles
- Two-resolution flip: a short-TTL researcher domain answers first with a public IP then with a loopback/RFC1918 value from the test vantage point.
- Host-validation record: whether the internal target validates the `Host`/`Origin` header when reached by IP — a target that ignores `Host` is the confused decision.
- Pinning check: repeated fetches observe the same IP (pinned) versus the flip (unpinned); pinning is the control passing.
- Cache-TTL oracle: a resolver/proxy cache that ignores the record's short TTL keeps the public answer and defeats rebinding — record the resolver behavior, do not assume absence of defense.
- Browser-vector oracle: a public page dispatches a request to `0.0.0.0`, which reaches loopback on macOS/Linux (Chromium Private Network Access bypass, fixed Chrome 128→133; WebKit blocks all-zero destinations; Firefox does not implement PNA) — one request is enough; CORS hides the response while the side effect lands.

### Dangling-record oracles
- Fingerprint match: the record's CNAME/`A` points at a service whose 404/`NoSuchBucket`/`Heroku | No such app` page is a documented claimable fingerprint.
- Claimability: the service lets a researcher account register the exact referenced name (or returns a vendor-documented claimable error), with no existing owner response.
- Claim asymmetry: the service blocks external claims or returns an owner-verification challenge — that is a hard block, not a takeover.
- Signposting: an NS/SOA/`_acme-challenge` or TXT record leases the name in a way that reveals the intended owner but still leaves it claimable.
- Mail-record variant: the dangling name owns an MX or SPF include rather than a website — the observable is authenticated mail (delivered under the victim domain), not served content.

### CDN / origin-discovery oracles
- Origin-convergence oracle: two independent signals agree on one origin (historical DNS, DNS-only records, mail-server bounce IPs, certificate SANs, header/error dialect) — provider docs list historical records, unproxied DNS records, and co-hosted mail service as the documented leak channels.
- Direct-origin differential: a request carrying the app's `Host` reaches the candidate origin and returns content the edge blocks or data the edge does not expose — plain IP discovery is not the finding.
- Protection inventory: Tunnel/no routable IP, secret-header validation (replay caveat), Authenticated Origin Pulls, provider IP allowlist (IP-spoofable), dedicated egress IPs — record which control is deployed before calling origin exposure a weakness.

### DNS record-surfacing oracles
- NSEC walk: a signed zone without NSEC3 answers nonexistent names with NSEC records that enumerate every owner name; NSEC3 hashes owner names, and opt-out spans may not cover insecure delegations (RFC 5155 §6).
- Nameserver cut-point data: an AXFR response must carry the cut-point NS RRset, revealing parent-side delegations a hardened setup would not (see AXFR notes).
- TXT signposts: `_acme-challenge`, `google-site-verification`, and vendor TXT records name the services and sometimes the owners of otherwise unadvertised names — a lead until a second signal confirms.

### Cross-family chains (compose verified primitives)

| Chain | Leg 1 (entry) | Leg 2 (escalation) | Leg 3 (persistence) | Oracle per leg |
|---|---|---|---|---|
| Dangling DNS -> cert | orphan CNAME at a claimable service | researcher claims the name | cert issued / content served | claim succeeds, fingerprint matches |
| Rebind -> internal trust | flip to internal IP | Host/origin trust not validated | reach internal admin or SSRF target | internal response body differs |
| SMTP smuggling -> spoof | authenticated send with non-standard EOD | service B splits into two mails | injected `MAIL FROM` passes SPF | two messages, one forged |
| Header injection -> template | CRLF survives into a structured header | value lands in a template field | renders evaluated in ticket UI | evaluated render visible |
| ARC rewrite | intermediary strips/changes authentication | ARC `cv` recomputed | receiver trusts stale assessment | `arc=` value changes disposition |
| Dangling selector -> DKIM pass | orphan `_domainkey` selector (absent/empty/parked) | researcher publishes replacement key | forged message signed with victim `d=`/`s=` verifies | verifier returns `dkim=pass` |
| Poisoned include -> SPF pass | SPF include target expired/squatted | researcher registers it with `+all` | receiver returns `spf=pass` for victim domain | `Authentication-Results` pass |
| Reset poisoning -> ATO | link host follows `Host`/`X-Forwarded-Host` | victim opens token to researcher host | researcher replays token on real app | token replay succeeds |

## Minimal safe proof

1. Baseline: record SPF, DKIM, DMARC, CAA, DNSSEC, and nameserver answers plus a benign researcher-email delivery header set before any probe.
2. Spoof-context probe: send a researcher-domain test message to the researcher mailbox only and record authentication-result headers; never spoof third-party domains to third parties.
3. Injection probe: submit one benign header or template token through a single input field and inspect only the researcher-delivered message and researcher-visible ticket rendering.
4. Rebinding probe: use a researcher domain with short TTL, record both resolutions, and test exactly one trust decision at low rate; halt on any non-researcher effect.
5. Takeover validation: confirm the dangling record, check service-side claimability with the researcher account, and claim only when program scope and service rules permit benign proof.
6. SMTP-smuggling probe (own accounts only): authenticate to your own sending account, send one message containing the non-standard end-of-DATA, and check whether two messages arrive in your own mailbox — never target another party's mailbox.
7. MTA-STS/CAA/DNSSEC probe: read-only queries plus a policy comparison (`mode`, `id`, RRset) — do not attempt to suppress or spoof records.
8. Local-part differential probe: register only researcher-owned mailbox variants, record what the app stores and how it routes; stop before any other user's identity is touched.
9. Reset-link handling probe: request one reset for your own account, capture the message, unwrap provider/ESP rewrites, and record the host and token binding without opening the link from an untrusted context.
10. Selector/include proof: publish only on researcher-owned selectors and domains, verify resulting signatures offline, and treat the pass verdict as the finding's evidence — no forged mail leaves the researcher's control.
11. Stop conditions: any third-party mailbox effect, production mail-loop risk, unrelated zone data, or customer hostname exposure beyond the oracle — halt, retain minimal evidence, and report.

## False positives

- Permissive mail-auth posture with no accepted spoof path — posture alone is hardening context, not spoofability; require a delivered researcher-spoof oracle.
- Marketing or notification mail without authentication alignment — bulk-mailer delegation by design; require header-from versus envelope-from alignment failure on a security-relevant flow.
- Unsubscribe link carrying an identifier that is random, single-purpose, and rate-limited — identifier presence is not enumeration; require sequential or guessable tokens.
- Email bombing surface with effective per-target rate limits or CAPTCHA — throttled delivery is the control passing; require demonstrated unbounded delivery to a researcher mailbox.
- Dangling record pointing at a service that blocks external claims or returns a hard error — unclaimable dangling is exposure context, not takeover; require researcher claim or vendor-confirmed claimable fingerprint.
- Single-signal origin guess (one header or one historic record) — require convergence of two independent signals before claiming disclosure, and a direct-origin response differential before claiming exposure.
- Missing CAA or DNSSEC alone — absent hardening without a demonstrated issuance or poisoning path is context, not a finding. Note CAA is only checked by conforming CAs and *relying parties MUST NOT use CAA in certificate validation*.
- Rebinding resolution flip with no reachable trust decision — DNS behavior alone is not impact; require the confused trust decision to occur.
- `-all` SPF that hard-fails early in the transaction — that is enforcement; it also means the failing mail never appears in DMARC reports, which is a *reporting* gap, not a spoofing gap.
- MTA-STS `mode: testing` treated as "no MTA-STS" — testing is a deliberate soft-deploy; require `enforce` behavior to differ before claiming downgrade impact.
- A DKIM key that is short/parkable but the selector is unused — an unused selector is not by itself a signing vulnerability; require a researcher-published key that makes a forged signature verify, or mail signed with a reachable/parkable selector that still validates.
- Dots-in-Gmail equivalence — the provider does this on purpose on `gmail.com` (and does not on Workspace custom domains); the bug is app-side duplicate-account or identity confusion, not Gmail behavior.
- Plus/hyphen alias acceptance — intentional aliasing; require a security-relevant effect (duplicate identity, reset confusion, mailbox-existence disclosure) rather than merely delivered mail.
- NSEC zone enumeration — standard DNSSEC behavior, and NSEC3 exists to prevent it; without program scope making enumeration reportable it is informational context.
- A reset token consumed by a scanner, link prefetcher, or the researcher's own opening — provider behavior; the finding requires a token usable by an unauthorized party (leak, splice, or cross-account binding).
- Duplicate DMARC records discarding every policy — that is a misconfiguration, not attacker control; require the resulting no-policy state to be exploitable under program criteria.
- DKIM selector NXDOMAIN alone — a missing key makes signatures unverifiable, which is safe; require a published, verifying replacement key before claiming selector takeover.

## Version/implementation notes

### SPF semantics (RFC 7208)
- Hard limits: a record may use at most **10** DNS-querying terms total (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`); exceeding it is `permerror`. Each `mx`/`ptr` evaluation may query at most **10** `A`/`AAAA` records (mx → `permerror`; ptr → ignore beyond the first 10).
- **Void lookups** (positive answer with zero records, or NXDOMAIN) should be limited to **two** (`permerror` beyond), configurable with a default of two.
- Evaluation should allow at least **20 s** before returning `temperror`; a transient DNS error is `temperror`, while NXDOMAIN is treated as "no error, zero answers" and evaluation continues.
- Qualifiers: `+` pass, `-` fail, `~` softfail, `?` neutral. `all` always matches and ends evaluation — mechanisms after it **MUST** be ignored and any `redirect` **MUST** be ignored. A record with no match and no `redirect` yields `neutral` (implicit `?all`).
- Zero records → `none`; more than one `v=spf1` record → `permerror`. These limits make DoS/`permerror`-shaped and DNS-side behavior part of the posture.
- SubdoMailing consequences: `include:` targets that expire or are squatted turn into authorization for whoever re-registers them (a "poisoned domain" publishing attacker IPs); the same applies to `a:`/`mx:` targets, CNAME-delegated names, and NS delegations. Auditing the SPF tree, not just the top-level record, is the defense.

### DKIM / DMARC alignment (RFC 6376 / 7489 / 9989)
- DMARC distinguishes the `RFC5322.From` (Author Domain) from the SPF/`MAIL FROM` and DKIM `d=` identifiers; alignment is **relaxed** (same Organizational Domain) or **strict** (exact match), chosen per SPF (`aspf`) and DKIM (`adkim`).
- DMARC legacy: RFC 7489 was **Informational**. DMARCbis is now **Standards Track — RFC 9989** (obsoletes RFC 7489 and RFC 9091), with RFC 9990 (aggregate reporting) and RFC 9991 (failure reporting).
- DMARCbis changes that alter test design: the Public Suffix List is replaced by the **DNS Tree Walk** and Public Suffix Domains (PSD); `pct=`, `rf=`, and `ri=` are deprecated; the `rua` size notation is obsolete; a new `np=` tag governs non-existent subdomains; the `psd=` tag (from RFC 9091) moves in; SPF is used for **MAIL FROM only** (no HELO fallback); and a `t=` test-mode tag can request a one-level-lenient policy.
- The DNS Tree Walk is capped so an Author Domain with more than eight labels never causes more than eight queries; a DMARC record published at a zone cut deeper than that cap is never discovered — a real misconfiguration seam.
- PSOs publish `psd=y`; a Domain Owner can declare an arbitrary node its Organizational Domain with `psd=n`, but only within the eight-label walk limit.
- External reporting destinations must pass the `_report._dmarc.<destination-host>` verification (TXT `v=DMARC1`), otherwise reports must not be sent.
- `p=reject` **MUST NOT** rely on SPF alone, and receivers **SHOULD NOT** reject solely on `p=reject` (RFC 9989 §7.4) — a receiver that does is the bug shape, not the sender. RFC 9989 also states that DMARC validates the **domain only**: it says nothing about the local-part of any identifier, and any one aligned DKIM signature is enough for a pass.
- Duplicate policy records are not merged: if more than one DMARC record is returned for the same target, **all** are discarded.

### Local-part parsing per provider
- RFC 5321: a mailbox is `local-part@domain`; the local-part **MUST** be treated as case-sensitive and its case preserved, and its meaning is assigned only by the destination host; mailbox domains follow normal DNS rules and are case-insensitive.
- Gmail (consumer `gmail.com`): dots are ignored (`first.last@` == `firstlast@`), and `+tag` variants deliver to the same mailbox; Google explicitly notes that Workspace/business addresses on a custom domain must match exactly, so dots are significant there. On consumer Gmail, nobody else can register a dotted variant of an existing username.
- Exchange Online: plus addressing (`user+tag@domain`) is enabled by default, receive-only; resolution tries the full address first, then falls back to the address without `+tag`; it can be disabled with `Set-OrganizationConfig -DisablePlusAddressInRecipients $true` (or the Exchange admin center).
- Yahoo Mail: disposable addresses are `nickname-keyword@yahoo.com` (hyphen separator), configured aliases (up to 500 with Mail Plus), delivered into the main inbox; they are provisioned, not a parsing trick.
- Cross-provider implication: "same mailbox, many spellings" (Gmail dots/plus, Exchange plus, Yahoo hyphens, common case-insensitivity) is routine. Apps that key identity on the raw string, normalize inconsistently, or reset by raw lookup while registering by normalized value create duplicate-identity and reset-confusion bugs even though every mail still lands in one inbox.
- Internationalized mail: RFC 6531 (SMTPUTF8) permits non-ASCII local-parts and requires 8BITMIME; address parsing delimiters are unchanged from RFC 5321, and IDN domains are looked up as A-labels while U-labels may appear in headers. A byte-string difference between how the app stores an address and how the mail system delivers it is the differential to record.

### Password-reset and magic-link handling per mailbox provider
- Microsoft Defender Safe Links rewrites inbound URLs to `https://<DataCenter>.safelinks.protection.outlook.com...` during mail flow, per recipient (including forwarded/replied mail), and asynchronously detonates URLs of unknown reputation; with "Do not rewrite URLs, do checks via SafeLinks API only" the raw URL stays in the message but is still checked. Consequence: the link a tester reads in the mailbox is a wrapper, and background detonation may already have fetched the target.
- PortSwigger notes reset links can be fetched "in some other way, for example, by an antivirus scanner" — a one-time token consumed by a scanner, prefetcher, or the researcher's own tooling is provider behavior, not automatically a flaw.
- Apple Mail Privacy Protection downloads remote content in the background regardless of whether the user engages with the message, routed through two relays — pixel/remote-content signals cannot be used as an "opened" oracle, and any server-side effect of loading content fires without a human.
- ESP click tracking (e.g., SendGrid link branding on a branded subdomain) and provider wrappers change the link host in the delivered message; unwrap before comparing hosts.
- Reset-flow shapes to test with a researcher account: host-derived link base (`Host`/`X-Forwarded-Host`), token in URL vs POST, one-time vs reusable, token bound to the requested address vs a stored account, and whether requesting a reset for an alias spelling returns a token usable on the base account.

### DKIM key, selector, and record details (RFC 6376 / 8301)
- The `d=` (signing domain) and `s=` (selector) are attacker-relevant: an absent, empty, or parkable selector record can be replaced by a researcher key, and a signature made with that key validates for the same `d=`/`s=` — the domain need not still be signing with the selector (reclaim/shadowing shape). The old selector namespace was delegated by design: periods in selectors define DNS label boundaries, so a selector record can be CNAME-delegated to a provider (SendGrid publishes `s1._domainkey`/`s2._domainkey` CNAMEs to `*.domainkey.*.sendgrid.net` as its default), which is exactly how an orphaned delegation becomes claimable.
- Revocation semantics: `p=` is required, and an **empty** `p=` means the key is revoked; verifiers SHOULD return an error for signatures referencing a revoked key. There is no defined semantic difference between a revoked key and a removed (nonexistent) key record — the difference is whether the name still resolves.
- Crypto floor (RFC 8301): `rsa-sha1` MUST NOT be used for signing or verifying; signers MUST use RSA ≥ 1024 bits (SHOULD ≥ 2048); verifiers MUST be able to validate 1024–4096 and MUST NOT accept signatures using RSA keys below 1024 bits as valid.
- The `l=` body-length tag limits how much of the body is hashed; RFC 6376 §8.2 warns it can allow display of fraudulent content without warning — appended body content after the signed length passes. Its value MUST NOT exceed the canonicalized body length, but is still a seam for apps that append footers or render beyond it.
- DKIM authenticates a *domain*, not the local-part or content; a valid signature from any domain (mailing list, bad actor) is not authenticity without DMARC alignment — under RFC 9989 any single DKIM-Authenticated Identifier that aligns is enough for a pass.
- Header canonicalization (`simple` vs `relaxed`) and the signed-header list (`h=`) decide whether an added/reordered header invalidates the signature — a signature that survives a header an app trusts is the seam.
- Replay (RFC 6376 §8.6) is amplified by ARC; a captured, still-valid message can be re-sent. Reusing a selector with a new key makes forged vs expired-key failures indistinguishable (RFC 6376 §3.1) — another reason selector names are security-relevant.

### SMTP smuggling (line-ending / END-OF-DATA)
- The standard end-of-DATA is `<CR><LF>.<CR><LF>`; smuggling uses a non-standard form such as `<LF>.<LF>` or `<LF>.<CR><LF>` produced by "originating" service A and misread as end-of-DATA by "destination" service B.
- Historical interoperability (Sendmail and successors accepting bare `<LF>`) is the root cause; A must forward the non-standard sequence verbatim for the composition to work.
- Consequence: B accepts a smuggled `MAIL`/`RCPT`/`DATA` (or `BDAT`) and then a second message body. The spoofed message **passes SPF-based DMARC at B** because its `MAIL FROM` domain is hosted at A and the connection originates from A.
- Vendor hardening: Postfix `smtpd_forbid_bare_newline = normalize|reject` (with `smtpd_forbid_bare_newline_exclusions`), `reject_unauth_pipelining` (older) / `smtpd_forbid_unauth_pipelining` (3.8.1+ patches, on by default from 3.9), and `smtpd_discard_ehlo_keywords = chunking` to drop `BDAT`. Postfix also warns some test tools report *non-viable* smuggling patterns.
- CVEs: Postfix CVE-2023-51764, Sendmail CVE-2023-51765, Exim CVE-2023-51766 (SEC Consult, Dec 2023).

### SMTP command and envelope boundaries (RFC 5321 / 3030)
- Command verbs and argument keywords are case-insensitive, with the sole exception of the mailbox local-part, which is case-sensitive and must be preserved. A command line (including `CRLF`) is limited to 512 octets, and a text line to 1000; extensions may raise the command limit.
- CRLF inside envelope fields is an injection boundary: the local-part semantics belong to the destination host, so a value that reaches an originator or MTA unneutralized (CWE-93) can become extra commands, extra recipients, or extra headers. Test with researcher-controlled inputs and a researcher mailbox only.
- BDAT/CHUNKING (RFC 3030) takes an exact octet count: too large and the receiver consumes the next command as data; too small and the remainder is parsed as (invalid) commands. Sending `BDAT` to a server that did not advertise `CHUNKING` makes the data parse as a very long command line.
- DATA and BDAT cannot be mixed in one transaction; after `BDAT LAST`, further BDAT is a `503`, and the state is indeterminate until `RSET`.

### ARC chain manipulation (RFC 8617)
- Three header fields form one ARC set sharing an instance tag: `ARC-Authentication-Results` (AAR), `ARC-Message-Signature` (AMS), `ARC-Seal` (AS). Instance values run 1–50 and must form a gapless, non-repeating sequence.
- Chain Validation Status is `none`/`pass`/`fail`; validation walks AS from newest to oldest and AMS from newest; if the newest AS is `fail` the whole chain is `fail`. On failure (including a DNS error — all ARC failures are permanent) the message is treated as having no ARC.
- The optional `oldest-pass` value and `smtp.remote-ip` are the reporting observables; an SMTP validator may signal failure with `5.7.29` ("ARC validation failure") or the broader `5.7.26`.
- Cost/abuse: validating an N-set chain can require up to **2×N** DNS queries, so long chains are a DoS/replay lever — a receiver's caching and signing-scope matter. ARC authenticates sealers, not their trustworthiness.

### MTA-STS (RFC 8461) & TLS reporting (RFC 8460)
- Discovery: TXT at `_mta-sts.<domain>` (`v=STSv1; id=...`), policy body at `https://mta-sts.<domain>/.well-known/mta-sts.txt` with `version`, `mode` (`enforce`|`testing`|`none`), one or more `mx:` lines, and `max_age` (≤ 31557600).
- `mx:` wildcards match only the entire left-most label (`*.example.com` matches `mail.example.com`, not `example.com`); redirects (3xx) **MUST NOT** be followed; HTTP caching **MUST NOT** be used; the policy host cert must be valid for `mta-sts.<domain>`; TLS 1.2+ and SNI are required.
- Policy delegation is allowed (CNAME `_mta-sts` + a host/reverse-proxy for `mta-sts.<domain>` with a cert for the policy host); `mode: none` is the clean opt-out.
- Weak-policy flag: `mx: *.example.com` means any host with a valid cert for that suffix is a valid MX; providers that host untrusted user content at `mta-sts.<domain>` widen the risk.

### CAA (RFC 8659) & DNSSEC
- A CA must compute the **Relevant RRset** by climbing from the FQDN up to (not including) the root until a CAA RRset is found (it no longer chases CNAME/DNAME, unlike RFC 6844).
- Tags: `issue` (only listed CAs may issue), `issuewild` (only listed CAs may issue wildcards; takes precedence over `issue` for wildcards), `iodef` (report URI). `0 issue ";"` (empty issuer) forbids issuance; a malformed issue value is treated as empty (forbids).
- The critical flag is bit 0 (wire value `128`); an unknown **critical** property blocks issuance. DNSSEC is *strongly recommended* but not required — signed-empty vs. bogus responses matter (a known PowerDNS < 4.0.4 bug mishandled unsigned empty RRsets under DNS 0x20 mixed-case queries).
- **Relying parties MUST NOT use CAA as part of certificate validation** — CAA is a pre-issuance control by conforming CAs only.
- Denial-of-existence choice matters for enumeration: a plain NSEC-signed zone is walkable name by name, NSEC3 hashed the owner names specifically to prevent that, and NSEC3 opt-out spans are allowed to omit insecure delegations (so absent names are not proof of absence under opt-out).

### AXFR / zone transfer (RFC 5936)
- A DNS implementation should not support AXFR by default in an open way; it **SHOULD** provide access control restricting transfers to specific clients, and general-purpose implementations are recommended to use **TSIG** (RFC 2845) and/or **SIG(0)** (RFC 2931).
- A successful AXFR against an authorized target is a legitimate disclosure; the finding is an *open* transfer from an Internet-reachable nameserver.
- The AXFR response must carry the cut-point NS RRset as registered with the zone (a deliberate way to expose inconsistent delegations), which can reveal parent-side records a hardened setup would not.

### Dangling DNS, selectors, and mail-record takeover
- Takeover claimability changes as providers add ownership verification; re-check vendor claim rules per engagement rather than relying on service lists from memory. Current vendor-documented outcomes worth knowing before testing: AWS S3 `The specified bucket does not exist`, Google Cloud Storage `NoSuchBucket`, Heroku `No such app` (edge case — provider blocks some claims), GitHub Pages `There isn't a GitHub Pages site here.` (edge case — domain verification), Azure and Vercel `DEPLOYMENT_NOT_FOUND`/`NXDOMAIN` shapes, and an explicit set of services the community marks **Not vulnerable** because they enforce ownership verification (CloudFront, Fastly, Kinsta, Mailchimp, Statuspage, Zendesk, and others).
- Missing CAA/DNSSEC or a dangling record without a successful claim is exposure context; only a researcher-controlled claim (or a vendor-documented claimable fingerprint) is a finding.
- CDN and certificate signals age quickly; treat historical DNS and transparency data as leads that require live two-signal convergence.
- Rebinding defenses (Host validation, auth on internal listeners, DNS pinning) vary by deployment; record the specific defense observed instead of assuming absence.
- SubdoMailing shows the mail-record variant at scale: dangling CNAMEs, expired domains in SPF includes, and NS/MX delegations let attackers send SPF- and DMARC-passing mail "from" the victim's namespace; with relaxed SPF alignment the attacker can also send as the parent domain. The protocols are working as designed — the DNS underneath them was not maintained.

### CDN origin protection (what the vendor says to do, and therefore what to test for)
- Cloudflare's documented origin-leak channels: historical DNS records (kept after proxying), unproxied (DNS-only) records such as FTP/SSH, and mail infrastructure co-hosted with the web resource (a bounce to a nonexistent address reveals the mail server IP); the vendor also recommends rotating origin IPs after onboarding and using non-standard names for DNS-only records that must exist.
- Documented controls to look for (and to credit as defenses rather than weaknesses): Cloudflare Tunnel (no publicly routable origin at all), secret HTTP header validation (replayable if the header is guessable/leakable), Authenticated Origin Pulls, allowlisting provider IP ranges (noted as vulnerable to IP spoofing), Magic Transit/Network Interconnect, and dedicated egress IPs.
- Test shape that survives review: origin reachable directly **and** a response difference versus the edge (blocked path served, internal-only data, vhost confusion). A discovered IP with identical behavior proves exposure, not impact.

### DNS rebinding: browser and server vectors
- The 0.0.0.0 Day class (Oligo Security): public pages could dispatch HTTP requests to `0.0.0.0`, which reaches loopback services on macOS/Linux, bypassing Chromium's Private Network Access; one request is enough, and CORS only hides the response. Remediation landed in Chromium 128→133 and WebKit (all-zero destination blocked); Firefox had no PNA implementation at the time of writing. Personal/local services (dev servers, AI tooling, admin panels) remaining unauthenticated on loopback are the exploitable side.
- Server-side rebinding and Host confusion share the same defense as the browser vector: validate the `Host` header on internal/local listeners and never trust "it's localhost" as authorization.

## References

- [T0 standards] RFC 7208, Sender Policy Framework (SPF) — 10-term lookup limit, mx/ptr A/AAAA cap, void-lookup limit 2, 20 s timeout, qualifiers, `all` termination, `permerror`/`temperror`: https://www.rfc-editor.org/rfc/rfc7208.html
- [T0 standards] RFC 5321, Simple Mail Transfer Protocol — local-part case sensitivity MUST be preserved, semantics assigned only by the destination host, 512-octet command line, 1000-octet text line: https://www.rfc-editor.org/rfc/rfc5321.html
- [T0 standards] RFC 6376, DKIM Signatures (STD 76) — `d=`/`s=`, selector delegation by label boundaries, `p=` empty means revoked, `l=` misuse (§8.2), canonicalization, replay (§8.6): https://www.rfc-editor.org/rfc/rfc6376.html
- [T0 standards] RFC 8301, DKIM Crypto Update — `rsa-sha1` MUST NOT be used, RSA ≥ 1024 for signers, verifiers reject < 1024: https://www.rfc-editor.org/rfc/rfc8301.html
- [T0 standards] RFC 7489, DMARC (legacy, Informational; obsoleted by RFC 9989/9990/9991): https://datatracker.ietf.org/doc/rfc7489/
- [T0 standards] RFC 9989, DMARC (Standards Track, obsoletes 7489 and 9091) — DNS Tree Walk (8-label cap), `psd`/`np`/`t`, deprecated `pct`/`rf`/`ri`, `p=reject` guidance, domain-only validation (no local-part), duplicate records discarded: https://www.rfc-editor.org/rfc/rfc9989.html
- [T0 standards] RFC 9990, DMARC Aggregate Reporting: https://www.rfc-editor.org/rfc/rfc9990.html
- [T1 vendor] dmarc.org, summary of changes in DMARCbis (Standards Track, Tree Walk/PSD, tag deprecations, SPF MAIL FROM only): https://dmarc.org/2025/12/summary-of-changes-in-dmarcbis/
- [T0 standards] RFC 8617, ARC Protocol — instance 1–50, `cv` status, X.7.29, 2N DNS queries, replay: https://datatracker.ietf.org/doc/rfc8617/
- [T0 standards] RFC 8461, MTA-STS — `_mta-sts` TXT, `.well-known/mta-sts.txt`, modes, `max_age`, `mx` wildcard, no redirects/caching, TLS 1.2+: https://datatracker.ietf.org/doc/rfc8461/
- [T0 standards] RFC 8659, CAA — Relevant RRset tree-climb, `issue`/`issuewild`/`iodef`, critical flag, DNSSEC, PowerDNS < 4.0.4 note: https://www.rfc-editor.org/rfc/rfc8659.html
- [T0 standards] RFC 5936, DNS Zone Transfer Protocol (AXFR) — restrict to specific clients, TSIG/SIG(0), cut-point NS RRset: https://www.rfc-editor.org/rfc/rfc5936.html
- [T0 standards] RFC 5155, DNSSEC Hashed Authenticated Denial of Existence (NSEC3) — NSEC zones are enumerable, NSEC3 protects against zone enumeration, opt-out spans: https://www.rfc-editor.org/rfc/rfc5155.html
- [T0 standards] RFC 3030, SMTP CHUNKING/BDAT — exact-octet chunking, desync effects, illegal BDAT parsed as a command line: https://www.rfc-editor.org/rfc/rfc3030.html
- [T0 standards] RFC 6531, SMTPUTF8 — non-ASCII local-parts, 8BITMIME required, parsing delimiters unchanged, A-label/U-label handling: https://www.rfc-editor.org/rfc/rfc6531.html
- [T1 standards] MITRE CWE-93, Improper Neutralization of CRLF Sequences ('CRLF Injection'): https://cwe.mitre.org/data/definitions/93.html
- [T1 vendor] Google, Gmail Help "Dots don't matter" — dots ignored on gmail.com, exact match required on Workspace custom domains: https://support.google.com/mail/answer/7436150
- [T1 vendor] Google Gmail Blog, plus addressing (`user+tag@gmail.com`): https://gmail.googleblog.com/2008/03/2-hidden-ways-to-get-more-from-your.html
- [T1 vendor] Microsoft, Plus Addressing in Exchange Online — default on, receive-only, fallback resolution without `+tag`, `Set-OrganizationConfig -DisablePlusAddressInRecipients`: https://learn.microsoft.com/en-us/exchange/recipients-in-exchange-online/plus-addressing-in-exchange-online
- [T1 vendor] Microsoft, Safe Links in Defender for Office 365 — URL rewriting via `<dc>.safelinks.protection.outlook.com`, per-recipient wrapping, asynchronous detonation, API-only mode: https://learn.microsoft.com/en-us/defender-office-365/safe-links-about
- [T1 vendor] Apple, Mail Privacy Protection — background download of remote content regardless of engagement, two-relay routing: https://www.apple.com/legal/privacy/data/en/mail-privacy-protection/
- [T1 vendor] Yahoo Mail Help, disposable addresses `nickname-keyword@yahoo.com` (up to 500, delivered to main inbox): https://help.yahoo.com/kb/SLN28815.html
- [T1 vendor] Twilio SendGrid, Configure domain authentication — `s1._domainkey`/`s2._domainkey` CNAMEs, link branding, custom return path, subdomains do not inherit authentication: https://docs.sendgrid.com/ui/account-and-settings/how-to-set-up-domain-authentication
- [T1 vendor] Cloudflare, Protect origin IP address — historical records, unproxied DNS records, mail infrastructure bounce disclosure, IP rotation: https://developers.cloudflare.com/learning-paths/prevent-ddos-attacks/advanced/protect-origin-ip/
- [T1 vendor] Cloudflare, Protect your origin server — Tunnel, header validation, Authenticated Origin Pulls, IP allowlisting caveat, dedicated egress IPs: https://developers.cloudflare.com/fundamentals/security/protect-your-origin-server/
- [T2 research] Red Sift, What is SubdoMailing? — poisoned SPF includes, expired-domain CNAME takeover, `aspf=s` limiting parent-domain blast radius, MX/NS risk: https://redsift.com/guides/subdomailing-guide
- [T2 research] DNS Institute, SPF Dangling DNS targets — 80+ production SPF records referencing nonexistent/squatted domains, with examples: https://dnsinstitute.com/research/dangling-dns/dangling-spf-20220515.html
- [T2 research] Oligo Security, 0.0.0.0 Day — PNA bypass via `0.0.0.0`, localhost reach from public pages, Chromium/WebKit fixes, Firefox PNA status: https://www.oligo.security/blog/0-0-0-0-day-exploiting-localhost-apis-from-the-browser
- [T2 research] PortSwigger Web Security Academy, Password reset poisoning — Host-header link base, token theft, scanner fetch note: https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning
- [T2 tooling] Can I take over XYZ? (EdOverflow/can-i-take-over-xyz) — per-service takeover status and fingerprints, including the Not-vulnerable set: https://github.com/edoverflow/can-i-take-over-xyz
- [T2 research] OWASP Cheat Sheet Series, Subdomain Takeover Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html
- [T1 vendor] Postfix, SMTP Smuggling response (non-standard END-OF-DATA, `smtpd_forbid_bare_newline`, `reject_unauth_pipelining`, `chunking`/BDAT, CVE-2023-51764/51765/51766): https://www.postfix.org/smtp-smuggling.html
- [T3 vuln intel] SEC Consult, SMTP Smuggling — spoofing e-mails worldwide: https://sec-consult.com/blog/detail/smtp-smuggling-spoofing-e-mails-worldwide/
- [T2 tooling] Dangling-DNS detection modules (BadDNS): https://blacklanternsecurity.github.io/baddns/modules/
- [T2 research] Dangling DNS find-and-fix: https://redsift.com/blog/dangling-dns-find-and-fix ; Azure prevention: https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover
- [T2 research] Dangling DNS overview: https://www.paloaltonetworks.com/cyberpedia/what-is-a-dangling-dns ; hijacking risk: https://www.digicert.com/blog/dangling-dns-records-and-the-risk-of-domain-hijacking
- [T2 research] PortSwigger Web Security Academy, HTTP Host header attacks — SSRF/origin trust decisions and email-generation surfaces: https://portswigger.net/web-security/host-header
