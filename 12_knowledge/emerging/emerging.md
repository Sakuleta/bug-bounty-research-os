# Emerging / Unfamiliar Behavior Triage

> SCOPE: Load when fingerprinting reveals an unfamiliar stack, version, protocol, or behavior with no dedicated pack; this pack routes the unknown into a hypothesis, it never replaces a dedicated pack. It also owns the novelty-discovery process: recognize an unfamiliar behavior, isolate it from environment and user error, build a first oracle, and record the primitive so it becomes reusable. Every triage ends with one owner — a dedicated pack, the dynamic technique engine, or a written non-applicable closure.

## Research families

- Unfamiliar framework, runtime, or platform version with unknown security primitives
- New protocol feature or extension the edge and origin may interpret differently
- Unknown parser, serializer, or canonicalization step observed in responses
- Unfamiliar authentication, federation, or session mechanism
- New client capability (browser API, mobile SDK, wallet flow) the backend trusts
- Vendor-specific extension (cache key rule, edge function, rewrite language)
- Recently disclosed technique with unclear architectural preconditions on this target
- Composite behavior spanning two packs with no clear owner
- Shared request/response parser behavior (a rule written for responses applied to requests)
- Anonymous memory-safety symptoms (text/binary blends, unexpected status flips) with no owned pack
- Anomalies produced by a *clean* RFC-compliant request (second response, forked response, injected status line)
- A feature described only in a response-processing section of a spec but honored on a request
- Autonomously generated technique leads that need live validation before they count
- A version string that changes between two responses on the same target (rolling deploy / canary)
- A new HTTP status code or RFC field the edge and origin treat differently
- A third-party integration whose docs describe behaviour the target does not exhibit
- An input whose handling is *undefined or ambiguous* in the current specification for the observed component — the spec gap itself is the primitive (RFC 9413: "where handling is not defined or where there is some ambiguity in the specification")
- A spurious protocol state transition — an out-of-order message accepted, or a session continuing after a fatal condition (the protocol-state-fuzzing signal)

## Preconditions

- Fingerprinted technology and version where possible; unknown-name claims without a version string stay leads, not hypotheses.
- One observed behavior (header, response shape, timing, error text) anchoring the triage — no open-ended research without a target observable.
- Dedicated packs checked first; this pack applies only after browser, edge, api, parsers, auth, logic, mobile, cloud, supply-chain, and agentic packs all decline ownership.
- Researcher-controlled test surface confirmed in scope before any external research-driven probing.
- Freshness ledger entry opened (`10_learning/freshness.yaml`) so the triage result persists beyond the current cycle.
- For a "new research technique" lead: the source names a concrete primitive (parser, boundary, state assumption) and the fingerprinted version is inside the range the source claims.
- For a symptom with no owner: a reproducible benign request whose response is *anomalous* (extra bytes, second response, status flip) and a clean control that stays normal.
- For a memory-safety lead: an isolated, repeatable, single-request trigger and an abort condition before you send it anywhere.
- For a cross-implementation claim: at least two distinct deployments (or two versions) in the same path, so the primitive is separable from an isolated bug.
- For an "unknown field" lead: the field actually appears in a response or error, not only in a spec you read.
- Ambiguity check first: RFC 9413 separates undefined or ambiguous handling (novel-class territory) from a clear specification violation (an ordinary implementation bug). Name which one you have before opening a novelty lead — the first needs a differential, the second a version-matched advisory.
- "Clean" is defined, not felt: the request must be RFC-compliant and unambiguous as a *single* request. A dirty request that gets two responses is normal HTTP/1.1 and is triaged as noise, not as a primitive.
- The transport state belongs to you: a state-learning or desync-shaped probe needs a connection or session the researcher owns and can reset. Never learn state on another user's traffic.
- A declared safety ceiling: single-shot and low-rate by construction, with an abort condition on unexpected 5xx or state change. Novelty proofs are differentials, never floods.

## Oracles

- Primitive extraction: current research names a concrete parser, boundary, or state assumption mappable to the observed stack version.
- Version-match signal: advisory, changelog, or research proof-of-concept targets the fingerprinted version range including this deployment.
- Differential confirmation: two researcher requests differing in one new-protocol field produce divergent security decisions where the documented behavior predicts identical handling.
- Assumption-collision candidate: two components in the observed path document incompatible handling of the same field, and both documents are version-matched.
- Negative triage: the unfamiliar behavior reproduces identically with security-relevant inputs neutralized, closing the triage as non-applicable with evidence.
- Promotion signal: the triage yields a precondition plus oracle plus safe proof mappable to a dedicated pack — promote and continue there.
- Novelty candidate: the triage yields a reproducible oracle with no matching known technique — escalate via 17_DYNAMIC_TECHNIQUE_ENGINE.md, not as a finding.
- Anomaly-candidate signal: a single RFC-compliant ("clean") request produces two responses or a text/binary blend — a possible memory-safety or novel-desync primitive with no current owner.
- Cross-class signal: a request-only component honoring a response-only field (or vice versa) — evidence of shared parser code, which widens the attack surface beyond the class under test.
- Status-line echo: the request's protocol string (e.g. `COW<`) is copied into the response status line unsanitized — evidence of an unbuffered code path that may enable a buffering breakdown.

- Reproducible anomaly: the same single clean request produces the anomaly twice in a row while the clean control stays normal — the minimum bar before escalation.
- Cross-implementation confirmation: the primitive reproduces on a second, different server/version in the same path, which separates a real class from a one-off implementation quirk.

### Oracle patterns (pick per primitive)

| Pattern | Shape | Detects | Main weakness |
|---|---|---|---|
| Ruler/boundary walk | bisect an implementation limit, then shift it with one candidate byte sequence | front-end transformations (rewrite, drop, mojibake) with no reflection needed | needs a stable, observable limit |
| One-factor differential | two requests differing in exactly one field | parser or decision divergence | build flags and rollout cohorts drift |
| Cross-request contamination | known-good request R0, trigger T on a second connection, re-read R0 | any cross-request state bleed, including unknown classes | requires shared connection state in the path |
| Clean-control anomaly | one RFC-compliant request vs one deliberately dirty control | unknown non-length primitives (forking, leaks) | "clean" must be derived from raw bytes, not assumed |
| State-machine inference | query a protocol alphabet, learn the state machine, inspect spurious transitions | logic flaws such as accepting out-of-order or post-fatal messages | exploitability needs manual follow-up |
| Normative invariant check | compare a response to a MUST (e.g. `Range` should yield `206`) | protocol non-conformance with cache or parser impact | the invariant must be normative, not a habit |
| Cross-implementation repeat | same trigger against a second build or version in the path | class vs one-off implementation bug | the second deployment must be architecturally comparable |
| Echo/reflection delta | reflected vs non-reflected variant of one request | downstream parser behavior | requires a reflection surface |

Triage outcome → route:

| Signal | Meaning | Route |
|---|---|---|
| Version-matched primitive + target differential | owned technique | promote to the owning pack |
| Reproducible oracle, no owned technique | genuine novelty lead | 17_DYNAMIC_TECHNIQUE_ENGINE.md |
| Anomaly with clean control | unknown primitive (memory/desync class) | this pack; escalate with control + anomaly |
| Reproduces with inputs neutralized | not security-relevant | close non-applicable with evidence |
| Cross-class (response field in request) | shared-parser surface | note in edge/parser packs, keep oracle here |
| Undefined/ambiguous spec handling with a target divergence | possible new class (spec gap) | this pack; build the single-probe differential |

### Worked shapes

- **Ruler walk (transformation oracle, no reflection).** Bisect a filler header (`A:` repeated) between a 200 and a 400 to find the header-length limit; on one measured server it sat at 64,040 bytes. Replacing two bytes with `c0 8a` moved the limit 10 bytes earlier — the sequence is charged 10 bytes more downstream than the bytes it replaced, so the front-end transformed it. One over-length/under-length pair per candidate sequence is the whole proof; stop after the first shift.
- **Cross-request contamination (class-agnostic).** Baseline a plain request with a stable response (`GET /` → 200). Send the candidate trigger on a *separate* connection, then repeat the plain request: a changed response (e.g. 405) proves the trigger altered another request's handling. The evaluator assumes nothing about the poisoned response, which is why it catches desync classes you have never seen. Follow up by combining the trigger with known-class payloads (CL.0 shapes, `GET / HTTP/777` → 505) to map the primitive to a known class.
- **Clean-request anomaly (unknown primitive).** Only a *clean* request that gets two responses is interesting. Verified shapes: dual matching `Content-Length: 28` headers — both valid and correct — treated as a zero-length body and exploited against an SSO server; `Content-Type: multipart/byteranges` with `Accept-Encoding: identity` returning a 400 followed by a second, headerless HTTP/0.9 response. Re-derive clean/dirty framing from the raw bytes; a harness can misclassify and hand you a false clean.
- **One-factor differential matrix.** Hold every byte except one factor: case (`get` vs `GET`), whitespace and `field : value` spacing, delimiter (`,` vs `+`), encoding (raw vs percent vs Unicode), field ordering, duplication, and version token (`HTTP/1.0`, `HTTP/2`, `HTTP/5.1`). Record handling per hop; a divergence where the spec predicts identical handling is the oracle.
- **State-machine inference.** Query a protocol alphabet (message types, orderings, resets) and learn the state machine from the responses; inspect the inferred machine for spurious transitions — a message accepted out of order, or a session that continues after a fatal condition. The same method found flaws in GnuTLS, JSSE, and OpenSSL, and because the learned machines are implementation-unique it doubles as a fingerprint. Spurious functionality is treated as dangerous until proven inconsequential.

## Minimal safe proof

1. Fingerprint: record banners, headers, version strings, SDK markers, error shapes, and documentation links for the unfamiliar component — two independent signals minimum.
2. Version pin: resolve the exact version or commit range and check vendor advisories, changelogs, and current research for that range only; record checked sources with dates.
3. Primitive map: extract at most three candidate primitives (parser, boundary, state) and map each to one observed target behavior with a one-line relevance argument.
4. Single-probe differential: send one benign differential per primitive (case, encoding, ordering, version-field variant) from the researcher session and record handling per hop.
5. Clean-request / anomaly probe: for a memory-symptom lead, send one RFC-compliant request with a clean control and compare; keep it single-shot and low-rate — never loop a crash-shaped probe against production.
6. Promote or close: on a divergent oracle, promote to the owning pack or the dynamic engine with precondition plus oracle; on convergence, close as non-applicable with the neutralized-input evidence.
7. Stop conditions: any destructive action, any other-user effect, any production state change, or any probe the version research flags as unsafe — halt, record, and report the triage boundary.

### Worked minimal proofs

- **Transformation:** one bisection to find the limit (two requests), one over/under pair with the candidate bytes; oracle = boundary shift; control = the same pair with a byte sequence the front-end ignores (no shift).
- **Contamination:** three requests — R0 baseline, trigger T on a fresh connection, R0 again; oracle = R0's response changes; control = T's own response is not simply R0's expected response echoed.
- **Clean anomaly:** one clean request + one dirty control; oracle = the anomaly appears for the clean request and the clean control stays normal; the dirty control is expected to produce the same anomaly, so it can never confirm the primitive on its own.
- **State learning:** a fixed alphabet run twice from a reset state; oracle = the learned transition accepts a sequence the specification forbids; control = the same alphabet against the documented behavior.

### Recording a new primitive so it is reusable

- Write one technique card per primitive — a card that cannot be re-run by someone else is a rumor. Minimum fields: `primitive` (class keyword + one-line mechanism), `source` (URL + fetch date), `precondition` (version/config/topology), `trigger` (exact bytes), `oracle` (observable delta), `control` (near-miss that must stay normal), `second implementation` (tested? result), `safety` (rate/abort), `owner` (pack or 17_DYNAMIC_TECHNIQUE_ENGINE.md).
- Name the primitive for retrieval, not for drama: "dual matching Content-Length treated as zero-length" — not "weird CL bug". The name is what a future cycle greps for.
- Dedupe before adding: search `12_knowledge/INDEX.yaml` `load_when` terms and the owning packs for the class keyword; if a pack owns it, append the card there and leave a one-line pointer here.
- Append the card to `10_learning/` (per `novelty-research.md`'s record format) and open the `10_learning/freshness.yaml` entry in the same pass; an unrecorded probe counts as not run.
- Record the negative result too: a primitive that closed non-applicable prevents the next cycle from paying for the same probe twice.

## False positives

- Version-string age mistaken for vulnerability — old does not mean reachable; require a version-matched primitive plus a target oracle.
- Research proof-of-concept cited without architectural preconditions — technique existence without this target's two-component differential is not applicability.
- Documentation wording differences between vendors mistaken for behavioral differentials — require observed divergent handling, not doc phrasing.
- Fingerprinting artifact from edge normalization (added headers, stripped versions) mistaken for origin behavior — confirm per-hop attribution before promoting.
- Staged rollout or cohort flag mistaken for a new primitive — rule out with flag-fixed repeats before claiming novelty.
- Error-text verbosity mistaken for a parser gap — require a decision or state divergence, not descriptive text.
- Successful promotion counted as a finding — promotion is routing, not proof; the owning pack's evidence standard still applies.
- Dual-response from an explicitly *dirty* request (ambiguous or duplicated length) mistaken for a novel primitive — HTTP/1.1 legitimately answers two requests; require the two-response behavior from a single, RFC-compliant request.
- Anomalous bytes that are a documented compression/binary feature (e.g. legitimate gzip body) mistaken for a memory leak — rule out with `Accept-Encoding: identity` before flagging.
- A technique the AI/research source generated but never validated on any live deployment — treat as a lead needing a live differential, never as a finding.
- HTTP pipelining mistaken for request smuggling — a server answering two requests on one connection is not contamination; distinguish pipelining from smuggling before promoting.
- Two arbitrary responses from a "clean" request that a second, differently-built request does not reproduce — non-determinism; require a reproducible, self-consistent trigger.

- An anomaly that the clean control also produces — if the control is anomalous too, the behaviour is environmental, not a new primitive.
- A "new" primitive that reproduces on only one host with no second implementation — treat as an implementation quirk until a second, different deployment confirms it.
- Client-side connection reuse producing the same two-response artifact as pipelining — force a fresh connection per probe and require the artifact to disappear; a library's reuse, not the server, can manufacture the signal.
- A success claim authored by the same AI or harness that ran the probe — an agent supplied a victim-response fingerprint that actually matched the attack response; capture fingerprints with deterministic code and validate against it, never against the model's narrative.
- A "clean" classification produced by your own tooling bug — the dual-`Content-Length` vector reached live testing marked clean only because of a harness defect; re-derive framing decisions from the raw bytes before trusting the control.
- A sanitized harness view as evidence — masking a `Connection: close` response header changed agent behavior; triage raw responses, not the filtered view your tooling hands you.
- An "inspiration"-contaminated generator restating the example it was given — feeding a prior technique as an example collapsed novelty (0% vs 5% measured; 30% only on newer models); score generated vectors against the source corpus before calling them new.
- A precondition hidden in the trigger's own success description — the dangling-byte technique worked only on method-agnostic back-ends; a primitive that requires such a topology must name it, or the next re-test will read as non-reproducible.

## Version/implementation notes

- Triage results expire fast: browser minors ship every two weeks since Chrome 153 (two-week cycle begins with the stable release of **Chrome 153 on 8 September 2026**; Extended Stable stays on its eight-week cycle) and framework minors monthly — always record the checked version and date.
- Vendor advisory, PortSwigger research, OWASP guidance, conference material, Hacktivity, CVE/CWE, changelogs, and cloud or browser bulletins are the default source set; weight vendor and primary research above aggregators.
- Unfamiliar stacks cluster around framework edges (server actions, middleware, edge functions), protocol translators (H2-to-H1, H3-to-H1), and identity bridges (federation, wallet, passkey) — check those seams first.
- When two packs both claim the behavior, keep the oracle in one and reference from the other; triage must not fork duplicate hypotheses.

### Reading a current-research technique into a black-box hypothesis

- PortSwigger's **HTTP Terminator** (Kettle, published 5 Aug 2026, updated 12 Aug 2026; Black Hat USA / DEF CON 34; source and tooling open-sourced) is the reference for turning a research lead into a testable hypothesis. Its discovery loop — **Ideation → Evaluation → Weaponization → Cascade** — is the same triage order this pack uses, so it is worth mapping a lead onto it.
- Its **protocol-ruler** technique is directly reusable as a black-box oracle: because servers have a header-length limit, sending an over-length header and moving the limit boundary by one byte reveals exactly *which* byte sequences a front-end transforms (value rewriting, header dropping, Unicode mojibake) — a transformation signal with no reflection needed. Measured prompt success: 0% naive, 5% when framed around a concrete sub-problem, 30% for the inspiration prompt on newer models; the enduring lesson is the technique, not the model.
- **Micro-inspiration** is the hypothesis-generation rule: feed the model 1–3-sentence RFC fragments, one at a time, and require 1–5 concrete vectors per fragment — large prompts cause context-contamination and collapse novelty (models "over-anchor"; the initial inspiration experiment dropped success to 0%). Feeding all HTTP and SMTP RFCs (138 documents) produced ~15,000 micro-fragments and 30,000+ unique vectors.
- The **evaluation primitive** is worth copying: pair a candidate trigger (sent on its own connection) with a plain request whose response is known-good, and flag any change in the *plain* request's response — this detects unknown cross-request contamination without assumptions about the response shape. A follow-up pass combines the trigger with known-class payloads to map it to an existing class.
- Named novel primitives from that work worth recognizing on a target: **dual-matching `Content-Length` headers** (a server treating two identical, valid `Content-Length` values as zero), the **dangling-byte** technique (a smuggled partial request that withholds one byte to remove a race), **response forking** (one request → two responses without a length disagreement), **status-line injection** (request protocol string copied into the response status line), and **range cache poisoning** (a `Range` response served without `206`). Each is a fingerprint to look for, not a bug to assume.
- Concrete desync triggers the terminator confirmed (use as fingerprints, respect scope/rate rules): `HTTP/1.0` + `Transfer-Encoding: gzip`, `Content-Type: multipart/byteranges` treated as a CL.0 body, `OPTIONS *?xyz`, `Early-Data: 1`, and dual matching `Content-Length` headers. Many are implementation-specific; one variant traced to an F5 Big-IP, another to Citrix NetScaler, and `OPTIONS *?xyz` worked as an early-response gadget on Apache but not in its default configuration.
- **Shared-Parser Confusion** is the general case: a server reuses the same code to parse requests and responses, so a response-only feature (e.g. `multipart/byteranges`) can be exploited in a *request*. Any request honoring a response-only header is a candidate (servers processing `Set-Cookie` in requests are the same shape); the closest prior published work is Orange Tsai's Location SSRF chain in "Confusion Attacks" (Apache). The terminator's anomaly work also surfaced a zero-day in Apache Traffic Server (now tracked as **CVE-2026-63078**).
- When the emerging behavior is desync-shaped, cross-read http-edge-cache/http-desync-cache.md; the durable mitigation the research states is to never use upstream HTTP/1.1, plus method allow-lists and a separate allow-list for methods permitted a request body.

### Cascade discipline (turning one hit into the next lead)

- A confirmed primitive is not the end of the triage; it is the next micro-inspiration. Interrogate every result with the HTTP Terminator's cascade prompt — "consider 1–3 plausible hypotheses that explain it", "do any of these hypotheses have security implications beyond this [class]?", "extrapolate beyond the attack class to the logical extreme" — and log the chain that produced it.
- The terminator's own cascades came from accidents worth imitating as probes: a mangled payload (`GET / /`) surfaced a memory leak while the system was only looking for desync, a permutation plus a `TRACE` body turned a cache-shaped payload into an inline-header response, and that anomaly became the Apache Traffic Server zero-day. Run the engine's second-order questions on purpose, not by luck.
- Keep the rejected corpus: sixteen RQP-enhancement hypotheses were generated and evaluated, one survived (dangling byte). A hypothesis that failed with a named control is reusable knowledge — record the control that killed it, so a later cycle does not re-run the same dead end.
- Human-owned step: broad conceptual jumps stayed with the researcher while the automated system handled generate-evaluate loops. In this workspace the cascade step is the `ASK`/`HYPOTHESIZE` gate, not an automation.
- Re-run the winning primitive once without whatever accident or permutation produced it before you cascade; a discovery that depends on a harness quirk (misclassified clean request, placebo feature, hidden header) cascades into fiction.

### Spec maintenance and the de-facto standard

- Check the *current* specification and its errata before calling a behavior undocumented: RFC 9413 documents that "divergent implementations of a specification emerge over time", and that when quirks become entrenched every implementation must replicate them to interoperate — "bug-for-bug compatible". The TLS example in that RFC: some servers terminated on a ClientHello ending with an empty extension, so clients had to keep sending a non-empty one.
- A deployed quirk may therefore be a de-facto standard, not a target bug — but the same dynamic is why newly clarified spec text is a fresh source of testable divergences. RFC 9413 notes the HTTP specification itself had to be restored to relevance after a period of minimal maintenance.
- Two framing invariants from RFC 9112 §6.1 make cheap per-hop fingerprints: a recipient of an HTTP/1.0 message containing `Transfer-Encoding` MUST treat the framing as faulty even if `Content-Length` is present, and a server MUST NOT send `Transfer-Encoding` in 1xx or 204 responses. A response-side rule honored on the request side is the shared-parser shape; the request-side HTTP/1.0 rule is the desync trigger shape.
- The same invariant list is a cross-implementation oracle: implementations agree on the MUSTs and diverge on undefined/ambiguous input, so the MUSTs are controls and the gaps are where new primitives live.

### Source → primitive map (what a fresh source usually gives you)

| Source type | What it yields | How to use it in triage |
|---|---|---|
| RFC / spec section | a normative rule the peer may not implement | send the compliant edge case, watch for divergence |
| IETF errata / -bis draft | a clarification of previously ambiguous handling | test the old vs clarified interpretation as a differential |
| Vendor changelog | a changed parser/route/auth default in a version range | version-pin, then look for the pre-fix behaviour |
| Vendor advisory / CVE | a concrete component + range + known trigger | map the trigger to this target's fingerprint |
| Conference / research blog | a technique with preconditions and an observable | reduce to a single-request differential before believing it |
| Hacktivity / writeup | the deployment topology that made a technique fire | look for the same topology, not the same payload |
| AI-generated technique | a hypothesis, often context-contaminated | validate on a live, third-party target before treating as real |

### Two-signal fingerprinting discipline

- Never promote on one signal: require at least two independent fingerprints (e.g. a response header plus an error shape, or a cookie name plus a JS chunk name) that agree on the component and version band.
- Attribute per hop: a `Server`/`X-Powered-By` added by a CDN or edge is not the origin; strip each hop's transform before mapping a version to the origin.
- Record the exact observed strings **and** the request that produced them — the triage log is evidence, not memory.
- Prefer black-box observables you can reproduce: header reflection, length-limit behaviour (the protocol-ruler technique), error vocabulary, and timing on a poisoned-vs-clean pair.
- A state-machine delta is a fingerprint too: learned protocol state machines differ per implementation, so the shape that diverges from the documented machine identifies the component as well as the bug.

### When the "unfamiliar" behaviour is actually a known class

- Before opening a novelty lead, run two cheap checks: (1) does the same behaviour already exist in a dedicated pack under a different name; (2) does a plain, unrelated request on the same hop reproduce it (i.e. it is a platform default, not a target bug)?
- Map the behaviour to a class keyword (desync, cache, parser-differential, authz, injection) and search the vendor changelog/advisory for that keyword inside the fingerprinted range — much "novel" behaviour is a documented change.
- If the behaviour is real and owned, stop here: this pack routes, it does not house the finding. Leave a one-line pointer in the owning pack instead of duplicating the oracle.

### Triaging with an autonomous / AI-generated artifact

- A technique or payload generated by an autonomous system (or an AI agent's own output) is a lead until a *live, third-party* differential proves it; a vector "valid in a codebase" but not in a realistic deployment is not applicable. The terminator deliberately did not count a trigger as a discovery until it was proven on a live, third-party site.
- Design the loop as **AI vs Code vs Human**: start AI-heavy, then move validation to deterministic code so results stay reproducible — heavily AI-dependent validation produced false positives (e.g. treating HTTP pipelining as a vulnerability) until deterministic checks were added; the final system reached zero false positives only after code gates decided success.
- When triaging against a documented anomaly, keep the RFC-compliant "clean" control: the value of an anomaly is precisely that a *clean* request produced two responses.
- Anomaly detectors worth adopting as fingerprints: text/binary blends in a response, a repeated `<!DOCTYPE`/`<html`, and inline `HTTP/1.1` header text appearing inside a response body.
- Feed one micro-fragment per generation step and keep examples out of the prompt: a model shown a prior technique as "inspiration" reproduces it instead of inventing (the measured over-anchoring failure); novelty is scored against the source corpus, not by how new the output looks.

## References

- [T0 standard] RFC 9413, "Maintaining Robust Protocols" (IAB, June 2023 — spec ambiguity vs implementation bugs, divergent implementations, bug-for-bug entrenchment, HTTP specification restoration): https://www.rfc-editor.org/rfc/rfc9413
- [T0 standard] RFC 9112, "HTTP/1.1" §6.1 (HTTP/1.0 + `Transfer-Encoding` MUST be treated as faulty framing; `Transfer-Encoding` forbidden on 1xx/204 responses): https://www.rfc-editor.org/rfc/rfc9112
- [T2 research] de Ruiter & Poll, "Protocol State Fuzzing of TLS Implementations" (USENIX Security 15 — state-machine learning, spurious transitions, per-implementation fingerprints): https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/de-ruiter
- [T2 research] PortSwigger, "HTTP/1.1 Must Die" (17 Oct 2025 — upstream HTTP/1.1 fatality, HTTP/2+ as the fix): https://portswigger.net/research/http1-must-die
- [T1 vendor] Chrome two-week release cycle (begins with Chrome 153 stable, 8 Sep 2026; Extended Stable unchanged): https://developer.chrome.com/blog/chrome-two-week-release
- [T2 research] PortSwigger, "Can AI do novel security research? Meet the HTTP Terminator" (5 Aug 2026; protocol-ruler, micro-inspiration, shared-parser confusion, dangling-byte, response forking, status-line injection, range cache poisoning; CVE-2026-63078): https://portswigger.net/research/can-ai-do-novel-security-research
- [T2 research] PortSwigger research index for HTTP desync attacks (`/research/http-desync-attacks-request-smuggling-reborn`, `/research/http1-must-die`): https://portswigger.net/research/request-smuggling
- [T2 research] PortSwigger Web Security Academy for parser and protocol differentials: https://portswigger.net/web-security
- [T2 research] OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10): https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ ; OWASP LLM project: https://owasp.org/projects/top-10-for-large-language-model-applications
- [T2 research] OWASP Smart Contract Top 10 (2025) — sibling taxonomy for the web3-emerging pack: https://owasp.org/www-project-smart-contract-top-10/
- 17_DYNAMIC_TECHNIQUE_ENGINE.md for novelty generation once triage yields a reproducible oracle
- 31_FRESHNESS_WATCHTOWER.md for source priority and ledger format governing this triage
