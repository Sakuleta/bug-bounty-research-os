# Dynamic Technique Engine

> Boundary: this file GENERATES new techniques (unknown-unknown engine). `12_knowledge/novelty-research.md` is the per-technique operational checklist used to validate one candidate. Generate here, validate there.

The technique library is a floor, not a ceiling. Known classes catch known bugs; new classes win engagements.

## Unknown-unknown pipeline

Run every anomalous observation through all eight stages. Skipping a stage is how novel classes are missed.

1. OBSERVED BEHAVIOR — Record raw, tool-independent facts: bytes sent, bytes received, timing, state change. No interpretation yet.
   - Q: What exactly happened, stripped of what I expected to happen?
2. ASSUMPTION — Name the belief each component acted on (e.g. "body ends here", "this header is single-valued", "this token is opaque").
   - Q: What must each component believe for this behavior to look correct to it?
3. DEPENDENCY — Map who trusts whom: which component consumes another's output without re-validating it.
   - Q: Which downstream decision inherits an upstream parse without a second check?
4. BOUNDARY — Locate the conversion point: proxy/backend, frontend/backend, parser/serializer, protocol version switch, auth layer/app layer.
   - Q: Where does representation or authority change hands?
5. INVARIANT — State the property that must hold across the boundary (e.g. "both sides agree on message length", "identity verified before action").
   - Q: What single sentence, if false, breaks security here?
6. ATTACK PRIMITIVE — Convert the broken invariant into one reusable action: smuggle bytes, inject a key, replay a state, confuse an identity.
   - Q: What is the smallest input that makes the two sides disagree on demand?
7. COMBINATION — Pair the primitive with a second, individually harmless behavior (cache write, redirect, retry, webhook, state restore).
   - Q: What boring feature turns this disagreement into impact?
8. NEW HYPOTHESIS — Write a falsifiable claim: precondition, oracle, negative control, expected impact. File it in `03_hypotheses/`.
   - Q: What observation would prove this wrong, and what would prove it real?

### Worked mini-pass

Observation: `POST` with `Content-Length: 4` plus trailing `GET /admin` bytes returns `200` fast, then the NEXT response is `403` slow. Assumption: terminator saw one complete request; backend saw request plus prefix of another. Dependency: backend trusts terminator's framing. Boundary: terminator/backend. Invariant broken: "one upstream message equals one downstream message". Primitive: dangling suffix. Combination: queue suffix ahead of an authenticated state change. Hypothesis: filed with timing oracle + fresh-connection control.

## Collision catalog

A new class exists wherever two components hold incompatible assumptions about the same bytes, identity, or state. Pattern: frontend assumes X / backend assumes Y / proxy assumes Z / browser normalizes A.

1. Length disagreement (proxy assumes `Transfer-Encoding`, backend assumes `Content-Length`). Derive: request smuggling variants per version pair. Probe with dual-framing and timing oracle.
2. Dangling-byte desync — WORKED EXAMPLE (PortSwigger HTTP Terminator research, Aug 2026, https://portswigger.net/research/http-terminator ; summary https://thehackernews.com/2026/08/ai-assisted-http-terminator-finds-novel.html):
> NOTE: dated instance; see 31_FRESHNESS_WATCHTOWER.md ledger for current primitives. a terminator/adapter layer consumes a request but leaves trailing bytes unclassified as belonging to any message; the backend re-attaches them to the next request on the connection. Frontend assumes "request fully consumed", backend assumes "bytes start a new message", proxy assumes "connection is clean". Primitive: append ambiguous suffix bytes after a framed body. Combination: pair with an authenticated state-changing endpoint queued second to convert a parse disagreement into cross-request action. Hypothesis template: "If suffix S is dangling, then second request R executes with victim context; negative control: S without keep-alive reuse shows no effect."
3. Normalization split (WAF assumes raw string, app decodes once more: double-URL-encoding, Unicode, plus-vs-space). Derive: per-decoder matrix, test each layer's view independently.
4. Cache-key vs auth-state split (cache assumes URL+host is identity, backend assumes cookie/session is identity). Derive: authenticated-response caching, key-injection via unkeyed header.
5. Serialization boundary (frontend sends JSON, gateway converts to query/form, backend parses types loosely: `true` vs `"true"`, duplicate keys, array vs scalar). Derive: type-confusion auth bypass, mass-assignment via converted shape.
6. Browser-vs-server origin split (browser normalizes trailing dot, case, or IDN; server compares literally for CORS/cookie scope/allowlist). Derive: scope-expansion where browser sends credentials but server sees a "different" host as allowed.

Rule: each collision entry must name X, Y, Z explicitly. "Parser differential" without naming both parsers is not a hypothesis.

## Combination operators

Primitives alone rarely pay. Apply these operators to turn a disagreement into impact:

- STORE then REUSE: primitive plants data (cache, object store, draft, search index); a later read executes it with higher trust.
- PREFIX then HIJACK: primitive controls the head of the next message, redirect, query, or command; the victim request completes it.
- DOWNGRADE then REPLAY: force HTTP/1.1 fallback, legacy auth, or unencrypted retry; replay captured bytes through the weaker path.
- RETRY then AMPLIFY: error handler, webhook, or queue worker replays the poisoned input with service identity instead of user identity.
- SPLIT then CONFUSE: one component sees two objects where the other sees one (duplicate keys, multipart boundaries, JWT body vs signature inputs).

Pick at most two operators per hypothesis. More than two means the primitive is not understood yet — return to stage 6.

## Hypothesis template

```text
H-ID: <id> | source: engine-collision-<#>
Precondition: <component versions + config that must hold>
Primitive: <one sentence>
Combination: <operator + boring feature>
Oracle: <exact observable delta>
Negative control: <near-identical run expected clean>
Impact: <state change / data / auth crossing>
```

## When to run

Run the full pipeline on: any response delta without a known cause, any version/config the checklist has no entry for, any fresh watchtower primitive, any BLOCKED branch with an unexplained anomaly. Do not run it on clean denies — those go to NEEDS_PIVOT, not invention.

## Anti-patterns

- Testing a public PoC before writing the precondition line. Relevance first, packets second.
- Filing "desync?" with no named parsers and no oracle. That is a topic, not a hypothesis.
- Counting a WAF block page as a negative control. Controls must reach the same backend path.
- Chaining three primitives before one reproduces alone. Isolate, then combine.

## Novelty questions

1. What does this stack parse twice?
2. What gets normalized differently by adjacent components?
3. What is trusted because it came from a different service?
4. What security state survives logout, downgrade, expiration or deletion?
5. What representation is protected while another is not?
6. What happens at protocol conversion boundaries?
7. What new capability is reachable by chaining two individually harmless behaviors?
8. Combination: which two confirmed-but-harmless behaviors, executed in one sequence, produce a state neither produces alone?
9. Combination: which cached/stored artifact from behavior A becomes attacker-controlled input to behavior B?
10. Combination: which retry, webhook, redirect, or restore path replays my input with higher privilege than the original request?

## Evidence standard

A new technique is not a finding until BOTH hold:

1. Target-specific impact — the primitive fires against THIS target (not a lab twin): state change, data return, or auth crossing, with request/response evidence.
2. Negative control — a near-identical input WITHOUT the hypothesized cause produces NO effect (e.g. same suffix over fresh connection, same sequence without cache reuse). Paste both.

Without the negative control, the result is an anomaly, not a technique. Record it as a `TECHNIQUE_EVALUATED` event (`researchctl technique evaluate`; `10_learning/technique-discoveries.md` is its projection) and move on.
