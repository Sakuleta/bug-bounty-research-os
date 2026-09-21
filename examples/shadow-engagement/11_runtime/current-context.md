# GENERATED — do not edit by hand; rebuilt by the control plane on every mutation (tools/build_context.py)

# Current Context

## ENTRY CONTRACT

# START — Research OS Entry Contract

You are the controller of an authorized security-research engagement.

Do not treat this repository as a document to memorize. Treat it as the persistent state of an ongoing investigation.

## First actions

1. Read `00_control/engagement.yaml`.
2. Read `00_control/research-contract.md`.
3. Read `00_control/identity-binding.yaml`.
4. Read `11_runtime/current-context.md`.
5. Read the current state manifests in `02_surface/`, `03_hypotheses/active/`, `04_cycles/`, and `10_learning/` as needed.
6. Check `11_runtime/run-status.yaml`.
7. Never trust conversation memory over durable state.

## Mission

Maximize useful, defensible security knowledge under explicit authorization.
The engagement objective is defined by durable workspace state; no `/goal` command is required to begin or continue research.
Do not maximize request count, finding count, or dramatic claims.

## Operating loop

```text
OBSERVE
→ MODEL
→ ASK A QUESTION
→ FORM HYPOTHESES
→ CHOOSE THE HIGHEST-INFORMATION SAFE TEST
→ TEST
→ VERIFY THE INSTRUMENT
→ CONTROL THE NEGATIVE OR POSITIVE
→ WRITE EVIDENCE
→ RECORD THE TECHNIQUE RESULT (TECHNIQUE_EVALUATED)
→ UPDATE STATE
→ CHALLENGE THE CONCLUSION
→ CREATE THE NEXT QUESTION
```

## Identity binding

`00_control/identity-binding.yaml` defines the only research identity and session context permitted for this workspace. Before authenticated or identity-sensitive actions:

```text
EXPECTED IDENTITY
→ AUTHENTICATED SESSION
→ MATCH
```

Do not infer identity from the workspace name, email filename, or conversation memory. If the active session does not match, repair or switch to the dedicated authorized session autonomously when possible. Ask the researcher only for a genuinely human-owned authentication factor or an explicit decisi

## ENGAGEMENT POLICY

program:
  name: "Shadow rehearsal (example.com)"
  platform: "DIRECT"
  url: "https://example.com"
  policy_source: "IANA example domain — reserved for documentation; harmless GETs only"
  policy_retrieved_at: "2026-09-21"

researcher:
  public_handle: "NONE"
  identity_reference: "local shadow run"
  profile: "00_control/researcher-profile.yaml"

scope:
  assets:
  - "example.com"
  out_of_scope: []
  allowed_functionality: ["read-only GET"]
  prohibited_functionality: ["any state-changing request"]
  asset_specific_rules: []

accounts:
  researcher_controlled: []
  roles_available: []
  account_creation_rules: "none — no accounts created"
  data_ownership_rules: "researcher-owned only"

traffic:
  required_headers: []
  rate_limits: "one request per action; no automation beyond the controlled executor"
  auth_traffic_policy: "anonymous only"
  automation_policy: "controlled executor only"

reporting:
  rules: "shadow run — nothing to report"
  severity_method: "n/a"
  disclosure: "n/a"
  human_approval_required: true

environment:
  workspace_path: "/Users/mardinli/Desktop/shadow-engagement"
  browser_profile: "none"
  network_context: "researcher workstation"

confidence: "VERIFIED"

## RUN STATUS

engagement_status: "CLOSED"
current_cycle: null
last_state_update: "2026-09-21T17:51:13Z"
last_audit: "2026-09-21T17:51:13Z"
open_high_value_hypotheses: "0"
open_unknowns: "0"
pending_human_gate: false
lab_ready: false

## FRESHNESS

# GENERATED — do not edit by hand; rebuild via tools/researchctl.py (control plane)
components: [{"action": "pinned today; two-week cadence noted", "last_checked": "2026-09-21", "new_primitives": [], "pinned_version": "v153", "sources": ["release-feed"], "target_component": "chrome"}, {"action": "no new primitives", "last_checked": "2026-09-21", "new_primitives": [], "pinned_version": "observed 2026-09-21", "sources": ["executor capture headers"], "target_component": "example.com edge (Cloudflare)"}]

## KNOWLEDGE_SELECTION

auto-selected packs (relevance-ranked, cap 4): http-edge-cache, data-layer, supply-chain, ai-agentic — confirm or override in the cycle knowledge_triage

## ACTIVE CYCLE

# GENERATED — do not edit by hand; rebuild via tools/researchctl.py (control plane)
cycle_id: null

## LAST RESULT

# GENERATED — do not edit by hand; rebuild via tools/researchctl.py (control plane)

# Last Result

- technique: T-000001 (http-edge-differential)
- result: INCONCLUSIVE
- cycle: C-0001
- time: 2026-09-21T17:51:10Z
- interpretation: Single GET only; cache-key behavior of raw vs normalized paths was not exercised.
- learning: For edge cache questions the executor must send the variant pair before any claim; one baseline request is not a negative.
- evidence: E-000001

## UNKNOWN / ASSUMPTION LEDGERS

# Persistent unknowns. Every material unknown gets a terminal state.
unknowns: []

# Assumptions that could change a security conclusion.
assumptions: []


## TOOL / LAB

# Tool registry
tools:
  - name: adb
    state: "MISSING"
    purpose: "Android SDK platform-tools"
    detail: ""
  - name: emulator
    state: "MISSING"
    purpose: "Android Emulator"
    detail: ""
  - name: docker
    state: "READY"
    purpose: "Docker"
    detail: "Docker version 29.4.0, build 9d7ad9f"
  - name: node
    state: "READY"
    purpose: "Node.js"
    detail: "v25.9.0"
  - name: python3
    state: "READY"
    purpose: "Python 3"
    detail: "Python 3.14.6"
  - name: nuclei
    state: "MISSING"
    purpose: "ProjectDiscovery nuclei"
    detail: ""
  - name: ffuf
    state: "MISSING"
    purpose: "ffuf"
    detail: ""
  - name: mitmproxy
    state: "MISSING"
    purpose: "mitmproxy"
    detail: ""
  - name: jadx
    state: "READY"
    purpose: "jadx"
    detail: "1.5.6"
  - name: frida
    state: "MISSING"
    purpose: "Frida tools"
    detail: ""
  - name: ios-simulator
    state: "FAILED"
    purpose: "Xcode simulator (macOS only)"
    detail: "xcrun: error: sh -c '/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild -sdk /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Dev"

status: FAILED
provisioner: tools/provision.py
isolated_lab: lab/
installation_policy: ai-runtime-managed
auto_exploit: false

## KNOWLEDGE/http-edge-cache

# HTTP / Edge / Cache

> SCOPE: Load when the target sits behind a CDN, reverse proxy, WAF, or cache, or when HTTP parsing behavior itself is the research surface.

## Research families

Request-boundary families — a front-end and a back-end disagree about where a request ends:

- HTTP/1.1 request smuggling and desync (CL.TE, TE.CL, TE.TE, H2.CL, H2.TE)
- Dangling-byte and zero-length prefix attacks (0.CL, CL.0)
- Client-side and browser-powered desync
- Response queue poisoning (no cache required)
- CRLF-powered / header-injection desync — an injection primitive (canonically an Nginx `proxy_pass http://backend$uri` or `return 302 $uri` directive, where `$uri` is URL-decoded so `%0d%0a` re-becomes a real CRLF) that turns one request into a smuggled prefix, a request split, or an injected `Content-Length`/`Transfer-Encoding`. Header injections are not low-impact bugs; a single injectable header is enough for a CL.TE desync.
- Request tunnelling — the front-end and back-end sockets are not shared, so the primitive is blind; distinct from smuggling because cross-user exploitation is blocked (non-blind HEAD and `Expect: 100-continue` variants recover the response)
- Reverse desync — response header injection / response splitting against a keep-alive origin (Amit Klein's 2004 lineage), now mostly blocked by browser/edge over-read
- Hop-by-hop framing abuse — an intermediary removes a header named in `Connection` at one hop but not the next, so the two hops frame the same message differently (RFC 9110 §7.6.1 mandates the removal; RFC 9113 §8.2.2 says H2 must treat such fields as malformed)
- Shared-parser confusion (one parser instance reused across logically separate components) and response forking — both surfaced as *classes* by the 2026 HTTP Terminator work; response fork

## KNOWLEDGE/data-layer

# Data Layer

> SCOPE: Load when list, search, filter, pagination, aggregation, export, resolver, or search-engine behavior can leak records or bypass authorization, across REST, GraphQL, direct query, or engine DSL surfaces.

## Research families

- ORM authorization-filter leakage (missing or inconsistent scope on querysets)
- Relationship and nested-object traversal (parent authorized, child unscoped)
- Aggregation, count, and facet side channels revealing hidden records
- Raw-query and query-builder escape (raw fragments, literal, text blocks)
- NoSQL operator semantics (comparison, regex, element-match, schema bypass)
- Search, sort, filter, and pagination differentials (cursor, offset, total counts)
- Export, report, and bulk-fetch paths with weaker checks than list views
- GraphQL resolver versus REST authorization mismatches on the same data
- Cache-versus-database authorization mismatch (cached aggregate served past revocation)
- JSON and query serialization mismatches (null, array, object, negative, string-null)
- Soft-delete, archive, and trash scope gaps (row dropped from list but alive in aggregate, search, export, or history)
- Field-level versus object-level authorization (guarded container exposes an unguarded field or nested edge)
- Filter-builder precedence bugs (an injected `OR`/`Q` clause widens past the mandatory tenant/owner predicate)
- Nested-filter and bracketed query-parameter operator injection (`filter[owner]=`, `field[$ne]=` mapped into the query language)
- Join / `through`-table scope gaps (association row scoped on the parent but not the join)
- Secondary-index authorization (denormalized search/cache index carrying rows the primary store would scope out — confirm per engagement)
- GraphQL global-ID resolution (`node`/`nodes`) reaching ob

## KNOWLEDGE/supply-chain

# Supply Chain / CI-CD

> SCOPE: Load only when the repository, build, artifact, or deployment pipeline asset is explicitly in 