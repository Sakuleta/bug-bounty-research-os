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

# Runtime-only engagement configuration.
# Populate ONLY from authoritative program sources.
# Never copy values from another engagement.

program:
  name: "<PROGRAM_NAME>"
  platform: "<HACKERONE|BUGCROWD|INTIGRITI|DIRECT|OTHER>"
  url: "<PROGRAM_URL>"
  policy_source: "<AUTHORITATIVE_POLICY_REFERENCE>"
  policy_retrieved_at: "<TIMESTAMP>"

researcher:
  public_handle: "<RESEARCHER_HANDLE_OR_NONE>"
  identity_reference: "<SECURE_IDENTITY_REFERENCE>"
  profile: "00_control/researcher-profile.yaml"

scope:
  assets: []
  out_of_scope: []
  allowed_functionality: []
  prohibited_functionality: []
  asset_specific_rules: []

accounts:
  researcher_controlled: []
  roles_available: []
  account_creation_rules: "<RULES>"
  data_ownership_rules: "<RULES>"

traffic:
  required_headers: []
  rate_limits: "<PROGRAM_LIMITS_OR_SAFE_DEFAULT>"
  auth_traffic_policy: "<RULES>"
  automation_policy: "<RULES>"

reporting:
  rules: "<RULES>"
  severity_method: "<PROGRAM_RULES>"
  disclosure: "<PROGRAM_RULES>"
  human_approval_required: true

environment:
  workspace_path: "<WORKSPACE_PATH>"
  browser_profile: "<DEDICATED_PROFILE_REFERENCE>"
  network_context: "<RESEARCH_NETWORK_CONTEXT>"

confidence: "VERIFIED|PARTIAL|UNKNOWN"

## RUN STATUS

engagement_status: "BOOTSTRAP"
current_cycle: null
last_state_update: null
last_audit: null
open_high_value_hypotheses: "0"
open_unknowns: "0"
pending_human_gate: false
lab_ready: false

## FRESHNESS

# GENERATED — do not edit by hand; rebuild via tools/researchctl.py (control plane)
components: []

## KNOWLEDGE_SELECTION

auto-selected packs (relevance-ranked, cap 4): supply-chain, data-layer, ai-agentic, business-logic — confirm or override in the cycle knowledge_triage

## ACTIVE CYCLE

# GENERATED — do not edit by hand; rebuild via tools/researchctl.py (control plane)
cycle_id: null

## LAST RESULT

# Last Result

NONE

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

## KNOWLEDGE/supply-chain

# Supply Chain / CI-CD

> SCOPE: Load only when the repository, build, artifact, or deployment pipeline asset is explicitly in scope; pipeline access alone is never the finding.

## Research families

- Dependency confusion and private-package shadowing (registry priority, namespace reservation)
- Typosquatting and name-normalization collisions (PEP 503 folding, npm scope-to-registry association, case/separator variants)
- Lockfile and manifest integrity (unpinned ranges, lockfile bypass, transitive substitution)
- Build trigger trust (fork PR builds, external contributor scripts, label-gated workflows)
- Pull-request workflow trust (approval bypass, stale-review reuse, bot auto-merge)
- Webhook and integrator verification (unsigned events, wrong scheme/method, replayed deliveries, secret rotation)
- Webhook replay and dedupe (timestamp/nonce freshness, delivery-ID reuse)
- Artifact provenance and substitution (unsigned builds, mutable tags, registry overwrite, copied attestations)
- Container build secrets (build-arg, layer, cache, and history leakage)
- IaC state and plan exposure (state files, plan output, destroy-shaped operations)
- Deployment pipeline authorization (environment promotion, approver scoping, secret scoping)
- Runner and cache poisoning (shared runners, poisoned cache keys, artifact reuse across branches)
- Release-build integrity vs. cache reuse (a release/publish job must not consume a writable cache)
- Third-party action/workflow compromise by mutable-reference mutation (tag retro-move, fork of the action)
- Trusted-publishing / OIDC trust misconfiguration (over-loose publisher or trust-policy match)
- OIDC subject-claim confusion (path/namespace recycling, wildcard subject, reusable-workflow identity)
- Package publishing bypass of the intended r

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

## KNOWLEDGE/ai-agentic

# AI / Agentic Applications

> SCOPE: Load only when the target actually exposes AI or agentic functionality (assistant, copilot, agent, RAG search, tool-using workflow, MCP server).

## Research families

Injection and retrieval:

- Direct prompt injection crossing a trust or capability boundary
- Indirect prompt injection via ingested third-party content
- Stored injection via RAG corpus, memory, or shared workspace
- Retrieval authorization bypass (unauthorized documents returned)
- RAG corpus poisoning by a lower-privilege contributor
- Retrieval-layer ACL drift: chunk, citation, or embedding returned where the owning document's ACL denies the requester
- Embedding inversion and cross-context vector-store leakage
- Provenance loss: untrusted content (a retrieved page, a ticket, a commit message) re-labeled or treated as an instruction
- Multimodal injection: instruction hidden in an image / audio / PDF that the model reads — including adversarial perturbations, not only visible hidd