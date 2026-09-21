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
- Multimodal injection: instruction hidden in an image / audio / PDF that the model reads — including adversarial perturbations, not only visible hidden text

Tools and agency:

- Tool misuse: browsing, file, code-execution, or messaging tools turned against internal resources
- Excessive agency: irreversible or high-privilege actions without confirmation
- Cross-tool privilege escalation (read tool output becomes write tool input)
- Toxic agent flows: fully trusted tools plus untrusted data (a malicious GitHub issue drives private-repo reads into a public PR)
- Output-sink execution: model output reaching a shell, `eval`, SQL builder, file path, or the DOM unsanitized (LLM05)
- Human-in-the-loop bypass on sensitive operations

Agent identity, memory, and delegation:

- Agent identity and privilege boundaries (whose authority does the agent act under)
- Memory contamination across sessions, users, or tenants
- Experience/self-improvement memory poisoning: poisoned "successful task" records imitated later
- Agent-to-agent delegation without authority attenuation (sub-agent inherits full privileges)
- Inter-agent (A2A) message spoofing and unauthenticated agent-to-agent trust

MCP and connectors:

- MCP server and connector trust boundaries
- MCP proxy / OAuth delegation abuse (confused deputy, token passthrough, consent-skipping)
- Local MCP server trust (one-click config that executes an attacker-chosen command)
- MCP tool poisoning: a compromised server's tool *descriptions* steer the model, plus rug-pull (description changed post-approval) and cross-server shadowing
- MCP header/body mirror desync: routing or rate-limiting acts on `Mcp-Method`/`Mcp-Name`/`Mcp-Param-*` while the server executes the body
- MCP state-handle hijacking (2026-07-28 replaced protocol sessions with server-minted handles)
- MCP Client ID Metadata Document SSRF and localhost redirect-URI impersonation
- MCP result-cache leakage (`cacheScope`/`ttlMs` on per-principal list results)

Other:

- Unsafe output handling (rendered markdown, links, actions executed without validation)

## Preconditions

- A model or agent acts with *someone's* authority over *something*: data, tools, or downstream users. No authority plus no tool equals no security finding.
- Attacker-controlled or third-party content reaches the model context: user input, retrieved documents, web pages, emails, tickets, file contents, tool outputs.
- A boundary exists to cross: another user's data, a higher-privilege action, an internal system, a different tenant, or an irreversible side effect.
- For RAG issues: a shared or multi-source corpus where the requester must not see every document, or where contributors differ in privilege from readers.
- For tool issues: at least one tool with network, file, code-execution, or messaging capability reachable from model-influenced input.
- For memory issues: persisted state (conversation memory, profile, cache) that survives sessions or is shared across trust boundaries; for experience memory, the agent re-uses records of past "successful" tasks as exemplars.
- For MCP issues: a Model Context Protocol server or connector whose advertised tools, resources, or prompts cross privilege levels.
- For delegation issues: a parent agent able to spawn sub-agents or call sibling agents whose toolsets exceed the parent's granted scope.
- Prompt injection does not need to be human-visible: any byte sequence the model parses (zero-width, base64, emoji, another language, white-on-white text) qualifies — the "sneaky" tag is not required.
- For multimodal issues: the pipeline OCRs, transcribes, or embeds attacker media before the model sees text, so text-only input filters do not apply; the media itself may be clean to a human reviewer.
- For MCP proxy / OAuth issues: the server is an OAuth *client* to a downstream API with a static client ID, dynamically registers MCP clients, and the downstream auth server issues a consent cookie.
- For local MCP issues: the client supports one-click server install/config that executes a command on the user's machine.
- For state-handle issues: the server mints a handle (cart ID, workflow ID) and trusts the caller to present it back, without binding it to the authenticated principal.
- For header-mirror issues: an intermediary (LB, gateway, rate limiter) or the server itself uses mirror headers as a source of truth while another component uses the body.
- For MCP cache issues: a shared intermediary caches MCP responses and a per-principal list result is marked `cacheScope: "public"` with a non-zero `ttlMs`.
- For CIMD issues: the authorization server accepts URL-based `client_id`s (Client ID Metadata Documents) and fetches them, or the client identifies itself by metadata URL with a `localhost` redirect URI.
- For A2A issues: identity travels only in HTTP headers (the JSON-RPC payload carries none), and the client trusts an Agent Card it did not validate to choose the endpoint, skill, or security scheme.

## Oracles

Injection and authority:

- Authority differential: the same request refused or scoped when asked directly, but fulfilled when routed through injected content, retrieved documents, or tool chaining.
- Retrieval leak: query as low-privilege user returns document chunks, citations, or embeddings whose ACL excludes that user — verify against direct document access denial.
- Poisoning persistence: contributor-planted instruction in the corpus executes for a *different* user session (stored injection); confirm the victim session never supplied the instruction.
- Toxic flow: an untrusted artifact (issue, PR body, commit message) causes reads from a second repository/tenant and a write to the attacker-visible one, with only trusted tools in the call log.
- Provenance re-labeling: content that entered as clearly-untrusted (retrieved page) is later treated as an instruction; the tell is the same text used as data in one turn and as a directive in the next.

Tools and agency:

- Tool SSRF/file-read: model-controlled URL or path argument in a browsing/file tool reaches an internal address or unauthorized file and returns content into the visible answer.
- Agency breach: agent performs an irreversible action (send, delete, publish, pay, merge) with no confirmation step where the UI promises one, or escalates from read-only request to write execution.
- Cross-tool escalation: output of a read-only tool (search, read) is passed as authoritative input to a privileged tool (execute, admin API) without re-authorization.
- Output-handling execution: rendered answer contains attacker-chosen markdown image, link, or plugin invocation that exfiltrates data or triggers action on view in the real client.
- Output-sink execution: model output reaches a shell, `eval`, a SQL builder, a file path, or the DOM unsanitized and the payload executes (LLM05) — the proof is execution at the sink, not the payload surviving in the chat text.
- System-prompt-derived bypass: the prompt reveals a limit, threshold, role table, or credential that lets a lower-privilege principal exceed it (LLM07) — require the disclosed rule to change an authorization decision.

Memory and delegation:

- Memory bleed: new session or different user receives facts, instructions, or data written by a prior session or another user.
- Experience poisoning: after ingestion of attacker-supplied material, a later benign-similar task retrieves the poisoned "experience" and the agent adopts the unsafe procedure, with the drift persisting across sessions and the transcript showing no injection.
- Delegation breach: sub-agent or sibling agent performs an action the invoking agent's own policy would refuse, with no re-authorization at the delegation boundary.
- Inter-agent spoof: a message claiming to come from a trusted sibling agent is accepted without authentication (no sender signature, no channel binding), and triggers a privileged action.

MCP transport / IAM:

- MCP session confusion (2025-11-25 and earlier): a resource/tool reachable with a *different* client's `Mcp-Session-Id`, or a resumable stream replaying another session's events.
- Confused-deputy consent skip: an authorization code for the MCP proxy is minted to an attacker-registered `redirect_uri` because the downstream auth server saw a prior consent cookie and skipped consent.
- Token passthrough: the MCP server forwards a token not issued *to itself* to the downstream API, or accepts tokens it did not validate an audience for.
- OAuth-discovery SSRF: a malicious MCP server populates `resource_metadata` / `authorization_servers` / `token_endpoint` with an internal or loopback URL, and the client fetches it.
- Local server config execution: a client's one-click config runs an attacker-supplied startup command with the client's privileges (curl/ssh-key exfil, `sudo`, obfuscated payload).
- Header/body mirror mismatch: send `Mcp-Method`, `Mcp-Name`, or `Mcp-Param-*` that disagree with the JSON-RPC body. Conforming server = `400` + `HeaderMismatch` (`-32020`); a server that executes the body while an intermediary routes on the header is the desync target. Watch the Base64 sentinel (`=?base64?...?=`) path: the server MUST decode an encoded `Mcp-Name`/`Mcp-Param-*` before comparing it to the body.
- State-handle hijack: present a guessed handle for another principal's cart/workflow; correct behavior is rejection; if the call succeeds and the original user's state changes, the handle was used as authentication.
- CIMD SSRF: register a `client_id` that is a URL pointing at an internal/link-local host and observe the authorization server fetch it (timing, errors, collaborator hit).
- Localhost redirect impersonation: claim a legitimate client's metadata URL as your `client_id` and bind any `localhost` port as `redirect_uri`; if the AS accepts and the code lands on your listener while the user saw the legitimate client name, the AS fails to bind the redirect to the real client.
- Cached list leak: a per-principal `tools/list`/`resources/list` marked `cacheScope: "public"` (with `ttlMs` > 0) is served from a shared cache to a second principal, exposing tool names, schemas, or resource URIs that principal should not see.
- Scope inflation: an over-broad scope advertised in discovery metadata is accepted by the server and authorizes a tool or resource call the requested scope should not cover.
- MCP audience confusion: a token issued for another resource (wrong audience) is accepted by the MCP server, or the server forwards a client token downstream unmodified.

Multimodal:

- Perturbation injection: a human-clean image or audio clip (adversarial perturbation blended in) steers the model to attacker-chosen output or later dialog — the payload is not readable text, so text filters and reviewers pass it.

A2A:

- Task-boundary breach: `tasks/list` or `tasks/get` returns tasks not visible to the authenticated client, or a `tenant` routing identifier that does not match the selected Agent Card `AgentInterface` is accepted.
- Card trust: a client resolves endpoint/skills/security scheme from an Agent Card it did not validate (no signature/domain binding), so a replaced or spoofed card redirects it to an attacker-controlled A2A endpoint.

Oracle → evidence table (what to record per crossing):

| Boundary | Benign control | Crossing evidence to capture |
|---|---|---|
| Another user's data | direct fetch as low-priv user = 403 | retrieved chunk/citation text, embedding hit, or count that includes it |
| Higher-privilege tool | direct tool call denied by policy | tool call executed, side effect read back in target system |
| Irreversible action | UI shows a confirmation gate | action completed with no confirmation in transcript or server log |
| Tenant isolation | cross-tenant request rejected | second tenant's content or action served to first tenant |
| Agent identity | agent acts as its own principal | agent acted as the invoking user with no attenuation |
| MCP session (≤2025-11-25) | own `Mcp-Session-Id` sees only its own events | second session's events/tool list delivered under the borrowed ID |
| MCP state handle (2026-07-28) | own handle resolves to own state | handle presented by another principal mutates/returns original state |
| MCP OAuth | consent screen shown for a new client | code delivered to attacker `redirect_uri` with no consent screen |
| MCP mirror headers | mismatched header/body rejected with 400 `-32020` | request executed or routed on the mismatched header value |
| MCP result cache | own session gets own list | `cacheScope: "public"` list served cross-principal through a shared cache |
| A2A task visibility | own principal sees only own tasks | foreign task returned, or mismatched `tenant` accepted |

## Minimal safe proof

1. Establish the baseline: perform the action directly (direct ask, direct document fetch, direct tool call) and record the refusal or scope as the secure-behavior control.
2. Single-boundary test: introduce one injection at a time (one document, one tool parameter, one memory entry) with a unique canary token; never poison shared corpora visible to real users — use researcher-created documents, sandboxed indexes, or your own tenant.
3. Prove crossing, not trickery: a jailbreak that changes tone but grants no new data or capability is not a finding; require the authority differential from the Oracles section.
4. Tool tests use collaborator endpoints and researcher-owned files only; never point browsing/file tools at internal hostnames discovered during recon, and never exfiltrate real third-party data.
5. Memory tests use two researcher-controlled sessions (one writes, one reads); never contaminate shared production memory or read another real user's stored context. For experience-memory tests, seed a researcher-owned "successful task" record and confirm a *later, benign* task retrieves it.
6. MCP transport/session tests use a researcher-authored server or a connector scoped to research resources; capture the `Origin`, `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, and (≤2025-11-25) `Mcp-Session-Id` values sent, since a missing/incorrect one is often the whole bug. Record the negotiated protocol revision first — session probes against a 2026-07-28 server prove nothing.
7. MCP OAuth tests use a researcher proxy and two researcher client registrations; drive the consent-skip path only against researcher accounts and stop the moment a code lands on a researcher redirect. CIMD/SSRF probes use a collaborator URL, never a real internal host.
8. Local-server tests, if any, run the supplied command only in an isolated VM/container you control — never execute an untrusted startup command on a host with real credentials.
9. Multimodal and header-mirror tests stay researcher-owned: your own media, your own proxy, your own cache; stop before poisoning anything a real user or shared worker reads.
10. Stop conditions: cross-tenant data returned, irreversible action executed, injection visible to other users, MCP tool performing an unapproved privileged operation, or a poisoned memory reaching a production session — halt, preserve evidence, clean up researcher artifacts, report.

## False positives

- Model roleplay or tone change with no data or capability gain — the question is unauthorized capability, not gullibility; require the differential.
- Hallucinated citation or fabricated document content that matches no real restricted record — rule out by checking the alleged source document's actual ACL and content.
- Refusal-bypass producing only public knowledge — no boundary crossed; require non-public data or privileged action.
- Tool error messages echoing the malicious input back verbatim without executing it — echo is not execution; require the side effect or returned internal content.
- RAG returning the attacker's *own* planted document to the attacker — correct behavior; require a victim-context retrieval.
- Confirmation dialog present and enforced server-side where a UI-only skip was suspected — rule out by replaying the confirmation-bypass request directly and observing rejection.
- Markdown rendering of attacker links in a client that neutralizes them (no auto-fetch, no credential attach) — require actual exfiltration or action in the real client.
- Sub-agent running with identical tool restrictions and independent confirmation gates that hold on direct replay — delegation mirroring the parent's policy correctly; require the scope or confirmation gap.
- System-prompt disclosure of generic behavioral instructions with no embedded secrets, credentials, or hidden capability grants — require leaked material that enables a boundary crossing.
- Tool that validates its own arguments server-side and rejects the model's malicious parameter (refused file path, blocked URL scheme) — the tool boundary held; require the executed side effect.
- Injection that only changes the *model's own answer text* inside the same user's session — self-influence with no crossing; require another principal, a tool, or an action.
- MCP `Origin` header absent on a non-browser client — the transport permits it for non-browser clients; require an actual cross-origin browser context (or a DNS-rebinding proof) to claim the Origin gap.
- Resumable stream replaying the same session's own events after `Last-Event-ID` — expected cursor behavior (≤2025-11-25); require another session's events.
- Multimodal payload that the tool pipeline rejects before the model sees it (OCR off, media sanitized) — require the instruction to actually reach a model with authority.
- MCP server that rejects a `javascript:`/`data:` authorization URL and uses non-shell URL opening — the client-side control held; require JavaScript/command execution or code delivery to an attacker redirect.
- "Token passthrough" where the downstream API independently validates audience and scope — the control exists downstream; require the token to be accepted for a resource it was not issued for.
- Scope that looks broad in metadata but is enforced server-side per operation — require the over-broad scope to actually authorize an unauthorized tool/resource call.
- Greedy scope request with no `scope` parameter in the initial `WWW-Authenticate` challenge — the MCP scope-selection guidance tells clients to fall back to `scopes_supported`; that fallback is spec-directed, not a client flaw. Require a server that treats claimed scopes as sufficient without its own authorization logic.
- Tool annotations that a client treats as untrusted — the specification says clients MUST treat annotations as untrusted unless they come from trusted servers, so an annotation that *looks* dangerous is not by itself a finding; require the behavior it was claimed to cause.
- Tool-name collision across two servers (both expose `search`) — the spec scopes uniqueness to a single server and tells aggregators to disambiguate (e.g., server prefix); a collision is expected. Require a collision that actually reroutes a call the user intended for the trusted tool.
- `Mcp-Session-Id` echoed to a 2026-07-28 server, or a GET to its MCP endpoint — correct behavior is to ignore the header and answer `405 Method Not Allowed`; no session is minted in that revision. Require an implementation that still honors sessions.
- Output that renders in the chat but never reaches a sink (no shell/DOM/SQL execution) — display in the model's own UI is not improper output handling; require execution downstream.
- System-prompt text that leaks only generic behaviour, with no secret and no delegated control — LLM07 treats disclosure alone as non-impactful; require secrets or a bypassed authorization check.
- A scope string that *looks* broad but no tool or resource is actually reachable with it — require the scope to authorize a call it should not.
- Cache hit across principals where the cached item is genuinely identical for all callers (public catalog) — require the cached payload to be principal-specific (per-user tool list, per-tenant resource URI).
- A2A `401`/`403` on an unauthenticated call — the control fired; require the request to succeed under an identity that should not see the task.

## Version/implementation notes

### Taxonomy version pinning

- Map findings to the current **OWASP Top 10 for Agentic Applications (2026)**, not the older LLM-only list, and record which revision was used. The ten entries are **ASI01** Agent Goal Hijack, **ASI02** Tool Misuse, **ASI03** Identity & Privilege Abuse, **ASI04** Agentic Supply Chain Vulnerabilities, **ASI05** Unexpected Code Execution, **ASI06** Memory & Context Poisoning, **ASI07** Insecure Inter-Agent Communication, **ASI08** Cascading Failures, **ASI09** Human-Agent Trust Exploitation, **ASI10** Rogue Agents. The launch note supplies the named incidents: EchoLeak → ASI01, Amazon Q → ASI02, GitHub MCP exploit → ASI04, AutoGPT RCE → ASI05, Gemini Memory Attack → ASI06, Replit meltdown → ASI10.
- The LLM-only taxonomy still applies to the model layer: **LLM01:2025** Prompt Injection splits **direct** (user's own input) from **indirect** (external content the model ingests), and states outright that RAG and fine-tuning do **not** fully mitigate prompt injection — so a deployment cannot claim "we use RAG, so injection is handled". Siblings: LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM04 Data/Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption.
- A **2026 edition** of the OWASP GenAI LLM Top 10 exists (published Aug 3, 2026): re-ranked entries, expanded scenarios, mapping to NIST/MITRE ATLAS/CWE and to the Agentic Top 10. Pin which edition a finding is mapped against; the 2025 entry IDs above remain the stable reference for the concepts as written.
- MITRE ATLAS technique IDs make reports machine-checkable: `AML.T0051.000` (LLM Prompt Injection: Direct), `AML.T0051.001` (Indirect), `AML.T0054` (LLM Jailbreak Injection: Direct).

### LLM06 Excessive Agency — the root-cause triad

- LLM06 frames the finding as one of **excessive functionality** (the tool exposes verbs the task doesn't need — a "read repo" extension that also deletes), **excessive permissions** (the extension's downstream identity has more than the task needs — SELECT-only intent but UPDATE/DELETE credentials), or **excessive autonomy** (high-impact actions execute with no human approval). Name which of the three is present; each maps to a different remediation.
- Two controls to check on the target: **complete mediation** (authorization enforced in the downstream system, not decided by the LLM) and **execution in the user's context** (the extension acts as the authenticated user with minimum scope, not a generic privileged identity). Their absence is the precondition for the agency oracles above.
- LLM06 also lists the triggers that make an agency bug reachable: hallucination/confabulation from *benign* prompts, and direct/indirect injection from a malicious user, a compromised earlier extension invocation, or a compromised peer agent in a multi-agent system.

### LLM08 Vector and Embedding Weaknesses — RAG attack catalog

- **Unauthorized access / data leakage**: embeddings of sensitive content retrieved without the requester's ACL — the oracle is the sensitive *content* surfacing in retrieved chunks.
- **Cross-context leak in multi-tenant vector stores**: two classes of users share one vector DB and one class's embeddings are retrieved for the other's query. The stated mitigation is a permission-aware vector store with strict logical/access partitioning.
- **Embedding inversion**: an attacker inverts embeddings to recover a significant amount of the source text — confidentiality loss even when the document endpoint is ACL'd.
- **Data poisoning**: intentional (insiders, prompts, data seeding, unverified providers) or accidental. The canonical scenario is hidden text (white-on-white) in a document that a RAG screening pipeline ingests **after formatting is stripped**; the fix is extraction that ignores formatting and detects hidden content, plus validating documents before they enter the knowledge base.
- **Behavior alteration**: retrieval changes the base model's behavior (e.g. loses empathy) — a quality/safety signal, not usually a bounty finding; note it only if it crosses a boundary.

### LLM05 Improper Output Handling and LLM07 System Prompt Leakage

- LLM05 is the downstream sink for everything the model emits: insufficient validation before output reaches a shell (`exec`/`eval` → RCE), a browser (unsanitized JS/Markdown → XSS), a SQL builder (→ injection), a filesystem path (→ traversal), or an email template (→ phishing). The prescribed controls: treat the model as any other untrusted user, apply context-aware output encoding, use parameterized queries, and set a strict CSP. For a bounty, identify the *sink* first — an output-handling oracle needs somewhere for the payload to execute, not just a payload.
- LLM05 impact rises under the same conditions as agency: the app grants the LLM more privilege than end users, the app is indirect-injection-vulnerable, third-party extensions under-validate input, per-context output encoding is missing, and monitoring/rate-limiting are absent.
- LLM07 states plainly that the **system prompt is not a secret and is not a security control**; disclosure alone is not the risk. The risk is that the prompt embeds secrets (API keys, connection strings) or that authorization and privilege separation were *delegated to the LLM* rather than enforced deterministically. The mitigation is externalizing secrets and enforcing controls outside the model; if an agent needs different access levels, use multiple least-privilege agents rather than one prompt with role logic. MITRE ATLAS maps system-prompt (meta-prompt) extraction to `AML.T0051.000`.

### Injection delivery surfaces (LLM01)

- LLM01 lists the delivery variants to try against one injection point: **multilingual/obfuscated** payloads (base64, emoji, other languages), **adversarial suffix** appended to a benign prompt, **payload splitting** across documents/resume chunks that only combine in context, and hidden text in an otherwise benign artifact.
- Integration quality decides the exploit: when the app differentiates instruction from data, LLM01 suggests bypasses are still found via **fake markup** (`***important system message: ...***`) and **forged user turns** (`---USER RESPONSE-- ... ---USER RESPONSE--`), as documented in PortSwigger's indirect-injection material. Probe both the parser and the turn structure, not just the words.
- The defenses LLM01 prescribes are the controls to check for absence: constrain behaviour in the system prompt; validate output format with deterministic code; input/output filtering (including RAG-triad checks for context relevance, groundedness, answer relevance); privilege control with API tokens held by the app and functions handled in code rather than handed to the model; human approval for high-risk actions; segregation and labelling of external content; and adversarial testing that treats the model as an untrusted user.
- OWASP's own framing: the model should be treated as a stochastic component, so "we told it not to" is not a control; require a deterministic boundary (authz, filter, egress rule) to be missing before calling it a finding.

### Real incidents to frame severity (T2)

- **EchoLeak (CVE-2025-32711, M365 Copilot, CVSS 9.3 per Microsoft / 7.5 per NVD, CWE-74)**: first zero-click production prompt-injection exfiltration. Chain: benign-looking attacker email evades the XPIA classifier → hidden instruction makes Copilot embed internal data into a **reference-style** markdown image/link (inline-link redaction missed the reference form) → the client auto-fetches images → CSP blocks arbitrary domains, so the URL routes through an allowlisted Microsoft Teams link-preview proxy (`asyncgw.teams.microsoft.com/urlp`) which fetches the attacker URL server-side. External attacker, no user click, no in-the-wild exploitation reported before the server-side fix. Use it as the template for "the exfil path is the finding, not the payload".
- **GitHub MCP toxic flow (Invariant Labs, May 2025)**: a malicious issue on a public repo is picked up by an agent with the GitHub MCP server connected; the agent reads private repositories and publishes the contents in a PR on the public repo. No compromised tool or MCP code — trusted tools plus untrusted data. GitHub cannot patch it server-side; the control is agent-system-level (least privilege, one-repo-per-session policy, runtime tool-flow guardrails).
- **MCP tool poisoning (Invariant Labs, Apr 2025)**: hidden `<IMPORTANT>` instructions inside a tool *description* (e.g. an `add` tool that asks the model to read `~/.cursor/mcp.json` and `~/.ssh/id_rsa` into a "sidenote" argument) are visible to the model and hidden from the approval UI. Two extensions matter for testing: **rug pulls** (the server changes the description after the user approved it) and **cross-server shadowing** (a poisoned description redefines how the *trusted* `send_email` tool must behave, so the user log shows only trusted tools). MCP-scan is the vendor's scanner/proxy for this.

### MCP authorization model (OAuth 2.1 subset)

- MCP authorization is **OPTIONAL** and applies only to HTTP transports; stdio servers **SHOULD NOT** use it and instead take credentials from the environment. When present it is an OAuth 2.1 subset: the MCP server is the **resource server** and **MUST** implement **OAuth 2.0 Protected Resource Metadata (RFC 9728)** advertising `authorization_servers`; clients discover via the `WWW-Authenticate` header on `401` and **MUST** use **Authorization Server Metadata (RFC 8414)** or **OpenID Connect Discovery**; as of revision `2026-07-28`, servers **MUST** support at least one of those discovery mechanisms and clients **MUST** support both. The base draft is OAuth 2.1 (`draft-ietf-oauth-v2-1-13`).
- Clients **MUST** send the **`resource` parameter (RFC 8707 Resource Indicators)** on both authorization and token requests, using the MCP server's canonical URI (lowercase scheme/host, no fragment, no trailing slash preferred), and servers **MUST** validate that a presented token was issued *specifically for them* (audience). Tokens **MUST NOT** appear in the query string and **MUST** be sent as `Authorization: Bearer` on every HTTP request. A server that skips audience validation is the precondition for the token-reuse and passthrough oracles.
- Clients **MUST** implement **PKCE** and register redirect URIs; authorization servers **MUST** exact-match `redirect_uri` against pre-registered values, and clients **SHOULD** verify `state`. Redirect URIs must be `localhost` or HTTPS, and all auth-server endpoints must be HTTPS. Error surfaces to fingerprint: `401` (missing/invalid token), `403` (invalid scope / insufficient permission), `400` (malformed request).
- **Client registration moved**: revision `2026-07-28` deprecates OAuth Dynamic Client Registration (RFC 7591) in favor of **Client ID Metadata Documents (CIMD)** — a URL `client_id` whose HTTPS document identifies the client. DCR remains for backward compatibility; clients **MUST** obtain a client ID by one of CIMD, pre-registration, or DCR. Previously the spec made DCR a SHOULD on both sides — treat "DCR is the only mechanism the server supports" as an older/legacy fingerprint. DCR still requires an appropriate `application_type` (SEP-837).
- **Mix-up attacks**: a client that talks to many authorization servers can be tricked by one it controls into redeeming an honest server's code. The spec mandates recording the validated `issuer`, requiring `iss` in authorization responses (RFC 9207) and string-comparing it without normalization; PKCE alone does not prevent mix-up (the verifier goes to the attacker's token endpoint) and resource indicators do not help when the attacker's AS intercepts first.
- **Credential binding**: clients **MUST** key persisted credentials by issuer, **MUST NOT** reuse them with another authorization server, and **MUST** re-register when the authorization server changes (SEP-2352).
- Where an MCP proxy uses a **static client ID** with a downstream authorization server it **MUST** obtain per-client user consent *before* forwarding to that server — that consent-before-forward rule is the specific fix for the confused-deputy oracle above.
- **Step-up authorization**: servers answer insufficient scope with `403` + `WWW-Authenticate: Bearer error="insufficient_scope", scope="..."`, and clients are expected to retry with the union of previously granted and newly challenged scopes (bounded retries). Fingerprint which scopes the server actually enforces per operation, not which it advertises.

### MCP transport and session trust

- The **current protocol revision is `2026-07-28`**; `2025-06-18`, `2025-11-25` are prior revisions and `2025-03-26` before that. Streamable HTTP replaced the older **HTTP+SSE** transport (`2024-11-05`), which is now classified Deprecated. Every request declares its version in `_meta.io.modelcontextprotocol/protocolVersion`; on Streamable HTTP the same value is mirrored into the **`MCP-Protocol-Version`** header and a mismatch between header and body **MUST** be rejected with `400` + `HeaderMismatch` (`-32020`). A server that supports clients older than `2025-06-18` MAY treat a missing header as `2025-03-26`; one that does not MUST reject the request.
- Revision `2026-07-28` **removed protocol-level sessions** and the `Mcp-Session-Id` header, removed the `initialize`/`initialized` handshake, removed the HTTP GET stream, removed SSE resumability (`Last-Event-ID`), and made `server/discover` a mandatory RPC that advertises supported versions, capabilities, and identity. Servers stateful across calls mint **explicit opaque handles** returned in tool results and passed back as ordinary arguments — that handle model is the new hijack surface (see security page: "State Handle Hijacking"). For revisions `2025-11-25` and earlier, the old model still applies: `Mcp-Session-Id` on the `InitializeResult`, MUST echo on later requests, SHOULD reject missing with `400`, MUST `404` terminated sessions, sessions MUST NOT be used for authentication, IDs secure/non-deterministic and bound to user info (`<user_id>:<session_id>`).
- Change notifications moved: `resources/subscribe`/`unsubscribe` and the GET stream are replaced by a single long-lived `subscriptions/listen` POST-response SSE stream, opt-in per notification type, tagged with `io.modelcontextprotocol/subscriptionId`; request-scoped notifications stay on their own request's stream. Cancellation on Streamable HTTP is closing the response stream — there is no `notifications/cancelled` on that transport.
- Server-to-client interactions (sampling, elicitation, roots) are no longer server-initiated JSON-RPC requests: they are embedded in an `InputRequiredResult` (`resultType: "input_required"`, `inputRequests`) and the client retries the original request with `inputResponses` (Multi Round-Trip Requests). All results now carry `resultType`; clients MUST treat results missing it from older servers as `"complete"`. Roots, Sampling, and Logging are deprecated features; as of `2026-07-28`, new implementations should not add them.
- The spec's own security warning remains the transport checklist: servers **MUST** validate `Origin` on all incoming connections to prevent **DNS rebinding** (invalid `Origin` → `403`), **SHOULD** bind only to `127.0.0.1` when local, and **SHOULD** authenticate all connections. A local MCP server that skips Origin validation is reachable from a remote web page.
- Required request headers create a routing/inspection seam: **`Mcp-Method`** on all requests, **`Mcp-Name`** on `tools/call`, `resources/read`, `prompts/get`, plus **`Mcp-Param-{Name}`** for any tool parameter annotated `x-mcp-header` in `inputSchema`. Values that are not plain ASCII are carried as Base64 with the `=?base64?…?=` sentinel (also for `Mcp-Name`). Servers **MUST** decode and compare mirrored values to the body, and MUST reject mismatches with `400`/`-32020`; intermediaries that route or rate-limit on mirrored headers SHOULD reject requests whose version predates header validation. Test both directions: server trusting body while proxy trusts header, and sentinel handling for non-ASCII tool names.
- **Result caching**: `tools/list`, `prompts/list`, `resources/list`, `resources/read`, and `resources/templates/list` now return `ttlMs` and `cacheScope` (`"public"` or `"private"`). A `public` result is declared safe for shared caches; if the payload varies by principal (per-user tools, per-tenant resources), the declaration is the bug and the leak shows up behind a shared intermediary.
- Tool trust additions in `2026-07-28`: clients **MUST** consider **tool annotations** untrusted unless they come from trusted servers; tool names are 1–128 chars, case-sensitive, restricted characters, uniqueness scoped to one server, and aggregating clients MAY see collisions and SHOULD disambiguate (prefix with server identifier). The `serverInfo` name is not a guarantee of authenticity. `x-mcp-header` has strict schema constraints (primitive types only, statically reachable via `properties`, no CR/LF, case-insensitively unique) and clients **MUST** reject invalid tool definitions (exclude the tool from `tools/list`).
- Transports differ in trust surface: **stdio** (client spawns the server as a subprocess, newline-delimited JSON-RPC on stdin/stdout, nothing non-MCP on stdout) vs **Streamable HTTP** (network-exposed, Origin/auth on the server) vs custom transports. The same server is safe under stdio and exposed under Streamable HTTP. In proxy architectures where a proxy spawns stdio servers, client-side XSS can steal the proxy token and escalate to command execution — the page's "stdio transport security in proxy scenarios".

### MCP attack catalog (spec security best-practices page)

- **Confused deputy (OAuth proxy)**: requires a static client ID to the third-party auth server, dynamic client registration allowed, a consent cookie set by the third-party auth server, and missing per-client consent at the MCP proxy. The attack mints an MCP auth code to an attacker-registered `redirect_uri`. Mitigations the spec mandates: a per-client consent registry checked *before* the third-party flow, `redirect_uri` exact-string match, single-use `state` bound to the session (set only after consent approval, deleted after validation, short expiry ~10 min), and consent cookies named with `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax`, signed/server-side, and bound to the specific `client_id`. A consent page that can be framed is itself a finding (`frame-ancestors`/`X-Frame-Options: DENY` required).
- **Token passthrough** (explicitly forbidden): the MCP server accepts tokens not issued *to it* and forwards them downstream, circumventing rate limiting/validation, breaking audit attribution, and turning a stolen token into a proxy for exfiltration. Two dimensions to test separately: **audience-validation failure** (token for service A accepted by server B) and **forwarding** (server B sends it to service C unvalidated). The server **MUST NOT** accept tokens not explicitly issued for it.
- **OAuth-discovery SSRF**: during discovery the client fetches a `resource_metadata` URL from `WWW-Authenticate`, the `authorization_servers` list, and the `token_endpoint`/`authorization_endpoint` — any of which a malicious server can point at internal IPs, `169.254.169.254` cloud metadata, loopback services, or a DNS-rebinding host. The page cross-references RFC 9728 §7.7 private-range blocking (block `10/8`, `172.16/12`, `192.168/16`, `127/8`, `::1`, `169.254/16`, `fc00::/7`, `fe80::/10`), warns against hand-rolled IP parsing (octal, hex, IPv4-mapped IPv6), and covers redirect chains and DNS TOCTOU. The same SSRF applies to an authorization server that fetches CIMD URLs from unknown clients.
- **Localhost redirect URI impersonation**: CIMD proves domain control, not which local process owns a `localhost` port; an attacker can present a legitimate client's metadata URL with their own localhost callback and collect the code under the legitimate client's displayed name. Test whether the AS warns/binds.
- **Session hijacking** (≤2025-11-25): two shapes — *prompt injection* (attacker injects an event into a shared queue under a victim session ID; a resume path delivers it, potentially offering tools the client never enabled) and *impersonation* (attacker replays a stolen session ID and the server does no further authz). The spec: servers **MUST** verify every inbound request and **MUST NOT** use sessions for auth. For `2026-07-28`, the analogue is the state handle: never treat possession of a handle as authentication, generate it non-deterministically, and key it to the verified user ID.
- **Local MCP server compromise**: one-click client config that runs an attacker startup command with the client's privileges (`sudo`, `rm -rf`, `curl` of SSH keys, obfuscated payloads). The client **MUST** show the exact untruncated command and require explicit consent, and **SHOULD** sandbox the spawned process.
- **OAuth authorization URL validation**: a malicious server supplies a `javascript:`/`data:`/`file:`/`vbscript:` authorization URL that the client passes to `window.open()` (XSS) or to a shell (command injection). Clients **MUST** allow only `http(s)` (loopback http for dev) and **MUST NOT** open URLs via a shell; web clients SHOULD set `script-src 'self'`/`default-src 'self'`.
- **Scope minimization**: broad/omnibus scopes (`files:*`, `admin:*`) granted up front because the server advertised every scope in `scopes_supported`. The page asks for a minimal initial scope set and incremental elevation via targeted `WWW-Authenticate scope="..."` challenges, and lists "treating claimed scopes in token as sufficient without server-side authorization logic" as a common mistake. Note the documented fallback: when a challenge carries no `scope`, clients are directed to request all of `scopes_supported` — so test server-side enforcement, not the client's greedy request.

### MCP implementation/trust-boundary variance

- MCP implementations vary in tool-description trust: some clients render tool descriptions as instructions, others sandbox them — the same MCP server can be safe under one client and exploitable under another. The spec's baseline is that clients MUST treat annotations as untrusted and note that the server `name` is no authenticity guarantee; descriptions themselves are still model-visible content.
- The **OWASP MCP Top 10 (2025)** names the server-side risk families to map against: `MCP01` Token Mismanagement & Secret Exposure, `MCP02` Privilege Escalation via Scope Creep, `MCP03` Tool Poisoning, `MCP04` Software Supply Chain & Dependency Tampering, `MCP05` Command Injection & Execution, `MCP06` Prompt Injection via Contextual Payloads, `MCP07` Insufficient Authentication & Authorization, `MCP08` Lack of Audit & Telemetry, `MCP09` Shadow MCP Servers, `MCP10` Context Injection & Over-Sharing.
- `MCP03` Tool Poisoning and `MCP07` are the two most reachable from a black-box engagement: a compromised or un-reviewed server's tool *descriptions* are instructions the model may follow, and a server that trusts its caller's identity without its own authz check collapses the whole chain to "whoever reaches the endpoint".
- Protocol revisions moved fast: Streamable HTTP was introduced at `2025-03-26`, reshaped at `2025-06-18` and `2025-11-25`, and the session model was removed at `2026-07-28`; the security best-practices page exists for each revision (the `2025-06-18` URL now serves the `2025-11-25` content). Record the server's negotiated version — and the security page revision you matched against — before quoting a "MUST".

### RAG and framework variance

- RAG framework defaults differ: some vector stores apply metadata filters client-side (bypassable) while others enforce server-side; test filter enforcement, not just filter presence. Confirm at the store layer by querying the same vector set with and without the filter from a low-privilege principal.
- The mainstream vendor pattern is metadata-filtered retrieval: documents/chunks live in a table with ACL/metadata columns (`source`, `accessLevel`, `department`), the table is synced to a vector index, and the query passes static + runtime filters through the vector search API/SDK. Drift happens when the ACL column is not updated with the source object (permission changed, document moved, contributor re-tagged), when a caller path omits the filter, or when a bot is keyed to a static "public" filter. The oracle is the same principal getting the same chunk unauthenticated by direct fetch and via the bot.
- Embedding-layer leakage (LLM08) can disclose source text through nearest-neighbour output even when the document endpoint is ACL'd; the oracle is cross-principal **content**, not just cross-principal metadata.
- The permission model is the product: a "permission-aware vector store" that partitions datasets is the control; its absence is the precondition for the multi-tenant leak oracle. Query-time authorization (ask the authz system for the permitted document set, then constrain retrieval) is stronger than post-retrieval filtering.

### Agent framework variance

- Agent framework defaults on confirmation gates differ (all-tools, write-only, none) — record the observed default and whether server-side enforcement backs the client prompt.
- Delegation implementations differ: some re-authorize at the sub-agent boundary, others pass a token that carries the parent's full scope. Fingerprint which one before framing a "sub-agent inherits privileges" claim.
- Multi-agent systems add a peer-trust seam: a compromised peer agent's output is attacker content that reaches the model context (LLM06 lists "a malicious/compromised peer agent" as a first-class trigger).
- Model-level behaviors (training extraction, multimodal hiding) are model properties, not deployment vulnerabilities, unless the deployment exposes them across a tenant or data boundary — keep the boundary framing. Multimodal injection research (Bagdasaryan et al.) shows the payload can be an adversarial perturbation in image or audio, invisible to the reviewer and outside text filters.
- Experience-memory implementations differ from fact memory: MemoryGraft (MetaGPT DataInterpreter + GPT-4o) shows a small number of poisoned "successful experience" records can dominate retrieval on benign later tasks and cause persistent behavioural drift — test recall of poison records as a separate metric from whether the injection is echoed.
- A2A splits identity from payload: JSON-RPC messages carry no user/client identity, so authentication is entirely an HTTP-header concern; the Agent Card advertises the schemes and skills, agents are expected to authorize per skill and act as gatekeepers for their backend systems, task listing must return only tasks visible to the authenticated client, and a mismatched `tenant` routing identifier must be rejected. Push-notification configs carry a webhook URL plus an auth token — an SSRF/token-leak surface when attacker-influenced.

## References

- [T2 research] OWASP Top 10 for Agentic Applications (2026), ASI01–ASI10 with named incidents: https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/ ; resource page: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- [T2 research] OWASP GenAI LLM01:2025 Prompt Injection (direct vs indirect, multimodal, prevention): https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- [T2 research] OWASP GenAI LLM06:2025 Excessive Agency (functionality/permissions/autonomy triad, complete mediation): https://genai.owasp.org/llmrisk/llm062025-excessive-agency/
- [T2 research] OWASP GenAI LLM08:2025 Vector and Embedding Weaknesses (inversion, cross-context leak, poisoning): https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/
- [T2 research] OWASP LLM project / Top 10: https://owasp.org/projects/top-10-for-large-language-model-applications ; 2026 edition resource page (Aug 3, 2026): https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
- [T2 research] OWASP MCP Top 10 (MCP01–MCP10, 2025): https://owasp.org/projects/mcp-top-10 ; practitioner summary: https://cycode.com/blog/owasp-mcp-top-10/ ; mirror: https://www.wiz.io/academy/ai-security/owasp-llm-top-10
- [T1 vendor] MCP specification, Streamable HTTP transport (Origin/DNS-rebinding, statelessness, required headers, `x-mcp-header`, resumability removal), revision 2026-07-28: https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http ; prior revision 2025-06-18 (sessions, `Mcp-Session-Id`, `Last-Event-ID`): https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
- [T1 vendor] MCP security best practices (confused deputy, token passthrough, discovery SSRF, session/state-handle hijacking, local server compromise, OAuth URL validation, scope minimization), revision 2026-07-28: https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices ; earlier content served at the 2025-06-18 URL: https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
- [T1 vendor] MCP specification, key changes for revision 2026-07-28 (sessions removed, `server/discover`, MRTR, `subscriptions/listen`, DCR deprecation, cacheable results): https://modelcontextprotocol.io/specification/2026-07-28/changelog
- [T1 vendor] MCP specification, versioning and per-request negotiation (`io.modelcontextprotocol/protocolVersion`, `UnsupportedProtocolVersionError`): https://modelcontextprotocol.io/specification/versioning
- [T1 vendor] MCP specification, tools (annotations untrusted, tool-name rules and collisions, `x-mcp-header`): https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- [T2 research] MITRE ATLAS prompt-injection techniques `AML.T0051.000` / `AML.T0051.001` / `AML.T0054`: https://atlas.mitre.org/techniques/AML.T0051.000
- [T2 research] PortSwigger Web Security Academy: LLM attacks including indirect and stored injection, tool-use exploitation — https://portswigger.net/web-security/llm-attacks
- [T2 research] OWASP GenAI LLM05:2025 Improper Output Handling (exec/eval, XSS, SQLi, path-traversal sinks): https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/
- [T2 research] OWASP GenAI LLM07:2025 System Prompt Leakage (prompt is not a secret or a control; delegated-authz risk): https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/
- [T1 vendor] MCP authorization spec, revision 2026-07-28 (OAuth 2.1 subset; RFC 8707 `resource`, RFC 9728 metadata, CIMD, PKCE, audience validation, `iss`/RFC 9207 mix-up): https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization ; prior revision 2025-06-18: https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
- [T2 research] EchoLeak (CVE-2025-32711) case study — XPIA classifier bypass, reference-markdown redaction bypass, image auto-fetch, Teams-proxy CSP bypass: https://arxiv.org/html/2509.10540v1 ; NVD record (CVSS, CWE-74): https://nvd.nist.gov/vuln/detail/CVE-2025-32711
- [T2 research] Invariant Labs — MCP Tool Poisoning Attacks (hidden description instructions, rug pulls, cross-server shadowing): https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
- [T2 research] Invariant Labs — GitHub MCP exploited (toxic agent flow via malicious issue; private-repo data into public PR): https://invariantlabs.ai/blog/mcp-github-vulnerability
- [T2 research] MemoryGraft — persistent compromise via poisoned experience retrieval (semantic imitation, cross-session drift on MetaGPT DataInterpreter + GPT-4o): https://arxiv.org/abs/2512.16962
- [T2 research] Bagdasaryan et al. — indirect instruction injection via adversarial perturbations in images and audio: https://arxiv.org/abs/2307.10490
- [T1 vendor] A2A Protocol — enterprise features (identity at HTTP layer only, Agent Card `security`, per-skill authorization, task visibility, push-notification auth): https://a2a-protocol.org/latest/topics/enterprise-ready/ ; specification: https://a2a-protocol.org/latest/specification/
- [T1 vendor] Databricks — RAG chatbot ACL with metadata filtering (ACL columns synced to vector index, static + runtime filters, filtered vs unfiltered retrieval test): https://community.databricks.com/t5/technical-blog/mastering-rag-chatbot-security-acl-and-metadata-filtering-with/ba-p/101946
