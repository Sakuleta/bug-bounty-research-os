# Agentic Paradigm

Activate only when the target exposes AI or agentic functionality (assistant, copilot, agent, RAG search, tool-using workflow). Otherwise skip; do not force this model onto CRUD apps.

## Chain model

```text
USER -> AGENT -> IDENTITY -> MEMORY -> RETRIEVAL -> POLICY -> TOOL -> EXTERNAL -> SIDE EFFECT
```

Each arrow is an authorization boundary. A vulnerability exists wherever attacker-controlled input crosses an arrow with the authority of the wrong principal.

## Scope check

Before testing, answer: which principals exist (end user, admin, service identity)? Which tools exist (read-only vs side-effecting)? Which inputs are attacker-reachable (own prompts only, shared docs, tickets, uploads, URLs)? If only self-chat with no tools and no shared state exists, file NOT_APPLICABLE and stop — prompt-trick output alone is not a boundary crossing.

## Per-edge boundary questions

1. USER -> AGENT: can a third party (shared link, pasted content, ticket, email) inject instructions the agent treats as user intent? (Goal hijack entry.)
2. AGENT -> IDENTITY: does the agent act with a fixed service identity, the user's identity, or a confused mix? Which actions assume which principal?
3. IDENTITY -> MEMORY: can one user's content enter memory later recalled in another user's session or a higher-privilege context? (Memory contamination.)
4. MEMORY -> RETRIEVAL: does recalled context carry authority (system notes, prior approvals) that retrieved documents can forge?
5. RETRIEVAL -> POLICY: is retrieved content (RAG docs, search results, web pages) treated as data or as instructions? Where is the sanitization point? (RAG poisoning.)
6. POLICY -> TOOL: can the agent reach a tool the current user could not invoke directly (admin API, billing, code exec, private repo)? (Tool misuse, excessive agency.)
7. TOOL -> EXTERNAL: does tool output (webhook body, file content, API response) flow back as trusted input to the next tool call? (Cross-tool escalation.)
8. EXTERNAL -> SIDE EFFECT: which effects are irreversible (send, delete, pay, publish, merge)? Is there a confirmation bound to the verified intent, not the agent's paraphrase?
9. SIDE EFFECT -> USER (feedback loop): does the agent report what it actually did, or a plausible-sounding summary? Can a failed/partial action be presented as success?

## Test patterns

| Pattern | Setup | Oracle (vulnerable) | Negative control |
|---|---|---|---|
| Goal hijack | plant instruction in lowest-trust channel (retrieved doc, ticket comment) | privileged action executes from unprivileged text | same instruction in quoted-data wrapper is refused |
| Tool misuse | ask agent for action the user role cannot do directly | agent-mediated result succeeds where direct API denies | unprivileged direct call also denied, agent asks for approval |
| Identity abuse | swap principals (second user, service token, expired session) | write executes under wrong authority | per-principal replay attributes correctly |
| RAG poisoning | insert canary instruction in a retrieved document | canary obeyed as command | canary quoted as data only |
| Memory contamination | store instruction in session A, trigger recall in B | cross-context execution occurs | recall stays in originating context |
| Cross-tool escalation | chain read tool (fetch URL/file) into write tool (send/commit/publish) | write inherits read-edge authority without re-check | write edge re-authorizes and refuses |

Compare direct-API denial vs agent-mediated result in every row. The gap between those two is the finding.

## Output and feedback rules

Treat agent output as untrusted when it renders retrieved content: verify links, code blocks, and file paths before acting. Treat agent summaries as claims, not logs: confirm side effects in the tool's own history/audit view. A plausible summary of a failed action is itself a reportable integrity gap if a principal could rely on it.

## Evidence standard for agentic findings

An agentic finding needs three artifacts: the planted input (exact text and channel), the agent's action trace (tool calls with parameters, not just the chat transcript), and the side-effect proof (audit log, mailbox, repo state). Transcript-only claims without tool-trace plus side-effect proof are anomalies, not findings.

Negative controls: same goal phrased as benign direct request (tests excessive agency vs intended function); same payload delivered as quoted data with explicit "do not follow" framing (tests instruction/data separation); same sequence as a second principal with no shared memory (tests contamination vs correct recall).

## Non-findings

Deleting or ignoring a prompt-injection string with no action taken is correct behavior, not a bypass. Refusing a disallowed action is correct even with a clumsy refusal message. Hallucinated tool output with no tool call is a reliability bug, not a security boundary crossing — unless a principal acts on it (then file under the feedback-loop edge with the downstream effect as impact).

## Triage order

Test edges in this order; stop at first confirmed crossing, file it, then continue:

1. POLICY -> TOOL (excessive agency pays fastest: ask for the most privileged plausible action first).
2. RETRIEVAL -> POLICY (poisoned doc → instruction execution).
3. USER -> AGENT (third-party instruction → goal change).
4. TOOL -> EXTERNAL -> SIDE EFFECT (read output becomes write input, then irreversible effect).
5. IDENTITY/MEMORY edges (contamination and confusion — slower, run last).

One edge per hypothesis. A test that touches three edges at once has no clean negative control — split it.

## Filing

File each confirmed agentic issue as a normal hypothesis first (precondition + oracle + negative control), then add three agentic fields: crossed edge (which arrow), confused principal (whose authority was borrowed), and OWASP descriptive name with source date. Route any irreversible-action test through HUMAN_GATE before execution. If the agent platform itself (not the deployment) is the vulnerable layer and it is out of scope, record as learning with the scope boundary cited — do not test out-of-scope infrastructure to prove the point.

## OWASP mapping (verified 2026)

Map confirmed findings to OWASP Top 10 for Agentic Applications 2026 by ID and name: ASI01 Agent Goal Hijack, ASI02 Tool Misuse and Exploitation, ASI03 Identity and Privilege Abuse, ASI04 Agentic Supply Chain Vulnerabilities (full list per OWASP). Primary source: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ ; category summaries: https://cycode.com/blog/owasp-top-10-agentic-applications/ and https://auth0.com/blog/owasp-top-10-agentic-applications-lessons/. If the list has moved on at test time, cite the checked name, ID, and date.
