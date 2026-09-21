---
name: ai-agentic
description: "Agentic and LLM application testing — prompt injection, RAG retrieval authorization, tool misuse, excessive agency, agent identity, memory contamination, MCP trust boundaries."
---

# AI / Agentic Applications

AI and agentic application testing asks whether a model acting with **someone's authority** over data, tools, or downstream users can be steered across a **trust or capability boundary** by attacker-controlled content.
Work the **prompt injection**, **RAG retrieval authorization**, **tool misuse**, **excessive agency**, **agent identity**, **memory contamination**, **MCP trust**, and **unsafe output handling** families when the target exposes an assistant, copilot, agent, RAG search, tool-using workflow, or MCP server — and require an authority differential, since the finding is unauthorized capability, not gullibility.

## Run this

1. **Establish the baseline** — perform the action directly (direct ask, direct document fetch, direct tool call) and record the refusal or scope as the secure-behavior control. Done when each targeted capability has a recorded direct-request control.

2. **Single-boundary test** — introduce one injection at a time (one document, one tool parameter, one memory entry) carrying a unique canary token, inside researcher-created documents, sandboxed indexes, or your own tenant. Done when one canary is placeable and attributable to a single boundary.

3. **Prove crossing, not trickery** — require the authority differential: the same request refused directly but fulfilled through injected content, retrieved documents, or tool chaining. Done when the differential is observed rather than a tone or refusal change.

4. **Tool tests on collaborator infrastructure** — keep browsing and file tools pointed at collaborator endpoints and researcher-owned files, never at internal hostnames from recon. Done when the tool's returned internal or unauthorized content lands in a visible researcher answer.

5. **Memory tests with two researcher sessions** — one session writes, a second reads. Done when the second session receives facts or instructions it never supplied, with both sessions researcher-owned.

6. **Retrieval authorization** — query as a low-privilege user and compare returned chunks, citations, and embeddings against direct document access denial. Done when each returned chunk has a matching direct-fetch denial.

7. **Output handling and delegation** — replay rendered markdown, links, or plugin invocations in the real client, and call sub-agents or siblings whose toolset exceeds the invoking agent's scope. Done when each is replayed with the delegate's own policy as the control.

## Done when

- Each tested family has a recorded direct-request or direct-fetch control showing the secure baseline.

- Every oracle rests on an authority differential — non-public data returned, or a privileged or irreversible action executed — not on tone or refusal changes.

- Each false-positive class has been ruled out against its stated cue: echo versus execution, RAG returning the attacker's own document, server-side-enforced confirmation, tool rejecting its own arguments.

## Stop conditions

Cross-tenant data returned, irreversible action executed, injection visible to other users, or an MCP tool performing an unapproved privileged operation.
Halt, preserve evidence, clean up researcher artifacts, and report.

## Depth

Field guide: `12_knowledge/ai-agentic/ai-agentic.md` — research families, preconditions, oracle catalog, false-positive disambiguation, and OWASP Agentic/LLM/MCP taxonomy mapping with RAG, MCP-client, and confirmation-gate default notes.
