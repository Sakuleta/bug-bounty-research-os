# Bug Bounty Research OS

A model-agnostic, stateful workflow for authorized security research.

This is not a single giant prompt.

The AI receives a small entry contract and then operates a persistent research workspace containing:

- engagement policy and authorization
- intelligence and attack-surface models
- hypothesis portfolio
- cycle-based execution
- evidence and validation
- audits and closure proof
- current security research
- runtime state
- tool registry
- isolated lab state

The AI is expected to operate autonomously inside the authorization boundary.

The durable core is intentionally small: `tools/control_plane.py` is the canonical state seam, `tools/researchctl.py` is the normal interface, and `tools/audit.py` proves internal coherence. Markdown/YAML projections are for inspection, not lifecycle mutation. `researchctl next` exposes the current legal state transitions and pending human gates without choosing the research decision.

`AGENTS.md` is the concise operational entry map for the controller. `START.md` remains the authoritative entry contract; detailed worker, report, runtime, evidence, and research rules remain in their dedicated documents.

## Core principle

```text
HUMAN INPUT IS THE EXCEPTION.
ROUTINE TECHNICAL WORK IS THE AI'S RESPONSIBILITY.
```

The AI should discover and use relevant available native/MCP/web/tool capabilities, prefer BUA for browser work when available, and provision ordinary isolated research infrastructure itself.

For mobile targets, the AI should normally obtain the authorized artifact, provision an emulator/simulator, install the app, configure observation, inspect the client and test the corresponding server-side flows itself.

Human gates are limited to genuinely human-owned inputs and consequential decisions such as OTP/MFA/CAPTCHA, credentials known only to the researcher, ambiguous authorization decisions, submission and disclosure.

## Start here

1. Read `START.md`.
2. Clone the template once per engagement and use the clone as that engagement's workspace
   (never push engagement state back to the template):
   `git clone https://github.com/Sakuleta/bug-bounty-research-os.git ~/Documents/<Engagement>`
3. Populate `00_control/` from authoritative program sources, including `identity-binding.yaml`.
4. Let the AI bootstrap tools, identity/session context, and the isolated research lab.
5. The engagement objective comes from workspace state; no `/goal` command is required.

## Do not preload the whole repository into every model call

Use `11_runtime/current-context.md` and the active cycle to construct a focused context.
Knowledge is pulled by relevance, not by volume.
