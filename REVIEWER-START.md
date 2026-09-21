# Reviewer start — orientation for an external review

This repository is an AI-operated Research OS for **authorized** bug-bounty
engagements: an event-sourced control plane, a tool-enforced execution layer,
and a knowledge/skill layer. You were asked (in chat) to review it. This file
only orients you inside the repository; the review questions and the deliverable
are in the request you received.

## Access contract

- The repo is public: `https://github.com/Sakuleta/bug-bounty-research-os`
- Fetch single files raw:
  `https://raw.githubusercontent.com/Sakuleta/bug-bounty-research-os/main/<path>`
- You have **no shell**, no access to the author's machine, no DSH harness, and
  no way to run code, tests, or the live executors. Do not ask for them.
- If a claim needs something that is not in this repository, mark it
  *not verifiable from the repo*, state the assumption you are making, and move
  on. Do not stall and do not invent evidence.
- Cite findings as `path:line` (repo-relative) and label each as
  `[code-verified]`, `[inferred]`, or `[assumption]`.
- Line counts below are approximate at tag `v7.1`.

## Tier 1 — the load-bearing seam (read these first)

| Path | ~lines | Why it matters |
|---|---|---|
| `ARCHITECTURE.md` | 102 | The claimed shape: event log → projections → guards |
| `START.md` | 148 | The engagement entry contract: loop, gates, closure |
| `AGENTS.md` | 138 | The operational flow an agent must follow |
| `tools/control_plane.py` | 1320 | **The single policy seam**: event schema, state machine, projections, guards, audit/freshness/evidence/technique records |
| `tools/audit.py` | 516 | What the machine audit actually checks (and what it does not) |
| `dsh-plugin/index.js` | 730 | Enforcement R1–R6: write protection, raw-egress gate, single-use preflight tokens, executor-side scope, browser-launch gate, capture redaction |
| `tools/test_control_plane.py` | 426 | Executable spec for the seam |
| `dsh-plugin/conformance.test.mjs` | 252 | Executable spec for the enforcer |
| `dsh-plugin/executor.integration.test.mjs` | 229 | Executable spec for the executors |

## Tier 2 — worked run (judge coherence vs ceremony)

`examples/shadow-engagement/` — a full single-cycle rehearsal (27 events,
machine closure PASS on seven audit classes, one evidence capture).
Reading order is in `examples/shadow-engagement/README.md`. Read
`11_runtime/events.jsonl` first, then re-derive the projections yourself and
check whether the audit's PASS is earned.

## Tier 3 — protocol docs (the rules the tools are supposed to encode)

`02_WORKFLOW.md` (112) · `03_ORCHESTRATOR.md` (87) · `04_CYCLE_PROTOCOL.md` (76) ·
`05_HYPOTHESIS_ENGINE.md` (57) · `06_EVIDENCE_VALIDATION.md` (84) ·
`07_AUDIT_CLOSURE.md` (84) · `08_human_gates.md` (68) · `09_RESEARCH_PROTOCOL.md` (61) ·
`10_STATE_MODEL.md` (90) · `11_WORKER_PROTOCOL.md` (92) · `12_REPORT_PROTOCOL.md` (66) ·
`13_RUNTIME.md` (61) · `15_TOOLING.md` (385) · `16_RESEARCH_LANES.md` (33) ·
`17_DYNAMIC_TECHNIQUE_ENGINE.md` (101) · `18_MODERN_SURFACES.md` (49) ·
`19_PROGRAM_LEARNING.md` (26) · `22_CONTEXT_MANIFEST.md` (25) ·
`24_ADVANCED_TRADECRAFT.md` (39) · `25_MINIMUM_MODEL_OUTPUT.md` (20) ·
`26_BOOTSTRAP_SEQUENCE.md` (51) · `28_CYCLE_STATE_MACHINE.md` (68) ·
`29_SECURITY_HYGIENE.md` (47) · `31_FRESHNESS_WATCHTOWER.md` (76) ·
`32_AGENTIC_PARADIGM.md` (74) · `33_METHOD_SELF_ATTACK.md` (54)

## Tier 4 — remaining tools, knowledge, skills, schemas

- Tools: `researchctl.py` (152, CLI over the seam), `cycle.py` (159),
  `build_context.py` (80), `knowledge_index.py` (121), `ts_triage.py` (128),
  `ts_claims.py` (125), `bua/run.mjs` (173, browser runner), `provision.py` (50),
  `validate_workspace.py` (95), `state.py` (45), `new_cycle.py` (16), and the
  other `test_*.py` suites.
- Knowledge: `12_knowledge/INDEX.yaml` + 17 field-guide packs (~6.3k lines).
- Skills: `.dsh/skills/<pack>/SKILL.md` (17), one per pack.
- Contracts: `schemas/*.json` (event and review records).

## Central claims worth verifying against code

1. Lifecycle state mutates **only** through the control plane; projected files
   are rebuildable views (`START.md`, `AGENTS.md` §3 vs `tools/control_plane.py`).
2. Raw network egress is blocked and every live action needs a single-use,
   digest-bound, scope-re-checked preflight token (`dsh-plugin/index.js`).
3. A cycle cannot CLOSE without a technique evaluation, and VERIFIED requires
   two independent reviews on distinct axes with distinct reviewers
   (`tools/control_plane.py`, `tools/audit.py`).
4. Closure requires the seven audit classes incl. a six-row method self-attack
   (`33_METHOD_SELF_ATTACK.md`, `tools/control_plane.py`).
5. Registered evidence is content-addressed and immutable; secrets are compared
   in memory and shredded (`AGENTS.md` §3, `29_SECURITY_HYGIENE.md`).
6. "Every rule in Markdown lives in a tool or a guard, or is deleted" — test
   this claim doc by doc against the code.

## Declared environment you cannot inspect (constraints, not claims)

The runtime harness (DSH) runs outside this repo: profiles `web` and `ro-smoke`;
the enforcer plugin is installed from the same source as `dsh-plugin/`; model
route `opencode-go-ds41 / deepseek-v4.1-flash`; search/MCP set includes Exa,
context7, Firecrawl, Tavily, Serper, Brave, Jina, TinyFish, Monid; user-level
skills live under `~/.agents/skills/`. Live observations by the author (gate
denials, browser end-to-end) are not reproduced here — judge the **mechanisms**
in source, and say what you would need to see to believe the live claims.
