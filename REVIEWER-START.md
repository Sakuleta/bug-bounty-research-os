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
- Line counts below are exact `wc -l` values for this tree at tag `v8.0`
  (`OS_VERSION` 8.0; verified programmatically when the tree moved); re-derive them if
  the tree moved.

## Tier 1 — the load-bearing seam (read these first)

| Path | lines (exact `wc -l`) | Why it matters |
|---|---|---|
| `ARCHITECTURE.md` | 102 | The claimed shape: event log → projections → guards |
| `START.md` | 154 | The engagement entry contract: loop, gates, closure |
| `AGENTS.md` | 255 | The operational flow an agent must follow |
| `tools/control_plane.py` | 2993 | **The single policy seam**: event schema (incl. `os_version` stamping), state machine, projections (incl. `knowledge-usage`/`knowledge-proposals`), guards, audit/freshness/evidence/technique/budget records, `KNOWLEDGE_PROPOSED`/`KNOWLEDGE_RESOLVED`, and the broker integration (`set_scope` policy push, `prepare` minting signed single-use tokens through `tools/broker/`, `scope_check` delegation) |
| `tools/audit.py` | 1034 | What the machine audit actually checks (and what it does not): reviewed-cycle binding, audit content, budget caps, closure-proof parsing, `--emit-proof` |
| `dsh-plugin/index.js` | 1472 | Enforcement R1–R7: write protection, raw-egress gate, single-use preflight tokens, executor-side scope, browser-launch gate, capture redaction, broker-minted token consumption (R7) |
| `tools/test_control_plane.py` | 2898 | Executable spec for the seam |
| `tools/test_scope_parity.py` | 125 | Cross-language scope parity: Python `scope_check` vs the enforcer `scopeReasonFor` (SKIPs when node is unavailable) |
| `tools/test_replay.py` | 367 | Executor replay diff (two identical runs over a canned local server) + capture integrity (secret scan, masker idempotence) in one harness |
| `tools/test_broker.py` | 905 | Executable spec for the policy broker (real daemon on a temp home, real Unix socket: protocol, policy, mint/consume, fail-closed paths, control-plane integration) |
| `tools/test_containment.py` | 291 | Executable spec for the SBPL generator (determinism, deny-default, literal-IP pins, `--print`/`--out` equivalence) and the containment selftest |
| `dsh-plugin/conformance.test.mjs` | 649 | Executable spec for the enforcer |
| `dsh-plugin/executor.integration.test.mjs` | 526 | Executable spec for the executors |
| `dsh-plugin/broker.integration.test.mjs` | 240 | Broker R7 end to end against the real Python broker: signed mint, consume-through-broker before dispatch, tamper/replay/narrowed-policy refusals |
| `tools/bua/run.test.mjs` | 368 | Executable spec for the browser runner: per-request scope routes (`route`/`routeWebSocket`), blocked-request and redirect-hop records |
| `tools/bua/run.e2e.test.mjs` | 280 | Guarded end-to-end browser suite — SKIPs without a provisioned browser |

## Tier 2 — worked run (judge coherence vs ceremony)

`examples/shadow-engagement/` — a full single-cycle rehearsal (27 events,
machine closure PASS on seven audit classes, a filled machine-checked closure
proof, one evidence capture; pre-7.3 events legitimately produce legacy warnings).
Reading order is in `examples/shadow-engagement/README.md`. Read
`11_runtime/events.jsonl` first, then re-derive the projections yourself and
check whether the audit's PASS is earned.

## Tier 3 — protocol docs (the rules the tools are supposed to encode)

`02_WORKFLOW.md` (112) · `03_ORCHESTRATOR.md` (87) · `04_CYCLE_PROTOCOL.md` (76) ·
`05_HYPOTHESIS_ENGINE.md` (61) · `06_EVIDENCE_VALIDATION.md` (84) ·
`07_AUDIT_CLOSURE.md` (150) · `08_human_gates.md` (68) · `09_RESEARCH_PROTOCOL.md` (61) ·
`10_STATE_MODEL.md` (91) · `11_WORKER_PROTOCOL.md` (111) · `12_REPORT_PROTOCOL.md` (85) ·
`13_RUNTIME.md` (61) · `15_TOOLING.md` (601) · `16_RESEARCH_LANES.md` (33) ·
`17_DYNAMIC_TECHNIQUE_ENGINE.md` (101) · `18_MODERN_SURFACES.md` (49) ·
`19_PROGRAM_LEARNING.md` (41) · `22_CONTEXT_MANIFEST.md` (32) ·
`24_ADVANCED_TRADECRAFT.md` (39) · `25_MINIMUM_MODEL_OUTPUT.md` (20) ·
`26_BOOTSTRAP_SEQUENCE.md` (51) · `28_CYCLE_STATE_MACHINE.md` (76) ·
`29_SECURITY_HYGIENE.md` (102) · `31_FRESHNESS_WATCHTOWER.md` (76) ·
`32_AGENTIC_PARADIGM.md` (74) · `33_METHOD_SELF_ATTACK.md` (54)

## Tier 4 — remaining tools, knowledge, skills, schemas

- Tools: `researchctl.py` (350), CLI over the seam (incl. the broker commands:
  `scope-set` policy push, broker-minted `prepare`, `scope-check` delegation,
  `broker serve`/`status`), `cycle.py` (159), `build_context.py` (164),
  `knowledge_index.py` (165), `ts_triage.py` (130),
  `ts_claims.py` (355), `bua/run.mjs` (532), browser runner, `provision.py` (50),
  `validate_workspace.py` (95), `state.py` (45), `new_cycle.py` (16),
  `harness_check.py` (146) — per-profile presence/drift + restart-pending check for the
  installed enforcer plugin — and the other `test_*.py` suites, incl.
  `test_harness_check.py` (136) and `test_replay.py` (367, also the capture-integrity
  harness for a workspace argument). Out-of-workspace layers: `broker/broker.py` (620,
  Unix-socket policy/key/mint authority) + `broker/client.py` (92), and
  `containment/generate_profile.py` (320) + `containment/selftest.py` (334) — macOS
  `sandbox-exec` egress containment with an in-machine proof (deprecated API,
  defense-in-depth; READMEs in both directories).
- Knowledge: `12_knowledge/INDEX.yaml` + 17 field-guide packs (~6.3k lines).
- Skills: `.dsh/skills/<pack>/SKILL.md` (17), one per pack.
- Contracts: `schemas/*.json` (event and review records).

## Central claims worth verifying against code

1. Lifecycle state mutates **only** through the control plane; projected files
   are rebuildable views (`START.md`, `AGENTS.md` §3 vs `tools/control_plane.py`).
2. Raw network egress is **intercepted** by the enforcer for a known binary list and
   only in `bash` — advisory interception, not an OS security boundary; interpreter
   one-liners and bash-invoked CLIs bypass it (documented v1 limit). Every live action
   needs a single-use, digest-bound, scope-re-checked preflight token
   (`dsh-plugin/index.js`).
3. A cycle cannot CLOSE without a technique evaluation, and its terminal
   `REVIEWED` (renamed from cycle `VERIFIED`; findings stay hypothesis-level
   `VERIFIED`) requires two independent reviews on distinct axes with distinct
   `reviewer` and `run_id`, each packet carrying `evidence_quotes` that must be a
   substring of the content-addressed store copy of the referenced evidence —
   never the living file (`tools/control_plane.py`, `tools/audit.py`).
4. Closure requires the seven audit classes incl. a six-row method self-attack
   (`33_METHOD_SELF_ATTACK.md`, `tools/control_plane.py`) and a machine-checked
   `06_audits/CLOSURE-PROOF.md`: `--emit-proof` writes the skeleton (mechanical
   facts + `TODO(human)` judgment prompts) and `--closure` fails on a missing
   file, an empty section, or an unanswered `TODO(human)` (`tools/audit.py`,
   `07_AUDIT_CLOSURE.md`).
5. Registered evidence is content-addressed and immutable; secrets are compared
   in memory and shredded (`AGENTS.md` §3, `29_SECURITY_HYGIENE.md`).
6. "Every rule in Markdown lives in a tool or a guard, or is deleted" — test
   this claim doc by doc against the code.
7. Scope is default-deny: unset/absent/empty assets refuse target traffic until
   `researchctl scope-set` records them (first record: `source_reference` from the
   program policy; re-records/widening: `human_reference`), `gate: none` is the
   explicit opt-out, and fetch-shaped web tools are gated for in-scope hosts
   (`tools/control_plane.py`, `dsh-plugin/index.js`).

## Declared environment you cannot inspect (constraints, not claims)

The runtime harness (DSH) runs outside this repo: profiles `web` and `ro-smoke`;
the enforcer plugin is installed from the same source as `dsh-plugin/`; model
route `opencode-go-ds41 / deepseek-v4.1-flash`; search/MCP set includes Exa,
context7, Firecrawl, Tavily, Serper, Brave, Jina, TinyFish, Monid; user-level
skills live under `~/.agents/skills/`. Live observations by the author (gate
denials, browser end-to-end) are not reproduced here — judge the **mechanisms**
in source, and say what you would need to see to believe the live claims.
