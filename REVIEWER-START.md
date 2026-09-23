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
- Line counts below are exact `wc -l` values for this tree on the v8.2 provenance
  branch (parent tag `v8.1`, `OS_VERSION` 8.2; verified programmatically when the
  tree moved); re-derive them if
  the tree moved.

## Tier 1 — the load-bearing seam (read these first)

| Path | lines (exact `wc -l`) | Why it matters |
|---|---|---|
| `ARCHITECTURE.md` | 102 | The claimed shape: event log → projections → guards |
| `START.md` | 153 | The engagement entry contract: loop, gates, closure |
| `AGENTS.md` | 305 | The operational flow an agent must follow |
| `tools/control_plane.py` | 3998 | **The single policy seam**: event schema (incl. `os_version` stamping), state machine, projections (incl. `knowledge-usage`/`knowledge-proposals`), guards, audit/freshness/evidence/technique/budget records, `KNOWLEDGE_PROPOSED`/`KNOWLEDGE_RESOLVED`, and the broker integration (`set_scope` policy push, `prepare` minting signed single-use tokens through `tools/broker/`, `scope_check` delegation) |
| `tools/audit.py` | 1435 | What the machine audit actually checks (and what it does not): reviewed-cycle binding, audit content, budget caps, closure-proof parsing, `--emit-proof` |
| `dsh-plugin/index.js` | 2673 | Enforcement R1–R7: write protection, raw-egress gate, single-use preflight tokens, executor-side scope, browser-launch gate, capture redaction, broker-minted token consumption (R7) |
| `tools/test_control_plane.py` | 3966 | Executable spec for the seam |
| `tools/test_scope_parity.py` | 131 | Cross-language scope parity: Python `scope_check` vs the enforcer `scopeReasonFor` (SKIPs when node is unavailable) |
| `tools/test_replay.py` | 368 | Executor replay diff (two identical runs over a canned local server) + capture integrity (secret scan, masker idempotence) in one harness |
| `tools/test_broker.py` | 1308 | Executable spec for the policy broker (real daemon on a temp home, real Unix socket: protocol, policy, mint/consume, fail-closed paths, control-plane integration) |
| `tools/test_containment.py` | 306 | Executable spec for the SBPL generator (determinism, deny-default, literal-IP pins, `--print`/`--out` equivalence) and the containment selftest |
| `tools/test_masker_parity.py` | 98 | Executable spec for the single secret-pattern source (`tools/secret-patterns.json` rendered into all three maskers) |
| `dsh-plugin/conformance.test.mjs` | 1002 | Executable spec for the enforcer |
| `dsh-plugin/executor.integration.test.mjs` | 730 | Executable spec for the executors |
| `dsh-plugin/broker.integration.test.mjs` | 317 | Broker R7 end to end against the real Python broker: signed mint, consume-through-broker before dispatch, tamper/replay/narrowed-policy refusals |
| `tools/bua/run.test.mjs` | 551 | Executable spec for the browser runner: per-request scope routes (`route`/`routeWebSocket`), blocked-request and redirect-hop records |
| `tools/bua/run.e2e.test.mjs` | 354 | Guarded end-to-end browser suite — SKIPs without a provisioned browser |
| `tools/bua/interactive.mjs` | 1660 | The write-capable arm: typed operations over executor handles, node-identity guards (freshness/occlusion/geometry via the click-trial actionability probe), per-dispatch preflight consumption bound to op+target+scope, a fresh login per run, a human gate that honors the decision (DENIED/CANCELLED never authorize) and postdates the token, per-action evidence registration (capture JSON + PNG, state snapshot) — controller-driven, never wired into the executor |
| `tools/bua/interactive-helpers.mjs` | 403 | The interactive arm's own copy of the shared mask/scope/worker-guard helpers (duplication over coupling: the read-only `run.mjs` stays untouched as the default arm); realpath-based `--profile` containment under `lab/` |
| `tools/bua/interactive.test.mjs` | 2294 | Executable guard suite for the interactive arm (adversarial probes first: stale handle, overlay, moved node, out-of-scope write, gate-less consequential action, refused gate, entry-token reuse, hop taint, traversal upload, symlink profile escape); `run.test.mjs` runs it before interaction APIs are allowed to exist |
| `tools/ts_bua.py` | 279 | The interactive-plan seam: one Jev fan-out per step, every answer through `validate_choice` with a strict simplex, per-action/per-cycle model-call caps, cost rows |
| `tools/test_bua.py` | 350 | Executable spec for the plan seam (policy gate, fan-out validation, caps, cost) |

## Tier 2 — worked run (judge coherence vs ceremony)

`examples/shadow-engagement/` — a full single-cycle rehearsal (36 events:
27 archival plus the closure-review gate pair and re-recorded current audits),
machine closure PASS on seven audit classes plus the closure-review gate attestation,
a filled machine-checked closure proof, one evidence capture; pre-7.3 events
legitimately produce legacy warnings).
Reading order is in `examples/shadow-engagement/README.md`. Read
`11_runtime/events.jsonl` first, then re-derive the projections yourself and
check whether the audit's PASS is earned.

## Tier 3 — protocol docs (the rules the tools are supposed to encode)

`02_WORKFLOW.md` (112) · `03_ORCHESTRATOR.md` (87) · `04_CYCLE_PROTOCOL.md` (76) ·
`05_HYPOTHESIS_ENGINE.md` (61) · `06_EVIDENCE_VALIDATION.md` (101) ·
`07_AUDIT_CLOSURE.md` (193) · `08_human_gates.md` (68) · `09_RESEARCH_PROTOCOL.md` (61) ·
`10_STATE_MODEL.md` (91) · `11_WORKER_PROTOCOL.md` (120) · `12_REPORT_PROTOCOL.md` (113) ·
`13_RUNTIME.md` (61) · `15_TOOLING.md` (620) · `16_RESEARCH_LANES.md` (33) ·
`17_DYNAMIC_TECHNIQUE_ENGINE.md` (101) · `18_MODERN_SURFACES.md` (49) ·
`19_PROGRAM_LEARNING.md` (41) · `22_CONTEXT_MANIFEST.md` (32) ·
`24_ADVANCED_TRADECRAFT.md` (39) · `25_MINIMUM_MODEL_OUTPUT.md` (20) ·
`26_BOOTSTRAP_SEQUENCE.md` (51) · `28_CYCLE_STATE_MACHINE.md` (76) ·
`29_SECURITY_HYGIENE.md` (108) · `31_FRESHNESS_WATCHTOWER.md` (76) ·
`32_AGENTIC_PARADIGM.md` (74) · `33_METHOD_SELF_ATTACK.md` (69)

## Tier 4 — remaining tools, knowledge, skills, schemas

- Tools: `researchctl.py` (514), CLI over the seam (incl. the broker commands:
  `scope-set` policy push, broker-minted `prepare`, `scope-check` delegation,
  `review-issue` review vouchers, `identity-binding` readout,
  `broker serve`/`status`), `cycle.py` (159), `build_context.py` (164),
  `knowledge_index.py` (165), `ts_triage.py` (141),
  `ts_claims.py` (668, incl. the verify-clause judge, judgment ledger and offline
  replay), `bua/run.mjs` (774), browser runner, `provision.py` (50),
  `validate_workspace.py` (117, OS-checkout vs engagement-snapshot contract),
  `secret-patterns.json` + `generate_secret_patterns.py` (92, the single
  secret-pattern source rendered into all three maskers), `state.py` (45),
  `new_cycle.py` (16),
  `harness_check.py` (146) — per-profile presence/drift + restart-pending check for the
  installed enforcer plugin — and the v8.3 verification organs: `ts_cost.py` (181),
  `ts_screen.py` (402), `ts_ground.py` (593), `ts_novelty.py` (300),
  `ts_rank.py` (353), `ts_label.py` (268), `ts_honesty.py` (227) — each backed by a
  paired eval under `tools/ts-eval/` — and the other `test_*.py` suites, incl.
  `test_harness_check.py` (136) and `test_replay.py` (368, also the capture-integrity
  harness for a workspace argument). Out-of-workspace layers: `broker/broker.py` (781,
  Unix-socket policy/key/mint/review-voucher authority) + `broker/client.py` (92), and
  `containment/generate_profile.py` (349) + `containment/selftest.py` (335) — macOS
  `sandbox-exec` egress containment with an in-machine proof (deprecated API,
  defense-in-depth; READMEs in both directories).
- Knowledge: `12_knowledge/INDEX.yaml` + 17 field-guide packs (~6.3k lines).
- Skills: `.dsh/skills/<pack>/SKILL.md` (17), one per pack, plus
  `.dsh/skills/fresh-verifier/SKILL.md` (adapted two-axis reviewer prompts —
  refute-don't-confirm, fingerprint stability, material-replacement
  re-verification, live-target routing; not a knowledge pack).
- Contracts: `schemas/*.json` (event and review records).

## Central claims worth verifying against code

1. Lifecycle state mutates **only** through the control plane; projected files
   are rebuildable views (`START.md`, `AGENTS.md` §3 vs `tools/control_plane.py`).
   [ENFORCED at the seam; bypass via direct file writes is AUDITED (hash chain),
   interpreter-mediated writes are KNOWN-LIMIT]
2. Raw network egress is **intercepted** by the enforcer for known tool spellings
   (resolved by basename; loopback is a parsed-host test) in `bash` — advisory
   interception, not an OS security boundary; interpreter one-liners and
   bash-invoked CLIs that avoid naming control-plane state bypass it, as does any
   non-`bash` tool call (residual risks in `15_TOOLING.md`; the kernel layer is
   `tools/containment/`). Every live action through the controlled executors
   needs a single-use, digest-bound, scope-re-checked preflight token
   (`dsh-plugin/index.js`). [ENFORCED (executor path) / KNOWN-LIMIT (raw egress)]
3. A cycle cannot CLOSE without a technique evaluation, and its terminal
   `REVIEWED` (renamed from cycle `VERIFIED`; findings stay hypothesis-level
   `VERIFIED`) requires review packets on distinct axes with distinct `reviewer`
   and `run_id` (trimmed, case-insensitive), each packet carrying `evidence_quotes`
   that must be a substring of the content-addressed store copy of the referenced
   evidence — never the living file (the store digest is re-verified first)
   (`tools/control_plane.py`, `tools/audit.py`). While the policy broker runs,
   each packet carries a broker-attested single-use voucher bound to workspace +
   hypothesis + axis + reviewer + run + exact packet digest; without a broker the
   packets merge on declared identities ("distinct declared runs", audit-noted).
   [ENFORCED (distinctness, vouchers in broker mode) / ATTESTED only via broker]
4. Closure requires the seven audit classes incl. a six-row method self-attack
   (`33_METHOD_SELF_ATTACK.md`, `tools/control_plane.py`), a resolved human gate
   attesting the closure review (gate id + reference bound in
   `06_audits/CLOSURE-PROOF.md`), and a machine-checked proof: `--emit-proof`
   writes the skeleton (mechanical facts + `TODO(human)` judgment prompts) and
   `--closure` fails on a missing file, an empty section, an unanswered
   `TODO(human)`, a missing/unresolved gate binding, or a recorded PASS that the
   freshly re-derived class result contradicts (`tools/audit.py`,
   `07_AUDIT_CLOSURE.md`). [ENFORCED (form + gate + contradiction) / judgment
   prose itself is ATTESTED, not machine-graded]
5. Registered evidence is content-addressed and immutable (snapshot-first copy,
   atomic rename, store digest re-verified before any review quote is accepted);
   secrets are compared in memory and shredded (`AGENTS.md` §3,
   `29_SECURITY_HYGIENE.md`; one pattern source `tools/secret-patterns.json`
   rendered into all three maskers, parity-tested). [ENFORCED + AUDITED]
6. Rule classification — read every Markdown rule with its class, because not
   every rule is enforced the same way:
   **ENFORCED** (a tool refuses the violating call), **AUDITED** (the ledger must
   show it; `tools/audit.py` errors when it does not), **DETECTED** (recorded and
   surfaced, e.g. redirect hops, webfetch tripwire — the action is not blocked),
   **PROCEDURAL** (agent/human discipline: OTP handling, submission channels,
   pivot budgets, model routes, cross-engagement isolation — no tool watches
   these), **KNOWN-LIMIT** (documented residual in `15_TOOLING.md`, accepted).
   Test each claim doc by doc against the code with the class in mind — a
   PROCEDURAL rule that reads as ENFORCED is doc↔code drift.
7. Scope is default-deny: unset/absent/empty assets refuse target traffic until
   `researchctl scope-set` records them (first record: `source_reference` from the
   program policy; re-records/widening: `human_reference`), `gate: none` is the
   explicit opt-out, and fetch-shaped web tools are gated for in-scope hosts
   (name-pattern tripwire over fetch-shaped tools reading the local binding, not
   the broker policy) (`tools/control_plane.py`, `dsh-plugin/index.js`).
   [ENFORCED (executor + scope-set) / DETECTED (webfetch tripwire)]

## Declared environment you cannot inspect (constraints, not claims)

The runtime harness (DSH) runs outside this repo: profiles `web` and `ro-smoke`;
the enforcer plugin is installed from the same source as `dsh-plugin/`; model
route `opencode-go-ds41 / deepseek-v4.1-flash`; search/MCP set includes Exa,
context7, Firecrawl, Tavily, Serper, Brave, Jina, TinyFish, Monid; user-level
skills live under `~/.agents/skills/`. Live observations by the author (gate
denials, browser end-to-end) are not reproduced here — judge the **mechanisms**
in source, and say what you would need to see to believe the live claims.
