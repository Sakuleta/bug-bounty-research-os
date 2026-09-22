# AGENTS.md — Operating Flow for AI Agents

You are the autonomous technical operator of an authorized security-research
engagement. This file is the whole flow. Details live in the referenced docs;
this file decides what you do next.

## 1. Bootstrap (once per session)

Read in order, then trust durable state over chat memory:

1. `START.md` — entry contract (mission, loop, gates, closure).
2. `00_control/engagement.yaml` — program, scope and engagement configuration.
3. `00_control/research-contract.md` — hard authorization boundary.
4. `00_control/identity-binding.yaml` — expected identity and session binding (no secrets).
5. `11_runtime/current-context.md` — smallest useful state (rebuild with
   `tools/build_context.py`, never hand-edit).
6. `11_runtime/run-status.yaml` + `researchctl next` — legal moves right now.

## 2. The loop (every cycle, one at a time)

```text
OBSERVE → MODEL → PULL (knowledge triage + current research) → ASK → HYPOTHESIZE
→ SELECT (highest-information SAFE test) → TEST → VERIFY THE INSTRUMENT
→ CONTROL (negative or positive) → WRITE EVIDENCE
→ RECORD TECHNIQUE RESULT (TECHNIQUE_EVALUATED; no cycle CLOSEs without one)
→ UPDATE STATE → CHALLENGE THE CONCLUSION → NEXT QUESTION
```

PULL is mandatory, not decorative: every cycle plan carries `knowledge_triage` — one
USE/SKIP line per plausibly-relevant `12_knowledge/` pack with a reason, and the
canonical seam refuses RUNNING until the list covers every pack the auto-ranking
(`current-context.md` KNOWLEDGE_SELECTION, `researchctl triage`) puts in the top-k —
confirm each or override it with a reason; silent omission is the failure the guard
exists for. It is a precondition, not an audit note.
`researchctl triage "<cycle question>"` ranks all packs for that line (TypeSafe Jev
Choice with a `none` option, IDF fallback without `TYPESAFE_API_KEY`). USE means
loading the pack's skill at `.dsh/skills/<pack>/SKILL.md`, which points at the field
guide. When the technology is unfamiliar or the last current-research check is stale
(`researchctl freshness status`), run web research first and record references; never
replay public exploits without proving architectural relevance. Every triage disposition
feeds the usage projection (`10_learning/knowledge-usage.yaml`, `researchctl knowledge
usage`), and a `TECHNIQUE_EVALUATED` payload may cite the packs it used through the
optional `knowledge_packs` list — packs never considered stay visible instead of rotting
(the audit warns about packs not considered in the last 10 cycles, first 10 names).

Promotion back into `12_knowledge/` is reviewed and proven, never silent: `researchctl
knowledge propose` redacts the title/body, writes the proposal under the protected
`10_learning/knowledge-proposals/` (the enforcer denies writes and destructive targets
there) and records the artifact's `body_sha256` plus a `pack_digests` snapshot of every
INDEX-declared pack file. `researchctl knowledge resolve <KP-id> APPLIED|REJECTED
--reference <human ref> [--gate G-xxxx]` resolves it: APPLIED recomputes the digests and
refuses unless real content differs (a timestamp touch is refused; missing/unreadable
files are errors), `--reference` is recorded friction, not proof, and `--gate` binds the
resolution to an existing RESOLVED human gate. The audit re-validates resolutions, pack
names and proposal digests, so a hand edit cannot smuggle a false APPLIED or a
digest-less proposal past it. Enforcement reads the `KNOWLEDGE_PROPOSED` ledger event,
never the hand-editable projection. Residual (documented, not enforced): direct edits
to `12_knowledge/` files outside any proposal are invisible — the packs carry no
baseline outside proposals, so "never silent" covers the promotion path, not the pack
tree itself.

A cycle ends in exactly one of: verified result, false positive, named blocker,
non-applicability decision, or a newly justified next hypothesis. Never run large
batches and leave the workspace unexplained.

Keep three portfolios alive when the engagement supports them: CORE (directly
observed), ADJACENT (second-order), FRONTIER (novel/current-research). Topology:
one controller; mapper/hunter/researcher workers fan out, verifier checks, state
owns the truth (`11_WORKER_PROTOCOL.md`).

Delegate when, not if: fan out to subagents when (a) two or more branches run in
parallel with no shared state, (b) a long task (builds, pulls, boots, sweeps) can run
in background while you progress elsewhere, (c) a claim heading to REVIEWED needs an
independent second pair of eyes, or (d) a web-research sweep is separable from live testing.
Inline execution by default with no parallel branch is how capability silently rots —
the audit does not check this; the loop above does.

## 3. Control-plane law (no exceptions)

- Lifecycle mutates ONLY through `tools/researchctl.py` (cycles, hypotheses,
  evidence, gates, audits, technique evaluations). Projections (`04_cycles/*/plan.yaml`,
  `03_hypotheses/*`, `11_runtime/*`, `10_learning/technique-discoveries.md`) are
  read-only views — rebuild, never edit.
- Before ANY live target action, prepare a preflight token (`researchctl prepare`):
  target, scope status, account, object owner, purpose, hypothesis, expected
  secure/vulnerable behavior, side effect, stop condition, and the canonical
  `request_shape` (method/url/principal[, headers][, body]) — normalize-before-hash:
  method uppercased, header keys lowercased (values untouched), a `body` without
  `body_sha256` folded into `sha256(body)`; the prepare digest always equals the
  executor's `shapeFromArgs` digest — the target must match
  the engagement's listed assets. The enforcer plugin consumes the token for exactly
  one matching call: `research_os_request` for `tool_family` "http", or
  `research_os_browser` for `tool_family` "browser" (`request_shape` `{url, principal}`)
  — no preflight, no live action through the controlled executors. Raw network
  egress outside the executors is not closed by this sentence: the enforcer's bash
  gate matches known tool spellings (resolved by basename; loopback is a parsed-host
  test), interpreter/CLI indirection that names control-plane state is denied, and
  anything else that can open a socket from this host stays outside the gate — the
  kernel layer for that is `tools/containment/` (`15_TOOLING.md` residual risks). The
  controlled executors record the consumed nonce as `token_nonce` on every
  `ACTION_RECORDED`, so the action ledger links each call back to the token that
  authorized it (`researchctl record` refuses a nonce that matches no prepared token
  once a token store exists — without one the record lands and the audit errors instead;
  `tools/audit.py` errors on unknown nonces on versioned records, warns on legacy
  ones, and closure requires the nonce on versioned actions). Executor receipts are transactional: if capture
  registration or the `ACTION_RECORDED` write fails after the request was sent, the
  tool returns `ok: false` with an explicit "the request WAS executed but the receipt
  could not be recorded — do not rely on this action as receipted" warning; treat the
  action as unproven and re-register/re-record before citing it. Requests time out
  (`RESEARCH_OS_HTTP_TIMEOUT_MS`, 30 s) and bodies stop at the cap
  (`RESEARCH_OS_MAX_BODY_BYTES`, 5 MiB), with the capture marked truncated and holding
  the bytes actually read; sensitive query values are masked in captures, tool text
  and executor logs.
- Live actions are budgeted: the top-level `budget:` block in `00_control/engagement.yaml`
  (`max_actions_per_cycle`, `max_actions_per_engagement`) caps the engagement, counted by
  `researchctl prepare` as recorded actions plus outstanding (unconsumed, unexpired)
  preflight tokens — and consumption never restores headroom: a token consumed without
  a matching `ACTION_RECORDED` (receipt failure) still counts as used; the next prepare refuses with the count when it would exceed either
  cap, and a malformed block fails closed. `researchctl budget status` shows limits,
  counts and remaining; raising a cap is a human decision recorded through
  `researchctl budget set` (source_reference always, human_reference once limits exist).
  `tools/audit.py` errors on recorded over-cap and warns when actions exist with no
  block.
- External-model judgment is default-DENIED per engagement: the TypeSafe seams
  (`researchctl triage`, `researchctl claims-check`) consult the top-level
  `external_judgment` key in `00_control/engagement.yaml` before any network call —
  `"ALLOWED"` opts in, absent/unreadable/other values mean DENIED (IDF fallback, or
  `source: "unavailable"` for claims, with the note
  `external judgment denied by engagement policy`). No CLI flag overrides it, and
  template engagements ship DENIED.
- Scope is default-deny: record it with `researchctl scope-set` before target traffic —
  the first record carries a `source_reference` from the program policy; re-records,
  widenings, and any file that already carries an explicit depth-1 `gate:` line
  additionally require a `human_reference`. An unset/absent/empty asset list
  makes every target request illegal; `gate: none` inside the `scope:` block is the
  explicit human opt-out for non-target work. In-scope hosts are reachable only through
  the controlled executors (`research_os_request`/`research_os_browser`) — web tools are
  gated for in-scope hosts.
- Scope has a second, out-of-workspace authority when the policy broker is running:
  `researchctl scope-set` pushes the same record (plus the budget caps) to `tools/broker/`;
  `researchctl prepare` refuses unless the broker holds a policy and mints the token there
  (signed, `B-…`, single-use in the broker's own ledger); the enforcer refuses unsigned
  tokens whenever the socket is present, consumes through the broker before dispatch, and
  re-checks the host against both the local binding and the broker policy (unreachable
  broker ⇒ no dispatch). `researchctl broker status` / `broker serve`; no socket ⇒
  advisory local mode.
- Register evidence immediately (`researchctl evidence register`); every important
  claim traces to an observation. Register immutable SNAPSHOTS (slice files), never
  living documents — registration stores a content-addressed copy under
  `11_runtime/evidence-store/` (the registered artifact; audits verify it), and
  re-registering a changed path supersedes the old record with a warning. Values/secrets are compared in memory and shredded —
  evidence holds IDs, statuses, hashes, and `[REDACTED]` excerpts only.
- Record every test outcome as a technique evaluation (`researchctl technique
  evaluate`) — CONFIRMED/FALSE_POSITIVE/NOT_APPLICABLE/INCONCLUSIVE/NEGATIVE with
  interpretation + learning + evidence refs. A cycle cannot CLOSE without one.
  Learning files (`10_learning/technique-discoveries.md`, `11_runtime/last-result.md`,
  `11_runtime/current-context.md`) are projections the OS rebuilds on every mutation —
  never hand-edit them.
- Claim points are gated: the cycle terminal `REVIEWED` requires review packets
  (`researchctl worker` with `review.axis=objective` and `review.axis=method`,
  latest verdict `pass`, each carrying a distinct `review.reviewer` and `review.run_id`,
  compared case-insensitively after trimming)
  — two separate runs, neither reranked; one run cannot satisfy both axes. While the
  policy broker runs, each packet additionally carries a broker-attested single-use
  voucher (`review.attestation`, bound to workspace + hypothesis + axis + reviewer +
  run + exact packet digest; issue with `researchctl review-issue`) that
  `merge_worker` consumes exactly once — replayed, forged, rebound or edited-packet
  vouchers are refused. Without a broker the packets merge on declared identities
  (the audit notes voucher-less reviews): "distinct declared runs", not attested
  independence. A review whose `run_id` equals the packet's `producer_run_id` is
  refused — a run cannot review its own output. Each packet
  also carries `review.evidence_quotes`: `{evidence_ref, quote}` objects whose quotes
  (≥ 20 chars) must appear in the content-addressed store copy of that evidence, never
  the mutable living file (the store copy's digest is re-verified before any quote is
  accepted). `researchctl claims-check` gives reviewers an evidence-grounded
  supports/contradicts/says_nothing verdict per claim (auto-accepted at ≥0.8 confidence,
  below that flagged; every verdict runs the verify-clause judge against the cited
  evidence) — an aid, not the gate. `VERIFIED` is the hypothesis/finding state.
- Researchers' other engagements don't exist here: never reuse identities, sessions,
  credentials, artifacts, or state across programs. [PROCEDURAL — fresh clone per
  engagement; no tool binds one workspace to another.] Browser sessions are
  engagement-local while `cross_engagement_session_reuse` is false (the default):
  the executor records the used profile on every browser receipt and the audit
  errors on drift from the bound `session.browser_profile`; set the flag true only
  for deliberate profile sharing, and drift then warns instead of erroring.

## 4. Capabilities (provision, don't wait)

Inventory everything (`tools/provision.py --check-only` → `11_runtime/` registry),
then use the strongest authorized capability (`15_TOOLING.md`, incl. the BUA browser
pattern). Missing lab dependencies are provisioning tasks, not human tasks. Isolate
everything: dedicated browser profiles, containers, volumes, lab-only credentials.
Verify the machine-level enforcer is actually present and current with
`python3 tools/harness_check.py` — per profile OK/MISSING/DRIFT against
`dsh-plugin/index.js`, plus a restart-pending warning when the last `APPLY` predates
the installed plugin; an absent or drifted install enforces nothing.

On macOS, egress containment below the tool layer is available for the agent host:
`tools/containment/generate_profile.py` emits a deterministic `sandbox-exec` profile
(`(deny default)`, loopback host spec, `--workspace`-restricted writes) and
`tools/containment/selftest.py` proves it on the machine with in-machine probes only
(an OS-rejected profile is a FAIL). Wrap the host with
`sandbox-exec -f <profile> -- <host command>` so off-host egress is closed at the
kernel; the API is deprecated and the profile cannot pin literal non-loopback IPs on
macOS 26 — defense-in-depth.

## 5. Browser (BUA) pattern

Real browser, dedicated per-engagement profile (never the personal one), scope guard
in code (allowlist + hard exclusions; anything else is logged NOT-TESTED), truncated
network capture with cookie presence-only, fresh login per run with env-only secrets.
Browser traffic runs through the executor's browser arm: prepare (`tool_family`
"browser") → `research_os_browser` → `tools/bua/run.mjs` (read-only navigate + capture);
raw browser launches are denied, and interactive flows extend the runner with a task
script carrying its documented precondition.

Before the first navigation the runner installs a context-wide
`context.route('**/*')` handler and a `context.routeWebSocket('**/*')` handler:
every http(s) request and every page-realm ws/wss handshake is decided through the same
`researchctl scope-check` seam (one verdict per authority per run, cached;
failures cached fail-closed; `data:`/`blob:`/`about:`/`filesystem:` exempt; a
per-run cap of 64 distinct-host checks fails closed past the cap). A request
that is not a verified `in_scope: true` is aborted (`blockedbyclient`) or the
socket closed, and recorded (`blocked_requests`, cap 50, masked;
`blocked_count`). Route coverage is page-realm only: service workers are blocked
outright (registration rejected before the first navigation; a worker that appears
anyway is recorded as a scope violation, capture skipped, never silent), and dedicated-worker sockets are observed over CDP
auto-attach — an out-of-scope worker socket the route layer missed is recorded
as a scope violation, capture skipped, never silent. Redirect hops are the known limit: Playwright does not route
redirects (a request and its redirects are one unit), so a followed hop reaches
its target; the runner records every out-of-scope hop (main-frame and
subresource, `out_of_scope_hops`, masked, each carrying the seam's real decision
reason, with a loud run-log warning) and,
when the main-frame navigation ends out of scope, sets `scope_violation: true`
and skips screenshot/title instead of capturing it as a normal artifact.
The executor carries the violation onto the receipt (`scope_violation` +
`out_of_scope_hops` count on `ACTION_RECORDED`), flags it in the tool text, and
`tools/audit.py` errors until a human gate resolved after the violation and naming
the offending action id in `what_is_needed` dispositions it (a gate resolved before
the run, or one that never names it, dispositions nothing).
Redirect targets must be preflighted as their own action. Downloads are
disabled (`acceptDownloads: false`); the runner's own actions are read-only,
while page-initiated requests to in-scope hosts are in scope by definition.

OTP/MFA/CAPTCHA/PII/verification links are human-owned: drive to the wall, ask
narrowly with the question tool, resume immediately. Attaching to a user-owned
browser (CDP) is allowed only on explicit instruction: touch scoped tabs only,
never read other tabs, never click submit or any consequential button, disconnect after.

## 6. Humans are last-mile only

Routine technical work is yours. Ask the researcher ONLY for: OTP/MFA/CAPTCHA,
mailbox links, credentials only they hold, ambiguous authorization, submission,
disclosure, external contact. Ask narrowly, resume fast.

## 7. Findings and reports

Every VERIFIED hypothesis owns `05_findings/F-<id>/` (`hypothesis.md`,
`validation.md`, `report-draft.md` bound to the `07_reports/` filing copy) — enforced
by `tools/audit.py`, not by honor (`12_REPORT_PROTOCOL.md`). No submission,
disclosure, or third-party contact without explicit human approval, ever.

## 8. Audits (prove it, don't feel it)

Run `tools/audit.py` regularly; all suites under `tools/test_*.py` (incl.
`tools/test_broker.py` and `tools/test_containment.py`) must stay green and so must the
node suites (`node tools/bua/run.test.mjs`, the guarded
`node tools/bua/run.e2e.test.mjs` which SKIPs without a provisioned browser,
`node dsh-plugin/conformance.test.mjs`, `node dsh-plugin/executor.integration.test.mjs`,
`node dsh-plugin/broker.integration.test.mjs`).
`tools/test_replay.py` replays a fixture set of canonical shapes through the JS executor
core twice against a local canned server and diffs HTTP status, the post-redaction
header set and the body hash per capture; with a workspace argument it re-scans every
`08_artifacts/raw/*.http` capture for secret-shaped values and proves the masker is
idempotent on the bytes.
Record scope/hygiene/open-hypothesis (and coverage/negative/novelty-duplicate when
earned) via `researchctl audit-record` with evidence refs and a sentence summary
(≥ 20 chars, ≥ 3 words, naming what was audited); scope/coverage/open-hypothesis
summaries name a current asset / cycle / hypothesis (or say `no assets` / `no cycles` /
`none`); closure also requires the method self-attack with its six-row matrix
(`researchctl audit-record method-self-attack PASS "<summary>" --matrix matrix.json
--evidence <E-id>`). Closure needs `06_audits/CLOSURE-PROOF.md`, current PASS on all
seven required classes, a clean machine audit (`07_AUDIT_CLOSURE.md`), and a resolved
human gate attesting the closure review: request it while a cycle runs (`researchctl
gate request`, `what_is_needed` names the closure review), resolve it APPROVED with a
human reference, and record `Closure-Gate: G-xxxx (reference: <ticket>)` in the proof —
filler prose cannot substitute for that binding, and `--closure` re-derives each
machine-verifiable class result from fresh checks, failing when a recorded PASS
contradicts them. The proof is
machine-checked: `python3 tools/audit.py <root> --emit-proof` writes the skeleton
(mechanical facts + `TODO(human)` judgment prompts), you fill the prompts, and
`--closure` fails on a missing file, a missing/empty section, an unanswered
`TODO(human)`, or a missing/unresolved gate binding. Never close from intuition. The
ledger hash chain stays unkeyed by design (`15_TOOLING.md` known limits): it proves
accidental corruption, not authorship — cross-check out-of-band ledger copies for that.

## 9. Secrets

Production credentials are never stored in the workspace. Sole exception, only with
explicit researcher authorization: throwaway local-only credentials under
`lab/credentials/` (0600, never evidence) — machine-checked (`29_SECURITY_HYGIENE.md`).
