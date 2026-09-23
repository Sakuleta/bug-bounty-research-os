# research-os-enforcer (DSH plugin)

DSH policy plugin that enforces the Research OS control-plane rules at the tool layer.
Source of truth lives here; the live install is a copy under the DSH profile.

## Rules

| Rule | Enforcement surface | Behavior |
|---|---|---|
| R1 — projection/canonical write protection | `tools.guard()` (monotonic, cannot be undone) | `write`/`edit` (and common shell write shapes, including directory-level destruction such as `rm -rf 11_runtime`, `rm 11_runtime/*`, `mv 04_cycles /tmp/x`, `find 11_runtime -delete`, `cd 11_runtime && rm …` — targets resolve bare names and globs, and any path that equals or is an ancestor of protected material is denied) targeting control-plane-owned paths inside a detected Research OS workspace are denied: runtime projections/views, the freshness/usage/proposal views (`10_learning/freshness.yaml`, `10_learning/knowledge-usage.yaml`, `10_learning/knowledge-proposals.yaml`, `10_learning/knowledge-proposals/**`), the evidence store (`11_runtime/evidence-store/**`), and `00_control/engagement.yaml` + `identity-binding.yaml` once the workspace leaves BOOTSTRAP (the agent may fill those during BOOTSTRAP only; unreadable status counts as protected). Mutate state through `tools/researchctl.py`. |
| R2 — ledger append-only via control plane | `tools.guard()` | `11_runtime/events.jsonl` direct writes denied. |
| R3 — raw network egress closed | `tools/pre-execute` (allow/deny) | Network-capable `bash` (curl/wget/ssh/...) to a non-local host is denied in OS workspaces. Target traffic goes through `research_os_request`; research material goes through the web tools; localhost/lab is never blocked. The web-fetch gate also denies fetch-shaped tools (scrape/crawl/map/parse/extract/read/fetch/browser/navigate/automation/computer; `_search` excluded) when the call references an in-scope asset host — raw or JSON-escaped URLs after userinfo/trailing-dot normalization, or schemeless host references like `t.example`; path-typed arguments (`file_path`, `path`, `cwd`, `workdir`, `out_dir`, `profile`, `*_path`) are not host references, and a plain file read is never denied. In-scope hosts are live targets, so prepare and use `research_os_request`/`research_os_browser`; out-of-scope URLs stay allowed as research material. **Egress gating is intercepted (advisory), not a boundary**: commands that do not name a NET_COMMANDS binary — python/node/php/git/npm and bash-invoked CLIs — bypass it. |
| R4 — single-use preflight binding | `research_os_request` tool | The executor consumes the token issued by `researchctl prepare` (canonical `argument_digest` over `{method,url,principal[,headers][,body_sha256]}`), executes the HTTP request, writes the capture under `08_artifacts/raw/`, registers it as evidence and records `ACTION_RECORDED`. Tokens expire (default 300 s) and are consumed before dispatch. |
| R5 — per-host scope at the executor | both executor tools | The executor re-reads `00_control/engagement.yaml` assets and refuses a host that is out of scope before any network I/O — a hand-crafted or stale token cannot widen scope. Same semantics as `prepare`: simple string list, `*.domain` wildcards, `host[:port]` compared exactly; absent/empty assets deny (scope unset — record it with `researchctl scope-set`, or set an explicit `gate: none` inside the `scope:` block for non-target work, which disables the executor gate, the web-fetch gate and the audit's historical host re-check); unparseable asset lists deny as unenforceable. The token store `11_runtime/action-tokens.jsonl` is write-protected like a projection (mint tokens only through `researchctl prepare`). |
| R6 — browser arm | `tools/pre-execute` + `research_os_browser` tool | Raw browser-automation launches (playwright/puppeteer/selenium, `--headless`, remote-debugging) in an OS workspace are denied outside the sanctioned path: prepare with `"tool_family": "browser"` (`request_shape {"url": …, "principal": …}`) → `research_os_browser` consumes the token, re-checks scope and runs the canonical read-only runner `tools/bua/run.mjs` (dedicated profile under `lab/`, scope guard, navigate + screenshot), whose run log is registered as evidence and recorded as `ACTION_RECORDED`. Install shape is judged **per command segment** (`&&`, `||`, `;`, `|`): the gate stands down only when every segment that mentions browser tooling is install-shaped, so `npx playwright install chromium` stays allowed while `npx playwright install chromium && npx playwright test <url>` and `npm install … && npx playwright test <url>` are denied. Explicit-localhost work stays allowed. |

Live flow: `researchctl prepare payload.json` → `research_os_request` (http family) or
`research_os_browser` (browser family) with the same shape → scope re-check → capture +
evidence + action recorded. The token store is transient
(`11_runtime/action-tokens.jsonl`), never the ledger; a consumed or mismatched token cannot
authorize a second call.

Executor robustness: requests time out after `RESEARCH_OS_HTTP_TIMEOUT_MS` (default 30000 ms)
via AbortController and response bodies stop at `RESEARCH_OS_MAX_BODY_BYTES` (default 5 MiB)
— the capture holds the bytes read up to the display cap and is marked when truncated
(a mid-body abort is flagged `partial: true` on the result). Receipts are
transactional: once the request was DISPATCHED (sent, even if it errored before headers)
or the runner was started (even with a non-zero exit), a failed capture registration or
`ACTION_RECORDED` write makes the tool return `ok: false` stating the request WAS executed
but the receipt could not be recorded — do not rely on that action as receipted.

Capture hygiene (29_SECURITY_HYGIENE: RAW → SANITIZE → REFERENCE): sensitive headers
(`set-cookie`, `cookie`, `authorization`, API-key headers) are redacted to `[REDACTED]` at
write time; sensitive query AND fragment values are masked (`?token=…` → `?token=[REDACTED]`,
`#code=…` → `#code=[REDACTED]`; the parameter name is matched as a case-insensitive
substring after percent-decoding, so `access_token`, `client_secret`, `X-Amz-Signature`
and `token2` are covered) in capture request lines, tool text, the token store, the
`bua/run.mjs` summary and `DENY(executor)` log lines; and secret-shaped
strings in bodies/logs (GitLab/GitHub tokens, AWS keys, JWTs, private-key blocks) are
scrubbed from both the capture and the tool output. **Path segments are not masked by
design** — never put a credential in a URL path. `tools/audit.py`
re-scans registered evidence and fails a workspace whose evidence still carries secret-shaped
values.

Workspace detection: walking up from the session cwd for any of
`11_runtime/events.jsonl`, `00_control/engagement.yaml` or the `11_runtime/` directory — a
deleted ledger alone does not disarm the enforcer. `OS_VERSION` is protected material
but not required for detection. Non-OS workspaces are untouched. Scope
checks fail closed (the controlled executors and the web-fetch gate both refuse when the
scope cannot be read), and a write guard that throws while the call mentions protected
material (ledger, tokens, run-status, evidence store, engagement bindings, ...) also fails
closed; other internal errors fail open and log to `~/.dsh/research-os-enforcer.log`.

Limits (deliberate): assets compare as `host[:port]` strings — a non-default port must be
listed with the port; headers participate with lowercase keys; the http executor speaks
HTTP(S) only; the browser arm is read-only (navigate + capture) and needs `playwright-core`
+ chromium provisioned in the workspace (the runner reports an actionable provisioning
error until then); a browser launch, network call, protected write or ledger deletion
hidden inside an arbitrary interpreter script (python/node/php) or a bash-invoked CLI is
not detectable by command scanning — egress gating is advisory interception, not a hard
boundary, and the runner + token remains the sanctioned path. Accepted residuals: (a) an
unresolvable variable target (`u=http://localhost:3000; curl $u`) denies fail-closed —
the gate cannot expand the variable, so it refuses rather than allow a possible egress;
(b) the inline-interpreter heuristic treats a `bash -c` payload mentioning protected
markers as suspicious even when it only reads (`bash -c "cat 11_runtime/events.jsonl"`
denies while a direct `cat 11_runtime/events.jsonl` read stays allowed).

## Goal deferral (veto-only, `goal-deferral/`)

`goal-deferral/` is the DSH side of the shared work-lease registry
(`tools/leases.py`, `.leases/<run>.jsonl` under the run workspace). It is
**veto-only**: it blocks DSH goal mutation (`create_goal`/`update_goal`) while a
run's lease is held (`active`, `awaiting-reconciliation` or
`unknown-recovery-required`), and it never pauses/resumes durable goal state and
never emits a continuation. The single continuation emitter for a run is the
OpenCode goal plugin (gate contract: `goal-deferral/opencode-gate-contract.md`).

- Observation: the registry file (same verdict rules as `tools/leases.py`,
  parity-tested — including the strict byte/line encoding contract and the
  released-commit verification) plus owner-scoped job lifecycle
  (`ctx.jobs.onJobsChanged` / `onJobDone`) and continuable-child edges
  (`subagent/start` / `subagent/end`); every edge re-reads the registry
  (subscribe-then-reread — no lost wake-up).
- Activation: an explicit `root` / `RESEARCH_OS_LEASE_ROOT` (plus optional
  `RESEARCH_OS_LEASE_RUN`; without a run id the whole workspace is watched), or
  per-call discovery of an ancestor directory containing `.leases/`. A workspace
  that never used leases is not deferred.
- Fail closed: a missing/unreadable registry, a corrupt line (an undecodable
  byte, or a raw U+0085/U+2028/U+2029 — the shared writer escapes those), an
  unverifiable version chain, a `released` record whose commit does not exist in
  the run's git work tree, and an expired `active` lease all block; a stale lease
  is never success. Internal `apply()` errors fail open like the rest of the
  plugin.
- Bounded reconciliation: a stable `unknown-recovery-required` state wakes at
  most one dispatch of the run workspace's `tools/researchctl.py <root>
  lease-reconcile <run>` (async `execFile`, injectable through
  `options.reconcile`); re-entering the unknown state re-arms exactly one more;
  a failed or unavailable CLI is logged and the lease stays blocking.
- Wiring: the module is part of the installed body (`install.sh` copies it into
  every profile) **and the enforcer's `apply()` dynamic-imports it**, so the veto
  installs through the same `tools.guard` seam as R1 — a lease-held workspace
  denies `create_goal`/`update_goal` even though the host only loads `index.js`.
  The real continuation veto belongs in the DSH `goal-round-driver` readiness
  gate (upstream/overlay, out of this repo's scope) — the adapter owns the
  predicate, the subscription and the integration coverage.

## Tests

```bash
node conformance.test.mjs          # guard + egress + token-selection cases (mocked harness)
node executor.integration.test.mjs # full R4 chain against a local lab server (real researchctl)
node goal-deferral/conformance.test.mjs           # veto matrix (mocked DSH seams + registry fixtures)
node goal-deferral/deferral.integration.test.mjs  # real lease registry + launch wrapper + fake driver
node goal-deferral/gate.matrix.test.mjs           # OpenCode pre-continuation gate contract matrix
```

## Install / update

```bash
./install.sh            # installs index.js, package.json and goal-deferral/ into web + ro-smoke
./install.sh --dry-run  # prints the copies it would make and touches nothing
# DSH_PROFILES="web" overrides the profile list
```

Then **restart the DSH host** (plugin bodies load at startup on this machine; see the
`cordis.patch.yml` finding note — no hot reload on Node 25).

Rollback: delete the `research-os-enforcer` insert row in
`~/.dsh/profiles/web/cordis.patch.yml`, remove
`~/.dsh/profiles/web/plugins/research-os-enforcer/`, restart the host.
