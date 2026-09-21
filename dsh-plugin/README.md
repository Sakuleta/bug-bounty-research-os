# research-os-enforcer (DSH plugin)

DSH policy plugin that enforces the Research OS control-plane rules at the tool layer.
Source of truth lives here; the live install is a copy under the DSH profile.

## Rules

| Rule | Enforcement surface | Behavior |
|---|---|---|
| R1 — projection/canonical write protection | `tools.guard()` (monotonic, cannot be undone) | `write`/`edit` (and common shell write shapes) targeting control-plane-owned paths inside a detected Research OS workspace are denied. Mutate state through `tools/researchctl.py`. |
| R2 — ledger append-only via control plane | `tools.guard()` | `11_runtime/events.jsonl` direct writes denied. |
| R3 — raw network egress closed | `tools/pre-execute` (allow/deny) | Network-capable `bash` (curl/wget/ssh/...) to a non-local host is denied in OS workspaces. Target traffic goes through `research_os_request`; research material goes through the web tools; localhost/lab is never blocked. |
| R4 — single-use preflight binding | `research_os_request` tool | The executor consumes the token issued by `researchctl prepare` (canonical `argument_digest` over `{method,url,principal[,headers][,body_sha256]}`), executes the HTTP request, writes the capture under `08_artifacts/raw/`, registers it as evidence and records `ACTION_RECORDED`. Tokens expire (default 300 s) and are consumed before dispatch. |
| R5 — per-host scope at the executor | both executor tools | The executor re-reads `00_control/engagement.yaml` assets and refuses a host that is out of scope before any network I/O — a hand-crafted or stale token cannot widen scope. Same semantics as `prepare`: simple string list, `*.domain` wildcards, `host[:port]` compared exactly; unparseable asset lists fail closed. The token store `11_runtime/action-tokens.jsonl` is write-protected like a projection (mint tokens only through `researchctl prepare`). |
| R6 — browser arm | `tools/pre-execute` + `research_os_browser` tool | Raw browser-automation launches (playwright/puppeteer/selenium, `--headless`, remote-debugging) in an OS workspace are denied outside the sanctioned path: prepare with `"tool_family": "browser"` (`request_shape {"url": …, "principal": …}`) → `research_os_browser` consumes the token, re-checks scope and runs the canonical read-only runner `tools/bua/run.mjs` (dedicated profile under `lab/`, scope guard, navigate + screenshot), whose run log is registered as evidence and recorded as `ACTION_RECORDED`. Install-shaped commands and explicit-localhost work stay allowed. |

Live flow: `researchctl prepare payload.json` → `research_os_request` (http family) or
`research_os_browser` (browser family) with the same shape → scope re-check → capture +
evidence + action recorded. The token store is transient
(`11_runtime/action-tokens.jsonl`), never the ledger; a consumed or mismatched token cannot
authorize a second call.

Capture hygiene (29_SECURITY_HYGIENE: RAW → SANITIZE → REFERENCE): sensitive headers
(`set-cookie`, `cookie`, `authorization`, API-key headers) are redacted to `[REDACTED]` at
write time, and secret-shaped strings in bodies/logs (GitLab/GitHub tokens, AWS keys, JWTs,
private-key blocks) are scrubbed from both the capture and the tool output. `tools/audit.py`
re-scans registered evidence and fails a workspace whose evidence still carries secret-shaped
values.

Workspace detection: walking up from the session cwd for `OS_VERSION` + `11_runtime/events.jsonl`.
Non-OS workspaces are untouched. Scope failures fail closed; other internal errors fail open
and log to `~/.dsh/research-os-enforcer.log`.

Limits (deliberate): assets compare as `host[:port]` strings — a non-default port must be
listed with the port; headers participate with lowercase keys; the http executor speaks
HTTP(S) only; the browser arm is read-only (navigate + capture) and needs `playwright-core`
+ chromium provisioned in the workspace (the runner reports an actionable provisioning
error until then); a browser launch hidden inside an arbitrary interpreter script is not
detectable by command scanning — the runner + token remains the sanctioned path.

## Tests

```bash
node conformance.test.mjs          # guard + egress + token-selection cases (mocked harness)
node executor.integration.test.mjs # full R4 chain against a local lab server (real researchctl)
```

## Install / update

```bash
./install.sh
```

Then **restart the DSH host** (plugin bodies load at startup on this machine; see the
`cordis.patch.yml` finding note — no hot reload on Node 25).

Rollback: delete the `research-os-enforcer` insert row in
`~/.dsh/profiles/web/cordis.patch.yml`, remove
`~/.dsh/profiles/web/plugins/research-os-enforcer/`, restart the host.
