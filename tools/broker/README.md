# Policy broker outside the agent-writable workspace (`tools/broker/`)

The enforcer and the control plane both read policy from files inside the workspace
(`00_control/engagement.yaml`, `11_runtime/action-tokens.jsonl`). A prompt-injected or
compromised agent that can edit those files can widen the scope it is measured against,
forge a token record, or replay a consumed nonce. This directory moves the authoritative
copies OUT of the workspace: a small stdlib Unix-socket daemon owns the scope snapshot,
the HMAC signing key, the single-use mint/consume ledger and the decision audit. The
workspace files stay the human-readable binding; the broker is the authority while its
socket is present.

```text
researchctl / enforcer ──newline JSON over <home>/broker.sock──▶ broker (foreground)
                                                                  ├─ policies/<wsid>.json  scope snapshot
                                                                  ├─ key                   32-byte HMAC key (0600)
                                                                  ├─ tokens.jsonl          mint / consume ledger
                                                                  └─ audit.log             every decision
```

## What moves out of the workspace

| artifact | workspace copy | broker copy | why |
| --- | --- | --- | --- |
| scope policy | `00_control/engagement.yaml` (human binding) | `policies/<sha256(workspace)>.json` | narrowing/widening the file cannot change what the broker mints |
| signing key | — | `key` (0600, created once, never leaves the home) | a workspace-local edit cannot forge a signature |
| token ledger | `11_runtime/action-tokens.jsonl` | `tokens.jsonl` | the broker refuses a replayed nonce from its own log |
| decision audit | enforcer log | `audit.log` | refusals and mints are recorded outside the agent's reach |

## Layout and permissions

| path | mode | role |
| --- | --- | --- |
| `<home>/` | `0700` | broker home (`RESEARCH_OS_BROKER_HOME`, default `~/.dsh/research-os-broker`) |
| `<home>/broker.sock` | `0600` | Unix socket; removed on SIGTERM/SIGINT |
| `<home>/key` | `0600` | 32 random bytes; `hello`/`status` never return it |
| `<home>/policies/` | process umask (`0755` with the common `022`) | per-workspace policy directory; the `0700` home is the boundary, so the directory mode is not a second wall |
| `<home>/policies/<wsid>.json` | `0600` | per-workspace policy snapshot (`wsid = sha256(resolved workspace path)`) |
| `<home>/tokens.jsonl` | `0600` | append-only mint/consume records (mint records carry the preflight) |
| `<home>/audit.log` | `0600` | one line per decision: `ok` / `refuse` / `error` |

## Protocol

Newline-delimited JSON over `broker.sock`, one request/response per line, 1 MiB bound.
A refusal is a normal response — `{"ok": false, "error": "…"}` — and a malformed frame or
unknown op is refused without crashing the daemon (the connection stays usable). A
connection may be idle for at most 5 s (`READ_TIMEOUT_SECONDS`) before the broker closes
it, at most 32 connections are served concurrently (the next is refused with
`too many concurrent connections (cap 32)`), and a response that would exceed the 1 MiB
line bound is replaced by a bounded refusal instead of being sent.

| op | request | success response |
| --- | --- | --- |
| `hello` | `{op}` | `{ok, version, capabilities}` |
| `status` | `{op, workspace}` | `{ok, version, workspace, policy_present, policy, key_present, socket, ledger_decode_errors}` |
| `policy.put` | `{op, workspace, assets, gate, source_reference, human_reference?, budget?}` | `{ok, workspace, policy}` |
| `policy.get` | `{op, workspace}` | `{ok, workspace, policy: object \| null}` |
| `scope.check` | `{op, workspace, url}` | `{ok, gate, in_scope, host, assets}` |
| `token.mint` | `{op, workspace, preflight, request_shape, tool_family?, ttl_seconds?}` | `{ok, token, preflight}` |
| `token.consume` | `{op, workspace, digest, tool_family, nonce, sig}` | `{ok, action_id, preflight}` |

- **`policy.put`** mirrors the `scope-set` rule: `source_reference` is always required;
  `human_reference` is required once a policy already exists (re-record) or the stored
  asset list is non-empty. Assets are validated like the scope writer (strings; empty,
  whitespace, quotes, backslash, `#` and control characters refused); `gate` is
  `assets` or `none`; `assets` mode needs a non-empty list. The optional `budget` object
  carries the workspace's caps (`max_actions_per_cycle`, `max_actions_per_engagement`,
  each a non-negative integer or `null` for uncapped; a malformed cap refuses the put);
  `scope-set` pushes the caps it reads from the engagement budget block at push time, so
  a later `policy.put` is how a cap change is refreshed. Every put stores
  `{assets, gate, source_reference, human_reference, updated_at, sequence, budget}`.
- **`token.mint`** requires a stored policy and decides scope from the broker's own copy
  using the canonical `asset_hosts` / `host_in_scope` helpers (imported from
  `tools/control_plane.py` — matching is never re-implemented). An unset or
  unenforceable policy refuses; `gate: none` allows any host; an out-of-scope host
  refuses with `target host '…' is outside the engagement scope (broker policy assets=…)`.
  `preflight.target` is required and its host must equal the `request_shape` url host —
  a preflight may not name one target and authorize another. `ttl_seconds` is an integer
  in 1–3600 (default 300); out-of-range or non-integer values refuse — the broker never
  silently clamps a token lifetime. The budget caps recorded with the policy are counted
  from the broker's OWN mint ledger, per `(workspace, preflight.cycle_id)` and per
  workspace; at or past a cap the mint refuses with the canonical
  `cycle budget exhausted (n/cap)` / `engagement budget exhausted (n/cap)` wording. A
  missing `budget` is uncapped; a malformed cap in a stored policy refuses (never reads
  as uncapped). On success it mints
  `{action_id, nonce, digest, tool_family, expires_at, workspace, sig}` where `digest` is
  the canonical request-shape digest (same bytes the executor hashes) and
  `sig = HMAC-SHA256(key, canonical_json({workspace, action_id, nonce, digest, tool_family, expires_at}))`,
  appends a mint record and returns the record plus the preflight.
- **`scope.check`** is the decision the BUA runner's per-request seam
  (`researchctl scope-check`) delegates to while the socket is present: it mirrors
  `control_plane.scope_check` against the broker's policy copy (`gate: "disabled"` for an
  explicit `gate: none`, `"assets"` otherwise, default-deny host rules, `assets` echoed).
  An unset or unenforceable policy refuses; the caller (CLI/runner) turns any refusal or
  transport failure into a DENY — never a fallback to the workspace-local scope.
- **`token.consume`** finds the mint record by nonce, then checks workspace, digest,
  `tool_family`, the constant-time signature compare, expiry, and finally the consume
  ledger (single use). Only then does it append the consume record and return
  `{ok, action_id, preflight}`. Consume-before-dispatch semantics live in the caller:
  the enforcer consumes before dispatch, so a crash between consume and request can only
  lose a token, never replay one.
- **Failure semantics**: journal-first. The decision log is preflighted before every
  op, and a state-changing op (`policy.put`, `token.mint`, `token.consume`) durably
  appends (fsync) an `INTENT <op>` record *before* it runs, then the outcome line
  after. If the log is unwritable up front (or the `INTENT` append fails), the request
  is refused and the op does NOT run, so no unlogged decision is ever taken. If the
  *outcome* append fails after the state change is applied, the response is an
  explicit `applied_but_unlogged` shape (`ok: false`, the op, and the error) — never
  a plain refusal — and the `INTENT` line is the decision record. Recovery: re-read
  `audit.log` for `INTENT` lines without a matching outcome line and reconcile the
  state files (`tokens.jsonl`, `policies/`) against them. A refused op whose outcome
  line also fails reports `applied_but_unlogged: false` (no state changed, but even
  the refusal went unlogged — repair the log). Unreadable `tokens.jsonl` lines are
  skipped for enforcement but counted and surfaced as `ledger_decode_errors` in
  `status` (silent corruption would hide a replayed or dropped nonce).
  `token.consume` stays fail-safe: the mint lookup, signature/expiry checks and the
  consume append hold the broker lock, so one nonce still consumes exactly once.

`tools/broker/client.py` is the stdlib client: `broker_path()` (env
`RESEARCH_OS_BROKER_SOCKET` wins; else `<home>/broker.sock` when it exists),
`available()`, `workspace_key()` (symlink-resolved absolute path — the string the broker
signs) and `call(op, timeout=3, **payload)`, which raises `BrokerUnavailable` on any
connect/timeout/parse failure. A broker *refusal* is a normal return.

## Run

```bash
# foreground daemon (prints the socket path); --home overrides the home
python3 tools/broker/broker.py --serve --home ~/.dsh/research-os-broker

# same, through the CLI seam
python3 tools/researchctl.py . broker serve
python3 tools/researchctl.py . broker status     # socket, available, policy, key, version
```

Adoption: start the broker, then record the scope (`researchctl scope-set …`) — the push
is automatic — and prepare as usual. While the broker socket is present:

1. `scope-set` writes the local binding + `SCOPE_CHANGED`, then pushes the policy to the
   broker (same assets/gate/references plus the current budget caps); a failing push
   raises (fail closed) and the error says how to repair it.
2. `prepare` requires a broker policy for the workspace and mints a **broker-signed**
   token (`B-…`, carrying `broker_sig`, `broker_nonce`, `broker_workspace`) that is
   mirrored into `11_runtime/action-tokens.jsonl`. No broker policy → actionable refusal
   (“register the scope with the broker: run `researchctl scope-set`”).
3. The enforcer refuses any token **without `broker_sig`** while the socket exists
   (“re-prepare so the token is broker-signed”), runs BOTH scope checks (the local
   engagement binding and the broker policy copy — either denial stops the call), then
   consumes the token **through the broker before dispatch** (a broker refusal or an
   unreachable broker means no dispatch). `researchctl scope-check` — the BUA runner's
   per-request seam — delegates to the broker the same way and denies when the broker is
   unreachable. The local trust path applies only when no socket exists.

| broker state | `scope-set` | `prepare` | executor |
| --- | --- | --- | --- |
| no socket | local write only (advisory) | local `A-…` token | local scope check only |
| socket + policy | local write + push | broker `B-…` token | unsigned refused; local + broker scope; broker consume |
| socket, no policy | push (first record) | refuse, name `scope-set` | n/a (no signed token exists) |
| socket unreachable | local write, then raise | refuse (fail closed) | refuse before dispatch (fail closed) |

## Migration and rollback

- **Adopt**: start the broker and re-run `researchctl scope-set` for each workspace (the
  policy push is part of the command). Until then nothing changes: no socket means
  advisory local mode.
- **Roll back**: stop the broker (`SIGTERM`/`SIGINT` removes the socket) or unset
  `RESEARCH_OS_BROKER_SOCKET`/`RESEARCH_OS_BROKER_HOME` for the agent. `prepare`,
  `scope-set` and the enforcer fall back to the workspace files immediately; no broker
  state is read.
- **Env knobs**: `RESEARCH_OS_BROKER_HOME` (daemon home and the client's default
  derivation), `RESEARCH_OS_BROKER_SOCKET` (explicit socket path for clients/enforcer;
  wins over the home). Both are plain process environment — see the threat model.
- Broker-minted tokens that survive a rollback carry `broker_sig`, but with no socket the
  enforcer treats them as ordinary local tokens (workspace scope applies). Re-preparing
  after a rollback is the clean path; the broker's own ledger still holds their nonces.
- The broker never deletes its `tokens.jsonl`/`audit.log`; removing the home is the
  explicit reset (back up first if the audit trail matters).

## Threat model (honest limits)

- **It is not an isolation boundary.** The home lives under the same UID as the agent.
  A process running as you can rewrite `~/.dsh/research-os-broker/policies/…`, replace
  the key, or delete the socket — the 0700 home protects against *other users*, not
  against your own tooling. What the broker removes is the *file-level* attack the OS
  cares about: a prompt-injected agent editing workspace files can no longer widen the
  scope it is checked against, forge a token, or replay a consumed nonce.
- **Downgrade is one unlink away.** Availability is decided by the socket file. Removing
  the socket (or clearing the env vars) puts `prepare`, `scope-set` and the enforcer back
  on the workspace-local path. If you need the broker to be mandatory, make raw-workspace
  edits impossible (see below) and treat a missing socket as an incident.
- **The key is only as private as the UID.** The `0700` home and `0600` files stop other
  users, not a process running as you: an agent host that can read files under the home
  (`file-read*` — the `tools/containment/` profile grants it) can read `key` and sign a
  token itself. The broker removes the *file-level* attack from inside the workspace
  (editing `engagement.yaml`/`action-tokens.jsonl` cannot widen scope, forge a signature
  or replay a nonce); it is not a cryptographic boundary against a compromised same-UID
  process that can reach the home.
- **Keeping broker mode mandatory is OS-isolation work.** `broker.sock` lives in the same
  UID's home; whether the agent host can reach it (or unlink it, or repoint
  `RESEARCH_OS_BROKER_SOCKET`) is decided entirely by the OS isolation you put around the
  host (separate UID, sandbox/container, or the `tools/containment/` profile with the
  home outside every `--workspace`). The containment profile allows `file-read*`
  everywhere — it does NOT isolate the key — so on a same-UID host the broker is a
  tamper-evidence and policy-authority layer, not a secret-keeping one.
- **The key never travels.** It is created once with `0600` inside the home, is never
  copied into a workspace, never registered as evidence, never printed by `hello`/
  `status`, and never written to `audit.log` (which records decisions, not payloads).
  Mint records do carry the preflight the caller supplied — `prepare` passes the redacted
  one — so `tokens.jsonl` stays inside the same 0700 home.
- **No network surface**: a Unix socket in the home, no TCP listener, no daemon beyond
  the foreground process you start.
- **Layered containment**: kernel-level egress control, not file authority, is what stops
  an uncooperative same-UID process — that layer is `tools/containment/`
  (`sandbox-exec` profile generator + selftest). Use them together: the broker raises the
  bar for policy tampering; the sandbox closes egress; the enforcer keeps the tool layer
  honest.

## Files

| file | role |
| --- | --- |
| `broker.py` | stdlib Unix-socket daemon (`--serve [--home DIR]`), policy/token/audit state |
| `client.py` | stdlib client (`broker_path`, `available`, `workspace_key`, `call`) |
| `../test_broker.py` | daemon + client + control-plane integration suite |
| `../../dsh-plugin/broker.integration.test.mjs` | executor consume/refresh path against the real broker |
| `README.md` | this document |
