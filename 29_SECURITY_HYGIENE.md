# Workspace Hygiene

## Never store

- passwords
- private keys
- active session tokens
- unrelated third-party PII
- payment secrets
- unrelated personal files

## Narrow, audited exception: local-only research credentials

When the researcher explicitly authorizes it, throwaway credentials for
researcher-owned local infrastructure (lab instances, local test accounts) may live
ONLY under `lab/credentials/` with `0600` permissions, and must NEVER be registered as
evidence, quoted into events/context, or stored anywhere else in the workspace.
`tools/audit.py` enforces all three. No exception exists for production credentials,
third-party secrets, or anything reusable outside the engagement.

Capability persistence is part of the contract: when a capability the engagement will
need again is created or handed over (account recovery codes, enrollment artifacts,
generated throwaway passwords), persist it immediately under `lab/credentials/` (0600)
or record its loss as a named blocker. Losing access is a hygiene failure, not a
research result — and never compensate by pasting the secret into chat, evidence, or
the event ledger (the control plane scrubs secret-shaped values on write and
`tools/audit.py` re-scans for them).

## Evidence path

```text
RAW
→ SANITIZE
→ REFERENCE
→ REPORT
```

Keep raw evidence isolated. Feed sanitized excerpts into reasoning whenever possible.
The controlled executors perform the SANITIZE step at write time: sensitive headers
(`set-cookie`, `cookie`, `authorization`, API-key headers) become `[REDACTED]`,
sensitive query AND fragment values are masked in captures, tool text, executor logs,
the token store, the ledger payload and the `tools/bua/run.mjs` summary — a parameter
name containing `token`/`secret`/`key`/`auth`/`sig`/`session`/`code`/`password`/
`passwd`/`cookie` (case-insensitive, percent-decoded) marks its value sensitive, so
`?access_token=…`, `#code=…` and `X-Amz-Signature=…` are all covered — and
secret-shaped strings in bodies/logs are scrubbed from captures and tool output.
`tools/audit.py` fails a workspace whose registered evidence still carries a
secret-shaped value.

Scan bound (deliberate): the evidence secret scan covers text-like files up to
1 MB — files larger than 1 MB and files containing a NUL byte (non-binary
heuristic) are skipped, so a large or binary capture is not proof of cleanliness.
Keep captures small and text-shaped; secrets in skipped files still violate the
RAW -> SANITIZE -> REFERENCE contract when discovered.

Residual (deliberate): **path segments are NOT masked** — the masker keeps scheme,
host, port and path byte-for-byte. Never put a credential in a URL path; a secret in a
path reaches captures, tool text and logs verbatim (`?`/`#` values and sensitive
headers are the covered surfaces).

## External-model judgment boundary

The TypeSafe (Jev) triage/claims seams send engagement-derived text (pack descriptions,
registered evidence excerpts) to an external API. The engagement gates this with the
top-level `external_judgment:` key in `00_control/engagement.yaml` — `"ALLOWED"` opts in;
anything else, including an absent or unreadable file, means DENIED (the template ships
`external_judgment: "DENIED"`). Denial is enforced in
`tools/control_plane.py:external_judgment_allowed` and consulted by `tools/ts_triage.py`
and `tools/ts_claims.py` before any network call; no CLI flag overrides it. Opt in only
after confirming the provider's data-handling terms for the engagement (see the provider
data boundary above).

## Signing-key boundary (policy broker)

The policy broker's HMAC key lives only at `<home>/key` (0600, created once, never
leaves the home). It is never copied into a workspace, never registered as evidence,
never quoted into the ledger or agent context, never returned by `status`/`hello`, and
never written to `audit.log`. The boundary is honest about its limit: a same-UID agent
that can read files can still read the key — keeping the broker home out of the agent's
reach requires OS isolation, not file modes. Treat any read of `<home>/key`,
`<home>/tokens.jsonl` or `<home>/audit.log` outside the broker as an incident. Rotate by
removing the broker home: it invalidates every outstanding token and the audit trail
with it, so keep an out-of-band copy of anything that must survive.

## Cost / budget boundary

Live actions burn a finite engagement budget, so capacity is capped in code, not by
intention: the top-level `budget:` block in `00_control/engagement.yaml`
(`max_actions_per_cycle`, `max_actions_per_engagement`) is counted by
`researchctl prepare` as recorded `ACTION_RECORDED` events plus outstanding
(unconsumed, unexpired) preflight tokens, and the next prepare is refused with the
count when it would exceed either cap. A malformed block fails closed (no live
action), and `tools/audit.py` errors on recorded over-cap and warns when a workspace
recorded actions with no block at all. Raising a cap is a human decision:
`researchctl budget set` requires a `source_reference` and, once limits exist (or a
prior `BUDGET_CHANGED` is recorded), a `human_reference`; the rewrite preserves every
other byte of the engagement file and records the `BUDGET_CHANGED` event.

## Provider data boundary

Engagement work must run on a model route that does not train on prompts or completions.
The configured contributor-tier Muse route trains on prompts, so it is not acceptable for
target data — check the active route before bootstrap and switch the engagement to a
non-training route first.

## Personal environment

Do not blanket-kill processes, overwrite unrelated files or use a personal browser profile as the normal research context.
