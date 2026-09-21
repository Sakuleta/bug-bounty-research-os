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
(`set-cookie`, `cookie`, `authorization`, API-key headers) become `[REDACTED]` and
secret-shaped strings in bodies/logs are scrubbed from captures and tool output.
`tools/audit.py` fails a workspace whose registered evidence still carries a
secret-shaped value.

## Personal environment

Do not blanket-kill processes, overwrite unrelated files or use a personal browser profile as the normal research context.
