# Novelty Research Checklist

> Boundary: this file VALIDATES one candidate technique (per-technique checklist). `17_DYNAMIC_TECHNIQUE_ENGINE.md` is the generation engine that produces candidates. Check here, generate there.

Run these 8 steps before testing any advanced or unfamiliar technique. Skip none.

1. Identify exact technology and version where possible; record fingerprint evidence.
2. Read current security research (see source triage below); link the two most relevant sources.
3. Identify prerequisites (preconditions): versions, config flags, protocol states required for the primitive to fire.
4. Identify false positives: what benign behavior mimics success, and what negative control rules it out.
5. Translate the technique into a black-box observable: exact response delta, timing delta, or state change visible without source access.
6. Design the smallest safe proof: minimal requests, test accounts only, no third-party impact, abort condition stated.
7. Create the target-specific hypothesis in `03_hypotheses/` (precondition + oracle + negative control + impact).
8. Record the source and result in `10_learning/` regardless of outcome.

## Source triage

Check in this order; stop early only with a written reason:

1. Vendor advisory / security feed for the pinned component.
2. Framework changelog (parse/serialize/auth/routing sections first).
3. PortSwigger Web Security Academy and research blog.
4. OWASP releases and cheat sheets relevant to the class.
5. Black Hat / DEF CON talks and whitepapers for the same stack.
6. HackerOne/Bugcrowd Hacktivity writeups on matching technology.
7. CVE/CWE entries for the pinned version range.

## Precondition / FP / oracle extraction

For each source, extract exactly three lines: PRECONDITION (what must be true on target), FALSE POSITIVE (what looks like success but is not), ORACLE (the observable that decides pass/fail, e.g. "second response reflects first request's suffix + 300ms delay delta").

Oracle examples: response-body reflection of smuggled bytes; status flip on the second queued request only; timing delta above baseline jitter on poisoned vs clean pairs; cache HIT on an authenticated URL from an anonymous session; state change visible in a second account.

## Common false positives

- Retry/timeout artifacts mistaken for desync delay. Control: repeat over a fresh connection.
- CDN edge caching the probe itself. Control: cache-buster plus `Cache-Status` inspection.
- Self-reflection of input (search echo, error echo) mistaken for injection impact. Control: canary with side-effect-free token.
- Own-session state read as cross-user leak. Control: second clean principal repeating the read.

## Minimal proof template

- Setup: accounts, scope confirmation, rate/abort limits.
- Sequence: numbered requests with exact bytes/headers (no placeholders).
- Oracle: expected vulnerable vs expected clean response, side by side.
- Negative control: near-identical run without the hypothesized cause.
- Cleanup: state reset, session invalidation, evidence redaction.

Safety ceiling: test accounts only, no other users' data, stop on unexpected 5xx or state corruption, report blocking anomalies to HUMAN_GATE instead of pushing through.

## Record format

Append to `10_learning/` one block per technique: `technique | source links | precondition match (yes/no + evidence) | oracle | result (confirmed/fp/n-a) | hypothesis ID or discard reason`. Unrecorded tests count as not run.
