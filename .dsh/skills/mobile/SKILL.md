---
name: mobile
description: "Mobile and companion client surfaces; API host and route discovery, web-versus-mobile authorization differentials, deep-link and webview-bridge trust, offline replay, and token-scope gaps."
---

# Mobile / Client Applications

A client-visible route, flag, or secret is a lead, not a finding: the proof is the same researcher action reaching server-side state where the documented web path denies. Work from a paired **web baseline**, mine candidates with their **source location**, and confirm each one with a **single-variable replay** on researcher data.

## Run this

1. **Baseline web and mobile together** — run the same researcher workflow on both and record hosts, versions, routes, tokens, and allow-versus-deny decisions per session. Done when every mobile flow tested has a written web counterpart decision.

2. **Mine candidates with source locations** — extract hosts, routes, flags, and link schemes from the client and record each as a hypothesis with its source before sending traffic. Done when every candidate has a source location and a named hypothesis.

3. **Replay one variable through the mobile API** — one mined route, version, or parameter with one field changed, sent from both researcher sessions and diffed against the web baseline. Done when each hypothesis has a recorded web-versus-mobile differential.

4. **Deliver one deep link and one bridge-shaped message** to the researcher device only, carrying researcher canaries; observe the handler and the server effect. Done when each delivery has an observed handler and server outcome.

5. **Replay the offline queue across a lifecycle event** — queue one researcher-state change offline, downgrade or revoke, reconnect, and check whether the server still applies it; restore state afterwards. Done when the post-revocation outcome is recorded.

6. **Confirm server-side impact on researcher data** — an authorization gap or state change on your own accounts is the finding; client-side exposure alone stays a lead.

## Done when

- Every hypothesis has a source location and a recorded server-side result on researcher data.

- Every mobile flow tested carries a paired web baseline allow-or-deny decision.

- Every deep-link, bridge, offline, and token-scope probe has one observed outcome recorded.

## Stop conditions

- A non-researcher account is affected, or a production push or sync is disturbed — halt, record the server oracle, and report.

- Auth-token material is disclosed beyond the researcher device — stop, secure the token, and report the oracle without reusing it.

- A platform, jailbreak, or root restriction would be crossed — pause that probe, note the restriction, and continue on the permitted surfaces.

## Depth

Field guide: `12_knowledge/mobile/mobile.md` — research families, oracle catalog, false-positive disambiguation, and iOS, Android, API-version, webview, and push notes.
