---
name: realtime
description: "Realtime protocol isolation — WebSocket, SSE, and WebTransport authentication, per-message versus connect-time authorization, Origin validation, stale-permission survival, and reconnect resume leakage."
---

# Realtime Protocols

Every realtime leg — handshake, subscription, per-message, resume — carries its own authorization decision, so the invariant is that a researcher session only receives or mutates what its own principal is authorized for on that leg. Lead with the transport fingerprint (WebSocket, SSE, WebTransport) and the observed auth mechanism (cookie, ticket, header, query token); the proof is a canary published in one researcher session's private channel arriving in the other's stream.

## Run this

1. **Record the transport and auth fingerprint** — plain WebSocket, socket library, SSE endpoint, or WebTransport session, plus cookie, ticket, header, or query token. Done when both the transport and the observed auth mechanism are written down.

2. **Baseline both researcher sessions** — connect, subscribe, publish one canary, disconnect, and resume from each session. Done when all five steps have an allow, deny, delivery, and ordering result recorded per session.

3. **Probe channel isolation a single time** — from session A request session B's private channel, topic, or subscription ID once and record delivery versus refusal. Done when the request count stays at one and the refusal-or-delivery result is written down.

4. **Probe per-message authorization** — send one B-owned object reference and one elevated action over A's authorized channel, compared against the REST baseline for the same objects. Done when both messages and their REST counterparts carry observed results.

5. **Probe the lifecycle legs** — downgrade or revoke A's permission, then test the existing connection, a reconnect with the old ticket, and a fresh connect. Done when each of the three legs has a recorded allow or deny.

6. **Probe resume and framing** — reconnect with a stale, a future, and an arbitrary sequence or last-event ID, and send one binary or malformed frame at low rate. Done when three resume diffs and one framing result are recorded.

## Done when

- Connect, subscribe, publish, resume, and disconnect each carry a recorded result from both researcher sessions, including delivery order.

- Every oracle in play is confirmed by canary delivery or second-session receipt rather than handshake success or a status code.

- Each false-positive candidate (shared lobby, error self-reflection, expected backlog, delayed close after revocation) has one recorded rule-out.

## Stop conditions

- Any non-researcher message or production-channel delivery — halt, close sockets, and report the isolated oracle.

- Broadcast amplification or connection exhaustion — stop opening parallel streams, return to the program's connection limit, and report.

- A credentialed cross-origin effect beyond researcher pages — halt the hijack probe, close sockets, and report.

- Server instability from a malformed-frame probe — keep the probe single-shot, stop, and report the framing boundary.

## Depth

Field guide: `12_knowledge/realtime/realtime.md` — research families, oracles, minimal safe proof, transport false positives, and broker/gateway version notes; framing and connection-reuse differentials are referenced from `12_knowledge/http-edge-cache/http-desync-cache.md`.
