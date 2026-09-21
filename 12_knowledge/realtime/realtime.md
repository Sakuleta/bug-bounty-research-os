# Realtime Protocols

> SCOPE: Load when WebSocket, SSE, or WebTransport channels carry authenticated actions or cross-user data, using researcher-controlled accounts and channels only.

## Research families

- WebSocket handshake authentication, Origin validation, and ticket or token binding
- Channel, room, topic, and subscription isolation between researcher accounts
- Per-message versus connect-time authorization on streams and datagrams
- Cross-site WebSocket hijacking where Origin is unvalidated and cookies attach
- Stale-permission survival across downgrade, revocation, logout, and reconnect
- Reconnection and resume semantics (sequence IDs, last-event IDs, stream close)
- SSE subscription creation, event injection, and stream-data authorization
- WebTransport session, stream, and datagram channel isolation over QUIC
- Binary versus text frame parsing and oversized or malformed message handling
- Presence, typing, notification, and broadcast fan-out as cross-user oracles
- WebSocket-over-HTTP/2 (RFC 8441 extended `CONNECT`) versus HTTP/1.1 upgrade auth paths
- Broker/gateway resumption: what the resume path re-authorizes versus the initial connect
- Frame-level compliance: masking, fragmentation, control-frame rules, protocol-version negotiation
- Close-handshake semantics (who closes, with what code) as a state/authorization signal
- Invalid-UTF-8 and oversized-message handling as a proxy for input-validation posture
- Broker session-recovery trust: client-supplied recovery identifiers (Socket.IO session `pid` + offset, Ably `recoveryKey`) and which principal the resume path re-evaluates
- Broker auth-endpoint contracts (Pusher `socket_id`/`channel_name` authorization, Ably capability tokens and `authorize()` re-auth) as an ACL surface
- SSE header-workaround seams: service-worker request rewriting, query-token fallback, cookie + Origin/CSRF posture
- Backpressure and ordering assumptions: client `bufferedAmount`, unreliable datagrams, per-stream versus per-session authorization
- WebSocket over HTTP/3 (RFC 9220 extended `CONNECT`) and where an H3-only path skips an H1/H2 guard
- Inter-server broker trust as an adjacent deployment seam (e.g. the python-socketio pickle bus, CVE-2025-61765)

## Preconditions

- Two researcher accounts plus a clean anonymous context, with private researcher channels or topics available per account.
- Baseline of connect, subscribe, publish, resume, and disconnect behavior recorded before probing.
- Fingerprinted transport (plain WebSocket, socket library, SSE endpoint, WebTransport session) and auth mechanism (cookie, ticket, header, query token).
- Every cross-user test uses researcher channels with canary messages; no probing of production rooms, other users, or shared support streams.
- Desync and transport-framing canonical detail lives in http-edge-cache/http-desync-cache.md and is referenced, not duplicated.
- Program rate and connection-count rules confirmed before opening parallel streams.
- For cross-site hijack claims: a browser client, a cookie that attaches at the handshake, and an Origin value the server does not reject.
- For `Last-Event-ID` / resume claims: a documented retention window and two researcher streams whose event IDs you can compare.
- For WebTransport claims: the session was bootstrapped over the observed transport (HTTP/3 or HTTP/2) and the auth header/cookie behavior of the `CONNECT` request is recorded.
- For frame-level claims: you have a raw socket path (not just the browser API) and can send hand-built frames single-shot.
- For broker-recovery claims: the recovery feature is actually enabled — Socket.IO `connectionStateRecovery` (server option) with the same session identity reachable, or Ably `recover`/`resume` in play — and you know the adapter: in-memory, Redis Streams, and MongoDB adapters persist recovery state, the plain Redis adapter does not.
- For broker auth-endpoint claims: a researcher app key plus a working server auth endpoint (Pusher-style `socket_id`/`channel_name` endpoint, Ably `authUrl`/`authCallback`), and private/presence or capability-scoped channels for both accounts.
- For SSE-via-service-worker claims: a service worker is registered and controlling the page scope, and the stream endpoint tolerates a proxied/rewritten request.
- For H3 mediation claims: the client really negotiates HTTP/3 and you captured the connection settings (`SETTINGS_ENABLE_CONNECT_PROTOCOL`, `SETTINGS_H3_DATAGRAM`).

## Oracles

- Subscription bypass: researcher session A receives canary events published in researcher session B's private channel after requesting that channel.
- Identifier-enumeration signal: sequential room, topic, or subscription IDs return other-researcher canary history instead of 403 or empty.
- Per-message gap: connection as A with a B-owned object reference in one message mutates or reads B-researcher state the REST baseline denies.
- Hijack-shaped confirmation: cross-origin socket or subscription request from a researcher attacker page attaches the researcher session and subscribes without Origin refusal.
- Stale-session survival: downgrade, role removal, revocation, or logout on A leaves the pre-existing socket, stream, or subscription delivering or accepting privileged researcher messages.
- Resume leakage: arbitrary sequence or last-event ID on reconnect returns researcher events outside the authorized window.
- Injection fan-out: researcher-published event with a benign marker renders in the second researcher session's stream without holding the publisher role.
- Datagram or binary differential: same logical message accepted in one encoding or channel and denied in another, crossing the expected authorization decision.
- Protocol-downgrade auth gap: the HTTP/1.1 `Upgrade` path enforces Origin/auth but the HTTP/2 `CONNECT`+`:protocol` path does not (or vice versa).
- Close-frame oracle: server accepts an unmasked client frame, or a client accepts a masked server frame, where RFC 6455 requires failing with close code `1002`.
- Framing-compliance differential: a control frame >125 bytes, or a fragmented control frame, is accepted rather than failed with `1002` — evidence the peer is not applying RFC 6455 §5.5.
- UTF-8 enforcement gap: invalid UTF-8 inside a text frame or a Close `reason` is accepted rather than failing with `1007` — an input-validation signal, useful as a fingerprint even when not itself a bounty.
- Version-negotiation signal: the server accepts a legacy `Sec-WebSocket-Version` (or a missing one) it should answer with `426`/`Sec-WebSocket-Version`; a downgrade path can skip a newer auth gate.

- Reconnect-gate drift: the initial connect enforces auth but the resume/reconnect path does not, so a reconnect without credentials still subscribes to the private channel.
- Scheme/subprotocol mismatch: a handshake over `ws://` (unencrypted) or with an unexpected `Sec-WebSocket-Protocol` value reaches a path that behaves differently from the normal `wss://` path.
- Extension-downgrade signal: a client that negotiated no extensions is still sent extension-shaped payloads (e.g. compressed), proving the server trusts a negotiation that never happened.
- Broker resume hijack: a reconnect carrying another researcher's recovery identifier (Socket.IO private session `pid` + offset, Ably `recoveryKey`) restores that researcher's rooms/channels and delivers the backlog.
- Middleware-skip drift: a connection recovered after a block or role change bypasses the connect middleware (the documented `skipMiddlewares` caution) yet still attaches to private rooms.
- Capability drift: a vendor re-auth that narrows capabilities (Ably `authorize()`, or the equivalent) does not detach already-attached channels, and they keep delivering after the down-scope.
- Cross-origin SSE: a `withCredentials` `EventSource` from a researcher attacker origin receives events that a stricter Origin/CSRF control blocks; a server-side effect (subscription registered, event consumed) counts even when CORS hides the body.
- Service-worker relay bypass: the header the service worker injects reaches the origin only while a worker controls the page; a non-controlled context falls back to cookie/query auth and still succeeds.
- Broker subscription ACL: subscribing to a `private-*`/`presence-*`-style channel without a signed auth token, or with one minted for a different `socket_id`/channel, is accepted by the broker or by the app's auth endpoint.
- H3 extended-CONNECT path: `:protocol=websocket` over HTTP/3 reaches a backend the H1 `Upgrade` path rejects (or vice versa); an unknown `:protocol` should draw `501`.
- Backpressure signal: `bufferedAmount` grows without bound on a slow reader while the server keeps fanning privileged data out for that principal — a client-API limitation worth noting, not by itself an authorization bug.
- Attach-time capability check: on a capability broker, subscribing/attaching to a channel the current token has no capability for must fail (Ably surfaces error `40160`); if attach succeeds, the enforcement point is missing or stale.

Oracle → strongest evidence to capture:

| Oracle | What actually proves it |
|---|---|
| Subscription bypass | B-session canary text/JSON delivered into A's handler, with B's publish timestamp |
| Per-message gap | state mutated or returned that the same principal's REST call already denied (diff both) |
| Hijack | credentialed socket established from a foreign `Origin`, subscription accepted, data returned |
| Stale survival | privileged action succeeds on the *old* connection after the revoke timestamp |
| Resume leakage | event ID returned that belongs to another stream/session or falls outside the retention window |
| Broker resume hijack | the resumed connection's own `recovered`/`resumed` flag is true while socket/identity metadata belongs to the other researcher |
| Middleware-skip drift | recovery succeeds for a principal blocked before reconnect, and a private-room message still arrives |
| Broker subscription ACL | signed auth token minted for A's socket (or no token) is accepted for B's channel name |
| SSE cross-origin | server-side subscription/effect for A's cookie from the attacker-origin `EventSource`, cross-checked with a blocked control |
| Close/framing | the wire response for a protocol violation recorded byte-for-byte (or its absence) |

## Minimal safe proof

1. Baseline: connect, subscribe, publish one canary, disconnect, and resume from both researcher sessions; record allow, deny, delivery, and ordering per step.
2. Isolation probe: from session A request session B's private channel, topic, or subscription ID exactly once and record delivery versus refusal; never enumerate beyond the researcher pair.
3. Broker ACL probe: replay A's broker auth request for B's channel name (Pusher-style `channel_name` swap, Ably capability token reuse, Socket.IO room join) exactly once; capture the signed auth token/request and the broker's refusal or delivery.
4. Per-message probe: send one B-owned object reference and one elevated action over A's authorized channel; compare against the REST authorization baseline for the same objects.
5. Lifecycle probe: downgrade or revoke A's permission, then test the existing connection, a reconnect with the old ticket, and a fresh connect; record which leg still succeeds.
6. Re-auth probe: invoke the vendor re-auth primitive to narrow A's capabilities and test an already-attached channel and a fresh subscribe; record which one still delivers.
7. Resume probe: reconnect with a stale, future, and arbitrary sequence or last-event ID, then repeat with another researcher's recovery identifier (`pid` + offset, `recoveryKey`); diff returned researcher events against the authorized window.
8. H3 path differential: if the endpoint negotiates HTTP/3, issue the same credentialed extended `CONNECT` with `:protocol=websocket` you used over H1 and compare the refusal, and confirm an unknown `:protocol` value draws `501`.
9. Handshake-probe confinement: send malformed frames (unmasked, bad opcode, oversized length, control-frame fragmentation) one shot at a time and low rate — these are framing compliance checks, not authorization results, unless DoS testing is explicitly in scope.
10. Stop conditions: any non-researcher message, production-channel delivery, broadcast amplification, connection exhaustion, or credentialed cross-origin effect beyond researcher pages — halt, close sockets, and report the isolated oracle.

## False positives

- Connection accepted but no private data delivered without a valid subscription — handshake success alone is not channel bypass; require canary delivery.
- Public or shared-lobby channel delivering its public feed to both sessions — shared visibility by design; require private researcher-channel crossover.
- Error frame echoing the sent message back to the sender — self-reflection, not cross-user delivery; require second-session receipt.
- Reconnect delivering the same-session backlog inside the authorized window — expected resume, not leakage; require out-of-window researcher events.
- Stale socket closing on next publish or heartbeat after revocation — delayed close converging to deny is the control passing; require a successful post-revocation action.
- Timing or ordering jitter under parallel streams — delivery skew without unauthorized content is transport behavior, not isolation failure.
- Binary-frame rejection with a clean error while text frames succeed — parser strictness, not authorization bypass; require an allow-versus-deny flip on the same privileged object.
- Presence or typing indicator visible to invited researcher participants — invited-participant signaling is intended fan-out, not subscription bypass.
- Server rejecting an unmasked frame with close code `1002` — that is RFC 6455 working correctly (clients MUST mask); require the *opposite* behavior for a claim.
- `EventSource` cross-origin request rejected by CORS despite `withCredentials` — correct credential handling; require the credentialed stream to actually deliver cross-origin events.
- A `204 No Content` / documented close terminating an SSE stream — that is the spec-mandated stop, not a dropped authorization check.
- WebTransport failing with a network error on a redirect — per spec redirects are not followed and the error is intentionally indistinguishable; not a bug.
- A client that waits for the server to close the TCP connection after the close handshake — normal, spec-suggested behavior; not a hang to report.
- Close code `1005` / `1006` appearing in a log — these are summary values for "no code received" / "abnormal close" and MUST NOT be sent on the wire; not a peer bug.
- A server that closes the socket when an extension is missing rather than downgrading — the negotiation control held; require the mismatched payload to actually be accepted.
- Sessions that expire and require a fresh authenticated connect after idle — expiring sessions are the control working, not a resume gap.
- Socket.IO `socket.recovered === true` on your own session inside `maxDisconnectionDuration` — the feature working; require recovery across principals or after a block.
- Socket.IO `connect_error` after the token in the `auth` option expires — the middleware re-validating on the fresh connect is the control passing, not a broken stream.
- Ably `40160` on attaching a channel after a down-scope — the capability check working; require an attach that still succeeds.
- Ably `recover` replaying your own backlog inside the ~2-minute window — expected; require out-of-window or other-principal backlog.
- `pusher:subscription_succeeded` reaching every presence member, or a Pusher client event not being delivered to its own sender — documented routing (presence fan-out, origin exclusion), not a leak or a drop.
- Ably presence "left" arriving up to ~2 minutes late (dropped-page state retention) or after Chrome discards a tab — connection lifecycle, not stale authorization.
- `bufferedAmount` growing on a slow client — the WebSocket API has no backpressure by design; document it, but it is not a server authorization failure.
- `501` for an unknown `:protocol` value over HTTP/3 — RFC 9220 says the server SHOULD respond that way; not a downgrade.
- A service worker not intercepting the very first navigation that registered it — worker lifecycle (`clients.claim()` timing), not an auth bypass.
- SSE reconnecting with `Last-Event-ID` after a transient network error — spec reestablishment; require an out-of-window ID or another principal's event.

## Version/implementation notes

### WebSocket over HTTP/1.1 (RFC 6455)

- The handshake is an HTTP `Upgrade` with `Sec-WebSocket-Version: 13`, a fresh random 16-byte `Sec-WebSocket-Key`, and a `Sec-WebSocket-Accept` the client validates as `base64(SHA-1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`; a non-`101` status means HTTP semantics still apply. A server that cannot speak the offered version MUST respond with a `Sec-WebSocket-Version` advertising what it does support (e.g. `400`/`426`).
- **`Sec-*` headers cannot be set by browser `XMLHttpRequest`/HTML/JS**, which is exactly what stops a form or XHR from faking a WebSocket handshake — so an "attacker can force the handshake from a web page" claim needs a different primitive. RFC 6455 §10.8 notes the handshake's SHA-1 use does not depend on collision resistance, so "SHA-1 in the handshake" is not itself a finding.
- The `Origin` header is browser-supplied and the server **MAY** use it to reject with `403`; if the server does not validate Origin it accepts connections from anywhere. A missing `Origin` **SHOULD NOT** be interpreted as a browser client — and §10.1 warns that non-browser clients can *fake* `Origin` entirely, so a server must not assume the peer is a trusted-origin script.
- Framing is where compliance bugs live: clients **MUST** mask every frame with an unpredictable 32-bit key, and a server receiving an unmasked frame **MUST** close (optionally `1002` Protocol Error); servers **MUST NOT** mask. Unknown opcodes and nonzero `RSV` without a negotiated extension also REQUIRE failing the connection. `ws` defaults to port 80, `wss` to 443.
- Cross-site WebSocket hijacking (CSWSH) is the canonical CSRF-on-handshake class: the browser attaches cookies to the upgrade from any origin, and the response is not protected by the same-origin policy, so Origin validation or a session-bound token on the handshake is the control. When testing a naive Origin allowlist, common bypass shapes are prefix/suffix matching (attacker domain that *starts with* or *ends with* the allowed host) and case/port normalisation differences.

### Frame-level compliance (RFC 6455 §5)

- Opcodes: `0x0` continuation, `0x1` text, `0x2` binary, `0x8` close, `0x9` ping, `0xA` pong; `0x3–0x7` and `0xB–0xF` are reserved and unknown opcodes MUST fail the connection.
- Fragmentation rules: an unfragmented message is one frame with FIN set and a non-zero opcode; a fragmented message is a FIN-clear opener, zero or more `0x0` continuations, and a FIN-set `0x0` terminator. **Fragments of one message MUST NOT be interleaved** with another, and receivers MUST handle control frames injected mid-message. All fragments share the first fragment's type.
- Control frames (`0x8/0x9/0xA`) **MUST have a payload of 125 bytes or less and MUST NOT be fragmented** — a peer that accepts a 200-byte ping or a fragmented ping is non-compliant. A Ping MUST be answered with a Pong carrying identical application data; unsolicited Pongs are allowed.
- Payload length uses the minimal encoding (a 124-byte payload must not be sent as `126,0,124`) and the 64-bit form's MSB MUST be 0. Oversized-length or non-minimal-length frames are fingerprinting signals for the parser used.
- Text frames must carry valid UTF-8 across the reassembled message; invalid UTF-8 in a text message (or a Close `reason`) MUST fail the connection (see `1007` below).

### Control frames, close status codes, and closure semantics (§5.5, §7)

- A Close frame `0x8` carries an optional 2-byte network-order status code followed by UTF-8 `reason`. Clients MUST mask it. The application MUST NOT send data frames after sending Close, and MUST reply to a received Close with a Close (usually echoing the code).
- Defined close codes worth reading as signals: `1000` normal, `1001` going away, `1002` protocol error, `1003` unsupported data, `1007` invalid frame payload data, `1008` policy violation, `1009` message too big, `1010` mandatory extension missing (client-only), `1011` internal server error, `1015` TLS handshake failure. `1005` (no status received) and `1006` (abnormal closure) are **summary values that MUST NOT be set on the wire**.
- Reserved ranges: `0–999` unused; `1000–2999` protocol/extensions; `3000–3999` libraries/frameworks registered with IANA; `4000–4999` private use (unregistered). A Close code outside these, or a framework using a reserved code, is a per-implementation observation to record, not automatically a bug.
- Closure asymmetry is a real oracle: the spec suggests the **server** close the underlying TCP first (so it holds `TIME_WAIT`), while a client SHOULD wait for that close. If a revocation/logout path only half-closes (server stops reading but keeps the socket), post-revocation state may still be accepted — test the live socket, not just a fresh connect.
- Reconnect behavior is part of the protocol: after an abnormal closure clients SHOULD back off (first attempt after a random delay, then truncated binary exponential backoff) precisely to avoid a reconnect storm that is itself a DoS. A server that tight-loops reconnects, or lacks `1008`/`1009`-style guardrails, is worth noting in the report.

### WebSocket over HTTP/2 (RFC 8441)

- HTTP/2 has no connection-wide `Upgrade`/`Connection` headers or `101`, so WebSockets ride an **extended `CONNECT`** with the `:protocol` pseudo-header set to `websocket`, opted into by server `SETTINGS_ENABLE_CONNECT_PROTOCOL` (`0x8`).
- In this mode `Sec-WebSocket-Key`/`Sec-WebSocket-Accept` are **not** processed (superseded by `:protocol`), `Host` becomes `:authority`, header names are lowercase, and an abrupt stream close is `RST_STREAM` with `CANCEL`. A gateway that terminates HTTP/1.1 and re-originates HTTP/2 can enforce Origin/auth on one hop and not the other — test both.

### WebSocket over HTTP/3 (RFC 9220)

- RFC 9220 reuses the RFC 8441 mechanism on HTTP/3: extended `CONNECT` with `:protocol` value `websocket`, gated by the HTTP/3 `SETTINGS_ENABLE_CONNECT_PROTOCOL` setting, whose value is again `0x08` (settings are registered separately per HTTP version).
- An extended `CONNECT` carrying an unknown or unsupported `:protocol` value SHOULD get `501 (Not Implemented)`; a server MAY add a `problem details` body.
- Stream closure replaces TCP closure: an orderly close is a QUIC stream FIN, and an abrupt reset is the stream error `H3_REQUEST_CANCELLED`. RFC 9220 adds no new security considerations beyond RFC 8441 — so any *difference* you observe between the H1 `Upgrade` path and the H3 `CONNECT` path is the implementation's, not the protocol's, and belongs in the report.

### Server-Sent Events (WHATWG HTML §9.2)

- `EventSource` fetches with `Accept: text/event-stream`, cache mode `no-store`, initiator type `other`; it **cannot set custom request headers**, so header-only auth degrades to cookie or query-token auth. `withCredentials: true` sets the credentials mode to `include` (this is the cross-origin cookie switch).
- Spec mechanics of the request: the constructor builds a **potential-CORS request** whose CORS state is `Anonymous` unless `withCredentials` makes it `Use Credentials` — so a cross-origin stream without `withCredentials` is fetched without cookies, and one with it needs a permissive server-side CORS/Origin posture. The stream request may be redirected with HTTP `301`/`307`, and the dispatched event's `origin` is the origin of the **final URL after redirects**.
- Reconnection re-sends the last `id:` value as the **`Last-Event-ID`** request header; the stream is UTF-8 only, field names are compared **literally (no case folding)**, `retry:` sets the reconnection delay, an `id:` containing NUL is ignored, and an empty `id:` resets the last event ID. A `204 No Content` tells the client to stop reconnecting.
- `Last-Event-ID`'s value space is "essentially any UTF-8 string without U+0000, U+000A, or U+000D" (the spec points to an open issue to define it better) — so treat it as attacker-controlled input on the server side, not as a trusted integer cursor.
- Browser connection limits are a real deployment constraint: over HTTP/1.1 it is ~**6 per browser+domain**, over HTTP/2 the negotiated stream limit (default ~100) applies — this shapes how a researcher parallelises probes and can explain throttled/queued streams that look like isolation failures. The spec also suggests a comment line every 15 seconds to survive proxy idle timeouts, and notes that HTTP chunking can break dispatch timing.

### SSE authentication internals (cookies, tokens, service workers)

- Because `EventSource` cannot set an `Authorization` header, real deployments choose among: cookie auth (browser attaches automatically; CSRF/Origin checks or `SameSite` then carry the whole control), query-parameter tokens (`/stream?token=...`, leaked to logs, browser history, referrers), or a **service worker relay** that intercepts the fetch and rewrites it with the header.
- A controlling service worker can intercept fetch-initiated requests and attach headers before the origin sees them; service workers are the standard place an SPA centralises its auth token, and the same relay that fronts downloads can front a stream. Whether a streaming response passes through a worker unbuffered is browser-dependent (`UNVERIFIED` for `EventSource` specifically) — fingerprint it, do not assume it.
- The auth seam to test: if the SW relays the token, is the stream endpoint *also* reachable without the worker (direct request, cookie-only fallback, worker not yet in control on first load)? A stream that is open without any credential is a finding regardless of how the documented client authenticates.

### WebTransport (W3C + IETF WEBTRANS)

- `WebTransport` is a `SecureContext` API (https only, no fragment) that opens a **session** over a single HTTP/3 or HTTP/2 connection, multiplexing reliable streams and unreliable datagrams. Over HTTP/3 the server must advertise `SETTINGS_WT_ENABLED > 0` and `SETTINGS_H3_DATAGRAM = 1`; over HTTP/2, `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`.
- The session is established by a `CONNECT` whose `:protocol` is `webtransport`, carrying a `WT-Available-Protocols` request header (client MUST NOT set it directly via `options.headers`) and a `wt-protocol` response header. **Redirects are not followed and their errors are made indistinguishable** to avoid a CORS-style info leak.
- Auth is a real seam: the WebTransport `CONNECT` request is created with **credentials mode `omit`**, so the handshake does not attach cookies by default — authentication usually rides an explicit `options.headers` value or a separate bootstrap fetch, and that assumption must be tested per deployment. `serverCertificateHashes` is only honoured on a non-pooled ("new") connection.
- Session auth does not imply per-stream or per-datagram auth: the session is established once, then many streams/datagrams follow. Test acting as A on an authorized session while referencing B's object on a specific stream or datagram.

### Extensions, subprotocols, and negotiation (RFC 6455 §9)

- Extensions are negotiated in the opening handshake via `Sec-WebSocket-Extensions`; a server **MUST NOT** return an extension the client did not offer, and a client **MUST** fail the connection if the response names an unrequested extension. Order is significant — `foo, bar` means data is processed `bar(foo(data))` — and a malformed extension value REQUIRES failing the connection, so this header is another parser surface for gateway-vs-origin disagreement.
- `permessage-deflate` changes frame payload semantics (compressed data + RSV1); a peer that assumes uncompressed payloads, or that mishandles the `client_no_context_takeover`/`server_no_context_takeover` parameters, is a fingerprint and a potential decompression-bomb sink.
- Subprotocols ride `Sec-WebSocket-Protocol`: the server **MUST** select one of the client's offered values or send none. A server that echoes a subprotocol the client never offered, or that switches auth behavior by subprotocol name, is a seam.

### Handshake authentication mechanisms and their seams

- RFC 6455 §10.5 prescribes **no** client-auth method: a server may use any HTTP mechanism — cookies, HTTP auth, or TLS client certificates. There is no "correct" WebSocket auth to assume; fingerprint which one is used and whether it is re-checked after the handshake.
- Cookie auth inherits the cross-site problem: a browser attaches cookies to the handshake, so Origin validation is the only thing stopping a foreign page from opening an authenticated socket (classic CSWSH). Test with a researcher attacker page on a *different* origin.
- Ticket/token auth often rides the URL query string or `Sec-WebSocket-Protocol`; a query-string token leaks into logs and proxies and may stay reusable after logout — test ticket reuse post-revocation and across origins.
- Subprotocol-as-auth: where a server stuffs a token into `Sec-WebSocket-Protocol`, a server that does not validate the value (or reflects an unoffered subprotocol) is the seam.

### Socket.IO (v4) specifics

- Auth runs in middlewares registered with `io.use(...)`, executed **once per connection** (even when the connection consists of multiple HTTP requests), not per message; calling `next(err)` refuses the connection and the client sees `connect_error`. The Socket instance is not yet connected inside the middleware, so a disconnect during a slow middleware emits no `disconnect` event.
- Client credentials are sent in the Socket.IO `auth` option and read server-side as `socket.handshake.auth`; the option may be a function, so a well-built client fetches a fresh token per (re)connect — which only matters if the reconnect actually re-runs the middleware (see recovery below).
- Starting with v4.6.0, `io.engine.use(...)` runs Express-style middleware for **each incoming HTTP request, including the upgrade**; the documented way to apply it only to the handshake is `req._query.sid === undefined`.
- Connection state recovery: when enabled, the server hands out a session with a public `id` and a **private `pid`**, then appends an offset to outgoing packets; on reconnect the client sends `{"pid": ..., "offset": ...}` and the server restores `socket.id`, `socket.rooms`, and `socket.data`. With `skipMiddlewares: true`, recovery skips the auth middleware entirely — the docs explicitly warn this "might allow users blocked during the disconnection period to reconnect without going through the middleware validations". Treat `pid` as a bearer resume credential: if the server accepts a `pid` it did not mint for that principal, recovery becomes cross-session.
- `maxDisconnectionDuration` bounds the backup; the docs advise a sensible finite value. Adapter support for recovery state: built-in in-memory, Redis Streams, and MongoDB (since adapter `0.3.0`) — the plain Redis adapter does **not** support it (PUB/SUB cannot persist packets), and Postgres/cluster adapters were WIP.
- Multi-server deployments once serialized inter-server traffic with Python pickle: python-socketio `< 5.14.0` deserialized broker messages (Redis/Kafka/RabbitMQ) with `pickle.loads`, giving RCE to anyone who can publish on the broker channel (CVE-2025-61765, fixed in 5.14.0 with safer JSON). The broker channel is an authorization boundary even when your app's own clients are authenticated.

### Pusher Channels specifics

- Private/presence subscription requires a server-signed auth token: the client POSTs `socket_id` and `channel_name` to the configured auth endpoint (default `/pusher/auth`), the server returns `200` with `{"auth": "$AUTHORIZATION_STRING"}` (presence adds `channel_data` with the `user_id`), and a non-200 or unparseable body surfaces as `pusher:subscription_error`. The docs' own sample endpoints "authenticate every user" as a warning — a live app that does this is the subscription-bypass bug.
- The app server decides the token's scope; test (a) an endpoint that mints a token for any `channel_name` the caller names, (b) token reuse with a different `socket_id`, and (c) the legacy JSONP `channelAuthorization.transport: 'jsonp'` mode, whose auth response crosses origins as script.
- Client events are an enforced, broker-side ACL: enabled per app, permitted only on private/presence channels, required to be prefixed `client-`, rejected when sent to a channel the connection is not subscribed to, not delivered back to the originator, and rate-limited to 10 messages/second per connection. Presence `user_id` metadata is taken from the server-issued auth token and is trustworthy; a `user_id` embedded in event `data` is attacker-controlled.

### Ably specifics

- Token auth is capability-based: a server-issued token (JWT preferred) carries per-channel capabilities and an optional `clientId`; access tokens have a maximum TTL of 24 hours, revocable tokens 1 hour. `client.auth.authorize()` re-uses the **live connection** to apply narrower or wider capabilities without disconnecting — an ideal control to test whether already-attached channels honour the new capabilities.
- All channels multiplex over the one connection, so connection-level authentication says nothing about channel-level capability: enforcement happens at each attach, and error `40160` is the documented signal that a client attached without the capability — a useful negative control and the trigger applications are told to re-auth on.
- Ably's own docs state API-key origin restrictions are "not a security boundary" (Origin headers are easily spoofed, and requests with no Origin are allowed when restrictions are set), and recommend server-side validation in the token-issuance path instead.
- Connection lifecycle: server heartbeat every 15 s, client declares `disconnected` after 25 s of silence; automatic reconnection attempts every ~15 s for up to two minutes, then `suspended`. Unexpected drops preserve connection state on the server for ~2 minutes. Fatal errors — invalid key, or an auth endpoint returning `403` — move the connection to `failed` with no automatic retry; a `403` from `authUrl`/`authCallback` is the documented way to stop a revoked session from reconnecting.
- Recovery has two modes: `resume` (automatic, same live SDK instance, backlog replayed if within the window) and `recover` (a **new** SDK instance supplies the previous connection's `recoveryKey`, which bundles the private connection key and the last received message serial). On `recover`, channels must be re-attached within 15 seconds or continuity is lost; developers should read the `resumed` flag on `attached` to know whether any messages were missed. The browser `recover` callback persists the key in `sessionStorage` (same-origin, same top-level context only), and multiple SDK instances on one origin can collide on the fixed key. A `recoveryKey` in the wrong hands is a resume credential for that connection's backlog — treat sessionStorage exposure (XSS, shared machines) as a real path.

### Diagnosing why a connection closed (symptom → cause)

| Symptom | Likely cause | What to check next |
|---|---|---|
| `1002` immediately | protocol violation (unmasked frame, bad opcode, nonzero `RSV`) | which §5 rule you broke; confirms the peer enforces framing |
| `1007` | invalid UTF-8 in text payload or Close reason | payload encoding, not authorization |
| `1008` | policy rejection (authz/rate) | whether a *reconnect* re-runs the same gate |
| `1009` | message too big | server size limit; compare frame size vs reassembled size |
| `1011` | server-side error | server fault, not a client protocol bug |
| silent close, `1006` observed | transport loss / half-close | whether a *live* socket still accepts privileged actions |
| `426` + `Sec-WebSocket-Version` | version not supported | the downgrade path and whether an older version skips a gate |
| `501` on an extended `CONNECT` | unknown `:protocol` (RFC 9220/8441) | whether the H1 path would have accepted the same request |

### HTTP/3, QUIC, and datagram transport notes

- WebTransport over HTTP/3 depends on HTTP Datagrams / QUIC **DATAGRAM** frames (RFC 9221) and the `SETTINGS_H3_DATAGRAM` flag; the W3C spec recommends ~64 KiB datagram buffers because the effective max datagram size is bounded by the QUIC max datagram frame size. Datagrams are unreliable and unordered — authorization logic that assumes ordering ("first message is the auth message") is a real seam.
- RFC 9221 mechanics: support is advertised by the `max_datagram_frame_size` transport parameter (`0x20`, default `0`, recommended `65535`), the frames are types `0x30`/`0x31` (LEN bit selects the explicit length), they carry **no flow control** (a receiver may drop them when it cannot keep up; they may also be dropped for congestion control or MTU limits), they are ack-eliciting but never retransmitted, and they belong to the connection, not to a stream — any multiplexing identifier is the application's job. Sending one before negotiation, or larger than advertised, is a `PROTOCOL_VIOLATION` (connection error).
- RFC 9297 layers HTTP Datagrams on top: `SETTINGS_H3_DATAGRAM` (`0x33`, value 0 or 1) gates QUIC-DATAGRAM use, each HTTP/3 datagram carries the Quarter Stream ID of the request it belongs to (connection error `H3_DATAGRAM_ERROR` otherwise), and datagrams arriving after the request stream closed are silently dropped. Over HTTP/1.1 or HTTP/2 the Capsule Protocol conveys datagrams **reliably and in order** instead — a WebTransport-over-H2 deployment therefore has different loss and ordering semantics than the same app over H3, and authorization logic that assumes one transport's guarantees can be exercised by forcing the other.
- WebTransport `sendOrder`/`sendGroup` control *send scheduling*, not authorization; do not read them as security signals. `exportKeyingMaterial` and `getStats` are per-session, not per-stream.
- QUIC-level 0-RTT, connection migration, and stream-reset behaviour belong to the http-edge-cache pack; keep channel-authorization findings here and cross-read when the transport itself is suspect.

### Handshake-derived session context

- A WebSocket handshake is an ordinary HTTP request, and the session context in which every later message is processed is generally fixed at that handshake — so the handshake is the highest-value mutation point, and header-trust decisions (e.g. `X-Forwarded-For`, custom auth headers) taken there become message-level trust (PortSwigger).
- Because it is plain HTTP, the handshake also crosses proxies, CDNs, and translation layers: a re-originated or translated upgrade can present a different Origin/header set at the origin than the browser sent, which is why Origin-enforcement hop must be identified, not assumed.

### Broker auth surfaces at a glance

| Broker | Subscription auth | Resume primitive | Re-auth / down-scope |
|---|---|---|---|
| Socket.IO v4 | `io.use` middleware on the connection; app decides rooms | private session `pid` + offset (recovery), middleware skippable | reconnect with fresh `auth` token |
| Pusher Channels | server-signed `auth` token per channel (`socket_id` + `channel_name`) | none (no server-side backlog; reconnect re-subscribes and re-authorizes) | endpoint called again on re-subscribe |
| Ably | per-channel capabilities inside the token | `recoveryKey` (`recover`) or automatic `resume` inside ~2 min | `authorize()` on the live connection |

### Gateway, proxy, and library variance

- Socket libraries and gateways differ on where auth runs (upgrade handler, subscription guard, per-message hook, resume path); test each leg because one guarded leg does not imply all legs.
- Resume and backlog behavior varies by broker, window size, retention, and clock handling; re-test resume IDs after the documented retention window.
- Origin and host validation differs between standalone socket servers, gateway-proxied sockets, and translated gRPC-web paths; confirm which hop validates Origin.
- Binary, text, ping, close, and continuation handling differs per server and version; malformed-frame probes stay single-shot and low-rate unless DoS testing is explicitly permitted.

### Transport constraint matrix

| Transport | Client can set custom headers | Cookies by default | Channel model | Primary auth seam |
|---|---|---|---|---|
| WebSocket over HTTP/1.1 | no (browser API) | yes (Origin-scoped) | multiplexed frames | handshake auth reused as per-message auth |
| WebSocket over HTTP/2 (RFC 8441) | no | yes | one HTTP/2 stream | HTTP/1.1 vs HTTP/2 handshake path disagreement |
| WebSocket over HTTP/3 (RFC 9220) | no | yes | one HTTP/3 stream | H1/H2 vs H3 extended-CONNECT auth disagreement |
| SSE (`EventSource`) | no | only with `withCredentials` | one event stream | query-token fallback; `Last-Event-ID` replay; service-worker relay |
| WebTransport | via `options.headers` | **no** (credentials mode `omit`) | streams + datagrams per session | session auth assumed for every stream/datagram |
| Broker SDK (Socket.IO / Pusher / Ably) | library-specific | library-specific | rooms / channels / capabilities | subscription ACL, resume identity, re-auth semantics |

## References

- [T0 standard] RFC 6455, The WebSocket Protocol (handshake §4, framing §5, close codes §7.4, security §10): https://www.rfc-editor.org/rfc/rfc6455.html
- [T0 standard] RFC 8441, Bootstrapping WebSockets with HTTP/2 (extended `CONNECT`, `:protocol`, `SETTINGS_ENABLE_CONNECT_PROTOCOL`): https://www.rfc-editor.org/rfc/rfc8441.html
- [T0 standard] RFC 9220, Bootstrapping WebSockets with HTTP/3 (H3 settings `0x08`, `501` for unknown `:protocol`, FIN vs `H3_REQUEST_CANCELLED`): https://www.rfc-editor.org/rfc/rfc9220.html
- [T0 standard] RFC 9221, An Unreliable Datagram Extension to QUIC (`max_datagram_frame_size` `0x20`, DATAGRAM frames `0x30`/`0x31`, no flow control): https://www.rfc-editor.org/rfc/rfc9221.html
- [T0 standard] RFC 9297, HTTP Datagrams and the Capsule Protocol (`SETTINGS_H3_DATAGRAM` `0x33`, Quarter Stream ID, `H3_DATAGRAM_ERROR`): https://www.rfc-editor.org/rfc/rfc9297.html
- [T0 standard] WHATWG HTML, Server-Sent Events (`EventSource`, potential-CORS request, `Last-Event-ID`, redirects, reconnection, `204`): https://html.spec.whatwg.org/multipage/server-sent-events.html
- [T0 standard] W3C WebTransport (Candidate Recommendation; sessions, streams, datagrams, `CONNECT` semantics): https://www.w3.org/TR/webtransport/
- [T1 vendor] MDN, `EventSource` (no custom headers; HTTP/1.1 6-connection limit, HTTP/2 ~100): https://developer.mozilla.org/en-US/docs/Web/API/EventSource
- [T1 vendor] MDN, `WebSocket` API (no custom handshake headers, no backpressure, `bufferedAmount`): https://developer.mozilla.org/en-US/docs/Web/API/WebSocket
- [T1 vendor] Socket.IO, Connection state recovery (private `pid`, offset, `skipMiddlewares` caution, adapter support): https://socket.io/docs/v4/connection-state-recovery
- [T1 vendor] Socket.IO, Middlewares (`io.use` once per connection, `handshake.auth`, `io.engine.use` per HTTP request including upgrade): https://socket.io/docs/v4/middlewares/
- [T1 vendor] Pusher Channels, Authorizing users (signed auth token contract, `socket_id`/`channel_name`, presence `channel_data`, JSONP transport): https://pusher.com/docs/channels/server_api/authorizing-users/
- [T1 vendor] Pusher Channels, Events (client-event restrictions, `client-` prefix, origin exclusion, 10 msg/s, presence `user_id` provenance): https://pusher.com/docs/channels/using_channels/events/
- [T1 vendor] Ably, Connections overview (multiplexing, heartbeats, 2-minute state preservation): https://ably.com/docs/connect
- [T1 vendor] Ably, Connection state and recovery (`resume` vs `recover`, `recoveryKey`, 15-second reattach, `sessionStorage` persistence, fatal `403`): https://ably.com/docs/connect/states
- [T1 vendor] Ably, Token auth (capabilities, 24 h / 1 h TTL limits, `authorize()` on a live connection, API-key origin restrictions not a security boundary): https://ably.com/docs/auth/token
- [T1 vendor] Next.js documentation (route handlers, streaming): https://nextjs.org
- [T2 research] PortSwigger Web Security Academy: WebSocket hijacking, handshake manipulation, access-control oracles — https://portswigger.net/web-security/websockets
- [T2 research] Christian Schneider, Cross-Site WebSocket Hijacking (CSWSH originator writeup; Origin check and handshake-token countermeasures): https://www.christian-schneider.net/blog/cross-site-websocket-hijacking/
- [T2 research] hahwul, How to Securing SSE (EventSource cannot set `Authorization`; cookie vs query-token auth; Origin/CSRF posture): https://www.hahwul.com/sec/web-security/sse/
- [T2 research] Bartosz Polnik, Using Service Worker as an auth relay (fetch interception attaching auth headers; demonstrates the relay pattern): https://itnext.io/using-service-worker-as-an-auth-relay-5abc402878dd
- [T2 research] BlueRock Security, CVE-2025-61765: RCE in the Socket.IO ecosystem (python-socketio pickle deserialization of broker messages, fixed in 5.14.0): https://www.bluerock.io/post/cve-2025-61765-bluerock-discovers-critical-rce-in-socket-io-ecosystem
- http-edge-cache/http-desync-cache.md for framing, multiplexing, and connection-reuse differentials referenced by this pack
