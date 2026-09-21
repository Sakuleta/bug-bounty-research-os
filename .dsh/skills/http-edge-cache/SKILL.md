---
name: http-edge-cache
description: "HTTP edge and cache behavior — request smuggling and desync (CL.TE, H2.CL, dangling bytes), cache poisoning and deception, host routing, HTTP/2–3 intermediary mismatches."
---

# HTTP / Edge / Cache

Two components in series resolving the same bytes differently — that disagreement is the bug. Every finding is a **trigger** (a parsing ambiguity the pair disagrees on) paired with a **gadget**: a queue, a cache, a redirect, a stored prefix that turns the disagreement into impact.

## Run this

1. **Baseline first** — the same request from two clean sessions: status, cache headers (`Age`, `X-Cache`, `CF-Cache-Status`), body hash, timing median over 5 samples. Done when the baseline table is written down.
2. **Probe the ambiguity non-destructively** — dual `Content-Length: 4`, `Transfer-Encoding: xchunked` (backends must ignore it), whitespace and casing variants. Identical handling on both layers is a recorded negative; stop the probe there.
3. **Time the following request** — smuggle a prefix pointing at a delay endpoint you control, then measure the *next* request's latency against a 5-sample interleaved control. Done when desync delay is separated from PoP jitter.
4. **Reflect a canary through one unkeyed input** — a unique token, no script; fetch the same URL with a cache-buster from a second session and look for the canary in the cached body.
5. **Check the deception shape** — request the `;.css`/`.css`-suffixed authenticated URL anonymously from a fresh profile; compare the body hash against the authenticated baseline.
6. **Fingerprint before choosing the oracle** — connection pinning (queue poisoning viable) vs per-request rotation (cache only); an H2→H1 translation in the path is the highest-yield surface.

## Done when

- Every candidate ambiguity has a verdict: identical handling (negative), divergent handling with a timing or queue oracle, or a persisted cache canary.
- Each oracle class carries one negative control; the canary is absent from clean cache.
- The tested hop path (client → edge → origin) is named for every result.

## Stop conditions

A 5xx spike; another user's session invalidated; poisoned content visible to a third party; a WAF block. Halt and report the oracle; leave any poisoned entry untouched for the program to clear. DoS-shaped triggers (CONTINUATION floods, compression bombs) run only where the program permits DoS testing.

## Depth

Field guide: `12_knowledge/http-edge-cache/http-desync-cache.md` — families, oracle catalog, false-positive disambiguation, per-vendor cache-key and connection-reuse notes, HTTP Terminator (2026) research links.
