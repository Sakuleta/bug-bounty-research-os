# Freshness Watchtower

Static checklists rot. Three 2026 facts force a per-engagement freshness loop: Chrome moved to a 2-week release cycle from Sept 2026 (v153+, https://developer.chrome.com/blog/chrome-two-week-release), OWASP published Top 10 for Agentic Applications 2026 (https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), and PortSwigger's Terminator research (Aug 2026, https://portswigger.net/research/http-terminator) added new desync primitives including dangling-byte for response queue poisoning. A technique list pinned at engagement start is stale by week three.

## Mechanism

Run at engagement start, then re-run on every trigger below. Cheap by design: fingerprint, diff, map, hypothesize.

```text
FINGERPRINT -> VERSION -> CHECK advisories/changelogs/research
  -> MAP new primitives to this stack -> HYPOTHESIZE or DISCARD with reason
```

1. FINGERPRINT — Record target components and versions: browser-relevant behavior, framework, proxy/CDN headers, auth provider, AI/agent endpoints if present. Source: banners, headers, JS bundles, error pages, docs.
2. VERSION — Pin each component in `10_learning/freshness.yaml`. Unversioned entries are treated as unknown, never as current.
3. CHECK — Query, in order: vendor advisory/security feed, framework changelog, PortSwigger Web Security Academy/blog, OWASP releases, BH/DC talks, Hacktivity writeups for the same stack, CVE/CWE entries.
4. MAP — For each new item ask: does this primitive's precondition exist in THIS architecture? If no precondition match, discard with one-line reason. Never import a public exploit blind.
5. HYPOTHESIZE — Surviving primitives become hypotheses in `03_hypotheses/` with source link and affected pinned version.

## Source priority

| Order | Source | What to pull |
|---|---|---|
| 1 | Vendor advisory / security feed | patches touching parse, auth, session, crypto |
| 2 | Framework changelog | parse/serialize/auth/routing diffs since pinned version |
| 3 | PortSwigger Academy / blog | new primitives and gadget classes |
| 4 | OWASP releases | new categories relevant to target (agentic, API, web) |
| 5 | BH / DC talks | stack-specific novel chains |
| 6 | Hacktivity writeups | same-technology confirmed techniques |
| 7 | CVE / CWE | version-range matches for pinned components |

Walk the table top-down per component. Note the last-checked date per source in the ledger.

## Watchtower triggers

Re-run the CHECK step immediately when any of these occur mid-engagement:

- New browser minor release (Chrome 2-week cadence: assume behavior drift in CORS, cookie, fetch, or cache handling).
- Framework minor/major release in the target stack (parse, serialize, auth, or routing changes).
- New PortSwigger or OWASP release touching a relevant class (desync, cache, auth, agentic).
- New CVE in any pinned component (map precondition before testing anything).

Trigger response budget: one CHECK pass per trigger, max ~30 minutes. File hypotheses or write discard reasons, then resume cycles.

## Worked example

Pinned: `terminator at 2026-09-01 behavior`. Trigger: Terminator research (Aug 2026) describes dangling-byte suffixes. MAP: target reuses keep-alive through a terminator/adapter (header evidence) — precondition plausible. HYPOTHESIZE: file H-14 with timing oracle. DISCARD case: if target closes connections per request (no reuse observed), discard with "no keep-alive reuse, dangling bytes cannot attach".

## Freshness ledger

Schema: `10_learning/freshness.yaml`. One entry per pinned component.

```yaml
- target_component: "cdn-terminator"
  pinned_version: "observed 2026-09-01, vX (header evidence)"
  last_checked: "2026-09-20"
  sources: ["vendor-changelog", "portswigger-blog", "cve-feed"]
  new_primitives: ["dangling-byte suffix (mapped: yes, H-14)"]
  action: "hypothesis filed / discarded: no keep-alive reuse on this host"
```

## Enforcement (the clock is mechanical)

The ledger is an event projection, not a hand file: `researchctl freshness record payload.json`
writes `FRESHNESS_RECORDED` (a later record replaces the previous ledger) and
`10_learning/freshness.yaml` is rebuilt from it. `researchctl freshness status` prints age,
staleness and pin state per component. `tools/audit.py` fails the workspace when any
component's `last_checked` is older than its `max_age_days` (default 14) — a stale
watchtower is an error, not a nudge — and warns on `UNKNOWN` pins so an unpinned component
stays visible. `11_runtime/current-context.md` carries the ledger, so the controller sees
the clock on every rebuild. Scanning sources stays agent web research; only the clock and
the record are mechanical.

## Rule

Never test a public exploit blind. Prove architectural relevance first: name the precondition, confirm it exists on target, then build the minimal target-specific proof. A PoC that fires elsewhere is reading material, not evidence.
