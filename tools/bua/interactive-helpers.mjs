/**
 * Research OS — the interactive arm's own copy of the shared scope/mask/guard helpers.
 *
 * `tools/bua/run.mjs` is the read-only default arm and stays untouched (SPRINT-BUA-SPEC
 * B1: "read-only `run.mjs` untouched as the default arm"). The write-capable arm needs
 * the same per-request scope interception, masking and worker guards, so this module
 * carries them for the interactive side: duplication over coupling is the spec's
 * explicit trade — the read-only runner must never grow exports or behavior to serve a
 * write-capable caller. Every function here mirrors the read-only runner's helper block
 * (same masking rules, same scope seam, same fail-closed caps); the interactive guard
 * suite pins the behavior this arm relies on.
 */
import { execFileSync } from 'node:child_process'
import { existsSync, realpathSync } from 'node:fs'
import { join, relative, resolve, sep } from 'node:path'

/** The helper module's own usage refusal: the read-only runner's `usage` exits the
 *  process, but this module must stay importable, so it throws a coded error instead —
 *  the interactive CLI maps code 2 to its usage exit. */
function usage(msg) {
  const error = new Error(msg)
  error.code = 2
  throw error
}
// Local mirror of the enforcer's `redactUrlSecrets` (dsh-plugin/index.js): the runner's
// own JSON summary is written by this process, so the plugin cannot sanitize it. Mask
// sensitive query/fragment parameter VALUES — name matched case-insensitively as a
// substring after percent-decoding, separators `&`/`;`, query AND fragment — plus
// secret-shaped values under benign names. Scheme, host, port and path stay untouched.
const SENSITIVE_QUERY_MARKERS = /(token|secret|key|auth|sig|session|code|password|passwd|cookie)/i
// A sensitive assignment nested inside ANOTHER component's decoded value: a
// double-encoded `next=/cb%26token%3Dxyz` decodes once to `next=/cb&token=xyz`.
const NESTED_SENSITIVE_ASSIGNMENT = /(^|[&;])\s*[A-Za-z0-9_.-]*(token|secret|key|auth|sig|session|code|password|passwd|cookie)[A-Za-z0-9_.-]*\s*=/i

/** Percent-decode tolerantly: valid escapes decode, malformed escapes and invalid
 *  UTF-8 stay as replacement-safe text (mirrors Python's `urllib.parse.unquote`). */
function decodeTolerant(text) {
  const bytes = []
  for (let i = 0; i < text.length; i++) {
    const esc = text[i] === '%' ? text.slice(i + 1, i + 3) : ''
    if (/^[0-9A-Fa-f]{2}$/.test(esc)) {
      bytes.push(parseInt(esc, 16))
      i += 2
    } else {
      for (const b of Buffer.from(text[i], 'utf8')) bytes.push(b)
    }
  }
  return Buffer.from(bytes).toString('utf8')
}
// BEGIN-GENERATED-SECRET-PATTERNS
// Source of truth: tools/secret-patterns.json — do not hand-edit; run python3 tools/generate_secret_patterns.py.
const SECRET_SHAPES = [
  /glpat-[A-Za-z0-9_.-]{16,}/g,
  /github_pat_[A-Za-z0-9_]{20,}/g,
  /gh[pousr]_[A-Za-z0-9]{16,}/g,
  /xox[baprs]-[A-Za-z0-9-]{10,}/g,
  /AKIA[0-9A-Z]{16}/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
  /eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\./g,
]
// END-GENERATED-SECRET-PATTERNS

function scrubSecrets(text) {
  let out = String(text == null ? '' : text)
  for (const re of SECRET_SHAPES) out = out.replace(re, '[REDACTED]')
  return out
}

function maskQueryPart(part) {
  const eq = part.indexOf('=')
  const name = eq < 0 ? part : part.slice(0, eq)
  let decoded = name
  try { decoded = decodeURIComponent(name) } catch {}
  if (SENSITIVE_QUERY_MARKERS.test(decoded)) return `${name}=[REDACTED]`
  if (eq < 0) return part
  const value = part.slice(eq + 1)
  if (NESTED_SENSITIVE_ASSIGNMENT.test(decodeTolerant(value))) return `${name}=[REDACTED]`
  return `${name}=${scrubSecrets(value)}`
}

export function maskUrlSecrets(url) {
  const raw = String(url == null ? '' : url)
  return raw.replace(/[?#][^\s#?]*/g,
    (seg) => seg[0] + seg.slice(1).split(/([&;])/).map((tok, i) => (i % 2 ? tok : maskQueryPart(tok))).join(''))
}

// ---- per-request scope interception (pure decision helpers, unit-testable) ---------
// Only schemes that cannot produce network traffic are exempt from the scope check;
// everything else must be a verified `in_scope: true` from the authoritative seam.
const SCHEME_EXEMPT = new Set(['data:', 'blob:', 'about:', 'filesystem:'])

/** True when the URL's scheme generates no network traffic (blob objects are in-memory,
 *  filesystem: is origin-local storage), so no scope check applies. */
export function schemeAllowed(url) {
  try { return SCHEME_EXEMPT.has(new URL(url).protocol) } catch { return false }
}

/** Cache key: the raw authority as written — userinfo stripped, ONE trailing dot
 *  stripped, lowercased — with the port preserved exactly as written. This mirrors
 *  `control_plane._normalize_host` (the seam's own unit), so the cache never merges
 *  `t.example:443` with `t.example` (the seam judges them different authorities) and
 *  never splits `t.example.` from `t.example` (the seam treats them as one).
 *  `new URL().host` would do both wrong: it collapses default ports and keeps the
 *  trailing dot.
 *
 *  An ambiguous authority (backslash, whitespace/control characters, encoded
 *  backslash — the WHATWG fetch stack would terminate or reinterpret it) has NO
 *  cache key: it must never merge with a cached allow verdict for the clean host,
 *  and `decideRequest` denies it without consulting the seam. */
const AUTHORITY_AMBIGUOUS = /[\\\s\x00-\x1f\x7f]|%5c/i
export function authorityAmbiguous(url) {
  const raw = String(url == null ? '' : url)
  const authority = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/?#]*)/.exec(raw)
  return !!authority && (!authority[1] || AUTHORITY_AMBIGUOUS.test(authority[1]))
}
export function hostKey(url) {
  const raw = String(url == null ? '' : url)
  const authority = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/?#]*)/.exec(raw)
  if (!authority) {
    try { return new URL(raw).host || undefined } catch { return undefined }
  }
  if (!authority[1] || AUTHORITY_AMBIGUOUS.test(authority[1])) return undefined
  let host = authority[1].split('@').pop()
  if (host.endsWith('.')) host = host.slice(0, -1)
  return host.toLowerCase() || undefined
}

/** Distinct hosts the authoritative seam may be spawned for in one run. A hostile page
 *  can point at unbounded subresource hosts; past the cap every further host fails
 *  closed without spawning (`reason: host_check_budget_exceeded`). */
export const DISTINCT_HOST_CHECK_CAP = 64

/** One authoritative verdict per host[:port] per run, failures cached too: a failing
 *  seam must stay fail-closed for every later request to that host, not flap per request. */
export function makeScopeCache(scopeCheckFn, cap = DISTINCT_HOST_CHECK_CAP) {
  const verdicts = new Map()
  return {
    seed(host, verdict) { if (host && !verdicts.has(host)) verdicts.set(host, verdict) },
    async check(url) {
      const host = hostKey(url)
      if (host && verdicts.has(host)) return verdicts.get(host)
      if (host && verdicts.size >= cap) {
        return { in_scope: false, gate: 'error', reason: 'host_check_budget_exceeded',
                 error: `distinct-host scope-check budget exceeded (cap ${cap})` }
      }
      let verdict
      try {
        const raw = await scopeCheckFn(url)
        verdict = { in_scope: raw != null && raw.in_scope === true, gate: raw == null ? undefined : raw.gate }
      } catch (e) {
        verdict = { in_scope: false, gate: 'error', error: String(e.message || e) }
      }
      if (host) verdicts.set(host, verdict)
      return verdict
    },
  }
}

/** Decide one intercepted request: an exempt scheme, or the cached authoritative verdict.
 *  Anything that is not http(s)/ws(s) with a verified in-scope verdict is blocked (fail
 *  closed). WebSockets are checked like their http(s) equivalent — ws: is the ws twin of
 *  http:, wss: of https: — never treated as traffic-free. An ambiguous authority is
 *  denied without consulting the seam: the fetch stack would connect somewhere the
 *  verdict does not describe. */
export async function decideRequest(url, cache) {
  const host = hostKey(url)
  if (schemeAllowed(url)) return { allow: true, reason: 'scheme_exempt', host }
  let parsed
  try { parsed = new URL(url) } catch { return { allow: false, reason: 'invalid_url', host } }
  if (!['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol)) {
    return { allow: false, reason: 'scheme_blocked', host }
  }
  if (authorityAmbiguous(url)) return { allow: false, reason: 'ambiguous_authority', host }
  const verdict = await cache.check(url)
  if (verdict.in_scope === true) return { allow: true, reason: 'in_scope', host }
  if (verdict.reason) return { allow: false, reason: verdict.reason, host }
  return { allow: false, reason: verdict.error ? 'scope_check_failed' : 'out_of_scope', host }
}

/** Mask everything that must never reach a file or a log: sensitive URL values (the
 *  runner's masker) plus secret shapes anywhere in free text (an error message can
 *  quote a URL or carry a bare token). */
export function maskText(text) {
  return scrubSecrets(maskUrlSecrets(String(text == null ? '' : text)))
}

/** Blocked requests stay summarized, not streamed: capped list + full count, masked. */
const BLOCKED_REQUESTS_CAP = 50
export function recordBlocked(summary, url, host, reason) {
  summary.blocked_count += 1
  if (summary.blocked_requests.length < BLOCKED_REQUESTS_CAP) {
    summary.blocked_requests.push({ host, url_masked: maskUrlSecrets(url), reason })
  }
}

/** Record one followed redirect hop: capped list + full count, masked. The entry
 *  carries the seam's real decision reason (`out_of_scope`, `host_check_budget_exceeded`,
 *  `scope_check_failed`, …) — never a blanket out-of-scope label — so audits and
 *  warnings cannot misread authority saturation as scope drift. */
const OUT_OF_SCOPE_HOPS_CAP = 50
export function recordOutOfScopeHop(summary, url, host, reason) {
  summary.out_of_scope_hop_count += 1
  if (summary.out_of_scope_hops.length < OUT_OF_SCOPE_HOPS_CAP) {
    summary.out_of_scope_hops.push({ host, url_masked: maskUrlSecrets(url), reason: reason || 'out_of_scope' })
  }
}

/** The one collector of followed out-of-scope redirect hops. `context.route` never sees
 *  a redirect hop, so a real redirect chain is witnessed only by walking
 *  `redirectedFrom()` — from a Response (subresource or navigation) or from the Request
 *  of a failed navigation. Returns the out-of-scope hops of the walked chain (so the
 *  caller can flag a scope violation) and records the newly seen ones; `seen` dedupes
 *  across the several responses that re-walk the same chain. */
export function makeHopCollector(summary, cache, warn = console.log) {
  const seen = new Set()
  return async function collectOutOfScopeHops(source) {
    const found = []
    for (const hop of redirectChain(source)) {
      const decision = await decideRequest(hop, cache)
      if (decision.allow) continue
      found.push({ url: hop, host: decision.host })
      if (seen.has(hop)) continue
      seen.add(hop)
      recordOutOfScopeHop(summary, hop, decision.host, decision.reason)
      warn(`bua-runner: WARNING followed redirect hop denied (${decision.reason || 'out_of_scope'}; ` +
        `playwright does not route redirect hops) host=${decision.host || '-'} url=${hop}`)
    }
    return found
  }
}

/** The `context.routeWebSocket` handler: the same cache/decision as `context.route`,
 *  but the allowed socket is connected and anything else is closed, never connected.
 *
 *  Route coverage is page-realm only (the router overrides the page's WebSocket
 *  constructor): sockets opened from dedicated workers or service workers never reach
 *  this handler — see `observeWorkerWebSocket` and the service-worker block below. */
export function makeWebSocketHandler(summary, cache, warn = console.log) {
  return async function handleWebSocket(ws) {
    const url = ws.url()
    const decision = await decideRequest(url, cache)
    if (decision.allow) return ws.connectToServer()
    recordBlocked(summary, url, decision.host, decision.reason)
    warn(`bua-runner: blocked ${decision.reason} ws host=${decision.host || '-'}`)
    return ws.close()
  }
}

/** The service-worker block, installed with `context.addInitScript` before the first
 *  navigation: new registrations are rejected (loudly, via the page console) and
 *  registrations lingering from a reused profile are unregistered. A service worker
 *  runs outside every route handler, so registration must never succeed here. */
export function serviceWorkerInitScript() {
  return `(() => {
  try {
    if (navigator.serviceWorker && navigator.serviceWorker.getRegistrations) {
      navigator.serviceWorker.getRegistrations()
        .then((rs) => Promise.all(rs.map((r) => r.unregister().catch(() => {}))))
        .catch(() => {});
    }
  } catch (e) { /* no service-worker support: nothing to block */ }
  try {
    if (navigator.serviceWorker && navigator.serviceWorker.register) {
      navigator.serviceWorker.register = function () {
        console.log('bua-runner: service worker registration blocked');
        return Promise.reject(new Error('bua-runner: service workers are disabled in the controlled context'));
      };
    }
  } catch (e) { /* non-configurable: the serviceworker event backstop still flags */ }
})();`
}

/** Backstop for a service worker that appears despite the registration block (a
 *  pre-existing controller winning a race, a profile with stored workers): record a
 *  violation, capture skipped, never silent — its traffic bypasses every route handler, so it must
 *  never pass silently. */
export function makeServiceWorkerHandler(summary, warn = console.log) {
  return async function handleServiceWorker() {
    summary.service_worker_violations = (summary.service_worker_violations || 0) + 1
    summary.scope_violation = true
    warn('bua-runner: WARNING a service worker appeared in the controlled context ' +
      'despite the registration block — flagging a scope violation')
  }
}

/** Observe one worker-opened socket the route layer may never see (CDP
 *  `Network.webSocketCreated` via auto-attach): an in-scope socket is ignored; an
 *  out-of-scope socket the route layer already blocked is not counted twice; one it
 *  missed is recorded as a scope violation, capture skipped, never silent. */
export async function observeWorkerWebSocket(summary, cache, url, warn = console.log) {
  const decision = await decideRequest(url, cache)
  if (decision.allow) return { flagged: false }
  const masked = maskUrlSecrets(url)
  const seen = (summary.blocked_requests || []).some((b) => b.url_masked === masked)
  if (seen) return { flagged: false, alreadyBlocked: true }
  recordBlocked(summary, url, decision.host, decision.reason)
  summary.scope_violation = true
  warn(`bua-runner: WARNING out-of-scope worker websocket missed by the route layer ` +
    `host=${decision.host || '-'} — flagging a scope violation`)
  return { flagged: true }
}

/** Masked redirect hops (oldest -> newest) of a navigation, bounded so a hostile
 *  redirect loop cannot inflate the summary. Accepts a Response, or a Request when the
 *  navigation failed and there is no response (a redirect hop that never resolved still
 *  walks back through `redirectedFrom()`). */
const REDIRECT_CHAIN_CAP = 20
export function redirectChain(source) {
  const hops = []
  let request = source == null ? null
    : typeof source.redirectedFrom === 'function' ? source
      : typeof source.request === 'function' ? source.request() : null
  while (request && hops.length < REDIRECT_CHAIN_CAP) {
    hops.push(maskUrlSecrets(request.url()))
    request = typeof request.redirectedFrom === 'function' ? request.redirectedFrom() : null
  }
  return hops.reverse()
}

/** True when `text` carries a secret-shaped value (the masker's own shapes). A credential
 *  must never be typed into a target field through the interactive arm: `TYPE` refuses
 *  secret-shaped payloads and credentials enter only through the env-only LOGIN flow. */
export function hasSecretShape(text) {
  const raw = String(text == null ? '' : text)
  return scrubSecrets(raw) !== raw
}

/** Walk up from cwd for a Research OS workspace root. Any one of the ledger, the
 *  engagement binding or the runtime directory marks the workspace (mirroring
 *  dsh-plugin/index.js, so deleting the OS_VERSION marker cannot disarm the
 *  runner); a directory with none of them is not a workspace (fail closed). */
export function findOsRoot(cwd) {
  let dir = resolve(cwd)
  for (let i = 0; i < 12; i++) {
    if (existsSync(join(dir, '11_runtime', 'events.jsonl'))
      || existsSync(join(dir, '00_control', 'engagement.yaml'))
      || existsSync(join(dir, '11_runtime'))) return dir
    const parent = resolve(dir, '..')
    if (parent === dir) break
    dir = parent
  }
  return undefined
}

/** Keep workspace-owned paths inside the workspace. */
export function insideRoot(root, rel, flag) {
  const abs = resolve(root, rel)
  if (abs !== resolve(root) && !abs.startsWith(resolve(root) + sep)) {
    usage(`${flag} must stay inside the workspace (got ${rel})`)
  }
  return abs
}

/** Resolve `--profile` to a real directory under the workspace's lab root.
 *
 *  Lexical containment is not containment: a workspace symlink (`lab/profile -> /tmp/x`)
 *  passes a string-prefix check while pointing outside, so the nearest existing ancestor
 *  of the profile path is realpath-resolved and must stay under `<root>/lab`. A profile
 *  inside the workspace but outside `lab/` is refused too — the interactive arm runs on a
 *  dedicated per-engagement lab profile only (never a shared/personal one). */
export function resolveProfileDir(root, rel) {
  const abs = insideRoot(root, rel, '--profile')
  const rootAbs = resolve(root)
  const labAbs = join(rootAbs, 'lab')
  if (abs !== labAbs && !abs.startsWith(labAbs + sep)) {
    usage(`--profile must stay under the workspace lab/ root (got ${rel})`)
  }
  let rootReal
  try { rootReal = realpathSync(rootAbs) } catch { usage(`the workspace root is not resolvable (got ${rel})`) }
  const labReal = join(rootReal, 'lab')
  let probe = abs
  while (!existsSync(probe)) {
    const parent = resolve(probe, '..')
    if (parent === probe) break
    probe = parent
  }
  let real
  try { real = realpathSync(probe) } catch { usage(`--profile is not resolvable (got ${rel})`) }
  const target = probe === abs ? real : join(real, relative(probe, abs))
  if (target !== labReal && !target.startsWith(labReal + sep)) {
    usage(`--profile resolves outside the workspace lab/ root (got ${rel})`)
  }
  return abs
}

/** The authoritative scope seam. `researchctl scope-check` exits non-zero on a denied
 *  target with the verdict still on stdout (researchctl.py returns 3 when in_scope is
 *  false); any other spawn/parse failure throws and every caller fails closed. */
export function scopeCheckVerdict(url, root) {
  try {
    return JSON.parse(execFileSync(
      'python3',
      [join(root, 'tools', 'researchctl.py'), root, 'scope-check', url],
      { encoding: 'utf8', timeout: 30000 },
    ))
  } catch (e) {
    let parsed = null
    try { parsed = JSON.parse(String(e.stdout || '')) } catch { /* not JSON */ }
    if (parsed && parsed.in_scope !== true) return parsed
    throw e
  }
}
