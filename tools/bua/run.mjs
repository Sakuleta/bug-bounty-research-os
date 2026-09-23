#!/usr/bin/env node
/**
 * Research OS — canonical BUA runner (v1: read-only navigate + capture).
 *
 * The browser arm of the executor discipline: `researchctl prepare` (tool_family
 * "browser") -> the `research_os_browser` DSH tool consumes the token and spawns
 * THIS runner -> scope guard -> capture -> evidence + ACTION_RECORDED.
 *
 * Usage:
 *   node tools/bua/run.mjs --url <target> --principal <label>
 *        [--out-dir 08_artifacts/raw] [--action A-000001] [--profile lab/bua-profile]
 *
 * Rules (15_TOOLING.md, "Browser automation (BUA)"):
 *   - scope guard in code: the target passes `researchctl scope-check` against
 *     00_control/engagement.yaml before the browser starts (exit 4 when denied), AND
 *     every intercepted http(s)/ws(s) request the context makes — the navigation, every
 *     subresource (JS/CSS/XHR) and every page-realm WebSocket upgrade — is checked
 *     against the same seam before it leaves the machine (`context.route` plus
 *     `context.routeWebSocket`, which only sees the page realm): any non-exempt
 *     request that is not a verified `in_scope: true` is aborted with
 *     `blockedbyclient` (a websocket is closed instead of connected) and recorded in the summary
 *     (`blocked_requests`, `blocked_count`), so a scoped page cannot embed traffic to
 *     an out-of-scope host. Service workers are blocked outright (registration is
 *     rejected and lingering registrations unregistered before the first navigation;
 *     a worker that appears anyway is recorded as a scope violation, capture skipped, never silent). Dedicated-worker sockets never
 *     reach the route layer, so they are observed over CDP auto-attach
 *     (`Network.webSocketCreated`): an out-of-scope worker socket the route layer
 *     missed is recorded as a scope violation, capture skipped, never silent.
 *     (A playwright-core too old for `routeWebSocket` cannot enforce the ws/wss half:
 *     the run is refused instead of proceeding unchecked — upgrade to enforce.)
 *     Distinct hosts are checked at most `DISTINCT_HOST_CHECK_CAP` times per run; past
 *     the cap every further host fails closed without spawning the seam
 *     (`reason: host_check_budget_exceeded`);
 *   - known limit (playwright): `context.route` treats a request and its redirects as
 *     one unit, so a redirect hop is followed by the browser and never reaches the
 *     handler. Every hop that produced a response is RECORDED (`redirect_chain`, also
 *     when the navigation then fails; `out_of_scope_hops` +
 *     `out_of_scope_hop_count` collect the hops that left scope, each with a loud
 *     WARNING in the run log), but a hop cannot be blocked through the route API —
 *     preflight a redirect target explicitly before relying on it;
 *   - a navigation that followed an out-of-scope hop is not captured as a normal
 *     artifact: the screenshot and page title are skipped and `scope_violation` is set
 *     (the exit code stays 0 — the chain and the hops are the product);
 *   - dedicated per-engagement profile inside the workspace — never the personal one —
 *     and the context refuses downloads (`acceptDownloads: false`);
 *   - read-only default: navigate + screenshot + page metadata + masked redirect chain.
 *     The runner's own actions are read-only; a page-initiated in-scope write (a form
 *     the page submits, an XHR the page fires) is still inside the scope guard because
 *     every request is intercepted, but no runner API call changes target state. A task
 *     that changes state on its own belongs in its own script with its documented
 *     precondition; this runner simply has no write path;
 *   - capture: screenshot PNG + JSON summary under the out dir; cookie VALUES are
 *     never read or logged (presence-only rule), secrets never printed (blocked
 *     requests, redirect hops and error text are masked).
 *
 * Exit codes: 0 ran (a page-level error is captured, not fatal — the capture is the
 *   product); 2 usage/root problem; 3 browser not provisioned or launch failed;
 *   4 scope denied.
 *
 * Provisioning (lab tooling): npm i -D playwright-core && npx playwright install chromium
 * or set RESEARCH_OS_CHROME to a Chrome/Chromium executable path.
 */
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { join, resolve, sep } from 'node:path'
import { pathToFileURL } from 'node:url'

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
/** True when `text` carries a secret-shaped value (the masker's own shapes). A credential
 *  must never be typed into a target field through the interactive arm: `TYPE` refuses
 *  secret-shaped payloads and credentials enter only through the env-only LOGIN flow. */
export function hasSecretShape(text) {
  const raw = String(text == null ? '' : text)
  return scrubSecrets(raw) !== raw
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

function usage(msg) {
  console.error('bua-runner: ' + msg)
  console.error('usage: node tools/bua/run.mjs --url <target> --principal <label> [--out-dir 08_artifacts/raw] [--action A-…] [--profile lab/bua-profile]')
  process.exit(2)
}

function parseArgs(argv) {
  const out = { 'out-dir': '08_artifacts/raw', profile: 'lab/bua-profile' }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (!a.startsWith('--')) usage('unexpected argument: ' + a)
    const key = a.slice(2)
    const val = argv[++i]
    if (val === undefined || val.startsWith('--')) usage('missing value for --' + key)
    out[key] = val
  }
  return out
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

async function main() {
  const args = parseArgs(process.argv.slice(2))
  if (!args.url || !args.principal) usage('--url and --principal are required')
  const root = findOsRoot(process.cwd())
  if (!root) usage('not inside a Research OS workspace (11_runtime/events.jsonl, 00_control/engagement.yaml or 11_runtime/)')
  insideRoot(root, args['out-dir'], '--out-dir')
  insideRoot(root, args.profile, '--profile')
  // Token-derived filenames (`<action>-<ts>.png/.bua.json`) must not escape the
  // out-dir: a forged action id carrying `/`, `..` or control characters fails
  // closed here, before any capture path is built.
  if (args.action !== undefined && !/^[A-Za-z0-9_-]{1,64}$/.test(String(args.action))) {
    usage('--action must match [A-Za-z0-9_-] (1-64 chars)')
  }

  // 1. Scope guard in code — the same seam the control plane and every intercepted
  //    request use: fail fast on the entry URL before the browser starts (exit 4).
  let scope
  try {
    scope = scopeCheckVerdict(args.url, root)
  } catch (e) {
    console.error('bua-runner: scope check failed: ' + String(e.message || e))
    process.exit(4)
  }
  if (scope.in_scope !== true) {
    const detail = scope.gate === 'unenforceable'
      ? 'the engagement asset list is not a simple host/URL list — scope is unenforceable'
      : `target '${scope.host || args.url}' is outside the engagement scope (assets=${JSON.stringify(scope.assets ?? [])})`
    console.error('bua-runner: ' + detail + '. Fix 00_control/engagement.yaml from the authoritative program policy first.')
    process.exit(4)
  }
  console.log(`bua-runner: scope ok — gate=${scope.gate} host=${scope.host || '-'}`)

  // 2. Playwright is workspace-local and lazily required (provisioning task, not a human task).
  let chromium
  try {
    const require = createRequire(join(root, 'package.json'))
    ;({ chromium } = require('playwright-core'))
  } catch (e) {
    console.error('bua-runner: playwright-core is not provisioned in this workspace.\n' +
      '  provision: npm i -D playwright-core && npx playwright install chromium\n' +
      '  or set RESEARCH_OS_CHROME to a Chrome/Chromium executable. (' + String(e.message || e) + ')')
    process.exit(3)
  }

  // 3. Dedicated per-engagement profile, headless by default.
  const profileDir = join(root, args.profile)
  mkdirSync(profileDir, { recursive: true })
  const ts = new Date().toISOString().replace(/[:.]/g, '-')
  const label = String(args.action || 'bua')
  const outDir = join(root, args['out-dir'])
  mkdirSync(outDir, { recursive: true })
  const shotRel = join(args['out-dir'], `${label}-${ts}.png`)
  const summaryRel = join(args['out-dir'], `${label}-${ts}.bua.json`)

  let context
  try {
    context = await chromium.launchPersistentContext(profileDir, {
      headless: true,
      executablePath: process.env.RESEARCH_OS_CHROME || undefined,
      viewport: { width: 1440, height: 900 },
      acceptDownloads: false, // read-only contract: a page can never make the runner save a file
    })
  } catch (e) {
    console.error('bua-runner: browser launch failed — provision with `npx playwright install chromium` ' +
      'or set RESEARCH_OS_CHROME. (' + String(e.message || e) + ')')
    process.exit(3)
  }

  // 4. Read-only capture: navigate, screenshot, metadata. No cookie values, no secrets.
  const summary = {
    url: maskUrlSecrets(args.url),
    principal: args.principal,
    action: args.action || null,
    profile: args.profile,
    started_at: new Date().toISOString(),
    status: null,
    final_url: null,
    redirect_chain: [],
    out_of_scope_hops: [],
    out_of_scope_hop_count: 0,
    scope_violation: false,
    title: null,
    error: null,
    blocked_requests: [],
    blocked_count: 0,
    service_worker_registrations_blocked: 0,
    service_worker_violations: 0,
    screenshot: shotRel,
  }

  // 4b. The controlled page, created before interception so CDP observation and the
  //     console watch attach before any navigation.
  let page = null
  try {
    page = context.pages()[0] || (await context.newPage())
  } catch (e) {
    console.error('bua-runner: page creation failed. (' + String(e.message || e) + ')')
    try { await context.close() } catch { /* already closed */ }
    process.exit(3)
  }
  // The service-worker block reports through the page console (the only channel out
  // of the init script): count loud rejections as blocked registrations.
  const watchPageConsole = (watched) => {
    try {
      watched.on('console', (msg) => {
        try {
          if (String(msg.text()).includes('service worker registration blocked')) {
            summary.service_worker_registrations_blocked += 1
            console.log('bua-runner: blocked service worker registration')
          }
        } catch { /* unparseable console text */ }
      })
    } catch { /* console watching unavailable */ }
  }
  try {
    for (const watched of context.pages()) watchPageConsole(watched)
    context.on('page', watchPageConsole)
  } catch { /* console watching unavailable */ }

  // 5. Per-request interception, installed BEFORE the first navigation: the entry URL
  //    and every subresource (JS/CSS/XHR) passes the scope seam first; anything that
  //    cannot be verified in-scope is aborted, not fetched. (Redirect hops are followed
  //    by the browser outside this handler — the known limit in the header.)
  const scopeCache = makeScopeCache((url) => scopeCheckVerdict(url, root))
  scopeCache.seed(hostKey(args.url), { in_scope: true, gate: scope.gate })
  const loggedBlockHosts = new Set()
  try {
    await context.route('**/*', async (route) => {
      const url = route.request().url()
      const decision = await decideRequest(url, scopeCache)
      if (decision.allow) return route.continue()
      recordBlocked(summary, url, decision.host, decision.reason)
      if (!loggedBlockHosts.has(decision.host)) {
        loggedBlockHosts.add(decision.host)
        console.log(`bua-runner: blocked ${decision.reason} host=${decision.host || '-'}`)
      }
      return route.abort('blockedbyclient')
    })
  } catch (e) {
    console.error('bua-runner: request interception could not be installed — refusing to browse unscoped. ' +
      '(' + String(e.message || e) + ')')
    try { await context.close() } catch { /* already closed */ }
    process.exit(3)
  }

  // 5a. Service workers run outside every route handler, so registration must never
  //     succeed in the controlled context: reject new registrations and unregister
  //     registrations lingering from a reused profile, before the first navigation.
  //     Missing init-script support fails closed. A worker that appears anyway (the
  //     'serviceworker' event, or one already running) records a violation and fails
  //     the run — its traffic bypasses every route handler.
  const handleServiceWorker = makeServiceWorkerHandler(summary)
  const swTasks = []
  try {
    await context.addInitScript(serviceWorkerInitScript())
  } catch (e) {
    console.error('bua-runner: service-worker block could not be installed — refusing to browse unscoped. ' +
      '(' + String(e.message || e) + ')')
    try { await context.close() } catch { /* already closed */ }
    process.exit(3)
  }
  try {
    if (typeof context.serviceWorkers === 'function') {
      for (const worker of context.serviceWorkers()) swTasks.push(handleServiceWorker(worker))
    }
    context.on('serviceworker', (worker) => { swTasks.push(handleServiceWorker(worker)) })
  } catch (e) {
    console.log('bua-runner: WARNING service-worker backstop unavailable: ' + maskText(String(e.message || e)))
  }

  // 5b. WebSockets are not routed by `context.route` (playwright keeps them on their
  //     own seam), so a page could open a socket to an out-of-scope host unchecked.
  //     `routeWebSocket` funnels every page-realm ws/wss upgrade through the same
  //     decision. Dedicated workers and service workers never reach it (page-realm
  //     routing only — see 5a and 5c). Without the API there is no ws/wss
  //     interception at all, so the run is refused instead of passing silently.
  const wsTasks = []
  if (typeof context.routeWebSocket === 'function') {
    const handleWebSocket = makeWebSocketHandler(summary, scopeCache)
    try {
      // The handler's decision can outlive DOMContentLoaded (it may spawn the seam), so
      // its task is tracked and settled before the summary is persisted.
      await context.routeWebSocket('**/*', (ws) => {
        const task = handleWebSocket(ws)
        wsTasks.push(task)
        return task
      })
    } catch (e) {
      console.error('bua-runner: websocket interception could not be installed — refusing to browse unscoped. ' +
        '(' + String(e.message || e) + ')')
      try { await context.close() } catch { /* already closed */ }
      process.exit(3)
    }
  } else {
    console.error('bua-runner: this playwright-core has no context.routeWebSocket — refusing to browse ' +
      'unscoped (a run without ws/wss interception would pass out-of-scope sockets with a silent ' +
      'blocked_count: 0); upgrade playwright-core')
    try { await context.close() } catch { /* already closed */ }
    process.exit(3)
  }

  // 5c. Dedicated/shared workers never reach the route handlers (page-realm routing
  //     only): observe their sockets over CDP. Each worker target is auto-attached
  //     paused (no race: the socket cannot outrun the observer), `Network` is enabled
  //     in the worker session, and every `Network.webSocketCreated` goes through the
  //     same scope decision — an out-of-scope worker socket the route layer missed is
  //     recorded as a scope violation, capture skipped, never silent (deduped — a
  //     socket the route layer blocked is never counted twice). Worker targets expose
  //     no Fetch domain, so observation + violation is the coverage here, exactly as
  //     the worker half cannot be closed through the route API. Setup failure fails
  //     closed. (Non-flattened attach: worker messages arrive wrapped in
  //     `Target.receivedMessageFromTarget` and worker commands go out through
  //     `Target.sendMessageToTarget` — flattened mode rejects the latter.)
  const workerWsTasks = []
  let cdpMsgId = 0
  const pendingEnables = new Map()
  const failWorkerScope = (note) => {
    summary.scope_violation = true
    console.log('bua-runner: WARNING worker websocket interception degraded (' + note +
      ') — flagging a scope violation')
  }
  const noteWorkerSocket = (url) => {
    workerWsTasks.push(observeWorkerWebSocket(summary, scopeCache, String(url || '')).catch((e) => {
      console.log('bua-runner: WARNING worker-websocket scope check failed: ' + maskText(String(e.message || e)))
    }))
  }
  try {
    const cdp = await context.newCDPSession(page)
    const toWorker = (sessionId, method, params, track) => {
      cdpMsgId += 1
      if (track) pendingEnables.set(cdpMsgId, sessionId)
      return cdp.send('Target.sendMessageToTarget', {
        sessionId, message: JSON.stringify({ id: cdpMsgId, method, params }),
      })
    }
    await cdp.send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: false })
    await cdp.send('Network.enable')
    cdp.on('Network.webSocketCreated', ({ url }) => { noteWorkerSocket(url) })
    cdp.on('Target.attachedToTarget', ({ targetInfo, sessionId, waitingForDebugger }) => {
      workerWsTasks.push((async () => {
        try {
          if (!/worker/i.test(String((targetInfo || {}).type || ''))) return
          // Ordered on the connection: the enable applies before the resume below.
          await toWorker(sessionId, 'Network.enable', {}, true)
        } catch (e) {
          failWorkerScope('Network.enable failed: ' + String(e.message || e))
        } finally {
          if (waitingForDebugger) {
            await toWorker(sessionId, 'Runtime.runIfWaitingForDebugger', {}).catch(() => {})
          }
        }
      })().catch((e) => {
        failWorkerScope(String(e.message || e))
      }))
    })
    cdp.on('Target.receivedMessageFromTarget', ({ sessionId, message }) => {
      workerWsTasks.push((async () => {
        let msg = null
        try { msg = JSON.parse(String(message)) } catch { return }
        if (msg.id && pendingEnables.has(msg.id)) {
          pendingEnables.delete(msg.id)
          if (msg.error) failWorkerScope('the worker rejected Network.enable')
          return
        }
        if (msg.method !== 'Network.webSocketCreated') return
        noteWorkerSocket(msg.params && msg.params.url)
      })().catch((e) => {
        console.log('bua-runner: WARNING worker-websocket scope check failed: ' + maskText(String(e.message || e)))
      }))
    })
  } catch (e) {
    console.error('bua-runner: worker websocket observation could not be installed — refusing to browse unscoped. ' +
      '(' + String(e.message || e) + ')')
    try { await context.close() } catch { /* already closed */ }
    process.exit(3)
  }

  // 5c. Subresource redirect hops: `context.route` treats a request and its redirects as
  //     one unit, so a followed hop never reaches the handler. The 'response' event
  //     fires for every hop that produced a response; walking `redirectedFrom()` there
  //     witnesses each hop — subresource or navigation — and records the out-of-scope
  //     ones via the shared collector (deduped there, since several responses re-walk
  //     the same chain). The checks run async, so the tasks are settled before the
  //     summary is persisted.
  const collectHops = makeHopCollector(summary, scopeCache)
  const hopTasks = []
  context.on('response', (response) => {
    hopTasks.push(collectHops(response).catch((e) => {
      console.log('bua-runner: WARNING redirect-hop scope check failed: ' + maskText(String(e.message || e)))
    }))
  })

  let lastNavRequest = null
  let resp = null
  try {
    page = page || context.pages()[0] || (await context.newPage())
    // A failed navigation returns no response, so this listener is the witness of the
    // request chain (and its hops) when `page.goto` throws.
    page.on('request', (req) => {
      if (req.isNavigationRequest() && req.frame() === page.mainFrame()) lastNavRequest = req
    })
    resp = await page.goto(args.url, { waitUntil: 'domcontentloaded', timeout: 30000 })
    summary.status = resp ? resp.status() : null
    summary.final_url = maskUrlSecrets(page.url())
  } catch (e) {
    summary.error = maskText(String(e.message || e))
  }
  summary.redirect_chain = redirectChain(resp || lastNavRequest)
  // The navigation's own chain, awaited: the response listener already saw every hop
  // that produced a response; this pass also covers a failed navigation (request chain,
  // no response) and decides whether a followed out-of-scope hop makes the landing page
  // a scope violation rather than a normal artifact.
  const navHops = await collectHops(resp || lastNavRequest)
  if (navHops.length) {
    summary.scope_violation = true
    summary.screenshot = null
    console.log(`bua-runner: scope violation — navigation followed ${navHops.length} out-of-scope ` +
      'redirect hop(s); title and screenshot are skipped (chain and hops are recorded)')
  } else if (page) {
    if (summary.scope_violation === true) {
      summary.screenshot = null
      console.log('bua-runner: scope violation — worker/service-worker traffic left scope; ' +
        'title and screenshot are skipped (chain and hops are recorded)')
    } else {
      try {
        summary.title = await page.title().catch(() => null)
        await page.screenshot({ path: join(root, shotRel) })
      } catch (e) {
        summary.screenshot = null
        if (!summary.error) summary.error = maskText(String(e.message || e))
      }
    }
  }
  try { await context.close() } catch { /* already closed */ }
  await Promise.allSettled([...hopTasks, ...wsTasks, ...swTasks, ...workerWsTasks])
  summary.finished_at = new Date().toISOString()
  writeFileSync(join(root, summaryRel), JSON.stringify(summary, null, 2) + '\n')
  if (summary.screenshot) console.log(`ARTIFACT ${summary.screenshot}`)
  console.log(`ARTIFACT ${summaryRel}`)
  console.log(`bua-runner: ${summary.status === null ? 'error: ' + summary.error : 'HTTP ' + summary.status} ` +
    `final=${summary.final_url || '-'} title=${JSON.stringify(summary.title)} blocked=${summary.blocked_count} ` +
    `out_of_scope_hops=${summary.out_of_scope_hop_count} violation=${summary.scope_violation}`)
  process.exit(0)
}

// The CLI flow runs only when this file is the entry point; importing it (tests) is safe.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main()
