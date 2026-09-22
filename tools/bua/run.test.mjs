/**
 * Unit tests for the BUA runner's per-request scope interception.
 *
 * The route handler needs a browser, but the DECISION it applies to every request is a
 * pure function over the URL and the authoritative `researchctl scope-check` verdict.
 * These cases pin that decision: scheme exemption, fail-closed scope failure, one
 * authoritative check per host[:port], masked + capped block records, redirect chain,
 * WebSocket decisions, followed out-of-scope redirect hops, the distinct-host check
 * budget and the raw-authority cache key (parity with control_plane._normalize_host).
 *
 * Run: `node tools/bua/run.test.mjs` (exits non-zero on failure).
 */
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  decideRequest, hostKey, makeHopCollector, makeScopeCache, makeWebSocketHandler,
  maskText, maskUrlSecrets, recordBlocked, redirectChain, schemeAllowed,
} from './run.mjs'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')

let passed = 0
const failures = []

function check(label, cond) {
  if (cond) {
    passed += 1
    console.log('ok: ' + label)
  } else {
    failures.push(label)
    console.log('FAIL: ' + label)
  }
}

// ---- scheme exemption: traffic-free schemes need no scope check -----------------
// data:/blob:/about:/filesystem: never leave the machine (blob objects are in-memory,
// filesystem: is origin-local storage), so they cannot produce out-of-scope traffic.
for (const url of ['data:text/html,<b>x</b>', 'blob:https://t.example/uuid-a', 'about:blank',
  'blob:null/uuid-b', 'filesystem:https://t.example/temporary/x']) {
  check('scheme-exempt without a scope check: ' + url.split(':')[0] + ':', schemeAllowed(url) === true)
}
check('http and https are never scheme-exempt',
  schemeAllowed('http://t.example/') === false && schemeAllowed('https://t.example/') === false)
check('an unknown or unparseable scheme is not exempt (fail closed)',
  schemeAllowed('ftp://t.example/x') === false && schemeAllowed('not a url') === false)

// ---- request decision: allow/block against the fake authoritative seam ----------
const verdicts = {
  't.example': { gate: 'assets', in_scope: true, host: 't.example' },
  'evil.example': { gate: 'assets', in_scope: false, host: 'evil.example' },
  'anything.example': { gate: 'disabled', in_scope: true, host: 'anything.example' },
}
const verdictCalls = []
const seam = async (url) => {
  verdictCalls.push(url)
  const host = new URL(url).host
  return verdicts[host] || { gate: 'assets', in_scope: false, host }
}
const seamCache = makeScopeCache(seam)

check('an in-scope host is allowed',
  (await decideRequest('https://t.example/app/a.js', seamCache)).allow === true)
check('the in-scope reason is named',
  (await decideRequest('https://t.example/app/a.js', seamCache)).reason === 'in_scope')
check('a gate-disabled engagement allows any host (same in_scope verdict)',
  (await decideRequest('https://anything.example/x', seamCache)).allow === true)
const outOfScope = await decideRequest('https://evil.example/tracker.js?sig=SECRET', seamCache)
check('an out-of-scope host is blocked', outOfScope.allow === false)
check('the out-of-scope block carries the host and a reason',
  outOfScope.host === 'evil.example' && outOfScope.reason === 'out_of_scope')
check('a scheme-exempt URL is allowed before any scope check',
  (await decideRequest('data:text/plain,hello', seamCache)).allow === true
  && (await decideRequest('about:blank', seamCache)).allow === true)
check('an uninspectable network scheme is blocked without a scope check',
  (await decideRequest('ftp://t.example/x', seamCache)).allow === false
  && (await decideRequest('file:///etc/passwd', seamCache)).allow === false)

// ---- fail closed: a spawn/parse failure blocks and is not retried per request ----
let failureCalls = 0
const failing = makeScopeCache(async () => { failureCalls += 1; throw new Error('spawn python3 ENOENT') })
const failedFirst = await decideRequest('https://t.example/a.js', failing)
const failedSecond = await decideRequest('https://t.example/b.js', failing)
check('a scope-check failure blocks the request (fail closed)', failedFirst.allow === false)
check('the failure reason is recorded as scope_check_failed',
  failedFirst.reason === 'scope_check_failed' && failedSecond.allow === false)
check('a failing host is spawned once, not once per subresource', failureCalls === 1)
const garbage = makeScopeCache(async () => ({}))
check('a verdict without in_scope:true blocks (fail closed)',
  (await decideRequest('https://t.example/x', garbage)).allow === false)

// ---- one authoritative check per host[:port] per run ----------------------------
const seen = []
const counting = makeScopeCache(async (url) => {
  seen.push(url)
  const host = new URL(url).host
  return { gate: 'assets', in_scope: host.startsWith('t.example'), host }
})
const manyUrls = [
  'https://t.example/a.js',
  'https://t.example/b.js?token=x',
  'https://t.example/c.css',
  'https://T.Example/d.js',
  'https://t.example:8443/api',
  'https://t.example:8443/api2',
  'https://cdn.other.example/lib.js',
]
const decisions = []
for (const url of manyUrls) decisions.push((await decideRequest(url, counting)).allow)
const perHost = {}
for (const url of seen) { const h = new URL(url).host; perHost[h] = (perHost[h] || 0) + 1 }
check('three distinct host[:port] keys produce exactly three seam checks', seen.length === 3)
check('the same host is checked once across subresources', perHost['t.example'] === 1)
check('an explicit port is a distinct cache key', perHost['t.example:8443'] === 1)
check('a third-party host is checked separately', perHost['cdn.other.example'] === 1)
check('decisions follow the seam verdict',
  decisions[0] === true && decisions[3] === true && decisions[4] === true && decisions[6] === false)
for (const url of manyUrls) await decideRequest(url, counting)
check('a warm cache spawns nothing further', seen.length === 3)
const seeded = makeScopeCache(async () => { throw new Error('must not run') })
seeded.seed('t.example', { in_scope: true, gate: 'assets' })
check('a seeded host skips the seam entirely',
  (await decideRequest('https://t.example/entry', seeded)).allow === true)

// ---- blocked records: masked, capped at 50, accurate count -----------------------
const summary = { blocked_requests: [], blocked_count: 0 }
for (let i = 0; i < 60; i++) {
  recordBlocked(summary, `https://evil.example/p${i}?token=SECRET${i}#code=HASH${i}`, 'evil.example', 'out_of_scope')
}
check('every block is counted, past the cap', summary.blocked_count === 60)
check('the recorded list stops at 50', summary.blocked_requests.length === 50)
check('records are masked with the runner masker',
  summary.blocked_requests[0].url_masked === 'https://evil.example/p0?token=[REDACTED]#code=[REDACTED]')
check('no secret value survives anywhere in the records',
  !JSON.stringify(summary.blocked_requests).includes('SECRET') && !JSON.stringify(summary.blocked_requests).includes('HASH'))
check('records carry host and reason',
  summary.blocked_requests[0].host === 'evil.example' && summary.blocked_requests[0].reason === 'out_of_scope')

// ---- redirect chain extraction (fake response object) ----------------------------
const fakeRequest = (url, previous) => ({ url: () => url, redirectedFrom: () => previous || null })
const hop1 = fakeRequest('https://t.example/start')
const hop2 = fakeRequest('https://t.example/next?token=REDIRECTSECRET', hop1)
const hop3 = fakeRequest('https://t.example/land?code=CODESECRET#frag', hop2)
const chain = redirectChain({ request: () => hop3 })
check('the chain is oldest -> newest', JSON.stringify(chain) === JSON.stringify([
  'https://t.example/start',
  'https://t.example/next?token=[REDACTED]',
  'https://t.example/land?code=[REDACTED]#frag',
]))
check('a single-hop navigation yields one entry',
  JSON.stringify(redirectChain({ request: () => hop1 })) === JSON.stringify(['https://t.example/start']))
check('a missing response yields an empty chain', redirectChain(null).length === 0)
check('a failed navigation still yields its chain from the request object',
  JSON.stringify(redirectChain(hop3)) === JSON.stringify([
    'https://t.example/start',
    'https://t.example/next?token=[REDACTED]',
    'https://t.example/land?code=[REDACTED]#frag',
  ]))
let longChain = fakeRequest('https://t.example/0')
for (let i = 1; i < 100; i++) longChain = fakeRequest(`https://t.example/${i}`, longChain)
check('the chain is bounded to the newest 20 hops', redirectChain({ request: () => longChain }).length === 20)
check('the bound keeps the landing hop last',
  redirectChain({ request: () => longChain }).pop() === 'https://t.example/99')

// ---- the existing masker stays the single masking seam ---------------------------
check('maskUrlSecrets is the masker the records use',
  maskUrlSecrets('https://evil.example/x?access_token=AB') === 'https://evil.example/x?access_token=[REDACTED]')

// ---- error text: masked before it is persisted or printed -------------------------
check('error text masks a sensitive URL',
  maskText('page.goto: net::ERR_FAILED at https://evil.example/cb?token=ERRSECRET#code=HASH') ===
  'page.goto: net::ERR_FAILED at https://evil.example/cb?token=[REDACTED]#code=[REDACTED]')
check('a bare secret-shaped value in error text is scrubbed',
  maskText('failed with glpat-ABCDEFGHIJKLMNOPQRST for https://t.example/ok') ===
  'failed with [REDACTED] for https://t.example/ok')
check('error masking tolerates null/undefined', maskText(null) === '' && maskText(undefined) === '')

// ---- hostKey: raw authority, port preserved exactly as written --------------------
// The cache key must be the seam's unit: `control_plane._normalize_host` strips
// userinfo and ONE trailing dot and lowercases, but never collapses a default port, so
// `t.example:443` and `t.example` are two different authorities to the seam.
check('the default https port is not collapsed into the bare host',
  hostKey('https://t.example:443/x') === 't.example:443' && hostKey('https://t.example/x') === 't.example')
check('the default http port is not collapsed either', hostKey('https://t.example:80/x') === 't.example:80')
check('userinfo is stripped', hostKey('https://user:pw@t.example/x') === 't.example')
check('case is folded', hostKey('https://T.EXAMPLE/x') === hostKey('https://t.example/x'))
check('one trailing dot is stripped, exactly like the seam',
  hostKey('https://t.example./x') === 't.example'
  && hostKey('https://t.example./x') === hostKey('https://t.example/x'))
check('a port after a trailing dot is preserved as written, exactly like the seam',
  hostKey('https://USER:PW@T.Example.:8443/x') === 't.example.:8443')
check('an explicit port survives lowercasing as written',
  hostKey('https://T.EXAMPLE:0443/x') === 't.example:0443')
check('a bracketed IPv6 authority keeps its brackets and port',
  hostKey('http://[::1]:8080/x') === '[::1]:8080')
check('unparseable input has no cache key',
  hostKey('not a url') === undefined && hostKey(null) === undefined)

// Cross-language parity: the same authority strings through the actual Python seam.
const PY_NORMALIZE = "import sys; sys.path.insert(0, 'tools'); from control_plane import _normalize_host; " +
  "sys.stdout.write(_normalize_host(sys.argv[1]))"
for (const authority of ['t.example:443', 't.example', 't.example:80', 't.example.',
                         'T.EXAMPLE:8443', 'user:pw@t.example', 't.example.:8443', '[::1]:8080']) {
  const seam = execFileSync('python3', ['-c', PY_NORMALIZE, authority],
    { cwd: REPO_ROOT, encoding: 'utf8' }).trim()
  check(`hostKey parity with control_plane._normalize_host: ${authority}`,
    hostKey(`http://${authority}/`) === seam)
}

// ---- distinct-host scope-check budget: fail closed past the cap, without spawning --
const budgetSeen = []
const budgetCache = makeScopeCache(async (url) => {
  budgetSeen.push(url)
  return { gate: 'assets', in_scope: true, host: new URL(url).host }
}, 4)
const budgetDecisions = []
for (let i = 0; i < 10; i++) budgetDecisions.push(await decideRequest(`https://h${i}.example/x`, budgetCache))
check('the seam is spawned once per distinct host up to the cap', budgetSeen.length === 4)
check('requests past the cap fail closed with the budget reason and no spawn',
  budgetDecisions[4].allow === false && budgetDecisions[4].reason === 'host_check_budget_exceeded'
  && budgetDecisions[9].reason === 'host_check_budget_exceeded')
check('an already-checked host still decides from cache past the cap',
  (await decideRequest('https://h0.example/y', budgetCache)).allow === true)
check('a budget denial is stable and spawns nothing further',
  (await decideRequest('https://h9.example/y', budgetCache)).reason === 'host_check_budget_exceeded'
  && budgetSeen.length === 4)
const defaultSeen = []
const defaultCache = makeScopeCache(async (url) => {
  defaultSeen.push(url)
  return { gate: 'assets', in_scope: true, host: new URL(url).host }
})
for (let i = 0; i < 70; i++) await decideRequest(`https://d${i}.example/x`, defaultCache)
check('the default distinct-host budget stops the seam at 64 spawns', defaultSeen.length === 64)
check('the first host past the default budget fails closed',
  (await decideRequest('https://d71.example/x', defaultCache)).reason === 'host_check_budget_exceeded'
  && defaultSeen.length === 64)

// ---- WebSockets: ws/wss are decided by the same cache as http(s) ------------------
check('ws and wss are never scheme-exempt',
  schemeAllowed('ws://t.example/socket') === false && schemeAllowed('wss://t.example/socket') === false)
const wsCache = makeScopeCache(async (url) => ({
  gate: 'assets', in_scope: new URL(url).host === 't.example', host: new URL(url).host,
}))
const wsIn = await decideRequest('ws://t.example/socket', wsCache)
const wsOut = await decideRequest('wss://evil.example/socket', wsCache)
check('an in-scope ws:// host is allowed through the shared decision',
  wsIn.allow === true && wsIn.reason === 'in_scope' && wsIn.host === 't.example')
check('an out-of-scope wss:// host is blocked through the shared decision',
  wsOut.allow === false && wsOut.reason === 'out_of_scope' && wsOut.host === 'evil.example')

const wsSummary = { blocked_requests: [], blocked_count: 0 }
const wsLogs = []
const wsHandler = makeWebSocketHandler(wsSummary, wsCache, (line) => wsLogs.push(line))
const fakeWs = (url) => ({
  url: () => url, connected: 0, closed: 0,
  connectToServer() { this.connected += 1 },
  close() { this.closed += 1 },
})
const allowedWs = fakeWs('wss://t.example/socket')
await wsHandler(allowedWs)
check('an in-scope websocket connects to the server',
  allowedWs.connected === 1 && allowedWs.closed === 0)
const deniedWs = fakeWs('wss://evil.example/socket?token=WSSECRET')
await wsHandler(deniedWs)
check('an out-of-scope websocket is closed, never connected',
  deniedWs.connected === 0 && deniedWs.closed === 1)
check('the blocked websocket is recorded masked, with host and reason',
  wsSummary.blocked_count === 1 && wsSummary.blocked_requests[0].host === 'evil.example'
  && wsSummary.blocked_requests[0].url_masked === 'wss://evil.example/socket?token=[REDACTED]'
  && wsSummary.blocked_requests[0].reason === 'out_of_scope')
check('the websocket block is logged once and carries no secret',
  wsLogs.length === 1 && wsLogs[0].includes('evil.example') && !wsLogs[0].includes('WSSECRET'))
const wsFailSummary = { blocked_requests: [], blocked_count: 0 }
const wsFailHandler = makeWebSocketHandler(wsFailSummary,
  makeScopeCache(async () => { throw new Error('spawn python3 ENOENT') }), () => {})
const failedWs = fakeWs('ws://t.example/socket')
await wsFailHandler(failedWs)
check('a failing scope check closes the websocket (fail closed) and records the failure',
  failedWs.connected === 0 && failedWs.closed === 1
  && wsFailSummary.blocked_requests[0].reason === 'scope_check_failed')

// ---- followed out-of-scope redirect hops (nav AND subresource) --------------------
const hopCache = makeScopeCache(async (url) => ({
  gate: 'assets', in_scope: new URL(url).host === 't.example', host: new URL(url).host,
}))
const hopSummary = { out_of_scope_hops: [], out_of_scope_hop_count: 0 }
const hopWarnings = []
const collectHops = makeHopCollector(hopSummary, hopCache, (line) => hopWarnings.push(line))
const rq = (url, previous) => ({ url: () => url, redirectedFrom: () => previous || null })
const inHop = rq('https://t.example/a.js')
check('an in-scope chain records nothing',
  (await collectHops({ request: () => inHop })).length === 0
  && hopSummary.out_of_scope_hop_count === 0 && hopWarnings.length === 0)
const outHop = rq('https://evil.example/cb?token=HOPSECRET', inHop)
const foundHops = await collectHops({ request: () => outHop })
check('a followed out-of-scope hop is recorded masked and returned as a violation',
  foundHops.length === 1 && hopSummary.out_of_scope_hop_count === 1
  && hopSummary.out_of_scope_hops[0].host === 'evil.example'
  && hopSummary.out_of_scope_hops[0].url_masked === 'https://evil.example/cb?token=[REDACTED]')
check('the hop warning keeps the existing loud wording',
  hopWarnings.length === 1
  && hopWarnings[0].startsWith('bua-runner: WARNING followed redirect hop was out of scope')
  && hopWarnings[0].includes('evil.example') && !hopWarnings[0].includes('HOPSECRET'))
await collectHops({ request: () => outHop })
check('the same hop seen through several responses is recorded once',
  hopSummary.out_of_scope_hop_count === 1 && hopWarnings.length === 1)
const mixedChain = rq('https://evil.example/next', rq('https://t.example/start'))
check('only the out-of-scope hops of a mixed chain are returned',
  (await collectHops({ request: () => mixedChain })).length === 1)
for (let i = 0; i < 60; i++) {
  await collectHops({ request: () => rq(`https://evil.example/hop${i}?sig=HOPSECRET${i}`) })
}
check('out-of-scope hops are counted in full and capped at 50',
  hopSummary.out_of_scope_hop_count === 62 && hopSummary.out_of_scope_hops.length === 50)
check('no hop secret survives anywhere in the records',
  !JSON.stringify(hopSummary.out_of_scope_hops).includes('HOPSECRET'))

// ---- an older playwright-core without routeWebSocket: warn loudly, record nothing ----
// A stub module (no real browser) whose context lacks the API exercises the CLI guard.
const oldRoot = mkdtempSync(join(tmpdir(), 'bua-old-playwright-'))
let oldRun
try {
  mkdirSync(join(oldRoot, '11_runtime'), { recursive: true })
  mkdirSync(join(oldRoot, '00_control'), { recursive: true })
  mkdirSync(join(oldRoot, 'node_modules', 'playwright-core'), { recursive: true })
  writeFileSync(join(oldRoot, 'OS_VERSION'), '7.1\n')
  writeFileSync(join(oldRoot, '11_runtime', 'events.jsonl'), '')
  writeFileSync(join(oldRoot, '00_control', 'engagement.yaml'), 'scope:\n  assets:\n  - "t.example"\n')
  symlinkSync(join(REPO_ROOT, 'tools'), join(oldRoot, 'tools'), 'dir')
  writeFileSync(join(oldRoot, 'node_modules', 'playwright-core', 'index.js'), `
const page = {
  on() {}, mainFrame: () => ({}),
  goto: async () => ({ status: () => 200 }),
  url: () => 'https://t.example/entry?token=STUBSECRET',
  title: async () => 'stub page',
  screenshot: async () => {},
}
module.exports = { chromium: { launchPersistentContext: async () => ({
  route: async () => {}, on() {}, pages: () => [page], newPage: async () => page, close: async () => {},
}) } }
`)
  oldRun = execFileSync('node', [
    join(REPO_ROOT, 'tools', 'bua', 'run.mjs'), '--url', 'https://t.example/entry?token=STUBSECRET',
    '--principal', 'old-playwright', '--action', 'stub-old', '--out-dir', 'artifacts',
  ], { cwd: oldRoot, encoding: 'utf8' })
  check('an old playwright-core without routeWebSocket warns loudly',
    oldRun.includes('WARNING this playwright-core has no context.routeWebSocket'))
  const artifacts = join(oldRoot, 'artifacts')
  const summaryFile = readdirSync(artifacts).find((f) => f.endsWith('.bua.json'))
  const oldSummary = JSON.parse(readFileSync(join(artifacts, summaryFile), 'utf8'))
  check('the warned run still completes and records nothing for ws',
    oldSummary.status === 200 && oldSummary.blocked_count === 0
    && oldSummary.out_of_scope_hop_count === 0)
  check('the stub run masks its own URL', !JSON.stringify(oldSummary).includes('STUBSECRET'))
} catch (e) {
  check('an old playwright-core without routeWebSocket run failed: '
    + String(e.message || e).split('\n')[0], false)
} finally {
  rmSync(oldRoot, { recursive: true, force: true })
}

console.log(`\n${passed}/${passed + failures.length} passed`)
if (failures.length) {
  console.log('FAILURES: ' + failures.join(' | '))
  process.exit(1)
}
