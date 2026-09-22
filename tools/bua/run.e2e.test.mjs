#!/usr/bin/env node
/**
 * Guarded end-to-end test for the BUA runner (`tools/bua/run.mjs`).
 *
 * Runs the REAL runner CLI (own chromium, own `researchctl scope-check` seam) against
 * two local http servers: one listed in the temp workspace's engagement assets
 * (`127.0.0.1:<in-port>`), one outside them (`127.0.0.1:<out-port>`). Only a browser can
 * show these contracts, so they live here instead of the unit suite:
 *   - an out-of-scope SUBRESOURCE is blocked before it leaves the machine (0 hits on the
 *     out-of-scope server) and recorded in `blocked_requests`;
 *   - a WebSocket upgrade to the out-of-scope host is closed (the server never completes
 *     an upgrade) and recorded; an in-scope upgrade completes (the in-scope page holds
 *     DOMContentLoaded until the server saw it, so the check is deterministic);
 *   - a subresource 302 to the out-of-scope host is FOLLOWED (the known playwright route
 *     limit) but recorded in `out_of_scope_hops`;
 *   - a navigation that follows an out-of-scope 302 is flagged `scope_violation` with the
 *     screenshot and title skipped, while a fully in-scope run is unaffected.
 *
 * SKIPs (exit 0) with `SKIP (playwright/chromium unavailable)` when chromium cannot be
 * provisioned, so a CI without a browser stays green. Temp workspaces are removed.
 *
 * Run: `node tools/bua/run.e2e.test.mjs`
 */
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
const OUT_REL = join('e2e-artifacts', 'raw')

// ---- guarded provisioning: no browser, no e2e ---------------------------------------
let chromium
try {
  const require = createRequire(join(REPO_ROOT, 'package.json'))
  ;({ chromium } = require('playwright-core'))
  const chromeOverride = process.env.RESEARCH_OS_CHROME
  if (!(chromeOverride ? existsSync(chromeOverride) : existsSync(chromium.executablePath()))) {
    throw new Error('chromium executable not provisioned (npx playwright install chromium ' +
      'or RESEARCH_OS_CHROME)')
  }
} catch (e) {
  console.log('SKIP (playwright/chromium unavailable) — ' + String(e.message || e))
  process.exit(0)
}
try {
  const probe = await chromium.launch({ headless: true })
  await probe.close()
} catch (e) {
  console.log('SKIP (playwright/chromium unavailable) — chromium could not launch: ' + String(e.message || e))
  process.exit(0)
}

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

// ---- two local servers: in-scope and out-of-scope -----------------------------------
const inState = { hits: {}, upgrades: 0 }
const outState = { hits: {}, upgrades: 0 }
const openSockets = []
const wsAccept = (key) => createHash('sha1')
  .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64')
const html = (res, title, body) => {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
  res.end(`<!doctype html><html><head><title>${title}</title></head><body>${body}</body></html>`)
}
const js = (res) => {
  res.writeHead(200, { 'content-type': 'text/javascript' })
  res.end('// local test script\n')
}
const respondUpgrade = (req, socket) => {
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${wsAccept(req.headers['sec-websocket-key'] || '')}\r\n\r\n`)
}

let outPort = 0
let inPort = 0
const outSrv = createServer((req, res) => {
  const path = (req.url || '/').split('?')[0]
  outState.hits[path] = (outState.hits[path] || 0) + 1
  if (path === '/violated.html') return html(res, 'violated', '<p>out of scope landing</p>')
  return js(res)
})
outSrv.on('upgrade', (req, socket) => {
  outState.upgrades += 1
  openSockets.push(socket)
  respondUpgrade(req, socket)
})
const inSrv = createServer((req, res) => {
  const path = (req.url || '/').split('?')[0]
  inState.hits[path] = (inState.hits[path] || 0) + 1
  if (path === '/index.html') {
    return html(res, 'hostile', [
      '<script src="/in.js"></script>',
      `<script src="http://127.0.0.1:${outPort}/out.js"></script>`,
      '<script src="/hop.js"></script>',
      `<script>new WebSocket('ws://127.0.0.1:${outPort}/socket')</script>`,
    ].join(''))
  }
  if (path === '/clean.html') {
    return html(res, 'clean page', [
      '<script src="/clean.js"></script>',
      `<script>new WebSocket('ws://127.0.0.1:${inPort}/socket-in')</script>`,
      // Parser-blocking: the server holds this response until the in-scope upgrade was
      // seen, so DOMContentLoaded (and the runner's capture) cannot outrun the check.
      '<script src="/wait-ws.js"></script>',
    ].join(''))
  }
  if (path === '/redirect.html') {
    res.writeHead(302, { location: `http://127.0.0.1:${outPort}/violated.html` })
    return res.end()
  }
  if (path === '/reset.html') {
    return req.socket.destroy() // a failing navigation whose URL carries secrets
  }
  if (path === '/hop.js') {
    res.writeHead(302, { location: `http://127.0.0.1:${outPort}/land.js` })
    return res.end()
  }
  if (path === '/wait-ws.js') {
    const deadline = Date.now() + 3000
    const wait = () => {
      if (inState.upgrades > 0 || Date.now() > deadline) return js(res)
      setTimeout(wait, 20)
    }
    return wait()
  }
  return js(res)
})
inSrv.on('upgrade', (req, socket) => {
  inState.upgrades += 1
  openSockets.push(socket)
  respondUpgrade(req, socket)
})

const tmpRoot = mkdtempSync(join(tmpdir(), 'bua-e2e-'))
const cleanup = () => {
  for (const socket of openSockets) { try { socket.destroy() } catch { /* gone */ } }
  for (const srv of [inSrv, outSrv]) { try { srv.close(); srv.closeAllConnections?.() } catch { /* gone */ } }
  rmSync(tmpRoot, { recursive: true, force: true })
}

try {
  await new Promise((r) => outSrv.listen(0, '127.0.0.1', r))
  outPort = outSrv.address().port
  await new Promise((r) => inSrv.listen(0, '127.0.0.1', r))
  inPort = inSrv.address().port

  // A minimal but real workspace: OS_VERSION + ledger marker (findOsRoot), the canonical
  // tools (symlinked) and provisioned node_modules (symlinked), and one scoped asset.
  mkdirSync(join(tmpRoot, '11_runtime'), { recursive: true })
  mkdirSync(join(tmpRoot, '00_control'), { recursive: true })
  writeFileSync(join(tmpRoot, 'OS_VERSION'), '7.1\n')
  writeFileSync(join(tmpRoot, '11_runtime', 'events.jsonl'), '')
  writeFileSync(join(tmpRoot, '00_control', 'engagement.yaml'),
    `scope:\n  assets:\n  - "127.0.0.1:${inPort}"\n`)
  symlinkSync(join(REPO_ROOT, 'tools'), join(tmpRoot, 'tools'), 'dir')
  symlinkSync(join(REPO_ROOT, 'node_modules'), join(tmpRoot, 'node_modules'), 'dir')

  // Async spawn on purpose: the local test servers live in THIS process, so a blocking
  // `spawnSync` would freeze them while the runner waits for its navigation (deadlock).
  const run = (url, action) => new Promise((done) => {
    const child = spawn('node', [
      join(REPO_ROOT, 'tools', 'bua', 'run.mjs'),
      '--url', url, '--principal', 'e2e', '--action', action,
      '--out-dir', OUT_REL, '--profile', join('lab', 'bua-profile'),
    ], { cwd: tmpRoot })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk) => { stdout += chunk })
    child.stderr.on('data', (chunk) => { stderr += chunk })
    const timer = setTimeout(() => child.kill('SIGKILL'), 90000)
    child.on('close', (status, signal) => {
      clearTimeout(timer)
      done({ status, signal, stdout, stderr })
    })
  })

  const summaryFor = (action) => {
    const dir = join(tmpRoot, OUT_REL)
    const files = existsSync(dir)
      ? readdirSync(dir).filter((f) => f.startsWith(action) && f.endsWith('.bua.json'))
      : []
    if (files.length !== 1) throw new Error(`expected exactly one ${action} summary, found ${files.length}`)
    return JSON.parse(readFileSync(join(dir, files[0]), 'utf8'))
  }

  // 1. Hostile page on the in-scope server: an out-of-scope subresource, an out-of-scope
  //    websocket, and a subresource 302 to the out-of-scope host.
  const hostile = await run(`http://127.0.0.1:${inPort}/index.html`, 'bua-e2e-hostile')
  check('the hostile run exits 0 (a blocked page is still captured)',
    hostile.status === 0 && (hostile.stdout || '').includes('blocked out_of_scope host=127.0.0.1:' + outPort))
  const hostileSummary = summaryFor('bua-e2e-hostile')
  check('the hostile run captured the in-scope page',
    hostileSummary.status === 200 && hostileSummary.title === 'hostile' && hostileSummary.scope_violation === false)
  check('the in-scope subresource was fetched', (inState.hits['/in.js'] || 0) >= 1)
  check('the out-of-scope subresource got ZERO hits on the out-of-scope server',
    (outState.hits['/out.js'] || 0) === 0)
  check('the out-of-scope subresource is recorded as blocked',
    hostileSummary.blocked_requests.some((b) =>
      b.host === `127.0.0.1:${outPort}` && b.reason === 'out_of_scope' && b.url_masked.endsWith('/out.js')))
  check('the WebSocket upgrade to the out-of-scope server never completed',
    outState.upgrades === 0)
  check('the out-of-scope websocket is recorded as blocked',
    hostileSummary.blocked_requests.some((b) =>
      b.host === `127.0.0.1:${outPort}` && b.reason === 'out_of_scope'
      && b.url_masked === `ws://127.0.0.1:${outPort}/socket`))
  check('the subresource 302 target was followed (route cannot block a hop) and hit the server',
    (outState.hits['/land.js'] || 0) >= 1)
  check('the followed out-of-scope hop is recorded in out_of_scope_hops',
    hostileSummary.out_of_scope_hop_count >= 1
    && hostileSummary.out_of_scope_hops.some((h) =>
      h.host === `127.0.0.1:${outPort}` && h.url_masked === `http://127.0.0.1:${outPort}/land.js`))
  check('the hostile capture wrote its screenshot',
    typeof hostileSummary.screenshot === 'string' && existsSync(join(tmpRoot, hostileSummary.screenshot)))

  // 2. Fully in-scope run: nothing blocked, nothing flagged, the in-scope websocket opened.
  const clean = await run(`http://127.0.0.1:${inPort}/clean.html`, 'bua-e2e-clean')
  check('the clean run exits 0', clean.status === 0)
  const cleanSummary = summaryFor('bua-e2e-clean')
  check('the clean run is unaffected: HTTP 200, title, no blocks, no hops, no violation',
    cleanSummary.status === 200 && cleanSummary.title === 'clean page'
    && cleanSummary.blocked_count === 0 && cleanSummary.out_of_scope_hop_count === 0
    && cleanSummary.scope_violation === false)
  check('the clean capture wrote its screenshot',
    typeof cleanSummary.screenshot === 'string' && existsSync(join(tmpRoot, cleanSummary.screenshot)))
  check('the in-scope WebSocket upgrade completed on the server (allow path connects)',
    inState.upgrades >= 1)

  // 3. Navigation that follows an out-of-scope 302: recorded and flagged, not blocked.
  const redirected = await run(`http://127.0.0.1:${inPort}/redirect.html`, 'bua-e2e-redirect')
  check('the redirected run exits 0', redirected.status === 0)
  check('the redirect hop is reported loudly',
    (redirected.stdout || '').includes('WARNING followed redirect hop was out of scope'))
  const redirectSummary = summaryFor('bua-e2e-redirect')
  check('the out-of-scope navigation hop is recorded',
    redirectSummary.out_of_scope_hop_count >= 1
    && redirectSummary.out_of_scope_hops.some((h) =>
      h.url_masked === `http://127.0.0.1:${outPort}/violated.html`))
  check('the landing page is flagged as a scope violation',
    redirectSummary.scope_violation === true)
  check('a violated navigation skips the screenshot and the title',
    redirectSummary.screenshot === null && redirectSummary.title === null
    && !readdirSync(join(tmpRoot, OUT_REL)).some((f) => f.startsWith('bua-e2e-redirect') && f.endsWith('.png')))

  // 4. A failing navigation whose URL carries secrets: the captured error text and the
  //    whole summary must not leak them.
  const failed = await run(`http://127.0.0.1:${inPort}/reset.html?token=ERRSECRET&sig=HASH`, 'bua-e2e-error')
  check('a failing navigation still exits 0 (the capture is the product)', failed.status === 0)
  const failedSummary = summaryFor('bua-e2e-error')
  check('the failing navigation is recorded as an error', typeof failedSummary.error === 'string'
    && failedSummary.error.length > 0)
  check('no secret from the failing URL survives anywhere in the summary',
    !JSON.stringify(failedSummary).includes('ERRSECRET') && !JSON.stringify(failedSummary).includes('HASH')
    && failedSummary.url.includes('token=[REDACTED]'))
} catch (e) {
  failures.push('unexpected error: ' + String(e.stack || e))
  console.log('FAIL: unexpected error: ' + String(e.stack || e))
} finally {
  cleanup()
}

console.log(`\n${passed}/${passed + failures.length} passed`)
if (failures.length) {
  console.log('FAILURES: ' + failures.join(' | '))
  process.exit(1)
}
