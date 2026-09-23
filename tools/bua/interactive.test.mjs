/**
 * Guard + loop suite for the write-capable BUA task script (`tools/bua/interactive.mjs`).
 *
 * The task script is the interactive arm: a typed-operation loop (CLICK/TYPE/SELECT/
 * NAVIGATE/UPLOAD/LOGIN/DONE/BLOCKED) over executor-issued opaque handles. This suite is
 * the checklist `INTERACTIVE-GUARDS.md` promises: it proves the loop with a mocked
 * snapshot/executor (no browser), that DONE never reports confirmed without a fresh
 * observation, that the step cap and the guard cap stop a run, and — the adversarial
 * half — that a stale handle, an overlay, a moved node, an out-of-scope write, a
 * consequential action without a resolved gate and a traversal upload are all refused
 * before any dispatch.
 *
 * Run: `node tools/bua/interactive.test.mjs` (exits non-zero on failure).
 */
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  DEFAULT_MAX_STEPS, GUARD_RETRY_CAP, REPLAN_CAP, TYPE_TEXT_MAX, buildBoundary,
  classifyAction, guardDispatch, parseOperation, planContext, resolveOperation,
  runInteractive, runLoop,
} from './interactive.mjs'

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

// ---- fixtures ---------------------------------------------------------------------
const entry = (handle, extra = {}) => ({
  handle, tag: 'button', type: 'button', name: '', role: 'button', text: '',
  ops: ['CLICK'], options: [], href: null, form_index: null,
  box: { x: 10, y: 10, width: 100, height: 30 }, ...extra,
})
const viewport = { width: 1440, height: 900 }
const fakeLocator = ({ box, hitError = null, visible = true } = {}) => ({
  boundingBox: async () => (visible ? (box || { x: 10, y: 10, width: 100, height: 30 }) : null),
  hitTargetCheck: async () => { if (hitError) throw new Error(hitError) },
})

// ===================================================================================
// 1. The loop (mocked snapshot/executor — no browser)
// ===================================================================================
function loopHarness(overrides = {}) {
  const calls = { dispatch: [], authorize: [], gate: [], guard: [], capture: [], record: [], verify: [] }
  const events = []
  const snapshotEntries = overrides.entries || [entry('e1')]
  const base = {
    maxSteps: 4,
    boundary: buildBoundary({ root: '/tmp/bua-boundary', entries: snapshotEntries }),
    snapshot: async () => ({ generation: 1, entries: snapshotEntries }),
    plan: async () => ({ ok: true, source: 'typesafe',
                         operation: { op: 'CLICK', handle: 'e1' } }),
    scopeRecheck: async () => ({ ok: true }),
    authorize: async (ctx) => {
      calls.authorize.push(ctx)
      return { ok: true, token: { action_id: 'A-000001', nonce: 'n1' } }
    },
    gate: async (ctx) => { calls.gate.push(ctx); return { ok: true, gate: 'G-0001' } },
    guard: async (ctx) => { calls.guard.push(ctx); return { ok: true, locator: fakeLocator() } },
    dispatch: async (ctx) => { calls.dispatch.push(ctx); return { ok: true, result: { ok: true } } },
    capture: async (ctx) => { calls.capture.push(ctx); return { ok: true, artifact: 'a.json', evidence: 'E-000001' } },
    record: async (ctx) => { calls.record.push(ctx); return { ok: true, id: 'A-000001' } },
    verify: async (ctx) => { calls.verify.push(ctx); return { ok: true, evidence: 'E-000002', capture: 'shot.png' } },
    onEvent: (e) => events.push(e),
    ...overrides,
  }
  return { deps: base, calls, events }
}

{
  const { deps, calls, events } = loopHarness({
    plan: (() => {
      const plans = [
        { ok: true, source: 'typesafe', operation: { op: 'CLICK', handle: 'e1' } },
        { ok: true, source: 'typesafe', operation: { op: 'DONE' } },
      ]
      let i = 0
      return async () => plans[Math.min(i++, plans.length - 1)]
    })(),
  })
  const summary = await runLoop(deps)
  check('B1 loop: a scripted CLICK dispatches exactly once', calls.dispatch.length === 1)
  check('B1 loop: the dispatched operation is the typed one the boundary resolved',
    calls.dispatch[0].op.op === 'CLICK' && calls.dispatch[0].op.handle === 'e1')
  check('B1 loop: a DONE plan verifies before it reports confirmed',
    summary.status === 'confirmed' && summary.confirmed_evidence === 'E-000002')
  check('B1 loop: the run stops at DONE (no further plan calls)', events.length === 2)
  check('B1 loop: every action records a receipt with the token it consumed',
    calls.record.length === 1 && calls.record[0].token.action_id === 'A-000001')
  check('B1 loop: each dispatched action registers its own evidence capture',
    calls.capture.length === 1 && calls.record[0].capture.evidence === 'E-000001')
}

// DONE is never independent evidence: verification failing must not report confirmed.
{
  const { deps, events } = loopHarness({
    plan: async () => ({ ok: true, source: 'typesafe', operation: { op: 'DONE' } }),
    verify: async () => ({ ok: false, reason: 'state re-read failed' }),
  })
  const summary = await runLoop(deps)
  check('B1 loop: DONE without a successful verification never reports confirmed',
    summary.status !== 'confirmed' && summary.status === 'blocked')
  check('B1 loop: the unverified DONE names its failing guard',
    String(summary.blocked_reason).includes('done_without_verification')
    && String(summary.blocked_reason).includes('state re-read failed'))
  check('B1 loop: an unverified DONE records the failing step',
    events.length === 1 && events[0].status === 'blocked')
}

// The step cap: a model that never says DONE cannot run forever.
{
  const { deps, calls } = loopHarness({ maxSteps: 3 })
  const summary = await runLoop(deps)
  check('B1 loop: the step cap ends a run that never reaches DONE',
    summary.status === 'blocked' && summary.blocked_reason === 'step_cap_reached')
  check('B1 loop: the cap bounds dispatch exactly (no step past the cap)', calls.dispatch.length === 3)
  check('B1 loop: the cap is the named MAX_STEPS budget', DEFAULT_MAX_STEPS >= 3)
}

// BLOCKED is a first-class outcome: the model may declare it, it is recorded, never retried.
{
  const { deps, calls } = loopHarness({
    plan: async () => ({ ok: true, source: 'typesafe',
                         operation: { op: 'BLOCKED', reason: 'human_required' } }),
  })
  const summary = await runLoop(deps)
  check('B1 loop: a model BLOCKED ends the run blocked, naming the reason',
    summary.status === 'blocked' && summary.blocked_reason === 'model_blocked: human_required')
  check('B1 loop: a model BLOCKED dispatches nothing', calls.dispatch.length === 0)
}

// A guard failure is recorded, never dispatched, and never retried past its cap.
{
  let guards = 0
  const { deps, calls, events } = loopHarness({
    guard: async () => { guards += 1; return { ok: false, guard: 'freshness', reason: 'stale snapshot' } },
  })
  const summary = await runLoop(deps)
  check('B1 loop: a failing guard dispatches nothing', calls.dispatch.length === 0)
  check('B1 loop: the failing guard is recorded on every attempt',
    events.length === GUARD_RETRY_CAP && events.every((e) => e.status === 'blocked' && e.guard === 'freshness'))
  check('B1 loop: the same guard is not retried blindly past the cap',
    guards === GUARD_RETRY_CAP && summary.status === 'blocked'
    && String(summary.blocked_reason).includes('guard_repeat_cap_reached'))
}

// An invalid model answer re-plans within the step budget and never dispatches.
{
  const sources = ['invalid_choice', 'invalid_choice', 'invalid_choice']
  let i = 0
  const { deps, calls } = loopHarness({
    plan: async () => ({ ok: false, source: sources[Math.min(i++, sources.length - 1)],
                         reason: 'choice is not the argmax' }),
  })
  const summary = await runLoop(deps)
  check('B1 loop: an invalid choice never dispatches', calls.dispatch.length === 0)
  check('B1 loop: an invalid choice re-plans a bounded number of times',
    summary.status === 'blocked' && String(summary.blocked_reason).includes('replan_cap_reached'))
  check('B1 loop: the re-plan cap is the named REPLAN_CAP budget', REPLAN_CAP >= 1)
}

// A denied/unavailable model posture never dispatches (no plan, no action).
{
  const { deps, calls } = loopHarness({
    plan: async () => ({ ok: false, source: 'denied',
                         reason: 'external judgment denied by engagement policy' }),
  })
  const summary = await runLoop(deps)
  check('B1 loop: a denied model posture blocks the run without dispatching',
    summary.status === 'blocked' && calls.dispatch.length === 0
    && String(summary.blocked_reason).includes('denied'))
}

// A receipt failure after dispatch is unproven: the run stops, it does not compound.
{
  const { deps } = loopHarness({
    record: async () => ({ ok: false, reason: 'ACTION_RECORDED write failed' }),
  })
  const summary = await runLoop(deps)
  check('B1 loop: a receipt failure stops the run as unproven',
    summary.status === 'blocked' && String(summary.blocked_reason).includes('receipt_failed'))
}

// ===================================================================================
// 2. CLI preconditions (fail closed before any browser is needed)
// ===================================================================================
function tempWorkspace({ assets = ['t.example'], binding = null, preflight = true } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'bua-interactive-'))
  mkdirSync(join(root, '11_runtime'), { recursive: true })
  mkdirSync(join(root, '00_control'), { recursive: true })
  writeFileSync(join(root, '11_runtime', 'events.jsonl'), '')
  writeFileSync(join(root, '00_control', 'engagement.yaml'),
    'scope:\n  assets:\n' + assets.map((a) => `  - "${a}"\n`).join(''))
  if (binding) writeFileSync(join(root, '00_control', 'identity-binding.yaml'), binding)
  if (preflight) {
    writeFileSync(join(root, 'preflight.json'), JSON.stringify({
      cycle_id: 'C-000001', target: 'https://t.example', account: 'researcher-A',
      object_owner: 'researcher-A', purpose: 'probe the interactive arm',
      hypothesis: 'H-0001', expected_secure: 'denied', expected_vulnerable: 'allowed',
      side_effect: 'none', stop_condition: 'stop on unsafe behavior',
    }))
  }
  symlinkSync(join(REPO_ROOT, 'tools'), join(root, 'tools'), 'dir')
  return root
}

function runCli(root, extraArgs = []) {
  try {
    const out = execFileSync('node', [
      join(REPO_ROOT, 'tools', 'bua', 'interactive.mjs'),
      '--url', 'https://t.example/app', '--principal', 'researcher-A',
      '--action', 'A-000001', '--profile', 'lab/bua-profile',
      '--preflight', 'preflight.json', ...extraArgs,
    ], { cwd: root, encoding: 'utf8' })
    return { status: 0, out }
  } catch (e) {
    return { status: e.status, out: String((e.stdout || '') + (e.stderr || '')) }
  }
}

{
  const root = tempWorkspace({ assets: ['other.example'] })
  try {
    const refused = runCli(root)
    check('B1 CLI: an out-of-scope entry URL is refused before any browser starts (exit 4)',
      refused.status === 4 && refused.out.includes('outside the engagement scope'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}
{
  const clean = mkdtempSync(join(tmpdir(), 'bua-interactive-clean-'))
  try {
    const refused = runCli(clean)
    check('B1 CLI: a directory that is not a workspace exits 2 (fail closed)',
      refused.status === 2 && refused.out.includes('not inside a Research OS workspace'))
  } finally {
    rmSync(clean, { recursive: true, force: true })
  }
}
{
  const root = tempWorkspace()
  try {
    let refused = { status: 0, out: '' }
    try {
      execFileSync('node', [join(REPO_ROOT, 'tools', 'bua', 'interactive.mjs'),
        '--url', 'https://t.example/app', '--principal', 'researcher-A', '--action', 'A-000001'],
      { cwd: root, encoding: 'utf8' })
    } catch (e) { refused = { status: e.status, out: String((e.stdout || '') + (e.stderr || '')) } }
    check('B4 CLI: the interactive path refuses to run without an explicit --profile (no silent lab default)',
      refused.status === 2 && refused.out.includes('--profile'))
    refused = { status: 0, out: '' }
    try {
      execFileSync('node', [join(REPO_ROOT, 'tools', 'bua', 'interactive.mjs'),
        '--url', 'https://t.example/app', '--principal', 'researcher-A', '--action', 'A-000001',
        '--profile', '../outside', '--preflight', 'preflight.json'],
      { cwd: root, encoding: 'utf8' })
    } catch (e) { refused = { status: e.status, out: String((e.stdout || '') + (e.stderr || '')) } }
    check('B4 CLI: a profile outside the workspace is refused (exit 2)',
      refused.status === 2 && refused.out.includes('inside the workspace'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

// ===================================================================================
// 3. Scope handlers are installed for the whole run (injected fake chromium)
// ===================================================================================
{
  const installOrder = []
  const page = {
    on() {}, mainFrame: () => ({}), url: () => 'https://t.example/app',
    title: async () => 'stub', screenshot: async () => {},
    goto: async () => ({ status: () => 200 }),
  }
  const context = {
    on() {}, pages: () => [page], newPage: async () => page, close: async () => {},
    async route() { installOrder.push('route') },
    async routeWebSocket() { installOrder.push('routeWebSocket') },
    async addInitScript() { installOrder.push('addInitScript') },
    async newCDPSession() {
      installOrder.push('cdp')
      return { send: async (m) => { installOrder.push('cdp:' + m); return {} }, on() {} }
    },
  }
  const chromium = {
    launchPersistentContext: async () => { installOrder.push('launch'); return context },
  }
  const root = tempWorkspace()
  try {
    const summary = await runInteractive({
      root,
      args: {
        url: 'https://t.example/app', principal: 'researcher-A', action: 'A-000001',
        profile: 'lab/bua-profile', 'preflight': 'preflight.json', 'out-dir': 'artifacts',
        steps: '1',
      },
      chromium,
      ctl: () => ({ binding_present: false }),
      scopeVerdict: () => ({ in_scope: true, gate: 'assets', host: 't.example' }),
      token: { action_id: 'A-000001', nonce: 'n1', tool_family: 'browser',
               argument_digest: 'd', preflight: { account: 'researcher-A' } },
      plan: async () => {
        installOrder.push('plan')
        return { ok: true, source: 'typesafe', operation: { op: 'DONE' } }
      },
      verify: async () => ({ ok: true, evidence: 'E-000001', capture: 'shot.png' }),
      log: () => {},
    })
    const firstPlan = installOrder.indexOf('plan')
    check('B1 handlers: the route handler is installed before the first planned action',
      installOrder.indexOf('route') > -1 && installOrder.indexOf('route') < firstPlan)
    check('B1 handlers: the websocket handler is installed for the run',
      installOrder.includes('routeWebSocket'))
    check('B1 handlers: the service-worker block is installed before the first navigation',
      installOrder.includes('addInitScript'))
    check('B1 handlers: worker sockets are observed over CDP for the run',
      installOrder.includes('cdp:Target.setAutoAttach'))
    check('B1 handlers: the run summary carries the scope-guard flags the read-only arm carries',
      summary.scope_violation === false && Array.isArray(summary.blocked_requests)
      && Array.isArray(summary.out_of_scope_hops) && summary.status === 'confirmed')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

// ===================================================================================
// 4. The boundary: model output never becomes selectors, coordinates, shell or JS
// ===================================================================================
{
  const entries = [
    entry('e1'),
    entry('e2', { tag: 'input', type: 'text', ops: ['CLICK', 'TYPE'] }),
    entry('e5', { tag: 'input', type: 'password', ops: ['LOGIN'] }),
    entry('e6', { tag: 'select', ops: ['SELECT'], options: ['a', 'b'] }),
  ]
  const boundary = buildBoundary({ root: '/tmp/bua-boundary', entries,
                                   textValues: ['admin'], uploadFiles: [], loginFlows: ['primary'] })
  const refused = (label, raw, needle) => {
    const parsed = parseOperation(raw, boundary)
    check(label, parsed.ok === false && String(parsed.reason).toLowerCase().includes(needle))
  }
  refused('B2 boundary: a model-emitted CSS selector is refused',
    { op: 'CLICK', selector: '#submit' }, 'selector')
  refused('B2 boundary: a selector smuggled as a handle is refused',
    { op: 'CLICK', handle: '#submit' }, 'opaque handle')
  refused('B2 boundary: model-emitted coordinates are refused',
    { op: 'CLICK', handle: 'e1', x: 10, y: 20 }, 'coordinates')
  refused('B2 boundary: model-emitted JavaScript is refused',
    { op: 'CLICK', handle: 'e1', script: 'fetch("/admin")' }, 'javascript')
  refused('B2 boundary: a model-emitted shell command is refused',
    { op: 'CLICK', handle: 'e1', command: 'curl https://evil.example' }, 'shell')
  refused('B2 boundary: an unexpected key is refused (closed schema)',
    { op: 'CLICK', handle: 'e1', href: 'https://evil.example' }, 'unexpected key')
  refused('B2 boundary: a string "CLICK(e1)" is not a typed operation',
    'CLICK(e1)', 'not a typed object')
  refused('B2 boundary: an unknown operation is refused',
    { op: 'EVALUATE', handle: 'e1' }, 'unknown operation')
  refused('B2 boundary: a stale handle is refused at the boundary',
    { op: 'CLICK', handle: 'e99' }, 'not in the executor snapshot')
  refused('B2 boundary: a javascript: navigation is refused',
    { op: 'NAVIGATE', url: 'javascript:alert(1)' }, 'not an http(s) navigation')
  refused('B2 boundary: a file: navigation is refused',
    { op: 'NAVIGATE', url: 'file:///etc/passwd' }, 'not an http(s) navigation')
  refused('B2 boundary: a data: navigation is refused',
    { op: 'NAVIGATE', url: 'data:text/html,<script>alert(1)</script>' }, 'not an http(s) navigation')
  refused('B2 boundary: userinfo in a URL is refused',
    { op: 'NAVIGATE', url: 'https://user:pw@t.example/' }, 'userinfo')
  refused('B2 boundary: an ambiguous authority is refused',
    { op: 'NAVIGATE', url: 'http://127.0.0.1:9\\@t.example/' }, 'ambiguous')
  refused('B2 boundary: over-long TYPE text is refused (the 2000-char cap)',
    { op: 'TYPE', handle: 'e2', text: 'x'.repeat(TYPE_TEXT_MAX + 1) }, 'plain string')
  refused('B2 boundary: a secret-shaped TYPE payload is refused (credentials never ride TYPE)',
    { op: 'TYPE', handle: 'e2', text: 'glpat-ABCDEFGHIJKLMNOPQRST' }, 'credential')
  refused('B2 boundary: TYPE never targets a credential field',
    { op: 'TYPE', handle: 'e5', text: 'hunter2' }, 'credential field')
  refused('B2 boundary: a SELECT option the target never offered is refused',
    { op: 'SELECT', handle: 'e6', option: 'not-offered' }, 'not offered')
  refused('B2 boundary: an upload file the executor never offered is refused',
    { op: 'UPLOAD', file: '/etc/passwd' }, 'not one of the executor-offered')
  refused('B2 boundary: a login flow that is not configured is refused',
    { op: 'LOGIN', flow: 'evil' }, 'not configured')
  const good = parseOperation({ op: 'TYPE', handle: 'e2', text: 'admin' }, boundary)
  check('B2 boundary: a typed operation over an executor handle passes',
    good.ok === true && good.op.text === 'admin')
  const nav = parseOperation({ op: 'NAVIGATE', url: 'https://t.example/app' }, boundary)
  check('B2 boundary: an in-shape http(s) navigation passes', nav.ok === true)
}

// ---- classification: read / state-changing / consequential ------------------------
{
  check('B2 classify: NAVIGATE is read', classifyAction({ op: 'NAVIGATE' }, null) === 'read')
  check('B2 classify: DONE and BLOCKED are read',
    classifyAction({ op: 'DONE' }, null) === 'read' && classifyAction({ op: 'BLOCKED' }, null) === 'read')
  check('B2 classify: LOGIN is consequential (credential use)',
    classifyAction({ op: 'LOGIN' }, null) === 'consequential')
  check('B2 classify: a submit button is consequential',
    classifyAction({ op: 'CLICK' }, entry('e1', { type: 'submit', text: 'Sign in' })) === 'consequential')
  check('B2 classify: a delete control is consequential',
    classifyAction({ op: 'CLICK' }, entry('e1', { text: 'Delete account' })) === 'consequential')
  check('B2 classify: a plain button is state-changing',
    classifyAction({ op: 'CLICK' }, entry('e1', { text: 'Next page' })) === 'state-changing')
  check('B2 classify: UPLOAD is state-changing',
    classifyAction({ op: 'UPLOAD' }, entry('e1')) === 'state-changing')
}

// ---- node-identity guards, re-checked at dispatch ---------------------------------
{
  const base = {
    generation: 7, currentGeneration: 7, entry: entry('e1'),
    locator: fakeLocator(), viewport,
  }
  const ok = await guardDispatch({ op: 'CLICK', handle: 'e1' }, base)
  check('B2 guard: a fresh, visible, uncovered node passes', ok.ok === true)
  const stale = await guardDispatch({ op: 'CLICK', handle: 'e1' }, { ...base, currentGeneration: 8 })
  check('B2 guard: a stale snapshot generation refuses dispatch',
    stale.ok === false && stale.guard === 'freshness')
  const gone = await guardDispatch({ op: 'CLICK', handle: 'e1' }, { ...base, entry: undefined })
  check('B2 guard: a handle that left the live snapshot refuses dispatch',
    gone.ok === false && gone.guard === 'freshness')
  const covered = await guardDispatch({ op: 'CLICK', handle: 'e1' },
    { ...base, locator: fakeLocator({ hitError: 'element is covered by <div class="overlay">' }) })
  check('B2 guard: an overlaid node is blocked, never clicked through',
    covered.ok === false && covered.guard === 'occlusion'
    && covered.reason.includes('covered by another element'))
  const moved = await guardDispatch({ op: 'CLICK', handle: 'e1' },
    { ...base, locator: fakeLocator({ box: { x: 90, y: 10, width: 100, height: 30 } }) })
  check('B2 guard: a node that moved beyond tolerance refuses dispatch',
    moved.ok === false && moved.guard === 'geometry' && moved.reason.includes('moved beyond tolerance'))
  const resized = await guardDispatch({ op: 'CLICK', handle: 'e1' },
    { ...base, locator: fakeLocator({ box: { x: 10, y: 10, width: 400, height: 30 } }) })
  check('B2 guard: a node that resized beyond tolerance refuses dispatch',
    resized.ok === false && resized.guard === 'geometry')
  const offscreen = await guardDispatch({ op: 'CLICK', handle: 'e1' },
    { ...base, locator: fakeLocator({ box: { x: 10, y: 1200, width: 100, height: 30 } }) })
  check('B2 guard: a node outside the viewport refuses dispatch (no scrolling)',
    offscreen.ok === false && offscreen.guard === 'geometry' && offscreen.reason.includes('outside the viewport'))
  const invisible = await guardDispatch({ op: 'CLICK', handle: 'e1' },
    { ...base, locator: fakeLocator({ visible: false }) })
  check('B2 guard: an invisible node refuses dispatch',
    invisible.ok === false && invisible.guard === 'geometry')
  const handleless = await guardDispatch({ op: 'NAVIGATE', url: 'https://t.example/' }, base)
  check('B2 guard: an operation without a handle skips the node guards',
    handleless.ok === true && handleless.targeted === false)
}

// ---- plan label resolution: the model can only name what the executor offered -----
{
  const boundary = buildBoundary({ root: '/tmp/bua-boundary',
    entries: [entry('e1'), entry('e6', { tag: 'select', ops: ['SELECT'], options: ['a', 'b'] }),
              entry('e7', { tag: 'a', ops: ['CLICK', 'NAVIGATE'], href: 'https://t.example/next' })],
    textValues: ['admin'], loginFlows: ['primary'] })
  const ctx = {
    targets: { CLICK: new Map([['e1', { handle: 'e1' }]]),
               TYPE: new Map([['e2', { handle: 'e2' }]]),
               SELECT: new Map([['e6=a', { handle: 'e6', option: 'a' }]]),
               NAVIGATE: new Map([['u0', { url: 'https://t.example/app' }]]) },
    texts: new Map([['t1', 'admin']]), files: new Map(), flows: new Map([['l1', 'primary']]),
    reasons: new Map([['b1', 'human_required']]),
  }
  check('B2 labels: an offered label resolves to a typed operation',
    resolveOperation({ op: 'CLICK', labels: { target: 'e1' } }, ctx).op.handle === 'e1')
  check('B2 labels: a forged target label is refused',
    resolveOperation({ op: 'CLICK', labels: { target: 'e99' } }, ctx).ok === false)
  check('B2 labels: a forged text label is refused',
    resolveOperation({ op: 'TYPE', labels: { target: 'e2', text: 't9' } }, ctx).ok === false)
  check('B2 labels: a composite select label resolves handle+option',
    JSON.stringify(resolveOperation({ op: 'SELECT', labels: { target: 'e6=a' } }, ctx).op)
    === JSON.stringify({ op: 'SELECT', handle: 'e6', option: 'a' }))
  check('B2 labels: a forged flow label is refused',
    resolveOperation({ op: 'LOGIN', labels: { flow: 'l9' } }, ctx).ok === false)
  check('B2 labels: a forged block reason is refused',
    resolveOperation({ op: 'BLOCKED', labels: { reason: 'b9' } }, ctx).ok === false)
  check('B2 labels: the executor still parses the resolved operation',
    parseOperation(resolveOperation({ op: 'CLICK', labels: { target: 'e1' } }, ctx).op, boundary).ok === true)
}

// ---- the real guard is what the loop uses (wiring, not just the pure function) ----
{
  const installOrder = []
  const dispatched = []
  const locator = {
    boundingBox: async () => ({ x: 10, y: 10, width: 100, height: 30 }),
    hitTargetCheck: async () => { throw new Error('element is covered by <div class="overlay">') },
  }
  const page = {
    on() {}, mainFrame: () => ({}), url: () => 'https://t.example/app',
    title: async () => 'stub', screenshot: async () => {},
    viewportSize: () => viewport, locator: () => ({ all: async () => [] }),
    goto: async () => ({ status: () => 200 }),
  }
  const context = {
    on() {}, pages: () => [page], newPage: async () => page, close: async () => {},
    async route() { installOrder.push('route') },
    async routeWebSocket() { installOrder.push('routeWebSocket') },
    async addInitScript() { installOrder.push('addInitScript') },
    async newCDPSession() { return { send: async () => ({}), on() {} } },
  }
  const root = tempWorkspace()
  try {
    const summary = await runInteractive({
      root,
      args: {
        url: 'https://t.example/app', principal: 'researcher-A', action: 'A-000001',
        profile: 'lab/bua-profile', preflight: 'preflight.json', 'out-dir': 'artifacts', steps: '2',
      },
      chromium: { launchPersistentContext: async () => context },
      ctl: () => ({ binding_present: false }),
      scopeVerdict: () => ({ in_scope: true, gate: 'assets', host: 't.example' }),
      token: { action_id: 'A-000001', nonce: 'n1', tool_family: 'browser',
               preflight: { account: 'researcher-A' } },
      snapshot: async () => ({ generation: 1, entries: [entry('e1')],
                               locators: new Map([['e1', locator]]),
                               url: 'https://t.example/app', title: 'stub' }),
      plan: async () => ({ ok: true, source: 'typesafe', operation: { op: 'CLICK', handle: 'e1' } }),
      authorize: async () => ({ ok: true, token: { action_id: 'A-000002', nonce: 'n2' } }),
      scopeRecheck: async () => ({ ok: true }),
      dispatch: async (ctx) => { dispatched.push(ctx); return { ok: true } },
      log: () => {},
    })
    check('B2 wiring: an occluded target is refused by the real guard before dispatch',
      dispatched.length === 0 && summary.status === 'blocked'
      && summary.events.some((e) => e.guard === 'occlusion'))
    check('B2 wiring: the refusal names the occlusion guard and never dispatches',
      String(summary.blocked_reason).includes('guard_repeat_cap_reached')
      && String(summary.blocked_reason).includes('occlusion'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

// ===================================================================================
// 5. Per-action authorization: preflight token, human gate, scope intersection
// ===================================================================================
{
  const { deps, calls, events } = loopHarness({
    authorize: async (ctx) => { calls.authorize.push(ctx); return { ok: false, reason: 'no prepared preflight token' } },
  })
  const summary = await runLoop(deps)
  check('B3 loop: a dispatch without a preflight token is refused',
    calls.dispatch.length === 0 && summary.status === 'blocked'
    && summary.events.some((e) => e.guard === 'authorization'))
  check('B3 loop: the authorization refusal names its reason',
    events[0].reason.includes('no prepared preflight token'))
}

{
  // A submit control classifies consequential: the gate is consulted, and without a
  // resolved gate naming the action nothing dispatches.
  const { deps, calls } = loopHarness({
    entries: [entry('e1', { type: 'submit', text: 'Submit' })],
    gate: async (ctx) => { calls.gate.push(ctx); return { ok: false, reason: 'no RESOLVED human gate names A-000001' } },
  })
  const summary = await runLoop(deps)
  check('B3 loop: a consequential action consults the human gate',
    calls.gate.length === GUARD_RETRY_CAP && calls.gate[0].actionId === 'A-000001')
  check('B3 loop: a consequential action without a resolved gate never dispatches',
    calls.dispatch.length === 0 && summary.status === 'blocked'
    && summary.events.some((e) => e.guard === 'human_gate'))
}

{
  const { deps, calls } = loopHarness({
    entries: [entry('e1', { type: 'submit', text: 'Submit' })],
    plan: (() => {
      const plans = [
        { ok: true, source: 'typesafe', operation: { op: 'CLICK', handle: 'e1' } },
        { ok: true, source: 'typesafe', operation: { op: 'DONE' } },
      ]
      let i = 0
      return async () => plans[Math.min(i++, plans.length - 1)]
    })(),
  })
  const summary = await runLoop(deps)
  check('B3 loop: a consequential action with a resolved gate dispatches',
    calls.dispatch.length === 1 && calls.gate.length === 1)
  check('B3 loop: the consequential receipt records the gate as resolved',
    calls.record[0].actionClass === 'consequential'
    && summary.history[0].gate === 'resolved'
    && summary.action_classes.consequential === 1)
}

{
  const { deps, calls } = loopHarness({
    scopeRecheck: async () => ({ ok: false, reason: 'out-of-scope dispatch refused (out_of_scope)' }),
  })
  const summary = await runLoop(deps)
  check('B3 loop: an out-of-scope write is refused and recorded, never followed',
    calls.dispatch.length === 0 && calls.authorize.length === 0
    && summary.events.some((e) => e.guard === 'scope' && e.reason.includes('out-of-scope')))
}

{
  const { deps, calls } = loopHarness({
    plan: (() => {
      const plans = [
        { ok: true, source: 'typesafe', operation: { op: 'CLICK', handle: 'e1' } },
        { ok: true, source: 'typesafe', operation: { op: 'DONE' } },
      ]
      let i = 0
      return async () => plans[Math.min(i++, plans.length - 1)]
    })(),
  })
  await runLoop(deps)
  check('B3 loop: every dispatched action registers its own evidence before its receipt',
    calls.capture.length === 1 && calls.capture[0].token.action_id === 'A-000001'
    && calls.record[0].capture.evidence === 'E-000001')
  check('B3 loop: the receipt carries the consumed token (nonce link for the audit)',
    calls.record[0].token.nonce === 'n1' && calls.record[0].actionClass === 'state-changing')
}

// ===================================================================================
// 6. The interactive arm's real authorization wiring (no token, no dispatch)
// ===================================================================================
{
  const dispatched = []
  const page = {
    on() {}, mainFrame: () => ({}), url: () => 'https://t.example/app',
    title: async () => 'stub', screenshot: async () => {},
    viewportSize: () => viewport, locator: () => ({ all: async () => [] }),
    goto: async () => ({ status: () => 200 }),
  }
  const context = {
    on() {}, pages: () => [page], newPage: async () => page, close: async () => {},
    async route() {}, async routeWebSocket() {}, async addInitScript() {},
    async newCDPSession() { return { send: async () => ({}), on() {} } },
  }
  const root = tempWorkspace()
  try {
    const summary = await runInteractive({
      root,
      args: {
        url: 'https://t.example/app', principal: 'researcher-A', action: 'A-000001',
        profile: 'lab/bua-profile', preflight: 'preflight.json', 'out-dir': 'artifacts', steps: '2',
      },
      chromium: { launchPersistentContext: async () => context },
      ctl: (args) => (args[0] === 'prepare'
        ? { error: 'cycle budget exhausted (2/2)' }
        : { binding_present: false }),
      scopeVerdict: () => ({ in_scope: true, gate: 'assets', host: 't.example' }),
      token: { action_id: 'A-000001', nonce: 'n1', tool_family: 'browser',
               preflight: { account: 'researcher-A' } },
      snapshot: async () => ({ generation: 1, entries: [entry('e1')],
                               locators: new Map([['e1', fakeLocator()]]),
                               url: 'https://t.example/app', title: 'stub' }),
      plan: async () => ({ ok: true, source: 'typesafe', operation: { op: 'CLICK', handle: 'e1' } }),
      scopeRecheck: async () => ({ ok: true }),
      dispatch: async (ctx) => { dispatched.push(ctx); return { ok: true } },
      log: () => {},
    })
    check('B3 wiring: a prepare refusal stops the run before any dispatch',
      dispatched.length === 0 && summary.status === 'blocked'
      && summary.events.some((e) => e.guard === 'authorization'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

{
  const root = tempWorkspace()
  try {
    const refused = runCli(root)
    check('B3 CLI: an action id with no prepared token refuses the run (exit 5, no browser)',
      refused.status === 5 && refused.out.includes('no prepared preflight token')
      && !refused.out.includes('playwright-core'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

// ===================================================================================
// 7. Identity and profile binding (no silent lab default on the interactive path)
// ===================================================================================
{
  const binding = 'binding_version: 1\nexpected_identity:\n  account_reference: researcher-A\n' +
    'session:\n  browser_profile: lab/bua-prog\n  session_must_match_identity: true\n'
  const root = tempWorkspace({ binding })
  try {
    const refused = runCli(root, ['--profile', 'lab/bua-other'])
    check('B4 CLI: a --profile that disagrees with the declared identity binding is refused (exit 5)',
      refused.status === 5 && refused.out.includes('identity binding'))
    const absent = runCli(root, ['--profile', 'lab/bua-prog'])
    check('B4 CLI: the bound profile passes the binding check and reaches the token check',
      absent.status === 5 && absent.out.includes('no prepared preflight token')
      && !absent.out.includes('identity binding'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}
{
  const root = tempWorkspace({ binding: 'expected_identity:\n\taccount_reference: x\n' })
  try {
    const refused = runCli(root)
    check('B4 CLI: a malformed identity binding fails the interactive path closed (exit 5)',
      refused.status === 5 && refused.out.toLowerCase().includes('malformed'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}
{
  const root = tempWorkspace()
  try {
    const refused = runCli(root, ['--profile', '/etc'])
    check('B4 CLI: an absolute profile outside the workspace is refused (exit 2)',
      refused.status === 2 && refused.out.includes('inside the workspace'))
    const absent = runCli(root)
    check('B4 CLI: an absent binding does not invent a profile — the token check is next (exit 5)',
      absent.status === 5 && absent.out.includes('no prepared preflight token'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}
{
  // Profile plumbing: the profile the controller passed is the profile the browser opens.
  const launched = []
  const page = {
    on() {}, mainFrame: () => ({}), url: () => 'https://t.example/app',
    title: async () => 'stub', screenshot: async () => {},
    viewportSize: () => viewport, locator: () => ({ all: async () => [] }),
    goto: async () => ({ status: () => 200 }),
  }
  const context = {
    on() {}, pages: () => [page], newPage: async () => page, close: async () => {},
    async route() {}, async routeWebSocket() {}, async addInitScript() {},
    async newCDPSession() { return { send: async () => ({}), on() {} } },
  }
  const root = tempWorkspace({
    binding: 'binding_version: 1\nexpected_identity:\n  account_reference: researcher-A\n' +
      'session:\n  browser_profile: lab/bua-prog\n',
  })
  try {
    const summary = await runInteractive({
      root,
      args: {
        url: 'https://t.example/app', principal: 'researcher-A', action: 'A-000001',
        profile: 'lab/bua-prog', preflight: 'preflight.json', 'out-dir': 'artifacts', steps: '1',
      },
      chromium: {
        launchPersistentContext: async (dir) => { launched.push(dir); return context },
      },
      ctl: () => ({ binding_present: true, browser_profile: 'lab/bua-prog',
                    account_reference: 'researcher-A' }),
      scopeVerdict: () => ({ in_scope: true, gate: 'assets', host: 't.example' }),
      token: { action_id: 'A-000001', nonce: 'n1', tool_family: 'browser',
               browser_profile: 'lab/bua-prog',
               preflight: { account: 'researcher-A' } },
      plan: async () => ({ ok: true, source: 'typesafe', operation: { op: 'DONE' } }),
      verify: async () => ({ ok: true, evidence: 'E-000001', capture: 'shot.png' }),
      log: () => {},
    })
    check('B4 profile: the interactive arm opens the dedicated profile it was given',
      launched.length === 1 && launched[0] === join(root, 'lab/bua-prog')
      && summary.status === 'confirmed')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}
{
  const root = tempWorkspace()
  const base = {
    root,
    args: {
      url: 'https://t.example/app', principal: 'researcher-A', action: 'A-000001',
      profile: 'lab/bua-other', preflight: 'preflight.json', 'out-dir': 'artifacts', steps: '1',
    },
    chromium: { launchPersistentContext: async () => { throw new Error('must not launch') } },
    scopeVerdict: () => ({ in_scope: true, gate: 'assets', host: 't.example' }),
    token: { action_id: 'A-000001', nonce: 'n1', tool_family: 'browser',
             browser_profile: 'lab/bua-prog', preflight: { account: 'researcher-A' } },
    plan: async () => ({ ok: true, source: 'typesafe', operation: { op: 'DONE' } }),
    log: () => {},
  }
  try {
    let code = null
    try {
      await runInteractive({ ...base, ctl: () => ({ binding_present: true,
                                                    browser_profile: 'lab/bua-prog',
                                                    account_reference: 'researcher-A' }) })
    } catch (e) { code = e.code }
    check('B4 wiring: a token bound to another profile than --profile is refused (exit 5)',
      code === 5)

    code = null
    try {
      await runInteractive({
        ...base,
        args: { ...base.args, profile: 'lab/bua-prog' },
        ctl: () => ({ binding_present: true, browser_profile: 'lab/bua-prog',
                      account_reference: 'researcher-A' }),
        token: { action_id: 'A-000001', nonce: 'n1', tool_family: 'browser',
                 browser_profile: 'lab/bua-prog', preflight: { account: 'intruder-acct' } },
      })
    } catch (e) { code = e.code }
    check('B4 wiring: a token account outside the declared identity binding is refused (exit 5)',
      code === 5)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

// ===================================================================================
// 8. Plan fan-out: the executor builds the whole model space
// ===================================================================================
{
  const entries = [
    entry('e1', { text: 'Sign in' }),
    entry('e2', { tag: 'input', type: 'text', ops: ['CLICK', 'TYPE'] }),
    entry('e6', { tag: 'select', ops: ['SELECT'], options: ['a', 'b'] }),
    entry('e7', { tag: 'a', ops: ['CLICK', 'NAVIGATE'], href: 'https://t.example/next' }),
  ]
  const boundary = buildBoundary({ root: '/tmp/bua-boundary', entries,
                                   textValues: ['admin'], loginFlows: ['primary'] })
  const ctx = planContext({
    boundary, entryUrl: 'https://t.example/app', step: 2, cycleId: 'C-0001',
    history: [{ step: 1, op: 'NAVIGATE', status: 'recorded' }],
    snapshot: { url: 'https://t.example/app', title: 'App', entries },
  })
  const q = ctx.request.questions
  check('B5 planContext: the operation question offers the executor vocabulary',
    JSON.stringify(q.bua_operation.choices) === JSON.stringify(['DONE', 'BLOCKED', 'CLICK', 'TYPE', 'SELECT', 'NAVIGATE', 'LOGIN']))
  check('B5 planContext: per-operation target questions carry executor labels only',
    JSON.stringify(q['bua_target:CLICK'].choices) === JSON.stringify(['e1', 'e2', 'e7'])
    && JSON.stringify(q['bua_target:SELECT'].choices) === JSON.stringify(['e6=a', 'e6=b']))
  check('B5 planContext: the entry URL and page links are opaque labels, not URLs in the choices',
    JSON.stringify(q['bua_target:NAVIGATE'].choices) === JSON.stringify(['u0', 'u1'])
    && !JSON.stringify(q['bua_target:NAVIGATE'].choices).includes('http'))
  check('B5 planContext: text, file, flow and block questions come from executor config',
    JSON.stringify(q.bua_text.choices) === JSON.stringify(['t1'])
    && JSON.stringify(q.bua_flow.choices) === JSON.stringify(['l1'])
    && q.bua_file === undefined && JSON.stringify(q.bua_block.choices) === JSON.stringify(['b1', 'b2', 'b3', 'b4']))
  check('B5 planContext: the model state names elements by handle and text, never by selector',
    ctx.request.state.elements[0].handle === 'e1'
    && ctx.request.state.elements[0].text === 'Sign in'
    && !('href' in ctx.request.state.elements[0]))
  check('B5 planContext: the labels resolve back to executor payloads',
    ctx.targets.CLICK.get('e1').handle === 'e1'
    && ctx.targets.NAVIGATE.get('u1').url === 'https://t.example/next'
    && ctx.targets.SELECT.get('e6=b').option === 'b')
}

// ---- the real plan seam, end to end (real researchctl, denied policy) --------------
{
  const root = mkdtempSync(join(tmpdir(), 'bua-plan-e2e-'))
  let token = null
  try {
    mkdirSync(join(root, '11_runtime'), { recursive: true })
    mkdirSync(join(root, '00_control'), { recursive: true })
    mkdirSync(join(root, '12_knowledge', 'fixture'), { recursive: true })
    writeFileSync(join(root, '11_runtime', 'events.jsonl'), '')
    writeFileSync(join(root, '12_knowledge', 'fixture', 'fixture.md'), '# Fixture pack\n')
    writeFileSync(join(root, '12_knowledge', 'INDEX.yaml'),
      'packs:\n  fixture:\n    load_when: [interactive, fixture]\n    files: [fixture.md]\n')
    writeFileSync(join(root, '00_control', 'engagement.yaml'),
      'scope:\n  assets:\n  - "t.example"\n' +
      'budget:\n  max_actions_per_cycle: 10\n  max_actions_per_engagement: 50\n')
    writeFileSync(join(root, 'preflight.json'), JSON.stringify({
      cycle_id: 'C-0001', target: 'https://t.example', account: 'researcher-A',
      object_owner: 'researcher-A', purpose: 'interactive end to end',
      hypothesis: 'H-0001', expected_secure: 'denied', expected_vulnerable: 'allowed',
      side_effect: 'none', stop_condition: 'stop on unsafe behavior',
    }))
    symlinkSync(join(REPO_ROOT, 'tools'), join(root, 'tools'), 'dir')
    writeFileSync(join(root, 'fixture.py'), `
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / 'tools'))
from control_plane import ControlPlane
root = Path(sys.argv[1])
cp = ControlPlane(root)
cp.create_cycle('C-0001', {
    'id': 'C-0001', 'type': 'DISCOVERY', 'objective': 'interactive fixture',
    'allowed_scope': ['t.example'], 'stop_conditions': ['stop'], 'controls': [],
    'status': 'PLANNED',
    'knowledge_triage': [{'pack': 'fixture', 'verdict': 'SKIP',
                          'reason': 'fixture triage covers this pack'}],
})
(root / '04_cycles/C-0001').mkdir(parents=True, exist_ok=True)
(root / '04_cycles/C-0001/objective.md').write_text(
    '# Cycle Objective\\n\\n## Question\\nDoes behavior differ by principal?\\n\\n'
    '## Minimal test\\nTwo-principal differential on a researcher-owned object.\\n')
cp.transition_cycle('C-0001', 'READY', reason='ready')
cp.transition_cycle('C-0001', 'RUNNING', reason='run')
cp.create_hypothesis('H-0001', {'cycle_id': 'C-0001', 'observation': 'fixture',
                                'hypothesis': 'fixture', 'secure_prediction': 'denied',
                                'vulnerable_prediction': 'allowed'})
tok = cp.prepare_action({
    'cycle_id': 'C-0001', 'target': 'https://t.example/app', 'scope_status': 'IN_SCOPE',
    'account': 'researcher-A', 'object_owner': 'researcher-A',
    'purpose': 'interactive end to end', 'hypothesis': 'H-0001',
    'expected_secure': 'denied', 'expected_vulnerable': 'allowed',
    'side_effect': 'none', 'stop_condition': 'stop on unsafe behavior',
    'tool_family': 'browser',
    'request_shape': {'url': 'https://t.example/app', 'principal': 'researcher-A'},
})
print(json.dumps(tok))
`)
    token = JSON.parse(execFileSync('python3', [join(root, 'fixture.py'), root], { encoding: 'utf8' }))

    const page = {
      on() {}, mainFrame: () => ({}), url: () => 'https://t.example/app',
      title: async () => 'App', screenshot: async () => {},
      viewportSize: () => viewport, locator: () => ({ all: async () => [] }),
      goto: async () => ({ status: () => 200 }),
    }
    const context = {
      on() {}, pages: () => [page], newPage: async () => page, close: async () => {},
      async route() {}, async routeWebSocket() {}, async addInitScript() {},
      async newCDPSession() { return { send: async () => ({}), on() {} } },
    }
    const summary = await runInteractive({
      root,
      args: {
        url: 'https://t.example/app', principal: 'researcher-A', action: token.action_id,
        profile: 'lab/bua-profile', preflight: 'preflight.json', 'out-dir': 'artifacts',
        steps: '2',
      },
      chromium: { launchPersistentContext: async () => context },
      log: () => {},
    })
    check('B5 e2e: a denied model policy blocks the interactive run before any dispatch',
      summary.status === 'blocked' && String(summary.blocked_reason).includes('denied'))
    check('B5 e2e: the run reports no confirmed action and no scope violation',
      summary.confirmed_evidence === null && summary.scope_violation === false)
    check('B5 e2e: the entry token was consumed exactly once by the real seam',
      execFileSync('python3', ['-c',
        "import json,sys;rows=[json.loads(l) for l in open(sys.argv[1]) if l.strip()];" +
        "print(sum(1 for r in rows if r.get('consumed')))", join(root, '11_runtime', 'action-tokens.jsonl')],
      { encoding: 'utf8' }).trim() === '1')
    const artifactsDir = join(root, 'artifacts')
    const summaryFile = readdirSync(artifactsDir).find((f) => f.endsWith('.interactive.json'))
    const artifact = JSON.parse(readFileSync(join(artifactsDir, summaryFile), 'utf8'))
    check('B5 e2e: the summary artifact carries the scope-guard flags and the blocked reason',
      artifact.blocked_reason.includes('denied') && Array.isArray(artifact.blocked_requests)
      && artifact.blocked_requests.length === 0)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

console.log(`\n${passed}/${passed + failures.length} passed`)
if (failures.length) {
  console.log('FAILURES: ' + failures.join(' | '))
  process.exit(1)
}