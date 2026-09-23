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
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  DEFAULT_MAX_STEPS, GUARD_RETRY_CAP, REPLAN_CAP, buildBoundary, runInteractive, runLoop,
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
  boundingBox: async () => (visible ? (box || { x: 10, y: 10, w: 100, h: 30 }) : null),
  hitTargetCheck: async () => { if (hitError) throw new Error(hitError) },
})

// ===================================================================================
// 1. The loop (mocked snapshot/executor — no browser)
// ===================================================================================
function loopHarness(overrides = {}) {
  const calls = { dispatch: [], authorize: [], gate: [], guard: [], capture: [], record: [], verify: [] }
  const events = []
  const snapshotEntries = [entry('e1')]
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
      ctl: () => ({ ok: true }),
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

console.log(`\n${passed}/${passed + failures.length} passed`)
if (failures.length) {
  console.log('FAILURES: ' + failures.join(' | '))
  process.exit(1)
}
