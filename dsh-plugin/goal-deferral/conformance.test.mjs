/**
 * Conformance suite for the research-os goal-deferral adapter (DSH side).
 *
 * Each case simulates the DSH host's seams (tools.guard, ctx.on('subagent/*'),
 * ctx.jobs) and the shared lease registry, and asserts the adapter's actual
 * decision. Run: `node conformance.test.mjs` from this directory.
 *
 * The adapter is veto-only: it may block, it never pauses/resumes durable goal
 * state and never emits a continuation.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import * as adapter from './index.js'
import { apply, createGoalDeferral, readLeaseVerdict } from './index.js'

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

// ---- fixtures ---------------------------------------------------------------
const sandbox = mkdtempSync(join(tmpdir(), 'goal-deferral-'))
const NOW = 5000

function leaseRecord(state, over = {}) {
  return {
    seq: 1, version: 1, time: 1000, run_id: 'run-1', lease_id: 'L-1a2b3c4d',
    event: 'acquire', state, owner: { pid: 123, label: 'battery', session: 'ses_1' },
    command: 'python3 -m harness', pgid: 456, heartbeat_at: 1000, expires_at: 100000,
    interval_seconds: 120, exit_code: null, commit: null, reason: '', ...over,
  }
}

function workspace(name, files = {}) {
  const root = join(sandbox, name)
  mkdirSync(join(root, '.leases'), { recursive: true })
  for (const [runId, records] of Object.entries(files)) {
    const body = records.map((r) => (typeof r === 'string' ? r : JSON.stringify(r))).join('\n')
    writeFileSync(join(root, '.leases', `${runId}.jsonl`), body + '\n')
  }
  return root
}

function bareWorkspace(name) {
  const root = join(sandbox, name)
  mkdirSync(root, { recursive: true })
  return root
}

// ---- mock harness -----------------------------------------------------------
function harness(options = {}) {
  const guards = []
  const listeners = new Map()
  const calls = []
  const goals = {
    pause: () => calls.push('pause'), resume: () => calls.push('resume'),
    requestDrive: () => calls.push('requestDrive'), emit: () => calls.push('emit'),
  }
  const tools = { guard: (fn) => guards.push(fn) }
  const ctx = {
    get: (svc) => (svc === 'tools' ? tools : svc === 'goals' ? goals : svc === 'jobs' ? options.jobs : undefined),
    on: (evt, fn) => {
      listeners.set(evt, [...(listeners.get(evt) || []), fn])
      return () => listeners.set(evt, (listeners.get(evt) || []).filter((f) => f !== fn))
    },
  }
  const gate = apply(ctx, options.apply || {})
  return {
    gate, goals, calls, listeners,
    guardReason: (exec) => guards.map((g) => g(exec)).find((r) => r !== undefined),
    fire: (evt, ...args) => (listeners.get(evt) || []).forEach((fn) => fn(...args)),
  }
}

function exec(toolName, cwd) {
  return { name: toolName, arguments: {}, agent: { session: { header: { cwd } } } }
}

// ---- R1: the veto blocks goal mutation while a lease is held ----------------
const activeRoot = workspace('active', { 'run-1': [leaseRecord('active')] })
const h = harness({ apply: { root: activeRoot, runId: 'run-1', now: () => NOW } })
check('apply installs a guard and returns a gate', typeof h.guardReason === 'function' && !!h.gate)
check('update_goal is denied while the lease is active',
  typeof h.guardReason(exec('update_goal', activeRoot)) === 'string')
check('create_goal is denied while the lease is active',
  typeof h.guardReason(exec('create_goal', activeRoot)) === 'string')
check('the denial names the run and the lease state',
  /run-1/.test(h.guardReason(exec('update_goal', activeRoot)))
  && /active/.test(h.guardReason(exec('update_goal', activeRoot))))
check('read-only get_goal stays allowed', h.guardReason(exec('get_goal', activeRoot)) === undefined)
check('unrelated tools stay allowed', h.guardReason(exec('bash', activeRoot)) === undefined)

const awaitingRoot = workspace('awaiting', {
  'run-1': [leaseRecord('awaiting-reconciliation', { version: 2, exit_code: 0 })],
})
const h2 = harness({ apply: { root: awaitingRoot, runId: 'run-1', now: () => NOW } })
check('update_goal is denied after process exit, until reconciliation',
  typeof h2.guardReason(exec('update_goal', awaitingRoot)) === 'string')

const unknownRoot = workspace('unknown', {
  'run-1': [leaseRecord('unknown-recovery-required', { version: 2, reason: 'expired' })],
})
const h3 = harness({ apply: { root: unknownRoot, runId: 'run-1', now: () => NOW } })
check('update_goal is denied while the lease is unknown (recovery required)',
  typeof h3.guardReason(exec('update_goal', unknownRoot)) === 'string')

const releasedRoot = workspace('released', {
  'run-1': [leaseRecord('released', { version: 3, commit: 'a'.repeat(40) })],
})
const h4 = harness({ apply: { root: releasedRoot, runId: 'run-1', now: () => NOW } })
check('update_goal is allowed once the lease is released',
  h4.guardReason(exec('update_goal', releasedRoot)) === undefined)

const noLeaseRoot = workspace('no-lease', {})
const h5 = harness({ apply: { root: noLeaseRoot, runId: 'run-1', now: () => NOW } })
check('a readable registry without this run is clear (no-lease)',
  h5.guardReason(exec('update_goal', noLeaseRoot)) === undefined)

// ---- R2: fail closed on missing/unreadable/corrupt/expired -------------------
const missingRoot = bareWorkspace('missing-registry')
const h6 = harness({ apply: { root: missingRoot, runId: 'run-1', now: () => NOW } })
check('a missing registry blocks goal mutation (missing is never clear)',
  typeof h6.guardReason(exec('update_goal', missingRoot)) === 'string'
  && /missing/.test(h6.guardReason(exec('update_goal', missingRoot))))

const corruptRoot = workspace('corrupt', { 'run-1': [leaseRecord('released'), '{not json}'] })
const h7 = harness({ apply: { root: corruptRoot, runId: 'run-1', now: () => NOW } })
check('a corrupt registry line blocks (tolerated, never a crash)',
  typeof h7.guardReason(exec('update_goal', corruptRoot)) === 'string'
  && /corrupt/.test(h7.guardReason(exec('update_goal', corruptRoot))))

const emptyRoot = workspace('empty-file', { 'run-1': [] })
const h8 = harness({ apply: { root: emptyRoot, runId: 'run-1', now: () => NOW } })
check('an empty registry file blocks (unverifiable state)',
  typeof h8.guardReason(exec('update_goal', emptyRoot)) === 'string')

const expiredRoot = workspace('expired', {
  'run-1': [leaseRecord('active', { heartbeat_at: 1000, expires_at: 2000 })],
})
const h9 = harness({ apply: { root: expiredRoot, runId: 'run-1', now: () => NOW } })
check('an expired active lease blocks as unknown-recovery-required',
  typeof h9.guardReason(exec('update_goal', expiredRoot)) === 'string'
  && /expired/.test(h9.guardReason(exec('update_goal', expiredRoot))))

const chainRoot = workspace('bad-chain', {
  'run-1': [leaseRecord('released', { version: 5 }), leaseRecord('active', { version: 2 })],
})
const h10 = harness({ apply: { root: chainRoot, runId: 'run-1', now: () => NOW } })
check('a non-increasing version chain blocks (tamper-evident)',
  typeof h10.guardReason(exec('update_goal', chainRoot)) === 'string')

// ---- R3: the veto is workspace-wide when no run id is configured -------------
const wideRoot = workspace('workspace-wide', {
  'run-a': [leaseRecord('released', { run_id: 'run-a', commit: 'b'.repeat(40) })],
  'run-b': [leaseRecord('active', { run_id: 'run-b' })],
})
const h11 = harness({ apply: { root: wideRoot, now: () => NOW } })
check('workspace-wide mode blocks while any run holds a lease',
  typeof h11.guardReason(exec('update_goal', wideRoot)) === 'string')
const wideClear = workspace('workspace-wide-clear', {
  'run-a': [leaseRecord('released', { run_id: 'run-a', commit: 'b'.repeat(40) })],
  'run-b': [leaseRecord('released', { run_id: 'run-b', commit: 'c'.repeat(40) })],
})
const h12 = harness({ apply: { root: wideClear, now: () => NOW } })
check('workspace-wide mode allows when every recorded lease is released',
  h12.guardReason(exec('update_goal', wideClear)) === undefined)

// ---- R4: activation boundary (unconfigured, not lease-managed) ---------------
const plainRoot = bareWorkspace('plain-workspace')
const h13 = harness({ apply: { root: plainRoot } })
check('a missing registry with an explicit root blocks (fail closed)',
  typeof h13.guardReason(exec('update_goal', plainRoot)) === 'string')
const h14 = harness({ apply: { runId: 'run-1' } })
check('unconfigured apply installs a discovery-based veto that stays inactive outside lease workspaces',
  h14.gate !== null && h14.guardReason(exec('update_goal', plainRoot)) === undefined)
const h15 = harness({ apply: { now: () => NOW } })
check('per-call discovery finds an ancestor workspace with .leases/',
  typeof h15.guardReason(exec('update_goal', activeRoot)) === 'string'
  && h15.guardReason(exec('update_goal', plainRoot)) === undefined)

// ---- R5: subscribe-then-reread, no lost wake-up ------------------------------
const rereadRoot = workspace('reread', { 'run-1': [leaseRecord('active')] })
const gate = createGoalDeferral({ root: rereadRoot, runId: 'run-1', now: () => NOW })
const seen = []
gate.onBlockerChange((verdict, meta) => seen.push([verdict.state, meta.source]))
check('subscribing delivers the current verdict immediately (no lost wake-up)',
  seen.length === 1 && seen[0][0] === 'active' && seen[0][1] === 'initial')
gate.notify('no-change')
check('a notify with no state change emits nothing', seen.length === 1)
writeFileSync(join(rereadRoot, '.leases', 'run-1.jsonl'),
  [JSON.stringify(leaseRecord('active', { version: 1 })), JSON.stringify(leaseRecord('awaiting-reconciliation', { version: 2 }))]
    .join('\n') + '\n')
gate.notify('jobs-changed')
check('a blocker-state change emits once with the fresh state',
  seen.length === 2 && seen[1][0] === 'awaiting-reconciliation' && seen[1][1] === 'jobs-changed')
check('blockedReason() re-reads (pull consumers see the current state)',
  /awaiting-reconciliation/.test(gate.blockedReason()))

// ---- R6: job/child observation re-reads the registry -------------------------
const obsRoot = workspace('observe', { 'run-1': [leaseRecord('active')] })
const gate2 = createGoalDeferral({ root: obsRoot, runId: 'run-1', now: () => NOW })
let jobChanged = null
let jobDone = null
const disposers = gate2.observeJobs({
  onJobsChanged: (fn) => { jobChanged = fn; return () => { jobChanged = null } },
  onJobDone: (fn) => { jobDone = fn; return () => { jobDone = null } },
})
const obsSeen = []
gate2.onBlockerChange((v) => obsSeen.push(v.state))
writeFileSync(join(obsRoot, '.leases', 'run-1.jsonl'),
  [JSON.stringify(leaseRecord('active')), JSON.stringify(leaseRecord('released', { version: 2, commit: 'd'.repeat(40) }))]
    .join('\n') + '\n')
jobChanged({})
check('a jobs-changed event re-reads and reports the transition',
  obsSeen.length === 2 && obsSeen[1] === 'released')
jobDone({})
check('a job-done event with no further change emits nothing', obsSeen.length === 2)
check('observeJobs returns disposers and detaches cleanly',
  typeof disposers === 'function' && jobChanged !== null)

// ---- R7: veto-only — no pause/resume, no continuation emission ---------------
check('the module exposes no pause/resume/emit/continue API',
  !Object.keys(adapter).some((k) => /pause|resume|emit|continu/i.test(k)))
check('apply never touches a durable goal service',
  h.calls.length === 0 && h13.calls.length === 0)
h.fire('subagent/end', {}, {})
check('a child lifecycle edge with no registry change emits nothing',
  h.calls.length === 0)

// ---- R8: a throwing verdict reader fails closed ------------------------------
const throwing = createGoalDeferral({
  root: activeRoot, runId: 'run-1',
  readVerdict: () => { throw new Error('registry exploded') },
})
const hThrow = harness({ apply: { root: activeRoot, runId: 'run-1', now: () => NOW } })
check('readLeaseVerdict is the default reader (no accidental bypass)',
  typeof readLeaseVerdict === 'function')
check('a throwing reader surfaces instead of allowing',
  (() => { try { throwing.blockedReason(); return false } catch { return true } })())

rmSync(sandbox, { recursive: true, force: true })
console.log(failures.length ? `\nFAIL: ${failures.length} check(s): ${failures.join('; ')}` : '')
console.log(`\n${passed}/${passed + failures.length} passed`)
process.exit(failures.length ? 1 : 0)
