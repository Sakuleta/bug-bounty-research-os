/**
 * Executable block/allow matrix for the OpenCode goal-plugin V2 pre-continuation gate
 * contract (`opencode-gate-contract.md`).
 *
 * The seam below mirrors the gate's INPUTS (the tracked-Task fold + the real shared
 * registry reader from `./index.js`); it is a harness, not the upstream plugin. The
 * contract is normative for the upstream fork; these checks pin its semantics here.
 *
 * Run: `node gate.matrix.test.mjs` from this directory.
 */
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { readLeaseVerdict } from './index.js'

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

// ---- the gate seam (mirrors taskBlockStatus + runAutoContinue inputs) ---------
const NOW = 5000

function taskBlockStatus(tracked) {
  if (!tracked || tracked.state === 'none') return { blocked: false, reason: 'no tracked task' }
  if (tracked.state === 'running') return { blocked: true, reason: 'tracked task running' }
  if (tracked.state === 'terminal-unreconciled') {
    return { blocked: true, reason: 'tracked task terminal, not reconciled by the parent' }
  }
  return { blocked: false, reason: 'tracked task reconciled' }
}

/** Upstream v0.1.50 semantics: 0/null means no ceiling, never "disable deferral". */
function taskBlockExpired(tracked, maxTaskBlockSeconds, now) {
  if (maxTaskBlockSeconds === null || maxTaskBlockSeconds === 0) return false
  if (!tracked || tracked.state !== 'terminal-unreconciled') return false
  return now - tracked.since > maxTaskBlockSeconds
}

function leaseBlockStatus(root, runId, now) {
  if (!root) return { blocked: false, state: 'unmanaged', reason: 'not lease-managed' }
  const verdict = readLeaseVerdict(root, runId, { now })
  return { blocked: verdict.blocked, state: verdict.state, reason: verdict.reason }
}

function preContinuationVerdict({ tracked, root = null, runId = null, now = NOW,
  maxTaskBlockSeconds = null }) {
  const task = taskBlockStatus(tracked)
  if (task.blocked && !taskBlockExpired(tracked, maxTaskBlockSeconds, now)) {
    return { allow: false, blocker: 'task', reason: task.reason }
  }
  const lease = leaseBlockStatus(root, runId, now)
  if (lease.blocked) return { allow: false, blocker: 'lease', reason: lease.reason }
  return { allow: true, blocker: null, reason: 'no blocking task and no held lease' }
}

// ---- fixtures ----------------------------------------------------------------
const sandbox = mkdtempSync(join(tmpdir(), 'gate-matrix-'))

function leaseRecord(state, over = {}) {
  return {
    seq: 1, version: 1, time: 1000, run_id: 'run-1', lease_id: 'L-1a2b3c4d', event: 'acquire',
    state, owner: { pid: 1, label: '', session: '' }, command: '', pgid: 2,
    heartbeat_at: 1000, expires_at: 100000, interval_seconds: 120, exit_code: null,
    commit: null, reason: '', ...over,
  }
}

function workspace(name, records) {
  const root = join(sandbox, name)
  mkdirSync(join(root, '.leases'), { recursive: true })
  if (records !== null) {
    writeFileSync(join(root, '.leases', 'run-1.jsonl'),
      records.map((r) => (typeof r === 'string' ? r : JSON.stringify(r))).join('\n') + '\n')
  }
  return root
}

/** A real git work tree with one commit; returns the commit sha (for released fixtures). */
function gitCommit(root) {
  const env = { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@e',
    GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@e' }
  execFileSync('git', ['init', '-q'], { cwd: root, env })
  execFileSync('git', ['commit', '-q', '--allow-empty', '-m', 'results'], { cwd: root, env })
  return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, env, encoding: 'utf8' }).trim()
}

const releasedRoot = workspace('released', null)
const releasedSha = gitCommit(releasedRoot)
writeFileSync(join(releasedRoot, '.leases', 'run-1.jsonl'),
  JSON.stringify(leaseRecord('released', { version: 3, commit: releasedSha })) + '\n')
const forgedRoot = workspace('forged-release', null)
writeFileSync(join(forgedRoot, '.leases', 'run-1.jsonl'),
  JSON.stringify(leaseRecord('released', { version: 3, commit: 'f'.repeat(40) })) + '\n')

const LEASES = {
  active: workspace('active', [leaseRecord('active')]),
  awaiting: workspace('awaiting', [leaseRecord('awaiting-reconciliation', { version: 2, exit_code: 0 })]),
  unknown: workspace('unknown', [leaseRecord('unknown-recovery-required', { version: 2 })]),
  expired: workspace('expired', [leaseRecord('active', { expires_at: 2000 })]),
  released: releasedRoot,
  forged: forgedRoot,
  noLease: workspace('no-lease', null),
  missing: join(sandbox, 'missing-registry'),
  corrupt: workspace('corrupt', [leaseRecord('released'), '{oops}']),
  badChain: workspace('bad-chain', [leaseRecord('released', { version: 5 }),
    leaseRecord('active', { version: 2 })]),
}
mkdirSync(LEASES.missing, { recursive: true })

// ---- the matrix --------------------------------------------------------------
const RUNNING = { state: 'running' }
const TERMINAL = { state: 'terminal-unreconciled', since: 0 }
const RECONCILED = { state: 'reconciled' }
const NONE = { state: 'none' }

const rows = [
  ['running task, released lease', { tracked: RUNNING, lease: 'released' }, false, 'task'],
  ['running task, held lease', { tracked: RUNNING, lease: 'active' }, false, 'task'],
  ['terminal unreconciled task, released lease',
    { tracked: TERMINAL, lease: 'released' }, false, 'task'],
  ['reconciled task, released lease allows',
    { tracked: RECONCILED, lease: 'released' }, true, null],
  ['reconciled task, no lease recorded allows',
    { tracked: RECONCILED, lease: 'noLease' }, true, null],
  ['no tracked task, released lease allows', { tracked: NONE, lease: 'released' }, true, null],
  ['no tracked task, unmanaged workspace allows', { tracked: NONE, root: null }, true, null],
  ['running task, unmanaged workspace still defers', { tracked: RUNNING, root: null }, false, 'task'],
  // The incident: a terminal/reconciled Task is not process exit, output
  // reconciliation or a commit — the lease alone must block the continuation.
  ['reconciled task, active lease (no Task-success shortcut)',
    { tracked: RECONCILED, lease: 'active' }, false, 'lease'],
  ['reconciled task, awaiting-reconciliation lease',
    { tracked: RECONCILED, lease: 'awaiting' }, false, 'lease'],
  ['reconciled task, unknown lease',
    { tracked: RECONCILED, lease: 'unknown' }, false, 'lease'],
  ['reconciled task, expired lease',
    { tracked: RECONCILED, lease: 'expired' }, false, 'lease'],
  ['reconciled task, missing registry in a managed root',
    { tracked: RECONCILED, lease: 'missing' }, false, 'lease'],
  ['reconciled task, corrupt registry',
    { tracked: RECONCILED, lease: 'corrupt' }, false, 'lease'],
  ['reconciled task, forged released lease (commit unproven)',
    { tracked: RECONCILED, lease: 'forged' }, false, 'lease'],
  ['reconciled task, unverifiable version chain',
    { tracked: RECONCILED, lease: 'badChain' }, false, 'lease'],
  ['no tracked task, active lease', { tracked: NONE, lease: 'active' }, false, 'lease'],
  ['reconciled task, task block expired, released lease allows',
    { tracked: TERMINAL, lease: 'released', maxTaskBlockSeconds: 60 }, true, null],
  ['reconciled task, task block expired, held lease still blocks',
    { tracked: TERMINAL, lease: 'active', maxTaskBlockSeconds: 60 }, false, 'lease'],
]

for (const [label, inputs, allow, blocker] of rows) {
  const root = inputs.root === null ? null
    : (inputs.lease ? LEASES[inputs.lease] : (inputs.root ?? LEASES.active))
  const verdict = preContinuationVerdict({
    tracked: inputs.tracked, root, runId: 'run-1', now: NOW,
    maxTaskBlockSeconds: inputs.maxTaskBlockSeconds ?? null,
  })
  check(`${label} -> ${allow ? 'allow' : 'block:' + blocker}`,
    verdict.allow === allow && verdict.blocker === blocker)
}

// ---- timeout rules (v0.1.50 pins) --------------------------------------------
check('max_task_block_seconds 0 means no ceiling (never expires a task block)',
  taskBlockExpired(TERMINAL, 0, 10 ** 9) === false
  && taskBlockExpired(TERMINAL, null, 10 ** 9) === false)
check('a task block with a ceiling expires on its own',
  taskBlockExpired(TERMINAL, 60, 3600) === true
  && taskBlockExpired(TERMINAL, 3600, 60) === false)
check('a task-block timeout never releases a held lease',
  preContinuationVerdict({ tracked: TERMINAL, root: LEASES.active, runId: 'run-1',
    now: NOW, maxTaskBlockSeconds: 0 }).allow === false)

// ---- the seam reads the real registry (not a stub) ---------------------------
check('the seam blocks because the real reader says so (corrupt fixture)',
  readLeaseVerdict(LEASES.corrupt, 'run-1', { now: NOW }).blocked === true
  && preContinuationVerdict({ tracked: RECONCILED, root: LEASES.corrupt, runId: 'run-1',
    now: NOW }).blocker === 'lease')

rmSync(sandbox, { recursive: true, force: true })
console.log(failures.length ? `\nFAIL: ${failures.length} check(s): ${failures.join('; ')}` : '')
console.log(`\n${passed}/${passed + failures.length} passed`)
process.exit(failures.length ? 1 : 0)
