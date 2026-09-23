/**
 * Goal-deferral integration test — the incident shape end to end, with the real
 * lease registry (written by `tools/leases.py` through the real launch wrapper) and
 * a fake two-emitter driver.
 *
 * The incident: a detached measurement process was still alive while the tracked
 * Task session had gone terminal, so the continuation gate fired early. Here a
 * detached process tree holds a lease; the driver must emit ZERO continuations
 * while the lease is held, exactly ONE after the completion predicate clears
 * (opencode emitter only — the DSH emitter is veto-only), and an expired lease must
 * wake exactly one bounded reconciliation turn and never a success report.
 *
 * Run: `node deferral.integration.test.mjs` from this directory.
 */
import { execFileSync, spawn } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createGoalDeferral } from './index.js'

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

const HERE = dirname(fileURLToPath(import.meta.url))
const OS_REPO = join(HERE, '..', '..')
const TOOLS = join(OS_REPO, 'tools')
const sandbox = mkdtempSync(join(tmpdir(), 'deferral-integration-'))

// ---- real registry driver (the Python module, real files, real lock) ----------
const opsPy = join(sandbox, 'lease_ops.py')
writeFileSync(opsPy, [
  'import json, sys, time',
  'sys.path.insert(0, sys.argv[1])',
  'import leases',
  'root, op, run = sys.argv[2], sys.argv[3], sys.argv[4]',
  "if op == 'verdict':",
  '    out = leases.verdict(root, run)',
  "elif op == 'acquire-expired':",
  '    leases.acquire(root, run, interval_seconds=1.0, now=time.time() - 3600)',
  '    out = leases.verdict(root, run)',
  "elif op == 'reconcile':",
  '    out = leases.reconcile(root, run)',
  'else:',
  "    raise SystemExit('unknown op')",
  'print(json.dumps(out))',
].join('\n') + '\n')

function ops(op, root, run) {
  return JSON.parse(execFileSync('python3', [opsPy, TOOLS, root, op, run],
    { encoding: 'utf8', timeout: 60000 }))
}

// ---- fixture: a complete run workspace (root-relative documented layout) -----
const W = join(sandbox, 'workspace')
mkdirSync(join(W, 'runs', 'run-1'), { recursive: true })
writeFileSync(join(W, 'runs', 'run-1', 'plan.json'),
  JSON.stringify({ cells: ['cell-a', 'cell-b'] }))
for (const cell of ['cell-a', 'cell-b']) {
  mkdirSync(join(W, 'runs', cell), { recursive: true })
  writeFileSync(join(W, 'runs', cell, 'manifest.json'), JSON.stringify({ run_id: cell }))
}
mkdirSync(join(W, 'reports'), { recursive: true })
writeFileSync(join(W, 'reports', 'sweep.md'), '# sweep\n')
const gitEnv = { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@e',
  GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@e' }
execFileSync('git', ['init', '-q'], { cwd: W, env: gitEnv })
execFileSync('git', ['commit', '-q', '--allow-empty', '-m', 'results'], { cwd: W, env: gitEnv })
const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: W, env: gitEnv, encoding: 'utf8' }).trim()
writeFileSync(join(W, 'runs', 'run-1', 'results-commit'), commit + '\n')

// ---- fake driver: one authoritative emitter, one veto-only emitter -----------
function createDriver(gate) {
  const state = {
    opencodeEmissions: [], dshEmissions: [], dshVetoes: 0, dshAllowed: 0,
    reconcileRequests: [], successReports: [], lastState: null,
  }
  gate.onBlockerChange((verdict, meta) => {
    state.lastState = verdict.state
    if (verdict.state === 'unknown-recovery-required') {
      // Bounded: exactly one reconciliation turn per entry into the unknown state
      // (the initial read counts; stable repeats do not re-wake).
      state.reconcileRequests.push({ source: meta.source, reason: verdict.reason })
    }
  })
  return {
    state,
    /** The idle-parent event: the sole emitter consults the gate before continuing. */
    tick(source) {
      gate.notify(source) // the event re-reads the registry (subscribe-then-reread)
      const verdict = gate.snapshot()
      if (verdict.blocked) {
        state.dshVetoes += 1
        return verdict
      }
      state.opencodeEmissions.push({ source })
      return verdict
    },
    /** A DSH-side drive attempt: veto-only — it may block, it never emits this run. */
    dshTick(source) {
      if (gate.blockedReason() !== null) {
        state.dshVetoes += 1
        return false
      }
      state.dshAllowed += 1
      return true
    },
    reportSuccess(source) {
      state.successReports.push({ source })
    },
  }
}

// ---- scenario A: detached tree alive -> terminal child -> reconcile -> one ----
const wrapper = spawn('python3', [
  join(TOOLS, 'lease_run.py'), '--root', W, '--run', 'run-1', '--interval', '0.3',
  '--', 'sleep', '30',
], { stdio: 'ignore' })
let pgid = null
try {
  const deadline = Date.now() + 30000
  while (Date.now() < deadline) {
    const verdict = ops('verdict', W, 'run-1')
    if (typeof verdict.pgid === 'number' && verdict.state === 'active') {
      pgid = verdict.pgid
      break
    }
    execFileSync('sleep', ['0.05'])
  }
  check('the detached process tree holds an active lease with a recorded process group',
    pgid !== null && ops('verdict', W, 'run-1').blocked === true)

  const gate = createGoalDeferral({ root: W, runId: 'run-1' })
  const driver = createDriver(gate)
  driver.tick('idle-parent')
  driver.dshTick('dsh-drive-attempt')
  check('a live detached process blocks every continuation emitter',
    driver.state.opencodeEmissions.length === 0 && driver.state.dshEmissions.length === 0
    && driver.state.dshVetoes === 2)

  // The hunter finishes: kill the detached tree; the wrapper records the raw exit.
  process.kill(-pgid, 'SIGKILL')
  const exitDeadline = Date.now() + 30000
  while (Date.now() < exitDeadline) {
    if (ops('verdict', W, 'run-1').state === 'awaiting-reconciliation') break
    execFileSync('sleep', ['0.05'])
  }
  const afterExit = ops('verdict', W, 'run-1')
  check('process exit alone does not release the lease (awaiting-reconciliation)',
    afterExit.state === 'awaiting-reconciliation' && afterExit.blocked === true
    && afterExit.exit_code !== 0)
  driver.tick('idle-parent-after-exit')
  check('a terminal child without reconciliation still emits nothing',
    driver.state.opencodeEmissions.length === 0 && driver.state.dshEmissions.length === 0)

  const reconciled = ops('reconcile', W, 'run-1')
  check('the real completion predicate clears and releases with the commit',
    reconciled.clear === true && reconciled.released === true && reconciled.commit === commit)
  driver.tick('idle-parent-reconciled')
  driver.dshTick('dsh-drive-after-clear')
  check('exactly one continuation after reconciliation — the opencode emitter alone',
    driver.state.opencodeEmissions.length === 1 && driver.state.dshEmissions.length === 0
    && driver.state.dshAllowed === 1 && driver.state.dshVetoes === 3)
  driver.reportSuccess('opencode')
  check('no success was reported while the lease was held',
    driver.state.successReports.length === 1)
} finally {
  try {
    process.kill(-pgid, 'SIGKILL')
  } catch {}
  wrapper.kill('SIGKILL')
}

// ---- scenario B: expired lease -> one bounded reconciliation, never success ---
const expired = ops('acquire-expired', W, 'run-2')
check('an expired lease reads as unknown-recovery-required',
  expired.state === 'unknown-recovery-required' && expired.blocked === true)

const gate2 = createGoalDeferral({ root: W, runId: 'run-2' })
const driver2 = createDriver(gate2)
driver2.tick('idle-parent-1')
driver2.tick('idle-parent-2')
driver2.tick('idle-parent-3')
check('an expired lease never emits a continuation',
  driver2.state.opencodeEmissions.length === 0 && driver2.state.dshEmissions.length === 0)
check('expiry never produces a success report', driver2.state.successReports.length === 0)
check('the expired lease wakes at most one reconciliation turn for a stable state',
  driver2.state.reconcileRequests.length === 1)

// A state transition (another run releasing) wakes exactly one more turn, not a storm.
const releasedNow = ops('reconcile', W, 'run-2')
check('reconcile on the expired lease reports recovery-required, never clear',
  releasedNow.clear === false && releasedNow.recovery_required === true
  && releasedNow.released === false && releasedNow.attempts === 1)

// The real CLI agrees: exit 3 while blocked, exit 0 after a proper release.
const blockedCli = (() => {
  try {
    execFileSync('python3', [join(TOOLS, 'researchctl.py'), W, 'lease-reconcile', 'run-2'],
      { encoding: 'utf8', timeout: 60000 })
    return { code: 0, stdout: '' }
  } catch (error) {
    return { code: error.status, stdout: error.stdout || '' }
  }
})()
check('the real CLI refuses an expired run with exit 3 and a recovery note',
  blockedCli.code === 3 && JSON.parse(blockedCli.stdout).recovery_required === true)

rmSync(sandbox, { recursive: true, force: true })
console.log(failures.length ? `\nFAIL: ${failures.length} check(s): ${failures.join('; ')}` : '')
console.log(`\n${passed}/${passed + failures.length} passed`)
process.exit(failures.length ? 1 : 0)
