/**
 * Goal-deferral adapter — the DSH side of the shared work-lease registry.
 *
 * Veto-only by construction: it blocks goal mutation while a run's lease is held
 * (`active` / `awaiting-reconciliation` / `unknown-recovery-required`), and it never
 * pauses/resumes durable goal state and never emits a continuation. The single
 * continuation emitter for a run is the OpenCode goal plugin (see
 * `opencode-gate-contract.md`); the DSH layer only vetoes.
 *
 * What it observes:
 *  - the shared registry `<root>/.leases/*.jsonl` (the same file format
 *    `tools/leases.py` writes; `readLeaseVerdict` mirrors its verdict rules and is
 *    parity-tested from `tools/test_leases.py`);
 *  - owner-scoped job lifecycle (`ctx.jobs.onJobsChanged` / `onJobDone`) and
 *    continuable-child lifecycle (`subagent/start` / `subagent/end`), re-reading the
 *    registry on every edge (subscribe-then-reread — no lost wake-up).
 *
 * Fail-closed rules (readers), identical to the Python side: a missing or unreadable
 * registry, a corrupt line, an unverifiable version chain and an expired `active`
 * lease all block; `awaiting-reconciliation` stays held until the completion
 * predicate clears; a stale lease is never success. Internal errors in `apply()`
 * fail open (the enforcer's contract), while the veto itself fails closed.
 *
 * Activation: the adapter only vetoes inside a lease-managed workspace — an explicit
 * `root`/`RESEARCH_OS_LEASE_ROOT`, or an ancestor of the call's cwd that contains
 * `.leases/`. Without one it installs nothing to block (a workspace that never used
 * leases is not deferred).
 *
 * Dependency-free: node stdlib only.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'

export const name = 'research-os-goal-deferral'
export const inject = ['tools']

/** The DSH goal-mutating tools (`@deepseek-ai/dsh-tool-goal`). Read-only `get_goal` stays allowed. */
export const GOAL_MUTATING_TOOLS = ['create_goal', 'update_goal']

const LEASE_STATES = ['active', 'awaiting-reconciliation', 'unknown-recovery-required', 'released']
const RUN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
// Worst state wins for the workspace-wide verdict (unknown > awaiting > active).
const WORST_ORDER = { active: 1, 'awaiting-reconciliation': 2, 'unknown-recovery-required': 3 }

function blocked(runId, state, reason, extra = {}) {
  return { runId, state, blocked: true, reason, ...extra }
}

function foldRecords(records) {
  let latest = null
  for (const record of records) {
    const version = record.version
    if (!Number.isInteger(version) || version < 1) {
      return { error: `record without a valid version (got ${JSON.stringify(version)})` }
    }
    if (latest && version <= latest.version) {
      return { error: `version chain is not strictly increasing (${version} after ${latest.version})` }
    }
    if (!LEASE_STATES.includes(record.state)) {
      return { error: `unknown lease state ${JSON.stringify(record.state)}` }
    }
    latest = record
  }
  if (!latest) return { error: 'no records' }
  return { latest }
}

function readLeaseFile(path, runId, nowSeconds) {
  let text
  try {
    text = readFileSync(path, 'utf8')
  } catch (error) {
    return blocked(runId, 'unknown-recovery-required',
      `lease registry file is unreadable: ${path} (${error}) (fail closed)`)
  }
  const records = []
  let corrupt = 0
  for (const line of text.split('\n')) {
    if (!line.trim()) continue
    let record
    try {
      record = JSON.parse(line)
    } catch {
      corrupt += 1
      continue
    }
    if (record && typeof record === 'object' && !Array.isArray(record)) records.push(record)
    else corrupt += 1
  }
  if (corrupt) {
    return blocked(runId, 'unknown-recovery-required',
      `lease registry has ${corrupt} corrupt line(s): ${path} — state cannot be established `
      + '(fail closed; a corrupt line is never a missed heartbeat and never a release)',
      { corruptLines: corrupt })
  }
  const folded = foldRecords(records)
  if (folded.error) {
    return blocked(runId, 'unknown-recovery-required',
      `lease registry state is unverifiable (${folded.error}): ${path} (fail closed)`)
  }
  const latest = folded.latest
  const common = {
    runId, version: latest.version, leaseId: latest.lease_id ?? null,
    owner: latest.owner && typeof latest.owner === 'object' ? latest.owner : {},
    pgid: latest.pgid ?? null, heartbeatAt: latest.heartbeat_at ?? null,
    expiresAt: latest.expires_at ?? null, exitCode: latest.exit_code ?? null,
    commit: latest.commit ?? null,
  }
  if (latest.state === 'released') {
    return { ...common, state: 'released', blocked: false,
      reason: `released after reconciliation (commit ${latest.commit})` }
  }
  if (latest.state === 'awaiting-reconciliation') {
    return { ...common, state: 'awaiting-reconciliation', blocked: true,
      reason: `process exited (exit_code=${latest.exit_code}) and the lease is held until the `
        + 'completion predicate clears' }
  }
  if (latest.state === 'active') {
    const expires = latest.expires_at
    if (typeof expires !== 'number' || !Number.isFinite(expires)) {
      return { ...common, state: 'unknown-recovery-required', blocked: true,
        reason: 'active lease without a readable expiry — liveness cannot be verified (fail closed)' }
    }
    if (expires <= nowSeconds) {
      return { ...common, state: 'unknown-recovery-required', blocked: true,
        reason: `heartbeat expired at ${expires} (missed heartbeats) — recovery required; `
          + 'stale is never success' }
    }
    return { ...common, state: 'active', blocked: true,
      reason: `lease held by pid ${common.owner.pid} (heartbeat ${latest.heartbeat_at}, `
        + `expires ${expires})` }
  }
  return { ...common, state: 'unknown-recovery-required', blocked: true,
    reason: `lease state ${latest.state} requires recovery` }
}

/**
 * Read the shared registry and return a verdict `{state, blocked, reason, runId, ...}`.
 *
 * `runId` given: that run's file. `runId` omitted/null: workspace-wide — blocked while
 * ANY recorded lease is held (the worst state wins). Missing/unreadable/corrupt input
 * is never clear.
 */
export function readLeaseVerdict(root, runId = null, options = {}) {
  const nowSeconds = typeof options.now === 'function'
    ? options.now()
    : (typeof options.now === 'number' ? options.now : Date.now() / 1000)
  const directory = join(root, '.leases')
  if (runId !== null && runId !== undefined && !RUN_ID_RE.test(String(runId))) {
    return blocked(String(runId), 'unknown-recovery-required',
      `unsafe run id ${JSON.stringify(runId)} — refusing to read a registry path built from it`)
  }
  if (!existsSync(directory)) {
    return blocked(runId, 'unknown-recovery-required',
      `lease registry missing: ${directory} (missing is never clear)`)
  }
  let entries
  try {
    entries = readdirSync(directory).filter((entry) => entry.endsWith('.jsonl')).sort()
  } catch (error) {
    return blocked(runId, 'unknown-recovery-required',
      `lease registry unreadable: ${directory} (${error}) — missing or unreadable is never clear`)
  }
  if (runId !== null && runId !== undefined) {
    const path = join(directory, `${runId}.jsonl`)
    if (!existsSync(path)) {
      return { runId, state: 'no-lease', blocked: false,
        reason: 'no lease recorded for this run (registry readable)' }
    }
    return readLeaseFile(path, runId, nowSeconds)
  }
  const runs = entries.map((entry) => readLeaseFile(
    join(directory, entry), entry.slice(0, -'.jsonl'.length), nowSeconds))
  const held = runs.filter((entry) => entry.blocked)
  if (!held.length) {
    return { runId: null, state: 'clear', blocked: false,
      reason: `${runs.length} lease file(s), none held`, runs }
  }
  const worst = held.reduce((a, b) =>
    ((WORST_ORDER[b.state] ?? 4) > (WORST_ORDER[a.state] ?? 4) ? b : a))
  return { ...worst, runId: null, blocked: true,
    reason: `run ${worst.runId}: ${worst.reason}`, runs }
}

/** Nearest ancestor of `start` that contains a `.leases/` directory, or null. */
export function findLeaseRoot(start) {
  let dir = resolve(String(start || '.'))
  for (let depth = 0; depth < 8; depth += 1) {
    if (existsSync(join(dir, '.leases'))) return dir
    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return null
}

function defaultResolveRoot(exec) {
  const cwd = (exec && exec.agent && exec.agent.session && exec.agent.session.header
    && exec.agent.session.header.cwd) || process.cwd()
  return findLeaseRoot(cwd)
}

function verdictKey(verdict) {
  return `${verdict.blocked ? 'blocked' : 'clear'}|${verdict.state}|${verdict.runId ?? ''}`
}

/**
 * The veto gate. `blockedReason()`/`snapshot()` read fresh (pull consumers always see
 * the current registry); `onBlockerChange` delivers the current verdict immediately on
 * subscribe and re-reads on every notification (subscribe-then-reread, no lost wake-up).
 */
export function createGoalDeferral(options = {}) {
  const staticRoot = options.root || null
  const runId = options.runId === undefined ? null : options.runId
  const now = typeof options.now === 'function' ? options.now : () => Date.now() / 1000
  const readVerdict = options.readVerdict || readLeaseVerdict
  const resolveRoot = options.resolveRoot || defaultResolveRoot
  const listeners = new Set()
  let lastKey = null

  function snapshot(exec) {
    const target = staticRoot || resolveRoot(exec)
    if (!target) {
      return { runId, state: 'clear', blocked: false,
        reason: 'no lease-managed workspace for this call' }
    }
    return readVerdict(target, runId, { now })
  }

  const gate = {
    snapshot,
    /** null when the run may proceed; a reason string while the lease holds. */
    blockedReason(exec) {
      const verdict = snapshot(exec)
      if (!verdict.blocked) return null
      const label = verdict.runId ?? runId ?? 'any run'
      return `${verdict.state} (${label}): ${verdict.reason}`
    },
    onBlockerChange(listener) {
      listeners.add(listener)
      const verdict = snapshot(null)
      lastKey = verdictKey(verdict)
      try {
        listener(verdict, { source: 'initial', initial: true })
      } catch (error) {
        console.error('research-os-goal-deferral: blocker listener failed: ' + error)
      }
      return () => listeners.delete(listener)
    },
    notify(source = 'notify') {
      const verdict = snapshot(null)
      const key = verdictKey(verdict)
      if (key === lastKey) return verdict
      lastKey = key
      for (const listener of listeners) {
        try {
          listener(verdict, { source })
        } catch (error) {
          console.error('research-os-goal-deferral: blocker listener failed: ' + error)
        }
      }
      return verdict
    },
    /** Subscribe to owner-scoped job lifecycle; every edge re-reads the registry. */
    observeJobs(jobs) {
      const disposers = []
      for (const method of ['onJobsChanged', 'onJobDone']) {
        try {
          if (jobs && typeof jobs[method] === 'function') {
            const dispose = jobs[method](() => gate.notify(method === 'onJobDone' ? 'job-done' : 'jobs-changed'))
            if (typeof dispose === 'function') disposers.push(dispose)
          }
        } catch (error) {
          console.error('research-os-goal-deferral: job observation failed: ' + error)
        }
      }
      return () => {
        for (const dispose of disposers) {
          try {
            dispose()
          } catch (error) {
            console.error('research-os-goal-deferral: job observer dispose failed: ' + error)
          }
        }
      }
    },
    /** Subscribe to continuable-child lifecycle edges; every edge re-reads. */
    observeChildren(ctx) {
      const disposers = []
      for (const event of ['subagent/start', 'subagent/end']) {
        try {
          if (ctx && typeof ctx.on === 'function') {
            const dispose = ctx.on(event, () => gate.notify(event))
            if (typeof dispose === 'function') disposers.push(dispose)
          }
        } catch (error) {
          console.error('research-os-goal-deferral: child observation failed: ' + error)
        }
      }
      return () => {
        for (const dispose of disposers) {
          try {
            dispose()
          } catch (error) {
            console.error('research-os-goal-deferral: child observer dispose failed: ' + error)
          }
        }
      }
    },
    /** Monotonic guard predicate: deny DSH goal mutation while the lease holds.
     *  Returns `undefined` (the guard idiom) when the call may proceed. */
    vetoReason(exec) {
      const tool = exec && exec.name
      if (!GOAL_MUTATING_TOOLS.includes(String(tool))) return undefined
      let verdict
      try {
        verdict = snapshot(exec)
      } catch (error) {
        return 'research-os-goal-deferral: goal mutation deferred — the lease verdict could not '
          + `be read (${error}) (failing closed)`
      }
      if (!verdict.blocked) return undefined
      const label = verdict.runId ?? runId ?? 'any run'
      return `research-os-goal-deferral: goal mutation deferred — ${verdict.state} (${label}): `
        + verdict.reason
    },
  }
  return gate
}

/**
 * DSH plugin entry: install the veto through the host's own seams.
 *
 * Registers a monotonic `tools.guard` (goal mutation only), subscribes to job and
 * child lifecycle edges, and returns the gate for callers that want `blockedReason()`.
 * Internal errors fail open (the host stays usable); the veto itself fails closed.
 */
export function apply(ctx, options = {}) {
  try {
    const tools = ctx && typeof ctx.get === 'function' ? ctx.get('tools') : undefined
    if (tools === undefined || typeof tools.guard !== 'function') {
      console.error('research-os-goal-deferral: ctx.tools unavailable — no veto installed')
      return null
    }
    const root = options.root || process.env.RESEARCH_OS_LEASE_ROOT || null
    const runId = options.runId || process.env.RESEARCH_OS_LEASE_RUN || null
    const gate = createGoalDeferral({ ...options, root, runId })
    const jobs = typeof ctx.get === 'function' ? ctx.get('jobs') : undefined
    if (jobs) gate.observeJobs(jobs)
    gate.observeChildren(ctx)
    tools.guard((exec) => {
      try {
        return gate.vetoReason(exec)
      } catch (error) {
        return 'research-os-goal-deferral: goal mutation deferred — veto evaluation failed '
          + `(${error}) (failing closed)`
      }
    })
    console.error('research-os-goal-deferral: active (veto-only; it never pauses/resumes goals '
      + 'and never emits continuations)')
    return gate
  } catch (error) {
    console.error('research-os-goal-deferral: apply failed: ' + error)
    return null
  }
}
