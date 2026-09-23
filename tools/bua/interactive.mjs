#!/usr/bin/env node
/**
 * Research OS — BUA interactive task-script runner (the write-capable arm).
 *
 * Documented precondition (INTERACTIVE-GUARDS.md §4): this script is NOT wired into the
 * executor. The read-only runner (`tools/bua/run.mjs`) stays the default arm; this script
 * exists beside it and refuses to run unless its precondition verifies:
 *
 *   1. the entry URL passes `researchctl scope-check` (exit 4 when denied);
 *   2. `--profile` is given explicitly and stays inside the workspace — there is no lab
 *      default on this arm — and it equals the engagement identity binding's
 *      `session.browser_profile` when that is declared (B4);
 *   3. `--action A-…` names a prepared, unconsumed, unexpired browser preflight token
 *      whose `argument_digest` matches the canonical `{url, principal}` shape; the entry
 *      navigation consumes it exactly once (no token, no dispatch, exit 5);
 *   4. `--preflight <file>` carries the engagement-level preflight fields every
 *      runner-initiated action must repeat (`researchctl prepare` refuses without them).
 *
 * The loop (model proposes, executor disposes):
 *   executor snapshot (indexed opaque handles) -> ONE Jev fan-out call
 *   (`researchctl bua-plan`: operation Choice + per-operation target Choice, every answer
 *   through `validate_choice`) -> typed operation over executor-issued handles ->
 *   per-dispatch re-checks (scope, single-use preflight token, human gate for
 *   consequential actions, node identity: freshness/occlusion/geometry) -> dispatch ->
 *   per-action evidence capture registered via `researchctl evidence register` ->
 *   ACTION_RECORDED carrying the consumed token's nonce.
 *
 *   - DONE is never independent evidence: the state is re-read by a fresh observation and
 *     the capture is registered before the run reports `confirmed`;
 *   - BLOCKED records the failing guard and is never retried blindly past the caps
 *     (`MAX_STEPS`, `GUARD_RETRY_CAP`, `REPLAN_CAP`);
 *   - the per-request route/WebSocket scope handlers, the service-worker block and the
 *     CDP worker-socket observation of `run.mjs` are installed for the whole run, so
 *     page-initiated traffic stays inside the same scope guard;
 *   - redirect hops are recorded AND block writes: after a followed out-of-scope hop the
 *     session is tainted (`scope_violation`) and no further write dispatches (the read
 *     path keeps the documented §5 behavior — hops recorded, capture skipped);
 *   - no downloads (`acceptDownloads: false`), no `page.evaluate`, no model-supplied
 *     selectors/coordinates/shell/JavaScript (rejected at the typed-operation boundary),
 *     uploads only from workspace-contained files, login secrets env-only and masked.
 *
 * Exit codes: 0 ran; 2 usage/root/config problem; 3 browser not provisioned or a scope
 *   guard could not be installed; 4 scope denied; 5 authorization refused (token, gate or
 *   identity binding).
 *
 * Usage:
 *   node tools/bua/interactive.mjs --url <entry> --principal <label> --action A-… \
 *        --profile <workspace dir> --preflight <workspace json> \
 *        [--out-dir 08_artifacts/raw] [--steps 12]
 */
import { execFileSync } from 'node:child_process'
import { mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { join, resolve, sep } from 'node:path'
import { pathToFileURL } from 'node:url'
import {
  authorityAmbiguous, decideRequest, findOsRoot, hasSecretShape, hostKey, insideRoot,
  makeHopCollector, makeScopeCache, makeServiceWorkerHandler, makeWebSocketHandler, maskText,
  maskUrlSecrets, observeWorkerWebSocket, serviceWorkerInitScript, scopeCheckVerdict,
} from './run.mjs'

// ---- named caps (the step/model budgets an interactive run may never exceed) --------
export const DEFAULT_MAX_STEPS = 12
export const MAX_STEPS_CAP = 50
export const GUARD_RETRY_CAP = 2
export const REPLAN_CAP = 2
export const TYPE_TEXT_MAX = 2000
export const OPTION_MAX = 200
export const URL_MAX = 2048
export const ACTION_TIMEOUT_MS = 15000
export const GEOMETRY_TOLERANCE = 8
export const MAX_SNAPSHOT_ENTRIES = 80
export const HISTORY_CAP = 20
export const BLOCKED_ACTIONS_CAP = 50
export const HANDLE_RE = /^e[1-9][0-9]{0,4}$/
export const OPERATIONS = ['CLICK', 'TYPE', 'SELECT', 'NAVIGATE', 'UPLOAD', 'LOGIN', 'DONE', 'BLOCKED']
export const CONTROL_CHARS = /[\x00-\x1f\x7f]/
/** The executor-owned vocabulary for a model-declared BLOCKED (never model prose). */
export const BLOCK_REASONS = new Map([
  ['b1', 'human_required'],
  ['b2', 'no_progress'],
  ['b3', 'unsafe_target'],
  ['b4', 'not_applicable'],
])
export const PREFLIGHT_FIELDS = [
  'cycle_id', 'target', 'account', 'object_owner', 'purpose', 'hypothesis',
  'expected_secure', 'expected_vulnerable', 'side_effect', 'stop_condition',
]

// A target whose own executor-read metadata says "this changes the world" is
// consequential: the model never gets to argue about the classification, and the class
// list is the spec's (submit, purchase, delete, credential use, external contact).
const CONSEQUENTIAL_PATTERN =
  /\b(submit|delete|remove|destroy|purchase|buy|pay|payment|checkout|transfer|confirm|authorize|approve|unsubscribe|deactivate|revoke|sign[-_ ]?out|log[-_ ]?out|contact)\b/i

/** Refusals carry their exit code; `main()` is the only place that exits. */
export class Refusal extends Error {
  constructor(code, message) {
    super(message)
    this.code = code
  }
}

// ===================================================================================
// 1. The typed-operation boundary (model output never becomes selectors, coordinates,
//    shell or JavaScript: a closed schema over executor-issued opaque handles)
// ===================================================================================
const FORBIDDEN_KEYS = new Map([
  ['selector', 'model output carried a CSS/XPath selector'],
  ['css', 'model output carried a CSS/XPath selector'],
  ['xpath', 'model output carried a CSS/XPath selector'],
  ['x', 'model output carried coordinates'],
  ['y', 'model output carried coordinates'],
  ['coords', 'model output carried coordinates'],
  ['coordinates', 'model output carried coordinates'],
  ['position', 'model output carried coordinates'],
  ['script', 'model output carried JavaScript'],
  ['js', 'model output carried JavaScript'],
  ['javascript', 'model output carried JavaScript'],
  ['code', 'model output carried JavaScript'],
  ['evaluate', 'model output carried JavaScript'],
  ['expression', 'model output carried JavaScript'],
  ['command', 'model output carried a shell command'],
  ['shell', 'model output carried a shell command'],
  ['cmd', 'model output carried a shell command'],
  ['argv', 'model output carried a shell command'],
])
const ALLOWED_KEYS = {
  CLICK: ['op', 'handle'],
  TYPE: ['op', 'handle', 'text'],
  SELECT: ['op', 'handle', 'option'],
  NAVIGATE: ['op', 'url'],
  UPLOAD: ['op', 'file'],
  LOGIN: ['op', 'flow'],
  DONE: ['op'],
  BLOCKED: ['op', 'reason'],
}

function checkNavigationUrl(url) {
  if (typeof url !== 'string' || !url.trim()) {
    return { ok: false, kind: 'boundary', reason: 'NAVIGATE requires a url string' }
  }
  const raw = url.trim()
  if (raw.length > URL_MAX) {
    return { ok: false, kind: 'boundary', reason: `url is longer than ${URL_MAX} chars` }
  }
  if (CONTROL_CHARS.test(raw)) {
    return { ok: false, kind: 'boundary', reason: 'url carries control characters' }
  }
  let parsed
  try { parsed = new URL(raw) } catch {
    return { ok: false, kind: 'boundary', reason: 'url is not parseable' }
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { ok: false, kind: 'boundary', reason: `scheme ${parsed.protocol} is not an http(s) navigation` }
  }
  if (!parsed.hostname) return { ok: false, kind: 'boundary', reason: 'url has no host' }
  if (parsed.username || parsed.password) {
    return { ok: false, kind: 'boundary', reason: 'url carries userinfo — credentials never ride a URL' }
  }
  if (authorityAmbiguous(raw)) {
    return { ok: false, kind: 'boundary', reason: 'url authority is ambiguous' }
  }
  return { ok: true, url: raw }
}

/** One typed operation, or the reason it is not one. The boundary the model cannot cross:
 *  a handle must be an executor-issued `e<N>`, a URL must be http(s) without userinfo, an
 *  option must be one the target itself offered, and a credential field is never a TYPE
 *  target (credentials are env-only and enter through LOGIN). */
export function parseOperation(raw, boundary) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, kind: 'boundary',
             reason: 'model operation is not a typed object (only CLICK/TYPE/SELECT/NAVIGATE/UPLOAD/LOGIN/DONE/BLOCKED are accepted)' }
  }
  const op = raw.op
  if (typeof op !== 'string' || !OPERATIONS.includes(op)) {
    return { ok: false, kind: 'boundary',
             reason: `unknown operation ${JSON.stringify(op)} — the model proposes a typed operation only` }
  }
  for (const key of Object.keys(raw)) {
    const forbidden = FORBIDDEN_KEYS.get(String(key).toLowerCase())
    if (forbidden) {
      return { ok: false, kind: 'boundary',
               reason: forbidden + ' — only typed operations over executor-issued handles are accepted' }
    }
    if (!ALLOWED_KEYS[op].includes(key)) {
      return { ok: false, kind: 'boundary', reason: `operation ${op} carries an unexpected key ${JSON.stringify(key)}` }
    }
  }
  const handleOp = () => {
    const handle = raw.handle
    if (typeof handle !== 'string' || !HANDLE_RE.test(handle)) {
      return { ok: false, kind: 'boundary',
               reason: `handle ${JSON.stringify(handle)} is not an executor-issued opaque handle (e1, e2, …)` }
    }
    const entry = boundary && boundary.index ? boundary.index.get(handle) : null
    if (!entry) {
      return { ok: false, kind: 'boundary',
               reason: `handle ${handle} is not in the executor snapshot — re-snapshot and re-plan, never dispatch on a stale handle` }
    }
    return { ok: true, entry }
  }
  switch (op) {
    case 'DONE':
      return { ok: true, op: { op: 'DONE' } }
    case 'BLOCKED': {
      const reason = raw.reason
      if (typeof reason !== 'string' || !reason.trim() || reason.length > 300 || CONTROL_CHARS.test(reason)) {
        return { ok: false, kind: 'boundary', reason: 'BLOCKED requires a bounded reason string (1..300 chars, no control characters)' }
      }
      return { ok: true, op: { op: 'BLOCKED', reason: reason.trim() } }
    }
    case 'CLICK': {
      const h = handleOp()
      return h.ok ? { ok: true, op: { op: 'CLICK', handle: raw.handle } } : h
    }
    case 'TYPE': {
      const h = handleOp()
      if (!h.ok) return h
      const text = raw.text
      if (typeof text !== 'string' || text.length === 0 || text.length > TYPE_TEXT_MAX || CONTROL_CHARS.test(text)) {
        return { ok: false, kind: 'boundary',
                 reason: `TYPE text must be a plain string of 1..${TYPE_TEXT_MAX} chars without control characters` }
      }
      if (String(h.entry.type || '').toLowerCase() === 'password') {
        return { ok: false, kind: 'boundary',
                 reason: 'TYPE never targets a credential field — credentials are env-only and enter through LOGIN' }
      }
      if (hasSecretShape(text)) {
        return { ok: false, kind: 'boundary',
                 reason: 'TYPE text carries a credential-shaped value — credentials are env-only ' +
                   'and enter through LOGIN, never as a model-chosen text payload' }
      }
      return { ok: true, op: { op: 'TYPE', handle: raw.handle, text } }
    }
    case 'SELECT': {
      const h = handleOp()
      if (!h.ok) return h
      const option = raw.option
      if (typeof option !== 'string' || !option || option.length > OPTION_MAX || CONTROL_CHARS.test(option)) {
        return { ok: false, kind: 'boundary', reason: `SELECT requires an option string of 1..${OPTION_MAX} chars` }
      }
      const offered = Array.isArray(h.entry.options) ? h.entry.options : []
      if (!offered.includes(option)) {
        return { ok: false, kind: 'boundary',
                 reason: `option ${JSON.stringify(option)} is not offered by ${raw.handle} — the executor reads the options, the model picks one` }
      }
      return { ok: true, op: { op: 'SELECT', handle: raw.handle, option } }
    }
    case 'NAVIGATE': {
      const checked = checkNavigationUrl(raw.url)
      return checked.ok ? { ok: true, op: { op: 'NAVIGATE', url: checked.url } } : checked
    }
    case 'UPLOAD': {
      const file = raw.file
      if (typeof file !== 'string' || !file) {
        return { ok: false, kind: 'boundary', reason: 'UPLOAD requires a workspace file path' }
      }
      const offered = boundary && boundary.uploads ? [...boundary.uploads.values()] : []
      if (!offered.includes(file)) {
        return { ok: false, kind: 'boundary',
                 reason: `upload file ${JSON.stringify(file)} is not one of the executor-offered workspace files` }
      }
      return { ok: true, op: { op: 'UPLOAD', file } }
    }
    case 'LOGIN': {
      const flow = raw.flow
      const offered = boundary && boundary.flows ? [...boundary.flows.values()] : []
      if (typeof flow !== 'string' || !offered.includes(flow)) {
        return { ok: false, kind: 'boundary', reason: `login flow ${JSON.stringify(flow)} is not configured for this run` }
      }
      return { ok: true, op: { op: 'LOGIN', flow } }
    }
    default:
      return { ok: false, kind: 'boundary', reason: `unhandled operation ${op}` }
  }
}

/** read / state-changing / consequential — the spec's three classes, decided in code from
 *  the executor's own snapshot metadata (never from model text). */
export function classifyAction(op, entry) {
  if (!op || typeof op !== 'object') return 'state-changing'
  if (op.op === 'NAVIGATE' || op.op === 'DONE' || op.op === 'BLOCKED') return 'read'
  if (op.op === 'LOGIN') return 'consequential' // credential use
  if (op.op === 'UPLOAD') return 'state-changing'
  const hay = [entry && entry.type, entry && entry.name, entry && entry.role,
               entry && entry.text, entry && entry.label]
    .filter((v) => typeof v === 'string').join(' ')
  if ((op.op === 'CLICK' || op.op === 'SELECT') && CONSEQUENTIAL_PATTERN.test(hay)) return 'consequential'
  return 'state-changing'
}

/** Uploads come from workspace-contained regular files only, resolved through symlinks
 *  (a symlink out of the workspace is refused, not followed), never from the 0600
 *  `lab/credentials/` tree (a credential must never egress to a target). */
export function resolveUploadPath(root, rel) {
  const raw = String(rel == null ? '' : rel)
  if (!raw.trim()) return { ok: false, reason: 'empty upload path' }
  if (CONTROL_CHARS.test(raw)) return { ok: false, reason: 'upload path carries control characters' }
  let rootReal
  try { rootReal = realpathSync(root) } catch { return { ok: false, reason: 'workspace root is not resolvable' } }
  const candidate = resolve(root, raw)
  let real
  try { real = realpathSync(candidate) } catch { return { ok: false, reason: `upload file is missing: ${raw}` } }
  if (real !== rootReal && !real.startsWith(rootReal + sep)) {
    return { ok: false, reason: `upload file must stay inside the workspace (got ${raw})` }
  }
  const creds = join(rootReal, 'lab', 'credentials')
  if (real === creds || real.startsWith(creds + sep)) {
    return { ok: false, reason: 'upload files must never come from lab/credentials (0600, never evidence, never egress)' }
  }
  let st
  try { st = statSync(real) } catch { return { ok: false, reason: `upload file is unreadable: ${raw}` } }
  if (!st.isFile()) return { ok: false, reason: `upload source is not a regular file: ${raw}` }
  return { ok: true, path: real }
}

/** The boundary context: the executor's snapshot index plus the executor-owned label
 *  spaces (text options, upload files, login flows, block reasons). Throws on a refused
 *  upload file or text value — a run with an unusable boundary must not start. */
export function buildBoundary({ root, entries = [], textValues = [], uploadFiles = [],
                                loginFlows = [], blockReasons = BLOCK_REASONS }) {
  const index = new Map()
  for (const e of Array.isArray(entries) ? entries : []) {
    if (e && typeof e.handle === 'string' && HANDLE_RE.test(e.handle) && !index.has(e.handle)) {
      index.set(e.handle, e)
    }
  }
  const texts = new Map()
  ;(Array.isArray(textValues) ? textValues : []).forEach((value, i) => {
    if (typeof value !== 'string' || value.length === 0 || value.length > TYPE_TEXT_MAX
        || CONTROL_CHARS.test(value)) {
      throw new Error(`text_values[${i}] must be a plain string of 1..${TYPE_TEXT_MAX} chars without control characters`)
    }
    texts.set(`t${i + 1}`, value)
  })
  const uploads = new Map()
  ;(Array.isArray(uploadFiles) ? uploadFiles : []).forEach((rel, i) => {
    const checked = resolveUploadPath(root, rel)
    if (!checked.ok) throw new Error(`upload_files[${i}]: ${checked.reason}`)
    uploads.set(`f${i + 1}`, checked.path)
  })
  const flows = new Map()
  ;(Array.isArray(loginFlows) ? loginFlows : []).forEach((flow, i) => {
    if (typeof flow !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,31}$/.test(flow)) {
      throw new Error(`login_flows[${i}] must be a lowercase flow name ([a-z0-9_-], ≤32 chars)`)
    }
    flows.set(`l${i + 1}`, flow)
  })
  return { root, index, texts, uploads, flows, blockReasons }
}

// ===================================================================================
// 2. Node-identity guards, re-checked at dispatch
// ===================================================================================
/** Freshness (the handle's snapshot generation must still be current), geometry (the
 *  bounding box must be visible, inside the viewport and unchanged beyond tolerance) and
 *  occlusion (the node must be the actual hit target — an overlay means blocked, never
 *  click-through). A failing guard returns a reason; it never dispatches. */
export async function guardDispatch(op, ctx) {
  if (!op || !op.handle) return { ok: true, targeted: false }
  const { generation, currentGeneration, entry, locator, viewport, tolerance = GEOMETRY_TOLERANCE } = ctx || {}
  if (generation !== currentGeneration) {
    return { ok: false, guard: 'freshness',
             reason: 'snapshot generation is stale — re-snapshot and re-plan (never dispatch on a stale handle)' }
  }
  if (!entry) {
    return { ok: false, guard: 'freshness',
             reason: `handle ${op.handle} is not in the live snapshot — re-snapshot and re-plan` }
  }
  if (!locator) {
    return { ok: false, guard: 'freshness', reason: `no live element for handle ${op.handle}` }
  }
  let box
  try { box = await locator.boundingBox() } catch (e) {
    return { ok: false, guard: 'geometry', reason: 'bounding box unavailable: ' + maskText(String(e.message || e)) }
  }
  if (!box) {
    return { ok: false, guard: 'geometry', reason: `handle ${op.handle} is not visible (no bounding box)` }
  }
  if (viewport && viewport.width && viewport.height) {
    const inside = box.x >= 0 && box.y >= 0
      && box.x + box.width <= viewport.width && box.y + box.height <= viewport.height
    if (!inside) {
      return { ok: false, guard: 'geometry',
               reason: `handle ${op.handle} is outside the viewport (box ${box.x},${box.y} ${box.width}x${box.height} ` +
                 `vs ${viewport.width}x${viewport.height}) — scrolling is not an authorized action` }
    }
  }
  const before = entry.box
  if (before && typeof before.x === 'number') {
    const moved = ['x', 'y', 'width', 'height']
      .some((k) => Math.abs(Number(box[k]) - Number(before[k])) > tolerance)
    if (moved) {
      return { ok: false, guard: 'geometry',
               reason: `handle ${op.handle} moved beyond tolerance ${tolerance}px since the snapshot ` +
                 `(was ${before.x},${before.y} ${before.width}x${before.height}; now ${box.x},${box.y} ${box.width}x${box.height})` }
    }
  }
  try {
    await locator.hitTargetCheck()
  } catch (e) {
    return { ok: false, guard: 'occlusion',
             reason: `handle ${op.handle} is covered by another element — blocked, never clicked through (` +
               maskText(String(e.message || e)) + ')' }
  }
  return { ok: true, box }
}

// ===================================================================================
// 3. The plan fan-out: executor-built Choice space, executor-side label resolution
// ===================================================================================
/** The executor-owned Choice space for one step: the model picks labels, never handles,
 *  URLs, selectors or text. `u0` is always the entry URL; `u1..un` are the links the
 *  executor extracted from the snapshot. */
export function planContext({ boundary, snapshot, entryUrl, step, history = [], cycleId = null }) {
  const entries = snapshot && Array.isArray(snapshot.entries) ? snapshot.entries : []
  const targets = { CLICK: new Map(), TYPE: new Map(), SELECT: new Map(), NAVIGATE: new Map() }
  if (entryUrl) targets.NAVIGATE.set('u0', { url: entryUrl })
  for (const e of entries) {
    if (!e || typeof e.handle !== 'string' || !HANDLE_RE.test(e.handle)) continue
    const ops = Array.isArray(e.ops) ? e.ops : []
    if (ops.includes('CLICK')) targets.CLICK.set(e.handle, { handle: e.handle })
    if (ops.includes('TYPE')) targets.TYPE.set(e.handle, { handle: e.handle })
    if (ops.includes('SELECT')) {
      for (const option of (Array.isArray(e.options) ? e.options : [])) {
        targets.SELECT.set(`${e.handle}=${option}`, { handle: e.handle, option })
      }
    }
    if (ops.includes('NAVIGATE') && typeof e.href === 'string' && e.href) {
      targets.NAVIGATE.set(`u${targets.NAVIGATE.size}`, { url: e.href })
    }
  }
  const questions = {}
  const opChoices = ['DONE', 'BLOCKED']
  if (targets.CLICK.size) opChoices.push('CLICK')
  if (targets.TYPE.size && boundary.texts.size) opChoices.push('TYPE')
  if (targets.SELECT.size) opChoices.push('SELECT')
  if (targets.NAVIGATE.size) opChoices.push('NAVIGATE')
  if (boundary.uploads.size) opChoices.push('UPLOAD')
  if (boundary.flows.size) opChoices.push('LOGIN')
  questions.bua_operation = {
    choices: opChoices,
    instructions: 'Which single next operation advances the objective? Pick DONE only when the ' +
      'objective is reached and the state can be verified by a fresh observation; pick BLOCKED when ' +
      'the run needs a human (OTP/MFA/CAPTCHA, credentials, ambiguous authorization).',
  }
  const add = (name, map, instructions) => {
    if (map.size) questions[name] = { choices: [...map.keys()], instructions }
  }
  add('bua_target:CLICK', targets.CLICK, 'Which element should be clicked?')
  add('bua_target:TYPE', targets.TYPE, 'Which field should receive text?')
  add('bua_target:SELECT', targets.SELECT, 'Which select element and option value?')
  add('bua_target:NAVIGATE', targets.NAVIGATE, 'Which URL should be navigated to (read path)?')
  add('bua_text', boundary.texts, 'Which configured text value should be typed?')
  add('bua_file', boundary.uploads, 'Which workspace file should be uploaded?')
  add('bua_flow', boundary.flows, 'Which configured login flow should run?')
  add('bua_block', boundary.blockReasons, 'Why is the run blocked?')
  const elements = entries.map((e) => ({
    handle: e.handle,
    tag: e.tag, type: e.type, name: e.name, role: e.role,
    text: maskText(String(e.text || '')).slice(0, 120),
    ops: e.ops, options: (e.options || []).slice(0, 10), form_index: e.form_index,
  }))
  return {
    targets, texts: boundary.texts, files: boundary.uploads, flows: boundary.flows,
    reasons: boundary.blockReasons,
    request: {
      step, cycle_id: cycleId,
      state: {
        url: maskUrlSecrets(String((snapshot && snapshot.url) || '')),
        title: maskText(String((snapshot && snapshot.title) || '')).slice(0, 200),
        step, history: history.slice(-HISTORY_CAP), elements,
      },
      questions,
    },
  }
}

/** Resolve the plan's executor-side labels into a typed operation. Labels the executor
 *  did not offer are refused — the model cannot name an element the executor never showed
 *  it, and it never supplies a selector, coordinate, URL or text value. */
export function resolveOperation(operation, ctx) {
  if (!operation || typeof operation !== 'object' || Array.isArray(operation)) {
    return { ok: false, reason: 'plan carried no typed operation' }
  }
  const op = String(operation.op || '')
  if (!OPERATIONS.includes(op)) {
    return { ok: false, reason: `plan proposed an unknown operation ${JSON.stringify(operation.op)}` }
  }
  const labels = operation.labels && typeof operation.labels === 'object' ? operation.labels : {}
  const take = (map, label, what) => {
    const key = String(label == null ? '' : label)
    if (!map.has(key)) {
      return { ok: false, reason: `${what} label ${JSON.stringify(key)} is not one the executor offered` }
    }
    return { ok: true, value: map.get(key) }
  }
  switch (op) {
    case 'DONE':
      return { ok: true, op: { op: 'DONE' } }
    case 'BLOCKED': {
      const r = take(ctx.reasons, labels.reason, 'block reason')
      return r.ok ? { ok: true, op: { op: 'BLOCKED', reason: r.value } } : r
    }
    case 'CLICK': {
      const t = take(ctx.targets.CLICK, labels.target, 'target')
      return t.ok ? { ok: true, op: { op: 'CLICK', handle: t.value.handle } } : t
    }
    case 'TYPE': {
      const t = take(ctx.targets.TYPE, labels.target, 'target')
      if (!t.ok) return t
      const x = take(ctx.texts, labels.text, 'text option')
      return x.ok ? { ok: true, op: { op: 'TYPE', handle: t.value.handle, text: x.value } } : x
    }
    case 'SELECT': {
      const t = take(ctx.targets.SELECT, labels.target, 'target')
      return t.ok ? { ok: true, op: { op: 'SELECT', handle: t.value.handle, option: t.value.option } } : t
    }
    case 'NAVIGATE': {
      const t = take(ctx.targets.NAVIGATE, labels.target, 'target')
      return t.ok ? { ok: true, op: { op: 'NAVIGATE', url: t.value.url } } : t
    }
    case 'UPLOAD': {
      const f = take(ctx.files, labels.file, 'upload file')
      return f.ok ? { ok: true, op: { op: 'UPLOAD', file: f.value } } : f
    }
    case 'LOGIN': {
      const f = take(ctx.flows, labels.flow, 'login flow')
      return f.ok ? { ok: true, op: { op: 'LOGIN', flow: f.value } } : f
    }
    default:
      return { ok: false, reason: `unhandled operation ${op}` }
  }
}

// ===================================================================================
// 4. The loop (mocked-snapshot testable; the browser lives in the deps)
// ===================================================================================
/** One interactive run: snapshot -> plan -> per-dispatch re-checks -> dispatch ->
 *  capture/receipt, with DONE requiring a fresh verification and BLOCKED a first-class
 *  outcome. Every deps entry is injectable so the loop is tested without a browser. */
export async function runLoop(deps) {
  const requested = Number.isInteger(deps.maxSteps) && deps.maxSteps > 0 ? deps.maxSteps : DEFAULT_MAX_STEPS
  const maxSteps = Math.min(requested, MAX_STEPS_CAP)
  const events = []
  const history = []
  const guardFails = new Map()
  const summary = {
    status: 'running', blocked_reason: null, steps: 0, events, history,
    confirmed_evidence: null, confirmed_capture: null,
    action_classes: { read: 0, 'state-changing': 0, consequential: 0 },
  }
  let replans = 0

  const emit = (event) => {
    events.push(event)
    if (deps.onEvent) deps.onEvent(event)
  }
  const blocked = (reason, extra = {}) => {
    summary.status = 'blocked'
    summary.blocked_reason = reason
    emit({ step: summary.steps, status: 'blocked', reason, ...extra })
  }
  const guardFail = (guard, reason, extra = {}) => {
    const n = (guardFails.get(guard) || 0) + 1
    guardFails.set(guard, n)
    emit({ step: summary.steps, status: 'blocked', guard, reason, ...extra })
    if (n >= GUARD_RETRY_CAP) {
      summary.status = 'blocked'
      summary.blocked_reason = `guard_repeat_cap_reached: ${guard} failed ${n}x — ${reason}`
      return true
    }
    return false
  }

  for (let step = 1; step <= maxSteps; step++) {
    summary.steps = step
    const snapshot = await deps.snapshot({ step, history })
    const planned = await deps.plan({ step, snapshot, history })
    if (!planned || planned.ok !== true) {
      const source = (planned && planned.source) || 'unavailable'
      const reason = (planned && planned.reason) || source
      if (source === 'invalid_choice' && replans < REPLAN_CAP) {
        replans += 1
        emit({ step, status: 'replan', source, reason })
        continue
      }
      blocked(source === 'invalid_choice' ? `replan_cap_reached: ${reason}` : `${source}: ${reason}`,
              { source })
      break
    }
    const boundary = planned.boundary
      || (typeof deps.boundary === 'function' ? deps.boundary({ snapshot }) : deps.boundary)
    const parsed = parseOperation(planned.operation, boundary)
    if (!parsed.ok) {
      if (guardFail('boundary', parsed.reason)) break
      continue
    }
    const op = parsed.op
    const entry = op.handle && boundary && boundary.index ? boundary.index.get(op.handle) : null
    const actionClass = classifyAction(op, entry)
    summary.action_classes[actionClass] = (summary.action_classes[actionClass] || 0) + 1

    if (op.op === 'DONE') {
      const verified = await deps.verify({ snapshot, step, history })
      if (verified && verified.ok === true) {
        summary.status = 'confirmed'
        summary.confirmed_evidence = verified.evidence || null
        summary.confirmed_capture = verified.capture || null
        emit({ step, op: 'DONE', status: 'confirmed', evidence: summary.confirmed_evidence })
      } else {
        blocked('done_without_verification: ' + String((verified && verified.reason) || 'fresh observation failed'),
                { op: 'DONE' })
      }
      break
    }
    if (op.op === 'BLOCKED') {
      blocked(`model_blocked: ${op.reason}`, { op: 'BLOCKED' })
      break
    }

    const scope = await deps.scopeRecheck({ op, entry, snapshot, step, actionClass })
    if (!scope || scope.ok !== true) {
      if (guardFail('scope', String((scope && scope.reason) || 'out-of-scope dispatch'), { op: op.op })) break
      continue
    }
    const authorized = await deps.authorize({ op, entry, snapshot, step, actionClass })
    if (!authorized || authorized.ok !== true) {
      if (guardFail('authorization', String((authorized && authorized.reason) || 'no preflight token'),
                    { op: op.op })) break
      continue
    }
    const token = authorized.token || {}
    if (actionClass === 'consequential') {
      const gate = await deps.gate({ op, entry, actionId: token.action_id, token, step })
      if (!gate || gate.ok !== true) {
        if (guardFail('human_gate', String((gate && gate.reason) || 'no resolved human gate'),
                      { op: op.op, action_id: token.action_id })) break
        continue
      }
    }
    const guarded = await deps.guard({ op, entry, snapshot, boundary, step })
    if (!guarded || guarded.ok !== true) {
      if (guardFail(String((guarded && guarded.guard) || 'freshness'),
                    String((guarded && guarded.reason) || 'dispatch guard failed'),
                    { op: op.op, action_id: token.action_id })) break
      continue
    }
    const dispatched = await deps.dispatch({ op, locator: guarded.locator, entry, snapshot, token, step })
    if (!dispatched || dispatched.ok !== true) {
      if (guardFail('dispatch', String((dispatched && dispatched.reason) || 'dispatch failed'),
                    { op: op.op, action_id: token.action_id })) break
      continue
    }
    const captured = await deps.capture({ op, entry, result: dispatched, snapshot, token, step, actionClass })
    if (!captured || captured.ok !== true) {
      blocked(`receipt_failed: ${String((captured && captured.reason) || 'capture could not be registered')} ` +
        '— the action WAS executed; treat it as unproven', { op: op.op, action_id: token.action_id })
      break
    }
    const receipt = await deps.record({ op, entry, result: dispatched, capture: captured, token, step, actionClass })
    if (!receipt || receipt.ok !== true) {
      blocked(`receipt_failed: ${String((receipt && receipt.reason) || 'ACTION_RECORDED failed')} ` +
        '— the action WAS executed; treat it as unproven', { op: op.op, action_id: token.action_id })
      break
    }
    const row = {
      step, op: op.op, handle: op.handle || null, action_id: receipt.id || token.action_id,
      action_class: actionClass, status: 'recorded', evidence: captured.evidence || null,
      gate: actionClass === 'consequential' ? 'resolved' : null,
    }
    history.push(row)
    if (history.length > HISTORY_CAP) history.shift()
    emit(row)
  }
  if (summary.status === 'running') blocked('step_cap_reached')
  return summary
}

// ===================================================================================
// 5. Runtime: the browser side of the loop (snapshot, dispatch, capture, receipts)
// ===================================================================================
const SNAPSHOT_BUCKETS = [['a', 'a'], ['button', 'button'], ['input', 'input'],
                          ['select', 'select'], ['textarea', 'textarea']]

/** Indexed, executor-produced snapshot. Everything the model sees is read through
 *  Playwright locators — there is no `page.evaluate` anywhere in this file. Element text
 *  is masked and bounded before it can reach the model or a capture. */
export async function snapshotPage(page, generation) {
  const entries = []
  const locators = new Map()
  const formBoxes = []
  let index = 0
  const push = async (loc, tag, formIndex) => {
    if (index >= MAX_SNAPSHOT_ENTRIES) return
    let box = null
    try { box = await loc.boundingBox() } catch { box = null }
    if (!box) return
    index += 1
    const handle = `e${index}`
    const attr = async (name) => { try { return await loc.getAttribute(name) } catch { return null } }
    const type = String((await attr('type')) || '').toLowerCase()
    const name = String((await attr('name')) || '').slice(0, 80)
    const role = String((await attr('role')) || '').slice(0, 40)
    let text = ''
    try { text = maskText(String(await loc.innerText())).slice(0, 120) } catch { text = '' }
    const href = tag === 'a' ? await attr('href') : null
    const options = []
    if (tag === 'select') {
      try {
        for (const opt of (await loc.locator('option').all()).slice(0, 20)) {
          const value = await opt.getAttribute('value')
          options.push(String(value == null ? '' : value).slice(0, OPTION_MAX))
        }
      } catch { /* options unreadable: the select offers nothing */ }
    }
    const ops = []
    if (tag === 'a' || tag === 'button' || tag === 'input') ops.push('CLICK')
    if (tag === 'a' && href) ops.push('NAVIGATE')
    if ((tag === 'input' && ['text', 'search', 'email', 'url', 'tel', 'number'].includes(type))
        || tag === 'textarea') ops.push('TYPE')
    if (tag === 'input' && type === 'password') ops.push('LOGIN')
    if (tag === 'select') ops.push('SELECT')
    if (!ops.length) return
    entries.push({
      handle, tag, type, name, role, text, ops, options,
      href: href ? maskUrlSecrets(href) : null, box, form_index: formIndex,
    })
    locators.set(handle, loc)
  }
  // Form-scoped first so a login flow can resolve the fields of one form (username /
  // password / submit) without any DOM traversal.
  let forms = []
  try { forms = await page.locator('form').all() } catch { forms = [] }
  for (let fi = 0; fi < forms.length; fi++) {
    let box = null
    try { box = await forms[fi].boundingBox() } catch { box = null }
    if (box) formBoxes.push(box)
    for (const [sel, tag] of SNAPSHOT_BUCKETS) {
      let all = []
      try { all = await forms[fi].locator(sel).all() } catch { all = [] }
      for (const loc of all) await push(loc, tag, fi)
    }
  }
  // ponytail: page-level controls inside a form box are skipped by geometry (they were
  // already captured form-scoped); upgrade to DOM ancestry if a JS-free API appears.
  const insideForm = (box) => formBoxes.some((f) => box.x >= f.x - 2 && box.y >= f.y - 2
    && box.x + box.width <= f.x + f.width + 2 && box.y + box.height <= f.y + f.height + 2)
  for (const [sel, tag] of SNAPSHOT_BUCKETS) {
    let all = []
    try { all = await page.locator(sel).all() } catch { all = [] }
    for (const loc of all) {
      let box = null
      try { box = await loc.boundingBox() } catch { box = null }
      if (box && formBoxes.length && insideForm(box)) continue
      await push(loc, tag, null)
    }
  }
  let title = ''
  try { title = await page.title() } catch { title = '' }
  return { generation, entries, locators, url: page.url(), title }
}

/** The login flow's fields, resolved from the executor snapshot: the password field the
 *  snapshot tagged, the nearest preceding text field of the same form and the next
 *  submit control of the same form. Pure, so the rule is tested without a browser. */
export function resolveLoginTargets(entries) {
  const list = Array.isArray(entries) ? entries : []
  const pi = list.findIndex((e) => e && Array.isArray(e.ops) && e.ops.includes('LOGIN'))
  if (pi < 0) return { ok: false, reason: 'no password field in the snapshot — the login wall is not reachable' }
  const password = list[pi]
  const sameForm = (e) => e && e.form_index === password.form_index
  let user = null
  for (let k = pi - 1; k >= 0; k--) {
    if (sameForm(list[k]) && (list[k].ops || []).includes('TYPE')) { user = list[k]; break }
  }
  let submit = null
  for (let k = pi + 1; k < list.length; k++) {
    if (sameForm(list[k]) && (list[k].ops || []).includes('CLICK')) { submit = list[k]; break }
  }
  if (!user) return { ok: false, reason: "no username field found in the password field's form" }
  if (!submit) return { ok: false, reason: "no submit control found in the password field's form" }
  return { ok: true, user: user.handle, password: password.handle, submit: submit.handle }
}

function scrubValues(text, secrets) {
  let out = maskText(String(text == null ? '' : text))
  for (const value of secrets) {
    if (value) out = out.split(value).join('[REDACTED]')
  }
  return out
}

/** DONE verification: a FRESH observation (new snapshot generation) plus a registered
 *  capture — a completed write is never reported confirmed without both. */
export async function verifyDone({ freshSnapshot, capture }) {
  const fresh = await freshSnapshot()
  if (!fresh || !Array.isArray(fresh.entries)) {
    return { ok: false, reason: 'fresh observation failed (no snapshot)' }
  }
  const captured = await capture({ snapshot: fresh, op: { op: 'DONE' }, actionClass: 'read' })
  if (!captured || captured.ok !== true) {
    return { ok: false, reason: 'verification capture could not be registered: ' +
      String((captured && captured.reason) || 'unknown') }
  }
  return {
    ok: true, evidence: captured.evidence || null, capture: captured.artifact || null,
    state: {
      url: maskUrlSecrets(String(fresh.url || '')),
      title: maskText(String(fresh.title || '')).slice(0, 200),
      entries: fresh.entries.length,
    },
  }
}

/** One typed dispatch. Playwright performs its own actionability checks (including the
 *  hit-target check) and this file never passes `force`, so an occluded node fails here
 *  too; the guard's trial check is the explicit pre-dispatch half. */
async function dispatchOp({ page, op, locator, entry, summary, collectHops, login, snapshot }) {
  try {
    switch (op.op) {
      case 'CLICK':
        await locator.click({ timeout: ACTION_TIMEOUT_MS })
        return { ok: true }
      case 'TYPE':
        await locator.fill(op.text, { timeout: ACTION_TIMEOUT_MS })
        return { ok: true }
      case 'SELECT':
        await locator.selectOption(op.option, { timeout: ACTION_TIMEOUT_MS })
        return { ok: true }
      case 'UPLOAD':
        await locator.setInputFiles(op.file, { timeout: ACTION_TIMEOUT_MS })
        return { ok: true }
      case 'NAVIGATE': {
        let resp = null
        let error = null
        try {
          resp = await page.goto(op.url, { waitUntil: 'domcontentloaded', timeout: 30000 })
        } catch (e) { error = maskText(String(e.message || e)) }
        const hops = await collectHops(resp)
        if (hops.length) {
          summary.scope_violation = true
          summary.screenshot = null
          return { ok: false,
                   reason: `navigation followed ${hops.length} out-of-scope redirect hop(s) — ` +
                     'recorded, and no further write dispatches on this session' }
        }
        if (error) return { ok: false, reason: error }
        return { ok: true, status: resp ? resp.status() : null, url: maskUrlSecrets(page.url()) }
      }
      case 'LOGIN':
        return await login({ snapshot })
      default:
        return { ok: false, reason: `unhandled operation ${op.op}` }
    }
  } catch (e) {
    return { ok: false, reason: scrubValues(String(e.message || e), []) }
  }
}

// ===================================================================================
// 6. CLI
// ===================================================================================
function usage(msg) {
  console.error('bua-interactive: ' + msg)
  console.error('usage: node tools/bua/interactive.mjs --url <entry> --principal <label> ' +
    '--action A-… --profile <workspace dir> --preflight <workspace json> ' +
    '[--out-dir 08_artifacts/raw] [--steps 12]')
  throw new Refusal(2, msg)
}

function parseArgs(argv) {
  const out = { 'out-dir': '08_artifacts/raw' }
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

export function loadPreflight(root, rel) {
  const abs = insideRoot(root, rel, '--preflight')
  let data = null
  try { data = JSON.parse(readFileSync(abs, 'utf8')) } catch (e) {
    throw new Refusal(2, '--preflight could not be read as JSON: ' + maskText(String(e.message || e)))
  }
  const missing = PREFLIGHT_FIELDS.filter((k) => !data || !String(data[k] || '').trim())
  if (missing.length) {
    throw new Refusal(2, '--preflight is missing: ' + missing.join(', ') +
      ' (every runner-initiated action repeats them through `researchctl prepare`)')
  }
  return data
}

function makeCtl(root, exec = execFileSync) {
  return (args) => {
    try {
      // Spawn with the workspace as cwd: every workspace-relative path the CLI takes
      // (shape json, plan request, evidence path, receipt json) resolves against the root,
      // exactly as `run.mjs` resolves its own out-dir.
      return JSON.parse(exec('python3', [join(root, 'tools', 'researchctl.py'), root, ...args],
        { encoding: 'utf8', timeout: 60000, cwd: root }))
    } catch (e) {
      let parsed = null
      try { parsed = JSON.parse(String(e.stdout || '')) } catch { /* not JSON */ }
      if (parsed && typeof parsed === 'object') return parsed
      // A refusal (`researchctl` prints `error: …` to stderr and exits 1) is an answer,
      // not a crash: return it so every caller refuses with the seam's own reason.
      const detail = String(e.stderr || '').split('\n')
        .filter((line) => line.trim()).slice(-1)[0] || String(e.message || e)
      return { ok: false, error: maskText(detail) }
    }
  }
}

/** Consume one prepared token through the CLI seam. The seam returns the token record
 *  (or `{ok: false, error}` on a refusal) — a record without an action id is a refusal. */
function consumeToken(ctl, actionId, shapeRel) {
  const res = ctl(['token-consume', actionId, shapeRel])
  if (!res || res.ok === false || !res.action_id) {
    return { ok: false, reason: String((res && (res.reason || res.error)) || 'unknown token') }
  }
  return { ok: true, token: res }
}

/** One interactive run with injected deps (the browser factory, the researchctl seam,
 *  the scope verdict, the entry token and every loop seam) so the CLI path is testable
 *  without a browser. */
export async function runInteractive({ root, args, chromium, ctl = makeCtl(root), scopeVerdict, token,
                                       plan, verify, snapshot, dispatch, capture, record, authorize,
                                       gate, guard, scopeRecheck, log = console.log }) {
  const outDirRel = args['out-dir']
  insideRoot(root, outDirRel, '--out-dir')
  insideRoot(root, args.profile, '--profile')
  const outDir = join(root, outDirRel)
  mkdirSync(outDir, { recursive: true })
  const preflight = loadPreflight(root, args.preflight)
  // The executor-owned label spaces are validated BEFORE the browser starts: a refused
  // upload file (traversal, symlink escape, lab/credentials), a malformed text value or a
  // bad flow name fails the run closed instead of surfacing mid-loop.
  buildBoundary({
    root, entries: [], textValues: preflight.text_values,
    uploadFiles: preflight.upload_files, loginFlows: preflight.login_flows,
  })
  const cycleId = String(preflight.cycle_id)
  const label = String(args.action || 'bua')
  const ts = new Date().toISOString().replace(/[:.]/g, '-')

  // 1. Scope guard in code — the same seam the read-only arm uses (exit 4 when denied).
  const scope = scopeVerdict ? scopeVerdict(args.url) : scopeCheckVerdict(args.url, root)
  if (!scope || scope.in_scope !== true) {
    throw new Refusal(4, (scope && scope.gate === 'unenforceable'
      ? 'the engagement asset list is not a simple host/URL list — scope is unenforceable'
      : `target '${(scope && scope.host) || args.url}' is outside the engagement scope`) +
      '. Fix 00_control/engagement.yaml from the authoritative program policy first.')
  }
  log(`bua-interactive: scope ok — gate=${scope.gate} host=${scope.host || '-'}`)

  // 2. Identity binding + the entry preflight token (single-use), both before the
  //    browser starts. A malformed binding fails closed; a declared profile must be the
  //    one this run uses; the token must be bound to that profile and to the bound
  //    account. There is no lab profile default on this arm.
  const binding = ctl(['identity-binding'])
  if (!binding || binding.ok === false || typeof binding.binding_present !== 'boolean') {
    throw new Refusal(5, 'the engagement identity binding could not be parsed (fail closed): ' +
      String((binding && (binding.error || binding.reason)) || 'unknown') +
      ' — repair 00_control/identity-binding.yaml before any interactive run')
  }
  const boundProfile = binding.binding_present === true ? binding.browser_profile : null
  if (boundProfile && String(args.profile) !== String(boundProfile)) {
    throw new Refusal(5, `--profile ${args.profile} does not match the engagement identity binding ` +
      `(${boundProfile} in 00_control/identity-binding.yaml) — the interactive arm never runs on an ` +
      'unbound profile')
  }
  let entryToken = token
  if (!entryToken) {
    const shape = { url: args.url, principal: args.principal }
    const shapeRel = join(outDirRel, `${label}-entry-shape.json`)
    writeFileSync(join(root, shapeRel), JSON.stringify(shape) + '\n')
    const consumed = consumeToken(ctl, args.action, shapeRel)
    if (!consumed.ok) {
      throw new Refusal(5, `entry preflight token ${args.action} was refused: ` +
        consumed.reason + ' — no token, no dispatch')
    }
    entryToken = consumed.token
  }
  if (!entryToken || !entryToken.action_id) {
    throw new Refusal(5, `entry preflight token ${args.action} could not be consumed — no token, no dispatch`)
  }
  if (entryToken.browser_profile && String(entryToken.browser_profile) !== String(args.profile)) {
    throw new Refusal(5, `the entry token is bound to browser profile ${entryToken.browser_profile}, ` +
      `not --profile ${args.profile} — prepare the action for the profile this run uses`)
  }
  if (binding.account_reference && entryToken.preflight && entryToken.preflight.account
      && String(entryToken.preflight.account) !== String(binding.account_reference)) {
    throw new Refusal(5, `the entry token's account (${entryToken.preflight.account}) does not match the ` +
      `workspace identity binding (${binding.account_reference}) — fail closed`)
  }

  // 3. Browser: workspace-local playwright-core, dedicated profile, downloads refused.
  let launch = chromium
  if (!launch) {
    try {
      const require = createRequire(join(root, 'package.json'))
      ;({ chromium: launch } = require('playwright-core'))
    } catch (e) {
      throw new Refusal(3, 'playwright-core is not provisioned in this workspace.\n' +
        '  provision: npm i -D playwright-core && npx playwright install chromium\n' +
        '  or set RESEARCH_OS_CHROME to a Chrome/Chromium executable. (' + maskText(String(e.message || e)) + ')')
    }
  }
  const profileDir = join(root, args.profile)
  mkdirSync(profileDir, { recursive: true })
  const summary = {
    url: maskUrlSecrets(args.url), principal: args.principal, action: args.action || null,
    profile: args.profile, started_at: new Date().toISOString(),
    status: null, blocked_reason: null, steps: 0, events: [], history: [],
    confirmed_evidence: null, confirmed_capture: null,
    action_classes: { read: 0, 'state-changing': 0, consequential: 0 },
    final_url: null, redirect_chain: [], out_of_scope_hops: [], out_of_scope_hop_count: 0,
    scope_violation: false, blocked_requests: [], blocked_count: 0,
    blocked_actions: [], blocked_action_count: 0,
    service_worker_registrations_blocked: 0, service_worker_violations: 0,
    screenshot: null, evidence: [], error: null,
  }
  let context
  try {
    context = await launch.launchPersistentContext(profileDir, {
      headless: true,
      executablePath: process.env.RESEARCH_OS_CHROME || undefined,
      viewport: { width: 1440, height: 900 },
      acceptDownloads: false,
    })
  } catch (e) {
    throw new Refusal(3, 'browser launch failed — provision with `npx playwright install chromium` ' +
      'or set RESEARCH_OS_CHROME. (' + maskText(String(e.message || e)) + ')')
  }

  let page = null
  const scopeCache = makeScopeCache((url) => scopeCheckVerdict(url, root))
  scopeCache.seed(hostKey(args.url), { in_scope: true, gate: scope.gate })
  const tasks = { ws: [], hop: [], sw: [], worker: [] }
  const secrets = []
  const scrub = (text) => scrubValues(text, secrets)
  const fatal = async (message) => {
    console.error('bua-interactive: ' + message)
    try { await context.close() } catch { /* already closed */ }
    throw new Refusal(3, message)
  }
  try {
    page = context.pages()[0] || (await context.newPage())
  } catch (e) {
    await fatal('page creation failed. (' + maskText(String(e.message || e)) + ')')
  }
  const watchPageConsole = (watched) => {
    try {
      watched.on('console', (msg) => {
        try {
          if (String(msg.text()).includes('service worker registration blocked')) {
            summary.service_worker_registrations_blocked += 1
            log('bua-interactive: blocked service worker registration')
          }
        } catch { /* unparseable console text */ }
      })
    } catch { /* console watching unavailable */ }
  }
  try {
    for (const watched of context.pages()) watchPageConsole(watched)
    context.on('page', watchPageConsole)
  } catch { /* console watching unavailable */ }

  // The same guard set the read-only arm installs, before the first planned action.
  try {
    await context.route('**/*', async (route) => {
      const url = route.request().url()
      const decision = await decideRequest(url, scopeCache)
      if (decision.allow) return route.continue()
      summary.blocked_count += 1
      if (summary.blocked_requests.length < 50) {
        summary.blocked_requests.push({ host: decision.host, url_masked: maskUrlSecrets(url), reason: decision.reason })
      }
      log(`bua-interactive: blocked ${decision.reason} host=${decision.host || '-'}`)
      return route.abort('blockedbyclient')
    })
  } catch (e) {
    await fatal('request interception could not be installed — refusing to browse unscoped. (' +
      maskText(String(e.message || e)) + ')')
  }
  const handleServiceWorker = makeServiceWorkerHandler(summary, log)
  try {
    await context.addInitScript(serviceWorkerInitScript())
  } catch (e) {
    await fatal('service-worker block could not be installed — refusing to browse unscoped. (' +
      maskText(String(e.message || e)) + ')')
  }
  try {
    if (typeof context.serviceWorkers === 'function') {
      for (const worker of context.serviceWorkers()) tasks.sw.push(handleServiceWorker(worker))
    }
    context.on('serviceworker', (worker) => { tasks.sw.push(handleServiceWorker(worker)) })
  } catch (e) {
    log('bua-interactive: WARNING service-worker backstop unavailable: ' + maskText(String(e.message || e)))
  }
  if (typeof context.routeWebSocket === 'function') {
    const handleWebSocket = makeWebSocketHandler(summary, scopeCache, log)
    try {
      await context.routeWebSocket('**/*', (ws) => {
        const task = handleWebSocket(ws)
        tasks.ws.push(task)
        return task
      })
    } catch (e) {
      await fatal('websocket interception could not be installed — refusing to browse unscoped. (' +
        maskText(String(e.message || e)) + ')')
    }
  } else {
    await fatal('this playwright-core has no context.routeWebSocket — refusing to browse unscoped ' +
      '(a run without ws/wss interception would pass out-of-scope sockets silently); upgrade playwright-core')
  }
  const failWorkerScope = (note) => {
    summary.scope_violation = true
    log('bua-interactive: WARNING worker websocket interception degraded (' + note +
      ') — flagging a scope violation')
  }
  const noteWorkerSocket = (url) => {
    tasks.worker.push(observeWorkerWebSocket(summary, scopeCache, String(url || ''), log).catch((e) => {
      log('bua-interactive: WARNING worker-websocket scope check failed: ' + maskText(String(e.message || e)))
    }))
  }
  try {
    const cdp = await context.newCDPSession(page)
    let cdpMsgId = 0
    const pendingEnables = new Map()
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
      tasks.worker.push((async () => {
        try {
          if (!/worker/i.test(String((targetInfo || {}).type || ''))) return
          await toWorker(sessionId, 'Network.enable', {}, true)
        } catch (e) {
          failWorkerScope('Network.enable failed: ' + String(e.message || e))
        } finally {
          if (waitingForDebugger) {
            await toWorker(sessionId, 'Runtime.runIfWaitingForDebugger', {}).catch(() => {})
          }
        }
      })().catch((e) => { failWorkerScope(String(e.message || e)) }))
    })
    cdp.on('Target.receivedMessageFromTarget', ({ sessionId, message }) => {
      tasks.worker.push((async () => {
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
        log('bua-interactive: WARNING worker-websocket scope check failed: ' + maskText(String(e.message || e)))
      }))
    })
  } catch (e) {
    await fatal('worker websocket observation could not be installed — refusing to browse unscoped. (' +
      maskText(String(e.message || e)) + ')')
  }
  const collectHops = makeHopCollector(summary, scopeCache, log)
  context.on('response', (response) => {
    tasks.hop.push(collectHops(response).catch((e) => {
      log('bua-interactive: WARNING redirect-hop scope check failed: ' + maskText(String(e.message || e)))
    }))
  })

  // ---- the loop's real deps -------------------------------------------------------
  let generation = 0
  let loginDone = false
  const realSnapshot = async () => {
    generation += 1
    const snapAt = await snapshotPage(page, generation)
    summary.final_url = maskUrlSecrets(page.url())
    return snapAt
  }
  // The live generation is whatever the last observation returned: the guard refuses a
  // handle whose snapshot generation is no longer current.
  const snap = async (ctx) => {
    const taken = await (snapshot || realSnapshot)(ctx)
    if (taken && typeof taken.generation === 'number') generation = taken.generation
    return taken
  }
  const realCapture = async ({ op, result, snapshot: snapAt, token: tok, step, actionClass }) => {
    const actionId = (tok && tok.action_id) || 'A-unknown'
    const captureRel = join(outDirRel, `${label}-s${step}-${actionId}.action.json`)
    const shotRel = join(outDirRel, `${label}-s${step}-${actionId}.png`)
    const receipt = {
      action_id: actionId, step, op: op.op, handle: op.handle || null,
      action_class: actionClass || classifyAction(op, null),
      url_masked: maskUrlSecrets(page.url()),
      status: (result && result.status !== undefined) ? result.status : null,
      login_flow: (result && result.login_flow) || null,
      secrets_source: (result && result.login_flow) ? 'env' : null,
      token_nonce_present: Boolean(tok && tok.nonce),
      scope: {
        violation: summary.scope_violation,
        out_of_scope_hop_count: summary.out_of_scope_hop_count,
        blocked_count: summary.blocked_count,
        blocked_action_count: summary.blocked_action_count,
      },
      captured_at: new Date().toISOString(),
    }
    writeFileSync(join(root, captureRel), JSON.stringify(JSON.parse(scrub(JSON.stringify(receipt))), null, 2) + '\n')
    let screenshot = null
    // A consequential action's surface (credential entry, submit) is never captured as a
    // screenshot; after a scope violation the run captures nothing normal either.
    if (actionClass !== 'consequential' && summary.scope_violation !== true) {
      try {
        await page.screenshot({ path: join(root, shotRel) })
        screenshot = shotRel
        summary.screenshot = shotRel
      } catch { screenshot = null }
    }
    const registered = ctl(['evidence', 'register', captureRel, 'bua-interactive-action',
                            `bua-interactive ${op.op} ${actionId}`, '--cycle', cycleId])
    if (!registered || !registered.entity_id) {
      return { ok: false, reason: 'evidence registration failed' }
    }
    summary.evidence.push(registered.entity_id)
    return { ok: true, artifact: captureRel, screenshot, evidence: registered.entity_id }
  }
  const realRecord = async ({ op, result, capture: cap, token: tok, step, actionClass }) => {
    const actionId = (tok && tok.action_id) || 'A-unknown'
    const payload = {
      ...((tok && tok.preflight) || {}),
      id: actionId,
      cycle_id: cycleId,
      token_nonce: (tok && tok.nonce) || undefined,
      action_class: actionClass,
      action_type: op.op,
      target: (tok && tok.preflight && tok.preflight.target) || args.url,
      request_shape: (tok && tok.preflight && tok.preflight.request_shape) || { url: args.url, principal: args.principal },
      evidence_refs: cap && cap.evidence ? [cap.evidence] : [],
      scope_violation: summary.scope_violation === true,
      out_of_scope_hops: summary.out_of_scope_hop_count,
    }
    const recordRel = join(outDirRel, `${label}-s${step}-${actionId}.receipt.json`)
    writeFileSync(join(root, recordRel), JSON.stringify(JSON.parse(scrub(JSON.stringify(payload))), null, 2) + '\n')
    const recorded = ctl(['action', recordRel])
    if (!recorded || !recorded.entity_id) {
      return { ok: false, reason: 'ACTION_RECORDED was refused' }
    }
    return { ok: true, id: recorded.entity_id }
  }
  const realAuthorize = async ({ op, snapshot: snapAt, step, actionClass }) => {
    if (op.op === 'NAVIGATE' && entryToken && String(entryToken.preflight && entryToken.preflight.target || args.url) === String(op.url)) {
      return { ok: true, token: entryToken }
    }
    const shape = { url: op.op === 'NAVIGATE' ? op.url : (snapAt.url || args.url), principal: args.principal }
    const shapeRel = join(outDirRel, `${label}-shape-s${step}.json`)
    writeFileSync(join(root, shapeRel), JSON.stringify(shape) + '\n')
    const prepareRel = join(outDirRel, `${label}-prepare-s${step}.json`)
    writeFileSync(join(root, prepareRel), JSON.stringify({
      ...preflight, target: shape.url, tool_family: 'browser', action_class: actionClass,
      request_shape: shape,
    }) + '\n')
    const prepared = ctl(['prepare', prepareRel])
    if (!prepared || !prepared.action_id) {
      return { ok: false, reason: 'prepare refused the action: ' + String((prepared && (prepared.error || prepared.reason)) || 'unknown') }
    }
    const consumed = consumeToken(ctl, prepared.action_id, shapeRel)
    if (!consumed.ok) {
      return { ok: false, reason: 'preflight token was refused: ' + consumed.reason }
    }
    return { ok: true, token: consumed.token }
  }
  const realGate = async ({ actionId }) => {
    const checked = ctl(['gate-check', actionId])
    if (!checked || checked.resolved !== true) {
      return { ok: false, reason: `consequential action ${actionId} has no RESOLVED human gate naming it — ` +
        'raise `researchctl gate request` with the action id in what_is_needed and resolve it before dispatch' }
    }
    return { ok: true, gate: checked.gate }
  }
  const realScopeRecheck = async ({ op, snapshot: snapAt }) => {
    const url = op.op === 'NAVIGATE' ? op.url : String((snapAt && snapAt.url) || '')
    if (op.op !== 'NAVIGATE' && summary.scope_violation === true) {
      return { ok: false, reason: 'a followed out-of-scope redirect hop tainted this session — ' +
        'writes are refused (the hop is recorded; preflight the redirect target as its own action)' }
    }
    if (!url) return { ok: false, reason: 'no live page URL for this action' }
    const decision = await decideRequest(url, scopeCache)
    if (decision.allow) return { ok: true }
    summary.blocked_action_count += 1
    if (summary.blocked_actions.length < BLOCKED_ACTIONS_CAP) {
      summary.blocked_actions.push({ op: op.op, host: decision.host,
                                     url_masked: maskUrlSecrets(url), reason: decision.reason })
    }
    log(`bua-interactive: refused ${op.op} — ${decision.reason} host=${decision.host || '-'}`)
    return { ok: false, reason: `out-of-scope dispatch refused (${decision.reason})` }
  }
  const login = async ({ snapshot: snapAt }) => {
    if (loginDone) {
      return { ok: false, reason: 'fresh login per run: a second LOGIN in the same run is refused' }
    }
    const targets = resolveLoginTargets(snapAt && snapAt.entries)
    if (!targets.ok) return { ok: false, reason: targets.reason }
    const user = process.env.RESEARCH_OS_BUA_LOGIN_USER
    const password = process.env.RESEARCH_OS_BUA_LOGIN_PASSWORD
    if (!user || !password) {
      return { ok: false, reason: 'login secrets are env-only ' +
        '(RESEARCH_OS_BUA_LOGIN_USER / RESEARCH_OS_BUA_LOGIN_PASSWORD) — refusing to log in without them' }
    }
    const locators = (snapAt && snapAt.locators) || new Map()
    try {
      await locators.get(targets.user).fill(user, { timeout: ACTION_TIMEOUT_MS })
      await locators.get(targets.password).fill(password, { timeout: ACTION_TIMEOUT_MS })
      loginDone = true
      secrets.push(password)
      await locators.get(targets.submit).click({ timeout: ACTION_TIMEOUT_MS })
      return { ok: true, login_flow: 'primary', secrets_source: 'env' }
    } catch (e) {
      return { ok: false, reason: scrub(String(e.message || e)) }
    }
  }
  const boundaryFor = ({ snapshot: snapAt }) => buildBoundary({
    root, entries: (snapAt && snapAt.entries) || [], textValues: preflight.text_values,
    uploadFiles: preflight.upload_files, loginFlows: preflight.login_flows,
  })
  const deps = {
    maxSteps: Number(args.steps) || DEFAULT_MAX_STEPS,
    boundary: boundaryFor,
    snapshot: snap,
    plan: plan || (async ({ step, snapshot: snapAt, history }) => {
      const boundary = boundaryFor({ snapshot: snapAt })
      const ctx = planContext({ boundary, snapshot: snapAt, entryUrl: args.url, step, history, cycleId })
      const planRel = join(outDirRel, `${label}-plan-s${step}.json`)
      writeFileSync(join(root, planRel), JSON.stringify(ctx.request, null, 2) + '\n')
      const planned = ctl(['bua-plan', planRel])
      if (!planned || planned.ok !== true) {
        return { ok: false, source: (planned && planned.source) || 'error',
                 reason: (planned && planned.reason) || 'plan refused' }
      }
      const resolved = resolveOperation(planned.operation, ctx)
      if (!resolved.ok) return { ok: false, source: 'boundary', reason: resolved.reason }
      const parsed = parseOperation(resolved.op, boundary)
      if (!parsed.ok) return { ok: false, source: 'boundary', reason: parsed.reason }
      return { ok: true, operation: parsed.op, boundary, source: planned.source, usage: planned.usage }
    }),
    verify: verify || (() => verifyDone({
      freshSnapshot: () => snap({ step: summary.steps, history: summary.history, fresh: true }),
      capture: (ctx) => realCapture({ ...ctx, step: summary.steps }),
    })),
    dispatch: dispatch || ((ctx) => dispatchOp({ page, ...ctx, summary, collectHops, login })),
    capture: capture || ((ctx) => realCapture(ctx)),
    record: record || ((ctx) => realRecord(ctx)),
    authorize: authorize || ((ctx) => realAuthorize(ctx)),
    gate: gate || ((ctx) => realGate(ctx)),
    guard: guard || ((ctx) => guardDispatch(ctx.op, {
      generation: ctx.snapshot.generation, currentGeneration: generation,
      entry: ctx.entry, locator: ctx.snapshot.locators && ctx.snapshot.locators.get(ctx.op.handle),
      viewport: typeof page.viewportSize === 'function' ? page.viewportSize() : null,
    })),
    scopeRecheck: scopeRecheck || ((ctx) => realScopeRecheck(ctx)),
  }
  const loop = await runLoop(deps)
  Object.assign(summary, loop)
  try { await context.close() } catch { /* already closed */ }
  await Promise.allSettled([...tasks.hop, ...tasks.ws, ...tasks.sw, ...tasks.worker])
  summary.finished_at = new Date().toISOString()
  const summaryRel = join(outDirRel, `${label}-${ts}.interactive.json`)
  writeFileSync(join(root, summaryRel), JSON.stringify(JSON.parse(scrub(JSON.stringify(summary))), null, 2) + '\n')
  log(`ARTIFACT ${summaryRel}`)
  log(`bua-interactive: ${summary.status}${summary.blocked_reason ? ' (' + summary.blocked_reason + ')' : ''} ` +
    `steps=${summary.steps} blocked=${summary.blocked_count} out_of_scope_hops=${summary.out_of_scope_hop_count} ` +
    `violation=${summary.scope_violation}`)
  return summary
}

async function main() {
  try {
    const args = parseArgs(process.argv.slice(2))
    const root = findOsRoot(process.cwd())
    if (!root) {
      usage('not inside a Research OS workspace (11_runtime/events.jsonl, 00_control/engagement.yaml or 11_runtime/)')
    }
    if (!args.url || !args.principal) usage('--url and --principal are required')
    if (!args.profile) {
      usage('--profile is required on the interactive arm (a dedicated per-engagement profile; ' +
        'there is no lab default here)')
    }
    if (!args.action) usage('--action <A-…> is required (the entry preflight token the controller prepared)')
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(String(args.action))) {
      usage('--action must match [A-Za-z0-9_-] (1-64 chars)')
    }
    if (!args.preflight) usage('--preflight <workspace json> is required (the per-action preflight fields)')
    const steps = args.steps === undefined ? DEFAULT_MAX_STEPS : Number(args.steps)
    if (!Number.isInteger(steps) || steps < 1 || steps > MAX_STEPS_CAP) {
      usage(`--steps must be an integer 1..${MAX_STEPS_CAP} (MAX_STEPS cap)`)
    }
    await runInteractive({ root, args: { ...args, steps: String(steps) } })
  } catch (e) {
    if (e instanceof Refusal) {
      console.error('bua-interactive: ' + maskText(e.message))
      process.exit(e.code)
    }
    console.error('bua-interactive: ' + maskText(String(e && e.message ? e.message : e)))
    process.exit(2)
  }
  process.exit(0)
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main()
