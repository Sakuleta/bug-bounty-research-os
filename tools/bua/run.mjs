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
 *     00_control/engagement.yaml before the browser starts (exit 4 when denied);
 *   - dedicated per-engagement profile inside the workspace — never the personal one;
 *   - read-only default: navigate + screenshot + page metadata. A task that changes
 *     state belongs in its own script with its documented precondition; this runner
 *     refuses nothing by accident, it simply has no write path;
 *   - capture: screenshot PNG + JSON summary under the out dir; cookie VALUES are
 *     never read or logged (presence-only rule), secrets never printed.
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
const SECRET_SHAPES = [
  /\bglpat-[A-Za-z0-9_-]{16,}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{16,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/g,
]

function scrubSecrets(text) {
  let out = String(text == null ? '' : text)
  for (const re of SECRET_SHAPES) out = out.replace(re, '[REDACTED]')
  return out
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

/** Walk up from cwd for a Research OS workspace root (OS_VERSION + ledger). */
function findOsRoot(cwd) {
  let dir = resolve(cwd)
  for (let i = 0; i < 12; i++) {
    if (existsSync(join(dir, 'OS_VERSION')) && existsSync(join(dir, '11_runtime', 'events.jsonl'))) return dir
    const parent = resolve(dir, '..')
    if (parent === dir) break
    dir = parent
  }
  return undefined
}

/** Keep workspace-owned paths inside the workspace. */
function insideRoot(root, rel, flag) {
  const abs = resolve(root, rel)
  if (abs !== resolve(root) && !abs.startsWith(resolve(root) + sep)) {
    usage(`${flag} must stay inside the workspace (got ${rel})`)
  }
  return abs
}

async function main() {
  const args = parseArgs(process.argv.slice(2))
  if (!args.url || !args.principal) usage('--url and --principal are required')
  const root = findOsRoot(process.cwd())
  if (!root) usage('not inside a Research OS workspace (OS_VERSION + 11_runtime/events.jsonl)')
  insideRoot(root, args['out-dir'], '--out-dir')
  insideRoot(root, args.profile, '--profile')

  // 1. Scope guard in code — the same seam the control plane uses.
  let scope
  try {
    scope = JSON.parse(execFileSync(
      'python3',
      [join(root, 'tools', 'researchctl.py'), root, 'scope-check', args.url],
      { encoding: 'utf8', timeout: 30000 },
    ))
  } catch (e) {
    let parsed = null
    try { parsed = JSON.parse(String(e.stdout || '')) } catch { /* not JSON */ }
    if (parsed && parsed.in_scope === false) {
      const detail = parsed.gate === 'unenforceable'
        ? 'the engagement asset list is not a simple host/URL list — scope is unenforceable'
        : `target '${parsed.host || args.url}' is outside the engagement scope (assets=${JSON.stringify(parsed.assets ?? [])})`
      console.error('bua-runner: ' + detail + '. Fix 00_control/engagement.yaml from the authoritative program policy first.')
      process.exit(4)
    }
    console.error('bua-runner: scope check failed: ' + String(e.message || e))
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
    title: null,
    error: null,
    screenshot: shotRel,
  }
  let page
  try {
    page = context.pages()[0] || (await context.newPage())
    const resp = await page.goto(args.url, { waitUntil: 'domcontentloaded', timeout: 30000 })
    summary.status = resp ? resp.status() : null
    summary.final_url = maskUrlSecrets(page.url())
    summary.title = await page.title().catch(() => null)
    await page.screenshot({ path: join(root, shotRel) })
  } catch (e) {
    summary.error = String(e.message || e)
    try { if (page) await page.screenshot({ path: join(root, shotRel) }) } catch { /* best effort */ }
  } finally {
    try { await context.close() } catch { /* already closed */ }
  }
  summary.finished_at = new Date().toISOString()
  writeFileSync(join(root, summaryRel), JSON.stringify(summary, null, 2) + '\n')
  console.log(`ARTIFACT ${shotRel}`)
  console.log(`ARTIFACT ${summaryRel}`)
  console.log(`bua-runner: ${summary.status === null ? 'error: ' + summary.error : 'HTTP ' + summary.status} ` +
    `final=${summary.final_url || '-'} title=${JSON.stringify(summary.title)}`)
  process.exit(0)
}

// The CLI flow runs only when this file is the entry point; importing it (tests) is safe.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main()
