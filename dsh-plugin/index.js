/**
 * research-os-enforcer — DSH policy plugin for the Bug Bounty Research OS.
 *
 * Enforcement surfaces (verified against the installed harness API):
 *
 *   1. `tools/pre-execute` waterfall — reorderable policy: allow/deny/ask.
 *   2. `tools.guard()` — monotonic final denial a later listener cannot undo.
 *   3. `research_os_request` tool — the controlled live-request executor: the ONLY
 *      sanctioned path for target traffic.
 *
 * Rules:
 *
 *   R1  Canonical/projection files are write-protected inside any detected Research
 *       OS workspace (fs tools + common shell write shapes). Mutate state through
 *       tools/researchctl.py; the OS rebuilds projections on every mutation.
 *   R2  The event ledger `11_runtime/events.jsonl` is append-only through the control
 *       plane; direct writes are denied.
 *   R3  Raw network egress (curl/wget/ssh/... to a non-local host) is closed in an OS
 *       workspace. Target traffic goes through `research_os_request`; research material
 *       goes through the web tools; localhost/lab traffic is never blocked.
 *   R4  `research_os_request` is single-use bound: it consumes the preflight token
 *       issued by `python3 tools/researchctl.py <root> prepare payload.json` whose
 *       `argument_digest` matches the call's canonical shape
 *       ({method, url, principal[, headers][, body_sha256]}), then executes, stores a
 *       request/response capture under 08_artifacts/raw/, registers it as evidence and
 *       records the action through the control plane.
 *   R5  The executor reads per-host scope from `00_control/engagement.yaml` assets
 *       (same semantics as `researchctl prepare`: simple string list, `*.domain`
 *       wildcards, host[:port] compared exactly) and refuses out-of-scope targets
 *       before dispatch — a hand-crafted or stale token cannot widen scope. The token
 *       store `11_runtime/action-tokens.jsonl` is control-plane-owned (write-protected
 *       like a projection). Scope failures fail CLOSED; other internal errors fail open.
 *   R6  Raw browser-automation launches inside an OS workspace are denied outside the
 *       browser executor: prepare with tool_family "browser" and call
 *       `research_os_browser`, which runs the canonical read-only runner
 *       (tools/bua/run.mjs — dedicated profile, scope guard, capture) and records the
 *       action. Install-shaped commands and explicit-localhost work stay allowed.
 *
 * v1 limits (documented, deliberate): digest covers lowercase header keys; the
 * controlled executor speaks HTTP(S) only; the browser arm is read-only (navigate +
 * capture) — interactive or state-changing flows use a dedicated task script with its
 * documented precondition; command-pattern gating cannot see a browser launch hidden
 * inside an arbitrary interpreter script, so the runner + token stays the sanctioned
 * path.
 *
 * Failure mode: internal errors fail OPEN (log line + allow). The conformance and
 * executor-integration suites keep the rules honest; the OS audit stays the source of
 * truth. Log: ~/.dsh/research-os-enforcer.log
 */
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { isAbsolute, join, resolve, sep } from 'node:path'

const name = 'research-os-enforcer'
const inject = ['tools']

const OS_MARKER = 'OS_VERSION'
const LEDGER_REL = '11_runtime/events.jsonl'
const TOKENS_REL = '11_runtime/action-tokens.jsonl'

// Paths the control plane owns. Matched against a workspace-relative POSIX path.
const PROTECTED_PATTERNS = [
  /^11_runtime\/(events\.jsonl|run-status\.yaml|active-cycle\.yaml|evidence-index\.jsonl|current-context\.md|last-result\.md|action-tokens\.jsonl)$/,
  /^11_runtime\/human-gates\/[^/]+\.yaml$/,
  /^04_cycles\/[^/]+\/plan\.yaml$/,
  /^03_hypotheses\/(active|archive)\/[^/]+\.yaml$/,
  /^06_audits\/closure-readiness\.yaml$/,
  /^10_learning\/technique-discoveries\.md$/,
]

// Commands that reach the network. Deliberately narrow: package installs and
// git operations are provisioning, not target access.
const NET_CMD = /(^|[;&|(]\s*|\s)(curl|wget|http|httpie|nc|ncat|nmap|socat|dig|nslookup|host)\b|openssl\s+s_client|\bssh\b|\bscp\b/
const LOCAL_HOST = /(^|[\s/@:.])(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0|::1|\.local|\.internal)([\s/:'"]|$)/i
const WRITE_TOKEN = /(>>?|\btee\b|sed\s+-i|\btruncate\b|\bcp\b|\bmv\b|\bdd\b|\binstall\b|python3?\s+-\s*<<|cat\s*<<)/
const BROWSER_LAUNCH = /\b(playwright|puppeteer|selenium|selenium-webdriver|chromedriver|geckodriver)\b|--headless\b|--remote-debugging-port\b|chrome-headless-shell/
const PM_QUERY = /(^|[\s;&|(])(npm|pnpm|yarn|bun)\s+(i|install|add|ls|list|view|info|why|audit|outdated)\b|\bpip3?\s+install\b|--version\b/

// Capture hygiene (29_SECURITY_HYGIENE: RAW -> SANITIZE -> REFERENCE). Values in these
// headers never reach a capture; secret-shaped strings in any text are redacted on write.
const SENSITIVE_HEADERS = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-access-token|api-key|x-csrf-token)\b/i
const SECRET_SHAPES = [
  /\bglpat-[A-Za-z0-9_-]{16,}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{16,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
]

function log(line) {
  try { appendFileSync(homedir() + '/.dsh/research-os-enforcer.log', new Date().toISOString() + ' ' + line + '\n') } catch {}
}

function sessionCwd(exec) {
  const cwd = exec && exec.agent && exec.agent.session && exec.agent.session.header && exec.agent.session.header.cwd
  return typeof cwd === 'string' && cwd ? cwd : undefined
}

/** Walk up from cwd looking for a Research OS workspace root (OS_VERSION + ledger). */
function findOsRoot(cwd) {
  if (!cwd) return undefined
  let dir = resolve(cwd)
  for (let i = 0; i < 12; i++) {
    try {
      if (existsSync(join(dir, OS_MARKER)) && existsSync(join(dir, LEDGER_REL))) return dir
    } catch {}
    const parent = resolve(dir, '..')
    if (parent === dir) break
    dir = parent
  }
  return undefined
}

/** Workspace-relative posix path for an absolute path inside root, else undefined. */
function relPosix(root, abs) {
  const r = resolve(root)
  const a = resolve(abs)
  if (a !== r && !a.startsWith(r + sep)) return undefined
  return a.slice(r.length + 1).split(sep).join('/')
}

function protectedReason(rel) {
  for (const re of PROTECTED_PATTERNS) {
    if (re.test(rel)) {
      if (rel === LEDGER_REL) {
        return `research-os-enforcer: ${LEDGER_REL} is the canonical append-only ledger — mutate it only through tools/researchctl.py (no direct writes).`
      }
      if (rel === TOKENS_REL) {
        return `research-os-enforcer: ${TOKENS_REL} holds single-use preflight tokens — mint them through python3 tools/researchctl.py <root> prepare; direct writes are denied.`
      }
      return `research-os-enforcer: ${rel} is a control-plane projection/view — do not edit it by hand. Mutate state through tools/researchctl.py; the OS rebuilds this file on every mutation.`
    }
  }
  return undefined
}

/** Resolve a tool-call file path (fs tools) against the session cwd. */
function targetAbs(exec) {
  const args = (exec && exec.arguments) || {}
  const raw = args.file_path
  if (typeof raw !== 'string' || !raw) return undefined
  const cwd = sessionCwd(exec)
  return isAbsolute(raw) ? raw : join(cwd || process.cwd(), raw)
}

/** Read the workspace's runtime status (small files; read fresh, never cached). */
function osStatus(root) {
  try {
    const text = readFileSync(join(root, '11_runtime', 'run-status.yaml'), 'utf8')
    const engagement = (text.match(/^engagement_status:\s*"?([A-Z_]+)"?/m) || [])[1] || 'UNKNOWN'
    const cycleRaw = (text.match(/^current_cycle:\s*"?([A-Za-z0-9-]+|null)"?/m) || [])[1] || null
    const cycle = cycleRaw === 'null' ? null : cycleRaw
    let cycleState = null
    if (cycle) {
      const planPath = join(root, '04_cycles', cycle, 'plan.yaml')
      if (existsSync(planPath)) {
        cycleState = (readFileSync(planPath, 'utf8').match(/^status:\s*"?([A-Z_]+)"?/m) || [])[1] || null
      }
    }
    return { engagement, cycle, cycleState }
  } catch (e) {
    return undefined
  }
}

/** R1/R2 — projection & ledger write protection for fs tools (monotonic guard). */
function fsWriteReason(exec) {
  try {
    if (!exec || (exec.name !== 'write' && exec.name !== 'edit')) return undefined
    const root = findOsRoot(sessionCwd(exec))
    if (!root) return undefined
    const abs = targetAbs(exec)
    if (!abs) return undefined
    const rel = relPosix(root, abs)
    if (rel === undefined) return undefined
    return protectedReason(rel)
  } catch (e) {
    log('guard-fs-error ' + e)
    return undefined
  }
}

/** R1/R2 — the same protection for shell write shapes, judging the WRITE TARGET.
 *
 *  `2>&1` / `>&2` are descriptor duplications, not file writes: only a real
 *  redirect target (or the path arguments of an explicitly writing tool) counts,
 *  so reading a protected file through bash stays allowed (live-verified fix).
 */
function bashWriteReason(exec) {
  try {
    if (!exec || exec.name !== 'bash') return undefined
    const args = exec.arguments || {}
    if (typeof args.command !== 'string') return undefined
    const cwd = (typeof args.workdir === 'string' && args.workdir) ? args.workdir : sessionCwd(exec)
    const root = findOsRoot(cwd)
    if (!root) return undefined
    const cmd = args.command
    const targets = []
    const redirected = /(^|[^>&])>>?\s*(?!&)([^\s;&|()<>]+)/g
    for (const m of cmd.matchAll(redirected)) targets.push(m[2])
    const WRITE_TOOL = /\b(tee|truncate|shred)\b|sed\s+-i|\bcp\b|\bmv\b|\bdd\b|\binstall\b/
    if (WRITE_TOOL.test(cmd)) {
      for (const t of cmd.split(/[\s"'`|&;()<>]+/)) if (t.includes('/')) targets.push(t)
    }
    if (/python3?\s+-\s*<<|cat\s*<<|<<-?\s*['"]?\w+/.test(cmd)) {
      // Heredoc bodies are executable scripts: scan every path-shaped token.
      for (const t of cmd.split(/[\s"'`|&;()<>]+/)) if (t.includes('/')) targets.push(t)
    }
    for (const tok of targets) {
      const abs = isAbsolute(tok) ? tok : join(cwd || root, tok)
      const rel = relPosix(root, abs)
      if (rel === undefined) continue
      const reason = protectedReason(rel)
      if (reason) return reason
    }
    return undefined
  } catch (e) {
    log('guard-bash-error ' + e)
    return undefined
  }
}

/** R3 — raw network egress is closed; target traffic goes through the executor. */
function liveGateReason(exec) {
  try {
    if (!exec || exec.name !== 'bash') return undefined
    const args = exec.arguments || {}
    if (typeof args.command !== 'string') return undefined
    const cmd = args.command
    if (!NET_CMD.test(cmd)) return undefined
    const root = findOsRoot(sessionCwd(exec))
    if (!root) return undefined
    const urls = cmd.match(/https?:\/\/[^\s'"]+/g) || []
    if (urls.length > 0 && urls.every((u) => LOCAL_HOST.test(u))) return undefined
    if (urls.length === 0 && LOCAL_HOST.test(cmd)) return undefined
    const st = osStatus(root)
    if (!st || st.engagement === 'BOOTSTRAP') {
      return 'research-os-enforcer: this Research OS workspace has no active engagement — no live target traffic before the engagement is configured and a cycle is RUNNING. Bootstrap first (START.md), advance a cycle through tools/researchctl.py, then use the research_os_request tool for target traffic. Localhost/lab traffic is never blocked.'
    }
    if (!st.cycle || st.cycleState !== 'RUNNING') {
      return `research-os-enforcer: live target access requires an active RUNNING cycle (current cycle: ${st.cycle || 'none'}, state: ${st.cycleState || 'none'}). Record or advance a cycle via tools/researchctl.py, then use the research_os_request tool. Localhost/lab traffic is never blocked.`
    }
    return 'research-os-enforcer: raw network commands are not the live path — prepare a preflight (python3 tools/researchctl.py . prepare payload.json) and send the matching request through the research_os_request tool; research material goes through the web tools. Localhost/lab traffic is never blocked.'
  } catch (e) {
    log('guard-live-error ' + e)
    return undefined
  }
}

/** R6 — raw browser-automation launches are not the live path; the browser executor is. */
function browserGateReason(exec) {
  try {
    if (!exec || exec.name !== 'bash') return undefined
    const args = exec.arguments || {}
    if (typeof args.command !== 'string') return undefined
    const cmd = args.command
    if (!BROWSER_LAUNCH.test(cmd)) return undefined
    if (PM_QUERY.test(cmd)) return undefined
    const root = findOsRoot(sessionCwd(exec))
    if (!root) return undefined
    const urls = cmd.match(/https?:\/\/[^\s'"]+/g) || []
    if (urls.length > 0 && urls.every((u) => LOCAL_HOST.test(u))) return undefined
    return 'research-os-enforcer: browser automation drives target traffic — a raw launch is not the live path. Prepare a browser preflight (python3 tools/researchctl.py . prepare payload.json with "tool_family": "browser" and request_shape {"url": …, "principal": …}) and call the research_os_browser tool; it runs the canonical runner tools/bua/run.mjs with the engagement scope guard. Localhost/lab browser work stays allowed — name the local URL explicitly.'
  } catch (e) {
    log('guard-browser-error ' + e)
    return undefined
  }
}

// ---------- engagement scope (R5) ----------

/** Parse the in-scope asset list, mirroring tools/control_plane.py engagement_assets().
 *
 *  Returns null when the file/block is absent or empty (no scope gate configured),
 *  the items when they are simple strings, and [] when the block exists but is not a
 *  simple string list — the caller treats [] as unenforceable and fails closed. */
function engagementAssets(root) {
  const p = join(root, '00_control', 'engagement.yaml')
  if (!existsSync(p)) return null
  let inAssets = false
  let unparsed = 0
  const items = []
  for (const line of readFileSync(p, 'utf8').split('\n')) {
    const stripped = line.trim()
    if (!stripped || stripped.startsWith('#')) continue
    if (!inAssets) {
      const m = stripped.match(/^assets:\s*(.*)$/)
      if (!m) continue
      const rest = m[1].trim()
      if (rest === '' || rest === '[]') { inAssets = true; continue }
      if (rest.startsWith('[') && rest.endsWith(']')) {
        for (const part of rest.slice(1, -1).split(',')) {
          const val = part.trim().replace(/^["']+|["']+$/g, '')
          if (val) items.push(val)
        }
        continue
      }
      unparsed += 1
      inAssets = true
      continue
    }
    if (!/^[ \t]/.test(line)) break
    const m = stripped.match(/^-\s*(.+?)\s*$/)
    if (!m) continue
    const val = m[1]
    if (val.startsWith('[') || val.startsWith('{')) { unparsed += 1; continue }
    const clean = val.replace(/^["']+|["']+$/g, '')
    if (clean) items.push(clean)
  }
  if (items.length) return items
  if (inAssets && unparsed) return []
  return null
}

/** Asset URL/host strings reduced to their host[:port], lowercase. */
function assetHosts(assets) {
  const hosts = []
  for (const asset of assets) {
    let value = String(asset).trim()
    if (value.includes('://')) value = value.slice(value.indexOf('://') + 3)
    const host = value.split('/')[0].split('?')[0].split('#')[0].trim().toLowerCase()
    if (host) hosts.push(host)
  }
  return hosts
}

/** Exact host[:port] match, plus `*.base` matching base and any subdomain. */
function hostInScope(host, patterns) {
  const h = String(host || '').toLowerCase()
  for (const pattern of patterns) {
    if (pattern.startsWith('*.')) {
      const base = pattern.slice(2)
      if (h === base || h.endsWith('.' + base)) return true
    } else if (h === pattern) return true
  }
  return false
}

/** Host[:port] of an absolute URL, mirroring the prepare-side extraction. */
function hostFromUrl(url) {
  const s = String(url || '')
  if (!s.includes('://')) return ''
  return s.slice(s.indexOf('://') + 3).split('/')[0].split('?')[0].split('#')[0].toLowerCase()
}

/** R5 — per-host scope gate, mirroring `researchctl prepare`. Fail closed on scope errors. */
function scopeReasonFor(root, url) {
  try {
    const assets = engagementAssets(root)
    if (assets === null) return undefined
    if (assets.length === 0) {
      return 'research-os-enforcer: engagement assets are present but not a simple string list; keep 00_control/engagement.yaml assets as host/URL strings — scope is unenforceable otherwise.'
    }
    const host = hostFromUrl(url)
    if (!host || !hostInScope(host, assetHosts(assets))) {
      return `research-os-enforcer: target host '${host || url}' is outside the engagement scope (00_control/engagement.yaml assets=${JSON.stringify(assets)}). Update the engagement scope from the authoritative program policy, then prepare a fresh preflight.`
    }
    return undefined
  } catch (e) {
    log('scope-error ' + e)
    return 'research-os-enforcer: engagement scope could not be read — refusing the request until 00_control/engagement.yaml parses as a simple asset list.'
  }
}

// ---------- preflight tokens (R4) ----------

/** Recursively sort object keys; the canonical form both sides hash. */
function canon(v) {
  if (Array.isArray(v)) return v.map(canon)
  if (v && typeof v === 'object') {
    const out = {}
    for (const k of Object.keys(v).sort()) out[k] = canon(v[k])
    return out
  }
  return v
}

function canonicalDigest(shape) {
  return createHash('sha256').update(JSON.stringify(canon(shape))).digest('hex')
}

/** Build the canonical request shape from tool args (lowercase header keys). */
function shapeFromArgs(args) {
  const shape = {
    method: String((args && args.method) || '').toUpperCase(),
    url: String((args && args.url) || ''),
    principal: String((args && args.principal) || ''),
  }
  if (args && args.body !== undefined && args.body !== null && String(args.body).length > 0) {
    shape.body_sha256 = createHash('sha256').update(String(args.body)).digest('hex')
  }
  if (args && args.headers && typeof args.headers === 'object') {
    const h = {}
    for (const k of Object.keys(args.headers)) h[String(k).toLowerCase()] = String(args.headers[k])
    shape.headers = h
  }
  return shape
}

/** Fold the append-only token store into latest-state-per-action. */
function loadTokenStates(root) {
  const states = new Map()
  const p = join(root, TOKENS_REL)
  if (!existsSync(p)) return states
  for (const line of readFileSync(p, 'utf8').split('\n')) {
    if (!line.trim()) continue
    let rec
    try { rec = JSON.parse(line) } catch { continue }
    if (!rec || !rec.action_id) continue
    states.set(rec.action_id, { ...(states.get(rec.action_id) || {}), ...rec })
  }
  return states
}

/** First unconsumed, unexpired, digest-matching token of the requested family (FIFO). */
function selectToken(states, digest, nowMs, family = 'http') {
  for (const st of states.values()) {
    if (st.consumed === true) continue
    if (st.argument_digest !== digest) continue
    if (String(st.tool_family || 'http') !== family) continue
    const exp = Date.parse(String(st.expires_at || ''))
    if (Number.isFinite(exp) && exp <= nowMs) continue
    return st
  }
  return undefined
}

function consumeToken(root, token) {
  appendFileSync(join(root, TOKENS_REL), JSON.stringify({
    action_id: token.action_id,
    nonce: token.nonce,
    consumed: true,
    consumed_at: new Date().toISOString(),
  }) + '\n')
}

function trunc(s, n) {
  const text = String(s == null ? '' : s)
  return text.length > n ? text.slice(0, n) + `\n…[truncated ${text.length - n} chars]` : text
}

/** Redact secret-shaped strings anywhere in free text. */
function redactSecrets(text) {
  let out = String(text == null ? '' : text)
  for (const re of SECRET_SHAPES) out = out.replace(re, '[REDACTED]')
  return out
}

/** Redact a `name: value` header line: sensitive header values become [REDACTED]. */
function redactHeaderLine(line) {
  const raw = String(line == null ? '' : line)
  const idx = raw.indexOf(':')
  if (idx < 0) return redactSecrets(raw)
  const headerName = raw.slice(0, idx).trim()
  if (SENSITIVE_HEADERS.test(headerName)) return `${headerName}: [REDACTED]`
  return `${headerName}: ${redactSecrets(raw.slice(idx + 1).replace(/^\s+/, ''))}`
}

/** Register a capture as evidence and record ACTION_RECORDED through the control plane. */
function registerCapture({ root, relPath, token, source }) {
  let evidence = ''
  const python = 'python3'
  const cli = join(root, 'tools', 'researchctl.py')
  try {
    const out = execFileSync(python, [cli, root, 'evidence', 'register', relPath, 'raw', source, '--cycle', token.cycle_id], { encoding: 'utf8', timeout: 60000 })
    const ev = JSON.parse(out)
    evidence = (ev.payload && ev.payload.id) || ''
  } catch (e) {
    log('executor-evidence-error ' + e)
  }
  let recorded = false
  try {
    const preflight = (token.preflight && typeof token.preflight === 'object') ? token.preflight : {}
    const payload = { ...preflight, id: token.action_id, ...(evidence ? { evidence_refs: [evidence] } : {}) }
    const payloadPath = join(tmpdir(), `research-os-action-${token.nonce}.json`)
    writeFileSync(payloadPath, JSON.stringify(payload))
    execFileSync(python, [cli, root, 'action', payloadPath], { encoding: 'utf8', timeout: 60000 })
    recorded = true
  } catch (e) {
    log('executor-record-error ' + e)
  }
  return { evidence, recorded }
}

/**
 * R4 — execute one controlled live request. Consumes the matching single-use token
 * BEFORE dispatching (crash-safe against replay), captures request/response, registers
 * the capture as evidence and records the action through the control plane.
 */
async function runControlledRequest({ root, args, fetchImpl }) {
  const fetchFn = fetchImpl || globalThis.fetch
  const shape = shapeFromArgs(args)
  if (!shape.method || !shape.url || !shape.principal) {
    return { ok: false, text: 'research_os_request requires method, url and principal (the account label used in the preflight).' }
  }
  const digest = canonicalDigest(shape)
  const token = selectToken(loadTokenStates(root), digest, Date.now())
  if (!token) {
    return { ok: false, text: 'research_os_request: no matching unconsumed preflight token (tokens are single-use and expire). Prepare one first:\n  python3 tools/researchctl.py . prepare payload.json\nwith request_shape:\n  ' + JSON.stringify(shape) }
  }
  consumeToken(root, token)
  const scopeDenied = scopeReasonFor(root, shape.url)
  if (scopeDenied) {
    log('DENY(executor) ' + shape.method + ' ' + shape.url + ' :: ' + scopeDenied)
    return { ok: false, text: scopeDenied }
  }
  let status = null
  let respHeaders = []
  let bodyText = ''
  let error = ''
  try {
    const init = { method: shape.method, redirect: 'manual' }
    if (shape.headers) init.headers = shape.headers
    if (args && args.body !== undefined && args.body !== null && String(args.body).length > 0) init.body = String(args.body)
    const resp = await fetchFn(shape.url, init)
    status = resp.status
    resp.headers.forEach((v, k) => { respHeaders.push(redactHeaderLine(`${k}: ${v}`)) })
    bodyText = await resp.text()
  } catch (e) {
    error = String(e && e.message ? e.message : e)
  }
  const rel = join('08_artifacts', 'raw', `${token.action_id}-${new Date().toISOString().replace(/[:.]/g, '-')}.http`)
  const abs = join(root, rel)
  try {
    mkdirSync(join(root, '08_artifacts', 'raw'), { recursive: true })
    writeFileSync(abs, [
      `# research_os_request — ${shape.method} ${shape.url}`,
      `# action: ${token.action_id} | cycle: ${token.cycle_id} | principal: ${shape.principal} | time: ${new Date().toISOString()}`,
      '',
      '--- request',
      `${shape.method} ${shape.url}`,
      ...(shape.headers ? Object.entries(shape.headers).map(([k, v]) => redactHeaderLine(`${k}: ${v}`)) : []),
      '',
      trunc(redactSecrets(args && args.body), 4000),
      '',
      '--- response',
      status === null ? `ERROR: ${redactSecrets(error)}` : `HTTP ${status}`,
      ...respHeaders,
      '',
      trunc(redactSecrets(bodyText), 40000),
    ].join('\n') + '\n')
  } catch (e) {
    log('executor-capture-error ' + e)
  }
  const relPath = rel.split(sep).join('/')
  const { evidence, recorded } = registerCapture({ root, relPath, token, source: 'controlled-executor' })
  const summary = status === null ? `error: ${error}` : `HTTP ${status}`
  return {
    ok: status !== null,
    text: `research_os_request ${shape.method} ${shape.url} → ${summary}\n- action: ${token.action_id} (token consumed)\n- evidence: ${recorded && evidence ? evidence : (evidence || 'NOT REGISTERED')}\n- capture: ${relPath}\n\n${trunc(redactSecrets(bodyText), 4000)}`,
  }
}

/** Canonical browser request shape (digest input): {url, principal}. */
function browserShapeFromArgs(args) {
  return {
    principal: String((args && args.principal) || ''),
    url: String((args && args.url) || ''),
  }
}

/**
 * R4/R5/R6 — run one controlled BUA browser action. Consumes the matching single-use
 * browser token BEFORE dispatch (crash-safe against replay), re-checks scope, runs the
 * canonical read-only runner (tools/bua/run.mjs) with a dedicated per-engagement
 * profile, writes the run log under 08_artifacts/raw/, registers it as evidence and
 * records the action.
 */
async function runControlledBrowser({ root, args }) {
  const shape = browserShapeFromArgs(args)
  if (!shape.url || !shape.principal) {
    return { ok: false, text: 'research_os_browser requires url and principal (the account label used in the preflight).' }
  }
  const digest = canonicalDigest(shape)
  const token = selectToken(loadTokenStates(root), digest, Date.now(), 'browser')
  if (!token) {
    return { ok: false, text: 'research_os_browser: no matching unconsumed browser preflight token (tokens are single-use and expire). Prepare one first:\n  python3 tools/researchctl.py . prepare payload.json\nwith "tool_family": "browser" and request_shape:\n  ' + JSON.stringify(shape) }
  }
  consumeToken(root, token)
  const scopeDenied = scopeReasonFor(root, shape.url)
  if (scopeDenied) {
    log('DENY(executor) browser ' + shape.url + ' :: ' + scopeDenied)
    return { ok: false, text: scopeDenied }
  }
  const runner = join(root, 'tools', 'bua', 'run.mjs')
  const rel = join('08_artifacts', 'raw', `${token.action_id}-${new Date().toISOString().replace(/[:.]/g, '-')}.browser.log`)
  const abs = join(root, rel)
  let exitCode = null
  let stdout = ''
  let stderr = ''
  let error = ''
  if (!existsSync(runner)) {
    error = 'BUA runner missing: tools/bua/run.mjs (copy the OS template — provisioning task)'
  } else {
    try {
      stdout = execFileSync('node', [runner, '--url', shape.url, '--principal', shape.principal,
        '--out-dir', '08_artifacts/raw', '--action', token.action_id],
      { cwd: root, encoding: 'utf8', timeout: 180000 })
      exitCode = 0
    } catch (e) {
      exitCode = typeof e.status === 'number' ? e.status : -1
      stdout = String(e.stdout || '')
      stderr = String(e.stderr || '')
      if (!stderr) error = String(e.message || e)
    }
  }
  try {
    mkdirSync(join(root, '08_artifacts', 'raw'), { recursive: true })
    writeFileSync(abs, [
      '# research_os_browser — BUA run',
      `# action: ${token.action_id} | cycle: ${token.cycle_id} | principal: ${shape.principal} | time: ${new Date().toISOString()}`,
      '',
      '--- runner',
      `node tools/bua/run.mjs --url ${shape.url} --principal ${shape.principal} --out-dir 08_artifacts/raw --action ${token.action_id}`,
      `exit: ${exitCode === null ? 'not started' : exitCode}`,
      ...(error ? ['error: ' + error] : []),
      '',
      '--- stdout',
      trunc(redactSecrets(stdout), 20000),
      '',
      '--- stderr',
      trunc(redactSecrets(stderr), 8000),
    ].join('\n') + '\n')
  } catch (e) {
    log('executor-capture-error ' + e)
  }
  const relPath = rel.split(sep).join('/')
  const { evidence, recorded } = registerCapture({ root, relPath, token, source: 'browser-executor' })
  const summary = exitCode === 0
    ? 'runner exit 0'
    : `runner ${exitCode === null ? 'not started' : 'exit ' + exitCode}${error ? ' — ' + error : ''}`
  return {
    ok: exitCode === 0,
    text: `research_os_browser ${shape.url} → ${summary}\n- action: ${token.action_id} (token consumed)\n- evidence: ${recorded && evidence ? evidence : (evidence || 'NOT REGISTERED')}\n- capture: ${relPath}\n\n${trunc(stdout, 4000)}`,
  }
}

// ---------- plugin ----------

const TOOL_OUTPUT = {
  schema: { type: 'object', additionalProperties: true },
  render(args, value) {
    const v = value || {}
    return [{ type: 'text', text: String(v.text || v.error || '') }]
  },
}

async function registerExecutor(ctx, tools) {
  let defineTool
  try {
    ({ defineTool } = await import('@deepseek-ai/dsh-tools'))
  } catch (e) {
    log('defineTool import failed: ' + e)
    return
  }
  tools.register(defineTool({
    name: 'research_os_request',
    description: 'Controlled live-request executor for Research OS workspaces. The only sanctioned path for target traffic: it consumes the single-use preflight token (researchctl prepare) whose argument_digest matches method+url+principal(+headers/body), re-checks the request host against the engagement asset list (00_control/engagement.yaml) and refuses out-of-scope targets, executes the HTTP request, stores the capture under 08_artifacts/raw/, registers it as evidence and records the action. Prepare first with the same request_shape, then call this within the token expiry window.',
    parameters: {
      method: { type: 'string', required: true, description: 'HTTP method, e.g. GET or POST' },
      url: { type: 'string', required: true, description: 'Absolute URL; must match the prepared request_shape' },
      principal: { type: 'string', required: true, description: 'Account label used in the preflight, e.g. researcher-A' },
      headers: { type: 'json', description: 'Optional headers object (lowercase keys); included in the digest when present' },
      body: { type: 'string', description: 'Optional request body; contributes body_sha256 to the digest when present' },
    },
    output: TOOL_OUTPUT,
    async execute(args, exec) {
      const root = findOsRoot(sessionCwd(exec))
      if (!root) return { ok: false, text: 'research_os_request: not inside a Research OS workspace.' }
      return await runControlledRequest({ root, args })
    },
  }))
  tools.register(defineTool({
    name: 'research_os_browser',
    description: 'Controlled BUA browser executor for Research OS workspaces. Consumes a browser-family single-use preflight token (researchctl prepare with "tool_family": "browser" and request_shape {url, principal}), re-checks the target host against 00_control/engagement.yaml assets, runs the canonical read-only runner tools/bua/run.mjs (dedicated per-engagement profile, navigate + screenshot; a clear provisioning error until playwright-core + chromium are installed), stores the run log under 08_artifacts/raw/, registers it as evidence and records the action. Interactive or state-changing browser flows use a dedicated task script with its documented precondition, not this tool.',
    parameters: {
      url: { type: 'string', required: true, description: 'Absolute URL; must match the prepared request_shape' },
      principal: { type: 'string', required: true, description: 'Account label used in the preflight, e.g. researcher-A' },
    },
    output: TOOL_OUTPUT,
    async execute(args, exec) {
      const root = findOsRoot(sessionCwd(exec))
      if (!root) return { ok: false, text: 'research_os_browser: not inside a Research OS workspace.' }
      return await runControlledBrowser({ root, args })
    },
  }))
}

function apply(ctx) {
  try {
    const tools = ctx.get('tools')
    if (tools === undefined) {
      console.error('research-os-enforcer: ctx.tools unavailable')
      return
    }
    // Monotonic guard: canonical/projection write protection cannot be undone by a
    // later allow. Denials are logged (guard denials are otherwise invisible in the log).
    tools.guard((exec) => {
      const reason = fsWriteReason(exec) || bashWriteReason(exec)
      if (reason) log('DENY(guard) ' + (exec && exec.name) + ' :: ' + reason)
      return reason
    })
    // Reorderable policy gate: raw network egress is closed inside OS workspaces.
    ctx.on('tools/pre-execute', async (exec, next) => {
      let reason
      try {
        reason = liveGateReason(exec) || browserGateReason(exec)
      } catch (e) {
        log('preexecute-error ' + e)
      }
      if (reason) {
        log('DENY ' + exec.name + ' :: ' + reason)
        return { kind: 'deny', reason }
      }
      return next()
    })
    registerExecutor(ctx, tools).catch((e) => log('executor-register-error ' + e))
    log('APPLY ok')
    console.error('research-os-enforcer: active (projection guard + egress/browser gates + controlled executors)')
  } catch (e) {
    log('apply-error ' + e)
    console.error('research-os-enforcer: apply failed: ' + e)
  }
}

export { name, inject, apply }
// Test surface (pure helpers + executor core): conformance and integration suites.
export { canonicalDigest, shapeFromArgs, browserShapeFromArgs, loadTokenStates, selectToken, runControlledRequest, runControlledBrowser, scopeReasonFor, redactSecrets, redactHeaderLine }
