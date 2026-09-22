/**
 * research-os-enforcer — DSH policy plugin for the Bug Bounty Research OS.
 *
 * Enforcement surfaces (verified against the installed harness API):
 *
 *   1. `tools/pre-execute` waterfall — reorderable policy: allow/deny/ask.
 *   2. `tools.guard()` — monotonic final denial a later listener cannot undo.
 *   3. `research_os_request` / `research_os_browser` tools — the controlled
 *      live-request executors: the ONLY sanctioned path for target traffic.
 *
 * Rules:
 *
 *   R1  Canonical/projection files are write-protected inside any detected Research
 *       OS workspace (fs tools + common shell write shapes): the runtime views, the
 *       freshness/usage views (`10_learning/freshness.yaml`,
 *       `10_learning/knowledge-usage.yaml`), the proposal view and its artifact dir
 *       (`10_learning/knowledge-proposals.yaml`, `10_learning/knowledge-proposals/**`),
 *       the evidence store
 *       (`11_runtime/evidence-store/**`) and — outside BOOTSTRAP —
 *       `00_control/engagement.yaml` + `00_control/identity-binding.yaml` (the agent
 *       may fill those only while BOOTSTRAP; afterwards they are human-owned). Mutate
 *       state through tools/researchctl.py; the OS rebuilds projections on every
 *       mutation.
 *   R2  The event ledger `11_runtime/events.jsonl` is append-only through the control
 *       plane; direct writes are denied.
 *   R3  Raw network egress (curl/wget/ssh/... to a non-local host) is closed in an OS
 *       workspace. Target traffic goes through `research_os_request`; research material
 *       goes through the web tools; localhost/lab traffic is never blocked. Egress
 *       gating is INTERCEPTED (advisory), not a boundary: commands that do not name a
 *       NET_COMMANDS binary — python/node/php/git/npm and bash-invoked CLIs — bypass it. A
 *       web-fetch target gate covers fetch-shaped tools (scrape/crawl/map/parse/
 *       extract/read/fetch/browser/navigate/automation/computer): retrieving an in-scope
 *       asset host through one of them is denied (preflight + executor instead),
 *       out-of-scope research material and search tools stay allowed, and JSON-escaped
 *       URLs are decoded before matching.
 *   R4  `research_os_request` is single-use bound: it consumes the preflight token
 *       issued by `python3 tools/researchctl.py <root> prepare payload.json` whose
 *       `argument_digest` matches the call's canonical shape
 *       ({method, url, principal[, headers][, body_sha256]}), then executes, stores a
 *       request/response capture under 08_artifacts/raw/, registers it as evidence and
 *       records the action through the control plane. Requests time out
 *       (RESEARCH_OS_HTTP_TIMEOUT_MS, default 30s), response bodies stop at
 *       RESEARCH_OS_MAX_BODY_BYTES (default 5 MB) with the capture marked truncated,
 *       sensitive query-parameter values are masked in capture lines, tool text and
 *       DENY(executor) log lines, and the receipt is transactional: a failed
 *       registration/record after the request was sent returns ok:false with the
 *       "do not rely on this action as receipted" warning.
 *   R5  The executor reads per-host scope from `00_control/engagement.yaml` assets
 *       (same semantics as `researchctl prepare`: simple string list, `*.domain`
 *       wildcards, host[:port] compared exactly) and refuses out-of-scope targets
 *       before dispatch — a hand-crafted or stale token cannot widen scope. Absent or
 *       empty assets deny (scope unset: record it with `researchctl scope-set`, or set
 *       an explicit `gate: none` inside the `scope:` block for non-target work);
 *       unparseable assets deny as unenforceable. The token store
 *       `11_runtime/action-tokens.jsonl` is control-plane-owned (write-protected like a
 *       projection).
 *   R6  Raw browser-automation launches inside an OS workspace are denied outside the
 *       browser executor: prepare with tool_family "browser" and call
 *       `research_os_browser`, which runs the canonical read-only runner
 *       (tools/bua/run.mjs — dedicated profile, scope guard, capture) and records the
 *       action. Install-shaped commands and explicit-localhost work stay allowed;
 *       install shape is judged per command segment (`&&`/`||`/`;`/`|`), so an install
 *       segment cannot stand the gate down for a later browser segment.
 *   R7  Broker policy (tools/broker/): when a broker socket is present the broker is
 *       MANDATORY — a token without `broker_sig` is refused (re-prepare), BOTH the local
 *       engagement binding and the broker policy copy must allow the target, and the
 *       token is consumed THROUGH THE BROKER before dispatch (a broker refusal or an
 *       unreachable broker fails closed — no dispatch). The local trust path survives
 *       only when no broker socket exists.
 *
 * v1 limits (documented, deliberate): the digest canonicalizes the shape (method
 * uppercased, lowercase header keys, body folded into body_sha256) exactly as the
 * Python prepare side does; the
 * controlled executor speaks HTTP(S) only; the browser arm is read-only (navigate +
 * capture) — interactive or state-changing flows use a dedicated task script with its
 * documented precondition; command-pattern gating cannot see a browser launch or a
 * network call hidden inside an arbitrary interpreter script or bash-invoked CLI, so
 * the runner + token stays the sanctioned path.
 *
 * Failure mode: internal errors fail OPEN (log line + allow), with three deliberate
 * exceptions: executor-side scope checks fail CLOSED, the web-fetch gate fails CLOSED
 * (including when the engagement scope file cannot be read), and a write guard that
 * throws while the call mentions protected material fails CLOSED (a guard crash must not
 * smuggle a protected write). The conformance and executor-integration suites keep the
 * rules honest; the OS audit stays the source of truth. Log:
 * ~/.dsh/research-os-enforcer.log
 */
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { appendFileSync, closeSync, existsSync, mkdirSync, openSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import net from 'node:net'
import { homedir, tmpdir } from 'node:os'
import { isAbsolute, join, resolve, sep } from 'node:path'

const name = 'research-os-enforcer'
const inject = ['tools']

const OS_MARKER = 'OS_VERSION'
const LEDGER_REL = '11_runtime/events.jsonl'
const TOKENS_REL = '11_runtime/action-tokens.jsonl'
const SCOPE_DIRTY_REL = '11_runtime/.scope-sync-dirty'

// The engagement binding files are bootstrap-conditional: the agent fills them during
// BOOTSTRAP; afterwards only direct human edits are legitimate.
const BOOTSTRAP_CONDITIONAL = /^00_control\/(engagement|identity-binding)\.yaml$/

// Paths the control plane owns. Matched against a workspace-relative POSIX path.
const PROTECTED_PATTERNS = [
  /^11_runtime\/(events\.jsonl|run-status\.yaml|active-cycle\.yaml|evidence-index\.jsonl|current-context\.md|last-result\.md|action-tokens\.jsonl)$/,
  /^11_runtime\/\.scope-sync-dirty$/,
  /^11_runtime\/\.token-claims\//,
  /^11_runtime\/human-gates\/[^/]+\.yaml$/,
  /^11_runtime\/evidence-store\//,
  /^04_cycles\/[^/]+\/plan\.yaml$/,
  /^03_hypotheses\/(active|archive)\/[^/]+\.yaml$/,
  /^06_audits\/closure-readiness\.yaml$/,
  /^10_learning\/technique-discoveries\.md$/,
  /^10_learning\/freshness\.yaml$/,
  /^10_learning\/knowledge-usage\.yaml$/,
  /^10_learning\/knowledge-proposals\.yaml$/,
  /^10_learning\/knowledge-proposals\//,
  BOOTSTRAP_CONDITIONAL,
]

// Case-insensitive markers for fail-closed guard errors: when a guard throws on a call
// that names protected material, deny instead of failing open.
const PROTECTED_MARKERS = [
  'events.jsonl', 'action-tokens.jsonl', 'run-status.yaml', 'active-cycle.yaml',
  'evidence-index.jsonl', 'current-context.md', 'last-result.md', 'closure-readiness.yaml',
  'freshness.yaml', 'evidence-store', 'engagement.yaml', 'identity-binding.yaml',
  'technique-discoveries.md', '04_cycles', '03_hypotheses',
  'knowledge-usage.yaml', 'knowledge-proposals.yaml', 'knowledge-proposals/',
  'os_version', 'scope-sync-dirty', 'token-claims',
]

// Static protected files and directories the control plane owns. A destructive target
// that equals or is an ancestor of any entry here is denied: `rm -rf 11_runtime` deletes
// control-plane-owned material just as surely as writing one protected file.
const PROTECTED_TARGETS = [
  '11_runtime/events.jsonl', '11_runtime/run-status.yaml', '11_runtime/active-cycle.yaml',  '11_runtime/evidence-index.jsonl', '11_runtime/current-context.md', '11_runtime/last-result.md',
  '11_runtime/action-tokens.jsonl', '11_runtime/.scope-sync-dirty', '11_runtime/.token-claims', '11_runtime/human-gates', '11_runtime/evidence-store',
  '04_cycles', '03_hypotheses/active', '03_hypotheses/archive',
  '06_audits/closure-readiness.yaml', '10_learning/technique-discoveries.md',
  '10_learning/freshness.yaml', '10_learning/knowledge-usage.yaml',
  '10_learning/knowledge-proposals.yaml', '10_learning/knowledge-proposals',
  '00_control/engagement.yaml', '00_control/identity-binding.yaml',
  'OS_VERSION',
]

// Commands that reach the network (see hasNetCommand). Deliberately narrow:
// package installs and git operations are provisioning, not target access.
const NET_COMMANDS = new Set(['curl', 'wget', 'http', 'httpie', 'nc', 'ncat', 'nmap',
  'socat', 'dig', 'nslookup', 'host', 'ssh', 'scp'])
/** Wrapper prefixes whose own flags/values precede the real command word. `command`,
 *  `exec` and `busybox` take the real command as their next word; `{`/`}` group
 *  commands (`{ curl …; }`) and are skipped the same way. */
const NET_WRAPPERS = new Set(['env', 'sudo', 'nohup', 'time', 'nice', 'timeout', 'stdbuf', 'xargs', 'command', 'exec', 'busybox'])
/** Index of the command word after skipping wrapper prefixes (with their flags). */
function netCommandIndex(words) {
  let i = 0
  while (i < words.length) {
    const w = stripQuotes(words[i])
    if (w === '{' || w === '}' || w === '!') { i++; continue }
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) { i++; continue }
    const base = w.toLowerCase().split(/[/\\]/).pop()
    if (!NET_WRAPPERS.has(base)) break
    i++
    const takeValue = (flags) => {
      while (i < words.length) {
        const raw = words[i]
        const ww = stripQuotes(raw)
        if (ww === '--') { i++; break }
        if (!(ww.startsWith('-') && ww.length > 1 && ww !== '-')) break
        if (!ww.includes('=') && flags.test(ww)) { i++; if (i < words.length) i++; continue }
        if (!ww.includes('=') && /^-(I|n|P|s|d|a|E)/.test(ww) && ww.length > 2) { i++; continue }
        i++
      }
    }
    if (base === 'env') {
      while (i < words.length) {
        const ww = stripQuotes(words[i])
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(ww)) { i++; continue }
        if (ww.startsWith('-') && ww.length > 1 && ww !== '-') {
          if (!ww.includes('=') && /^(-u|--user|--unset|--chdir)$/.test(ww)) { i++; if (i < words.length) i++ }
          else i++
          continue
        }
        break
      }
    } else if (base === 'sudo') takeValue(/^(-u|-g|-h|-p|-C|-D|--user|--group|--host|--prompt|--chdir)$/)
    else if (base === 'timeout') {
      takeValue(/^(-s|-k|--signal|--kill-after)$/)
      if (i < words.length && /^[\d.]+[smhd]?$/.test(stripQuotes(words[i]))) i++
    } else if (base === 'nice') takeValue(/^(-n|--adjustment)$/)
    else if (base === 'stdbuf') takeValue(/^(-i|-o|-e|--input|--output|--error)$/)
    else if (base === 'xargs') takeValue(/^(-I|-n|-P|-s|-d|-a|-E|--replace|--max-args|--max-procs|--max-chars|--delimiter|--arg-file|--eof)$/)
    else takeValue(/^(--format|--output|-f|-o)$/)
  }
  return i
}
/** True when any command segment starts a network binary: quotes stripped, basename
 *  after the last `/` (so `'curl'` and `/usr/bin/curl` both count), wrapper prefixes
 *  (`env`, `sudo`, `nohup`, `time`, `nice`, `timeout`, `stdbuf`, `xargs` with their
 *  own flags) and `VAR=x` prefixes skipped, `openssl` only with `s_client`. */
function hasNetCommand(cmd) {
  const segments = normalizeIfs(cmd).replace(/["']/g, '').split(/&&|\|\||[;|&()\n]/)
  for (const seg of segments) {
    const words = seg.trim().split(/\s+/).filter(Boolean)
    if (words.length === 0) continue
    const idx = netCommandIndex(words)
    if (idx >= words.length) continue
    const base = stripQuotes(words[idx]).toLowerCase().split(/[/\\]/).pop()
    if (NET_COMMANDS.has(base)) return true
    if (base === 'openssl' && /\bs_client\b/.test(seg)) return true
  }
  return false
}
/** True for exactly the loopback exemption: `localhost`, `*.localhost`,
 *  `127.0.0.0/8` or `[::1]` — a path substring never qualifies. */
function isLoopbackHostname(name) {
  let h = String(name || '').toLowerCase()
  if (h.endsWith('.')) h = h.slice(0, -1)
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1)
  if (h === 'localhost' || h.endsWith('.localhost') || h === '::1') return true
  const octets = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/)
  return !!octets && Number(octets[1]) === 127 && octets.slice(2).every((o) => Number(o) <= 255)
}
/** True when the URL's authority is unambiguously a loopback host: the manual
 *  authority parse (WHATWG-cross-checked, "" on ambiguity) reduced to its hostname,
 *  WHATWG-normalized (so `127.1` and hex/octal forms judge as the loopback they are).
 *  Unexpanded variable ports (`localhost:$PORT`) are WHATWG-unparseable: fall back
 *  to the manual hostname so loopback stays exempt while `evil.example:$PORT`
 *  still denies. Ambiguous authorities (backslash, whitespace, %5c) still deny. */
function urlLoopbackExempt(url) {
  const host = hostFromUrl(url)
  if (host) {
    let name = host.startsWith('[') ? host.slice(0, host.indexOf(']') + 1) : host.split(':')[0]
    try {
      name = new URL(`http://${name}/`).hostname.toLowerCase()
    } catch {
      return false
    }
    return isLoopbackHostname(name)
  }
  const s = String(url || '')
  if (!s.includes('://')) return false
  const rest = s.slice(s.indexOf('://') + 3)
  let end = rest.length
  for (const term of ['/', '?', '#']) {
    const i = rest.indexOf(term)
    if (i >= 0) end = Math.min(end, i)
  }
  const manual = normalizeHost(rest.slice(0, end))
  if (!manual) return false
  let name = manual.startsWith('[') ? manual.slice(0, manual.indexOf(']') + 1) : manual.split(':')[0]
  try {
    name = new URL(`http://${name}/`).hostname.toLowerCase()
  } catch {
    name = String(name || '').toLowerCase()
  }
  return isLoopbackHostname(name)
}
/** Flags whose values are not destinations (headers, data, method, credentials,
 *  output files): skipped when deriving schemeless targets. `--url` is NOT here —
 *  its value IS a destination. */
const EGRESS_VALUE_FLAGS = /^(-H|--header|-d|--data|--data-raw|--data-ascii|--data-binary|--data-urlencode|--request|-X|-u|--user|-o|-O|--output|-e|--referer|--user-agent|-A|-p|--port|--proxy|-x|--resolve|--connect-to)$/
/** Bare non-flag arguments of net-command segments as schemeless host parts
 *  (cut at the first `/`, `?` or `#`; URL tokens, pure ports and flag values
 *  excluded). Empty when the command names no bare destination. */
function schemelessTargets(cmd) {
  const out = []
  for (const seg of splitSegments(normalizeIfs(cmd))) {
    const words = shellWords(seg.trim())
    if (words.length === 0) continue
    const idx = netCommandIndex(words)
    if (idx >= words.length) continue
    const base = stripQuotes(words[idx]).toLowerCase().split(/[/\\]/).pop()
    if (!NET_COMMANDS.has(base) && !(base === 'openssl' && /\bs_client\b/.test(seg))) continue
    let j = idx + 1
    while (j < words.length) {
      const w = stripQuotes(words[j])
      if (w === '--') { j++; continue }
      if (w.startsWith('-') && w.length > 1 && w !== '-') {
        const eq = w.indexOf('=')
        if (eq > 0 && w.slice(0, eq) === '--url' && w.slice(eq + 1)) {
          const val = w.slice(eq + 1)
          if (!val.includes('://')) {
            let hostpart = val
            if (hostpart.startsWith('//')) hostpart = hostpart.slice(2)
            hostpart = hostpart.split('/')[0].split('?')[0].split('#')[0].trim()
            if (hostpart) out.push(hostpart)
          }
          j++
          continue
        }
        if (!w.includes('=') && EGRESS_VALUE_FLAGS.test(w)) { j++; if (j < words.length) j++; continue }
        j++
        continue
      }
      if (w.includes('://')) { j++; continue }
      if (/^\d+$/.test(w)) { j++; continue }
      if (w === '-') { j++; continue }
      let hostpart = w
      if (hostpart.startsWith('//')) hostpart = hostpart.slice(2)
      hostpart = hostpart.split('/')[0].split('?')[0].split('#')[0].trim()
      if (hostpart) out.push(hostpart)
      j++
    }
  }
  return out
}
/** True when every bare destination is an exact loopback host (at least one).
 *  Unparseable hosts fail closed (not exempt). */
function schemelessLoopbackExempt(cmd) {
  const targets = schemelessTargets(cmd)
  if (targets.length === 0) return false
  return targets.every((h) => urlLoopbackExempt('http://' + h + '/'))
}
const LOCAL_HOST = /(^|[\s/@:.])(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0|::1|\.local|\.internal)([\s/:'"]|$)/i
const WRITE_TOKEN = /(>>?|\btee\b|sed\s+-i|\btruncate\b|\bcp\b|\bmv\b|\bdd\b|\binstall\b|python3?\s+-\s*<<|cat\s*<<)/
const BROWSER_LAUNCH = /\b(playwright|puppeteer|selenium|selenium-webdriver|chromedriver|geckodriver)\b|--headless\b|--remote-debugging-port\b|chrome-headless-shell/
// Install-shaped package queries (provisioning, not target access). `npx` is special:
// the package name sits between `npx` and the install verb (`npx playwright install
// chromium` is the browser runner's own provisioning instruction), so only an explicit
// install/query verb after the package counts — `npx playwright test <url>` stays gated.
const PM_QUERY = /(^|[\s;&|(])(npm|pnpm|yarn|bun)\s+(i|install|add|ls|list|view|info|why|audit|outdated)\b|\bpip3?\s+install\b|\bnpx(\s+-{1,2}[\w=-]+)*\s+[A-Za-z0-9@][\w@./-]*\s+(i|install|add|ls|list|view|info|why|audit|outdated)\b|--version\b/

// Capture hygiene (29_SECURITY_HYGIENE: RAW -> SANITIZE -> REFERENCE). Values in these
// headers never reach a capture; secret-shaped strings in any text are redacted on write.
const SENSITIVE_HEADERS = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-access-token|api-key|x-csrf-token)\b/i
// BEGIN-GENERATED-SECRET-PATTERNS
// Source of truth: tools/secret-patterns.json — do not hand-edit; run python3 tools/generate_secret_patterns.py.
const SECRET_SHAPES = [
  /glpat-[A-Za-z0-9_.-]{16,}/g,
  /github_pat_[A-Za-z0-9_]{20,}/g,
  /gh[pousr]_[A-Za-z0-9]{16,}/g,
  /xox[baprs]-[A-Za-z0-9-]{10,}/g,
  /AKIA[0-9A-Z]{16}/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
  /eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\./g,
]
// END-GENERATED-SECRET-PATTERNS

function log(line) {
  try { appendFileSync(homedir() + '/.dsh/research-os-enforcer.log', new Date().toISOString() + ' ' + line + '\n') } catch {}
}

function sessionCwd(exec) {
  const cwd = exec && exec.agent && exec.agent.session && exec.agent.session.header && exec.agent.session.header.cwd
  return typeof cwd === 'string' && cwd ? cwd : undefined
}

/** Walk up from cwd looking for a Research OS workspace root.
 *
 *  Detection must survive ledger deletion (an interpreter bypass deletes the ledger to
 *  disarm the enforcer), so OS_VERSION alone is not enough but the ledger is not
 *  required either: any one of the ledger, the engagement binding or the runtime
 *  directory marks the workspace. Detection must also survive deletion of the
 *  OS_VERSION marker itself (removing the marker would otherwise disarm every rule):
 *  when the marker is gone but any other workspace marker is present, the directory
 *  is still a workspace (fail closed). A directory with none of the markers is
 *  unaffected.
 */
function findOsRoot(cwd) {
  if (!cwd) return undefined
  let dir = resolve(cwd)
  for (let i = 0; i < 12; i++) {
    try {
      const other = existsSync(join(dir, LEDGER_REL))
        || existsSync(join(dir, '00_control', 'engagement.yaml'))
        || existsSync(join(dir, '11_runtime'))
      if (other) return dir
    } catch {}
    const parent = resolve(dir, '..')
    if (parent === dir) break
    dir = parent
  }
  return undefined
}

/** Workspace-relative posix paths for an absolute path inside root.
 *
 *  The lexical resolution plus, when the target exists, the symlink-resolved one
 *  (macOS `/var` → `/private/var`, case-insensitive variants, in-workspace
 *  symlinks pointing at protected files): a write through any name of a protected
 *  file is judged against the protected file. Returns [] when outside the root. */
function relsFor(root, abs) {
  const rels = []
  const lex = relPosix(root, abs)
  if (lex !== undefined) rels.push(lex)
  try {
    const realRoot = realpathSync(root)
    const real = realpathSync(abs)
    const r = relPosix(realRoot, real)
    if (r !== undefined && !rels.includes(r)) rels.push(r)
  } catch {}
  return rels
}

/** Workspace-relative posix path for an absolute path inside root, else undefined. */
function relPosix(root, abs) {
  const r = resolve(root)
  const a = resolve(abs)
  if (a !== r && !a.startsWith(r + sep)) return undefined
  return a.slice(r.length + 1).split(sep).join('/')
}

function protectedReason(rel, root) {
  if (rel === OS_MARKER) {
    return 'research-os-enforcer: OS_VERSION is the workspace marker — removing or editing it disarms every rule, so direct writes are denied.'
  }
  // Case-insensitive filesystems (default macOS APFS) resolve `11_RUNTIME/...` to
  // the real protected file: match casefolded, but keep the as-written rel in the
  // message text (user-visible messages unchanged).
  const low = String(rel).toLowerCase()
  if (low === OS_MARKER.toLowerCase()) {
    return 'research-os-enforcer: OS_VERSION is the workspace marker — removing or editing it disarms every rule, so direct writes are denied.'
  }
  for (const re of PROTECTED_PATTERNS) {
    if (!re.test(low)) continue
    if (re === BOOTSTRAP_CONDITIONAL) {
      const st = root ? osStatus(root) : undefined
      if (st && st.engagement === 'BOOTSTRAP') return undefined
      return `research-os-enforcer: ${rel} binds the engagement — the agent may write it only during BOOTSTRAP; afterwards only direct human edits are legitimate.`
    }
    if (rel === LEDGER_REL) {
      return `research-os-enforcer: ${LEDGER_REL} is the canonical append-only ledger — mutate it only through tools/researchctl.py (no direct writes).`
    }
    if (rel === TOKENS_REL) {
      return `research-os-enforcer: ${TOKENS_REL} holds single-use preflight tokens — mint them through python3 tools/researchctl.py <root> prepare; direct writes are denied.`
    }
    if (rel.startsWith('11_runtime/evidence-store/')) {
      return `research-os-enforcer: ${rel} is inside the content-addressed evidence store — register evidence through tools/researchctl.py; direct writes are denied.`
    }
    return `research-os-enforcer: ${rel} is a control-plane projection/view — do not edit it by hand. Mutate state through tools/researchctl.py; the OS rebuilds this file on every mutation.`
  }
  return undefined
}

/** Deny a destructive target that equals or is an ancestor of protected material.
 *
 *  The per-file `protectedReason` sees only exact paths; this catches the directory
 *  shapes (`rm -rf 11_runtime`, `rm 11_runtime/*`, `mv 04_cycles /tmp/x`) that would
 *  delete protected files wholesale. The resolved rel path must be non-empty (root)
 *  and every statically-known protected file/dir is checked for containment.
 */
function ancestorProtectedReason(rel, root) {
  if (rel === '') {
    return 'research-os-enforcer: refusing to destroy the workspace root — it contains control-plane-owned material. Mutate state through tools/researchctl.py; the OS rebuilds projections on every mutation.'
  }
  // Casefolded like protectedReason: `rm -rf 11_RUNTIME` deletes the same material.
  const low = String(rel).toLowerCase()
  const st = root ? osStatus(root) : undefined
  for (const p of PROTECTED_TARGETS) {
    const pl = p.toLowerCase()
    if (low !== pl && !pl.startsWith(low + '/')) continue
    if (low === pl && BOOTSTRAP_CONDITIONAL.test(pl) && st && st.engagement === 'BOOTSTRAP') continue
    return `research-os-enforcer: '${rel}' contains control-plane-owned material (${p}) — directory-level destruction is denied. Mutate state through tools/researchctl.py; the OS rebuilds projections on every mutation.`
  }
  return undefined
}

/** Does this text mention control-plane-owned material? (case-insensitive) */
function mentionsProtected(text) {
  const t = String(text == null ? '' : text).toLowerCase()
  return PROTECTED_MARKERS.some((marker) => t.includes(marker))
}

/** Serialize a call's arguments for marker scanning without ever throwing. */
function argsText(exec) {
  try { return JSON.stringify((exec && exec.arguments) || {}) } catch { return '' }
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
    for (const rel of relsFor(root, abs)) {
      const reason = protectedReason(rel, root)
      if (reason) return reason
    }
    return undefined
  } catch (e) {
    log('guard-fs-error ' + e)
    if (mentionsProtected(argsText(exec))) {
      return 'research-os-enforcer: the write guard could not evaluate the write target and this call touches protected state — refusing (failing closed). Mutate protected state through tools/researchctl.py; retry without the protected path if this call was unrelated.'
    }
    return undefined
  }
}

/** Strip ALL quote characters from an extracted target (shell quote-concatenation:
 *  `11_runtime/"events.jsonl"`, `"11_runtime"/events.jsonl` and
 *  `11_runtim"e"/events.jsonl` all open the protected file). ANSI-C `$'…'` and
 *  locale `$"…"` quote the same way: drop the `$` prefix so the resolved path
 *  is judged (`11_runtime/$'events.jsonl'` is the protected file). */
function stripQuotes(token) {
  return String(token).replace(/\$(?=['"])/g, '').replace(/["']/g, '')
}

/** Normalize `$IFS`/`${IFS}` to whitespace for command tokenization (bash splits
 *  words on the expanded value). Quote-aware: occurrences inside single or double
 *  quotes stay literal — inside single quotes bash performs no expansion, and inside
 *  double quotes the expansion never splits words — so `'${IFS}'` and `"a${IFS}b"`
 *  are not separators. Backslash-escaped `$` never expands. */
function normalizeIfs(cmd) {
  const s = String(cmd)
  let out = ''
  let quote = null
  for (let i = 0; i < s.length;) {
    const c = s[i]
    if (quote) {
      if (quote === '"' && c === '\\' && i + 1 < s.length) { out += c + s[i + 1]; i += 2; continue }
      out += c
      if (c === quote) quote = null
      i++
      continue
    }
    if (c === '\\' && i + 1 < s.length) { out += c + s[i + 1]; i += 2; continue }
    if (c === '"' || c === "'") { quote = c; out += c; i++; continue }
    if (s.startsWith('${IFS}', i)) { out += ' '; i += 6; continue }
    if (s.startsWith('$IFS', i)) { out += ' '; i += 4; continue }
    out += c
    i++
  }
  return out
}

/** Expand `{a,b,...}` groups recursively with nesting (bash semantics). A group
 *  without a top-level comma is not an expansion (`{a}` stays literal). Depth is
 *  tracked (cap 10); an unbalanced brace fails closed to the static prefix before
 *  the `{`, which the target judges as a directory-level hit when it can reach
 *  protected material. Braces inside single/double quotes never expand (shell
 *  semantics), so `rm "11_runtime/{events.jsonl,y}"` is a literal path. */
function braceExpand(token, depth = 0) {
  const s = String(token)
  const open = firstUnquoted(s, '{', 0)
  if (open < 0) return [s]
  if (depth > 10) return [s.slice(0, open)]
  let level = 0
  let close = -1
  let quote = null
  for (let i = open; i < s.length; i++) {
    const c = s[i]
    if (quote) {
      if (c === quote) quote = null
      continue
    }
    if (c === '"' || c === "'") { quote = c; continue }
    if (c === '{') level++
    else if (c === '}') {
      level--
      if (level === 0) { close = i; break }
    }
  }
  if (close < 0) return [s.slice(0, open)]
  const inner = s.slice(open + 1, close)
  const parts = []
  let cur = ''
  let nest = 0
  quote = null
  for (let i = 0; i < inner.length; i++) {
    const c = inner[i]
    if (quote) {
      cur += c
      if (c === quote) quote = null
      continue
    }
    if (c === '"' || c === "'") { quote = c; cur += c; continue }
    if (c === '{') nest++
    else if (c === '}') nest--
    if (c === ',' && nest === 0) { parts.push(cur); cur = '' }
    else cur += c
  }
  parts.push(cur)
  if (parts.length < 2) return [s]
  return parts.flatMap((part) => braceExpand(s.slice(0, open) + part + s.slice(close + 1), depth + 1))
}

/** Index of the first `ch` at or after `from` outside any quoted span. */
function firstUnquoted(s, ch, from) {
  let quote = null
  for (let i = from; i < s.length; i++) {
    const c = s[i]
    if (quote) {
      if (c === quote) quote = null
      continue
    }
    if (c === '"' || c === "'") { quote = c; continue }
    if (c === ch) return i
  }
  return -1
}

/** Translate a shell glob to a RegExp over one path level (`*` never crosses `/`). */
function globToRegExp(pattern) {
  let out = ''
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]
    if (c === '*') out += '[^/]*'
    else if (c === '?') out += '[^/]'
    else if (c === '[') {
      const close = pattern.indexOf(']', i + 1)
      out += close < 0 ? '\\[' : pattern.slice(i, close + 1)
      if (close >= 0) i = close
    } else if ('\\.+^${}()|'.includes(c)) out += '\\' + c
    else out += c
  }
  return new RegExp('^' + out + '$')
}

/** Expand a glob token against the filesystem. Returns the matching absolute paths,
 *  or null when the parent directory cannot be read (unresolvable — callers fail
 *  closed on the static prefix instead). */
function expandGlob(base, token) {
  const absPattern = isAbsolute(token) ? token : join(base, token)
  const wildAt = absPattern.search(/[*?\[]/)
  const slash = absPattern.slice(0, wildAt).lastIndexOf(sep)
  const dir = slash < 0 ? base : absPattern.slice(0, slash)
  let names
  try {
    names = readdirSync(dir)
  } catch {
    return null
  }
  const re = globToRegExp(absPattern)
  return names.map((name) => join(dir, name)).filter((p) => re.test(p))
}

/** Fail-closed static-prefix rule for unresolvable globs: deny when the literal
 *  prefix before the first wildcard can reach protected material — i.e. it equals,
 *  contains, or string-prefixes a protected path (so `11_runtim*` cannot slip past
 *  `11_runtime/`). A bare leading wildcard denies (it can reach anything). */
function prefixReachesProtected(root, base, token) {
  const wildAt = token.search(/[*?\[]/)
  if (wildAt <= 0) return true
  const abs = isAbsolute(token.slice(0, wildAt)) ? token.slice(0, wildAt) : join(base, token.slice(0, wildAt))
  for (const rel of relsFor(root, abs)) {
    const low = rel.toLowerCase()
    for (const p of PROTECTED_TARGETS) {
      const pl = p.toLowerCase()
      if (pl.startsWith(low) || low.startsWith(pl)) return true
    }
  }
  return false
}

/** Judge one extracted target token (braces expanded quote-aware, then quotes
 *  stripped, globs resolved) against every applicable base. Returns the denial
 *  reason or undefined. */
function targetReason(root, bases, token) {
  for (const raw of braceExpand(String(token))) {
    const variant = stripQuotes(raw)
    if (/[*?\[]/.test(variant)) {
      let matches = null
      for (const base of bases) {
        const expanded = expandGlob(base, variant)
        if (expanded === null) continue
        matches = (matches || []).concat(expanded)
      }
      if (matches !== null && matches.length > 0) {
        for (const abs of matches) {
          for (const rel of relsFor(root, abs)) {
            const reason = protectedReason(rel, root) || ancestorProtectedReason(rel, root)
            if (reason) return reason
          }
        }
        continue
      }
      for (const base of bases) {
        if (prefixReachesProtected(root, base, variant)) {
          return `research-os-enforcer: '${variant}' is an unresolvable glob whose static prefix can reach control-plane-owned material — refusing (failing closed). Mutate state through tools/researchctl.py; the OS rebuilds projections on every mutation.`
        }
      }
      continue
    }
    for (const base of bases) {
      const abs = isAbsolute(variant) ? variant : join(base, variant)
      for (const rel of relsFor(root, abs)) {
        const reason = protectedReason(rel, root) || ancestorProtectedReason(rel, root)
        if (reason) return reason
      }
    }
  }
  return undefined
}
/** Split a command into header lines and heredoc bodies.
 *
 *  Returns { stripped, bodies }: `stripped` keeps every line except heredoc body
 *  lines — headers carrying the `<<MARKER` operator and closing markers stay, so
 *  redirect targets and command words there are still judged; `bodies` holds the
 *  removed body text for the conditional body sweep. A body line is inert text
 *  unless it lands in the workspace (a redirect target resolving inside the root)
 *  or feeds an interpreter's stdin — otherwise scanning it is a false positive
 *  (a `/`-sweep hit, or a NET_COMMANDS/browser-launch match on documentation text).
 *  `<<<` herestrings never start a body; `<<-` allows tab-indented closers;
 *  multiple heredocs queue in order; an unterminated heredoc swallows the rest
 *  (shell semantics). A `<<` inside a quoted span is literal text, not an operator,
 *  so `echo "a << b"` cannot hide later lines from detection.
 */
const HEREDOC_OP = /<<(?!<)(-?)\s*(?:'([^']+)'|"([^"]+)"|\\([^\s;&|()<>]+)|([^\s;&|()<>]+))/g
/** True when the line offset sits inside a single/double-quoted span (rough shell
 *  quoting: backslash escapes skipped). A `<<` inside quotes is literal text, not a
 *  heredoc operator, so `echo "a << b"` cannot hide later lines from detection. */
function inQuotes(line, index) {
  let single = false
  let double = false
  for (let i = 0; i < index; i++) {
    const c = line[i]
    if (c === '\\') { i++; continue }
    if (c === "'" && !double) single = !single
    else if (c === '"' && !single) double = !double
  }
  return single || double
}
function splitHeredocs(cmd) {
  const kept = []
  const bodies = []
  const pending = []
  for (const line of String(cmd).split('\n')) {
    if (pending.length > 0) {
      const cur = pending[0]
      const closer = cur.dash ? line.replace(/^\t+/, '') : line
      if (closer === cur.marker) {
        kept.push(line)
        pending.shift()
      } else {
        bodies.push(line)
      }
      continue
    }
    kept.push(line)
    HEREDOC_OP.lastIndex = 0
    let m
    while ((m = HEREDOC_OP.exec(line)) !== null) {
      const marker = m[2] ?? m[3] ?? m[4] ?? m[5]
      if (!marker) continue
      if (inQuotes(line, m.index)) continue
      pending.push({ marker, dash: m[1] === '-' })
    }
  }
  return { stripped: kept.join('\n'), bodies }
}

/** True when a redirect/extraction token resolves inside the workspace root. */
function targetInsideRoot(root, bases, tok) {
  for (const raw of braceExpand(String(tok))) {
    const variant = stripQuotes(raw)
    const plain = variant.search(/[*?\[]/) >= 0
      ? variant.slice(0, variant.search(/[*?\[]/))
      : variant
    for (const base of bases) {
      const abs = isAbsolute(plain) ? plain : join(base, plain)
      if (relsFor(root, abs).length > 0) return true
    }
  }
  return false
}

// A heredoc body is a program, not data, only when it feeds an interpreter's
// stdin (`python3 - <<'PY'`, `cat <<'EOF' | python3 -`): otherwise the body sweep
// below stays off and inert text cannot deny.
const INTERP_STDIN_HEREDOC = /\b(python3?|node|perl|ruby|php|sh|bash|zsh)\s+-\s*<</
const PIPE_TO_INTERP = /\|\s*(python3?|node|perl|ruby|php|sh|bash|zsh)\b/
/** Split one shell segment into words with crude quote awareness (quotes group but
 *  are kept on the word; the caller strips them). */
function shellWords(text) {
  const words = []
  let cur = ''
  let quote = null
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (quote) {
      cur += c
      if (c === quote) quote = null
    } else if (c === '"' || c === "'") {
      quote = c
      cur += c
    } else if (/\s/.test(c)) {
      if (cur) { words.push(cur); cur = '' }
    } else {
      cur += c
    }
  }
  if (cur) words.push(cur)
  return words
}

/** Split a command into segments on `&&`, `||`, `;`, `|`, `&`, parens and newlines —
 *  but never inside a quoted span, so an inline payload (`-c "open(…)"`) stays one
 *  segment with its interpreter word. */
function splitSegments(cmd) {
  const segments = []
  let cur = ''
  let quote = null
  const push = () => { segments.push(cur); cur = '' }
  for (let i = 0; i < String(cmd).length; i++) {
    const c = cmd[i]
    if (quote) {
      cur += c
      if (c === quote) quote = null
      continue
    }
    if (c === '"' || c === "'") { quote = c; cur += c; continue }
    if (c === '&' && cmd[i + 1] === '&') { push(); i++; continue }
    if (c === '|' && cmd[i + 1] === '|') { push(); i++; continue }
    if (c === ';' || c === '|' || c === '&' || c === '(' || c === ')' || c === '\n') { push(); continue }
    cur += c
  }
  push()
  return segments
}

const INLINE_INTERP = new Set(['python3', 'python', 'node', 'perl', 'ruby', 'php', 'sh', 'bash', 'zsh'])
/** Break backtick command substitutions into segments: `` echo `python3 -c …` ``
 *  executes the inner command, so the inner text is judged as a command, not as
 *  data to `echo`. Backticks inside single quotes are literal and kept. */
function breakBackticks(cmd) {
  let out = ''
  let single = false
  let double = false
  for (let i = 0; i < String(cmd).length; i++) {
    const c = cmd[i]
    if (c === '\\' && !single) { out += c; if (i + 1 < String(cmd).length) out += String(cmd)[++i]; continue }
    if (c === "'" && !double) { single = !single; out += c; continue }
    if (c === '"' && !single) { double = !double; out += c; continue }
    if (c === '`' && !single) { out += ';'; continue }
    out += c
  }
  return out
}
// A payload naming control-plane-owned material: the guard's marker list plus the
// runtime/control dir prefixes (a payload can destroy `11_runtime` wholesale without
// naming any single file in it).
const PAYLOAD_PROTECTED_DIR = /(^|[^a-z0-9_.-])(11_runtime|00_control)\//i

/** Repo tool scripts are the sanctioned mutation path (`tools/researchctl.py`, the
 *  BUA runner, …): an interpreter invoking one is never judged by the payload rule,
 *  no matter what its arguments name. Workspace-relative, resolved inside the root. */
function isAllowlistedTool(root, script) {
  const clean = stripQuotes(script)
  if (/^tools\//.test(clean) && /\.(py|mjs)$/.test(clean)) {
    return relsFor(root, join(root, clean)).length > 0
  }
  return false
}

/** W12 — inline-interpreter payloads naming protected state.
 *
 *  The redirect/heredoc/destructive scans only see the command's targets; an inline
 *  program (`python3 -c "open('11_runtime/events.jsonl','a')…"`, `node -e …`) names
 *  protected state in its PAYLOAD, past every shape rule. Deny when a `-c`/`-e`
 *  payload mentions protected markers or protected-relative paths — unless the
 *  invocation runs an allowlisted repo tool script.
 *
 *  Residual scope (deliberate, documented): a script FILE whose command text names
 *  nothing protected (`python3 /tmp/x.py`, `node script.js`) still passes — its
 *  content is unseen — as does a program piped over stdin without a heredoc
 *  (`echo … | python3`). Closing those needs OS-level write rules on the protected
 *  paths (see the containment layer); this heuristic closes the inline-text hole
 *  without breaking repo tooling, reads, or benign tmp operations.
 */
function interpPayloadReason(exec) {
  try {
    if (!exec || exec.name !== 'bash') return undefined
    const args = exec.arguments || {}
    if (typeof args.command !== 'string') return undefined
    const root = findOsRoot(sessionCwd(exec))
    if (!root) return undefined
    const cmd = normalizeIfs(breakBackticks(splitHeredocs(args.command).stripped))
    for (const seg of splitSegments(cmd)) {
      const words = shellWords(seg.trim())
      if (words.length === 0) continue
      const baseOf = (w) => stripQuotes(w).toLowerCase().split(/[/\\]/).pop().replace(/^[`$({]+|[`$)};]+$/g, '')
      const heads = new Set([0])
      const skipFlags = (from, valueFlags) => {
        let k = from
        while (k < words.length) {
          const ww = stripQuotes(words[k])
          if (ww === '--') { k++; break }
          if (!(ww.startsWith('-') && ww.length > 1 && ww !== '-')) break
          if (!ww.includes('=') && valueFlags.test(ww)) { k++; if (k < words.length) k++; continue }
          if (!ww.includes('=') && /^-(I|n|P|s|d|a|E)/.test(ww) && ww.length > 2) { k++; continue }
          k++
        }
        return k
      }
      const skipWrapperChain = () => {
        let k = 0
        for (;;) {
          if (k < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(stripQuotes(words[k]))) { k++; continue }
          if (k >= words.length) break
          const b = baseOf(words[k])
          if (!['env', 'sudo', 'nohup', 'nice', 'time', 'timeout', 'stdbuf', 'xargs', 'command', 'exec'].includes(b)) break
          k++
          if (b === 'env') {
            while (k < words.length) {
              const ww = stripQuotes(words[k])
              if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(ww)) { k++; continue }
              if (ww.startsWith('-') && ww.length > 1 && ww !== '-') {
                if (!ww.includes('=') && /^(-u|--user|--unset|--chdir)$/.test(ww)) { k++; if (k < words.length) k++ }
                else k++
                continue
              }
              break
            }
          } else if (b === 'sudo') k = skipFlags(k, /^(-u|-g|-h|-p|-C|-D|--user|--group|--host|--prompt|--chdir)$/)
          else if (b === 'timeout') {
            k = skipFlags(k, /^(-s|-k|--signal|--kill-after)$/)
            if (k < words.length && /^[\d.]+[smhd]?$/.test(stripQuotes(words[k]))) k++
          } else if (b === 'nice') k = skipFlags(k, /^(-n|--adjustment)$/)
          else if (b === 'stdbuf') k = skipFlags(k, /^(-i|-o|-e|--input|--output|--error)$/)
          else if (b === 'xargs') k = skipFlags(k, /^(-I|-n|-P|-s|-d|-a|-E|--replace|--max-args|--max-procs|--max-chars|--delimiter|--arg-file|--eof)$/)
          else if (b === 'command' || b === 'exec') { /* no flags: next word is the command */ }
          else k = skipFlags(k, /^(--format|--output|-f|-o)$/)
        }
        return k
      }
      const cmdHead = skipWrapperChain()
      heads.add(cmdHead)
      // `-exec` is an argument of `find`, not a command word: anchor only when the
      // segment's command is `find`, so `echo marker -exec python3 -c …` (data)
      // stays allowed while `find . -exec python3 -c …` stays denied. `xargs`
      // anchors only when `xargs` itself sits at a command-word position, so
      // `echo xargs python3 -c …` (data) stays allowed while a piped
      // `xargs -I{} python3 -c …` stays denied.
      const cmdBase = cmdHead < words.length ? baseOf(words[cmdHead]) : ''
      const headSet = new Set([0, cmdHead])
      for (let j = 0; j < words.length; j++) {
        const b = baseOf(words[j])
        if ((b === '-exec' || b === '-execdir') && cmdBase === 'find') { if (j + 1 < words.length) heads.add(j + 1) }
        if (b === 'xargs' && headSet.has(j)) heads.add(skipFlags(j + 1, /^(-I|-n|-P|-s|-d|-a|-E|--replace|--max-args|--max-procs|--max-chars|--delimiter|--arg-file|--eof)$/))
      }
      for (const h of heads) {
        if (h >= words.length) continue
        if (!INLINE_INTERP.has(baseOf(words[h]))) continue
        let payload = null
        let script = null
        for (let i = h + 1; i < words.length; i++) {
          const w = stripQuotes(words[i])
          if ((w === '-c' || w === '-e') && i + 1 < words.length) { payload = stripQuotes(words[i + 1]); break }
          if (w === '-c' || w === '-e') { payload = ''; break }
          if (/^-/.test(w)) continue
          script = words[i]
          break
        }
        if (script !== null && payload === null && isAllowlistedTool(root, script)) continue
        if (payload !== null && payload !== ''
          && (mentionsProtected(payload) || PAYLOAD_PROTECTED_DIR.test(payload))) {
          return 'research-os-enforcer: this inline-interpreter payload names control-plane state — ' +
            'split the work or use tools/researchctl.py; direct protected writes are denied.'
        }
      }
    }
    return undefined
  } catch (e) {
    log('guard-interp-error ' + e)
    if (mentionsProtected(argsText(exec))) {
      return 'research-os-enforcer: the interpreter guard could not evaluate the payload and this call touches protected state — refusing (failing closed). Mutate protected state through tools/researchctl.py; retry without the protected path if this call was unrelated.'
    }
    return undefined
  }
}
/** R1/R2 — the same protection for shell write shapes, judging the WRITE TARGET.
 *
 *  `2>&1` / `>&2` are descriptor duplications, not file writes: only a real
 *  redirect target (or the path arguments of an explicitly writing tool) counts,
 *  so reading a protected file through bash stays allowed (live-verified fix).
 *  Destructive shapes (rm/rmdir/unlink/mv/cp/dd/find -delete/ln/perl -i/sed -i —
 *  any `ln` spelling, so flag-order (`ln -f -s`) and hardlink (`ln src dst`)
 *  variants cannot dodge the check) resolve their targets too — bare names, `dd
 *  of=` operands, brace expansions and globs (expanded against the filesystem
 *  when readable, else the static prefix before the first wildcard fails
 *  closed) — and are denied when the resolved path equals or is an ancestor of
 *  control-plane-owned material. A link whose target does not exist yet cannot be
 *  resolved, so the link SOURCE is always judged: creating the link and writing
 *  through it in one command (`ln -s <protected> /tmp/x && echo >> /tmp/x`)
 *  denies on the source. Same-command `NAME=value` assignments are substituted
 *  into judged operands (`$V`/`${V}`), so the source cannot hide in a variable
 *  either (command-substitution sources remain a known residual — the guard is
 *  static). Surrounding quotes are
 *  stripped and `$IFS`/`${IFS}` normalized before tokenization. `cd <dir> && …`
 *  adds the rebased directory as another base, and an untrusted `workdir` never
 *  moves the root (session cwd) but its targets are judged too — so
 *  `cd 11_runtime && rm events.jsonl` cannot slip through.
 */
function bashWriteReason(exec) {
  try {
    if (!exec || exec.name !== 'bash') return undefined
    const args = exec.arguments || {}
    if (typeof args.command !== 'string') return undefined
    // The root is discovered from the session cwd only — never from an untrusted
    // `workdir`, which could otherwise move the command outside the workspace.
    const cwd = sessionCwd(exec)
    const root = findOsRoot(cwd)
    if (!root) return undefined
    // Heredoc bodies are inert text, not commands: strip them before any
    // command-word, redirect or destructive-shape detection, and sweep the bodies
    // for protected targets only when the text lands in the workspace (a redirect
    // target resolving inside the root) or feeds an interpreter's stdin.
    const { stripped, bodies } = splitHeredocs(args.command)
    // `$IFS`/`${IFS}` split words at the shell: normalize to whitespace before
    // tokenization so `rm${IFS}11_runtime/events.jsonl` cannot hide the target.
    const cmd = normalizeIfs(stripped)
    // Static same-command assignments (`F=path`) so link sources and redirect
    // targets through `$F`/`${F}` judge as the assigned value. Last assignment
    // wins; only simple `NAME=value` words (quoted values unquoted).
    const assigned = {}
    for (const m of cmd.matchAll(/(?:^|[\s;&|()]+)([A-Za-z_][A-Za-z0-9_]*)=('[^']*'|"[^"]*"|[^\s;&|()<>]+)/g)) {
      assigned[m[1]] = stripQuotes(m[2])
    }
    const subst = (tok) => String(tok).replace(/\$([A-Za-z_][A-Za-z0-9_]*)|\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g,
      (whole, a, b) => (assigned[a ?? b] !== undefined ? assigned[a ?? b] : whole))
    const targets = []
    const redirects = []
    const redirected = /(^|[^>&])>>?\s*(?!&)([^\s;&|()<>]+)/g
    for (const m of cmd.matchAll(redirected)) { targets.push(subst(m[2])); redirects.push(subst(m[2])) }
    const bases = [cwd || root]
    for (const m of cmd.matchAll(/(?:^|[;&|]\s*)cd\s+([^\s;&|()<>]+)/g)) {
      const abs = isAbsolute(m[1]) ? m[1] : join(cwd || root, m[1])
      if (relPosix(root, abs) !== undefined) bases.push(abs)
    }
    // Relative targets are canonicalized from the session cwd — and also through
    // any provided workdir, so a protected hit computed through it still denies.
    if (typeof args.workdir === 'string' && args.workdir) {
      const wd = isAbsolute(args.workdir) ? args.workdir : join(cwd || root, args.workdir)
      if (!bases.includes(wd)) bases.push(wd)
    }
    const DESTRUCTIVE = /\b(tee|truncate|shred|rm|rmdir|unlink|mv|cp|dd|install|ln)\b|sed\s+-i|perl\s+-i|-delete\b/
    if (DESTRUCTIVE.test(cmd)) {
      // Keep quotes on the token: brace expansion is quote-aware (quoted braces
      // never expand), and stripQuotes runs inside targetReason.
      for (const t of cmd.split(/[\s`|&;()<>]+/)) {
        if (!t || t.startsWith('-')) continue
        let tok = t
        if (tok.startsWith('of=')) tok = tok.slice(3)
        else if (tok.includes('=')) continue
        targets.push(subst(tok))
      }
    }
    if (bodies.length > 0 && (redirects.some((t) => targetInsideRoot(root, bases, t))
      || INTERP_STDIN_HEREDOC.test(cmd) || PIPE_TO_INTERP.test(cmd))) {
      // The bodies land in the workspace or run as an interpreter program:
      // scan every path-shaped token for protected material.
      for (const t of bodies.join('\n').split(/[\s"'`|&;()<>]+/)) if (t.includes('/')) targets.push(t)
    }
    for (const tok of targets) {
      const reason = targetReason(root, bases, tok)
      if (reason) return reason
    }
    return undefined
  } catch (e) {
    log('guard-bash-error ' + e)
    if (mentionsProtected(argsText(exec))) {
      return 'research-os-enforcer: the write guard could not evaluate the write target and this call touches protected state — refusing (failing closed). Mutate protected state through tools/researchctl.py; retry without the protected path if this call was unrelated.'
    }
    return undefined
  }
}

/** R3 — raw network egress is closed; target traffic goes through the executor. */
function liveGateReason(exec) {
  try {
    if (!exec || exec.name !== 'bash') return undefined
    const args = exec.arguments || {}
    if (typeof args.command !== 'string') return undefined
    const cmd = normalizeIfs(splitHeredocs(args.command).stripped)
    if (!hasNetCommand(cmd)) return undefined
    const root = findOsRoot(sessionCwd(exec))
    if (!root) return undefined
    const urls = cmd.match(/https?:\/\/[^\s'"]+/g) || []
    if (urls.length > 0) {
      // Every URL's parsed HOSTNAME must be loopback: a `/localhost` path or a
      // `user@localhost@evil` userinfo never exempts. Bare destinations are
      // judged too: a loopback URL plus a raw-egress host is still raw egress.
      if (urls.every(urlLoopbackExempt)) {
        const bare = schemelessTargets(cmd)
        if (bare.length === 0 || bare.every((h) => urlLoopbackExempt('http://' + h + '/'))) return undefined
      }
    } else if (schemelessLoopbackExempt(cmd)) return undefined
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

/** Browser-family binary basenames: user-facing browsers (automation harnesses are
 *  covered by BROWSER_LAUNCH above). First-word position, case-insensitive. */
const BROWSER_FAMILY = /^(google-chrome.*|chromium.*|chrome|firefox.*|safari)$/i
/** `-a <app>` names that count as a browser for `open -a` (case-insensitive). */
const OPEN_BROWSER_APP = /chrome|chromium|firefox|safari|brave|edge|opera|vivaldi|arc/i
/** True when a local filesystem path is named (not a host): absolute, `./`/`../`,
 *  `~`-rooted, exactly `.`/`..`, or an existing file/dir relative to cwd. */
function isLocalPathArg(raw, cwd) {
  const w = stripQuotes(raw)
  if (!w) return false
  if (w === '.' || w === '..') return true
  if (w.startsWith('/') || w.startsWith('./') || w.startsWith('../') || w.startsWith('~')) return true
  if (cwd) {
    try {
      const abs = isAbsolute(w) ? w : join(cwd, w)
      if (existsSync(abs)) return true
    } catch {}
  }
  return false
}
/** True when a quote-stripped command segment launches a user-facing browser:
 *  a family binary as the command word (after wrapper prefixes), `open -a
 *  <browser app>`, `open -b <browser bundle-id>`, or a bare `open <http(s)://…>`
 *  (default-browser open). */
function browserAppLaunch(cmd) {
  for (const seg of splitSegments(normalizeIfs(cmd))) {
    const words = shellWords(seg.trim())
    if (words.length === 0) continue
    const idx = netCommandIndex(words)
    if (idx >= words.length) continue
    const head = stripQuotes(words[idx])
    if (BROWSER_FAMILY.test(head.split(/[/\\]/).pop())) return true
    if (head.toLowerCase().split(/[/\\]/).pop() !== 'open') continue
    const rest = words.slice(idx + 1)
    const lower = rest.map((x) => stripQuotes(x).toLowerCase())
    const ai = lower.indexOf('-a')
    if (ai >= 0) {
      if (OPEN_BROWSER_APP.test(rest.slice(ai + 1).map((x) => stripQuotes(x)).join(' '))) return true
      continue
    }
    const bi = lower.indexOf('-b')
    if (bi >= 0) {
      if (bi + 1 < rest.length && OPEN_BROWSER_APP.test(stripQuotes(rest[bi + 1]))) return true
      continue
    }
    if (rest.some((w) => /https?:\/\//i.test(stripQuotes(w)))) return true
  }
  return false
}
/** Bare (schemeless) destinations of user-facing browser launches: family-binary
 *  args and `open -a/-b <browser app>` args after the app, excluding flags, flag
 *  values, URL tokens and local file/dir paths (URLs are judged separately).
 *  Quote-aware so `open -a "Google Chrome"` leaves no destination. Empty when the
 *  launch names no destination (`chromium --no-sandbox`, `open -a "Google Chrome"`
 *  stay allowed). `cwd` resolves existing relative paths. */
function browserBareTargets(cmd, cwd) {
  const out = []
  for (const seg of splitSegments(normalizeIfs(cmd))) {
    const words = shellWords(seg.trim())
    if (words.length === 0) continue
    const idx = netCommandIndex(words)
    if (idx >= words.length) continue
    const head = stripQuotes(words[idx])
    if (BROWSER_FAMILY.test(head.split(/[/\\]/).pop())) {
      let j = idx + 1
      while (j < words.length) {
        if (isLocalPathArg(words[j], cwd)) { j++; continue }
        const w = stripQuotes(words[j])
        if (w === '--') { j++; continue }
        if (w.startsWith('-') && w.length > 1 && w !== '-') {
          if (!w.includes('=') && /^(--user-data-dir|--profile-directory|--remote-debugging-port|--remote-debugging-address|--headless)$/.test(w)) {
            j++
            if (j < words.length && !stripQuotes(words[j]).startsWith('-')) j++
            continue
          }
          j++
          continue
        }
        if (w.includes('://')) { j++; continue }
        let hostpart = w
        if (hostpart.startsWith('//')) hostpart = hostpart.slice(2)
        hostpart = hostpart.split('/')[0].split('?')[0].split('#')[0].trim()
        if (hostpart) out.push(hostpart)
        j++
      }
    } else if (head.toLowerCase().split(/[/\\]/).pop() === 'open') {
      const lower = words.map((x) => stripQuotes(x).toLowerCase())
      let ai = -1
      let bi = -1
      for (let k = idx + 1; k < lower.length; k++) {
        if (ai < 0 && lower[k] === '-a') ai = k
        if (bi < 0 && lower[k] === '-b') bi = k
      }
      if (ai < 0 && bi < 0) continue
      let j = ai >= 0 ? ai + 2 : bi + 2
      while (j < words.length) {
        if (isLocalPathArg(words[j], cwd)) { j++; continue }
        const w = stripQuotes(words[j])
        if (w === '--') { j++; continue }
        if (w.startsWith('-') && w.length > 1 && w !== '-') { j++; continue }
        if (w.includes('://')) { j++; continue }
        let hostpart = w
        if (hostpart.startsWith('//')) hostpart = hostpart.slice(2)
        hostpart = hostpart.split('/')[0].split('?')[0].split('#')[0].trim()
        if (hostpart) out.push(hostpart)
        j++
      }
    }
  }
  return out
}
/** Bare host-like destinations of automation-harness segments (R6 schemeless
 *  loopback): non-flag, non-URL tokens containing host characters. Subcommand
 *  words (`open`, `test`) carry no host characters and are skipped. */
function automationBareTargets(cmd) {
  const out = []
  for (const seg of splitSegments(normalizeIfs(cmd))) {
    if (!BROWSER_LAUNCH.test(seg)) continue
    const words = shellWords(seg.trim())
    if (words.length === 0) continue
    const idx = netCommandIndex(words)
    for (let j = idx + 1; j < words.length; j++) {
      const w = stripQuotes(words[j])
      if (!w || w === '--') continue
      if (w.startsWith('-') && w.length > 1 && w !== '-') continue
      if (w.includes('://')) continue
      if (/^\d+$/.test(w)) continue
      let hostpart = w
      if (hostpart.startsWith('//')) hostpart = hostpart.slice(2)
      hostpart = hostpart.split('/')[0].split('?')[0].split('#')[0].trim()
      if (!hostpart) continue
      if (!/[.:[\]]/.test(hostpart) && !isLoopbackHostname(hostpart)) continue
      out.push(hostpart)
    }
  }
  return out
}
/** R6 — raw browser-automation launches are not the live path; the browser executor is.
 *
 *  W7 additionally recognizes user-facing browser launches (family binary, `open -a`
 *  browser app, `open <url>`): those deny only out-of-scope destinations — in-scope
 *  and loopback targets stay allowed — while automation harnesses keep the R6 rule. */
function browserGateReason(exec) {
  try {
    if (!exec || exec.name !== 'bash') return undefined
    const args = exec.arguments || {}
    if (typeof args.command !== 'string') return undefined
    const cmd = normalizeIfs(splitHeredocs(args.command).stripped)
    if (!BROWSER_LAUNCH.test(cmd)) {
      // W7: user-facing browser launches deny out-of-scope destinations only.
      if (!browserAppLaunch(cmd)) return undefined
      const root = findOsRoot(sessionCwd(exec))
      if (!root) return undefined
      const urls = cmd.match(/https?:\/\/[^\s'"]+/g) || []
      const bare = browserBareTargets(cmd, sessionCwd(exec) || root)
      if (urls.length === 0 && bare.length === 0) return undefined
      const bad = urls.find((u) => !urlLoopbackExempt(u) && scopeReasonFor(root, u) !== undefined)
        || bare.find((d) => {
          const cand = 'http://' + d + '/'
          return !urlLoopbackExempt(cand) && scopeReasonFor(root, cand) !== undefined
        })
      if (bad === undefined) return undefined
      return 'research-os-enforcer: this browser launch targets an out-of-scope destination — prepare a browser preflight (python3 tools/researchctl.py . prepare payload.json with "tool_family": "browser" and request_shape {"url": …, "principal": …}) and call the research_os_browser tool; in-scope and localhost targets stay allowed.'
    }
    // Judge install shape per COMMAND SEGMENT: one install-shaped segment must not stand
    // the gate down for a later browser segment (`npx playwright install chromium &&
    // npx playwright test <remote>`). The gate stands down only when every segment that
    // mentions browser tooling is install-shaped; a compound command with a non-install
    // browser segment (or an install segment plus a bare `npx playwright test`) is denied.
    const browserSegments = cmd.split(/\s*(?:&&|\|\||;|\|)\s*/).filter((seg) => BROWSER_LAUNCH.test(seg))
    if (browserSegments.length > 0 && browserSegments.every((seg) => PM_QUERY.test(seg))) return undefined
    const root = findOsRoot(sessionCwd(exec))
    if (!root) return undefined
    const urls = cmd.match(/https?:\/\/[^\s'"]+/g) || []
    if (urls.length > 0 && urls.every(urlLoopbackExempt)) return undefined
    if (urls.length === 0) {
      const bare = automationBareTargets(cmd)
      if (bare.length > 0 && bare.every((h) => urlLoopbackExempt('http://' + h + '/'))) return undefined
    }
    return 'research-os-enforcer: browser automation drives target traffic — a raw launch is not the live path. Prepare a browser preflight (python3 tools/researchctl.py . prepare payload.json with "tool_family": "browser" and request_shape {"url": …, "principal": …}) and call the research_os_browser tool; it runs the canonical runner tools/bua/run.mjs with the engagement scope guard. Localhost/lab browser work stays allowed — name the local URL explicitly.'
  } catch (e) {
    log('guard-browser-error ' + e)
    return undefined
  }
}

// ---------- engagement scope (R5) ----------

/** Leading whitespace of a line (the depth measure for the scope block). */
function leadingWs(line) {
  const m = String(line).match(/^[ \t]*/)
  return m ? m[0] : ''
}

/** First non-blank, non-indented line after `start` (the scope block boundary). */
function scopeBlockEnd(lines, start) {
  for (let j = start + 1; j < lines.length; j++) {
    if (lines[j].trim() && !/^[ \t]/.test(lines[j])) return j
  }
  return lines.length
}

/** Indentation of the block's first real (non-comment) entry = depth 1. */
function scopeChildIndent(lines, start, end) {
  for (let j = start + 1; j < end; j++) {
    const stripped = lines[j].trim()
    if (stripped && !stripped.startsWith('#')) return leadingWs(lines[j])
  }
  return '  '
}

/** Parse one `assets:` entry's items, mirroring tools/control_plane.py. */
function assetsItems(lines, entry, end, legacy) {
  const rest = lines[entry].trim().slice('assets:'.length).trim()
  const items = []
  let unparsed = 0
  if (rest === '' || rest === '[]') {
    for (let j = entry + 1; j < end; j++) {
      const raw = lines[j]
      const stripped = raw.trim()
      if (!stripped || stripped.startsWith('#')) continue
      if (!/^[ \t]/.test(raw)) break
      if (!legacy && !stripped.startsWith('-')) break
      const m = stripped.match(/^-\s*(.+?)\s*$/)
      if (!m) continue
      const val = m[1]
      if (val.startsWith('[') || val.startsWith('{')) { unparsed += 1; continue }
      const clean = val.replace(/^["']+|["']+$/g, '')
      if (clean) items.push(clean)
    }
  } else if (rest.startsWith('[') && rest.endsWith(']')) {
    for (const part of rest.slice(1, -1).split(',')) {
      const val = part.trim().replace(/^["']+|["']+$/g, '')
      if (val) items.push(val)
    }
  } else {
    unparsed += 1
  }
  if (items.length) return items
  if (unparsed) return []
  return null
}

/** Parse the in-scope asset list, mirroring tools/control_plane.py engagement_assets().
 *
 *  Depth-aware: only a depth-1 `assets:` entry inside the top-level `scope:` block is
 *  authoritative. A legacy top-level `assets:` block is still accepted, but ONLY when no
 *  `scope:` block exists (a shadowed legacy block can never override the scope).
 *  Returns null when the file/block is absent or empty (no scope gate configured), the
 *  items when they are simple strings, and [] when the block exists but is not a simple
 *  string list — the caller treats [] as unenforceable and fails closed. */
function engagementAssets(root) {
  const p = join(root, '00_control', 'engagement.yaml')
  if (!existsSync(p)) return null
  const lines = readFileSync(p, 'utf8').split(/\r\n|\r|\n/)
  const scopeAt = lines.findIndex((line) => !/^[ \t]/.test(line) && /^scope:\s*(#.*)?$/.test(line.trim()))
  if (scopeAt >= 0) {
    const end = scopeBlockEnd(lines, scopeAt)
    const indent = scopeChildIndent(lines, scopeAt, end)
    let entry = -1
    for (let j = scopeAt + 1; j < end; j++) {
      const stripped = lines[j].trim()
      if (!stripped || stripped.startsWith('#')) continue
      if (leadingWs(lines[j]) !== indent) continue
      if (/^assets:/.test(stripped)) { entry = j; break }
    }
    return entry < 0 ? null : assetsItems(lines, entry, end, false)
  }
  for (let i = 0; i < lines.length; i++) {
    if (/^[ \t]/.test(lines[i])) continue
    if (/^assets:/.test(lines[i].trim())) return assetsItems(lines, i, lines.length, true)
  }
  return null
}

/** Explicit `gate: none` opt-out: canonical rule shared with tools/control_plane.py.
 *
 *  After a top-level (unindented) `scope:` line, scan its indented block until the
 *  first non-blank, non-indented line. Only depth-1 entries count (fixed by the first
 *  non-comment block line's indentation). A depth-1 `gate:` line disables the gate when
 *  its value, with any trailing `#` comment cut, fullmatches gate:\s*['"]?none['"]?.
 */
function scopeGateDisabled(root) {
  const p = join(root, '00_control', 'engagement.yaml')
  if (!existsSync(p)) return false
  const lines = readFileSync(p, 'utf8').split(/\r\n|\r|\n/)
  const scopeAt = lines.findIndex((line) => !/^[ \t]/.test(line) && /^scope:\s*(#.*)?$/.test(line.trim()))
  if (scopeAt < 0) return false
  const end = scopeBlockEnd(lines, scopeAt)
  const indent = scopeChildIndent(lines, scopeAt, end)
  for (let j = scopeAt + 1; j < end; j++) {
    const stripped = lines[j].trim()
    if (!stripped || stripped.startsWith('#')) continue
    if (leadingWs(lines[j]) !== indent) continue
    const candidate = stripped.split('#')[0].trim()
    if (/^gate:\s*['"]?none['"]?\s*$/.test(candidate)) return true
  }
  return false
}

/** Classify the scope gate: disabled (gate: none) | unset | unenforceable | list. */
function scopeGateState(root) {
  if (scopeGateDisabled(root)) return { kind: 'disabled' }
  const assets = engagementAssets(root)
  if (assets === null) return { kind: 'unset' }
  if (assets.length === 0) return { kind: 'unenforceable' }
  return { kind: 'list', assets }
}

/** Host normalization shared with tools/control_plane.py: strip userinfo, one trailing dot.
 *
 *  A backslash terminates the authority in the WHATWG URL parser (the real fetch
 *  stack), so `http://127.0.0.1\@example.test/` connects to 127.0.0.1 while a naive
 *  `/`-split reads `example.test`. Whitespace/control characters and an encoded
 *  backslash (%5c, either case) are equally ambiguous to one parser or another: any
 *  authority carrying them normalizes to "" (fail closed, never matches scope). */
const AUTHORITY_AMBIGUOUS = /[\\\s\x00-\x1f\x7f]|%5c/i
function normalizeHost(host) {
  const h = String(host || '')
  if (!h || AUTHORITY_AMBIGUOUS.test(h)) return ''
  const at = h.lastIndexOf('@')
  let out = at >= 0 ? h.slice(at + 1) : h
  if (out.endsWith('.')) out = out.slice(0, -1)
  return out.toLowerCase()
}

/** Asset URL/host strings reduced to their host[:port], lowercase. URL inputs keep
 *  surrounding whitespace so the authority parse denies it (fail closed); bare
 *  hosts tolerate surrounding spaces. */
function assetHosts(assets) {
  const hosts = []
  for (const asset of assets) {
    const raw = String(asset)
    const isUrl = raw.includes('://')
    let value = isUrl ? raw.slice(raw.indexOf('://') + 3) : raw.trim()
    const authority = value.split('/')[0].split('?')[0].split('#')[0]
    const host = normalizeHost(isUrl ? authority : authority.trim())
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

/** Hostname part (no port) of a normalized host[:port], for the WHATWG cross-check. */
function manualHostname(host) {
  const h = String(host || '')
  if (h.startsWith('[')) {
    const close = h.indexOf(']')
    return (close >= 0 ? h.slice(0, close + 1) : h).toLowerCase()
  }
  return h.split(':')[0].toLowerCase()
}

/** Host[:port] of an absolute URL, mirroring the prepare-side extraction.
 *
 *  The authority runs to the first of `/`, `?`, `#` (a backslash inside it denies
 *  rather than terminates); userinfo ends at the last `@` before that terminator.
 *  After the manual parse, the WHATWG hostname is cross-checked (one trailing dot
 *  stripped, hostname-only so default-port collapsing cannot false-positive): any
 *  disagreement — or any ambiguity — yields "" (fail closed, never matches scope). */
function hostFromUrl(url) {
  const s = String(url || '')
  if (!s.includes('://')) return ''
  const rest = s.slice(s.indexOf('://') + 3)
  let end = rest.length
  for (const term of ['/', '?', '#']) {
    const i = rest.indexOf(term)
    if (i >= 0) end = Math.min(end, i)
  }
  const manual = normalizeHost(rest.slice(0, end))
  if (!manual) return ''
  try {
    const parsed = new URL(s)
    let whost = String(parsed.hostname || '').toLowerCase()
    if (whost.endsWith('.')) whost = whost.slice(0, -1)
    if (!whost || manualHostname(manual) !== whost) return ''
  } catch {
    return ''
  }
  return manual
}

/** Dispatch-time guard: re-derive the host the fetch stack will connect to and
 *  require it to be unambiguous and WHATWG-agreed. Returns undefined when the URL
 *  may be sent, else the refusal text — callers deny WITHOUT sending. Unreachable
 *  in normal flow (prepare and the scope re-check refuse first); defense in depth
 *  against a scope-approved host that is not the connected host. */
function dispatchHostReason(url) {
  if (hostFromUrl(url)) return undefined
  return 'research-os-enforcer: the request URL authority is ambiguous or unparseable ' +
    '(backslash, whitespace/control characters, or an encoded backslash diverge the ' +
    'fetch stack from the scope check) — refusing without sending; prepare a preflight ' +
    'for the canonical URL instead.'
}

/** R4/R5 — the cycle must still be RUNNING at dispatch, not just at prepare time.
 *
 *  `prepare` proved the cycle RUNNING when the token was minted, but the token can sit
 *  in the store while a human gate, close or block moves the cycle on. This re-reads
 *  the runtime status at the same point the scope re-check runs — same defensive
 *  intent — and refuses dispatch unless the current cycle is the token's cycle and is
 *  still RUNNING. Fail closed when the status cannot be read. */
function cycleLiveReason(root, token) {
  const st = osStatus(root)
  if (!st) {
    return 'research-os-enforcer: runtime status could not be read at dispatch — refusing the request; restore 11_runtime/run-status.yaml and prepare a fresh preflight.'
  }
  if (st.cycle !== token.cycle_id || st.cycleState !== 'RUNNING') {
    return `research-os-enforcer: the cycle moved to ${st.cycleState || 'none'} after the token was minted ` +
      `(current cycle: ${st.cycle || 'none'}, token cycle: ${token.cycle_id}) — prepare a fresh preflight.`
  }
  return undefined
}

/** R5 — per-host scope gate, mirroring `researchctl prepare`. Fail closed on scope errors. */
function scopeReasonFor(root, url) {
  try {
    const state = scopeGateState(root)
    if (state.kind === 'disabled') return undefined
    if (state.kind === 'unset') {
      return 'research-os-enforcer: no engagement scope configured — record it (researchctl scope-set) or set an explicit `gate: none` for non-target work.'
    }
    if (state.kind === 'unenforceable') {
      return 'research-os-enforcer: engagement assets are present but not a simple string list; keep 00_control/engagement.yaml assets as host/URL strings — scope is unenforceable otherwise.'
    }
    const host = hostFromUrl(url)
    if (!host || !hostInScope(host, assetHosts(state.assets))) {
      return `research-os-enforcer: target host '${host || url}' is outside the engagement scope (00_control/engagement.yaml assets=${JSON.stringify(state.assets)}). Update the engagement scope from the authoritative program policy, then prepare a fresh preflight.`
    }
    return undefined
  } catch (e) {
    log('scope-error ' + e)
    return 'research-os-enforcer: engagement scope could not be read — refusing the request until 00_control/engagement.yaml parses as a simple asset list.'
  }
}

// ---------- web-fetch target gate (R3b) ----------

/** Argument keys that name filesystem paths, not host references: the schemeless-host
 *  fallback must skip them, or a plain file read (`file_path: "t.example/notes.md"`)
 *  would be denied as an in-scope host. */
function isPathArgumentKey(key) {
  const k = String(key).toLowerCase()
  return k === 'file_path' || k === 'path' || k === 'cwd' || k === 'workdir'
    || k === 'out_dir' || k === 'profile' || k.endsWith('_path')
}

/** JSON-escaped slashes (`https:\/\/host/…`) still name a URL: decode before matching. */
function normalizeSlashes(text) {
  return String(text).replace(/\\\//g, '/')
}

/** Collect every http(s) URL (case-insensitive) in a value, recursing through strings. */
function collectUrls(value, out = []) {
  if (typeof value === 'string') {
    for (const m of normalizeSlashes(value).matchAll(/https?:\/\/[^\s'"]+/gi)) out.push(m[0])
  } else if (Array.isArray(value)) {
    for (const v of value) collectUrls(v, out)
  } else if (value && typeof value === 'object') {
    for (const v of Object.values(value)) collectUrls(v, out)
  }
  return out
}

/** Collect every string leaf in a value (for schemeless host references), skipping
 *  path-typed argument keys — a file path that looks like a host is not a URL. */
function collectStrings(value, out = [], key = '') {
  if (typeof value === 'string') {
    if (!isPathArgumentKey(key)) out.push(normalizeSlashes(value))
  } else if (Array.isArray(value)) {
    for (const v of value) collectStrings(v, out, key)
  } else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) collectStrings(v, out, k)
  }
  return out
}

/** Schemeless reference → candidate host[:port]: trim, drop `//`, take the part before
 *  any of `/?#`; strip a `:port` only when the candidate does not itself match an asset. */
function schemelessHost(value, patterns) {
  let candidate = String(value).trim()
  if (candidate.startsWith('//')) candidate = candidate.slice(2)
  candidate = candidate.split(/[/?#]/)[0]
  if (candidate.includes(':') && !hostInScope(candidate.toLowerCase(), patterns)) {
    candidate = candidate.split(':')[0]
  }
  return candidate.toLowerCase()
}

/** R3b — fetch-shaped web tools must not retrieve an in-scope live target.
 *
 *  The sanctioned executors are checked before the name pattern (defense-in-depth for
 *  renamed tools: the executors do not match the pattern today, but a rename must not
 *  route them around the pattern check into this gate). URLs are collected first: a call
 *  with no URL — a plain file read — is never denied, even when the scope is
 *  unenforceable. Scope unset/disabled → allow (no configured target boundary, so
 *  research tools stay usable); scope unenforceable with a URL → deny (fail closed); an
 *  unreadable scope file → deny (fail closed); an in-scope URL (raw or JSON-escaped) or
 *  schemeless host reference (path-typed argument keys excluded) → deny with the
 *  executor path, naming the normalized host (never the raw URL).
 */
function webFetchGateReason(exec) {
  try {
    if (!exec || typeof exec.name !== 'string') return undefined
    if (exec.name === 'research_os_request' || exec.name === 'research_os_browser') return undefined
    if (!/(scrape|extract|crawl|map|parse|read|fetch|browser|navigate|automation|computer)/i.test(exec.name)) return undefined
    if (/_search$/i.test(exec.name)) return undefined
    const root = findOsRoot(sessionCwd(exec))
    if (!root) return undefined
    const args = exec.arguments || {}
    const urls = collectUrls(args)
    const strings = collectStrings(args)
    if (strings.length === 0) return undefined
    const state = scopeGateState(root)
    if (state.kind === 'disabled' || state.kind === 'unset') return undefined
    if (state.kind === 'unenforceable') {
      if (urls.length === 0) return undefined
      return 'research-os-enforcer: engagement assets are present but not a simple string list — scope is unenforceable, so web fetches are denied until 00_control/engagement.yaml lists simple host/URL strings.'
    }
    const patterns = assetHosts(state.assets)
    const hosts = []
    for (const url of urls) {
      const host = hostFromUrl(url)
      if (host) hosts.push(host)
    }
    for (const s of strings) {
      if (/https?:\/\//i.test(s)) continue
      const host = schemelessHost(s, patterns)
      if (host) hosts.push(host)
    }
    for (const host of hosts) {
      if (hostInScope(host, patterns)) {
        return `research-os-enforcer: '${host}' is an in-scope live target — web tools must not retrieve it. Prepare a preflight (python3 tools/researchctl.py . prepare payload.json) and use the research_os_request / research_os_browser executor instead.`
      }
    }
    return undefined
  } catch (e) {
    log('guard-webfetch-error ' + e)
    return 'research-os-enforcer: engagement scope could not be read — refusing the web fetch until 00_control/engagement.yaml parses as a simple asset list.'
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

/** A plain object literal — not an array, `Headers`, Map or class instance. */
function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

/** Build the canonical request shape from tool args (lowercase header keys).
 *
 *  Headers must be a plain object: an array, a `Headers` instance or a string would
 *  otherwise digest as an empty/mangled shape and the token could never match for a
 *  reason the model cannot see. Reject loudly instead. */
function shapeFromArgs(args) {
  const shape = {
    method: String((args && args.method) || '').toUpperCase(),
    url: String((args && args.url) || ''),
    principal: String((args && args.principal) || ''),
  }
  if (args && args.body !== undefined && args.body !== null && String(args.body).length > 0) {
    shape.body_sha256 = createHash('sha256').update(String(args.body)).digest('hex')
  }
  if (args && args.headers !== undefined && args.headers !== null) {
    if (!isPlainObject(args.headers)) {
      throw new TypeError('headers must be a plain object mapping header names to string values (got '
        + (Array.isArray(args.headers) ? 'an array' : typeof args.headers === 'object' ? 'a non-plain object' : typeof args.headers) + ')')
    }
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

/** First unconsumed, unexpired, digest-matching token of the requested family (FIFO).
 *
 *  Fail closed on expiry: a missing or unparseable `expires_at` is never selectable
 *  (it must count as outstanding budget-side, but it can never dispatch). */
function selectToken(states, digest, nowMs, family = 'http') {
  for (const st of states.values()) {
    if (st.consumed === true) continue
    if (st.argument_digest !== digest) continue
    if (String(st.tool_family || 'http') !== family) continue
    const exp = Date.parse(String(st.expires_at || ''))
    if (!Number.isFinite(exp) || exp <= nowMs) continue
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

/** Atomically claim a token for this dispatch (`O_EXCL` under `.token-claims/`,
 *  keyed by nonce). Two parallel dispatches on one token: exactly one claim wins;
 *  the loser refuses before any scope, broker or network effect. The claim is
 *  released only on definite non-dispatch (a refusal before the fetch runs); once
 *  the request is sent the claim stays with the consumed marker. */
function claimToken(root, token) {
  const nonce = String(token.nonce || '').replace(/[^A-Za-z0-9_-]/g, '')
  if (!nonce) {
    return { ok: false, error: 'the preflight token has no usable nonce — refusing the request' }
  }
  const path = join(root, '11_runtime', '.token-claims', nonce)
  try {
    mkdirSync(join(root, '11_runtime', '.token-claims'), { recursive: true })
    const fd = openSync(path, 'wx')
    try { closeSync(fd) } catch {}
    return { ok: true, path }
  } catch (e) {
    if (e && e.code === 'EEXIST') {
      return { ok: false, error: 'the preflight token is already claimed by a concurrent dispatch — preflight tokens are single-use' }
    }
    return { ok: false, error: 'the preflight token claim could not be written (' + (e && e.code ? e.code : String(e && e.message ? e.message : e)) + ') — refusing the request (failing closed)' }
  }
}

function releaseClaim(path) {
  try { rmSync(path, { force: true }) } catch {}
}

/** Strict allow-list for token-derived filename segments (nonce, action_id).

 *  Token records are workspace-writable, so a forged record could carry
 *  `../../evil` or control characters into temp/capture filenames. Only
 *  `[A-Za-z0-9_-]` (≤64 chars) passes — anything else fails closed before any
 *  path, temp or capture use. */
function safeTokenSegment(value) {
  const s = String(value || '')
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(s)) return null
  return s
}

/** Fail-closed token identity check for one controlled call: both the nonce and
 *  the action id must be filename-safe. Sanitized values are written back onto
 *  the token so every downstream use (claims, consume records, receipts,
 *  temp/capture filenames) carries the validated form; legit minted values
 *  already match and pass through unchanged. */
function sanitizeTokenIdentity(token) {
  const nonce = safeTokenSegment(token.nonce)
  const action = safeTokenSegment(token.action_id)
  if (!nonce || !action) return null
  token.nonce = nonce
  token.action_id = action
  return token
}

/** Resolve the dedicated browser profile for one controlled browser action.
 *
 *  The profile comes from the engagement identity binding
 *  (`researchctl identity-binding`, parsed from `00_control/identity-binding.yaml`):
 *  a declared `session.browser_profile` is used verbatim, otherwise the lab
 *  default — always passed EXPLICITLY, never a silent runner fallback. A garbled
 *  binding or a profile resolving outside the workspace root fails closed before
 *  any browser starts. Returns `{profile}` or `{error}`. */
function browserProfileFor(root) {
  const DEFAULT_PROFILE = 'lab/bua-profile'
  let binding
  try {
    const out = execFileSync('python3', [join(root, 'tools', 'researchctl.py'), root, 'identity-binding'],
      { encoding: 'utf8', timeout: 30000 })
    binding = JSON.parse(out)
  } catch (e) {
    return { error: 'the identity binding could not be read (fail closed): ' +
      String(e && e.message ? e.message : e) + ' — repair 00_control/identity-binding.yaml' }
  }
  const declared = binding && typeof binding.browser_profile === 'string' && binding.browser_profile
    ? binding.browser_profile : DEFAULT_PROFILE
  const abs = resolve(root, declared)
  const base = resolve(root)
  if (abs !== base && !abs.startsWith(base + sep)) {
    return { error: `the bound browser profile ${JSON.stringify(declared)} resolves outside the workspace root — refusing the browser action (fail closed)` }
  }
  return { profile: declared }
}

/** Pick the runner profile for one dispatch: the live binding first, the
 *  prepare-time token binding when the seam is down, the lab default loudly last.
 *
 *  A malformed binding or an outside-root profile fails closed even when a token
 *  binding exists (the contract is garbled *now*). An unreadable seam (researchctl
 *  missing at dispatch) falls back without going silent: the chosen profile rides
 *  explicitly on the runner command and its run log, and the tool text says so.
 *  Returns `{profile, note?}` or `{error}`. */
function resolveBrowserProfile(root, token) {
  const DEFAULT_PROFILE = 'lab/bua-profile'
  const insideRoot = (rel) => {
    const abs = resolve(root, String(rel))
    const base = resolve(root)
    return abs === base || abs.startsWith(base + sep)
  }
  const live = browserProfileFor(root)
  if (!live.error) return { profile: live.profile }
  if (/malformed|outside the workspace root/.test(live.error)) return { error: live.error }
  const tokenProfile = (token && typeof token.browser_profile === 'string' && token.browser_profile)
    ? token.browser_profile : ''
  if (tokenProfile) {
    if (!insideRoot(tokenProfile)) {
      return { error: `the token-bound browser profile ${JSON.stringify(tokenProfile)} resolves outside the workspace root — refusing the browser action (fail closed)` }
    }
    return { profile: tokenProfile, note: 'identity seam unreadable at dispatch; using the prepare-time profile' }
  }
  return { profile: DEFAULT_PROFILE, note: 'identity seam unreadable at dispatch and no token-bound profile; using the lab default explicitly' }
}

// ---------- policy broker (R7) ----------
//
// The broker (tools/broker/) keeps the policy snapshot, the signing key and the
// single-use token ledger OUTSIDE the workspace. Discovery is env-first, then the
// default home socket when the file exists; an absent socket is advisory local mode,
// but any transport/parse failure on a present socket fails closed at the call site.

const BROKER_SOCKET_REL = ['.dsh', 'research-os-broker', 'broker.sock']
const BROKER_MAX_LINE = 1024 * 1024

/** Broker socket path when one is configured AND present, else undefined.
 *
 *  Parity with tools/broker/client.py broker_path() + available(): the socket env
 *  wins, else the socket under RESEARCH_OS_BROKER_HOME (default
 *  ~/.dsh/research-os-broker). Existence decides availability either way — a
 *  configured-but-missing socket is not a broker (same as client.available()),
 *  while a present-but-unreachable socket fails closed at the call site, never a
 *  silent local fallback. */
function brokerPath() {
  if (process.env.RESEARCH_OS_BROKER_SOCKET) {
    let sock = process.env.RESEARCH_OS_BROKER_SOCKET
    if (sock === '~') sock = homedir()
    else if (sock.startsWith('~/')) sock = join(homedir(), sock.slice(2))
    return existsSync(sock) ? sock : undefined
  }
  let home = process.env.RESEARCH_OS_BROKER_HOME
  if (home === '~') home = homedir()
  else if (home && home.startsWith('~/')) home = join(homedir(), home.slice(2))
  const candidate = home ? join(home, 'broker.sock') : join(homedir(), ...BROKER_SOCKET_REL)
  return existsSync(candidate) ? candidate : undefined
}

/** Canonical workspace identity the broker signs: the symlink-resolved absolute path.
 *
 *  macOS `/var` is a symlink to `/private/var`; the Python side resolves with
 *  `Path.resolve()`, so a lexical `path.resolve()` here would not match the signature. */
function brokerWorkspace(root) {
  try { return realpathSync(root) } catch { return resolve(root) }
}

/** One newline-delimited JSON call against the broker. Throws on any failure (a broker
 *  refusal is a normal `{ok:false}` response; transport and parse errors are not). */
function brokerCall(op, payload = {}, timeoutMs = 3000) {
  return new Promise((resolvePromise, reject) => {
    const path = brokerPath()
    if (!path) {
      reject(new Error('no broker socket (start one: researchctl broker serve)'))
      return
    }
    const sock = net.connect({ path })
    let buf = ''
    let settled = false
    let timer = null
    const finish = (err, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try { sock.destroy() } catch {}
      if (err) reject(err)
      else resolvePromise(value)
    }
    timer = setTimeout(
      () => finish(new Error(`broker ${op} timed out after ${timeoutMs}ms`)), timeoutMs)
    sock.on('connect', () => {
      const line = JSON.stringify({ op, ...payload }) + '\n'
      if (line.length > BROKER_MAX_LINE) {
        finish(new Error(`broker ${op} request exceeds the ${BROKER_MAX_LINE} byte line bound`))
        return
      }
      sock.write(line)
    })
    sock.on('data', (chunk) => {
      buf += chunk
      if (buf.length > BROKER_MAX_LINE) {
        finish(new Error(`broker ${op} response exceeds the ${BROKER_MAX_LINE} byte line bound`))
        return
      }
      const end = buf.indexOf('\n')
      if (end < 0) return
      try {
        finish(null, JSON.parse(buf.slice(0, end)))
      } catch (e) {
        finish(new Error(`broker ${op} response is not JSON: ${e && e.message ? e.message : e}`))
      }
    })
    sock.on('error', (e) => finish(e))
    sock.on('close', () => finish(new Error(`broker ${op} closed the connection without a response`)))
  })
}

/** Consume a broker-signed token through the broker. Never falls back silently: any
 *  transport failure returns `{ok:false, unreachable:true}` with an actionable error. */
async function brokerConsumeToken(root, token, shape, family) {
  try {
    const resp = await brokerCall('token.consume', {
      workspace: brokerWorkspace(root),
      digest: canonicalDigest(shape),
      tool_family: family,
      nonce: String(token.broker_nonce || token.nonce || ''),
      sig: String(token.broker_sig || ''),
    })
    if (!resp || typeof resp !== 'object') return { ok: false, error: 'broker returned a non-object response' }
    return resp
  } catch (e) {
    return {
      ok: false,
      unreachable: true,
      error: `broker unreachable (${e && e.message ? e.message : e}) — refusing the request; start it with ` +
        '`researchctl broker serve` (or remove the stale socket), then prepare a fresh preflight',
    }
  }
}

/** The broker's policy copy for this workspace (one read per call). Throws fail-closed. */
async function brokerPolicyGet(root) {
  const resp = await brokerCall('policy.get', { workspace: brokerWorkspace(root) })
  if (!resp || resp.ok !== true) throw new Error(resp && resp.error ? resp.error : 'broker policy.get failed')
  return resp.policy
}

/** R7 scope decision from the BROKER policy copy (the authority while a broker is up). */
function brokerScopeReason(policy, url) {
  if (!policy) {
    return 'research-os-enforcer: the broker holds no policy for this workspace — register the scope with the broker (researchctl scope-set), then prepare a fresh preflight.'
  }
  if (String(policy.gate) === 'none') return undefined
  const assets = Array.isArray(policy.assets) ? policy.assets : null
  if (assets === null || assets.length === 0) {
    return 'research-os-enforcer: the broker policy is unenforceable (empty or non-list assets) — repair it with researchctl scope-set; refusing the request.'
  }
  const host = hostFromUrl(url)
  if (!host || !hostInScope(host, assetHosts(assets))) {
    return `research-os-enforcer: target host '${host || url}' is outside the engagement scope (broker policy assets=${JSON.stringify(assets)}) — refusing the request; update the broker policy through researchctl scope-set.`
  }
  return undefined
}

/** The shared broker-mode gate for one controlled call (both executor arms).
 *
 *  While a broker socket exists the broker is the authority, never an optional extra:
 *   - a token without `broker_sig` is refused (the operator must re-prepare);
 *   - BOTH scope checks run — the local engagement binding and the broker policy copy —
 *     and either denial stops the dispatch (belt and braces);
 *   - the token then consumes through the broker; a refusal retires the local record,
 *     a transport failure leaves it retryable, and neither dispatches.
 *  Returns `undefined` when the call may proceed, else the refusal text. The local
 *  trust path survives only when no socket exists. */
async function consumeBrokerToken(root, token, shape, family) {
  if (brokerPath() === undefined) return scopeReasonFor(root, shape.url)
  if (!token.broker_sig) {
    consumeToken(root, token)
    return 'the policy broker is running; re-prepare so the token is broker-signed ' +
      '(python3 tools/researchctl.py . prepare payload.json)'
  }
  const localDenied = scopeReasonFor(root, shape.url)
  if (localDenied) {
    consumeToken(root, token)
    return localDenied
  }
  let policy
  try {
    policy = await brokerPolicyGet(root)
  } catch (e) {
    return `broker unreachable — the broker policy could not be read (${e && e.message ? e.message : e}) — ` +
      'refusing the request (fail closed); start it with `researchctl broker serve` and prepare a fresh preflight'
  }
  const brokerDenied = brokerScopeReason(policy, shape.url)
  if (brokerDenied) {
    consumeToken(root, token)
    return brokerDenied
  }
  const consumed = await brokerConsumeToken(root, token, shape, family)
  if (consumed.ok !== true) {
    if (!consumed.unreachable) consumeToken(root, token)
    return String(consumed.error || 'broker refused the token')
  }
  return undefined
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

// Query/fragment parameters whose VALUE is a credential: a parameter NAME containing
// any of these substrings (case-insensitive, after percent-decoding) marks the value
// sensitive. Substrings on purpose — `access-token`, `client_secret`, `token2`,
// `X-Amz-Signature`, `code`, `session_id` all match, not just the exact names.
const SENSITIVE_QUERY_MARKERS = /(token|secret|key|auth|sig|session|code|password|passwd|cookie)/i

// A sensitive assignment nested inside ANOTHER component's decoded value: a
// double-encoded `next=/cb%26token%3Dxyz` decodes once to `next=/cb&token=xyz`, so a
// downstream consumer that decodes `next` would see the token. Matched after a `&`/`;`
// separator or at the value's start.
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

/** Mask one query/fragment component (`name=value`) when its decoded name — or a
 *  sensitive assignment nested in its decoded value — is sensitive. */
function redactQueryPart(part) {
  const eq = part.indexOf('=')
  const name = eq < 0 ? part : part.slice(0, eq)
  let decoded = name
  try { decoded = decodeURIComponent(name) } catch {}
  if (SENSITIVE_QUERY_MARKERS.test(decoded)) return `${name}=[REDACTED]`
  if (eq < 0) return part
  const value = part.slice(eq + 1)
  if (NESTED_SENSITIVE_ASSIGNMENT.test(decodeTolerant(value))) return `${name}=[REDACTED]`
  return `${name}=${redactSecrets(value)}`
}

/** Mask sensitive parameter values in one query-or-fragment span (no leading ?/#). */
function redactQuerySpan(span) {
  return span.split(/([&;])/).map((tok, i) => (i % 2 ? tok : redactQueryPart(tok))).join('')
}

/** Mask sensitive query AND fragment parameter values in a URL (`?token=…`, `#code=…`).
 *  Scheme, host, port and path stay untouched; a component separator (`&`/`;`) is
 *  preserved, and only the name is percent-decoded before matching. */
function redactUrlSecrets(url) {
  const raw = String(url == null ? '' : url)
  return raw.replace(/[?#][^\s#?]*/g, (seg) => seg[0] + redactQuerySpan(seg.slice(1)))
}

/** Redact a header VALUE by name: sensitive header names become [REDACTED] wholesale,
 *  other values are scrubbed for secret shapes (the same rules captures use). */
function redactHeaderValue(name, value) {
  if (SENSITIVE_HEADERS.test(String(name))) return '[REDACTED]'
  return redactSecrets(String(value == null ? '' : value))
}

/** A request shape safe to echo in tool text: URL query/fragment secrets and sensitive
 *  header values are redacted, everything else (digest-relevant facts) stays visible. */
function redactShapeForText(shape) {
  const out = { ...shape, url: redactUrlSecrets(shape.url) }
  if (out.headers && typeof out.headers === 'object') {
    const headers = {}
    for (const [k, v] of Object.entries(out.headers)) headers[k] = redactHeaderValue(k, v)
    out.headers = headers
  }
  return out
}

/** Executor HTTP limits, read from the environment at call time (defaults 30s / 5 MB). */
function httpLimits() {
  const timeoutMs = Number(process.env.RESEARCH_OS_HTTP_TIMEOUT_MS)
  const maxBytes = Number(process.env.RESEARCH_OS_MAX_BODY_BYTES)
  return {
    timeoutMs: Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : 30000,
    maxBytes: Number.isFinite(maxBytes) && maxBytes > 0 ? maxBytes : 5 * 1024 * 1024,
  }
}

/** Read a response body up to `maxBytes`, cancelling the stream once the cap is hit.
 *  A read failure (abort/timeout mid-body) returns the bytes already received plus the
 *  error, so the caller can record the partial capture and say what happened. */
async function readBodyCapped(resp, maxBytes) {
  if (resp.body && typeof resp.body.getReader === 'function') {
    const reader = resp.body.getReader()
    const chunks = []
    let bytes = 0
    let truncated = false
    try {
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        const chunk = value instanceof Uint8Array ? value : new Uint8Array(value)
        if (bytes + chunk.length > maxBytes) {
          chunks.push(chunk.subarray(0, maxBytes - bytes))
          bytes = maxBytes
          truncated = true
          try { await reader.cancel() } catch {}
          break
        }
        chunks.push(chunk)
        bytes += chunk.length
      }
    } catch (e) {
      return { text: Buffer.concat(chunks).toString('utf8'), bytes, truncated,
        error: String(e && e.message ? e.message : e) }
    }
    return { text: Buffer.concat(chunks).toString('utf8'), bytes, truncated, error: '' }
  }
  try {
    const text = await resp.text()
    const blob = Buffer.from(text)
    if (blob.length > maxBytes) {
      return { text: blob.subarray(0, maxBytes).toString('utf8'), bytes: maxBytes, truncated: true, error: '' }
    }
    return { text, bytes: blob.length, truncated: false, error: '' }
  } catch (e) {
    return { text: '', bytes: 0, truncated: false, error: String(e && e.message ? e.message : e) }
  }
}

const RECEIPT_FAILURE_WARNING = 'the request WAS executed but the receipt could not be recorded — do not rely on this action as receipted'

/** Read the runner's machine summary (`ARTIFACT ...bua.json` on stdout) for scope
 *  signals the exit code cannot carry: a followed out-of-scope redirect hop sets
 *  `scope_violation: true` and records `out_of_scope_hops`. Returns the flags, or
 *  {} when the runner reported none (stubs, old runners, failed starts). */
function readBrowserSummary(root, stdout) {
  try {
    for (const line of String(stdout || '').split('\n')) {
      const m = /^ARTIFACT\s+(.+?\.bua\.json)\s*$/.exec(line.trim())
      if (!m) continue
      const abs = join(root, m[1]);
      if (!abs.startsWith(resolve(root) + sep) && abs !== resolve(root)) continue
      let parsed = null
      try { parsed = JSON.parse(readFileSync(abs, 'utf8')) } catch { continue }
      if (!parsed || typeof parsed !== 'object') continue
      const flags = {}
      if (parsed.scope_violation === true) flags.scope_violation = true
      // The receipt carries the spec-named `out_of_scope_hops` count, as the
      // runner reports it (integer preferred, hop-record length as fallback).
      if (Number.isInteger(parsed.out_of_scope_hop_count)) {
        flags.out_of_scope_hops = parsed.out_of_scope_hop_count
      } else if (Array.isArray(parsed.out_of_scope_hops)) {
        flags.out_of_scope_hops = parsed.out_of_scope_hops.length
      }
      if (flags.scope_violation || flags.out_of_scope_hops) return flags
    }
  } catch { /* a summary that cannot be read carries no flags */ }
  return {}
}

/** Register a capture as evidence and record ACTION_RECORDED through the control plane. */
function registerCapture({ root, relPath, token, source, runFlags }) {
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
    const payload = { ...preflight, id: token.action_id, token_nonce: token.nonce, ...(evidence ? { evidence_refs: [evidence] } : {}) }
    // Browser scope signals ride the receipt: a run the runner flagged carries
    // scope_violation + the spec-named `out_of_scope_hops` count, so the audit
    // can demand human disposition.
    if (runFlags && (runFlags.scope_violation || runFlags.out_of_scope_hops)) {
      if (runFlags.scope_violation) payload.scope_violation = true
      if (Number.isInteger(runFlags.out_of_scope_hops)) {
        payload.out_of_scope_hops = runFlags.out_of_scope_hops
      }
    }
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
  let shape
  try {
    shape = shapeFromArgs(args)
  } catch (e) {
    return { ok: false, text: 'research_os_request: ' + String(e && e.message ? e.message : e) }
  }
  if (!shape.method || !shape.url || !shape.principal) {
    return { ok: false, text: 'research_os_request requires method, url and principal (the account label used in the preflight).' }
  }
  const digest = canonicalDigest(shape)
  const safeUrl = redactUrlSecrets(shape.url)
  const token = selectToken(loadTokenStates(root), digest, Date.now())
  if (!token) {
    return { ok: false, text: 'research_os_request: no matching unconsumed preflight token (tokens are single-use and expire). Prepare one first:\n  python3 tools/researchctl.py . prepare payload.json\nwith request_shape:\n  ' + JSON.stringify(redactShapeForText(shape)) }
  }
  if (!sanitizeTokenIdentity(token)) {
    log(`DENY(executor) ${shape.method} ${safeUrl} :: the matched token carries a nonce or action id outside [A-Za-z0-9_-] — refusing before any path, temp or capture use (fail closed)`)
    return { ok: false, text: 'research_os_request: the matched preflight token carries an unsafe nonce or action id — refusing the request (fail closed); prepare a fresh preflight' }
  }
  // R7: while a broker socket exists the broker is mandatory — unsigned tokens are
  // refused, both scope checks (local + broker) must pass, and the token consumes
  // through the broker before dispatch. Any denial means no dispatch, no fallback.
  // The broker gate runs BEFORE the local claim: the broker's authoritative refusal
  // (already-consumed, bad signature) must win over the claim conflict, and a broker
  // refusal retires the local record exactly as before. The claim then serializes
  // only the local append→dispatch window against parallel dispatches.
  const brokerDenial = await consumeBrokerToken(root, token, shape, 'http')
  if (brokerDenial) {
    const reason = redactUrlSecrets(brokerDenial)
    const where = brokerPath() === undefined ? 'executor' : 'executor broker'
    log(`DENY(${where}) ${shape.method} ${safeUrl} :: ${reason}`)
    return { ok: false, text: `research_os_request: ${reason}` }
  }
  // Atomic claim before the local append: two parallel dispatches on one token —
  // exactly one claim wins and the loser refuses before any network effect. The
  // claim persists after dispatch (released only on definite non-dispatch below),
  // so a re-appended record can never ride the same nonce twice.
  const claim = claimToken(root, token)
  if (!claim.ok) {
    log(`DENY(executor) ${shape.method} ${safeUrl} :: ${claim.error}`)
    return { ok: false, text: `research_os_request: ${claim.error}` }
  }
  consumeToken(root, token)
  const lifecycleDenied = cycleLiveReason(root, token)
  if (lifecycleDenied) {
    releaseClaim(claim.path)
    log('DENY(executor) lifecycle ' + shape.method + ' ' + safeUrl + ' :: ' + lifecycleDenied)
    return { ok: false, text: lifecycleDenied }
  }
  const dispatchDenied = dispatchHostReason(shape.url)
  if (dispatchDenied) {
    releaseClaim(claim.path)
    log('DENY(executor) dispatch-host ' + shape.method + ' ' + safeUrl + ' :: ' + dispatchDenied)
    return { ok: false, text: dispatchDenied }
  }
  let status = null
  let respHeaders = []
  let bodyText = ''
  let truncated = false
  let partial = false
  let error = ''
  const { timeoutMs, maxBytes } = httpLimits()
  const controller = new AbortController()
  let timedOut = false
  let dispatched = false
  const timer = setTimeout(() => { timedOut = true; controller.abort() }, timeoutMs)
  try {
    const init = { method: shape.method, redirect: 'manual', signal: controller.signal }
    if (shape.headers) init.headers = shape.headers
    if (args && args.body !== undefined && args.body !== null && String(args.body).length > 0) init.body = String(args.body)
    dispatched = true
    const resp = await fetchFn(shape.url, init)
    status = resp.status
    resp.headers.forEach((v, k) => { respHeaders.push(redactHeaderLine(`${k}: ${v}`)) })
    const read = await readBodyCapped(resp, maxBytes)
    bodyText = read.text
    truncated = read.truncated
    if (read.error) {
      // Headers arrived, the body read stopped early: the capture holds a partial body.
      partial = true
      error = timedOut
        ? `body read timed out after ${timeoutMs}ms with ${read.bytes} bytes captured`
        : `body read failed after ${read.bytes} bytes: ${read.error}`
    }
  } catch (e) {
    error = timedOut ? `request timeout after ${timeoutMs}ms` : String(e && e.message ? e.message : e)
  } finally {
    clearTimeout(timer)
  }
  const rel = join('08_artifacts', 'raw', `${token.action_id}-${new Date().toISOString().replace(/[:.]/g, '-')}.http`)
  const abs = join(root, rel)
  let captureWritten = false
  try {
    mkdirSync(join(root, '08_artifacts', 'raw'), { recursive: true })
    writeFileSync(abs, [
      `# research_os_request — ${shape.method} ${safeUrl}`,
      `# action: ${token.action_id} | cycle: ${token.cycle_id} | principal: ${shape.principal} | time: ${new Date().toISOString()}`,
      '',
      '--- request',
      `${shape.method} ${safeUrl}`,
      ...(shape.headers ? Object.entries(shape.headers).map(([k, v]) => redactHeaderLine(`${k}: ${v}`)) : []),
      '',
      trunc(redactSecrets(args && args.body), 4000),
      '',
      '--- response',
      status === null ? `ERROR: ${redactSecrets(error)}` : `HTTP ${status}${truncated ? ` (truncated at ${maxBytes} bytes)` : ''}${error ? ` — ${redactSecrets(error)}` : ''}`,
      ...respHeaders,
      '',
      trunc(redactSecrets(bodyText), 40000),
    ].join('\n') + '\n')
    captureWritten = true
  } catch (e) {
    log('executor-capture-error ' + e)
  }
  const relPath = rel.split(sep).join('/')
  const { evidence, recorded } = registerCapture({ root, relPath, token, source: 'controlled-executor' })
  const receipted = captureWritten && recorded && Boolean(evidence)
  const summary = status === null
    ? `error: ${error}`
    : (truncated
        ? `HTTP ${status} (body truncated at ${maxBytes} bytes)`
        : (error ? `HTTP ${status} — ${error}` : `HTTP ${status}`))
  const base = `research_os_request ${shape.method} ${safeUrl} → ${summary}\n- action: ${token.action_id} (token consumed)\n- evidence: ${recorded && evidence ? evidence : (evidence || 'NOT REGISTERED')}\n- capture: ${relPath}`
  // The warning is about DISPATCH, not success: once the request was sent, a failed
  // receipt must surface even when the request itself errored before any response.
  if (dispatched && !receipted) {
    return { ok: false, text: `${base}\n\nWARNING: ${RECEIPT_FAILURE_WARNING}`, ...(partial ? { partial: true } : {}) }
  }
  return { ok: status !== null, text: `${base}\n\n${trunc(redactSecrets(bodyText), 4000)}`, ...(partial ? { partial: true } : {}) }
}

/** Scope-sync DIRTY gate for browser dispatch: the local binding was committed but
 *  the broker push failed, so the broker copy is stale — refuse until resync. Only
 *  while a broker socket is in force (no socket means local mode governs). Returns
 *  undefined when dispatch may proceed, else the refusal text. */
function scopeSyncDirtyReason(root) {
  try {
    if (!existsSync(join(root, SCOPE_DIRTY_REL))) return undefined
  } catch {
    return undefined
  }
  if (brokerPath() === undefined) return undefined
  return 'research_os_browser: the workspace scope is not synced to the policy broker ' +
    '(scope-sync DIRTY — a scope record was committed locally but the broker push failed, ' +
    'so the broker copy is stale). Resync with `researchctl scope-sync` (or re-run ' +
    '`researchctl scope-set`); browser dispatch refuses until the broker copy is current.'
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
  const dirtyDenied = scopeSyncDirtyReason(root)
  if (dirtyDenied) {
    log('DENY(executor) dirty browser ' + redactUrlSecrets(shape.url) + ' :: ' + dirtyDenied)
    return { ok: false, text: dirtyDenied }
  }
  const digest = canonicalDigest(shape)
  const safeUrl = redactUrlSecrets(shape.url)
  const token = selectToken(loadTokenStates(root), digest, Date.now(), 'browser')
  if (!token) {
    return { ok: false, text: 'research_os_browser: no matching unconsumed browser preflight token (tokens are single-use and expire). Prepare one first:\n  python3 tools/researchctl.py . prepare payload.json\nwith "tool_family": "browser" and request_shape:\n  ' + JSON.stringify(redactShapeForText(shape)) }
  }
  if (!sanitizeTokenIdentity(token)) {
    log(`DENY(executor browser) ${safeUrl} :: the matched token carries a nonce or action id outside [A-Za-z0-9_-] — refusing before any path, temp or capture use (fail closed)`)
    return { ok: false, text: 'research_os_browser: the matched preflight token carries an unsafe nonce or action id — refusing the request (fail closed); prepare a fresh preflight' }
  }
  // R7: same mandatory broker gate as the HTTP arm — unsigned refusal, both scope
  // checks, broker consume; no dispatch on any denial. The broker gate runs BEFORE
  // the local claim (see the HTTP arm): the broker's authoritative refusal must win
  // over a claim conflict. The claim then serializes only the local append→dispatch
  // window against parallel dispatches.
  const brokerDenial = await consumeBrokerToken(root, token, shape, 'browser')
  if (brokerDenial) {
    const reason = redactUrlSecrets(brokerDenial)
    const where = brokerPath() === undefined ? 'executor browser' : 'executor broker browser'
    log(`DENY(${where}) ${safeUrl} :: ${reason}`)
    return { ok: false, text: `research_os_browser: ${reason}` }
  }
  // Atomic claim before the local append (see the HTTP arm): exactly one parallel
  // dispatch wins; the claim persists after dispatch and is released only on
  // definite non-dispatch below.
  const claim = claimToken(root, token)
  if (!claim.ok) {
    log(`DENY(executor browser) ${safeUrl} :: ${claim.error}`)
    return { ok: false, text: `research_os_browser: ${claim.error}` }
  }
  consumeToken(root, token)
  const lifecycleDenied = cycleLiveReason(root, token)
  if (lifecycleDenied) {
    releaseClaim(claim.path)
    log('DENY(executor) lifecycle browser ' + safeUrl + ' :: ' + lifecycleDenied)
    return { ok: false, text: lifecycleDenied }
  }
  const dispatchDenied = dispatchHostReason(shape.url)
  if (dispatchDenied) {
    releaseClaim(claim.path)
    log('DENY(executor) dispatch-host browser ' + safeUrl + ' :: ' + dispatchDenied)
    return { ok: false, text: dispatchDenied }
  }
  // The browser profile is bound, not defaulted: the identity binding declares the
  // dedicated per-engagement profile and the runner always receives it explicitly.
  // Prefer the live binding; a token-bound profile covers a dispatch-time seam
  // outage, and the lab default is the last resort — always explicit, never silent.
  const resolved = resolveBrowserProfile(root, token)
  if (resolved.error) {
    releaseClaim(claim.path)
    log('DENY(executor) profile browser ' + safeUrl + ' :: ' + resolved.error)
    return { ok: false, text: `research_os_browser: ${resolved.error}` }
  }
  const browserProfile = resolved.profile
  const runner = join(root, 'tools', 'bua', 'run.mjs')
  const rel = join('08_artifacts', 'raw', `${token.action_id}-${new Date().toISOString().replace(/[:.]/g, '-')}.browser.log`)
  const abs = join(root, rel)
  let captureWritten = false
  let exitCode = null
  let stdout = ''
  let stderr = ''
  let error = ''
  let dispatched = false
  if (!existsSync(runner)) {
    error = 'BUA runner missing: tools/bua/run.mjs (copy the OS template — provisioning task)'
  } else {
    try {
      dispatched = true
      stdout = execFileSync('node', [runner, '--url', shape.url, '--principal', shape.principal,
        '--out-dir', '08_artifacts/raw', '--action', token.action_id, '--profile', browserProfile],
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
      `node tools/bua/run.mjs --url ${safeUrl} --principal ${shape.principal} --out-dir 08_artifacts/raw --action ${token.action_id} --profile ${browserProfile}`,
      `exit: ${exitCode === null ? 'not started' : exitCode}`,
      ...(error ? ['error: ' + error] : []),
      '',
      '--- stdout',
      trunc(redactSecrets(stdout), 20000),
      '',
      '--- stderr',
      trunc(redactSecrets(stderr), 8000),
    ].join('\n') + '\n')
    captureWritten = true
  } catch (e) {
    log('executor-capture-error ' + e)
  }
  const relPath = rel.split(sep).join('/')
  const runFlags = readBrowserSummary(root, stdout)
  const hopCount = Number.isInteger(runFlags.out_of_scope_hops) ? runFlags.out_of_scope_hops : 0
  if (runFlags.scope_violation) {
    log(`FLAG(executor browser) ${safeUrl} :: the runner reported scope_violation with ${hopCount} out-of-scope hops — receipt flagged for human review`)
  }
  const { evidence, recorded } = registerCapture({ root, relPath, token, source: 'browser-executor', runFlags })
  const receipted = captureWritten && recorded && Boolean(evidence)
  const summary = exitCode === 0
    ? 'runner exit 0'
    : `runner ${exitCode === null ? 'not started' : 'exit ' + exitCode}${error ? ' — ' + error : ''}`
  const flagged = runFlags.scope_violation
    ? `\n- scope: FLAGGED — scope_violation with ${hopCount} out-of-scope hops (raise a human gate for disposition; the audit errors until one is resolved)`
    : ''
  const base = `research_os_browser ${safeUrl} → ${summary}\n- action: ${token.action_id} (token consumed)${flagged}\n- profile: ${browserProfile}${resolved.note ? ' (' + resolved.note + ')' : ''}\n- evidence: ${recorded && evidence ? evidence : (evidence || 'NOT REGISTERED')}\n- capture: ${relPath}`
  // Once the runner was started, a failed receipt must surface even on a non-zero exit.
  if (dispatched && !receipted) {
    return { ok: false, text: `${base}\n\nWARNING: ${RECEIPT_FAILURE_WARNING}` }
  }
  return { ok: exitCode === 0, text: `${base}\n\n${trunc(stdout, 4000)}` }
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
      const reason = fsWriteReason(exec) || bashWriteReason(exec) || interpPayloadReason(exec)
      if (reason) log('DENY(guard) ' + (exec && exec.name) + ' :: ' + reason)
      return reason
    })
    // Reorderable policy gates: raw network egress and web-fetch tools are closed
    // against live targets inside OS workspaces, and raw browser launches are denied.
    ctx.on('tools/pre-execute', async (exec, next) => {
      let reason
      try {
        reason = liveGateReason(exec) || browserGateReason(exec) || webFetchGateReason(exec)
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
export { canonicalDigest, shapeFromArgs, browserShapeFromArgs, loadTokenStates, selectToken, runControlledRequest, runControlledBrowser, scopeReasonFor, redactSecrets, redactHeaderLine, redactUrlSecrets, redactShapeForText, mentionsProtected }
export { brokerPath, brokerWorkspace, brokerCall, brokerConsumeToken, consumeBrokerToken, brokerPolicyGet, brokerScopeReason }
export { claimToken, dispatchHostReason, safeTokenSegment, sanitizeTokenIdentity, browserProfileFor }
export { scopeSyncDirtyReason }
