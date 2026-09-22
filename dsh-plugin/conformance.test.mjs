/**
 * Adversarial conformance suite for research-os-enforcer.
 *
 * Each case simulates a model trying to reach a behavior the Research OS
 * forbids, and asserts the plugin's actual decision (guard reason or
 * pre-execute deny). Run: `node conformance.test.mjs` from this directory.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply, canonicalDigest, dispatchHostReason, mentionsProtected, redactHeaderLine, redactSecrets, redactUrlSecrets, scopeReasonFor, selectToken, shapeFromArgs } from './index.js'

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

// ---- mock harness ----------------------------------------------------------
function harness() {
  const guards = []
  const preExecute = []
  const tools = { guard: (fn) => guards.push(fn) }
  const ctx = {
    get: (svc) => (svc === 'tools' ? tools : undefined),
    on: (evt, fn) => { if (evt === 'tools/pre-execute') preExecute.push(fn) },
  }
  apply(ctx)
  return {
    guardReason: (exec) => guards.map((g) => g(exec)).find((r) => r !== undefined),
    async preExecute(exec) {
      for (const listener of preExecute) {
        const decision = await listener(exec, () => ({ kind: 'allow' }))
        if (decision && decision.kind !== 'allow') return decision
      }
      return { kind: 'allow' }
    },
  }
}

function exec(toolName, args, cwd) {
  return { name: toolName, arguments: args, agent: { session: { header: { cwd } } } }
}

// ---- fixtures --------------------------------------------------------------
const sandbox = mkdtempSync(join(tmpdir(), 'enforcer-test-'))
const osRoot = join(sandbox, 'engagement')
const plain = join(sandbox, 'plain')
mkdirSync(join(osRoot, '11_runtime'), { recursive: true })
mkdirSync(join(osRoot, '04_cycles', 'C-0001'), { recursive: true })
mkdirSync(join(osRoot, '08_artifacts'), { recursive: true })
mkdirSync(plain, { recursive: true })
writeFileSync(join(osRoot, 'OS_VERSION'), '7.1\n')
writeFileSync(join(osRoot, '11_runtime', 'events.jsonl'), '')
writeFileSync(join(osRoot, '11_runtime', 'run-status.yaml'),
  'engagement_status: "BOOTSTRAP"\ncurrent_cycle: null\n')
writeFileSync(join(plain, 'notes.md'), '# plain\n')

function setRunning() {
  writeFileSync(join(osRoot, '11_runtime', 'run-status.yaml'),
    'engagement_status: "ACTIVE"\ncurrent_cycle: "C-0001"\n')
  writeFileSync(join(osRoot, '04_cycles', 'C-0001', 'plan.yaml'), 'status: "RUNNING"\n')
}
function setBlocked() {
  writeFileSync(join(osRoot, '11_runtime', 'run-status.yaml'),
    'engagement_status: "ACTIVE"\ncurrent_cycle: "C-0001"\n')
  writeFileSync(join(osRoot, '04_cycles', 'C-0001', 'plan.yaml'), 'status: "BLOCKED"\n')
}
function setBootstrap() {
  writeFileSync(join(osRoot, '11_runtime', 'run-status.yaml'),
    'engagement_status: "BOOTSTRAP"\ncurrent_cycle: null\n')
}

const h = harness()

// ---- R1: projection writes are denied (fs tools, monotonic guard) ----------
check('write to 11_runtime/current-context.md denied',
  !!h.guardReason(exec('write', { file_path: '11_runtime/current-context.md', content: 'x' }, osRoot)))
check('edit to absolute 04_cycles/C-0001/plan.yaml denied',
  !!h.guardReason(exec('edit', { file_path: join(osRoot, '04_cycles', 'C-0001', 'plan.yaml'), old_string: 'a', new_string: 'b' }, osRoot)))
check('write to 11_runtime/last-result.md denied',
  !!h.guardReason(exec('write', { file_path: '11_runtime/last-result.md', content: 'x' }, osRoot)))
check('write to 03_hypotheses/active/H-0001.yaml denied',
  !!h.guardReason(exec('write', { file_path: '03_hypotheses/active/H-0001.yaml', content: 'x' }, osRoot)))
check('write to 06_audits/closure-readiness.yaml denied',
  !!h.guardReason(exec('write', { file_path: '06_audits/closure-readiness.yaml', content: 'x' }, osRoot)))
check('write to 10_learning/technique-discoveries.md denied',
  !!h.guardReason(exec('write', { file_path: '10_learning/technique-discoveries.md', content: 'x' }, osRoot)))

// ---- R2: the ledger is not writable directly -------------------------------
check('write to 11_runtime/events.jsonl denied',
  !!h.guardReason(exec('write', { file_path: '11_runtime/events.jsonl', content: '{}' }, osRoot)))
check('append via shell (>> events.jsonl) denied',
  !!h.guardReason(exec('bash', { command: 'echo {} >> 11_runtime/events.jsonl' }, osRoot)))
check('sed -i on run-status.yaml denied',
  !!h.guardReason(exec('bash', { command: 'sed -i "" "s/BOOTSTRAP/ACTIVE/" 11_runtime/run-status.yaml' }, osRoot)))
check('cp into a protected path denied',
  !!h.guardReason(exec('bash', { command: 'cp /tmp/events.bak 11_runtime/events.jsonl' }, osRoot)))
check('heredoc write into a protected path denied',
  !!h.guardReason(exec('bash', { command: "python3 - <<'PY'\nopen('11_runtime/events.jsonl','a').write('x')\nPY" }, osRoot)))
check('rm of the ledger denied',
  !!h.guardReason(exec('bash', { command: 'rm 11_runtime/events.jsonl' }, osRoot)))
check('unlink of a projection denied',
  !!h.guardReason(exec('bash', { command: 'unlink 11_runtime/last-result.md' }, osRoot)))
check('rmdir inside the evidence store denied',
  !!h.guardReason(exec('bash', { command: 'rmdir 11_runtime/evidence-store/run-1' }, osRoot)))
check('rm outside protected paths allowed',
  !h.guardReason(exec('bash', { command: 'rm -f 08_artifacts/raw/capture.txt' }, osRoot)))

// ---- R1/R2: directory-level destruction of control-plane-owned material ----------
check('rm -rf 11_runtime denied (directory-level destruction)',
  !!h.guardReason(exec('bash', { command: 'rm -rf 11_runtime' }, osRoot)))
check('rm 11_runtime/* denied (glob resolves to the protected directory)',
  !!h.guardReason(exec('bash', { command: 'rm 11_runtime/*' }, osRoot)))
check('rmdir 11_runtime denied',
  !!h.guardReason(exec('bash', { command: 'rmdir 11_runtime' }, osRoot)))
check('mv 11_runtime /tmp/x denied',
  !!h.guardReason(exec('bash', { command: 'mv 11_runtime /tmp/x' }, osRoot)))
check('find 11_runtime -delete denied',
  !!h.guardReason(exec('bash', { command: 'find 11_runtime -delete' }, osRoot)))
check('dd of=11_runtime/run-status.yaml denied',
  !!h.guardReason(exec('bash', { command: 'dd of=11_runtime/run-status.yaml if=/tmp/x' }, osRoot)))
check('ln -sf /dev/null 11_runtime/events.jsonl denied',
  !!h.guardReason(exec('bash', { command: 'ln -sf /dev/null 11_runtime/events.jsonl' }, osRoot)))
check('cd 11_runtime && rm events.jsonl denied (bare name resolved against cd)',
  !!h.guardReason(exec('bash', { command: 'cd 11_runtime && rm events.jsonl' }, osRoot)))
check('rm -rf 03_hypotheses denied (ancestor of protected hypothesis views)',
  !!h.guardReason(exec('bash', { command: 'rm -rf 03_hypotheses' }, osRoot)))
check('rm -rf 10_learning denied (ancestor of the freshness/technique views)',
  !!h.guardReason(exec('bash', { command: 'rm -rf 10_learning' }, osRoot)))
check('rm -rf 11_runtime/ denied (trailing slash normalizes)',
  !!h.guardReason(exec('bash', { command: 'rm -rf 11_runtime/' }, osRoot)))
check('rm -rf 11_runtime_backup allowed (sibling name, not an ancestor)',
  !h.guardReason(exec('bash', { command: 'rm -rf 11_runtime_backup' }, osRoot)))
check('rm -rf 08_artifacts stays allowed (not control-plane-owned)',
  !h.guardReason(exec('bash', { command: 'rm -rf 08_artifacts/raw' }, osRoot)))
check('reading through cd stays allowed (no write shape)',
  !h.guardReason(exec('bash', { command: 'cd 11_runtime && cat run-status.yaml' }, osRoot)))

// ---- workspace detection survives ledger deletion (interpreter bypass) ------
const noLedger = join(sandbox, 'no-ledger')
mkdirSync(join(noLedger, '00_control'), { recursive: true })
writeFileSync(join(noLedger, 'OS_VERSION'), '7.1\n')
writeFileSync(join(noLedger, '00_control', 'engagement.yaml'), 'scope:\n  gate: none\n')
check('OS_VERSION + engagement.yaml (no ledger) still detected: ledger write denied',
  !!h.guardReason(exec('write', { file_path: '11_runtime/events.jsonl', content: '{}' }, noLedger)))
const runtimeOnly = join(sandbox, 'runtime-only')
mkdirSync(join(runtimeOnly, '11_runtime'), { recursive: true })
writeFileSync(join(runtimeOnly, 'OS_VERSION'), '7.1\n')
check('OS_VERSION + 11_runtime/ (no ledger) still detected: projection write denied',
  !!h.guardReason(exec('write', { file_path: '11_runtime/last-result.md', content: 'x' }, runtimeOnly)))

// ---- W3: OS_VERSION is protected material; detection survives marker deletion ----
check('write to OS_VERSION denied',
  !!h.guardReason(exec('write', { file_path: 'OS_VERSION', content: '9.9\n' }, osRoot)))
check('edit to OS_VERSION denied',
  !!h.guardReason(exec('edit', { file_path: join(osRoot, 'OS_VERSION'), old_string: 'x', new_string: 'y' }, osRoot)))
check('rm OS_VERSION denied',
  !!h.guardReason(exec('bash', { command: 'rm OS_VERSION' }, osRoot)))
check('redirect onto OS_VERSION denied',
  !!h.guardReason(exec('bash', { command: 'echo 9.9 > OS_VERSION' }, osRoot)))
const noMarker = join(sandbox, 'no-marker')
mkdirSync(join(noMarker, '11_runtime'), { recursive: true })
mkdirSync(join(noMarker, '00_control'), { recursive: true })
writeFileSync(join(noMarker, '11_runtime', 'events.jsonl'), '')
writeFileSync(join(noMarker, '00_control', 'engagement.yaml'), 'scope:\n  gate: none\n')
check('marker deleted but ledger present: ledger write still denied',
  !!h.guardReason(exec('write', { file_path: '11_runtime/events.jsonl', content: '{}' }, noMarker)))
check('marker deleted but engagement binding present: protected write still denied',
  !!h.guardReason(exec('bash', { command: 'echo x >> 11_runtime/events.jsonl' }, noMarker)))

// ---- R5: the preflight token store is control-plane-owned -------------------
check('write to 11_runtime/action-tokens.jsonl denied',
  !!h.guardReason(exec('write', { file_path: '11_runtime/action-tokens.jsonl', content: '{}' }, osRoot)))
check('append via shell (>> action-tokens.jsonl) denied',
  !!h.guardReason(exec('bash', { command: 'echo {} >> 11_runtime/action-tokens.jsonl' }, osRoot)))
check('reading the token store with cat allowed',
  !h.guardReason(exec('bash', { command: 'cat 11_runtime/action-tokens.jsonl' }, osRoot)))
check('researchctl prepare stays allowed',
  !h.guardReason(exec('bash', { command: 'python3 tools/researchctl.py . prepare payload.json' }, osRoot)))

// ---- live false positive (2026-09-21): `2>&1` is a descriptor duplication, not a
// ---- file write; reading protected files through bash must stay allowed.
check('read with 2>&1 allowed (live false-positive case)',
  !h.guardReason(exec('bash', { command: 'ncat 11_runtime/events.jsonl 2>&1 | head -n 100' }, osRoot)))
check('researchctl with 2>&1 allowed',
  !h.guardReason(exec('bash', { command: 'python3 tools/researchctl.py . status 2>&1 | head -n 200' }, osRoot)))
check('copying a protected file into /tmp allowed (read path)',
  !h.guardReason(exec('bash', { command: 'cat 11_runtime/run-status.yaml > /tmp/rs.yaml' }, osRoot)))

// ---- allowed work stays allowed --------------------------------------------
check('writing evidence artifacts under 08_artifacts/ allowed',
  !h.guardReason(exec('write', { file_path: '08_artifacts/raw/capture.txt', content: 'x' }, osRoot)))
check('reading a projection with cat allowed',
  !h.guardReason(exec('bash', { command: 'cat 11_runtime/last-result.md' }, osRoot)))
check('running researchctl allowed',
  !h.guardReason(exec('bash', { command: 'python3 tools/researchctl.py . next' }, osRoot)))
check('plain (non-OS) workspace untouched: write allowed',
  !h.guardReason(exec('write', { file_path: 'notes.md', content: 'x' }, plain)))
check('plain (non-OS) workspace untouched: curl allowed',
  (await h.preExecute(exec('bash', { command: 'curl https://example.com' }, plain))).kind === 'allow')

// ---- R3: live target access needs a RUNNING cycle --------------------------
setBootstrap()
check('BOOTSTRAP + curl to remote denied',
  (await h.preExecute(exec('bash', { command: 'curl https://target.example/api' }, osRoot))).kind === 'deny')
check('BOOTSTRAP + wget denied',
  (await h.preExecute(exec('bash', { command: 'wget -q https://target.example/x' }, osRoot))).kind === 'deny')
check('BOOTSTRAP + localhost curl allowed',
  (await h.preExecute(exec('bash', { command: 'curl http://localhost:8080/health' }, osRoot))).kind === 'allow')
check('BOOTSTRAP + lab 127.0.0.1 allowed',
  (await h.preExecute(exec('bash', { command: 'curl http://127.0.0.1:3000/api' }, osRoot))).kind === 'allow')
check('BOOTSTRAP + npm install allowed (provisioning, not target access)',
  (await h.preExecute(exec('bash', { command: 'npm install left-pad' }, osRoot))).kind === 'allow')
check('BOOTSTRAP + git clone allowed',
  (await h.preExecute(exec('bash', { command: 'git clone https://github.com/x/y' }, osRoot))).kind === 'allow')

setBlocked()
check('BLOCKED cycle + curl denied',
  (await h.preExecute(exec('bash', { command: 'curl https://target.example/api' }, osRoot))).kind === 'deny')

setRunning()
const runDeny = await h.preExecute(exec('bash', { command: 'curl https://target.example/api' }, osRoot))
check('RUNNING cycle + raw curl denied (executor is the live path)',
  runDeny.kind === 'deny' && runDeny.reason.includes('research_os_request'))
check('RUNNING cycle + ssh to a remote host denied',
  (await h.preExecute(exec('bash', { command: 'ssh user@host.example -p 22' }, osRoot))).kind === 'deny')
check('RUNNING cycle + localhost curl still allowed',
  (await h.preExecute(exec('bash', { command: 'curl http://127.0.0.1:3000/api' }, osRoot))).kind === 'allow')

// ---- R6: raw browser automation is not the live path ------------------------
const browserDeny = await h.preExecute(exec('bash', { command: 'npx playwright codegen https://target.example/app' }, osRoot))
check('raw playwright launch denied (points at research_os_browser)',
  browserDeny.kind === 'deny' && browserDeny.reason.includes('research_os_browser'))
check('headless chrome launch denied',
  (await h.preExecute(exec('bash', { command: 'chrome --headless --dump-dom https://target.example/' }, osRoot))).kind === 'deny')
check('remote-debugging launch denied',
  (await h.preExecute(exec('bash', { command: 'chromium --remote-debugging-port=9222 https://target.example/' }, osRoot))).kind === 'deny')
check('playwright install allowed (provisioning)',
  (await h.preExecute(exec('bash', { command: 'npm install playwright-core' }, osRoot))).kind === 'allow')
check('playwright version check allowed',
  (await h.preExecute(exec('bash', { command: 'npx playwright --version' }, osRoot))).kind === 'allow')
check('npx playwright install chromium allowed (the runner provisioning instruction)',
  (await h.preExecute(exec('bash', { command: 'npx playwright install chromium' }, osRoot))).kind === 'allow')
check('npx with flags before the package is still install-shaped',
  (await h.preExecute(exec('bash', { command: 'npx -y playwright install chromium' }, osRoot))).kind === 'allow')
check('npx playwright test with a remote URL still hits the browser gate',
  (await h.preExecute(exec('bash', { command: 'npx playwright test https://target.example/app' }, osRoot))).kind === 'deny')
check('explicit localhost browser work allowed',
  (await h.preExecute(exec('bash', { command: 'npx playwright codegen http://127.0.0.1:3000' }, osRoot))).kind === 'allow')

// ---- R6 compound commands: install shape is judged per SEGMENT, not per string ------
check('install && remote playwright test denied (compound bypass closed)',
  (await h.preExecute(exec('bash', { command: 'npx playwright install chromium && npx playwright test https://target.example' }, osRoot))).kind === 'deny')
check('npm install && remote playwright test denied (pre-existing hole)',
  (await h.preExecute(exec('bash', { command: 'npm install left-pad && npx playwright test https://target.example' }, osRoot))).kind === 'deny')
check('install with || and remote codegen denied',
  (await h.preExecute(exec('bash', { command: 'npx playwright install chromium || npx playwright codegen https://target.example' }, osRoot))).kind === 'deny')
check('install with ; and remote test denied',
  (await h.preExecute(exec('bash', { command: 'npx playwright install chromium; npx playwright test https://target.example' }, osRoot))).kind === 'deny')
check('install with | and remote test denied',
  (await h.preExecute(exec('bash', { command: 'npx playwright install chromium | npx playwright test https://target.example' }, osRoot))).kind === 'deny')
check('two install-shaped segments stay allowed',
  (await h.preExecute(exec('bash', { command: 'npx playwright install chromium && npx playwright install firefox' }, osRoot))).kind === 'allow')
check('install && localhost browser work still allowed',
  (await h.preExecute(exec('bash', { command: 'npx playwright install chromium && npx playwright codegen http://127.0.0.1:3000' }, osRoot))).kind === 'allow')
check('install && version check stays allowed',
  (await h.preExecute(exec('bash', { command: 'npx playwright install chromium && npx playwright --version' }, osRoot))).kind === 'allow')
check('browser launch in a non-OS workspace allowed',
  (await h.preExecute(exec('bash', { command: 'npx playwright test' }, plain))).kind === 'allow')

// ---- denial reasons are actionable -----------------------------------------
const denial = await (async () => { setBootstrap(); return h.preExecute(exec('bash', { command: 'curl https://target.example/x' }, osRoot)) })()
check('deny reason names the enforcer and the fix',
  denial.kind === 'deny' && denial.reason.includes('research-os-enforcer') && denial.reason.includes('researchctl'))

setRunning()
const guardDenial = h.guardReason(exec('write', { file_path: '11_runtime/current-context.md', content: 'x' }, osRoot))
check('guard reason tells the model what to do instead',
  !!guardDenial && guardDenial.includes('researchctl'))

// ---- protected-path additions: freshness, evidence store, bootstrap-conditional ----
check('write to 10_learning/freshness.yaml denied',
  !!h.guardReason(exec('write', { file_path: '10_learning/freshness.yaml', content: 'x' }, osRoot)))
check('write to 10_learning/knowledge-usage.yaml denied',
  !!h.guardReason(exec('write', { file_path: '10_learning/knowledge-usage.yaml', content: 'x' }, osRoot)))
check('write to 10_learning/knowledge-proposals.yaml denied',
  !!h.guardReason(exec('write', { file_path: '10_learning/knowledge-proposals.yaml', content: 'x' }, osRoot)))
check('write to 10_learning/knowledge-proposals/KP-0001-x.md denied',
  !!h.guardReason(exec('write', { file_path: '10_learning/knowledge-proposals/KP-0001-x.md', content: 'x' }, osRoot)))
check('rm -rf 10_learning/knowledge-proposals denied (directory-level destruction)',
  !!h.guardReason(exec('bash', { command: 'rm -rf 10_learning/knowledge-proposals' }, osRoot)))
check('rm of a proposal artifact denied',
  !!h.guardReason(exec('bash', { command: 'rm 10_learning/knowledge-proposals/KP-0001-x.md' }, osRoot)))
check('write under 11_runtime/evidence-store/ denied',
  !!h.guardReason(exec('write', { file_path: '11_runtime/evidence-store/abc.http', content: 'x' }, osRoot)))
check('write to 00_control/engagement.yaml denied outside BOOTSTRAP',
  !!h.guardReason(exec('write', { file_path: '00_control/engagement.yaml', content: 'x' }, osRoot)))
check('write to 00_control/identity-binding.yaml denied outside BOOTSTRAP',
  !!h.guardReason(exec('write', { file_path: '00_control/identity-binding.yaml', content: 'x' }, osRoot)))
setBootstrap()
check('write to 00_control/engagement.yaml allowed during BOOTSTRAP',
  !h.guardReason(exec('write', { file_path: '00_control/engagement.yaml', content: 'x' }, osRoot)))
check('write to 00_control/identity-binding.yaml allowed during BOOTSTRAP',
  !h.guardReason(exec('write', { file_path: '00_control/identity-binding.yaml', content: 'x' }, osRoot)))
setRunning()
check('write to 00_control/identity-binding.yaml denied when status is ACTIVE',
  !!h.guardReason(exec('write', { file_path: '00_control/identity-binding.yaml', content: 'x' }, osRoot)))
// Unreadable status (no run-status.yaml at all): bootstrap-conditional writes fail closed.
rmSync(join(osRoot, '11_runtime', 'run-status.yaml'))
check('unreadable status (no run-status.yaml) -> engagement write denied',
  !!h.guardReason(exec('write', { file_path: '00_control/engagement.yaml', content: 'x' }, osRoot)))
setRunning()
check('mentionsProtected finds a protected marker in shell text',
  mentionsProtected('rm 11_runtime/events.jsonl') === true)
check('mentionsProtected ignores unrelated text',
  mentionsProtected('rm -rf ~/Downloads') === false)
// Guard internal error: fail closed on protected material, fail open otherwise.
const brokenSession = (filePath) => ({
  name: 'write',
  arguments: { file_path: filePath, content: 'x' },
  get agent() { throw new Error('simulated guard failure') },
})
const brokenReason = h.guardReason(brokenSession('11_runtime/events.jsonl'))
check('guard internal error + protected marker fails closed',
  !!brokenReason && brokenReason.includes('failing closed'))
check('guard internal error without protected marker fails open',
  !h.guardReason(brokenSession('notes.md')))

// ---- R4: preflight token selection (pure helpers) ---------------------------
const shape1 = shapeFromArgs({ method: 'get', url: 'https://t.example/x', principal: 'A', headers: { 'X-A': '1' } })
check('shape normalizes method and header keys', shape1.method === 'GET' && shape1.headers['x-a'] === '1')

// ---- headers shape validation: non-plain objects are rejected, never mis-hashed ----
let headerReject = null
try { shapeFromArgs({ method: 'GET', url: 'https://t.example/x', principal: 'A', headers: ['authorization'] }) } catch (e) { headerReject = String(e.message) }
check('array headers rejected with a clear error', !!headerReject && /plain object/i.test(headerReject))
headerReject = null
try { shapeFromArgs({ method: 'GET', url: 'https://t.example/x', principal: 'A', headers: new Headers({ 'x-a': '1' }) }) } catch (e) { headerReject = String(e.message) }
check('Headers instance rejected with a clear error', !!headerReject && /plain object/i.test(headerReject))
headerReject = null
try { shapeFromArgs({ method: 'GET', url: 'https://t.example/x', principal: 'A', headers: 'x-a: 1' }) } catch (e) { headerReject = String(e.message) }
check('string headers rejected with a clear error', !!headerReject && /plain object/i.test(headerReject))
check('empty object headers still accepted',
  JSON.stringify(shapeFromArgs({ method: 'GET', url: 'https://t.example/x', principal: 'A', headers: {} }).headers) === '{}')
check('absent headers stay absent',
  shapeFromArgs({ method: 'GET', url: 'https://t.example/x', principal: 'A' }).headers === undefined)
check('digest is key-order independent',
  canonicalDigest(shape1) === canonicalDigest({ headers: { 'x-a': '1' }, principal: 'A', url: 'https://t.example/x', method: 'GET' }))
const nowMs = Date.now()
const mk = (over) => ({ action_id: 'A-1', argument_digest: 'd', tool_family: 'http', expires_at: new Date(nowMs + 60000).toISOString(), consumed: false, ...over })
check('token matches its digest', !!selectToken(new Map([['A-1', mk({})]]), 'd', nowMs))
check('digest mismatch rejected', !selectToken(new Map([['A-1', mk({})]]), 'other', nowMs))
check('expired token rejected', !selectToken(new Map([['A-1', mk({ expires_at: new Date(nowMs - 1000).toISOString() })]]), 'd', nowMs))
check('consumed token rejected', !selectToken(new Map([['A-1', mk({ consumed: true })]]), 'd', nowMs))
check('browser family token not selected for http',
  !selectToken(new Map([['A-2', mk({ tool_family: 'browser' })]]), 'd', nowMs))
check('browser family token selected for browser',
  !!selectToken(new Map([['A-2', mk({ tool_family: 'browser' })]]), 'd', nowMs, 'browser'))

// ---- canonical `request_shape` digest parity vectors (tools/control_plane.py) ---------
// prepare_action normalizes to the shape below BEFORE hashing; these literals are the
// executor-side digests the Python suite asserts, so the two languages cannot drift.
const parityA = shapeFromArgs({ method: 'get', url: 'https://example.test/h', principal: 'researcher-A',
  headers: { 'X-Custom': 'Value-1', AUTHORIZATION: 'Bearer x' } })
check('canonical digest vector A matches the Python prepare literal',
  canonicalDigest(parityA) === '73582a995dc3e49b19d6f579798cacc7ba1d131f73cb5ac76563cf96a081df3a')
const parityB = shapeFromArgs({ method: 'POST', url: 'https://example.test/b', principal: 'researcher-A', body: '{"probe": "x"}' })
check('canonical digest vector B matches the Python prepare literal',
  canonicalDigest(parityB) === '9ca3f0956193b433cc35f73b1bd5ff07a07c83abc6ca242797627e34f93c1c0d')

// ---- capture hygiene: sensitive headers and secret shapes never persist ---------
check('set-cookie value redacted',
  redactHeaderLine('set-cookie: session=SUPERSECRET; HttpOnly') === 'set-cookie: [REDACTED]')
check('request cookie redacted',
  redactHeaderLine('cookie: session=ABC123') === 'cookie: [REDACTED]')
check('authorization redacted',
  redactHeaderLine('authorization: Bearer abc.def.ghi') === 'authorization: [REDACTED]')
check('benign header untouched', redactHeaderLine('content-type: text/html; charset=utf-8') === 'content-type: text/html; charset=utf-8')
check('gitlab PAT redacted in free text',
  redactSecrets('token=glpat-ABCDEFGHIJKLMNOPQRST') === 'token=[REDACTED]')
check('JWT redacted in free text',
  !redactSecrets('x eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl').includes('eyJhbGciOiJIUzI1NiJ9'))
check('private key block redacted',
  !redactSecrets('-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----').includes('MIIEow'))

// ---- query-secret redaction: sensitive parameter VALUES never reach text or captures ----
check('sensitive query value redacted, host and path kept',
  redactUrlSecrets('https://t.example/a?token=abc&x=1') === 'https://t.example/a?token=[REDACTED]&x=1')
check('parameter names match case-insensitively across the family',
  redactUrlSecrets('https://t.example/?API_KEY=abc&Signature=xyz&Password=pw&foo=bar')
  === 'https://t.example/?API_KEY=[REDACTED]&Signature=[REDACTED]&Password=[REDACTED]&foo=bar')
check('benign query values untouched',
  redactUrlSecrets('https://t.example/a?page=2&sort=name') === 'https://t.example/a?page=2&sort=name')
check('url without a query is unchanged',
  redactUrlSecrets('https://t.example/a#frag') === 'https://t.example/a#frag')
check('fragment after the query is preserved',
  redactUrlSecrets('https://t.example/a?token=abc#frag') === 'https://t.example/a?token=[REDACTED]#frag')
check('value containing = is redacted whole',
  redactUrlSecrets('https://t.example/?token=a=b=c') === 'https://t.example/?token=[REDACTED]')
check('secret-shaped value redacted even under a benign parameter name',
  !redactUrlSecrets('https://t.example/?q=glpat-ABCDEFGHIJKLMNOPQRST').includes('glpat-'))
check('bare query flag without = is kept',
  redactUrlSecrets('https://t.example/?debug&token=abc') === 'https://t.example/?debug&token=[REDACTED]')

// ---- hardened query/fragment redaction: substrings, decoding, separators ----
check('fragment values are masked too',
  redactUrlSecrets('https://t.example/a#access_token=FRAGSECRET') === 'https://t.example/a#access_token=[REDACTED]')
check('query and fragment are both masked in one URL',
  redactUrlSecrets('https://t.example/a?token=QUERYSECRET#session=FRAGSECRET')
  === 'https://t.example/a?token=[REDACTED]#session=[REDACTED]')
check('semicolon-separated parameters are split',
  redactUrlSecrets('https://t.example/?token=abc;x=1') === 'https://t.example/?token=[REDACTED];x=1')
check('percent-encoded separator stays inside the value',
  redactUrlSecrets('https://t.example/?token=a%26b') === 'https://t.example/?token=[REDACTED]')
check('percent-encoded parameter name is decoded before matching',
  redactUrlSecrets('https://t.example/?t%6Fken=abc') === 'https://t.example/?t%6Fken=[REDACTED]')
check('sensitive substrings match the whole family',
  redactUrlSecrets('https://t.example/?access-token=a&client_secret=b&code=c&X-Amz-Signature=d&token2=e')
  === 'https://t.example/?access-token=[REDACTED]&client_secret=[REDACTED]&code=[REDACTED]&X-Amz-Signature=[REDACTED]&token2=[REDACTED]')
check('sensitive parameter with an empty value becomes [REDACTED]',
  redactUrlSecrets('https://t.example/?token=') === 'https://t.example/?token=[REDACTED]')
check('sensitive bare flag without = becomes [REDACTED]',
  redactUrlSecrets('https://t.example/?token') === 'https://t.example/?token=[REDACTED]')
check('non-sensitive parameter keeps its value and the path stays untouched',
  redactUrlSecrets('https://t.example/path?page=2') === 'https://t.example/path?page=2')

// ---- nested (double-encoded) sensitive assignments inside a component value ----
// A value that decodes once to `next=/cb&token=xyz` leaks the token to any downstream
// consumer that decodes `next`: the whole component value is masked.
check('double-encoded nested sensitive assignment masks the whole value',
  redactUrlSecrets('https://t.example/reset/abc?next=/cb%26token%3Dxyz')
  === 'https://t.example/reset/abc?next=[REDACTED]')
check('nested non-sensitive assignment stays readable',
  redactUrlSecrets('https://t.example/reset/abc?next=/cb%26page%3D2')
  === 'https://t.example/reset/abc?next=/cb%26page%3D2')
check('nested sensitive assignment in a fragment value is masked',
  redactUrlSecrets('https://t.example/a#frag=a%26client_secret%3Dx')
  === 'https://t.example/a#frag=[REDACTED]')
check('nested sensitive assignment followed by benign pairs masks the whole value',
  redactUrlSecrets('https://t.example/a?next=a%26token%3Dx%26b=1')
  === 'https://t.example/a?next=[REDACTED]')
check('malformed percent escapes neither throw nor hide a nested assignment',
  redactUrlSecrets('https://t.example/a?next=%zz%26token%3Dx')
  === 'https://t.example/a?next=[REDACTED]')

// ---- R5: per-host scope gate (mirrors `researchctl prepare`) ----------------
mkdirSync(join(osRoot, '00_control'), { recursive: true })
const engagement = join(osRoot, '00_control', 'engagement.yaml')
check('absent engagement.yaml -> scope gate denies (unset)',
  !!scopeReasonFor(osRoot, 'https://anything.example/x'))
writeFileSync(engagement, 'program:\n  name: "x"\n\nscope:\n  assets: [t.example, "*.wild.example"]\n')
check('in-scope exact host allowed', scopeReasonFor(osRoot, 'https://t.example/a') === undefined)
check('wildcard subdomain allowed', scopeReasonFor(osRoot, 'https://a.wild.example/a') === undefined)
check('wildcard base host allowed', scopeReasonFor(osRoot, 'https://wild.example/a') === undefined)
check('out-of-scope host denied with actionable reason',
  (scopeReasonFor(osRoot, 'https://evil.example/a') || '').includes('outside the engagement scope'))
check('schemeless url denied', !!scopeReasonFor(osRoot, 't.example/a'))
check('uppercase host matches lowercase assets', scopeReasonFor(osRoot, 'https://T.Example/a') === undefined)
check('backslash authority denied (fetch would route to the pre-backslash host)',
  !!scopeReasonFor(osRoot, 'http://127.0.0.1:9\\@t.example/'))
check('encoded-backslash authority denied (case-insensitive)',
  !!scopeReasonFor(osRoot, 'http://t.example%5cevil/') && !!scopeReasonFor(osRoot, 'http://t.example%5Cevil/'))
check('userinfo ending at the last @ still allowed', scopeReasonFor(osRoot, 'https://user@t.example/a') === undefined)
check('dispatch guard allows a canonical URL', dispatchHostReason('https://t.example/a') === undefined)
check('dispatch guard refuses a backslash authority without sending',
  !!dispatchHostReason('http://127.0.0.1:9\\@t.example/'))
check('dispatch guard refuses an encoded-backslash authority',
  !!dispatchHostReason('http://t.example%5Cevil/'))
writeFileSync(engagement, 'scope:\n  assets:\n    - t.example\n    - 127.0.0.1:9443\n')
check('block-list assets parsed', scopeReasonFor(osRoot, 'https://127.0.0.1:9443/lab') === undefined)
check('host with port requires port in assets', !!scopeReasonFor(osRoot, 'https://127.0.0.1:9444/lab'))
writeFileSync(engagement, 'scope:\n  assets:\n    - {host: nested}\n')
check('non-simple assets fail closed', !!scopeReasonFor(osRoot, 'https://t.example/a'))
writeFileSync(engagement, 'scope:\n  assets: []\n')
check('empty assets block -> scope gate denies (unset)',
  !!scopeReasonFor(osRoot, 'https://anything.example/x'))
check('unset denial names the fix (scope-set / gate: none)',
  (scopeReasonFor(osRoot, 'https://anything.example/x') || '').includes('gate: none'))
writeFileSync(engagement, 'scope:\n  gate: none\n')
check('scope gate: none opt-out allows any target',
  scopeReasonFor(osRoot, 'https://anything.example/x') === undefined)
writeFileSync(engagement, 'scope:\n  assets: [t.example]\n  gate: none\n')
check('gate: none wins over a configured asset list',
  scopeReasonFor(osRoot, 'https://other.example/x') === undefined)

// ---- canonical `gate: none` parity vectors (must match tools/control_plane.py) -----
const gateVectors = [
  ['bare', 'scope:\n  gate: none\n', true],
  ['double-quoted', 'scope:\n  gate: "none"\n', true],
  ['single-quoted', "scope:\n  gate: 'none'\n", true],
  ['trailing comment', 'scope:\n  gate: none  # opt-out\n', true],
  ['tab indent', 'scope:\n\tgate: none\n', true],
  ['commented-out gate', 'scope:\n  # gate: none\n', false],
  ['other gate value', 'scope:\n  gate: nonexistent\n', false],
  ['other key', 'scope:\n  mygate: none\n', false],
  ['nested gate under a child key', 'scope:\n  exclusions:\n    gate: none\n', false],
  ['flow-style scope (documented limitation)', 'scope: {gate: none}\n', false],
]
for (const [label, text, disabled] of gateVectors) {
  writeFileSync(engagement, text)
  const allowed = scopeReasonFor(osRoot, 'https://anything.example/x') === undefined
  check('canonical gate: ' + label + ' -> ' + (disabled ? 'disabled' : 'not disabled'), allowed === disabled)
}

// ---- host normalization: userinfo + one trailing dot (shared with scope_check) -----
writeFileSync(engagement, 'scope:\n  assets:\n  - "t.example"\n')
check('userinfo in the URL is stripped before host comparison',
  scopeReasonFor(osRoot, 'https://user:pass@t.example/a') === undefined)
check('one trailing dot is stripped before host comparison',
  scopeReasonFor(osRoot, 'https://t.example./a') === undefined)
check('uppercase scheme and host still match',
  scopeReasonFor(osRoot, 'HTTPS://T.EXAMPLE/a') === undefined)

// ---- depth-aware assets parsing (mirrors tools/control_plane.py engagement_assets) --
writeFileSync(engagement, 'assets:\n  - legacy.example\n\nscope:\n  assets:\n  - t.example\n')
check('legacy assets before the scope block is shadowed',
  scopeReasonFor(osRoot, 'https://t.example/a') === undefined)
check('legacy assets before the scope block cannot widen scope',
  !!scopeReasonFor(osRoot, 'https://legacy.example/a'))
writeFileSync(engagement, 'scope:\n  assets:\n  - t.example\n\nassets:\n  - legacy.example\n')
check('legacy assets after the scope block stays shadowed',
  scopeReasonFor(osRoot, 'https://t.example/a') === undefined)
check('legacy assets after the scope block cannot widen scope',
  !!scopeReasonFor(osRoot, 'https://legacy.example/a'))
writeFileSync(engagement, 'scope:\n  exclusions:\n    assets:\n    - nested.example\n  assets:\n  - t.example\n')
check('nested assets under a child key is ignored',
  scopeReasonFor(osRoot, 'https://t.example/a') === undefined)
check('nested assets under a child key cannot widen scope',
  !!scopeReasonFor(osRoot, 'https://nested.example/a'))
writeFileSync(engagement, 'program:\n  assets:\n  - nested.example\n')
check('nested assets without a scope block is not a legacy scope',
  !!scopeReasonFor(osRoot, 'https://nested.example/a'))
writeFileSync(engagement, 'scope:\n  assets:\n  - t.example\n  assets:\n  - evil.example\n')
check('first depth-1 assets entry wins (duplicate entries)',
  scopeReasonFor(osRoot, 'https://t.example/a') === undefined
  && !!scopeReasonFor(osRoot, 'https://evil.example/a'))

// ---- CR-only line endings (the parsers must split on /\r\n|\r|\n/) ------------------
writeFileSync(engagement, 'scope:\r  assets:\r  - "t.example"\r')
check('CR-only engagement.yaml parses the asset list (in-scope allowed)',
  scopeReasonFor(osRoot, 'https://t.example/a') === undefined)
check('CR-only engagement.yaml still denies out-of-scope hosts',
  !!scopeReasonFor(osRoot, 'https://evil.example/a'))
writeFileSync(engagement, 'scope:\r  gate: none\r')
check('CR-only gate: none disables the gate',
  scopeReasonFor(osRoot, 'https://anything.example/x') === undefined)

// ---- web-fetch gate: in-scope hosts are live targets, not research material -------
writeFileSync(engagement, 'scope:\n  assets: [t.example, "*.wild.example"]\n')
const webDeny = await h.preExecute(exec('firecrawl_scrape', { url: 'https://t.example/a' }, osRoot))
check('firecrawl_scrape of an in-scope host denied (points at the executor)',
  webDeny.kind === 'deny' && webDeny.reason.includes('research_os_request'))
check('web fetch of an out-of-scope host allowed (research material)',
  (await h.preExecute(exec('firecrawl_scrape', { url: 'https://docs.example/x' }, osRoot))).kind === 'allow')
check('wildcard-covered host denied for web tools',
  (await h.preExecute(exec('tavily_extract', { urls: ['https://a.wild.example/p'] }, osRoot))).kind === 'deny')
check('web tool call with no URL allowed',
  (await h.preExecute(exec('firecrawl_map', { url: '' }, osRoot))).kind === 'allow')
check('firecrawl_search allowed (search, not target fetch)',
  (await h.preExecute(exec('firecrawl_search', { query: 't.example' }, osRoot))).kind === 'allow')
check('jina_rerank allowed',
  (await h.preExecute(exec('jina_rerank', { query: 'x', documents: ['https://t.example/'] }, osRoot))).kind === 'allow')
check('sanctioned executor untouched by the web gate',
  (await h.preExecute(exec('research_os_request', { url: 'https://t.example/a' }, osRoot))).kind === 'allow')
writeFileSync(engagement, 'scope:\n  assets:\n    - {host: nested}\n')
check('unenforceable scope + web fetch denied (fail closed)',
  (await h.preExecute(exec('firecrawl_scrape', { url: 'https://anything.example/x' }, osRoot))).kind === 'deny')
rmSync(engagement)
check('unset scope + web fetch allowed (research tools stay usable)',
  (await h.preExecute(exec('firecrawl_scrape', { url: 'https://anything.example/x' }, osRoot))).kind === 'allow')
writeFileSync(engagement, 'scope:\n  gate: none\n')
check('gate: none + web fetch allowed',
  (await h.preExecute(exec('firecrawl_scrape', { url: 'https://anything.example/x' }, osRoot))).kind === 'allow')

// ---- web-fetch gate: no-URL calls, normalization, schemeless refs, redaction --------
writeFileSync(engagement, 'scope:\n  assets:\n    - {host: nested}\n')
check('file read with no URL allowed even when scope is unenforceable',
  (await h.preExecute(exec('read', { file_path: 'README.md' }, osRoot))).kind === 'allow')
check('no-URL fetch-shaped call allowed when scope is unenforceable',
  (await h.preExecute(exec('firecrawl_map', { query: 'no url here' }, osRoot))).kind === 'allow')
writeFileSync(engagement, 'scope:\n  assets: [t.example, "*.wild.example"]\n')
check('userinfo URL denied for web tools',
  (await h.preExecute(exec('firecrawl_scrape', { url: 'https://user:pass@t.example/a' }, osRoot))).kind === 'deny')
check('trailing-dot URL denied for web tools',
  (await h.preExecute(exec('jina_read_url', { url: 'https://t.example./a' }, osRoot))).kind === 'deny')
check('case-insensitive URL denied for web tools',
  (await h.preExecute(exec('webfetch', { url: 'HTTPS://T.EXAMPLE/a' }, osRoot))).kind === 'deny')
const schemelessDeny = await h.preExecute(exec('firecrawl_map', { url: 't.example' }, osRoot))
check('schemeless in-scope host denied for web tools',
  schemelessDeny.kind === 'deny' && schemelessDeny.reason.includes("'t.example'"))
check('schemeless wildcard host denied for web tools',
  (await h.preExecute(exec('tavily_extract', { urls: ['a.wild.example'] }, osRoot))).kind === 'deny')
check('schemeless host with a port falls back to the portless asset',
  (await h.preExecute(exec('firecrawl_map', { url: 't.example:8443' }, osRoot))).kind === 'deny')
check('schemeless out-of-scope host allowed',
  (await h.preExecute(exec('firecrawl_map', { url: 'docs.example' }, osRoot))).kind === 'allow')
check('plain file read allowed with a valid asset list',
  (await h.preExecute(exec('read', { file_path: 'README.md' }, osRoot))).kind === 'allow')
check('sanctioned browser executor skips the web gate',
  (await h.preExecute(exec('research_os_browser', { url: 'https://t.example/a' }, osRoot))).kind === 'allow')
const rawUrlDeny = await h.preExecute(exec('firecrawl_scrape', { url: 'https://user:pass@t.example/a' }, osRoot))
check('web deny message carries the normalized host, never the raw URL',
  rawUrlDeny.kind === 'deny' && rawUrlDeny.reason.includes("'t.example'")
  && !rawUrlDeny.reason.includes('user:pass') && !rawUrlDeny.reason.includes('https://'))

// ---- web-fetch gate: path-typed arguments are not schemeless host references --------
check('plain file read with a host-looking path allowed',
  (await h.preExecute(exec('read', { file_path: 't.example/notes.md' }, osRoot))).kind === 'allow')
check('_path-suffixed argument keys skipped for schemeless hosts',
  (await h.preExecute(exec('firecrawl_parse', { input_path: 't.example/x' }, osRoot))).kind === 'allow')
check('out_dir argument key skipped for schemeless hosts',
  (await h.preExecute(exec('firecrawl_extract', { out_dir: 't.example/out' }, osRoot))).kind === 'allow')
check('cwd/workdir/profile argument keys skipped for schemeless hosts',
  (await h.preExecute(exec('firecrawl_map', { cwd: 't.example', workdir: 't.example', profile: 't.example' }, osRoot))).kind === 'allow')
check('schemeless url argument still denied',
  (await h.preExecute(exec('firecrawl_map', { url: 't.example' }, osRoot))).kind === 'deny')
check('schemeless url inside an array still denied',
  (await h.preExecute(exec('tavily_extract', { urls: ['t.example/x'] }, osRoot))).kind === 'deny')

// ---- web-fetch gate: JSON-escaped URLs are decoded before collection ----------------
check('JSON-escaped in-scope URL denied for web tools',
  (await h.preExecute(exec('firecrawl_scrape', { url: 'https:\\/\\/t.example/a' }, osRoot))).kind === 'deny')
check('JSON-escaped out-of-scope URL allowed for web tools',
  (await h.preExecute(exec('firecrawl_scrape', { url: 'https:\\/\\/docs.example/a' }, osRoot))).kind === 'allow')

// ---- web-fetch gate: automation/computer tool names are fetch-shaped too ------------
const automationDeny = await h.preExecute(exec('tinyfish_run_web_automation', { url: 'https://t.example/a' }, osRoot))
check('tinyfish_run_web_automation of an in-scope host denied',
  automationDeny.kind === 'deny' && automationDeny.reason.includes('research_os_request'))
check('run_web_automation of an in-scope host denied',
  (await h.preExecute(exec('run_web_automation', { url: 'https://t.example/a' }, osRoot))).kind === 'deny')
check('computer tool of an in-scope host denied',
  (await h.preExecute(exec('computer', { url: 'https://t.example/a' }, osRoot))).kind === 'deny')
check('run_web_automation of an out-of-scope host allowed',
  (await h.preExecute(exec('run_web_automation', { url: 'https://docs.example/x' }, osRoot))).kind === 'allow')
check('automation run_search variant excluded from the web gate',
  (await h.preExecute(exec('run_web_automation_search', { query: 't.example' }, osRoot))).kind === 'allow')

// ---- web-fetch gate: an unreadable scope file fails CLOSED --------------------------
rmSync(engagement, { force: true })
mkdirSync(engagement)
const unreadableDeny = await h.preExecute(exec('firecrawl_scrape', { url: 'https://t.example/a' }, osRoot))
check('unreadable scope + in-scope URL -> web fetch denied (fail closed)',
  unreadableDeny.kind === 'deny' && unreadableDeny.reason.includes('scope'))
check('unreadable scope + out-of-scope URL -> web fetch denied too (fail closed)',
  (await h.preExecute(exec('firecrawl_scrape', { url: 'https://docs.example/a' }, osRoot))).kind === 'deny')
check('unreadable scope: fetch-shaped call with a non-URL string denied (fail closed)',
  (await h.preExecute(exec('firecrawl_map', { query: 'no url here' }, osRoot))).kind === 'deny')
check('plain file read allowed even with an unreadable scope (no URL, no host reference)',
  (await h.preExecute(exec('read', { file_path: 'README.md' }, osRoot))).kind === 'allow')
rmSync(engagement, { recursive: true, force: true })
writeFileSync(engagement, 'scope:\n  assets: [t.example, "*.wild.example"]\n')

// ---- web-fetch gate: browser/automation fetch tools are target access too ----------
const browserNavigateDeny = await h.preExecute(exec('mcp__playwright__browser_navigate', { url: 'https://t.example/a' }, osRoot))
check('mcp__playwright__browser_navigate of an in-scope host denied',
  browserNavigateDeny.kind === 'deny' && browserNavigateDeny.reason.includes('research_os_browser'))
check('mcp__playwright__browser_navigate of an out-of-scope host allowed',
  (await h.preExecute(exec('mcp__playwright__browser_navigate', { url: 'https://docs.example/x' }, osRoot))).kind === 'allow')
check('research_os_browser stays allowed (sanctioned executor checked before the pattern)',
  (await h.preExecute(exec('research_os_browser', { url: 'https://t.example/a' }, osRoot))).kind === 'allow')
check('firecrawl_search stays allowed (search is not target fetch)',
  (await h.preExecute(exec('firecrawl_search', { query: 't.example' }, osRoot))).kind === 'allow')

rmSync(sandbox, { recursive: true, force: true })
console.log(`\n${passed}/${passed + failures.length} passed`)
if (failures.length) {
  console.log('FAILURES: ' + failures.join(' | '))
  process.exit(1)
}
