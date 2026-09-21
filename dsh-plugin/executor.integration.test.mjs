/**
 * Executor integration test — the full R4 chain against a real local lab server:
 * prepare (researchctl) → research_os_request consumes the token → HTTP request →
 * capture under 08_artifacts/raw/ → evidence registered → ACTION_RECORDED in the ledger
 * → the token is single-use → a mismatched digest cannot authorize.
 *
 * Run: node executor.integration.test.mjs
 */
import { execFileSync } from 'node:child_process'
import { appendFileSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
const MODULE = process.env.ENFORCER_MODULE || './index.js'
const { browserShapeFromArgs, canonicalDigest, runControlledBrowser, runControlledRequest, shapeFromArgs } = await import(MODULE)

let passed = 0
const failures = []
function check(label, cond) {
  if (cond) { passed += 1; console.log('ok: ' + label) }
  else { failures.push(label); console.log('FAIL: ' + label) }
}

const OS_REPO = join(dirname(fileURLToPath(import.meta.url)), '..')

const LEAK_TOKEN = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZWNyZXQifQ.c2lnbmF0dXJl'
let labHits = 0
const server = createServer((req, res) => {
  labHits += 1
  if (req.url.startsWith('/secret')) {
    res.writeHead(200, {
      'content-type': 'text/plain',
      'set-cookie': 'session=SUPERSECRETVALUE; HttpOnly; Secure',
    })
    res.end('response body carries ' + LEAK_TOKEN)
    return
  }
  res.writeHead(200, { 'content-type': 'text/plain' })
  res.end('hello-from-lab')
})
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
const url = `http://127.0.0.1:${server.address().port}/ok`

const root = mkdtempSync(join(tmpdir(), 'enforcer-exec-'))
cpSync(join(OS_REPO, 'tools'), join(root, 'tools'), { recursive: true })
writeFileSync(join(root, 'OS_VERSION'), '7.1\n')

// 1b. Scope fixture: an unset scope denies at prepare and at the executor, so the lab
//     host must be a listed asset for the happy-path chain below.
mkdirSync(join(root, '00_control'), { recursive: true })
writeFileSync(join(root, '00_control', 'engagement.yaml'), `scope:\n  assets: ["127.0.0.1:${server.address().port}"]\n`)

// 1. A real RUNNING cycle built through the control plane.
const setupPy = join(root, 'setup.py')
writeFileSync(setupPy, [
  'import sys',
  'from pathlib import Path',
  'sys.path.insert(0, sys.argv[2])',
  'from control_plane import ControlPlane',
  'root = Path(sys.argv[1])',
  "for d in ['02_surface','03_hypotheses/active','03_hypotheses/archive','04_cycles','10_learning','11_runtime']:",
  "    (root / d).mkdir(parents=True, exist_ok=True)",
  "(root / '02_surface/endpoints.yaml').write_text('endpoints: []\\n')",
  'cp = ControlPlane(root)',
  "cp.create_cycle('C-0001', {'id':'C-0001','type':'DISCOVERY','objective':'executor integration','allowed_scope':['127.0.0.1'],'stop_conditions':['stop'],'status':'PLANNED','knowledge_triage':[{'pack':'api-protocols','verdict':'USE','reason':'integration test'}]})",
  "(root / '04_cycles/C-0001/objective.md').write_text('# Cycle Objective\\n\\n## Question\\nDoes the executor work?\\n\\n## Minimal test\\nOne local lab request.\\n')",
  "cp.create_hypothesis('H-0001', {'cycle_id':'C-0001','observation':'o','hypothesis':'h','secure_prediction':'s','vulnerable_prediction':'v'})",
  "cp.transition_cycle('C-0001','READY',reason='ready')",
  "cp.transition_cycle('C-0001','RUNNING',reason='run')",
  "print('setup ok')",
].join('\n') + '\n')
execFileSync('python3', [setupPy, root, join(root, 'tools')], { encoding: 'utf8', timeout: 60000 })

// 2. Prepare a single-use preflight token for the lab URL.
const shape = shapeFromArgs({ method: 'GET', url, principal: 'researcher-A' })
const preparePayload = {
  cycle_id: 'C-0001', target: url, scope_status: 'IN_SCOPE', account: 'researcher-A',
  object_owner: 'researcher-A', purpose: 'executor integration', hypothesis: 'H-0001',
  expected_secure: 'lab responds 200', expected_vulnerable: 'n/a', side_effect: 'none',
  stop_condition: 'stop after one request', tool_family: 'http', request_shape: shape,
}
const preparePath = join(root, 'prepare.json')
writeFileSync(preparePath, JSON.stringify(preparePayload))
const prepareNonce = JSON.parse(execFileSync(
  'python3', [join(root, 'tools', 'researchctl.py'), root, 'prepare', preparePath],
  { encoding: 'utf8', timeout: 60000 })).nonce

// 3. The executor consumes the token, reaches the lab, and records the chain.
const r1 = await runControlledRequest({ root, args: { method: 'GET', url, principal: 'researcher-A' } })
check('executor reaches the lab and consumes the token',
  r1.ok === true && r1.text.includes('HTTP 200') && r1.text.includes('hello-from-lab') && r1.text.includes('token consumed'))
const ledger = readFileSync(join(root, '11_runtime/events.jsonl'), 'utf8')
check('evidence registered for the capture', ledger.includes('EVIDENCE_REGISTERED'))
check('action recorded with the token id', ledger.includes('ACTION_RECORDED') && ledger.includes('A-000001'))
const recordedAction = ledger.split('\n').filter(Boolean).map((line) => JSON.parse(line))
  .find((event) => event.type === 'ACTION_RECORDED')
check('action payload carries the consumed token nonce',
  Boolean(recordedAction) && recordedAction.payload.token_nonce === prepareNonce)
check('token marked consumed in the store',
  readFileSync(join(root, '11_runtime/action-tokens.jsonl'), 'utf8').includes('"consumed":true'))
check('capture registered under 08_artifacts/raw',
  readFileSync(join(root, '11_runtime/evidence-index.jsonl'), 'utf8').includes('08_artifacts/raw/'))

// 3b. Capture hygiene: sensitive request/response values are redacted at write time.
//     (29_SECURITY_HYGIENE: RAW -> SANITIZE -> REFERENCE; audit re-scans evidence.)
const secretUrl = new URL('/secret', url).toString()
const secretShape = shapeFromArgs({
  method: 'GET', url: secretUrl, principal: 'researcher-A',
  headers: { Cookie: 'session=REQUESTSECRET', Authorization: 'Bearer ' + LEAK_TOKEN },
})
writeFileSync(preparePath, JSON.stringify({ ...preparePayload, target: secretUrl, request_shape: secretShape }))
execFileSync('python3', [join(root, 'tools', 'researchctl.py'), root, 'prepare', preparePath], { encoding: 'utf8', timeout: 60000 })
const rs = await runControlledRequest({
  root,
  args: {
    method: 'GET', url: secretUrl, principal: 'researcher-A',
    headers: { Cookie: 'session=REQUESTSECRET', Authorization: 'Bearer ' + LEAK_TOKEN },
  },
})
check('secret response still reaches the researcher', rs.ok === true && rs.text.includes('HTTP 200'))
const secretRel = rs.text.match(/capture: (\S+)/)[1]
const secretCapture = readFileSync(join(root, secretRel), 'utf8')
check('set-cookie value redacted in the capture',
  secretCapture.includes('set-cookie: [REDACTED]') && !secretCapture.includes('SUPERSECRETVALUE'))
check('request credentials redacted in the capture',
  secretCapture.includes('cookie: [REDACTED]') && secretCapture.includes('authorization: [REDACTED]')
  && !secretCapture.includes('REQUESTSECRET'))
check('secret-shaped body values redacted from capture and tool output',
  !secretCapture.includes(LEAK_TOKEN) && !rs.text.includes(LEAK_TOKEN) && secretCapture.includes('[REDACTED]'))

// 4. Single use: the same call cannot ride the same token twice.
const r2 = await runControlledRequest({ root, args: { method: 'GET', url, principal: 'researcher-A' } })
check('token is single-use', r2.ok === false && r2.text.includes('no matching unconsumed preflight token'))

// 5. A token prepared for another URL cannot authorize this call.
const otherShape = shapeFromArgs({ method: 'GET', url: url + '/other', principal: 'researcher-A' })
writeFileSync(preparePath, JSON.stringify({ ...preparePayload, target: url + '/other', request_shape: otherShape }))
execFileSync('python3', [join(root, 'tools', 'researchctl.py'), root, 'prepare', preparePath], { encoding: 'utf8', timeout: 60000 })
const r3 = await runControlledRequest({ root, args: { method: 'GET', url, principal: 'researcher-A' } })
check('mismatched digest cannot authorize', r3.ok === false)

// 6. R5: the executor reads engagement scope itself — a hand-crafted token (the token
//    store is the only writer surface prepare does not gate at runtime) cannot
//    authorize an out-of-scope host, and the request never reaches the network.
mkdirSync(join(root, '00_control'), { recursive: true })
const engagementPath = join(root, '00_control', 'engagement.yaml')
const tokensPath = join(root, '11_runtime/action-tokens.jsonl')
let craftedId = 0
function craftToken(shape, family = 'http') {
  craftedId += 1
  appendFileSync(tokensPath, JSON.stringify({
    action_id: `A-9${String(craftedId).padStart(5, '0')}`,
    nonce: `crafted-${craftedId}`,
    argument_digest: canonicalDigest(shape),
    tool_family: family,
    expires_at: new Date(Date.now() + 60000).toISOString(),
    consumed: false,
    cycle_id: 'C-0001',
    preflight: preparePayload,
  }) + '\n')
}
function runnerRuns() {
  try {
    return readFileSync(join(root, 'runs.log'), 'utf8').trim().split('\n').filter(Boolean).length
  } catch {
    return 0
  }
}
writeFileSync(engagementPath, 'scope:\n  assets: ["allowed.example"]\n')
const craftShapeA = shapeFromArgs({ method: 'GET', url, principal: 'researcher-A' })
craftToken(craftShapeA)
const hitsBefore = labHits
const r4 = await runControlledRequest({ root, args: { method: 'GET', url, principal: 'researcher-A' } })
check('out-of-scope host refused before dispatch (scope read from engagement.yaml)',
  r4.ok === false && r4.text.includes('outside the engagement scope') && labHits === hitsBefore)

// 7. In-scope control: the same crafted-token path reaches the lab once the host is listed.
writeFileSync(engagementPath, `scope:\n  assets: ["127.0.0.1:${server.address().port}"]\n`)
craftToken(shapeFromArgs({ method: 'GET', url, principal: 'researcher-A' }))
const r5 = await runControlledRequest({ root, args: { method: 'GET', url, principal: 'researcher-A' } })
check('in-scope host passes the executor scope gate', r5.ok === true && labHits === hitsBefore + 1)

// 8. R6: the browser arm — prepare (tool_family browser) -> research_os_browser runs the
//    canonical runner (stubbed here) -> capture + evidence + ACTION_RECORDED, single-use.
mkdirSync(join(root, 'tools', 'bua'), { recursive: true })
writeFileSync(join(root, 'tools', 'bua', 'run.mjs'), [
  "import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs'",
  "import { join } from 'node:path'",
  'const args = process.argv.slice(2)',
  "const get = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d }",
  "const url = get('--url', ''); const out = get('--out-dir', '08_artifacts/raw'); const action = get('--action', 'bua')",
  'mkdirSync(out, { recursive: true })',
  "writeFileSync(join(out, action + '-stub.png'), 'png')",
  "appendFileSync(join(process.cwd(), 'runs.log'), url + '\\n')",
  "console.log('ARTIFACT ' + join(out, action + '-stub.png'))",
  'process.exit(0)',
].join('\n') + '\n')
const browserUrl = url + '/app'
const browserShape = browserShapeFromArgs({ url: browserUrl, principal: 'researcher-A' })
writeFileSync(preparePath, JSON.stringify({ ...preparePayload, target: browserUrl, tool_family: 'browser', request_shape: browserShape }))
execFileSync('python3', [join(root, 'tools', 'researchctl.py'), root, 'prepare', preparePath], { encoding: 'utf8', timeout: 60000 })
const br1 = await runControlledBrowser({ root, args: { url: browserUrl, principal: 'researcher-A' } })
check('browser executor runs the runner and consumes the token',
  br1.ok === true && br1.text.includes('runner exit 0') && br1.text.includes('token consumed'))
check('browser run captured as browser-executor evidence',
  readFileSync(join(root, '11_runtime/evidence-index.jsonl'), 'utf8').includes('browser-executor'))
const br2 = await runControlledBrowser({ root, args: { url: browserUrl, principal: 'researcher-A' } })
check('browser token is single-use', br2.ok === false && br2.text.includes('no matching unconsumed browser preflight token'))

writeFileSync(engagementPath, 'scope:\n  assets: ["allowed.example"]\n')
const runsBefore = runnerRuns()
craftToken(browserShapeFromArgs({ url: browserUrl, principal: 'researcher-A' }), 'browser')
const br3 = await runControlledBrowser({ root, args: { url: browserUrl, principal: 'researcher-A' } })
check('out-of-scope browser request refused before the runner starts',
  br3.ok === false && br3.text.includes('outside the engagement scope') && runnerRuns() === runsBefore)

writeFileSync(engagementPath, `scope:\n  assets: ["127.0.0.1:${server.address().port}"]\n`)
craftToken(browserShapeFromArgs({ url: browserUrl, principal: 'researcher-A' }), 'browser')
rmSync(join(root, 'tools', 'bua', 'run.mjs'))
const br4 = await runControlledBrowser({ root, args: { url: browserUrl, principal: 'researcher-A' } })
check('missing runner yields an actionable provisioning error',
  br4.ok === false && br4.text.includes('BUA runner missing'))

// 9. The real runner template: scope guard first (exit 4), provisioning second (exit 3).
const realRunner = join(OS_REPO, 'tools', 'bua', 'run.mjs')
let realScopeCode = 0
try { execFileSync('node', [realRunner, '--url', 'https://out-of-scope.example/x', '--principal', 'A'], { cwd: root, encoding: 'utf8' }) } catch (e) { realScopeCode = e.status }
check('real runner refuses an out-of-scope target (exit 4)', realScopeCode === 4)
let realProvisionCode = 0
try { execFileSync('node', [realRunner, '--url', `http://127.0.0.1:${server.address().port}/ok`, '--principal', 'A'], { cwd: root, encoding: 'utf8' }) } catch (e) { realProvisionCode = e.status }
check('real runner reports missing playwright (exit 3)', realProvisionCode === 3)

server.close()
rmSync(root, { recursive: true, force: true })
console.log(`\n${passed}/${passed + failures.length} passed`)
if (failures.length) {
  console.log('FAILURES: ' + failures.join(' | '))
  process.exit(1)
}
