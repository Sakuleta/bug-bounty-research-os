/**
 * Executor integration test — the full R4 chain against a real local lab server:
 * prepare (researchctl) → research_os_request consumes the token → HTTP request →
 * capture under 08_artifacts/raw/ → evidence registered → ACTION_RECORDED in the ledger
 * → the token is single-use → a mismatched digest cannot authorize.
 *
 * Run: node executor.integration.test.mjs
 */
import { execFileSync } from 'node:child_process'
import { appendFileSync, cpSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { tmpdir, homedir } from 'node:os'
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

// 0. The canonical BUA runner owns a local URL masker (the enforcer cannot rewrite the
//    runner's own JSON summary): the summary url/final_url must not persist query or
//    fragment secrets. Import is side-effect free (the CLI flow only runs as a script).
const bua = await import(join(OS_REPO, 'tools', 'bua', 'run.mjs'))
check('BUA runner exposes its local URL masker', typeof bua.maskUrlSecrets === 'function')
check('BUA runner masker masks query and fragment secrets',
  bua.maskUrlSecrets('https://t.example/app?access_token=AB&page=2#code=CD')
  === 'https://t.example/app?access_token=[REDACTED]&page=2#code=[REDACTED]')
check('BUA runner masker keeps benign URLs untouched',
  bua.maskUrlSecrets('https://t.example/app?page=2') === 'https://t.example/app?page=2')
check('BUA runner masker masks nested (double-encoded) sensitive assignments',
  bua.maskUrlSecrets('https://t.example/app?next=/cb%26token%3Dxyz') === 'https://t.example/app?next=[REDACTED]')

const LEAK_TOKEN = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZWNyZXQifQ.c2lnbmF0dXJl'
let labHits = 0
const server = createServer((req, res) => {
  labHits += 1
  if (req.url.startsWith('/stall')) {
    return // never respond: the client-side timeout must fire
  }
  if (req.url.startsWith('/slowbody')) {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.write('partial-body-bytes-')
    return // headers and some bytes sent; the rest never arrives
  }
  if (req.url.startsWith('/large')) {
    res.writeHead(200, { 'content-type': 'application/octet-stream' })
    const chunk = Buffer.alloc(64 * 1024, 97)
    for (let i = 0; i < 16; i++) res.write(chunk)
    res.end()
    return
  }
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
  "for d in ['02_surface','03_hypotheses/active','03_hypotheses/archive','04_cycles','10_learning','11_runtime','12_knowledge/api-protocols']:",
  "    (root / d).mkdir(parents=True, exist_ok=True)",
  "(root / '02_surface/endpoints.yaml').write_text('endpoints: []\\n')",
  "(root / '12_knowledge/api-protocols/api.md').write_text('# api-protocols\\n')",
  "(root / '12_knowledge/INDEX.yaml').write_text('packs:\\n  api-protocols:\\n    load_when: [executor]\\n    files: [api.md]\\n')",
  'cp = ControlPlane(root)',
  "cp.create_cycle('C-0001', {'id':'C-0001','type':'DISCOVERY','objective':'executor integration','allowed_scope':['127.0.0.1'],'stop_conditions':['stop'],'status':'PLANNED','knowledge_triage':[{'pack':'api-protocols','verdict':'USE','reason':'integration test covers the api-protocols pack'}]})",
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

// 3c. Query-secret redaction: sensitive query VALUES never reach captures, deny messages
//     or the DENY log; host and path stay visible.
const queryUrl = url + '/q?token=QUERYSECRET&page=2'
const queryShape = shapeFromArgs({ method: 'GET', url: queryUrl, principal: 'researcher-A' })
writeFileSync(preparePath, JSON.stringify({ ...preparePayload, target: queryUrl, request_shape: queryShape }))
execFileSync('python3', [join(root, 'tools', 'researchctl.py'), root, 'prepare', preparePath], { encoding: 'utf8', timeout: 60000 })
const rq = await runControlledRequest({ root, args: { method: 'GET', url: queryUrl, principal: 'researcher-A' } })
check('query-secret request succeeds', rq.ok === true)
const queryRel = rq.text.match(/capture: (\S+)/)[1]
const queryCapture = readFileSync(join(root, queryRel), 'utf8')
check('capture request line masks the sensitive query value, keeps host/path',
  queryCapture.includes(`GET ${url}/q?token=[REDACTED]&page=2`) && !queryCapture.includes('QUERYSECRET'))
check('success text masks the sensitive query value',
  rq.text.includes(`GET ${url}/q?token=[REDACTED]&page=2`) && !rq.text.includes('QUERYSECRET'))
const rqNoToken = await runControlledRequest({ root, args: { method: 'GET', url: queryUrl, principal: 'researcher-A' } })
check('no-token deny message carries the redacted URL',
  rqNoToken.ok === false && rqNoToken.text.includes('token=[REDACTED]') && !rqNoToken.text.includes('QUERYSECRET'))

// 3c-2. A nested (double-encoded) assignment inside a benign parameter value must be
//       masked whole: `next=/cb%26token%3D…` decodes once to `next=/cb&token=…`.
const nestedUrl = url + '/q?next=/cb%26token%3DNESTEDSECRET'
const nestedShape = shapeFromArgs({ method: 'GET', url: nestedUrl, principal: 'researcher-A' })
writeFileSync(preparePath, JSON.stringify({ ...preparePayload, target: nestedUrl, request_shape: nestedShape }))
execFileSync('python3', [join(root, 'tools', 'researchctl.py'), root, 'prepare', preparePath], { encoding: 'utf8', timeout: 60000 })
const rn = await runControlledRequest({ root, args: { method: 'GET', url: nestedUrl, principal: 'researcher-A' } })
check('nested query-secret request succeeds', rn.ok === true)
const nestedRel = rn.text.match(/capture: (\S+)/)[1]
const nestedCapture = readFileSync(join(root, nestedRel), 'utf8')
check('capture request line masks a nested sensitive assignment',
  nestedCapture.includes(`GET ${url}/q?next=[REDACTED]`) && !nestedCapture.includes('NESTEDSECRET'))
check('success text masks the nested sensitive assignment',
  rn.text.includes(`GET ${url}/q?next=[REDACTED]`) && !rn.text.includes('NESTEDSECRET'))

// 3c-bis. A no-token refusal must never echo raw header VALUES either: the shape hint
//        redacts sensitive headers with the same rules captures use.
const noTok = await runControlledRequest({
  root,
  args: {
    method: 'GET', url: url + '/never-prepared', principal: 'researcher-A',
    headers: { Authorization: 'Bearer NO_TOKEN_AUTH_SECRET', 'X-Api-Key': 'NO_TOKEN_API_SECRET' },
  },
})
check('no-token message redacts sensitive header values, keeps the names',
  noTok.ok === false
  && noTok.text.includes('"authorization":"[REDACTED]"') && noTok.text.includes('"x-api-key":"[REDACTED]"')
  && !noTok.text.includes('NO_TOKEN_AUTH_SECRET') && !noTok.text.includes('NO_TOKEN_API_SECRET'))

// 3c-ter. Non-plain headers are refused with an actionable message (an array or a
//         Headers instance would otherwise silently produce an empty/odd digest shape).
const badHeaders = await runControlledRequest({
  root,
  args: { method: 'GET', url: url + '/bad-headers', principal: 'researcher-A', headers: ['authorization'] },
})
check('array headers produce an actionable refusal, not a digest',
  badHeaders.ok === false && /plain object/i.test(badHeaders.text))
const badHeadersInstance = await runControlledRequest({
  root,
  args: { method: 'GET', url: url + '/bad-headers', principal: 'researcher-A', headers: new Headers({ 'x-a': '1' }) },
})
check('Headers-instance headers produce an actionable refusal',
  badHeadersInstance.ok === false && /plain object/i.test(badHeadersInstance.text))

// 3d. Timeout: a stalled response aborts at RESEARCH_OS_HTTP_TIMEOUT_MS and the capture
//     records exactly what happened.
const stallUrl = new URL('/stall', url).toString()
writeFileSync(preparePath, JSON.stringify({ ...preparePayload, target: stallUrl, request_shape: shapeFromArgs({ method: 'GET', url: stallUrl, principal: 'researcher-A' }) }))
execFileSync('python3', [join(root, 'tools', 'researchctl.py'), root, 'prepare', preparePath], { encoding: 'utf8', timeout: 60000 })
process.env.RESEARCH_OS_HTTP_TIMEOUT_MS = '400'
const rt = await runControlledRequest({ root, args: { method: 'GET', url: stallUrl, principal: 'researcher-A' } })
delete process.env.RESEARCH_OS_HTTP_TIMEOUT_MS
check('stalled request times out with the exact reason',
  rt.ok === false && rt.text.includes('request timeout after 400ms'))
const stallCapture = readFileSync(join(root, rt.text.match(/capture: (\S+)/)[1]), 'utf8')
check('timeout capture records the abort',
  stallCapture.includes('ERROR: request timeout after 400ms') && stallCapture.includes('--- response'))

// 3d-bis. A timeout after the headers (body stream stalls) still records the bytes that
//        arrived and says exactly what happened.
const slowUrl = new URL('/slowbody', url).toString()
writeFileSync(preparePath, JSON.stringify({ ...preparePayload, target: slowUrl, request_shape: shapeFromArgs({ method: 'GET', url: slowUrl, principal: 'researcher-A' }) }))
execFileSync('python3', [join(root, 'tools', 'researchctl.py'), root, 'prepare', preparePath], { encoding: 'utf8', timeout: 60000 })
process.env.RESEARCH_OS_HTTP_TIMEOUT_MS = '400'
const rsb = await runControlledRequest({ root, args: { method: 'GET', url: slowUrl, principal: 'researcher-A' } })
delete process.env.RESEARCH_OS_HTTP_TIMEOUT_MS
check('mid-body timeout reports the status, the timeout and the captured bytes',
  rsb.ok === true && rsb.text.includes('HTTP 200')
  && rsb.text.includes('body read timed out after 400ms') && rsb.text.includes('19 bytes captured'))
const slowCapture = readFileSync(join(root, rsb.text.match(/capture: (\S+)/)[1]), 'utf8')
check('mid-body timeout capture keeps the partial bytes and the reason',
  slowCapture.includes('HTTP 200 — body read timed out after 400ms')
  && slowCapture.includes('partial-body-bytes-'))
check('mid-body timeout marks the result object partial', rsb.partial === true)
check('a request that errored before any body is not marked partial', rt.partial === undefined)

// 3e. Size cap: a large streamed body stops at RESEARCH_OS_MAX_BODY_BYTES; the capture
//     keeps the bytes that were actually read.
const largeUrl = new URL('/large', url).toString()
writeFileSync(preparePath, JSON.stringify({ ...preparePayload, target: largeUrl, request_shape: shapeFromArgs({ method: 'GET', url: largeUrl, principal: 'researcher-A' }) }))
execFileSync('python3', [join(root, 'tools', 'researchctl.py'), root, 'prepare', preparePath], { encoding: 'utf8', timeout: 60000 })
process.env.RESEARCH_OS_MAX_BODY_BYTES = '10240'
const rl = await runControlledRequest({ root, args: { method: 'GET', url: largeUrl, principal: 'researcher-A' } })
delete process.env.RESEARCH_OS_MAX_BODY_BYTES
check('large body is truncated with the exact reason',
  rl.ok === true && rl.text.includes('HTTP 200 (body truncated at 10240 bytes)'))
check('a cap-truncated (complete read) body is not marked partial', rl.partial === undefined)
const largeCapture = readFileSync(join(root, rl.text.match(/capture: (\S+)/)[1]), 'utf8')
check('capture records the capped bytes and the truncation marker',
  largeCapture.includes('HTTP 200 (truncated at 10240 bytes)')
  && largeCapture.includes('aaaa') && largeCapture.length < 60000)

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

// 6b. The DENY(executor) log line names the target without leaking query secrets.
const ENFORCER_LOG = join(homedir(), '.dsh', 'research-os-enforcer.log')
const logBefore = (() => { try { return readFileSync(ENFORCER_LOG, 'utf8').length } catch { return 0 } })()
const evilUrl = 'https://evil.example/x?token=LOGSECRET'
craftToken(shapeFromArgs({ method: 'GET', url: evilUrl, principal: 'researcher-A' }))
const r4b = await runControlledRequest({ root, args: { method: 'GET', url: evilUrl, principal: 'researcher-A' } })
const denyLog = (() => { try { return readFileSync(ENFORCER_LOG, 'utf8').slice(logBefore) } catch { return '' } })()
check('out-of-scope query-secret request denied', r4b.ok === false)
check('DENY(executor) log line masks the query secret, keeps host/path',
  denyLog.includes('DENY(executor) GET https://evil.example/x?token=[REDACTED]')
  && !denyLog.includes('LOGSECRET'))

// 7. In-scope control: the same crafted-token path reaches the lab once the host is listed.
writeFileSync(engagementPath, `scope:\n  assets: ["127.0.0.1:${server.address().port}"]\n`)
craftToken(shapeFromArgs({ method: 'GET', url, principal: 'researcher-A' }))
const r5 = await runControlledRequest({ root, args: { method: 'GET', url, principal: 'researcher-A' } })
check('in-scope host passes the executor scope gate', r5.ok === true && labHits === hitsBefore + 1)

// 7b. Concurrency: two parallel dispatches on one token — exactly one proceeds.
craftToken(shapeFromArgs({ method: 'GET', url, principal: 'researcher-A' }))
const raceBefore = labHits
const [raceA, raceB] = await Promise.all([
  runControlledRequest({ root, args: { method: 'GET', url, principal: 'researcher-A' } }),
  runControlledRequest({ root, args: { method: 'GET', url, principal: 'researcher-A' } }),
])
check('two parallel dispatches consume one token exactly once',
  [raceA, raceB].filter((r) => r.ok === true).length === 1 && labHits === raceBefore + 1)

// 7c. An unparseable expires_at is never selectable (fail closed).
const badShape = shapeFromArgs({ method: 'GET', url: url + '/badexpiry', principal: 'researcher-A' })
craftedId += 1
appendFileSync(tokensPath, JSON.stringify({
  action_id: `A-9${String(craftedId).padStart(5, '0')}`,
  nonce: `crafted-${craftedId}`,
  argument_digest: canonicalDigest(badShape),
  tool_family: 'http',
  expires_at: 'not-a-date-at-all',
  consumed: false,
  cycle_id: 'C-0001',
  preflight: preparePayload,
}) + '\n')
const rBad = await runControlledRequest({ root, args: { method: 'GET', url: url + '/badexpiry', principal: 'researcher-A' } })
check('a token with an unparseable expiry is not selectable',
  rBad.ok === false && rBad.text.includes('no matching unconsumed preflight token')
  && labHits === raceBefore + 1)

// 7b. Lifecycle re-check at dispatch: prepare proved the cycle RUNNING, but the token
//     can sit in the store while a gate/close moves the cycle on — the executor must
//     refuse and the refusal still consumes the token (single-use, crash-safe).
const lifeUrl = url + '/life'
writeFileSync(preparePath, JSON.stringify({ ...preparePayload, target: lifeUrl, request_shape: shapeFromArgs({ method: 'GET', url: lifeUrl, principal: 'researcher-A' }) }))
const lifeNonce = JSON.parse(execFileSync('python3', [join(root, 'tools', 'researchctl.py'), root, 'prepare', preparePath], { encoding: 'utf8', timeout: 60000 })).nonce
const py = (code) => execFileSync('python3', ['-c', code, root, join(root, 'tools')], { encoding: 'utf8', timeout: 60000 })
py([
  'import sys',
  'from pathlib import Path',
  'sys.path.insert(0, sys.argv[2])',
  'from control_plane import ControlPlane',
  "ControlPlane(Path(sys.argv[1])).request_gate('G-0001', {'cycle_id': 'C-0001', 'what_is_needed': 'x', 'why_human_only': 'y', 'resume_after': 'z'})",
  "print('gate opened')",
].join('\n'))
const hitsBeforeLife = labHits
const rLife = await runControlledRequest({ root, args: { method: 'GET', url: lifeUrl, principal: 'researcher-A' } })
check('a cycle that moved to HUMAN_GATE after prepare refuses dispatch',
  rLife.ok === false && rLife.text.includes('the cycle moved to HUMAN_GATE')
  && rLife.text.includes('fresh preflight') && labHits === hitsBeforeLife)
check('the lifecycle refusal still consumes the token',
  readFileSync(join(root, '11_runtime/action-tokens.jsonl'), 'utf8').split('\n')
    .some((line) => line.includes(lifeNonce) && line.includes('"consumed":true')))
py([
  'import sys',
  'from pathlib import Path',
  'sys.path.insert(0, sys.argv[2])',
  'from control_plane import ControlPlane',
  "ControlPlane(Path(sys.argv[1])).resolve_gate('G-0001', decision='RESUME', reference='test fixture')",
  "print('gate resolved')",
].join('\n'))
const resumedUrl = url + '/resumed'
writeFileSync(preparePath, JSON.stringify({ ...preparePayload, target: resumedUrl, request_shape: shapeFromArgs({ method: 'GET', url: resumedUrl, principal: 'researcher-A' }) }))
execFileSync('python3', [join(root, 'tools', 'researchctl.py'), root, 'prepare', preparePath], { encoding: 'utf8', timeout: 60000 })
const rResumed = await runControlledRequest({ root, args: { method: 'GET', url: resumedUrl, principal: 'researcher-A' } })
check('resolving the gate back to RUNNING allows the next controlled request', rResumed.ok === true)

// 7c. Same refusal when the cycle closed.
const closedUrl = url + '/closed'
writeFileSync(preparePath, JSON.stringify({ ...preparePayload, target: closedUrl, request_shape: shapeFromArgs({ method: 'GET', url: closedUrl, principal: 'researcher-A' }) }))
execFileSync('python3', [join(root, 'tools', 'researchctl.py'), root, 'prepare', preparePath], { encoding: 'utf8', timeout: 60000 })
writeFileSync(join(root, '04_cycles', 'C-0001', 'plan.yaml'), 'status: "CLOSED"\n')
const hitsBeforeClosed = labHits
const rClosed = await runControlledRequest({ root, args: { method: 'GET', url: closedUrl, principal: 'researcher-A' } })
check('a cycle that moved to CLOSED after prepare refuses dispatch',
  rClosed.ok === false && rClosed.text.includes('the cycle moved to CLOSED') && labHits === hitsBeforeClosed)
writeFileSync(join(root, '04_cycles', 'C-0001', 'plan.yaml'), 'status: "RUNNING"\n')

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
// 8b. Browser capture header lines mask query secrets too.
const browserQueryUrl = browserUrl + '?token=BROWSERSECRET&x=1'
writeFileSync(preparePath, JSON.stringify({ ...preparePayload, target: browserQueryUrl, tool_family: 'browser', request_shape: browserShapeFromArgs({ url: browserQueryUrl, principal: 'researcher-A' }) }))
execFileSync('python3', [join(root, 'tools', 'researchctl.py'), root, 'prepare', preparePath], { encoding: 'utf8', timeout: 60000 })
const brq = await runControlledBrowser({ root, args: { url: browserQueryUrl, principal: 'researcher-A' } })
const browserCapture = readFileSync(join(root, brq.text.match(/capture: (\S+)/)[1]), 'utf8')
check('browser capture command line masks query secrets',
  brq.ok === true && browserCapture.includes(`--url ${browserUrl}?token=[REDACTED]&x=1`)
  && !browserCapture.includes('BROWSERSECRET'))
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

// 10. Transactional receipts: when capture registration or action recording fails after
//     the request was sent, the result must be an explicit failure — never a success.
const txUrl = new URL('/tx', url).toString()
writeFileSync(preparePath, JSON.stringify({ ...preparePayload, target: txUrl, request_shape: shapeFromArgs({ method: 'GET', url: txUrl, principal: 'researcher-A' }) }))
execFileSync('python3', [join(root, 'tools', 'researchctl.py'), root, 'prepare', preparePath], { encoding: 'utf8', timeout: 60000 })
const cliPath = join(root, 'tools', 'researchctl.py')
const cliBackup = join(root, 'tools', 'researchctl.py.bak')
renameSync(cliPath, cliBackup)
const hitsBeforeTx = labHits
const tx = await runControlledRequest({ root, args: { method: 'GET', url: txUrl, principal: 'researcher-A' } })
renameSync(cliBackup, cliPath)
check('receipt failure returns ok:false with the exact warning',
  tx.ok === false
  && tx.text.includes('the request WAS executed but the receipt could not be recorded — do not rely on this action as receipted'))
check('receipt failure still reports the executed HTTP status and capture',
  tx.text.includes('HTTP 200') && tx.text.includes('- capture: 08_artifacts/raw/'))
check('receipt failure means the request really was executed', labHits === hitsBeforeTx + 1)
const txCapture = readFileSync(join(root, tx.text.match(/capture: (\S+)/)[1]), 'utf8')
check('receipt failure still writes the capture', txCapture.includes(`GET ${txUrl}`))

// 10c. Dispatch-aware warning: the request was SENT, errored before headers (connection
//      refused) and the receipt failed — the warning must still fire, never a silent error.
writeFileSync(engagementPath, 'scope:\n  assets: ["127.0.0.1:1"]\n')
const refusedUrl = 'http://127.0.0.1:1/refused'
writeFileSync(preparePath, JSON.stringify({ ...preparePayload, target: refusedUrl, request_shape: shapeFromArgs({ method: 'GET', url: refusedUrl, principal: 'researcher-A' }) }))
execFileSync('python3', [join(root, 'tools', 'researchctl.py'), root, 'prepare', preparePath], { encoding: 'utf8', timeout: 60000 })
renameSync(cliPath, cliBackup)
const refused = await runControlledRequest({ root, args: { method: 'GET', url: refusedUrl, principal: 'researcher-A' } })
renameSync(cliBackup, cliPath)
writeFileSync(engagementPath, `scope:\n  assets: ["127.0.0.1:${server.address().port}"]\n`)
check('a sent-but-errored request with a failed receipt still carries the warning',
  refused.ok === false && refused.text.includes('error:')
  && refused.text.includes('the request WAS executed but the receipt could not be recorded — do not rely on this action as receipted'))

// 10b. Same contract for the browser arm (the stub runner was removed above; restore it).
writeFileSync(join(root, 'tools', 'bua', 'run.mjs'), [
  "import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs'",
  "import { join } from 'node:path'",
  'const args = process.argv.slice(2)',
  "const get = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d }",
  "const out = get('--out-dir', '08_artifacts/raw'); const action = get('--action', 'bua')",
  'mkdirSync(out, { recursive: true })',
  "writeFileSync(join(out, action + '-stub.png'), 'png')",
  "console.log('ARTIFACT ' + join(out, action + '-stub.png'))",
  'process.exit(0)',
].join('\n') + '\n')
writeFileSync(preparePath, JSON.stringify({ ...preparePayload, target: browserUrl, tool_family: 'browser', request_shape: browserShapeFromArgs({ url: browserUrl, principal: 'researcher-A' }) }))
execFileSync('python3', [join(root, 'tools', 'researchctl.py'), root, 'prepare', preparePath], { encoding: 'utf8', timeout: 60000 })
renameSync(cliPath, cliBackup)
const txb = await runControlledBrowser({ root, args: { url: browserUrl, principal: 'researcher-A' } })
renameSync(cliBackup, cliPath)
check('browser receipt failure returns ok:false with the exact warning',
  txb.ok === false
  && txb.text.includes('the request WAS executed but the receipt could not be recorded — do not rely on this action as receipted'))

// 10d. Dispatch-aware warning for the browser arm: the runner STARTED and exited non-zero
//      (the run happened) while the receipt failed — the warning must fire too.
writeFileSync(join(root, 'tools', 'bua', 'run.mjs'), [
  "import { mkdirSync, writeFileSync } from 'node:fs'",
  "import { join } from 'node:path'",
  'const args = process.argv.slice(2)',
  "const get = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d }",
  "const out = get('--out-dir', '08_artifacts/raw'); const action = get('--action', 'bua')",
  'mkdirSync(out, { recursive: true })',
  "writeFileSync(join(out, action + '-stub.png'), 'png')",
  "console.error('runner failed by design')",
  'process.exit(1)',
].join('\n') + '\n')
writeFileSync(preparePath, JSON.stringify({ ...preparePayload, target: browserUrl, tool_family: 'browser', request_shape: browserShapeFromArgs({ url: browserUrl, principal: 'researcher-A' }) }))
execFileSync('python3', [join(root, 'tools', 'researchctl.py'), root, 'prepare', preparePath], { encoding: 'utf8', timeout: 60000 })
renameSync(cliPath, cliBackup)
const txr = await runControlledBrowser({ root, args: { url: browserUrl, principal: 'researcher-A' } })
renameSync(cliBackup, cliPath)
check('a non-zero browser runner with a failed receipt still carries the warning',
  txr.ok === false && txr.text.includes('runner exit 1')
  && txr.text.includes('the request WAS executed but the receipt could not be recorded — do not rely on this action as receipted'))

server.close()
rmSync(root, { recursive: true, force: true })
console.log(`\n${passed}/${passed + failures.length} passed`)
if (failures.length) {
  console.log('FAILURES: ' + failures.join(' | '))
  process.exit(1)
}
