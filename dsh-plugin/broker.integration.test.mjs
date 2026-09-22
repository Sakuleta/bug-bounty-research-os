/**
 * Broker integration test — the R7 path end to end against the real Python broker:
 * the broker records the policy and SIGNS a token over the canonical digest, the token
 * is mirrored into the workspace store, and the executor consumes it THROUGH THE BROKER
 * before dispatch. Proven here: a valid consume dispatches; a tampered signature, a
 * replayed nonce and a narrowed broker policy all refuse before dispatch (the broker
 * policy overrides the workspace engagement.yaml); a token WITHOUT broker_sig is
 * refused while the socket exists (broker mode is mandatory, not opportunistic); both
 * the local binding and the broker policy must allow the target; a broker that dies
 * after minting fails closed.
 *
 * Run: node dsh-plugin/broker.integration.test.mjs
 */
import { execFileSync, spawn } from 'node:child_process'
import { appendFileSync, cpSync, existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const OS_REPO = join(dirname(fileURLToPath(import.meta.url)), '..')
const {
  brokerPath, brokerWorkspace, canonicalDigest, runControlledRequest, shapeFromArgs,
} = await import('./index.js')

let passed = 0
const failures = []
function check(label, cond) {
  if (cond) { passed += 1; console.log('ok: ' + label) }
  else { failures.push(label); console.log('FAIL: ' + label) }
}

async function waitFor(pred, what, ms = 10000) {
  const deadline = Date.now() + ms
  while (Date.now() < deadline) {
    if (pred()) return
    await new Promise((resolve) => setTimeout(resolve, 25))
  }
  throw new Error('timed out waiting for ' + what)
}

// 1. A real broker on a temp home; env discovery points both sides at its socket.
const brokerHome = mkdtempSync(join(tmpdir(), 'ros-broker-'))
const brokerSocket = join(brokerHome, 'broker.sock')
const brokerProc = spawn(
  'python3', [join(OS_REPO, 'tools', 'broker', 'broker.py'), '--serve', '--home', brokerHome],
  { stdio: 'ignore' })
process.env.RESEARCH_OS_BROKER_SOCKET = brokerSocket
await waitFor(() => existsSync(brokerSocket), 'the broker socket')

// 2. The python client (minting/consuming surface the control plane uses).
function pyBroker(op, payload) {
  const code = [
    'import json, sys',
    `sys.path.insert(0, ${JSON.stringify(join(OS_REPO, 'tools'))})`,
    'from broker import client',
    'print(json.dumps(client.call(sys.argv[1], timeout=5, **json.loads(sys.argv[2]))))',
  ].join('\n')
  return JSON.parse(execFileSync('python3', ['-c', code, op, JSON.stringify(payload)],
    { encoding: 'utf8', env: process.env }))
}

// 3. Fixture workspace: tools copy, OS marker, scope, a RUNNING cycle and H-0001.
const root = mkdtempSync(join(tmpdir(), 'ros-broker-ws-'))
cpSync(join(OS_REPO, 'tools'), join(root, 'tools'), { recursive: true })
writeFileSync(join(root, 'OS_VERSION'), '7.7\n')
const setupPy = join(root, 'setup.py')
writeFileSync(setupPy, [
  'import sys',
  'from pathlib import Path',
  'sys.path.insert(0, sys.argv[2])',
  'from control_plane import ControlPlane',
  'root = Path(sys.argv[1])',
  "for d in ['00_control','02_surface','03_hypotheses/active','03_hypotheses/archive','04_cycles','10_learning','11_runtime','12_knowledge/api-protocols']:",
  "    (root / d).mkdir(parents=True, exist_ok=True)",
  "(root / '02_surface/endpoints.yaml').write_text('endpoints: []\\n')",
  "(root / '12_knowledge/api-protocols/api.md').write_text('# api-protocols\\n')",
  "(root / '12_knowledge/INDEX.yaml').write_text('packs:\\n  api-protocols:\\n    load_when: [broker]\\n    files: [api.md]\\n')",
  '(root / "00_control/engagement.yaml").write_text(\'scope:\\n  assets: ["lab.example"]\\n\')',
  'cp = ControlPlane(root)',
  "cp.create_cycle('C-0001', {'id':'C-0001','type':'DISCOVERY','objective':'broker integration','allowed_scope':['lab.example'],'stop_conditions':['stop'],'status':'PLANNED','knowledge_triage':[{'pack':'api-protocols','verdict':'USE','reason':'broker integration covers the api-protocols pack'}]})",
  "(root / '04_cycles/C-0001/objective.md').write_text('# Cycle Objective\\n\\n## Question\\nDoes the broker gate the request?\\n\\n## Minimal test\\nOne stubbed request.\\n')",
  "cp.create_hypothesis('H-0001', {'cycle_id':'C-0001','observation':'o','hypothesis':'h','secure_prediction':'s','vulnerable_prediction':'v'})",
  "cp.transition_cycle('C-0001','READY',reason='ready')",
  "cp.transition_cycle('C-0001','RUNNING',reason='run')",
  "print('setup ok')",
].join('\n') + '\n')
execFileSync('python3', [setupPy, root, join(root, 'tools')], { encoding: 'utf8', timeout: 60000 })

const workspaceKey = realpathSync(root)
const REV1 = 'EV-000001:0000000000000000000000000000000000000000000000000000000000000001'
const REV2 = 'EV-000002:0000000000000000000000000000000000000000000000000000000000000002'
const REV3 = 'EV-000003:0000000000000000000000000000000000000000000000000000000000000003'
const policyPut = pyBroker('policy.put', {
  workspace: workspaceKey, assets: ['lab.example'], gate: 'assets',
  source_reference: 'policy://program/scope', scope_revision: REV1,
})
check('the broker records the workspace policy', policyPut.ok === true && policyPut.policy.assets[0] === 'lab.example')

// 4. Helper seams: discovery points at the env socket and the workspace identity is
//    symlink-resolved (macOS /var -> /private/var), matching what the broker signed.
check('brokerPath discovers the env socket', brokerPath() === brokerSocket)
check('brokerWorkspace resolves symlinks', brokerWorkspace(root) === workspaceKey)

// 4b. Discovery parity with tools/broker/client.py (SOCKET > HOME/socket > default):
//     a HOME-only setup must resolve, the socket env must win, and a
//     configured-but-missing socket is not a broker (parity with client.available).
{
  const savedSocket = process.env.RESEARCH_OS_BROKER_SOCKET
  const savedHome = process.env.RESEARCH_OS_BROKER_HOME
  const fakeHome = mkdtempSync(join(tmpdir(), 'ros-broker-home-'))
  const fakeSocket = join(fakeHome, 'broker.sock')
  writeFileSync(fakeSocket, '')
  try {
    delete process.env.RESEARCH_OS_BROKER_SOCKET
    process.env.RESEARCH_OS_BROKER_HOME = fakeHome
    check('brokerPath follows RESEARCH_OS_BROKER_HOME when no socket env is set',
      brokerPath() === fakeSocket)
    process.env.RESEARCH_OS_BROKER_SOCKET = brokerSocket
    check('the socket env wins over the home env', brokerPath() === brokerSocket)
    process.env.RESEARCH_OS_BROKER_SOCKET = join(fakeHome, 'missing.sock')
    delete process.env.RESEARCH_OS_BROKER_HOME
    check('a configured-but-missing socket is not a broker', brokerPath() === undefined)
  } finally {
    if (savedSocket === undefined) delete process.env.RESEARCH_OS_BROKER_SOCKET
    else process.env.RESEARCH_OS_BROKER_SOCKET = savedSocket
    if (savedHome === undefined) delete process.env.RESEARCH_OS_BROKER_HOME
    else process.env.RESEARCH_OS_BROKER_HOME = savedHome
    rmSync(fakeHome, { recursive: true, force: true })
  }
}

// 5. Mint a signed token through the python client, mirror it into the workspace store.
const url = 'http://lab.example/x'
const shape = shapeFromArgs({ method: 'GET', url, principal: 'researcher-A' })
const preflight = {
  cycle_id: 'C-0001', target: url, scope_status: 'IN_SCOPE', account: 'researcher-A',
  object_owner: 'researcher-A', purpose: 'broker integration', hypothesis: 'H-0001',
  expected_secure: 'stub responds 200', expected_vulnerable: 'n/a', side_effect: 'none',
  stop_condition: 'stop after one request', tool_family: 'http', request_shape: shape,
}
function mint() {
  const resp = pyBroker('token.mint', {
    workspace: workspaceKey, preflight, request_shape: shape, tool_family: 'http',
  })
  if (!resp.ok) throw new Error('mint failed: ' + resp.error)
  return resp.token
}
function writeToken(token, { digest = canonicalDigest(shape), sig, nonce, recordPreflight = preflight } = {}) {
  appendFileSync(join(root, '11_runtime/action-tokens.jsonl'), JSON.stringify({
    action_id: token.action_id, nonce: token.nonce,
    broker_nonce: nonce || token.nonce, broker_sig: sig || token.sig,
    broker_workspace: token.workspace, argument_digest: digest, tool_family: 'http',
    issued_at: new Date().toISOString(), expires_at: token.expires_at,
    cycle_id: 'C-0001', hypothesis: 'H-0001', target: recordPreflight.target,
    consumed: false, preflight: recordPreflight,
  }) + '\n')
}

function consumeCount() {
  const ledger = readFileSync(join(brokerHome, 'tokens.jsonl'), 'utf8')
  return (ledger.match(/"kind":"consume"/g) || []).length
}

let dispatches = 0
const stubFetch = async () => {
  dispatches += 1
  return { status: 200, headers: { forEach() {} }, text: async () => 'hello-from-stub' }
}
const callExecutor = (callUrl = url) => runControlledRequest({
  root, args: { method: 'GET', url: callUrl, principal: 'researcher-A' }, fetchImpl: stubFetch,
})

// 6. Valid consume: the broker records the consume and the request dispatches.
const t1 = mint()
writeToken(t1)
const r1 = await callExecutor()
check('a broker-signed token consumes through the broker and dispatches',
  r1.ok === true && dispatches === 1 && r1.text.includes('HTTP 200') && r1.text.includes('token consumed'))
check('the broker ledger records the consume',
  readFileSync(join(brokerHome, 'tokens.jsonl'), 'utf8').includes(`"nonce":"${t1.nonce}"`)
  && readFileSync(join(brokerHome, 'tokens.jsonl'), 'utf8').includes('"kind":"consume"'))

// 7. Replay: the same broker nonce cannot ride a fresh local record.
writeToken(t1)
const r2 = await callExecutor()
check('a replayed broker token is refused before dispatch',
  r2.ok === false && dispatches === 1 && r2.text.includes('already consumed'))

// 8. Tampered signature: refused before dispatch.
const t3 = mint()
const badSig = (t3.sig[0] === '0' ? '1' : '0') + t3.sig.slice(1)
writeToken(t3, { sig: badSig })
const r3 = await callExecutor()
check('a tampered broker signature is refused before dispatch',
  r3.ok === false && dispatches === 1 && r3.text.includes('signature does not verify'))

// 9. A token without broker_sig is REFUSED while the broker socket exists — the local
//    trust path survives only when no socket exists. No dispatch, no broker consume.
const consumesBefore = consumeCount()
appendFileSync(join(root, '11_runtime/action-tokens.jsonl'), JSON.stringify({
  action_id: 'A-999001', nonce: 'a'.repeat(32), argument_digest: canonicalDigest(shape),
  tool_family: 'http', expires_at: new Date(Date.now() + 120000).toISOString(),
  consumed: false, cycle_id: 'C-0001', hypothesis: 'H-0001', target: url, preflight,
}) + '\n')
const r4 = await callExecutor()
check('an unsigned token is refused while the broker runs',
  r4.ok === false && dispatches === 1
  && r4.text.includes('policy broker is running')
  && r4.text.includes('broker-signed'))
check('the unsigned token never reaches the broker consume ledger',
  consumeCount() === consumesBefore)

// 10. Broker authority: the broker policy is narrowed AFTER the token was minted; the
//     workspace engagement.yaml still lists lab.example, yet dispatch is refused.
const t5 = mint()
pyBroker('policy.put', {
  workspace: workspaceKey, assets: ['other.example'], gate: 'assets',
  source_reference: 'policy://program/scope', human_reference: 'ticket-js-1',
  scope_revision: REV2,
})
writeToken(t5)
const r5 = await callExecutor()
check('the broker policy overrides the workspace engagement.yaml',
  r5.ok === false && dispatches === 1
  && r5.text.includes('outside the engagement scope')
  && r5.text.includes('broker policy assets=["other.example"]')
  && readFileSync(join(root, '00_control/engagement.yaml'), 'utf8').includes('lab.example'))

// 10b. Belt and braces: the local binding must ALSO allow the target. With the broker
//      policy still widened to other.example, a broker-signed token for other.example
//      mints fine — and the executor still refuses, on the local engagement.yaml.
const wideUrl = 'http://other.example/y'
const wideShape = shapeFromArgs({ method: 'GET', url: wideUrl, principal: 'researcher-A' })
const widePreflight = { ...preflight, target: wideUrl, request_shape: wideShape }
const wideMint = pyBroker('token.mint', {
  workspace: workspaceKey, preflight: widePreflight, request_shape: wideShape, tool_family: 'http',
})
if (!wideMint.ok) throw new Error('wide mint failed: ' + wideMint.error)
writeToken(wideMint.token, { digest: canonicalDigest(wideShape), recordPreflight: widePreflight })
const rWide = await callExecutor(wideUrl)
check('a wider broker policy still meets the local binding',
  rWide.ok === false && dispatches === 1
  && rWide.text.includes('outside the engagement scope')
  && rWide.text.includes('00_control/engagement.yaml'))

// 11. HOME-only discovery end to end (broker alive): drop the socket env — the
//     executor must still consult the broker (audit-logged consume), never run silent
//     local mode while the broker holds policy.
pyBroker('policy.put', {
  workspace: workspaceKey, assets: ['lab.example'], gate: 'assets',
  source_reference: 'policy://program/scope', human_reference: 'ticket-js-2',
  scope_revision: REV3,
})
delete process.env.RESEARCH_OS_BROKER_SOCKET
process.env.RESEARCH_OS_BROKER_HOME = brokerHome
check('brokerPath discovers the home socket without the socket env',
  brokerPath() === brokerSocket)
const consumesBeforeHome = consumeCount()
const tHome = mint()
writeToken(tHome)
const rHome = await callExecutor()
check('home-only discovery consumes through the broker, never silently local',
  rHome.ok === true && dispatches === 2 && consumeCount() === consumesBeforeHome + 1
  && readFileSync(join(brokerHome, 'audit.log'), 'utf8').includes('token.consume'))

// 12. Broker gone after the mint: the stale socket fails closed, never silently local.
const t6 = mint()
writeToken(t6)
brokerProc.kill('SIGKILL')
await new Promise((resolve) => brokerProc.on('exit', resolve))
const r6 = await callExecutor()
check('a broker-signed token fails closed when the broker is gone',
  r6.ok === false && dispatches === 2 && r6.text.includes('broker unreachable'))

// 12. Cleanup + summary. The exit hook also cleans up after an assertion crash, so a
//     failing run never leaves a daemon or a fixture behind.
function cleanup() {
  try { brokerProc.kill() } catch {}
  try { rmSync(root, { recursive: true, force: true }) } catch {}
  try { rmSync(brokerHome, { recursive: true, force: true }) } catch {}
}
process.on('exit', cleanup)
cleanup()
console.log(`\n${passed}/${passed + failures.length} passed`)
if (failures.length) {
  console.log('FAILURES: ' + failures.join(' | '))
  process.exit(1)
}
