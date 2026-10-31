import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createTeleptyTransport, normalizeConfig } from '../src/index.js';
import { startStubDaemon, freshToken, startTeleptyDaemon, startAtermEndpoint, registerAterm, delay } from './helpers.js';
import { makeSandbox } from './helpers/fault-fs.js';
import { startFakeTelepty } from './helpers/fake-telepty.js';

for (const [status, body] of [[500, {}], [502, { code: 'DELIVERY_UNCERTAIN', delivery_uncertain: true }],
  [503, {}], [409, { code: 'DELIVERY_UNCERTAIN', delivery_uncertain: true }]]) {
  test(`inject HTTP ${status} uncertainty stays unknown and same request ID never re-sends`, async t => {
    const stub = await startStubDaemon({ 'POST /api/sessions/:id/inject': () => ({ status, body }) });
    const tr = createTeleptyTransport(normalizeConfig({ teleptyUrl: stub.origin, token: freshToken(), targets: ['target-1'], inboxPrefix: 'uncertain' }));
    t.after(async () => { await tr.close(); await stub.close(); });
    const request = { target: 'target-1', text: 'synthetic uncertain message', request_id: 'same-request' };
    const first = await tr.send(request);
    assert.equal(first.ok, true); assert.equal(first.accepted, 'unknown'); assert.equal(first.delivery, 'unknown');
    assert.equal(first.completion_fact, null);
    const again = await tr.send(request);
    assert.equal(again.accepted, 'unknown'); assert.equal(again.state, 'uncertain'); assert.equal(again.deduplicated, true);
    assert.equal(again.nonce, first.nonce);
    assert.equal((await tr.health()).store.uncertain, 1);
    assert.equal(stub.requests.filter(r => r.pathname.endsWith('/inject')).length, 1);
  });
}
test('a known 403 denial remains refused and does not re-send', async t => {
  const stub = await startStubDaemon({ 'POST /api/sessions/:id/inject': () => ({ status: 403, body: { code: 'PEER_LANE_DENIED' } }) });
  const tr = createTeleptyTransport(normalizeConfig({ teleptyUrl: stub.origin, token: freshToken(), targets: ['target-1'], inboxPrefix: 'denied' }));
  t.after(async () => { await tr.close(); await stub.close(); });
  const request = { target: 'target-1', text: 'not authorized', request_id: 'same-denial' };
  const first = await tr.send(request); assert.equal(first.ok, false); assert.equal(first.error.accepted, false);
  const again = await tr.send(request); assert.equal(again.accepted, false); assert.equal(again.state, 'refused');
  assert.equal(stub.requests.filter(r => r.pathname.endsWith('/inject')).length, 1);
});
test('HTTP uncertainty survives durable close/reopen without another inject', async t => {
  const sb = makeSandbox('ts-http-unknown-');
  const stub = await startFakeTelepty();
  stub.hooks.beforeInject = () => ({ status: 503, body: {} });
  const config = normalizeConfig({ teleptyUrl: stub.origin, token: stub.token, targets: ['target-1'], inboxPrefix: 'durable', stateDir: sb.stateDir });
  let tr = createTeleptyTransport(config, sb.seam());
  t.after(async () => { await tr.close(); await stub.close(); sb.remove(); });
  const request = { target: 'target-1', text: 'durable synthetic message', request_id: 'durable-unknown' };
  const first = await tr.send(request); assert.equal(first.accepted, 'unknown');
  assert.equal(JSON.parse(fs.readFileSync(path.join(sb.stateDir, 'state.json'), 'utf8')).requests['r:durable-unknown'].state, 'uncertain');
  await tr.close(); tr = createTeleptyTransport(config, sb.seam());
  const again = await tr.send(request); assert.equal(again.accepted, 'unknown'); assert.equal(again.state, 'uncertain');
  assert.equal(stub.injectArrivals.length, 1);
});
test('real candidate endpoint 503 stays unknown through Telesession and never repeats the effect', async t => {
  const sb = makeSandbox('ts-real-unknown-');
  const daemon = await startTeleptyDaemon({ orchestratorSids: 'ts-orch' });
  const endpoint = await startAtermEndpoint({ status: 503 });
  let tr;
  t.after(async () => { if (tr) await tr.close(); await endpoint.close(); await daemon.stop(); sb.remove(); });
  await registerAterm(daemon, 'ts-orch', endpoint.endpoint);
  const config = normalizeConfig({ teleptyUrl: daemon.origin, token: daemon.token, targets: ['ts-orch'], inboxPrefix: 'realunknown', stateDir: sb.stateDir });
  tr = createTeleptyTransport(config, sb.seam());
  const request = { target: 'ts-orch', text: 'candidate synthetic effect', request_id: 'real-once' };
  const first = await tr.send(request);
  assert.equal(first.ok, true); assert.equal(first.accepted, 'unknown'); assert.equal(first.reason, 'DELIVERY_UNCERTAIN');
  const again = await tr.send(request);
  assert.equal(again.accepted, 'unknown'); assert.equal(again.state, 'uncertain'); assert.equal(again.nonce, first.nonce);
  await delay(500);
  assert.equal(endpoint.received.length, 1);
  const dead = fs.readFileSync(path.join(daemon.mailboxDir, 'ts-orch', 'dead-letter.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(dead.length, 1); assert.equal(dead[0].outcome, 'unknown'); assert.equal(dead[0].retryable, false);
  assert.ok(dead[0].payload.includes(request.text));
  await tr.close(); tr = createTeleptyTransport(config, sb.seam());
  const restored = await tr.send(request);
  assert.equal(restored.state, 'uncertain'); assert.equal(restored.accepted, 'unknown');
  assert.equal(endpoint.received.length, 1);
});
