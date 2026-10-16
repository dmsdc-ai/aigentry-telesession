import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { EventEmitter } from "node:events";
import { createTeleptyTransport, REQUIRED_CAPABILITIES } from "../src/transports/telepty.js";
import { transportSendPrimitive } from "../src/relay/runner.js";
import { relayTick } from "../src/relay/relay.js";
import { createRouteResolver } from "../src/relay/route.js";

// Synthetic boundary only: no socket, daemon, child process, filesystem or real fetch.
// Actual transport HTTP parsing, request records, receipt mapping and relay classification run.
function fixture(t, inject) {
  const calls = [];
  const posts = [];
  const unexpected = [];
  let observation = { tracking_state: "aborted" };
  t.mock.method(http, "createServer", () => {
    const server = new EventEmitter();
    server.listen = (options, ready) => {
      assert.deepEqual(options, { host: "127.0.0.1", port: 0 });
      ready();
    };
    server.address = () => ({ port: 12345 });
    server.close = () => {};
    server.closeAllConnections = () => {};
    return server;
  });
  const response = (body, status = 200) => new Response(JSON.stringify(body), { status });
  t.mock.method(globalThis, "fetch", async (url, options) => {
    const u = new URL(url);
    assert.equal(u.origin, "http://127.0.0.1:12345");
    assert.equal(options.redirect, "error");
    calls.push(options.method + " " + u.pathname);
    const body = options.body === undefined ? null : JSON.parse(options.body);
    if (options.method === "GET" && u.pathname === "/api/meta")
      return response({ capabilities: REQUIRED_CAPABILITIES, pid: 123 });
    if (options.method === "GET" && u.pathname === "/api/sessions")
      return response([{ id: "target" }]);
    if (options.method === "POST" && u.pathname === "/api/sessions/register")
      return response({ session_id: body.session_id, session_token: "synthetic-inbox-token", session_epoch: "inbox-epoch" }, 201);
    if (options.method === "POST" && u.pathname === "/api/sessions/target/inject") {
      posts.push(body);
      return inject ? inject(response, posts.length) : response({ success: true, inject_id: "inject-1", exact_target: true, session_id: "target" });
    }
    if (options.method === "GET" && u.pathname === "/api/inject-observations/inject-1")
      return response({ inject_id: "inject-1", session_id: "target", session_epoch: "target-epoch", ...observation });
    if (options.method === "DELETE" && u.pathname === "/api/sessions/" + transport.inboxId && u.search === "?owned=true")
      return response({ success: true });
    unexpected.push(options.method + " " + u.pathname);
    throw new Error("Unexpected synthetic route");
  });
  const transport = createTeleptyTransport({
    teleptyOrigin: "http://127.0.0.1:12345", token: "synthetic-daemon-token",
    targets: ["target"], inboxPrefix: "uncertain_test",
  });
  t.after(async () => {
    await transport.close();
    assert.deepEqual(unexpected, []);
  });
  return { transport, posts, calls, observe: (value) => { observation = value; } };
}

const item = () => ({
  key: "a".repeat(32), nonce: "b".repeat(32), kind: "relay", peer_id: "local",
  session: "target", text: "synthetic payload", attempt: 0,
});

// Storage fixture only. Actual relayTick decides every transition and attempt count.
function outbox() {
  const row = { ...item(), to: { host: "local", session: "target" }, state: "queued", attempts: 0 };
  return {
    row,
    outbox: () => [structuredClone(row)],
    outboxClaim(key) {
      assert.equal(key, row.key);
      assert.equal(row.state, "queued");
      row.state = "intent";
      return { ok: true, item: structuredClone(row) };
    },
    outboxTransition(key, from, fields) {
      assert.equal(key, row.key);
      assert.equal(row.state, from);
      Object.assign(row, fields);
      return { ok: true };
    },
  };
}
const resolver = createRouteResolver([{ peer_id: "local", locators: ["local"] }]);

test("504 DELIVERY_UNCERTAIN retains unknown acceptance and same request without another POST", async (t) => {
  const f = fixture(t, (response) => response({ code: "DELIVERY_UNCERTAIN" }, 504));
  const args = { target: "target", text: "synthetic payload", request_id: "uncertain-request" };
  const first = await f.transport.send(args);
  assert.equal(first.ok, true);
  assert.equal(first.accepted, "unknown");
  assert.equal(first.state, "uncertain");
  assert.equal(first.reason, "DELIVERY_UNCERTAIN");
  assert.equal(first.completion_fact, null);
  const count = f.calls.length;
  const again = await f.transport.send(args);
  assert.equal(again.state, "uncertain");
  assert.equal(again.accepted, "unknown");
  assert.equal(again.nonce, first.nonce);
  assert.equal(again.request_id, first.request_id);
  assert.equal(again.deduplicated, true);
  assert.equal(f.calls.length, count);
  assert.equal(f.posts.length, 1);
});

test("504 actual transport and relay caller remain uncertain across ticks without new identity", async (t) => {
  const f = fixture(t, (response) => response({ code: "DELIVERY_UNCERTAIN" }, 504));
  const ledger = outbox();
  const ids = [];
  const send = transportSendPrimitive((args) => {
    ids.push(args.request_id);
    return f.transport.send(args);
  });
  const first = await relayTick({ ledger, send, resolver });
  assert.deepEqual(first.uncertain, [ledger.row.key]);
  assert.deepEqual(first.failed, []);
  assert.deepEqual(first.requeued, []);
  assert.equal(ledger.row.state, "uncertain");
  assert.equal(ledger.row.attempts, 0);
  const second = await relayTick({ ledger, send, resolver });
  assert.deepEqual(second.uncertain, [ledger.row.key]);
  assert.deepEqual(ids, ["relay:" + ledger.row.key]);
  assert.equal(f.posts.length, 1);
  assert.equal((await send(item())).sent, "unknown");
  assert.equal(f.posts.length, 1);
});

test("aborted tracking through actual receipt is unknown; positive observations retain precedence", async (t) => {
  const f = fixture(t);
  const sent = await f.transport.send({ target: "target", text: "synthetic payload", request_id: "receipt-request" });
  assert.equal(sent.accepted, true);
  const aborted = await f.transport.receipt({ inject_id: sent.inject_id });
  assert.equal(aborted.ok, true);
  assert.equal(aborted.receipt, "unknown");
  assert.equal(aborted.tracking_state, "aborted");
  assert.equal(aborted.completion_fact, null);
  f.observe({ tracking_state: "aborted", consumption: { status: "observed" } });
  assert.equal((await f.transport.receipt({ inject_id: sent.inject_id })).receipt, "consumption_observed");
  f.observe({ tracking_state: "aborted", observation: { kind: "inject_parked" } });
  assert.equal((await f.transport.receipt({ inject_id: sent.inject_id })).receipt, "queued");
  assert.equal(f.posts.length, 1);
});

test("definite HTTP refusal remains failed, not unknown or retried", async (t) => {
  const f = fixture(t, (response) => response({ code: "TARGET_NOT_FOUND" }, 404));
  const ledger = outbox();
  const send = transportSendPrimitive(f.transport.send);
  const first = await relayTick({ ledger, send, resolver });
  assert.deepEqual(first.failed, [ledger.row.key]);
  assert.deepEqual(first.uncertain, []);
  await relayTick({ ledger, send, resolver });
  assert.equal(f.posts.length, 1);
  const prior = await f.transport.send({ target: "target", text: ledger.row.text, request_id: "relay:" + ledger.row.key });
  assert.equal(prior.accepted, false);
  assert.equal(prior.state, "refused");
});

test("ECONNREFUSED permits a new attempt identity only after definite non-send", async (t) => {
  const f = fixture(t, (response, count) => {
    if (count === 1) throw Object.assign(new Error("synthetic refusal"), { cause: { code: "ECONNREFUSED" } });
    return response({ success: true, inject_id: "inject-1", exact_target: true, session_id: "target" });
  });
  const ledger = outbox();
  const ids = [];
  const send = transportSendPrimitive((args) => { ids.push(args.request_id); return f.transport.send(args); });
  assert.deepEqual((await relayTick({ ledger, send, resolver })).requeued, [ledger.row.key]);
  assert.deepEqual((await relayTick({ ledger, send, resolver })).sent, [ledger.row.key]);
  assert.deepEqual(ids, ["relay:" + ledger.row.key, "relay:" + ledger.row.key + ":1"]);
  assert.equal(f.posts.length, 2);
});

test("remote peer refusal precedes local injection", async (t) => {
  const f = fixture(t);
  assert.deepEqual(await transportSendPrimitive(f.transport.send)({ ...item(), peer_id: "remote" }),
    { ok: false, sent: "no", code: "PEER_UNSUPPORTED" });
  assert.equal(f.calls.length, 0);
});

test("REQUEST_IN_FLIGHT remains unknown through the actual transport caller", async (t) => {
  let release;
  let entered;
  const started = new Promise((resolve) => { entered = resolve; });
  const gate = new Promise((resolve) => { release = resolve; });
  const f = fixture(t, async (response) => {
    entered();
    await gate;
    return response({ success: true, inject_id: "inject-1", exact_target: true, session_id: "target" });
  });
  const send = transportSendPrimitive(f.transport.send);
  const pending = send(item());
  try {
    await started;
    assert.deepEqual(await send(item()), { ok: false, sent: "unknown", code: "REQUEST_IN_FLIGHT" });
  } finally {
    release();
    assert.equal((await pending).ok, true);
  }
  assert.equal(f.posts.length, 1);
});
