// In-process relay runner + one-shot CLI (SPEC 2026-10-11 §10): opt-in (interval 0 = off), bounded per
// tick, never two ticks at once, restart surfaces `uncertain` without a resend, health block, and the
// CLI refuses a held ledger lock (never reclaims). Fake send / loopback fake telepty only.

import { describe, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { openLedger } from "../src/relay/ledger.js";
import { createRouteResolver } from "../src/relay/route.js";
import { createRelayRunner, transportSendPrimitive } from "../src/relay/runner.js";
import { normalizeConfig, loadConfig, createTeleptyTransport } from "../src/index.js";
import { waitFor } from "./helpers.js";
import { makeSandbox } from "./helpers/fault-fs.js";
import { startFakeTelepty } from "./helpers/fake-telepty.js";

const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const NONCE = "e".repeat(32);
const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "bin", "telesession-relay-tick.js");
const NO_LOOPBACK = process.env.TELESESSION_TEST_NO_LOOPBACK === "1"
  ? "NOTRUN: loopback bind/connect not permitted here (TELESESSION_TEST_NO_LOOPBACK=1)" : false;
const resolver = createRouteResolver([{ peer_id: "peer-d", locators: ["dest-box"] }]);

function setup(t) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "telesession-runner-"));
  const dir = path.join(base, "ledger");
  const ledgers = [];
  const runners = [];
  const open = () => { const l = openLedger({ dir, resolver }); ledgers.push(l); return l; };
  t.after(() => { for (const r of runners) r.stop(); for (const l of ledgers) l.close(); fs.rmSync(base, { recursive: true, force: true }); });
  const l = open();
  l.createRequest({
    nonce: NONCE, request_id: null, origin: { host: "peer-d", session: "inbox" }, destination: { host: "peer-d", session: "w" },
    reply_to: { host: "peer-d", session: "inbox" }, generation: "g1", payload_sha256: sha("p"), deadline_ms: 60000,
  });
  const runner = (opts) => { const r = createRelayRunner({ resolver, ...opts }); runners.push(r); return r; };
  return { dir, l, open, runner };
}

const item = (kind, extra = {}) => ({ nonce: NONCE, to: { host: "dest-box", session: "w" }, kind, text: `p-${kind}`, ...extra });

test("disabled by default: interval 0 schedules nothing; health says enabled:false; an explicit tick still works", async (t) => {
  const { l, runner } = setup(t);
  l.enqueue(item("a"));
  let sends = 0;
  const r = runner({ ledger: l, send: async () => { sends += 1; return { ok: true, transport_id: "inj-a" }; } });
  assert.equal(r.start(), false, "no timer without an interval");
  await new Promise((res) => setTimeout(res, 30));
  assert.equal(sends, 0);
  assert.deepEqual(r.health(), { enabled: false, running: false, last_tick_at: null, last_result: null, uncertain_count: 0, queued_count: 1, quarantined_count: 0, oldest_quarantined_age_ms: null });
  const out = await r.tick();
  assert.equal(out.ok, true);
  assert.equal(sends, 1);
  const h = r.health();
  assert.match(h.last_tick_at, /^\d{4}-\d\d-\d\dT/);
  assert.deepEqual(h.last_result, { sent: 1, requeued: 0, failed: 0, uncertain: 0, unresolved: 0, skipped: 0, deferred: 0, commit_failed: 0 });
  assert.equal(h.queued_count, 0);
});

test("fake send → sent / failed / uncertain with receipts; health counts the uncertain item", async (t) => {
  const { l, runner } = setup(t);
  const a = l.enqueue(item("a")).key;
  const b = l.enqueue(item("b")).key;
  const c = l.enqueue(item("c")).key;
  const send = async (x) => {
    if (x.kind === "a") return { ok: true, transport_id: "inj-a" };
    if (x.kind === "b") return { ok: false, sent: "yes", code: "SESSION_NOT_FOUND" };
    return { ok: false, sent: "unknown", code: "DAEMON_TIMEOUT" };
  };
  const out = await runner({ ledger: l, send }).tick();
  assert.deepEqual([out.sent, out.failed, out.uncertain], [[a], [b], [c]]);
  const by = Object.fromEntries(l.outbox().map((o) => [o.kind, o]));
  assert.deepEqual([by.a.state, by.a.receipt.transport_id], ["sent", "inj-a"]);
  assert.deepEqual([by.b.state, by.b.last_error], ["failed", "SESSION_NOT_FOUND"]);
  assert.deepEqual([by.c.state, by.c.last_error], ["uncertain", "DAEMON_TIMEOUT"]);
  const r2 = runner({ ledger: l, send });
  assert.equal(r2.health().uncertain_count, 1);
});

test("never two ticks at once: a second tick while the first is sending is refused; send runs once", async (t) => {
  const { l, runner } = setup(t);
  l.enqueue(item("a"));
  let release;
  const hung = new Promise((res) => { release = res; });
  let sends = 0;
  const r = runner({ ledger: l, send: async () => { sends += 1; await hung; return { ok: true, transport_id: "inj-a" }; } });
  const first = r.tick();
  while (sends === 0) await new Promise((res) => setImmediate(res));
  assert.equal(r.health().running, true);
  assert.deepEqual(await r.tick(), { ok: false, code: "RELAY_TICK_IN_PROGRESS" });
  release();
  assert.equal((await first).ok, true);
  assert.equal(sends, 1);
  assert.equal(r.health().running, false);
});

test("bounded per tick: max items and max time leave the rest queued (deferred), picked up by the next tick", async (t) => {
  const { l, runner } = setup(t);
  for (const k of ["a", "b", "c"]) l.enqueue(item(k));
  const sent = [];
  const send = async (x) => { sent.push(x.kind); return { ok: true, transport_id: `inj-${x.kind}` }; };
  const r = runner({ ledger: l, send, maxItems: 2 });
  const out = await r.tick();
  assert.equal(out.sent.length, 2);
  assert.equal(out.deferred.length, 1);
  assert.equal(l.outbox().filter((o) => o.state === "queued").length, 1);
  assert.equal((await r.tick()).sent.length, 1);
  assert.equal(sent.length, 3);
  // Max time: a clock already past the tick budget after the first send defers the remainder.
  for (const k of ["d", "e"]) l.enqueue(item(k));
  let t0 = 0;
  const slow = runner({ ledger: l, send: async (x) => { t0 += 10_000; return send(x); }, maxTickMs: 5000, now: () => t0 });
  const o2 = await slow.tick();
  assert.deepEqual([o2.sent.length, o2.deferred.length], [1, 1]);
});

test("restart: an intent left by a dead process is uncertain on reopen; the runner surfaces it and never resends", async (t) => {
  const { dir, l, open, runner } = setup(t);
  const { key } = l.enqueue(item("a"));
  let release;
  const hung = new Promise((res) => { release = res; });
  let entered = 0;
  const tick = runner({ ledger: l, send: async () => { entered += 1; await hung; return { ok: true, transport_id: "late" }; } }).tick();
  while (entered === 0) await new Promise((res) => setImmediate(res));
  fs.unlinkSync(path.join(dir, "lock")); // the operator's documented recovery after confirming the holder is gone
  const l2 = open();
  let sends = 0;
  const r2 = runner({ ledger: l2, send: async () => { sends += 1; return { ok: true, transport_id: "x" }; } });
  assert.equal(r2.health().uncertain_count, 1);
  const out = await r2.tick();
  assert.deepEqual(out.uncertain, [key]);
  assert.equal(sends, 0);
  release();
  await tick;
  assert.equal(l2.outbox()[0].state, "uncertain");
});

test("enabled interval: start() ticks on its own timer; stop() ends it", async (t) => {
  const { l, runner } = setup(t);
  l.enqueue(item("a"));
  const r = runner({ ledger: l, send: async () => ({ ok: true, transport_id: "inj-a" }), intervalMs: 20 });
  assert.equal(r.start(), true);
  assert.equal(r.health().enabled, true);
  await waitFor(() => r.health().last_tick_at !== null, { timeoutMs: 3000, description: "a timer tick" });
  r.stop();
  assert.equal(l.outbox()[0].state, "sent");
});

test("transportSendPrimitive maps transport send records to the relay contract", async () => {
  const calls = [];
  const map = (rec) => transportSendPrimitive(async (a) => { calls.push(a); return rec; });
  const it = { key: "k".repeat(32), peer_id: "local", session: "target-1", text: "hi" };
  assert.deepEqual(await map({ ok: true, accepted: true, inject_id: "inj-1" })(it), { ok: true, transport_id: "inj-1" });
  assert.deepEqual(calls[0], { target: "target-1", text: "hi", request_id: `relay:${"k".repeat(32)}`, destination: { host: "local", session: "target-1" } });
  assert.deepEqual(await map({ ok: true, accepted: "unknown", reason: "DAEMON_TIMEOUT" })(it), { ok: false, sent: "unknown", code: "DAEMON_TIMEOUT" });
  assert.deepEqual(await map({ ok: true, accepted: false, error_code: "SESSION_NOT_FOUND" })(it), { ok: false, sent: "yes", code: "SESSION_NOT_FOUND" });
  assert.deepEqual(await map({ ok: false, error: { code: "SESSION_NOT_FOUND", http_status: 404, accepted: false } })(it), { ok: false, sent: "yes", code: "SESSION_NOT_FOUND" });
  assert.deepEqual(await map({ ok: false, error: { code: "DAEMON_UNREACHABLE", accepted: false } })(it), { ok: false, sent: "no", code: "DAEMON_UNREACHABLE" });
  assert.deepEqual(await map({ ok: false, error: { code: "EXACT_ROUTING_UNCONFIRMED", accepted: "unknown" } })(it), { ok: false, sent: "unknown", code: "EXACT_ROUTING_UNCONFIRMED" });
  assert.deepEqual(await map({ ok: false, error: { code: "TARGET_NOT_ALLOWED" } })(it), { ok: false, sent: "no", code: "TARGET_NOT_ALLOWED" });
  assert.deepEqual(await map({ ok: false, error: { code: "TRANSPORT_INTERNAL" } })(it), { ok: false, sent: "unknown", code: "TRANSPORT_INTERNAL" });
});

// Acceptance (a): the route's peer must reach the transport send (the primitive used to send `target: session`
// only). The same session name on two hosts: the local peer's item reaches the send with its exact peer; the
// other peer's item is refused before any send (PEER_UNSUPPORTED, #2026101110 U2 — remote forward is telepty#111).
test("relay destination: the same session on two hosts — the local peer is sent with its exact peer, the other refused PEER_UNSUPPORTED (telepty#111)", async (t) => {
  const two = createRouteResolver([{ peer_id: "peer-a", locators: ["box-a"] }, { peer_id: "peer-b", locators: ["box-b"] }]);
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "telesession-runner-dest-"));
  const l = openLedger({ dir: path.join(base, "ledger"), resolver: two });
  t.after(() => { l.close(); fs.rmSync(base, { recursive: true, force: true }); });
  l.createRequest({
    nonce: NONCE, request_id: null, origin: { host: "peer-a", session: "inbox" }, destination: { host: "peer-a", session: "w" },
    reply_to: { host: "peer-a", session: "inbox" }, generation: "g1", payload_sha256: sha("p"), deadline_ms: 60000,
  });
  const toA = l.enqueue({ nonce: NONCE, to: { host: "box-a", session: "w" }, kind: "relay", text: "for a" }).key;
  const toB = l.enqueue({ nonce: NONCE, to: { host: "box-b", session: "w" }, kind: "relay", text: "for b" }).key;
  const calls = [];
  const send = transportSendPrimitive(async (a) => { calls.push(a); return { ok: true, accepted: true, inject_id: `inj-${calls.length}` }; }, { localPeer: "peer-a" });
  const out = await createRelayRunner({ ledger: l, send, resolver: two }).tick();
  assert.deepEqual([out.sent, out.requeued], [[toA], [toB]]);
  assert.deepEqual(calls.map((c) => [c.text, c.destination]), [["for a", { host: "peer-a", session: "w" }]]);
  assert.equal(l.outbox().find((o) => o.key === toB).last_error, "PEER_UNSUPPORTED");
});

test("config: TELESESSION_RELAY_INTERVAL_MS is opt-in; absent/0 keeps the config shape; invalid or without a state dir refused", () => {
  const env = { TELESESSION_TARGETS: "t1", TELESESSION_INBOX_PREFIX: "tsr", TELESESSION_TELEPTY_URL: "http://127.0.0.1:3848", TELESESSION_TELEPTY_TOKEN: "tok" };
  const dir = path.join(os.tmpdir(), "x-state");
  assert.equal(loadConfig(env).relayIntervalMs, 0);
  assert.deepEqual(Object.keys(loadConfig(env)).sort(), ["inboxPrefix", "targets", "teleptyOrigin"]);
  assert.equal(loadConfig({ ...env, TELESESSION_RELAY_INTERVAL_MS: "0" }).relayIntervalMs, 0);
  assert.equal(loadConfig({ ...env, TELESESSION_STATE_DIR: dir, TELESESSION_RELAY_INTERVAL_MS: "5000" }).relayIntervalMs, 5000);
  for (const bad of ["5", "abc", "-1", "1.5", "3600001"]) {
    assert.throws(() => loadConfig({ ...env, TELESESSION_STATE_DIR: dir, TELESESSION_RELAY_INTERVAL_MS: bad }), (e) => e.code === "CONFIG_RELAY_INTERVAL_INVALID", bad);
  }
  assert.throws(() => loadConfig({ ...env, TELESESSION_RELAY_INTERVAL_MS: "5000" }), (e) => e.code === "CONFIG_STATE_DIR_REQUIRED");
  assert.equal(normalizeConfig({ teleptyUrl: "http://127.0.0.1:3848", token: "t", targets: ["t1"], inboxPrefix: "p" }).relayIntervalMs, 0);
});

describe("relay runner inside the transport and the one-shot CLI (loopback fake telepty)", { skip: NO_LOOPBACK }, () => {
  async function transportSetup(t, cfgExtra = {}) {
    const sb = makeSandbox("ts-runner-");
    const fake = await startFakeTelepty();
    const ledger = openLedger({ dir: path.join(sb.root, "ledger") });
    const cfg = normalizeConfig({ teleptyUrl: fake.origin, token: fake.token, targets: ["target-1"], inboxPrefix: "tsr", stateDir: sb.stateDir, ...cfgExtra });
    const tr = createTeleptyTransport(cfg, sb.seam(), { ledger });
    t.after(async () => { await tr.close(); ledger.close(); await fake.close(); sb.remove(); });
    return { sb, fake, ledger, tr };
  }

  test("health has a relay block (disabled by default); relayTick sends a queued local item via the transport send", async (t) => {
    const { fake, ledger, tr } = await transportSetup(t);
    const h = await tr.health();
    assert.equal(h.ok, true, JSON.stringify(h));
    assert.deepEqual(h.relay, { enabled: false, running: false, last_tick_at: null, last_result: null, uncertain_count: 0, queued_count: 0, quarantined_count: 0, oldest_quarantined_age_ms: null });
    const s = await tr.send({ target: "target-1", text: "origin job" });
    assert.equal(s.ok, true, JSON.stringify(s));
    const { key } = ledger.enqueue({ nonce: s.nonce, to: { host: "local", session: "target-1" }, kind: "relay", text: "relayed hop text" });
    const out = await tr.relayTick();
    assert.equal(out.ok, true, JSON.stringify(out));
    assert.deepEqual(out.sent, [key]);
    const o = ledger.outbox()[0];
    assert.equal(o.state, "sent");
    assert.equal(o.receipt.transport_id, fake.injectsTo("target-1").at(-1).inject_id);
    assert.ok(fake.sessions.get("target-1").delivered.at(-1).prompt.endsWith("\nrelayed hop text"));
    assert.equal((await tr.health()).relay.last_result.sent, 1);
  });

  test("relay enabled by config ticks on its own inside the transport and stops on close", async (t) => {
    const { ledger, tr } = await transportSetup(t, { relayIntervalMs: 1000 });
    const s = await tr.send({ target: "target-1", text: "origin job" });
    ledger.enqueue({ nonce: s.nonce, to: { host: "local", session: "target-1" }, kind: "relay", text: "auto relayed" });
    assert.equal((await tr.health()).relay.enabled, true);
    await waitFor(() => ledger.outbox()[0].state === "sent", { timeoutMs: 5000, description: "timer tick sent the item" });
  });

  function cliEnv(sb, origin = "http://127.0.0.1:9", token = "x") {
    return {
      PATH: process.env.PATH, HOME: sb.home, TELESESSION_TARGETS: "target-1", TELESESSION_INBOX_PREFIX: "tsc",
      TELESESSION_TELEPTY_URL: origin, TELESESSION_TELEPTY_TOKEN: token, TELESESSION_STATE_DIR: sb.stateDir,
    };
  }

  test("CLI refuses a ledger lock held by a live process (LEDGER_LOCKED) and a stale one (LEDGER_LOCK_STALE); never reclaims", (t) => {
    const sb = makeSandbox("ts-cli-");
    t.after(() => sb.remove());
    const dir = path.join(sb.stateDir, "ledger");
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.chmodSync(sb.stateDir, 0o700);
    const lock = path.join(dir, "lock");
    fs.writeFileSync(lock, JSON.stringify({ v: 1, owner: "f".repeat(32), pid: process.pid }), { mode: 0o600 });
    const r = spawnSync(process.execPath, [CLI], { env: cliEnv(sb), cwd: sb.project, encoding: "utf8", timeout: 20000 });
    assert.equal(r.status, 3, r.stderr);
    assert.match(r.stderr, /LEDGER_LOCKED/);
    assert.equal(r.stdout, "");
    const dead = spawnSync(process.execPath, ["-e", ""]).pid;
    fs.writeFileSync(lock, JSON.stringify({ v: 1, owner: "f".repeat(32), pid: dead }), { mode: 0o600 });
    const r2 = spawnSync(process.execPath, [CLI], { env: cliEnv(sb), cwd: sb.project, encoding: "utf8", timeout: 20000 });
    assert.equal(r2.status, 3, r2.stderr);
    assert.match(r2.stderr, /LEDGER_LOCK_STALE/);
    assert.ok(fs.existsSync(lock), "the lock is never reclaimed");
  });

  test("CLI runs exactly one tick when the ledger is free and releases the lock", async (t) => {
    const sb = makeSandbox("ts-cli-ok-");
    const fake = await startFakeTelepty();
    t.after(async () => { await fake.close(); sb.remove(); });
    // An origin record + a queued relay item, written by an earlier (closed) process.
    fs.mkdirSync(sb.stateDir, { mode: 0o700 });
    const l = openLedger({ dir: path.join(sb.stateDir, "ledger") });
    l.createRequest({
      nonce: NONCE, request_id: null, origin: { host: "local", session: "inbox" }, destination: { host: "local", session: "target-1" },
      reply_to: { host: "local", session: "inbox" }, generation: null, payload_sha256: sha("p"), deadline_ms: 60000,
    });
    const { key } = l.enqueue({ nonce: NONCE, to: { host: "local", session: "target-1" }, kind: "relay", text: "from the CLI" });
    l.close();
    const child = spawn(process.execPath, [CLI], { env: cliEnv(sb, fake.origin, fake.token), cwd: sb.project, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr += d; });
    const code = await new Promise((res) => child.on("exit", res));
    assert.equal(code, 0, stderr);
    const out = JSON.parse(stdout);
    assert.deepEqual(out.sent, [key]);
    assert.ok(fake.sessions.get("target-1").delivered.at(-1).prompt.endsWith("\nfrom the CLI"));
    assert.ok(!fs.existsSync(path.join(sb.stateDir, "ledger", "lock")), "lock released");
    const l2 = openLedger({ dir: path.join(sb.stateDir, "ledger") });
    t.after(() => l2.close());
    assert.equal(l2.outbox()[0].state, "sent");
  });
});
