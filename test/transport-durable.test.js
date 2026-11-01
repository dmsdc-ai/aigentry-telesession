// telesession durable transport (L2 over L1) — independent request/transport vectors authored from the
// FROZEN contract (IMPLEMENTATION-CONTRACT-R2.json apis.config/transport/mcp_adapter/bin + test_vectors,
// SPEC-R2 §2 and §6–§8, CONTROLLER-ADDENDA). Real store on the real fs; telepty is modelled by a
// loopback fake daemon (helpers/fake-telepty.js) following SPEC-R2 F1–F5.
//
// Two groups:
//  * pure (no sockets): config additions, synchronous startup refusals, bin exit 2, MCP request_id schema.
//  * socket-backed: everything that needs the fake daemon and the transport's own loopback receiver.
//    Set TELESESSION_TEST_NO_LOOPBACK=1 where loopback bind/connect is not permitted: those cases are then
//    reported as SKIP "NOTRUN" instead of failing on EPERM. They never claim a pass without running.

import { describe, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { ConfigError, loadConfig, normalizeConfig, createTeleptyTransport } from "../src/index.js";
import { StoreError, openStore } from "../src/store.js";
import { BIN, PACKAGE_DIR, freshToken, runNode, waitFor } from "./helpers.js";
import {
  createFaultFs, foreignLock, hex, inspectDir, makeInbox, makeRequest, makeSandbox, makeState, newInboxId,
  readJson, sha256, tmpLeftovers, wirePrompt, writeLockFile, writeStateDir,
} from "./helpers/fault-fs.js";
import { startFakeTelepty, parseWire } from "./helpers/fake-telepty.js";
import { startChildHost } from "./helpers/child-host.js";

const PREFIX = "tsd";
const UNUSED_ORIGIN = "http://127.0.0.1:47999";
const POSIX = process.platform !== "win32";
const NO_LOOPBACK = process.env.TELESESSION_TEST_NO_LOOPBACK === "1"
  ? "NOTRUN: loopback bind/connect not permitted here (TELESESSION_TEST_NO_LOOPBACK=1)" : false;
const HAS_SDK = (() => { try { import.meta.resolve("@modelcontextprotocol/sdk/client/index.js"); return true; } catch { return false; } })();
const NO_SDK = HAS_SDK ? false : "NOTRUN: @modelcontextprotocol/sdk not resolvable (node_modules link absent)";

function throwsCode(fn, Klass, code) {
  let err = null;
  try { fn(); } catch (e) { err = e; }
  assert.ok(err, `expected ${code}`);
  assert.ok(err instanceof Klass, `expected ${Klass.name}, got ${err && err.name}`);
  assert.equal(err.code, code);
  return err;
}

const statePath = (sb) => path.join(sb.stateDir, "state.json");
const diskState = (sb) => readJson(statePath(sb));
const recordOnDisk = (sb, requestId) => diskState(sb).requests[`r:${requestId}`];

// R3 §6: health()/listAllowedTargets() are read-only and never start recovery; send/receipt/readReply
// await it. A receipt for an id this transport never issued runs recovery and then refuses.
async function recoverVia(tr) {
  const r = await tr.receipt({ inject_id: `unissued-${hex(8)}` });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, "INJECT_NOT_ISSUED", JSON.stringify(r));
}

// A rename onto state.json whose fsynced tmp content satisfies `pred(parsedState)`.
const renamesStateWhere = (pred) => (ctx) => {
  if (ctx.op !== "renameSync" || !ctx.paths[1] || path.basename(ctx.paths[1]) !== "state.json") return false;
  try { return pred(JSON.parse(ctx.base.readFileSync(ctx.paths[0], "utf8"))); } catch { return false; }
};

// ── pure: config additions ──

describe("config durable additions (pure)", () => {
  const base = (extra = {}) => ({ teleptyUrl: UNUSED_ORIGIN, token: freshToken(), targets: ["target-1"], inboxPrefix: PREFIX, ...extra });

  test("stateDir lexical refusals → CONFIG_STATE_DIR_INVALID; valid dir kept; absent → null/false", () => {
    const abs = path.resolve("/var/lib/telesession-test-never-created");
    const bad = [
      "relative/dir", `${abs}${path.sep}..${path.sep}x`, `${abs}${path.sep}`, `${abs}\u0000x`, `${abs}\u0001x`, `${abs}\u007fx`,
      path.join(abs, "a".repeat(520)), "",
    ];
    for (const stateDir of bad) throwsCode(() => normalizeConfig(base({ stateDir })), ConfigError, "CONFIG_STATE_DIR_INVALID");
    const ok = normalizeConfig(base({ stateDir: abs }));
    assert.equal(ok.stateDir, abs);
    assert.equal(ok.persistInboxCredential, false);
    assert.ok(Object.keys(ok).includes("stateDir"));
    assert.ok(!Object.keys(ok).includes("token"));
    const mem = normalizeConfig(base());
    assert.equal(mem.stateDir, null);
    assert.equal(mem.persistInboxCredential, false);
    assert.equal(normalizeConfig(base({ stateDir: null })).stateDir, null);
    throwsCode(() => normalizeConfig(base({ persistInboxCredential: true })), ConfigError, "CONFIG_STATE_DIR_REQUIRED");
    assert.equal(normalizeConfig(base({ stateDir: abs, persistInboxCredential: true })).persistInboxCredential, true);
  });

  test("check order: targets, prefix, url, token, stateDir, persist", () => {
    throwsCode(() => normalizeConfig(base({ token: "bad token", stateDir: "rel" })), ConfigError, "CONFIG_TOKEN_INVALID");
    throwsCode(() => normalizeConfig(base({ teleptyUrl: "http://10.0.0.1:1", stateDir: "rel" })), ConfigError, "CONFIG_URL_INVALID");
    throwsCode(() => normalizeConfig(base({ stateDir: "rel", persistInboxCredential: true })), ConfigError, "CONFIG_STATE_DIR_INVALID");
  });

  test("env: TELESESSION_STATE_DIR empty = unset; TELESESSION_PERSIST_INBOX_CREDENTIAL unset|''|'0'|'1' only", () => {
    const abs = path.resolve("/var/lib/telesession-test-never-created");
    const env = (extra) => ({
      TELESESSION_TARGETS: "target-1", TELESESSION_INBOX_PREFIX: PREFIX, TELESESSION_TELEPTY_URL: UNUSED_ORIGIN,
      TELESESSION_TELEPTY_TOKEN: freshToken(), ...extra,
    });
    assert.equal(loadConfig(env({ TELESESSION_STATE_DIR: "" })).stateDir, null);
    for (const v of [undefined, "", "0"]) {
      const c = loadConfig(env({ TELESESSION_STATE_DIR: abs, ...(v === undefined ? {} : { TELESESSION_PERSIST_INBOX_CREDENTIAL: v }) }));
      assert.equal(c.persistInboxCredential, false, String(v));
    }
    assert.equal(loadConfig(env({ TELESESSION_STATE_DIR: abs, TELESESSION_PERSIST_INBOX_CREDENTIAL: "1" })).persistInboxCredential, true);
    throwsCode(() => loadConfig(env({ TELESESSION_PERSIST_INBOX_CREDENTIAL: "1" })), ConfigError, "CONFIG_STATE_DIR_REQUIRED");
    for (const v of ["true", "yes", "2", " 1", "1 ", "01"]) {
      throwsCode(() => loadConfig(env({ TELESESSION_STATE_DIR: abs, TELESESSION_PERSIST_INBOX_CREDENTIAL: v })), ConfigError, "CONFIG_PERSIST_INVALID");
    }
    throwsCode(() => loadConfig(env({ TELESESSION_STATE_DIR: "rel" })), ConfigError, "CONFIG_STATE_DIR_INVALID");
  });

  test("native win32 lexical refusals: UNC, \\\\?\\, \\\\.\\, drive-relative", { skip: process.platform === "win32" ? false : "NOTRUN: native Windows only (TV20)" }, () => {
    for (const stateDir of ["\\\\srv\\share\\ts", "\\\\?\\C:\\ts", "\\\\.\\C:\\ts", "C:ts"]) {
      throwsCode(() => normalizeConfig(base({ stateDir })), ConfigError, "CONFIG_STATE_DIR_INVALID");
    }
  });
});

// ── pure: startup refusals happen synchronously, before any HTTP ──

describe("startup refusals (synchronous, zero HTTP, no sockets)", () => {
  test("STORE_LOCKED / STORE_PATH_FORBIDDEN thrown by createTeleptyTransport; lock untouched; memory mode touches no fs", (t) => {
    const sb = makeSandbox("ts-durable-");
    t.after(() => sb.remove());
    const cfg = (stateDir) => normalizeConfig({ teleptyUrl: UNUSED_ORIGIN, token: freshToken(), targets: ["target-1"], inboxPrefix: PREFIX, stateDir });
    writeStateDir(sb.stateDir, makeState({ origin: UNUSED_ORIGIN, prefix: PREFIX, inbox: makeInbox({ prefix: PREFIX, phase: "deleted" }) }), { lock: foreignLock() });
    const before = inspectDir(sb.stateDir);
    throwsCode(() => createTeleptyTransport(cfg(sb.stateDir), sb.seam()), StoreError, "STORE_LOCKED");
    assert.deepEqual(inspectDir(sb.stateDir), before);
    const inProject = path.join(sb.project, ".telesession");
    fs.mkdirSync(inProject, { mode: 0o700 });
    throwsCode(() => createTeleptyTransport(cfg(inProject), sb.seam()), StoreError, "STORE_PATH_FORBIDDEN");
    assert.deepEqual(fs.readdirSync(inProject), []);
    const ff = createFaultFs();
    const tr = createTeleptyTransport(cfg(null), sb.seam({ fs: ff.fs }));
    assert.deepEqual(ff.calls, [], "stateDir unset → the store seam is never touched");
    return tr.close();
  });

  test("bin: StoreError at startup → exit 2, one code-only stderr line, no token/path", { skip: NO_SDK }, async (t) => {
    const sb = makeSandbox("ts-durable-bin-");
    t.after(() => sb.remove());
    writeStateDir(sb.stateDir, makeState({ origin: UNUSED_ORIGIN, prefix: PREFIX }), { lock: foreignLock() });
    const token = freshToken();
    const env = {
      HOME: sb.home, USERPROFILE: sb.home, TMPDIR: sb.root,
      TELESESSION_TARGETS: "target-1", TELESESSION_INBOX_PREFIX: PREFIX, TELESESSION_TELEPTY_URL: UNUSED_ORIGIN,
      TELESESSION_TELEPTY_TOKEN: token, TELESESSION_STATE_DIR: sb.stateDir,
    };
    const cases = [
      [{}, "STORE_LOCKED"],
      [{ TELESESSION_PERSIST_INBOX_CREDENTIAL: "yes" }, "CONFIG_PERSIST_INVALID"],
      [{ TELESESSION_STATE_DIR: "relative/dir" }, "CONFIG_STATE_DIR_INVALID"],
      [{ TELESESSION_STATE_DIR: "", TELESESSION_PERSIST_INBOX_CREDENTIAL: "1" }, "CONFIG_STATE_DIR_REQUIRED"],
    ];
    const lockBefore = inspectDir(sb.stateDir).lock;
    for (const [extra, code] of cases) {
      const res = await runNode([BIN], { name: `durable-refuse-${code}`, env: { ...env, ...extra } });
      assert.equal(res.code, 2, `${code}: ${res.log}`);
      assert.equal(res.log, `telesession-mcp refused: ${code}\n`);
      assert.ok(!res.log.includes(token) && !res.log.includes(sb.root));
    }
    assert.deepEqual(inspectDir(sb.stateDir).lock, lockBefore);
  });

  test("MCP telesession_send: request_id optional, pattern-checked, strict schema (stdio, no daemon call)", { skip: NO_SDK }, async (t) => {
    const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
    const { StdioClientTransport } = await import("@modelcontextprotocol/sdk/client/stdio.js");
    const sb = makeSandbox("ts-durable-mcp-");
    const logFile = path.join(sb.root, "mcp-stderr.log");
    const fd = fs.openSync(logFile, "w");
    const transport = new StdioClientTransport({
      command: process.execPath, args: [BIN], cwd: PACKAGE_DIR, stderr: fd,
      env: {
        HOME: sb.home, USERPROFILE: sb.home, TMPDIR: sb.root, PATH: process.env.PATH || "",
        TELESESSION_TARGETS: "target-1", TELESESSION_INBOX_PREFIX: PREFIX, TELESESSION_TELEPTY_URL: UNUSED_ORIGIN,
        TELESESSION_TELEPTY_TOKEN: freshToken(),
      },
    });
    const client = new Client({ name: "telesession-durable-test", version: "0.0.0" });
    try { await client.connect(transport); } finally { fs.closeSync(fd); }
    t.after(async () => { try { await client.close(); } finally { sb.remove(); } });
    const { tools } = await client.listTools();
    assert.equal(tools.length, 6, "only telesession_request_status added (task #2026101110)");
    const send = tools.find((x) => x.name === "telesession_send");
    assert.equal(send.inputSchema.additionalProperties, false);
    assert.ok(send.inputSchema.properties.request_id, "request_id declared");
    assert.deepEqual([...send.inputSchema.required].sort(), ["target", "text"], "request_id optional");
    const refused = async (args) => {
      try {
        const r = await client.callTool({ name: "telesession_send", arguments: args });
        assert.equal(r.isError, true, JSON.stringify(args));
      } catch (err) {
        assert.match(String(err.message), /-32602|invalid/i);
      }
    };
    for (const request_id of ["", "has space", "a/b", "x".repeat(129), "naïve", 7]) {
      await refused({ target: "target-1", text: "hi", request_id });
    }
    await refused({ target: "target-1", text: "hi", request_id: "ok-1", extra: true });
  });
});

// ── socket-backed vectors ──

async function setup(t, { targets = ["target-1"], persist = false, fake: fakeOpts = {} } = {}) {
  const sb = makeSandbox("ts-durable-");
  const fake = await startFakeTelepty({ targets, ...fakeOpts });
  const transports = [];
  const results = [];
  t.after(async () => {
    for (const tr of transports) { try { await tr.close(); } catch { /* closed */ } }
    await fake.close();
    sb.remove();
  });
  const config = (extra = {}) => normalizeConfig({
    teleptyUrl: fake.origin, token: fake.token, targets, inboxPrefix: PREFIX,
    stateDir: sb.stateDir, persistInboxCredential: persist, ...extra,
  });
  // Every public result is captured so secret-exposure checks can scan all of them.
  const wrap = (tr) => {
    const w = {};
    for (const k of ["health", "listAllowedTargets", "send", "receipt", "readReply"]) {
      w[k] = async (args) => { const r = await tr[k](args); results.push(r); return r; };
    }
    w.close = async () => { const r = await tr.close(); results.push(r); return r; };
    w.raw = tr;
    return w;
  };
  const make = ({ storeOptions = {}, cfg = {}, dir } = {}) => {
    const tr = createTeleptyTransport(config({ ...(dir ? { stateDir: dir } : {}), ...cfg }), sb.seam(storeOptions));
    transports.push(tr);
    return wrap(tr);
  };
  return { sb, fake, make, config, results };
}

const replyText = (nonce, body = "answer") => `REPLY ${nonce} ${body}`;

async function sendCaptured(fake, tr, args) {
  const before = fake.sessions.get(args.target)?.delivered.length ?? 0;
  const r = await tr.send(args);
  const s = fake.sessions.get(args.target);
  const d = s && s.delivered.length > before ? s.delivered[s.delivered.length - 1] : null;
  return { r, wire: d ? parseWire(d.prompt) : null, delivered: d };
}

async function trustedReply(tr, nonce, waitMs = 8000) {
  const r = await tr.readReply({ nonce, wait_ms: waitMs });
  assert.equal(r.ok, true, JSON.stringify(r));
  return r;
}

const waitMail = (fake, pred, description) => waitFor(() => fake.mailbox.find(pred), { timeoutMs: 8000, description });

describe("durable transport vectors (loopback fake telepty)", { skip: NO_LOOPBACK }, () => {
  test("TV08 exact dedupe: same id+target+bytes → prior record, zero requests; same after graceful restart (zero inject)", async (t) => {
    const { sb, fake, make } = await setup(t);
    const a = make();
    const { r: first, wire } = await sendCaptured(fake, a, { target: "target-1", text: "build the report", request_id: "job-1" });
    assert.equal(first.ok, true, JSON.stringify(first));
    assert.equal(first.state, "accepted");
    assert.equal(first.durability, "durable");
    assert.equal(first.deduplicated, false);
    assert.equal(first.request_id, "job-1");
    assert.equal(first.completion_fact, null);
    assert.equal(wire.nonce, first.nonce);
    const n = fake.requests.length;
    const again = await a.send({ target: "target-1", text: "build the report", request_id: "job-1" });
    assert.equal(again.ok, true);
    assert.equal(again.deduplicated, true);
    assert.equal(again.nonce, first.nonce);
    assert.equal(again.state, "accepted");
    assert.equal(fake.requests.length, n, "zero telepty requests for an in-process duplicate");
    const h = await a.health();
    assert.deepEqual(Object.keys(h.store).sort(), ["credential_persisted", "gaps", "mode", "orphans", "pending", "permissions", "recovery", "state", "uncertain"]);
    assert.equal(h.store.mode, "durable");
    assert.equal(h.store.state, "ok");
    assert.equal((await a.close()).outcome, "deleted");
    const b = make();
    const injectsBefore = fake.injectArrivals.length;
    const after = await b.send({ target: "target-1", text: "build the report", request_id: "job-1" });
    assert.equal(after.ok, true, JSON.stringify(after));
    assert.equal(after.deduplicated, true);
    assert.equal(after.nonce, first.nonce);
    assert.equal(after.inject_id, first.inject_id);
    assert.equal(fake.injectArrivals.length, injectsBefore, "never re-sent across restart");
    assert.ok(!fs.readFileSync(statePath(sb), "utf8").includes("build the report"), "prompt text never persisted");
  });

  test("TV09 conflicts: different bytes (trailing space, NFC vs NFD) or target → REQUEST_ID_CONFLICT, zero inject", async (t) => {
    const { fake, make } = await setup(t, { targets: ["target-1", "target-2"] });
    const a = make();
    assert.equal((await a.send({ target: "target-1", text: "caf\u00e9", request_id: "c-1" })).ok, true);
    const n = fake.injectArrivals.length;
    for (const [args, conflict] of [
      [{ target: "target-1", text: "caf\u00e9 ", request_id: "c-1" }, "body"],
      [{ target: "target-1", text: "cafe\u0301", request_id: "c-1" }, "body"],
      [{ target: "target-2", text: "caf\u00e9", request_id: "c-1" }, "target"],
    ]) {
      const r = await a.send(args);
      assert.equal(r.ok, false);
      assert.equal(r.error.code, "REQUEST_ID_CONFLICT");
      assert.equal(r.error.conflict, conflict);
    }
    assert.equal(fake.injectArrivals.length, n);
  });

  test("TV09b concurrent same request_id → REQUEST_IN_FLIGHT, exactly one inject", async (t) => {
    const { fake, make } = await setup(t);
    const a = make();
    assert.equal((await a.health()).ok, true);
    fake.hooks.beforeInject = () => new Promise((r) => setTimeout(r, 400));
    const [x, y] = await Promise.all([
      a.send({ target: "target-1", text: "once", request_id: "dup-1" }),
      new Promise((r) => setTimeout(r, 100)).then(() => a.send({ target: "target-1", text: "once", request_id: "dup-1" })),
    ]);
    assert.equal(x.ok, true, JSON.stringify(x));
    assert.equal(y.ok, false);
    assert.equal(y.error.code, "REQUEST_IN_FLIGHT");
    assert.equal(fake.injectArrivals.length, 1);
  });

  test("TV01 reserve commit fails → STORE_WRITE_FAILED, zero inject, prior bytes intact; same id later sends once", async (t) => {
    const { sb, fake, make } = await setup(t);
    const ff = createFaultFs();
    const a = make({ storeOptions: { fs: ff.fs } });
    assert.equal((await a.send({ target: "target-1", text: "warm-up", request_id: "w-1" })).ok, true);
    let bytesAtFault = null;
    const isReserve = renamesStateWhere((st) => st.requests["r:r-1"] && st.requests["r:r-1"].state === "reserved");
    const rule = ff.fail({ op: "renameSync", errno: "ENOSPC", when: (ctx) => { const hit = isReserve(ctx); if (hit) bytesAtFault = fs.readFileSync(statePath(sb)); return hit; } });
    const n = fake.injectArrivals.length;
    const r = await a.send({ target: "target-1", text: "real job", request_id: "r-1" });
    assert.equal(rule.hits, 1);
    assert.equal(r.ok, false);
    assert.equal(r.error.code, "STORE_WRITE_FAILED");
    assert.equal(r.error.errno, "ENOSPC");
    assert.equal(fake.injectArrivals.length, n, "zero inject when the reserve did not commit");
    assert.deepEqual(fs.readFileSync(statePath(sb)), bytesAtFault);
    assert.deepEqual(tmpLeftovers(sb.stateDir), []);
    const ok = await a.send({ target: "target-1", text: "real job", request_id: "r-1" });
    assert.equal(ok.ok, true, JSON.stringify(ok));
    assert.equal(ok.deduplicated, false);
    assert.equal(fake.injectArrivals.length, n + 1);
  });

  test("TV13 post-inject commit fails → durability:degraded, STORE_DEGRADED until a commit lands; restart: uncertain then audit-verified, never re-sent", async (t) => {
    const { sb, fake, make } = await setup(t);
    const ff = createFaultFs();
    const a = make({ storeOptions: { fs: ff.fs } });
    const failB = ff.fail({ op: "renameSync", errno: "ENOSPC", times: Infinity, when: renamesStateWhere((st) => st.requests["r:b"]?.state === "accepted") });
    const b = await a.send({ target: "target-1", text: "job b", request_id: "b" });
    assert.equal(b.ok, true, JSON.stringify(b));
    assert.equal(b.durability, "degraded");
    assert.equal(recordOnDisk(sb, "b").state, "reserved");
    const n = fake.injectArrivals.length;
    const refused = await a.send({ target: "target-1", text: "job c", request_id: "c" });
    assert.equal(refused.ok, false);
    assert.equal(refused.error.code, "STORE_DEGRADED");
    assert.equal(fake.injectArrivals.length, n);
    assert.equal((await a.health()).store.state, "degraded");
    ff.clear();
    assert.equal((await a.health()).store.state, "ok", "health() retried the held delta");
    assert.equal(recordOnDisk(sb, "b").state, "accepted");
    assert.ok(failB.hits >= 2);
    ff.fail({ op: "renameSync", errno: "ENOSPC", times: Infinity, when: renamesStateWhere((st) => st.requests["r:d"]?.state === "accepted") });
    const d = await a.send({ target: "target-1", text: "job d", request_id: "d" });
    assert.equal(d.durability, "degraded");
    await a.close();
    ff.clear();
    assert.equal(recordOnDisk(sb, "d").state, "reserved");
    const a2 = make();
    assert.equal(recordOnDisk(sb, "d").state, "uncertain", "startup sync: reserved → uncertain");
    assert.equal(recordOnDisk(sb, "d").uncertain_reason, "process_restart");
    const injected = fake.injectArrivals.length;
    const again = await a2.send({ target: "target-1", text: "job d", request_id: "d" });
    assert.equal(again.ok, true, JSON.stringify(again));
    assert.equal(again.deduplicated, true);
    assert.equal(again.state, "accepted", "the one fully verified audit row recovered it");
    assert.equal(again.recovery, "audit_verified_match");
    assert.equal(again.inject_id, d.inject_id);
    assert.equal(fake.injectArrivals.length, injected, "never re-sent");
  });

  // TV03 / TV23 recovery from a lock-free state fixture (stands in for the future reviewed repair gate).
  test("TV03/TV23 audit recovery: only one fully verified row recovers; forged/claimed/partial/multi-page rows never do", async (t) => {
    const variants = [
      ["exact success", (ctx) => [ctx.row()], { state: "accepted", recovery: "audit_verified_match" }],
      ["exact queued", (ctx) => [ctx.row({ delivery_result: "queued" })], { state: "accepted", recovery: "audit_verified_match" }],
      ["exact failed cannot prove zero effect", (ctx) => [ctx.row({ delivery_result: "failed:write" })], { state: "uncertain", recovery: "unverified" }],
      ["exact delivery unknown remains unknown", (ctx) => [ctx.row({ delivery_result: "failed:DELIVERY_UNCERTAIN" })], { state: "uncertain", recovery: "unverified" }],
      ["exact blocked", (ctx) => [ctx.row({ delivery_result: "blocked:peer_lane" })], { state: "refused", recovery: "audit_verified_match" }],
      ["no rows", () => [], { state: "uncertain", recovery: "not_found" }],
      ["two verified rows", (ctx) => [ctx.row(), ctx.row()], { state: "uncertain", recovery: "ambiguous" }],
      ["audit unavailable", (ctx) => { ctx.fake.flags.auditAvailable = false; return [ctx.row()]; }, { state: "uncertain", recovery: "audit_unavailable" }],
      ["claimed from only (no verified sender)", (ctx) => [ctx.row({ verified_sender_sid: null, verified_sender_epoch: null, verified_sender_generation: null })], { state: "uncertain", recovery: "unverified" }],
      ["TV23 forged by another token holder", (ctx) => { ctx.fake.injectAs(ctx.fake.sessions.get("target-2").bearer, "target-1", ctx.wire, ctx.sender.id, { ts: new Date(ctx.rec.created_at + 500).toISOString() }); return []; }, { state: "uncertain", recovery: "unverified" }],
      ["verified epoch differs", (ctx) => [ctx.row({ verified_sender_epoch: "epoch-other" })], { state: "uncertain" }],
      ["verified generation differs", (ctx) => [ctx.row({ verified_sender_generation: ctx.sender.generation + 1 })], { state: "uncertain" }],
      ["spoof_suspected", (ctx) => [ctx.row({ spoof_suspected: true })], { state: "uncertain" }],
      ["to_alias set", (ctx) => [ctx.row({ to_alias: "alias-1" })], { state: "uncertain" }],
      ["wrong payload hash", (ctx) => [ctx.row({ payload_sha256: sha256(ctx.wire + " ") })], { state: "uncertain" }],
      ["outside the window", (ctx) => { ctx.fake.flags.ignoreWindow = true; return [ctx.row({ ts: new Date(ctx.rec.created_at + 20000).toISOString() })]; }, { state: "uncertain" }],
      ["next_cursor set (incomplete page)", (ctx) => { ctx.fake.flags.forceNextCursor = true; return [ctx.row()]; }, { state: "uncertain" }],
    ];
    for (const [name, seed, expect] of variants) {
      await t.test(name, async (st) => {
        const { sb, fake, make } = await setup(st, { targets: ["target-1", "target-2"] });
        const sender = { id: newInboxId(PREFIX), epoch: `epoch-${hex(8)}`, generation: 5 };
        const rec = makeRequest({ request_id: "rec-1", target: "target-1", text: "recover me", sender });
        const wire = wirePrompt(rec.nonce, sender.id, "recover me");
        writeStateDir(sb.stateDir, makeState({
          origin: fake.origin, prefix: PREFIX, requests: [rec],
          inbox: makeInbox({ prefix: PREFIX, id: sender.id, phase: "deleted" }),
        }));
        const ctx = {
          fake, rec, wire, sender,
          row: (o = {}) => fake.addAuditRow({
            ts: new Date(rec.created_at + 500).toISOString(), to: "target-1", to_alias: null, claimed_from: sender.id,
            verified_sender_sid: sender.id, verified_sender_epoch: sender.epoch, verified_sender_generation: sender.generation,
            spoof_suspected: false, payload_sha256: rec.payload_sha256, delivery_result: "success", ...o,
          }),
        };
        const rows = seed(ctx);
        const tr = make();
        assert.equal(recordOnDisk(sb, "rec-1").state, "uncertain");
        const r = await tr.send({ target: "target-1", text: "recover me", request_id: "rec-1" });
        assert.equal(r.ok, true, JSON.stringify(r));
        assert.equal(r.deduplicated, true);
        assert.equal(r.state, expect.state);
        if (expect.recovery) assert.equal(r.recovery, expect.recovery);
        else assert.ok(["not_found", "ambiguous", "unverified"].includes(r.recovery), `recovery ${r.recovery}`);
        if (expect.recovery === "audit_verified_match") assert.equal(r.inject_id, rows[0].inject_id);
        assert.equal(fake.injectArrivals.length, 0, "recovery never re-POSTs the inject");
        const probe = fake.requests.find((q) => q.path === "/api/injects" && q.query.to === "target-1");
        assert.ok(probe, "audit probe issued");
        assert.deepEqual(probe.query, {
          to: "target-1", from: sender.id, since: new Date(rec.created_at - 2000).toISOString(),
          until: new Date(rec.created_at + 12000).toISOString(), limit: "200",
        });
        if (expect.recovery !== "audit_unavailable") assert.equal((await tr.health()).store.recovery, "done");
        if (expect.state === "accepted") {
          const rc = await tr.receipt({ inject_id: r.inject_id });
          assert.equal(rc.ok, true, "recovered inject_id is answerable");
        }
      });
    }
  });

  test("TV02 SIGKILL on inject arrival → restart STORE_LOCKED; disk holds reserved + exact payload/sender binding; zero processed inject", async (t) => {
    const { sb, fake, config } = await setup(t);
    let host;
    fake.hooks.beforeInject = async () => { await host.crash(); return "hang"; };
    host = startChildHost("transport-send", {
      config: { teleptyUrl: fake.origin, token: fake.token, targets: ["target-1"], inboxPrefix: PREFIX, stateDir: sb.stateDir },
      storeOptions: sb.seam(), send: { target: "target-1", text: "crash me", request_id: "k-1" },
    }, { name: "transport-crash-before-inject" });
    t.after(() => host.stop());
    await host.waitExit(15000);
    assert.equal(host.child.signalCode, "SIGKILL", host.readLog());
    throwsCode(() => createTeleptyTransport(config(), sb.seam()), StoreError, "STORE_LOCKED");
    const arrival = fake.injectArrivals[0];
    const reg = fake.registrations[0];
    const inbox = fake.sessions.get(reg.session_id);
    const rec = recordOnDisk(sb, "k-1");
    assert.equal(rec.state, "reserved");
    assert.equal(rec.payload_sha256, sha256(arrival.body.prompt), "hash of the exact wire prompt sent");
    assert.equal(rec.reply_to, reg.session_id);
    assert.equal(rec.sender_inbox_id, reg.session_id);
    assert.equal(rec.sender_inbox_epoch, inbox.epoch);
    assert.equal(rec.sender_inbox_generation, inbox.generation);
    assert.equal(arrival.sessionToken, inbox.bearer);
    assert.equal(fake.injects.length, 0);
  });

  test("TV03 SIGKILL after the daemon accepted → STORE_LOCKED; lock-free copy recovers accepted from the audit, zero re-send", async (t) => {
    const { sb, fake, config, make } = await setup(t);
    let host;
    fake.hooks.afterInject = async () => { await host.crash(); return "hang"; };
    host = startChildHost("transport-send", {
      config: { teleptyUrl: fake.origin, token: fake.token, targets: ["target-1"], inboxPrefix: PREFIX, stateDir: sb.stateDir },
      storeOptions: sb.seam(), send: { target: "target-1", text: "crash later", request_id: "k-2" },
    }, { name: "transport-crash-after-inject" });
    t.after(() => host.stop());
    await host.waitExit(15000);
    assert.equal(host.child.signalCode, "SIGKILL", host.readLog());
    fake.hooks.afterInject = undefined;
    throwsCode(() => createTeleptyTransport(config(), sb.seam()), StoreError, "STORE_LOCKED");
    assert.equal(recordOnDisk(sb, "k-2").state, "reserved");
    assert.equal(fake.injects.length, 1);
    const copy = path.join(sb.home, ".local", "state", "telesession-repaired");
    fs.mkdirSync(copy, { mode: 0o700 });
    fs.copyFileSync(statePath(sb), path.join(copy, "state.json"));
    fs.chmodSync(path.join(copy, "state.json"), 0o600);
    const tr = make({ dir: copy });
    const r = await tr.send({ target: "target-1", text: "crash later", request_id: "k-2" });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.state, "accepted");
    assert.equal(r.recovery, "audit_verified_match");
    assert.equal(r.inject_id, fake.injects[0].inject_id);
    assert.equal(fake.injectArrivals.length, 1, "never re-sent");
    const h = await tr.health();
    assert.ok(h.store.orphans.includes(fake.registrations[0].session_id), "ready inbox without credential → rotated, old id orphaned");
  });

  test("TV07/TV04 stored reply survives graceful restart: trusted from replies/, answered, receipt answers, bound inject_id never reused", async (t) => {
    const { sb, fake, make } = await setup(t);
    const a = make();
    const { r: s1 } = await sendCaptured(fake, a, { target: "target-1", text: "q1", request_id: "q1" });
    const { r: s2 } = await sendCaptured(fake, a, { target: "target-1", text: "q2", request_id: "q2" });
    const inbox = s1.reply_to;
    const text1 = replyText(s1.nonce, "first");
    const out = fake.replyFrom("target-1", inbox, text1);
    assert.equal(out.status, 200);
    await waitMail(fake, (m) => m.inject_id === out.body.inject_id && m.state === "delivered", "reply stored (200)");
    assert.equal((await a.close()).outcome, "deleted");
    const b = make();
    const r1 = await trustedReply(b, s1.nonce);
    assert.equal(r1.reply, "trusted");
    assert.equal(r1.text, text1);
    assert.equal(r1.inject_id, out.body.inject_id);
    assert.equal(recordOnDisk(sb, "q1").state, "answered", "answered committed before text returned");
    assert.equal((await b.receipt({ inject_id: s1.inject_id })).ok, true, "pre-restart inject_id answerable");
    assert.equal((await b.close()).outcome, "deleted");
    const c = make();
    await recoverVia(c);
    const text2 = replyText(s2.nonce, "replayed binding");
    fake.addAuditRow({
      inject_id: out.body.inject_id, to: inbox, claimed_from: "target-1", verified_sender_sid: "target-1",
      verified_sender_epoch: fake.sessions.get("target-1").epoch, verified_sender_generation: fake.sessions.get("target-1").generation,
      payload_sha256: sha256(text2),
    }, { observe: false });
    fake.deliverRaw(inbox, text2);
    await waitMail(fake, (m) => m.text === text2 && m.state !== "pending", "replayed delivery settled");
    const r2 = await c.readReply({ nonce: s2.nonce, wait_ms: 6000 });
    assert.equal(r2.ok, true);
    assert.equal(r2.reply, "not_observed");
    assert.ok((r2.quarantined.duplicate || 0) >= 1, JSON.stringify(r2));
  });

  test("TV16 quotas: 1024 retained records → STORE_FULL zero inject; 64 reply files → receiver 503 then dead-letter", async (t) => {
    const { sb, fake, make } = await setup(t, { fake: { retryDelaysMs: [50, 100] } });
    const sender = { id: newInboxId(PREFIX), epoch: "e-1", generation: 1 };
    const recs = [];
    for (let i = 0; i < 1024; i++) recs.push(makeRequest({ request_id: `old-${i}`, sender, state: "accepted", created_at: Date.now() - 20 * 60 * 1000, inject_id: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`, target_epoch: "x" }));
    writeStateDir(sb.stateDir, makeState({ origin: fake.origin, prefix: PREFIX, requests: recs, inbox: makeInbox({ prefix: PREFIX, id: sender.id, phase: "deleted" }) }));
    const a = make();
    const full = await a.send({ target: "target-1", text: "one more", request_id: "new-1" });
    assert.equal(full.ok, false);
    assert.equal(full.error.code, "STORE_FULL");
    assert.equal(fake.injectArrivals.length, 0);
    await a.close();

    const dir2 = path.join(sb.home, ".local", "state", "telesession-replies");
    const pre = openStore({ dir: dir2, origin: fake.origin, inboxPrefix: PREFIX, persistCredential: false, newInboxId: () => newInboxId(PREFIX) }, sb.seam());
    for (let i = 0; i < 64; i++) {
      const nonce = hex(16);
      const text = replyText(nonce, `filler ${i}`);
      assert.deepEqual(pre.putReply({ nonce, sha256: sha256(text), text, received_at: new Date().toISOString() }), { ok: true });
    }
    pre.close();
    const b = make({ dir: dir2 });
    const { r: s } = await sendCaptured(fake, b, { target: "target-1", text: "ask", request_id: "ask-1" });
    assert.equal(s.ok, true, JSON.stringify(s));
    const out = fake.replyFrom("target-1", s.reply_to, replyText(s.nonce));
    const item = await waitMail(fake, (m) => m.inject_id === out.body.inject_id && m.state === "dead_letter", "dead-letter after 3 refusals");
    assert.deepEqual(item.statuses, [503, 503, 503]);
    const rr = await b.readReply({ nonce: s.nonce, wait_ms: 0 });
    assert.equal(rr.reply, "not_observed");
  });

  test("TV10b target deleted+recreated (new epoch) → reply quarantined epoch_mismatch; never re-sent to the new instance", async (t) => {
    const { fake, make } = await setup(t);
    const a = make();
    const { r: s } = await sendCaptured(fake, a, { target: "target-1", text: "old instance", request_id: "e-1" });
    assert.equal(s.target_epoch_known, true);
    fake.recreateTarget("target-1");
    fake.replyFrom("target-1", s.reply_to, replyText(s.nonce, "from new instance"));
    const r = await a.readReply({ nonce: s.nonce, wait_ms: 6000 });
    assert.equal(r.reply, "not_observed");
    assert.ok((r.quarantined.epoch_mismatch || 0) >= 1, JSON.stringify(r));
    assert.equal(fake.injectsTo("target-1").length, 1);
  });

  test("TV10 daemon restart (target kept): inbox_absent gap, create_only same id, new bearer only, surviving retry still trusted", async (t) => {
    const { sb, fake, make } = await setup(t, { fake: { retryDelaysMs: [500, 1500] } });
    const a = make();
    const { r: s1 } = await sendCaptured(fake, a, { target: "target-1", text: "before restart", request_id: "g-1" });
    const inbox = s1.reply_to;
    const oldBearer = fake.sessions.get(inbox).bearer;
    let failOnce = true;
    fake.hooks.beforeDelivery = (item) => (item.session_id === inbox && failOnce ? ((failOnce = false), "fail") : undefined);
    const out = fake.replyFrom("target-1", inbox, replyText(s1.nonce, "survivor"));
    fake.restartDaemon();
    const reqMark = fake.requests.length;
    const s2 = await a.send({ target: "target-1", text: "after restart", request_id: "g-2" });
    assert.equal(s2.ok, true, JSON.stringify(s2));
    assert.equal(s2.reply_to, inbox, "same inbox id re-created");
    const reg = fake.registrations[fake.registrations.length - 1];
    assert.equal(reg.session_id, inbox);
    assert.equal(reg.create_only, true);
    const newBearer = fake.sessions.get(inbox).bearer;
    assert.notEqual(newBearer, oldBearer);
    assert.ok(fake.requests.slice(reqMark).every((q) => q.sessionToken !== oldBearer), "stale bearer never used");
    assert.equal(fake.injectArrivals[fake.injectArrivals.length - 1].sessionToken, newBearer);
    await waitMail(fake, (m) => m.inject_id === out.body.inject_id && m.state === "delivered", "surviving retry delivered");
    const r = await trustedReply(a, s1.nonce);
    assert.equal(r.reply, "trusted");
    const gaps = diskState(sb).inbox.gaps;
    assert.ok(gaps.some((g) => g.cause === "inbox_absent"), JSON.stringify(gaps));
    const view = await a.send({ target: "target-1", text: "before restart", request_id: "g-1" });
    assert.equal(view.route_interrupted, true);
    assert.equal(view.reply_loss_possible, true);
  });

  test("TV05 lost register response → INBOX_REGISTRATION_UNKNOWN, no retry/DELETE; restart rotates, old session untouched", async (t) => {
    const { fake, make } = await setup(t);
    fake.hooks.onRegister = () => "reset";
    const a = make();
    const r = await a.send({ target: "target-1", text: "x", request_id: "u-1" });
    assert.equal(r.ok, false);
    assert.equal(r.error.code, "INBOX_REGISTRATION_UNKNOWN");
    const again = await a.send({ target: "target-1", text: "y", request_id: "u-2" });
    assert.equal(again.ok, false);
    assert.equal(fake.registrations.length, 1, "no in-process retry");
    assert.equal(fake.injectArrivals.length, 0);
    const oldId = fake.registrations[0].session_id;
    const oldSession = { ...fake.sessions.get(oldId) };
    assert.equal((await a.close()).outcome, "registration_unknown");
    fake.hooks.onRegister = undefined;
    const b = make();
    const h0 = await b.health();
    assert.equal(h0.store.recovery, "pending", "health() is read-only: it never starts recovery");
    assert.equal(fake.registrations.length, 1, "health() registers nothing");
    await recoverVia(b);
    const h = await b.health();
    assert.ok(h.store.orphans.includes(oldId), JSON.stringify(h.store));
    const s = await b.send({ target: "target-1", text: "z", request_id: "u-3" });
    assert.equal(s.ok, true, JSON.stringify(s));
    assert.notEqual(s.reply_to, oldId);
    assert.deepEqual(fake.deletes, [], "no DELETE of an id never proven ours");
    assert.deepEqual({ ...fake.sessions.get(oldId) }, oldSession);
  });

  test("TV06b retained inbox without persisted credential → rotate, orphan, no DELETE; pending nonce reply_route lost", async (t) => {
    const { sb, fake, make } = await setup(t);
    const a = make();
    const { r: s } = await sendCaptured(fake, a, { target: "target-1", text: "pending", request_id: "p-1" });
    fake.hooks.onDelete = () => ({ status: 500, body: { code: "INTERNAL" } });
    const c = await a.close();
    assert.equal(c.outcome, "retained");
    fake.hooks.onDelete = undefined;
    const deletes = fake.deletes.length;
    const b = make();
    await recoverVia(b);
    const h = await b.health();
    assert.ok(h.store.orphans.includes(s.reply_to), JSON.stringify(h.store));
    assert.equal(fake.deletes.length, deletes, "no DELETE attempted without a credential");
    assert.ok(diskState(sb).inbox.orphans.some((o) => o.id === s.reply_to && o.cause === "credential_absent"));
    const r = await b.readReply({ nonce: s.nonce, wait_ms: 0 });
    assert.equal(r.reply, "not_observed");
    assert.equal(r.reply_route, "lost");
    assert.equal(r.reply_loss_possible, true);
  });

  test("TV06/TV06c persisted credential: reply while receiver down → retries → dead-letter; reattach (owned DELETE→create_only) shows loss lower bound; later reply trusted", { skip: POSIX ? false : "credential persistence is POSIX-only" }, async (t) => {
    const { sb, fake, make } = await setup(t, { persist: true, fake: { retryDelaysMs: [50, 100] } });
    const a = make();
    const { r: s } = await sendCaptured(fake, a, { target: "target-1", text: "long job", request_id: "l-1" });
    const inbox = s.reply_to;
    fake.hooks.onDelete = () => ({ status: 500, body: { code: "INTERNAL" } });
    assert.equal((await a.close()).outcome, "retained");
    fake.hooks.onDelete = undefined;
    assert.equal(fs.statSync(path.join(sb.stateDir, "credential.json")).mode & 0o777, 0o600);
    const lost = fake.replyFrom("target-1", inbox, replyText(s.nonce, "while down"));
    assert.equal(lost.status, 200, "F3d: 200 + audit success although the receiver is down");
    const dead = await waitMail(fake, (m) => m.inject_id === lost.body.inject_id && m.state === "dead_letter", "dead-letter");
    assert.equal(dead.attempts, 3);
    const b = make();
    await recoverVia(b);
    const h = await b.health();
    assert.ok(h.store.gaps >= 1);
    const del = fake.deletes[fake.deletes.length - 1];
    assert.equal(del.id, inbox);
    assert.equal(del.owned, "true");
    const reg = fake.registrations[fake.registrations.length - 1];
    assert.equal(reg.session_id, inbox, "same id re-created after owned DELETE");
    const r = await b.readReply({ nonce: s.nonce, wait_ms: 0 });
    assert.equal(r.reply, "not_observed");
    assert.equal(r.reply_loss_possible, true);
    assert.ok(r.unreceived_audit_rows >= 1, JSON.stringify(r));
    const text2 = replyText(s.nonce, "after reattach");
    fake.replyFrom("target-1", inbox, text2);
    const ok = await trustedReply(b, s.nonce);
    assert.equal(ok.reply, "trusted");
    assert.equal(ok.text, text2);
    assert.equal(ok.text.includes("while down"), false, "nothing fabricated, no replay");
  });

  test("TV06c absent inbox: reply → 404 with NO audit row; after re-create unreceived_audit_rows is 0 although a reply was lost", async (t) => {
    const { fake, make } = await setup(t);
    const a = make();
    const { r: s } = await sendCaptured(fake, a, { target: "target-1", text: "q", request_id: "z-1" });
    fake.restartDaemon();
    const rows = fake.audit.length;
    const lost = fake.replyFrom("target-1", s.reply_to, replyText(s.nonce, "into the void"));
    assert.equal(lost.status, 404);
    assert.equal(fake.audit.length, rows, "F3a: no audit row");
    assert.equal((await a.send({ target: "target-1", text: "next", request_id: "z-2" })).ok, true);
    const r = await a.readReply({ nonce: s.nonce, wait_ms: 0 });
    assert.equal(r.reply, "not_observed");
    assert.equal(r.reply_loss_possible, true);
    assert.equal(r.unreceived_audit_rows, 0, "0 is a lower bound, not proof of no loss");
  });

  test("TV19 reattach DELETE 403 → rotate, orphan owned_delete_forbidden, no further mutation of that id", { skip: POSIX ? false : "credential persistence is POSIX-only" }, async (t) => {
    const { sb, fake, make } = await setup(t, { persist: true });
    const a = make();
    const { r: s } = await sendCaptured(fake, a, { target: "target-1", text: "x", request_id: "f-1" });
    fake.hooks.onDelete = () => ({ status: 500, body: {} });
    assert.equal((await a.close()).outcome, "retained");
    fake.hooks.onDelete = undefined;
    fake.sessions.get(s.reply_to).bearer = `replaced-${hex(8)}`;   // the persisted bearer no longer owns it
    const mark = fake.requests.length;
    const b = make();
    await recoverVia(b);
    const h = await b.health();
    assert.ok(h.store.orphans.includes(s.reply_to));
    assert.ok(diskState(sb).inbox.orphans.some((o) => o.id === s.reply_to && o.cause === "owned_delete_forbidden"));
    const touching = fake.requests.slice(mark).filter((q) => q.method !== "GET" && (q.path.includes(encodeURIComponent(s.reply_to)) || q.body?.session_id === s.reply_to));
    assert.equal(touching.length, 1, "exactly the one refused DELETE");
    assert.equal(touching[0].method, "DELETE");
  });

  test("TV18 graceful close → phase deleted + credential cleared; restart create_only same id without DELETE; register body exact", { skip: POSIX ? false : "credential persistence is POSIX-only" }, async (t) => {
    const { sb, fake, make } = await setup(t, { persist: true });
    const a = make();
    const { r: s } = await sendCaptured(fake, a, { target: "target-1", text: "x", request_id: "t-1" });
    assert.equal((await a.close()).outcome, "deleted");
    assert.equal(diskState(sb).inbox.phase, "deleted");
    assert.equal(fs.existsSync(path.join(sb.stateDir, "credential.json")), false);
    const deletes = fake.deletes.length;
    const b = make();
    assert.equal((await b.send({ target: "target-1", text: "y", request_id: "t-2" })).reply_to, s.reply_to);
    assert.equal(fake.deletes.length, deletes);
    for (const reg of fake.registrations) {
      assert.deepEqual(Object.keys(reg.body).sort(), ["command", "create_only", "delivery_endpoint", "delivery_type", "session_id"]);
      assert.equal(reg.body.delivery_type, "aterm");
      assert.equal(reg.body.command, "telesession-inbox");
      assert.equal(reg.body.create_only, true);
    }
  });

  test("TV11 lock replaced under a live transport → sends STORE_LOCK_LOST, receiver 503, close() no DELETE, lock untouched", async (t) => {
    const { sb, fake, make } = await setup(t, { fake: { retryDelaysMs: [50, 100] } });
    const a = make();
    const { r: s } = await sendCaptured(fake, a, { target: "target-1", text: "x", request_id: "lk-1" });
    const foreign = foreignLock();
    writeLockFile(sb.stateDir, foreign);
    const n = fake.injectArrivals.length;
    const r = await a.send({ target: "target-1", text: "y", request_id: "lk-2" });
    assert.equal(r.ok, false);
    assert.equal(r.error.code, "STORE_LOCK_LOST");
    assert.equal(fake.injectArrivals.length, n);
    const out = fake.replyFrom("target-1", s.reply_to, replyText(s.nonce));
    const item = await waitMail(fake, (m) => m.inject_id === out.body.inject_id && m.state !== "pending", "delivery settled");
    assert.equal(item.statuses[0], 503);
    assert.equal((await a.health()).store.state, "lock_lost");
    const deletes = fake.deletes.length;
    const c = await a.close();
    assert.equal(c.outcome, "retained");
    assert.equal(c.code, "STORE_LOCK_LOST");
    assert.equal(fake.deletes.length, deletes);
    assert.equal(fs.readFileSync(path.join(sb.stateDir, "lock"), "utf8"), foreign);
  });

  test("TV13 ENOSPC on putReply → receiver 503 (nothing claimed); daemon retry after space frees → trusted", async (t) => {
    const { sb, fake, make } = await setup(t, { fake: { retryDelaysMs: [100, 200] } });
    const ff = createFaultFs();
    const a = make({ storeOptions: { fs: ff.fs } });
    const { r: s } = await sendCaptured(fake, a, { target: "target-1", text: "x", request_id: "sp-1" });
    const repliesDir = path.join(sb.stateDir, "replies");
    const rule = ff.fail({ op: ["writeSync", "writeFileSync"], errno: "ENOSPC", when: (ctx) => ctx.paths.some((p) => path.dirname(p) === repliesDir || (path.dirname(p) === sb.stateDir && /\.tmp$/.test(p))) });
    const out = fake.replyFrom("target-1", s.reply_to, replyText(s.nonce, "eventually"));
    const item = await waitMail(fake, (m) => m.inject_id === out.body.inject_id && m.state === "delivered", "delivered on retry");
    assert.equal(rule.hits, 1);
    assert.deepEqual(item.statuses.slice(0, 2), [503, 200]);
    const r = await trustedReply(a, s.nonce);
    assert.equal(r.reply, "trusted");
  });

  test("TV17 secrets: token, bearers, receiver secret path and state dir never in results, state.json or stderr; credential.json only when persisted", async (t) => {
    for (const persist of POSIX ? [false, true] : [false]) {
      await t.test(`persist=${persist}`, async (st) => {
        const { sb, fake, make, results } = await setup(st, { persist });
        const a = make();
        const { r: s } = await sendCaptured(fake, a, { target: "target-1", text: "secret-free?", request_id: "s-1" });
        fake.replyFrom("target-1", s.reply_to, replyText(s.nonce));
        await trustedReply(a, s.nonce);
        await a.health();
        await a.listAllowedTargets();
        await a.receipt({ inject_id: s.inject_id });
        await a.close();
        const secrets = [fake.token, sb.stateDir, sb.root, ...[...fake.sessions.values()].map((x) => x.bearer)];
        for (const reg of fake.registrations) secrets.push(new URL(reg.body.delivery_endpoint).pathname);
        const blob = JSON.stringify(results);
        for (const secret of secrets) assert.ok(!blob.includes(secret), "result leaks a secret");
        const stateText = fs.readFileSync(statePath(sb), "utf8");
        for (const secret of [fake.token, ...secrets.slice(3)]) assert.ok(!stateText.includes(secret), "state.json leaks a secret");
        assert.ok(!stateText.includes("secret-free?"), "prompt text not persisted");
        const credFile = path.join(sb.stateDir, "credential.json");
        if (!persist) assert.equal(fs.existsSync(credFile), false);
      });
    }
  });

  test("TV22 memory-only regression: stateDir unset → no store fs calls, durability memory_only, MVP fields intact", async (t) => {
    const { sb, fake, make } = await setup(t);
    const ff = createFaultFs();
    const a = make({ cfg: { stateDir: null }, storeOptions: { fs: ff.fs } });
    const { r: s } = await sendCaptured(fake, a, { target: "target-1", text: "mem", request_id: "m-1" });
    assert.equal(s.ok, true, JSON.stringify(s));
    assert.equal(s.durability, "memory_only");
    assert.equal(s.accepted, true);
    assert.equal(s.reply, "not_observed");
    assert.equal((await a.health()).store.mode, "memory");
    fake.replyFrom("target-1", s.reply_to, replyText(s.nonce));
    assert.equal((await trustedReply(a, s.nonce)).reply, "trusted");
    assert.equal((await a.close()).outcome, "deleted");
    assert.deepEqual(ff.calls, []);
    assert.equal(fs.existsSync(sb.stateDir), false);
  });

  test("TV15 expiry: past expires_at → expired + NONCE_EXPIRED; past retain_until → record and reply file purged, id reusable", async (t) => {
    const { sb, fake, make } = await setup(t);
    const sender = { id: newInboxId(PREFIX), epoch: "e-1", generation: 1 };
    const expired = makeRequest({ request_id: "x-1", sender, state: "accepted", created_at: Date.now() - 20 * 60 * 1000, inject_id: "00000000-0000-4000-8000-000000000001", target_epoch: "te" });
    const purgedNonce = hex(16);
    const text = replyText(purgedNonce, "old");
    const purged = makeRequest({ request_id: "x-2", sender, state: "answered", nonce: purgedNonce,
      created_at: Date.now() - 25 * 60 * 60 * 1000, inject_id: "00000000-0000-4000-8000-000000000002", target_epoch: "te",
      reply: { candidates: [], trusted: { sha256: sha256(text), inject_id: "00000000-0000-4000-8000-000000000003",
        verified_sender: { sid: "target-1", generation: 1 }, received_at: new Date(Date.now() - 25 * 60 * 60 * 1000 + 60_000).toISOString() } } });
    writeStateDir(sb.stateDir, makeState({ origin: fake.origin, prefix: PREFIX, requests: [expired, purged], inbox: makeInbox({ prefix: PREFIX, id: sender.id, phase: "deleted" }) }));
    const pre = openStore({ dir: sb.stateDir, origin: fake.origin, inboxPrefix: PREFIX, persistCredential: false, newInboxId: () => sender.id }, sb.seam());
    assert.deepEqual(pre.putReply({ nonce: purged.nonce, sha256: sha256(text), text, received_at: new Date().toISOString() }), { ok: true });
    pre.close();
    const a = make();
    assert.equal(recordOnDisk(sb, "x-1").state, "expired");
    assert.equal(recordOnDisk(sb, "x-2"), undefined);
    assert.deepEqual(fs.readdirSync(path.join(sb.stateDir, "replies")), []);
    const r = await a.readReply({ nonce: expired.nonce, wait_ms: 0 });
    assert.equal(r.ok, false);
    assert.equal(r.error.code, "NONCE_EXPIRED");
    const reuse = await a.send({ target: "target-1", text: "fresh", request_id: "x-2" });
    assert.equal(reuse.ok, true, JSON.stringify(reuse));
    assert.equal(reuse.deduplicated, false);
    assert.equal(fake.injectArrivals.length, 1);
  });
});
