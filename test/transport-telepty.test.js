// telesession telepty transport — called directly (no MCP). Two fixture kinds:
//  • a recording stub of the documented telepty HTTP surface, for HTTP-client and receiver limits;
//  • a REAL telepty daemon spawned from source (hermetic HOME/token/ephemeral port), for routing,
//    credential, audit binding and the daemon's real mailbox DeliveryEngine.

import { describe, test, before, after, mock } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";
import { normalizeConfig, createTeleptyTransport, REQUIRED_CAPABILITIES } from "../src/index.js";
import {
  HAS_TELEPTY, PACKAGE_DIR, TELEPTY_DIR, delay, freshToken, listSessionIds, nonceFromPrompt, registerAterm, runNode,
  startAtermEndpoint, startStubDaemon, startTeleptyDaemon, waitFor,
} from "./helpers.js";

const sha256 = (s) => createHash("sha256").update(s).digest("hex");
const hex32 = () => randomBytes(16).toString("hex");

function transportFor(origin, token, targets = ["target-1"], inboxPrefix = "tst") {
  return createTeleptyTransport(normalizeConfig({ teleptyUrl: origin, token, targets, inboxPrefix }));
}

// Raw request (lets a test set Host / Origin / chunking, which fetch forbids).
function rawRequest(url, { method = "POST", headers = {}, body, chunks } = {}) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const req = http.request({ host: u.hostname, port: u.port, path: u.pathname + u.search, method, headers, agent: false }, (res) => {
      res.resume();
      res.on("end", () => resolve({ status: res.statusCode }));
      res.on("error", () => resolve({ status: res.statusCode }));
    });
    req.setTimeout(8000, () => req.destroy(new Error("client timeout")));
    req.on("error", (err) => resolve({ status: null, error: err.code || err.message }));
    if (chunks) { for (const c of chunks) req.write(c); req.end(); } else req.end(body);
  });
}

function postJson(url, obj, extraHeaders = {}) {
  const body = JSON.stringify(obj);
  const u = new URL(url);
  return rawRequest(url, { headers: { host: u.host, "content-type": "application/json", "content-length": Buffer.byteLength(body), ...extraHeaders }, body });
}

function assertNoCompletionClaim(record) {
  assert.equal(record.completion_fact, null);
  const s = JSON.stringify(record);
  assert.ok(!/"(completed|complete|done|task_complete)"\s*:/i.test(s), `no completion field in ${s}`);
}

// ── Stub-daemon boundaries ──

describe("HTTP client and receiver limits (recording stub daemon)", () => {
  test("argument/allowlist validation happens before any request", async (t) => {
    const stub = await startStubDaemon();
    const tr = transportFor(stub.origin, freshToken(), ["target-1"]);
    t.after(async () => { await tr.close(); await stub.close(); });
    const bad = [
      [tr.send, { target: "target-1", text: "" }, "INVALID_ARGUMENT"],
      [tr.send, { target: "target-1", text: "x".repeat(8001) }, "INVALID_ARGUMENT"],
      [tr.send, { target: "target-1", text: "a\u0000b" }, "INVALID_ARGUMENT"],
      [tr.send, { target: "target-1", text: 5 }, "INVALID_ARGUMENT"],
      [tr.send, { target: "target/1", text: "x" }, "INVALID_ARGUMENT"],
      [tr.send, { target: "other-session", text: "x" }, "TARGET_NOT_ALLOWED"],
      [tr.send, { target: "target", text: "x" }, "TARGET_NOT_ALLOWED"],          // prefix of an allowlisted id
      [tr.send, { target: "target-1-2", text: "x" }, "TARGET_NOT_ALLOWED"],      // extension of an allowlisted id
      [tr.send, { target: "TARGET-1", text: "x" }, "TARGET_NOT_ALLOWED"],
      [tr.send, { target: tr.inboxId, text: "x" }, "TARGET_NOT_ALLOWED"],
      [tr.receipt, { inject_id: "../x" }, "INVALID_ARGUMENT"],
      [tr.receipt, { inject_id: "00000000-0000-4000-8000-000000000001" }, "INJECT_NOT_ISSUED"],
      [tr.readReply, { nonce: "zz" }, "INVALID_ARGUMENT"],
      [tr.readReply, { nonce: hex32(), wait_ms: -1 }, "INVALID_ARGUMENT"],
      [tr.readReply, { nonce: hex32(), wait_ms: 60001 }, "INVALID_ARGUMENT"],
      [tr.readReply, { nonce: hex32(), wait_ms: 1.5 }, "INVALID_ARGUMENT"],
      [tr.readReply, { nonce: hex32() }, "NONCE_NOT_ISSUED"],
    ];
    for (const [fn, args, code] of bad) {
      const r = await fn(args);
      assert.equal(r.ok, false, JSON.stringify(args));
      assert.equal(r.error.code, code, JSON.stringify(args));
      assert.equal(r.completion_fact, null);
    }
    assert.equal(stub.requests.length, 0, "zero requests for refused arguments");
  });

  test("a daemon without the required capabilities is refused after one read, before any mutation", async (t) => {
    const stub = await startStubDaemon();
    stub.state.capabilities = ["sessions", "wrapped-sessions", "mailbox"];  // pre-#1215 daemon
    const tr = transportFor(stub.origin, freshToken());
    t.after(async () => { await stub.close(); });
    const r = await tr.send({ target: "target-1", text: "hello" });
    assert.equal(r.error.code, "DAEMON_LACKS_CAPABILITY");
    assert.deepEqual(r.error.missing, [...REQUIRED_CAPABILITIES]);
    const h = await tr.health();
    assert.equal(h.ok, true);
    assert.deepEqual(h.telepty.capabilities_missing, [...REQUIRED_CAPABILITIES]);
    assert.deepEqual(await tr.close(), { inbox_id: tr.inboxId, outcome: "not_created" });
    assert.deepEqual(stub.requests.map((q) => `${q.method} ${q.pathname}`), ["GET /api/meta", "GET /api/meta"]);
  });

  test("absent target, inbox collision, legacy re-register and lost registration never inject", async (t) => {
    const stub = await startStubDaemon();
    t.after(() => stub.close());
    const token = freshToken();

    stub.state.sessions = ["other-session"];
    let tr = transportFor(stub.origin, token);
    assert.equal((await tr.send({ target: "target-1", text: "x" })).error.code, "TARGET_NOT_PRESENT");
    assert.equal(stub.mutations().length, 0);
    await tr.close();
    stub.state.sessions = ["target-1"];

    const cases = [
      ["409", () => ({ status: 409, body: { success: false, code: "SESSION_EXISTS" } }), "INBOX_COLLISION", "collided"],
      ["200", (req, body) => ({ status: 200, body: { session_id: body.session_id, reregistered: true } }), "INBOX_COLLISION", "collided"],
      ["reset", (req) => { req.socket.destroy(); return undefined; }, "INBOX_REGISTRATION_UNKNOWN", "registration_unknown"],
    ];
    for (const [name, route, code, outcome] of cases) {
      const s = await startStubDaemon({ "POST /api/sessions/register": route });
      tr = transportFor(s.origin, token);
      const first = await tr.send({ target: "target-1", text: "x" });
      const second = await tr.send({ target: "target-1", text: "x" });
      const closed = await tr.close();
      await s.close();
      assert.equal(first.error.code, code, name);
      assert.equal(second.error.code, code, `${name}: fatal is sticky, no re-register`);
      assert.deepEqual(closed, { inbox_id: tr.inboxId, outcome }, name);
      assert.deepEqual(s.mutations().map((q) => `${q.method} ${q.pathname}`), ["POST /api/sessions/register"], `${name}: one register, no inject, no delete`);
      const reg = s.requests.find((q) => q.method === "POST").body;
      assert.equal(reg.create_only, true);
      assert.equal(reg.session_id, tr.inboxId);
      assert.equal(reg.delivery_type, "aterm");
    }
  });

  test("inject reply must echo exact routing; otherwise EXACT_ROUTING_UNCONFIRMED", async (t) => {
    for (const echo of [{ exact_target: undefined }, { session_id: "target-1-9" }, { exact_target: "true" }]) {
      const stub = await startStubDaemon({
        "POST /api/sessions/:id/inject": (req, body, id) => ({ body: { success: true, inject_id: "11111111-1111-4111-8111-111111111111", exact_target: true, session_id: id, ...echo } }),
      });
      const tr = transportFor(stub.origin, freshToken());
      const r = await tr.send({ target: "target-1", text: "x" });
      await tr.close();
      await stub.close();
      assert.equal(r.ok, false);
      assert.equal(r.error.code, "EXACT_ROUTING_UNCONFIRMED");
      assert.equal(r.error.accepted, "unknown");
      const inj = stub.requests.find((q) => q.pathname.endsWith("/inject"));
      assert.equal(inj.body.exact_target, true);
      assert.equal(inj.pathname, "/api/sessions/target-1/inject");
    }
  });

  test("redirects are refused and never followed", async (t) => {
    const elsewhere = await startStubDaemon();
    const stub = await startStubDaemon({ "GET /api/meta": () => ({ status: 302, headers: { location: `${elsewhere.origin}/api/meta` }, raw: "" }) });
    t.after(async () => { await stub.close(); await elsewhere.close(); });
    const tr = transportFor(stub.origin, freshToken());
    const r = await tr.health();
    assert.equal(r.error.code, "DAEMON_REDIRECT_REFUSED");
    assert.equal(elsewhere.requests.length, 0);
  });

  test("response body cap (256 KiB) by declared length and by streamed bytes", async (t) => {
    const big = Buffer.alloc(300 * 1024, 0x20);
    const declared = await startStubDaemon({
      "GET /api/meta": (req, body, id, res) => { res.writeHead(200, { "content-type": "application/json", "content-length": big.length }); res.end(big); },
    });
    const streamed = await startStubDaemon({
      "GET /api/meta": (req, body, id, res) => {
        res.writeHead(200, { "content-type": "application/json", "transfer-encoding": "chunked" });
        for (let i = 0; i < 6; i++) res.write(Buffer.alloc(50 * 1024, 0x20));
        res.end("{}");
      },
    });
    t.after(async () => { await declared.close(); await streamed.close(); });
    for (const s of [declared, streamed]) {
      const r = await transportFor(s.origin, freshToken()).health();
      assert.equal(r.error.code, "DAEMON_BODY_TOO_LARGE");
    }
  });

  test("one deadline covers headers AND body: a stalled body times out (GET 5 s)", async (t) => {
    const stub = await startStubDaemon({
      "GET /api/meta": (req, body, id, res) => { res.writeHead(200, { "content-type": "application/json" }); res.write('{"name":'); },
    });
    t.after(() => stub.close());
    const started = Date.now();
    const r = await transportFor(stub.origin, freshToken()).health();
    const elapsed = Date.now() - started;
    assert.equal(r.error.code, "DAEMON_TIMEOUT");
    assert.ok(elapsed >= 4500 && elapsed < 8000, `elapsed ${elapsed}ms`);
  });

  test("an inject with no response is reported accepted:'unknown' and never re-sent (10 s)", async (t) => {
    const stub = await startStubDaemon({ "POST /api/sessions/:id/inject": () => undefined });  // never answers
    t.after(() => stub.close());
    const tr = transportFor(stub.origin, freshToken());
    const started = Date.now();
    const r = await tr.send({ target: "target-1", text: "maybe delivered" });
    const elapsed = Date.now() - started;
    assert.equal(r.ok, true);
    assert.equal(r.accepted, "unknown");
    assert.equal(r.inject_id, null);
    assert.equal(r.delivery, "unknown");
    assert.equal(r.reason, "DAEMON_TIMEOUT");
    assert.match(r.nonce, /^[0-9a-f]{32}$/);
    assert.ok(elapsed >= 9500 && elapsed < 14000, `elapsed ${elapsed}ms`);
    await delay(500);
    assert.equal(stub.requests.filter((q) => q.pathname.endsWith("/inject")).length, 1, "exactly one inject, no retry");
    // The nonce stays live: a reply could still arrive.
    assert.equal((await tr.readReply({ nonce: r.nonce })).reply, "not_observed");
    await tr.close();
  });

  test("token, endpoint, bearer and daemon error text never appear in results or logs", async (t) => {
    const token = freshToken();
    const secretText = "SECRET-DAEMON-TEXT-" + freshToken();
    let bearer;
    const stub = await startStubDaemon({
      "POST /api/sessions/register": (req, body) => { bearer = "bearer-" + freshToken(); return { status: 201, body: { session_id: body.session_id, session_token: bearer, session_epoch: "e1" } }; },
      "POST /api/sessions/:id/inject": () => ({ status: 500, body: { error: `${secretText} ${token}`, code: "lowercase-not-a-code", detail: { url: "http://127.0.0.1" } } }),
      "GET /api/injects": () => ({ status: 502, body: { error: secretText, code: "UPSTREAM_SAYS" } }),
    });
    t.after(() => stub.close());
    const captured = [];
    const orig = { log: console.log, warn: console.warn, error: console.error, info: console.info, debug: console.debug, err: process.stderr.write };
    for (const k of ["log", "warn", "error", "info", "debug"]) console[k] = (...a) => captured.push(a.join(" "));
    process.stderr.write = (chunk, ...rest) => { captured.push(String(chunk)); return true; };
    const results = [];
    try {
      const tr = transportFor(stub.origin, token);
      results.push(await tr.health(), await tr.listAllowedTargets());
      results.push(await tr.send({ target: "target-1", text: "x" }));
      results.push(await tr.close());
    } finally {
      for (const k of ["log", "warn", "error", "info", "debug"]) console[k] = orig[k];
      process.stderr.write = orig.err;
    }
    const send = results[2];
    assert.equal(send.ok, true);
    assert.equal(send.reason, "DAEMON_HTTP_500");
    assert.equal(send.accepted, "unknown");
    const all = JSON.stringify(results) + captured.join("\n");
    for (const s of [token, bearer, secretText, stub.origin, `127.0.0.1:${stub.port}`, "x-telepty"]) {
      assert.ok(!all.includes(s), `leaked: ${s.slice(0, 24)}…`);
    }
    // Credentials go only where they belong.
    for (const q of stub.requests) assert.equal(q.headers["x-telepty-token"], token);
    for (const q of stub.requests) {
      const usesBearer = q.pathname.endsWith("/inject") || q.method === "DELETE";
      assert.equal(q.headers["x-telepty-session-token"], usesBearer ? bearer : undefined, `${q.method} ${q.pathname}`);
    }
    // The 500 leaves acceptance unknown: no resend; close() deletes only the owned inbox.
    assert.equal(results[3].outcome, "deleted");
    assert.ok(stub.requests.some((q) => q.method === "DELETE" && q.url === `/api/sessions/${encodeURIComponent(results[3].inbox_id)}?owned=true`));
  });

  test("receiver: secret path, method, type, Origin, Host, size order; 64-text quota → 503; dedupe; counts only", async (t) => {
    const stub = await startStubDaemon();
    const tr = transportFor(stub.origin, freshToken());
    t.after(async () => { await tr.close(); await stub.close(); });
    const s = await tr.send({ target: "target-1", text: "x" });
    assert.equal(s.accepted, true);
    const endpoint = stub.state.registerEndpoint;
    assert.match(endpoint, /^http:\/\/127\.0\.0\.1:\d+\/[A-Za-z0-9_-]{43}$/);
    const u = new URL(endpoint);
    const good = (text) => ({ text, session_id: tr.inboxId });
    const json = JSON.stringify(good(`REPLY ${s.nonce} probe`));
    const hdr = { host: u.host, "content-type": "application/json" };

    const cases = [
      ["wrong path", `${u.origin}/nope`, { headers: hdr, body: json }, 404],
      ["path prefix", `${u.origin}${u.pathname.slice(0, -1)}`, { headers: hdr, body: json }, 404],
      ["GET", endpoint, { method: "GET", headers: { host: u.host } }, 405],
      ["text/plain", endpoint, { headers: { ...hdr, "content-type": "text/plain" }, body: json }, 415],
      ["Origin", endpoint, { headers: { ...hdr, origin: "http://evil.example" }, body: json }, 403],
      ["Host localhost", endpoint, { headers: { ...hdr, host: `localhost:${u.port}` }, body: json }, 421],
      ["bad json", endpoint, { headers: hdr, body: "{" }, 400],
      ["wrong session", endpoint, { headers: hdr, body: JSON.stringify({ text: "REPLY x", session_id: "target-1" }) }, 400],
      ["text not string", endpoint, { headers: hdr, body: JSON.stringify({ text: 5, session_id: tr.inboxId }) }, 400],
    ];
    for (const [name, url, opts, status] of cases) {
      assert.equal((await rawRequest(url, opts)).status, status, name);
    }
    // Oversize: refused by declared length (headers only) and by streamed bytes. The receiver may
    // reset the socket right after its 413, so a reset after an unread 413 is accepted too.
    const declared = await rawRequest(endpoint, { headers: { ...hdr, "content-length": String(64 * 1024 + 1) } });
    assert.ok(declared.status === 413 || ["ECONNRESET", "EPIPE"].includes(declared.error), `declared oversize → ${JSON.stringify(declared)}`);
    const chunked = await rawRequest(endpoint, { headers: hdr, chunks: Array.from({ length: 5 }, () => Buffer.alloc(16 * 1024, 0x61)) });
    assert.ok(chunked.status === 413 || ["ECONNRESET", "EPIPE"].includes(chunked.error), `chunked oversize → ${JSON.stringify(chunked)}`);

    assert.equal((await postJson(endpoint, good("no nonce here"))).status, 200);
    assert.equal((await postJson(endpoint, good(`REPLY ${hex32()} unknown`))).status, 200);
    assert.equal((await postJson(endpoint, good("   "))).status, 200);
    for (let i = 0; i < 64; i++) assert.equal((await postJson(endpoint, good(`REPLY ${s.nonce} part ${i}`))).status, 200, `part ${i}`);
    assert.equal((await postJson(endpoint, good(`REPLY ${s.nonce} part 64`))).status, 503, "65th held text → 503");
    assert.equal((await postJson(endpoint, good(`REPLY ${s.nonce} part 3`))).status, 200, "identical bytes deduped");

    const r = await tr.readReply({ nonce: s.nonce, wait_ms: 0 });
    assert.equal(r.reply, "not_observed");
    assert.equal(r.pending_candidates, 64);
    assert.deepEqual(r.inbox, { inbox_rejected: 1, duplicate_delivery: 1, no_nonce: 1, unknown_nonce: 1, expired_nonce: 0, empty_dropped: 1 });
    assert.ok(!JSON.stringify(r).includes("part "), "held text is never returned untrusted");
    // Audit never matches (stub audit is empty) → after the bounded backoff every candidate is quarantined.
    const final = await tr.readReply({ nonce: s.nonce, wait_ms: 7000 });
    assert.equal(final.reply, "not_observed");
    assert.equal(final.pending_candidates, 0);
    assert.deepEqual(final.quarantined, { audit_unmatched: 64 });
  });

  test("bounded issued nonces (16), daemon restart observation, owned close and TRANSPORT_CLOSING", async (t) => {
    const stub = await startStubDaemon();
    t.after(() => stub.close());
    const tr = transportFor(stub.origin, freshToken());
    for (let i = 0; i < 16; i++) assert.equal((await tr.send({ target: "target-1", text: `n${i}` })).accepted, true);
    const before = stub.requests.length;
    assert.equal((await tr.send({ target: "target-1", text: "17th" })).error.code, "ISSUED_LIMIT");
    assert.equal(stub.requests.length, before, "ISSUED_LIMIT makes no request");
    assert.equal(stub.requests.filter((q) => q.pathname === "/api/sessions/register").length, 1, "one lazy inbox");

    assert.equal((await tr.health()).daemon_restart, "not_observed");
    stub.state.pid = 9999;
    assert.equal((await tr.health()).daemon_restart, "observed");
    stub.state.pid = 4242;
    assert.equal((await tr.health()).daemon_restart, "observed", "sticky");

    const closing = tr.close();
    assert.equal(tr.close(), closing, "same close promise");
    assert.deepEqual(await closing, { inbox_id: tr.inboxId, outcome: "deleted" });
    const n = stub.requests.length;
    assert.equal((await tr.send({ target: "target-1", text: "late" })).error.code, "TRANSPORT_CLOSING");
    assert.equal(stub.requests.length, n);
    assert.equal(stub.requests.filter((q) => q.method === "DELETE").length, 1);

    const refused = await startStubDaemon({ "DELETE /api/sessions/:id": () => ({ status: 403, body: { code: "OWNED_DELETE_FORBIDDEN" } }) });
    const tr2 = transportFor(refused.origin, freshToken());
    await tr2.send({ target: "target-1", text: "x" });
    assert.deepEqual(await tr2.close(), { inbox_id: tr2.inboxId, outcome: "retained", code: "OWNED_DELETE_FORBIDDEN" });
    await refused.close();
  });

  test("second client adapter: core API driven without MCP/zod and without telepty source", async (t) => {
    const stub = await startStubDaemon();
    t.after(() => stub.close());
    const script = `
      import { register } from "node:module";
      const hooks = "export async function resolve(s, c, n) { if (/^(zod|@modelcontextprotocol\\\\/sdk)(\\\\/|$)/.test(s)) throw new Error('FORBIDDEN_IMPORT ' + s); return n(s, c); }";
      register("data:text/javascript," + encodeURIComponent(hooks));
      const core = await import(process.env.CORE_URL);
      const tr = core.createTeleptyTransport(core.normalizeConfig({ teleptyUrl: process.env.STUB, token: process.env.TOK, targets: ["target-1"], inboxPrefix: "cli" }));
      const adapter = { health: tr.health, list: tr.listAllowedTargets, send: tr.send, read: tr.readReply };
      const out = {};
      out.health = await adapter.health();
      out.list = await adapter.list();
      out.send = await adapter.send({ target: "target-1", text: "from a non-MCP adapter" });
      out.read = await adapter.read({ nonce: out.send.nonce, wait_ms: 0 });
      out.close = await tr.close();
      let blocked = false;
      try { await import("zod"); } catch (e) { blocked = /FORBIDDEN_IMPORT/.test(e.message); }
      console.log("RESULT " + JSON.stringify({ out, blocked }));
    `;
    const res = await runNode(["--input-type=module", "-e", script], {
      name: "cli-adapter",
      env: { CORE_URL: pathToFileURL(path.join(PACKAGE_DIR, "src", "index.js")).href, STUB: stub.origin, TOK: freshToken() },
    });
    assert.equal(res.code, 0, res.log);
    const { out, blocked } = JSON.parse(/RESULT (.*)/.exec(res.log)[1]);
    assert.equal(blocked, true, "the import guard was active");
    assert.equal(out.health.ok, true);
    assert.deepEqual(out.list.targets, [{ id: "target-1", present: true }]);
    assert.equal(out.send.accepted, true);
    assert.equal(out.read.reply, "not_observed");
    assert.equal(out.close.outcome, "deleted");
  });

  test("naming: no Dot/profile-specific branch in package source", () => {
    const files = [];
    const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (p.endsWith(".js")) files.push(p); } };
    walk(path.join(PACKAGE_DIR, "src"));
    walk(path.join(PACKAGE_DIR, "bin"));
    for (const f of files) {
      const lines = fs.readFileSync(f, "utf8").split("\n");
      lines.forEach((line, i) => {
        assert.ok(!/telepty_dot|TELEPTY_MCP_PROFILE|DotConfig|dot-broker\.mjs['"]|profile\s*===?\s*["']dot/.test(line) || /^\s*(\*|\/\/)/.test(line), `${f}:${i + 1}`);
        if (/\bdot\b|chatgpt/i.test(line)) assert.match(line, /^\s*(\*|\/\/)/, `Dot/ChatGPT mention outside a comment: ${f}:${i + 1}`);
      });
    }
    assert.ok(files.length >= 5);
  });
});

// ── Real telepty fixture daemon ──

const ORCH = ["ts-orch", "ts-orch2", "ts-spoofer"];

describe("against a real telepty daemon (fixture)", { skip: HAS_TELEPTY ? false : `NOTRUN: telepty source not found at ${TELEPTY_DIR}` }, () => {
  let d;
  let target;      // ts-orch aterm endpoint
  let targetCred;

  before(async () => {
    d = await startTeleptyDaemon({ orchestratorSids: ORCH.join(" ") });
    target = await startAtermEndpoint();
    targetCred = await registerAterm(d, "ts-orch", target.endpoint);
  });
  after(async () => {
    if (target) await target.close();
    if (d) await d.stop();
  });

  const mk = (targets = ["ts-orch"]) => transportFor(d.origin, d.token, targets, "tsr");
  const reply = (inboxId, prompt, { bearer, from } = {}) => d.request(`/api/sessions/${encodeURIComponent(inboxId)}/inject`, {
    method: "POST", sessionToken: bearer, body: { prompt, ...(from ? { from } : {}) },
  });
  const auditRows = async (to) => (await d.request(`/api/injects?to=${encodeURIComponent(to)}&limit=1000`)).body.injects;
  const waitAudit = (to, text, n = 1) => waitFor(async () => (await auditRows(to)).filter((r) => r.payload_sha256 === sha256(text)).length >= n,
    { timeoutMs: 5000, description: `audit row for ${text.slice(0, 40)}` });
  const deliveredTo = (ep, nonce) => ep.received.find((m) => m.body && nonceFromPrompt(m.body.text)?.nonce === nonce);

  test("health/list are read-only and filtered to the allowlist", async () => {
    const tr = mk(["ts-orch", "ts-absent"]);
    const before = await listSessionIds(d);
    const h = await tr.health();
    assert.equal(h.ok, true);
    assert.deepEqual(h.telepty.capabilities_missing, []);
    assert.match(h.telepty.version, /^\d+\.\d+\.\d+/);
    assert.deepEqual(h.inbox, { id: tr.inboxId, state: "none" });
    const l = await tr.listAllowedTargets();
    assert.deepEqual(l.targets, [{ id: "ts-orch", present: true }, { id: "ts-absent", present: false }]);
    assert.deepEqual(await listSessionIds(d), before, "no session created by health/list");
    assert.equal((await tr.close()).outcome, "not_created");
  });

  test("send → real HTTP inject → target delivery → verified reply → readReply (nonce+epoch+hash)", async () => {
    const tr = mk();
    try {
      const text = "roundtrip prompt ✓";
      const s = await tr.send({ target: "ts-orch", text });
      assert.equal(s.ok, true, JSON.stringify(s));
      assert.equal(s.accepted, true);
      assert.match(s.inject_id, /^[0-9a-f-]{36}$/);
      assert.equal(s.target, "ts-orch");
      assert.equal(s.reply_to, tr.inboxId);
      assert.ok(["queued", "unknown"].includes(s.delivery));
      assert.equal(s.target_epoch_known, true);
      assert.equal(s.reply, "not_observed");
      assert.equal(s.durability, "memory_only");
      assert.equal(s.daemon_restart, "not_observed");
      assertNoCompletionClaim(s);

      await waitFor(() => deliveredTo(target, s.nonce), { description: "delivery to target endpoint" });
      const got = deliveredTo(target, s.nonce).body;
      assert.equal(got.session_id, "ts-orch");
      assert.equal(got.text, `[telesession nonce=${s.nonce} reply-to=${tr.inboxId}]\n${text}`);

      const obs = (await d.request(`/api/inject-observations/${s.inject_id}`)).body;
      assert.equal(obs.session_id, "ts-orch");
      assert.equal(obs.session_epoch, targetCred.epoch);
      assert.equal(obs.completion_fact, null);
      const row = (await waitFor(async () => (await auditRows("ts-orch")).find((r) => r.inject_id === s.inject_id))) ;
      assert.equal(row.verified_sender_sid, tr.inboxId, "the inject was sent with the inbox's own bearer");
      assert.equal(row.to_alias, null);

      const rc = await tr.receipt({ inject_id: s.inject_id });
      assert.equal(rc.ok, true);
      assert.ok(["consumption_observed", "queued", "refused", "unknown"].includes(rc.receipt));
      assertNoCompletionClaim(rc);

      const answer = `REPLY ${s.nonce} the answer`;
      const ri = await reply(tr.inboxId, answer, { bearer: targetCred.bearer, from: "ts-orch" });
      assert.equal(ri.status, 200, ri.text);
      const rr = await tr.readReply({ nonce: s.nonce, wait_ms: 8000 });
      assert.equal(rr.reply, "trusted", JSON.stringify(rr));
      assert.equal(rr.text, answer);
      assert.equal(rr.inject_id, ri.body.inject_id);
      assert.equal(rr.verified_sender.sid, "ts-orch");
      assertNoCompletionClaim(rr);
      assert.equal((await tr.readReply({ nonce: s.nonce })).text, answer, "stable on re-read");
    } finally {
      const c = await tr.close();
      assert.equal(c.outcome, "deleted");
    }
    assert.ok(!(await listSessionIds(d)).includes(tr.inboxId), "owned inbox removed");
    assert.ok((await listSessionIds(d)).includes("ts-orch"), "target untouched");
  });

  test("untrusted replies are quarantined as counts: missing/other credential, same-bytes ambiguity, spoof, unknown/no nonce", async () => {
    const tr = mk();
    const other = await startAtermEndpoint();
    try {
      const otherCred = await registerAterm(d, "ts-other-session", other.endpoint);
      const s = await tr.send({ target: "ts-orch", text: "quarantine me" });
      assert.equal(s.accepted, true);
      const texts = {
        none: `REPLY ${s.nonce} no credential`,
        other: `REPLY ${s.nonce} other credential`,
        same: `REPLY ${s.nonce} same bytes`,
        spoof: `REPLY ${s.nonce} spoofed from`,
      };
      assert.equal((await reply(tr.inboxId, texts.none)).status, 200);
      assert.equal((await reply(tr.inboxId, texts.other, { bearer: otherCred.bearer })).status, 200);
      assert.equal((await reply(tr.inboxId, texts.same, { bearer: targetCred.bearer, from: "ts-orch" })).status, 200);
      assert.equal((await reply(tr.inboxId, texts.same, { bearer: targetCred.bearer, from: "ts-orch" })).status, 200);
      assert.equal((await reply(tr.inboxId, texts.spoof, { bearer: targetCred.bearer, from: "ts-spoofer" })).status, 200);
      assert.equal((await reply(tr.inboxId, `REPLY ${hex32()} unknown nonce`, { bearer: targetCred.bearer, from: "ts-orch" })).status, 200);
      assert.equal((await reply(tr.inboxId, "no nonce at all", { bearer: targetCred.bearer, from: "ts-orch" })).status, 200);
      await waitAudit(tr.inboxId, texts.same, 2);
      for (const k of ["none", "other", "spoof"]) await waitAudit(tr.inboxId, texts[k]);

      const r = await waitFor(async () => {
        const x = await tr.readReply({ nonce: s.nonce, wait_ms: 0 });
        return Object.values(x.quarantined || {}).reduce((a, b) => a + b, 0) >= 4 && x.inbox.no_nonce >= 1 && x.inbox.unknown_nonce >= 1 ? x : null;
      }, { timeoutMs: 10000, intervalMs: 200, description: "all candidates classified" });
      assert.equal(r.reply, "not_observed");
      assert.deepEqual(r.quarantined, { claimed_only: 1, verified_other: 1, audit_ambiguous: 1, spoof_suspected: 1 });
      assert.equal(r.inbox.duplicate_delivery, 1, "second identical delivery deduped while unresolved");
      assert.equal(r.inbox.no_nonce, 1);
      assert.equal(r.inbox.unknown_nonce, 1);
      const js = JSON.stringify(r);
      for (const t of Object.values(texts)) assert.ok(!js.includes(t), "quarantined text never returned");

      // Quarantine does not poison the nonce: the genuine reply is still trusted.
      const good = `REPLY ${s.nonce} genuine`;
      await reply(tr.inboxId, good, { bearer: targetCred.bearer, from: "ts-orch" });
      const ok = await tr.readReply({ nonce: s.nonce, wait_ms: 8000 });
      assert.equal(ok.reply, "trusted");
      assert.equal(ok.text, good);
    } finally {
      await tr.close();
      await d.request("/api/sessions/ts-other-session", { method: "DELETE" });
      await other.close();
    }
  });

  test("stale and replaced target instances: revoked bearer → claimed_only, new epoch → epoch_mismatch", async () => {
    const ep = await startAtermEndpoint();
    const tr = mk(["ts-orch2"]);
    try {
      const cred1 = await registerAterm(d, "ts-orch2", ep.endpoint);
      const s = await tr.send({ target: "ts-orch2", text: "before restart of the target" });
      assert.equal(s.target_epoch_known, true);
      const del = await d.request("/api/sessions/ts-orch2?owned=true", { method: "DELETE", sessionToken: cred1.bearer });
      assert.equal(del.status, 200, del.text);
      const cred2 = await registerAterm(d, "ts-orch2", ep.endpoint);
      assert.notEqual(cred2.epoch, cred1.epoch);
      const t1 = `REPLY ${s.nonce} from the revoked instance`;
      const t2 = `REPLY ${s.nonce} from the new instance`;
      assert.equal((await reply(tr.inboxId, t1, { bearer: cred1.bearer })).status, 200);
      assert.equal((await reply(tr.inboxId, t2, { bearer: cred2.bearer, from: "ts-orch2" })).status, 200);
      await waitAudit(tr.inboxId, t1);
      await waitAudit(tr.inboxId, t2);
      const r = await waitFor(async () => {
        const x = await tr.readReply({ nonce: s.nonce, wait_ms: 0 });
        return Object.values(x.quarantined || {}).reduce((a, b) => a + b, 0) >= 2 ? x : null;
      }, { timeoutMs: 10000, intervalMs: 200, description: "stale replies classified" });
      assert.deepEqual(r.quarantined, { claimed_only: 1, epoch_mismatch: 1 });
      assert.equal(r.reply, "not_observed");
    } finally {
      await tr.close();
      await d.request("/api/sessions/ts-orch2", { method: "DELETE" });
      await ep.close();
    }
  });

  test("expired nonce: readReply → NONCE_EXPIRED and a late reply is only counted", async () => {
    const tr = mk();
    try {
      const s = await tr.send({ target: "ts-orch", text: "expire me" });
      const live = await tr.send({ target: "ts-orch", text: "stay live" });
      mock.timers.enable({ apis: ["Date"], now: Date.now() });
      try {
        mock.timers.tick(15 * 60 * 1000 + 1000);
        const live2 = await tr.send({ target: "ts-orch", text: "issued after the jump" });
        assert.equal((await tr.readReply({ nonce: s.nonce })).error.code, "NONCE_EXPIRED");
        assert.equal((await tr.readReply({ nonce: live.nonce })).error.code, "NONCE_EXPIRED");
        await reply(tr.inboxId, `REPLY ${s.nonce} too late`, { bearer: targetCred.bearer, from: "ts-orch" });
        const r = await waitFor(async () => {
          const x = await tr.readReply({ nonce: live2.nonce, wait_ms: 0 });
          return x.inbox && x.inbox.expired_nonce >= 1 ? x : null;
        }, { timeoutMs: 5000, description: "late reply counted" });
        assert.equal(r.reply, "not_observed");
        assert.ok(!JSON.stringify(r).includes("too late"));
      } finally {
        mock.timers.reset();
      }
    } finally {
      await tr.close();
    }
  });

  test("exact target only: an alias-shaped id is TARGET_NOT_PRESENT and nothing is created", async () => {
    const ep = await startAtermEndpoint();
    const tr = mk(["ts-alias"]);
    try {
      await registerAterm(d, "ts-alias-5", ep.endpoint);
      const r = await tr.send({ target: "ts-alias", text: "must not reach ts-alias-5" });
      assert.equal(r.error.code, "TARGET_NOT_PRESENT");
      assert.ok(!(await listSessionIds(d)).includes(tr.inboxId));
      await delay(300);
      assert.equal(ep.received.length, 0);
      assert.equal((await tr.close()).outcome, "not_created");
    } finally {
      await d.request("/api/sessions/ts-alias-5", { method: "DELETE" });
      await ep.close();
    }
  });

  test("create_only inbox collision leaves the squatting session unchanged and injects nothing", async () => {
    const tr = mk();
    const squat = await d.request("/api/sessions/register", {
      method: "POST", body: { session_id: tr.inboxId, delivery_type: "aterm", delivery_endpoint: "http://127.0.0.1:47991/squat", command: "squatter" },
    });
    assert.equal(squat.status, 201);
    const before = (await d.request(`/api/sessions/${tr.inboxId}`)).body;
    const deliveredBefore = target.received.length;
    const r = await tr.send({ target: "ts-orch", text: "should not be sent" });
    assert.equal(r.error.code, "INBOX_COLLISION");
    const afterRec = (await d.request(`/api/sessions/${tr.inboxId}`)).body;
    assert.equal(afterRec.command, "squatter");
    assert.equal(afterRec.command, before.command);
    assert.deepEqual(await tr.close(), { inbox_id: tr.inboxId, outcome: "collided" });
    assert.ok((await listSessionIds(d)).includes(tr.inboxId), "not deleted by the transport");
    await delay(300);
    assert.equal(target.received.length, deliveredBefore);
    await d.request(`/api/sessions/${tr.inboxId}?owned=true`, { method: "DELETE", sessionToken: squat.body.session_token });
  });

  test("telepty's peer-lane guard surfaces as a refusal code, nothing delivered (target outside AIGENTRY_ORCHESTRATOR_SIDS)", async () => {
    const ep = await startAtermEndpoint();
    const tr = mk(["ts-peer"]);
    try {
      await registerAterm(d, "ts-peer", ep.endpoint);
      const r = await tr.send({ target: "ts-peer", text: "plain prompt" });
      assert.equal(r.ok, false);
      assert.equal(r.error.code, "PEER_INJECT_BLOCKED");
      assert.equal(r.error.http_status, 403);
      assert.equal(r.error.accepted, false);
      await delay(300);
      assert.equal(ep.received.length, 0);
    } finally {
      await tr.close();
      await d.request("/api/sessions/ts-peer", { method: "DELETE" });
      await ep.close();
    }
  });

  test("backpressure: receiver 503 retains unknown payload without replay after space frees", async (t) => {
    const tr = mk();
    try {
      const s = await tr.send({ target: "ts-orch", text: "flood me" });
      const box = path.join(d.mailboxDir, tr.inboxId);
      const readJsonl = (f) => { try { return fs.readFileSync(path.join(box, f), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; } };
      const latest = () => { const m = new Map(); for (const e of readJsonl("state.jsonl")) m.set(e.msg_id, e.state); return m; };
      for (let i = 0; i < 64; i++) {
        const r = await reply(tr.inboxId, `REPLY ${s.nonce} part ${i}`, { bearer: targetCred.bearer, from: "ts-orch" });
        assert.equal(r.status, 200);
      }
      await waitFor(() => [...latest().values()].filter((v) => v === "acked").length === 64, { timeoutMs: 10000, description: "64 deliveries acked" });

      const r65 = await reply(tr.inboxId, `REPLY ${s.nonce} part 64`, { bearer: targetCred.bearer, from: "ts-orch" });
      assert.equal(r65.status, 502);
      assert.equal(r65.body.delivery_uncertain, true);
      assert.equal(r65.body.retryable, false);
      const held = readJsonl("dead-letter.jsonl").find(row => row.payload === `REPLY ${s.nonce} part 64`);
      assert.ok(held);
      const msgId = held.msg_id;
      assert.equal(typeof msgId, "string");
      assert.equal(latest().get(msgId), "dead_letter");
      assert.equal(held.payload, `REPLY ${s.nonce} part 64`);
      assert.equal(held.outcome, "unknown");

      const rr = await tr.readReply({ nonce: s.nonce, wait_ms: 3000 });
      assert.equal(rr.reply, "trusted");
      assert.equal(rr.text, `REPLY ${s.nonce} part 0`);

      await delay(2500);
      const states = readJsonl("state.jsonl").filter((e) => e.msg_id === msgId).map((e) => e.state);
      t.diagnostic(`msg ${msgId} states: ${states.join(" → ")}`);
      assert.equal(states.includes("nacked"), false);
      assert.equal(states.includes("acked"), false);
      assert.equal(latest().get(msgId), "dead_letter");
      assert.ok(readJsonl("inbox.jsonl").some(m => m.msg_id === msgId && m.attempt === 0));
      assert.equal(readJsonl("dead-letter.jsonl").length, 1);

      const again = await tr.readReply({ nonce: s.nonce });
      assert.equal(again.reply, "trusted");
      assert.equal(again.text, `REPLY ${s.nonce} part 0`, "unknown delivery did not displace the trusted reply");
      // Counters for the rejected delivery live on the transport inbox; read them through a fresh nonce.
      const probe = await tr.send({ target: "ts-orch", text: "probe counters" });
      const counts = await tr.readReply({ nonce: probe.nonce });
      t.diagnostic(`inbox counters: ${JSON.stringify(counts.inbox)}`);
      assert.equal(counts.inbox.inbox_rejected, 1);
    } finally {
      await tr.close();
    }
  });
});
