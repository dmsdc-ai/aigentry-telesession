// telesession MCP adapter + `telesession-mcp` command, exercised through the installed MCP SDK
// client over a real stdio child (StdioClientTransport), not by calling handlers directly.

import { describe, test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  BIN, HAS_TELEPTY, PACKAGE_DIR, TELEPTY_DIR, freshToken, listSessionIds, logPath, makeTempHome, nonceFromPrompt,
  registerAterm, runNode, startAtermEndpoint, startStubDaemon, startTeleptyDaemon, waitFor,
} from "./helpers.js";

const TOOLS = ["telesession_health", "telesession_list_targets", "telesession_read_reply", "telesession_receipt", "telesession_request_status", "telesession_send"];
const UNUSED_LOOPBACK = "http://127.0.0.1:47999";   // never the telepty default port; nothing listens here

function sdkVersion() {
  let dir = path.dirname(fileURLToPath(import.meta.resolve("@modelcontextprotocol/sdk/client/index.js")));
  for (;;) {
    const p = path.join(dir, "package.json");
    if (fs.existsSync(p)) {
      const pkg = JSON.parse(fs.readFileSync(p, "utf8"));
      if (pkg.name === "@modelcontextprotocol/sdk") return pkg.version;
    }
    const up = path.dirname(dir);
    if (up === dir) return null;
    dir = up;
  }
}

async function connectMcp(env, name) {
  const home = makeTempHome("telesession-mcp-home-");
  const file = logPath(name);
  const fd = fs.openSync(file, "w");
  const transport = new StdioClientTransport({
    command: process.execPath, args: [BIN], cwd: PACKAGE_DIR, stderr: fd,
    env: { ...home.env, ...env },
  });
  const client = new Client({ name: "telesession-test-client", version: "0.0.0" });
  try {
    await client.connect(transport);
  } finally {
    fs.closeSync(fd);
  }
  let closed = false;
  async function close() {
    if (closed) return fs.readFileSync(file, "utf8");
    closed = true;
    try { await client.close(); } finally { home.remove(); }   // SDK close: stdin end → SIGTERM → SIGKILL, bounded
    return fs.readFileSync(file, "utf8");
  }
  return { client, close, stderrFile: file };
}

function record(result) {
  assert.equal(result.content.length, 1);
  assert.equal(result.content[0].type, "text");
  const rec = JSON.parse(result.content[0].text);
  assert.equal(rec.completion_fact, null);
  assert.equal(result.isError === true, rec.ok === false, "isError iff ok:false");
  return rec;
}

// Schema refusal: the SDK either throws (JSON-RPC InvalidParams) or returns isError — never a call.
async function refused(client, name, args) {
  try {
    const r = await client.callTool({ name, arguments: args });
    assert.equal(r.isError, true, `${name} ${JSON.stringify(args)} must be refused`);
    return "isError";
  } catch (err) {
    assert.match(String(err.message), /-32602|invalid/i);
    return "threw";
  }
}

const cfgEnv = (origin, extra = {}) => ({
  TELESESSION_TARGETS: "target-1,target-2", TELESESSION_INBOX_PREFIX: "tsm",
  TELESESSION_TELEPTY_URL: origin, TELESESSION_TELEPTY_TOKEN: freshToken(), ...extra,
});

test("installed MCP SDK version vs declared ^1.26.0", (t) => {
  const v = sdkVersion();
  const declared = JSON.parse(fs.readFileSync(path.join(PACKAGE_DIR, "package.json"), "utf8")).dependencies["@modelcontextprotocol/sdk"];
  t.diagnostic(`@modelcontextprotocol/sdk installed ${v}, declared ${declared}`);
  assert.equal(declared, "^1.26.0");
  const [maj, min] = v.split(".").map(Number);
  assert.ok(maj === 1 && min >= 26, `installed ${v} satisfies ${declared}`);
});

test("telesession-mcp refuses invalid config: exit 2, one code-only stderr line, no secret", async () => {
  const secret = freshToken();
  const cases = [
    [{ TELESESSION_TELEPTY_URL: "http://10.1.2.3:4000" }, "CONFIG_URL_INVALID"],
    [{ TELESESSION_TELEPTY_URL: "http://localhost:4000" }, "CONFIG_URL_INVALID"],
    [{ TELESESSION_INBOX_PREFIX: "a-b" }, "CONFIG_INBOX_PREFIX_INVALID"],
    [{ TELESESSION_TARGETS: "" }, "CONFIG_TARGETS_INVALID"],
    [{ TELESESSION_TELEPTY_TOKEN_FILE: "/abs/token" }, "CONFIG_TOKEN_SOURCE_CONFLICT"],
    [{ TELESESSION_TELEPTY_TOKEN: "" }, "CONFIG_TOKEN_MISSING"],
    [{ TELESESSION_TELEPTY_TOKEN: `${secret} ${secret}` }, "CONFIG_TOKEN_INVALID"],
    [{ TELESESSION_TELEPTY_TOKEN: "", TELESESSION_TELEPTY_TOKEN_FILE: "relative/token" }, "CONFIG_TOKEN_FILE_INVALID"],
  ];
  for (const [env, code] of cases) {
    const home = makeTempHome();
    const res = await runNode([BIN], { name: `mcp-refuse-${code}`, env: { ...home.env, ...cfgEnv(UNUSED_LOOPBACK, { TELESESSION_TELEPTY_TOKEN: secret }), ...env } });
    home.remove();
    assert.equal(res.code, 2, `${code}: ${res.log}`);
    assert.equal(res.log, `telesession-mcp refused: ${code}\n`);
    assert.ok(!res.log.includes(secret));
  }
});

test("exactly six strict tools over real stdio; schema/allowlist refusals need no daemon", async () => {
  const mcp = await connectMcp(cfgEnv(UNUSED_LOOPBACK), "mcp-tools");
  let stderr;
  try {
    const { tools } = await mcp.client.listTools();
    assert.deepEqual(tools.map((x) => x.name).sort(), TOOLS);
    for (const tool of tools) {
      assert.equal(tool.inputSchema.type, "object");
      assert.equal(tool.inputSchema.additionalProperties, false, `${tool.name} is strict`);
      assert.ok(!/kill|register|shell|spawn|exec|url|delete|admin/i.test(tool.name));
    }
    const send = tools.find((x) => x.name === "telesession_send");
    assert.deepEqual([...send.inputSchema.required].sort(), ["target", "text"]);

    const kinds = [];
    kinds.push(await refused(mcp.client, "telesession_send", { target: "target-1", text: "x", extra: 1 }));
    kinds.push(await refused(mcp.client, "telesession_send", { target: "target-1", text: "a\u0000b" }));
    kinds.push(await refused(mcp.client, "telesession_send", { target: "target-1", text: "x".repeat(8001) }));
    kinds.push(await refused(mcp.client, "telesession_send", { target: "../x", text: "x" }));
    kinds.push(await refused(mcp.client, "telesession_health", { x: 1 }));
    kinds.push(await refused(mcp.client, "telesession_list_targets", { all: true }));
    kinds.push(await refused(mcp.client, "telesession_read_reply", { nonce: "0".repeat(32), wait_ms: 60001 }));
    kinds.push(await refused(mcp.client, "telesession_read_reply", { nonce: "nope" }));
    kinds.push(await refused(mcp.client, "telesession_receipt", { inject_id: "a/b" }));
    kinds.push(await refused(mcp.client, "telesession_request_status", { nonce: "nope" }));
    kinds.push(await refused(mcp.client, "telesession_request_status", { nonce: "0".repeat(32), cursor: -1 }));
    kinds.push(await refused(mcp.client, "telesession_read_reply", { nonce: "0".repeat(32), cursor: 1.5 }));
    kinds.push(await refused(mcp.client, "telesession_send", { target: "target-1", text: "x", destination: { host: "h", session: "s", extra: 1 } }));
    for (const target of ["other-session", "target", "target-1-x", "TARGET-1"]) {
      const rec = record(await mcp.client.callTool({ name: "telesession_send", arguments: { target, text: "hi" } }));
      assert.equal(rec.error.code, "TARGET_NOT_ALLOWED", target);
    }
    const nn = record(await mcp.client.callTool({ name: "telesession_read_reply", arguments: { nonce: "0".repeat(32) } }));
    assert.equal(nn.error.code, "NONCE_NOT_ISSUED");
    const rs = record(await mcp.client.callTool({ name: "telesession_request_status", arguments: { nonce: "0".repeat(32) } }));
    assert.equal(rs.error.code, "LEDGER_NOT_CONFIGURED", "memory-only config has no ledger");
    assert.ok(kinds.every((k) => k === kinds[0]), `consistent refusal style: ${kinds}`);
  } finally {
    stderr = await mcp.close();
  }
  assert.match(stderr, /^telesession: inbox tsm-i[0-9a-f]{32} not_created\n$/m);
});

describe("MCP against a recording stub daemon", () => {
  let stub;
  before(async () => { stub = await startStubDaemon(); stub.state.sessions = ["target-1", "other-session", "secret-session"]; });
  after(async () => { if (stub) await stub.close(); });

  test("health/list are read-only and allowlist-filtered; refused calls make zero requests", async () => {
    const mcp = await connectMcp(cfgEnv(stub.origin), "mcp-stub");
    let stderr;
    try {
      const h = record(await mcp.client.callTool({ name: "telesession_health", arguments: {} }));
      assert.equal(h.ok, true);
      assert.deepEqual(h.telepty.capabilities_missing, []);
      const lres = await mcp.client.callTool({ name: "telesession_list_targets", arguments: {} });
      const l = record(lres);
      assert.deepEqual(l.targets, [{ id: "target-1", present: true }, { id: "target-2", present: false }]);
      assert.ok(!/other-session|secret-session/.test(lres.content[0].text));
      const n = stub.requests.length;
      await refused(mcp.client, "telesession_send", { target: "target-1", text: "x", extra: 1 });
      await refused(mcp.client, "telesession_send", { target: "target-1", text: "a\u0000b" });
      record(await mcp.client.callTool({ name: "telesession_send", arguments: { target: "other-session", text: "x" } }));
      record(await mcp.client.callTool({ name: "telesession_send", arguments: { target: "target", text: "x" } }));
      assert.equal(stub.requests.length, n, "no request for any refused call");
      assert.deepEqual([...new Set(stub.requests.map((q) => `${q.method} ${q.pathname}`))].sort(), ["GET /api/meta", "GET /api/sessions"]);
    } finally {
      stderr = await mcp.close();
    }
    assert.match(stderr, /inbox tsm-i[0-9a-f]{32} not_created/);
    assert.equal(stub.mutations().length, 0);

    // Invalid config against a reachable daemon: refused before any request.
    const before = stub.requests.length;
    const res = await runNode([BIN], { name: "mcp-refuse-stub", env: { ...makeTempHome().env, ...cfgEnv(stub.origin, { TELESESSION_INBOX_PREFIX: "bad-prefix" }) } });
    assert.equal(res.code, 2);
    assert.equal(stub.requests.length, before);
  });
});

describe("MCP end-to-end against a real telepty daemon (fixture)", { skip: HAS_TELEPTY ? false : `NOTRUN: telepty source not found at ${TELEPTY_DIR}` }, () => {
  let d;
  let ep;
  let cred;
  before(async () => {
    d = await startTeleptyDaemon({ orchestratorSids: "mcp-orch" });
    ep = await startAtermEndpoint();
    cred = await registerAterm(d, "mcp-orch", ep.endpoint);
  });
  after(async () => {
    if (ep) await ep.close();
    if (d) await d.stop();
  });

  test("send → reply → read_reply trusted; stdin close deletes the owned inbox; token never on stderr", async () => {
    const tokenDir = makeTempHome("telesession-token-");
    const tokenFile = path.join(tokenDir.dir, "config.json");
    fs.writeFileSync(tokenFile, JSON.stringify({ authToken: d.token }));
    const mcp = await connectMcp({
      TELESESSION_TARGETS: "mcp-orch", TELESESSION_INBOX_PREFIX: "tsm",
      TELESESSION_TELEPTY_URL: d.origin, TELESESSION_TELEPTY_TOKEN_FILE: tokenFile,
    }, "mcp-e2e");
    let stderr;
    let inboxId;
    try {
      const s = record(await mcp.client.callTool({ name: "telesession_send", arguments: { target: "mcp-orch", text: "via mcp" } }));
      assert.equal(s.accepted, true, JSON.stringify(s));
      inboxId = s.reply_to;
      assert.ok((await listSessionIds(d)).includes(inboxId));
      await waitFor(() => ep.received.find((m) => nonceFromPrompt(m.body && m.body.text)?.nonce === s.nonce), { description: "target delivery" });
      const answer = `REPLY ${s.nonce} mcp answer`;
      const ri = await d.request(`/api/sessions/${inboxId}/inject`, { method: "POST", sessionToken: cred.bearer, body: { prompt: answer, from: "mcp-orch" } });
      assert.equal(ri.status, 200);
      const rr = record(await mcp.client.callTool({ name: "telesession_read_reply", arguments: { nonce: s.nonce, wait_ms: 8000 } }));
      assert.equal(rr.reply, "trusted");
      assert.equal(rr.text, answer);
      const rc = record(await mcp.client.callTool({ name: "telesession_receipt", arguments: { inject_id: s.inject_id } }));
      assert.equal(rc.ok, true);
    } finally {
      stderr = await mcp.close();
      tokenDir.remove();
    }
    assert.match(stderr, new RegExp(`telesession: inbox ${inboxId} deleted\\n`));
    assert.ok(!stderr.includes(d.token));
    assert.ok(!(await listSessionIds(d)).includes(inboxId), "owned inbox deleted on stdin close");
    assert.ok((await listSessionIds(d)).includes("mcp-orch"));
  });
});
