/**
 * Test helpers for @dmsdc-ai/telesession. Native Node only (no shell, no test dependency).
 *
 * Every fixture here is hermetic: a telepty daemon spawned from a source checkout on an ephemeral
 * loopback port with its own temp HOME and a fresh random token, plain node:http stubs, and child
 * processes whose stdio goes to log files (stdin ignored) and that are always reaped by a bounded
 * stop. Nothing reads the host's ~/.telepty, auth or default port.
 *
 * Env knobs (all optional):
 *   TELESESSION_TEST_TELEPTY_DIR  telepty source checkout (default: ../../telepty next to this package)
 *   TELESESSION_TEST_LOG_DIR      where child logs go (default: a temp dir under os.tmpdir())
 */

import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const PACKAGE_DIR = path.resolve(here, "..");
export const TELEPTY_DIR = process.env.TELESESSION_TEST_TELEPTY_DIR || path.resolve(PACKAGE_DIR, "..", "telepty");
export const TELEPTY_DAEMON = path.join(TELEPTY_DIR, "daemon.js");
export const HAS_TELEPTY = fs.existsSync(TELEPTY_DAEMON);
export const BIN = path.join(PACKAGE_DIR, "bin", "telesession-mcp.js");

const LOG_DIR = process.env.TELESESSION_TEST_LOG_DIR
  || fs.mkdtempSync(path.join(os.tmpdir(), "telesession-test-logs-"));
fs.mkdirSync(LOG_DIR, { recursive: true });
let logSeq = 0;

export function logPath(name) {
  logSeq += 1;
  return path.join(LOG_DIR, `${process.pid}-${String(logSeq).padStart(3, "0")}-${name}.log`);
}

export const delay = (ms) => new Promise((r) => setTimeout(r, ms));

export async function waitFor(check, { timeoutMs = 5000, intervalMs = 50, description = "condition" } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const v = await check();
    if (v) return v;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${description}`);
    await delay(intervalMs);
  }
}

export const freshToken = () => randomBytes(24).toString("hex");

export function makeTempHome(prefix = "telesession-home-") {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return {
    dir,
    env: { HOME: dir, USERPROFILE: dir, TMPDIR: dir, TEMP: dir, TMP: dir },
    remove: () => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } },
  };
}

// Minimal inherited env: PATH plus Windows essentials. Nothing else from the host leaks in.
function baseEnv() {
  const env = {};
  for (const k of ["PATH", "Path", "SystemRoot", "SYSTEMROOT", "ComSpec", "PATHEXT", "WINDIR"]) {
    if (process.env[k] !== undefined) env[k] = process.env[k];
  }
  return env;
}

// Bounded stop for any child: SIGTERM, then SIGKILL; resolves once exited (or after the bound).
async function stopChild(child, graceMs = 3000) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise((r) => child.once("exit", r));
  try { child.kill("SIGTERM"); } catch { /* gone */ }
  let timer;
  const t = new Promise((r) => { timer = setTimeout(() => r("timeout"), graceMs); });
  const res = await Promise.race([exited, t]);
  clearTimeout(timer);
  if (res === "timeout" && child.exitCode === null) {
    try { child.kill("SIGKILL"); } catch { /* gone */ }
    let t2;
    await Promise.race([exited, new Promise((r) => { t2 = setTimeout(r, 2000); })]);
    clearTimeout(t2);
  }
}

// Spawn `node <args>` with stdin ignored and stdout/stderr to one log file; wait for exit (bounded).
export async function runNode(args, { env = {}, cwd = PACKAGE_DIR, name = "child", timeoutMs = 15000 } = {}) {
  const file = logPath(name);
  const fd = fs.openSync(file, "w");
  const child = spawn(process.execPath, args, { cwd, env: { ...baseEnv(), ...env }, stdio: ["ignore", fd, fd], windowsHide: true });
  fs.closeSync(fd);
  let timer;
  try {
    const code = await Promise.race([
      new Promise((r) => child.once("exit", (c, s) => r({ code: c, signal: s }))),
      new Promise((r) => { timer = setTimeout(() => r(null), timeoutMs); }),
    ]);
    return { ...(code || { code: null, signal: "TIMEOUT" }), log: fs.readFileSync(file, "utf8"), file };
  } finally {
    clearTimeout(timer);
    await stopChild(child);
  }
}

// ── Real telepty fixture daemon ──

export async function startTeleptyDaemon({ orchestratorSids = "", env: extraEnv = {} } = {}) {
  if (!HAS_TELEPTY) throw new Error(`telepty source not found at ${TELEPTY_DIR}`);
  const home = makeTempHome("telesession-daemon-home-");
  const token = freshToken();
  const file = logPath("telepty-daemon");
  const fd = fs.openSync(file, "w");
  const env = {
    ...baseEnv(), ...home.env,
    PORT: "0", HOST: "127.0.0.1",
    TELEPTY_AUTH_TOKEN: token,
    TELEPTY_NO_TAILNET_AUTO: "1",
    NO_UPDATE_NOTIFIER: "1", TELEPTY_DISABLE_UPDATE_NOTIFIER: "1",
    AIGENTRY_MAILBOX_DIR: path.join(home.dir, "mailbox"),
    // telepty's peer-lane guard: the operator names the orchestrator lane explicitly. An empty value
    // falls back to telepty's built-in default sids.
    AIGENTRY_ORCHESTRATOR_SIDS: orchestratorSids,
    ...extraEnv,
  };
  const child = spawn(process.execPath, [TELEPTY_DAEMON], { cwd: TELEPTY_DIR, env, stdio: ["ignore", fd, fd], windowsHide: true });
  fs.closeSync(fd);
  const readLog = () => { try { return fs.readFileSync(file, "utf8"); } catch { return ""; } };
  let port;
  try {
    port = await waitFor(() => {
      if (child.exitCode !== null) throw new Error(`telepty daemon exited early (${child.exitCode}); see ${file}`);
      // Port 0 in the banner means the bind failed (express 5 calls back with the error too).
      const m = /listening on https?:\/\/[^\s]+:([1-9]\d*)/.exec(readLog());
      return m ? Number(m[1]) : null;
    }, { timeoutMs: 10000, description: "telepty daemon banner" });
    await waitFor(async () => {
      try { return (await fetch(`http://127.0.0.1:${port}/api/health`)).ok; } catch { return false; }
    }, { timeoutMs: 5000, description: "telepty daemon health" });
  } catch (err) {
    await stopChild(child);
    home.remove();
    throw err;
  }
  const origin = `http://127.0.0.1:${port}`;

  async function request(pathname, { method = "GET", body, headers = {}, sessionToken, noAuth = false } = {}) {
    const h = { ...headers };
    if (!noAuth) h["x-telepty-token"] = token;
    if (sessionToken) h["x-telepty-session-token"] = sessionToken;
    if (body !== undefined) h["content-type"] = "application/json";
    const res = await fetch(origin + pathname, {
      method, headers: h, redirect: "manual", signal: AbortSignal.timeout(10000),
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { json = null; }
    return { status: res.status, body: json, text };
  }

  async function stop() {
    await stopChild(child);
    home.remove();
  }

  return {
    origin, port, token, home: home.dir, logFile: file, readLog, request, stop,
    mailboxDir: env.AIGENTRY_MAILBOX_DIR,
    isAlive: () => child.exitCode === null && child.signalCode === null,
  };
}

// Register an aterm session whose delivery endpoint is `endpoint`. Returns the one-time bearer.
export async function registerAterm(daemon, sid, endpoint, extra = {}) {
  const r = await daemon.request("/api/sessions/register", {
    method: "POST",
    body: { session_id: sid, delivery_type: "aterm", delivery_endpoint: endpoint, command: "fixture-target", ...extra },
  });
  if (r.status !== 201) throw new Error(`register ${sid} → ${r.status} ${r.text}`);
  return { bearer: r.body.session_token, epoch: r.body.session_epoch, generation: r.body.credential_generation };
}

export async function listSessionIds(daemon) {
  const r = await daemon.request("/api/sessions");
  return Array.isArray(r.body) ? r.body.map((s) => s.id) : null;
}

export function nonceFromPrompt(text) {
  const m = /^\[telesession nonce=([0-9a-f]{32}) reply-to=([A-Za-z0-9._-]+)\]\n/.exec(String(text));
  return m ? { nonce: m[1], replyTo: m[2] } : null;
}

// ── Plain HTTP fixtures ──

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", () => resolve(""));
  });
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port: 0 }, () => { server.off("error", reject); resolve(); });
  });
  return server.address().port;
}

async function closeServer(server) {
  try { server.closeAllConnections(); } catch { /* none */ }
  await new Promise((r) => server.close(() => r()));
}

// aterm target endpoint: records every delivered {text, session_id}; replies with `status`.
export async function startAtermEndpoint({ status = 200 } = {}) {
  const received = [];
  const state = { status };
  const server = http.createServer(async (req, res) => {
    const raw = await readBody(req);
    let body = null;
    try { body = JSON.parse(raw); } catch { body = null; }
    received.push({ method: req.method, url: req.url, body });
    res.writeHead(state.status, { "content-type": "application/json" });
    res.end('{"ok":true}');
  });
  const port = await listen(server);
  return { endpoint: `http://127.0.0.1:${port}/deliver`, received, state, close: () => closeServer(server) };
}

// Recording stub of the documented telepty HTTP surface. `routes` keys are "METHOD /path" (query
// stripped; `:id` segments matched by prefix rules below); a route returns {status, body, headers}
// or handles `res` itself and returns undefined. Every request is recorded.
export async function startStubDaemon(overrides = {}) {
  const requests = [];
  const state = { sessions: ["target-1", "other-session"], capabilities: ["sessions", "inject-exact-target", "register-create-only", "delete-owned-session"], pid: 4242, registerEndpoint: null, injectSeq: 0 };
  const defaults = {
    "GET /api/meta": () => ({ body: { name: "stub", version: "0.0.0-stub", pid: state.pid, capabilities: state.capabilities } }),
    "GET /api/sessions": () => ({ body: state.sessions.map((id) => ({ id })) }),
    "POST /api/sessions/register": (req, body) => {
      state.registerEndpoint = body && body.delivery_endpoint;
      return { status: 201, body: { session_id: body.session_id, session_token: "stub-bearer-" + freshToken(), session_epoch: "stub-epoch-1" } };
    },
    "POST /api/sessions/:id/inject": (req, body, id) => {
      state.injectSeq += 1;
      return { body: { success: true, inject_id: `00000000-0000-4000-8000-${String(state.injectSeq).padStart(12, "0")}`, exact_target: true, session_id: id } };
    },
    "GET /api/inject-observations/:id": (req, body, id) => ({ body: { inject_id: id, session_id: "target-1", session_epoch: "target-epoch-1", tracking_state: "tracked" } }),
    "GET /api/injects": () => ({ body: { injects: [], next_cursor: null } }),
    "DELETE /api/sessions/:id": () => ({ body: { success: true } }),
  };
  const routes = { ...defaults, ...overrides };
  const server = http.createServer(async (req, res) => {
    const raw = await readBody(req);
    let body = null;
    try { body = raw ? JSON.parse(raw) : null; } catch { body = null; }
    const pathname = String(req.url).split("?")[0];
    requests.push({ method: req.method, url: req.url, pathname, headers: req.headers, body });
    let key = `${req.method} ${pathname}`;
    let id = null;
    if (!routes[key]) {
      const m = /^\/api\/(sessions|inject-observations)\/([^/]+)(\/inject)?$/.exec(pathname);
      if (m) {
        id = decodeURIComponent(m[2]);
        key = m[1] === "sessions" ? (m[3] ? `${req.method} /api/sessions/:id/inject` : `${req.method} /api/sessions/:id`) : `${req.method} /api/inject-observations/:id`;
      }
    }
    const route = routes[key];
    if (!route) { res.writeHead(404, { "content-type": "application/json" }); res.end('{"error":"not found"}'); return; }
    const out = await route(req, body, id, res);
    if (out === undefined) return;
    res.writeHead(out.status || 200, { "content-type": "application/json", ...(out.headers || {}) });
    res.end(typeof out.raw === "string" ? out.raw : JSON.stringify(out.body));
  });
  server.keepAliveTimeout = 1;
  const port = await listen(server);
  return {
    origin: `http://127.0.0.1:${port}`, port, requests, state,
    mutations: () => requests.filter((r) => r.method !== "GET"),
    close: () => closeServer(server),
  };
}

// ── Restartable real telepty fixture (task 1215 RC5) ──
// Same hermetic env as startTeleptyDaemon, but the temp HOME, the token and the bound port survive
// restart(): a restart-continuity test needs the SAME sessions.json and the same origin (a new port is
// a different telesession config). restart() signals ONLY this fixture's own daemon child, waits for it
// (bounded), and boots daemon.js again on that HOME and port. stop() reaps the child and removes HOME.

export async function startRestartableTeleptyDaemon({ orchestratorSids = "", env: extraEnv = {} } = {}) {
  if (!HAS_TELEPTY) throw new Error(`telepty source not found at ${TELEPTY_DIR}`);
  const home = makeTempHome("telesession-restart-home-");
  const token = freshToken();
  const env = {
    ...baseEnv(), ...home.env,
    HOST: "127.0.0.1",
    TELEPTY_AUTH_TOKEN: token,
    TELEPTY_NO_TAILNET_AUTO: "1",
    NO_UPDATE_NOTIFIER: "1", TELEPTY_DISABLE_UPDATE_NOTIFIER: "1",
    AIGENTRY_MAILBOX_DIR: path.join(home.dir, "mailbox"),
    AIGENTRY_ORCHESTRATOR_SIDS: orchestratorSids,
    ...extraEnv,
  };
  let child = null;
  let file = null;
  let port = 0;
  const readLog = () => { try { return file ? fs.readFileSync(file, "utf8") : ""; } catch { return ""; } };

  async function boot() {
    file = logPath("telepty-daemon-restartable");
    const fd = fs.openSync(file, "w");
    child = spawn(process.execPath, [TELEPTY_DAEMON], { cwd: TELEPTY_DIR, env: { ...env, PORT: String(port) }, stdio: ["ignore", fd, fd], windowsHide: true });
    fs.closeSync(fd);
    const c = child;
    const bound = await waitFor(() => {
      if (c.exitCode !== null || c.signalCode !== null) throw new Error(`telepty daemon exited early (${c.exitCode ?? c.signalCode}); see ${file}`);
      const m = /listening on https?:\/\/[^\s]+:([1-9]\d*)/.exec(readLog());
      return m ? Number(m[1]) : null;
    }, { timeoutMs: 10000, description: "telepty daemon banner" });
    if (port !== 0 && bound !== port) throw new Error(`restarted telepty daemon bound ${bound}, not the kept port ${port}`);
    port = bound;
    await waitFor(async () => {
      try { return (await fetch(`http://127.0.0.1:${port}/api/health`)).ok; } catch { return false; }
    }, { timeoutMs: 5000, description: "telepty daemon health" });
  }

  // Resolves {code, signal} of the exit this signal caused; falls back to the bounded stopChild.
  async function signalDaemon(signal, boundMs = 8000) {
    const c = child;
    if (!c) return { code: null, signal: null };
    const exited = new Promise((r) => c.once("exit", (code, sig) => r({ code, signal: sig })));
    if (c.exitCode !== null || c.signalCode !== null) return { code: c.exitCode, signal: c.signalCode };
    try { c.kill(signal); } catch { /* gone */ }
    let timer;
    const res = await Promise.race([exited, new Promise((r) => { timer = setTimeout(() => r(null), boundMs); })]);
    clearTimeout(timer);
    if (res) return res;
    await stopChild(c);
    return { code: c.exitCode, signal: c.signalCode, timedOut: true };
  }

  async function restart({ signal = "SIGTERM" } = {}) {
    const exit = await signalDaemon(signal);
    await boot();
    return exit;
  }

  async function stop() {
    if (child) await stopChild(child);
    home.remove();
  }

  async function request(pathname, { method = "GET", body, headers = {}, sessionToken, noAuth = false } = {}) {
    const h = { ...headers };
    if (!noAuth) h["x-telepty-token"] = token;
    if (sessionToken) h["x-telepty-session-token"] = sessionToken;
    if (body !== undefined) h["content-type"] = "application/json";
    const res = await fetch(`http://127.0.0.1:${port}` + pathname, {
      method, headers: h, redirect: "manual", signal: AbortSignal.timeout(10000),
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { json = null; }
    return { status: res.status, body: json, text };
  }

  try {
    await boot();
  } catch (err) {
    if (child) await stopChild(child);
    home.remove();
    throw err;
  }
  return {
    get origin() { return `http://127.0.0.1:${port}`; },
    get port() { return port; },
    get logFile() { return file; },
    token, home: home.dir, readLog, request, restart, stop,
    mailboxDir: env.AIGENTRY_MAILBOX_DIR,
    pid: () => (child ? child.pid : null),
    isAlive: () => child !== null && child.exitCode === null && child.signalCode === null,
  };
}

// A real `telepty allow` bridge (cli.js) wrapping `node <script>` in a PTY, owned by `daemon`'s HOME.
// stdin is a pipe that is never written (the bridge reads it as the operator keyboard; an open pipe is
// what the telepty bridge harness uses too). stdout/stderr — the PTY output — go to one log file.
export function startTeleptyBridge(daemon, { sid, script, env: extraEnv = {} }) {
  const file = logPath("telepty-bridge");
  const fd = fs.openSync(file, "w");
  const child = spawn(process.execPath, [path.join(TELEPTY_DIR, "cli.js"), "allow", "--id", sid, process.execPath, script], {
    cwd: TELEPTY_DIR,
    env: {
      ...baseEnv(),
      HOME: daemon.home, USERPROFILE: daemon.home, TMPDIR: daemon.home, TEMP: daemon.home, TMP: daemon.home,
      TELEPTY_HOST: "127.0.0.1",
      TELEPTY_PORT: String(daemon.port),
      TELEPTY_AUTH_TOKEN: daemon.token,
      TELEPTY_NO_TAILNET_AUTO: "1",
      NO_UPDATE_NOTIFIER: "1", TELEPTY_DISABLE_UPDATE_NOTIFIER: "1",
      AIGENTRY_MAILBOX_DIR: daemon.mailboxDir,
      TERM: "xterm-256color",
      ...extraEnv,
    },
    stdio: ["pipe", fd, fd],
    windowsHide: true,
  });
  fs.closeSync(fd);
  child.stdin.on("error", () => { /* bridge gone */ });
  return {
    child, logFile: file,
    readLog: () => { try { return fs.readFileSync(file, "utf8"); } catch { return ""; } },
    isAlive: () => child.exitCode === null && child.signalCode === null,
    stop: () => stopChild(child),
  };
}
