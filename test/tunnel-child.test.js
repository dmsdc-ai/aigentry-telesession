// telesession tunnel child launcher — pure env/argv/plan construction and lifecycle with an injected
// fake spawn. No real child, MCP server, telepty daemon or tunnel client is started.

import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import path from "node:path";
import {
  CHILD_CONFIG_KEYS, TunnelChildError, assertNoArgs, buildChildEnv, buildSpawnPlan, exitCodeFor,
  resolveMcpEntry, runChild,
} from "../src/tunnel-child.js";

const SECRET = "sk-should-never-reach-the-child-" + "z".repeat(16);
const BASE = Object.freeze({
  TELESESSION_TELEPTY_URL: "http://127.0.0.1:3848",
  TELESESSION_TELEPTY_TOKEN_FILE: "/opt/keys/telepty-config.json",
  TELESESSION_TARGETS: "orchestrator",
  TELESESSION_INBOX_PREFIX: "telesession_kkoma",
});
const POSIX_PLAN = Object.freeze({ execPath: "/usr/local/bin/node", entryPath: "/opt/pkg/bin/telesession-mcp.js" });

function refuses(fn, code) {
  let caught;
  try { fn(); } catch (err) { caught = err; }
  assert.ok(caught instanceof TunnelChildError, `expected TunnelChildError ${code}, got ${caught}`);
  assert.equal(caught.code, code);
  assert.equal(caught.message, code, "message is the code only");
  assert.ok(!String(caught.stack).includes(SECRET), "secret never in error stack");
  return caught;
}

test("buildChildEnv: malicious and unlisted keys are dropped; exact allowlist survives byte-for-byte", () => {
  const parent = {
    ...BASE,
    TELESESSION_STATE_DIR: "/var/lib/telesession",
    TELESESSION_PERSIST_INBOX_CREDENTIAL: "0",
    TELESESSION_TELEPTY_TOKEN: "",
    TELESESSION_DEBUG: SECRET, TELESESSION_TEST_TELEPTY_DIR: "/tmp/x",
    OPENAI_API_KEY: SECRET, OPENAI_ADMIN_KEY: SECRET, CONTROL_PLANE_API_KEY: SECRET, ANTHROPIC_API_KEY: SECRET,
    TUNNEL_CLIENT_PROFILE_DIR: "/home/u/.config/tunnel-client", AWS_SECRET_ACCESS_KEY: SECRET,
    NODE_OPTIONS: "--require /tmp/evil.js", NODE_PATH: "/tmp/evil", NODE_EXTRA_CA_CERTS: "/tmp/ca.pem",
    HTTP_PROXY: "http://proxy:1", HTTPS_PROXY: "http://proxy:1", http_proxy: "http://proxy:1", NO_PROXY: "*",
    PATH: "/usr/bin:/bin", HOME: "/home/u", LD_PRELOAD: "/tmp/evil.so", DYLD_INSERT_LIBRARIES: "/tmp/evil.dylib",
    TMPDIR: "/tmp/u", LANG: "ko_KR.UTF-8", LC_ALL: "ko_KR.UTF-8", SystemRoot: "C:\\Windows", TEMP: "C:\\Temp",
  };
  const snapshot = JSON.stringify(parent);
  const env = buildChildEnv(Object.freeze(parent), { platform: "linux" });
  assert.equal(JSON.stringify(parent), snapshot, "parent env not mutated");
  assert.equal(Object.getPrototypeOf(env), null, "no inherited properties reach spawn's for..in");
  assert.deepEqual(Object.keys(env).sort(), [
    "LANG", "LC_ALL", "TELESESSION_INBOX_PREFIX", "TELESESSION_PERSIST_INBOX_CREDENTIAL", "TELESESSION_STATE_DIR",
    "TELESESSION_TARGETS", "TELESESSION_TELEPTY_TOKEN_FILE", "TELESESSION_TELEPTY_URL", "TMPDIR",
  ]);
  for (const k of Object.keys(env)) assert.equal(env[k], parent[k]);
  assert.ok(!JSON.stringify({ ...env }).includes(SECRET));
  assert.ok(!("TELESESSION_TELEPTY_TOKEN" in env));
  assert.deepEqual([...CHILD_CONFIG_KEYS].sort(), [
    "TELESESSION_INBOX_PREFIX", "TELESESSION_PERSIST_INBOX_CREDENTIAL", "TELESESSION_STATE_DIR",
    "TELESESSION_TARGETS", "TELESESSION_TELEPTY_TOKEN_FILE", "TELESESSION_TELEPTY_URL",
  ]);
});

test("buildChildEnv: inherited prototype properties of the parent env are ignored", () => {
  const parent = Object.assign(Object.create({ OPENAI_API_KEY: SECRET, TELESESSION_TARGETS: "proto-target" }), BASE);
  const env = buildChildEnv(parent, { platform: "darwin" });
  assert.equal(env.TELESESSION_TARGETS, "orchestrator");
  assert.ok(!("OPENAI_API_KEY" in env));
});

test("buildChildEnv: a token VALUE is refused, never transferred", () => {
  refuses(() => buildChildEnv({ ...BASE, TELESESSION_TELEPTY_TOKEN: SECRET }, { platform: "linux" }), "TUNNEL_CHILD_TOKEN_VALUE_FORBIDDEN");
  refuses(() => buildChildEnv({ ...BASE, telesession_telepty_token: SECRET }, { platform: "win32" }), "TUNNEL_CHILD_TOKEN_VALUE_FORBIDDEN");
  // POSIX names are case-sensitive: a lowercase variant is just an unlisted key and is dropped.
  const env = buildChildEnv({ ...BASE, telesession_telepty_token: SECRET }, { platform: "linux" });
  assert.ok(!JSON.stringify({ ...env }).includes(SECRET));
});

test("buildChildEnv: token file reference must be nonempty and absolute (platform rules)", () => {
  const { TELESESSION_TELEPTY_TOKEN_FILE: _, ...noFile } = BASE;
  refuses(() => buildChildEnv(noFile, { platform: "linux" }), "TUNNEL_CHILD_TOKEN_FILE_REQUIRED");
  refuses(() => buildChildEnv({ ...noFile, TELESESSION_TELEPTY_TOKEN_FILE: "" }, { platform: "linux" }), "TUNNEL_CHILD_TOKEN_FILE_REQUIRED");
  for (const rel of ["token.json", "./token.json", "../keys/token.json", "~/token.json"]) {
    refuses(() => buildChildEnv({ ...BASE, TELESESSION_TELEPTY_TOKEN_FILE: rel }, { platform: "linux" }), "TUNNEL_CHILD_TOKEN_FILE_INVALID");
  }
  for (const rel of ["C:token.json", "token.json", ".\\token.json"]) {
    refuses(() => buildChildEnv({ ...BASE, TELESESSION_TELEPTY_TOKEN_FILE: rel }, { platform: "win32" }), "TUNNEL_CHILD_TOKEN_FILE_INVALID");
  }
  refuses(() => buildChildEnv({ ...BASE, TELESESSION_TELEPTY_TOKEN_FILE: "/opt/a\u0000b" }, { platform: "linux" }), "TUNNEL_CHILD_ENV_INVALID");
  refuses(() => buildChildEnv({ ...BASE, TELESESSION_TARGETS: 7 }, { platform: "linux" }), "TUNNEL_CHILD_ENV_INVALID");
});

test("buildChildEnv: file references with spaces and Korean pass through unchanged as env values", () => {
  const posix = "/Users/김 테스트/telepty 설정/토큰 파일.json";
  assert.equal(buildChildEnv({ ...BASE, TELESESSION_TELEPTY_TOKEN_FILE: posix }, { platform: "darwin" }).TELESESSION_TELEPTY_TOKEN_FILE, posix);
  const win = "C:\\Users\\김 테스트\\telepty 설정\\토큰 파일.json";
  assert.equal(buildChildEnv({ ...BASE, TELESESSION_TELEPTY_TOKEN_FILE: win }, { platform: "win32" }).TELESESSION_TELEPTY_TOKEN_FILE, win);
  const unc = "\\\\server\\share\\토큰 파일.json";
  assert.equal(buildChildEnv({ ...BASE, TELESESSION_TELEPTY_TOKEN_FILE: unc }, { platform: "win32" }).TELESESSION_TELEPTY_TOKEN_FILE, unc);
});

test("buildChildEnv: Windows key casing is canonicalized; ambiguous variants are refused", () => {
  const parent = {
    telesession_telepty_url: BASE.TELESESSION_TELEPTY_URL, Telesession_Telepty_Token_File: "C:\\keys\\t.json",
    TELESESSION_TARGETS: "orchestrator", telesession_inbox_prefix: "ts",
    systemroot: "C:\\Windows", windir: "C:\\Windows", Temp: "C:\\Temp", tmp: "C:\\Tmp",
    Path: "C:\\Windows\\system32", USERPROFILE: "C:\\Users\\u", TMPDIR: "/tmp", LANG: "C", "=C:": "C:\\",
    Openai_Api_Key: SECRET, node_options: "--require x",
  };
  const env = buildChildEnv(parent, { platform: "win32" });
  assert.deepEqual(Object.keys(env).sort(), [
    "SystemRoot", "TELESESSION_INBOX_PREFIX", "TELESESSION_TARGETS", "TELESESSION_TELEPTY_TOKEN_FILE",
    "TELESESSION_TELEPTY_URL", "TEMP", "TMP", "WINDIR",
  ]);
  assert.equal(env.TELESESSION_TELEPTY_TOKEN_FILE, "C:\\keys\\t.json");
  assert.equal(env.SystemRoot, "C:\\Windows");
  // The same mixed-case env on POSIX keeps only exact-case names.
  refuses(() => buildChildEnv(parent, { platform: "linux" }), "TUNNEL_CHILD_TOKEN_FILE_REQUIRED");
  const posixEnv = buildChildEnv({ ...parent, TELESESSION_TELEPTY_TOKEN_FILE: "/k/t.json" }, { platform: "linux" });
  assert.deepEqual(Object.keys(posixEnv).sort(), ["LANG", "TELESESSION_TARGETS", "TELESESSION_TELEPTY_TOKEN_FILE", "TMPDIR"]);

  const win = { ...BASE, TELESESSION_TELEPTY_TOKEN_FILE: "C:\\k\\t.json" };
  refuses(() => buildChildEnv({ ...win, telesession_targets: "other" }, { platform: "win32" }), "TUNNEL_CHILD_ENV_AMBIGUOUS");
  refuses(() => buildChildEnv({ ...win, telesession_telepty_token_file: "C:\\x.json" }, { platform: "win32" }), "TUNNEL_CHILD_ENV_AMBIGUOUS");
  refuses(() => buildChildEnv({ ...win, TEMP: "C:\\a", temp: "C:\\b" }, { platform: "win32" }), "TUNNEL_CHILD_ENV_AMBIGUOUS");
  refuses(() => buildChildEnv({ ...win, TELESESSION_TELEPTY_TOKEN: "", telesession_telepty_token: "" }, { platform: "win32" }), "TUNNEL_CHILD_ENV_AMBIGUOUS");
  // On POSIX two case variants are distinct names; only the exact one is forwarded.
  assert.equal(buildChildEnv({ ...BASE, telesession_targets: "other" }, { platform: "linux" }).TELESESSION_TARGETS, "orchestrator");
});

test("assertNoArgs / buildSpawnPlan: any CLI argument is refused", () => {
  assertNoArgs([]);
  for (const argv of [["--help"], [""], ["x"], ["--", "/bin/sh"], ["--inspect"], ["-e", "1"], undefined, "x"]) {
    refuses(() => assertNoArgs(argv), "TUNNEL_CHILD_ARGS_UNEXPECTED");
    refuses(() => buildSpawnPlan({ argv, env: BASE, platform: "linux", ...POSIX_PLAN }), "TUNNEL_CHILD_ARGS_UNEXPECTED");
  }
});

test("buildSpawnPlan: fixed node + packaged entry, no shell, inherited stdio, not detached, no overrides", () => {
  const plan = buildSpawnPlan({
    argv: [], env: { ...BASE, OPENAI_API_KEY: SECRET }, platform: "linux", ...POSIX_PLAN,
    command: "/bin/sh", args: ["-c", "id"], shell: true, cwd: "/", options: { shell: true },
  });
  assert.equal(plan.command, POSIX_PLAN.execPath);
  assert.deepEqual([...plan.args], [POSIX_PLAN.entryPath]);
  assert.deepEqual(Object.keys(plan.options).sort(), ["detached", "env", "shell", "stdio"]);
  assert.equal(plan.options.shell, false);
  assert.equal(plan.options.stdio, "inherit");
  assert.equal(plan.options.detached, false);
  assert.ok(Object.isFrozen(plan) && Object.isFrozen(plan.args) && Object.isFrozen(plan.options));
  assert.ok(!JSON.stringify(plan).includes(SECRET), "no secret in argv or child env");
  assert.ok(!plan.args.some((a) => a.includes("TELESESSION_")), "no config value in argv");

  const spaced = { execPath: "C:\\Program Files\\nodejs\\node.exe", entryPath: "C:\\앱 폴더\\telesession\\bin\\telesession-mcp.js" };
  const winPlan = buildSpawnPlan({ argv: [], env: { ...BASE, TELESESSION_TELEPTY_TOKEN_FILE: "C:\\k\\t.json" }, platform: "win32", ...spaced });
  assert.equal(winPlan.command, spaced.execPath);
  assert.deepEqual([...winPlan.args], [spaced.entryPath], "a spaced/Korean entry stays one argv element");

  for (const bad of [{ execPath: "node" }, { entryPath: "bin/telesession-mcp.js" }, { execPath: undefined }, { entryPath: "/a\u0000b" }]) {
    refuses(() => buildSpawnPlan({ argv: [], env: BASE, platform: "linux", ...POSIX_PLAN, ...bad }), "TUNNEL_CHILD_ENTRY_INVALID");
  }
  refuses(() => buildSpawnPlan({ argv: [], env: BASE, platform: "win32", execPath: "node.exe", entryPath: spaced.entryPath }), "TUNNEL_CHILD_ENTRY_INVALID");
});

test("resolveMcpEntry: packaged bin/telesession-mcp.js relative to the module URL", () => {
  assert.equal(resolveMcpEntry("file:///opt/pkg/src/tunnel-child.js", (u) => u.pathname), "/opt/pkg/bin/telesession-mcp.js");
  const real = resolveMcpEntry();
  assert.ok(path.isAbsolute(real));
  assert.ok(real.endsWith(path.join("bin", "telesession-mcp.js")));
});

test("exitCodeFor: numeric code passes through; signal maps to 128+n; unknown → 1", () => {
  assert.equal(exitCodeFor(0, null), 0);
  assert.equal(exitCodeFor(2, null), 2);
  assert.equal(exitCodeFor(null, "SIGTERM"), 143);
  assert.equal(exitCodeFor(null, "SIGKILL"), 137);
  assert.equal(exitCodeFor(null, "SIGNOPE"), 1);
  assert.equal(exitCodeFor(null, null), 1);
});

// ── lifecycle with injected fakes ──

// Omitted pid defaults to 4242; an explicit `pid: undefined` stays undefined (no pid yet).
function fakeChild(opts = {}) {
  const child = new EventEmitter();
  child.pid = "pid" in opts ? opts.pid : 4242;
  child.kills = [];
  child.kill = (sig) => { child.kills.push(sig); return true; };
  return child;
}

function fakeTimers() {
  const t = { pending: new Map(), next: 1, cleared: [] };
  t.setTimer = (fn, ms) => { const id = t.next++; t.pending.set(id, { fn, ms }); return id; };
  t.clearTimer = (id) => { t.cleared.push(id); t.pending.delete(id); };
  t.fire = () => { for (const [id, { fn }] of [...t.pending]) { t.pending.delete(id); fn(); } };
  return t;
}

function harness({ platform = "linux", spawnImpl } = {}) {
  const plan = buildSpawnPlan({ argv: [], env: BASE, platform: "linux", ...POSIX_PLAN });
  const signals = new EventEmitter();
  const timers = fakeTimers();
  const diags = [];
  const calls = [];
  let child = null;
  const spawn = spawnImpl || ((cmd, args, opts) => { calls.push({ cmd, args, opts }); child = fakeChild(); return child; });
  const done = runChild(plan, {
    spawn, signals, platform, graceMs: 1234, setTimer: timers.setTimer, clearTimer: timers.clearTimer,
    onDiagnostic: (c) => diags.push(c),
  });
  return { plan, signals, timers, diags, calls, done, child: () => child };
}

const SIGNALS = ["SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK"];
const listenerTotal = (em) => SIGNALS.reduce((n, s) => n + em.listenerCount(s), 0);

test("runChild: spawns exactly the plan (no shell) and reflects the child's exit code", async () => {
  const h = harness();
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].cmd, POSIX_PLAN.execPath);
  assert.deepEqual(h.calls[0].args, [POSIX_PLAN.entryPath]);
  assert.equal(h.calls[0].opts.shell, false);
  assert.equal(h.calls[0].opts.stdio, "inherit");
  assert.equal(h.calls[0].opts.detached, false);
  assert.equal(h.calls[0].opts.env, h.plan.options.env);
  assert.equal(listenerTotal(h.signals), 3, "POSIX: SIGINT/SIGTERM/SIGHUP");
  h.child().emit("exit", 3, null);
  assert.equal(await h.done, 3);
  assert.equal(listenerTotal(h.signals), 0, "signal listeners removed after exit");
  assert.deepEqual(h.diags, []);
  assert.deepEqual(h.child().kills, []);
});

test("runChild: synchronous spawn throw → nonzero, stable code, no raw error", async () => {
  const h = harness({ spawnImpl: () => { throw new Error(`ENOENT ${SECRET} /secret/path`); } });
  assert.equal(await h.done, 1);
  assert.deepEqual(h.diags, ["TUNNEL_CHILD_SPAWN_FAILED"]);
  assert.equal(listenerTotal(h.signals), 0);
});

test("runChild: async spawn error before a pid exists → nonzero, listeners removed", async () => {
  let child;
  const h = harness({ spawnImpl: () => { child = fakeChild({ pid: undefined }); return child; } });
  child.emit("error", Object.assign(new Error(`spawn ${SECRET}`), { code: "ENOENT" }));
  assert.equal(await h.done, 1);
  assert.deepEqual(h.diags, ["TUNNEL_CHILD_SPAWN_FAILED"]);
  assert.equal(listenerTotal(h.signals), 0);
});

test("runChild: error after spawn (e.g. kill failure) does not settle; exit does", async () => {
  const h = harness();
  h.child().emit("error", new Error("kill EPERM"));
  let settled = false;
  h.done.then(() => { settled = true; });
  await new Promise((r) => setImmediate(r));
  assert.equal(settled, false);
  h.child().emit("exit", 0, null);
  assert.equal(await h.done, 0);
  assert.deepEqual(h.diags, []);
});

test("runChild POSIX: signal forwarded once to the owned child, bounded SIGKILL escalation, 128+n exit", async () => {
  const h = harness({ platform: "linux" });
  h.signals.emit("SIGTERM");
  h.signals.emit("SIGINT");
  assert.deepEqual(h.child().kills, ["SIGTERM"], "forwarded once");
  assert.equal(h.timers.pending.size, 1);
  assert.equal([...h.timers.pending.values()][0].ms, 1234);
  h.timers.fire();
  assert.deepEqual(h.child().kills, ["SIGTERM", "SIGKILL"]);
  h.child().emit("exit", null, "SIGKILL");
  assert.equal(await h.done, 137);
  assert.equal(listenerTotal(h.signals), 0);
});

test("runChild POSIX: graceful child exit inside the grace window cancels escalation", async () => {
  const h = harness({ platform: "darwin" });
  h.signals.emit("SIGINT");
  assert.deepEqual(h.child().kills, ["SIGINT"]);
  h.child().emit("exit", 0, null);
  assert.equal(await h.done, 0);
  assert.equal(h.timers.pending.size, 0);
  assert.equal(h.timers.cleared.length, 1);
  assert.deepEqual(h.child().kills, ["SIGINT"], "no SIGKILL after exit");
});

test("runChild win32: no immediate TerminateProcess; terminate only after the grace window", async () => {
  const h = harness({ platform: "win32" });
  assert.equal(listenerTotal(h.signals), 4, "win32 also listens for SIGBREAK");
  h.signals.emit("SIGINT");
  assert.deepEqual(h.child().kills, [], "child shares the console/stdin and stops on its own first");
  h.timers.fire();
  assert.deepEqual(h.child().kills, [undefined], "child.kill() of the owned child only");
  h.child().emit("exit", 1, null);
  assert.equal(await h.done, 1);
  assert.equal(listenerTotal(h.signals), 0);
});

test("runChild: kill that throws is contained; exit still settles", async () => {
  const h = harness();
  h.child().kill = () => { throw new Error("ESRCH"); };
  h.signals.emit("SIGTERM");
  h.timers.fire();
  h.child().emit("exit", null, "SIGTERM");
  assert.equal(await h.done, 143);
});
