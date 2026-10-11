// Independent tester checks for the tunnel child launcher. Pure: fake spawn/signals/timers and static
// source reads only. The bin wrapper, MCP server, telepty daemon and tunnel client are never started.

import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { TunnelChildError, buildChildEnv, buildSpawnPlan, resolveMcpEntry, runChild } from "../src/tunnel-child.js";

const BASE = Object.freeze({
  TELESESSION_TELEPTY_URL: "http://127.0.0.1:3848",
  TELESESSION_TELEPTY_TOKEN_FILE: "/opt/keys/telepty-config.json",
  TELESESSION_TARGETS: "orchestrator",
  TELESESSION_INBOX_PREFIX: "ts",
});
const PLAN_IN = Object.freeze({ execPath: "/usr/local/bin/node", entryPath: "/opt/pkg/bin/telesession-mcp.js" });
const read = (rel) => fs.readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");

function code(fn) {
  try { fn(); } catch (err) { assert.ok(err instanceof TunnelChildError); return err; }
  assert.fail("expected TunnelChildError");
}

// Unlike the coder's fakeChild({ pid = 4242 }), `pid` is set verbatim so an explicit undefined stays undefined.
function child(pid) {
  const c = new EventEmitter();
  c.pid = pid;
  c.kills = [];
  c.kill = (sig) => { c.kills.push(sig); return true; };
  return c;
}

// No parameter default for pid: attempt 1 used `pid = 777`, which repeated the same undefined→default trap.
function run(platform, opts = {}) {
  const pid = "pid" in opts ? opts.pid : 777;
  const plan = buildSpawnPlan({ argv: [], env: BASE, platform: "linux", ...PLAN_IN });
  const signals = new EventEmitter();
  const timers = { pending: new Map(), next: 1, cleared: [] };
  const setTimer = (fn, ms) => { const id = timers.next++; timers.pending.set(id, { fn, ms }); return id; };
  const clearTimer = (id) => { timers.cleared.push(id); timers.pending.delete(id); };
  const fire = () => { for (const [id, { fn }] of [...timers.pending]) { timers.pending.delete(id); fn(); } };
  const diags = [];
  const c = child(pid);
  const done = runChild(plan, { spawn: () => c, signals, platform, graceMs: 50, setTimer, clearTimer, onDiagnostic: (d) => diags.push(d) });
  return { c, done, signals, timers, fire, diags };
}
const listeners = (em) => ["SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK"].reduce((n, s) => n + em.listenerCount(s), 0);

test("wiring: bin passes real argv/env/platform/execPath and the resolved entry to the helper, with real spawn", () => {
  const bin = read("../bin/telesession-tunnel-child.js");
  assert.match(bin, /import \{ spawn \} from "node:child_process";/);
  assert.match(bin, /from "\.\.\/src\/tunnel-child\.js";/);
  for (const s of ["argv: process.argv.slice(2)", "env: process.env", "platform: process.platform",
    "execPath: process.execPath", "entryPath: resolveMcpEntry()", "process.exit(2)"]) {
    assert.ok(bin.includes(s), `bin contains ${s}`);
  }
  // resolveMcpEntry() from src/ points at the packaged sibling bin/telesession-mcp.js (checked to exist; not run).
  const entry = resolveMcpEntry();
  assert.equal(entry, fileURLToPath(new URL("../bin/telesession-mcp.js", import.meta.url)));
  assert.ok(fs.statSync(entry).isFile());
});

test("stdio: launcher sources never touch stdout/stdin; refusals and diagnostics go to stderr only", () => {
  for (const rel of ["../bin/telesession-tunnel-child.js", "../src/tunnel-child.js"]) {
    const src = read(rel);
    for (const banned of ["process.stdout", "process.stdin", "console.", "shell: true", "exec(", "execSync", "spawnSync"]) {
      assert.ok(!src.includes(banned), `${rel} has no ${banned}`);
    }
  }
  const bin = read("../bin/telesession-tunnel-child.js");
  assert.equal(bin.match(/process\.stderr\.write/g).length, 2);
});

test("runChild: error from a child with no pid settles 1 with the stable code (corrected fake)", async () => {
  const h = run("linux", { pid: undefined });
  assert.equal(h.c.pid, undefined, "fake really has no pid");
  h.c.emit("error", Object.assign(new Error("spawn ENOENT /secret"), { code: "ENOENT" }));
  assert.equal(await h.done, 1);
  assert.deepEqual(h.diags, ["TUNNEL_CHILD_SPAWN_FAILED"]);
  assert.equal(listeners(h.signals), 0);
  h.c.emit("exit", 0, null); // a late exit after settling is ignored
  assert.equal(await h.done, 1);
});

test("runChild: error with a pid does not settle; exit does", async () => {
  const h = run("linux");
  h.c.emit("error", new Error("kill EPERM"));
  let settled = false;
  h.done.then(() => { settled = true; });
  await new Promise((r) => setImmediate(r));
  assert.equal(settled, false);
  h.c.emit("exit", 0, null);
  assert.equal(await h.done, 0);
  assert.deepEqual(h.diags, []);
});

test("runChild POSIX: one forward, later signals ignored, SIGKILL after grace, 128+n, listeners removed", async () => {
  const h = run("linux");
  assert.equal(listeners(h.signals), 3);
  h.signals.emit("SIGHUP");
  h.signals.emit("SIGTERM");
  h.signals.emit("SIGINT");
  assert.deepEqual(h.c.kills, ["SIGHUP"]);
  assert.equal(h.timers.pending.size, 1);
  assert.equal([...h.timers.pending.values()][0].ms, 50);
  h.fire();
  assert.deepEqual(h.c.kills, ["SIGHUP", "SIGKILL"]);
  h.c.emit("exit", null, "SIGKILL");
  assert.equal(await h.done, 137);
  assert.equal(listeners(h.signals), 0);
});

test("runChild POSIX: exit inside the grace window clears the timer; no SIGKILL", async () => {
  const h = run("darwin");
  h.signals.emit("SIGINT");
  h.c.emit("exit", 130, null);
  assert.equal(await h.done, 130);
  assert.equal(h.timers.pending.size, 0);
  assert.equal(h.timers.cleared.length, 1);
  assert.deepEqual(h.c.kills, ["SIGINT"]);
});

test("runChild win32: SIGBREAK also handled; nothing forwarded; one child.kill() after grace", async () => {
  const h = run("win32");
  assert.equal(listeners(h.signals), 4);
  h.signals.emit("SIGBREAK");
  h.signals.emit("SIGINT");
  assert.deepEqual(h.c.kills, []);
  assert.equal(h.timers.pending.size, 1);
  h.fire();
  assert.deepEqual(h.c.kills, [undefined]);
  h.c.emit("exit", 1, null);
  assert.equal(await h.done, 1);
  assert.equal(listeners(h.signals), 0);
});

test("runChild: a throwing kill is contained and exit still settles", async () => {
  const h = run("linux");
  h.c.kill = () => { throw new Error("ESRCH"); };
  h.signals.emit("SIGTERM");
  h.fire();
  h.c.emit("exit", null, "SIGTERM");
  assert.equal(await h.done, 143);
});

test("win32: case collisions on platform keys and the token key are refused; single empty token variant is dropped", () => {
  const win = { ...BASE, TELESESSION_TELEPTY_TOKEN_FILE: "C:\\k\\t.json" };
  assert.equal(code(() => buildChildEnv({ ...win, SystemRoot: "C:\\Windows", SYSTEMROOT: "D:\\x" }, { platform: "win32" })).code, "TUNNEL_CHILD_ENV_AMBIGUOUS");
  assert.equal(code(() => buildChildEnv({ ...win, Telesession_Telepty_Token: "" , TELESESSION_TELEPTY_TOKEN: "x" }, { platform: "win32" })).code, "TUNNEL_CHILD_ENV_AMBIGUOUS");
  const env = buildChildEnv({ ...win, Telesession_Telepty_Token: "" }, { platform: "win32" });
  assert.ok(!Object.keys(env).some((k) => k.toUpperCase() === "TELESESSION_TELEPTY_TOKEN"));
});

test("rejection diagnostics carry the code only, never the offending value", () => {
  const value = "토큰 파일/../secret value.json";
  const err = code(() => buildChildEnv({ ...BASE, TELESESSION_TELEPTY_TOKEN_FILE: value }, { platform: "linux" }));
  assert.equal(err.code, "TUNNEL_CHILD_TOKEN_FILE_INVALID");
  assert.equal(err.message, "TUNNEL_CHILD_TOKEN_FILE_INVALID");
  assert.ok(!String(err.stack).includes("secret value"));
});
