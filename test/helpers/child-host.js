/**
 * Child-process host for crash tests. Native Node only, no shell.
 *
 * Parent side: startChildHost(mode, spec) spawns `node child-host.js --telesession-child-host <mode>`
 * with stdin ignored, stderr to a log file, and stdout as a pipe used ONLY for the fixture protocol
 * (one JSON object per line: {event:"ready"|"result"|"closed"|"error", ...}), plus an IPC channel used
 * ONLY for the graceful stop request. Every child is reaped by a bounded stop (SIGTERM on POSIX, an IPC
 * {cmd:"stop"} on win32 where SIGTERM is TerminateProcess; then SIGKILL).
 *
 * Child side (only when argv carries the flag; importing this file — e.g. when `node --test test/`
 * loads it — has no side effect):
 *   store-hold      openStore on spec.dir via the REAL src/store.js, optionally commit spec.requests,
 *                   report ready, then idle until graceful stop → store.close() → "closed" → exit 0.
 *   transport-send  createTeleptyTransport via the REAL src/index.js with spec.config (+ storeOptions),
 *                   report ready, run one send(spec.send), report the result, idle until graceful stop →
 *                   transport.close() → "closed" → exit 0.
 * A SIGKILL from the parent is the abrupt crash under test; nothing in the child can react to it.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { requestKey } from "./fault-fs.js";

const here = path.dirname(fileURLToPath(import.meta.url));
export const CHILD_HOST = fileURLToPath(import.meta.url);
const FLAG = "--telesession-child-host";
const SRC = path.resolve(here, "..", "..", "src");

// ── Parent side ──

function childLogDir() {
  const dir = process.env.TELESESSION_TEST_LOG_DIR || path.join(os.tmpdir(), "telesession-child-logs");
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

let seq = 0;

function baseEnv() {
  const env = {};
  for (const k of ["PATH", "Path", "SystemRoot", "SYSTEMROOT", "ComSpec", "PATHEXT", "WINDIR", "TMPDIR", "TEMP", "TMP"]) {
    if (process.env[k] !== undefined) env[k] = process.env[k];
  }
  return env;
}

export function startChildHost(mode, spec, { name = mode } = {}) {
  seq += 1;
  const logFile = path.join(childLogDir(), `${process.pid}-${String(seq).padStart(3, "0")}-${name}.log`);
  const fd = fs.openSync(logFile, "w");
  const child = spawn(process.execPath, [CHILD_HOST, FLAG, mode], {
    env: { ...baseEnv(), TELESESSION_CHILD_SPEC: JSON.stringify(spec) },
    stdio: ["ignore", "pipe", fd, "ipc"],
    windowsHide: true,
  });
  fs.closeSync(fd);
  const events = [];
  const waiters = [];
  const exited = new Promise((resolve) => child.once("exit", (code, signal) => resolve({ code, signal })));
  const rl = readline.createInterface({ input: child.stdout });
  rl.on("line", (line) => {
    let ev;
    try { ev = JSON.parse(line); } catch { ev = { event: "unparsed", line }; }
    events.push(ev);
    for (const w of [...waiters]) {
      if (w.pred(ev)) { waiters.splice(waiters.indexOf(w), 1); clearTimeout(w.timer); w.resolve(ev); }
    }
  });

  function nextEvent(pred, timeoutMs = 10000) {
    const hit = events.find(pred);
    if (hit) return Promise.resolve(hit);
    return new Promise((resolve, reject) => {
      const w = { pred, resolve };
      w.timer = setTimeout(() => {
        waiters.splice(waiters.indexOf(w), 1);
        reject(new Error(`child ${name}: event timeout; log ${logFile}`));
      }, timeoutMs);
      waiters.push(w);
      exited.then(() => setTimeout(() => {
        if (waiters.includes(w)) { waiters.splice(waiters.indexOf(w), 1); clearTimeout(w.timer); reject(new Error(`child ${name} exited; log ${logFile}`)); }
      }, 50));
    });
  }

  async function waitExit(timeoutMs = 5000) {
    let timer;
    const r = await Promise.race([exited, new Promise((res) => { timer = setTimeout(() => res(null), timeoutMs); })]);
    clearTimeout(timer);
    return r;
  }

  // Abrupt crash: SIGKILL and wait (bounded) until the OS reports the exit.
  async function crash() {
    try { child.kill("SIGKILL"); } catch { /* gone */ }
    return waitExit(5000);
  }

  // Graceful stop with a bound: SIGTERM (POSIX) or an IPC stop request (win32), then SIGKILL.
  // On win32 child.kill("SIGTERM") is TerminateProcess, so the child's SIGTERM handler would never run.
  async function stop(graceMs = 5000) {
    if (child.exitCode === null && child.signalCode === null) {
      if (process.platform === "win32") {
        try { child.send({ cmd: "stop" }, () => { /* send errors: the SIGKILL bound below still reaps */ }); } catch { /* gone */ }
      } else {
        try { child.kill("SIGTERM"); } catch { /* gone */ }
      }
      const r = await waitExit(graceMs);
      if (r === null) await crash();
    }
    rl.close();
    return waitExit(1000);
  }

  return {
    child, pid: child.pid, events, nextEvent, crash, stop, waitExit, logFile,
    readLog: () => { try { return fs.readFileSync(logFile, "utf8"); } catch { return ""; } },
  };
}

// ── Child side ──

function emit(obj) { process.stdout.write(JSON.stringify(obj) + "\n"); }

async function childMain(mode) {
  const spec = JSON.parse(process.env.TELESESSION_CHILD_SPEC || "{}");
  let closeFn = async () => {};
  let stopping = false;
  const gracefulStop = () => {
    if (stopping) return;
    stopping = true;
    Promise.resolve()
      .then(() => closeFn())
      .then((r) => emit({ event: "closed", result: r ?? null }))
      .catch((e) => emit({ event: "closed", error: (e && e.code) || "CLOSE_THREW" }))
      // Exit only after "closed" is flushed: stdout pipe writes may be asynchronous.
      .finally(() => process.stdout.write("", () => process.exit(0)));
  };
  process.on("SIGTERM", gracefulStop);
  process.on("message", (m) => { if (m && m.cmd === "stop") gracefulStop(); });
  const keepAlive = setInterval(() => {}, 1 << 30);

  if (mode === "store-hold") {
    const { openStore } = await import(pathToFileURL(path.join(SRC, "store.js")).href);
    let store;
    try {
      store = openStore({
        dir: spec.dir, origin: spec.origin, inboxPrefix: spec.inboxPrefix,
        persistCredential: !!spec.persistCredential, newInboxId: () => spec.inboxId,
      }, spec.seam || undefined);
    } catch (e) {
      emit({ event: "error", code: (e && e.code) || "THREW" });
      clearInterval(keepAlive);
      process.exit(3);
    }
    closeFn = async () => { store.close(); return null; };
    let commit = null;
    if (Array.isArray(spec.requests) && spec.requests.length) {
      commit = store.commit((draft) => { for (const r of spec.requests) draft.requests[requestKey(r)] = r; });
    }
    emit({ event: "ready", pid: process.pid, commit, generation: store.snapshot().generation });
    return;
  }

  if (mode === "transport-send") {
    const { createTeleptyTransport, normalizeConfig } = await import(pathToFileURL(path.join(SRC, "index.js")).href);
    let transport;
    try {
      transport = createTeleptyTransport(normalizeConfig(spec.config), spec.storeOptions || undefined);
    } catch (e) {
      emit({ event: "error", code: (e && e.code) || "THREW" });
      clearInterval(keepAlive);
      process.exit(3);
    }
    closeFn = () => transport.close();
    emit({ event: "ready", pid: process.pid, inbox_id: transport.inboxId ?? null });
    const result = await transport.send(spec.send);
    emit({ event: "result", result });
    return;
  }

  emit({ event: "error", code: "UNKNOWN_MODE" });
  process.exit(3);
}

if (process.argv[2] === FLAG) {
  childMain(process.argv[3]).catch((e) => {
    emit({ event: "error", code: (e && e.code) || "CHILD_THREW" });
    process.exit(3);
  });
}
