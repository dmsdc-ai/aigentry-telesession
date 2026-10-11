/**
 * telesession tunnel child launcher — builds a clean environment for the packaged telesession-mcp
 * entry and runs it as an owned stdio child. This filters the CHILD environment only: it is not an
 * OS sandbox and does not sanitize this already-started process. Pure construction (env, argv,
 * spawn plan) is separate from the side-effecting lifecycle so both can be tested with fakes.
 * Diagnostics are stable codes only: no env values, paths or error stacks.
 */

import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Exactly the keys src/config.js reads, except TELESESSION_TELEPTY_TOKEN (refused, never forwarded).
export const CHILD_CONFIG_KEYS = Object.freeze([
  "TELESESSION_TELEPTY_URL",
  "TELESESSION_TELEPTY_TOKEN_FILE",
  "TELESESSION_TARGETS",
  "TELESESSION_INBOX_PREFIX",
  "TELESESSION_STATE_DIR",
  "TELESESSION_PERSIST_INBOX_CREDENTIAL",
]);
const WIN32_PLATFORM_KEYS = Object.freeze(["SystemRoot", "WINDIR", "TEMP", "TMP"]);
const POSIX_PLATFORM_KEYS = Object.freeze(["TMPDIR", "LANG", "LC_ALL"]);
const TOKEN_KEY = "TELESESSION_TELEPTY_TOKEN";
const TOKEN_FILE_KEY = "TELESESSION_TELEPTY_TOKEN_FILE";
const DEFAULT_GRACE_MS = 5000;

export class TunnelChildError extends Error {
  constructor(code) {
    super(code);
    this.name = "TunnelChildError";
    this.code = code;
  }
}

// Own keys of `env` matching `name`: case-insensitively on win32 (its env is case-insensitive), exact elsewhere.
function lookup(env, keys, name, win32) {
  const upper = name.toUpperCase();
  const hits = keys.filter((k) => (win32 ? k.toUpperCase() === upper : k === name));
  if (hits.length > 1) throw new TunnelChildError("TUNNEL_CHILD_ENV_AMBIGUOUS");
  if (hits.length === 0) return undefined;
  const value = env[hits[0]];
  if (typeof value !== "string" || value.includes("\u0000")) throw new TunnelChildError("TUNNEL_CHILD_ENV_INVALID");
  return value;
}

// Pure: parent env in, new null-prototype child env out (or TunnelChildError). Never mutates `env`.
export function buildChildEnv(env, { platform = process.platform } = {}) {
  const e = env || {};
  const keys = Object.keys(e);
  const win32 = platform === "win32";
  const token = lookup(e, keys, TOKEN_KEY, win32);
  if (token !== undefined && token !== "") throw new TunnelChildError("TUNNEL_CHILD_TOKEN_VALUE_FORBIDDEN");
  const tokenFile = lookup(e, keys, TOKEN_FILE_KEY, win32);
  if (tokenFile === undefined || tokenFile === "") throw new TunnelChildError("TUNNEL_CHILD_TOKEN_FILE_REQUIRED");
  if (!(win32 ? path.win32 : path.posix).isAbsolute(tokenFile)) throw new TunnelChildError("TUNNEL_CHILD_TOKEN_FILE_INVALID");
  // Null prototype: spawn enumerates env with for..in, so inherited properties must not exist.
  const child = Object.create(null);
  for (const name of [...CHILD_CONFIG_KEYS, ...(win32 ? WIN32_PLATFORM_KEYS : POSIX_PLATFORM_KEYS)]) {
    const value = lookup(e, keys, name, win32);
    if (value !== undefined) child[name] = value;
  }
  return child;
}

export function assertNoArgs(argv) {
  if (!Array.isArray(argv) || argv.length !== 0) throw new TunnelChildError("TUNNEL_CHILD_ARGS_UNEXPECTED");
}

// The fixed packaged MCP entry next to this module; `toPath` is injectable for host-independent tests.
export function resolveMcpEntry(moduleUrl = import.meta.url, toPath = fileURLToPath) {
  return toPath(new URL("../bin/telesession-mcp.js", moduleUrl));
}

// Pure: the complete spawn description. Command and args are fixed; nothing here is overridable.
export function buildSpawnPlan({ argv, env, platform = process.platform, execPath, entryPath } = {}) {
  assertNoArgs(argv);
  const P = platform === "win32" ? path.win32 : path.posix;
  for (const p of [execPath, entryPath]) {
    if (typeof p !== "string" || p.includes("\u0000") || !P.isAbsolute(p)) throw new TunnelChildError("TUNNEL_CHILD_ENTRY_INVALID");
  }
  return Object.freeze({
    command: execPath,
    args: Object.freeze([entryPath]),
    options: Object.freeze({ env: buildChildEnv(env, { platform }), stdio: "inherit", shell: false, detached: false }),
  });
}

// POSIX shell convention for a signal-terminated child: 128 + signal number.
export function exitCodeFor(code, signal) {
  if (typeof code === "number") return code;
  const n = signal ? os.constants.signals[signal] : undefined;
  return typeof n === "number" ? 128 + n : 1;
}

/**
 * Side effects: spawn the planned child and settle with the exit code this process should use.
 * Only the owned child is ever signalled. POSIX: a received signal is forwarded once, then SIGKILL
 * after `graceMs`. win32: child.kill() is TerminateProcess (no graceful signal exists), so nothing
 * is forwarded at once — the child already shares the console and stdin — and it is terminated
 * only if still alive after `graceMs`.
 */
export function runChild(plan, {
  spawn, signals = process, platform = process.platform, graceMs = DEFAULT_GRACE_MS,
  setTimer = setTimeout, clearTimer = clearTimeout, onDiagnostic = () => {},
} = {}) {
  return new Promise((resolve) => {
    const win32 = platform === "win32";
    const names = win32 ? ["SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK"] : ["SIGINT", "SIGTERM", "SIGHUP"];
    const bound = [];
    let child = null;
    let timer = null;
    let done = false;

    const finish = (code) => {
      if (done) return;
      done = true;
      if (timer !== null) clearTimer(timer);
      for (const [name, fn] of bound) {
        try { signals.removeListener(name, fn); } catch { /* not removable on this platform */ }
      }
      resolve(code);
    };
    const kill = (sig) => {
      try { child.kill(sig); } catch { /* already gone; exit settles */ }
    };
    const onSignal = (name) => {
      if (done || timer !== null) return;
      if (!win32) kill(name);
      timer = setTimer(() => kill(win32 ? undefined : "SIGKILL"), graceMs);
    };

    try {
      child = spawn(plan.command, [...plan.args], { ...plan.options });
    } catch {
      onDiagnostic("TUNNEL_CHILD_SPAWN_FAILED");
      finish(1);
      return;
    }
    child.once("exit", (code, signal) => finish(exitCodeFor(code, signal)));
    child.on("error", () => {
      // Before a pid exists this is a spawn failure; later errors (e.g. kill) are settled by "exit".
      if (child.pid !== undefined) return;
      onDiagnostic("TUNNEL_CHILD_SPAWN_FAILED");
      finish(1);
    });
    for (const name of names) {
      const fn = () => onSignal(name);
      try { signals.on(name, fn); bound.push([name, fn]); } catch { /* signal not supported on this platform */ }
    }
  });
}
