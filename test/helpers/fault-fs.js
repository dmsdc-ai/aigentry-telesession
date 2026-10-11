/**
 * Real-filesystem helpers for the durable-store tests. Native Node only.
 *
 * createFaultFs() wraps the REAL node:fs: every *Sync call goes to the real filesystem unless a
 * targeted rule matches, in which case that one call throws a genuine-looking errno error (code,
 * errno, syscall, and a message that carries the path, like a real fs error, so tests can prove the
 * store never forwards it). Every call is logged with the paths it touched (fds are mapped back to
 * the path they were opened with), so tests can assert what the store did NOT do (no chmod, no
 * unlink/rename of a foreign lock, no write before a refusal). It is passed to openStore through
 * the documented test seam (2nd argument {fs}); it never fakes store behaviour.
 *
 * The R2 state fixtures below build state.json files that follow state_schema_v1 of
 * IMPLEMENTATION-CONTRACT-R2.json field for field, written with the real fs (0700 dir, 0600 file).
 * They simulate what a previous process left on disk; they are not a stand-in for the store.
 * Per CONTRACT-CLARIFICATION-R3 §1 a Request carries no `key` property: its identity is the
 * enclosing requests-map key, derived here independently by requestKey().
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";

// ── Fault-injecting wrapper over the real fs ──

function errnoError(code, op, p) {
  const err = new Error(`${code}: injected fault, ${op.replace(/Sync$/, "")} '${p || ""}'`);
  err.code = code;
  err.errno = os.constants.errno[code] !== undefined ? -os.constants.errno[code] : -1;
  err.syscall = op.replace(/Sync$/, "");
  if (p) err.path = p;
  return err;
}

const opMatches = (ruleOp, op) => ruleOp === "*" || ruleOp === op || (Array.isArray(ruleOp) && ruleOp.includes(op));

export function createFaultFs({ base = fs } = {}) {
  const calls = [];
  const rules = [];
  const fdPaths = new Map();

  function pathsOf(op, args) {
    const out = [];
    const take = (a) => {
      if (typeof a === "string") out.push(path.resolve(a));
      else if (a instanceof URL) out.push(path.resolve(a.pathname));
      else if (Buffer.isBuffer(a) && op !== "writeSync" && op !== "writeFileSync" && op !== "appendFileSync") out.push(path.resolve(a.toString()));
      else if (typeof a === "number" && fdPaths.has(a)) out.push(fdPaths.get(a));
    };
    if (op === "renameSync" || op === "linkSync" || op === "copyFileSync" || op === "symlinkSync") { take(args[0]); take(args[1]); }
    else take(args[0]);
    return out;
  }

  function wrap(op, fn) {
    const wrapped = function (...args) {
      const paths = pathsOf(op, args);
      const ctx = { op, paths, args, base };
      calls.push({ op, paths });
      for (const rule of rules) {
        if (rule.remaining <= 0 || !rule.throws || !opMatches(rule.op, op)) continue;
        if (rule.when && !rule.when(ctx)) continue;
        rule.remaining -= 1;
        rule.hits += 1;
        throw errnoError(rule.errno, op, paths[0]);
      }
      let result = fn.apply(base, args);
      if (op === "openSync" && typeof result === "number" && paths[0]) fdPaths.set(result, paths[0]);
      if (op === "closeSync") fdPaths.delete(args[0]);
      for (const rule of rules) {
        if (rule.remaining <= 0 || !rule.map || !opMatches(rule.op, op)) continue;
        if (rule.when && !rule.when(ctx)) continue;
        rule.remaining -= 1;
        rule.hits += 1;
        result = rule.map(result, ctx);
      }
      return result;
    };
    for (const key of Object.keys(fn)) {
      if (typeof fn[key] === "function") wrapped[key] = wrap(`${op}.${key}`, fn[key]);
    }
    return wrapped;
  }

  const cache = new Map();
  const proxy = new Proxy(base, {
    get(target, prop) {
      const v = target[prop];
      if (typeof prop !== "string" || typeof v !== "function" || !prop.endsWith("Sync")) return v;
      if (!cache.has(prop)) cache.set(prop, wrap(prop, v));
      return cache.get(prop);
    },
  });

  function addRule(rule) {
    const r = { remaining: rule.times ?? 1, hits: 0, ...rule };
    rules.push(r);
    return r;
  }

  return {
    fs: proxy,
    calls,
    // Throw `errno` from the next `times` (default 1) calls of `op` for which `when(ctx)` holds.
    fail: ({ op, when, errno = "ENOSPC", times = 1 }) => addRule({ op, when, errno, times, throws: true }),
    // Rewrite the real result of the next `times` matching calls (e.g. a stat with another uid).
    mapResult: ({ op, when, map, times = Infinity }) => addRule({ op, when, map, times }),
    clear: () => { rules.length = 0; },
    resetCalls: () => { calls.length = 0; },
    callsTouching: (p) => calls.filter((c) => c.paths.some((x) => x === p)),
    mutatingCalls: () => calls.filter((c) => MUTATING.has(c.op.split(".")[0])),
  };
}

const MUTATING = new Set([
  "writeFileSync", "appendFileSync", "writeSync", "renameSync", "unlinkSync", "rmSync", "rmdirSync", "mkdirSync",
  "chmodSync", "fchmodSync", "lchmodSync", "chownSync", "fchownSync", "lchownSync", "utimesSync", "futimesSync",
  "lutimesSync", "truncateSync", "ftruncateSync", "linkSync", "symlinkSync", "copyFileSync", "cpSync", "mkdtempSync",
]);

// Predicates for rules.
export const touches = (re) => (ctx) => ctx.paths.some((p) => re.test(path.basename(p)));
export const renamesOnto = (name) => (ctx) => ctx.op === "renameSync" && ctx.paths[1] && path.basename(ctx.paths[1]) === name;
// A rename onto state.json whose source (the fsynced tmp) contains `needle`: pins one specific commit.
export const renamesStateContaining = (needle) => (ctx) => {
  if (!renamesOnto("state.json")(ctx)) return false;
  try { return ctx.base.readFileSync(ctx.paths[0], "utf8").includes(needle); } catch { return false; }
};
// The open(O_CREAT|O_EXCL)/write of a tmp file in `dir`.
export const tmpIn = (dir) => (ctx) => ctx.paths.some((p) => path.dirname(p) === dir && /\.tmp$/.test(p));

// ── Directory inspection with the real fs ──

export const sha256 = (s) => createHash("sha256").update(typeof s === "string" ? Buffer.from(s, "utf8") : s).digest("hex");

// name → {sha256, mode, size, mtimeMs, nlink, symlink} for every entry under dir (recursive).
export function inspectDir(dir) {
  const out = {};
  const walk = (d, rel) => {
    let names;
    try { names = fs.readdirSync(d); } catch { return; }
    for (const name of names.sort()) {
      const full = path.join(d, name);
      const key = rel ? `${rel}/${name}` : name;
      const st = fs.lstatSync(full);
      if (st.isDirectory()) { out[key + "/"] = { mode: st.mode & 0o777, dir: true }; walk(full, key); continue; }
      out[key] = {
        sha256: st.isSymbolicLink() ? null : sha256(fs.readFileSync(full)),
        mode: st.mode & 0o777, size: st.size, mtimeMs: st.mtimeMs, nlink: st.nlink, symlink: st.isSymbolicLink(),
      };
    }
  };
  walk(dir, "");
  return out;
}

export const tmpLeftovers = (dir) => {
  try { return fs.readdirSync(dir).filter((n) => /\.tmp$/.test(n)); } catch { return []; }
};

// ── Hermetic sandbox: a fake home H, a project cwd P outside H, both under os.tmpdir() ──

export function makeSandbox(prefix = "ts-store-") {
  // Native realpath, as src/store.js uses for its dir: on Windows the JS realpath can keep 8.3 short names /
  // drive-letter case that the native one expands, so exact path predicates would never match the store's calls.
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  const home = path.join(root, "home");
  const project = path.join(root, "work", "project");
  fs.mkdirSync(home, { mode: 0o700 });
  fs.mkdirSync(project, { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(home, ".local", "state"), { recursive: true, mode: 0o700 });
  const stateDir = path.join(home, ".local", "state", "telesession");
  return {
    root, home, project, stateDir,
    // openStore 2nd-arg seam values; bin/production never passes these.
    seam: (extra = {}) => ({ homedir: home, cwd: project, ...extra }),
    remove: () => {
      try { fs.chmodSync(root, 0o700); } catch { /* best effort */ }
      try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
    },
  };
}

// ── R2 state fixtures (state_schema_v1) ──

export const hex = (bytes) => randomBytes(bytes).toString("hex");
export const newInboxId = (prefix) => `${prefix}-i${hex(16)}`;
export const wirePrompt = (nonce, inboxId, text) => `[telesession nonce=${nonce} reply-to=${inboxId}]\n` + text;

const TTL_MS = 15 * 60 * 1000;
const RETAIN_MS = 24 * 60 * 60 * 1000;

export function makeInbox({ prefix = "tsd", id = newInboxId(prefix), phase = "none", epoch = null, generation = null, registered_at = null, gaps = [], orphans = [] } = {}) {
  return { id, phase, epoch, registered_at, gaps, orphans, generation };
}

// One Request record. `sender` = {id, epoch, generation} of the inbox whose bearer sent (or was
// about to send) the inject; payload_sha256 is computed over the exact wire prompt.
export function makeRequest({
  request_id = "req-1", target = "target-1", text = "hello from fixture", sender, state = "reserved",
  created_at = Date.now() - 60_000, nonce = hex(16), ...overrides
} = {}) {
  if (!sender || typeof sender.id !== "string") throw new Error("makeRequest needs sender {id, epoch, generation}");
  const wire = wirePrompt(nonce, sender.id, text);
  const expires = created_at + TTL_MS;
  return {
    request_id, target,
    body_sha256: sha256(text),
    body_len: Buffer.byteLength(text, "utf8"),
    nonce,
    reply_to: sender.id,
    state,
    inject_id: null,
    target_epoch: null,
    created_at,
    sent_at: created_at,
    expires_at: expires,
    retain_until: expires + RETAIN_MS,
    error_code: null,
    http_status: null,
    uncertain_reason: null,
    recovery: null,
    route_interrupted: false,
    reply: { candidates: [], trusted: null },
    quarantined: {},
    payload_sha256: sha256(wire),
    sender_inbox_id: sender.id,
    sender_inbox_epoch: sender.epoch,
    sender_inbox_generation: sender.generation,
    reply_loss_possible: false,
    ...overrides,
  };
}

// The requests-map key of a Request (R3 §1): r:<request_id>, or n:<nonce> when request_id is null.
export const requestKey = (r) => (r.request_id === null ? `n:${r.nonce}` : `r:${r.request_id}`);

export function makeState({ origin, prefix = "tsd", inbox = makeInbox({ prefix }), requests = [], generation = 1, ...overrides } = {}) {
  if (typeof origin !== "string") throw new Error("makeState needs the binding origin");
  const map = {};
  for (const r of requests) map[requestKey(r)] = r;
  return {
    schema: "telesession-state",
    version: 1,
    generation,
    binding: { origin, inbox_prefix: prefix },
    inbox,
    requests: map,
    bound_inject_ids: [],
    retired_nonces: [],
    counters: {},
    ...overrides,
  };
}

// Writes dir (0700) + state.json (0600) as a previous process would have left them. No lock file
// unless `lock` content is given (a raw string, written 0600). Returns the exact state.json bytes.
export function writeStateDir(dir, state, { lock, raw } = {}) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700);
  const bytes = Buffer.from(raw !== undefined ? raw : JSON.stringify(state), "utf8");
  fs.writeFileSync(path.join(dir, "state.json"), bytes, { mode: 0o600 });
  fs.chmodSync(path.join(dir, "state.json"), 0o600);
  if (lock !== undefined) writeLockFile(dir, lock);
  return bytes;
}

export function writeLockFile(dir, content) {
  const p = path.join(dir, "lock");
  fs.writeFileSync(p, content, { mode: 0o600 });
  fs.chmodSync(p, 0o600);
  return p;
}

export const foreignLock = ({ owner = hex(16), pid = 999999, created_at = new Date().toISOString() } = {}) =>
  JSON.stringify({ v: 1, owner, pid, created_at });

export const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
