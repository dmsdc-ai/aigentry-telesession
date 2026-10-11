/**
 * telesession durable store (SPEC-R2 §3–§5, IMPLEMENTATION-CONTRACT-R2 apis.store). One private state
 * directory per inbox binding: strict single-writer lock, schema-validated state.json, reply files and an
 * opt-in POSIX-only inbox credential, all written atomically (tmp + fsync + rename + dir fsync).
 *
 * Never persisted: telepty token, receiver port/secret path, prompt text, pid as proof. Errors carry a code
 * and at most an errno NAME — never a path. The lock is strict: EEXIST is STORE_LOCKED regardless of age,
 * pid or content; nothing here ever renames, reclaims or unlinks a lock it does not own. After an abrupt
 * crash the lock stays and every open is STORE_LOCKED: automatic unlock/restart is NOT PROVIDED.
 *
 * Node >= 20 builtins only. Synchronous. The second openStore argument is a test seam only.
 */

import nodeFs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";

export const STORE_SCHEMA = "telesession-state";
export const STORE_VERSION = 1;
export const STORE_LIMITS = Object.freeze({
  requests: 1024, replies: 64, replyTextBytes: 65536, replyFileBytes: 98304, stateBytes: 1048576,
  retainMs: 86400000, gaps: 32, orphans: 16, boundInjectIds: 1024, retiredNonces: 256,
});

const LOCK_BYTES = 4096;
const CREDENTIAL_BYTES = 16 * 1024;
const NAMED_INT_MAX = 64;
const CANDIDATES_MAX = 4;
const DIR_MAX_CHARS = 512;
const RENAME_RETRY_MS = [25, 50, 100];
const RENAME_RETRY_CODES = new Set(["EPERM", "EBUSY", "EACCES"]);
const DIR_FSYNC_IGNORED = new Set(["EISDIR", "EPERM", "EINVAL", "EBADF"]);

const HEX32_RE = /^[0-9a-f]{32}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const SID_RE = /^[A-Za-z0-9._-]{1,128}$/;
const REQUEST_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const INJECT_ID_RE = /^[A-Za-z0-9-]{1,128}$/;
const NAME_RE = /^[a-z][a-z0-9_]{0,63}$/;
const CODE_RE = /^[A-Z0-9_]{1,64}$/;
const ERRNO_RE = /^E[A-Z0-9]{1,31}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/;
const PREFIX_RE = /^[A-Za-z0-9._]{1,48}$/;
const ORIGIN_RE = /^http:\/\/(?:127(?:\.\d{1,3}){3}|\[::1\]):[1-9]\d{0,4}$/;
const BEARER_RE = /^[\x21-\x7E]{1,4096}$/;
const CTRL_RE = /[\x00-\x1f\x7f]/;
const STATE_TMP_RE = /^\.(?:state|credential)\.json\.[0-9a-f]{16}\.tmp$/;
const REPLY_NAME_RE = /^[0-9a-f]{32}-[0-9a-f]{64}\.json$/;
const REPLY_TMP_RE = /^\.[0-9a-f]{32}-[0-9a-f]{64}\.json\.[0-9a-f]{16}\.tmp$/;

const TOP_KEYS = ["schema", "version", "generation", "binding", "inbox", "requests", "bound_inject_ids", "retired_nonces", "counters"];
const INBOX_KEYS = ["id", "phase", "epoch", "registered_at", "gaps", "orphans", "generation"];
const REQUEST_KEYS = [
  "request_id", "target", "body_sha256", "body_len", "nonce", "reply_to", "state", "inject_id", "target_epoch",
  "created_at", "sent_at", "expires_at", "retain_until", "error_code", "http_status", "uncertain_reason", "recovery",
  "route_interrupted", "reply", "quarantined", "payload_sha256", "sender_inbox_id", "sender_inbox_epoch",
  "sender_inbox_generation", "reply_loss_possible",
];
const PHASES = new Set(["none", "registering", "ready", "deleting", "deleted", "unknown", "collided"]);
const GAP_CAUSES = new Set(["inbox_absent", "process_restart", "reattached", "rotated"]);
const ORPHAN_CAUSES = new Set(["registration_unknown", "collided", "credential_absent", "owned_delete_forbidden"]);
const REQUEST_STATES = new Set(["reserved", "accepted", "refused", "uncertain", "answered", "expired"]);
const UNCERTAIN_REASONS = new Set([null, "no_response", "exact_routing_unconfirmed", "process_restart"]);
const RECOVERIES = new Set([null, "audit_verified_match", "not_found", "ambiguous", "unverified", "audit_unavailable"]);

export class StoreError extends Error {
  constructor(code, errno) {
    super(code);
    this.name = "StoreError";
    this.code = code;
    if (errno) this.errno = errno;
  }
}

function errnoName(err) {
  const c = err && err.code;
  return typeof c === "string" && ERRNO_RE.test(c) ? c : undefined;
}

function fail(code, errno) {
  return errno ? { ok: false, code, errno } : { ok: false, code };
}

function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

// ── Strict shape helpers: own enumerable data properties only, plain prototypes, no symbols ──

function plainKeys(v) {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return null;
  const proto = Object.getPrototypeOf(v);
  if (proto !== Object.prototype && proto !== null) return null;
  if (Object.getOwnPropertySymbols(v).length !== 0) return null;
  const names = Object.getOwnPropertyNames(v);
  for (const k of names) {
    const d = Object.getOwnPropertyDescriptor(v, k);
    if (!d.enumerable || !("value" in d)) return null;
  }
  return names;
}

function exactKeys(v, keys) {
  const names = plainKeys(v);
  return names !== null && names.length === keys.length && keys.every((k) => Object.prototype.hasOwnProperty.call(v, k));
}

function plainList(v, max) {
  if (!Array.isArray(v) || Object.getPrototypeOf(v) !== Array.prototype || v.length > max) return false;
  if (Object.getOwnPropertySymbols(v).length !== 0 || Object.getOwnPropertyNames(v).length !== v.length + 1) return false;
  for (let i = 0; i < v.length; i++) {
    const d = Object.getOwnPropertyDescriptor(v, i);
    if (!d || !("value" in d)) return false;
  }
  return true;
}

const isStr = (v, re) => typeof v === "string" && re.test(v);
const isInt = (v) => Number.isSafeInteger(v) && v >= 0;
const isIntOrNull = (v) => v === null || isInt(v);
const isBool = (v) => typeof v === "boolean";
const isIso = (v) => isStr(v, ISO_RE) && Number.isFinite(Date.parse(v));
const isIsoOrNull = (v) => v === null || isIso(v);
const isEpoch = (v) => typeof v === "string" && v.length >= 1 && v.length <= 256 && !CTRL_RE.test(v);
const isEpochOrNull = (v) => v === null || isEpoch(v);
const isSid = (v) => isStr(v, SID_RE) && !/^\.+$/.test(v);

function isInboxId(v, prefix) {
  return typeof v === "string" && v.length === prefix.length + 34 && v.startsWith(prefix + "-i")
    && HEX32_RE.test(v.slice(prefix.length + 2));
}

function isNamedInts(v) {
  const names = plainKeys(v);
  return names !== null && names.length <= NAMED_INT_MAX && names.every((k) => NAME_RE.test(k) && isInt(v[k]));
}

function isInbox(v, prefix) {
  if (!exactKeys(v, INBOX_KEYS)) return false;
  if (!isInboxId(v.id, prefix) || !PHASES.has(v.phase) || !isEpochOrNull(v.epoch) || !isIsoOrNull(v.registered_at)
      || !isIntOrNull(v.generation)) return false;
  if (!plainList(v.gaps, STORE_LIMITS.gaps) || !plainList(v.orphans, STORE_LIMITS.orphans)) return false;
  return v.gaps.every((g) => exactKeys(g, ["at", "cause", "audit_since"]) && isIso(g.at) && GAP_CAUSES.has(g.cause) && isIso(g.audit_since))
    && v.orphans.every((o) => exactKeys(o, ["id", "cause"]) && isInboxId(o.id, prefix) && ORPHAN_CAUSES.has(o.cause));
}

function isReply(v) {
  if (!exactKeys(v, ["candidates", "trusted"]) || !plainList(v.candidates, CANDIDATES_MAX)) return false;
  if (!v.candidates.every((c) => exactKeys(c, ["sha256", "received_at", "attempt"])
      && isStr(c.sha256, HEX64_RE) && isIso(c.received_at) && isInt(c.attempt))) return false;
  const t = v.trusted;
  if (t === null) return true;
  return exactKeys(t, ["sha256", "inject_id", "verified_sender", "received_at"]) && isStr(t.sha256, HEX64_RE)
    && isStr(t.inject_id, INJECT_ID_RE) && isIso(t.received_at)
    && exactKeys(t.verified_sender, ["sid", "generation"]) && isSid(t.verified_sender.sid) && isIntOrNull(t.verified_sender.generation);
}

function isRequest(key, r, prefix) {
  if (!exactKeys(r, REQUEST_KEYS)) return false;
  if (r.request_id === null) {
    if (!isStr(r.nonce, HEX32_RE) || key !== "n:" + r.nonce) return false;
  } else if (!isStr(r.request_id, REQUEST_ID_RE) || key !== "r:" + r.request_id) {
    return false;
  }
  return isSid(r.target) && isStr(r.body_sha256, HEX64_RE) && isInt(r.body_len) && isStr(r.nonce, HEX32_RE)
    && isInboxId(r.reply_to, prefix) && REQUEST_STATES.has(r.state)
    && (r.inject_id === null || isStr(r.inject_id, INJECT_ID_RE)) && isEpochOrNull(r.target_epoch)
    && isInt(r.created_at) && isInt(r.sent_at) && isInt(r.expires_at) && isInt(r.retain_until)
    && (r.error_code === null || isStr(r.error_code, CODE_RE))
    && (r.http_status === null || (Number.isSafeInteger(r.http_status) && r.http_status >= 100 && r.http_status <= 599))
    && UNCERTAIN_REASONS.has(r.uncertain_reason) && RECOVERIES.has(r.recovery) && isBool(r.route_interrupted)
    && isReply(r.reply) && isNamedInts(r.quarantined) && isStr(r.payload_sha256, HEX64_RE)
    && isInboxId(r.sender_inbox_id, prefix) && isEpoch(r.sender_inbox_epoch) && isInt(r.sender_inbox_generation)
    && isBool(r.reply_loss_possible);
}

function isState(s) {
  if (!exactKeys(s, TOP_KEYS) || s.schema !== STORE_SCHEMA || s.version !== STORE_VERSION || !isInt(s.generation)) return false;
  const b = s.binding;
  if (!exactKeys(b, ["origin", "inbox_prefix"]) || !isStr(b.origin, ORIGIN_RE) || !isStr(b.inbox_prefix, PREFIX_RE)) return false;
  if (!isInbox(s.inbox, b.inbox_prefix)) return false;
  const keys = plainKeys(s.requests);
  if (keys === null || keys.length > STORE_LIMITS.requests) return false;
  const nonces = new Set();
  for (const k of keys) {
    const r = s.requests[k];
    if (!isRequest(k, r, b.inbox_prefix) || nonces.has(r.nonce)) return false;
    nonces.add(r.nonce);
  }
  return plainList(s.bound_inject_ids, STORE_LIMITS.boundInjectIds) && s.bound_inject_ids.every((x) => isStr(x, INJECT_ID_RE))
    && plainList(s.retired_nonces, STORE_LIMITS.retiredNonces) && s.retired_nonces.every((x) => isStr(x, HEX32_RE))
    && isNamedInts(s.counters);
}

function isCredential(c, prefix) {
  return exactKeys(c, ["v", "inbox_id", "epoch", "generation", "bearer"]) && c.v === 1 && isInboxId(c.inbox_id, prefix)
    && isEpoch(c.epoch) && isIntOrNull(c.generation) && isStr(c.bearer, BEARER_RE);
}

function deepFreeze(v) {
  if (v !== null && typeof v === "object") {
    for (const k of Object.keys(v)) deepFreeze(v[k]);
    Object.freeze(v);
  }
  return v;
}

function decodeJson(buf) {
  // fatal: invalid UTF-8 is corruption; ignoreBOM: a BOM is kept and fails JSON.parse (we never write one).
  return JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(buf));
}

// ── Lexical + path predicate (SPEC-R2 §2, §3) ──

function lexicalOk(dir, P, win32) {
  if (typeof dir !== "string" || dir.length < 1 || dir.length > DIR_MAX_CHARS || CTRL_RE.test(dir)) return false;
  if (!P.isAbsolute(dir) || P.normalize(dir) !== dir) return false;
  if (dir.endsWith(P.sep) || (win32 && dir.endsWith("/"))) return false;
  if (win32 && (dir.startsWith("\\\\") || dir.startsWith("//") || /^[A-Za-z]:(?![\\/])/.test(dir))) return false;
  return true;
}

function makePredicate(P, win32, H, C, T) {
  const norm = (p) => (win32 ? p.toLowerCase() : p);
  const same = (a, b) => norm(a) === norm(b);
  const inside = (a, b) => {
    const rel = P.relative(norm(b), norm(a));
    return rel !== "" && rel !== ".." && !rel.startsWith(".." + P.sep) && !P.isAbsolute(rel);
  };
  const isRoot = (p) => P.parse(p).root === p;
  const project = !isRoot(C) && !same(C, H) && !inside(H, C);
  return (R) => isRoot(R) || same(R, H) || same(R, C) || inside(H, R) || inside(C, R)
    || T.some((t) => inside(t, R) || same(R, t) || inside(R, t))
    || (project && inside(R, C));
}

// ── Store ──

export function openStore(opts, seams) {
  const { dir, origin, inboxPrefix, newInboxId } = opts || {};
  const persistCredential = Boolean(opts) && opts.persistCredential === true;
  const s = seams || {};
  const fsx = s.fs || nodeFs;
  const now = s.now || Date.now;
  const platform = s.platform || process.platform;
  const cwd = s.cwd !== undefined ? s.cwd : process.cwd();
  const homedir = s.homedir !== undefined ? s.homedir : os.homedir();
  const win32 = platform === "win32";
  const P = win32 ? path.win32 : path.posix;
  const C_ = fsx.constants || nodeFs.constants;
  const NOFOLLOW = typeof C_.O_NOFOLLOW === "number" ? C_.O_NOFOLLOW : 0;
  const realpath = (p) => (typeof fsx.realpathSync.native === "function" ? fsx.realpathSync.native(p) : fsx.realpathSync(p));
  const uid = typeof process.getuid === "function" ? process.getuid() : null;

  if (!isStr(origin, ORIGIN_RE) || !isStr(inboxPrefix, PREFIX_RE) || typeof newInboxId !== "function") {
    throw new StoreError("STORE_BINDING_MISMATCH");
  }
  if (!lexicalOk(dir, P, win32)) throw new StoreError("STORE_PATH_FORBIDDEN");

  function privateOk(st) {
    return win32 || (uid !== null && st.uid === uid && (st.mode & 0o077) === 0);
  }

  // Bounded, no-follow, single-link read. Limit is applied from lstat/fstat BEFORE any buffer allocation.
  function readBounded(file, limit) {
    let st;
    try { st = fsx.lstatSync(file); } catch (err) {
      return err && err.code === "ENOENT" ? { status: "missing" } : { status: "bad", errno: errnoName(err) };
    }
    if (st.isSymbolicLink() || !st.isFile() || st.nlink !== 1 || st.size > limit) return { status: "bad" };
    let fd = null;
    try {
      fd = fsx.openSync(file, C_.O_RDONLY | NOFOLLOW);
      const fst = fsx.fstatSync(fd);
      if (!fst.isFile() || fst.nlink !== 1 || fst.size > limit
          || (!win32 && (fst.ino !== st.ino || fst.dev !== st.dev))) return { status: "bad" };
      const buf = Buffer.alloc(fst.size + 1);
      let off = 0;
      for (;;) {
        const n = fsx.readSync(fd, buf, off, buf.length - off, null);
        if (n <= 0) break;
        off += n;
        if (off === buf.length) return { status: "bad" }; // grew while reading
      }
      return { status: "ok", buf: buf.subarray(0, off) };
    } catch (err) {
      return { status: "bad", errno: errnoName(err) };
    } finally {
      if (fd !== null) { try { fsx.closeSync(fd); } catch { /* already closed */ } }
    }
  }

  function syncDir(dirPath) {
    let fd;
    try { fd = fsx.openSync(dirPath, "r"); } catch (err) {
      if (DIR_FSYNC_IGNORED.has(err && err.code)) return;
      throw err;
    }
    try { fsx.fsyncSync(fd); } catch (err) {
      if (!DIR_FSYNC_IGNORED.has(err && err.code)) throw err;
    } finally {
      try { fsx.closeSync(fd); } catch { /* best effort */ }
    }
  }

  function renameWithRetry(from, to) {
    for (let i = 0; ; i++) {
      try { fsx.renameSync(from, to); return; } catch (err) {
        if (!win32 || i >= RENAME_RETRY_MS.length || !RENAME_RETRY_CODES.has(err && err.code)) throw err;
        sleepSync(RENAME_RETRY_MS[i]);
      }
    }
  }

  // tmp (O_EXCL, no-follow, 0600) → write → fsync → close → rename → dir fsync. Failure leaves no tmp.
  function atomicWrite(file, bytes) {
    const dirPath = path.dirname(file);
    const tmp = path.join(dirPath, `.${path.basename(file)}.${randomBytes(8).toString("hex")}.tmp`);
    let fd = null;
    let renamed = false;
    try {
      fd = fsx.openSync(tmp, C_.O_WRONLY | C_.O_CREAT | C_.O_EXCL | NOFOLLOW, 0o600);
      let off = 0;
      while (off < bytes.length) {
        const n = fsx.writeSync(fd, bytes, off, bytes.length - off);
        if (!(n > 0)) throw Object.assign(new Error("EIO"), { code: "EIO" });
        off += n;
      }
      fsx.fsyncSync(fd);
      const closing = fd;
      fd = null;
      fsx.closeSync(closing);
      renameWithRetry(tmp, file);
      renamed = true;
      syncDir(dirPath);
      return { ok: true };
    } catch (err) {
      if (fd !== null) { try { fsx.closeSync(fd); } catch { /* best effort */ } }
      if (!renamed) { try { fsx.unlinkSync(tmp); } catch { /* never created or already gone */ } }
      return fail("STORE_WRITE_FAILED", errnoName(err));
    }
  }

  // ── Path checks (SPEC-R2 §3). Run before mkdir on realpath(parent)/leaf and again after it. ──

  function realOr(p) {
    try { return realpath(p); } catch { return P.normalize(p); }
  }
  if (typeof homedir !== "string" || !P.isAbsolute(homedir) || typeof cwd !== "string" || !P.isAbsolute(cwd)) {
    throw new StoreError("STORE_PATH_FORBIDDEN");
  }
  const H = realOr(homedir);
  const C = realOr(cwd);
  const T = [P.join(H, ".telepty"), P.join(H, ".config", "aigentry-telepty"), P.join(H, ".aigentry", "mailbox")].map(realOr);
  const forbidden = makePredicate(P, win32, H, C, T);

  let parentReal;
  try {
    const parent = path.dirname(dir);
    if (!fsx.statSync(parent).isDirectory()) throw new StoreError("STORE_PATH_FORBIDDEN");
    parentReal = realpath(parent);
  } catch (err) {
    throw new StoreError("STORE_PATH_FORBIDDEN", errnoName(err));
  }

  function inspectLeaf() {
    let st = null;
    try { st = fsx.lstatSync(dir); } catch (err) {
      if (!err || err.code !== "ENOENT") throw new StoreError("STORE_PATH_FORBIDDEN", errnoName(err));
    }
    if (st && (st.isSymbolicLink() || !st.isDirectory())) throw new StoreError("STORE_PATH_FORBIDDEN");
    let R;
    try { R = st ? realpath(dir) : path.join(parentReal, path.basename(dir)); } catch (err) {
      throw new StoreError("STORE_PATH_FORBIDDEN", errnoName(err));
    }
    if (forbidden(R)) throw new StoreError("STORE_PATH_FORBIDDEN");
    if (st && !privateOk(st)) throw new StoreError("STORE_PERMISSIONS_INVALID");
    if (persistCredential && win32) throw new StoreError("STORE_CREDENTIAL_PLATFORM_UNSUPPORTED");
    return { exists: st !== null, R };
  }

  let leaf = inspectLeaf();
  if (!leaf.exists) {
    try { fsx.mkdirSync(dir, { mode: 0o700 }); } catch (err) {
      if (!err || err.code !== "EEXIST") throw new StoreError("STORE_WRITE_FAILED", errnoName(err));
    }
    leaf = inspectLeaf();
    if (!leaf.exists) throw new StoreError("STORE_PATH_FORBIDDEN");
  }
  const R = leaf.R;
  const lockPath = path.join(R, "lock");
  const statePath = path.join(R, "state.json");
  const credentialPath = path.join(R, "credential.json");
  const repliesPath = path.join(R, "replies");

  // ── Lock: O_EXCL create; EEXIST is STORE_LOCKED, always. ──
  const owner = randomBytes(16).toString("hex");
  let lockFd;
  try { lockFd = fsx.openSync(lockPath, "wx", 0o600); } catch (err) {
    if (err && err.code === "EEXIST") throw new StoreError("STORE_LOCKED");
    throw new StoreError("STORE_WRITE_FAILED", errnoName(err));
  }
  try {
    const bytes = Buffer.from(JSON.stringify({ v: 1, owner, pid: process.pid, created_at: new Date(now()).toISOString() }), "utf8");
    let off = 0;
    while (off < bytes.length) {
      const n = fsx.writeSync(lockFd, bytes, off, bytes.length - off);
      if (!(n > 0)) throw Object.assign(new Error("EIO"), { code: "EIO" });
      off += n;
    }
    fsx.fsyncSync(lockFd);
  } catch (err) {
    try { fsx.closeSync(lockFd); } catch { /* best effort */ }
    // Created by this call with O_EXCL a moment ago: ours to remove.
    try { fsx.unlinkSync(lockPath); } catch { /* best effort */ }
    throw new StoreError("STORE_WRITE_FAILED", errnoName(err));
  }
  try { fsx.closeSync(lockFd); } catch { /* fsync already done */ }
  try { syncDir(R); } catch { /* lock durability is not load-bearing */ }

  let lost = false;
  let closed = false;

  function ownerMatches() {
    const r = readBounded(lockPath, LOCK_BYTES);
    if (r.status !== "ok") return false;
    try {
      const j = decodeJson(r.buf);
      return plainKeys(j) !== null && j.v === 1 && j.owner === owner;
    } catch {
      return false;
    }
  }

  // Pre-write check: defensive, not authority. A miss is sticky.
  function lockHeld() {
    if (lost || closed) return false;
    if (!ownerMatches()) lost = true;
    return !lost;
  }

  function releaseLock() {
    if (lost || !ownerMatches()) return;
    try { fsx.unlinkSync(lockPath); } catch { return; }
    try { syncDir(R); } catch { /* best effort */ }
  }

  function sweep(dirPath, re) {
    let names;
    try { names = fsx.readdirSync(dirPath); } catch { return; }
    for (const name of names) {
      if (!re.test(name)) continue;
      const p = path.join(dirPath, name);
      try { if (fsx.lstatSync(p).isFile()) fsx.unlinkSync(p); } catch { /* best effort */ }
    }
  }

  let state;
  try {
    let rst = null;
    try { rst = fsx.lstatSync(repliesPath); } catch (err) {
      if (!err || err.code !== "ENOENT") throw new StoreError("STORE_CORRUPT", errnoName(err));
    }
    if (rst && (rst.isSymbolicLink() || !rst.isDirectory())) throw new StoreError("STORE_CORRUPT");
    if (rst && !privateOk(rst)) throw new StoreError("STORE_PERMISSIONS_INVALID");

    sweep(R, STATE_TMP_RE);
    if (rst) sweep(repliesPath, REPLY_TMP_RE);

    const r = readBounded(statePath, STORE_LIMITS.stateBytes);
    if (r.status === "missing") {
      let id;
      try { id = newInboxId(); } catch { throw new StoreError("STORE_BINDING_MISMATCH"); }
      if (!isInboxId(id, inboxPrefix)) throw new StoreError("STORE_BINDING_MISMATCH");
      state = {
        schema: STORE_SCHEMA, version: STORE_VERSION, generation: 0,
        binding: { origin, inbox_prefix: inboxPrefix },
        inbox: { id, phase: "none", epoch: null, registered_at: null, gaps: [], orphans: [], generation: null },
        requests: {}, bound_inject_ids: [], retired_nonces: [], counters: {},
      };
    } else if (r.status !== "ok") {
      throw new StoreError("STORE_CORRUPT", r.errno);
    } else {
      let parsed;
      try { parsed = decodeJson(r.buf); } catch { throw new StoreError("STORE_CORRUPT"); }
      if (plainKeys(parsed) === null || parsed.schema !== STORE_SCHEMA) throw new StoreError("STORE_CORRUPT");
      if (parsed.version !== STORE_VERSION) throw new StoreError("STORE_VERSION_UNSUPPORTED");
      if (!isState(parsed)) throw new StoreError("STORE_CORRUPT");
      if (parsed.binding.origin !== origin || parsed.binding.inbox_prefix !== inboxPrefix) {
        throw new StoreError("STORE_BINDING_MISMATCH");
      }
      state = parsed;
    }
    deepFreeze(state);
  } catch (err) {
    releaseLock();
    if (err instanceof StoreError) throw err;
    throw new StoreError("STORE_CORRUPT", errnoName(err));
  }

  function replyFile(nonce, sha256) {
    return path.join(repliesPath, `${nonce}-${sha256}.json`);
  }

  function readReplyFile(nonce, sha256) {
    const r = readBounded(replyFile(nonce, sha256), STORE_LIMITS.replyFileBytes);
    if (r.status === "missing") return fail("REPLY_MISSING");
    if (r.status !== "ok") return fail("REPLY_CORRUPT", r.errno);
    let j;
    try { j = decodeJson(r.buf); } catch { return fail("REPLY_CORRUPT"); }
    if (!exactKeys(j, ["v", "nonce", "sha256", "received_at", "text"]) || j.v !== 1 || j.nonce !== nonce
        || j.sha256 !== sha256 || typeof j.text !== "string" || !isIso(j.received_at)
        || Buffer.byteLength(j.text, "utf8") > STORE_LIMITS.replyTextBytes
        || createHash("sha256").update(j.text, "utf8").digest("hex") !== sha256) {
      return fail("REPLY_CORRUPT");
    }
    return { ok: true, text: j.text, received_at: j.received_at };
  }

  // Counts reply files without materializing an unbounded listing; stops once the limit is reached.
  function replyCountReached() {
    if (typeof fsx.opendirSync !== "function") {
      let names;
      try { names = fsx.readdirSync(repliesPath); } catch (err) {
        if (err && err.code === "ENOENT") return false;
        throw err;
      }
      return names.filter((n) => REPLY_NAME_RE.test(n)).length >= STORE_LIMITS.replies;
    }
    let d;
    try { d = fsx.opendirSync(repliesPath); } catch (err) {
      if (err && err.code === "ENOENT") return false;
      throw err;
    }
    let count = 0;
    try {
      for (let e = d.readSync(); e !== null; e = d.readSync()) {
        if (REPLY_NAME_RE.test(e.name) && ++count >= STORE_LIMITS.replies) return true;
      }
      return false;
    } finally {
      try { d.closeSync(); } catch { /* best effort */ }
    }
  }

  function ensureRepliesDir() {
    let st = null;
    try { st = fsx.lstatSync(repliesPath); } catch (err) {
      if (!err || err.code !== "ENOENT") throw err;
    }
    if (!st) {
      try { fsx.mkdirSync(repliesPath, { mode: 0o700 }); } catch (err) {
        if (!err || err.code !== "EEXIST") throw err;
      }
      syncDir(R);
      st = fsx.lstatSync(repliesPath);
    }
    return !st.isSymbolicLink() && st.isDirectory() && privateOk(st);
  }

  return Object.freeze({
    snapshot() {
      return state;
    },

    commit(mutator) {
      try {
        if (closed || lost) return fail("STORE_LOCK_LOST");
        if (typeof mutator !== "function") return fail("STORE_INVALID_MUTATION");
        const draft = structuredClone(state);
        let ret;
        try { ret = mutator(draft); } catch { return fail("STORE_INVALID_MUTATION"); }
        if (ret !== null && (typeof ret === "object" || typeof ret === "function") && typeof ret.then === "function") {
          return fail("STORE_INVALID_MUTATION"); // async mutators are not supported: commit is sync
        }
        if (!isState(draft) || draft.generation !== state.generation
            || draft.binding.origin !== state.binding.origin || draft.binding.inbox_prefix !== state.binding.inbox_prefix
            || state.generation >= Number.MAX_SAFE_INTEGER) {
          return fail("STORE_INVALID_MUTATION");
        }
        const json = JSON.stringify({ ...draft, generation: state.generation + 1 });
        const bytes = Buffer.from(json, "utf8");
        if (bytes.length > STORE_LIMITS.stateBytes) return fail("STORE_FULL");
        if (!lockHeld()) return fail("STORE_LOCK_LOST");
        const w = atomicWrite(statePath, bytes);
        if (!w.ok) return w;
        state = deepFreeze(JSON.parse(json));
        return { ok: true };
      } catch (err) {
        return fail("STORE_WRITE_FAILED", errnoName(err));
      }
    },

    putReply({ nonce, sha256, text, received_at } = {}) {
      try {
        if (closed || lost) return fail("STORE_LOCK_LOST");
        if (!isStr(nonce, HEX32_RE) || !isStr(sha256, HEX64_RE) || typeof text !== "string" || !isIso(received_at)) {
          return fail("STORE_INVALID_MUTATION");
        }
        if (Buffer.byteLength(text, "utf8") > STORE_LIMITS.replyTextBytes) return fail("STORE_FULL");
        if (createHash("sha256").update(text, "utf8").digest("hex") !== sha256) return fail("STORE_INVALID_MUTATION");
        const bytes = Buffer.from(JSON.stringify({ v: 1, nonce, sha256, received_at, text }), "utf8");
        if (bytes.length > STORE_LIMITS.replyFileBytes) return fail("STORE_FULL");
        const existing = readReplyFile(nonce, sha256);
        if (existing.ok) return { ok: true };
        if (existing.code !== "REPLY_MISSING") return fail("STORE_WRITE_FAILED", existing.errno || "EEXIST");
        if (replyCountReached()) return fail("STORE_FULL");
        if (!lockHeld()) return fail("STORE_LOCK_LOST");
        if (!ensureRepliesDir()) return fail("STORE_WRITE_FAILED");
        return atomicWrite(replyFile(nonce, sha256), bytes);
      } catch (err) {
        return fail("STORE_WRITE_FAILED", errnoName(err));
      }
    },

    readReply({ nonce, sha256 } = {}) {
      if (!isStr(nonce, HEX32_RE) || !isStr(sha256, HEX64_RE)) return fail("REPLY_MISSING");
      const r = readReplyFile(nonce, sha256);
      return r.ok ? r : fail(r.code);
    },

    deleteReply({ nonce, sha256 } = {}) {
      try {
        if (!isStr(nonce, HEX32_RE) || !isStr(sha256, HEX64_RE) || !lockHeld()) return;
        const file = replyFile(nonce, sha256);
        const st = fsx.lstatSync(file);
        if (st.isSymbolicLink() || !st.isFile()) return;
        fsx.unlinkSync(file);
        syncDir(repliesPath);
      } catch { /* best effort */ }
    },

    readCredential() {
      if (!persistCredential || closed || lost) return null;
      const r = readBounded(credentialPath, CREDENTIAL_BYTES);
      if (r.status !== "ok") return null;
      let c;
      try { c = decodeJson(r.buf); } catch { return null; }
      if (!isCredential(c, inboxPrefix)) return null;
      return { inbox_id: c.inbox_id, epoch: c.epoch, generation: c.generation, bearer: c.bearer };
    },

    writeCredential({ inbox_id, epoch, generation, bearer } = {}) {
      try {
        if (!persistCredential) return fail("STORE_CREDENTIAL_DISABLED");
        if (closed || lost) return fail("STORE_LOCK_LOST");
        const c = { v: 1, inbox_id, epoch, generation, bearer };
        if (!isCredential(c, inboxPrefix)) return fail("STORE_INVALID_MUTATION");
        if (!lockHeld()) return fail("STORE_LOCK_LOST");
        return atomicWrite(credentialPath, Buffer.from(JSON.stringify(c), "utf8"));
      } catch (err) {
        return fail("STORE_WRITE_FAILED", errnoName(err));
      }
    },

    clearCredential() {
      try {
        if (closed || lost) return fail("STORE_LOCK_LOST");
        if (!lockHeld()) return fail("STORE_LOCK_LOST");
        try { fsx.lstatSync(credentialPath); } catch (err) {
          if (err && err.code === "ENOENT") return { ok: true };
          throw err;
        }
        fsx.unlinkSync(credentialPath);
        syncDir(R);
        return { ok: true };
      } catch (err) {
        if (err && err.code === "ENOENT") return { ok: true };
        return fail("STORE_WRITE_FAILED", errnoName(err));
      }
    },

    lockState() {
      return lockHeld() ? "held" : "lost";
    },

    info() {
      return { mode: "durable", permissions: win32 ? "unverified" : "verified", credential_persisted: persistCredential };
    },

    close() {
      if (closed) return;
      try { releaseLock(); } catch { /* never touches a foreign lock */ }
      closed = true;
    },
  });
}
