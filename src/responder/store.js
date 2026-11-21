/**
 * Durable state of the scoped responder (issue #18). One private directory, same write discipline as
 * src/store.js and src/relay/ledger.js: strict single-writer lock (EEXIST is RESPONDER_LOCKED, never
 * reclaimed), schema-validated `responder.json`, tmp (O_EXCL, 0600) + fsync + rename + dir fsync.
 *
 * Holds request BINDINGS (what a scoped reply is allowed to do) and their OUTCOMES, plus a bounded audit
 * of every acceptance and refusal with its reason. Never persisted: the session bearer (only its digest),
 * the telepty token, reply bodies (only the composed reply's hash). Errors carry a code and at most an
 * errno NAME, never a path.
 *
 * Open-time recovery: a binding left `sending` by an abrupt exit becomes a PROCESS_RESTART `uncertain`
 * outcome, so the reply is never sent a second time; expired bindings past retention are dropped.
 *
 * Node >= 20 builtins only. Synchronous. `seams` is a test seam only.
 */

import nodeFs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";

export const RESPONDER_SCHEMA = "telesession-responder";
export const RESPONDER_VERSION = 1;
export const RESPONDER_STORE_LIMITS = Object.freeze({
  bindings: 256, audit: 256, stateBytes: 1024 * 1024, retainMs: 3600000, attempts: 3,
});

const HEX32_RE = /^[0-9a-f]{32}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const SID_RE = /^[A-Za-z0-9._-]{1,128}$/;
const INJECT_ID_RE = /^[A-Za-z0-9-]{1,128}$/;
const CODE_RE = /^[A-Z0-9_]{1,64}$/;
const REASON_RE = /^[a-z][a-z0-9_]{0,63}$/;
const ERRNO_RE = /^E[A-Z0-9]{1,31}$/;
const ORIGIN_RE = /^http:\/\/(?:127(?:\.\d{1,3}){3}|\[::1\]):[1-9]\d{0,4}$/;
const HOST_RE = /^[A-Za-z0-9._:[\]-]{1,253}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/;
const TMP_RE = /^\.responder\.json\.[0-9a-f]{16}\.tmp$/;
const LOCK_BYTES = 4096;
const STATES = new Set(["issued", "sending", "accepted", "refused"]);
const RESULTS = new Set(["sent", "uncertain", "refused"]);
const EVENTS = new Set(["issued", "reissued", "accepted", "refused", "duplicate", "recovered"]);
const DIR_FSYNC_IGNORED = new Set(["EISDIR", "EPERM", "EINVAL", "EBADF"]);

export class ResponderStoreError extends Error {
  constructor(code, errno) {
    super(code);
    this.name = "ResponderStoreError";
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

const isPlain = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isStr = (v, re) => typeof v === "string" && re.test(v);
const isInt = (v) => Number.isSafeInteger(v) && v >= 0;
const isIntOrNull = (v) => v === null || isInt(v);
const isEpochOrNull = (v) => v === null || (typeof v === "string" && v.length >= 1 && v.length <= 256 && !/[\u0000-\u001f\u007f]/.test(v));
const isEndpoint = (e) => isPlain(e) && isStr(e.host, HOST_RE) && isStr(e.session, SID_RE);

// A recorded outcome is final: `sent` (one authenticated inject), `uncertain` (the response was lost;
// never re-sent) or `refused` (with the reason it was refused for).
function isOutcome(o) {
  return o === null || (isPlain(o) && isStr(o.at, ISO_RE) && RESULTS.has(o.result)
    && (o.reason === null || isStr(o.reason, REASON_RE) || isStr(o.reason, CODE_RE))
    && (o.inject_id === null || isStr(o.inject_id, INJECT_ID_RE))
    && (o.reply_sha256 === null || isStr(o.reply_sha256, HEX64_RE)));
}

function isPrincipal(p) {
  return isPlain(p) && isStr(p.sid, SID_RE) && isStr(p.credential_sha256, HEX64_RE)
    && isEpochOrNull(p.epoch) && isIntOrNull(p.generation);
}

function isBinding(key, b) {
  return isPlain(b) && b.binding_id === key && isStr(key, HEX32_RE) && isStr(b.nonce, HEX32_RE)
    && (b.correlation_id === null || isStr(b.correlation_id, HEX32_RE))
    && isEndpoint(b.destination) && isPrincipal(b.principal)
    && isStr(b.origin_inject_id, INJECT_ID_RE) && isStr(b.payload_sha256, HEX64_RE)
    && isStr(b.challenge_sha256, HEX64_RE) && STATES.has(b.state) && isOutcome(b.outcome)
    && isInt(b.created_ms) && isInt(b.expires_ms) && isInt(b.attempts);
}

function isAuditEntry(e) {
  return isPlain(e) && isStr(e.at, ISO_RE) && EVENTS.has(e.event)
    && (e.binding_id === null || isStr(e.binding_id, HEX32_RE))
    && (e.reason === null || isStr(e.reason, REASON_RE) || isStr(e.reason, CODE_RE))
    && (e.inject_id === null || isStr(e.inject_id, INJECT_ID_RE));
}

function isResponderState(s) {
  if (!isPlain(s) || s.schema !== RESPONDER_SCHEMA || s.version !== RESPONDER_VERSION || !isInt(s.generation)) return false;
  if (!isPlain(s.binding) || !isStr(s.binding.origin, ORIGIN_RE) || !isStr(s.binding.session, SID_RE)) return false;
  if (!isPlain(s.bindings) || !Array.isArray(s.audit)) return false;
  if (Object.keys(s.bindings).length > RESPONDER_STORE_LIMITS.bindings || s.audit.length > RESPONDER_STORE_LIMITS.audit) return false;
  return Object.entries(s.bindings).every(([k, b]) => isBinding(k, b)) && s.audit.every(isAuditEntry);
}

/**
 * Opens (and locks) the responder directory for ONE session at ONE daemon origin. A state file recorded
 * for another session or origin is refused (RESPONDER_BINDING_MISMATCH) and never rewritten: bindings are
 * only meaningful for the principal that recorded them.
 */
export function openResponderStore(opts, seams) {
  const { dir, session, origin } = opts || {};
  const s = seams || {};
  const fsx = s.fs || nodeFs;
  const now = s.now || (opts && opts.now) || Date.now;
  const platform = s.platform || process.platform;
  const win32 = platform === "win32";
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  const C_ = fsx.constants || nodeFs.constants;
  const NOFOLLOW = typeof C_.O_NOFOLLOW === "number" ? C_.O_NOFOLLOW : 0;

  if (typeof dir !== "string" || !path.isAbsolute(dir) || path.normalize(dir) !== dir) throw new ResponderStoreError("RESPONDER_PATH_INVALID");
  if (!isStr(session, SID_RE) || !isStr(origin, ORIGIN_RE)) throw new ResponderStoreError("RESPONDER_BINDING_MISMATCH");

  const statePath = path.join(dir, "responder.json");
  const lockPath = path.join(dir, "lock");
  const iso = (ms) => new Date(ms).toISOString();

  // win32: ownership and mode are NOT verifiable here (no POSIX uid/mode semantics), so the check is
  // defined as "not checked" and info().permissions reports `unverified` — exactly src/store.js's rule.
  function privateOk(st) {
    return win32 || (uid !== null && st.uid === uid && (st.mode & 0o077) === 0);
  }

  function readBounded(file, limit) {
    let st;
    try { st = fsx.lstatSync(file); } catch (err) {
      return err && err.code === "ENOENT" ? { status: "missing" } : { status: "bad", errno: errnoName(err) };
    }
    if (st.isSymbolicLink() || !st.isFile() || st.nlink !== 1 || st.size > limit) return { status: "bad" };
    let fd = null;
    try {
      fd = fsx.openSync(file, C_.O_RDONLY | NOFOLLOW);
      const buf = Buffer.alloc(st.size + 1);
      let off = 0;
      for (;;) {
        const n = fsx.readSync(fd, buf, off, buf.length - off, null);
        if (n <= 0) break;
        off += n;
        if (off === buf.length) return { status: "bad" };          // grew while reading
      }
      return { status: "ok", buf: buf.subarray(0, off) };
    } catch (err) {
      return { status: "bad", errno: errnoName(err) };
    } finally {
      if (fd !== null) { try { fsx.closeSync(fd); } catch { /* already closed */ } }
    }
  }

  function syncDir(p) {
    let fd;
    try { fd = fsx.openSync(p, "r"); } catch (err) {
      if (DIR_FSYNC_IGNORED.has(err && err.code)) return;
      throw err;
    }
    try { fsx.fsyncSync(fd); } catch (err) {
      if (!DIR_FSYNC_IGNORED.has(err && err.code)) throw err;
    } finally {
      try { fsx.closeSync(fd); } catch { /* best effort */ }
    }
  }

  function atomicWrite(file, bytes) {
    const d = path.dirname(file);
    const tmp = path.join(d, `.${path.basename(file)}.${randomBytes(8).toString("hex")}.tmp`);
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
      fsx.renameSync(tmp, file);
      renamed = true;
      syncDir(d);
      return { ok: true };
    } catch (err) {
      if (fd !== null) { try { fsx.closeSync(fd); } catch { /* best effort */ } }
      if (!renamed) { try { fsx.unlinkSync(tmp); } catch { /* never created or already gone */ } }
      return fail("RESPONDER_WRITE_FAILED", errnoName(err));
    }
  }

  // ── Directory ──
  let dst = null;
  try { dst = fsx.lstatSync(dir); } catch (err) {
    if (!err || err.code !== "ENOENT") throw new ResponderStoreError("RESPONDER_WRITE_FAILED", errnoName(err));
  }
  if (dst === null) {
    try { fsx.mkdirSync(dir, { mode: 0o700 }); } catch (err) {
      if (!err || err.code !== "EEXIST") throw new ResponderStoreError("RESPONDER_WRITE_FAILED", errnoName(err));
    }
    dst = fsx.lstatSync(dir);
  }
  if (dst.isSymbolicLink() || !dst.isDirectory()) throw new ResponderStoreError("RESPONDER_PATH_INVALID");
  if (!privateOk(dst)) throw new ResponderStoreError("RESPONDER_PERMISSIONS_INVALID");

  // ── Lock: O_EXCL create; EEXIST is RESPONDER_LOCKED, always. Never renamed, reclaimed or unlinked
  // unless this process owns it. Operator recovery: confirm no pump runs, then remove `<dir>/lock`. ──
  const owner = randomBytes(16).toString("hex");
  try {
    const fd = fsx.openSync(lockPath, "wx", 0o600);
    try {
      fsx.writeSync(fd, Buffer.from(JSON.stringify({ v: 1, owner, pid: process.pid, created_at: iso(now()) }), "utf8"));
      fsx.fsyncSync(fd);
    } finally {
      fsx.closeSync(fd);
    }
  } catch (err) {
    if (err && err.code === "EEXIST") throw new ResponderStoreError("RESPONDER_LOCKED");
    throw new ResponderStoreError("RESPONDER_WRITE_FAILED", errnoName(err));
  }

  let closed = false;
  let lost = false;

  function ownerMatches() {
    const r = readBounded(lockPath, LOCK_BYTES);
    if (r.status !== "ok") return false;
    try { return JSON.parse(r.buf.toString("utf8")).owner === owner; } catch { return false; }
  }

  function lockHeld() {
    if (lost || closed) return false;
    if (!ownerMatches()) lost = true;
    return !lost;
  }

  function releaseLock() {
    if (lost || !ownerMatches()) return;
    try { fsx.unlinkSync(lockPath); syncDir(dir); } catch { /* best effort */ }
  }

  function sweepTmp() {
    let names;
    try { names = fsx.readdirSync(dir); } catch { return; }
    for (const name of names) {
      if (!TMP_RE.test(name)) continue;
      try {
        const p = path.join(dir, name);
        if (fsx.lstatSync(p).isFile()) fsx.unlinkSync(p);
      } catch { /* best effort */ }
    }
  }

  let state;
  try {
    sweepTmp();
    const r = readBounded(statePath, RESPONDER_STORE_LIMITS.stateBytes);
    if (r.status === "missing") {
      state = {
        schema: RESPONDER_SCHEMA, version: RESPONDER_VERSION, generation: 0,
        binding: { origin, session }, bindings: {}, audit: [],
      };
    } else if (r.status !== "ok") {
      throw new ResponderStoreError("RESPONDER_CORRUPT", r.errno);
    } else {
      let parsed;
      try { parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(r.buf)); } catch { throw new ResponderStoreError("RESPONDER_CORRUPT"); }
      if (isPlain(parsed) && parsed.schema === RESPONDER_SCHEMA && parsed.version !== RESPONDER_VERSION) throw new ResponderStoreError("RESPONDER_VERSION_UNSUPPORTED");
      if (!isResponderState(parsed)) throw new ResponderStoreError("RESPONDER_CORRUPT");
      if (parsed.binding.origin !== origin || parsed.binding.session !== session) throw new ResponderStoreError("RESPONDER_BINDING_MISMATCH");
      state = parsed;
    }
  } catch (err) {
    releaseLock();
    closed = true;
    if (err instanceof ResponderStoreError) throw err;
    throw new ResponderStoreError("RESPONDER_CORRUPT", errnoName(err));
  }

  function commit(mutator) {
    if (closed || lost) return fail("RESPONDER_LOCK_LOST");
    if (typeof mutator !== "function") return fail("RESPONDER_INVALID_MUTATION");
    const draft = structuredClone(state);
    let ret;
    try { ret = mutator(draft); } catch { return fail("RESPONDER_INVALID_MUTATION"); }
    if (ret && ret.ok === false) return ret;
    draft.generation = state.generation + 1;
    if (!isResponderState(draft) || draft.binding.origin !== state.binding.origin || draft.binding.session !== state.binding.session) {
      return fail("RESPONDER_INVALID_MUTATION");
    }
    const bytes = Buffer.from(JSON.stringify(draft), "utf8");
    if (bytes.length > RESPONDER_STORE_LIMITS.stateBytes) return fail("RESPONDER_FULL");
    if (!lockHeld()) return fail("RESPONDER_LOCK_LOST");
    const w = atomicWrite(statePath, bytes);
    if (!w.ok) return w;
    state = draft;
    return { ok: true, value: ret };
  }

  // Bounded audit: the oldest entries are dropped, the recorded outcomes are not.
  function pushAudit(draft, entry) {
    draft.audit.push({ at: entry.at, event: entry.event, binding_id: entry.binding_id ?? null, reason: entry.reason ?? null, inject_id: entry.inject_id ?? null });
    while (draft.audit.length > RESPONDER_STORE_LIMITS.audit) draft.audit.shift();
  }

  // Past retention: the binding (and its recorded outcome) is dropped. Called before every insert.
  function pruneDraft(draft, t) {
    for (const [k, b] of Object.entries(draft.bindings)) {
      if (t > b.expires_ms + RESPONDER_STORE_LIMITS.retainMs) delete draft.bindings[k];
    }
  }

  // Open-time recovery: `sending` is a send whose outcome this process never saw. The inject MAY have
  // taken effect, so the binding counts as consumed (`accepted`) with an `uncertain` outcome and is
  // NEVER re-sent: a second authenticated reply for one request must not be possible.
  const stuck = Object.values(state.bindings).filter((b) => b.state === "sending");
  if (stuck.length) {
    const t = now();
    const r = commit((d) => {
      for (const b of Object.values(d.bindings)) {
        if (b.state !== "sending") continue;
        b.state = "accepted";
        b.outcome = { at: iso(t), result: "uncertain", reason: "PROCESS_RESTART", inject_id: null, reply_sha256: b.outcome && b.outcome.reply_sha256 ? b.outcome.reply_sha256 : null };
        pushAudit(d, { at: iso(t), event: "recovered", binding_id: b.binding_id, reason: "PROCESS_RESTART" });
      }
    });
    if (!r.ok) {
      releaseLock();
      closed = true;
      throw new ResponderStoreError(r.code, r.errno);
    }
  }

  return Object.freeze({
    snapshot() {
      return structuredClone(state);
    },
    binding(id) {
      const b = isStr(id, HEX32_RE) ? state.bindings[id] : undefined;
      return b === undefined ? null : structuredClone(b);
    },
    bindings() {
      return Object.values(structuredClone(state.bindings));
    },
    audit() {
      return structuredClone(state.audit);
    },
    commit,
    pushAudit,
    pruneDraft,
    limits: RESPONDER_STORE_LIMITS,
    lockState() {
      return lockHeld() ? "held" : "lost";
    },
    info() {
      return { mode: "durable", session, origin, permissions: win32 ? "unverified" : "verified" };
    },
    close() {
      if (closed) return;
      try { releaseLock(); } catch { /* never touches a foreign lock */ }
      closed = true;
    },
  });
}
