/**
 * Durable state of the scoped responder (issue #18). One private directory, same write discipline as
 * src/store.js and src/relay/ledger.js: strict single-writer lock, schema-validated `responder.json`,
 * tmp (O_EXCL, 0600) + fsync + rename + dir fsync. Errors carry a code and at most an errno NAME.
 *
 * Review r1 F01: the state file is AUTHENTICATED. Every committed body carries a monotonic counter, the
 * previous commit's MAC and `mac = HMAC-SHA256(stateKey, canonicalJson(body))`, where `stateKey` is
 * derived from the session credential the pump holds IN MEMORY and is never written here. An edited,
 * spliced or hand-written file fails to verify and is refused without being rewritten; a file recorded
 * under another credential instance is refused as rotated. A rollback to an earlier AUTHENTIC snapshot
 * cannot be detected from this file alone (a one-shot pump has no external anchor): that is caught by the
 * audit reconciliation in src/responder/responder.js before any send.
 *
 * Review r1 F06: win32 is refused. Windows ACLs are not verified by this implementation, so the
 * responder does not run there rather than claiming protection it has not checked.
 * Review r1 F12: a lock left by a dead holder is reported as RESPONDER_LOCK_STALE (never reclaimed).
 *
 * Never persisted: the session bearer or its plain digest (only a derived tag), the telepty token, the
 * challenge (digest only), the request text, the reply body (hash only).
 *
 * Node >= 20 builtins only. Synchronous. `seams` is a test seam only.
 */

import nodeFs from "node:fs";
import path from "node:path";
import { createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";

export const RESPONDER_SCHEMA = "telesession-responder";
export const RESPONDER_VERSION = 2;
export const RESPONDER_STORE_LIMITS = Object.freeze({
  bindings: 256, audit: 256, sentHashes: 256, stateBytes: 1024 * 1024, retainMs: 3600000,
  sentHashRetainMs: 5400000, attempts: 3,
});

const STATE_KEY_SALT = "telesession-responder/state-key/v1";
const MAC_DOMAIN = "telesession-responder/state/v1\n";
const TAG_INFO = "credential-tag/v1";

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
const isEpoch = (v) => typeof v === "string" && v.length >= 1 && v.length <= 256 && !/[\u0000-\u001f\u007f]/.test(v);
const isEpochOrNull = (v) => v === null || isEpoch(v);
const isEndpoint = (e) => isPlain(e) && isStr(e.host, HOST_RE) && isStr(e.session, SID_RE);

// ── Record authentication (F01) ──

// Keys sorted by code point at every level, no whitespace: the MAC input must not depend on the key
// order a JSON parser happened to produce. Integers, strings, booleans, null, arrays, plain objects.
export function canonicalJson(v) {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number" && Number.isSafeInteger(v)) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (isPlain(v)) return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(",")}}`;
  throw new ResponderStoreError("RESPONDER_INVALID_MUTATION");
}

/**
 * The state key: HKDF-SHA256 over the session bearer, bound to this daemon origin and session id. The
 * pump holds the bearer in memory only; this key is never written to the store, so a same-user actor
 * that cannot read the bearer cannot forge a record.
 */
export function deriveStateKey(bearer, { origin, session } = {}) {
  if (typeof bearer !== "string" || bearer.length < 1 || !isStr(origin, ORIGIN_RE) || !isStr(session, SID_RE)) {
    throw new ResponderStoreError("RESPONDER_BINDING_MISMATCH");
  }
  return Buffer.from(hkdfSync("sha256", Buffer.from(bearer, "utf8"), Buffer.from(STATE_KEY_SALT, "utf8"),
    Buffer.from(`${origin}\n${session}`, "utf8"), 32));
}

// The credential INSTANCE identity, derived from the state key (never a digest of the bearer itself).
export function credentialTagOf(stateKey) {
  if (!Buffer.isBuffer(stateKey) || stateKey.length !== 32) throw new ResponderStoreError("RESPONDER_STATE_KEY_REQUIRED");
  return createHmac("sha256", stateKey).update(TAG_INFO, "utf8").digest("hex");
}

const macOf = (stateKey, body) => createHmac("sha256", stateKey).update(MAC_DOMAIN + canonicalJson(body), "utf8").digest("hex");

function macEqual(a, b) {
  if (!isStr(a, HEX64_RE) || !isStr(b, HEX64_RE)) return false;
  return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}

// ── Schema ──

function isOutcome(o) {
  return o === null || (isPlain(o) && isStr(o.at, ISO_RE) && RESULTS.has(o.result)
    && (o.reason === null || isStr(o.reason, REASON_RE) || isStr(o.reason, CODE_RE))
    && (o.inject_id === null || isStr(o.inject_id, INJECT_ID_RE))
    && (o.reply_sha256 === null || isStr(o.reply_sha256, HEX64_RE))
    && (o.destination_instance_ok === null || typeof o.destination_instance_ok === "boolean"));
}

function isPrincipal(p) {
  return isPlain(p) && isStr(p.sid, SID_RE) && isStr(p.credential_tag, HEX64_RE)
    && isEpochOrNull(p.epoch) && isIntOrNull(p.generation);
}

// The requester instance the trusted inbound row attributed the request to (F02).
function isInstance(i) {
  return isPlain(i) && isEpochOrNull(i.epoch) && isIntOrNull(i.generation);
}

function isBinding(key, b) {
  return isPlain(b) && b.binding_id === key && isStr(key, HEX32_RE) && isStr(b.nonce, HEX32_RE)
    && (b.correlation_id === null || isStr(b.correlation_id, HEX32_RE))
    && isEndpoint(b.destination) && isPrincipal(b.principal) && isInstance(b.destination_instance)
    && isEpoch(b.recipient_epoch) && isStr(b.origin_inject_id, INJECT_ID_RE)
    && isStr(b.payload_sha256, HEX64_RE) && isStr(b.challenge_sha256, HEX64_RE)
    && STATES.has(b.state) && isOutcome(b.outcome)
    && isInt(b.created_ms) && isInt(b.origin_ts_ms) && isInt(b.expires_ms) && isInt(b.attempts);
}

function isAuditEntry(e) {
  return isPlain(e) && isStr(e.at, ISO_RE) && EVENTS.has(e.event)
    && (e.binding_id === null || isStr(e.binding_id, HEX32_RE))
    && (e.reason === null || isStr(e.reason, REASON_RE) || isStr(e.reason, CODE_RE))
    && (e.inject_id === null || isStr(e.inject_id, INJECT_ID_RE));
}

// Every reply payload this credential instance has prepared for a send (F01: the audit reconciliation
// compares the daemon's rows against exactly this list).
const isSentHash = (x) => isPlain(x) && isStr(x.sha256, HEX64_RE) && isInt(x.at_ms);

function isResponderBody(s) {
  if (!isPlain(s) || s.schema !== RESPONDER_SCHEMA || s.version !== RESPONDER_VERSION || !isInt(s.generation)) return false;
  if (!isPlain(s.binding) || !isStr(s.binding.origin, ORIGIN_RE) || !isStr(s.binding.session, SID_RE)) return false;
  if (!isStr(s.credential_tag, HEX64_RE) || !(s.prev_mac === "" || isStr(s.prev_mac, HEX64_RE))) return false;
  if (!isPlain(s.bindings) || !Array.isArray(s.audit) || !Array.isArray(s.sent_hashes)) return false;
  if (Object.keys(s.bindings).length > RESPONDER_STORE_LIMITS.bindings || s.audit.length > RESPONDER_STORE_LIMITS.audit
      || s.sent_hashes.length > RESPONDER_STORE_LIMITS.sentHashes) return false;
  return Object.entries(s.bindings).every(([k, b]) => isBinding(k, b)) && s.audit.every(isAuditEntry)
    && s.sent_hashes.every(isSentHash);
}

/**
 * Opens (and locks) the responder directory for ONE session instance at ONE daemon origin.
 * `stateKey` (32 bytes, from deriveStateKey) authenticates every record and is not stored.
 */
export function openResponderStore(opts, seams) {
  const { dir, session, origin, stateKey } = opts || {};
  const s = seams || {};
  const fsx = s.fs || nodeFs;
  const now = s.now || (opts && opts.now) || Date.now;
  const platform = s.platform || process.platform;
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  const C_ = fsx.constants || nodeFs.constants;
  const NOFOLLOW = typeof C_.O_NOFOLLOW === "number" ? C_.O_NOFOLLOW : 0;

  // F06: no verified ownership/ACL check exists here for win32, so the responder refuses to run on it.
  if (platform === "win32") throw new ResponderStoreError("RESPONDER_PLATFORM_UNSUPPORTED");
  if (typeof dir !== "string" || !path.isAbsolute(dir) || path.normalize(dir) !== dir) throw new ResponderStoreError("RESPONDER_PATH_INVALID");
  if (!isStr(session, SID_RE) || !isStr(origin, ORIGIN_RE)) throw new ResponderStoreError("RESPONDER_BINDING_MISMATCH");
  if (!Buffer.isBuffer(stateKey) || stateKey.length !== 32) throw new ResponderStoreError("RESPONDER_STATE_KEY_REQUIRED");

  const credentialTag = credentialTagOf(stateKey);
  const statePath = path.join(dir, "responder.json");
  const lockPath = path.join(dir, "lock");
  const iso = (ms) => new Date(ms).toISOString();

  const privateOk = (st) => uid !== null && st.uid === uid && (st.mode & 0o077) === 0;

  function readBounded(file, limit) {
    let st;
    try { st = fsx.lstatSync(file); } catch (err) {
      return err && err.code === "ENOENT" ? { status: "missing" } : { status: "bad", errno: errnoName(err) };
    }
    if (st.isSymbolicLink() || !st.isFile() || st.nlink !== 1 || st.size > limit) return { status: "bad" };
    let fd = null;
    try {
      fd = fsx.openSync(file, C_.O_RDONLY | NOFOLLOW);
      // F09: the opened descriptor must be the object that was checked.
      const fst = fsx.fstatSync(fd);
      if (!fst.isFile() || fst.nlink !== 1 || fst.size > limit || fst.ino !== st.ino || fst.dev !== st.dev) return { status: "bad" };
      const buf = Buffer.alloc(fst.size + 1);
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

  // Detection only: the lock is NEVER reclaimed (pid reuse). Operator recovery: confirm no pump runs for
  // this directory, then remove `<dir>/lock` (F12; same rule as src/relay/ledger.js).
  function lockHolderDead() {
    const r = readBounded(lockPath, LOCK_BYTES);
    if (r.status !== "ok") return false;
    let pid;
    try { pid = JSON.parse(r.buf.toString("utf8")).pid; } catch { return false; }
    if (!Number.isSafeInteger(pid) || pid <= 0) return false;
    try { process.kill(pid, 0); return false; } catch (e) { return Boolean(e) && e.code === "ESRCH"; }
  }

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
    if (err && err.code === "EEXIST") throw new ResponderStoreError(lockHolderDead() ? "RESPONDER_LOCK_STALE" : "RESPONDER_LOCKED");
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

  const freshBody = () => ({
    schema: RESPONDER_SCHEMA, version: RESPONDER_VERSION, generation: 0,
    binding: { origin, session }, credential_tag: credentialTag,
    bindings: {}, sent_hashes: [], audit: [], prev_mac: "",
  });

  let state;
  let stateMac = "";
  try {
    sweepTmp();
    const r = readBounded(statePath, RESPONDER_STORE_LIMITS.stateBytes);
    if (r.status === "missing") {
      state = freshBody();
    } else if (r.status !== "ok") {
      throw new ResponderStoreError("RESPONDER_CORRUPT", r.errno);
    } else {
      let parsed;
      try { parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(r.buf)); } catch { throw new ResponderStoreError("RESPONDER_CORRUPT"); }
      if (!isPlain(parsed) || parsed.schema !== RESPONDER_SCHEMA) throw new ResponderStoreError("RESPONDER_CORRUPT");
      if (parsed.version !== RESPONDER_VERSION) throw new ResponderStoreError("RESPONDER_VERSION_UNSUPPORTED");
      const { mac, ...body } = parsed;
      if (!isResponderBody(body)) throw new ResponderStoreError("RESPONDER_CORRUPT");
      // A file written for another session, origin or credential instance is never adopted or rewritten.
      if (body.binding.origin !== origin || body.binding.session !== session) throw new ResponderStoreError("RESPONDER_BINDING_MISMATCH");
      if (body.credential_tag !== credentialTag) throw new ResponderStoreError("RESPONDER_CREDENTIAL_ROTATED");
      if (!macEqual(typeof mac === "string" ? mac : "", macOf(stateKey, body))) throw new ResponderStoreError("RESPONDER_STATE_UNAUTHENTIC");
      state = body;
      stateMac = mac;
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
    draft.prev_mac = stateMac;
    draft.credential_tag = credentialTag;
    if (!isResponderBody(draft) || draft.binding.origin !== state.binding.origin || draft.binding.session !== state.binding.session) {
      return fail("RESPONDER_INVALID_MUTATION");
    }
    let mac;
    try { mac = macOf(stateKey, draft); } catch { return fail("RESPONDER_INVALID_MUTATION"); }
    const bytes = Buffer.from(JSON.stringify({ ...draft, mac }), "utf8");
    if (bytes.length > RESPONDER_STORE_LIMITS.stateBytes) return fail("RESPONDER_FULL");
    if (!lockHeld()) return fail("RESPONDER_LOCK_LOST");
    const w = atomicWrite(statePath, bytes);
    if (!w.ok) return w;
    state = draft;
    stateMac = mac;
    return { ok: true, value: ret };
  }

  // Bounded audit: the oldest entries are dropped, the recorded outcomes are not.
  function pushAudit(draft, entry) {
    draft.audit.push({ at: entry.at, event: entry.event, binding_id: entry.binding_id ?? null, reason: entry.reason ?? null, inject_id: entry.inject_id ?? null });
    while (draft.audit.length > RESPONDER_STORE_LIMITS.audit) draft.audit.shift();
  }

  // The hash of a reply payload this instance is about to inject. Recorded BEFORE the send, so the audit
  // reconciliation can account for the row even if the outcome write is lost. Full and nothing prunable
  // means no send: dropping a hash that the audit window still shows would look like a rollback.
  function addSentHash(draft, sha256, atMs) {
    if (draft.sent_hashes.some((x) => x.sha256 === sha256)) return { ok: true };
    if (draft.sent_hashes.length >= RESPONDER_STORE_LIMITS.sentHashes) return { ok: false, code: "RESPONDER_FULL" };
    draft.sent_hashes.push({ sha256, at_ms: atMs });
    return { ok: true };
  }

  // Past retention: the binding (and its recorded outcome) and old send hashes are dropped.
  function pruneDraft(draft, t) {
    for (const [k, b] of Object.entries(draft.bindings)) {
      if (t > b.expires_ms + RESPONDER_STORE_LIMITS.retainMs) delete draft.bindings[k];
    }
    draft.sent_hashes = draft.sent_hashes.filter((x) => t <= x.at_ms + RESPONDER_STORE_LIMITS.sentHashRetainMs);
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
        b.outcome = {
          at: iso(t), result: "uncertain", reason: "PROCESS_RESTART", inject_id: null,
          reply_sha256: b.outcome && b.outcome.reply_sha256 ? b.outcome.reply_sha256 : null,
          destination_instance_ok: null,
        };
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
    sentHashes() {
      return structuredClone(state.sent_hashes);
    },
    audit() {
      return structuredClone(state.audit);
    },
    commit,
    pushAudit,
    pruneDraft,
    addSentHash,
    limits: RESPONDER_STORE_LIMITS,
    lockState() {
      return lockHeld() ? "held" : "lost";
    },
    info() {
      return { mode: "durable", session, origin, credential_tag: credentialTag, permissions: "verified", authenticated: true };
    },
    close() {
      if (closed) return;
      try { releaseLock(); } catch { /* never touches a foreign lock */ }
      closed = true;
    },
  });
}
