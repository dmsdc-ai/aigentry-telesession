/**
 * telesession correlation ledger (SPEC 2026-10-11 §4–§8, §10). One private directory: strict
 * single-writer lock, `ledger.json` (records + outbox), reply files `replies/<nonce>-<sha256>.json`.
 * Same write discipline as src/store.js: tmp (O_EXCL, 0600) + fsync + rename + dir fsync; a reply file is
 * durable BEFORE the commit that references it. Errors carry a code (+ errno name), never a path.
 *
 * Stages are monotonic; events are validated (hash, authentication, hop, source, generation) and refused
 * without any state change. A timeout is `unknown`, never "not delivered". Nothing here sends; the relay
 * tick (relay.js) drives the outbox with an injected send. Never exactly-once.
 *
 * Node >= 20 builtins only. Synchronous. `seams` is a test seam only.
 */

import nodeFs from "node:fs";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";

export const LEDGER_SCHEMA = "telesession-ledger";
export const LEDGER_VERSION = 1;
export const LEDGER_LIMITS = Object.freeze({
  records: 1024, repliesPerRecord: 32, outbox: 256, ledgerBytes: 4 * 1024 * 1024, replyTextBytes: 65536,
  replyFileBytes: 98304, eventsPerRecord: 64, retired: 256, latePending: 4, outboxTextChars: 8000,
  retainMs: 7 * 86400000, sendAttempts: 3,
});
export const STAGES = Object.freeze(["transport_accepted", "durable_received", "agent_consumed", "processing_completed", "origin_ack_received"]);

const EVENT_STAGES = new Set(["transport_accepted", "durable_received", "agent_consumed", "processing_completed", "rejected"]);
const DESTINATION_STAGES = new Set(["agent_consumed", "processing_completed", "rejected"]);
const OUTBOX_STATES = ["queued", "intent", "sent", "uncertain", "failed"];
const HEX32_RE = /^[0-9a-f]{32}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const REQUEST_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const HOST_RE = /^[A-Za-z0-9._:\[\]-]{1,253}$/;
const SID_RE = /^[A-Za-z0-9._-]{1,128}$/;
const KIND_RE = /^[a-z][a-z0-9_]{0,31}$/;
const CODE_RE = /^[A-Za-z0-9_]{1,64}$/;
const ERRNO_RE = /^E[A-Z0-9]{1,31}$/;
const TMP_RE = /^\.(?:ledger\.json|[0-9a-f]{32}-[0-9a-f]{64}\.json)\.[0-9a-f]{16}\.tmp$/;
const LOCK_BYTES = 4096;
const READ_ONLY_CODES = new Set(["EACCES", "EROFS", "EPERM"]);
const DIR_FSYNC_IGNORED = new Set(["EISDIR", "EPERM", "EINVAL", "EBADF"]);

export class LedgerError extends Error {
  constructor(code, errno) {
    super(code);
    this.name = "LedgerError";
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

const sha256hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const isEndpoint = (e) => e !== null && typeof e === "object" && typeof e.host === "string" && HOST_RE.test(e.host)
  && typeof e.session === "string" && SID_RE.test(e.session);
const endpointOf = (e) => ({ host: e.host, session: e.session });
const isPlain = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

function isRecord(key, r) {
  return isPlain(r) && r.nonce === key && HEX32_RE.test(r.nonce) && HEX64_RE.test(r.payload_sha256)
    && isEndpoint(r.origin) && isEndpoint(r.destination) && isEndpoint(r.reply_to) && (r.via === null || isEndpoint(r.via))
    && isPlain(r.stages) && Array.isArray(r.replies) && Number.isSafeInteger(r.next_seq) && r.next_seq >= 1
    && Array.isArray(r.events) && Array.isArray(r.late_pending) && isPlain(r.rejected) && isPlain(r.unproven)
    && Number.isSafeInteger(r.created_ms) && Number.isSafeInteger(r.deadline_ms) && Number.isSafeInteger(r.retain_until_ms);
}

function isLedgerState(s) {
  if (!isPlain(s) || s.schema !== LEDGER_SCHEMA || s.version !== LEDGER_VERSION || !Number.isSafeInteger(s.generation)) return false;
  if (!isPlain(s.records) || !isPlain(s.outbox) || !Array.isArray(s.retired)) return false;
  if (Object.keys(s.records).length > LEDGER_LIMITS.records || Object.keys(s.outbox).length > LEDGER_LIMITS.outbox) return false;
  return Object.entries(s.records).every(([k, r]) => isRecord(k, r))
    && Object.values(s.outbox).every((o) => isPlain(o) && OUTBOX_STATES.includes(o.state) && HEX32_RE.test(o.nonce));
}

export function openLedger(opts, seams) {
  const { dir, resolver = null } = opts || {};
  const s = seams || {};
  const fsx = s.fs || nodeFs;
  const now = (opts && opts.now) || Date.now;
  const win32 = process.platform === "win32";
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  const C_ = fsx.constants || nodeFs.constants;
  const NOFOLLOW = typeof C_.O_NOFOLLOW === "number" ? C_.O_NOFOLLOW : 0;
  if (typeof dir !== "string" || !path.isAbsolute(dir) || path.normalize(dir) !== dir) throw new LedgerError("LEDGER_PATH_INVALID");

  const canon = (host) => (resolver ? resolver.canonical(host) : host);
  const same = (a, b) => (resolver ? resolver.sameEndpoint(a, b) : Boolean(a && b) && a.host === b.host && a.session === b.session);
  const hopKey = (e) => `${canon(e.host) || "?" + e.host}/${e.session}`;
  const iso = (ms) => new Date(ms).toISOString();

  const ledgerPath = path.join(dir, "ledger.json");
  const lockPath = path.join(dir, "lock");
  const repliesPath = path.join(dir, "replies");

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
        if (off === buf.length) return { status: "bad" };
      }
      return { status: "ok", buf: buf.subarray(0, off) };
    } catch (err) {
      return { status: "bad", errno: errnoName(err) };
    } finally {
      if (fd !== null) { try { fsx.closeSync(fd); } catch { /* closed */ } }
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
      if (!renamed) { try { fsx.unlinkSync(tmp); } catch { /* not created */ } }
      return fail("LEDGER_WRITE_FAILED", errnoName(err));
    }
  }

  // ── Directory + lock. A permission-limited directory with a readable ledger opens read_only. ──
  let st = null;
  try { st = fsx.lstatSync(dir); } catch (err) {
    if (!err || err.code !== "ENOENT") throw new LedgerError("LEDGER_WRITE_FAILED", errnoName(err));
  }
  if (st === null) {
    try { fsx.mkdirSync(dir, { mode: 0o700 }); } catch (err) {
      if (!err || err.code !== "EEXIST") throw new LedgerError("LEDGER_WRITE_FAILED", errnoName(err));
    }
    st = fsx.lstatSync(dir);
  }
  if (st.isSymbolicLink() || !st.isDirectory()) throw new LedgerError("LEDGER_PATH_INVALID");
  if (!privateOk(st)) throw new LedgerError("LEDGER_PERMISSIONS_INVALID");

  const owner = randomBytes(16).toString("hex");
  let mode = "read_write";
  try {
    const fd = fsx.openSync(lockPath, "wx", 0o600);
    try {
      fsx.writeSync(fd, Buffer.from(JSON.stringify({ v: 1, owner, pid: process.pid, created_at: iso(now()) }), "utf8"));
      fsx.fsyncSync(fd);
    } finally {
      fsx.closeSync(fd);
    }
  } catch (err) {
    if (err && err.code === "EEXIST") throw new LedgerError("LEDGER_LOCKED");
    if (!READ_ONLY_CODES.has(err && err.code)) throw new LedgerError("LEDGER_WRITE_FAILED", errnoName(err));
    mode = "read_only";
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
    if (mode !== "read_write" || lost || !ownerMatches()) return;
    try { fsx.unlinkSync(lockPath); syncDir(dir); } catch { /* best effort */ }
  }

  let state;
  try {
    const r = readBounded(ledgerPath, LEDGER_LIMITS.ledgerBytes);
    if (r.status === "missing") {
      if (mode === "read_only") throw new LedgerError("LEDGER_WRITE_FAILED", "EACCES");
      state = { schema: LEDGER_SCHEMA, version: LEDGER_VERSION, generation: 0, records: {}, outbox: {}, retired: [] };
    } else if (r.status !== "ok") {
      throw new LedgerError("LEDGER_CORRUPT", r.errno);
    } else {
      try { state = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(r.buf)); } catch { throw new LedgerError("LEDGER_CORRUPT"); }
      if (isPlain(state) && state.schema === LEDGER_SCHEMA && state.version !== LEDGER_VERSION) throw new LedgerError("LEDGER_VERSION_UNSUPPORTED");
      if (!isLedgerState(state)) throw new LedgerError("LEDGER_CORRUPT");
    }
  } catch (err) {
    releaseLock();
    if (err instanceof LedgerError) throw err;
    throw new LedgerError("LEDGER_CORRUPT", errnoName(err));
  }

  function commit(mutator) {
    if (mode !== "read_write") return fail("LEDGER_READ_ONLY");
    if (closed || lost) return fail("LEDGER_LOCK_LOST");
    const draft = structuredClone(state);
    let ret;
    try { ret = mutator(draft); } catch { return fail("LEDGER_INVALID_MUTATION"); }
    if (ret && ret.ok === false) return ret;
    draft.generation = state.generation + 1;
    const bytes = Buffer.from(JSON.stringify(draft), "utf8");
    if (bytes.length > LEDGER_LIMITS.ledgerBytes) return fail("LEDGER_FULL");
    if (!lockHeld()) return fail("LEDGER_LOCK_LOST");
    const w = atomicWrite(ledgerPath, bytes);
    if (!w.ok) return w;
    state = draft;
    return { ok: true, value: ret };
  }

  function replyFile(nonce, sha) {
    return path.join(repliesPath, `${nonce}-${sha}.json`);
  }

  function writeReplyFile(nonce, sha, text, receivedAt) {
    const existing = readReplyFile(nonce, sha);
    if (existing.ok) return { ok: true };
    if (!lockHeld()) return fail("LEDGER_LOCK_LOST");
    try {
      try { fsx.mkdirSync(repliesPath, { mode: 0o700 }); } catch (err) { if (!err || err.code !== "EEXIST") throw err; }
      const rst = fsx.lstatSync(repliesPath);
      if (rst.isSymbolicLink() || !rst.isDirectory() || !privateOk(rst)) return fail("LEDGER_WRITE_FAILED");
    } catch (err) {
      return fail("LEDGER_WRITE_FAILED", errnoName(err));
    }
    return atomicWrite(replyFile(nonce, sha), Buffer.from(JSON.stringify({ v: 1, nonce, sha256: sha, received_at: receivedAt, text }), "utf8"));
  }

  function readReplyFile(nonce, sha) {
    const r = readBounded(replyFile(nonce, sha), LEDGER_LIMITS.replyFileBytes);
    if (r.status === "missing") return fail("REPLY_MISSING");
    if (r.status !== "ok") return fail("REPLY_CORRUPT", r.errno);
    let j;
    try { j = JSON.parse(r.buf.toString("utf8")); } catch { return fail("REPLY_CORRUPT"); }
    if (!isPlain(j) || j.nonce !== nonce || j.sha256 !== sha || typeof j.text !== "string" || sha256hex(j.text) !== sha) return fail("REPLY_CORRUPT");
    return { ok: true, text: j.text, received_at: j.received_at };
  }

  function unlinkReply(nonce, sha) {
    try { fsx.unlinkSync(replyFile(nonce, sha)); } catch { /* best effort */ }
  }

  function attestationOf(rec, from) {
    if (same(from, rec.destination)) return "destination";
    if (rec.via && same(from, rec.via)) return "relayed_by_leg1_destination";
    return "intermediary";
  }

  // ── Open-time recovery (writable only): intent without receipt → uncertain; retire past retention. ──
  if (mode === "read_write") {
    try {
      for (const name of fsx.readdirSync(dir)) if (TMP_RE.test(name)) { try { fsx.unlinkSync(path.join(dir, name)); } catch { /* best effort */ } }
      try { for (const name of fsx.readdirSync(repliesPath)) if (TMP_RE.test(name)) { try { fsx.unlinkSync(path.join(repliesPath, name)); } catch { /* best effort */ } } } catch { /* no replies dir yet */ }
    } catch { /* best effort sweep */ }
    const stuck = Object.values(state.outbox).some((o) => o.state === "intent");
    const t = now();
    const old = Object.values(state.records).filter((r) => t > r.retain_until_ms);
    if (stuck || old.length) {
      const r = commit((d) => {
        for (const o of Object.values(d.outbox)) if (o.state === "intent") { o.state = "uncertain"; o.last_error = "PROCESS_RESTART"; }
        retire(d, old.map((x) => x.nonce));
      });
      if (!r.ok) { releaseLock(); throw new LedgerError(r.code, r.errno); }
      for (const rec of old) for (const x of [...rec.replies, ...rec.late_pending]) unlinkReply(rec.nonce, x.sha256);
    }
  }

  function retire(d, nonces) {
    for (const n of nonces) {
      delete d.records[n];
      for (const [k, o] of Object.entries(d.outbox)) if (o.nonce === n) delete d.outbox[k];
      if (!d.retired.includes(n)) d.retired.push(n);
      while (d.retired.length > LEDGER_LIMITS.retired) d.retired.shift();
    }
  }

  // ── Public API ──

  function createRequest(a = {}) {
    if (!HEX32_RE.test(a.nonce || "") || !(a.request_id === null || a.request_id === undefined || REQUEST_ID_RE.test(a.request_id))
        || !isEndpoint(a.origin) || !isEndpoint(a.destination) || !isEndpoint(a.reply_to)
        || !(a.via === undefined || a.via === null || isEndpoint(a.via))
        || !(a.generation === null || (typeof a.generation === "string" && a.generation.length > 0 && a.generation.length <= 256))
        || !HEX64_RE.test(a.payload_sha256 || "") || !Number.isSafeInteger(a.deadline_ms) || a.deadline_ms < 0) {
      return fail("INVALID_ARGUMENT");
    }
    const prior = state.records[a.nonce];
    if (prior) {
      return prior.payload_sha256 === a.payload_sha256 ? { ok: true, deduplicated: true } : fail("NONCE_CONFLICT");
    }
    if (state.retired.includes(a.nonce)) return fail("NONCE_RETIRED");
    const t = now();
    const retainMs = Number.isSafeInteger(a.retain_ms) && a.retain_ms > 0 ? a.retain_ms : LEDGER_LIMITS.retainMs;
    const r = commit((d) => {
      if (Object.keys(d.records).length >= LEDGER_LIMITS.records) {
        const due = Object.values(d.records).filter((x) => t > x.retain_until_ms).map((x) => x.nonce);
        retire(d, due);
        if (Object.keys(d.records).length >= LEDGER_LIMITS.records) return fail("LEDGER_FULL");
      }
      d.records[a.nonce] = {
        nonce: a.nonce, request_id: a.request_id ?? null, origin: endpointOf(a.origin), destination: endpointOf(a.destination),
        via: a.via ? endpointOf(a.via) : null,
        via_generation: a.via && typeof a.via_generation === "string" && a.via_generation.length <= 256 ? a.via_generation : null,
        reply_to: endpointOf(a.reply_to), generation: a.generation,
        payload_sha256: a.payload_sha256, stage: null, stages: Object.fromEntries(STAGES.map((k) => [k, null])), terminal: null,
        created_ms: t, deadline_ms: t + a.deadline_ms, retain_until_ms: t + Math.max(retainMs, a.deadline_ms),
        replies: [], next_seq: 1, checkpoint: null, ack_seq: null, unproven: {}, late_pending: [], events: [], rejected: {},
      };
    });
    return r.ok ? { ok: true, deduplicated: false } : r;
  }

  function reject(nonce, reason) {
    commit((d) => { const q = d.records[nonce]; if (q) q.rejected[reason] = (q.rejected[reason] || 0) + 1; });
    return fail(reason);
  }

  function recordEvent(ev = {}) {
    if (mode !== "read_write") return fail("LEDGER_READ_ONLY");
    const rec = state.records[ev.nonce];
    if (!rec) return fail("UNKNOWN_CORRELATION");
    if (!EVENT_STAGES.has(ev.stage) || !isEndpoint(ev.from)) return fail("INVALID_ARGUMENT");
    if (ev.payload_sha256 !== rec.payload_sha256) return reject(rec.nonce, "HASH_MISMATCH");
    if (rec.terminal) return fail("TERMINAL");
    const final = DESTINATION_STAGES.has(ev.stage);
    if (ev.authenticated !== true) {
      if (final && ev.provenance_unavailable === true) {
        const r = commit((d) => { d.records[rec.nonce].unproven[ev.stage] = "REMOTE_PROVENANCE_UNAVAILABLE"; });
        return r.ok ? fail("REMOTE_PROVENANCE_UNAVAILABLE") : r;
      }
      return reject(rec.nonce, "UNAUTHENTICATED");
    }
    if (final && ev.hop !== "destination") return reject(rec.nonce, "HOP_NOT_FINAL");
    if (final && !same(ev.from, rec.destination)) return reject(rec.nonce, "SOURCE_MISMATCH");
    if (final && (rec.generation === null || ev.generation !== rec.generation)) return reject(rec.nonce, "GENERATION_MISMATCH");
    const key = `${rec.payload_sha256}:${hopKey(ev.from)}:${ev.stage}`;
    if (rec.events.includes(key)) return { ok: true, applied: false, deduplicated: true, stage: rec.stage };
    const at = iso(now());
    const r = commit((d) => {
      const q = d.records[rec.nonce];
      q.events.push(key);
      while (q.events.length > LEDGER_LIMITS.eventsPerRecord) q.events.shift();
      if (ev.stage === "rejected") {
        q.terminal = { state: "rejected", at, reason: typeof ev.reason === "string" && CODE_RE.test(ev.reason) ? ev.reason : null };
        return;
      }
      const raise = (stage) => {
        if (q.stages[stage] === null) q.stages[stage] = at;
        if (q.stage === null || STAGES.indexOf(stage) > STAGES.indexOf(q.stage)) q.stage = stage;
      };
      raise(ev.stage);
      if (ev.stage === "processing_completed") {
        raise("origin_ack_received");
        q.ack_seq = Number.isSafeInteger(ev.reply_seq) && ev.reply_seq >= 0 && ev.reply_seq < q.next_seq ? ev.reply_seq : q.next_seq - 1;
        delete q.unproven.processing_completed;
      }
    });
    return r.ok ? { ok: true, applied: true, deduplicated: false, stage: state.records[rec.nonce].stage } : r;
  }

  function appendEntry(rec, sha, from, receivedAt, late) {
    const dedupe = `${rec.nonce}:${sha}:${hopKey(from)}`;
    const prior = rec.replies.find((x) => x.dedupe_key === dedupe);
    if (prior) return { ok: true, seq: prior.seq, deduplicated: true };
    if (rec.replies.length >= LEDGER_LIMITS.repliesPerRecord) return fail("LEDGER_FULL");
    const r = commit((d) => {
      const q = d.records[rec.nonce];
      const seq = q.next_seq;
      q.next_seq += 1;
      q.replies.push({
        seq, sha256: sha, from: endpointOf(from), verified: true, attestation: attestationOf(q, from),
        received_at: receivedAt, dedupe_key: dedupe, late_after_ttl: late,
      });
      q.late_pending = q.late_pending.filter((x) => x.sha256 !== sha);
      return seq;
    });
    return r.ok ? { ok: true, seq: r.value, deduplicated: false } : r;
  }

  function appendReply({ nonce, text, from, verified, received_at, late_after_ttl } = {}) {
    if (mode !== "read_write") return fail("LEDGER_READ_ONLY");
    const rec = state.records[nonce];
    if (!rec) return fail("UNKNOWN_CORRELATION");
    if (typeof text !== "string" || !isEndpoint(from)) return fail("INVALID_ARGUMENT");
    if (verified !== true) return fail("UNAUTHENTICATED");
    if (Buffer.byteLength(text, "utf8") > LEDGER_LIMITS.replyTextBytes) return fail("LEDGER_FULL");
    const sha = sha256hex(text);
    const receivedAt = typeof received_at === "string" ? received_at : iso(now());
    const dup = rec.replies.find((x) => x.dedupe_key === `${rec.nonce}:${sha}:${hopKey(from)}`);
    if (dup) return { ok: true, seq: dup.seq, deduplicated: true };
    const w = writeReplyFile(rec.nonce, sha, text, receivedAt);
    if (!w.ok) return w;
    return appendEntry(rec, sha, from, receivedAt, late_after_ttl === true);
  }

  // Late bytes (after the transport TTL) are held unverified until the adapter verifies or drops them.
  function holdLate({ nonce, sha256, text, received_at } = {}) {
    if (mode !== "read_write") return fail("LEDGER_READ_ONLY");
    const rec = state.records[nonce];
    if (!rec) return fail("UNKNOWN_CORRELATION");
    if (now() > rec.retain_until_ms) return fail("NONCE_EXPIRED");
    if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > LEDGER_LIMITS.replyTextBytes) return fail("INVALID_ARGUMENT");
    if (sha256hex(text) !== sha256) return fail("HASH_MISMATCH");
    if (rec.late_pending.some((x) => x.sha256 === sha256) || rec.replies.some((x) => x.sha256 === sha256)) return { ok: true, deduplicated: true };
    if (rec.late_pending.length >= LEDGER_LIMITS.latePending) return fail("LEDGER_FULL");
    const receivedAt = typeof received_at === "string" ? received_at : iso(now());
    const w = writeReplyFile(nonce, sha256, text, receivedAt);
    if (!w.ok) return w;
    const r = commit((d) => { d.records[nonce].late_pending.push({ sha256, received_at: receivedAt }); });
    if (!r.ok) { unlinkReply(nonce, sha256); return r; }
    return { ok: true, deduplicated: false };
  }

  function latePending() {
    const out = [];
    for (const rec of Object.values(state.records)) {
      for (const x of rec.late_pending) {
        out.push({
          nonce: rec.nonce, sha256: x.sha256, received_at: x.received_at, destination: { ...rec.destination },
          via: rec.via ? { ...rec.via } : null, via_generation: rec.via_generation ?? null,
          generation: rec.generation, created_ms: rec.created_ms, retain_until_ms: rec.retain_until_ms,
        });
      }
    }
    return out;
  }

  function promoteLate({ nonce, sha256, from } = {}) {
    if (mode !== "read_write") return fail("LEDGER_READ_ONLY");
    const rec = state.records[nonce];
    if (!rec) return fail("UNKNOWN_CORRELATION");
    const held = rec.late_pending.find((x) => x.sha256 === sha256);
    if (!held || !isEndpoint(from)) return fail("INVALID_ARGUMENT");
    const f = readReplyFile(nonce, sha256);
    if (!f.ok) return f;
    return appendEntry(rec, sha256, from, held.received_at, true);
  }

  function dropLate({ nonce, sha256, reason } = {}) {
    if (mode !== "read_write") return fail("LEDGER_READ_ONLY");
    const rec = state.records[nonce];
    if (!rec || !rec.late_pending.some((x) => x.sha256 === sha256)) return fail("INVALID_ARGUMENT");
    const why = typeof reason === "string" && CODE_RE.test(reason) ? reason : "late_unverified";
    const r = commit((d) => {
      const q = d.records[nonce];
      q.late_pending = q.late_pending.filter((x) => x.sha256 !== sha256);
      q.rejected[why] = (q.rejected[why] || 0) + 1;
    });
    if (r.ok && !rec.replies.some((x) => x.sha256 === sha256)) unlinkReply(nonce, sha256);
    return r.ok ? { ok: true } : r;
  }

  function readReplies({ nonce, cursor = 0 } = {}) {
    const rec = state.records[nonce];
    if (!rec) return fail("UNKNOWN_CORRELATION");
    if (!Number.isSafeInteger(cursor) || cursor < 0) return fail("INVALID_ARGUMENT");
    const replies = [];
    for (const x of rec.replies) {
      if (x.seq <= cursor) continue;
      const f = readReplyFile(nonce, x.sha256);
      replies.push({
        seq: x.seq, sha256: x.sha256, from: { ...x.from }, attestation: x.attestation, received_at: x.received_at,
        late_after_ttl: x.late_after_ttl, ...(f.ok ? { text: f.text } : { text: null, error: f.code }),
      });
    }
    return { ok: true, nonce, replies, next_cursor: rec.next_seq - 1 };
  }

  function view(rec) {
    const t = now();
    const items = Object.values(state.outbox).filter((o) => o.nonce === rec.nonce);
    const outbox = Object.fromEntries(OUTBOX_STATES.map((k) => [k, items.filter((o) => o.state === k).length]));
    const deadlinePassed = t > rec.deadline_ms;
    const delivered = rec.ack_seq !== null && rec.checkpoint !== null && rec.checkpoint.cursor >= rec.ack_seq;
    const reasons = [];
    if (Object.values(rec.unproven).includes("REMOTE_PROVENANCE_UNAVAILABLE")) reasons.push("REMOTE_PROVENANCE_UNAVAILABLE");
    let status;
    if (rec.terminal) status = "rejected";
    else if (rec.stage === "origin_ack_received") {
      status = delivered ? "completed" : "pending";
      if (!delivered) reasons.push("AWAITING_ORIGIN_AGENT_READ");
    } else if (outbox.uncertain > 0) { status = "unknown"; reasons.push("OUTBOX_UNCERTAIN"); }
    else if (deadlinePassed) { status = "unknown"; reasons.push("DEADLINE_PASSED"); }
    else status = "pending";
    return {
      ok: true, nonce: rec.nonce, request_id: rec.request_id, status, status_reasons: reasons,
      stage: rec.stage === null ? "unknown" : rec.stage,
      stages: Object.fromEntries(STAGES.map((k) => [k, rec.stages[k] === null ? "unknown" : rec.stages[k]])),
      unproven: { ...rec.unproven }, terminal: rec.terminal ? { ...rec.terminal } : null,
      deadline_passed: deadlinePassed, reply_count: rec.replies.length,
      late_after_ttl_count: rec.replies.filter((x) => x.late_after_ttl).length, late_pending: rec.late_pending.length,
      cursor: rec.next_seq - 1, ack_seq: rec.ack_seq, delivered_to_origin_agent: delivered,
      checkpoint: rec.checkpoint ? { ...rec.checkpoint } : null, outbox, rejected: { ...rec.rejected }, completion_fact: null,
    };
  }

  // A cursor records the origin agent's checkpoint (monotonic). Without one, status is read-only.
  function status({ nonce, cursor } = {}) {
    if (typeof nonce !== "string" || !HEX32_RE.test(nonce)) return fail("INVALID_ARGUMENT");
    if (cursor !== undefined && (!Number.isSafeInteger(cursor) || cursor < 0)) return fail("INVALID_ARGUMENT");
    let rec = state.records[nonce];
    if (!rec || now() > rec.retain_until_ms) {
      return { ok: true, nonce, status: rec || state.retired.includes(nonce) ? "expired" : "not_tracked", completion_fact: null };
    }
    if (cursor !== undefined && mode === "read_write") {
      const c = Math.min(cursor, rec.next_seq - 1);
      if (rec.checkpoint === null || c > rec.checkpoint.cursor) {
        const r = commit((d) => { d.records[nonce].checkpoint = { cursor: c, at: iso(now()) }; });
        if (!r.ok) return r;
        rec = state.records[nonce];
      }
    }
    return view(rec);
  }

  function record(nonce) {
    const rec = state.records[nonce];
    return rec ? structuredClone(rec) : null;
  }

  function readLateText(nonce, sha256) {
    const rec = state.records[nonce];
    if (!rec || !rec.late_pending.some((x) => x.sha256 === sha256)) return fail("REPLY_MISSING");
    return readReplyFile(nonce, sha256);
  }

  function has(nonce) {
    const rec = state.records[nonce];
    return Boolean(rec) && now() <= rec.retain_until_ms;
  }

  // ── Outbox (driven by relay.js) ──

  function enqueue({ nonce, to, kind, text } = {}) {
    if (mode !== "read_write") return fail("LEDGER_READ_ONLY");
    if (!state.records[nonce]) return fail("UNKNOWN_CORRELATION");
    if (!isEndpoint(to) || typeof kind !== "string" || !KIND_RE.test(kind) || typeof text !== "string"
        || text.length < 1 || text.length > LEDGER_LIMITS.outboxTextChars || text.includes("\u0000")) {
      return fail("INVALID_ARGUMENT");
    }
    const payload = sha256hex(text);
    const key = sha256hex(`${nonce}:${payload}:${hopKey(to)}:${kind}`).slice(0, 32);
    if (state.outbox[key]) return { ok: true, key, deduplicated: true };
    if (Object.keys(state.outbox).length >= LEDGER_LIMITS.outbox) return fail("LEDGER_FULL");
    const r = commit((d) => {
      d.outbox[key] = {
        key, nonce, kind, to: endpointOf(to), payload_sha256: payload, text, state: "queued", attempts: 0,
        created_at: iso(now()), intent_at: null, receipt: null, last_error: null,
      };
    });
    return r.ok ? { ok: true, key, deduplicated: false } : r;
  }

  function outbox() {
    return Object.values(state.outbox).map((o) => structuredClone(o))
      .sort((a, b) => (a.created_at < b.created_at ? -1 : a.created_at > b.created_at ? 1 : a.key < b.key ? -1 : 1));
  }

  function outboxTransition(key, from, fields) {
    const r = commit((d) => {
      const o = d.outbox[key];
      if (!o || o.state !== from) return fail("OUTBOX_STATE_CHANGED");
      Object.assign(o, fields);
      if (fields.state === "sent") o.text = null;
    });
    return r.ok ? { ok: true } : r;
  }

  return Object.freeze({
    get mode() { return mode; },
    createRequest, recordEvent, appendReply, readReplies, status, has, record,
    holdLate, latePending, readLateText, promoteLate, dropLate,
    enqueue, outbox, outboxTransition,
    close() {
      if (closed) return;
      try { releaseLock(); } catch { /* owner-matched only */ }
      closed = true;
    },
  });
}
