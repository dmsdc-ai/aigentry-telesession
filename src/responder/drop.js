/**
 * The tool-runtime side of the scoped responder (issue #18): a private DROP DIRECTORY, because a filtered
 * tool runtime can always write a file but can never be given a session credential. Nothing here
 * authenticates anything — every file is a claim that src/responder/responder.js checks against the
 * daemon's audit, its observation and the binding record.
 *
 *   <drop>/.telesession-responder-drop   the marker this feature writes when it CREATES the directory
 *   <drop>/inbound/<name>.json       {v:1, prompt, arrival_ms?}            written by the tool or the host
 *   <drop>/capabilities/<id>.json    {v:1, binding_id, challenge, …}       written HERE, read by the tool
 *   <drop>/replies/<id>.json         {v:1, binding_id, challenge, body}    written by the tool
 *   <drop>/results/<name>            the record of what happened                  written HERE
 *
 * WHAT IT MAY DELETE (review r2 R06, guarantee G4 — the feature never damages the host):
 *   1. files it wrote itself: a capability, a result, or one of its own `.<name>.<16hex>.tmp`
 *      temporaries, and a temporary only when it is older than `tmpGraceMs` so a concurrent writer's
 *      file survives;
 *   2. the ONE input file it has just answered, identified by its exact name, its queue AND its exact
 *      content hash as recorded in the responder's own state (`noteConsumed`), re-verified on disk
 *      immediately before the unlink.
 * Anything else — an unrecognised name, a directory, a symlink, a file whose content changed — is
 * LEFT ALONE and only counted (`foreign`). It never recurses and never removes a directory. All of this
 * happens only inside a directory that carries this feature's marker; a directory without the marker is
 * refused (`RESPONDER_DROP_NOT_OURS`), so a replaced or operator-chosen path is never swept.
 *
 * On-disk lifetime, the whole truth: an inbound claim holds the request text and a reply drop holds the
 * reply body in plaintext until the pass that answers it removes it; a capability holds its challenge in
 * plaintext until it is spent, refused terminally or swept after its binding's deadline; a result holds
 * codes, hashes and an outcome — never a body, a challenge or a bearer — and is swept after
 * `resultRetainMs`. A pass that cannot publish leaves the input in place and reports a retry, so a crash
 * or a full disk can extend those lifetimes until the next pass.
 *
 * Node >= 20 builtins only. Synchronous fs, no shell, no recursive removal.
 */

import nodeFs from "node:fs";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";

export const DROP_LIMITS = Object.freeze({
  fileBytes: 64 * 1024, perPass: 32, scanEntries: 256, bodyChars: 7900, promptChars: 8192,
  resultRetainMs: 86400000, tmpGraceMs: 60000,
});

export const DROP_MARKER = ".telesession-responder-drop";
const SUBDIRS = Object.freeze(["inbound", "capabilities", "replies", "results"]);
const INPUT_QUEUES = Object.freeze(["inbound", "replies"]);
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.json$/;
const CAPABILITY_NAME_RE = /^[0-9a-f]{32}\.json$/;
const OWN_TMP_RE = /^\.[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.json\.[0-9a-f]{16}\.tmp$/;
const HEX32_RE = /^[0-9a-f]{32}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const CHALLENGE_RE = /^[A-Za-z0-9_-]{43}$/;
const DIR_FSYNC_IGNORED = new Set(["EISDIR", "EPERM", "EINVAL", "EBADF"]);
// Codes that may succeed later (audit read, observation, daemon, durable write). r2 R14: this list is
// consulted ONLY when the responder recorded no outcome; once an outcome exists the drop is terminal,
// whatever the code looks like.
const RETRYABLE_CODES = new Set([
  "AUDIT_UNAVAILABLE", "RECONCILE_AUDIT_INCOMPLETE", "INBOUND_AUDIT_INCOMPLETE", "OBSERVATION_UNAVAILABLE",
  "DAEMON_UNREACHABLE", "DAEMON_BAD_RESPONSE", "DAEMON_BODY_TOO_LARGE", "DAEMON_BODY_UNREADABLE",
  "RESPONDER_WRITE_FAILED", "RESPONDER_LOCK_LOST", "RESPONDER_FULL", "BINDING_IN_FLIGHT",
  "BINDING_STATE_CHANGED", "CREDENTIAL_UNAVAILABLE",
]);

export class DropError extends Error {
  constructor(code) {
    super(code);
    this.name = "DropError";
    this.code = code;
  }
}

const isPlain = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const exactKeys = (v, keys) => isPlain(v) && Object.keys(v).length === keys.length && keys.every((k) => Object.prototype.hasOwnProperty.call(v, k));
const sha256hex = (b) => createHash("sha256").update(b).digest("hex");

/**
 * Opens the private drop directory. With `create` it is created and marked; an existing directory must
 * already carry this feature's marker, otherwise nothing in it is read, written or removed.
 */
export function openDropDir(dir, { fs = nodeFs, platform = process.platform, create = true, now = Date.now } = {}) {
  // Windows file-access semantics are not verified by this implementation, so the responder does not run
  // there rather than claim a protection it has not checked.
  if (platform === "win32") throw new DropError("RESPONDER_PLATFORM_UNSUPPORTED");
  if (typeof dir !== "string" || !path.isAbsolute(dir) || path.normalize(dir) !== dir) throw new DropError("RESPONDER_DROP_PATH_INVALID");
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  const C_ = fs.constants || nodeFs.constants;
  const NOFOLLOW = typeof C_.O_NOFOLLOW === "number" ? C_.O_NOFOLLOW : 0;
  const privateOk = (st) => uid !== null && st.uid === uid && (st.mode & 0o077) === 0;

  function syncDir(p) {
    let fd;
    try { fd = fs.openSync(p, "r"); } catch (err) {
      if (DIR_FSYNC_IGNORED.has(err && err.code)) return;
      return;                                       // best effort: never fail a pass on a dir fsync
    }
    try { fs.fsyncSync(fd); } catch { /* best effort */ } finally {
      try { fs.closeSync(fd); } catch { /* best effort */ }
    }
  }

  function inspectDir(p, { mayCreate }) {
    let st = null;
    try { st = fs.lstatSync(p); } catch (err) {
      if (!err || err.code !== "ENOENT") throw new DropError("RESPONDER_DROP_WRITE_FAILED");
    }
    if (st === null) {
      if (!mayCreate) throw new DropError("RESPONDER_DROP_NOT_FOUND");
      try { fs.mkdirSync(p, { mode: 0o700 }); } catch (err) {
        if (!err || err.code !== "EEXIST") throw new DropError("RESPONDER_DROP_WRITE_FAILED");
      }
      st = fs.lstatSync(p);
      return { st, created: true };
    }
    if (st.isSymbolicLink() || !st.isDirectory()) throw new DropError("RESPONDER_DROP_PATH_INVALID");
    if (!privateOk(st)) throw new DropError("RESPONDER_DROP_PERMISSIONS_INVALID");
    return { st, created: false };
  }

  const root = inspectDir(dir, { mayCreate: create });
  if (!root.created) {
    if (!privateOk(root.st)) throw new DropError("RESPONDER_DROP_PERMISSIONS_INVALID");
  }

  // The marker: proof that this directory is this feature's queue and not some other directory a
  // configuration (or a replacement) pointed at. Written when we create it; required afterwards.
  const markerPath = path.join(dir, DROP_MARKER);
  let markerSt = null;
  try { markerSt = fs.lstatSync(markerPath); } catch (err) {
    if (!err || err.code !== "ENOENT") throw new DropError("RESPONDER_DROP_NOT_OURS");
  }
  if (markerSt === null) {
    // The marker is written ONLY for a directory this call created. An existing directory without it is
    // somebody else's and is never read, written or swept (r2 R06).
    if (!root.created) throw new DropError("RESPONDER_DROP_NOT_OURS");
    let fd = null;
    try {
      fd = fs.openSync(markerPath, C_.O_WRONLY | C_.O_CREAT | C_.O_EXCL | NOFOLLOW, 0o600);
      fs.writeSync(fd, Buffer.from(`${JSON.stringify({ v: 1, marker: "telesession-responder-drop", created_at: new Date(now()).toISOString() })}\n`, "utf8"));
      fs.fsyncSync(fd);
    } catch {
      throw new DropError("RESPONDER_DROP_NOT_OURS");
    } finally {
      if (fd !== null) { try { fs.closeSync(fd); } catch { /* best effort */ } }
    }
    syncDir(dir);
  } else if (markerSt.isSymbolicLink() || !markerSt.isFile()) {
    throw new DropError("RESPONDER_DROP_NOT_OURS");
  }

  // Resolved identity, for the caller's containment decisions (r2 R08) — never a lexical comparison.
  let real = dir;
  try { real = typeof fs.realpathSync.native === "function" ? fs.realpathSync.native(dir) : fs.realpathSync(dir); } catch { real = dir; }
  const rootId = `${root.st.dev}:${root.st.ino}`;

  for (const name of SUBDIRS) inspectDir(path.join(dir, name), { mayCreate: true });

  // The subdirectory is re-checked on every use. Node exposes no openat/dirfd, so an ancestor replaced
  // between this check and the operation is a stated residual (FINDING-MAP-R2.md R06/R08), bounded by
  // the marker requirement and by never deleting anything we did not write or record.
  function subdir(sub) {
    const p = path.join(dir, sub);
    inspectDir(p, { mayCreate: false });
    return p;
  }

  function readBounded(file) {
    let st;
    try { st = fs.lstatSync(file); } catch (err) {
      return err && err.code === "ENOENT" ? { status: "missing" } : { status: "bad" };
    }
    if (st.isSymbolicLink() || !st.isFile() || st.nlink !== 1 || st.size > DROP_LIMITS.fileBytes) return { status: "bad" };
    let fd = null;
    try {
      fd = fs.openSync(file, C_.O_RDONLY | NOFOLLOW);
      const fst = fs.fstatSync(fd);
      if (!fst.isFile() || fst.nlink !== 1 || fst.size > DROP_LIMITS.fileBytes || fst.ino !== st.ino || fst.dev !== st.dev) {
        return { status: "bad" };
      }
      const buf = Buffer.alloc(fst.size + 1);
      let off = 0;
      for (;;) {
        const n = fs.readSync(fd, buf, off, buf.length - off, null);
        if (n <= 0) break;
        off += n;
        if (off === buf.length) return { status: "bad" };
      }
      const bytes = buf.subarray(0, off);
      return { status: "ok", text: bytes.toString("utf8"), sha256: sha256hex(bytes), dev: fst.dev, ino: fst.ino };
    } catch {
      return { status: "bad" };
    } finally {
      if (fd !== null) { try { fs.closeSync(fd); } catch { /* already closed */ } }
    }
  }

  // r2 R12: a complete write, fsync, rename and a fsync of the destination directory, or a reported
  // failure. The caller must not acknowledge or remove an input when this fails.
  function write(sub, name, value) {
    let d;
    try { d = subdir(sub); } catch { return { ok: false, code: "RESPONDER_DROP_WRITE_FAILED" }; }
    const file = path.join(d, name);
    const tmp = path.join(d, `.${name}.${randomBytes(8).toString("hex")}.tmp`);
    const bytes = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
    let fd = null;
    let renamed = false;
    try {
      fd = fs.openSync(tmp, C_.O_WRONLY | C_.O_CREAT | C_.O_EXCL | NOFOLLOW, 0o600);
      let off = 0;
      while (off < bytes.length) {
        const n = fs.writeSync(fd, bytes, off, bytes.length - off);
        if (!(n > 0)) throw Object.assign(new Error("EIO"), { code: "EIO" });
        off += n;
      }
      fs.fsyncSync(fd);
      const closing = fd;
      fd = null;
      fs.closeSync(closing);
      fs.renameSync(tmp, file);
      renamed = true;
      syncDir(d);
      return { ok: true };
    } catch {
      if (fd !== null) { try { fs.closeSync(fd); } catch { /* best effort */ } }
      if (!renamed) { try { fs.unlinkSync(tmp); } catch { /* never created */ } }
      return { ok: false, code: "RESPONDER_DROP_WRITE_FAILED" };
    }
  }

  /**
   * One bounded listing. r2 R06: an entry that is not a recognised name is NEVER removed — it is counted
   * as `foreign` and left exactly as it is. Only our own stale temporaries are cleaned. r2 R11: when more
   * names match than one pass may answer, the selection is a uniform random sample, so no stable prefix
   * can starve the rest (this component keeps no per-file history). r2 R17: a queue that cannot be read
   * is reported as an error, never as an empty queue.
   */
  function list(sub) {
    let d;
    try { d = subdir(sub); } catch (err) { return { names: [], foreign: 0, scanned: 0, swept: 0, error: (err && err.code) || "RESPONDER_DROP_WRITE_FAILED" }; }
    let dh;
    try { dh = fs.opendirSync(d); } catch (err) {
      return { names: [], foreign: 0, scanned: 0, swept: 0, error: `RESPONDER_DROP_UNREADABLE_${(err && err.code) || "EIO"}` };
    }
    const matched = [];
    let foreign = 0;
    let scanned = 0;
    let swept = 0;
    const cutoff = now() - DROP_LIMITS.tmpGraceMs;
    try {
      for (let e = dh.readSync(); e !== null && scanned < DROP_LIMITS.scanEntries; e = dh.readSync()) {
        scanned += 1;
        const name = e.name;
        if (OWN_TMP_RE.test(name)) {
          // Ours, and only once it can no longer belong to a writer that is still publishing (R11).
          try {
            const st = fs.lstatSync(path.join(d, name));
            if (st.isFile() && st.nlink === 1 && st.mtimeMs < cutoff) { fs.unlinkSync(path.join(d, name)); swept += 1; }
          } catch { /* gone */ }
          continue;
        }
        if (NAME_RE.test(name)) { matched.push(name); continue; }
        foreign += 1;                                  // left untouched, on purpose
      }
    } finally {
      try { dh.closeSync(); } catch { /* best effort */ }
    }
    let names = matched;
    if (matched.length > DROP_LIMITS.perPass) {
      names = [];
      const pool = [...matched];
      while (names.length < DROP_LIMITS.perPass && pool.length > 0) {
        const i = randomBytes(2).readUInt16BE(0) % pool.length;
        names.push(pool.splice(i, 1)[0]);
      }
    }
    names.sort();
    return { names, foreign, scanned, swept, error: null };
  }

  function read(sub, name) {
    if (!NAME_RE.test(name)) return { ok: false, code: "DROP_INVALID" };
    let d;
    try { d = subdir(sub); } catch { return { ok: false, code: "DROP_UNREADABLE" }; }
    const r = readBounded(path.join(d, name));
    if (r.status !== "ok") return { ok: false, code: r.status === "missing" ? "DROP_MISSING" : "DROP_UNREADABLE" };
    let value;
    try { value = JSON.parse(r.text); } catch { return { ok: false, code: "DROP_INVALID", sha256: r.sha256 }; }
    return { ok: true, value, sha256: r.sha256 };
  }

  // Removes a file this feature WROTE (a capability or a result). Never a directory, never a symlink.
  function removeOwn(sub, name) {
    if (sub === "capabilities" ? !CAPABILITY_NAME_RE.test(name) : !NAME_RE.test(name)) return { ok: false, code: "NOT_OURS" };
    if (sub !== "capabilities" && sub !== "results") return { ok: false, code: "NOT_OURS" };
    let d;
    try { d = subdir(sub); } catch { return { ok: false, code: "RESPONDER_DROP_WRITE_FAILED" }; }
    const file = path.join(d, name);
    try {
      const st = fs.lstatSync(file);
      if (st.isSymbolicLink() || !st.isFile() || st.nlink !== 1) return { ok: false, code: "NOT_OURS" };
      fs.unlinkSync(file);
      return { ok: true };
    } catch (err) {
      return err && err.code === "ENOENT" ? { ok: true } : { ok: false, code: "RESPONDER_DROP_WRITE_FAILED" };
    }
  }

  /**
   * Removes the ONE input this pass answered. `record` is the responder's own consumed-input record
   * (queue, name, sha256); the file on disk must still be a regular single-link file with exactly that
   * content. Anything else is left alone (r2 R06).
   */
  function removeConsumedInput(record) {
    if (!isPlain(record) || !INPUT_QUEUES.includes(record.queue) || !NAME_RE.test(String(record.name)) || !HEX64_RE.test(String(record.sha256))) {
      return { ok: false, code: "NOT_RECORDED" };
    }
    let d;
    try { d = subdir(record.queue); } catch { return { ok: false, code: "RESPONDER_DROP_WRITE_FAILED" }; }
    const file = path.join(d, record.name);
    const r = readBounded(file);
    if (r.status === "missing") return { ok: true, already: true };
    if (r.status !== "ok") return { ok: false, code: "DROP_CHANGED" };
    if (r.sha256 !== record.sha256) return { ok: false, code: "DROP_CHANGED" };
    try {
      fs.unlinkSync(file);
      return { ok: true };
    } catch (err) {
      return err && err.code === "ENOENT" ? { ok: true, already: true } : { ok: false, code: "RESPONDER_DROP_WRITE_FAILED" };
    }
  }

  // Expired capabilities and old results, both written by this feature (r2 R06/F13). Bounded per pass.
  function sweep(isSpentCapability) {
    const swept = { capabilities: 0, results: 0, foreign: 0, errors: [] };
    const caps = list("capabilities");
    if (caps.error) swept.errors.push({ queue: "capabilities", code: caps.error });
    swept.foreign += caps.foreign;
    for (const name of caps.names) {
      if (!CAPABILITY_NAME_RE.test(name)) { swept.foreign += 1; continue; }
      const id = name.slice(0, -5);
      if (HEX32_RE.test(id) && isSpentCapability(id) && removeOwn("capabilities", name).ok) swept.capabilities += 1;
    }
    const results = list("results");
    if (results.error) swept.errors.push({ queue: "results", code: results.error });
    swept.foreign += results.foreign;
    const cutoff = now() - DROP_LIMITS.resultRetainMs;
    for (const name of results.names) {
      try {
        let d;
        try { d = subdir("results"); } catch { break; }
        if (fs.lstatSync(path.join(d, name)).mtimeMs < cutoff && removeOwn("results", name).ok) swept.results += 1;
      } catch { /* gone already */ }
    }
    return swept;
  }

  return Object.freeze({
    dir, real, id: rootId, marker: markerPath, permissions: "verified",
    list, read, write, removeOwn, removeConsumedInput, sweep,
  });
}

// Strict shapes: a reply drop may carry NOTHING but its capability and its body. A destination, nonce,
// principal or generation in the file is a refusal, not an override.
export function parseInboundClaim(v) {
  if (!exactKeys(v, ["v", "prompt"]) && !exactKeys(v, ["v", "prompt", "arrival_ms"])) return null;
  if (v.v !== 1 || typeof v.prompt !== "string" || v.prompt.length < 1 || v.prompt.length > DROP_LIMITS.promptChars) return null;
  if (v.arrival_ms !== undefined && !Number.isSafeInteger(v.arrival_ms)) return null;
  return { prompt: v.prompt, ...(v.arrival_ms === undefined ? {} : { arrival_ms: v.arrival_ms }) };
}

export function parseReplyDrop(v) {
  if (!exactKeys(v, ["v", "binding_id", "challenge", "body"])) return null;
  if (v.v !== 1 || typeof v.binding_id !== "string" || !HEX32_RE.test(v.binding_id)) return null;
  if (typeof v.challenge !== "string" || !CHALLENGE_RE.test(v.challenge)) return null;
  if (typeof v.body !== "string" || v.body.length < 1 || v.body.length > DROP_LIMITS.bodyChars || v.body.includes("\u0000")) return null;
  return { binding_id: v.binding_id, challenge: v.challenge, body: v.body };
}

const errorOf = (r) => (r && r.ok === false && r.error && typeof r.error.code === "string" ? r.error : null);

/**
 * r2 R14: whether a refusal may be presented again. A refusal the responder RECORDED as an outcome is
 * terminal whatever its code looks like; only a refusal that left the binding spendable (or never
 * touched it) is retryable, and then only for a code that can succeed later.
 */
export function retryable(result) {
  const err = errorOf(result);
  if (err === null) return false;
  if (isPlain(err.outcome)) return false;
  return RETRYABLE_CODES.has(err.code);
}

/**
 * ONE bounded pass: register inbound claims (issuing capabilities for the verified ones), then perform
 * the scoped replies, then sweep. Counts are per outcome kind — a duplicate or an uncertain outcome is
 * never counted or reported as a new send. Returns codes and counts only: caller-chosen filenames are
 * not echoed, because they are untrusted text. `errors` is non-empty when a queue could not be read or a
 * result could not be published; the caller must treat that as a failed pass (r2 R17).
 */
export async function runDropPass({ responder, drop }) {
  const out = {
    inbound: { processed: 0, issued: 0, capabilities: 0, refused: 0, retried: 0, foreign: 0 },
    replies: { processed: 0, sent: 0, duplicate: 0, uncertain: 0, refused: 0, retried: 0, foreign: 0 },
    codes: {}, errors: [], swept: { capabilities: 0, results: 0, foreign: 0 },
  };
  const note = (code) => { out.codes[code] = (out.codes[code] || 0) + 1; };

  // Publishes the answer for an input, then — and only then — records and removes that exact input.
  function finish(queue, name, sha256, value, counters) {
    const published = drop.write("results", name, value);
    if (!published.ok) {
      counters.retried += 1;
      note("RESPONDER_DROP_WRITE_FAILED");
      out.errors.push({ queue: "results", code: "RESPONDER_DROP_WRITE_FAILED" });
      return false;
    }
    const recorded = responder.noteConsumed({ queue, name, sha256 });
    if (!recorded || recorded.ok !== true) {
      counters.retried += 1;
      const code = recorded && recorded.error && recorded.error.code ? recorded.error.code : "RESPONDER_WRITE_FAILED";
      note(code);
      out.errors.push({ queue, code });
      return false;
    }
    const removed = drop.removeConsumedInput(recorded.record);
    if (!removed.ok) {
      note(removed.code);
      out.errors.push({ queue, code: removed.code });
    }
    return true;
  }

  const inbound = drop.list("inbound");
  out.inbound.foreign = inbound.foreign;
  if (inbound.error) out.errors.push({ queue: "inbound", code: inbound.error });
  for (const name of inbound.names) {
    out.inbound.processed += 1;
    const r = drop.read("inbound", name);
    const claim = r.ok ? parseInboundClaim(r.value) : null;
    if (claim === null) {
      const code = r.ok ? "DROP_INVALID" : r.code;
      if (code === "DROP_MISSING") { note(code); continue; }
      if (typeof r.sha256 !== "string") { note(code); out.errors.push({ queue: "inbound", code }); continue; }
      out.inbound.refused += 1;
      note(code);
      finish("inbound", name, r.sha256, { v: 1, kind: "inbound", ok: false, code }, out.inbound);
      continue;
    }
    const rec = await responder.recordInbound(claim);
    if (retryable(rec)) {
      out.inbound.retried += 1;
      note(errorOf(rec).code);
      continue;                                        // the claim stays for the next pass
    }
    if (rec.ok === true) {
      // The capability (and ONLY it) is handed to the tool runtime, and only a published capability
      // consumes the claim.
      let capability = null;
      if (typeof rec.challenge === "string") {
        const w = drop.write("capabilities", `${rec.binding_id}.json`, {
          v: 1, binding_id: rec.binding_id, challenge: rec.challenge, nonce: rec.nonce,
          destination_session: rec.destination.session, expires_at: rec.expires_at,
        });
        if (!w.ok) {
          out.inbound.retried += 1;
          note("RESPONDER_DROP_WRITE_FAILED");
          out.errors.push({ queue: "capabilities", code: "RESPONDER_DROP_WRITE_FAILED" });
          continue;
        }
        capability = `capabilities/${rec.binding_id}.json`;
        out.inbound.capabilities += 1;                 // r2 R14: counted only when one was published
      }
      out.inbound.issued += 1;
      note(rec.reissued === true ? "REISSUED" : rec.deduplicated === true ? "DEDUPLICATED" : "ISSUED");
      finish("inbound", name, r.sha256, {
        v: 1, kind: "inbound", ok: true, binding_id: rec.binding_id, nonce: rec.nonce,
        destination_session: rec.destination.session, expires_at: rec.expires_at,
        reissued: rec.reissued === true, deduplicated: rec.deduplicated === true, capability,
        outcome: rec.outcome === undefined ? null : rec.outcome,
      }, out.inbound);
      continue;
    }
    const err = errorOf(rec);
    out.inbound.refused += 1;
    note(err.code);
    finish("inbound", name, r.sha256, { v: 1, kind: "inbound", ok: false, code: err.code, candidates: err.candidates ?? null }, out.inbound);
  }

  const replies = drop.list("replies");
  out.replies.foreign = replies.foreign;
  if (replies.error) out.errors.push({ queue: "replies", code: replies.error });
  for (const name of replies.names) {
    out.replies.processed += 1;
    const r = drop.read("replies", name);
    const parsed = r.ok ? parseReplyDrop(r.value) : null;
    if (parsed === null) {
      const code = r.ok ? "DROP_INVALID" : r.code;
      if (code === "DROP_MISSING") { note(code); continue; }
      if (typeof r.sha256 !== "string") { note(code); out.errors.push({ queue: "replies", code }); continue; }
      out.replies.refused += 1;
      note(code);
      finish("replies", name, r.sha256, { v: 1, kind: "reply", ok: false, code }, out.replies);
      continue;
    }
    const sent = await responder.reply(parsed);
    if (retryable(sent)) {
      out.replies.retried += 1;
      note(errorOf(sent).code);
      continue;
    }
    const err = errorOf(sent);
    const code = err === null ? null : err.code;
    const outcome = sent.ok === true ? sent.outcome : (err && err.outcome) || null;
    const kindOf = sent.ok === true && sent.duplicate === true ? "duplicate"
      : sent.ok === true ? "sent"
        : outcome && outcome.result === "uncertain" ? "uncertain" : "refused";
    out.replies[kindOf] += 1;
    note(code === null ? (kindOf === "duplicate" ? "DUPLICATE" : "SENT") : code);
    const done = finish("replies", name, r.sha256, {
      v: 1, kind: "reply", ok: sent.ok === true, result: kindOf, code, binding_id: parsed.binding_id,
      outcome, duplicate: sent.duplicate === true,
      durability: sent.ok === true ? sent.durability : (err && err.durability) || null,
    }, out.replies);
    // r2 R14: the capability is removed only when its binding can never be spent again — decided from
    // the recorded state, not from the shape of an error code.
    if (done && !["live", "sending"].includes(responder.capabilityState(parsed.binding_id))) {
      drop.removeOwn("capabilities", `${parsed.binding_id}.json`);
    }
  }

  const spent = (id) => !["live", "sending"].includes(responder.capabilityState(id));
  const swept = drop.sweep(spent);
  out.swept = { capabilities: swept.capabilities, results: swept.results, foreign: swept.foreign };
  for (const e of swept.errors) out.errors.push(e);
  return out;
}
