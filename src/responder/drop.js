/**
 * The tool-runtime side of the scoped responder (issue #18): a private DROP DIRECTORY, because a filtered
 * tool runtime can always write a file but can never be given a session credential. Nothing here
 * authenticates anything — every file is a claim that src/responder/responder.js checks against the
 * daemon's audit, its observation and the authenticated binding record.
 *
 *   <drop>/inbound/<name>.json       {v:1, prompt, arrival_ms?}            written by the tool or the host
 *   <drop>/capabilities/<id>.json    {v:1, binding_id, challenge, …}       written HERE, read by the tool
 *   <drop>/replies/<id>.json         {v:1, binding_id, challenge, body}    written by the tool
 *   <drop>/results/<name>            the record of what happened                  written HERE
 *
 * On-disk lifetime (review r1 F13), the whole truth: an inbound claim holds the request text and a reply
 * drop holds the reply body in plaintext until the pass that answers it removes it; a capability holds
 * its challenge in plaintext until it is spent, refused terminally or swept after its binding's deadline;
 * a result holds codes, hashes and an outcome — never a body, a challenge or a bearer — and is swept
 * after `resultRetainMs`. A pass that cannot publish leaves the input in place and reports a retry, so a
 * crash or a full disk can extend those lifetimes until the next pass. Everything is owner-only (0600 in
 * 0700 directories) and win32 is refused, because its ACLs are not verified here (F06).
 *
 * Bounded: `scanEntries` directory entries examined, `perPass` files of each kind answered, `fileBytes`
 * per file, strict names and keys. An entry that can never be a valid drop (bad name, symlink,
 * non-regular, oversize, unparsable, widened shape) is answered and removed; a retryable one is kept.
 * Node >= 20 builtins only. Synchronous fs, no shell, no recursive removal.
 */

import nodeFs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";

export const DROP_LIMITS = Object.freeze({
  fileBytes: 64 * 1024, perPass: 32, scanEntries: 256, bodyChars: 7900, promptChars: 8192,
  resultRetainMs: 86400000,
});

const SUBDIRS = Object.freeze(["inbound", "capabilities", "replies", "results"]);
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.json$/;
const HEX32_RE = /^[0-9a-f]{32}$/;
const CHALLENGE_RE = /^[A-Za-z0-9_-]{43}$/;
// Codes that may succeed later (audit read, observation, daemon, durable write): the file stays for the
// next pass. REPLY_UNCERTAIN is deliberately NOT here: that send may have taken effect and is never
// repeated. AUDIT_UNACCOUNTED_REPLY is NOT here either: it means the local history disagrees with the
// daemon, which an operator must look at (F01).
const RETRYABLE_CODES = new Set([
  "AUDIT_UNAVAILABLE", "RECONCILE_AUDIT_INCOMPLETE", "INBOUND_AUDIT_INCOMPLETE", "OBSERVATION_UNAVAILABLE",
  "RESPONDER_WRITE_FAILED", "RESPONDER_LOCK_LOST", "RESPONDER_FULL", "BINDING_IN_FLIGHT",
  "BINDING_STATE_CHANGED", "CREDENTIAL_UNAVAILABLE",
]);
const retryable = (code) => code !== null && (RETRYABLE_CODES.has(code) || code.startsWith("DAEMON_"));
// A refusal that leaves the binding spendable: its capability file must survive (F11).
const NON_TERMINAL = new Set(["CHALLENGE_MISMATCH"]);

export class DropError extends Error {
  constructor(code) {
    super(code);
    this.name = "DropError";
    this.code = code;
  }
}

const isPlain = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const exactKeys = (v, keys) => isPlain(v) && Object.keys(v).length === keys.length && keys.every((k) => Object.prototype.hasOwnProperty.call(v, k));

/** Opens (and, with `create`, creates) the private drop directory and its four subdirectories. */
export function openDropDir(dir, { fs = nodeFs, platform = process.platform, create = true, now = Date.now } = {}) {
  // F06: Windows ACLs are not verified by this implementation, so the responder refuses to run there.
  if (platform === "win32") throw new DropError("RESPONDER_PLATFORM_UNSUPPORTED");
  if (typeof dir !== "string" || !path.isAbsolute(dir) || path.normalize(dir) !== dir) throw new DropError("RESPONDER_DROP_PATH_INVALID");
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  const C_ = fs.constants || nodeFs.constants;
  const NOFOLLOW = typeof C_.O_NOFOLLOW === "number" ? C_.O_NOFOLLOW : 0;
  const privateOk = (st) => uid !== null && st.uid === uid && (st.mode & 0o077) === 0;

  function ensureDir(p) {
    let st = null;
    try { st = fs.lstatSync(p); } catch (err) {
      if (!err || err.code !== "ENOENT") throw new DropError("RESPONDER_DROP_WRITE_FAILED");
    }
    if (st === null) {
      if (!create) throw new DropError("RESPONDER_DROP_NOT_FOUND");
      try { fs.mkdirSync(p, { mode: 0o700 }); } catch (err) {
        if (!err || err.code !== "EEXIST") throw new DropError("RESPONDER_DROP_WRITE_FAILED");
      }
      st = fs.lstatSync(p);
    }
    if (st.isSymbolicLink() || !st.isDirectory()) throw new DropError("RESPONDER_DROP_PATH_INVALID");
    if (!privateOk(st)) throw new DropError("RESPONDER_DROP_PERMISSIONS_INVALID");
    return st;
  }

  ensureDir(dir);
  for (const name of SUBDIRS) ensureDir(path.join(dir, name));

  // F09: the subdirectory is re-checked on every pass, and the opened descriptor must be the object that
  // was stat'ed. Node exposes no openat/dirfd, so a same-user actor that renames a subdirectory between
  // this check and a write is a stated residual (FINDING-MAP-R1.md F09), not a silent one.
  function subdir(sub) {
    return ensureDir(path.join(dir, sub));
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
      return { status: "ok", text: buf.subarray(0, off).toString("utf8") };
    } catch {
      return { status: "bad" };
    } finally {
      if (fd !== null) { try { fs.closeSync(fd); } catch { /* already closed */ } }
    }
  }

  // F10: a complete write, fsync and rename, or a reported failure. Short writes are looped, never
  // assumed; the caller must not acknowledge or remove an input when this fails.
  function write(sub, name, value) {
    try { subdir(sub); } catch { return { ok: false, code: "RESPONDER_DROP_WRITE_FAILED" }; }
    const file = path.join(dir, sub, name);
    const tmp = path.join(dir, sub, `.${name}.${randomBytes(8).toString("hex")}.tmp`);
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
      return { ok: true };
    } catch {
      if (fd !== null) { try { fs.closeSync(fd); } catch { /* best effort */ } }
      if (!renamed) { try { fs.unlinkSync(tmp); } catch { /* never created */ } }
      return { ok: false, code: "RESPONDER_DROP_WRITE_FAILED" };
    }
  }

  // F08: bounded enumeration. At most `scanEntries` entries are examined and `perPass` names returned;
  // an entry that can never be a valid drop is removed here so it cannot stall every later pass.
  function list(sub) {
    let d;
    try { d = fs.opendirSync(path.join(dir, sub)); } catch { return { names: [], dropped: 0, scanned: 0 }; }
    const names = [];
    let dropped = 0;
    let scanned = 0;
    try {
      for (let e = d.readSync(); e !== null && scanned < DROP_LIMITS.scanEntries; e = d.readSync()) {
        scanned += 1;
        const name = e.name;
        if (name.startsWith(".") && name.endsWith(".tmp")) { if (remove(sub, name)) dropped += 1; continue; }
        if (!NAME_RE.test(name)) { if (remove(sub, name)) dropped += 1; continue; }
        if (names.length < DROP_LIMITS.perPass) names.push(name);
      }
    } finally {
      try { d.closeSync(); } catch { /* best effort */ }
    }
    names.sort();
    return { names, dropped, scanned };
  }

  // Removes one entry of any type (a symlink is unlinked, never followed). Returns whether it is gone.
  function remove(sub, name) {
    const file = path.join(dir, sub, name);
    try {
      const st = fs.lstatSync(file);
      if (st.isDirectory()) { fs.rmdirSync(file); return true; }      // empty only; never recursive
      fs.unlinkSync(file);
      return true;
    } catch (err) {
      return Boolean(err) && err.code === "ENOENT";
    }
  }

  function read(sub, name) {
    const r = readBounded(path.join(dir, sub, name));
    if (r.status !== "ok") return { ok: false, code: r.status === "missing" ? "DROP_MISSING" : "DROP_UNREADABLE" };
    try { return { ok: true, value: JSON.parse(r.text) }; } catch { return { ok: false, code: "DROP_INVALID" }; }
  }

  // F13: expired capabilities and old results do not linger. Bounded per pass; mtime-based, because a
  // capability names its own deadline and a result carries no secret.
  function sweep(isExpiredCapability) {
    const swept = { capabilities: 0, results: 0 };
    const caps = list("capabilities");
    for (const name of caps.names) {
      const id = name.slice(0, -5);
      if (!HEX32_RE.test(id) || isExpiredCapability(id)) { if (remove("capabilities", name)) swept.capabilities += 1; }
    }
    const results = list("results");
    const cutoff = now() - DROP_LIMITS.resultRetainMs;
    for (const name of results.names) {
      try {
        if (fs.lstatSync(path.join(dir, "results", name)).mtimeMs < cutoff && remove("results", name)) swept.results += 1;
      } catch { /* gone already */ }
    }
    return swept;
  }

  return Object.freeze({ dir, list, read, write, remove, sweep, permissions: "verified" });
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

const errorCode = (r) => (r && r.ok === false && r.error && typeof r.error.code === "string" ? r.error.code : null);

/**
 * ONE bounded pass: register inbound claims (issuing capabilities for the verified ones), then perform
 * the scoped replies, then sweep. Counts are per outcome kind — a duplicate or an uncertain outcome is
 * never counted or reported as a new send (F11). Returns codes and counts only: caller-chosen filenames
 * are not echoed, because they are untrusted text (F13).
 */
export async function runDropPass({ responder, drop }) {
  const out = {
    inbound: { processed: 0, issued: 0, refused: 0, retried: 0, dropped: 0 },
    replies: { processed: 0, sent: 0, duplicate: 0, uncertain: 0, refused: 0, retried: 0, dropped: 0 },
    codes: {},
    swept: { capabilities: 0, results: 0 },
  };
  const note = (code) => { out.codes[code] = (out.codes[code] || 0) + 1; };
  // A result that cannot be published leaves the input in place for the next pass (F10).
  const publish = (name, value) => drop.write("results", name, value).ok;

  const inbound = drop.list("inbound");
  out.inbound.dropped = inbound.dropped;
  for (const name of inbound.names) {
    out.inbound.processed += 1;
    const r = drop.read("inbound", name);
    const claim = r.ok ? parseInboundClaim(r.value) : null;
    if (claim === null) {
      const code = r.ok ? "DROP_INVALID" : r.code;
      if (code === "DROP_MISSING") { note(code); continue; }
      out.inbound.refused += 1;
      note(code);
      if (publish(name, { v: 1, kind: "inbound", ok: false, code })) drop.remove("inbound", name);
      continue;
    }
    const rec = await responder.recordInbound(claim);
    const code = errorCode(rec);
    if (retryable(code)) {
      out.inbound.retried += 1;
      note(code);
      continue;                                        // the claim stays for the next pass
    }
    if (rec.ok === true) {
      // The capability (and ONLY it) is handed to the tool runtime, and only a published capability
      // consumes the claim (F10).
      let published = true;
      if (typeof rec.challenge === "string") {
        published = drop.write("capabilities", `${rec.binding_id}.json`, {
          v: 1, binding_id: rec.binding_id, challenge: rec.challenge, nonce: rec.nonce,
          destination_session: rec.destination.session, expires_at: rec.expires_at,
        }).ok;
      }
      if (!published) {
        out.inbound.retried += 1;
        note("RESPONDER_DROP_WRITE_FAILED");
        continue;
      }
      out.inbound.issued += 1;
      note(rec.reissued === true ? "REISSUED" : rec.deduplicated === true ? "DEDUPLICATED" : "ISSUED");
      const ok = publish(name, {
        v: 1, kind: "inbound", ok: true, binding_id: rec.binding_id, nonce: rec.nonce,
        destination_session: rec.destination.session, expires_at: rec.expires_at,
        reissued: rec.reissued === true, deduplicated: rec.deduplicated === true,
        capability: typeof rec.challenge === "string" ? `capabilities/${rec.binding_id}.json` : null,
        outcome: rec.outcome === undefined ? null : rec.outcome,
      });
      if (ok) drop.remove("inbound", name);
      continue;
    }
    out.inbound.refused += 1;
    note(code);
    const ok = publish(name, { v: 1, kind: "inbound", ok: false, code, candidates: rec.error.candidates ?? null });
    if (ok) drop.remove("inbound", name);
  }

  const replies = drop.list("replies");
  out.replies.dropped = replies.dropped;
  for (const name of replies.names) {
    out.replies.processed += 1;
    const r = drop.read("replies", name);
    const parsed = r.ok ? parseReplyDrop(r.value) : null;
    if (parsed === null) {
      const code = r.ok ? "DROP_INVALID" : r.code;
      if (code === "DROP_MISSING") { note(code); continue; }
      out.replies.refused += 1;
      note(code);
      if (publish(name, { v: 1, kind: "reply", ok: false, code })) drop.remove("replies", name);
      continue;
    }
    const sent = await responder.reply(parsed);
    const code = errorCode(sent);
    if (retryable(code)) {
      out.replies.retried += 1;
      note(code);
      continue;
    }
    const outcome = sent.ok === true ? sent.outcome : (sent.error.outcome ?? null);
    const kindOf = sent.ok === true && sent.duplicate === true ? "duplicate"
      : sent.ok === true ? "sent"
        : code === "REPLY_UNCERTAIN" ? "uncertain" : "refused";
    out.replies[kindOf] += 1;
    note(code === null ? (kindOf === "duplicate" ? "DUPLICATE" : "SENT") : code);
    const published = publish(name, {
      v: 1, kind: "reply", ok: sent.ok === true, result: kindOf, code, binding_id: parsed.binding_id,
      outcome, duplicate: sent.duplicate === true, durability: sent.ok === true ? sent.durability : (sent.error.durability ?? null),
    });
    if (!published) {
      // The outcome is durable in the authenticated store; the next pass answers it from the record.
      out.replies.retried += 1;
      note("RESPONDER_DROP_WRITE_FAILED");
      continue;
    }
    drop.remove("replies", name);
    // F11: a capability is removed only once its binding can never be spent again.
    if (!NON_TERMINAL.has(code)) drop.remove("capabilities", `${parsed.binding_id}.json`);
  }

  // F13: expired capabilities and old results are swept; a capability whose binding is gone or spent is
  // expired by definition.
  const spent = (id) => {
    const st = responder.capabilityState(id);
    return st === "absent" || st === "spent" || st === "expired";
  };
  out.swept = drop.sweep(spent);
  return out;
}
