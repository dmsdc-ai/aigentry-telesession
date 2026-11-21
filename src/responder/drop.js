/**
 * The tool-runtime side of the scoped responder (issue #18): a private DROP DIRECTORY, because a filtered
 * tool runtime can always write a file but can never be given a session credential. Nothing here
 * authenticates anything — every file is a claim that src/responder/responder.js checks against the
 * daemon audit and the recorded binding.
 *
 *   <drop>/inbound/<name>.json       {v:1, prompt, arrival_ms?}            written by the tool or the host
 *   <drop>/capabilities/<id>.json    {v:1, binding_id, challenge, …}       written HERE, read by the tool
 *   <drop>/replies/<id>.json         {v:1, binding_id, challenge, body}    written by the tool
 *   <drop>/results/<name>            the record of what happened                  written HERE
 *
 * The capability carries no bearer: it names one request and is spent by one reply. The directory is the
 * trust boundary (POSIX: owner-only, verified at open; win32: ownership/mode are NOT verifiable and are
 * reported `unverified`, as src/store.js does).
 *
 * Bounded: at most `perPass` files of each kind per pass, `fileBytes` per file, strict names and keys.
 * A file whose refusal is final is answered and removed; a retryable one is left for the next pass.
 * Node >= 20 builtins only. Synchronous fs, no shell, no recursive removal.
 */

import nodeFs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";

export const DROP_LIMITS = Object.freeze({ fileBytes: 64 * 1024, perPass: 32, bodyChars: 7900, promptChars: 8192 });

const SUBDIRS = Object.freeze(["inbound", "capabilities", "replies", "results"]);
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.json$/;
const HEX32_RE = /^[0-9a-f]{32}$/;
const CHALLENGE_RE = /^[A-Za-z0-9_-]{43}$/;
// Codes that may succeed later (audit read, daemon, durable write): the file stays for the next pass.
// REPLY_UNCERTAIN is deliberately NOT here: that send may have taken effect and is never repeated.
const RETRYABLE_CODES = new Set(["AUDIT_UNAVAILABLE", "RESPONDER_WRITE_FAILED", "RESPONDER_LOCK_LOST",
  "RESPONDER_FULL", "BINDING_IN_FLIGHT", "BINDING_STATE_CHANGED"]);
const retryable = (code) => code !== null && (RETRYABLE_CODES.has(code) || code.startsWith("DAEMON_"));

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
export function openDropDir(dir, { fs = nodeFs, platform = process.platform, create = true } = {}) {
  if (typeof dir !== "string" || !path.isAbsolute(dir) || path.normalize(dir) !== dir) throw new DropError("RESPONDER_DROP_PATH_INVALID");
  const win32 = platform === "win32";
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  const C_ = fs.constants || nodeFs.constants;
  const NOFOLLOW = typeof C_.O_NOFOLLOW === "number" ? C_.O_NOFOLLOW : 0;
  const privateOk = (st) => win32 || (uid !== null && st.uid === uid && (st.mode & 0o077) === 0);

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
  }

  ensureDir(dir);
  for (const name of SUBDIRS) ensureDir(path.join(dir, name));

  function readBounded(file) {
    let st;
    try { st = fs.lstatSync(file); } catch (err) {
      return err && err.code === "ENOENT" ? { status: "missing" } : { status: "bad" };
    }
    if (st.isSymbolicLink() || !st.isFile() || st.nlink !== 1 || st.size > DROP_LIMITS.fileBytes) return { status: "bad" };
    let fd = null;
    try {
      fd = fs.openSync(file, C_.O_RDONLY | NOFOLLOW);
      const buf = Buffer.alloc(st.size + 1);
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

  function write(sub, name, value) {
    const file = path.join(dir, sub, name);
    const tmp = path.join(dir, sub, `.${name}.${randomBytes(8).toString("hex")}.tmp`);
    let fd = null;
    try {
      fd = fs.openSync(tmp, C_.O_WRONLY | C_.O_CREAT | C_.O_EXCL | NOFOLLOW, 0o600);
      fs.writeSync(fd, Buffer.from(`${JSON.stringify(value)}\n`, "utf8"));
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = null;
      fs.renameSync(tmp, file);
      return { ok: true };
    } catch {
      if (fd !== null) { try { fs.closeSync(fd); } catch { /* best effort */ } }
      try { fs.unlinkSync(tmp); } catch { /* never created */ }
      return { ok: false, code: "RESPONDER_DROP_WRITE_FAILED" };
    }
  }

  function list(sub) {
    let names;
    try { names = fs.readdirSync(path.join(dir, sub)); } catch { return []; }
    return names.filter((n) => NAME_RE.test(n)).sort().slice(0, DROP_LIMITS.perPass);
  }

  function remove(sub, name) {
    try {
      const file = path.join(dir, sub, name);
      if (fs.lstatSync(file).isFile()) fs.unlinkSync(file);
    } catch { /* best effort: already gone */ }
  }

  function read(sub, name) {
    const r = readBounded(path.join(dir, sub, name));
    if (r.status !== "ok") return { ok: false, code: r.status === "missing" ? "DROP_MISSING" : "DROP_UNREADABLE" };
    try { return { ok: true, value: JSON.parse(r.text) }; } catch { return { ok: false, code: "DROP_INVALID" }; }
  }

  return Object.freeze({
    dir, list, read, write, remove,
    permissions: win32 ? "unverified" : "verified",
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

const errorCode = (r) => (r && r.ok === false && r.error && typeof r.error.code === "string" ? r.error.code : null);

/**
 * ONE bounded pass: register inbound claims (issuing capabilities for the verified ones), then perform the
 * scoped replies. Returns counts and the per-file codes; it never throws for a bad file.
 */
export async function runDropPass({ responder, drop }) {
  const out = { inbound: { processed: 0, issued: 0, refused: 0, retried: 0 }, replies: { processed: 0, sent: 0, refused: 0, retried: 0 }, files: [] };

  for (const name of drop.list("inbound")) {
    out.inbound.processed += 1;
    const r = drop.read("inbound", name);
    const claim = r.ok ? parseInboundClaim(r.value) : null;
    if (claim === null) {
      out.inbound.refused += 1;
      out.files.push({ kind: "inbound", name, code: r.ok ? "DROP_INVALID" : r.code });
      drop.write("results", name, { v: 1, kind: "inbound", ok: false, code: r.ok ? "DROP_INVALID" : r.code });
      drop.remove("inbound", name);
      continue;
    }
    const rec = await responder.recordInbound(claim);
    const code = errorCode(rec);
    if (retryable(code)) {
      out.inbound.retried += 1;
      out.files.push({ kind: "inbound", name, code, retry: true });
      continue;                                        // the claim stays for the next pass
    }
    if (rec.ok === true) {
      out.inbound.issued += 1;
      if (typeof rec.challenge === "string") {
        // The capability (and ONLY it) is handed to the tool runtime.
        drop.write("capabilities", `${rec.binding_id}.json`, {
          v: 1, binding_id: rec.binding_id, challenge: rec.challenge, nonce: rec.nonce,
          destination_session: rec.destination.session, expires_at: rec.expires_at,
        });
      }
      drop.write("results", name, {
        v: 1, kind: "inbound", ok: true, binding_id: rec.binding_id, nonce: rec.nonce,
        destination_session: rec.destination.session, expires_at: rec.expires_at,
        reissued: rec.reissued === true, deduplicated: rec.deduplicated === true,
        capability: typeof rec.challenge === "string" ? `capabilities/${rec.binding_id}.json` : null,
        outcome: rec.outcome === undefined ? null : rec.outcome,
      });
    } else {
      out.inbound.refused += 1;
      drop.write("results", name, { v: 1, kind: "inbound", ok: false, code, candidates: rec.error.candidates ?? null });
    }
    out.files.push({ kind: "inbound", name, code: code === null ? "ISSUED" : code });
    drop.remove("inbound", name);
  }

  for (const name of drop.list("replies")) {
    out.replies.processed += 1;
    const r = drop.read("replies", name);
    const parsed = r.ok ? parseReplyDrop(r.value) : null;
    if (parsed === null) {
      out.replies.refused += 1;
      out.files.push({ kind: "reply", name, code: r.ok ? "DROP_INVALID" : r.code });
      drop.write("results", name, { v: 1, kind: "reply", ok: false, code: r.ok ? "DROP_INVALID" : r.code });
      drop.remove("replies", name);
      continue;
    }
    const sent = await responder.reply(parsed);
    const code = errorCode(sent);
    if (retryable(code)) {
      out.replies.retried += 1;
      out.files.push({ kind: "reply", name, code, retry: true });
      continue;
    }
    if (sent.ok === true) out.replies.sent += 1; else out.replies.refused += 1;
    drop.write("results", name, {
      v: 1, kind: "reply", ok: sent.ok === true, code, binding_id: parsed.binding_id,
      outcome: sent.ok === true ? sent.outcome : (sent.error.outcome ?? null),
      duplicate: sent.duplicate === true,
    });
    out.files.push({ kind: "reply", name, code: code === null ? "SENT" : code });
    drop.remove("replies", name);
    // The spent capability is removed with its binding's single use.
    drop.remove("capabilities", `${parsed.binding_id}.json`);
  }
  return out;
}
