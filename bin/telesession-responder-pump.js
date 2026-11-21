#!/usr/bin/env node

/**
 * telesession-responder-pump — ONE pass of the scoped responder (issue #18), for the HOST process of a
 * telepty session whose model tool runtime filters the environment. It must run where the session
 * credential exists (the session host), NEVER inside the model's tool shell: the tool shell only writes
 * files into the drop directory and never sees a bearer.
 *
 * INERT until an operator activates it: without `TELESESSION_RESPONDER=1` nothing runs (exit 2). Enabling
 * it changes who can cause a trusted send, so activation is a separate approval.
 *
 * WHAT THIS GUARANTEES, in plain words (full statement in DESIGN.md §4 and README):
 *   G1 the tool runtime is never handed a reusable session bearer by this feature — nothing is written to
 *      its environment, the drop directory, this output or the state;
 *   G2 a reply is bound to the trusted inbound request: destination, nonce, principal and session
 *      instance come from the verified inbound audit row, and an honest tool runtime that makes a
 *      mistake (wrong id, duplicate, late, retried after a crash, concurrent calls), a forged or stale
 *      request, or a remote sender cannot cause a send to another destination, as another principal,
 *      twice, or after the requester's deadline;
 *   G3 claimed-only quarantine and default-off behaviour are unchanged;
 *   G4 the feature never damages the host: it removes only files it wrote plus the one input it has just
 *      answered (recorded and content-verified), never recurses, and never blocks the normal traffic of
 *      an intact installation.
 * NOT GUARANTEED: protection against a process running as the SAME OS user with arbitrary file write.
 * Such a process can read the daemon's own credential files, rewrite this package's code or replace this
 * command, so no local design can hold against it. It is out of scope, not defended against here.
 *
 * Config: TELESESSION_* (README.md) for the telepty URL and control token, plus
 *   TELESESSION_RESPONDER=1                 activation (default off)
 *   TELESESSION_RESPONDER_DROP_DIR=<abs>    the private drop directory the tool runtime writes to
 *   TELEPTY_SESSION_ID / TELEPTY_SESSION_TOKEN / TELEPTY_SESSION_EPOCH   this session's own credential
 *   TELEPTY_SESSION_GENERATION              recorded when present (optional)
 * The epoch is REQUIRED: an unknown live session instance is refused rather than assumed (r2 R03).
 * Responder state (bindings, outcomes, audit) is <state dir>/responder, one file per credential
 * instance, one lock for the directory.
 *
 * stdout: the pass result as one JSON line — counts and codes only, never a bearer, a body, a challenge
 * or a caller-chosen filename. Exit 0 = pass ran cleanly, 1 = pass failed or a queue/publication error,
 * 2 = config/activation/platform, 3 = responder state (locked, stale lock, corrupt, unauthentic).
 */

import fs from "node:fs";
import path from "node:path";
import { loadConfig } from "../src/index.js";
import { openResponderStore, deriveStateKey } from "../src/responder/store.js";
import { createResponder, classifyInjectResponse, RESPONDER_LIMITS } from "../src/responder/responder.js";
import { openDropDir, runDropPass } from "../src/responder/drop.js";

const SID_RE = /^[A-Za-z0-9._-]{1,128}$/;
const BEARER_RE = /^[\x21-\x7E]{1,4096}$/;
const EPOCH_RE = /^[^\u0000-\u001f\u007f]{1,256}$/;
const READ_TIMEOUT_MS = 5000;
const WRITE_TIMEOUT_MS = 10000;
const BODY_CAP = 256 * 1024;

const refuse = (code, exit) => {
  process.stderr.write(`telesession-responder-pump refused: ${code}\n`);
  process.exit(exit);
};

if (process.argv.length > 2) refuse("ARGS_UNEXPECTED", 2);

const env = process.env;
if (env.TELESESSION_RESPONDER !== "1") refuse("RESPONDER_NOT_ACTIVATED", 2);
// Windows file-access semantics are not verified by this implementation, so it does not run there.
if (process.platform === "win32") refuse("RESPONDER_PLATFORM_UNSUPPORTED", 2);

let cfg;
try { cfg = loadConfig(env); } catch (err) { refuse((err && err.code) || "CONFIG_INVALID", 2); }
if (cfg.stateDir === null) refuse("RESPONDER_STATE_DIR_REQUIRED", 2);
// Profile mode scopes the client token to this assistant's own inbox namespace and targets; reading the
// audit of THIS session and injecting into the requester's inbox are outside that scope (FOLLOWUPS.md).
if (cfg.profile !== null) refuse("RESPONDER_PROFILE_UNSUPPORTED", 2);

const sid = typeof env.TELEPTY_SESSION_ID === "string" ? env.TELEPTY_SESSION_ID : "";
const bearer = typeof env.TELEPTY_SESSION_TOKEN === "string" ? env.TELEPTY_SESSION_TOKEN : "";
const epoch = typeof env.TELEPTY_SESSION_EPOCH === "string" ? env.TELEPTY_SESSION_EPOCH : "";
if (!SID_RE.test(sid) || !BEARER_RE.test(bearer)) refuse("RESPONDER_SESSION_CREDENTIAL_MISSING", 2);
// r2 R03: without the live instance there is nothing to compare a recorded instance against.
if (!EPOCH_RE.test(epoch)) refuse("RESPONDER_SESSION_EPOCH_REQUIRED", 2);
const generation = /^\d{1,15}$/.test(String(env.TELEPTY_SESSION_GENERATION || "")) ? Number(env.TELEPTY_SESSION_GENERATION) : null;

const dropDir = typeof env.TELESESSION_RESPONDER_DROP_DIR === "string" ? env.TELESESSION_RESPONDER_DROP_DIR : "";
if (dropDir === "" || !path.isAbsolute(dropDir) || path.normalize(dropDir) !== dropDir) refuse("RESPONDER_DROP_DIR_INVALID", 2);

// r2 R18: the private state root is created here (one level, 0700) when its parent exists, so a freshly
// configured host does not fail its first pass. Its parent is an operator prerequisite, exactly as for
// the requester's own store (src/store.js).
const stateRoot = path.join(cfg.stateDir, "responder");
try {
  if (!fs.existsSync(cfg.stateDir)) fs.mkdirSync(cfg.stateDir, { mode: 0o700 });
} catch (err) {
  refuse(err && err.code === "ENOENT" ? "RESPONDER_STATE_DIR_PARENT_MISSING" : "RESPONDER_STATE_DIR_UNWRITABLE", 2);
}

// r2 R08: containment is decided on RESOLVED paths and filesystem identity, never on spelling. The tool
// runtime writes into the drop directory by design, so the state must not be reachable through it.
const realOf = (p) => {
  try { return typeof fs.realpathSync.native === "function" ? fs.realpathSync.native(p) : fs.realpathSync(p); } catch { return null; }
};
const idOf = (p) => { try { const st = fs.statSync(p); return `${st.dev}:${st.ino}`; } catch { return null; } };
const contains = (parent, child) => {
  const rel = path.relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
};
const realStateDir = realOf(cfg.stateDir) || cfg.stateDir;
const realStateRoot = realOf(stateRoot) || path.join(realStateDir, "responder");
const realDrop = realOf(dropDir) || dropDir;
const dropId = idOf(dropDir);
if ((dropId !== null && (dropId === idOf(cfg.stateDir) || dropId === idOf(stateRoot)))
    || contains(realStateRoot, realDrop) || contains(realDrop, realStateRoot)
    || contains(realStateDir, realDrop) || contains(realDrop, realStateDir)) {
  refuse("RESPONDER_DROP_DIR_OVERLAPS_STATE", 2);
}

// F15: a bounded read of the daemon's answer. Declared or streamed bytes over the cap are refused before
// any parsing, exactly as src/transports/telepty.js does for the same endpoints. A body lost after the
// headers is reported as such (r2 R10), never as a definitive answer.
async function readCapped(res) {
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > BODY_CAP) {
    try { await res.body?.cancel(); } catch { /* already closed */ }
    return { tooLarge: true };
  }
  if (!res.body) return { text: "" };
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > BODY_CAP) {
      try { await reader.cancel(); } catch { /* already closed */ }
      return { tooLarge: true };
    }
    chunks.push(value);
  }
  return { text: Buffer.concat(chunks).toString("utf8") };
}

// The telepty calls the responder needs. The control token reads sessions, the audit and observations;
// the SESSION token authenticates the reply — that is the whole point, and it never leaves this process.
async function call(method, pathname, { body, sessionToken, timeoutMs } = {}) {
  const headers = { "x-telepty-token": cfg.token };
  if (sessionToken) headers["x-telepty-session-token"] = sessionToken;
  if (body !== undefined) headers["content-type"] = "application/json";
  let res;
  try {
    res = await fetch(cfg.teleptyOrigin + pathname, {
      method, headers, redirect: "error", signal: AbortSignal.timeout(timeoutMs),
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
  } catch {
    return { ok: false, status: null, parsed: null, tooLarge: false, bodyFailed: false };
  }
  let read;
  try { read = await readCapped(res); } catch {
    return { ok: false, status: res.status, parsed: null, tooLarge: false, bodyFailed: true };
  }
  if (read.tooLarge) return { ok: false, status: res.status, parsed: null, tooLarge: true, bodyFailed: false };
  let parsed = null;
  let bodyFailed = false;
  try { parsed = read.text ? JSON.parse(read.text) : null; } catch { parsed = null; bodyFailed = true; }
  return { ok: res.ok, status: res.status, parsed, tooLarge: false, bodyFailed };
}

const daemon = {
  async sessions() {
    const r = await call("GET", "/api/sessions", { timeoutMs: READ_TIMEOUT_MS });
    if (r.tooLarge) return { ok: false, code: "DAEMON_BODY_TOO_LARGE" };
    if (!r.ok || !Array.isArray(r.parsed)) return { ok: false, code: r.status === null ? "DAEMON_UNREACHABLE" : "DAEMON_BAD_RESPONSE" };
    return { ok: true, ids: r.parsed.filter((s) => s && typeof s.id === "string").map((s) => s.id) };
  },

  async injects({ to, from, since, until, limit }) {
    const q = `?to=${encodeURIComponent(to)}${from === undefined ? "" : `&from=${encodeURIComponent(from)}`}`
      + `&since=${encodeURIComponent(since)}&until=${encodeURIComponent(until)}&limit=${limit}`;
    const r = await call("GET", `/api/injects${q}`, { timeoutMs: READ_TIMEOUT_MS });
    if (r.tooLarge) return { ok: false, code: "DAEMON_BODY_TOO_LARGE" };
    if (!r.ok || !r.parsed || !Array.isArray(r.parsed.injects)) {
      return { ok: false, code: r.status === null ? "DAEMON_UNREACHABLE" : "DAEMON_BAD_RESPONSE" };
    }
    return { ok: true, injects: r.parsed.injects, next_cursor: r.parsed.next_cursor ?? null };
  },

  async observe(injectId) {
    const r = await call("GET", `/api/inject-observations/${encodeURIComponent(injectId)}`, { timeoutMs: READ_TIMEOUT_MS });
    if (r.tooLarge) return { ok: false, code: "DAEMON_BODY_TOO_LARGE" };
    if (!r.ok || !r.parsed) return { ok: false, code: r.status === null ? "DAEMON_UNREACHABLE" : "OBSERVATION_UNAVAILABLE" };
    // A foreign or untracked inject answers with the schema-v2 `tracking_state: "unavailable"` body and
    // no session epoch: that is no instance evidence, so it fails closed.
    if (r.parsed.inject_id !== injectId || typeof r.parsed.session_id !== "string"
        || typeof r.parsed.session_epoch !== "string" || r.parsed.session_epoch === "") {
      return { ok: false, code: "OBSERVATION_UNAVAILABLE" };
    }
    return { ok: true, session_id: r.parsed.session_id, session_epoch: r.parsed.session_epoch };
  },

  // F07 + r2 R10: classified by the shared pure rule, which follows src/transports/telepty.js — an
  // explicitly uncertain, 5xx or unreadable answer is never a refusal, and success requires the
  // exact-target echoes.
  async inject({ to, prompt, from, sessionToken }) {
    const r = await call("POST", `/api/sessions/${encodeURIComponent(to)}/inject`, {
      body: { prompt, from, reply_to: from, exact_target: true }, sessionToken, timeoutMs: WRITE_TIMEOUT_MS,
    });
    return classifyInjectResponse(r, { to });
  },
};

let store;
try {
  store = openResponderStore({
    dir: stateRoot, session: sid, origin: cfg.teleptyOrigin,
    stateKey: deriveStateKey(bearer, { origin: cfg.teleptyOrigin, session: sid }),
  });
} catch (err) { refuse((err && err.code) || "RESPONDER_OPEN_FAILED", 3); }

let drop;
try { drop = openDropDir(dropDir); } catch (err) {
  store.close();
  refuse((err && err.code) || "RESPONDER_DROP_INVALID", 2);
}

let code = 1;
try {
  const responder = createResponder({
    store, daemon, activated: true,
    credential: () => ({ sid, bearer, epoch, generation }),
  });
  const pass = await runDropPass({ responder, drop });
  const st = responder.status();
  // r2 R17: a queue that could not be read, or a result that could not be published, is a FAILED pass —
  // never the same output as a healthy idle queue.
  const ok = pass.errors.length === 0;
  process.stdout.write(`${JSON.stringify({
    ok, session: sid, pass, bindings: st.bindings, counters: st.counters,
    state: { authenticated: st.authenticated_state, permissions: st.permissions, lock: st.lock, file: store.info().state_name },
    limits: {
      body_chars: RESPONDER_LIMITS.bodyChars, ttl_ms: RESPONDER_LIMITS.ttlMs,
      deadline_margin_ms: RESPONDER_LIMITS.deadlineMarginMs, send_margin_ms: RESPONDER_LIMITS.sendMarginMs,
    },
    completion_fact: null,
  })}\n`);
  code = ok ? 0 : 1;
} catch (err) {
  process.stderr.write(`telesession-responder-pump failed: ${(err && err.code) || "RESPONDER_PASS_FAILED"}\n`);
} finally {
  store.close();
}
process.exit(code);
