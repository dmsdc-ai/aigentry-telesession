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
 * GUARANTEE SCOPE (review r1 F01; field result 2026-11-21). The responder's state is authenticated with
 * a key derived from the session credential this process holds in memory, so a same-user actor that
 * cannot read that credential cannot forge, transplant or silently edit a binding, and a rolled-back or
 * deleted history is caught by reconciling the daemon's audit before any send. A tool runtime that DOES
 * inherit the session credential (codex-cli default shell policy) can reply as this session directly,
 * without this component, so nothing here constrains it. The operator must therefore declare the
 * filtered configuration with `TELESESSION_RESPONDER_TOOL_ENV=filtered`; verify it by running
 * `env | grep TELEPTY_SESSION` INSIDE the model's tool shell and seeing no output. Anything else is
 * refused (`RESPONDER_TOOL_ENV_UNVERIFIED`).
 *
 * Config: TELESESSION_* (README.md) for the telepty URL and control token, plus
 *   TELESESSION_RESPONDER=1                   activation (default off)
 *   TELESESSION_RESPONDER_TOOL_ENV=filtered   operator declaration of the scope above
 *   TELESESSION_RESPONDER_DROP_DIR=<abs>      the private drop directory the tool runtime writes to
 *   TELEPTY_SESSION_ID / TELEPTY_SESSION_TOKEN       this session's own credential (host env)
 *   TELEPTY_SESSION_EPOCH / TELEPTY_SESSION_GENERATION   recorded when present (optional)
 * The responder state (bindings, outcomes, audit) is <state dir>/responder, with its own lock.
 *
 * stdout: the pass result as one JSON line — counts and codes only, never a bearer, a body, a challenge
 * or a caller-chosen filename. Exit 0 = pass ran, 1 = pass failed, 2 = config/activation/platform,
 * 3 = responder state (locked, stale lock, corrupt, unauthentic, rotated).
 */

import path from "node:path";
import { loadConfig } from "../src/index.js";
import { openResponderStore, deriveStateKey } from "../src/responder/store.js";
import { createResponder, classifyInjectResponse, RESPONDER_LIMITS } from "../src/responder/responder.js";
import { openDropDir, runDropPass } from "../src/responder/drop.js";

const SID_RE = /^[A-Za-z0-9._-]{1,128}$/;
const BEARER_RE = /^[\x21-\x7E]{1,4096}$/;
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
// F06: no verified ACL check exists for win32 here, so the responder does not run there.
if (process.platform === "win32") refuse("RESPONDER_PLATFORM_UNSUPPORTED", 2);
// F01 scope: the integrity guarantee holds only where the tool runtime cannot read the session
// credential. The operator declares that configuration explicitly; nothing else is accepted.
if (env.TELESESSION_RESPONDER_TOOL_ENV !== "filtered") refuse("RESPONDER_TOOL_ENV_UNVERIFIED", 2);

let cfg;
try { cfg = loadConfig(env); } catch (err) { refuse((err && err.code) || "CONFIG_INVALID", 2); }
if (cfg.stateDir === null) refuse("RESPONDER_STATE_DIR_REQUIRED", 2);
// Profile mode scopes the client token to this assistant's own inbox namespace and targets; reading the
// audit of THIS session and injecting into the requester's inbox are outside that scope (FOLLOWUPS.md).
if (cfg.profile !== null) refuse("RESPONDER_PROFILE_UNSUPPORTED", 2);

const dropDir = typeof env.TELESESSION_RESPONDER_DROP_DIR === "string" ? env.TELESESSION_RESPONDER_DROP_DIR : "";
if (dropDir === "" || !path.isAbsolute(dropDir) || path.normalize(dropDir) !== dropDir) refuse("RESPONDER_DROP_DIR_INVALID", 2);
const stateRoot = path.join(cfg.stateDir, "responder");
// The tool runtime writes into the drop directory by design; the authenticated state must not be
// reachable through it (and vice versa), so the two trees may not contain one another.
const within = (child, parent) => {
  const rel = path.relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
};
if (within(stateRoot, dropDir) || within(dropDir, stateRoot)) refuse("RESPONDER_DROP_DIR_OVERLAPS_STATE", 2);

const sid = typeof env.TELEPTY_SESSION_ID === "string" ? env.TELEPTY_SESSION_ID : "";
const bearer = typeof env.TELEPTY_SESSION_TOKEN === "string" ? env.TELEPTY_SESSION_TOKEN : "";
if (!SID_RE.test(sid) || !BEARER_RE.test(bearer)) refuse("RESPONDER_SESSION_CREDENTIAL_MISSING", 2);
const epoch = typeof env.TELEPTY_SESSION_EPOCH === "string" && env.TELEPTY_SESSION_EPOCH !== "" ? env.TELEPTY_SESSION_EPOCH : null;
const generation = /^\d{1,15}$/.test(String(env.TELEPTY_SESSION_GENERATION || "")) ? Number(env.TELEPTY_SESSION_GENERATION) : null;

// F15: a bounded read of the daemon's answer. Declared or streamed bytes over the cap are refused
// before any parsing, exactly as src/transports/telepty.js does for the same endpoints.
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

// The telepty calls the responder needs. The control token reads the audit and observations; the SESSION
// token authenticates the reply — that is the whole point, and it never leaves this process.
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
    return { ok: false, status: null, parsed: null, tooLarge: false };
  }
  let read;
  try { read = await readCapped(res); } catch { return { ok: false, status: res.status, parsed: null, tooLarge: false }; }
  if (read.tooLarge) return { ok: false, status: res.status, parsed: null, tooLarge: true };
  let parsed = null;
  try { parsed = read.text ? JSON.parse(read.text) : null; } catch { parsed = null; }
  return { ok: res.ok, status: res.status, parsed, tooLarge: false };
}

const daemon = {
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
    if (r.parsed.inject_id !== injectId || typeof r.parsed.session_id !== "string" || typeof r.parsed.session_epoch !== "string" || r.parsed.session_epoch === "") {
      return { ok: false, code: "OBSERVATION_UNAVAILABLE" };
    }
    return { ok: true, session_id: r.parsed.session_id, session_epoch: r.parsed.session_epoch };
  },

  // F07: classified by the shared pure rule (src/responder/responder.js classifyInjectResponse), which
  // follows src/transports/telepty.js: an explicitly uncertain or 5xx answer is never a refusal.
  async inject({ to, prompt, from, sessionToken }) {
    return classifyInjectResponse(await call("POST", `/api/sessions/${encodeURIComponent(to)}/inject`, {
      body: { prompt, from, reply_to: from, exact_target: true }, sessionToken, timeoutMs: WRITE_TIMEOUT_MS,
    }));
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
  process.stdout.write(`${JSON.stringify({
    ok: true, session: sid, pass, bindings: st.bindings, counters: st.counters,
    state: { authenticated: st.authenticated_state, permissions: st.permissions, lock: st.lock },
    limits: { body_chars: RESPONDER_LIMITS.bodyChars, ttl_ms: RESPONDER_LIMITS.ttlMs, deadline_margin_ms: RESPONDER_LIMITS.deadlineMarginMs },
    completion_fact: null,
  })}\n`);
  code = 0;
} catch (err) {
  process.stderr.write(`telesession-responder-pump failed: ${(err && err.code) || "RESPONDER_PASS_FAILED"}\n`);
} finally {
  store.close();
}
process.exit(code);
