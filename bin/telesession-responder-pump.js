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
 * Config: TELESESSION_* (README.md) for the telepty URL and control token, plus
 *   TELESESSION_RESPONDER=1                 activation (default off)
 *   TELESESSION_RESPONDER_DROP_DIR=<abs>    the private drop directory the tool runtime writes to
 *   TELEPTY_SESSION_ID / TELEPTY_SESSION_TOKEN     this session's own credential (host env)
 *   TELEPTY_SESSION_EPOCH / TELEPTY_SESSION_GENERATION   recorded when present (optional)
 * The responder state (bindings, outcomes, audit) is <state dir>/responder, with its own lock.
 *
 * stdout: the pass result as one JSON line (no bearer, no body, no token). Exit 0 = pass ran, 1 = pass
 * failed, 2 = config/activation, 3 = responder state (locked, corrupt, mismatched).
 */

import path from "node:path";
import { loadConfig } from "../src/index.js";
import { openResponderStore } from "../src/responder/store.js";
import { createResponder, RESPONDER_LIMITS } from "../src/responder/responder.js";
import { openDropDir, runDropPass } from "../src/responder/drop.js";

const SID_RE = /^[A-Za-z0-9._-]{1,128}$/;
const BEARER_RE = /^[\x21-\x7E]{1,4096}$/;
const READ_TIMEOUT_MS = 5000;
const WRITE_TIMEOUT_MS = 10000;

const refuse = (code, exit) => {
  process.stderr.write(`telesession-responder-pump refused: ${code}\n`);
  process.exit(exit);
};

if (process.argv.length > 2) refuse("ARGS_UNEXPECTED", 2);

const env = process.env;
if (env.TELESESSION_RESPONDER !== "1") refuse("RESPONDER_NOT_ACTIVATED", 2);

let cfg;
try { cfg = loadConfig(env); } catch (err) { refuse((err && err.code) || "CONFIG_INVALID", 2); }
if (cfg.stateDir === null) refuse("RESPONDER_STATE_DIR_REQUIRED", 2);
// Profile mode scopes the client token to this assistant's own inbox namespace and targets; reading the
// audit of THIS session and injecting into the requester's inbox are outside that scope (FOLLOWUPS.md).
if (cfg.profile !== null) refuse("RESPONDER_PROFILE_UNSUPPORTED", 2);

const dropDir = typeof env.TELESESSION_RESPONDER_DROP_DIR === "string" ? env.TELESESSION_RESPONDER_DROP_DIR : "";
if (dropDir === "" || !path.isAbsolute(dropDir) || path.normalize(dropDir) !== dropDir) refuse("RESPONDER_DROP_DIR_INVALID", 2);

const sid = typeof env.TELEPTY_SESSION_ID === "string" ? env.TELEPTY_SESSION_ID : "";
const bearer = typeof env.TELEPTY_SESSION_TOKEN === "string" ? env.TELEPTY_SESSION_TOKEN : "";
if (!SID_RE.test(sid) || !BEARER_RE.test(bearer)) refuse("RESPONDER_SESSION_CREDENTIAL_MISSING", 2);
const epoch = typeof env.TELEPTY_SESSION_EPOCH === "string" && env.TELEPTY_SESSION_EPOCH !== "" ? env.TELEPTY_SESSION_EPOCH : null;
const generation = /^\d{1,15}$/.test(String(env.TELEPTY_SESSION_GENERATION || "")) ? Number(env.TELEPTY_SESSION_GENERATION) : null;

// The two telepty calls the responder needs. The control token reads the audit; the SESSION token
// authenticates the reply — that is the whole point, and it never leaves this process.
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
    return { ok: false, status: null, parsed: null };
  }
  let parsed = null;
  try { parsed = await res.json(); } catch { parsed = null; }
  return { ok: res.ok, status: res.status, parsed };
}

const daemon = {
  async injects({ to, since, until, limit }) {
    const q = `?to=${encodeURIComponent(to)}&since=${encodeURIComponent(since)}&until=${encodeURIComponent(until)}&limit=${limit}`;
    const r = await call("GET", `/api/injects${q}`, { timeoutMs: READ_TIMEOUT_MS });
    if (!r.ok || !r.parsed || !Array.isArray(r.parsed.injects)) return { ok: false, code: r.status === null ? "DAEMON_UNREACHABLE" : "DAEMON_BAD_RESPONSE" };
    return { ok: true, injects: r.parsed.injects, next_cursor: r.parsed.next_cursor ?? null };
  },
  async inject({ to, prompt, from, sessionToken }) {
    const r = await call("POST", `/api/sessions/${encodeURIComponent(to)}/inject`, {
      body: { prompt, from, reply_to: from, exact_target: true }, sessionToken, timeoutMs: WRITE_TIMEOUT_MS,
    });
    if (r.ok && r.parsed && r.parsed.success === true && typeof r.parsed.inject_id === "string") {
      return { ok: true, inject_id: r.parsed.inject_id };
    }
    // No response, or a 5xx: the inject may still have taken effect. `unknown` keeps the outcome
    // uncertain and the binding spent, so nothing is ever re-sent.
    if (r.status === null) return { ok: false, code: "DAEMON_UNREACHABLE", sent: "unknown" };
    if (r.status >= 500) return { ok: false, code: `DAEMON_HTTP_${r.status}`, sent: "unknown" };
    const code = r.parsed && typeof r.parsed.code === "string" && /^[A-Z_]{1,64}$/.test(r.parsed.code) ? r.parsed.code : `DAEMON_HTTP_${r.status}`;
    return { ok: false, code, sent: r.ok ? "unknown" : "yes" };
  },
};

let store;
try {
  store = openResponderStore({ dir: path.join(cfg.stateDir, "responder"), session: sid, origin: cfg.teleptyOrigin });
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
    permissions: { state: store.info().permissions, drop: drop.permissions },
    limits: { body_chars: RESPONDER_LIMITS.bodyChars, ttl_ms: RESPONDER_LIMITS.ttlMs },
    completion_fact: null,
  })}\n`);
  code = 0;
} catch (err) {
  process.stderr.write(`telesession-responder-pump failed: ${(err && err.code) || "RESPONDER_PASS_FAILED"}\n`);
} finally {
  store.close();
}
process.exit(code);
