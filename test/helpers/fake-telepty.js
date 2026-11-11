/**
 * Stateful loopback model of the documented telepty HTTP surface used by telesession, following the
 * source facts in SPEC-R2 §1 (F1–F5). Native Node only (node:http). It models the DAEMON; it never
 * stands in for telesession code.
 *
 * Modelled facts:
 *   F3a inject to an absent id → 404 SESSION_NOT_FOUND, NO audit row.
 *   F3b audit hashes the exact request prompt (payload_sha256 = sha256(prompt)).
 *   F3d aterm inject → mailbox enqueue + first attempt → 200 success + audit "success" REGARDLESS of the
 *       first attempt (audit success = enqueued, not received).
 *   F3e failed attempt → retry after retryDelaysMs[0], [1]; 3rd failure → dead-letter; resolver = live
 *       sessions only (an absent id is a failed attempt).
 *   F3f owned DELETE purges queued retries for that id; daemon restart does NOT purge.
 *   F1  restartDaemon(): aterm sessions vanish, wrapped targets keep id + epoch, pid changes.
 *   F4  register create_only (201/409) and owned DELETE (200/403/404) are exact.
 *   F5  /api/injects `from` matches claimed OR verified sender; next_cursor null unless forced
 *       (flags.forceNextCursor); flags.ignoreWindow returns rows outside since/until so the client's
 *       own window check is exercised; flags.auditAvailable=false → 503.
 *
 * Every request is recorded (method, path, query, whether a session token was sent and which one).
 * Hooks let a test act at precise points: beforeInject / afterInject (e.g. SIGKILL a child, then
 * "hang" or "reset" the connection), onRegister ("reset" after creating = lost response), onDelete
 * ({status} override), beforeDelivery ("fail" = receiver unreachable for that attempt).
 *
 * Issue #16 `clientProfiles` (received contract564 §3 + review569 §3): emulates the RESPONSES of a Telepty
 * `client-profile-scope-v1` daemon so client behaviour can be tested. It is not enforcement evidence: only a
 * real Telepty build proves the server side. `[{profile, inbox_prefix, targets, generation, token}]`;
 * `profileScope:false` models 0.10.1 / feature off (any client token → 401). flags: callerOverride (merged
 * into the profile `caller`), registryUnavailable (503), metaStatus (forced meta status for profile callers),
 * metaDrop (n: the next n GET /api/meta connections are destroyed without a response = transport failure, not an
 * answer). hooks.beforeProfileList (async, awaited before a profile GET /api/sessions is answered) lets a test hold
 * one operation at a fixed point while another runs (review698 CF3), with no timer.
 * Response shapes follow the real server (review698 CF4, server source of 6eebf71a): a profile list is exactly
 * `[{id}]`; a foreign or unknown observation is the schema-v2 `tracking_state:"unavailable"` body with
 * `reason:"not_observed_by_daemon_epoch"` (observationUnavailableBody). The fake does NOT emulate not_before /
 * grant history (A2), digest reload or any other server-only rule; only S-R rows on a real daemon show those.
 */

import http from "node:http";
import { createHash, randomBytes, randomUUID } from "node:crypto";

export const FAKE_CAPABILITIES = Object.freeze(["sessions", "inject-exact-target", "register-create-only", "delete-owned-session"]);

const sha256 = (s) => createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");
const hex = (n) => randomBytes(n).toString("hex");

export function parseWire(prompt) {
  const m = /^\[telesession nonce=([0-9a-f]{32}) reply-to=([A-Za-z0-9._-]+)(?: correlation=[0-9a-f]{32})?\]\n([\s\S]*)$/.exec(String(prompt));
  return m ? { nonce: m[1], replyTo: m[2], text: m[3] } : null;
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", () => resolve(""));
  });
}

// POST JSON to an aterm endpoint with node:http (no Origin header, Host = 127.0.0.1:port).
function postJson(endpoint, body, timeoutMs = 5000) {
  return new Promise((resolve) => {
    let url;
    try { url = new URL(endpoint); } catch { resolve(0); return; }
    const data = Buffer.from(JSON.stringify(body));
    const req = http.request({
      host: url.hostname, port: url.port, path: url.pathname + url.search, method: "POST",
      headers: { "content-type": "application/json", "content-length": data.length },
      timeout: timeoutMs,
    }, (res) => { res.resume(); res.on("end", () => resolve(res.statusCode)); res.on("error", () => resolve(0)); });
    req.on("timeout", () => req.destroy());
    req.on("error", () => resolve(0));
    req.end(data);
  });
}

export const PROFILE_SCOPE_CAPABILITY = "client-profile-scope-v1";
// Server daemon.js `unavailable(reason)` body (GET /api/inject-observations/:id), fields in the server's order. The
// server's `capability` value (CAPABILITY_STAGE_A) is defined outside the review packet; the fake sends a fixed
// empty object there and the client reads none of it.
export function observationUnavailableBody(injectId, reason = "not_observed_by_daemon_epoch") {
  return {
    type: "task_completion_unknown", schema_version: 2, inject_id: injectId, completion_fact: null, terminal: false,
    tracking_state: "unavailable", reason, observation: { kind: "tracking_unavailable", trigger: reason },
    consumption: { status: "not_established", basis: "no_tracked_inject" }, capability: {},
  };
}
const PROFILE_FORBIDDEN_HEADERS = ["authorization", "x-telepty-token", "x-telepty-principal", "x-telepty-owner-token",
  "x-telepty-input-policy-capability", "x-telepty-bridge-capabilities", "x-telepty-assertion"];

export async function startFakeTelepty({ targets = ["target-1"], retryDelaysMs = [1000, 2000], capabilities = FAKE_CAPABILITIES,
  clientProfiles = null, profileScope = clientProfiles !== null } = {}) {
  const token = hex(24);
  const sessions = new Map();          // id → {id, type, epoch, generation, bearer, endpoint, delivered[]}
  const audit = [];                    // audit rows (persist across restartDaemon, like the audit file)
  const observations = new Map();      // inject_id → observation body
  const mailbox = [];                  // {seq, session_id, text, inject_id, attempts, state, deliveredTo[]}
  const requests = [];
  const injectArrivals = [];           // every POST …/inject that reached the daemon (before hooks)
  const injects = [];                  // injects the daemon PROCESSED (audited or 404)
  const registrations = [];
  const deletes = [];
  const hooks = {};
  const timers = new Set();
  let generationSeq = 0;
  let mailSeq = 0;
  let pid = 40000 + Math.floor(Math.random() * 20000);
  const flags = { auditAvailable: true, forceNextCursor: false, ignoreWindow: false, callerOverride: null, registryUnavailable: false, metaStatus: null, omitProfileCapability: false, metaDrop: 0 };
  const observationSource = new Map();  // inject_id → claimed `from` (profile observation ownership)
  const caps = () => (profileScope && !flags.omitProfileCapability ? [...capabilities, PROFILE_SCOPE_CAPABILITY] : [...capabilities]);
  // Namespace = exact `<prefix>-i<32 hex>` (contract564 §3.2), never a startsWith test.
  const inNs = (p, id) => typeof id === "string" && id.length === p.inbox_prefix.length + 34
    && id.startsWith(`${p.inbox_prefix}-i`) && /^[0-9a-f]{32}$/.test(id.slice(p.inbox_prefix.length + 2));

  function addWrapped(id) {
    generationSeq += 1;
    const s = { id, type: "wrapped", epoch: `epoch-${hex(8)}`, generation: generationSeq, bearer: `tgt-${hex(24)}`, endpoint: null, delivered: [] };
    sessions.set(id, s);
    return s;
  }
  for (const id of targets) addWrapped(id);

  function principalFor(bearer) {
    if (!bearer) return null;
    for (const s of sessions.values()) if (s.bearer === bearer) return { sid: s.id, epoch: s.epoch, generation: s.generation };
    return null;
  }

  function schedule(fn, ms) {
    const t = setTimeout(() => { timers.delete(t); fn(); }, ms);
    timers.add(t);
    return t;
  }

  async function attempt(item) {
    if (item.state !== "pending") return;
    item.attempts += 1;
    const session = sessions.get(item.session_id);
    let ok = false;
    const verdict = hooks.beforeDelivery ? await hooks.beforeDelivery(item) : undefined;
    if (verdict !== "fail" && session && session.type === "aterm" && session.endpoint) {
      const status = await postJson(session.endpoint, { session_id: item.session_id, text: item.text });
      item.statuses.push(status);
      ok = status >= 200 && status < 300;
      if (ok) item.deliveredTo.push(session.epoch);
    } else {
      item.statuses.push(session ? "blocked" : "absent");
    }
    if (item.state !== "pending") return;              // purged while in flight
    if (ok) { item.state = "delivered"; return; }
    if (item.attempts >= 3) { item.state = "dead_letter"; return; }
    item.timer = schedule(() => attempt(item), retryDelaysMs[item.attempts - 1]);
  }

  // The daemon-side inject path (HTTP route and replyFrom share it).
  function processInject(id, body, sessionToken, { ts } = {}) {
    const prompt = typeof body.prompt === "string" ? body.prompt : "";
    const from = typeof body.from === "string" ? body.from : null;
    const session = sessions.get(id);
    const record = { to: id, prompt, from, sessionToken: sessionToken || null, status: null, inject_id: null };
    injects.push(record);
    if (!session) { record.status = 404; return { status: 404, body: { code: "SESSION_NOT_FOUND" } }; }   // F3a
    const p = principalFor(sessionToken);
    const inject_id = randomUUID();
    let strategy = "direct";
    if (session.type === "wrapped") {
      session.delivered.push({ prompt, inject_id, from });
    } else {
      strategy = "mailbox";
      mailSeq += 1;
      const item = { seq: mailSeq, session_id: id, text: prompt, inject_id, attempts: 0, state: "pending", statuses: [], deliveredTo: [] };
      mailbox.push(item);
      attempt(item);                                     // first attempt; result does NOT change the response (F3d)
    }
    audit.push({
      ts: ts || new Date().toISOString(), inject_id, kind: "inject", source: "inject",
      claimed_from: from, verified_sender_sid: p ? p.sid : null, verified_sender_epoch: p ? p.epoch : null,
      verified_sender_generation: p ? p.generation : null,
      to: id, to_alias: null, origin: "trusted-local",
      spoof_suspected: !!(from && p && from !== p.sid),
      payload_sha256: sha256(prompt), delivery_result: "success",
    });
    observations.set(inject_id, { inject_id, session_id: id, session_epoch: session.epoch, tracking_state: "tracked" });
    observationSource.set(inject_id, from);
    record.status = 200;
    record.inject_id = inject_id;
    return { status: 200, body: { success: true, inject_id, exact_target: body.exact_target === true, session_id: id, strategy } };
  }

  function send(res, status, body) {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  }

  const server = http.createServer(async (req, res) => {
    const raw = await readBody(req);
    let body = null;
    try { body = raw ? JSON.parse(raw) : null; } catch { body = null; }
    const url = new URL(req.url, "http://fake");
    const sessionToken = req.headers["x-telepty-session-token"] || null;
    const entry = {
      method: req.method, path: url.pathname, query: Object.fromEntries(url.searchParams), sessionToken,
      authorized: req.headers["x-telepty-token"] === token, body,
    };
    requests.push(entry);
    const rawNames = req.rawHeaders.filter((_, i) => i % 2 === 0).map((n) => n.toLowerCase());
    entry.clientToken = rawNames.includes("x-telepty-client-token") ? req.headers["x-telepty-client-token"] : null;
    entry.rootTokenSent = rawNames.includes("x-telepty-token");
    if (req.method === "GET" && url.pathname === "/api/meta" && flags.metaDrop > 0) {
      flags.metaDrop -= 1;
      entry.dropped = true;
      return req.socket.destroy();
    }
    if (entry.clientToken !== null) {
      const out = profileRoute(req, url, body, rawNames, entry);
      if (out) return send(res, out.status, out.body);
    } else if (!entry.authorized) return send(res, 401, { code: "UNAUTHORIZED" });
    const ctx = { req, res, body, entry };

    if (req.method === "GET" && url.pathname === "/api/meta") {
      const caller = profileScope ? (entry.profile
        ? { kind: "client-profile", profile: entry.profile.profile, generation: entry.profile.generation, inbox_prefix: entry.profile.inbox_prefix,
          targets: [...entry.profile.targets], enforcement: "server", shared_token: false, ...(flags.callerOverride || {}) }
        : { kind: "shared-control", enforcement: "none", shared_token: true }) : undefined;
      return send(res, 200, { name: "fake-telepty", version: "0.0.0-fake", pid, capabilities: caps(), ...(caller ? { caller } : {}) });
    }
    if (entry.profile && req.method === "GET" && url.pathname === "/api/sessions") {
      const p = entry.profile;
      if (hooks.beforeProfileList) await hooks.beforeProfileList(entry);
      return send(res, 200, [...sessions.values()].filter((x) => p.targets.includes(x.id) || inNs(p, x.id)).map((x) => ({ id: x.id })));
    }
    if (entry.profile && req.method === "GET" && /^\/api\/inject-observations\/[^/]+$/.test(url.pathname)) {
      const id = decodeURIComponent(url.pathname.split("/").pop());
      if (!inNs(entry.profile, observationSource.get(id))) return send(res, 200, observationUnavailableBody(id));
    }
    if (!entry.profile && profileScope && clientProfiles && req.method === "POST" && url.pathname === "/api/sessions/register"
        && clientProfiles.some((p) => inNs(p, body && body.session_id))) {
      return send(res, 403, { code: "PROFILE_NAMESPACE_RESERVED" });
    }
    if (req.method === "GET" && url.pathname === "/api/sessions") {
      return send(res, 200, [...sessions.values()].map((s) => ({ id: s.id, type: s.type })));
    }
    if (req.method === "POST" && url.pathname === "/api/sessions/register") {
      const b = body || {};
      registrations.push({ session_id: b.session_id, create_only: b.create_only, body: b });
      if (b.create_only !== true || typeof b.session_id !== "string") return send(res, 400, { code: "INVALID_REQUEST" });
      if (sessions.has(b.session_id)) return send(res, 409, { code: "SESSION_EXISTS" });
      generationSeq += 1;
      const s = {
        id: b.session_id, type: "aterm", epoch: `epoch-${hex(8)}`, generation: generationSeq,
        bearer: `inbox-${hex(24)}`, endpoint: b.delivery_endpoint, delivered: [], command: b.command,
        provenance_capable: b.provenance_capable,
      };
      sessions.set(s.id, s);
      const verdict = hooks.onRegister ? await hooks.onRegister({ ...ctx, session: s }) : undefined;
      if (verdict === "reset") { req.socket.destroy(); return undefined; }
      return send(res, 201, { session_id: s.id, session_token: s.bearer, session_epoch: s.epoch, credential_generation: s.generation });
    }
    let m = /^\/api\/sessions\/([^/]+)\/inject$/.exec(url.pathname);
    if (req.method === "POST" && m) {
      const id = decodeURIComponent(m[1]);
      injectArrivals.push({ to: id, body, sessionToken });
      const pre = hooks.beforeInject ? await hooks.beforeInject({ ...ctx, id }) : undefined;
      if (pre === "hang") return undefined;
      if (pre === "reset") { req.socket.destroy(); return undefined; }
      if (pre && typeof pre === "object") return send(res, pre.status, pre.body);
      const out = processInject(id, body || {}, sessionToken);
      const post = hooks.afterInject ? await hooks.afterInject({ ...ctx, id, out }) : undefined;
      if (post === "hang") return undefined;
      if (post === "reset") { req.socket.destroy(); return undefined; }
      return send(res, out.status, out.body);
    }
    m = /^\/api\/inject-observations\/([^/]+)$/.exec(url.pathname);
    if (req.method === "GET" && m) {
      const obs = observations.get(decodeURIComponent(m[1]));
      return obs ? send(res, 200, obs) : send(res, 404, { code: "INJECT_NOT_FOUND" });
    }
    if (req.method === "GET" && url.pathname === "/api/injects") {
      if (!flags.auditAvailable) return send(res, 503, { code: "AUDIT_UNAVAILABLE" });
      const q = entry.query;
      const since = q.since ? Date.parse(q.since) : -Infinity;
      const until = q.until ? Date.parse(q.until) : Infinity;
      const limit = Math.min(Number(q.limit) || 200, 1000);
      const rows = audit.filter((r) => (!q.to || r.to === q.to)
        && (!q.from || r.claimed_from === q.from || r.verified_sender_sid === q.from)
        && (flags.ignoreWindow || (Date.parse(r.ts) >= since && Date.parse(r.ts) <= until))).slice(0, limit);
      return send(res, 200, { injects: rows, next_cursor: flags.forceNextCursor ? "cursor-2" : null });
    }
    m = /^\/api\/sessions\/([^/]+)$/.exec(url.pathname);
    if (req.method === "DELETE" && m) {
      const id = decodeURIComponent(m[1]);
      deletes.push({ id, owned: entry.query.owned, sessionToken });
      const pre = hooks.onDelete ? await hooks.onDelete({ ...ctx, id }) : undefined;
      if (pre && typeof pre === "object") return send(res, pre.status, pre.body || {});
      if (pre === "reset") { req.socket.destroy(); return undefined; }
      const s = sessions.get(id);
      if (!s) return send(res, 404, { code: "SESSION_NOT_FOUND" });
      if (entry.query.owned !== "true" || !sessionToken || sessionToken !== s.bearer) return send(res, 403, { code: "SESSION_TOKEN_MISMATCH" });
      sessions.delete(id);
      for (const item of mailbox) {                        // F3f: purge queued retries for this id
        if (item.session_id === id && item.state === "pending") { item.state = "purged"; if (item.timer) { clearTimeout(item.timer); timers.delete(item.timer); } }
      }
      return send(res, 200, { success: true });
    }
    return send(res, 404, { code: "NOT_FOUND" });
  });
  server.keepAliveTimeout = 1;

  // Profile gate (emulated): returns a refusal {status, body}, or null after setting entry.profile.
  function profileRoute(req, url, body, rawNames, entry) {
    if (!profileScope) return { status: 401, body: { code: "PERMISSION_DENIED" } };
    const count = (n) => rawNames.filter((x) => x === n).length;
    if (count("x-telepty-client-token") !== 1 || count("x-telepty-session-token") > 1
        || PROFILE_FORBIDDEN_HEADERS.some((h) => count(h) > 0) || url.searchParams.has("token") || url.searchParams.has("owner_token")) {
      return { status: 400, body: { code: "CREDENTIAL_AMBIGUOUS" } };
    }
    if (flags.registryUnavailable) return { status: 503, body: { code: "PROFILE_REGISTRY_UNAVAILABLE" } };
    const p = (clientProfiles || []).find((x) => x.token === entry.clientToken);
    if (!p) return { status: 401, body: { code: "PROFILE_CREDENTIAL_INVALID" } };
    entry.profile = p;
    const m = req.method;
    const q = [...url.searchParams.keys()];
    if (m === "GET" && url.pathname === "/api/meta") return flags.metaStatus ? { status: flags.metaStatus, body: { code: "FORCED" } } : null;
    if (m === "GET" && url.pathname === "/api/sessions" && q.length === 0) return null;
    if (m === "POST" && url.pathname === "/api/sessions/register") {
      const b = body || {};
      if (!inNs(p, b.session_id)) return { status: 403, body: { code: "PROFILE_NAMESPACE_DENIED" } };
      if (b.create_only !== true || b.delivery_type !== "aterm") return { status: 403, body: { code: "PROFILE_REQUEST_FIELD_DENIED" } };
      return null;
    }
    let mm = /^\/api\/sessions\/([^/]+)\/inject$/.exec(url.pathname);
    if (m === "POST" && mm) {
      const b = body || {};
      if (!p.targets.includes(decodeURIComponent(mm[1]))) return { status: 403, body: { code: "PROFILE_TARGET_DENIED" } };
      if (!inNs(p, b.from) || b.reply_to !== b.from) return { status: 403, body: { code: "PROFILE_SENDER_DENIED" } };
      return null;
    }
    if (m === "GET" && url.pathname === "/api/injects") {
      const to = url.searchParams.get("to");
      const from = url.searchParams.get("from");
      if (inNs(p, to) || (inNs(p, from) && (to === null || p.targets.includes(to)))) return null;
      return { status: 403, body: { code: "PROFILE_READ_DENIED" } };
    }
    if (m === "GET" && /^\/api\/inject-observations\/[^/]+$/.test(url.pathname)) return null;
    mm = /^\/api\/sessions\/([^/]+)$/.exec(url.pathname);
    if (m === "DELETE" && mm && q.join() === "owned") {
      return inNs(p, decodeURIComponent(mm[1])) ? null : { status: 403, body: { code: "PROFILE_NAMESPACE_DENIED" } };
    }
    return { status: 403, body: { code: "PROFILE_ACTION_DENIED" } };
  }

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port: 0 }, () => { server.off("error", reject); resolve(); });
  });
  const origin = `http://127.0.0.1:${server.address().port}`;

  return {
    origin, token, sessions, audit, observations, mailbox, requests, injectArrivals, injects, registrations, deletes, hooks, flags,
    get pid() { return pid; },
    // Only POST …/inject requests the daemon processed, optionally for one target.
    injectsTo: (id) => injects.filter((r) => r.to === id),
    mutations: () => requests.filter((r) => r.method !== "GET"),
    // The target session (its own bearer) sends `text` to `to` through the daemon, like a reply.
    replyFrom(fromSid, to, text, { from = fromSid, bearer } = {}) {
      const s = sessions.get(fromSid);
      return processInject(to, { prompt: text, from, exact_target: true }, bearer !== undefined ? bearer : s && s.bearer);
    },
    // Another holder of a valid token (e.g. a different session's bearer) injecting anything. `ts` places
    // the audit row in time (e.g. inside a recovery probe window).
    injectAs(bearer, to, prompt, from, { ts } = {}) { return processInject(to, { prompt, from, exact_target: true }, bearer, { ts }); },
    addAuditRow(row, { observe = true } = {}) {
      const full = {
        ts: new Date().toISOString(), inject_id: randomUUID(), kind: "inject", source: "inject", claimed_from: null,
        verified_sender_sid: null, verified_sender_epoch: null, verified_sender_generation: null, to: null, to_alias: null,
        origin: "trusted-local", spoof_suspected: false, payload_sha256: null, delivery_result: "success", ...row,
      };
      audit.push(full);
      const s = sessions.get(full.to);
      if (observe) observations.set(full.inject_id, { inject_id: full.inject_id, session_id: full.to, session_epoch: s ? s.epoch : null, tracking_state: "tracked" });
      return full;
    },
    // Mailbox delivery WITHOUT an audit row (models a replayed/out-of-band delivery to an inbox).
    deliverRaw(to, text) {
      mailSeq += 1;
      const item = { seq: mailSeq, session_id: to, text, inject_id: null, attempts: 0, state: "pending", statuses: [], deliveredTo: [] };
      mailbox.push(item);
      attempt(item);
      return item;
    },
    addWrapped,
    // F1: aterm sessions vanish, wrapped keep id + epoch, new pid; mailbox and audit survive.
    restartDaemon() {
      for (const [id, s] of sessions) if (s.type === "aterm") sessions.delete(id);
      pid += 1;
    },
    recreateTarget(id) { sessions.delete(id); return addWrapped(id); },
    lastDelivered(id) { const s = sessions.get(id); return s && s.delivered.length ? s.delivered[s.delivered.length - 1] : null; },
    async close() {
      for (const t of timers) clearTimeout(t);
      timers.clear();
      try { server.closeAllConnections(); } catch { /* none */ }
      await new Promise((r) => server.close(() => r()));
    },
  };
}
