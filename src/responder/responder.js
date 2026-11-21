/**
 * telesession scoped responder (issue #18). A model whose tool runtime filters the environment holds NO
 * session id, token or credential path, so a reply it sends itself carries no verified sender and the
 * requester stores it as a `claimed_only` candidate with its body quarantined (src/transports/telepty.js
 * classifyAuditRows). This component closes that gap without handing a reusable session bearer to the
 * tool runtime:
 *
 *   1. `recordInbound({prompt, arrival_ms})` takes a CLAIM — any writer may present it — and checks it
 *      against THIS session's own daemon audit: exactly one row of a complete page, to this session,
 *      trusted-local, not spoofed, same payload hash, whose VERIFIED sender is the prompt's own reply-to
 *      inbox. Only then is a binding recorded. Destination, nonce, principal and credential instance come
 *      from that row and from the credential this process already holds — never from a file or argument.
 *   2. The capability handed to the tool runtime is `{binding_id, challenge}`: single use, bound to that
 *      one request, carrying no bearer and expiring with the request.
 *   3. `reply({binding_id, challenge, body})` — `body` is the only caller-supplied content. This process
 *      composes `REPLY <nonce> <body>` and performs the authenticated inject itself.
 *
 * Every acceptance and refusal is recorded with its reason. At most ONE authenticated send per binding: a
 * duplicate returns the recorded outcome without sending again, and a lost response stays `uncertain` and
 * is never re-sent (this package never claims exactly-once). Nothing that is quarantined today becomes
 * readable: an inbound request without verified sender evidence yields no binding at all, and no path here
 * changes how a reply is classified on the requester's side.
 *
 * INERT until an operator activates it (`activated: true`; `TELESESSION_RESPONDER=1` for the command).
 * Node >= 20 builtins only. No shell, no daemon lifecycle, no credential written to disk.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export const RESPONDER_LIMITS = Object.freeze({
  bodyChars: 7900, ttlMs: 15 * 60 * 1000, inboundBeforeMs: 2000, inboundAfterMs: 120000,
  auditRows: 200, promptChars: 8192, arrivalMaxMs: 1e15,
});

const SID_RE = /^[A-Za-z0-9._-]{1,128}$/;
const HEX32_RE = /^[0-9a-f]{32}$/;
const INJECT_ID_RE = /^[A-Za-z0-9-]{1,128}$/;
const CHALLENGE_RE = /^[A-Za-z0-9_-]{43}$/;
const BEARER_RE = /^[\x21-\x7E]{1,4096}$/;
// The exact wire header src/transports/telepty.js writes (`correlation` is absent in 0.1.x records).
const WIRE_RE = /^\[telesession nonce=([0-9a-f]{32}) reply-to=([A-Za-z0-9._-]{1,128})(?: correlation=([0-9a-f]{32}))?\]\n([\s\S]*)$/;
const DELIVERY_OK = new Set(["success", "queued"]);
const LOCAL = "local";

export class ResponderError extends Error {
  constructor(code) {
    super(code);
    this.name = "ResponderError";
    this.code = code;
  }
}

const sha256hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const iso = (ms) => new Date(ms).toISOString();
const isPlain = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

function ok(obj) {
  return { ok: true, ...obj, completion_fact: null };
}

function fail(code, extra = {}) {
  return { ok: false, error: { code, ...extra }, completion_fact: null };
}

// ── Pure classifiers (no I/O; they authenticate nothing on their own) ──

export function parseRequestWire(prompt) {
  const m = typeof prompt === "string" ? WIRE_RE.exec(prompt) : null;
  return m ? { nonce: m[1], replyTo: m[2], correlationId: m[3] === undefined ? null : m[3], text: m[4] } : null;
}

// The reply bytes. The nonce comes from the recorded binding, so a caller can never correlate its body
// with another request; `body` is the only caller-supplied part.
export function composeReply(nonce, body) {
  return `REPLY ${nonce} ${body}`;
}

/**
 * The ONE audit row that proves the inbound request: the claimed reply-to inbox is also the VERIFIED
 * sender of exactly this payload to this session, inside the arrival window, stamped local by this
 * daemon. A truncated page cannot show that a row is the only one, so it is never trusted.
 * `rows` are GET /api/injects rows. Returns {ok:true,row} or {ok:false,code,candidates}.
 */
export function selectInboundRow(rows, { session, replyTo, payloadSha256, lo, hi, complete }) {
  if (complete !== true) return { ok: false, code: "INBOUND_AUDIT_INCOMPLETE", candidates: null };
  const same = (Array.isArray(rows) ? rows : []).filter((r) => isPlain(r)
    && r.to === session && r.to_alias === null && r.origin === "trusted-local" && DELIVERY_OK.has(r.delivery_result)
    && r.payload_sha256 === payloadSha256 && r.claimed_from === replyTo && r.verified_sender_sid === replyTo
    && r.spoof_suspected === false && typeof r.inject_id === "string" && INJECT_ID_RE.test(r.inject_id)
    && Number.isFinite(Date.parse(r.ts)) && Date.parse(r.ts) >= lo && Date.parse(r.ts) <= hi);
  if (same.length === 0) return { ok: false, code: "INBOUND_UNVERIFIED", candidates: 0 };
  if (same.length > 1) return { ok: false, code: "INBOUND_AMBIGUOUS", candidates: same.length };
  return { ok: true, row: same[0] };
}

// ── Component ──

/**
 * `store`    — openResponderStore() of this session's private directory (it holds the lock).
 * `credential` — () => {sid, bearer, epoch?, generation?}: the session credential this HOST process owns.
 *                The bearer is used for the inject and hashed for the binding; it is never stored,
 *                returned or logged.
 * `daemon`   — {injects({to, since, until, limit}), inject({to, prompt, from, sessionToken})}: the two
 *              telepty reads/writes this needs, injected so the component stays transport-agnostic.
 * `activated` — must be true. Without it the responder refuses to exist (operator activation gate).
 */
export function createResponder({ store, credential, daemon, now = Date.now, activated = false } = {}) {
  if (activated !== true) throw new ResponderError("RESPONDER_NOT_ACTIVATED");
  if (!store || typeof store.commit !== "function" || typeof store.binding !== "function") throw new ResponderError("RESPONDER_STORE_REQUIRED");
  if (typeof credential !== "function") throw new ResponderError("RESPONDER_CREDENTIAL_REQUIRED");
  if (!daemon || typeof daemon.injects !== "function" || typeof daemon.inject !== "function") throw new ResponderError("RESPONDER_DAEMON_REQUIRED");

  const counters = { issued: 0, reissued: 0, accepted: 0, refused: 0, duplicate: 0, uncertain: 0 };

  // The credential of THIS session, as this process holds it. `credential_sha256` is the credential
  // INSTANCE: a rotated session credential (a new session generation) has another digest, so every
  // binding recorded under the previous instance is refused.
  function principal() {
    let c;
    try { c = credential(); } catch { return null; }
    if (!isPlain(c) || typeof c.sid !== "string" || !SID_RE.test(c.sid)) return null;
    if (typeof c.bearer !== "string" || !BEARER_RE.test(c.bearer)) return null;
    const epoch = typeof c.epoch === "string" && c.epoch.length >= 1 && c.epoch.length <= 256 && !/[\u0000-\u001f\u007f]/.test(c.epoch) ? c.epoch : null;
    const generation = Number.isSafeInteger(c.generation) && c.generation >= 0 ? c.generation : null;
    return { sid: c.sid, bearer: c.bearer, epoch, generation, credential_sha256: sha256hex(c.bearer) };
  }

  function record(entry) {
    const t = iso(now());
    return store.commit((d) => store.pushAudit(d, { ...entry, at: t }));
  }

  // A refusal is answered only after it was recorded; a failed audit write is reported, never hidden.
  function refuse(code, reason, { binding_id = null, extra = {} } = {}) {
    counters.refused += 1;
    const r = record({ event: "refused", binding_id, reason });
    return fail(code, { ...extra, ...(r && r.ok ? {} : { audit: "degraded" }) });
  }

  // A binding whose principal is no longer the credential this process holds can never be used again.
  function principalVerdict(b, p) {
    if (b.principal.sid !== p.sid) return "principal_mismatch";
    if (b.principal.credential_sha256 !== p.credential_sha256) return "session_generation_changed";
    if (b.principal.epoch !== null && p.epoch !== null && b.principal.epoch !== p.epoch) return "session_generation_changed";
    if (b.principal.generation !== null && p.generation !== null && b.principal.generation !== p.generation) return "session_generation_changed";
    return null;
  }

  function digestsEqual(a, b) {
    const x = Buffer.from(a, "hex");
    const y = Buffer.from(b, "hex");
    return x.length === y.length && x.length > 0 && timingSafeEqual(x, y);
  }

  const view = (b) => ({
    binding_id: b.binding_id, nonce: b.nonce, correlation_id: b.correlation_id,
    destination: { ...b.destination }, state: b.state, expires_at: iso(b.expires_ms),
    outcome: b.outcome === null ? null : { ...b.outcome },
  });

  /**
   * Record the trusted inbound request binding for a request this session received, and issue the scoped
   * capability for it. The claim itself proves nothing: without exactly one matching VERIFIED audit row
   * no binding exists, so a forged prompt cannot create a reply route to anywhere.
   */
  async function recordInbound({ prompt, arrival_ms } = {}) {
    // `arrival_ms` is bounded so every derived timestamp (window, expiry) is a representable instant.
    if (typeof prompt !== "string" || prompt.length < 1 || prompt.length > RESPONDER_LIMITS.promptChars
        || (arrival_ms !== undefined && !(Number.isSafeInteger(arrival_ms) && arrival_ms >= 0 && arrival_ms <= RESPONDER_LIMITS.arrivalMaxMs))) {
      return refuse("INVALID_ARGUMENT", "claim_invalid");
    }
    const m = parseRequestWire(prompt);
    if (!m) return refuse("INBOUND_NOT_TELESESSION", "inbound_not_telesession");
    const p = principal();
    if (p === null) return refuse("CREDENTIAL_UNAVAILABLE", "credential_unavailable");
    // Loopback guard: a request that claims this very session as its reply inbox is never a reply route.
    if (m.replyTo === p.sid) return refuse("INBOUND_SELF", "inbound_self");

    const payloadSha = sha256hex(prompt);
    const prior = store.bindings().find((b) => b.payload_sha256 === payloadSha && b.nonce === m.nonce
      && b.destination.session === m.replyTo && b.principal.sid === p.sid);
    if (prior && prior.outcome !== null) {
      // The single use is spent: the capability is not re-issued, the recorded outcome is the answer.
      counters.duplicate += 1;
      record({ event: "duplicate", binding_id: prior.binding_id, reason: "duplicate" });
      return ok({ ...view(prior), deduplicated: true, reissued: false });
    }

    const arrival = arrival_ms === undefined ? now() : arrival_ms;
    const lo = arrival - RESPONDER_LIMITS.inboundBeforeMs;
    const hi = arrival + RESPONDER_LIMITS.inboundAfterMs;
    const r = await daemon.injects({ to: p.sid, since: iso(lo), until: iso(hi), limit: RESPONDER_LIMITS.auditRows });
    if (!isPlain(r) || r.ok !== true) {
      // No evidence read → no binding. Recorded as a refusal; the claim may be presented again later.
      const code = isPlain(r) && typeof r.code === "string" && /^[A-Z0-9_]{1,64}$/.test(r.code) ? r.code : "AUDIT_UNAVAILABLE";
      return refuse(code, code);
    }
    const sel = selectInboundRow(r.injects, {
      session: p.sid, replyTo: m.replyTo, payloadSha256: payloadSha, lo, hi, complete: r.next_cursor == null,
    });
    if (!sel.ok) return refuse(sel.code, "inbound_unverified", { extra: { candidates: sel.candidates } });

    const challenge = randomBytes(32).toString("base64url");
    const challengeSha = sha256hex(challenge);
    const t = now();

    if (prior) {
      // The binding stands (destination, nonce, principal, expiry unchanged); only the capability is
      // re-issued, because its delivery to the tool runtime may have been lost. `attempts` is NOT reset.
      const c = store.commit((d) => {
        const b = d.bindings[prior.binding_id];
        if (!b || b.outcome !== null) return { ok: false, code: "BINDING_STATE_CHANGED" };
        b.challenge_sha256 = challengeSha;
        store.pushAudit(d, { at: iso(t), event: "reissued", binding_id: b.binding_id, reason: null });
        return undefined;
      });
      if (!c.ok) return fail(c.code, c.errno ? { errno: c.errno } : {});
      counters.reissued += 1;
      const b = store.binding(prior.binding_id);
      return ok({ ...view(b), challenge, reissued: true, deduplicated: false });
    }

    const bindingId = randomBytes(16).toString("hex");
    const expires = arrival + RESPONDER_LIMITS.ttlMs;
    const fresh = {
      binding_id: bindingId, nonce: m.nonce, correlation_id: m.correlationId,
      destination: { host: LOCAL, session: m.replyTo },
      principal: { sid: p.sid, credential_sha256: p.credential_sha256, epoch: p.epoch, generation: p.generation },
      origin_inject_id: sel.row.inject_id, payload_sha256: payloadSha, challenge_sha256: challengeSha,
      state: "issued", outcome: null, created_ms: t, expires_ms: expires, attempts: 0,
    };
    const c = store.commit((d) => {
      store.pruneDraft(d, t);
      if (Object.keys(d.bindings).length >= store.limits.bindings) return { ok: false, code: "RESPONDER_FULL" };
      d.bindings[bindingId] = fresh;
      store.pushAudit(d, { at: iso(t), event: "issued", binding_id: bindingId, reason: null });
      return undefined;
    });
    if (!c.ok) return fail(c.code, c.errno ? { errno: c.errno } : {});
    counters.issued += 1;
    return ok({ ...view(store.binding(bindingId)), challenge, reissued: false, deduplicated: false });
  }

  /**
   * Perform the authenticated reply for one issued capability. Destination, nonce, principal and session
   * generation come from the recorded binding only; `body` is the only caller-supplied content.
   */
  async function reply({ binding_id, challenge, body } = {}) {
    if (typeof binding_id !== "string" || !HEX32_RE.test(binding_id)
        || typeof challenge !== "string" || !CHALLENGE_RE.test(challenge)
        || typeof body !== "string" || body.length < 1 || body.length > RESPONDER_LIMITS.bodyChars || body.includes("\u0000")) {
      return refuse("DROP_INVALID", "drop_invalid", { binding_id: typeof binding_id === "string" && HEX32_RE.test(binding_id) ? binding_id : null });
    }
    const b0 = store.binding(binding_id);
    if (b0 === null) return refuse("BINDING_UNKNOWN", "binding_unknown");
    // Single use: a binding that already has an outcome answers with THAT outcome and sends nothing.
    if (b0.outcome !== null) {
      counters.duplicate += 1;
      record({ event: "duplicate", binding_id, reason: "duplicate" });
      return ok({ ...view(b0), duplicate: true, sent: false });
    }
    if (b0.state === "sending") {
      // Another pass of this process is in the middle of its one send; no second send is started.
      return refuse("BINDING_IN_FLIGHT", "duplicate", { binding_id });
    }
    if (!digestsEqual(b0.challenge_sha256, sha256hex(challenge))) {
      const t = now();
      const left = Math.max(0, store.limits.attempts - (b0.attempts + 1));
      const c = store.commit((d) => {
        const b = d.bindings[binding_id];
        if (!b || b.outcome !== null) return { ok: false, code: "BINDING_STATE_CHANGED" };
        b.attempts += 1;
        if (b.attempts >= store.limits.attempts) {
          b.state = "refused";
          b.outcome = { at: iso(t), result: "refused", reason: "attempts_exhausted", inject_id: null, reply_sha256: null };
        }
        store.pushAudit(d, { at: iso(t), event: "refused", binding_id, reason: left === 0 ? "attempts_exhausted" : "challenge_mismatch" });
        return undefined;
      });
      counters.refused += 1;
      return fail("CHALLENGE_MISMATCH", { attempts_left: left, ...(c && c.ok ? {} : { audit: "degraded" }) });
    }
    const p = principal();
    if (p === null) return refuse("CREDENTIAL_UNAVAILABLE", "credential_unavailable", { binding_id });

    const t0 = now();
    if (t0 > b0.expires_ms) return settle(binding_id, { at: iso(t0), result: "refused", reason: "expired", inject_id: null, reply_sha256: null }, "BINDING_EXPIRED");
    const bad = principalVerdict(b0, p);
    if (bad !== null) {
      return settle(binding_id, { at: iso(t0), result: "refused", reason: bad, inject_id: null, reply_sha256: null },
        bad === "principal_mismatch" ? "PRINCIPAL_MISMATCH" : "SESSION_GENERATION_CHANGED");
    }

    const prompt = composeReply(b0.nonce, body);
    const replySha = sha256hex(prompt);
    // Intent first: the binding is durably `sending` BEFORE the inject, so a crash in the middle can only
    // become `uncertain` on the next open — never a second send.
    const intent = store.commit((d) => {
      const b = d.bindings[binding_id];
      if (!b || b.state !== "issued" || b.outcome !== null) return { ok: false, code: "BINDING_STATE_CHANGED" };
      b.state = "sending";
      b.outcome = null;
      return undefined;
    });
    if (!intent.ok) return fail(intent.code, intent.errno ? { errno: intent.errno } : {});

    let sendResult;
    try {
      sendResult = await daemon.inject({
        to: b0.destination.session, prompt, from: p.sid, sessionToken: p.bearer,
      });
    } catch {
      sendResult = { ok: false, code: "DAEMON_UNREACHABLE", sent: "unknown" };
    }
    const at = iso(now());
    let outcome;
    if (isPlain(sendResult) && sendResult.ok === true && typeof sendResult.inject_id === "string" && INJECT_ID_RE.test(sendResult.inject_id)) {
      outcome = { at, result: "sent", reason: null, inject_id: sendResult.inject_id, reply_sha256: replySha };
    } else {
      const code = isPlain(sendResult) && typeof sendResult.code === "string" && /^[A-Z0-9_]{1,64}$/.test(sendResult.code) ? sendResult.code : "DAEMON_BAD_RESPONSE";
      const sent = isPlain(sendResult) ? sendResult.sent : "unknown";
      // A definitive refusal is `refused`; anything else may have taken effect and stays `uncertain`.
      outcome = sent === "no" || sent === "yes"
        ? { at, result: "refused", reason: code, inject_id: null, reply_sha256: replySha }
        : { at, result: "uncertain", reason: code, inject_id: null, reply_sha256: replySha };
    }
    return settle(binding_id, outcome, outcome.result === "sent" ? null : outcome.result === "uncertain" ? "REPLY_UNCERTAIN" : outcome.reason);
  }

  // Records a final outcome (durably if possible) and answers. A failed write leaves the binding
  // `sending` on disk: the next open turns it into `uncertain`, so the reply is still never re-sent.
  function settle(bindingId, outcome, failCode) {
    const c = store.commit((d) => {
      const b = d.bindings[bindingId];
      if (!b || b.outcome !== null) return { ok: false, code: "BINDING_STATE_CHANGED" };
      b.state = outcome.result === "refused" ? "refused" : "accepted";
      b.outcome = outcome;
      store.pushAudit(d, {
        at: outcome.at, event: outcome.result === "refused" ? "refused" : "accepted",
        binding_id: bindingId, reason: outcome.reason, inject_id: outcome.inject_id,
      });
      return undefined;
    });
    const durability = c.ok ? "durable" : "degraded";
    if (outcome.result === "sent") counters.accepted += 1;
    else if (outcome.result === "uncertain") counters.uncertain += 1;
    else counters.refused += 1;
    const b = store.binding(bindingId);
    const base = b === null ? { binding_id: bindingId } : view(b);
    if (failCode !== null) return fail(failCode, { binding_id: bindingId, outcome: { ...outcome }, durability });
    return ok({ ...base, outcome: { ...outcome }, sent: true, duplicate: false, durability });
  }

  function status() {
    const bindings = store.bindings();
    const counts = { issued: 0, sending: 0, accepted: 0, refused: 0 };
    for (const b of bindings) counts[b.state] += 1;
    return ok({
      session: store.info().session, activated: true, permissions: store.info().permissions,
      lock: store.lockState(), bindings: counts, counters: { ...counters }, audit: store.audit().slice(-16),
    });
  }

  return Object.freeze({ recordInbound, reply, status, limits: RESPONDER_LIMITS });
}
