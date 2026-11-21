/**
 * telesession scoped responder (issue #18). A model whose tool runtime filters the environment holds NO
 * session id, token or credential path, so a reply it sends itself carries no verified sender and the
 * requester stores it as a `claimed_only` candidate with its body quarantined (src/transports/telepty.js
 * classifyAuditRows). This component closes that gap without handing a reusable session bearer to the
 * tool runtime:
 *
 *   1. `recordInbound({prompt, arrival_ms})` takes a CLAIM — any writer may present it — and proves it
 *      against the daemon: exactly one row of a complete page carries this payload to this session, and
 *      that row must be trusted-local, delivered, unspoofed and VERIFIED as sent by the prompt's own
 *      reply-to inbox. The daemon's observation of that same inject must also name THIS session and its
 *      current instance. Only then is a binding recorded, atomically and uniquely per request.
 *   2. The capability handed to the tool runtime is `{binding_id, challenge}`: single use, bound to one
 *      request, carrying no bearer and expiring with the REQUESTER's own deadline.
 *   3. `reply({binding_id, challenge, body})` — `body` is the only caller-supplied content. Before the
 *      one authenticated inject, this re-proves the recipient instance, checks the destination instance
 *      and RECONCILES the daemon's audit against this store's own send history, so a rolled-back or
 *      deleted state file cannot mint a second send (review r1 F01).
 *
 * Every acceptance and refusal is recorded with its reason. At most ONE authenticated send per binding;
 * a lost response stays `uncertain` and is never re-sent (this package never claims exactly-once).
 * Nothing that is quarantined today becomes readable: an inbound request without verified sender
 * evidence yields no binding, and no path here changes how a reply is classified on the requester's side.
 *
 * Guarantee scope (review r1 F01, field result 2026-11-21): the store is authenticated with a key
 * derived from the session credential the pump holds in memory. That resists a same-user actor which
 * cannot read that credential — the filtered tool runtime of issue #18. A tool runtime that DOES inherit
 * the session credential (codex-cli default shell policy) can reply directly without this component, so
 * no property here constrains it; the command refuses to run unless the operator declares the filtered
 * configuration (`TELESESSION_RESPONDER_TOOL_ENV=filtered`).
 *
 * INERT until an operator activates it (`activated: true`; `TELESESSION_RESPONDER=1` for the command).
 * Node >= 20 builtins only. No shell, no daemon lifecycle, no credential written to disk.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export const RESPONDER_LIMITS = Object.freeze({
  bodyChars: 7900,
  ttlMs: 15 * 60 * 1000,          // the requester's own nonce TTL (src/transports/telepty.js ISSUED_TTL_MS)
  // F05: the trusted row is stamped at or after the requester's send, so `row.ts + ttl - margin` is at or
  // before the requester's deadline unless the daemon stamped the row more than `margin` late.
  deadlineMarginMs: 30000,
  inboundLookbackMs: 15 * 60 * 1000,   // a claim may be presented any time inside the request's life
  inboundSkewMs: 2000,                 // …and the row may be at most this far after the claimed arrival
  reconcileSkewMs: 5000,
  auditRows: 200, promptChars: 8192, arrivalMaxMs: 1e15,
});

const SID_RE = /^[A-Za-z0-9._-]{1,128}$/;
const HEX32_RE = /^[0-9a-f]{32}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const INJECT_ID_RE = /^[A-Za-z0-9-]{1,128}$/;
const CHALLENGE_RE = /^[A-Za-z0-9_-]{43}$/;
const BEARER_RE = /^[\x21-\x7E]{1,4096}$/;
const CODE_RE = /^[A-Z0-9_]{1,64}$/;
// The exact wire header src/transports/telepty.js writes (`correlation` is absent in 0.1.x records).
const WIRE_RE = /^\[telesession nonce=([0-9a-f]{32}) reply-to=([A-Za-z0-9._-]{1,128})(?: correlation=([0-9a-f]{32}))?\]\n([\s\S]*)$/;
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
const isEpoch = (v) => typeof v === "string" && v.length >= 1 && v.length <= 256 && !/[\u0000-\u001f\u007f]/.test(v);
const codeOf = (r, dflt) => (isPlain(r) && typeof r.code === "string" && CODE_RE.test(r.code) ? r.code : dflt);

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
 * The ONE audit row that proves the inbound request.
 *
 * Review r1 F14: ambiguity is decided over EVERY row that carries this payload to this session, before
 * any trust predicate — a spoofed or unverified twin of the same delivery therefore blocks issuance
 * instead of letting its verified sibling authorize a capability (the same rule the requester's own
 * classifier applies to same-hash candidates). The surviving row must then be stamped local by this
 * daemon, delivered (`success`), unspoofed, and verified as sent by the prompt's own reply-to inbox.
 * A truncated page cannot show that a row is the only one, so it is never trusted.
 */
export function selectInboundRow(rows, { session, replyTo, payloadSha256, lo, hi, complete }) {
  if (complete !== true) return { ok: false, code: "INBOUND_AUDIT_INCOMPLETE", candidates: null };
  const sameDelivery = (Array.isArray(rows) ? rows : []).filter((r) => isPlain(r)
    && r.to === session && r.payload_sha256 === payloadSha256
    && Number.isFinite(Date.parse(r.ts)) && Date.parse(r.ts) >= lo && Date.parse(r.ts) <= hi);
  if (sameDelivery.length === 0) return { ok: false, code: "INBOUND_UNVERIFIED", candidates: 0 };
  if (sameDelivery.length > 1) return { ok: false, code: "INBOUND_AMBIGUOUS", candidates: sameDelivery.length };
  const row = sameDelivery[0];
  const trusted = row.to_alias === null && row.origin === "trusted-local" && row.delivery_result === "success"
    && row.claimed_from === replyTo && row.verified_sender_sid === replyTo && row.spoof_suspected === false
    && typeof row.inject_id === "string" && INJECT_ID_RE.test(row.inject_id);
  return trusted ? { ok: true, row } : { ok: false, code: "INBOUND_UNVERIFIED", candidates: 1 };
}

/**
 * Review r1 F07: the daemon's answer to a reply inject, classified by the SAME uncertainty rules as
 * src/transports/telepty.js (:126-132). An inject may have taken effect before an error, and an
 * explicitly uncertain answer is never a refusal — `sent: "no"` (a definitive refusal with no
 * uncertainty marker) is the only case that records `refused`; everything else stays `uncertain`, so the
 * binding is spent and nothing is ever re-sent. Pure: `r` is {ok, status, parsed, tooLarge}.
 */
export function classifyInjectResponse(r) {
  const res = isPlain(r) ? r : {};
  const parsed = isPlain(res.parsed) ? res.parsed : null;
  if (res.ok === true && parsed && parsed.success === true && typeof parsed.inject_id === "string" && INJECT_ID_RE.test(parsed.inject_id)) {
    return { ok: true, inject_id: parsed.inject_id };
  }
  if (res.status === null || res.status === undefined) return { ok: false, code: "DAEMON_UNREACHABLE", sent: "unknown" };
  if (res.tooLarge === true) return { ok: false, code: "DAEMON_BODY_TOO_LARGE", sent: "unknown" };
  const code = parsed && typeof parsed.code === "string" && CODE_RE.test(parsed.code) ? parsed.code : `DAEMON_HTTP_${res.status}`;
  const uncertain = res.status >= 500 || code === "DELIVERY_UNCERTAIN" || (parsed && parsed.delivery_uncertain === true) || res.ok === true;
  return { ok: false, code, sent: uncertain ? "unknown" : "no" };
}

// ── Component ──

/**
 * `store`    — openResponderStore() of this session's private directory (it holds the lock and the MAC key).
 * `credential` — () => {sid, bearer, epoch?, generation?}: the session credential this HOST process owns.
 *                The bearer is used for the inject; it is never stored, returned or logged.
 * `daemon`   — {injects({to, from, since, until, limit}), inject({to, prompt, from, sessionToken}),
 *              observe(injectId)}: the three telepty reads/writes this needs, injected so the component
 *              stays transport-agnostic.
 * `activated` — must be true. Without it the responder refuses to exist (operator activation gate).
 */
export function createResponder({ store, credential, daemon, now = Date.now, activated = false } = {}) {
  if (activated !== true) throw new ResponderError("RESPONDER_NOT_ACTIVATED");
  if (!store || typeof store.commit !== "function" || typeof store.binding !== "function") throw new ResponderError("RESPONDER_STORE_REQUIRED");
  if (typeof credential !== "function") throw new ResponderError("RESPONDER_CREDENTIAL_REQUIRED");
  if (!daemon || typeof daemon.injects !== "function" || typeof daemon.inject !== "function" || typeof daemon.observe !== "function") {
    throw new ResponderError("RESPONDER_DAEMON_REQUIRED");
  }

  const counters = { issued: 0, reissued: 0, accepted: 0, refused: 0, duplicate: 0, uncertain: 0 };
  const credentialTag = store.info().credential_tag;

  // The credential of THIS session, as this process holds it. The store was opened with a key derived
  // from the same bearer, so `credential_tag` is the credential INSTANCE: a rotated session credential
  // cannot even open this directory (RESPONDER_CREDENTIAL_ROTATED).
  function principal() {
    let c;
    try { c = credential(); } catch { return null; }
    if (!isPlain(c) || typeof c.sid !== "string" || !SID_RE.test(c.sid)) return null;
    if (typeof c.bearer !== "string" || !BEARER_RE.test(c.bearer)) return null;
    if (c.sid !== store.info().session) return null;
    return {
      sid: c.sid, bearer: c.bearer, credential_tag: credentialTag,
      epoch: isEpoch(c.epoch) ? c.epoch : null,
      generation: Number.isSafeInteger(c.generation) && c.generation >= 0 ? c.generation : null,
    };
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

  function digestsEqual(a, b) {
    if (typeof a !== "string" || typeof b !== "string" || !HEX64_RE.test(a) || !HEX64_RE.test(b)) return false;
    return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
  }

  const view = (b) => ({
    binding_id: b.binding_id, nonce: b.nonce, correlation_id: b.correlation_id,
    destination: { ...b.destination }, state: b.state, expires_at: iso(b.expires_ms),
    outcome: b.outcome === null ? null : { ...b.outcome },
  });

  // The daemon's own observation of an inject: for the inbound request it names THIS session and the
  // instance that received it; for our reply it names the destination instance that received it.
  async function observed(injectId) {
    let r;
    try { r = await daemon.observe(injectId); } catch { return { ok: false, code: "DAEMON_UNREACHABLE" }; }
    if (!isPlain(r) || r.ok !== true || typeof r.session_id !== "string" || !isEpoch(r.session_epoch)) {
      return { ok: false, code: codeOf(r, "OBSERVATION_UNAVAILABLE") };
    }
    return { ok: true, session_id: r.session_id, session_epoch: r.session_epoch };
  }

  /**
   * F01 (b): the daemon's audit is not same-user writable, so it — not the local file — decides whether
   * this instance has already injected a reply into that inbox. Every row attributable to this session
   * instance must be accounted for by this store's own send history; an unaccounted row means the local
   * history was rolled back, deleted or written by something else, and nothing is sent.
   */
  async function reconcile(b, p) {
    const lo = b.origin_ts_ms - RESPONDER_LIMITS.reconcileSkewMs;
    const hi = now() + RESPONDER_LIMITS.reconcileSkewMs;
    let r;
    try {
      r = await daemon.injects({
        to: b.destination.session, from: p.sid, since: iso(lo), until: iso(hi), limit: RESPONDER_LIMITS.auditRows,
      });
    } catch {
      return { ok: false, code: "DAEMON_UNREACHABLE" };
    }
    if (!isPlain(r) || r.ok !== true) return { ok: false, code: codeOf(r, "AUDIT_UNAVAILABLE") };
    if (r.next_cursor != null) return { ok: false, code: "RECONCILE_AUDIT_INCOMPLETE" };
    const known = new Set(store.sentHashes().map((x) => x.sha256));
    const mine = (Array.isArray(r.injects) ? r.injects : []).filter((row) => isPlain(row)
      && row.to === b.destination.session && row.verified_sender_sid === p.sid
      && row.verified_sender_epoch === b.recipient_epoch && row.spoof_suspected === false
      && typeof row.payload_sha256 === "string" && HEX64_RE.test(row.payload_sha256));
    const unaccounted = mine.filter((row) => !known.has(row.payload_sha256));
    if (unaccounted.length > 0) return { ok: false, code: "AUDIT_UNACCOUNTED_REPLY", unaccounted: unaccounted.length };
    return { ok: true, replies: mine.length };
  }

  /**
   * F02: positive evidence that the destination inbox is still the instance the request came from. The
   * daemon offers no epoch-pinned inject, so this is a pre-send check on the rows that exist plus the
   * post-send observation below; absence of rows is not evidence and is not treated as one.
   */
  async function destinationInstanceOk(b, p) {
    if (b.destination_instance.epoch === null) return { ok: true, checked: false };
    let r;
    try {
      r = await daemon.injects({
        to: p.sid, from: b.destination.session, since: iso(b.origin_ts_ms - RESPONDER_LIMITS.reconcileSkewMs),
        until: iso(now() + RESPONDER_LIMITS.reconcileSkewMs), limit: RESPONDER_LIMITS.auditRows,
      });
    } catch {
      return { ok: false, code: "DAEMON_UNREACHABLE" };
    }
    if (!isPlain(r) || r.ok !== true) return { ok: false, code: codeOf(r, "AUDIT_UNAVAILABLE") };
    const theirs = (Array.isArray(r.injects) ? r.injects : []).filter((row) => isPlain(row)
      && row.verified_sender_sid === b.destination.session && isEpoch(row.verified_sender_epoch));
    const changed = theirs.some((row) => row.verified_sender_epoch !== b.destination_instance.epoch);
    return changed ? { ok: false, code: "DESTINATION_INSTANCE_CHANGED" } : { ok: true, checked: theirs.length > 0 };
  }

  /**
   * Record the trusted inbound request binding for a request this session received, and issue the scoped
   * capability for it. The claim itself proves nothing: without exactly one matching VERIFIED audit row
   * and a matching daemon observation of that inject, no binding exists.
   */
  async function recordInbound({ prompt, arrival_ms } = {}) {
    const t0 = now();
    if (typeof prompt !== "string" || prompt.length < 1 || prompt.length > RESPONDER_LIMITS.promptChars
        || (arrival_ms !== undefined && !(Number.isSafeInteger(arrival_ms) && arrival_ms >= 0
          && arrival_ms <= RESPONDER_LIMITS.arrivalMaxMs && arrival_ms <= t0 + RESPONDER_LIMITS.inboundSkewMs))) {
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

    const arrival = arrival_ms === undefined ? t0 : arrival_ms;
    const lo = arrival - RESPONDER_LIMITS.inboundLookbackMs;
    const hi = arrival + RESPONDER_LIMITS.inboundSkewMs;
    let r;
    try {
      r = await daemon.injects({ to: p.sid, since: iso(lo), until: iso(hi), limit: RESPONDER_LIMITS.auditRows });
    } catch {
      return refuse("DAEMON_UNREACHABLE", "DAEMON_UNREACHABLE");
    }
    if (!isPlain(r) || r.ok !== true) {
      // No evidence read → no binding. Recorded as a refusal; the claim may be presented again later.
      const code = codeOf(r, "AUDIT_UNAVAILABLE");
      return refuse(code, code);
    }
    const sel = selectInboundRow(r.injects, {
      session: p.sid, replyTo: m.replyTo, payloadSha256: payloadSha, lo, hi, complete: r.next_cursor == null,
    });
    if (!sel.ok) return refuse(sel.code, sel.code === "INBOUND_AMBIGUOUS" ? "inbound_ambiguous" : "inbound_unverified", { extra: { candidates: sel.candidates } });

    // F05: the deadline comes from the trusted row, never from the caller's arrival.
    const originTs = Date.parse(sel.row.ts);
    const expires = originTs + RESPONDER_LIMITS.ttlMs - RESPONDER_LIMITS.deadlineMarginMs;
    if (t0 >= expires) return refuse("INBOUND_PAST_DEADLINE", "past_deadline", { extra: { expires_at: iso(expires) } });

    // F03: the daemon's observation of that inject must name THIS session and the instance it is now.
    const obs = await observed(sel.row.inject_id);
    if (!obs.ok) return refuse(obs.code, "recipient_instance_unproven");
    if (obs.session_id !== p.sid) return refuse("RECIPIENT_MISMATCH", "recipient_mismatch");
    if (p.epoch !== null && obs.session_epoch !== p.epoch) return refuse("RECIPIENT_INSTANCE_CHANGED", "recipient_instance_changed");

    const challenge = randomBytes(32).toString("base64url");
    const challengeSha = sha256hex(challenge);

    if (prior) {
      // The binding stands (destination, nonce, principal, instance, deadline unchanged); only the
      // capability is re-issued, because its delivery to the tool runtime may have been lost.
      // `attempts` is NOT reset, and a changed recipient instance refuses the re-issue.
      if (prior.recipient_epoch !== obs.session_epoch) return refuse("RECIPIENT_INSTANCE_CHANGED", "recipient_instance_changed", { binding_id: prior.binding_id });
      const c = store.commit((d) => {
        const b = d.bindings[prior.binding_id];
        if (!b || b.outcome !== null || b.state !== "issued") return { ok: false, code: "BINDING_STATE_CHANGED" };
        b.challenge_sha256 = challengeSha;
        store.pushAudit(d, { at: iso(now()), event: "reissued", binding_id: b.binding_id, reason: null });
        return undefined;
      });
      if (!c.ok) return fail(c.code, c.errno ? { errno: c.errno } : {});
      counters.reissued += 1;
      return ok({ ...view(store.binding(prior.binding_id)), challenge, reissued: true, deduplicated: false });
    }

    const bindingId = randomBytes(16).toString("hex");
    const fresh = {
      binding_id: bindingId, nonce: m.nonce, correlation_id: m.correlationId,
      destination: { host: LOCAL, session: m.replyTo },
      principal: { sid: p.sid, credential_tag: p.credential_tag, epoch: p.epoch, generation: p.generation },
      destination_instance: {
        epoch: isEpoch(sel.row.verified_sender_epoch) ? sel.row.verified_sender_epoch : null,
        generation: Number.isSafeInteger(sel.row.verified_sender_generation) ? sel.row.verified_sender_generation : null,
      },
      recipient_epoch: obs.session_epoch,
      origin_inject_id: sel.row.inject_id, payload_sha256: payloadSha, challenge_sha256: challengeSha,
      state: "issued", outcome: null, created_ms: t0, origin_ts_ms: originTs, expires_ms: expires, attempts: 0,
    };
    // F04: uniqueness per trusted inbound request is decided INSIDE the commit, under the single-writer
    // lock, so two concurrent registrations cannot mint two capabilities for one request.
    const c = store.commit((d) => {
      store.pruneDraft(d, t0);
      if (Object.values(d.bindings).some((b) => b.payload_sha256 === payloadSha && b.principal.sid === p.sid)) {
        return { ok: false, code: "BINDING_EXISTS" };
      }
      if (Object.keys(d.bindings).length >= store.limits.bindings) return { ok: false, code: "RESPONDER_FULL" };
      d.bindings[bindingId] = fresh;
      store.pushAudit(d, { at: iso(t0), event: "issued", binding_id: bindingId, reason: null });
      return undefined;
    });
    if (!c.ok) {
      if (c.code !== "BINDING_EXISTS") return fail(c.code, c.errno ? { errno: c.errno } : {});
      // The concurrent winner's binding is the only one; this caller gets no second capability.
      const winner = store.bindings().find((b) => b.payload_sha256 === payloadSha && b.principal.sid === p.sid);
      counters.duplicate += 1;
      record({ event: "duplicate", binding_id: winner ? winner.binding_id : null, reason: "binding_exists" });
      return fail("BINDING_EXISTS", winner ? { binding_id: winner.binding_id } : {});
    }
    counters.issued += 1;
    return ok({ ...view(store.binding(bindingId)), challenge, reissued: false, deduplicated: false });
  }

  const outcomeOf = (result, reason) => ({
    at: iso(now()), result, reason, inject_id: null, reply_sha256: null, destination_instance_ok: null,
  });

  /**
   * Perform the authenticated reply for one issued capability. Destination, nonce, principal, instance
   * and deadline come from the recorded binding only; `body` is the only caller-supplied content.
   */
  async function reply({ binding_id, challenge, body } = {}) {
    if (typeof binding_id !== "string" || !HEX32_RE.test(binding_id)
        || typeof challenge !== "string" || !CHALLENGE_RE.test(challenge)
        || typeof body !== "string" || body.length < 1 || body.length > RESPONDER_LIMITS.bodyChars || body.includes("\u0000")) {
      return refuse("DROP_INVALID", "drop_invalid", { binding_id: typeof binding_id === "string" && HEX32_RE.test(binding_id) ? binding_id : null });
    }
    const b0 = store.binding(binding_id);
    if (b0 === null) return refuse("BINDING_UNKNOWN", "binding_unknown");
    // The capability is checked BEFORE anything about the binding is answered, so a caller holding only
    // an id learns nothing about its destination, nonce or outcome (review r1 REVIEW.md §"What
    // authorizes the send"). Attempts are consumed only while the binding is still spendable.
    if (!digestsEqual(b0.challenge_sha256, sha256hex(challenge))) {
      if (b0.outcome !== null) return refuse("CHALLENGE_MISMATCH", "challenge_mismatch", { binding_id });
      const t = now();
      const left = Math.max(0, store.limits.attempts - (b0.attempts + 1));
      const c = store.commit((d) => {
        const b = d.bindings[binding_id];
        if (!b || b.outcome !== null) return { ok: false, code: "BINDING_STATE_CHANGED" };
        b.attempts += 1;
        if (b.attempts >= store.limits.attempts) {
          b.state = "refused";
          b.outcome = { at: iso(t), result: "refused", reason: "attempts_exhausted", inject_id: null, reply_sha256: null, destination_instance_ok: null };
        }
        store.pushAudit(d, { at: iso(t), event: "refused", binding_id, reason: left === 0 ? "attempts_exhausted" : "challenge_mismatch" });
        return undefined;
      });
      counters.refused += 1;
      return fail("CHALLENGE_MISMATCH", { attempts_left: left, ...(c && c.ok ? {} : { audit: "degraded" }) });
    }
    // Single use: a binding that already has an outcome answers with THAT outcome and sends nothing.
    if (b0.outcome !== null) {
      counters.duplicate += 1;
      record({ event: "duplicate", binding_id, reason: "duplicate" });
      return ok({ ...view(b0), duplicate: true, sent: false });
    }
    if (b0.state === "sending") {
      // Another call is in the middle of its one send; no second send is started.
      return refuse("BINDING_IN_FLIGHT", "duplicate", { binding_id });
    }
    const p = principal();
    if (p === null) return refuse("CREDENTIAL_UNAVAILABLE", "credential_unavailable", { binding_id });
    if (b0.principal.sid !== p.sid) return settle(binding_id, outcomeOf("refused", "principal_mismatch"), "PRINCIPAL_MISMATCH");
    if (b0.principal.credential_tag !== p.credential_tag) return settle(binding_id, outcomeOf("refused", "session_generation_changed"), "SESSION_GENERATION_CHANGED");

    // F05: the requester's own deadline, taken from the trusted inbound row at registration.
    if (now() > b0.expires_ms) return settle(binding_id, outcomeOf("refused", "expired"), "BINDING_EXPIRED");

    // F03: re-prove that this session is still the instance the request was delivered to.
    const obs = await observed(b0.origin_inject_id);
    if (!obs.ok) return refuse(obs.code, "recipient_instance_unproven", { binding_id });
    if (obs.session_id !== p.sid) return settle(binding_id, outcomeOf("refused", "recipient_mismatch"), "RECIPIENT_MISMATCH");
    if (obs.session_epoch !== b0.recipient_epoch) return settle(binding_id, outcomeOf("refused", "recipient_instance_changed"), "RECIPIENT_INSTANCE_CHANGED");

    // F02: contrary evidence that the requester inbox is now another instance refuses the send.
    const dest = await destinationInstanceOk(b0, p);
    if (!dest.ok) {
      if (dest.code === "DESTINATION_INSTANCE_CHANGED") return settle(binding_id, outcomeOf("refused", "destination_instance_changed"), dest.code);
      return refuse(dest.code, "destination_instance_unproven", { binding_id });
    }

    // F01: the daemon's audit must agree with this store's own send history before anything is sent.
    const rec = await reconcile(b0, p);
    if (!rec.ok) {
      if (rec.code === "AUDIT_UNACCOUNTED_REPLY") {
        return refuse(rec.code, "audit_unaccounted_reply", { binding_id, extra: { unaccounted: rec.unaccounted } });
      }
      return refuse(rec.code, "reconcile_unavailable", { binding_id });
    }

    const prompt = composeReply(b0.nonce, body);
    const replySha = sha256hex(prompt);
    // Intent first: the binding is durably `sending` and the payload hash is in the send history BEFORE
    // the inject, so a crash in the middle can only become `uncertain` on the next open — never a second
    // send — and the row this send creates is already accounted for by the next reconciliation.
    const intent = store.commit((d) => {
      const b = d.bindings[binding_id];
      if (!b || b.state !== "issued" || b.outcome !== null) return { ok: false, code: "BINDING_STATE_CHANGED" };
      const h = store.addSentHash(d, replySha, now());
      if (!h.ok) return h;
      b.state = "sending";
      b.outcome = null;
      return undefined;
    });
    if (!intent.ok) return fail(intent.code, intent.errno ? { errno: intent.errno } : {});

    let sendResult;
    try {
      sendResult = await daemon.inject({ to: b0.destination.session, prompt, from: p.sid, sessionToken: p.bearer });
    } catch {
      sendResult = { ok: false, code: "DAEMON_UNREACHABLE", sent: "unknown" };
    }
    const at = iso(now());
    let outcome;
    if (isPlain(sendResult) && sendResult.ok === true && typeof sendResult.inject_id === "string" && INJECT_ID_RE.test(sendResult.inject_id)) {
      // F02 (post-send): the daemon's observation names the instance that actually received it.
      let instanceOk = null;
      if (b0.destination_instance.epoch !== null) {
        const delivered = await observed(sendResult.inject_id);
        if (delivered.ok && delivered.session_id === b0.destination.session) {
          instanceOk = delivered.session_epoch === b0.destination_instance.epoch;
        }
      }
      outcome = {
        at, result: "sent", reason: instanceOk === false ? "destination_instance_changed" : null,
        inject_id: sendResult.inject_id, reply_sha256: replySha, destination_instance_ok: instanceOk,
      };
    } else {
      const code = codeOf(sendResult, "DAEMON_BAD_RESPONSE");
      const sent = isPlain(sendResult) ? sendResult.sent : "unknown";
      // Only an explicit "no effect" is a refusal; anything else may have taken effect (F07).
      outcome = sent === "no"
        ? { at, result: "refused", reason: code, inject_id: null, reply_sha256: replySha, destination_instance_ok: null }
        : { at, result: "uncertain", reason: code, inject_id: null, reply_sha256: replySha, destination_instance_ok: null };
    }
    return settle(binding_id, outcome,
      outcome.result === "sent" ? null : outcome.result === "uncertain" ? "REPLY_UNCERTAIN" : outcome.reason);
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

  // What the drop directory needs to know about a capability file without reading any record: whether it
  // can still be spent. `absent` / `spent` / `expired` mean its plaintext challenge may be swept (F13).
  function capabilityState(bindingId) {
    const b = store.binding(bindingId);
    if (b === null) return "absent";
    if (b.outcome !== null) return "spent";
    if (now() > b.expires_ms) return "expired";
    return b.state === "sending" ? "sending" : "live";
  }

  function status() {
    const counts = { issued: 0, sending: 0, accepted: 0, refused: 0 };
    for (const b of store.bindings()) counts[b.state] += 1;
    return ok({
      session: store.info().session, activated: true, permissions: store.info().permissions,
      authenticated_state: store.info().authenticated === true, lock: store.lockState(),
      bindings: counts, counters: { ...counters }, audit: store.audit().slice(-16),
    });
  }

  return Object.freeze({ recordInbound, reply, status, capabilityState, limits: RESPONDER_LIMITS });
}
