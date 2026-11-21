// Scoped responder (issue #18): the trusted inbound request binding, the single-use request-bound
// capability, and the authenticated send performed by the host-side component that owns the session
// credential. Real durable store and real drop directory on the real filesystem; the three telepty calls
// (audit read, observation, inject) are injected fakes, so these cases run without a daemon or a socket.
//
// Covered: duplicate, expiry from the REQUESTER's deadline, restart/reconnect, rotated credential,
// forged binding id, a binding for another destination, oversized body, every inbound refusal
// (including the claimed-only inbound request, which must never yield a binding), the activation gate,
// and one case per review-r1 finding: F01 tampered / rolled-back / deleted state, F02 replaced requester
// instance, F03 stale responder instance, F04 two concurrent registrations, F05 post-deadline send,
// F06 win32 refusal, F07 uncertainty mapping, F08 junk entries, F10 unpublishable result, F11 capability
// retention, F12 stale lock, F13 sweep, F14 ambiguous same-payload delivery.
//
// The responder refuses to run on win32 (F06), so the cases that need its durable state are NOTRUN
// there; the platform refusal itself is asserted on every platform through the injected `platform`.

import { describe, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {
  openResponderStore, ResponderStoreError, RESPONDER_STORE_LIMITS, deriveStateKey, credentialTagOf, canonicalJson,
} from "../src/responder/store.js";
import {
  createResponder, ResponderError, RESPONDER_LIMITS, classifyInjectResponse, composeReply, parseRequestWire,
  selectInboundRow,
} from "../src/responder/responder.js";
import { openDropDir, runDropPass, parseInboundClaim, parseReplyDrop, DROP_LIMITS } from "../src/responder/drop.js";
import { foreignLock, hex, makeSandbox, sha256 } from "./helpers/fault-fs.js";

const ORIGIN = "http://127.0.0.1:47999";
const SESSION = "ts-responder";
const PREFIX = "tsrp";
const MY_EPOCH = "session-epoch-1";
const INBOX_EPOCH = "inbox-epoch-1";
const POSIX = process.platform !== "win32";
const NO_RESPONDER = POSIX ? false : "NOTRUN: the responder refuses win32 (review r1 F06)";

const inboxId = () => `${PREFIX}-i${hex(16)}`;
const wire = (nonce, replyTo, text = "please answer", correlation = null) =>
  `[telesession nonce=${nonce} reply-to=${replyTo}${correlation === null ? "" : ` correlation=${correlation}`}]\n${text}`;

function throwsCode(fn, code) {
  let err = null;
  try { fn(); } catch (e) { err = e; }
  assert.ok(err, `expected ${code}`);
  assert.equal(err.code, code, `expected ${code}, got ${err.code}: ${err.message}`);
  return err;
}

function auditRow(over = {}) {
  return {
    ts: new Date().toISOString(), inject_id: `inj-${hex(8)}`, kind: "inject", source: "inject",
    claimed_from: null, verified_sender_sid: null, verified_sender_epoch: null, verified_sender_generation: null,
    to: null, to_alias: null, origin: "trusted-local", spoof_suspected: false, payload_sha256: null,
    delivery_result: "success", ...over,
  };
}

// The row telepty writes when an inbox injected exactly this prompt into this session with its OWN bearer.
const verifiedRow = (prompt, replyTo, over = {}) => auditRow({
  to: SESSION, claimed_from: replyTo, verified_sender_sid: replyTo, verified_sender_epoch: INBOX_EPOCH,
  verified_sender_generation: 7, payload_sha256: sha256(prompt), ...over,
});

/**
 * The daemon this host talks to: an audit log, observations and an inject that appends to both, exactly
 * as a real daemon would. `state.rows` is the audit; `state.observations` maps inject_id → what the
 * daemon observed; `state.sent` records every authenticated inject this responder made.
 */
function makeDaemon(clock) {
  const state = {
    rows: [], observations: new Map(), nextCursor: null, auditFail: null, observeFail: null,
    injectResult: null, throwOnInject: false, destinationEpoch: INBOX_EPOCH, queries: [], sent: [],
  };
  const daemon = {
    injects: async (q) => {
      state.queries.push(q);
      if (state.auditFail !== null) return { ok: false, code: state.auditFail };
      const lo = Date.parse(q.since);
      const hi = Date.parse(q.until);
      const rows = state.rows.filter((r) => Date.parse(r.ts) >= lo && Date.parse(r.ts) <= hi
        && (q.to === undefined || r.to === q.to)
        && (q.from === undefined || r.claimed_from === q.from || r.verified_sender_sid === q.from));
      return { ok: true, injects: rows.slice(0, q.limit), next_cursor: state.nextCursor };
    },
    observe: async (injectId) => {
      if (state.observeFail !== null) return { ok: false, code: state.observeFail };
      const o = state.observations.get(injectId);
      return o === undefined ? { ok: false, code: "OBSERVATION_UNAVAILABLE" } : { ok: true, ...o };
    },
    inject: async (a) => {
      state.sent.push(a);
      if (state.throwOnInject) throw new Error("socket closed");
      if (state.injectResult !== null) return state.injectResult;
      const injectId = `inj-sent-${state.sent.length}`;
      // The daemon records the authenticated inject and its delivery observation.
      state.rows.push(auditRow({
        ts: new Date(clock.ms).toISOString(), inject_id: injectId, to: a.to, claimed_from: a.from,
        verified_sender_sid: SESSION, verified_sender_epoch: MY_EPOCH, verified_sender_generation: 3,
        payload_sha256: sha256(a.prompt),
      }));
      state.observations.set(injectId, { session_id: a.to, session_epoch: state.destinationEpoch });
      return { ok: true, inject_id: injectId };
    },
  };
  return { state, daemon };
}

function setup(t, { session = SESSION } = {}) {
  const sb = makeSandbox("ts-responder-");
  const clock = { ms: Date.now() };
  const dir = path.join(sb.root, "responder");
  const { state, daemon } = makeDaemon(clock);
  const cred = { sid: session, bearer: `tgt-${hex(12)}`, epoch: MY_EPOCH, generation: 3 };
  const stores = [];
  const open = ({ bearer = cred.bearer } = {}) => {
    const store = openResponderStore({
      dir, session, origin: ORIGIN, stateKey: deriveStateKey(bearer, { origin: ORIGIN, session }),
    }, { now: () => clock.ms });
    stores.push(store);
    const responder = createResponder({
      store, daemon, activated: true, now: () => clock.ms, credential: () => ({ ...cred }),
    });
    return { store, responder };
  };
  t.after(() => {
    for (const s of stores) { try { s.close(); } catch { /* closed */ } }
    sb.remove();
  });
  const first = open();
  return { sb, dir, clock, state, daemon, cred, open, store: first.store, responder: first.responder };
}

// One verified inbound request (audit row + the daemon's observation of it) and its issued capability.
async function issued(ctx, { text = "what is the status?", tsMs = null, register = true, responder = null } = {}) {
  const nonce = hex(16);
  const replyTo = inboxId();
  const prompt = wire(nonce, replyTo, text, hex(16));
  const ts = new Date(tsMs === null ? ctx.clock.ms : tsMs).toISOString();
  const row = verifiedRow(prompt, replyTo, { ts });
  ctx.state.rows.push(row);
  ctx.state.observations.set(row.inject_id, { session_id: SESSION, session_epoch: MY_EPOCH });
  if (!register) return { nonce, replyTo, prompt, row };
  const rec = await (responder || ctx.responder).recordInbound({ prompt, arrival_ms: ctx.clock.ms });
  assert.equal(rec.ok, true, JSON.stringify(rec));
  return { nonce, replyTo, prompt, row, rec };
}

const otherChallenge = (c) => c.slice(0, 42) + (c.endsWith("A") ? "B" : "A");
const statePath = (ctx) => path.join(ctx.dir, "responder.json");
const readState = (ctx) => JSON.parse(fs.readFileSync(statePath(ctx), "utf8"));
const writeState = (ctx, value) => fs.writeFileSync(statePath(ctx), JSON.stringify(value), { mode: 0o600 });

describe("scoped responder — pure classifiers", () => {
  test("parseRequestWire reads the transport's wire header only", () => {
    const nonce = hex(16);
    const replyTo = inboxId();
    const correlation = hex(16);
    assert.deepEqual(parseRequestWire(wire(nonce, replyTo, "body text", correlation)),
      { nonce, replyTo, correlationId: correlation, text: "body text" });
    assert.deepEqual(parseRequestWire(wire(nonce, replyTo, "body text")),
      { nonce, replyTo, correlationId: null, text: "body text" });
    for (const bad of ["", "plain prompt", `REPLY ${nonce} not a request`, `[telesession nonce=xyz reply-to=${replyTo}]\nx`, null, 7]) {
      assert.equal(parseRequestWire(bad), null, JSON.stringify(bad));
    }
  });

  test("composeReply puts the recorded nonce first and fits the transport's 8000-char prompt limit", () => {
    const nonce = hex(16);
    assert.equal(composeReply(nonce, "hello"), `REPLY ${nonce} hello`);
    assert.ok(composeReply(nonce, "x".repeat(RESPONDER_LIMITS.bodyChars)).length <= 8000);
  });

  test("F14 selection needs exactly one SAME-PAYLOAD delivery of a complete page, then a verified row", () => {
    const replyTo = inboxId();
    const prompt = wire(hex(16), replyTo);
    const base = { session: SESSION, replyTo, payloadSha256: sha256(prompt), lo: 0, hi: 9e15, complete: true };
    assert.equal(selectInboundRow([verifiedRow(prompt, replyTo)], base).ok, true);
    assert.deepEqual(selectInboundRow([verifiedRow(prompt, replyTo)], { ...base, complete: false }),
      { ok: false, code: "INBOUND_AUDIT_INCOMPLETE", candidates: null });
    assert.deepEqual(selectInboundRow([], base), { ok: false, code: "INBOUND_UNVERIFIED", candidates: 0 });
    // F14: a spoofed or unverified twin of the same delivery blocks issuance; its verified sibling must
    // not authorize anything, because the two cannot be told apart by payload alone.
    for (const twin of [
      verifiedRow(prompt, replyTo, { spoof_suspected: true }),
      verifiedRow(prompt, replyTo, { verified_sender_sid: null }),
      verifiedRow(prompt, replyTo, { origin: "peer" }),
    ]) {
      assert.deepEqual(selectInboundRow([verifiedRow(prompt, replyTo), twin], base),
        { ok: false, code: "INBOUND_AMBIGUOUS", candidates: 2 }, JSON.stringify(twin.spoof_suspected));
    }
    // A single row still has to pass every trust predicate.
    for (const bad of [{ spoof_suspected: true }, { verified_sender_sid: null }, { verified_sender_sid: "someone-else" },
      { origin: "peer" }, { to_alias: "alias" }, { delivery_result: "queued" }, { delivery_result: "failed:x" }, { inject_id: 7 }]) {
      assert.deepEqual(selectInboundRow([verifiedRow(prompt, replyTo, bad)], base),
        { ok: false, code: "INBOUND_UNVERIFIED", candidates: 1 }, JSON.stringify(bad));
    }
  });

  test("a reply drop may carry NOTHING but its capability and its body", () => {
    const id = hex(16);
    const challenge = "A".repeat(43);
    assert.deepEqual(parseReplyDrop({ v: 1, binding_id: id, challenge, body: "answer" }), { binding_id: id, challenge, body: "answer" });
    for (const bad of [
      { v: 1, binding_id: id, challenge, body: "answer", destination: { session: "elsewhere" } },
      { v: 1, binding_id: id, challenge, body: "answer", nonce: hex(16) },
      { v: 1, binding_id: id, challenge, body: "answer", principal: { sid: "someone" } },
      { v: 2, binding_id: id, challenge, body: "answer" },
      { v: 1, binding_id: "nothex", challenge, body: "answer" },
      { v: 1, binding_id: id, challenge: "short", body: "answer" },
      { v: 1, binding_id: id, challenge, body: "" },
      { v: 1, binding_id: id, challenge, body: "a\u0000b" },
      { v: 1, binding_id: id, challenge, body: "x".repeat(RESPONDER_LIMITS.bodyChars + 1) },
    ]) assert.equal(parseReplyDrop(bad), null, JSON.stringify(bad).slice(0, 80));
    assert.deepEqual(parseInboundClaim({ v: 1, prompt: "p" }), { prompt: "p" });
    assert.deepEqual(parseInboundClaim({ v: 1, prompt: "p", arrival_ms: 5 }), { prompt: "p", arrival_ms: 5 });
    assert.equal(parseInboundClaim({ v: 1, prompt: "p", binding_id: hex(16) }), null);
  });

  test("F07 an uncertain or 5xx inject answer is never recorded as a definitive refusal", () => {
    const id = "00000000-0000-4000-8000-000000000001";
    assert.deepEqual(classifyInjectResponse({ ok: true, status: 200, parsed: { success: true, inject_id: id } }),
      { ok: true, inject_id: id });
    const cases = [
      [{ ok: false, status: null, parsed: null }, "DAEMON_UNREACHABLE", "unknown"],
      [{ ok: false, status: 503, parsed: null }, "DAEMON_HTTP_503", "unknown"],
      [{ ok: false, status: 500, parsed: { code: "INTERNAL" } }, "INTERNAL", "unknown"],
      [{ ok: false, status: 409, parsed: { code: "DELIVERY_UNCERTAIN" } }, "DELIVERY_UNCERTAIN", "unknown"],
      [{ ok: false, status: 409, parsed: { code: "SOMETHING", delivery_uncertain: true } }, "SOMETHING", "unknown"],
      [{ ok: false, status: 400, parsed: null, tooLarge: true }, "DAEMON_BODY_TOO_LARGE", "unknown"],
      [{ ok: true, status: 200, parsed: { success: false } }, "DAEMON_HTTP_200", "unknown"],
      [{ ok: false, status: 404, parsed: { code: "SESSION_NOT_FOUND" } }, "SESSION_NOT_FOUND", "no"],
      [{ ok: false, status: 403, parsed: { code: "PEER_INJECT_BLOCKED" } }, "PEER_INJECT_BLOCKED", "no"],
    ];
    for (const [r, code, sent] of cases) {
      assert.deepEqual(classifyInjectResponse(r), { ok: false, code, sent }, JSON.stringify(r));
    }
  });

  test("F01 state key and credential tag: derived from the bearer, bound to origin and session", () => {
    const k1 = deriveStateKey("bearer-one", { origin: ORIGIN, session: SESSION });
    assert.equal(k1.length, 32);
    assert.notEqual(credentialTagOf(k1), credentialTagOf(deriveStateKey("bearer-two", { origin: ORIGIN, session: SESSION })));
    assert.notEqual(credentialTagOf(k1), credentialTagOf(deriveStateKey("bearer-one", { origin: ORIGIN, session: "other" })));
    assert.equal(credentialTagOf(k1), credentialTagOf(deriveStateKey("bearer-one", { origin: ORIGIN, session: SESSION })));
    throwsCode(() => deriveStateKey("", { origin: ORIGIN, session: SESSION }), "RESPONDER_BINDING_MISMATCH");
    throwsCode(() => credentialTagOf(Buffer.alloc(8)), "RESPONDER_STATE_KEY_REQUIRED");
    // The MAC input must not depend on key order.
    assert.equal(canonicalJson({ b: 1, a: [2, { d: null, c: true }] }), '{"a":[2,{"c":true,"d":null}],"b":1}');
  });

  test("F06 the responder refuses win32: no store, no drop directory, no claimed protection", (t) => {
    const sb = makeSandbox("ts-responder-win32-");
    t.after(() => sb.remove());
    const key = deriveStateKey("bearer", { origin: ORIGIN, session: SESSION });
    throwsCode(() => openResponderStore({ dir: path.join(sb.root, "s"), session: SESSION, origin: ORIGIN, stateKey: key },
      { platform: "win32" }), "RESPONDER_PLATFORM_UNSUPPORTED");
    throwsCode(() => openDropDir(path.join(sb.root, "d"), { platform: "win32" }), "RESPONDER_PLATFORM_UNSUPPORTED");
    assert.equal(fs.existsSync(path.join(sb.root, "s")), false, "a refused platform creates nothing");
    assert.equal(fs.existsSync(path.join(sb.root, "d")), false);
    if (!POSIX) {
      // Native Windows: the same refusal without any seam.
      throwsCode(() => openResponderStore({ dir: path.join(sb.root, "s2"), session: SESSION, origin: ORIGIN, stateKey: key }),
        "RESPONDER_PLATFORM_UNSUPPORTED");
      throwsCode(() => openDropDir(path.join(sb.root, "d2")), "RESPONDER_PLATFORM_UNSUPPORTED");
    }
  });
});

describe("scoped responder — bindings and the authenticated send", { skip: NO_RESPONDER }, () => {
  test("S1 a verified inbound request yields one capability; the reply is injected with the session credential", async (t) => {
    const ctx = setup(t);
    const { nonce, replyTo, rec } = await issued(ctx);
    assert.match(rec.binding_id, /^[0-9a-f]{32}$/);
    assert.match(rec.challenge, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(rec.nonce, nonce);
    assert.deepEqual(rec.destination, { host: "local", session: replyTo });
    assert.equal(rec.state, "issued");
    assert.equal(rec.completion_fact, null);
    assert.equal(ctx.state.sent.length, 0, "recording a binding sends nothing");

    const out = await ctx.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body: "status: green" });
    assert.equal(out.ok, true, JSON.stringify(out));
    assert.equal(out.sent, true);
    assert.equal(out.outcome.result, "sent");
    assert.equal(out.outcome.inject_id, "inj-sent-1");
    assert.equal(out.outcome.destination_instance_ok, true, "the reply reached the recorded requester instance");
    assert.equal(out.durability, "durable");
    assert.deepEqual(ctx.state.sent, [{
      to: replyTo, prompt: `REPLY ${nonce} status: green`, from: SESSION, sessionToken: ctx.cred.bearer,
    }]);

    // Never persisted: the bearer, the challenge, the request text, the reply body.
    const raw = fs.readFileSync(statePath(ctx), "utf8");
    for (const secret of [ctx.cred.bearer, rec.challenge, "what is the status?", "status: green"]) {
      assert.equal(raw.includes(secret), false, secret);
    }
    const stored = JSON.parse(raw);
    assert.equal(stored.bindings[rec.binding_id].state, "accepted");
    assert.equal(stored.bindings[rec.binding_id].challenge_sha256, sha256(rec.challenge));
    assert.match(stored.mac, /^[0-9a-f]{64}$/);
    assert.deepEqual(stored.audit.map((e) => e.event), ["issued", "accepted"]);
    assert.equal(fs.lstatSync(statePath(ctx)).mode & 0o777, 0o600);
  });

  test("S2 duplicate: the spent capability answers with the recorded outcome and never sends again", async (t) => {
    const ctx = setup(t);
    const { rec } = await issued(ctx);
    const first = await ctx.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body: "first" });
    assert.equal(first.outcome.result, "sent");
    for (const body of ["first", "a different body"]) {
      const again = await ctx.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body });
      assert.equal(again.ok, true, JSON.stringify(again));
      assert.equal(again.duplicate, true);
      assert.equal(again.sent, false);
      assert.equal(again.outcome.inject_id, first.outcome.inject_id, "the same recorded outcome");
    }
    assert.equal(ctx.state.sent.length, 1, "exactly one authenticated send for one binding");
  });

  test("S3/F05 expiry comes from the REQUESTER's deadline in the trusted row, not from the claim", async (t) => {
    const ctx = setup(t);
    // A row stamped a minute ago expires a minute earlier than an arrival-based deadline would.
    const rowAge = 60000;
    const a = await issued(ctx, { tsMs: ctx.clock.ms - rowAge });
    const expected = ctx.clock.ms - rowAge + RESPONDER_LIMITS.ttlMs - RESPONDER_LIMITS.deadlineMarginMs;
    assert.equal(Date.parse(a.rec.expires_at), expected);
    ctx.clock.ms = expected + 1;
    const out = await ctx.responder.reply({ binding_id: a.rec.binding_id, challenge: a.rec.challenge, body: "too late" });
    assert.equal(out.ok, false, JSON.stringify(out));
    assert.equal(out.error.code, "BINDING_EXPIRED");
    assert.equal(out.error.outcome.result, "refused");
    assert.equal(out.error.outcome.reason, "expired");
    assert.equal(ctx.state.sent.length, 0, "an expired binding never sends");

    // A request already past its deadline never yields a capability at all.
    const stale = await issued(ctx, { text: "stale request", tsMs: ctx.clock.ms - RESPONDER_LIMITS.ttlMs, register: false });
    const refused = await ctx.responder.recordInbound({ prompt: stale.prompt, arrival_ms: ctx.clock.ms });
    assert.equal(refused.ok, false);
    assert.equal(refused.error.code, "INBOUND_PAST_DEADLINE");

    // An earlier result is preserved past expiry: the duplicate still answers `sent`.
    const b = await issued(ctx, { text: "second request" });
    const sent = await ctx.responder.reply({ binding_id: b.rec.binding_id, challenge: b.rec.challenge, body: "in time" });
    assert.equal(sent.outcome.result, "sent");
    ctx.clock.ms += RESPONDER_LIMITS.ttlMs;
    const late = await ctx.responder.reply({ binding_id: b.rec.binding_id, challenge: b.rec.challenge, body: "in time" });
    assert.equal(late.duplicate, true);
    assert.equal(late.outcome.result, "sent");
    assert.equal(late.outcome.inject_id, sent.outcome.inject_id);
    assert.equal(ctx.state.sent.length, 1);
  });

  test("S4 restart: binding and outcome survive a reopen, and an interrupted send becomes uncertain, never a second send", async (t) => {
    const ctx = setup(t);
    const { rec } = await issued(ctx);
    const sent = await ctx.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body: "answered before the restart" });
    assert.equal(sent.outcome.result, "sent");
    ctx.store.close();

    // Reconnect/restart: another process opens the same directory.
    const second = ctx.open();
    const after = await second.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body: "answered before the restart" });
    assert.equal(after.ok, true, JSON.stringify(after));
    assert.equal(after.duplicate, true);
    assert.equal(after.outcome.inject_id, sent.outcome.inject_id, "the outcome survived the restart");
    assert.equal(ctx.state.sent.length, 1, "no re-send after a restart");
    second.store.close();

    // A lost response: the inject may have taken effect, so the outcome stays uncertain for good.
    const third = ctx.open();
    const b = await issued(ctx, { text: "second request", responder: third.responder });
    const interrupted = ctx.state.sent.length;
    ctx.state.throwOnInject = true;
    const lost = await third.responder.reply({ binding_id: b.rec.binding_id, challenge: b.rec.challenge, body: "did it arrive?" });
    ctx.state.throwOnInject = false;
    assert.equal(lost.error.code, "REPLY_UNCERTAIN");
    assert.equal(ctx.state.sent.length, interrupted + 1);
    assert.equal(third.store.binding(b.rec.binding_id).outcome.result, "uncertain");
    third.store.close();

    const fourth = ctx.open();
    const retry = await fourth.responder.reply({ binding_id: b.rec.binding_id, challenge: b.rec.challenge, body: "did it arrive?" });
    assert.equal(retry.duplicate, true);
    assert.equal(retry.outcome.result, "uncertain");
    assert.equal(ctx.state.sent.length, interrupted + 1, "an uncertain outcome is never retried automatically");
  });

  test("S5/F01 a process killed between the intent and the outcome leaves `sending`; reopen makes it uncertain, never a second send", async (t) => {
    const ctx = setup(t);
    const { rec } = await issued(ctx);
    // Exactly what the pump's intent commit writes just before its one inject, authenticated by the MAC
    // of that commit — the state an abruptly killed pump leaves behind.
    const intent = ctx.store.commit((d) => {
      d.bindings[rec.binding_id].state = "sending";
      d.bindings[rec.binding_id].outcome = null;
      d.sent_hashes.push({ sha256: sha256(composeReply(rec.nonce, "interrupted")), at_ms: ctx.clock.ms });
    });
    assert.equal(intent.ok, true, JSON.stringify(intent));
    ctx.store.close();
    assert.equal(readState(ctx).bindings[rec.binding_id].state, "sending");

    const reopened = ctx.open();
    const b = reopened.store.binding(rec.binding_id);
    assert.equal(b.state, "accepted");
    assert.equal(b.outcome.result, "uncertain");
    assert.equal(b.outcome.reason, "PROCESS_RESTART");
    assert.equal(reopened.store.audit().at(-1).event, "recovered");
    const retry = await reopened.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body: "interrupted" });
    assert.equal(retry.duplicate, true);
    assert.equal(retry.outcome.result, "uncertain");
    assert.equal(ctx.state.sent.length, 0, "an interrupted send is never repeated");
  });

  test("S6 a rotated session credential cannot even open the directory, and its bindings stay unusable", async (t) => {
    const ctx = setup(t);
    const { rec } = await issued(ctx);
    ctx.store.close();
    // The session credential was rotated: the state key changes, so the recorded instance no longer matches.
    throwsCode(() => openResponderStore({
      dir: ctx.dir, session: SESSION, origin: ORIGIN,
      stateKey: deriveStateKey(`tgt-${hex(12)}`, { origin: ORIGIN, session: SESSION }),
    }, { now: () => ctx.clock.ms }), "RESPONDER_CREDENTIAL_ROTATED");
    assert.equal(fs.existsSync(path.join(ctx.dir, "lock")), false, "a refused open releases the lock it took");
    // With the original credential the record is still there and still spendable.
    const again = ctx.open();
    assert.equal(again.store.binding(rec.binding_id).state, "issued");
  });

  test("S7 forged binding id, wrong challenge (bounded attempts) and a cross-binding challenge all send nothing", async (t) => {
    const ctx = setup(t);
    const a = await issued(ctx, { text: "request A" });
    const b = await issued(ctx, { text: "request B" });

    const forged = await ctx.responder.reply({ binding_id: hex(16), challenge: a.rec.challenge, body: "x" });
    assert.equal(forged.error.code, "BINDING_UNKNOWN");

    const cross = await ctx.responder.reply({ binding_id: a.rec.binding_id, challenge: b.rec.challenge, body: "x" });
    assert.equal(cross.error.code, "CHALLENGE_MISMATCH");
    assert.equal(cross.error.attempts_left, RESPONDER_STORE_LIMITS.attempts - 1);

    const wrong = otherChallenge(a.rec.challenge);
    for (const left of [RESPONDER_STORE_LIMITS.attempts - 2, 0]) {
      const r = await ctx.responder.reply({ binding_id: a.rec.binding_id, challenge: wrong, body: "x" });
      assert.equal(r.error.code, "CHALLENGE_MISMATCH");
      assert.equal(r.error.attempts_left, left);
    }
    // The attempts are spent: even the right capability now answers with the recorded refusal.
    const after = await ctx.responder.reply({ binding_id: a.rec.binding_id, challenge: a.rec.challenge, body: "legitimate" });
    assert.equal(after.ok, true, JSON.stringify(after));
    assert.equal(after.duplicate, true);
    assert.equal(after.outcome.reason, "attempts_exhausted");
    assert.equal(ctx.state.sent.length, 0);

    // B is untouched and reaches only ITS OWN destination, with ITS OWN nonce.
    const ok = await ctx.responder.reply({ binding_id: b.rec.binding_id, challenge: b.rec.challenge, body: "for B" });
    assert.equal(ok.ok, true, JSON.stringify(ok));
    assert.deepEqual([ctx.state.sent.length, ctx.state.sent[0].to, ctx.state.sent[0].prompt],
      [1, b.replyTo, `REPLY ${b.nonce} for B`]);
  });

  test("S8 oversized, empty and NUL bodies are refused before any send; a spent binding leaks nothing to an id holder", async (t) => {
    const ctx = setup(t);
    const { rec } = await issued(ctx);
    for (const body of ["x".repeat(RESPONDER_LIMITS.bodyChars + 1), "", "a\u0000b"]) {
      const r = await ctx.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body });
      assert.equal(r.ok, false);
      assert.equal(r.error.code, "DROP_INVALID");
    }
    for (const bad of [{ binding_id: "short", challenge: rec.challenge, body: "x" }, { binding_id: rec.binding_id, challenge: "short", body: "x" }, {}]) {
      assert.equal((await ctx.responder.reply(bad)).error.code, "DROP_INVALID");
    }
    assert.equal(ctx.state.sent.length, 0);
    const ok = await ctx.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body: "x".repeat(RESPONDER_LIMITS.bodyChars) });
    assert.equal(ok.ok, true, JSON.stringify(ok));
    assert.ok(ctx.state.sent[0].prompt.length <= 8000);
    // A caller holding only the id and a well-shaped challenge learns nothing about the binding.
    const probe = await ctx.responder.reply({ binding_id: rec.binding_id, challenge: otherChallenge(rec.challenge), body: "probe" });
    assert.equal(probe.error.code, "CHALLENGE_MISMATCH");
    assert.equal(JSON.stringify(probe).includes(rec.nonce), false, "no nonce, destination or outcome is returned");
  });

  test("S9 an inbound request without exactly one VERIFIED row never yields a binding", async (t) => {
    const ctx = setup(t);
    const cases = [
      ["the daemon never saw this request (forged claim)", () => [], "INBOUND_UNVERIFIED"],
      ["claimed only: the inbound inject carried no session credential", (p, r) => [verifiedRow(p, r, { verified_sender_sid: null, verified_sender_epoch: null, verified_sender_generation: null })], "INBOUND_UNVERIFIED"],
      ["another session's credential was verified", (p, r) => [verifiedRow(p, r, { verified_sender_sid: "someone-else" })], "INBOUND_UNVERIFIED"],
      ["the claimed sender is not the verified one (spoof)", (p, r) => [verifiedRow(p, r, { spoof_suspected: true })], "INBOUND_UNVERIFIED"],
      ["not stamped local by this daemon", (p, r) => [verifiedRow(p, r, { origin: "peer" })], "INBOUND_UNVERIFIED"],
      ["another payload", (p, r) => [verifiedRow(p, r, { payload_sha256: sha256("other prompt") })], "INBOUND_UNVERIFIED"],
      ["delivered to another session", (p, r) => [verifiedRow(p, r, { to: "other-session" })], "INBOUND_UNVERIFIED"],
      ["delivered through an alias", (p, r) => [verifiedRow(p, r, { to_alias: "alias" })], "INBOUND_UNVERIFIED"],
      ["not an accepted delivery", (p, r) => [verifiedRow(p, r, { delivery_result: "queued" })], "INBOUND_UNVERIFIED"],
      ["outside the request's life", (p, r) => [verifiedRow(p, r, { ts: new Date(ctx.clock.ms - 2 * RESPONDER_LIMITS.ttlMs).toISOString() })], "INBOUND_UNVERIFIED"],
      ["F14 a spoofed twin of the same delivery", (p, r) => [verifiedRow(p, r), verifiedRow(p, r, { spoof_suspected: true })], "INBOUND_AMBIGUOUS"],
      ["two indistinguishable rows", (p, r) => [verifiedRow(p, r), verifiedRow(p, r)], "INBOUND_AMBIGUOUS"],
    ];
    for (const [name, rows, code] of cases) {
      const nonce = hex(16);
      const replyTo = inboxId();
      const prompt = wire(nonce, replyTo, name);
      ctx.state.rows = rows(prompt, replyTo);
      for (const row of ctx.state.rows) ctx.state.observations.set(row.inject_id, { session_id: SESSION, session_epoch: MY_EPOCH });
      const r = await ctx.responder.recordInbound({ prompt, arrival_ms: ctx.clock.ms });
      assert.equal(r.ok, false, name);
      assert.equal(r.error.code, code, name);
      assert.deepEqual(ctx.store.bindings(), [], name);
    }
    // A truncated audit page proves nothing.
    const nonce = hex(16);
    const replyTo = inboxId();
    const prompt = wire(nonce, replyTo, "twice");
    const row = verifiedRow(prompt, replyTo);
    ctx.state.rows = [row];
    ctx.state.observations.set(row.inject_id, { session_id: SESSION, session_epoch: MY_EPOCH });
    ctx.state.nextCursor = "cursor-2";
    assert.equal((await ctx.responder.recordInbound({ prompt, arrival_ms: ctx.clock.ms })).error.code, "INBOUND_AUDIT_INCOMPLETE");
    ctx.state.nextCursor = null;
    // An unavailable audit read issues nothing and is recorded; it may be presented again later.
    ctx.state.auditFail = "DAEMON_TIMEOUT";
    assert.equal((await ctx.responder.recordInbound({ prompt, arrival_ms: ctx.clock.ms })).error.code, "DAEMON_TIMEOUT");
    ctx.state.auditFail = null;
    // Not a telesession request; this session as its own reply inbox; an unusable claim.
    assert.equal((await ctx.responder.recordInbound({ prompt: "just a prompt" })).error.code, "INBOUND_NOT_TELESESSION");
    assert.equal((await ctx.responder.recordInbound({ prompt: wire(hex(16), SESSION, "loopback") })).error.code, "INBOUND_SELF");
    assert.equal((await ctx.responder.recordInbound({ prompt: "" })).error.code, "INVALID_ARGUMENT");
    assert.equal((await ctx.responder.recordInbound({ prompt, arrival_ms: ctx.clock.ms + 60000 })).error.code, "INVALID_ARGUMENT");
    assert.deepEqual(ctx.store.bindings(), []);
    assert.equal(ctx.state.sent.length, 0);
  });

  test("S10 the same request presented twice reuses its binding; a spent one is not re-issued", async (t) => {
    const ctx = setup(t);
    const { prompt, rec } = await issued(ctx);
    const again = await ctx.responder.recordInbound({ prompt, arrival_ms: ctx.clock.ms });
    assert.equal(again.ok, true, JSON.stringify(again));
    assert.equal(again.binding_id, rec.binding_id);
    assert.equal(again.reissued, true);
    assert.match(again.challenge, /^[A-Za-z0-9_-]{43}$/);
    assert.notEqual(again.challenge, rec.challenge, "a re-issued capability is a new one");
    assert.equal(ctx.store.bindings().length, 1);
    assert.equal(again.expires_at, rec.expires_at, "the deadline does not move on re-issue");
    // The superseded capability no longer opens the binding.
    assert.equal((await ctx.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body: "old capability" })).error.code, "CHALLENGE_MISMATCH");
    const sent = await ctx.responder.reply({ binding_id: again.binding_id, challenge: again.challenge, body: "new capability" });
    assert.equal(sent.ok, true, JSON.stringify(sent));
    // Spent: presenting the request again returns the outcome and no capability at all.
    const spent = await ctx.responder.recordInbound({ prompt, arrival_ms: ctx.clock.ms });
    assert.equal(spent.ok, true);
    assert.equal(spent.deduplicated, true);
    assert.equal(spent.challenge, undefined, "no capability for a spent binding");
    assert.equal(spent.outcome.result, "sent");
    assert.equal(ctx.state.sent.length, 1);
  });

  test("S11 activation gate and store guards", async (t) => {
    const ctx = setup(t);
    await issued(ctx);                       // a committed, authenticated state file exists
    const args = { store: ctx.store, daemon: ctx.daemon, credential: () => ({ ...ctx.cred }) };
    for (const activated of [undefined, false, "yes", 1]) {
      throwsCode(() => createResponder({ ...args, activated }), "RESPONDER_NOT_ACTIVATED");
    }
    assert.ok(throwsCode(() => createResponder({ ...args }), "RESPONDER_NOT_ACTIVATED") instanceof ResponderError);
    throwsCode(() => createResponder({ activated: true, daemon: ctx.daemon, credential: args.credential }), "RESPONDER_STORE_REQUIRED");
    throwsCode(() => createResponder({ activated: true, store: ctx.store, daemon: ctx.daemon }), "RESPONDER_CREDENTIAL_REQUIRED");
    throwsCode(() => createResponder({ activated: true, store: ctx.store, credential: args.credential }), "RESPONDER_DAEMON_REQUIRED");
    throwsCode(() => createResponder({ activated: true, store: ctx.store, credential: args.credential, daemon: { injects: () => {}, inject: () => {} } }), "RESPONDER_DAEMON_REQUIRED");

    const key = deriveStateKey(ctx.cred.bearer, { origin: ORIGIN, session: SESSION });
    // A directory already held by a LIVE pump is refused and never reclaimed.
    const locked = throwsCode(() => openResponderStore({ dir: ctx.dir, session: SESSION, origin: ORIGIN, stateKey: key }), "RESPONDER_LOCKED");
    assert.ok(locked instanceof ResponderStoreError);
    assert.ok(fs.existsSync(path.join(ctx.dir, "lock")), "the held lock is untouched");
    assert.equal(ctx.store.lockState(), "held");

    // State recorded for another session or another daemon is never reused.
    ctx.store.close();
    throwsCode(() => openResponderStore({ dir: ctx.dir, session: "another-session", origin: ORIGIN, stateKey: deriveStateKey(ctx.cred.bearer, { origin: ORIGIN, session: "another-session" }) }), "RESPONDER_BINDING_MISMATCH");
    throwsCode(() => openResponderStore({ dir: ctx.dir, session: SESSION, origin: "http://127.0.0.1:47998", stateKey: deriveStateKey(ctx.cred.bearer, { origin: "http://127.0.0.1:47998", session: SESSION }) }), "RESPONDER_BINDING_MISMATCH");
    throwsCode(() => openResponderStore({ dir: "relative/dir", session: SESSION, origin: ORIGIN, stateKey: key }), "RESPONDER_PATH_INVALID");
    throwsCode(() => openResponderStore({ dir: ctx.dir, session: SESSION, origin: ORIGIN }), "RESPONDER_STATE_KEY_REQUIRED");
    assert.equal(fs.existsSync(path.join(ctx.dir, "lock")), false, "every refused open released the lock it took");
  });

  test("S12/F12 a lock left by a dead holder is reported stale and NEVER reclaimed", async (t) => {
    const ctx = setup(t);
    await issued(ctx);
    ctx.store.close();
    const lockPath = path.join(ctx.dir, "lock");
    const key = deriveStateKey(ctx.cred.bearer, { origin: ORIGIN, session: SESSION });
    const open = () => openResponderStore({ dir: ctx.dir, session: SESSION, origin: ORIGIN, stateKey: key }, { now: () => ctx.clock.ms });

    fs.writeFileSync(lockPath, foreignLock({ pid: process.pid }), { mode: 0o600 });
    throwsCode(open, "RESPONDER_LOCKED");
    assert.ok(fs.existsSync(lockPath), "a live holder's lock is never removed");

    fs.writeFileSync(lockPath, foreignLock({ pid: 999999 }), { mode: 0o600 });
    throwsCode(open, "RESPONDER_LOCK_STALE");
    assert.ok(fs.existsSync(lockPath), "a stale lock is reported, not reclaimed");
    // Documented one-line operator recovery, after confirming no pump runs for this directory.
    fs.unlinkSync(lockPath);
    const reopened = open();
    assert.equal(reopened.store.bindings().length, 1);
  });

  test("F01 a tampered record is refused: the destination cannot be rewritten under the pump", async (t) => {
    const ctx = setup(t);
    const { rec, replyTo } = await issued(ctx);
    await ctx.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body: "the real answer" });
    assert.equal(ctx.state.sent.length, 1);
    ctx.store.close();
    const disk = readState(ctx);
    const attacker = inboxId();
    disk.bindings[rec.binding_id].destination.session = attacker;
    writeState(ctx, disk);
    const key = deriveStateKey(ctx.cred.bearer, { origin: ORIGIN, session: SESSION });
    throwsCode(() => openResponderStore({ dir: ctx.dir, session: SESSION, origin: ORIGIN, stateKey: key }, { now: () => ctx.clock.ms }),
      "RESPONDER_STATE_UNAUTHENTIC");
    // The refused open neither rewrote the file nor kept the lock, and nothing else was sent.
    assert.equal(readState(ctx).bindings[rec.binding_id].destination.session, attacker);
    assert.equal(fs.existsSync(path.join(ctx.dir, "lock")), false);
    assert.equal(ctx.state.sent.length, 1);

    // Every other field is covered by the same MAC, including the challenge digest and the outcome.
    for (const edit of [
      (d) => { d.bindings[rec.binding_id].nonce = hex(16); },
      (d) => { d.bindings[rec.binding_id].challenge_sha256 = sha256("attacker challenge"); },
      (d) => { d.bindings[rec.binding_id].expires_ms += 3600000; },
      (d) => { d.bindings[rec.binding_id].outcome = null; },
      (d) => { d.sent_hashes = []; },
      (d) => { d.audit = []; },
      (d) => { d.generation += 1; },
    ]) {
      const fresh = readState(ctx);
      fresh.bindings[rec.binding_id].destination.session = replyTo;
      edit(fresh);
      writeState(ctx, fresh);
      throwsCode(() => openResponderStore({ dir: ctx.dir, session: SESSION, origin: ORIGIN, stateKey: key }, { now: () => ctx.clock.ms }),
        "RESPONDER_STATE_UNAUTHENTIC");
    }
  });

  test("F01 a rolled-back store cannot mint a second send: the daemon's audit decides", async (t) => {
    const ctx = setup(t);
    const { rec } = await issued(ctx);
    const before = fs.readFileSync(statePath(ctx));          // an AUTHENTIC pre-send snapshot
    const sent = await ctx.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body: "the real answer" });
    assert.equal(sent.outcome.result, "sent");
    assert.equal(ctx.state.sent.length, 1);
    ctx.store.close();

    // Same-user rollback between two passes: the MAC still verifies, the binding looks unspent.
    fs.writeFileSync(statePath(ctx), before, { mode: 0o600 });
    const rolled = ctx.open();
    assert.equal(rolled.store.binding(rec.binding_id).state, "issued", "the snapshot is authentic and adopted");
    const second = await rolled.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body: "a second answer" });
    assert.equal(second.ok, false, JSON.stringify(second));
    assert.equal(second.error.code, "AUDIT_UNACCOUNTED_REPLY");
    assert.equal(second.error.unaccounted, 1);
    assert.equal(ctx.state.sent.length, 1, "no second authenticated send after a rollback");
    assert.equal(rolled.store.audit().at(-1).reason, "audit_unaccounted_reply");
  });

  test("F01 a deleted spend history cannot mint a second send either", async (t) => {
    const ctx = setup(t);
    const { prompt, rec } = await issued(ctx);
    await ctx.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body: "the real answer" });
    assert.equal(ctx.state.sent.length, 1);
    ctx.store.close();

    // The whole history is deleted and the (genuine) request is registered again from scratch.
    fs.unlinkSync(statePath(ctx));
    const wiped = ctx.open();
    const fresh = await wiped.responder.recordInbound({ prompt, arrival_ms: ctx.clock.ms });
    assert.equal(fresh.ok, true, JSON.stringify(fresh));
    assert.notEqual(fresh.binding_id, rec.binding_id);
    const second = await wiped.responder.reply({ binding_id: fresh.binding_id, challenge: fresh.challenge, body: "a second answer" });
    assert.equal(second.ok, false, JSON.stringify(second));
    assert.equal(second.error.code, "AUDIT_UNACCOUNTED_REPLY");
    assert.equal(ctx.state.sent.length, 1, "the daemon's own record of the first reply blocks the second");
  });

  test("F02 a replaced requester instance: contrary evidence refuses, and a late replacement is recorded", async (t) => {
    const ctx = setup(t);
    const a = await issued(ctx, { text: "request A" });
    // The requester inbox was re-created: its newer row carries another verified epoch.
    ctx.state.rows.push(auditRow({
      ts: new Date(ctx.clock.ms).toISOString(), to: SESSION, claimed_from: a.replyTo,
      verified_sender_sid: a.replyTo, verified_sender_epoch: "inbox-epoch-2", verified_sender_generation: 8,
      payload_sha256: sha256("another request from the replacement"),
    }));
    const refused = await ctx.responder.reply({ binding_id: a.rec.binding_id, challenge: a.rec.challenge, body: "for the original" });
    assert.equal(refused.ok, false, JSON.stringify(refused));
    assert.equal(refused.error.code, "DESTINATION_INSTANCE_CHANGED");
    assert.equal(refused.error.outcome.reason, "destination_instance_changed");
    assert.equal(ctx.state.sent.length, 0, "nothing is injected into a replacement instance");

    // Without contrary evidence the send happens, and the daemon's observation of the delivery records
    // whether it reached the instance the request came from.
    const b = await issued(ctx, { text: "request B" });
    ctx.state.destinationEpoch = "inbox-epoch-3";
    const out = await ctx.responder.reply({ binding_id: b.rec.binding_id, challenge: b.rec.challenge, body: "for B" });
    assert.equal(out.ok, true, JSON.stringify(out));
    assert.equal(out.outcome.destination_instance_ok, false);
    assert.equal(out.outcome.reason, "destination_instance_changed");
  });

  test("F03 a stale responder instance never authenticates a reply", async (t) => {
    const ctx = setup(t);
    // Registration: the daemon's observation of the inbound inject must name THIS session and instance.
    const other = await issued(ctx, { text: "for another session", register: false });
    ctx.state.observations.set(other.row.inject_id, { session_id: "another-session", session_epoch: MY_EPOCH });
    assert.equal((await ctx.responder.recordInbound({ prompt: other.prompt, arrival_ms: ctx.clock.ms })).error.code, "RECIPIENT_MISMATCH");

    const stale = await issued(ctx, { text: "delivered to the previous instance", register: false });
    ctx.state.observations.set(stale.row.inject_id, { session_id: SESSION, session_epoch: "session-epoch-0" });
    assert.equal((await ctx.responder.recordInbound({ prompt: stale.prompt, arrival_ms: ctx.clock.ms })).error.code, "RECIPIENT_INSTANCE_CHANGED");

    const unproven = await issued(ctx, { text: "no observation at all", register: false });
    ctx.state.observations.delete(unproven.row.inject_id);
    assert.equal((await ctx.responder.recordInbound({ prompt: unproven.prompt, arrival_ms: ctx.clock.ms })).error.code, "OBSERVATION_UNAVAILABLE");
    assert.deepEqual(ctx.store.bindings(), [], "no binding without proven recipient instance");

    // Spend time: the instance is re-proved, so a session replaced after issuance cannot send.
    const live = await issued(ctx, { text: "live request" });
    ctx.state.observations.set(live.row.inject_id, { session_id: SESSION, session_epoch: "session-epoch-9" });
    const r = await ctx.responder.reply({ binding_id: live.rec.binding_id, challenge: live.rec.challenge, body: "after replacement" });
    assert.equal(r.ok, false, JSON.stringify(r));
    assert.equal(r.error.code, "RECIPIENT_INSTANCE_CHANGED");
    assert.equal(ctx.state.sent.length, 0);
  });

  test("F04 two concurrent registrations of one request mint exactly one capability", async (t) => {
    const ctx = setup(t);
    const nonce = hex(16);
    const replyTo = inboxId();
    const prompt = wire(nonce, replyTo, "concurrent", hex(16));
    const row = verifiedRow(prompt, replyTo, { ts: new Date(ctx.clock.ms).toISOString() });
    ctx.state.rows.push(row);
    ctx.state.observations.set(row.inject_id, { session_id: SESSION, session_epoch: MY_EPOCH });

    const claim = { prompt, arrival_ms: ctx.clock.ms };
    const [one, two] = await Promise.all([ctx.responder.recordInbound(claim), ctx.responder.recordInbound(claim)]);
    const issuedOnes = [one, two].filter((r) => r.ok === true && typeof r.challenge === "string");
    const refusedOnes = [one, two].filter((r) => r.ok === false);
    assert.equal(issuedOnes.length, 1, JSON.stringify([one, two]));
    assert.equal(refusedOnes.length, 1);
    assert.equal(refusedOnes[0].error.code, "BINDING_EXISTS");
    assert.equal(refusedOnes[0].error.binding_id, issuedOnes[0].binding_id, "the loser is told which binding stands");
    assert.equal(ctx.store.bindings().length, 1, "one trusted inbound request, one binding");

    const sent = await ctx.responder.reply({ binding_id: issuedOnes[0].binding_id, challenge: issuedOnes[0].challenge, body: "once" });
    assert.equal(sent.ok, true, JSON.stringify(sent));
    assert.equal(ctx.state.sent.length, 1);
  });

  test("F01 reconciliation fails closed when the audit cannot be read or cannot be shown complete", async (t) => {
    const ctx = setup(t);
    const { rec } = await issued(ctx);
    ctx.state.nextCursor = "cursor-2";
    const truncated = await ctx.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body: "x" });
    assert.equal(truncated.error.code, "RECONCILE_AUDIT_INCOMPLETE");
    ctx.state.nextCursor = null;
    ctx.state.auditFail = "DAEMON_TIMEOUT";
    assert.equal((await ctx.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body: "x" })).error.code, "DAEMON_TIMEOUT");
    ctx.state.auditFail = null;
    ctx.state.observeFail = "OBSERVATION_UNAVAILABLE";
    assert.equal((await ctx.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body: "x" })).error.code, "OBSERVATION_UNAVAILABLE");
    ctx.state.observeFail = null;
    assert.equal(ctx.state.sent.length, 0, "nothing is sent while the evidence is incomplete");
    // With the evidence available again the same capability still works.
    const ok = await ctx.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body: "x" });
    assert.equal(ok.ok, true, JSON.stringify(ok));
  });
});

describe("scoped responder — drop directory (the tool runtime's only surface)", { skip: NO_RESPONDER }, () => {
  function dropSetup(t) {
    const ctx = setup(t);
    const drop = openDropDir(path.join(ctx.sb.root, "drop"), { now: () => ctx.clock.ms });
    return { ctx, drop };
  }

  const writeClaim = (drop, name, value) => fs.writeFileSync(path.join(drop.dir, "inbound", name), JSON.stringify(value), { mode: 0o600 });
  const writeReply = (drop, name, value) => fs.writeFileSync(path.join(drop.dir, "replies", name), JSON.stringify(value), { mode: 0o600 });
  const result = (drop, name) => JSON.parse(fs.readFileSync(path.join(drop.dir, "results", name), "utf8"));

  test("D1 a claim file yields a capability file; a reply drop carrying only a body is sent once", async (t) => {
    const { ctx, drop } = dropSetup(t);
    const { nonce, replyTo, prompt } = await issued(ctx, { register: false });
    writeClaim(drop, "request-1.json", { v: 1, prompt, arrival_ms: ctx.clock.ms });

    const p1 = await runDropPass({ responder: ctx.responder, drop });
    assert.deepEqual([p1.inbound.processed, p1.inbound.issued, p1.inbound.refused, p1.inbound.retried], [1, 1, 0, 0]);
    assert.equal(fs.existsSync(path.join(drop.dir, "inbound", "request-1.json")), false, "the claim is consumed");
    const capNames = fs.readdirSync(path.join(drop.dir, "capabilities"));
    assert.equal(capNames.length, 1);
    const capFile = path.join(drop.dir, "capabilities", capNames[0]);
    const cap = JSON.parse(fs.readFileSync(capFile, "utf8"));
    assert.deepEqual([cap.v, cap.nonce, cap.destination_session], [1, nonce, replyTo]);
    assert.match(cap.challenge, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(fs.readFileSync(capFile, "utf8").includes(ctx.cred.bearer), false, "a capability carries no bearer");
    assert.equal(fs.lstatSync(capFile).mode & 0o777, 0o600);
    assert.equal(result(drop, "request-1.json").binding_id, cap.binding_id);

    // The filtered tool runtime writes its answer: the body and the capability, nothing else.
    const dropName = `${cap.binding_id}.json`;
    const body = "answered from a filtered tool runtime";
    writeReply(drop, dropName, { v: 1, binding_id: cap.binding_id, challenge: cap.challenge, body });
    const p2 = await runDropPass({ responder: ctx.responder, drop });
    assert.deepEqual([p2.replies.processed, p2.replies.sent, p2.replies.duplicate, p2.replies.refused], [1, 1, 0, 0]);
    assert.deepEqual([ctx.state.sent.length, ctx.state.sent[0].to, ctx.state.sent[0].prompt, ctx.state.sent[0].sessionToken],
      [1, replyTo, `REPLY ${nonce} ${body}`, ctx.cred.bearer]);
    assert.equal(fs.existsSync(path.join(drop.dir, "replies", dropName)), false, "the drop is consumed");
    assert.equal(fs.existsSync(capFile), false, "the spent capability is removed");
    const sentResult = result(drop, dropName);
    assert.deepEqual([sentResult.ok, sentResult.result, sentResult.outcome.result], [true, "sent", "sent"]);
    assert.equal(JSON.stringify(sentResult).includes(body), false, "a result carries no body");
    assert.equal(JSON.stringify(p2).includes(dropName), false, "the pass summary echoes no caller-chosen filename");

    // A replayed drop is answered from the record as a DUPLICATE, never counted as a new send.
    writeReply(drop, dropName, { v: 1, binding_id: cap.binding_id, challenge: cap.challenge, body });
    const p3 = await runDropPass({ responder: ctx.responder, drop });
    assert.deepEqual([p3.replies.sent, p3.replies.duplicate], [0, 1]);
    assert.equal(ctx.state.sent.length, 1, "one authenticated send for one request");
    assert.equal(result(drop, dropName).result, "duplicate");
  });

  test("D2 unusable files are answered and removed; a retryable one is kept for the next pass", async (t) => {
    const { ctx, drop } = dropSetup(t);
    const { prompt } = await issued(ctx, { text: "retryable", register: false });

    fs.writeFileSync(path.join(drop.dir, "inbound", "bad.json"), "{not json", { mode: 0o600 });
    writeReply(drop, "widened.json", {
      v: 1, binding_id: hex(16), challenge: "A".repeat(43), body: "x", destination: { session: "elsewhere" },
    });
    writeClaim(drop, "retry.json", { v: 1, prompt, arrival_ms: ctx.clock.ms });
    ctx.state.auditFail = "DAEMON_UNREACHABLE";

    const p1 = await runDropPass({ responder: ctx.responder, drop });
    assert.equal(fs.existsSync(path.join(drop.dir, "inbound", "bad.json")), false);
    assert.equal(result(drop, "bad.json").code, "DROP_INVALID");
    assert.equal(fs.existsSync(path.join(drop.dir, "replies", "widened.json")), false, "a widened drop is refused, not applied");
    assert.equal(result(drop, "widened.json").code, "DROP_INVALID");
    assert.equal(p1.inbound.retried, 1);
    assert.ok(fs.existsSync(path.join(drop.dir, "inbound", "retry.json")), "a retryable claim stays for the next pass");
    assert.equal(ctx.state.sent.length, 0);
    assert.equal(fs.readdirSync(path.join(drop.dir, "capabilities")).length, 0);

    ctx.state.auditFail = null;
    const p2 = await runDropPass({ responder: ctx.responder, drop });
    assert.equal(p2.inbound.issued, 1);
    assert.equal(fs.existsSync(path.join(drop.dir, "inbound", "retry.json")), false);
    assert.equal(fs.readdirSync(path.join(drop.dir, "capabilities")).length, 1);
  });

  test("D3/F08 junk entries are cleared instead of stalling every later pass", async (t) => {
    const { ctx, drop } = dropSetup(t);
    const { prompt } = await issued(ctx, { register: false });
    fs.writeFileSync(path.join(drop.dir, "inbound", "not-a-drop.txt"), "x", { mode: 0o600 });
    fs.symlinkSync(path.join(drop.dir, "results"), path.join(drop.dir, "inbound", "link.json"));
    fs.mkdirSync(path.join(drop.dir, "inbound", "dir.json"), { mode: 0o700 });
    fs.writeFileSync(path.join(drop.dir, "inbound", ".stale.json.0123456789abcdef.tmp"), "x", { mode: 0o600 });
    writeClaim(drop, "valid.json", { v: 1, prompt, arrival_ms: ctx.clock.ms });

    const p = await runDropPass({ responder: ctx.responder, drop });
    assert.equal(p.inbound.issued, 1, JSON.stringify(p));
    assert.equal(p.inbound.dropped, 2, "the bad name and the stale tmp are removed by the scan");
    for (const gone of ["not-a-drop.txt", ".stale.json.0123456789abcdef.tmp", "link.json", "dir.json", "valid.json"]) {
      assert.equal(fs.existsSync(path.join(drop.dir, "inbound", gone)), false, gone);
    }
    assert.equal(result(drop, "link.json").code, "DROP_UNREADABLE", "a symlink is never followed");
    assert.equal(result(drop, "dir.json").code, "DROP_UNREADABLE");
  });

  test("D4/F10 an unpublishable result keeps the input; the next pass answers it from the record", async (t) => {
    const { ctx, drop } = dropSetup(t);
    const { rec } = await issued(ctx);
    const name = `${rec.binding_id}.json`;
    writeReply(drop, name, { v: 1, binding_id: rec.binding_id, challenge: rec.challenge, body: "answer" });
    const results = path.join(drop.dir, "results");
    fs.chmodSync(results, 0o500);
    try {
      const p1 = await runDropPass({ responder: ctx.responder, drop });
      assert.equal(p1.replies.sent, 1, JSON.stringify(p1));
      assert.equal(p1.replies.retried, 1, "the result could not be published");
      assert.equal(ctx.state.sent.length, 1);
      assert.ok(fs.existsSync(path.join(drop.dir, "replies", name)), "the input stays until its result is published");
    } finally {
      fs.chmodSync(results, 0o700);
    }
    const p2 = await runDropPass({ responder: ctx.responder, drop });
    assert.equal(p2.replies.duplicate, 1);
    assert.equal(ctx.state.sent.length, 1, "no second send while the result is republished");
    assert.equal(result(drop, name).result, "duplicate");
    assert.equal(fs.existsSync(path.join(drop.dir, "replies", name)), false);
  });

  test("D5/F11 a wrong challenge keeps the live capability; F13 expired capabilities and old results are swept", async (t) => {
    const { ctx, drop } = dropSetup(t);
    const { rec } = await issued(ctx);
    const capName = `${rec.binding_id}.json`;
    // The pass issues the capability file for this binding (re-issue of the same request).
    writeClaim(drop, "claim.json", { v: 1, prompt: (await issued(ctx, { register: false })).prompt, arrival_ms: ctx.clock.ms });
    await runDropPass({ responder: ctx.responder, drop });
    fs.writeFileSync(path.join(drop.dir, "capabilities", capName),
      JSON.stringify({ v: 1, binding_id: rec.binding_id, challenge: rec.challenge, nonce: rec.nonce, destination_session: rec.destination.session, expires_at: rec.expires_at }), { mode: 0o600 });

    writeReply(drop, capName, { v: 1, binding_id: rec.binding_id, challenge: otherChallenge(rec.challenge), body: "wrong capability" });
    const p1 = await runDropPass({ responder: ctx.responder, drop });
    assert.equal(p1.replies.refused, 1);
    assert.equal(result(drop, capName).code, "CHALLENGE_MISMATCH");
    assert.ok(fs.existsSync(path.join(drop.dir, "capabilities", capName)), "a live capability survives one bad attempt (F11)");
    assert.equal(ctx.state.sent.length, 0);

    // A capability whose binding does not exist, and a result older than its retention, are swept.
    const orphan = `${hex(16)}.json`;
    fs.writeFileSync(path.join(drop.dir, "capabilities", orphan), JSON.stringify({ v: 1 }), { mode: 0o600 });
    const old = path.join(drop.dir, "results", capName);
    const past = (ctx.clock.ms - DROP_LIMITS.resultRetainMs - 60000) / 1000;
    fs.utimesSync(old, past, past);
    const p2 = await runDropPass({ responder: ctx.responder, drop });
    assert.equal(fs.existsSync(path.join(drop.dir, "capabilities", orphan)), false, "an orphan capability is swept");
    assert.equal(fs.existsSync(old), false, "an old result is swept");
    assert.ok(p2.swept.capabilities >= 1 && p2.swept.results >= 1, JSON.stringify(p2.swept));

    // Spending the binding removes its capability; the sweep then has nothing to keep.
    writeReply(drop, capName, { v: 1, binding_id: rec.binding_id, challenge: rec.challenge, body: "right capability" });
    const p3 = await runDropPass({ responder: ctx.responder, drop });
    assert.equal(p3.replies.sent, 1, JSON.stringify(p3));
    assert.equal(fs.existsSync(path.join(drop.dir, "capabilities", capName)), false);
  });

  test("D6 the drop directory must be private, and a missing one is refused when it may not be created", (t) => {
    const sb = makeSandbox("ts-responder-perm-");
    t.after(() => sb.remove());
    const loose = path.join(sb.root, "loose-drop");
    fs.mkdirSync(loose, { mode: 0o700 });
    fs.chmodSync(loose, 0o777);
    throwsCode(() => openDropDir(loose), "RESPONDER_DROP_PERMISSIONS_INVALID");
    assert.equal(openDropDir(path.join(sb.root, "fresh-drop")).permissions, "verified");
    throwsCode(() => openDropDir(path.join(sb.root, "missing"), { create: false }), "RESPONDER_DROP_NOT_FOUND");
    throwsCode(() => openDropDir("not/absolute"), "RESPONDER_DROP_PATH_INVALID");
  });
});
