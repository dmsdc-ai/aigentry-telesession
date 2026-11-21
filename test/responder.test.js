// Scoped responder (issue #18): the trusted inbound request binding, the single-use request-bound
// capability, and the authenticated send performed by the host-side component that owns the session
// credential. Real durable store and real drop directory on the real filesystem; the two telepty calls
// are injected fakes, so these cases run without a daemon, a socket or a shell.
//
// Covered here: duplicate, expiry, restart/reconnect, session-generation change, forged binding id, a
// binding for another destination, oversized body, every inbound refusal (including the claimed-only
// inbound request, which must never yield a binding), the activation gate and the file-permission rule
// on POSIX and on win32.

import { describe, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { openResponderStore, ResponderStoreError, RESPONDER_STORE_LIMITS } from "../src/responder/store.js";
import {
  createResponder, ResponderError, RESPONDER_LIMITS, composeReply, parseRequestWire, selectInboundRow,
} from "../src/responder/responder.js";
import { openDropDir, runDropPass, parseInboundClaim, parseReplyDrop } from "../src/responder/drop.js";
import { hex, makeSandbox, sha256 } from "./helpers/fault-fs.js";

const ORIGIN = "http://127.0.0.1:47999";
const SESSION = "ts-responder";
const PREFIX = "tsrp";
const POSIX = process.platform !== "win32";

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
  to: SESSION, claimed_from: replyTo, verified_sender_sid: replyTo, verified_sender_epoch: "inbox-epoch",
  verified_sender_generation: 7, payload_sha256: sha256(prompt), ...over,
});

function makeDaemon() {
  const state = { rows: [], nextCursor: null, auditFail: null, injectResult: null, throwOnInject: false, queries: [], sent: [] };
  const daemon = {
    injects: async (q) => {
      state.queries.push(q);
      if (state.auditFail !== null) return { ok: false, code: state.auditFail };
      const lo = Date.parse(q.since);
      const hi = Date.parse(q.until);
      return {
        ok: true,
        injects: state.rows.filter((r) => Date.parse(r.ts) >= lo && Date.parse(r.ts) <= hi).slice(0, q.limit),
        next_cursor: state.nextCursor,
      };
    },
    inject: async (a) => {
      state.sent.push(a);
      if (state.throwOnInject) throw new Error("socket closed");
      return state.injectResult === null ? { ok: true, inject_id: `inj-sent-${state.sent.length}` } : state.injectResult;
    },
  };
  return { state, daemon };
}

function setup(t, { session = SESSION } = {}) {
  const sb = makeSandbox("ts-responder-");
  const clock = { ms: Date.now() };
  const dir = path.join(sb.root, "responder");
  const { state, daemon } = makeDaemon();
  const cred = { sid: session, bearer: `tgt-${hex(12)}`, epoch: "session-epoch-1", generation: 3 };
  const stores = [];
  const open = () => {
    const store = openResponderStore({ dir, session, origin: ORIGIN }, { now: () => clock.ms });
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

// One verified inbound request plus its issued capability.
async function issued(ctx, { text = "what is the status?" } = {}) {
  const nonce = hex(16);
  const replyTo = inboxId();
  const prompt = wire(nonce, replyTo, text, hex(16));
  ctx.state.rows.push(verifiedRow(prompt, replyTo));
  const rec = await ctx.responder.recordInbound({ prompt, arrival_ms: ctx.clock.ms });
  assert.equal(rec.ok, true, JSON.stringify(rec));
  return { nonce, replyTo, prompt, rec };
}

const otherChallenge = (c) => c.slice(0, 42) + (c.endsWith("A") ? "B" : "A");

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

  test("selectInboundRow needs exactly one verified row of a COMPLETE page", () => {
    const replyTo = inboxId();
    const prompt = wire(hex(16), replyTo);
    const base = { session: SESSION, replyTo, payloadSha256: sha256(prompt), lo: 0, hi: 9e15, complete: true };
    assert.equal(selectInboundRow([verifiedRow(prompt, replyTo)], base).ok, true);
    assert.deepEqual(selectInboundRow([verifiedRow(prompt, replyTo)], { ...base, complete: false }),
      { ok: false, code: "INBOUND_AUDIT_INCOMPLETE", candidates: null });
    assert.deepEqual(selectInboundRow([verifiedRow(prompt, replyTo), verifiedRow(prompt, replyTo)], base),
      { ok: false, code: "INBOUND_AMBIGUOUS", candidates: 2 });
    assert.deepEqual(selectInboundRow([], base), { ok: false, code: "INBOUND_UNVERIFIED", candidates: 0 });
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
});

describe("scoped responder — bindings and the authenticated send", () => {
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
    assert.equal(ctx.state.queries.length, 1, "exactly one audit read");

    const out = await ctx.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body: "status: green" });
    assert.equal(out.ok, true, JSON.stringify(out));
    assert.equal(out.sent, true);
    assert.equal(out.outcome.result, "sent");
    assert.equal(out.outcome.inject_id, "inj-sent-1");
    assert.equal(out.durability, "durable");
    assert.deepEqual(ctx.state.sent, [{
      to: replyTo, prompt: `REPLY ${nonce} status: green`, from: SESSION, sessionToken: ctx.cred.bearer,
    }]);

    // Never persisted: the bearer, the challenge, the request text, the reply body.
    const raw = fs.readFileSync(path.join(ctx.dir, "responder.json"), "utf8");
    for (const secret of [ctx.cred.bearer, rec.challenge, "what is the status?", "status: green"]) {
      assert.equal(raw.includes(secret), false, secret);
    }
    const stored = JSON.parse(raw);
    assert.equal(stored.bindings[rec.binding_id].state, "accepted");
    assert.equal(stored.bindings[rec.binding_id].challenge_sha256, sha256(rec.challenge));
    assert.deepEqual(stored.audit.map((e) => e.event), ["issued", "accepted"]);
    if (POSIX) assert.equal(fs.lstatSync(path.join(ctx.dir, "responder.json")).mode & 0o777, 0o600);
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

  test("S3 expiry: an expired binding is refused; a binding whose result is already recorded keeps it", async (t) => {
    const ctx = setup(t);
    const a = await issued(ctx);
    ctx.clock.ms += RESPONDER_LIMITS.ttlMs + 1;
    const out = await ctx.responder.reply({ binding_id: a.rec.binding_id, challenge: a.rec.challenge, body: "too late" });
    assert.equal(out.ok, false, JSON.stringify(out));
    assert.equal(out.error.code, "BINDING_EXPIRED");
    assert.equal(out.error.outcome.result, "refused");
    assert.equal(out.error.outcome.reason, "expired");
    assert.equal(ctx.state.sent.length, 0, "an expired binding never sends");

    // An earlier result is preserved past expiry: the duplicate still answers `sent`.
    const b = await issued(ctx, { text: "second request" });
    const sent = await ctx.responder.reply({ binding_id: b.rec.binding_id, challenge: b.rec.challenge, body: "in time" });
    assert.equal(sent.outcome.result, "sent");
    ctx.clock.ms += RESPONDER_LIMITS.ttlMs + 1;
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

    // A process killed between the intent and the outcome leaves `sending` on disk.
    const file = path.join(ctx.dir, "responder.json");
    const disk = JSON.parse(fs.readFileSync(file, "utf8"));
    disk.bindings[rec.binding_id].state = "sending";
    disk.bindings[rec.binding_id].outcome = null;
    fs.writeFileSync(file, JSON.stringify(disk), { mode: 0o600 });

    const third = ctx.open();
    const recovered = third.store.binding(rec.binding_id);
    assert.equal(recovered.state, "accepted");
    assert.equal(recovered.outcome.result, "uncertain");
    assert.equal(recovered.outcome.reason, "PROCESS_RESTART");
    assert.equal(third.store.audit().at(-1).event, "recovered");
    const retry = await third.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body: "answered before the restart" });
    assert.equal(retry.duplicate, true);
    assert.equal(retry.outcome.result, "uncertain");
    assert.equal(ctx.state.sent.length, 1, "an interrupted send is never repeated");
    third.store.close();
  });

  test("S5 a lost response is recorded uncertain and the binding stays spent", async (t) => {
    const ctx = setup(t);
    const { rec } = await issued(ctx);
    ctx.state.throwOnInject = true;
    const out = await ctx.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body: "did it arrive?" });
    assert.equal(out.ok, false);
    assert.equal(out.error.code, "REPLY_UNCERTAIN");
    assert.equal(out.error.outcome.result, "uncertain");
    assert.equal(ctx.state.sent.length, 1);
    ctx.state.throwOnInject = false;
    const again = await ctx.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body: "did it arrive?" });
    assert.equal(again.duplicate, true);
    assert.equal(again.outcome.result, "uncertain");
    assert.equal(ctx.state.sent.length, 1, "an uncertain outcome is never retried automatically");
  });

  test("S6 session-generation change: a binding recorded under the previous credential instance is refused", async (t) => {
    const ctx = setup(t);
    const rotated = await issued(ctx);
    ctx.cred.bearer = `tgt-${hex(12)}`;                       // the session credential was rotated
    const out = await ctx.responder.reply({ binding_id: rotated.rec.binding_id, challenge: rotated.rec.challenge, body: "after rotation" });
    assert.equal(out.ok, false, JSON.stringify(out));
    assert.equal(out.error.code, "SESSION_GENERATION_CHANGED");
    assert.equal(out.error.outcome.reason, "session_generation_changed");
    assert.equal(ctx.state.sent.length, 0);

    const byGeneration = await issued(ctx, { text: "generation request" });
    ctx.cred.generation += 1;
    const g = await ctx.responder.reply({ binding_id: byGeneration.rec.binding_id, challenge: byGeneration.rec.challenge, body: "newer generation" });
    assert.equal(g.error.code, "SESSION_GENERATION_CHANGED");

    const byEpoch = await issued(ctx, { text: "epoch request" });
    ctx.cred.epoch = "session-epoch-2";
    const e = await ctx.responder.reply({ binding_id: byEpoch.rec.binding_id, challenge: byEpoch.rec.challenge, body: "newer epoch" });
    assert.equal(e.error.code, "SESSION_GENERATION_CHANGED");

    const byPrincipal = await issued(ctx, { text: "principal request" });
    ctx.cred.sid = "another-session";
    const p = await ctx.responder.reply({ binding_id: byPrincipal.rec.binding_id, challenge: byPrincipal.rec.challenge, body: "another principal" });
    assert.equal(p.error.code, "PRINCIPAL_MISMATCH");
    assert.equal(ctx.state.sent.length, 0, "no send under a changed principal or generation");
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

  test("S8 oversized, empty and NUL bodies are refused before any send", async (t) => {
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
    // The binding is untouched by refused drops and still works.
    const ok = await ctx.responder.reply({ binding_id: rec.binding_id, challenge: rec.challenge, body: "x".repeat(RESPONDER_LIMITS.bodyChars) });
    assert.equal(ok.ok, true, JSON.stringify(ok));
    assert.ok(ctx.state.sent[0].prompt.length <= 8000);
  });

  test("S9 an inbound request without exactly one VERIFIED row never yields a binding", async (t) => {
    const ctx = setup(t);
    const cases = [
      ["the daemon never saw this request (forged claim)", () => []],
      ["claimed only: the inbound inject carried no session credential", (p, r) => [verifiedRow(p, r, { verified_sender_sid: null, verified_sender_epoch: null, verified_sender_generation: null })]],
      ["another session's credential was verified", (p, r) => [verifiedRow(p, r, { verified_sender_sid: "someone-else" })]],
      ["the claimed sender is not the verified one (spoof)", (p, r) => [verifiedRow(p, r, { spoof_suspected: true })]],
      ["not stamped local by this daemon", (p, r) => [verifiedRow(p, r, { origin: "peer" })]],
      ["another payload", (p, r) => [verifiedRow(p, r, { payload_sha256: sha256("other prompt") })]],
      ["delivered to another session", (p, r) => [verifiedRow(p, r, { to: "other-session" })]],
      ["delivered through an alias", (p, r) => [verifiedRow(p, r, { to_alias: "alias" })]],
      ["not an accepted delivery", (p, r) => [verifiedRow(p, r, { delivery_result: "failed:dead_letter" })]],
      ["outside the arrival window", (p, r) => [verifiedRow(p, r, { ts: new Date(Date.now() - 3600000).toISOString() })]],
    ];
    for (const [name, rows] of cases) {
      const nonce = hex(16);
      const replyTo = inboxId();
      const prompt = wire(nonce, replyTo, name);
      ctx.state.rows = rows(prompt, replyTo);
      const r = await ctx.responder.recordInbound({ prompt, arrival_ms: ctx.clock.ms });
      assert.equal(r.ok, false, name);
      assert.equal(r.error.code, "INBOUND_UNVERIFIED", name);
      assert.deepEqual(ctx.store.bindings(), [], name);
      assert.equal(ctx.store.audit().at(-1).reason, "inbound_unverified", name);
    }
    // Two indistinguishable rows cannot name one request.
    const nonce = hex(16);
    const replyTo = inboxId();
    const prompt = wire(nonce, replyTo, "twice");
    ctx.state.rows = [verifiedRow(prompt, replyTo), verifiedRow(prompt, replyTo)];
    assert.equal((await ctx.responder.recordInbound({ prompt, arrival_ms: ctx.clock.ms })).error.code, "INBOUND_AMBIGUOUS");
    // A truncated audit page proves nothing.
    ctx.state.rows = [verifiedRow(prompt, replyTo)];
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

  test("S11 activation gate and store guards", (t) => {
    const ctx = setup(t);
    const args = { store: ctx.store, daemon: ctx.daemon, credential: () => ({ ...ctx.cred }) };
    for (const activated of [undefined, false, "yes", 1]) {
      throwsCode(() => createResponder({ ...args, activated }), "RESPONDER_NOT_ACTIVATED");
    }
    assert.ok(throwsCode(() => createResponder({ ...args }), "RESPONDER_NOT_ACTIVATED") instanceof ResponderError);
    throwsCode(() => createResponder({ activated: true, daemon: ctx.daemon, credential: args.credential }), "RESPONDER_STORE_REQUIRED");
    throwsCode(() => createResponder({ activated: true, store: ctx.store, daemon: ctx.daemon }), "RESPONDER_CREDENTIAL_REQUIRED");
    throwsCode(() => createResponder({ activated: true, store: ctx.store, credential: args.credential }), "RESPONDER_DAEMON_REQUIRED");

    // A directory already held by a live pump is refused and never reclaimed.
    const locked = throwsCode(() => openResponderStore({ dir: ctx.dir, session: SESSION, origin: ORIGIN }), "RESPONDER_LOCKED");
    assert.ok(locked instanceof ResponderStoreError);
    assert.ok(fs.existsSync(path.join(ctx.dir, "lock")), "the held lock is untouched");
    assert.equal(ctx.store.lockState(), "held");

    // State recorded for another session or another daemon is never reused.
    ctx.store.close();
    throwsCode(() => openResponderStore({ dir: ctx.dir, session: "another-session", origin: ORIGIN }), "RESPONDER_BINDING_MISMATCH");
    throwsCode(() => openResponderStore({ dir: ctx.dir, session: SESSION, origin: "http://127.0.0.1:47998" }), "RESPONDER_BINDING_MISMATCH");
    throwsCode(() => openResponderStore({ dir: "relative/dir", session: SESSION, origin: ORIGIN }), "RESPONDER_PATH_INVALID");
    // A refused open releases the lock it took, so the operator's next pass is not blocked.
    assert.equal(fs.existsSync(path.join(ctx.dir, "lock")), false);
  });
});

describe("scoped responder — drop directory (the tool runtime's only surface)", () => {
  test("D1 a claim file yields a capability file; a reply drop carrying only a body is sent once", async (t) => {
    const ctx = setup(t);
    const drop = openDropDir(path.join(ctx.sb.root, "drop"));
    const nonce = hex(16);
    const replyTo = inboxId();
    const prompt = wire(nonce, replyTo, "what is the status?", hex(16));
    ctx.state.rows.push(verifiedRow(prompt, replyTo));
    fs.writeFileSync(path.join(drop.dir, "inbound", "request-1.json"), JSON.stringify({ v: 1, prompt, arrival_ms: ctx.clock.ms }), { mode: 0o600 });

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
    if (POSIX) assert.equal(fs.lstatSync(capFile).mode & 0o777, 0o600);
    const issuedResult = JSON.parse(fs.readFileSync(path.join(drop.dir, "results", "request-1.json"), "utf8"));
    assert.equal(issuedResult.ok, true);
    assert.equal(issuedResult.binding_id, cap.binding_id);

    // The filtered tool runtime writes its answer: the body and the capability, nothing else.
    const dropName = `${cap.binding_id}.json`;
    const body = "answered from a filtered tool runtime";
    const writeDrop = () => fs.writeFileSync(path.join(drop.dir, "replies", dropName),
      JSON.stringify({ v: 1, binding_id: cap.binding_id, challenge: cap.challenge, body }), { mode: 0o600 });
    writeDrop();
    const p2 = await runDropPass({ responder: ctx.responder, drop });
    assert.deepEqual([p2.replies.processed, p2.replies.sent, p2.replies.refused], [1, 1, 0]);
    assert.deepEqual([ctx.state.sent.length, ctx.state.sent[0].to, ctx.state.sent[0].prompt, ctx.state.sent[0].sessionToken],
      [1, replyTo, `REPLY ${nonce} ${body}`, ctx.cred.bearer]);
    assert.equal(fs.existsSync(path.join(drop.dir, "replies", dropName)), false, "the drop is consumed");
    assert.equal(fs.existsSync(capFile), false, "the spent capability is removed");
    const sentResult = JSON.parse(fs.readFileSync(path.join(drop.dir, "results", dropName), "utf8"));
    assert.equal(sentResult.ok, true);
    assert.equal(sentResult.outcome.result, "sent");

    // A replayed drop is answered from the record; nothing is sent twice.
    writeDrop();
    const p3 = await runDropPass({ responder: ctx.responder, drop });
    assert.equal(p3.replies.sent, 1);
    assert.equal(ctx.state.sent.length, 1, "one authenticated send for one request");
    assert.equal(JSON.parse(fs.readFileSync(path.join(drop.dir, "results", dropName), "utf8")).duplicate, true);
  });

  test("D2 unusable files are answered and removed; a retryable one is kept for the next pass", async (t) => {
    const ctx = setup(t);
    const drop = openDropDir(path.join(ctx.sb.root, "drop"));
    const nonce = hex(16);
    const replyTo = inboxId();
    const prompt = wire(nonce, replyTo, "retryable");
    ctx.state.rows.push(verifiedRow(prompt, replyTo));

    fs.writeFileSync(path.join(drop.dir, "inbound", "bad.json"), "{not json", { mode: 0o600 });
    fs.writeFileSync(path.join(drop.dir, "replies", "widened.json"), JSON.stringify({
      v: 1, binding_id: hex(16), challenge: "A".repeat(43), body: "x", destination: { session: "elsewhere" },
    }), { mode: 0o600 });
    fs.writeFileSync(path.join(drop.dir, "inbound", "retry.json"), JSON.stringify({ v: 1, prompt, arrival_ms: ctx.clock.ms }), { mode: 0o600 });
    ctx.state.auditFail = "DAEMON_UNREACHABLE";

    const p1 = await runDropPass({ responder: ctx.responder, drop });
    assert.equal(fs.existsSync(path.join(drop.dir, "inbound", "bad.json")), false);
    assert.equal(JSON.parse(fs.readFileSync(path.join(drop.dir, "results", "bad.json"), "utf8")).code, "DROP_INVALID");
    assert.equal(fs.existsSync(path.join(drop.dir, "replies", "widened.json")), false, "a widened drop is refused, not applied");
    assert.equal(JSON.parse(fs.readFileSync(path.join(drop.dir, "results", "widened.json"), "utf8")).code, "DROP_INVALID");
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

  test("D3 file permissions: POSIX ownership and mode are verified; win32 is defined as unverified", (t) => {
    const sb = makeSandbox("ts-responder-perm-");
    t.after(() => sb.remove());
    const loose = path.join(sb.root, "loose-drop");
    fs.mkdirSync(loose, { mode: 0o700 });
    fs.chmodSync(loose, 0o777);
    throwsCode(() => openDropDir(loose, { platform: "linux" }), "RESPONDER_DROP_PERMISSIONS_INVALID");
    assert.equal(openDropDir(loose, { platform: "win32" }).permissions, "unverified");
    assert.equal(openDropDir(path.join(sb.root, "fresh-drop")).permissions, POSIX ? "verified" : "unverified");
    throwsCode(() => openDropDir(path.join(sb.root, "missing"), { create: false }), "RESPONDER_DROP_NOT_FOUND");
    throwsCode(() => openDropDir("not/absolute"), "RESPONDER_DROP_PATH_INVALID");

    const store = openResponderStore({ dir: path.join(sb.root, "state-win32"), session: SESSION, origin: ORIGIN }, { platform: "win32" });
    t.after(() => store.close());
    assert.equal(store.info().permissions, "unverified");
    assert.deepEqual(store.bindings(), []);
  });
});
