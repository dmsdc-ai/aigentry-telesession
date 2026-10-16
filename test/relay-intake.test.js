// SPEC 2026-10-12 §7 U4 — R-side relay intake and re-send/recovery (rows L1, L2, L3, RS1, RS2; RC2 is in
// real-daemon-restart.test.js). Isolated: one loopback fake telepty daemon (fake-telepty.js) carries O, R and D
// on one host (a same-host relayed record, §2.5 N-c: F's key pinned at O under `local`), and the synthetic F
// (fake-receipts.js) adopts every inject the fake delivers to D, with its J and relay_context, standing in for
// the PROPOSED telepty#100 T-2…T-5 on that daemon. Not evidence that telepty implements them.
// Names (BLK-1): O calls F's host "mac", R calls it "macbook", F's self label is "host-m" (locators of the local
// peer in each node's own table; U2 stays fail-closed for any other peer).

import { describe, test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { createRouteResolver } from "../src/relay/route.js";
import { openLedger } from "../src/relay/ledger.js";
import { relayContextVariant, nextRelayContext, RELAY_HOP_MAX } from "../src/relay/relay-context.js";
import { normalizeConfig, createTeleptyTransport } from "../src/index.js";
import { makeSandbox } from "./helpers/fault-fs.js";
import { startFakeTelepty } from "./helpers/fake-telepty.js";
import { createFakeReceiptSeam, assertDistinctNames } from "./helpers/fake-receipts.js";
import { validateRelayContext } from "./helpers/relay-context.js";

const NO_LOOPBACK = process.env.TELESESSION_TEST_NO_LOOPBACK === "1"
  ? "NOTRUN: loopback bind/connect not permitted here (TELESESSION_TEST_NO_LOOPBACK=1)" : false;

const O_F = "mac";
const R_F = "macbook";
const F_LABEL = "host-m";
const CID = "c".repeat(32);
const WIRE_RE = /^\[telesession nonce=([0-9a-f]{32}) reply-to=(\S+) correlation=([0-9a-f]{32})\]\n/;

test("U4 nextRelayContext: verbatim copy of C and I; hop = inbound + 1; I = null or an inbound direct-final → no context; hop 5 is built and left to the send's RELAY_HOP_LIMIT", () => {
  const fin = nextRelayContext({ inbound: null, correlationId: CID, originInjectId: "I-1", finalSession: "w" });
  assert.deepEqual(fin, { v: 2, leg: "final", correlation_id: CID, origin_inject_id: "I-1", final_session: "w", hop: 1 });
  assert.deepEqual(validateRelayContext(fin, { resolvedSid: "w" }), { ok: true, variant: "final" });
  assert.deepEqual(nextRelayContext({ inbound: { v: 2, leg: "origin", correlation_id: CID }, correlationId: CID, originInjectId: "I-1", finalSession: "w" }), fin);
  const inbound = { v: 2, leg: "final", correlation_id: "d".repeat(32), origin_inject_id: "I-0", final_session: "r2", hop: 2 };
  assert.deepEqual(nextRelayContext({ inbound, correlationId: CID, originInjectId: "leg-inject", finalSession: "w" }),
    { v: 2, leg: "final", correlation_id: "d".repeat(32), origin_inject_id: "I-0", final_session: "w", hop: 3 }, "C and I copied verbatim from a final inbound");
  assert.equal(nextRelayContext({ inbound: null, correlationId: CID, originInjectId: null, finalSession: "w" }), null, "I = null → no context (R3-BLK-2)");
  assert.equal(nextRelayContext({ inbound: { v: 2, leg: "final", correlation_id: CID, origin_inject_id: null, final_session: "r", hop: 0 }, correlationId: CID, originInjectId: "x", finalSession: "w" }), null, "direct-final inbound → no context (N4-a)");
  assert.equal(nextRelayContext({ inbound: { v: 2, leg: "bogus", correlation_id: CID }, correlationId: CID, originInjectId: "x", finalSession: "w" }), null, "an invalid inbound context is never copied");
  const five = nextRelayContext({ inbound: { ...inbound, hop: RELAY_HOP_MAX }, correlationId: CID, originInjectId: "x", finalSession: "w" });
  assert.equal(five.hop, 5);
  assert.equal(relayContextVariant(five), null, "hop 5 is not a valid context");
  assert.equal(relayContextVariant(five, { maxHop: RELAY_HOP_MAX + 1 }), "final", "but the ledger may hold it until the send refuses it");
});

test("U4 relayContextVariant agrees with the shared test validator (role forward) on the §1.2.2 forms", () => {
  const base = { v: 2, leg: "final", correlation_id: CID, origin_inject_id: "I-1", final_session: "w", hop: 1 };
  const cases = [base, { ...base, hop: 0 }, { ...base, origin_inject_id: null }, { ...base, origin_inject_id: null, hop: 0 }, { ...base, hop: 5 },
    { v: 2, leg: "origin", correlation_id: CID }, { v: 2, leg: "origin", correlation_id: CID, final_session: "w" }, { ...base, leg: "x" },
    { ...base, correlation_id: "C" }, { ...base, v: 1 }, { ...base, extra: 1 }, { ...base, final_session: "" }, { ...base, hop: 1.5 }, [], "x"];
  for (const c of cases) {
    const v = validateRelayContext(c, { role: "forward" });
    assert.equal(relayContextVariant(c), v.ok ? v.variant : null, JSON.stringify(c));
  }
});

// O (origin), R (relayer) and D ("w") on one fake daemon; F = the seam adopting every inject delivered to "w".
async function relayWorld(t, { originLookup, originContext = false } = {}) {
  assertDistinctNames(O_F, R_F, F_LABEL);
  const F = createFakeReceiptSeam({ selfLabel: F_LABEL, mode: "unproven" });
  const fake = await startFakeTelepty({ targets: ["target-1", "w"] });
  F.finalDaemon({ sid: "w", epoch: fake.sessions.get("w").epoch });
  const toW = [];
  fake.hooks.beforeInject = ({ id, body }) => {
    // Models O's T-1 origin context on leg 1 (§1.2(a)); O's send does not pass it today (U4 spec gap).
    if (originContext && id === "target-1" && body && !body.relay_context) {
      const m = WIRE_RE.exec(body.prompt);
      if (m) body.relay_context = { v: 2, leg: "origin", correlation_id: m[3] };
    }
    return undefined;
  };
  fake.hooks.afterInject = ({ id, body, out }) => {
    if (id !== "w" || out.status !== 200) return undefined;
    toW.push(structuredClone(body));
    const a = F.inject({ J: out.body.inject_id, sid: "w", prompt: body.prompt, relay_context: body.relay_context });
    assert.equal(a.ok, true, JSON.stringify(a));
    return undefined;
  };
  const open = [];
  const node = (prefix, targets, resolver, ext = {}) => {
    const sb = makeSandbox(prefix);
    const l = openLedger({ dir: path.join(sb.root, "ledger") });
    const tr = createTeleptyTransport(normalizeConfig({ teleptyUrl: fake.origin, token: fake.token, targets, inboxPrefix: prefix.replace(/-$/, ""), stateDir: sb.stateDir }),
      sb.seam(), { ledger: l, resolver, ...ext });
    open.push({ tr, l, sb });
    return { tr, l };
  };
  t.after(async () => { for (const o of open) { await o.tr.close(); o.l.close(); o.sb.remove(); } await fake.close(); });
  const O = node("tso-", ["target-1"], createRouteResolver([F.publicPeerEntry("local", ["local", O_F])]), { receipts: F.adapter });
  const R = node("tsr-", ["w"], createRouteResolver([{ peer_id: "local", locators: ["local", R_F] }]), originLookup ? { originLookup } : {});
  const send = async (text = "build and ACK", request_id) => {
    const s = await O.tr.send({ target: "target-1", text, ...(request_id ? { request_id } : {}), destination: { host: O_F, session: "w" } });
    assert.equal(s.ok, true, JSON.stringify(s));
    return s;
  };
  const leg1Prompt = (s) => fake.sessions.get("target-1").delivered.find((x) => x.inject_id === s.inject_id).prompt;
  const intake = async (s, extra = {}) => R.tr.relayIntake({ prompt: leg1Prompt(s), session: "target-1", to: { host: R_F, session: "w" }, ...extra });
  const item = (key) => R.l.outbox().find((o) => o.key === key);
  const status = (s, cursor) => O.tr.requestStatus({ nonce: s.nonce, ...(cursor !== undefined ? { cursor } : {}) });
  const completed = async (s) => {
    const st = await status(s);
    return st.stage === "origin_ack_received" && (await status(s, st.next_cursor)).status === "completed";
  };
  // A verified inject from O's inbox (its own bearer) to R, outside O's send: a second genuine leg-1 row.
  const injectFromInbox = (prompt, relay_context) => fake.injectAs(fake.sessions.get(O.tr.inboxId).bearer, "target-1", prompt, O.tr.inboxId, { relay_context });
  return { F, fake, O, R, toW, send, leg1Prompt, intake, item, status, completed, injectFromInbox };
}

describe("U4 rows: R-side relay intake through the synthetic F (isolated)", { skip: NO_LOOPBACK }, () => {
  test("U4 baseline: R's intake finds I (interim §1.2(b)), forwards the final context R → F verbatim, F signs, O completes", async (t) => {
    const w = await relayWorld(t);
    const s = await w.send();
    const r = await w.intake(s);
    assert.equal(r.ok, true, JSON.stringify(r));
    const ctx = { v: 2, leg: "final", correlation_id: s.correlation_id, origin_inject_id: s.inject_id, final_session: "w", hop: 1 };
    assert.deepEqual([r.origin_inject_id, r.relay_context, r.origin_lookup], [s.inject_id, ctx, undefined]);
    assert.deepEqual(w.item(r.key).relay_context, ctx);
    const tick = await w.R.tr.relayTick();
    assert.deepEqual(tick.sent, [r.key], JSON.stringify(tick));
    assert.deepEqual(w.toW.map((b) => b.relay_context), [ctx], "the context reaches F's inject body verbatim");
    assert.deepEqual(validateRelayContext(w.toW[0].relay_context, { resolvedSid: "w" }), { ok: true, variant: "final" });
    const J = w.item(r.key).receipt.transport_id;
    w.F.attest(J, "agent_consumed");
    w.F.attest(J, "processing_completed");
    assert.equal(await w.completed(s), true);
  });

  for (const lookup of ["interim", "t1"]) {
    test(`L1 I lookup ambiguous at R (${lookup}): ORIGIN_INJECT_AMBIGUOUS on R's outbox item; forwarded WITHOUT relay_context; J delivered; NOT_RECEIPT_ELIGIBLE; O pending, never completed; the leg-1 addendum still arrives`, async (t) => {
      const w = await relayWorld(t, lookup === "t1" ? { originLookup: "t1", originContext: true } : {});
      const s = await w.send();
      // A second verified leg-1 inject from the same inbox in the same window (interim) / with the same C (T-1).
      const p = w.leg1Prompt(s);
      const second = w.injectFromInbox(p, lookup === "t1" ? { v: 2, leg: "origin", correlation_id: s.correlation_id } : undefined);
      assert.equal(second.status, 200);
      const r = await w.intake(s);
      assert.equal(r.ok, true, JSON.stringify(r));
      assert.deepEqual([r.origin_inject_id, r.relay_context, r.origin_lookup], [null, null, { code: "ORIGIN_INJECT_AMBIGUOUS", candidates: 2 }]);
      assert.deepEqual([w.item(r.key).relay_context, w.item(r.key).origin_lookup], [null, { code: "ORIGIN_INJECT_AMBIGUOUS", candidates: 2 }], "counted in R's outbox item");
      const tick = await w.R.tr.relayTick();
      assert.deepEqual(tick.sent, [r.key], JSON.stringify(tick));
      assert.equal(w.toW.length, 1, "J is delivered to D");
      assert.equal(Object.hasOwn(w.toW[0], "relay_context"), false, "no relay_context at all (never a null-I final context)");
      const J = w.item(r.key).receipt.transport_id;
      assert.deepEqual(w.F.attest(J, "processing_completed"), { ok: false, code: "NOT_RECEIPT_ELIGIBLE" }, "no v2 receipt can exist");
      // The leg-1 destination's own reply still reaches O as the relayed addendum.
      assert.equal(w.fake.replyFrom("target-1", s.reply_to, `REPLY ${s.nonce} relayed; final pending`).status, 200);
      assert.equal((await w.O.tr.readReply({ nonce: s.nonce, wait_ms: 5000 })).reply, "trusted");
      const st = await w.status(s);
      assert.deepEqual([st.status, st.stage, st.replies.map((x) => x.attestation), st.receipt_refusals],
        ["pending", "transport_accepted", ["relayed_by_leg1_destination"], undefined], JSON.stringify(st));
      assert.equal(await w.completed(s), false);
    });

    test(`L3 I lookup spoof attempt (${lookup}): a planted row with claimed_from = O's inbox and no verified sender is ignored; I = the genuine inject; completed`, async (t) => {
      const w = await relayWorld(t, lookup === "t1" ? { originLookup: "t1", originContext: true } : {});
      const s = await w.send();
      w.fake.addAuditRow({ to: "target-1", claimed_from: s.reply_to, payload_sha256: "0".repeat(64),
        ...(lookup === "t1" ? { relay_context: { v: 2, leg: "origin", correlation_id: s.correlation_id } } : {}) });
      const r = await w.intake(s);
      assert.equal(r.ok, true, JSON.stringify(r));
      assert.equal(r.origin_inject_id, s.inject_id);
      assert.equal(r.origin_lookup, undefined);
      await w.R.tr.relayTick();
      const J = w.item(r.key).receipt.transport_id;
      w.F.attest(J, "agent_consumed");
      w.F.attest(J, "processing_completed");
      assert.equal(await w.completed(s), true);
    });
  }

  test("U4 T-1 lookup when no leg-1 row carries an origin context (O sends none today, as on db2f532): no row passes → I = null, forwarded without context (fail-closed)", async (t) => {
    const w = await relayWorld(t, { originLookup: "t1" });
    const s = await w.send();
    const r = await w.intake(s);
    assert.deepEqual([r.ok, r.relay_context, r.origin_lookup], [true, null, { code: "ORIGIN_INJECT_AMBIGUOUS", candidates: 0 }], JSON.stringify(r));
  });

  test("U4 intake refusals: no wire header / bad args → INVALID_ARGUMENT; audit read failure → typed code, nothing enqueued; re-intake of the same prompt → deduplicated", async (t) => {
    const w = await relayWorld(t);
    const s = await w.send();
    assert.equal((await w.R.tr.relayIntake({ prompt: "no header", session: "target-1", to: { host: R_F, session: "w" } })).error.code, "INVALID_ARGUMENT");
    assert.equal((await w.intake(s, { to: { host: R_F } })).error.code, "INVALID_ARGUMENT");
    w.fake.flags.auditAvailable = false;
    const down = await w.intake(s);
    assert.equal(down.ok, false);
    assert.equal(w.R.l.outbox().length, 0, "nothing enqueued on a failed lookup");
    w.fake.flags.auditAvailable = true;
    const a = await w.intake(s);
    const b = await w.intake(s);
    assert.deepEqual([a.ok, b.ok, b.key, b.deduplicated, b.relay_context], [true, true, a.key, true, a.relay_context]);
  });

  test("L2 hop limit: an inbound hop-4 context re-relayed → RELAY_HOP_LIMIT before any inject; requeued to max_attempts, then failed; nothing reaches F", async (t) => {
    const w = await relayWorld(t, { originLookup: "t1" });
    const s = await w.send();
    // The genuine leg-1 row carries an inbound FINAL context at hop 4 (R is the fifth relayer in a chain).
    const inbound = { v: 2, leg: "final", correlation_id: s.correlation_id, origin_inject_id: "I-chain", final_session: "target-1", hop: 4 };
    w.fake.audit.find((x) => x.inject_id === s.inject_id).relay_context = inbound;
    const r = await w.intake(s);
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.deepEqual(r.relay_context, { ...inbound, final_session: "w", hop: 5 });
    for (let i = 0; i < 3; i++) await w.R.tr.relayTick();
    const it = w.item(r.key);
    assert.deepEqual([it.state, it.last_error, it.attempts, it.quarantine.reason], ["failed", "RELAY_HOP_LIMIT", 3, "max_attempts"]);
    assert.equal(w.fake.injectArrivals.filter((x) => x.to === "w").length, 0, "no inject to F");
  });

  test("RS1 re-send after a transport failure: R's first relay send sent:\"no\" (D not present) → requeued → sent; one J applied; O completes", async (t) => {
    const w = await relayWorld(t);
    const s = await w.send();
    const r = await w.intake(s);
    const d = w.fake.sessions.get("w");
    w.fake.sessions.delete("w");
    const t1 = await w.R.tr.relayTick();
    assert.deepEqual([t1.requeued, w.item(r.key).state, w.item(r.key).last_error, w.item(r.key).attempts], [[r.key], "queued", "TARGET_NOT_PRESENT", 1]);
    w.fake.sessions.set("w", d);
    const t2 = await w.R.tr.relayTick();
    assert.deepEqual(t2.sent, [r.key]);
    assert.deepEqual([w.toW.length, w.toW[0].relay_context], [1, r.relay_context], "one inject, the same context");
    const J = w.item(r.key).receipt.transport_id;
    w.F.attest(J, "agent_consumed");
    w.F.attest(J, "processing_completed");
    const st = await w.status(s);
    assert.deepEqual([st.stage, st.replies.length], ["origin_ack_received", 1], JSON.stringify(st));
    assert.equal(await w.completed(s), true);
  });

  test("RS2 re-send creating two J (operator re-enqueue with the same context): J1 completes first (first_ack_seq); J2 moves ack_seq forward, NEWER_FINAL_ACK_UNREAD; no duplicate seq", async (t) => {
    const w = await relayWorld(t);
    const s = await w.send();
    const r = await w.intake(s);
    await w.R.tr.relayTick();
    const first = w.item(r.key);
    const again = w.R.l.enqueue({ nonce: first.nonce, to: first.to, kind: "relay_resend", text: "build and ACK (re-sent)", relay_context: first.relay_context });
    assert.equal(again.ok, true, JSON.stringify(again));
    await w.R.tr.relayTick();
    const [J1, J2] = [first.receipt.transport_id, w.item(again.key).receipt.transport_id];
    assert.notEqual(J1, J2);
    assert.deepEqual(w.toW.map((b) => b.relay_context), [r.relay_context, r.relay_context]);
    w.F.attest(J1, "processing_completed");
    const st1 = await w.status(s);
    assert.deepEqual([st1.stage, st1.first_ack_seq, st1.ack_seq], ["origin_ack_received", 1, 1], JSON.stringify(st1));
    assert.equal((await w.status(s, st1.next_cursor)).status, "completed", "the origin agent read J1's completion");
    w.F.attest(J2, "processing_completed");
    const st2 = await w.status(s, st1.next_cursor);
    assert.deepEqual([st2.first_ack_seq, st2.ack_seq, st2.reply_count, st2.replies.map((x) => x.seq)], [1, 2, 2, [2]], JSON.stringify(st2));
    assert.ok(st2.status_reasons.includes("NEWER_FINAL_ACK_UNREAD"), JSON.stringify(st2.status_reasons));
    assert.equal((await w.status(s)).reply_count, 2, "a second pull adds nothing");
  });
});
