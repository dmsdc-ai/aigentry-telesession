// Full-route isolated E2E (SPEC 2026-10-11 §9.1), no human step: origin send → leg-1 destination (fake
// telepty target) → leg-1 relays the envelope over its own ledger + relay runner → fake final daemon →
// own-bearer-attested final receipt → origin ledger origin_ack_received → origin agent polls request_status
// with a cursor → completed. Proven vs unproven provenance; duplicate / out-of-order receipts collapse.
// This is the Linux-side proof of the protocol with FAKE adapters; it does not claim the telepty APIs exist.

import { describe, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { normalizeConfig, createTeleptyTransport } from "../src/index.js";
import { openLedger } from "../src/relay/ledger.js";
import { createRouteResolver } from "../src/relay/route.js";
import { createRelayRunner } from "../src/relay/runner.js";
import { createProvenanceAdapter, applyReceipts, applyConsumption, NO_RECEIPTS } from "../src/relay/adapters.js";
import { makeSandbox } from "./helpers/fault-fs.js";
import { startFakeTelepty } from "./helpers/fake-telepty.js";
import { createFakeReceiptSeam, FAKE_PROOF_BASIS } from "./helpers/fake-receipts.js";

const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const NO_LOOPBACK = process.env.TELESESSION_TEST_NO_LOOPBACK === "1"
  ? "NOTRUN: loopback bind/connect not permitted here (TELESESSION_TEST_NO_LOOPBACK=1)" : false;
const FINAL = { host: "remote-peer", session: "remote-worker" };
const FINAL_EPOCH = "remote-epoch-1";

test("ProvenanceAdapter: authenticated only with a verified_sender_host AND an allowlisted sender_proof.basis", () => {
  const p = createProvenanceAdapter({ allowedBases: [FAKE_PROOF_BASIS] });
  assert.deepEqual(p.verify({ verified_sender_host: "remote-peer", sender_proof: { basis: FAKE_PROOF_BASIS } }), { authenticated: true, host: "remote-peer", basis: FAKE_PROOF_BASIS });
  assert.deepEqual(p.verify({ verified_sender_host: "remote-peer", sender_proof: { basis: "claimed" } }), { authenticated: false, host: null, basis: "claimed" });
  assert.deepEqual(p.verify({ sender_proof: { basis: FAKE_PROOF_BASIS } }), { authenticated: false, host: null, basis: FAKE_PROOF_BASIS });
  assert.deepEqual(p.verify({ claimed_from: "remote-peer", origin_host: "remote-peer" }), { authenticated: false, host: null, basis: null }, "markers never authenticate");
  assert.deepEqual(createProvenanceAdapter().verify({ verified_sender_host: "remote-peer", sender_proof: { basis: FAKE_PROOF_BASIS } }).authenticated, false, "default: nothing allowlisted");
  assert.deepEqual(p.verify(null), { authenticated: false, host: null, basis: null });
});

test("default ReceiptAdapter is today's behaviour (no receipts, consumption unknown)", async () => {
  assert.deepEqual(await NO_RECEIPTS.fetch("0".repeat(32)), []);
  assert.deepEqual(await NO_RECEIPTS.consumption("x"), { status: "unknown" });
});

test("consumption observation → agent_consumed for a direct record only (hop fact for a relayed one); never a completion", (t) => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "telesession-consume-"));
  const l = openLedger({ dir: path.join(base, "ledger") });
  t.after(() => { l.close(); fs.rmSync(base, { recursive: true, force: true }); });
  const mk = (nonce, extra) => l.createRequest({
    nonce, request_id: null, origin: { host: "local", session: "inbox" }, destination: { host: "local", session: "t1" },
    reply_to: { host: "local", session: "inbox" }, generation: "ep-1", payload_sha256: sha("p"), deadline_ms: 60000, ...extra,
  });
  mk("1".repeat(32));
  mk("2".repeat(32), { destination: FINAL, via: { host: "local", session: "t1" }, via_generation: "ep-1", generation: null });
  assert.deepEqual(applyConsumption({ ledger: l, nonce: "1".repeat(32), observation: { status: "observed", session_epoch: "other" } }), { applied: false, code: "GENERATION_MISMATCH" });
  assert.deepEqual(applyConsumption({ ledger: l, nonce: "1".repeat(32), observation: { status: "unknown", session_epoch: "ep-1" } }), { applied: false, code: "NOT_OBSERVED" });
  assert.deepEqual(applyConsumption({ ledger: l, nonce: "1".repeat(32), observation: { status: "observed", session_epoch: "ep-1" } }), { applied: true });
  const s = l.status({ nonce: "1".repeat(32) });
  assert.equal(s.stage, "agent_consumed");
  assert.equal(s.status, "pending", "consumption is not completion");
  assert.deepEqual(applyConsumption({ ledger: l, nonce: "2".repeat(32), observation: { status: "observed", session_epoch: "ep-1" } }), { applied: false, code: "HOP_FACT_ONLY" });
  assert.equal(l.status({ nonce: "2".repeat(32) }).stages.agent_consumed, "unknown");
});

describe("full route: origin → leg-1 → relay → fake final daemon → final receipt → origin ACK (isolated)", { skip: NO_LOOPBACK }, () => {
  async function route(t, mode) {
    const sb = makeSandbox("ts-e2e-");
    const fake = await startFakeTelepty();
    const seam = createFakeReceiptSeam({ mode, host: FINAL.host });
    const originLedger = openLedger({ dir: path.join(sb.root, "origin-ledger") });
    const leg1Ledger = openLedger({ dir: path.join(sb.root, "leg1-ledger") });
    const cfg = normalizeConfig({ teleptyUrl: fake.origin, token: fake.token, targets: ["target-1"], inboxPrefix: "tse", stateDir: sb.stateDir });
    const origin = createTeleptyTransport(cfg, sb.seam(), {
      ledger: originLedger, receipts: seam.adapter, provenance: createProvenanceAdapter({ allowedBases: [FAKE_PROOF_BASIS] }),
    });
    t.after(async () => { await origin.close(); originLedger.close(); leg1Ledger.close(); await fake.close(); sb.remove(); });

    // 1. The origin agent asks for work two hops away.
    const s = await origin.send({ target: "target-1", text: "build and ACK", request_id: "e2e-1", destination: FINAL });
    assert.equal(s.ok, true, JSON.stringify(s));
    // 2. Leg-1 destination (an orchestrator on this host) reads the wire header: nonce + correlation_id.
    const prompt = fake.sessions.get("target-1").delivered.at(-1).prompt;
    const m = /^\[telesession nonce=([0-9a-f]{32}) reply-to=(\S+) correlation=([0-9a-f]{32})\]\n([\s\S]*)$/.exec(prompt);
    assert.ok(m, prompt);
    assert.deepEqual([m[1], m[3]], [s.nonce, s.correlation_id]);
    // 3. Leg-1 relays over its own ledger + relay runner; the envelope carries the origin's correlation_id.
    const daemon = seam.finalDaemon({ sid: FINAL.session, epoch: FINAL_EPOCH });
    const leg2Nonce = "9".repeat(32);
    const envelope = {
      v: 1, correlation_id: s.correlation_id, origin_request_id: "e2e-1", payload_sha256: sha(prompt),
      origin: { host: "origin-host", sid: m[2] }, final: { host_label: FINAL.host, sid: FINAL.session, epoch: FINAL_EPOCH },
      reply_locator: "origin-host", hop: 1, deadline_at: new Date(Date.now() + 600000).toISOString(),
    };
    assert.equal(leg1Ledger.createRequest({
      nonce: leg2Nonce, correlation_id: s.correlation_id, request_id: null, origin: { host: "leg1-host", session: "target-1" }, destination: FINAL,
      reply_to: { host: "leg1-host", session: "target-1" }, generation: null, payload_sha256: sha(JSON.stringify(envelope)), deadline_ms: 600000,
    }).ok, true);
    const { key } = leg1Ledger.enqueue({ nonce: leg2Nonce, to: FINAL, kind: "relay", text: JSON.stringify(envelope) });
    const runner = createRelayRunner({ ledger: leg1Ledger, send: daemon.send, resolver: createRouteResolver([{ peer_id: FINAL.host, locators: [FINAL.host] }]) });
    const tick = await runner.tick();
    assert.deepEqual(tick.sent, [key], JSON.stringify(tick));
    assert.equal(daemon.inbound.length, 1);
    assert.equal(daemon.inbound[0].envelope.correlation_id, s.correlation_id);
    return { s, origin, daemon, envelope: daemon.inbound[0].envelope, seam };
  }

  test("proven provenance: final receipt → origin_ack_received → completed after the origin agent's checkpoint", async (t) => {
    const { s, origin, daemon, envelope } = await route(t, "proven");
    const before = await origin.requestStatus({ request_id: "e2e-1" });
    assert.deepEqual([before.status, before.stage], ["pending", "transport_accepted"]);
    // 4. The final session consumes and completes; its daemon attests with the session's own bearer.
    daemon.attest(envelope, "agent_consumed");
    daemon.attest(envelope, "processing_completed");
    const st = await origin.requestStatus({ request_id: "e2e-1" });
    assert.equal(st.stage, "origin_ack_received", JSON.stringify(st));
    assert.equal(st.status, "pending");
    assert.ok(st.status_reasons.includes("AWAITING_ORIGIN_AGENT_READ"));
    assert.notEqual(st.stages.agent_consumed, "unknown");
    assert.deepEqual(st.unproven, {});
    assert.equal(st.final_ack_seq, 1);
    assert.equal(st.replies[0].attestation, "destination");
    assert.match(st.replies[0].text, /^\[telesession receipt stage=processing_completed\]\n/);
    assert.deepEqual(JSON.parse(st.replies[0].text.split("\n")[1]).provenance, { host: FINAL.host, basis: FAKE_PROOF_BASIS });
    // 5. The origin agent polls with its cursor: the final receipt is recorded → completed.
    const done = await origin.requestStatus({ nonce: s.nonce, cursor: st.next_cursor });
    assert.deepEqual([done.status, done.delivered_to_origin_agent], ["completed", true]);
  });

  test("unproven provenance: the same receipts stay pending/unknown with REMOTE_PROVENANCE_UNAVAILABLE; nothing stored as a reply", async (t) => {
    const { origin, daemon, envelope } = await route(t, "unproven");
    daemon.attest(envelope, "agent_consumed");
    daemon.attest(envelope, "processing_completed");
    const st = await origin.requestStatus({ request_id: "e2e-1", cursor: 0 });
    assert.equal(st.status, "pending", JSON.stringify(st));
    assert.equal(st.stage, "transport_accepted");
    assert.deepEqual(st.unproven, { agent_consumed: "REMOTE_PROVENANCE_UNAVAILABLE", processing_completed: "REMOTE_PROVENANCE_UNAVAILABLE" });
    assert.ok(st.status_reasons.includes("REMOTE_PROVENANCE_UNAVAILABLE"));
    assert.equal(st.reply_count, 0);
    assert.equal(st.final_ack_seq, null);
  });

  test("duplicate, out-of-order and foreign-correlation receipts collapse; one ACK, no regression", async (t) => {
    const { s, origin, daemon, envelope } = await route(t, "proven");
    const done = daemon.attest(envelope, "processing_completed", { seqOverride: 2 });
    daemon.replay(done);
    daemon.attest(envelope, "agent_consumed", { seqOverride: 1 });
    daemon.attest(envelope, "processing_completed", { correlation_id: "f".repeat(32) });
    const st = await origin.requestStatus({ correlation_id: s.correlation_id });
    assert.equal(st.stage, "origin_ack_received", JSON.stringify(st));
    assert.notEqual(st.stages.agent_consumed, "unknown", "out-of-order evidence fills the timestamp");
    assert.deepEqual([st.reply_count, st.final_ack_seq], [1, 1]);
    const again = await origin.requestStatus({ correlation_id: s.correlation_id });
    assert.deepEqual([again.reply_count, again.final_ack_seq, again.stage], [1, 1, "origin_ack_received"], "a second pull changes nothing");
    assert.equal((await origin.requestStatus({ correlation_id: "f".repeat(32) })).status, "not_tracked");
  });

  test("direct record: the consumption observation of the origin's inject → agent_consumed via request_status (not completion)", async (t) => {
    const sb = makeSandbox("ts-e2e-direct-");
    const fake = await startFakeTelepty();
    const seam = createFakeReceiptSeam();
    const l = openLedger({ dir: path.join(sb.root, "ledger") });
    const cfg = normalizeConfig({ teleptyUrl: fake.origin, token: fake.token, targets: ["target-1"], inboxPrefix: "tsd", stateDir: sb.stateDir });
    const tr = createTeleptyTransport(cfg, sb.seam(), { ledger: l, receipts: seam.adapter });
    t.after(async () => { await tr.close(); l.close(); await fake.close(); sb.remove(); });
    const s = await tr.send({ target: "target-1", text: "direct job" });
    assert.equal(s.ok, true, JSON.stringify(s));
    assert.equal((await tr.requestStatus({ nonce: s.nonce })).stage, "transport_accepted");
    seam.observe(s.inject_id, "observed", fake.sessions.get("target-1").epoch);
    const st = await tr.requestStatus({ nonce: s.nonce });
    assert.deepEqual([st.stage, st.status, st.final_ack_seq], ["agent_consumed", "pending", null]);
  });

  test("applyReceipts refuses malformed, hop (non-final), non-own-bearer and foreign-correlation receipts without state change", async (t) => {
    const { s, seam } = await route(t, "proven");
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "telesession-receipts-"));
    const l = openLedger({ dir: path.join(base, "ledger") });
    t.after(() => { l.close(); fs.rmSync(base, { recursive: true, force: true }); });
    l.createRequest({
      nonce: s.nonce, correlation_id: s.correlation_id, request_id: null, origin: { host: "local", session: "inbox" }, destination: FINAL,
      via: { host: "local", session: "target-1" }, via_generation: "ep", reply_to: { host: "local", session: "inbox" }, generation: null,
      payload_sha256: sha("p"), deadline_ms: 60000,
    });
    const prov = createProvenanceAdapter({ allowedBases: [FAKE_PROOF_BASIS] });
    const hop = { correlation_id: s.correlation_id, inject_id: "i1", stage: "processing_completed", role: "hop", seq: 1, at: "x",
      attested_by: { host_label: FINAL.host, sid: FINAL.session, epoch: FINAL_EPOCH }, auth_basis: "own_bearer", verified_sender_host: FINAL.host, sender_proof: { basis: FAKE_PROOF_BASIS } };
    const out = applyReceipts({ ledger: l, nonce: s.nonce, receipts: [
      hop, { ...hop, role: "final", auth_basis: "daemon_token" }, { ...hop, role: "final", correlation_id: "f".repeat(32) }, { junk: true }, null,
    ], provenance: prov });
    assert.deepEqual(out, { applied: 0, unproven: 0, deduplicated: 0, refused: { HOP_FACT_ONLY: 1, NOT_OWN_BEARER: 1, CORRELATION_MISMATCH: 1, INVALID_RECEIPT: 2 } });
    assert.equal(l.status({ nonce: s.nonce }).stage, "unknown");
    assert.equal(seam.receipts.size, 0);
  });
});

// Review 3 B2: a proven processing_completed receipt the ledger refuses stores no reply entry; N-c: bounded fields.
describe("applyReceipts: a refused proven receipt stores nothing (review 3 B2, N-c)", () => {
  const CID = "a".repeat(32);
  const N = "1".repeat(32);
  const prov = createProvenanceAdapter({ allowedBases: [FAKE_PROOF_BASIS] });
  const rc = (o) => ({ correlation_id: CID, inject_id: "i1", stage: "processing_completed", role: "final", seq: 1, at: "2026-10-12T00:00:00.000Z",
    attested_by: { host_label: FINAL.host, sid: FINAL.session, epoch: "E1" }, auth_basis: "own_bearer", verified_sender_host: FINAL.host,
    sender_proof: { basis: FAKE_PROOF_BASIS }, ...o });
  function mk(t) {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "telesession-b2-"));
    const l = openLedger({ dir: path.join(base, "ledger") });
    t.after(() => { l.close(); fs.rmSync(base, { recursive: true, force: true }); });
    assert.equal(l.createRequest({
      nonce: N, correlation_id: CID, request_id: null, origin: { host: "local", session: "inbox" }, destination: FINAL,
      via: { host: "local", session: "t1" }, via_generation: "ep", reply_to: { host: "local", session: "inbox" }, generation: null,
      payload_sha256: sha("p"), deadline_ms: 60000,
    }).ok, true);
    return l;
  }

  test("GENERATION_MISMATCH: no reply, reason counted, stage unchanged", (t) => {
    const l = mk(t);
    assert.equal(applyReceipts({ ledger: l, nonce: N, receipts: [rc({ stage: "agent_consumed" })], provenance: prov }).applied, 1);
    const out = applyReceipts({ ledger: l, nonce: N, receipts: [rc({ seq: 2, attested_by: { sid: FINAL.session, epoch: "E2" } })], provenance: prov });
    assert.deepEqual(out, { applied: 0, unproven: 0, deduplicated: 0, refused: { GENERATION_MISMATCH: 1 } });
    const s = l.status({ nonce: N });
    assert.deepEqual([s.reply_count, s.stage, s.rejected], [0, "agent_consumed", { GENERATION_MISMATCH: 1 }]);
    assert.deepEqual(l.readReplies({ nonce: N, cursor: 0 }).replies, []);
  });

  test("SOURCE_MISMATCH: no reply, reason counted, stage unchanged", (t) => {
    const l = mk(t);
    const out = applyReceipts({ ledger: l, nonce: N, receipts: [rc({ verified_sender_host: "other-peer" })], provenance: prov });
    assert.deepEqual(out, { applied: 0, unproven: 0, deduplicated: 0, refused: { SOURCE_MISMATCH: 1 } });
    const s = l.status({ nonce: N });
    assert.deepEqual([s.reply_count, s.stage, s.rejected], [0, "unknown", { SOURCE_MISMATCH: 1 }]);
  });

  test("accepted receipt: one verified reply + origin_ack_received; a replay dedupes to the same entry", (t) => {
    const l = mk(t);
    assert.deepEqual(applyReceipts({ ledger: l, nonce: N, receipts: [rc(), rc()], provenance: prov }), { applied: 1, unproven: 0, deduplicated: 1, refused: {} });
    const s = l.status({ nonce: N });
    assert.deepEqual([s.reply_count, s.stage, s.final_ack_seq], [1, "origin_ack_received", 1]);
  });

  // Acceptance (b): a receipt resolves to the inject that carried the request and to the final host + session;
  // another inject_id, host or session is refused and stores nothing. NO_RECEIPTS stays the default (not wired).
  test("receipt binding: resolves to the original inject_id + host + session; another inject, host or session is refused", async (t) => {
    const l = mk(t);
    assert.deepEqual(await NO_RECEIPTS.fetch(CID), []);
    const wrong = [rc({ inject_id: "i-other" }), rc({ verified_sender_host: "other-peer" }), rc({ attested_by: { host_label: FINAL.host, sid: "other-sid", epoch: "E1" } })];
    assert.deepEqual(applyReceipts({ ledger: l, nonce: N, receipts: wrong, provenance: prov, injectIds: ["i1"] }),
      { applied: 0, unproven: 0, deduplicated: 0, refused: { INJECT_MISMATCH: 1, SOURCE_MISMATCH: 2 } });
    assert.deepEqual([l.status({ nonce: N }).reply_count, l.status({ nonce: N }).stage], [0, "unknown"]);
    assert.equal(applyReceipts({ ledger: l, nonce: N, receipts: [rc()], provenance: prov, injectIds: ["i1"] }).applied, 1);
    const [entry] = l.readReplies({ nonce: N, cursor: 0 }).replies;
    const body = JSON.parse(entry.text.split("\n").slice(1).join("\n"));
    assert.deepEqual([body.inject_id, body.provenance.host, body.attested_by.sid, entry.from], ["i1", FINAL.host, FINAL.session, FINAL]);
  });

  test("N-c: an over-long or malformed at / host_label / inject_id / epoch is INVALID_RECEIPT, nothing stored", (t) => {
    const l = mk(t);
    const bad = [
      rc({ at: "2".repeat(65) }), rc({ at: 7 }), rc({ inject_id: "i".repeat(129) }), rc({ inject_id: "i\n1" }),
      rc({ attested_by: { host_label: "h".repeat(254), sid: FINAL.session, epoch: "E1" } }),
      rc({ attested_by: { host_label: FINAL.host, sid: FINAL.session, epoch: "E\u00001" } }),
    ];
    assert.deepEqual(applyReceipts({ ledger: l, nonce: N, receipts: bad, provenance: prov }), { applied: 0, unproven: 0, deduplicated: 0, refused: { INVALID_RECEIPT: 6 } });
    const s = l.status({ nonce: N });
    assert.deepEqual([s.reply_count, s.stage], [0, "unknown"]);
  });
});
