// Transport + correlation ledger (SPEC 2026-10-11 §8, review corrections 1–3), over the loopback fake
// telepty: addenda after an initial (terminal) reply, read_reply cursor, request_status, a relayed
// final destination (REMOTE_PROVENANCE_UNAVAILABLE), and a verified reply after the 15-min nonce TTL.

import { describe, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { normalizeConfig, createTeleptyTransport } from "../src/index.js";
import { openLedger } from "../src/relay/ledger.js";
import { waitFor } from "./helpers.js";
import { makeSandbox, readJson, writeStateDir } from "./helpers/fault-fs.js";
import { startFakeTelepty } from "./helpers/fake-telepty.js";

const PREFIX = "tsl";
const NO_LOOPBACK = process.env.TELESESSION_TEST_NO_LOOPBACK === "1"
  ? "NOTRUN: loopback bind/connect not permitted here (TELESESSION_TEST_NO_LOOPBACK=1)" : false;

async function setup(t) {
  const sb = makeSandbox("ts-ledger-");
  const fake = await startFakeTelepty();
  const ledger = openLedger({ dir: path.join(sb.root, "ledger") });
  const transports = [];
  t.after(async () => {
    for (const tr of transports) { try { await tr.close(); } catch { /* closed */ } }
    ledger.close();
    await fake.close();
    sb.remove();
  });
  const make = () => {
    const cfg = normalizeConfig({ teleptyUrl: fake.origin, token: fake.token, targets: ["target-1"], inboxPrefix: PREFIX, stateDir: sb.stateDir });
    const tr = createTeleptyTransport(cfg, sb.seam(), { ledger });
    transports.push(tr);
    return tr;
  };
  return { sb, fake, ledger, make };
}

const REMOTE = { host: "remote-peer", session: "remote-orchestrator" };

describe("transport with correlation ledger (loopback fake telepty)", { skip: NO_LOOPBACK }, () => {
  test("T1 late ACK after a terminal initial reply → addendum seq 2 via read_reply cursor; existing fields unchanged", async (t) => {
    const { fake, make } = await setup(t);
    const tr = make();
    const s = await tr.send({ target: "target-1", text: "please ACK", request_id: "job-1" });
    assert.equal(s.ok, true, JSON.stringify(s));
    fake.replyFrom("target-1", s.reply_to, `REPLY ${s.nonce} no ACK within the window`);
    const r1 = await tr.readReply({ nonce: s.nonce, wait_ms: 8000 });
    assert.equal(r1.reply, "trusted", JSON.stringify(r1));
    assert.equal(r1.text, `REPLY ${s.nonce} no ACK within the window`);
    assert.deepEqual(r1.replies.map((x) => x.seq), [1]);
    assert.equal(r1.next_cursor, 1);

    fake.replyFrom("target-1", s.reply_to, `REPLY ${s.nonce} ACK: done`);
    const r2 = await tr.readReply({ nonce: s.nonce, wait_ms: 8000, cursor: 1 });
    assert.equal(r2.reply, "trusted");
    assert.equal(r2.text, `REPLY ${s.nonce} no ACK within the window`, "first reply fields unchanged");
    assert.deepEqual(r2.replies.map((x) => [x.seq, x.text, x.attestation]), [[2, `REPLY ${s.nonce} ACK: done`, "destination"]]);
    assert.equal(r2.next_cursor, 2);
    assert.ok(!(r2.quarantined && r2.quarantined.duplicate), "addendum is not quarantined as duplicate");

    const st = await tr.requestStatus({ nonce: s.nonce, cursor: 2 });
    assert.equal(st.ok, true, JSON.stringify(st));
    assert.equal(st.stage, "origin_ack_received");
    assert.equal(st.delivered_to_origin_agent, true);
    assert.equal(st.status, "completed");
    assert.equal(st.reply_count, 2);
  });

  test("T12 relayed final destination: target replies are relayed_by_leg1_destination; remote stage unproven", async (t) => {
    const { fake, make } = await setup(t);
    const tr = make();
    const s = await tr.send({ target: "target-1", text: "relay to remote", destination: REMOTE });
    assert.equal(s.ok, true, JSON.stringify(s));
    fake.replyFrom("target-1", s.reply_to, `REPLY ${s.nonce} remote ACK received`);
    const r = await tr.readReply({ nonce: s.nonce, wait_ms: 8000 });
    assert.equal(r.reply, "trusted", JSON.stringify(r));
    assert.equal(r.replies[0].attestation, "relayed_by_leg1_destination");
    const st = await tr.requestStatus({ nonce: s.nonce, cursor: 1 });
    assert.equal(st.status, "pending");
    assert.notEqual(st.stage, "origin_ack_received");
    assert.deepEqual(st.unproven, { processing_completed: "REMOTE_PROVENANCE_UNAVAILABLE" });
    assert.ok(st.status_reasons.includes("REMOTE_PROVENANCE_UNAVAILABLE"));
    assert.equal((await tr.send({ target: "target-1", text: "x", destination: { host: "bad host", session: "s" } })).error.code, "INVALID_ARGUMENT");
  });

  test("T11 verified reply after the 15-min transport TTL is stored as late_after_ttl addendum and counted", async (t) => {
    const { sb, fake, make } = await setup(t);
    const a = make();
    const s = await a.send({ target: "target-1", text: "slow job", request_id: "slow-1" });
    assert.equal(s.ok, true, JSON.stringify(s));
    assert.equal((await a.close()).outcome, "deleted");
    // Age the transport record past its TTL (the ledger record keeps its own retention).
    const state = readJson(path.join(sb.stateDir, "state.json"));
    const q = state.requests["r:slow-1"];
    const shift = 16 * 60 * 1000;
    for (const k of ["created_at", "sent_at", "expires_at", "retain_until"]) q[k] -= shift;
    fs.unlinkSync(path.join(sb.stateDir, "state.json"));
    writeStateDir(sb.stateDir, state);

    const b = make();
    const other = await b.send({ target: "target-1", text: "fresh job", request_id: "fresh-1" });
    assert.equal(other.ok, true, JSON.stringify(other));
    assert.equal((await b.readReply({ nonce: s.nonce })).error.code, "NONCE_EXPIRED", "transport TTL semantics unchanged (OQ-1)");

    const late = `REPLY ${s.nonce} ACK after the TTL`;
    fake.replyFrom("target-1", other.reply_to, late);
    const st = await waitFor(async () => {
      const x = await b.requestStatus({ nonce: s.nonce });
      return x.ok && x.late_after_ttl_count === 1 ? x : null;
    }, { timeoutMs: 8000, description: "late reply verified" });
    assert.equal(st.reply_count, 1);
    assert.deepEqual(st.replies.map((x) => [x.seq, x.text, x.late_after_ttl]), [[1, late, true]]);
    assert.equal(st.stage, "origin_ack_received");
    assert.equal(st.status, "pending", "not yet read by the origin agent");
    assert.equal((await b.requestStatus({ nonce: s.nonce, cursor: 1 })).status, "completed");
  });

  test("request_status without a ledger → LEDGER_NOT_CONFIGURED; bad arguments refused", async (t) => {
    const { fake, make } = await setup(t);
    const cfg = normalizeConfig({ teleptyUrl: fake.origin, token: fake.token, targets: ["target-1"], inboxPrefix: PREFIX });
    const mem = createTeleptyTransport(cfg);
    t.after(() => mem.close());
    assert.equal((await mem.requestStatus({ nonce: "0".repeat(32) })).error.code, "LEDGER_NOT_CONFIGURED");
    const tr = make();
    assert.equal((await tr.requestStatus({ nonce: "nope" })).error.code, "INVALID_ARGUMENT");
    assert.equal((await tr.requestStatus({ nonce: "0".repeat(32), cursor: -1 })).error.code, "INVALID_ARGUMENT");
    assert.equal((await tr.requestStatus({ nonce: "0".repeat(32) })).status, "not_tracked");
    assert.equal((await tr.readReply({ nonce: "0".repeat(32), cursor: -1 })).error.code, "INVALID_ARGUMENT");
  });
});
