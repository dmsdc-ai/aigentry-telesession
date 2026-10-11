// Post-expiry lookup (SPEC 2026-10-11 §8): after the transport's 15-min nonce TTL (read_reply
// NONCE_EXPIRED) the ledger still answers request_status by nonce, request_id or correlation_id (exactly
// one), records the origin agent's checkpoint, and read_reply returns the ledger's verified replies with
// source "ledger". Loopback fake telepty; the transport record is aged by rewriting the store.

import { describe, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { normalizeConfig, createTeleptyTransport } from "../src/index.js";
import { openLedger } from "../src/relay/ledger.js";
import { waitFor } from "./helpers.js";
import { makeSandbox, readJson, writeStateDir } from "./helpers/fault-fs.js";
import { startFakeTelepty } from "./helpers/fake-telepty.js";

const NO_LOOPBACK = process.env.TELESESSION_TEST_NO_LOOPBACK === "1"
  ? "NOTRUN: loopback bind/connect not permitted here (TELESESSION_TEST_NO_LOOPBACK=1)" : false;
const ACK_FINAL = "[telesession ack=final]";

async function setup(t) {
  const sb = makeSandbox("ts-postexp-");
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
    const cfg = normalizeConfig({ teleptyUrl: fake.origin, token: fake.token, targets: ["target-1"], inboxPrefix: "tsx", stateDir: sb.stateDir });
    const tr = createTeleptyTransport(cfg, sb.seam(), { ledger });
    transports.push(tr);
    return tr;
  };
  // Close `tr`, age its store record past the transport TTL, reopen.
  const expire = async (tr, key) => {
    await tr.close();
    const state = readJson(path.join(sb.stateDir, "state.json"));
    for (const k of ["created_at", "sent_at", "expires_at", "retain_until"]) state.requests[key][k] -= 16 * 60 * 1000;
    fs.unlinkSync(path.join(sb.stateDir, "state.json"));
    writeStateDir(sb.stateDir, state);
    return make();
  };
  return { fake, ledger, make, expire };
}

describe("post-expiry lookup and final receipt (loopback fake telepty)", { skip: NO_LOOPBACK }, () => {
  test("expired transport nonce + ledger record → full status by nonce, request_id and correlation_id; read_reply from the ledger", async (t) => {
    const { fake, make, expire } = await setup(t);
    const a = make();
    const s = await a.send({ target: "target-1", text: "job", request_id: "pe-1" });
    assert.equal(s.ok, true, JSON.stringify(s));
    fake.replyFrom("target-1", s.reply_to, `REPLY ${s.nonce} interim`);
    assert.equal((await a.readReply({ nonce: s.nonce, wait_ms: 8000 })).reply, "trusted");
    fake.replyFrom("target-1", s.reply_to, `REPLY ${s.nonce}\n${ACK_FINAL} done`);
    await a.readReply({ nonce: s.nonce, wait_ms: 8000, cursor: 1 });
    const b = await expire(a, "r:pe-1");

    const rr = await b.readReply({ nonce: s.nonce });
    assert.equal(rr.ok, true, JSON.stringify(rr));
    assert.deepEqual([rr.source, rr.expiry, rr.reply, rr.text], ["ledger", "NONCE_EXPIRED", "trusted", `REPLY ${s.nonce} interim`]);
    assert.deepEqual(rr.replies.map((x) => x.seq), [1, 2]);
    assert.equal(rr.next_cursor, 2);
    assert.deepEqual((await b.readReply({ nonce: s.nonce, cursor: 1 })).replies.map((x) => x.seq), [2]);

    const byNonce = await b.requestStatus({ nonce: s.nonce });
    assert.equal(byNonce.ok, true, JSON.stringify(byNonce));
    assert.deepEqual([byNonce.stage, byNonce.final_ack_seq, byNonce.first_ack_seq, byNonce.lifecycle, byNonce.status],
      ["origin_ack_received", 2, 2, "active", "pending"]);
    assert.equal(byNonce.transport_nonce, "expired");
    assert.ok(byNonce.status_reasons.includes("TRANSPORT_NONCE_EXPIRED"), JSON.stringify(byNonce.status_reasons));
    assert.deepEqual(byNonce.replies.map((x) => x.seq), [1, 2]);
    for (const key of [{ request_id: "pe-1" }, { correlation_id: s.correlation_id }]) {
      const st = await b.requestStatus(key);
      assert.deepEqual([st.ok, st.nonce, st.correlation_id, st.request_id, st.final_ack_seq], [true, s.nonce, s.correlation_id, "pe-1", 2], JSON.stringify(key));
    }
    // The origin agent's final receipt after expiry, by request_id.
    const done = await b.requestStatus({ request_id: "pe-1", cursor: 2 });
    assert.deepEqual([done.status, done.delivered_to_origin_agent, done.checkpoint.cursor], ["completed", true, 2]);
    assert.equal((await b.requestStatus({ correlation_id: s.correlation_id })).status, "completed");
  });

  test("exactly one lookup key; unknown request_id / correlation_id → not_tracked without leaking other records", async (t) => {
    const { make } = await setup(t);
    const tr = make();
    const s = await tr.send({ target: "target-1", text: "job", request_id: "pe-2" });
    assert.equal(s.ok, true, JSON.stringify(s));
    for (const bad of [{}, { nonce: s.nonce, request_id: "pe-2" }, { request_id: "pe-2", correlation_id: s.correlation_id }, { request_id: "bad id" }, { correlation_id: "XYZ" }]) {
      assert.equal((await tr.requestStatus(bad)).error.code, "INVALID_ARGUMENT", JSON.stringify(bad));
    }
    const { ledger: c1, ...u1 } = await tr.requestStatus({ request_id: "nope" });
    assert.deepEqual(u1, { ok: true, request_id: "nope", status: "not_tracked", completion_fact: null });
    const { ledger: c2, ...u2 } = await tr.requestStatus({ correlation_id: "0".repeat(32) });
    assert.deepEqual(u2, { ok: true, correlation_id: "0".repeat(32), status: "not_tracked", completion_fact: null });
    assert.deepEqual(Object.keys(c1).sort(), ["ack_event_failed", "late_dropped", "mode", "write_failed"], "counters only");
    assert.deepEqual(c1, c2);
    const st = await tr.requestStatus({ nonce: s.nonce });
    assert.equal(st.transport_nonce, "live");
    assert.ok(!st.status_reasons.includes("TRANSPORT_NONCE_EXPIRED"));
  });

  test("read_reply after expiry with no stored reply keeps NONCE_EXPIRED; a late final reply after expiry is stored, shown, completed once checkpointed", async (t) => {
    const { fake, make, expire } = await setup(t);
    const a = make();
    const s = await a.send({ target: "target-1", text: "slow", request_id: "pe-3" });
    assert.equal(s.ok, true, JSON.stringify(s));
    const b = await expire(a, "r:pe-3");
    assert.equal((await b.readReply({ nonce: s.nonce })).error.code, "NONCE_EXPIRED");
    const other = await b.send({ target: "target-1", text: "fresh", request_id: "pe-3b" });
    assert.equal(other.ok, true, JSON.stringify(other));
    const late = `REPLY ${s.nonce} ${ACK_FINAL} finally`;
    fake.replyFrom("target-1", other.reply_to, late);
    const st = await waitFor(async () => {
      const x = await b.requestStatus({ correlation_id: s.correlation_id });
      return x.ok && x.late_after_ttl_count === 1 ? x : null;
    }, { timeoutMs: 8000, description: "late reply verified" });
    assert.deepEqual([st.status, st.stage, st.final_ack_seq], ["pending", "origin_ack_received", 1]);
    assert.ok(st.status_reasons.includes("LATE_AFTER_TTL"));
    const rr = await b.readReply({ nonce: s.nonce });
    assert.deepEqual([rr.source, rr.text, rr.replies[0].late_after_ttl], ["ledger", late, true]);
    assert.equal((await b.requestStatus({ correlation_id: s.correlation_id, cursor: 1 })).status, "completed");
  });
});
