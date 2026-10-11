// Review N11 bullets 2–3: a nonce the daemon accepted always gets a ledger record. A crash or ledger
// failure between the store commit and the ledger create, and the audit-recovery path (uncertain →
// accepted after a restart), leave a store record without one; the next transport open / recovery
// reconstructs it. The store does not keep `destination`/`correlation_id`, so a reconstructed record is
// fail-closed: destination unknown, the leg-1 target as `via`, never a false completion (RECONSTRUCTED).

import { describe, test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { normalizeConfig, createTeleptyTransport } from "../src/index.js";
import { openLedger } from "../src/relay/ledger.js";
import { makeSandbox, makeRequest, makeState, makeInbox, writeStateDir, newInboxId, hex } from "./helpers/fault-fs.js";
import { startFakeTelepty } from "./helpers/fake-telepty.js";

const NO_LOOPBACK = process.env.TELESESSION_TEST_NO_LOOPBACK === "1"
  ? "NOTRUN: loopback bind/connect not permitted here (TELESESSION_TEST_NO_LOOPBACK=1)" : false;
const PREFIX = "tsr";
const ACK_FINAL = "[telesession ack=final]";

describe("ledger record reconstruction (loopback fake telepty)", { skip: NO_LOOPBACK }, () => {
  async function setup(t) {
    const sb = makeSandbox("ts-reconcile-");
    const fake = await startFakeTelepty();
    const real = openLedger({ dir: path.join(sb.root, "ledger") });
    const trs = [];
    t.after(async () => { for (const x of trs) { try { await x.close(); } catch { /* closed */ } } real.close(); await fake.close(); sb.remove(); });
    const make = (ledger = real) => {
      const cfg = normalizeConfig({ teleptyUrl: fake.origin, token: fake.token, targets: ["target-1"], inboxPrefix: PREFIX, stateDir: sb.stateDir });
      const tr = createTeleptyTransport(cfg, sb.seam(), { ledger });
      trs.push(tr);
      return tr;
    };
    return { sb, fake, real, make };
  }

  test("ledger create failed after the store commit → reconstructed on the next open, fail-closed, readable", async (t) => {
    const { fake, real, make } = await setup(t);
    const failing = { ...real, get mode() { return real.mode; }, createRequest: () => ({ ok: false, code: "LEDGER_WRITE_FAILED" }) };
    const a = make(failing);
    const s = await a.send({ target: "target-1", text: "job", request_id: "n11-a" });
    assert.equal(s.ok, true, JSON.stringify(s));
    assert.equal(real.record(s.nonce), null, "the crash window: accepted inject, no ledger record");
    await a.close();

    const b = make();
    const rec = real.record(s.nonce);
    assert.ok(rec, "reconstructed on open");
    assert.deepEqual([rec.request_id, rec.reconstructed, rec.correlation_id, rec.destination.host, rec.via.session], ["n11-a", true, null, "unknown", "target-1"]);
    const st = await b.requestStatus({ request_id: "n11-a" });
    assert.equal(st.stage, "transport_accepted");
    assert.ok(st.status_reasons.includes("RECONSTRUCTED"), JSON.stringify(st.status_reasons));
    const again = await b.send({ target: "target-1", text: "job", request_id: "n11-a" });
    assert.equal(again.deduplicated, true);

    // A final reply is kept as data but cannot prove a completion for a reconstructed record.
    fake.replyFrom("target-1", s.reply_to, `REPLY ${s.nonce} ${ACK_FINAL} done`);
    assert.equal((await b.readReply({ nonce: s.nonce, wait_ms: 8000 })).reply, "trusted");
    await b.requestStatus({ nonce: s.nonce, cursor: 1 });
    const st2 = await b.requestStatus({ nonce: s.nonce });
    assert.deepEqual([st2.status, st2.reply_count, st2.replies[0].attestation], ["pending", 1, "relayed_by_leg1_destination"]);
    assert.deepEqual(st2.unproven, { processing_completed: "REMOTE_PROVENANCE_UNAVAILABLE" });
  });

  test("audit-recovery path: an uncertain record recovered as accepted gets a (reconstructed) ledger record", async (t) => {
    const { sb, fake, real, make } = await setup(t);
    const sender = { id: newInboxId(PREFIX), epoch: `epoch-${hex(8)}`, generation: 5 };
    const rec = makeRequest({ request_id: "n11-b", target: "target-1", text: "recover me", sender });
    writeStateDir(sb.stateDir, makeState({ origin: fake.origin, prefix: PREFIX, requests: [rec], inbox: makeInbox({ prefix: PREFIX, id: sender.id, phase: "deleted" }) }));
    fake.addAuditRow({
      ts: new Date(rec.created_at + 500).toISOString(), to: "target-1", to_alias: null, claimed_from: sender.id,
      verified_sender_sid: sender.id, verified_sender_epoch: sender.epoch, verified_sender_generation: sender.generation,
      spoof_suspected: false, payload_sha256: rec.payload_sha256, delivery_result: "success",
    });
    const tr = make();
    assert.equal(real.record(rec.nonce), null, "uncertain: no inject_id yet, nothing reconstructed");
    const r = await tr.send({ target: "target-1", text: "recover me", request_id: "n11-b" });
    assert.deepEqual([r.ok, r.deduplicated, r.state, r.recovery], [true, true, "accepted", "audit_verified_match"], JSON.stringify(r));
    assert.equal(fake.injectArrivals.length, 0, "never re-sent");
    const lr = real.record(rec.nonce);
    assert.ok(lr, "ledger record after the audit recovery");
    assert.deepEqual([lr.request_id, lr.reconstructed], ["n11-b", true]);
    assert.equal((await tr.requestStatus({ request_id: "n11-b" })).stage, "transport_accepted");
  });
});
