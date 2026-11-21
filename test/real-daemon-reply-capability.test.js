import { describe, test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createTeleptyTransport, normalizeConfig } from "../src/index.js";
import { openLedger } from "../src/relay/ledger.js";
import { waitFor } from "./helpers.js";
import { FAKE_CAPABILITIES, startFakeTelepty } from "./helpers/fake-telepty.js";
import { makeSandbox } from "./helpers/fault-fs.js";

const PROOF = "reply-capability-v1";
const TARGET = "target-1";
const NO_LOOPBACK = process.env.TELESESSION_TEST_NO_LOOPBACK === "1";

async function setup(t, ledger) {
  const fake = await startFakeTelepty({ capabilities: [...FAKE_CAPABILITIES, PROOF] });
  const sender = fake.sessions.get(TARGET);
  const transport = createTeleptyTransport(normalizeConfig({
    teleptyUrl: fake.origin, token: fake.token, targets: [TARGET], inboxPrefix: "tscap", replyCapability: "on",
  }), undefined, { ledger });
  t.after(async () => {
    try { await transport.close(); } finally { await fake.close(); }
  });

  fake.hooks.afterInject = ({ out, body }) => {
    if (out.status !== 200 || !body.reply_capability) return;
    out.body.reply_capability = {
      v: 1, id: randomBytes(16).toString("base64url"), not_after_ms: body.reply_capability.not_after_ms,
      responder: { session_id: TARGET, epoch: sender.epoch, generation: sender.generation },
    };
  };

  async function deliverReply(sent, body, proofFields, auditTimeMs = Date.now()) {
    const request = fake.injectArrivals.find((x) => x.body.prompt.includes("nonce=" + sent.nonce + " "));
    const text = request.body.reply_capability.reply_prefix + body;
    fake.addAuditRow({
      ts: new Date(auditTimeMs).toISOString(), to: sent.reply_to, claimed_from: TARGET,
      verified_sender_sid: TARGET, verified_sender_epoch: sender.epoch, verified_sender_generation: sender.generation,
      payload_sha256: createHash("sha256").update(text).digest("hex"), ...proofFields,
    }, { observe: false });
    const item = fake.deliverRaw(sent.reply_to, text);
    await waitFor(() => item.state === "delivered", { description: "reply bytes reached telesession inbox" });
    return text;
  }

  function proofFor(sent, inboundId = sent.inject_id) {
    return {
      source: PROOF, sender_proof: PROOF, reply_capability_id: sent.reply_capability.id,
      reply_to_inject_id: inboundId, reply_attempt: 1,
    };
  }
  return { fake, transport, deliverReply, proofFor };
}

describe("reply capability client integration (SPEC fake, no real daemon or CLI)", { skip: NO_LOOPBACK }, () => {
  test("I3: the capability audit reply is trusted and an unauthenticated legacy reply is claimed-only", async (t) => {
    const { fake, transport, deliverReply, proofFor } = await setup(t);
    const args = { target: TARGET, text: "request" };
    const cap = await transport.send(args);
    assert.equal(cap.accepted, true);
    assert.equal(cap.reply_capability.v, 1);
    const expected = await deliverReply(cap, "verified reply", proofFor(cap));
    const read = await transport.readReply({ nonce: cap.nonce });
    assert.equal(read.reply, "trusted");
    assert.equal(read.text, expected);
    assert.equal(read.verified_sender.sid, TARGET);

    const claimed = await transport.send(args);
    fake.replyFrom(TARGET, claimed.reply_to, "REPLY " + claimed.nonce + "\nclaimed reply", { bearer: null });
    const rejected = await waitFor(async () => {
      const result = await transport.readReply({ nonce: claimed.nonce });
      return result.quarantined?.claimed_only === 1 ? result : null;
    }, { description: "claimed-only reply quarantined" });
    assert.equal(rejected.reply, "not_observed");
    assert.equal(Object.hasOwn(rejected, "text"), false);
  });

  test("I7: live promotion rejects a foreign binding and accepts the legacy audit row", async (t) => {
    const { transport, deliverReply, proofFor } = await setup(t);
    const sent = await transport.send({ target: TARGET, text: "request" });
    await deliverReply(sent, "foreign capability reply", proofFor(sent, randomUUID()));
    const rejected = await transport.readReply({ nonce: sent.nonce });
    assert.equal(rejected.reply, "not_observed");
    assert.deepEqual(rejected.quarantined, { capability_mismatch: 1 });
    assert.equal(Object.hasOwn(rejected, "text"), false);

    const text = await deliverReply(sent, "verified legacy reply");
    const read = await transport.readReply({ nonce: sent.nonce });
    assert.equal(read.reply, "trusted");
    assert.equal(read.text, text);
  });

  test("I7: late promotion requires the original inbound inject id and preserves legacy handling", async (t) => {
    const sandbox = makeSandbox("ts-cap-late-");
    const realNow = Date.now;
    let clockOffsetMs = 0;
    const now = () => realNow() + clockOffsetMs;
    t.mock.method(Date, "now", now);
    const ledger = openLedger({ dir: path.join(sandbox.root, "ledger"), now });
    const { transport, deliverReply, proofFor } = await setup(t, ledger);
    t.after(() => {
      ledger.close();
      sandbox.remove();
    });

    const args = { target: TARGET, text: "request" };
    const retained = await transport.send({ ...args, request_id: "late-retained" });
    const unretained = await transport.send(args);
    assert.equal(retained.accepted, true);
    assert.equal(unretained.accepted, true);
    const auditTimeMs = now();
    clockOffsetMs = 16 * 60 * 1000;

    await deliverReply(retained, "foreign late proof", proofFor(retained, randomUUID()), auditTimeMs);
    await deliverReply(unretained, "unauthenticated binding", proofFor(unretained), auditTimeMs);
    assert.equal((await transport.readReply({ nonce: retained.nonce })).error.code, "NONCE_EXPIRED");
    assert.deepEqual(ledger.record(retained.nonce).rejected, { capability_mismatch: 1 });
    assert.deepEqual(ledger.record(unretained.nonce).rejected, { capability_mismatch: 1 });

    const matched = await deliverReply(retained, "matched late proof", proofFor(retained), auditTimeMs);
    const legacy = await deliverReply(unretained, "verified late legacy reply", undefined, auditTimeMs);
    for (const [sent, text] of [[retained, matched], [unretained, legacy]]) {
      const read = await transport.readReply({ nonce: sent.nonce });
      assert.deepEqual([read.reply, read.source, read.text], ["trusted", "ledger", text]);
      assert.equal(read.replies[0].late_after_ttl, true);
    }
  });
});
