import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { createTeleptyTransport, loadConfig } from "../src/index.js";
import { waitFor } from "./helpers.js";
import { FAKE_CAPABILITIES, startFakeTelepty } from "./helpers/fake-telepty.js";

const CAPABILITY = "reply-capability-v1";
const TARGET = "target-1";
const NO_LOOPBACK = process.env.TELESESSION_TEST_NO_LOOPBACK === "1";
const SEND = { target: TARGET, text: "request", request_id: "negotiation-1" };

function envFor(fake, mode) {
  return {
    TELESESSION_TELEPTY_URL: fake.origin,
    TELESESSION_TELEPTY_TOKEN: fake.token,
    TELESESSION_TARGETS: TARGET,
    TELESESSION_INBOX_PREFIX: "tscap",
    TELESESSION_REPLY_CAPABILITY: mode,
  };
}

async function setup(t, { mode = "on", advertised = true, respond } = {}) {
  const fake = await startFakeTelepty({ capabilities: advertised ? [...FAKE_CAPABILITIES, CAPABILITY] : FAKE_CAPABILITIES });
  const transport = createTeleptyTransport(loadConfig(envFor(fake, mode)));
  t.after(async () => {
    try { await transport.close(); } finally { await fake.close(); }
  });
  if (respond) {
    fake.hooks.beforeInject = ({ body }) => {
      const responder = fake.sessions.get(TARGET);
      const metadata = {
        v: 1, id: randomBytes(16).toString("base64url"), not_after_ms: body.reply_capability?.not_after_ms,
        responder: { session_id: TARGET, epoch: responder.epoch, generation: responder.generation },
      };
      return respond({
        success: true, inject_id: randomUUID(), exact_target: true, session_id: TARGET,
        reply_capability: metadata,
      });
    };
  }
  return { fake, transport };
}

test("reply capability config accepts on and off and rejects other values", () => {
  const base = { origin: "http://127.0.0.1:3000", token: "fixture-host-token" };
  assert.equal(loadConfig(envFor(base, undefined)).replyCapability, "off");
  assert.equal(loadConfig(envFor(base, "off")).replyCapability, "off");
  assert.equal(loadConfig(envFor(base, "on")).replyCapability, "on");
  for (const bad of ["", "ON", "true", " off "]) {
    assert.throws(() => loadConfig(envFor(base, bad)), { code: "CONFIG_REPLY_CAPABILITY_INVALID" });
  }
});

test("D1: W7 documentation does not instruct users to print credentials", () => {
  const printCredential = /\b(?:echo|print|printf)\b[^\r\n]*(?:\bTELEPTY_SESSION_[A-Z0-9_*]*|\b(?:reply|capability)[ -]token\b)/i;
  for (const doc of ["README.md", "API-CONTRACT-TELESESSION.md", "CHANGELOG.md"]) {
    const content = readFileSync(new URL("../" + doc, import.meta.url), "utf8");
    assert.equal(printCredential.test(content), false, doc);
  }
});

describe("reply capability negotiation (loopback fake daemon)", { skip: NO_LOOPBACK }, () => {
  test("I4: off keeps the old wire and result shape even when advertised", async (t) => {
    const { fake, transport } = await setup(t, { mode: "off" });
    const result = await transport.send(SEND);
    assert.equal(result.accepted, true);
    assert.equal(Object.hasOwn(result, "reply_capability"), false);
    assert.deepEqual(Object.keys(fake.injectArrivals[0].body), ["prompt", "from", "reply_to", "exact_target"]);
    assert.equal(result.target_epoch_known, true);
  });

  test("I4: an older daemon receives the old inject and reports unsupported", async (t) => {
    const { fake, transport } = await setup(t, { advertised: false });
    const result = await transport.send(SEND);
    assert.equal(result.accepted, true);
    assert.equal(result.reply_capability, "unsupported");
    assert.equal(Object.hasOwn(fake.injectArrivals[0].body, "reply_capability"), false);
  });

  test("I4: an advertising daemon that ignores the field reports not_minted", async (t) => {
    const { fake, transport } = await setup(t);
    const before = Date.now();
    const result = await transport.send(SEND);
    assert.equal(result.accepted, true);
    assert.equal(result.reply_capability, "not_minted");
    const request = fake.injectArrivals[0].body.reply_capability;
    assert.deepEqual(request, { v: 1, not_after_ms: request.not_after_ms, reply_prefix: "REPLY " + result.nonce + "\n" });
    assert.ok(request.not_after_ms >= before + 900_000 && request.not_after_ms <= Date.now() + 900_000);
    assert.equal(result.target_epoch_known, true);
  });

  test("I4: a mint refusal is not retried without the field", async (t) => {
    const code = "REPLY_CAPABILITY_DEADLINE_INVALID";
    const { fake, transport } = await setup(t, { respond: () => ({ status: 400, body: { code } }) });
    assert.deepEqual(await transport.send(SEND), {
      ok: false, error: { code, http_status: 400, accepted: false }, completion_fact: null,
    });
    assert.equal(fake.injectArrivals.length, 1);
    assert.ok(fake.injectArrivals[0].body.reply_capability);
  });

  test("I4: valid mint supplies the epoch and fresh metadata without observation or dedupe state", async (t) => {
    let metadata;
    const { fake, transport } = await setup(t, {
      respond(body) {
        metadata = structuredClone(body.reply_capability);
        body.reply_capability.unexpected = "discard-me";
        return { status: 200, body };
      },
    });
    const result = await transport.send(SEND);
    assert.equal(result.accepted, true);
    assert.equal(result.target_epoch_known, true);
    assert.deepEqual(result.reply_capability, metadata);
    assert.equal(fake.requests.some((r) => r.path.startsWith("/api/inject-observations/")), false);
    const dedup = await transport.send(SEND);
    assert.equal(dedup.deduplicated, true);
    assert.equal(Object.hasOwn(dedup, "reply_capability"), false);
    assert.equal(fake.injectArrivals.length, 1);
  });

  test("I4: uncertain mint records the binding only when all required metadata is valid", async (t) => {
    for (const invalid of [null, "flag", "capability id", "inject id", "responder epoch"]) {
      await t.test(invalid ?? "well-formed", async (entry) => {
        let inbound;
        const { fake, transport } = await setup(entry, {
          respond(body) {
            const failure = { code: "DELIVERY_UNCERTAIN", delivery_uncertain: true,
              inject_id: body.inject_id, reply_capability: body.reply_capability };
            inbound = structuredClone(failure);
            if (invalid === "flag") delete failure.delivery_uncertain;
            if (invalid === "capability id") failure.reply_capability.id = "malformed";
            if (invalid === "inject id") delete failure.inject_id;
            if (invalid === "responder epoch") failure.reply_capability.responder.epoch = "";
            return { status: 500, body: failure };
          },
        });
        const result = await transport.send(SEND);
        assert.equal(result.accepted, "unknown");
        assert.equal(result.inject_id, null);
        assert.deepEqual(result.reply_capability, invalid ? "not_minted" : inbound.reply_capability);
        const dedup = await transport.send(SEND);
        assert.equal(dedup.accepted, "unknown");
        assert.equal(Object.hasOwn(dedup, "reply_capability"), false);
        assert.equal(fake.injectArrivals.length, 1);
        assert.equal(fake.requests.some((r) => r.path.startsWith("/api/inject-observations/")), false);

        const receipt = await transport.receipt({ inject_id: inbound.inject_id });
        assert.equal(receipt.error.code, invalid ? "INJECT_NOT_ISSUED" : "INJECT_NOT_FOUND");

        const { responder } = inbound.reply_capability;
        const text = "REPLY " + result.nonce + "\nreply to an uncertain inject";
        fake.addAuditRow({
          source: CAPABILITY, sender_proof: CAPABILITY, reply_to_inject_id: inbound.inject_id,
          reply_capability_id: inbound.reply_capability.id, reply_attempt: 1, to: transport.inboxId, claimed_from: TARGET,
          verified_sender_sid: TARGET, verified_sender_epoch: responder.epoch,
          verified_sender_generation: responder.generation,
          payload_sha256: createHash("sha256").update(text).digest("hex"),
        }, { observe: false });
        const item = fake.deliverRaw(transport.inboxId, text);
        await waitFor(() => item.state === "delivered", { description: "uncertain request reply reached the inbox" });
        const reply = await transport.readReply({ nonce: result.nonce });
        assert.equal(reply.reply, invalid ? "not_observed" : "trusted");
        assert.equal(reply.text, invalid ? undefined : text);
      });
    }
  });
});
