// Task #2026101110 U2 — cross-host relay send fails closed (fake telepty only; no real cross-host transfer).
// telepty db2f532 has no daemon-side `sid@host` inject (the exact remote forward is telepty#111), so a relay
// item routed to another peer is refused before any inject (PEER_UNSUPPORTED) and never reaches the LOCAL
// daemon's same-name session; the transport's default resolver names any non-local host PEER_UNKNOWN.
// Reproduced first (Rule 35): before the fix the peer-b item was injected into the local `target-1`.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { normalizeConfig, createTeleptyTransport } from "../src/index.js";
import { openLedger } from "../src/relay/ledger.js";
import { createRouteResolver } from "../src/relay/route.js";
import { startFakeTelepty } from "./helpers/fake-telepty.js";

const NO_LOOPBACK = process.env.TELESESSION_TEST_NO_LOOPBACK === "1"
  ? "NOTRUN: loopback bind/connect not permitted here (TELESESSION_TEST_NO_LOOPBACK=1)" : false;
const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const N = "d".repeat(32);
const TWO = createRouteResolver([{ peer_id: "local", locators: ["local"] }, { peer_id: "peer-b", locators: ["box-b"] }]);

// A transport + ledger holding one request; `resolver` undefined = the transport's default (local only).
async function setup(t, resolver) {
  const fake = await startFakeTelepty({ targets: ["target-1"] });
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "telesession-xh-"));
  const ledger = openLedger({ dir: path.join(base, "ledger"), resolver: TWO });
  const tr = createTeleptyTransport(normalizeConfig({ teleptyUrl: fake.origin, token: fake.token, targets: ["target-1"], inboxPrefix: "xh" }),
    undefined, { ledger, ...(resolver ? { resolver } : {}) });
  t.after(async () => { await tr.close(); ledger.close(); await fake.close(); fs.rmSync(base, { recursive: true, force: true }); });
  ledger.createRequest({
    nonce: N, request_id: null, origin: { host: "local", session: "inbox" }, destination: { host: "peer-b", session: "target-1" },
    reply_to: { host: "local", session: "inbox" }, generation: null, payload_sha256: sha("p"), deadline_ms: 60000,
  });
  const localTexts = () => fake.injectArrivals.filter((r) => r.to === "target-1").map((r) => r.body.prompt.split("\n").slice(1).join("\n"));
  return { fake, tr, ledger, localTexts };
}

test("U2 (a) telepty#111: a relay item for another peer is refused PEER_UNSUPPORTED before any inject", { skip: NO_LOOPBACK }, async (t) => {
  const { fake, tr, ledger } = await setup(t, TWO);
  const key = ledger.enqueue({ nonce: N, to: { host: "box-b", session: "target-1" }, kind: "relay", text: "for peer-b" }).key;
  const out = await tr.relayTick();
  assert.deepEqual(out.requeued, [key]);
  const o = ledger.outbox().find((x) => x.key === key);
  assert.deepEqual([o.state, o.last_error, o.attempts], ["queued", "PEER_UNSUPPORTED", 1]);
  assert.equal(fake.injectArrivals.length, 0, "nothing was injected into the local daemon");
});

test("U2 (b) telepty#111: same name on two hosts — the local item is sent, the peer-b item never reaches the local session", { skip: NO_LOOPBACK }, async (t) => {
  const { tr, ledger, localTexts } = await setup(t, TWO);
  const toLocal = ledger.enqueue({ nonce: N, to: { host: "local", session: "target-1" }, kind: "relay", text: "for local" }).key;
  const toB = ledger.enqueue({ nonce: N, to: { host: "box-b", session: "target-1" }, kind: "relay", text: "for peer-b" }).key;
  const out = await tr.relayTick();
  assert.deepEqual([out.sent, out.requeued], [[toLocal], [toB]]);
  assert.deepEqual(localTexts(), ["for local"]);
});

test("U2 (c) telepty#111: the transport's default resolver names a non-local destination PEER_UNKNOWN; nothing is injected", { skip: NO_LOOPBACK }, async (t) => {
  const { fake, tr, ledger } = await setup(t);
  const key = ledger.enqueue({ nonce: N, to: { host: "box-b", session: "target-1" }, kind: "relay", text: "for peer-b" }).key;
  const out = await tr.relayTick();
  assert.deepEqual(out.unresolved, [key]);
  const o = ledger.outbox().find((x) => x.key === key);
  assert.deepEqual([o.state, o.last_error, o.attempts], ["queued", "PEER_UNKNOWN", 0]);
  assert.equal(fake.injectArrivals.length, 0);
});

// The local path is unchanged: a local relay item and an origin send with a remote destination (the relayed
// model: the local leg-1 target carries it) still inject the local target exactly once each.
test("U2 control: local relay item and origin send(destination≠local) still use the local leg-1 target", { skip: NO_LOOPBACK }, async (t) => {
  const { fake, tr, ledger, localTexts } = await setup(t);
  const key = ledger.enqueue({ nonce: N, to: { host: "local", session: "target-1" }, kind: "relay", text: "for local" }).key;
  assert.deepEqual((await tr.relayTick()).sent, [key]);
  const r = await tr.send({ target: "target-1", text: "via leg-1", request_id: "xh-v", destination: { host: "peer-b", session: "orch" } });
  assert.equal(r.ok, true);
  assert.deepEqual(localTexts(), ["for local", "via leg-1"]);
  assert.equal(fake.injectArrivals.every((x) => x.body.exact_target === true), true);
});
