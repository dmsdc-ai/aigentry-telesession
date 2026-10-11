// Relay tick (SPEC 2026-10-11 §10): claim+intent → send → receipt; crash between intent and receipt
// → uncertain and no resend; dedupe; definite non-send requeues (bounded); route resolution failure
// never sends. The send primitive is injected; nothing here starts a loop or timer.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { openLedger } from "../src/relay/ledger.js";
import { createRouteResolver } from "../src/relay/route.js";
import { relayTick } from "../src/relay/relay.js";

const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const NONCE = "d".repeat(32);
const resolver = createRouteResolver([
  { peer_id: "peer-o", locators: ["10.0.0.1", "origin-box"] },
  { peer_id: "peer-d", locators: ["10.0.0.2", "dest-box"] },
]);

function setup(t) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "telesession-outbox-"));
  const dir = path.join(base, "ledger");
  const ledgers = [];
  const open = () => { const l = openLedger({ dir, resolver }); ledgers.push(l); return l; };
  t.after(() => { for (const l of ledgers) l.close(); fs.rmSync(base, { recursive: true, force: true }); });
  const l = open();
  l.createRequest({
    nonce: NONCE, request_id: null, origin: { host: "peer-o", session: "inbox" }, destination: { host: "peer-d", session: "w" },
    reply_to: { host: "peer-o", session: "inbox" }, generation: "g1", payload_sha256: sha("p"), deadline_ms: 60000,
  });
  return { dir, l, open };
}

const item = (extra = {}) => ({ nonce: NONCE, to: { host: "dest-box", session: "w" }, kind: "request", text: "p", ...extra });

test("send → receipt; a second tick and a duplicate enqueue relay nothing", async (t) => {
  const { l } = setup(t);
  const e1 = l.enqueue(item());
  const e2 = l.enqueue(item({ to: { host: "10.0.0.2", session: "w" } }));
  assert.equal(e1.ok, true);
  assert.deepEqual([e2.ok, e2.deduplicated, e2.key], [true, true, e1.key], "same peer, other locator form");
  const calls = [];
  const send = async (x) => { calls.push(x); return { ok: true, transport_id: "inj-1" }; };
  const r1 = await relayTick({ ledger: l, send, resolver });
  assert.deepEqual(r1.sent, [e1.key]);
  assert.equal(calls.length, 1);
  assert.deepEqual([calls[0].locator, calls[0].session, calls[0].text], ["10.0.0.2", "w", "p"]);
  const o = l.outbox().find((x) => x.key === e1.key);
  assert.equal(o.state, "sent");
  assert.equal(o.receipt.transport_id, "inj-1");
  assert.equal(o.text, null, "payload text cleared after the receipt");
  const r2 = await relayTick({ ledger: l, send, resolver });
  assert.deepEqual(r2.sent, []);
  assert.equal(l.enqueue(item()).deduplicated, true);
  assert.equal(calls.length, 1, "never relayed again after a receipt");
});

test("T5 crash between intent and receipt → uncertain on reopen; tick never resends", async (t) => {
  const { dir, l, open } = setup(t);
  const { key } = l.enqueue(item());
  let release;
  const hung = new Promise((r) => { release = r; });
  let entered = 0;
  const tick = relayTick({ ledger: l, resolver, send: async () => { entered += 1; await hung; return { ok: true, transport_id: "late" }; } });
  while (entered === 0) await new Promise((r) => setImmediate(r));
  assert.equal(l.outbox().find((x) => x.key === key).state, "intent", "intent durable before send");
  // Simulated crash: the process is gone; an operator removed its stale lock (never automatic).
  fs.unlinkSync(path.join(dir, "lock"));
  const l2 = open();
  const o = l2.outbox().find((x) => x.key === key);
  assert.equal(o.state, "uncertain");
  assert.equal(l2.status({ nonce: NONCE }).status, "unknown");
  let calls = 0;
  const r = await relayTick({ ledger: l2, resolver, send: async () => { calls += 1; return { ok: true, transport_id: "x" }; } });
  assert.equal(calls, 0);
  assert.deepEqual(r.uncertain, [key]);
  release();
  await tick; // the dead instance's lock is gone: its late write is refused, not applied
  assert.equal(l2.outbox().find((x) => x.key === key).state, "uncertain");
});

test("definite non-send requeues (bounded); refusal fails; unknown send is uncertain", async (t) => {
  const { l } = setup(t);
  const a = l.enqueue(item({ kind: "a" })).key;
  const b = l.enqueue(item({ kind: "b" })).key;
  const c = l.enqueue(item({ kind: "c" })).key;
  const send = async (x) => {
    if (x.kind === "a") return { ok: false, sent: "no", code: "DAEMON_UNREACHABLE" };
    if (x.kind === "b") return { ok: false, sent: "yes", code: "SESSION_NOT_FOUND" };
    throw new Error("socket reset");
  };
  const r1 = await relayTick({ ledger: l, send, resolver });
  assert.deepEqual(r1.requeued, [a]);
  assert.deepEqual(r1.failed, [b]);
  assert.deepEqual(r1.uncertain, [c]);
  await relayTick({ ledger: l, send, resolver });
  const r3 = await relayTick({ ledger: l, send, resolver });
  assert.deepEqual(r3.failed, [a], "3 definite non-sends → failed");
  const st = Object.fromEntries(l.outbox().map((x) => [x.kind, x.state]));
  assert.deepEqual(st, { a: "failed", b: "failed", c: "uncertain" });
});

test("unresolved route never sends and stays queued", async (t) => {
  const { l } = setup(t);
  const { key } = l.enqueue(item({ to: { host: "unknown-box", session: "w" } }));
  let calls = 0;
  const r = await relayTick({ ledger: l, resolver, send: async () => { calls += 1; return { ok: true, transport_id: "x" }; } });
  assert.equal(calls, 0);
  assert.deepEqual(r.unresolved, [key]);
  const o = l.outbox().find((x) => x.key === key);
  assert.deepEqual([o.state, o.last_error], ["queued", "ROUTE_UNRESOLVED"]);
});
