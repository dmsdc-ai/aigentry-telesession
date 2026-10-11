// Retention / quarantine model (SPEC 2026-10-11 §6, §11): record lifecycle active → past_deadline →
// retired (a marker; files kept), outbox quarantine with a reason, never replayed, listed in status and
// health; deletion is an operator action with a dry-run listing only. Nothing here deletes a file.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { openLedger } from "../src/relay/ledger.js";
import { createRouteResolver } from "../src/relay/route.js";
import { relayTick } from "../src/relay/relay.js";
import { createRelayRunner } from "../src/relay/runner.js";

const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const NONCE = "b".repeat(32);
const DEST = { host: "peer-d", session: "w" };
const PRUNE = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "bin", "telesession-ledger-prune.js");
const resolver = createRouteResolver([{ peer_id: "peer-d", locators: ["dest-box"] }]);

function clock(start = Date.parse("2026-10-12T00:00:00Z")) {
  let t = start;
  const now = () => t;
  now.advance = (ms) => { t += ms; };
  return now;
}

function setup(t, { deadline_ms = 60000, retain_ms = 600000 } = {}) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "telesession-retention-"));
  const dir = path.join(base, "ledger");
  const now = clock();
  const ledgers = [];
  const open = () => { const l = openLedger({ dir, resolver, now }); ledgers.push(l); return l; };
  t.after(() => { for (const l of ledgers) l.close(); fs.rmSync(base, { recursive: true, force: true }); });
  const l = open();
  assert.equal(l.createRequest({
    nonce: NONCE, request_id: "job-r", origin: { host: "peer-o", session: "inbox" }, destination: DEST, reply_to: { host: "peer-o", session: "inbox" },
    generation: "g1", payload_sha256: sha("p"), deadline_ms, retain_ms,
  }).ok, true);
  return { base, dir, now, open, l };
}

const item = (extra = {}) => ({ nonce: NONCE, to: { host: "dest-box", session: "w" }, kind: "relay", text: "p", ...extra });
const files = (dir) => {
  const out = [];
  const walk = (d) => { for (const n of fs.readdirSync(d)) { const p = path.join(d, n); if (fs.lstatSync(p).isDirectory()) walk(p); else if (n !== "lock") out.push(path.relative(dir, p)); } };
  walk(dir);
  return out.sort();
};

test("lifecycle: active within the deadline, past_deadline after it (still tracked), retired after retain_until", (t) => {
  const { l, now, open } = setup(t);
  assert.equal(l.status({ nonce: NONCE }).lifecycle, "active");
  now.advance(60001);
  const s = l.status({ nonce: NONCE });
  assert.deepEqual([s.lifecycle, s.status], ["past_deadline", "unknown"]);
  now.advance(600000);
  assert.equal(l.status({ nonce: NONCE }).lifecycle, "retired", "derived before the marker is written");
  l.close();
  const l2 = open();
  const r = l2.record(NONCE);
  assert.ok(r, "the retired record is kept");
  assert.match(r.retired_at, /^\d{4}-/);
});

test("age-based quarantine: a queued item past its record deadline is quarantined, never sent, listed in status and health", async (t) => {
  const { l, now } = setup(t);
  const { key } = l.enqueue(item());
  now.advance(60001);
  const sw = l.sweepOutbox();
  assert.deepEqual(sw, { ok: true, quarantined: [key] });
  let sends = 0;
  const out = await relayTick({ ledger: l, resolver, send: async () => { sends += 1; return { ok: true, transport_id: "x" }; } });
  assert.equal(sends, 0);
  assert.deepEqual(out.sent, []);
  const o = l.outbox()[0];
  assert.equal(o.state, "queued", "state is the transport fact; quarantine is a review marker");
  assert.equal(o.quarantine.reason, "past_deadline");
  const s = l.status({ nonce: NONCE });
  assert.equal(s.outbox.quarantined, 1);
  assert.deepEqual(s.quarantined.map((x) => [x.key, x.reason, x.state]), [[key, "past_deadline", "queued"]]);
  const h = createRelayRunner({ ledger: l, resolver, send: async () => ({ ok: true, transport_id: "x" }), now }).health();
  assert.deepEqual([h.quarantined_count, h.queued_count, h.oldest_quarantined_age_ms], [1, 0, 60001]);
  assert.deepEqual(l.sweepOutbox(), { ok: true, quarantined: [] }, "idempotent");
});

test("correlation-less item (its record retired) is quarantined no_live_correlation on open; an uncertain item too", (t) => {
  const { l, now, open } = setup(t, { deadline_ms: 600000, retain_ms: 600000 });
  const a = l.enqueue(item({ kind: "a" })).key;
  const b = l.enqueue(item({ kind: "b" })).key;
  assert.equal(l.outboxTransition(b, "queued", { state: "uncertain" }).ok, true);
  now.advance(600001);
  l.close();
  const l2 = open();
  const q = Object.fromEntries(l2.outbox().map((o) => [o.key, o.quarantine && o.quarantine.reason]));
  assert.deepEqual(q, { [a]: "no_live_correlation", [b]: "no_live_correlation" });
});

test("a changed payload is a new key; the old queued item is quarantined payload_changed", (t) => {
  const { l } = setup(t);
  const old = l.enqueue(item({ text: "v1" })).key;
  const neu = l.enqueue(item({ text: "v2" }));
  assert.equal(neu.ok, true);
  assert.notEqual(neu.key, old);
  const by = Object.fromEntries(l.outbox().map((o) => [o.key, o]));
  assert.equal(by[old].quarantine.reason, "payload_changed");
  assert.equal(by[neu.key].quarantine, null);
  assert.equal(by[neu.key].state, "queued");
});

test("retries exhausted: failed with quarantine max_attempts", async (t) => {
  const { l } = setup(t);
  l.enqueue(item());
  const send = async () => ({ ok: false, sent: "no", code: "DAEMON_UNREACHABLE" });
  for (let i = 0; i < 3; i += 1) await relayTick({ ledger: l, resolver, send });
  const o = l.outbox()[0];
  assert.deepEqual([o.state, o.quarantine.reason], ["failed", "max_attempts"]);
});

test("retired record stays readable (status + replies + checkpoint); nothing is deleted on retire or quarantine", (t) => {
  const { dir, l, now, open } = setup(t);
  l.appendReply({ nonce: NONCE, text: "[telesession ack=final] done", from: DEST, verified: true });
  l.enqueue(item());
  const before = files(dir);
  assert.ok(before.some((f) => f.startsWith("replies")), JSON.stringify(before));
  now.advance(700000);
  l.close();
  const l2 = open();
  assert.equal(l2.sweepOutbox().ok, true);
  assert.deepEqual(files(dir), before, "same files after retire + quarantine");
  const s = l2.status({ nonce: NONCE });
  assert.deepEqual([s.ok, s.status, s.lifecycle, s.request_id], [true, "expired", "retired", "job-r"]);
  assert.ok(s.status_reasons.includes("RETIRED"));
  assert.equal(s.reply_count, 1);
  assert.equal(l2.readReplies({ nonce: NONCE, cursor: 0 }).replies[0].text, "[telesession ack=final] done");
  assert.equal(l2.status({ nonce: NONCE, cursor: 1 }).checkpoint.cursor, 1, "a final receipt is still recorded");
  assert.equal(l2.status({ nonce: "c".repeat(32) }).status, "not_tracked");
  assert.equal(l2.createRequest({
    nonce: NONCE, request_id: null, origin: DEST, destination: DEST, reply_to: DEST, generation: null, payload_sha256: sha("other"), deadline_ms: 1,
  }).code, "NONCE_CONFLICT");
});

test("prunable listing (dry run): retired records and quarantined items are listed; the prune CLI only supports --dry-run", (t) => {
  const { base, dir, l, now, open } = setup(t);
  l.appendReply({ nonce: NONCE, text: "r1", from: DEST, verified: true });
  const { key } = l.enqueue(item());
  now.advance(700000);
  l.close();
  const l2 = open();
  const p = l2.prunable();
  assert.deepEqual(p.records.map((x) => [x.nonce, x.reply_files]), [[NONCE, 1]]);
  assert.deepEqual(p.outbox.map((x) => [x.key, x.reason]), [[key, "no_live_correlation"]]);
  l2.close();
  const before = files(dir);
  const env = { PATH: process.env.PATH, TELESESSION_STATE_DIR: base };
  // The CLI reads <state dir>/ledger.
  const dry = spawnSync(process.execPath, [PRUNE, "--dry-run"], { env, encoding: "utf8", timeout: 20000 });
  assert.equal(dry.status, 0, dry.stderr);
  const listed = JSON.parse(dry.stdout);
  assert.equal(listed.dry_run, true);
  assert.deepEqual(listed.records.map((x) => x.nonce), [NONCE]);
  const real = spawnSync(process.execPath, [PRUNE], { env, encoding: "utf8", timeout: 20000 });
  assert.equal(real.status, 2);
  assert.match(real.stderr, /PRUNE_DRY_RUN_ONLY/);
  assert.deepEqual(files(dir), before, "the CLI deleted nothing");
});
