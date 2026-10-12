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

// Review S4: relay text is kept only while it may still be sent; failed / uncertain / quarantined items
// keep the payload hash and a bounded excerpt (200 code points).
test("S4 failed, uncertain and quarantined items drop the relay text (hash + bounded excerpt kept); a requeued item keeps it", async (t) => {
  const { l, now } = setup(t);
  const long = "x".repeat(150) + "가".repeat(100);
  const keys = {};
  for (const k of ["yes", "unk", "no", "late"]) keys[k] = l.enqueue(item({ kind: k, text: `${k}:${long}` })).key;
  const send = async (x) => (x.kind === "yes" ? { ok: false, sent: "yes", code: "REFUSED" }
    : x.kind === "unk" ? { ok: false, sent: "unknown", code: "DAEMON_TIMEOUT" }
      : x.kind === "no" ? { ok: false, sent: "no", code: "DAEMON_UNREACHABLE" } : { ok: true, transport_id: "t" });
  const only = (k) => ({ ...l, outbox: () => l.outbox().filter((o) => o.kind === k) });
  for (const k of ["yes", "unk", "no"]) await relayTick({ ledger: only(k), resolver, send });
  const by = () => Object.fromEntries(l.outbox().map((o) => [o.kind, o]));
  assert.equal(by().no.state, "queued");
  assert.equal(by().no.text, `no:${long}`, "requeued: the text is still needed");
  for (const k of ["yes", "unk"]) {
    const o = by()[k];
    assert.equal(o.text, null, k);
    assert.equal(Array.from(o.excerpt).length, 200, k);
    assert.ok(`${k}:${long}`.startsWith(o.excerpt), k);
    assert.match(o.payload_sha256, /^[0-9a-f]{64}$/);
  }
  for (let i = 0; i < 2; i += 1) await relayTick({ ledger: only("no"), resolver, send });
  assert.deepEqual([by().no.state, by().no.text, by().no.quarantine.reason], ["failed", null, "max_attempts"]);
  // Quarantine (past deadline) drops it too; a payload change drops the old one's.
  const v1 = l.enqueue(item({ kind: "chg", text: "v1 text" })).key;
  l.enqueue(item({ kind: "chg", text: "v2 text" }));
  assert.deepEqual([l.outbox().find((o) => o.key === v1).text, l.outbox().find((o) => o.key === v1).excerpt], [null, "v1 text"]);
  now.advance(60001);
  l.sweepOutbox();
  assert.equal(by().late.text, null);
  assert.equal(by().late.excerpt, `late:${long}`.slice(0, 200));
});

test("S4 an intent left by a dead process becomes uncertain on reopen and drops its text", async (t) => {
  const { dir, l, open } = setup(t);
  const { key } = l.enqueue(item({ text: "secretless but long relay text" }));
  let release;
  const hung = new Promise((res) => { release = res; });
  let entered = 0;
  const tick = relayTick({ ledger: l, resolver, send: async () => { entered += 1; await hung; return { ok: true, transport_id: "x" }; } });
  while (entered === 0) await new Promise((res) => setImmediate(res));
  fs.unlinkSync(path.join(dir, "lock"));
  const l2 = open();
  const o = l2.outbox().find((x) => x.key === key);
  assert.deepEqual([o.state, o.text, o.excerpt], ["uncertain", null, "secretless but long relay text"]);
  release();
  await tick;
});

// Review 3 B1: the prune dry run is strictly read-only (no lock, no recovery, no sweep, no write).
test("prune --dry-run leaves ledger.json and the directory byte-identical (pending intent, orphan/tmp files, past-retention record)", async (t) => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "telesession-prune-ro-"));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const dir = path.join(base, "ledger");
  const l = openLedger({ dir, resolver });
  const mk = (n, extra) => l.createRequest({
    nonce: n, request_id: null, origin: { host: "peer-o", session: "inbox" }, destination: DEST, reply_to: { host: "peer-o", session: "inbox" },
    generation: "g", payload_sha256: sha(n), deadline_ms: 1, retain_ms: 1, ...extra,
  });
  assert.equal(mk("1".repeat(32)).ok, true);
  assert.equal(mk("2".repeat(32), { deadline_ms: 600000, retain_ms: 600000 }).ok, true);
  assert.equal(mk("3".repeat(32), { deadline_ms: 1, retain_ms: 600000 }).ok, true);
  assert.equal(l.appendReply({ nonce: "2".repeat(32), text: "r", from: DEST, verified: true }).ok, true);
  const { key } = l.enqueue({ nonce: "2".repeat(32), to: { host: "dest-box", session: "w" }, kind: "relay", text: "relay text" });
  assert.equal(l.outboxTransition(key, "queued", { state: "intent", intent_at: new Date().toISOString() }).ok, true);
  l.enqueue({ nonce: "3".repeat(32), to: { host: "dest-box", session: "w" }, kind: "relay", text: "past deadline" });
  l.close();
  fs.writeFileSync(path.join(dir, "replies", `${"2".repeat(32)}-${"0".repeat(64)}.json`), "{}", { mode: 0o600 });
  fs.writeFileSync(path.join(dir, `.ledger.json.${"0".repeat(16)}.tmp`), "x", { mode: 0o600 });
  await new Promise((res) => setTimeout(res, 20));
  const snap = () => {
    const out = {};
    const walk = (d) => { for (const n of fs.readdirSync(d).sort()) { const p = path.join(d, n); out[path.relative(dir, p)] = fs.lstatSync(p).isDirectory() ? (walk(p), "dir") : fs.readFileSync(p, "hex"); } };
    walk(dir);
    return out;
  };
  const before = snap();
  assert.equal(before.lock, undefined);
  const dry = spawnSync(process.execPath, [PRUNE, "--dry-run"], { env: { PATH: process.env.PATH, TELESESSION_STATE_DIR: base }, encoding: "utf8", timeout: 20000 });
  assert.equal(dry.status, 0, dry.stderr);
  assert.deepEqual(JSON.parse(dry.stdout).records.map((x) => x.nonce), ["1".repeat(32)]);
  assert.deepEqual(snap(), before, "nothing written, swept or locked");
  // The read-only open itself: no lock file, every mutator refused, a held lock still refused.
  const ro = openLedger({ dir, readOnly: true });
  assert.equal(ro.mode, "read_only");
  assert.equal(ro.sweepOutbox().code, "LEDGER_READ_ONLY");
  assert.equal(ro.recordEvent({ nonce: "2".repeat(32) }).code, "LEDGER_READ_ONLY");
  assert.equal(ro.outbox().find((o) => o.key === key).state, "intent", "no open-time recovery");
  ro.close();
  assert.deepEqual(snap(), before);
  const w = openLedger({ dir });
  assert.throws(() => openLedger({ dir, readOnly: true }), { code: "LEDGER_LOCKED" });
  w.close();
  assert.throws(() => openLedger({ dir: path.join(base, "absent"), readOnly: true }), { code: "LEDGER_NOT_FOUND" });
  assert.equal(fs.existsSync(path.join(base, "absent")), false);
});

// Review 3 N-b (§6.1): a retired record accepts reads and checkpoints only; events and replies are refused (counted).
test("retired record refuses recordEvent and appendReply with RETIRED (counted); reads and checkpoints still work", (t) => {
  const { l, now, open } = setup(t);
  assert.equal(l.appendReply({ nonce: NONCE, text: "before", from: DEST, verified: true }).ok, true);
  now.advance(700000);
  const ev = { nonce: NONCE, stage: "processing_completed", payload_sha256: sha("p"), from: DEST, hop: "destination", generation: "g1", authenticated: true };
  assert.equal(l.recordEvent(ev).code, "RETIRED", "derived retirement (before the marker)");
  l.close();
  const l2 = open();
  assert.match(l2.record(NONCE).retired_at, /^\d{4}-/);
  assert.equal(l2.recordEvent(ev).code, "RETIRED");
  assert.equal(l2.appendReply({ nonce: NONCE, text: "after", from: DEST, verified: true }).code, "RETIRED");
  const s = l2.status({ nonce: NONCE, cursor: 1 });
  assert.deepEqual([s.reply_count, s.stage, s.rejected.RETIRED, s.checkpoint.cursor], [1, "unknown", 3, 1]);
  assert.equal(l2.readReplies({ nonce: NONCE, cursor: 0 }).replies[0].text, "before");
});

// Issue #5 (owner review F1): `records` bounds the non-retired records. Retirement stays a marker (nothing is
// deleted), so a ledger whose records are all past retention keeps accepting new requests.
function fillRecords(dir, n) {
  const file = path.join(dir, "ledger.json");
  const s = JSON.parse(fs.readFileSync(file, "utf8"));
  const proto = s.records[NONCE];
  for (let i = 0; i < n; i++) {
    const nonce = i.toString(16).padStart(32, "0");
    s.records[nonce] = { ...structuredClone(proto), nonce, request_id: `fill-${i}` };
  }
  delete s.records[NONCE];
  fs.writeFileSync(file, JSON.stringify(s));
}
const fresh = (nonce) => ({
  nonce, request_id: null, origin: { host: "peer-o", session: "inbox" }, destination: DEST, reply_to: { host: "peer-o", session: "inbox" },
  generation: "g1", payload_sha256: sha("q"), deadline_ms: 60000,
});

test("#5 a ledger whose 1024 records are all retired still accepts a new request; the retired records stay and reopen works", (t) => {
  const { l, now, open, dir } = setup(t);
  l.close();
  fillRecords(dir, 1024);
  now.advance(700000);
  const l2 = open();
  assert.equal(l2.record("0".repeat(32)).retired_at !== null, true, "retired on open (marker)");
  const c = l2.createRequest(fresh("f".repeat(32)));
  assert.equal(c.ok, true, JSON.stringify(c));
  assert.ok(l2.record("0".repeat(32)), "the retired record is kept");
  assert.deepEqual(l2.capacity(), { ok: true });
  l2.close();
  const l3 = open();
  assert.ok(l3.record("f".repeat(32)) && l3.record("0".repeat(32)), "1025 records (1024 retired) reopen without LEDGER_CORRUPT");
});

test("#5 retirement during createRequest: 1024 records past retain_until (no marker yet) → the new request is accepted", (t) => {
  const { l, now, open, dir } = setup(t);
  l.close();
  fillRecords(dir, 1024);
  const l2 = open();
  now.advance(700000);
  assert.equal(l2.createRequest(fresh("e".repeat(32))).ok, true);
  assert.match(l2.record("0".repeat(32)).retired_at, /^\d{4}-/);
});

test("#5 1024 non-retired records → createRequest and capacity() refuse LEDGER_FULL (fail closed, with a code)", (t) => {
  const { l, open, dir } = setup(t);
  l.close();
  fillRecords(dir, 1024);
  const l2 = open();
  assert.deepEqual(l2.capacity(), { ok: false, code: "LEDGER_FULL" });
  assert.deepEqual(l2.createRequest(fresh("d".repeat(32))), { ok: false, code: "LEDGER_FULL" });
});
