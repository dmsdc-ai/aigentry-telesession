// Correlation ledger (SPEC 2026-10-11 §4–§8): stages, addenda with a monotonic sequence + cursor,
// authenticated-event validation, restart recovery, timeout → unknown, permission-limited directory.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { openLedger, LedgerError } from "../src/relay/ledger.js";
import { createRouteResolver } from "../src/relay/route.js";

const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const NONCE = "a".repeat(32);
const PAYLOAD = sha("do the thing");
const ORIGIN = { host: "peer-o", session: "inbox-1" };
const DEST = { host: "peer-d", session: "worker-1" };
const HOP = { host: "peer-o", session: "relay-1" };
const resolver = createRouteResolver([
  { peer_id: "peer-o", locators: ["10.0.0.1", "origin-box"] },
  { peer_id: "peer-d", locators: ["10.0.0.2", "dest-box"] },
]);

function tempDir(t) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "telesession-ledger-"));
  t.after(() => {
    for (const d of [base, path.join(base, "ledger"), path.join(base, "ro-parent")]) { try { fs.chmodSync(d, 0o700); } catch { /* absent */ } }
    fs.rmSync(base, { recursive: true, force: true });
  });
  return path.join(base, "ledger");
}

function clock(start = Date.parse("2026-10-11T12:00:00Z")) {
  let t = start;
  const now = () => t;
  now.advance = (ms) => { t += ms; };
  return now;
}

function setup(t, opts = {}) {
  const dir = tempDir(t);
  const now = clock();
  const open = () => openLedger({ dir, resolver, now });
  const l = open();
  t.after(() => l.close());
  const c = l.createRequest({
    nonce: NONCE, request_id: "req-1", origin: ORIGIN, destination: DEST, reply_to: ORIGIN,
    generation: "gen-1", payload_sha256: PAYLOAD, deadline_ms: 120000, ...opts,
  });
  assert.equal(c.ok, true, JSON.stringify(c));
  return { dir, now, open, l };
}

const ack = (stage, extra = {}) => ({
  nonce: NONCE, stage, payload_sha256: PAYLOAD, generation: "gen-1", from: DEST, authenticated: true, hop: "destination", ...extra,
});

test("T1 late ACK after a terminal initial reply lands as addendum seq 2 and completes the request", (t) => {
  const { l, now } = setup(t);
  const first = l.appendReply({ nonce: NONCE, text: "no ACK within the window", from: HOP, verified: true });
  assert.deepEqual([first.ok, first.seq, first.deduplicated], [true, 1, false]);
  now.advance(125000); // past the 120 s window: still tracked
  assert.equal(l.status({ nonce: NONCE }).status, "unknown");
  const late = l.appendReply({ nonce: NONCE, text: "ACK: done", from: { host: "dest-box", session: "worker-1" }, verified: true });
  assert.deepEqual([late.ok, late.seq], [true, 2]);
  assert.equal(l.recordEvent(ack("processing_completed")).ok, true);
  const s = l.status({ nonce: NONCE });
  assert.equal(s.status, "pending", "ACK recorded but not yet read by the origin agent");
  assert.equal(s.stage, "origin_ack_received");
  assert.equal(s.cursor, 2);
  assert.equal(s.ack_seq, 2);
  assert.equal(s.delivered_to_origin_agent, false);
  assert.ok(s.status_reasons.includes("AWAITING_ORIGIN_AGENT_READ"));
  const done = l.status({ nonce: NONCE, cursor: 2 });
  assert.equal(done.delivered_to_origin_agent, true);
  assert.equal(done.status, "completed");
  const r = l.readReplies({ nonce: NONCE, cursor: 1 });
  assert.deepEqual(r.replies.map((x) => [x.seq, x.text]), [[2, "ACK: done"]]);
  assert.equal(r.next_cursor, 2);
  assert.deepEqual(l.readReplies({ nonce: NONCE, cursor: 0 }).replies.map((x) => x.seq), [1, 2], "ordered by seq");
});

test("T2 the same ACK twice collapses to one reply and one applied event", (t) => {
  const { l } = setup(t);
  const a = l.appendReply({ nonce: NONCE, text: "ACK", from: DEST, verified: true });
  const b = l.appendReply({ nonce: NONCE, text: "ACK", from: { host: "10.0.0.2", session: "worker-1" }, verified: true });
  assert.equal(a.seq, 1);
  assert.deepEqual([b.ok, b.seq, b.deduplicated], [true, 1, true], "same text from the same peer (other locator form)");
  const e1 = l.recordEvent(ack("processing_completed"));
  const e2 = l.recordEvent(ack("processing_completed"));
  assert.deepEqual([e1.applied, e1.deduplicated], [true, false]);
  assert.deepEqual([e2.applied, e2.deduplicated], [false, true]);
  assert.equal(l.readReplies({ nonce: NONCE, cursor: 0 }).replies.length, 1);
  assert.equal(l.status({ nonce: NONCE }).reply_count, 1);
});

test("T3 out-of-order ACKs: completed before consumed; stage never regresses, timestamp filled later", (t) => {
  const { l, now } = setup(t);
  l.recordEvent(ack("transport_accepted", { from: HOP, hop: "intermediary" }));
  now.advance(1000);
  l.recordEvent(ack("processing_completed"));
  let s = l.status({ nonce: NONCE });
  assert.equal(s.stage, "origin_ack_received");
  assert.equal(s.stages.agent_consumed, "unknown", "no evidence yet");
  assert.equal(s.stages.durable_received, "unknown");
  now.advance(1000);
  const late = l.recordEvent(ack("agent_consumed"));
  assert.equal(late.ok, true);
  s = l.status({ nonce: NONCE });
  assert.equal(s.stage, "origin_ack_received", "no regression");
  assert.equal(s.stages.agent_consumed, "2026-10-11T12:00:02.000Z");
  assert.equal(s.stages.processing_completed, "2026-10-11T12:00:01.000Z");
});

test("T4 restart recovery: reopening mid-flow reloads records, seq and checkpoint; next seq continues", (t) => {
  const { l, open } = setup(t);
  l.appendReply({ nonce: NONCE, text: "r1", from: HOP, verified: true });
  l.recordEvent(ack("durable_received"));
  l.status({ nonce: NONCE, cursor: 1 });
  const before = l.status({ nonce: NONCE });
  l.close();
  const l2 = open();
  t.after(() => l2.close());
  const after = l2.status({ nonce: NONCE });
  assert.deepEqual(after, before);
  assert.deepEqual(after.checkpoint.cursor, 1);
  assert.equal(l2.appendReply({ nonce: NONCE, text: "r2", from: DEST, verified: true }).seq, 2);
  assert.equal(l2.appendReply({ nonce: NONCE, text: "r1", from: HOP, verified: true }).seq, 1, "idempotent re-entry");
  assert.equal(l2.createRequest({
    nonce: NONCE, request_id: "req-1", origin: ORIGIN, destination: DEST, reply_to: ORIGIN,
    generation: "gen-1", payload_sha256: PAYLOAD, deadline_ms: 120000,
  }).deduplicated, true);
});

test("T6 wrong hash / generation / host / unauthenticated / intermediary-final events are rejected without state advance", (t) => {
  const { l } = setup(t);
  const base = l.status({ nonce: NONCE });
  const cases = [
    [ack("processing_completed", { payload_sha256: sha("other") }), "HASH_MISMATCH"],
    [ack("processing_completed", { generation: "gen-0" }), "GENERATION_MISMATCH"],
    [ack("processing_completed", { from: { host: "peer-o", session: "worker-1" } }), "SOURCE_MISMATCH"],
    [ack("processing_completed", { from: { host: "unlisted-box", session: "worker-1" } }), "SOURCE_MISMATCH"],
    [ack("processing_completed", { authenticated: false }), "UNAUTHENTICATED"],
    [ack("processing_completed", { hop: "intermediary" }), "HOP_NOT_FINAL"],
    [ack("processing_completed", { nonce: "b".repeat(32) }), "UNKNOWN_CORRELATION"],
    [ack("agent_consumed", { from: HOP, hop: "intermediary" }), "HOP_NOT_FINAL"],
  ];
  for (const [ev, code] of cases) {
    const r = l.recordEvent(ev);
    assert.deepEqual([r.ok, r.code], [false, code], code);
  }
  const after = l.status({ nonce: NONCE });
  assert.equal(after.stage, base.stage);
  assert.deepEqual(after.stages, base.stages);
  assert.equal(after.status, "pending");
  assert.deepEqual(after.rejected, {
    HASH_MISMATCH: 1, GENERATION_MISMATCH: 1, SOURCE_MISMATCH: 2, UNAUTHENTICATED: 1, HOP_NOT_FINAL: 2,
  });
  assert.equal(l.appendReply({ nonce: NONCE, text: "x", from: DEST, verified: false }).code, "UNAUTHENTICATED");
  assert.equal(l.status({ nonce: NONCE }).reply_count, 0);
});

test("T13 completed requires origin_ack_received AND checkpoint ≥ ack_seq; an older checkpoint stays pending", (t) => {
  const { l } = setup(t);
  l.appendReply({ nonce: NONCE, text: "working", from: DEST, verified: true });
  assert.equal(l.status({ nonce: NONCE, cursor: 1 }).status, "pending");
  l.appendReply({ nonce: NONCE, text: "ACK", from: DEST, verified: true });
  l.recordEvent(ack("processing_completed"));
  const s = l.status({ nonce: NONCE });
  assert.deepEqual([s.status, s.ack_seq, s.checkpoint.cursor, s.delivered_to_origin_agent], ["pending", 2, 1, false]);
  assert.equal(l.status({ nonce: NONCE, cursor: 0 }).checkpoint.cursor, 1, "checkpoint never moves back");
  assert.equal(l.status({ nonce: NONCE, cursor: 2 }).status, "completed");
});

test("T12 remote destination without provenance: explicit reason; relayed addendum attestation", (t) => {
  const LEG1 = { host: "peer-o", session: "orchestrator-1" };
  const { l } = setup(t, { via: LEG1 });
  const r = l.appendReply({ nonce: NONCE, text: "remote says ACK", from: LEG1, verified: true });
  assert.equal(r.ok, true);
  const direct = l.appendReply({ nonce: NONCE, text: "hop note", from: HOP, verified: true });
  const [a, b] = l.readReplies({ nonce: NONCE, cursor: 0 }).replies;
  assert.equal(a.attestation, "relayed_by_leg1_destination");
  assert.equal(b.attestation, "intermediary");
  assert.equal(direct.seq, 2);
  const ev = l.recordEvent(ack("processing_completed", { authenticated: false, provenance_unavailable: true }));
  assert.deepEqual([ev.ok, ev.code], [false, "REMOTE_PROVENANCE_UNAVAILABLE"]);
  const s = l.status({ nonce: NONCE, cursor: 2 });
  assert.notEqual(s.stage, "origin_ack_received", "remote stage unproven");
  assert.equal(s.status, "pending");
  assert.deepEqual(s.unproven, { processing_completed: "REMOTE_PROVENANCE_UNAVAILABLE" });
  assert.ok(s.status_reasons.includes("REMOTE_PROVENANCE_UNAVAILABLE"));
});

test("T11 (ledger) late bytes held after the transport TTL; verified → addendum late_after_ttl, counted; unverified → dropped", (t) => {
  const { l, now } = setup(t);
  l.appendReply({ nonce: NONCE, text: "initial", from: DEST, verified: true });
  now.advance(16 * 60 * 1000);
  const text = "ACK after ttl";
  const h = l.holdLate({ nonce: NONCE, sha256: sha(text), text, received_at: new Date(now()).toISOString() });
  assert.equal(h.ok, true);
  assert.equal(l.holdLate({ nonce: NONCE, sha256: sha("x"), text: "y", received_at: new Date(now()).toISOString() }).code, "HASH_MISMATCH");
  l.holdLate({ nonce: NONCE, sha256: sha("forged"), text: "forged", received_at: new Date(now()).toISOString() });
  assert.deepEqual(l.latePending().map((x) => x.sha256), [sha(text), sha("forged")]);
  const p = l.promoteLate({ nonce: NONCE, sha256: sha(text), from: DEST });
  assert.deepEqual([p.ok, p.seq], [true, 2]);
  l.dropLate({ nonce: NONCE, sha256: sha("forged"), reason: "audit_unmatched" });
  assert.deepEqual(l.latePending(), []);
  const r = l.readReplies({ nonce: NONCE, cursor: 1 }).replies;
  assert.deepEqual(r.map((x) => [x.seq, x.text, x.late_after_ttl]), [[2, text, true]]);
  const s = l.status({ nonce: NONCE });
  assert.equal(s.late_after_ttl_count, 1);
  assert.equal(s.rejected.audit_unmatched, 1);
  assert.equal(l.holdLate({ nonce: "e".repeat(32), sha256: sha(text), text, received_at: new Date(now()).toISOString() }).code, "UNKNOWN_CORRELATION");
});

test("authenticated destination refusal is terminal rejected; later replies are still kept as addenda", (t) => {
  const { l } = setup(t);
  assert.equal(l.recordEvent(ack("rejected", { reason: "busy" })).ok, true);
  assert.equal(l.status({ nonce: NONCE }).status, "rejected");
  assert.equal(l.recordEvent(ack("processing_completed")).code, "TERMINAL");
  assert.equal(l.appendReply({ nonce: NONCE, text: "sorry", from: DEST, verified: true }).seq, 1);
});

test("T7 deadline passed without ACK → unknown (never not_delivered); retired record → expired", (t) => {
  const { l, now } = setup(t, { deadline_ms: 1000, retain_ms: 5000 });
  assert.equal(l.status({ nonce: NONCE }).status, "pending");
  now.advance(1001);
  const s = l.status({ nonce: NONCE });
  assert.equal(s.status, "unknown");
  assert.equal(s.deadline_passed, true);
  assert.ok(!JSON.stringify(s).includes("not_delivered"));
  now.advance(5000);
  assert.equal(l.status({ nonce: NONCE }).status, "expired");
  assert.equal(l.status({ nonce: "c".repeat(32) }).status, "not_tracked");
});

test("T9 permission-limited directory: no crash; reads work; mutations return LEDGER_READ_ONLY", { skip: process.platform === "win32" || (process.getuid && process.getuid() === 0) }, (t) => {
  const { dir, l, open } = setup(t);
  l.appendReply({ nonce: NONCE, text: "r1", from: DEST, verified: true });
  l.close();
  fs.chmodSync(dir, 0o500);
  t.after(() => { try { fs.chmodSync(dir, 0o700); } catch { /* removed */ } });
  const ro = open();
  assert.equal(ro.mode, "read_only");
  assert.equal(ro.status({ nonce: NONCE }).reply_count, 1);
  assert.equal(ro.readReplies({ nonce: NONCE, cursor: 0 }).replies[0].text, "r1");
  assert.equal(ro.appendReply({ nonce: NONCE, text: "r2", from: DEST, verified: true }).code, "LEDGER_READ_ONLY");
  assert.equal(ro.recordEvent(ack("processing_completed")).code, "LEDGER_READ_ONLY");
  ro.close();
  // A parent that cannot hold the ledger at all: a LedgerError with a code, not a crash.
  const parent = path.dirname(dir);
  const blocked = path.join(parent, "ro-parent");
  fs.mkdirSync(blocked, { mode: 0o500 });
  t.after(() => { try { fs.chmodSync(blocked, 0o700); } catch { /* removed */ } });
  assert.throws(() => openLedger({ dir: path.join(blocked, "ledger"), resolver }), (e) => e instanceof LedgerError && e.code === "LEDGER_WRITE_FAILED");
});

test("strict lock: a second open is LEDGER_LOCKED; corrupt ledger.json is LEDGER_CORRUPT", (t) => {
  const { dir, l, open } = setup(t);
  assert.throws(() => open(), (e) => e instanceof LedgerError && e.code === "LEDGER_LOCKED");
  l.close();
  fs.writeFileSync(path.join(dir, "ledger.json"), "{", { mode: 0o600 });
  assert.throws(() => open(), (e) => e instanceof LedgerError && e.code === "LEDGER_CORRUPT");
});
