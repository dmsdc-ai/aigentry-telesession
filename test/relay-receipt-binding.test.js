// Relayed-receipt binding (SPEC 2026-10-12, task #2026101110 U1; issues #8, #7): origin-side B0–B9 against a
// SYNTHETIC final daemon (test/helpers/fake-receipts.js). Keys are generated in this process only and never
// persisted. Nothing here is evidence that telepty#100 / #111 / #113 exist (SPEC §2.4, §5).

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { generateKeyPairSync, sign, createHash } from "node:crypto";
import { canonicalJson, RECEIPT_SIG_DOMAIN, verifyReceiptSig, keyIdOf } from "../src/relay/receipt-sig.js";
import { createRouteResolver, RouteError } from "../src/relay/route.js";
import { openLedger, LEDGER_VERSION, APPLIED_RECEIPTS_MAX } from "../src/relay/ledger.js";

const b64url = (buf) => buf.toString("base64url");
function keyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ type: "spki", format: "der" });
  return { privateKey, spki: der.toString("base64"), keyId: `ed25519:${b64url(createHash("sha256").update(der).digest())}` };
}
const BODY = {
  v: 2, correlation_id: "c".repeat(32), origin_inject_id: "I-1", final_inject_id: "J-1", final_session: "w", final_session_epoch: "E1",
  stage: "processing_completed", seq: 1, at: "2026-10-17T00:00:00.000Z", attested_by: { sid: "w", epoch: "E1", generation: 1 },
  delivered_payload_sha256: "d".repeat(64), session_guard: "peer-scope-v1",
};
function signed(k, body = BODY) {
  const b = { ...body, key_id: k.keyId };
  const sig = sign(null, Buffer.from(RECEIPT_SIG_DOMAIN + canonicalJson(b), "utf8"), k.privateKey);
  return { ...b, inject_id: b.final_inject_id, role: "final", auth_basis: "own_bearer", sig: b64url(sig) };
}

// ── §7 step 1: src/relay/receipt-sig.js (verify only) ──

test("step 1 canonicalJson: keys sorted at every level, no whitespace, integers/null/strings/bools only", () => {
  assert.equal(canonicalJson({ b: 1, a: { d: null, c: "x" }, e: [2, "y"] }), '{"a":{"c":"x","d":null},"b":1,"e":[2,"y"]}');
  assert.equal(canonicalJson("é"), '"é"');
  for (const bad of [1.5, undefined, () => 1, NaN, Infinity, 2n]) assert.throws(() => canonicalJson({ x: bad }), /CANONICAL_UNSUPPORTED/);
  assert.equal(RECEIPT_SIG_DOMAIN, "telepty-final-receipt/v1\n");
});

test("step 1 keyIdOf: \"ed25519:\" + base64url(sha256(SPKI DER))", () => {
  const k = keyPair();
  assert.equal(keyIdOf(k.spki), k.keyId);
  assert.match(k.keyId, /^ed25519:[A-Za-z0-9_-]{43}$/);
  assert.equal(keyIdOf("not base64 der"), null);
});

test("step 1 verifyReceiptSig: ok under the pinned key; KEY_UNKNOWN for an unpinned key_id; SIGNATURE_INVALID for a changed body or wrong key", () => {
  const k = keyPair();
  const other = keyPair();
  const pinned = new Map([[k.keyId, k.spki]]);
  const r = signed(k);
  assert.deepEqual(verifyReceiptSig(r, pinned), { ok: true });
  assert.deepEqual(verifyReceiptSig(r, new Map()), { ok: false, code: "KEY_UNKNOWN" });
  assert.deepEqual(verifyReceiptSig(signed(other), pinned), { ok: false, code: "KEY_UNKNOWN" });
  assert.deepEqual(verifyReceiptSig({ ...r, stage: "agent_consumed" }, pinned), { ok: false, code: "SIGNATURE_INVALID" });
  assert.deepEqual(verifyReceiptSig({ ...r, attested_by: { ...r.attested_by, epoch: "E2" } }, pinned), { ok: false, code: "SIGNATURE_INVALID" });
  // Signed by another key but naming the pinned key_id.
  const forged = signed(other);
  assert.deepEqual(verifyReceiptSig({ ...forged, key_id: k.keyId, sig: signed(other, { ...BODY }).sig }, pinned), { ok: false, code: "SIGNATURE_INVALID" });
  assert.deepEqual(verifyReceiptSig({ ...r, sig: "!!" }, pinned), { ok: false, code: "SIGNATURE_INVALID" });
  assert.deepEqual(verifyReceiptSig({ ...r, seq: 1.5 }, pinned), { ok: false, code: "SIGNATURE_INVALID" });
  // Fields outside the signed body (inject_id, role, auth_basis, sig) are not part of the signed bytes.
  assert.deepEqual(verifyReceiptSig({ ...r, auth_basis: "x" }, pinned), { ok: true });
});

// ── §7 step 2: src/relay/route.js receipt_keys, receiptKeys, peerOfKey ──

test("step 2 resolver: receipt_keys pinned per peer → receiptKeys(host) map (any locator form) and peerOfKey(key_id); none pinned → empty map", () => {
  const a = keyPair();
  const b = keyPair();
  const r = createRouteResolver([
    { peer_id: "local", locators: ["local"] },
    { peer_id: "mac", locators: ["mac", "10.0.0.9"], receipt_keys: [{ key_id: a.keyId, public_key_spki_b64: a.spki }, { key_id: b.keyId, public_key_spki_b64: b.spki }] },
  ]);
  assert.deepEqual([...r.receiptKeys("mac")], [[a.keyId, a.spki], [b.keyId, b.spki]]);
  assert.deepEqual([...r.receiptKeys("10.0.0.9")], [[a.keyId, a.spki], [b.keyId, b.spki]]);
  assert.deepEqual([...r.receiptKeys("local")], []);
  assert.deepEqual([...r.receiptKeys("nowhere")], []);
  assert.equal(r.peerOfKey(a.keyId), "mac");
  assert.equal(r.peerOfKey("ed25519:" + "x".repeat(43)), null);
  assert.equal(r.canonical("10.0.0.9"), "mac", "existing resolver behaviour unchanged");
});

test("N-3 key_id ≠ fingerprint of its SPKI, one key_id under two peers, and malformed receipt_keys → ROUTE_TABLE_INVALID at construction", () => {
  const a = keyPair();
  const b = keyPair();
  const peer = (id, keys) => ({ peer_id: id, locators: [id], receipt_keys: keys });
  const bad = [
    [peer("mac", [{ key_id: b.keyId, public_key_spki_b64: a.spki }])],
    [peer("mac", [{ key_id: a.keyId, public_key_spki_b64: a.spki }]), peer("linux", [{ key_id: a.keyId, public_key_spki_b64: a.spki }])],
    [peer("mac", [{ key_id: a.keyId, public_key_spki_b64: a.spki }, { key_id: a.keyId, public_key_spki_b64: a.spki }])],
    [peer("mac", [{ key_id: "rsa:abc", public_key_spki_b64: a.spki }])],
    [peer("mac", [{ key_id: a.keyId, public_key_spki_b64: a.spki + "A".repeat(128) }])],
    [peer("mac", Array.from({ length: 5 }, () => { const k = keyPair(); return { key_id: k.keyId, public_key_spki_b64: k.spki }; }))],
    [peer("mac", "not-a-list")],
    [peer("mac", [null])],
  ];
  for (const table of bad) assert.throws(() => createRouteResolver(table), (e) => e instanceof RouteError && e.code === "ROUTE_TABLE_INVALID");
  assert.doesNotThrow(() => createRouteResolver([peer("mac", [{ key_id: a.keyId, public_key_spki_b64: a.spki }]), peer("linux", [])]));
});

// ── §7 step 3: src/relay/ledger.js origin_inject_id, applied_receipts (bounded 16, same commit) ──

const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const NONCE = "1".repeat(32);
const CID = "c".repeat(32);
const LEG1 = { host: "local", session: "target-1" };
const DEST = { host: "mac", session: "w" };

function tmpLedger(t, opts = {}) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "telesession-rb-"));
  const dir = path.join(base, "ledger");
  let l = openLedger({ dir, ...opts });
  t.after(() => { l.close(); fs.rmSync(base, { recursive: true, force: true }); });
  return { get l() { return l; }, dir, reopen() { l.close(); l = openLedger({ dir, ...opts }); return l; } };
}
function relayedRecord(l, extra = {}) {
  return l.createRequest({
    nonce: NONCE, correlation_id: CID, request_id: null, origin: { host: "local", session: "inbox" }, destination: DEST, via: LEG1, via_generation: "ep",
    reply_to: { host: "local", session: "inbox" }, generation: null, payload_sha256: sha("p"), deadline_ms: 60000, origin_inject_id: "I-1", ...extra,
  });
}
const destEvent = (stage, extra = {}) => ({
  nonce: NONCE, stage, payload_sha256: sha("p"), correlation_id: CID, from: DEST, hop: "destination", generation: "E1", learn_generation: true, authenticated: true, ...extra,
});

test("step 3 createRequest stores origin_inject_id (validated); LEDGER_VERSION stays 1", (t) => {
  const h = tmpLedger(t);
  assert.equal(LEDGER_VERSION, 1);
  assert.equal(relayedRecord(h.l, { origin_inject_id: "bad id" }).code, "INVALID_ARGUMENT");
  assert.equal(relayedRecord(h.l).ok, true);
  assert.equal(h.l.record(NONCE).origin_inject_id, "I-1");
  assert.equal(h.reopen().record(NONCE).origin_inject_id, "I-1", "persisted");
});

test("step 3 recordEvent receipt_identity: appended in the same commit as the event; a present identity is deduplicated; 16 bound → RECEIPT_LIMIT, never evicted", (t) => {
  const h = tmpLedger(t);
  relayedRecord(h.l);
  const id = (n) => sha(`mac/J-${n}/processing_completed`);
  const apply = (n) => {
    const text = `reply ${n}`;
    const a = h.l.appendReply({ nonce: NONCE, text, from: DEST, verified: true, correlation_id: CID });
    return h.l.recordEvent(destEvent("processing_completed", { reply_seq: a.seq, reply_sha256: sha(text), receipt_identity: id(n) }));
  };
  assert.equal(apply(1).applied, true);
  assert.deepEqual(h.l.record(NONCE).applied_receipts, [id(1)]);
  const dup = h.l.recordEvent(destEvent("agent_consumed", { receipt_identity: id(1) }));
  assert.deepEqual([dup.ok, dup.applied, dup.deduplicated], [true, false, true], "identity present → deduplicated, even for another event");
  assert.deepEqual(h.l.recordEvent(destEvent("agent_consumed", { receipt_identity: id(1), check_only: true })).deduplicated, true);
  for (let n = 2; n <= APPLIED_RECEIPTS_MAX; n++) assert.equal(apply(n).applied, true, `identity ${n}`);
  assert.equal(APPLIED_RECEIPTS_MAX, 16);
  const before = h.l.record(NONCE);
  assert.deepEqual(h.l.recordEvent(destEvent("processing_completed", { reply_sha256: sha("x"), receipt_identity: id(17) })), { ok: false, code: "RECEIPT_LIMIT" });
  assert.deepEqual(h.l.recordEvent(destEvent("processing_completed", { reply_sha256: sha("x"), receipt_identity: id(17), check_only: true })), { ok: false, code: "RECEIPT_LIMIT" });
  assert.deepEqual(h.l.record(NONCE), before, "no state change at the bound");
  assert.equal(h.l.recordEvent(destEvent("agent_consumed", { receipt_identity: id(3) })).deduplicated, true, "an applied identity still dedupes at the bound");
  assert.equal(h.l.recordEvent(destEvent("agent_consumed", { receipt_identity: "nothex" })).code, "INVALID_ARGUMENT");
});

test("step 3 a tampered origin_inject_id or applied_receipts in ledger.json → LEDGER_CORRUPT on open", (t) => {
  const h = tmpLedger(t);
  relayedRecord(h.l);
  h.l.close();
  const file = path.join(h.dir, "ledger.json");
  const good = fs.readFileSync(file, "utf8");
  for (const patch of [{ origin_inject_id: "bad id" }, { origin_inject_id: 7 }, { applied_receipts: ["x"] }, { applied_receipts: "x" },
    { applied_receipts: Array.from({ length: 17 }, (_, i) => sha(String(i))) }]) {
    const st = JSON.parse(good);
    Object.assign(st.records[NONCE], patch);
    fs.writeFileSync(file, JSON.stringify(st), { mode: 0o600 });
    assert.throws(() => openLedger({ dir: h.dir }), (e) => e.code === "LEDGER_CORRUPT", JSON.stringify(patch));
  }
  const st = JSON.parse(good);
  Object.assign(st.records[NONCE], { origin_inject_id: null, applied_receipts: Array.from({ length: 16 }, (_, i) => sha(String(i))) });
  fs.writeFileSync(file, JSON.stringify(st), { mode: 0o600 });
  h.reopen();
  assert.equal(h.l.record(NONCE).applied_receipts.length, 16);
});
