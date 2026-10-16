// Relayed-receipt binding (SPEC 2026-10-12, task #2026101110 U1; issues #8, #7): origin-side B0–B9 against a
// SYNTHETIC final daemon (test/helpers/fake-receipts.js). Keys are generated in this process only and never
// persisted. Nothing here is evidence that telepty#100 / #111 / #113 exist (SPEC §2.4, §5).

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, createHash } from "node:crypto";
import { canonicalJson, RECEIPT_SIG_DOMAIN, verifyReceiptSig, keyIdOf } from "../src/relay/receipt-sig.js";
import { createRouteResolver, RouteError } from "../src/relay/route.js";

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
