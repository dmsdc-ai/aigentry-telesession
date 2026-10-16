// Relayed-receipt binding (SPEC 2026-10-12, task #2026101110 U1; issues #8, #7): origin-side B0–B9 against a
// SYNTHETIC final daemon (test/helpers/fake-receipts.js). Keys are generated in this process only and never
// persisted. Nothing here is evidence that telepty#100 / #111 / #113 exist (SPEC §2.4, §5).

import { describe, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { generateKeyPairSync, sign, createHash } from "node:crypto";
import { canonicalJson, RECEIPT_SIG_DOMAIN, verifyReceiptSig, keyIdOf } from "../src/relay/receipt-sig.js";
import { createRouteResolver, RouteError } from "../src/relay/route.js";
import { openLedger, LEDGER_VERSION, APPLIED_RECEIPTS_MAX } from "../src/relay/ledger.js";
import { applyReceipts, createProvenanceAdapter } from "../src/relay/adapters.js";
import { normalizeConfig, createTeleptyTransport } from "../src/index.js";
import { makeSandbox, readJson, writeStateDir } from "./helpers/fault-fs.js";
import { startFakeTelepty } from "./helpers/fake-telepty.js";
import { FAKE_PROOF_BASIS } from "./helpers/fake-receipts.js";

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

// ── §7 step 4: src/relay/adapters.js path S (B0–B9, B6g, no provenance call) vs path D (unchanged) ──

const THROWING_PROVENANCE = Object.freeze({ verify() { throw new Error("path S must not consult the provenance adapter"); } });
function v2(k, over = {}, attested = null) {
  const body = { ...BODY, correlation_id: CID, origin_inject_id: "I-1", final_inject_id: "J-1", stage: "agent_consumed", ...over };
  if (attested) body.attested_by = { ...body.attested_by, ...attested };
  return signed(k, body);
}
function pathS(t, { keys = [], extra } = {}) {
  const h = tmpLedger(t);
  relayedRecord(h.l, extra);
  const table = [{ peer_id: "local", locators: ["local"] }, { peer_id: "mac", locators: ["mac"], receipt_keys: keys.map((k) => ({ key_id: k.keyId, public_key_spki_b64: k.spki })) }];
  return { h, apply: (receipts, o = {}) => applyReceipts({ ledger: h.l, nonce: NONCE, receipts, provenance: THROWING_PROVENANCE, pinnedKeys: createRouteResolver(o.table || table), localPeer: "local" }) };
}
const OUT = (o) => ({ applied: 0, unproven: 0, deduplicated: 0, refused: {}, ...o });

test("step 4 path S: a v2 receipt signed under the key pinned for O's own name binds; reply names I, J, final_session, key_id; provenance never consulted", (t) => {
  const k = keyPair();
  const { h, apply } = pathS(t, { keys: [k] });
  assert.deepEqual(apply([v2(k), v2(k, { stage: "processing_completed", seq: 2 })]), OUT({ applied: 2 }));
  const st = h.l.status({ nonce: NONCE });
  assert.deepEqual([st.stage, st.reply_count, st.unproven], ["origin_ack_received", 1, {}]);
  const [entry] = h.l.readReplies({ nonce: NONCE, cursor: 0 }).replies;
  const body = JSON.parse(entry.text.split("\n").slice(1).join("\n"));
  assert.deepEqual([entry.attestation, entry.from], ["destination", DEST]);
  assert.deepEqual([body.origin_inject_id, body.final_inject_id, body.final_session, body.key_id, body.host], ["I-1", "J-1", "w", k.keyId, "mac"]);
  assert.equal(h.l.record(NONCE).applied_receipts.length, 2);
});

test("step 4 path S refusal order B0–B7: each refuses with its code, changes no stage and sets no marker", (t) => {
  const k = keyPair();
  const other = keyPair();
  const { h, apply } = pathS(t, { keys: [k] });
  const v1 = { correlation_id: CID, inject_id: "J-1", stage: "agent_consumed", role: "final", seq: 1, at: "x", attested_by: { sid: "w", epoch: "E1" }, auth_basis: "own_bearer" };
  const cases = [
    [{ junk: true }, "INVALID_RECEIPT"],
    [v1, "SIGNATURE_REQUIRED"],
    [{ ...v2(k), inject_id: "J-2" }, "INVALID_RECEIPT"],
    [{ ...v2(k), v: 3 }, "INVALID_RECEIPT"],
    [v2(k, { correlation_id: "f".repeat(32) }), "CORRELATION_MISMATCH"],
    [{ ...v2(k), role: "hop" }, "HOP_FACT_ONLY"],
    [{ ...v2(k), auth_basis: "daemon_token" }, "NOT_OWN_BEARER"],
    [v2(k, { origin_inject_id: "I-2" }), "INJECT_MISMATCH"],
    [v2(k, { origin_inject_id: null }), "INJECT_MISMATCH"],
    [v2(other), "KEY_UNKNOWN"],
    [{ ...v2(k), stage: "processing_completed" }, "SIGNATURE_INVALID"],
    [v2(k, { session_guard: null }), "F_GUARD_ABSENT"],
    [v2(k, { session_guard: "other" }), "F_GUARD_ABSENT"],
    [v2(k, { final_session: "x" }, { sid: "x" }), "SOURCE_MISMATCH"],
    [v2(k, {}, { sid: "x" }), "SOURCE_MISMATCH"],
    [v2(k, {}, { epoch: "E2" }), "SOURCE_MISMATCH"],
  ];
  for (const [i, [r, code]] of cases.entries()) assert.deepEqual(apply([r]), OUT({ refused: { [code]: 1 } }), `${i} ${code}`);
  const st = h.l.status({ nonce: NONCE });
  assert.deepEqual([st.stage, st.unproven, st.reply_count, st.rejected], ["unknown", {}, 0, {}]);
});

test("step 4 path S: B3 INJECT_UNKNOWN without rec.origin_inject_id; B5 SOURCE_MISMATCH for a key pinned under another peer; terminal → STALE_AFTER_TERMINAL; B9 dedupe", (t) => {
  const k = keyPair();
  const g = keyPair();
  const noI = pathS(t, { keys: [k], extra: { origin_inject_id: undefined } });
  assert.deepEqual(noI.apply([v2(k)]), OUT({ refused: { INJECT_UNKNOWN: 1 } }));
  const { h, apply } = pathS(t, { keys: [k] });
  const table = [{ peer_id: "local", locators: ["local"] }, { peer_id: "mac", locators: ["mac"], receipt_keys: [{ key_id: k.keyId, public_key_spki_b64: k.spki }] },
    { peer_id: "linux", locators: ["linux"], receipt_keys: [{ key_id: g.keyId, public_key_spki_b64: g.spki }] }];
  assert.deepEqual(apply([v2(g)], { table }), OUT({ refused: { SOURCE_MISMATCH: 1 } }));
  assert.deepEqual(apply([v2(k), v2(k), v2(k, { seq: 9, at: "later" })]), OUT({ applied: 1, deduplicated: 2 }));
  assert.deepEqual(apply([v2(k, { stage: "rejected", final_inject_id: "J-2" })]), OUT({ applied: 1 }));
  assert.equal(h.l.status({ nonce: NONCE }).status, "rejected");
  assert.deepEqual(apply([v2(k, { stage: "processing_completed", final_inject_id: "J-3" })]), OUT({ refused: { STALE_AFTER_TERMINAL: 1 } }));
});

test("step 4 path selection by record: a local direct record (via null, destination local) keeps the 8016f25 rule even for a v2-shaped receipt", (t) => {
  const k = keyPair();
  const h = tmpLedger(t);
  h.l.createRequest({ nonce: NONCE, correlation_id: CID, request_id: null, origin: { host: "local", session: "inbox" }, destination: { host: "local", session: "w" },
    reply_to: { host: "local", session: "inbox" }, generation: "E1", payload_sha256: sha("p"), deadline_ms: 60000, origin_inject_id: "J-1" });
  const r = { ...v2(k, { origin_inject_id: "ignored" }), sig: "A".repeat(86) };
  // No allowlisted provenance → the 8016f25 unproven path (marker), and the bad signature is never evaluated.
  assert.deepEqual(applyReceipts({ ledger: h.l, nonce: NONCE, receipts: [r], injectIds: ["J-1"], pinnedKeys: createRouteResolver([{ peer_id: "local", locators: ["local"] }]) }), OUT({ unproven: 1 }));
  assert.deepEqual(applyReceipts({ ledger: h.l, nonce: NONCE, receipts: [{ ...r, inject_id: "J-9", final_inject_id: "J-9" }], injectIds: ["J-1"] }), OUT({ refused: { INJECT_MISMATCH: 1 } }));
});

// ── §7 step 5: src/transports/telepty.js wiring (origin_inject_id, known set, pinnedKeys, receipt_refusals) ──

const NO_LOOPBACK = process.env.TELESESSION_TEST_NO_LOOPBACK === "1"
  ? "NOTRUN: loopback bind/connect not permitted here (TELESESSION_TEST_NO_LOOPBACK=1)" : false;

// One origin (O): fake daemon + store + ledger + transport; `receipts` is a settable list served by the adapter.
async function originSide(t, { resolver, prefix = "ts-rb-" } = {}) {
  const sb = makeSandbox(prefix);
  const fake = await startFakeTelepty();
  const served = new Map();
  const adapter = { fetch: async (c) => structuredClone(served.get(c) || []), consumption: async () => ({ status: "unknown" }) };
  const ledgerDir = path.join(sb.root, "ledger");
  const open = [];
  const make = ({ ledger = true } = {}) => {
    const l = ledger ? openLedger({ dir: ledgerDir }) : null;
    const cfg = normalizeConfig({ teleptyUrl: fake.origin, token: fake.token, targets: ["target-1"], inboxPrefix: "tsr", stateDir: sb.stateDir });
    const tr = createTeleptyTransport(cfg, sb.seam(), {
      ...(l ? { ledger: l } : {}), receipts: adapter, provenance: createProvenanceAdapter({ allowedBases: [FAKE_PROOF_BASIS] }), ...(resolver ? { resolver } : {}),
    });
    const o = { tr, l };
    open.push(o);
    return o;
  };
  const closeOne = async (o) => { await o.tr.close(); if (o.l) o.l.close(); open.splice(open.indexOf(o), 1); };
  t.after(async () => { for (const o of [...open]) await closeOne(o); await fake.close(); sb.remove(); });
  const ageStore = (key, ms) => {
    const state = readJson(path.join(sb.stateDir, "state.json"));
    for (const k of ["created_at", "sent_at", "expires_at", "retain_until"]) state.requests[key][k] -= ms;
    fs.unlinkSync(path.join(sb.stateDir, "state.json"));
    writeStateDir(sb.stateDir, state);
  };
  return { sb, fake, served, make, closeOne, ageStore };
}
const v1Direct = (s, epoch, stage, seq) => ({ correlation_id: s.correlation_id, inject_id: s.inject_id, stage, role: "final", seq, at: "2026-10-17T00:00:00.000Z",
  attested_by: { host_label: "local", sid: "target-1", epoch }, auth_basis: "own_bearer", verified_sender_host: "local", sender_proof: { basis: FAKE_PROOF_BASIS } });

describe("step 5 transport wiring (loopback fake telepty)", { skip: NO_LOOPBACK }, () => {
  test("step 5 openLedgerRecord persists origin_inject_id = the send's inject_id", async (t) => {
    const o = await originSide(t);
    const { tr, l } = o.make();
    const s = await tr.send({ target: "target-1", text: "job", request_id: "w-1" });
    assert.equal(s.ok, true, JSON.stringify(s));
    assert.equal(l.record(s.nonce).origin_inject_id, s.inject_id);
  });

  test("B-D2 direct after the store purged the request (ledger live): still bound through rec.origin_inject_id", async (t) => {
    const o = await originSide(t);
    const a = o.make();
    const s = await a.tr.send({ target: "target-1", text: "job", request_id: "bd2" });
    assert.equal(s.ok, true, JSON.stringify(s));
    const epoch = o.fake.sessions.get("target-1").epoch;
    await o.closeOne(a);
    o.ageStore("r:bd2", 86400000 + 16 * 60 * 1000);
    const b = o.make();
    assert.equal((await b.tr.readReply({ nonce: s.nonce })).error.code, "NONCE_EXPIRED", "store record purged");
    o.served.set(s.correlation_id, [v1Direct(s, epoch, "agent_consumed", 1), v1Direct(s, epoch, "processing_completed", 2)]);
    const st = await b.tr.requestStatus({ nonce: s.nonce });
    assert.deepEqual([st.stage, st.final_ack_seq, st.receipt_refusals], ["origin_ack_received", 1, undefined], JSON.stringify(st));
  });

  test("step 5 reconcileLedger: a reconstructed record carries the store's inject_id as origin_inject_id", async (t) => {
    const o = await originSide(t);
    const a = o.make({ ledger: false });
    const s = await a.tr.send({ target: "target-1", text: "job", request_id: "rc-0" });
    assert.equal(s.ok, true, JSON.stringify(s));
    await o.closeOne(a);
    const b = o.make();
    assert.deepEqual([b.l.record(s.nonce).reconstructed, b.l.record(s.nonce).origin_inject_id], [true, s.inject_id]);
  });

  test("step 5 request_status: pinnedKeys from the configured resolver bind a relayed v2 receipt; receipt_refusals = last pull only, omitted when empty", async (t) => {
    const k = keyPair();
    const resolver = createRouteResolver([{ peer_id: "local", locators: ["local"] }, { peer_id: "mac", locators: ["mac"], receipt_keys: [{ key_id: k.keyId, public_key_spki_b64: k.spki }] }]);
    const o = await originSide(t, { resolver });
    const { tr } = o.make();
    const s = await tr.send({ target: "target-1", text: "job", request_id: "ps-1", destination: DEST });
    assert.equal(s.ok, true, JSON.stringify(s));
    const rc = (stage, extra = {}) => v2(k, { correlation_id: s.correlation_id, origin_inject_id: s.inject_id, final_inject_id: "J-1", stage, ...extra });
    const v1 = { correlation_id: s.correlation_id, inject_id: "J-1", stage: "agent_consumed", role: "final", seq: 1, at: "x", attested_by: { sid: "w", epoch: "E1" }, auth_basis: "own_bearer" };
    o.served.set(s.correlation_id, [v1, rc("agent_consumed", { session_guard: null })]);
    for (let i = 0; i < 2; i++) {
      const st = await tr.requestStatus({ nonce: s.nonce });
      assert.deepEqual([st.stage, st.receipt_refusals], ["transport_accepted", { SIGNATURE_REQUIRED: 1, F_GUARD_ABSENT: 1 }], `poll ${i}: ${JSON.stringify(st)}`);
    }
    o.served.set(s.correlation_id, [rc("agent_consumed"), rc("processing_completed", { seq: 2 })]);
    const st = await tr.requestStatus({ nonce: s.nonce });
    assert.deepEqual([st.stage, st.receipt_refusals, st.replies[0].attestation], ["origin_ack_received", undefined, "destination"], JSON.stringify(st));
    assert.equal((await tr.requestStatus({ nonce: s.nonce, cursor: st.next_cursor })).status, "completed");
  });
});
