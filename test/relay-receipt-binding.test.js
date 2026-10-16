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
import { createRelayRunner } from "../src/relay/runner.js";
import { normalizeConfig, createTeleptyTransport } from "../src/index.js";
import { makeSandbox, readJson, writeStateDir } from "./helpers/fault-fs.js";
import { startFakeTelepty } from "./helpers/fake-telepty.js";
import { FAKE_PROOF_BASIS, createFakeReceiptSeam, assertDistinctNames } from "./helpers/fake-receipts.js";
import { validateRelayContext } from "./helpers/relay-context.js";

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
async function originSide(t, { resolver, prefix = "ts-rb-", fakeOpts = {}, receipts } = {}) {
  const sb = makeSandbox(prefix);
  const fake = await startFakeTelepty(fakeOpts);
  const served = new Map();
  const adapter = receipts || { fetch: async (c) => structuredClone(served.get(c) || []), consumption: async () => ({ status: "unknown" }) };
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

// ── §7 step 6: §6 rows against the synthetic F (fake-receipts.js), fake-telepty.js (fake #111) and relay-context.js ──
// Names (BLK-1): O calls F "mac", R calls F "macbook", F's self label is "host-m"; O is "local" at O, "kkoma" at R.

const O_F = "mac";
const R_F = "macbook";
const F_LABEL = "host-m";
const R_O = "kkoma";
const LOCAL_PEER = { peer_id: "local", locators: ["local"] };
const envText = (sid, correlation_id = CID) => JSON.stringify({ v: 1, correlation_id, final: { host_label: R_F, sid, epoch: "E1" } });
const finalCtx = (o = {}) => ({ v: 2, leg: "final", correlation_id: CID, origin_inject_id: "I-1", final_session: "w", hop: 1, ...o });

function record(l, { nonce, correlation_id, origin_inject_id, destination = DEST, via = LEG1, generation = null }) {
  const c = l.createRequest({
    nonce, correlation_id, request_id: null, origin: { host: "local", session: "inbox" }, destination, via, via_generation: via ? "ep" : null,
    reply_to: { host: "local", session: "inbox" }, generation, payload_sha256: sha("p"), deadline_ms: 60000, origin_inject_id,
  });
  assert.equal(c.ok, true, JSON.stringify(c));
}
// O's ledger with the relayed record (C, I) for mac/w and a seam F with D = "w" (epoch E1) behind it.
function world(t, seamOpts = {}, { ledgerOpts } = {}) {
  assertDistinctNames(O_F, R_F, F_LABEL);
  const F = createFakeReceiptSeam({ selfLabel: F_LABEL, mode: "unproven", ...seamOpts });
  const D = F.finalDaemon({ sid: "w", epoch: "E1" });
  const h = tmpLedger(t, ledgerOpts);
  relayedRecord(h.l);
  const pinned = (peer = O_F) => createRouteResolver([LOCAL_PEER, ...(peer === O_F ? [] : [{ peer_id: O_F, locators: [O_F] }]), F.publicPeerEntry(peer, [peer])]);
  const apply = (receipts, { keys = pinned(), nonce = NONCE } = {}) => applyReceipts({ ledger: h.l, nonce, receipts, provenance: THROWING_PROVENANCE, pinnedKeys: keys, localPeer: "local" });
  const relay = async (ctx = finalCtx(), sid = "w") => {
    const r = await D.send({ session: sid, text: envText(sid, ctx.correlation_id), relay_context: ctx });
    assert.equal(r.ok, true, JSON.stringify(r));
    return r.transport_id;
  };
  const completed = (nonce = NONCE) => {
    const st = h.l.status({ nonce });
    return st.stage === "origin_ack_received" && h.l.status({ nonce, cursor: st.cursor }).status === "completed";
  };
  return { F, D, h, l: h.l, pinned, apply, relay, completed };
}
const pendingNoMarker = (l, nonce = NONCE) => {
  const st = l.status({ nonce });
  assert.deepEqual([st.status, st.unproven, st.reply_count, st.stages.processing_completed], ["pending", {}, 0, "unknown"], JSON.stringify(st));
};

async function daemonCall(fake, method, p, body) {
  const res = await fetch(fake.origin + p, { method, headers: { "x-telepty-token": fake.token, "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: res.status, body: await res.json() };
}

describe("§6 rows: binding through the synthetic F (isolated)", { skip: NO_LOOPBACK }, () => {
  test("B-R1 relayed: O → R (fake-telepty) → R's relay send with {C, I} → fake #111 → seam F; distinct names; applied 2 → origin_ack_received → completed", async (t) => {
    assertDistinctNames(O_F, R_F, F_LABEL);
    const F = createFakeReceiptSeam({ selfLabel: F_LABEL, mode: "unproven" });
    const D = F.finalDaemon({ sid: "w", epoch: "E1" });
    const resolver = createRouteResolver([LOCAL_PEER, F.publicPeerEntry(O_F, [O_F])]);
    const o = await originSide(t, { resolver, receipts: F.adapter, fakeOpts: { forward111: true, peers: { [R_F]: D } } });
    const { tr } = o.make();
    const s = await tr.send({ target: "target-1", text: "build and ACK", request_id: "br1", destination: DEST });
    assert.equal(s.ok, true, JSON.stringify(s));
    // R reads the wire header (C, reply-to) and looks I up at its own daemon (interim §1.2(b): verified sender = O's inbox).
    const m = /^\[telesession nonce=([0-9a-f]{32}) reply-to=(\S+) correlation=([0-9a-f]{32})\]\n/.exec(o.fake.sessions.get("target-1").delivered.at(-1).prompt);
    const rows = (await daemonCall(o.fake, "GET", "/api/injects?to=target-1")).body.injects.filter((r) => r.verified_sender_sid === m[2]);
    assert.equal(rows.length, 1);
    const I = rows[0].inject_id;
    assert.deepEqual([I, m[3]], [s.inject_id, s.correlation_id]);
    // R's relay send through the fake #111 on R's daemon, R's own name for F; final context (V3).
    const ctx = { v: 2, leg: "final", correlation_id: m[3], origin_inject_id: I, final_session: "w", hop: 1 };
    assert.deepEqual(validateRelayContext(ctx, { resolvedSid: "w" }), { ok: true, variant: "final" });
    const fw = await daemonCall(o.fake, "POST", `/api/sessions/${encodeURIComponent(`w@${R_F}`)}/inject`, { prompt: envText("w", m[3]), exact_target: true, relay_context: ctx });
    assert.equal(fw.status, 200, JSON.stringify(fw.body));
    const J = fw.body.inject_id;
    assert.deepEqual([fw.body.routing_receipt.stage, o.fake.forwards[0].relay_context], ["transport_accepted", ctx], "#111 forwards the context verbatim");
    assert.equal((await tr.requestStatus({ nonce: s.nonce })).stage, "transport_accepted", "the routing receipt is hop evidence only (H2)");
    F.attest(J, "agent_consumed");
    F.attest(J, "processing_completed");
    const st = await tr.requestStatus({ nonce: s.nonce });
    assert.deepEqual([st.stage, st.receipt_refusals, st.replies[0].attestation, st.unproven], ["origin_ack_received", undefined, "destination", {}], JSON.stringify(st));
    const body = JSON.parse(st.replies[0].text.split("\n").slice(1).join("\n"));
    assert.deepEqual([body.origin_inject_id, body.final_inject_id, body.host], [I, J, O_F]);
    assert.equal((await tr.requestStatus({ nonce: s.nonce, cursor: st.next_cursor })).status, "completed");
  });

  test("B-R2 relayed, no pinned key: KEY_UNKNOWN ×2; pending; no marker; never evaluated as v1 (I-8)", async (t) => {
    const w = world(t);
    const J = await w.relay();
    const rs = [w.F.attest(J, "agent_consumed"), w.F.attest(J, "processing_completed")];
    assert.deepEqual(w.apply(rs, { keys: createRouteResolver([LOCAL_PEER, { peer_id: O_F, locators: [O_F] }]) }), OUT({ refused: { KEY_UNKNOWN: 2 } }));
    pendingNoMarker(w.l);
  });

  test("B-R3 relayed, legacy v1 receipt (unsigned) → SIGNATURE_REQUIRED; pending", async (t) => {
    const w = world(t);
    const J = await w.relay();
    assert.deepEqual(w.apply([w.F.unsigned(J, "processing_completed")]), OUT({ refused: { SIGNATURE_REQUIRED: 1 } }));
    pendingNoMarker(w.l);
  });

  test("N-1 names differ at every node: completed; the receipt carries no host name; control: key pinned under another O peer → SOURCE_MISMATCH", async (t) => {
    const w = world(t);
    const rTable = createRouteResolver([{ peer_id: R_O, locators: [R_O] }, { peer_id: R_F, locators: [R_F] }]);
    assert.equal(rTable.resolve({ host: R_F, session: "w" }).peer_id, R_F, "R routes by its own name for F");
    const J = await w.relay();
    const rc = w.F.attest(J, "processing_completed");
    for (const name of [O_F, R_F, F_LABEL, R_O, "local"]) assert.equal(Object.values(rc).includes(name), false, name);
    assert.equal(Object.keys(rc).some((k) => /host/.test(k)), false);
    assert.deepEqual(w.apply([rc], { keys: w.pinned("linux") }), OUT({ refused: { SOURCE_MISMATCH: 1 } }));
    assert.deepEqual(w.apply([rc]), OUT({ applied: 1 }));
    assert.equal(w.completed(), true);
  });

  test("N-2 R misroutes to another daemon G (also has `w`, key pinned at O under linux) → SOURCE_MISMATCH; F's genuine receipt still binds", async (t) => {
    const w = world(t);
    const G = createFakeReceiptSeam({ selfLabel: "host-g", mode: "unproven" });
    const GD = G.finalDaemon({ sid: "w", epoch: "E1" });
    const keys = createRouteResolver([LOCAL_PEER, w.F.publicPeerEntry(O_F, [O_F]), G.publicPeerEntry("linux", ["linux"])]);
    const Jg = (await GD.send({ session: "w", text: envText("w"), relay_context: finalCtx() })).transport_id;
    assert.deepEqual(w.apply([G.attest(Jg, "processing_completed")], { keys }), OUT({ refused: { SOURCE_MISMATCH: 1 } }));
    pendingNoMarker(w.l);
    const J = await w.relay();
    assert.deepEqual(w.apply([w.F.attest(J, "processing_completed")], { keys }), OUT({ applied: 1 }));
  });

  test("X1 forged by a relayer: unpinned key → KEY_UNKNOWN; pinned key_id with the wrong key → SIGNATURE_INVALID; status unchanged", async (t) => {
    const w = world(t);
    const J = await w.relay();
    assert.deepEqual(w.apply([w.F.forge(J, "processing_completed")]), OUT({ refused: { KEY_UNKNOWN: 1 } }));
    assert.deepEqual(w.apply([w.F.forge(J, "processing_completed", { keyId: w.F.keyId() })]), OUT({ refused: { SIGNATURE_INVALID: 1 } }));
    pendingNoMarker(w.l);
  });

  test("X2 relayer-modified: tamper(stage) on an agent_consumed receipt → SIGNATURE_INVALID", async (t) => {
    const w = world(t);
    const J = await w.relay();
    assert.deepEqual(w.apply([w.F.tamper(w.F.attest(J, "agent_consumed"), "stage", "processing_completed")]), OUT({ refused: { SIGNATURE_INVALID: 1 } }));
    pendingNoMarker(w.l);
  });

  test("X3 re-targeted to another request: record 1's receipt under record 2 → CORRELATION_MISMATCH; retarget(C2) → INJECT_MISMATCH; record 2 unchanged", async (t) => {
    const w = world(t);
    const N2 = "2".repeat(32);
    const C2 = "e".repeat(32);
    record(w.l, { nonce: N2, correlation_id: C2, origin_inject_id: "I-2" });
    const r1 = w.F.attest(await w.relay(), "processing_completed");
    assert.deepEqual(w.apply([r1], { nonce: N2 }), OUT({ refused: { CORRELATION_MISMATCH: 1 } }));
    assert.deepEqual(w.apply([w.F.retarget(r1, { correlation_id: C2 })], { nonce: N2 }), OUT({ refused: { INJECT_MISMATCH: 1 } }));
    pendingNoMarker(w.l, N2);
  });

  test("X4 re-targeted endpoint: retarget(final_session) → SOURCE_MISMATCH", async (t) => {
    const w = world(t);
    const r = w.F.attest(await w.relay(), "processing_completed");
    assert.deepEqual(w.apply([w.F.retarget(r, { final_session: "x" })]), OUT({ refused: { SOURCE_MISMATCH: 1 } }));
    pendingNoMarker(w.l);
  });

  test("X5 cross-origin replay: a genuine F receipt for another origin's record (its own C and I) → CORRELATION_MISMATCH", async (t) => {
    const w = world(t);
    const J = await w.relay(finalCtx({ correlation_id: "9".repeat(32), origin_inject_id: "other-origin-I" }));
    assert.deepEqual(w.apply([w.F.attest(J, "processing_completed")]), OUT({ refused: { CORRELATION_MISMATCH: 1 } }));
    pendingNoMarker(w.l);
  });

  test("X6 replay / resign / two pulls → deduplicated; one reply, one seq; ack_seq unchanged", async (t) => {
    const w = world(t);
    const r = w.F.attest(await w.relay(), "processing_completed");
    assert.deepEqual(w.apply([r]), OUT({ applied: 1 }));
    const before = w.l.status({ nonce: NONCE });
    assert.deepEqual(w.apply([w.F.replay(r), w.F.resign(r, { seq: 7, at: "2026-10-18T00:00:00.000Z" })]), OUT({ deduplicated: 2 }));
    assert.deepEqual(w.apply(w.F.receipts.get(CID)), OUT({ deduplicated: 2 }));
    const after = w.l.status({ nonce: NONCE });
    assert.deepEqual([after.reply_count, after.ack_seq, after.cursor], [1, before.ack_seq, before.cursor]);
  });

  test("X6b applied_receipts at its bound: 16 identities, a 17th genuine receipt (new J) → RECEIPT_LIMIT, no new reply; a replay of an applied one is still deduplicated", async (t) => {
    const w = world(t);
    const applied = [];
    for (let i = 0; i < 16; i++) {
      const r = w.F.attest(await w.relay(), "processing_completed");
      assert.deepEqual(w.apply([r]), OUT({ applied: 1 }), `J ${i + 1}`);
      applied.push(r);
    }
    const before = w.l.record(NONCE);
    assert.deepEqual(w.apply([w.F.attest(await w.relay(), "processing_completed")]), OUT({ refused: { RECEIPT_LIMIT: 1 } }));
    assert.deepEqual(w.l.record(NONCE), before, "no state change");
    assert.deepEqual([before.replies.length, before.applied_receipts.length], [16, 16]);
    assert.deepEqual(w.apply([applied[3]]), OUT({ deduplicated: 1 }));
  });

  test("X7 stale after terminal: rejected, then processing_completed by a direct applyReceipts call → STALE_AFTER_TERMINAL; status-path control: no pull, no receipt_refusals", async (t) => {
    const F = createFakeReceiptSeam({ selfLabel: F_LABEL, mode: "unproven" });
    const D = F.finalDaemon({ sid: "w", epoch: "E1" });
    const resolver = createRouteResolver([LOCAL_PEER, F.publicPeerEntry(O_F, [O_F])]);
    const o = await originSide(t, { resolver, receipts: F.adapter });
    const { tr, l } = o.make();
    const s = await tr.send({ target: "target-1", text: "job", request_id: "x7", destination: DEST });
    const J = (await D.send({ session: "w", text: envText("w", s.correlation_id), relay_context: finalCtx({ correlation_id: s.correlation_id, origin_inject_id: s.inject_id }) })).transport_id;
    F.attest(J, "rejected");
    assert.equal((await tr.requestStatus({ nonce: s.nonce })).status, "rejected");
    const late = F.stale(J, "processing_completed");
    const st = await tr.requestStatus({ nonce: s.nonce });
    assert.deepEqual([st.status, st.receipt_refusals], ["rejected", undefined]);
    assert.deepEqual(applyReceipts({ ledger: l, nonce: s.nonce, receipts: [late], pinnedKeys: resolver, localPeer: "local" }), OUT({ refused: { STALE_AFTER_TERMINAL: 1 } }));
    assert.equal(l.status({ nonce: s.nonce }).status, "rejected");
  });

  test("X8 rejected after ACK → REJECT_AFTER_ACK; past retain_until → RETIRED; completed stays", async (t) => {
    let clock = Date.now();
    const w = world(t, {}, { ledgerOpts: { now: () => clock } });
    const J = await w.relay();
    assert.deepEqual(w.apply([w.F.attest(J, "processing_completed")]), OUT({ applied: 1 }));
    assert.equal(w.completed(), true);
    assert.deepEqual(w.apply([w.F.attest(J, "rejected")]), OUT({ refused: { REJECT_AFTER_ACK: 1 } }));
    clock += 8 * 86400000;
    assert.deepEqual(w.apply([w.F.attest(await w.relay(), "processing_completed")]), OUT({ refused: { RETIRED: 1 } }));
    assert.equal(w.l.status({ nonce: NONCE }).status, "completed");
  });

  test("X9 squatting (RS-9): guard null → the squat's receipt is F_GUARD_ABSENT, pending; under P-1 the squat is PEER_SCOPE_DENIED and the real D's receipt completes", async (t) => {
    const off = world(t, { guard: null });
    const sq = off.F.squat({ sid: "w", relay_context: finalCtx() });
    assert.equal(sq.ok, true);
    assert.deepEqual(off.apply([off.F.attest(sq.J, "processing_completed")]), OUT({ refused: { F_GUARD_ABSENT: 1 } }));
    pendingNoMarker(off.l);
    const on = world(t);
    assert.deepEqual(on.F.squat({ sid: "w", relay_context: finalCtx() }), { ok: false, code: "PEER_SCOPE_DENIED" });
    assert.deepEqual(on.apply([on.F.attest(await on.relay(), "processing_completed")]), OUT({ applied: 1 }));
    assert.equal(on.completed(), true);
  });

  test("X9b a squat before P-1 survives the upgrade: signed session_guard null → F_GUARD_ABSENT; control guardScope:\"daemon\" → completed", async (t) => {
    for (const [guardScope, expectCompleted] of [["credential", false], ["daemon", true]]) {
      const w = world(t, { guard: null, guardScope });
      const sq = w.F.squat({ sid: "w", relay_context: finalCtx(), principal: "peer" });
      w.F.setGuard("peer-scope-v1");
      const r = w.F.attest(sq.J, "processing_completed");
      if (expectCompleted) {
        assert.equal(r.session_guard, "peer-scope-v1");
        assert.deepEqual(w.apply([r]), OUT({ applied: 1 }));
        assert.equal(w.completed(), true, "control: the daemon-wide guard lets the squat complete");
      } else {
        assert.equal(r.session_guard, null);
        assert.deepEqual(w.apply([r]), OUT({ refused: { F_GUARD_ABSENT: 1 } }));
        pendingNoMarker(w.l);
      }
    }
  });

  test("X9c P-1 switched off and on: a squat during the off period stays F_GUARD_ABSENT", async (t) => {
    const w = world(t);
    w.F.setGuard(null);
    const sq = w.F.squat({ sid: "w", relay_context: finalCtx(), principal: "peer" });
    w.F.setGuard("peer-scope-v1");
    assert.deepEqual(w.apply([w.F.attest(sq.J, "processing_completed")]), OUT({ refused: { F_GUARD_ABSENT: 1 } }));
    pendingNoMarker(w.l);
  });

  test("X9d JWT principal under P-1: squat PEER_SCOPE_DENIED, real D completes; a JWT-registered w2 is unmarked → F_GUARD_ABSENT; control markRule:\"non-peer\" → w2 passes B6g", async (t) => {
    for (const [markRule, w2Applies] of [["local-only", false], ["non-peer", true]]) {
      const w = world(t, { markRule });
      assert.deepEqual(w.F.squat({ sid: "w", relay_context: finalCtx(), principal: "jwt" }), { ok: false, code: "PEER_SCOPE_DENIED" });
      assert.deepEqual(w.apply([w.F.attest(await w.relay(), "processing_completed")]), OUT({ applied: 1 }));
      const N2 = "2".repeat(32);
      const C2 = "e".repeat(32);
      record(w.l, { nonce: N2, correlation_id: C2, origin_inject_id: "I-2", destination: { host: O_F, session: "w2" } });
      assert.equal(w.F.register("w2", { principal: "jwt" }).peer_scope_v1, w2Applies);
      const minted = w.F.inject({ sid: "w2", prompt: "work", relay_context: finalCtx({ correlation_id: C2, origin_inject_id: "I-2", final_session: "w2" }) });
      const r = w.F.attest(minted.J, "processing_completed");
      assert.deepEqual(w.apply([r], { nonce: N2 }), w2Applies ? OUT({ applied: 1 }) : OUT({ refused: { F_GUARD_ABSENT: 1 } }), markRule);
    }
  });

  test("X9e off-host holder of the pre-P-1 local token: squat and register UNAUTHORIZED after the first enablement; control rotateOnEnable:false → the squat completes", async (t) => {
    for (const rotateOnEnable of [true, false]) {
      const w = world(t, { guard: null, rotateOnEnable });
      w.F.setGuard("peer-scope-v1");
      assert.equal(w.F.register("w", { principal: "local" }).peer_scope_v1, true, "D re-registered under P-1 (as G2)");
      const sq = w.F.squat({ sid: "w", relay_context: finalCtx(), principal: "old-local" });
      if (rotateOnEnable) {
        assert.deepEqual(sq, { ok: false, code: "UNAUTHORIZED" });
        assert.deepEqual(w.F.register("w3", { principal: "old-local" }), { ok: false, code: "UNAUTHORIZED" });
        assert.deepEqual(w.apply([w.F.attest(await w.relay(), "processing_completed")]), OUT({ applied: 1 }));
      } else {
        assert.deepEqual([sq.ok, sq.peer_scope_v1], [true, true]);
        const r = w.F.attest(sq.J, "processing_completed");
        assert.equal(r.session_guard, "peer-scope-v1");
        assert.deepEqual(w.apply([r]), OUT({ applied: 1 }), "control: completed with no work by D");
      }
      assert.equal(w.completed(), true);
    }
  });

  test("X9f re-exposure procedure: the exposed-period key K is never re-pinned → r′ KEY_UNKNOWN; re-send under K2 completes; control re-pinning K completes r′", async (t) => {
    for (const repinK of [false, true]) {
      const w = world(t);
      const pinK = w.F.publicPeerEntry(O_F, [O_F]);
      const sq = w.F.squat({ sid: "w", relay_context: finalCtx(), principal: "local" });
      assert.deepEqual([sq.ok, sq.peer_scope_v1], [true, true]);
      const rPrime = w.F.attest(sq.J, "processing_completed");
      // (1) F unpinned at O.
      assert.deepEqual(w.apply([rPrime], { keys: createRouteResolver([LOCAL_PEER, { peer_id: O_F, locators: [O_F] }]) }), OUT({ refused: { KEY_UNKNOWN: 1 } }));
      // (3) destroy + re-register w; (3a) F switches to K2; (4) pin K2 only (control: re-pin K).
      w.F.register("w", { principal: "local" });
      w.F.rotateKey();
      const table = createRouteResolver([LOCAL_PEER, repinK ? pinK : w.F.publicPeerEntry(O_F, [O_F])]);
      if (repinK) {
        assert.deepEqual(w.apply([rPrime], { keys: table }), OUT({ applied: 1 }));
        assert.equal(w.completed(), true, "control: completed with no work by D");
      } else {
        assert.deepEqual(w.apply([rPrime], { keys: table }), OUT({ refused: { KEY_UNKNOWN: 1 } }));
        pendingNoMarker(w.l);
        assert.deepEqual(w.apply([w.F.attest(await w.relay(), "processing_completed")], { keys: table }), OUT({ applied: 1 }));
        assert.equal(w.completed(), true);
      }
    }
  });

  test("G1 F without P-1, honest flow → F_GUARD_ABSENT ×2; pending (I-8)", async (t) => {
    const w = world(t, { guard: null });
    const J = await w.relay();
    assert.deepEqual(w.apply([w.F.attest(J, "agent_consumed"), w.F.attest(J, "processing_completed")]), OUT({ refused: { F_GUARD_ABSENT: 2 } }));
    pendingNoMarker(w.l);
  });

  test("G2 honest D registered before P-1: F_GUARD_ABSENT ×2; after D re-registers under P-1 and the request is re-sent: completed", async (t) => {
    const w = world(t, { guard: null });
    w.F.setGuard("peer-scope-v1");
    const J = await w.relay();
    assert.deepEqual(w.apply([w.F.attest(J, "agent_consumed"), w.F.attest(J, "processing_completed")]), OUT({ refused: { F_GUARD_ABSENT: 2 } }));
    pendingNoMarker(w.l);
    assert.equal(w.F.register("w", { principal: "local" }).peer_scope_v1, true);
    const J2 = await w.relay();
    assert.deepEqual(w.apply([w.F.attest(J2, "agent_consumed"), w.F.attest(J2, "processing_completed")]), OUT({ applied: 2 }));
    assert.equal(w.completed(), true);
  });

  test("V1 leg 1 carries the origin context: accepted (no final_session check); audit row stores it; T-1 lookup correlation_id=C returns exactly I", async (t) => {
    const fake = await startFakeTelepty({ targets: ["target-1"] });
    t.after(() => fake.close());
    const ctx = { v: 2, leg: "origin", correlation_id: CID };
    const r = await daemonCall(fake, "POST", "/api/sessions/target-1/inject", { prompt: "leg 1", exact_target: true, relay_context: ctx });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    await daemonCall(fake, "POST", "/api/sessions/target-1/inject", { prompt: "other", exact_target: true });
    const rows = (await daemonCall(fake, "GET", `/api/injects?to=target-1&correlation_id=${CID}`)).body.injects;
    assert.deepEqual(rows.map((x) => [x.inject_id, x.relay_context]), [[r.body.inject_id, ctx]]);
    assert.equal(fake.audit.find((x) => x.inject_id !== r.body.inject_id).relay_context, null, "no context → stored as null");
  });

  test("V2 receipts for the leg-1 inject I: honest attest → NOT_RECEIPT_ELIGIBLE; forced (buggy daemon) signs origin_inject_id null → INJECT_MISMATCH at O", async (t) => {
    const w = world(t);
    const R = createFakeReceiptSeam({ selfLabel: "host-r", mode: "unproven" });
    R.finalDaemon({ sid: "target-1", epoch: "R1" });
    const leg1 = R.inject({ sid: "target-1", prompt: "leg 1", relay_context: { v: 2, leg: "origin", correlation_id: CID } });
    assert.equal(leg1.ok, true);
    assert.deepEqual(R.attest(leg1.J, "processing_completed"), { ok: false, code: "NOT_RECEIPT_ELIGIBLE" });
    const forced = R.attest(leg1.J, "processing_completed", { forceSign: true });
    assert.deepEqual([forced.origin_inject_id, forced.final_inject_id], [null, leg1.J]);
    assert.deepEqual(w.apply([forced]), OUT({ refused: { INJECT_MISMATCH: 1 } }));
    pendingNoMarker(w.l);
  });

  test("V5 mixed forms → RELAY_CONTEXT_INVALID at fake-telepty (deliver and the forwarding fake #111) and at the seam; no inject id minted, nothing delivered", async (t) => {
    const F = createFakeReceiptSeam({ selfLabel: F_LABEL });
    const D = F.finalDaemon({ sid: "w", epoch: "E1" });
    const fake = await startFakeTelepty({ targets: ["target-1", "w"], forward111: true, peers: { [R_F]: D } });
    t.after(() => fake.close());
    const bad = [
      finalCtx({ hop: 0 }), finalCtx({ origin_inject_id: null, hop: 1 }), finalCtx({ hop: 5 }),
      { v: 2, leg: "origin", correlation_id: CID, final_session: "w" }, { ...finalCtx(), leg: "middle" }, finalCtx({ correlation_id: "not-hex" }),
    ];
    for (const ctx of bad) {
      for (const role of ["deliver", "forward"]) assert.deepEqual(validateRelayContext(ctx, { resolvedSid: "w", role }), { ok: false, code: "RELAY_CONTEXT_INVALID" }, `${role} ${JSON.stringify(ctx)}`);
      assert.deepEqual((await daemonCall(fake, "POST", "/api/sessions/w/inject", { prompt: "x", exact_target: true, relay_context: ctx })).body, { code: "RELAY_CONTEXT_INVALID" });
      assert.deepEqual((await daemonCall(fake, "POST", `/api/sessions/${encodeURIComponent(`w@${R_F}`)}/inject`, { prompt: envText("w"), relay_context: ctx })).body, { code: "RELAY_CONTEXT_INVALID" });
      assert.deepEqual(await D.send({ session: "w", text: envText("w"), relay_context: ctx }), { ok: false, sent: "yes", code: "RELAY_CONTEXT_INVALID" });
    }
    assert.deepEqual([fake.audit.length, fake.sessions.get("w").delivered.length, D.inbound.length], [0, 0, 0]);
  });

  test("V6 intermediate hop in a chain O → R1 → R2 → F: R2's daemon receipt → SOURCE_MISMATCH (pinned under linux) / KEY_UNKNOWN (unpinned); F's hop-2 receipt binds", async (t) => {
    const w = world(t);
    const R2 = createFakeReceiptSeam({ selfLabel: "host-r2", mode: "unproven" });
    const R2D = R2.finalDaemon({ sid: "r2", epoch: "R2E" });
    const J12 = (await R2D.send({ session: "r2", text: envText("r2"), relay_context: finalCtx({ final_session: "r2" }) })).transport_id;
    const r = R2.attest(J12, "processing_completed");
    const withLinux = createRouteResolver([LOCAL_PEER, w.F.publicPeerEntry(O_F, [O_F]), R2.publicPeerEntry("linux", ["linux"])]);
    assert.deepEqual(w.apply([r], { keys: withLinux }), OUT({ refused: { SOURCE_MISMATCH: 1 } }));
    assert.deepEqual(w.apply([r]), OUT({ refused: { KEY_UNKNOWN: 1 } }));
    assert.deepEqual(w.apply([w.F.attest(await w.relay(finalCtx({ hop: 2 })), "processing_completed")], { keys: withLinux }), OUT({ applied: 1 }));
  });

  test("V7 final_session mismatch: refused at the delivering seam; under role forward it passes the fake #111 and is refused at the seam", async (t) => {
    const F = createFakeReceiptSeam({ selfLabel: F_LABEL });
    const D = F.finalDaemon({ sid: "w", epoch: "E1" });
    const fake = await startFakeTelepty({ targets: ["target-1"], forward111: true, peers: { [R_F]: D } });
    t.after(() => fake.close());
    const ctx = finalCtx({ final_session: "x" });
    assert.deepEqual(validateRelayContext(ctx, { resolvedSid: "w", role: "deliver" }), { ok: false, code: "RELAY_CONTEXT_INVALID" });
    assert.deepEqual(validateRelayContext(ctx, { role: "forward" }), { ok: true, variant: "final" });
    assert.deepEqual(await D.send({ session: "w", text: envText("w"), relay_context: ctx }), { ok: false, sent: "yes", code: "RELAY_CONTEXT_INVALID" });
    const fw = await daemonCall(fake, "POST", `/api/sessions/${encodeURIComponent(`w@${R_F}`)}/inject`, { prompt: envText("w"), relay_context: ctx });
    assert.deepEqual([fw.status, fw.body.code, fake.forwards[0].relay_context], [502, "RELAY_CONTEXT_INVALID", ctx]);
    assert.equal(D.inbound.length, 0);
  });

  // DX1–DX4: path S on a destination ≠ local direct record (the transport-level DX run is U2). The record is
  // created by the test: via null, destination mac/w, origin_inject_id = the J the fake #111 returned. Its
  // generation is F's epoch: the ledger learns an epoch only for a relayed record (spec gap, REPORT).
  async function crossHostDirect(t, seamOpts = {}) {
    const F = createFakeReceiptSeam({ selfLabel: F_LABEL, mode: "proven", ...seamOpts });
    const D = F.finalDaemon({ sid: "w", epoch: "E1" });
    const fake = await startFakeTelepty({ targets: ["target-1"], forward111: true, peers: { [O_F]: D } });
    t.after(() => fake.close());
    const C = "b".repeat(32);
    const ctx = { v: 2, leg: "final", correlation_id: C, origin_inject_id: null, final_session: "w", hop: 0 };
    const fw = await daemonCall(fake, "POST", `/api/sessions/${encodeURIComponent(`w@${O_F}`)}/inject`, { prompt: envText("w", C), exact_target: true, relay_context: ctx });
    assert.equal(fw.status, 200, JSON.stringify(fw.body));
    assert.equal(F.final(fw.body.inject_id).variant, "direct-final", "V4: the forwarder checked shape only, the seam checked final_session");
    const h = tmpLedger(t);
    record(h.l, { nonce: NONCE, correlation_id: C, origin_inject_id: fw.body.inject_id, via: null, generation: "E1" });
    const apply = (receipts, keys = createRouteResolver([LOCAL_PEER, F.publicPeerEntry(O_F, [O_F])])) => applyReceipts({ ledger: h.l, nonce: NONCE, receipts, provenance: THROWING_PROVENANCE, pinnedKeys: keys, localPeer: "local" });
    return { F, D, l: h.l, J: fw.body.inject_id, C, apply };
  }

  test("DX1 cross-host direct through the fake #111: path S, B4d passes, completed after the checkpoint; the provenance adapter is not called", async (t) => {
    const x = await crossHostDirect(t);
    const rs = [x.F.attest(x.J, "agent_consumed"), x.F.attest(x.J, "processing_completed")];
    assert.equal(rs[1].origin_inject_id, null);
    assert.deepEqual(x.apply(rs), OUT({ applied: 2 }));
    const st = x.l.status({ nonce: NONCE });
    assert.equal(x.l.status({ nonce: NONCE, cursor: st.cursor }).status, "completed");
  });

  test("DX2 cross-host direct: no pinned key → KEY_UNKNOWN; unsigned → SIGNATURE_REQUIRED; tamper → SIGNATURE_INVALID; no state change, no marker", async (t) => {
    const x = await crossHostDirect(t);
    const r = x.F.attest(x.J, "processing_completed");
    assert.deepEqual(x.apply([r], createRouteResolver([LOCAL_PEER, { peer_id: O_F, locators: [O_F] }])), OUT({ refused: { KEY_UNKNOWN: 1 } }));
    assert.deepEqual(x.apply([x.F.unsigned(x.J, "processing_completed")]), OUT({ refused: { SIGNATURE_REQUIRED: 1 } }));
    assert.deepEqual(x.apply([x.F.tamper(r, "seq", 99)]), OUT({ refused: { SIGNATURE_INVALID: 1 } }));
    const st = x.l.status({ nonce: NONCE });
    assert.deepEqual([st.stage, st.unproven, st.reply_count, st.rejected], ["unknown", {}, 0, {}]);
  });

  test("DX3 cross-host direct: a receipt naming another J → INJECT_MISMATCH", async (t) => {
    const x = await crossHostDirect(t);
    const J2 = x.F.inject({ sid: "w", prompt: "again", relay_context: { v: 2, leg: "final", correlation_id: x.C, origin_inject_id: null, final_session: "w", hop: 0 } }).J;
    assert.deepEqual(x.apply([x.F.attest(J2, "processing_completed")]), OUT({ refused: { INJECT_MISMATCH: 1 } }));
  });

  test("DX4 local direct with v2 receipts (path D): the 8016f25 outcome exactly; sig not evaluated", async (t) => {
    const k = keyPair();
    const o = await originSide(t);
    const { tr } = o.make();
    const s = await tr.send({ target: "target-1", text: "build and ACK", request_id: "dx4" });
    const epoch = o.fake.sessions.get("target-1").epoch;
    const rc = (stage, seq) => ({
      ...v2(k, { correlation_id: s.correlation_id, origin_inject_id: null, final_inject_id: s.inject_id, final_session: "target-1", final_session_epoch: epoch, stage, seq },
        { sid: "target-1", epoch }), sig: "A".repeat(86), verified_sender_host: "local", sender_proof: { basis: FAKE_PROOF_BASIS },
    });
    o.served.set(s.correlation_id, [rc("agent_consumed", 1), rc("processing_completed", 2)]);
    const st = await tr.requestStatus({ request_id: "dx4" });
    assert.deepEqual([st.stage, st.final_ack_seq, st.unproven, st.replies[0].attestation, st.receipt_refusals], ["origin_ack_received", 1, {}, "destination", undefined], JSON.stringify(st));
    const body = JSON.parse(st.replies[0].text.split("\n").slice(1).join("\n"));
    assert.deepEqual([body.inject_id, body.provenance.host, body.origin_inject_id], [s.inject_id, "local", undefined], "path D reply format, v2 fields ignored");
    assert.equal((await tr.requestStatus({ nonce: s.nonce, cursor: st.next_cursor })).status, "completed");
  });

  test("S1 same-name target on two pinned hosts: a genuine peer-a/w receipt (same I + C) → SOURCE_MISMATCH; the peer-b/w receipt applies", async (t) => {
    const A = createFakeReceiptSeam({ selfLabel: "host-a", mode: "unproven" });
    const B = createFakeReceiptSeam({ selfLabel: "host-b", mode: "unproven" });
    const AD = A.finalDaemon({ sid: "w", epoch: "E1" });
    const BD = B.finalDaemon({ sid: "w", epoch: "E1" });
    const h = tmpLedger(t);
    record(h.l, { nonce: NONCE, correlation_id: CID, origin_inject_id: "I-1", destination: { host: "peer-b", session: "w" } });
    const keys = createRouteResolver([LOCAL_PEER, A.publicPeerEntry("peer-a"), B.publicPeerEntry("peer-b")]);
    const apply = (rs) => applyReceipts({ ledger: h.l, nonce: NONCE, receipts: rs, provenance: THROWING_PROVENANCE, pinnedKeys: keys, localPeer: "local" });
    const Ja = (await AD.send({ session: "w", text: envText("w"), relay_context: finalCtx() })).transport_id;
    const Jb = (await BD.send({ session: "w", text: envText("w"), relay_context: finalCtx() })).transport_id;
    assert.deepEqual(apply([A.attest(Ja, "processing_completed")]), OUT({ refused: { SOURCE_MISMATCH: 1 } }));
    assert.deepEqual(apply([B.attest(Jb, "processing_completed")]), OUT({ applied: 1 }));
  });

  // L2 (stand-in): R's relay intake (§1.2, the verbatim copy and RELAY_HOP_LIMIT) is U4; here R's relay send is a
  // test-side model that refuses to build hop 5 before sending, so only relay.js's outbox handling is src code.
  test("L2 hop limit: an inbound hop-4 context re-relayed → RELAY_HOP_LIMIT before sending; outbox failed; nothing reaches F", async (t) => {
    const w = world(t);
    const R = tmpLedger(t);
    record(R.l, { nonce: NONCE, correlation_id: CID, origin_inject_id: "I-1", via: null, destination: { host: R_F, session: "w" }, generation: "E1" });
    const inbound = finalCtx({ hop: 4 });
    const key = R.l.enqueue({ nonce: NONCE, to: { host: R_F, session: "w" }, kind: "relay", text: envText("w") }).key;
    const send = async (item) => {
      const next = { ...inbound, final_session: item.session, hop: inbound.hop + 1 };
      if (next.hop > 4) return { ok: false, sent: "no", code: "RELAY_HOP_LIMIT" };
      return w.D.send({ ...item, relay_context: next });
    };
    const runner = createRelayRunner({ ledger: R.l, send, resolver: createRouteResolver([{ peer_id: R_F, locators: [R_F] }]) });
    for (let i = 0; i < 3; i++) await runner.tick();
    const item = R.l.outbox().find((o) => o.key === key);
    assert.deepEqual([item.state, item.last_error, item.attempts], ["failed", "RELAY_HOP_LIMIT", 3]);
    assert.equal(w.D.inbound.length, 0);
  });

  test("H4 telesession never posts to a remote daemon: non-local relay items → PEER_UNSUPPORTED (pinned resolver) / PEER_UNKNOWN (default); zero requests to any other daemon", async (t) => {
    const remote = await startFakeTelepty({ targets: ["w"] });
    t.after(() => remote.close());
    const F = createFakeReceiptSeam({ selfLabel: F_LABEL });
    for (const [resolver, code] of [[createRouteResolver([LOCAL_PEER, F.publicPeerEntry(O_F, [O_F, new URL(remote.origin).host])]), "PEER_UNSUPPORTED"], [undefined, "PEER_UNKNOWN"]]) {
      const o = await originSide(t, { resolver });
      const { tr, l } = o.make();
      const s = await tr.send({ target: "target-1", text: "job", request_id: `h4-${code}`, destination: DEST });
      assert.equal(s.ok, true);
      const key = l.enqueue({ nonce: s.nonce, to: DEST, kind: "relay", text: "for F" }).key;
      await tr.relayTick();
      assert.equal(l.outbox().find((x) => x.key === key).last_error, code);
      assert.deepEqual(o.fake.injectArrivals.map((x) => x.to), ["target-1"], "only the leg-1 inject reached the local daemon");
    }
    assert.equal(remote.requests.length, 0, "no request reached the other daemon");
  });

  test("RC1 origin restart mid-flow: ledger and transport reopened between the relay send and F's receipts; receipts bind (I persisted); seq/cursor continue", async (t) => {
    const F = createFakeReceiptSeam({ selfLabel: F_LABEL, mode: "unproven" });
    const D = F.finalDaemon({ sid: "w", epoch: "E1" });
    const resolver = createRouteResolver([LOCAL_PEER, F.publicPeerEntry(O_F, [O_F])]);
    const o = await originSide(t, { resolver, receipts: F.adapter });
    const a = o.make();
    const s = await a.tr.send({ target: "target-1", text: "job", request_id: "rc1", destination: DEST });
    F.attest((await D.send({ session: "w", text: envText("w", s.correlation_id), relay_context: finalCtx({ correlation_id: s.correlation_id, origin_inject_id: s.inject_id }) })).transport_id, "agent_consumed");
    assert.equal((await a.tr.requestStatus({ nonce: s.nonce })).stage, "agent_consumed");
    const J2 = (await D.send({ session: "w", text: envText("w", s.correlation_id), relay_context: finalCtx({ correlation_id: s.correlation_id, origin_inject_id: s.inject_id }) })).transport_id;
    await o.closeOne(a);
    const b = o.make();
    assert.equal(b.l.record(s.nonce).origin_inject_id, s.inject_id);
    F.attest(J2, "processing_completed");
    const st = await b.tr.requestStatus({ nonce: s.nonce });
    assert.deepEqual([st.stage, st.replies.map((x) => x.seq), st.next_cursor], ["origin_ack_received", [1], 1], JSON.stringify(st));
    assert.equal((await b.tr.requestStatus({ nonce: s.nonce, cursor: st.next_cursor })).status, "completed");
  });
});

// C1: the 8016f25 isRecord, frozen verbatim (src/relay/ledger.js at 8016f25 = 66dfafe), so a U1 ledger is checked by
// the predicate an older build would apply on rollback.
const C1_HEX32 = /^[0-9a-f]{32}$/;
const C1_HEX64 = /^[0-9a-f]{64}$/;
const C1_HOST = /^[A-Za-z0-9._:\[\]-]{1,253}$/;
const C1_SID = /^[A-Za-z0-9._-]{1,128}$/;
const c1Plain = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const c1Endpoint = (e) => e !== null && typeof e === "object" && typeof e.host === "string" && C1_HOST.test(e.host) && typeof e.session === "string" && C1_SID.test(e.session);
const c1Reply = (x) => c1Plain(x) && Number.isSafeInteger(x.seq) && x.seq >= 1 && C1_HEX64.test(x.sha256) && c1Endpoint(x.from);
const c1Late = (x) => c1Plain(x) && C1_HEX64.test(x.sha256);
function isRecord8016f25(key, r) {
  return c1Plain(r) && r.nonce === key && C1_HEX32.test(r.nonce) && C1_HEX64.test(r.payload_sha256)
    && c1Endpoint(r.origin) && c1Endpoint(r.destination) && c1Endpoint(r.reply_to) && (r.via === null || c1Endpoint(r.via))
    && (r.correlation_id === undefined || r.correlation_id === null || C1_HEX32.test(r.correlation_id))
    && (r.retired_at === undefined || r.retired_at === null || typeof r.retired_at === "string")
    && (r.reconstructed === undefined || typeof r.reconstructed === "boolean")
    && c1Plain(r.stages) && Array.isArray(r.replies) && r.replies.every(c1Reply) && Number.isSafeInteger(r.next_seq) && r.next_seq >= 1
    && Array.isArray(r.events) && Array.isArray(r.late_pending) && r.late_pending.every(c1Late) && c1Plain(r.rejected) && c1Plain(r.unproven)
    && Number.isSafeInteger(r.created_ms) && Number.isSafeInteger(r.deadline_ms) && Number.isSafeInteger(r.retain_until_ms);
}

test("C1 compat: an 8016f25 ledger (no new fields) opens under U1 code; a U1 ledger passes the 8016f25 isRecord; fields preserved, no version error", async (t) => {
  const w = world(t);
  assert.deepEqual(w.apply([w.F.attest(await w.relay(), "agent_consumed")]), OUT({ applied: 1 }));
  w.h.l.close();
  const file = path.join(w.h.dir, "ledger.json");
  const u1 = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(u1.version, 1);
  const rec = u1.records[NONCE];
  assert.deepEqual([rec.origin_inject_id, rec.applied_receipts.length], ["I-1", 1]);
  assert.equal(isRecord8016f25(NONCE, rec), true, "U1 record accepted by the 8016f25 predicate");
  // An 8016f25-written record: the same state without the U1 fields.
  const old = structuredClone(u1);
  delete old.records[NONCE].origin_inject_id;
  delete old.records[NONCE].applied_receipts;
  fs.unlinkSync(file);
  fs.writeFileSync(file, JSON.stringify(old), { mode: 0o600 });
  const l = w.h.reopen();
  assert.deepEqual([l.record(NONCE).stage, l.record(NONCE).origin_inject_id, l.record(NONCE).applied_receipts], ["agent_consumed", undefined, undefined]);
  assert.deepEqual(w.apply([w.F.attest(await w.relay(), "processing_completed")]), OUT({ refused: { INJECT_UNKNOWN: 1 } }), "a pre-U1 relayed record stays refused (§4.4)");
});

test("§5 guard: no file in the repository working tree contains a PEM private-key header (keys are generated in-test only)", () => {
  const root = path.join(path.dirname(new URL(import.meta.url).pathname), "..");
  const pem = new RegExp("-----BEGIN [A-Z ]*" + "PRIVATE KEY-----");
  const hits = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (e.name === "node_modules" || e.name === ".git") continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.isFile() && pem.test(fs.readFileSync(p, "utf8"))) hits.push(path.relative(root, p));
    }
  };
  walk(root);
  assert.deepEqual(hits, []);
});
