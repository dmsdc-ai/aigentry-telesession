/**
 * Receipt v2 signature verification (SPEC 2026-10-12 §2.2, §7 step 1). Verify only: no signing exists in
 * src/ (signing lives only in the test fixture). The signed bytes are RECEIPT_SIG_DOMAIN + canonicalJson(body)
 * where `body` has exactly the §2.2 keys; `inject_id`, `role`, `auth_basis` and `sig` travel outside it.
 * Ed25519 from node:crypto (Article 17). Pure, no I/O.
 */

import { createHash, createPublicKey, verify } from "node:crypto";

export const RECEIPT_SIG_DOMAIN = "telepty-final-receipt/v1\n";

const isPlain = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

// Keys sorted by code point at every level, no whitespace; integers, strings, booleans, null, arrays and
// plain objects only. Anything else throws CANONICAL_UNSUPPORTED.
export function canonicalJson(v) {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number" && Number.isSafeInteger(v)) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (isPlain(v)) {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(",")}}`;
  }
  throw new Error("CANONICAL_UNSUPPORTED");
}

// "ed25519:" + base64url(sha256(SPKI DER)) of an Ed25519 public key given as SPKI DER base64; null if invalid.
export function keyIdOf(spkiB64) {
  try {
    const der = Buffer.from(spkiB64, "base64");
    if (createPublicKey({ key: der, format: "der", type: "spki" }).asymmetricKeyType !== "ed25519") return null;
    return `ed25519:${createHash("sha256").update(der).digest("base64url")}`;
  } catch {
    return null;
  }
}

function signedBody(r) {
  const a = isPlain(r.attested_by) ? r.attested_by : {};
  return {
    v: r.v, correlation_id: r.correlation_id, origin_inject_id: r.origin_inject_id, final_inject_id: r.final_inject_id,
    final_session: r.final_session, final_session_epoch: r.final_session_epoch, stage: r.stage, seq: r.seq, at: r.at,
    attested_by: { sid: a.sid, epoch: a.epoch, generation: a.generation }, delivered_payload_sha256: r.delivered_payload_sha256,
    session_guard: r.session_guard, key_id: r.key_id,
  };
}

// `pinnedKeys`: Map key_id → public_key_spki_b64 (the keys pinned under one peer).
export function verifyReceiptSig(receipt, pinnedKeys) {
  const spki = isPlain(receipt) && typeof receipt.key_id === "string" && pinnedKeys instanceof Map ? pinnedKeys.get(receipt.key_id) : undefined;
  if (typeof spki !== "string") return { ok: false, code: "KEY_UNKNOWN" };
  try {
    const bytes = Buffer.from(RECEIPT_SIG_DOMAIN + canonicalJson(signedBody(receipt)), "utf8");
    const key = createPublicKey({ key: Buffer.from(spki, "base64"), format: "der", type: "spki" });
    const sig = typeof receipt.sig === "string" ? Buffer.from(receipt.sig, "base64url") : null;
    return sig !== null && sig.length === 64 && verify(null, bytes, key, sig) ? { ok: true } : { ok: false, code: "SIGNATURE_INVALID" };
  } catch {
    return { ok: false, code: "SIGNATURE_INVALID" };
  }
}
