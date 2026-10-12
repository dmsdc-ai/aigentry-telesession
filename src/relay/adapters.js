/**
 * Provenance + receipt adapters (SPEC 2026-10-11 §9.1) and their mapping onto ledger events. Interfaces:
 *   ProvenanceAdapter.verify(row)            → {authenticated, host, basis}
 *   ReceiptAdapter.fetch(correlation_id)     → Promise<receipt[]>   (proposed telepty GET /api/requests/:id/receipts)
 *   ReceiptAdapter.consumption(inject_id)    → Promise<{status, session_epoch?}>  (GET /api/inject-observations/:id)
 * Defaults are today's behaviour: no remote provenance is ever proven (empty basis allowlist) and no receipt
 * or consumption is read (NO_RECEIPTS). Mapping (agreed contract):
 *   - consumption `observed` → `agent_consumed` for a direct record only (the leg-1 consumption of a relayed
 *     record is a hop fact, not the final destination's);
 *   - a receipt applies a destination stage only when it is the final daemon's own-bearer attestation
 *     (`role:"final"`, `auth_basis:"own_bearer"`) AND its provenance is proven; otherwise the stage stays
 *     unproven with REMOTE_PROVENANCE_UNAVAILABLE. A proven `processing_completed` receipt is validated as an
 *     event first; only an accepted (or already-applied) one is then stored as a verified reply entry, so the origin agent's cursor/checkpoint covers it (→ origin_ack_received).
 * Pure over the ledger API; no I/O of its own.
 */

import { createHash } from "node:crypto";

const HEX32_RE = /^[0-9a-f]{32}$/;
const HOST_RE = /^[A-Za-z0-9._:\[\]-]{1,253}$/;
const SID_RE = /^[A-Za-z0-9._-]{1,128}$/;
const BASIS_RE = /^[A-Za-z0-9._:-]{1,64}$/;
// Review 3 N-c: receipt fields copied into the stored reply text are bounded like the other inputs.
const INJECT_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const AT_RE = /^[0-9A-Za-z.:+-]{1,64}$/;
const EPOCH_RE = /^[\x21-\x7e]{1,256}$/;
const RECEIPT_STAGES = new Set(["agent_consumed", "processing_completed", "rejected"]);
const RECEIPTS_MAX = 64;

const sha256hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const isPlain = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

export function createProvenanceAdapter({ allowedBases = [] } = {}) {
  const allowed = new Set(allowedBases.filter((b) => typeof b === "string" && BASIS_RE.test(b)));
  return Object.freeze({
    verify(row) {
      const host = isPlain(row) && typeof row.verified_sender_host === "string" && HOST_RE.test(row.verified_sender_host) ? row.verified_sender_host : null;
      const basis = isPlain(row) && isPlain(row.sender_proof) && typeof row.sender_proof.basis === "string" && BASIS_RE.test(row.sender_proof.basis)
        ? row.sender_proof.basis : null;
      return host !== null && basis !== null && allowed.has(basis) ? { authenticated: true, host, basis } : { authenticated: false, host: null, basis };
    },
  });
}

export const DEFAULT_PROVENANCE = createProvenanceAdapter();
export const NO_RECEIPTS = Object.freeze({ fetch: async () => [], consumption: async () => ({ status: "unknown" }) });

function isReceipt(r) {
  return isPlain(r) && typeof r.correlation_id === "string" && HEX32_RE.test(r.correlation_id) && RECEIPT_STAGES.has(r.stage)
    && (r.role === "final" || r.role === "hop") && Number.isSafeInteger(r.seq) && r.seq >= 0
    && typeof r.inject_id === "string" && INJECT_ID_RE.test(r.inject_id) && isPlain(r.attested_by)
    && (r.at === undefined || r.at === null || (typeof r.at === "string" && AT_RE.test(r.at)))
    && (r.attested_by.host_label === undefined || r.attested_by.host_label === null
      || (typeof r.attested_by.host_label === "string" && HOST_RE.test(r.attested_by.host_label)))
    && typeof r.attested_by.sid === "string" && SID_RE.test(r.attested_by.sid)
    && typeof r.attested_by.epoch === "string" && EPOCH_RE.test(r.attested_by.epoch);
}

// Receipts in the order fetched (out-of-order evidence is handled by the ledger: stages never regress).
// `injectIds`: the inject(s) this origin knows carried the request. Fail closed: a receipt naming another
// inject is refused (INJECT_MISMATCH), and with no known inject every receipt is refused (INJECT_UNKNOWN).
// Host + session: a proven receipt is source-checked by the ledger (verified host + attested sid vs the
// destination); an unproven one is source-checked here (attested sid) before its marker is set.
// `attested_by.host_label` is not part of the binding (SPEC §9.1: the host is the verified sender host).
export function applyReceipts({ ledger, nonce, receipts, provenance = DEFAULT_PROVENANCE, injectIds }) {
  const out = { applied: 0, unproven: 0, deduplicated: 0, refused: {} };
  const injects = new Set(injectIds === undefined || injectIds === null ? [] : injectIds);
  const refuse = (code) => { out.refused[code] = (out.refused[code] || 0) + 1; };
  for (const r of (Array.isArray(receipts) ? receipts : []).slice(0, RECEIPTS_MAX)) {
    const rec = ledger.record(nonce);
    if (!rec) { refuse("UNKNOWN_CORRELATION"); continue; }
    if (!isReceipt(r)) { refuse("INVALID_RECEIPT"); continue; }
    if (r.correlation_id !== rec.correlation_id) { refuse("CORRELATION_MISMATCH"); continue; }
    if (r.role !== "final") { refuse("HOP_FACT_ONLY"); continue; }
    if (r.auth_basis !== "own_bearer") { refuse("NOT_OWN_BEARER"); continue; }
    if (injects.size === 0) { refuse("INJECT_UNKNOWN"); continue; }
    if (!injects.has(r.inject_id)) { refuse("INJECT_MISMATCH"); continue; }
    const prov = provenance.verify(r);
    if (!prov.authenticated && r.attested_by.sid !== rec.destination.session) { refuse("SOURCE_MISMATCH"); continue; }
    const from = { host: prov.authenticated ? prov.host : rec.destination.host, session: r.attested_by.sid };
    const ev = {
      nonce, stage: r.stage, payload_sha256: rec.payload_sha256, correlation_id: r.correlation_id, from, hop: "destination",
      generation: r.attested_by.epoch, learn_generation: true, authenticated: prov.authenticated, provenance_unavailable: !prov.authenticated,
    };
    if (prov.authenticated && r.stage === "processing_completed") {
      // The ACK as a verified entry the origin agent reads (and checkpoints): deterministic, so a replayed
      // receipt dedupes to the same seq.
      const text = `[telesession receipt stage=processing_completed]\n${JSON.stringify({
        correlation_id: r.correlation_id, inject_id: r.inject_id, seq: r.seq, at: typeof r.at === "string" ? r.at : null,
        attested_by: { host_label: typeof r.attested_by.host_label === "string" ? r.attested_by.host_label : null, sid: r.attested_by.sid, epoch: r.attested_by.epoch },
        auth_basis: r.auth_basis, provenance: { host: prov.host, basis: prov.basis },
      })}`;
      // Review 3 B2: the event is validated (source, epoch, …) before the reply is stored; a refusal stores nothing.
      const c = ledger.recordEvent({ ...ev, reply_sha256: sha256hex(text), check_only: true });
      if (!c.ok) { refuse(c.code); continue; }
      const a = ledger.appendReply({ nonce, text, from, verified: true, correlation_id: r.correlation_id });
      if (!a.ok) { refuse(a.code); continue; }
      Object.assign(ev, { reply_seq: a.seq, reply_sha256: sha256hex(text) });
    }
    const e = ledger.recordEvent(ev);
    if (e.ok && e.applied) out.applied += 1;
    else if (e.ok) out.deduplicated += 1;
    else if (e.code === "REMOTE_PROVENANCE_UNAVAILABLE") out.unproven += 1;
    else refuse(e.code);
  }
  return out;
}

// GET /api/inject-observations/:inject_id for the inject this origin issued. Only for a direct record: the
// observing daemon is the destination's own daemon, and the epoch must be the record's generation.
export function applyConsumption({ ledger, nonce, observation }) {
  const rec = ledger.record(nonce);
  if (!rec) return { applied: false, code: "UNKNOWN_CORRELATION" };
  if (!isPlain(observation) || observation.status !== "observed") return { applied: false, code: "NOT_OBSERVED" };
  if (rec.via !== null) return { applied: false, code: "HOP_FACT_ONLY" };
  const e = ledger.recordEvent({
    nonce, stage: "agent_consumed", payload_sha256: rec.payload_sha256, from: rec.destination, hop: "destination",
    generation: typeof observation.session_epoch === "string" ? observation.session_epoch : null, authenticated: true,
  });
  return e.ok ? { applied: e.applied === true } : { applied: false, code: e.code };
}
