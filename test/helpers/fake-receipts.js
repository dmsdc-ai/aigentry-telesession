/**
 * Fake of the AGREED (proposed, not yet implemented) telepty receipt seam, for isolated tests only:
 *   envelope  {v, correlation_id, origin_request_id?, payload_sha256, origin, final:{host_label, sid, epoch},
 *              reply_locator, hop, deadline_at}
 *   receipt   {correlation_id, inject_id, stage, role, seq, at, consumption, attested_by, auth_basis}
 *             as served by GET /api/requests/:correlation_id/receipts, plus the provenance fields the carrying
 *             telepty would attach (#100): verified_sender_host + sender_proof.basis — present only in
 *             "proven" mode
 *   GET /api/inject-observations/:inject_id → {status, session_epoch} (consumption.status) via `observe()`.
 * A fake final daemon accepts envelopes (the relay send primitive) and attests receipts with its own bearer
 * (`auth_basis: "own_bearer"`). Nothing here claims the real telepty APIs exist.
 */

import { randomUUID } from "node:crypto";

export const FAKE_PROOF_BASIS = "peer_mtls_host_attested";

export function createFakeReceiptSeam({ mode = "proven", host = "remote-peer", basis = FAKE_PROOF_BASIS } = {}) {
  const receipts = new Map();       // correlation_id → receipt[] (as stored by the origin-side daemon)
  const observations = new Map();   // inject_id → {status, session_epoch}
  const inbound = [];               // envelopes the fake final daemon accepted

  const provenance = () => (mode === "proven" ? { verified_sender_host: host, sender_proof: { basis } } : {});

  // A receipt the final daemon attests and the seam carries back to the origin daemon.
  function post(receipt) {
    const list = receipts.get(receipt.correlation_id) || [];
    list.push({ ...receipt, ...provenance() });
    receipts.set(receipt.correlation_id, list);
  }

  function finalDaemon({ sid, epoch }) {
    const at = () => new Date().toISOString();
    let seq = 0;
    return {
      // Relay send primitive (relay.js contract): the envelope text is delivered to `sid`.
      send: async (item) => {
        let env;
        try { env = JSON.parse(item.text); } catch { return { ok: false, sent: "yes", code: "ENVELOPE_INVALID" }; }
        if (!env || env.v !== 1 || env.final.sid !== sid || item.session !== sid) return { ok: false, sent: "yes", code: "ENVELOPE_INVALID" };
        const inject_id = randomUUID();
        inbound.push({ inject_id, envelope: env });
        return { ok: true, transport_id: inject_id };
      },
      inbound,
      // The final session consumed / finished the work: own-bearer-attested receipts.
      attest(env, stage, { inject_id = inbound.find((x) => x.envelope.correlation_id === env.correlation_id).inject_id, seqOverride, correlation_id } = {}) {
        seq += 1;
        const r = {
          correlation_id: correlation_id || env.correlation_id, inject_id, stage, role: "final", seq: seqOverride ?? seq, at: at(),
          consumption: { status: stage === "agent_consumed" ? "observed" : "unknown" },
          attested_by: { host_label: host, sid, epoch }, auth_basis: "own_bearer",
        };
        post(r);
        return r;
      },
      replay(r) { post(r); },
    };
  }

  return {
    receipts, observations, inbound, finalDaemon,
    observe(injectId, status, sessionEpoch = null) { observations.set(injectId, { status, session_epoch: sessionEpoch }); },
    // ReceiptAdapter over this seam.
    adapter: {
      fetch: async (correlationId) => (receipts.get(correlationId) || []).map((r) => structuredClone(r)),
      consumption: async (injectId) => observations.get(injectId) || { status: "unknown" },
    },
  };
}
