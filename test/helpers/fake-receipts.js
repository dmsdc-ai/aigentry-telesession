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
 *
 * SPEC 2026-10-12 §5 (U1): the seam also stands in for telepty#100 T-1…T-7 on a final daemon F. It MUST NOT be
 * taken as evidence that those exist. Synthetic Ed25519 keys are generated here, in the test process, once per
 * seam (never written, never read from env or disk, never shared across seams). v2 receipts are signed over
 * "telepty-final-receipt/v1\n" + canonical(body) (§2.2; this file has its own canonical(), independent of src/).
 *   - relay_context is validated with test/helpers/relay-context.js (role "deliver", resolvedSid = the session);
 *   - credentials: sid → (epoch, generation); the per-(sid, epoch) `peer_scope_v1` mark of §2.5 P-1;
 *   - `attest(J, stage)` (J a string) builds the §2.2 body from the stored J record only; the legacy
 *     `attest(envelope, stage, …)` (an object) is unchanged;
 *   - options: guardScope "daemon" (control of X9b), markRule "non-peer" (control of X9d), rotateOnEnable false
 *     (control of X9e) model the superseded revisions and exist only as controls.
 */

import { randomUUID, generateKeyPairSync, createHash, sign } from "node:crypto";
import { validateRelayContext } from "./relay-context.js";

export const FAKE_PROOF_BASIS = "peer_mtls_host_attested";
export const SESSION_GUARD = "peer-scope-v1";
const DOMAIN = "telepty-final-receipt/v1\n";

const sha256 = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const canonical = (v) => (v !== null && typeof v === "object" && !Array.isArray(v)
  ? `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`
  : Array.isArray(v) ? `[${v.map(canonical).join(",")}]` : JSON.stringify(v));

function syntheticKeys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ type: "spki", format: "der" });
  return Object.freeze({ privateKey, spki: der.toString("base64"), keyId: `ed25519:${createHash("sha256").update(der).digest("base64url")}` });
}

// §5 "Distinct names (BLK-1)": O's peer id for F, R's peer id for F and F's self label must all differ.
export function assertDistinctNames(...names) {
  if (new Set(names).size !== names.length) throw new Error(`fixture bug: one string used for two naming roles (${names.join(", ")})`);
}

const BODY_KEYS = ["v", "correlation_id", "origin_inject_id", "final_inject_id", "final_session", "final_session_epoch", "stage", "seq", "at",
  "attested_by", "delivered_payload_sha256", "session_guard", "key_id"];
const bodyOf = (r) => Object.fromEntries(BODY_KEYS.map((k) => [k, k === "attested_by"
  ? { sid: r.attested_by.sid, epoch: r.attested_by.epoch, generation: r.attested_by.generation } : r[k]]));

function signWith(k, body) {
  const b = { ...body, key_id: body.key_id ?? k.keyId };
  const sig = sign(null, Buffer.from(DOMAIN + canonical(b), "utf8"), k.privateKey).toString("base64url");
  return { ...b, inject_id: b.final_inject_id, role: "final", auth_basis: "own_bearer", sig };
}

export function createFakeReceiptSeam({ mode = "proven", host = "remote-peer", basis = FAKE_PROOF_BASIS, selfLabel = host, keys,
  guard = SESSION_GUARD, guardScope = "credential", markRule = "local-only", rotateOnEnable = true } = {}) {
  const receipts = new Map();       // correlation_id → receipt[] (as stored by the origin-side daemon)
  const observations = new Map();   // inject_id → {status, session_epoch}
  const inbound = [];               // envelopes the fake final daemon accepted

  let key = keys || syntheticKeys();
  const otherKeys = syntheticKeys();
  let guardNow = guard;
  let localTokenReplaced = guard === SESSION_GUARD;
  const credentials = new Map();    // sid → {epoch, generation} (the current credential)
  const marks = new Map();          // `${sid}\n${epoch}` → peer_scope_v1 (per issued credential, never added later)
  const finals = new Map();         // J → frozen {J, relay_context, variant, session, epoch, generation, delivered_payload_sha256}
  const seqs = new Map();           // J → last seq
  let generationSeq = 0;

  const provenance = () => (mode === "proven" ? { verified_sender_host: host, sender_proof: { basis } } : {});

  // A receipt the final daemon attests and the seam carries back to the origin daemon.
  function post(receipt) {
    const list = receipts.get(receipt.correlation_id) || [];
    list.push({ ...receipt, ...provenance() });
    receipts.set(receipt.correlation_id, list);
  }

  // §5 Credentials: a fresh (epoch, generation) per registration; marked iff P-1 is on and the principal is local.
  function issue(sid, principal, epoch) {
    if (principal === "old-local" && localTokenReplaced) return { ok: false, code: "UNAUTHORIZED" };
    const eff = principal === "old-local" ? "local" : principal;
    generationSeq += 1;
    const e = epoch || `epoch-${randomUUID()}`;
    const mark = guardNow === SESSION_GUARD && (markRule === "non-peer" ? eff !== "peer" : eff === "local");
    credentials.set(sid, { epoch: e, generation: generationSeq });
    marks.set(`${sid}\n${e}`, mark);
    return { ok: true, sid, epoch: e, generation: generationSeq, peer_scope_v1: mark };
  }

  // The delivering daemon's inject route for a local session (T-2 applied; nothing minted on refusal).
  // `J` (U4 rows, RC2): adopt the inject id a daemon in front of the seam already minted, instead of minting one.
  function inject({ sid, prompt, relay_context, J: minted }) {
    const c = credentials.get(sid);
    if (!c) return { ok: false, code: "SESSION_NOT_FOUND" };
    const v = validateRelayContext(relay_context, { resolvedSid: sid, role: "deliver" });
    if (!v.ok) return v;
    if (minted !== undefined && (typeof minted !== "string" || finals.has(minted))) return { ok: false, code: "INJECT_ID_INVALID" };
    const J = minted ?? randomUUID();
    finals.set(J, Object.freeze({
      J, relay_context: relay_context ? Object.freeze(structuredClone(relay_context)) : null, variant: v.variant, session: sid,
      epoch: c.epoch, generation: c.generation, delivered_payload_sha256: sha256(String(prompt)),
    }));
    return { ok: true, J };
  }

  function guardFor(f) {
    if (guardNow !== SESSION_GUARD) return null;
    return guardScope === "daemon" || marks.get(`${f.session}\n${f.epoch}`) === true ? SESSION_GUARD : null;
  }

  function bodyFor(f, stage, { seq } = {}) {
    const n = seq ?? (seqs.get(f.J) || 0) + 1;
    seqs.set(f.J, Math.max(n, seqs.get(f.J) || 0));
    const ctx = f.relay_context;
    return {
      v: 2, correlation_id: ctx ? ctx.correlation_id : null, origin_inject_id: f.variant === "final" ? ctx.origin_inject_id : null,
      final_inject_id: f.J, final_session: f.session, final_session_epoch: f.epoch, stage, seq: n, at: new Date().toISOString(),
      attested_by: { sid: f.session, epoch: f.epoch, generation: f.generation }, delivered_payload_sha256: f.delivered_payload_sha256,
      session_guard: guardFor(f),
    };
  }

  // T-3…T-5: D posts a stage with its own bearer (sid + epoch must be J's); F signs only for a final or
  // direct-final context. `forceSign` (row V2 only) models a buggy daemon that skips the eligibility refusal.
  function attestV2(J, stage, { forceSign = false, seq } = {}) {
    const f = finals.get(J);
    if (!f) return { ok: false, code: "INJECT_NOT_FOUND" };
    if (!forceSign && f.variant !== "final" && f.variant !== "direct-final") return { ok: false, code: "NOT_RECEIPT_ELIGIBLE" };
    const c = credentials.get(f.session);
    if (!c || c.epoch !== f.epoch) return { ok: false, code: "SESSION_CREDENTIAL_MISMATCH" };
    const r = signWith(key, bodyFor(f, stage, { seq }));
    post(r);
    return r;
  }

  function finalDaemon({ sid, epoch }) {
    issue(sid, "local", epoch);
    const at = () => new Date().toISOString();
    let seq = 0;
    return {
      // Relay send primitive (relay.js contract): the envelope text is delivered to `sid`.
      send: async (item) => {
        let env;
        try { env = JSON.parse(item.text); } catch { return { ok: false, sent: "yes", code: "ENVELOPE_INVALID" }; }
        if (!env || env.v !== 1 || env.final.sid !== sid || item.session !== sid) return { ok: false, sent: "yes", code: "ENVELOPE_INVALID" };
        const minted = inject({ sid, prompt: item.text, relay_context: item.relay_context ?? env.relay_context });
        if (!minted.ok) return { ok: false, sent: "yes", code: minted.code };
        const inject_id = minted.J;
        inbound.push({ inject_id, envelope: env });
        return { ok: true, transport_id: inject_id };
      },
      inbound,
      // The final session consumed / finished the work: own-bearer-attested receipts. A string first argument is
      // the v2 path (SPEC 2026-10-12 §5 attest(J, stage, opts)); an envelope object is the legacy v1 path.
      attest(env, stage, opts = {}) {
        if (typeof env === "string") return attestV2(env, stage, opts);
        const { inject_id = inbound.find((x) => x.envelope.correlation_id === env.correlation_id).inject_id, seqOverride, correlation_id } = opts;
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
    receipts, observations, inbound, finalDaemon, selfLabel, otherKeys,
    observe(injectId, status, sessionEpoch = null) { observations.set(injectId, { status, session_epoch: sessionEpoch }); },
    // ReceiptAdapter over this seam.
    adapter: {
      fetch: async (correlationId) => (receipts.get(correlationId) || []).map((r) => structuredClone(r)),
      consumption: async (injectId) => observations.get(injectId) || { status: "unknown" },
    },
    // ── SPEC 2026-10-12 §5 (v2 / synthetic F) ──
    keyId: () => key.keyId,
    publicPeerEntry: (peerIdAtO, locatorsAtO = [peerIdAtO]) => ({
      peer_id: peerIdAtO, locators: [...locatorsAtO], receipt_keys: [{ key_id: key.keyId, public_key_spki_b64: key.spki }],
    }),
    rotateKey() { key = syntheticKeys(); return key.keyId; },
    register: (sid, { principal = "local" } = {}) => issue(sid, principal),
    setGuard(g) {
      if (g === SESSION_GUARD && rotateOnEnable) localTokenReplaced = true;
      guardNow = g;
    },
    get guard() { return guardNow; },
    get localTokenReplaced() { return localTokenReplaced; },
    inject,
    attest: attestV2,
    final: (J) => finals.get(J) || null,
    // RS-9: kill/delete + re-register `sid` (fresh epoch) and inject J′ with the copied context.
    squat({ sid, prompt = "squat", relay_context, principal = "peer" }) {
      if (principal === "old-local" && localTokenReplaced) return { ok: false, code: "UNAUTHORIZED" };
      const eff = principal === "old-local" ? "local" : principal;
      if (guardNow === SESSION_GUARD && eff !== "local") return { ok: false, code: "PEER_SCOPE_DENIED" };
      credentials.delete(sid);
      const reg = issue(sid, principal);
      if (!reg.ok) return reg;
      const minted = inject({ sid, prompt, relay_context });
      return minted.ok ? { ok: true, J: minted.J, epoch: reg.epoch, peer_scope_v1: reg.peer_scope_v1 } : minted;
    },
    // ── Adversarial producers: each returns a receipt object and changes no stored J record. ──
    carry(r) { post(r); return r; },
    forge(J, stage, { key: k = otherKeys, keyId } = {}) {
      const f = finals.get(J);
      return signWith(k, { ...bodyFor(f, stage), key_id: keyId ?? k.keyId });
    },
    tamper(receipt, field, value) { return { ...structuredClone(receipt), [field]: value }; },
    retarget(receipt, fields) { return signWith(key, { ...bodyOf(receipt), ...fields, key_id: key.keyId }); },
    replay(receipt) { post(receipt); return receipt; },
    resign(receipt, { seq, at } = {}) { return signWith(key, { ...bodyOf(receipt), seq: seq ?? receipt.seq, at: at ?? receipt.at, key_id: key.keyId }); },
    stale: (J, stage) => attestV2(J, stage),
    unsigned(J, stage) {
      const f = finals.get(J);
      const n = (seqs.get(J) || 0) + 1;
      seqs.set(J, n);
      return {
        correlation_id: f.relay_context ? f.relay_context.correlation_id : null, inject_id: J, stage, role: "final", seq: n, at: new Date().toISOString(),
        attested_by: { sid: f.session, epoch: f.epoch }, auth_basis: "own_bearer",
      };
    },
  };
}
