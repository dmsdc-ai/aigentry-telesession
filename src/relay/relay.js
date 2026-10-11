/**
 * Host-side relay tick (SPEC 2026-10-11 §10), reusing the claim → intent → send → receipt → uncertain →
 * dedup state machine of the orchestrator's outbox design. One call = one pass over `queued` items; it
 * never loops, never schedules itself and never resends an `intent`/`uncertain`/`sent` item. Running it
 * as a process, timer or unit is a separate approval.
 *
 * send(item) → {ok:true, transport_id} | {ok:false, sent:"no"|"yes"|"unknown", code}. A throw is
 * `sent:"unknown"`. `sent` is hop evidence only; it never completes a request.
 */

import { LEDGER_LIMITS } from "./ledger.js";

const CODE_RE = /^[A-Za-z0-9_]{1,64}$/;
const TRANSPORT_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;

const codeOf = (r) => (r && typeof r.code === "string" && CODE_RE.test(r.code) ? r.code : "SEND_FAILED");

export async function relayTick({ ledger, send, resolver }) {
  const out = { sent: [], requeued: [], failed: [], uncertain: [], unresolved: [], skipped: [] };
  for (const item of ledger.outbox()) {
    if (item.state === "uncertain") { out.uncertain.push(item.key); continue; }
    if (item.state !== "queued") continue;
    const route = resolver.resolve(item.to);
    if (!route.ok) {
      ledger.outboxTransition(item.key, "queued", { last_error: route.code });
      out.unresolved.push(item.key);
      continue;
    }
    // CLAIM + INTENT: durable before the send; the ledger lock is the claim.
    const intent = ledger.outboxTransition(item.key, "queued", { state: "intent", intent_at: new Date().toISOString() });
    if (!intent.ok) { out.skipped.push(item.key); continue; }
    let r;
    try {
      r = await send({ key: item.key, nonce: item.nonce, kind: item.kind, peer_id: route.peer_id, locator: route.locator, session: route.session, text: item.text });
    } catch {
      r = { ok: false, sent: "unknown", code: "SEND_THREW" };
    }
    if (r && r.ok === true && typeof r.transport_id === "string" && TRANSPORT_ID_RE.test(r.transport_id)) {
      ledger.outboxTransition(item.key, "intent", { state: "sent", receipt: { transport_id: r.transport_id, at: new Date().toISOString() }, last_error: null });
      out.sent.push(item.key);
    } else if (r && r.ok === false && r.sent === "no") {
      const attempts = item.attempts + 1;
      const done = attempts >= LEDGER_LIMITS.sendAttempts;
      ledger.outboxTransition(item.key, "intent", { state: done ? "failed" : "queued", attempts, intent_at: null, last_error: codeOf(r) });
      (done ? out.failed : out.requeued).push(item.key);
    } else if (r && r.ok === false && r.sent === "yes") {
      ledger.outboxTransition(item.key, "intent", { state: "failed", attempts: item.attempts + 1, last_error: codeOf(r) });
      out.failed.push(item.key);
    } else {
      ledger.outboxTransition(item.key, "intent", { state: "uncertain", last_error: r && r.ok === true ? "RECEIPT_MALFORMED" : codeOf(r) });
      out.uncertain.push(item.key);
    }
  }
  return out;
}
