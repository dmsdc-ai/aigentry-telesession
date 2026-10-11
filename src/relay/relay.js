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

// Bounded: at most `maxItems` sends and no new send once `now() >= deadlineAt`; the rest stays
// `queued` and is reported in `deferred` (picked up by a later tick).
export async function relayTick({ ledger, send, resolver, maxItems = Infinity, deadlineAt = Infinity, now = Date.now }) {
  const out = { sent: [], requeued: [], failed: [], uncertain: [], unresolved: [], skipped: [], deferred: [], commit_failed: [] };
  let attempted = 0;
  // A transition whose commit failed is reported as {key, code} instead of its outcome bucket.
  const settle = (key, from, fields, bucket) => {
    const c = ledger.outboxTransition(key, from, fields);
    if (c && c.ok === true) bucket.push(key);
    else out.commit_failed.push({ key, code: c && typeof c.code === "string" && CODE_RE.test(c.code) ? c.code : "COMMIT_FAILED" });
  };
  for (const item of ledger.outbox()) {
    if (item.state === "uncertain") { out.uncertain.push(item.key); continue; }
    if (item.state !== "queued") continue;
    if (attempted >= maxItems || now() >= deadlineAt) { out.deferred.push(item.key); continue; }
    const route = resolver.resolve(item.to);
    if (!route.ok) {
      settle(item.key, "queued", { last_error: route.code }, out.unresolved);
      continue;
    }
    // CLAIM + INTENT: durable before the send; the ledger lock is the claim.
    const intent = ledger.outboxTransition(item.key, "queued", { state: "intent", intent_at: new Date().toISOString() });
    if (!intent.ok) { out.skipped.push(item.key); continue; }
    attempted += 1;
    let r;
    try {
      r = await send({ key: item.key, nonce: item.nonce, kind: item.kind, peer_id: route.peer_id, locator: route.locator, session: route.session, text: item.text });
    } catch {
      r = { ok: false, sent: "unknown", code: "SEND_THREW" };
    }
    if (r && r.ok === true && typeof r.transport_id === "string" && TRANSPORT_ID_RE.test(r.transport_id)) {
      settle(item.key, "intent", { state: "sent", receipt: { transport_id: r.transport_id, at: new Date().toISOString() }, last_error: null }, out.sent);
    } else if (r && r.ok === false && r.sent === "no") {
      const attempts = item.attempts + 1;
      const done = attempts >= LEDGER_LIMITS.sendAttempts;
      settle(item.key, "intent", { state: done ? "failed" : "queued", attempts, intent_at: null, last_error: codeOf(r) }, done ? out.failed : out.requeued);
    } else if (r && r.ok === false && r.sent === "yes") {
      settle(item.key, "intent", { state: "failed", attempts: item.attempts + 1, last_error: codeOf(r) }, out.failed);
    } else {
      settle(item.key, "intent", { state: "uncertain", last_error: r && r.ok === true ? "RECEIPT_MALFORMED" : codeOf(r) }, out.uncertain);
    }
  }
  return out;
}
