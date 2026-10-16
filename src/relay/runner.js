/**
 * In-process relay runner (SPEC 2026-10-11 §10). Runs relayTick inside the process that owns the ledger
 * lock: opt-in (`intervalMs` 0 = no timer; config TELESESSION_RELAY_INTERVAL_MS), bounded per tick
 * (`maxItems`, `maxTickMs`), never two ticks at once (in-process guard), no resend after a restart
 * (an `intent` left by a dead process is `uncertain` on open and only surfaced). Enabling the interval
 * in a live deployment is a separate approval.
 *
 * transportSendPrimitive(send) adapts the transport's own `send` to the relay send contract.
 */

import { relayTick } from "./relay.js";

export const RELAY_TICK_LIMITS = Object.freeze({ maxItems: 16, maxTickMs: 5000 });

const BUCKETS = ["sent", "requeued", "failed", "uncertain", "unresolved", "skipped", "deferred", "commit_failed"];

export function createRelayRunner({ ledger, send, resolver, intervalMs = 0, maxItems = RELAY_TICK_LIMITS.maxItems,
  maxTickMs = RELAY_TICK_LIMITS.maxTickMs, now = Date.now } = {}) {
  let running = null;
  let timer = null;
  let lastTickAt = null;
  let lastResult = null;

  async function run() {
    try {
      // A failed sweep leaves expired/retired items unquarantined: no claim or send on top of it (TS2).
      if (typeof ledger.sweepOutbox === "function") {
        const sw = ledger.sweepOutbox();
        if (!sw || sw.ok !== true) {
          lastResult = { error: "RELAY_SWEEP_FAILED" };
          return { ok: false, code: "RELAY_SWEEP_FAILED" };
        }
      }
      const out = await relayTick({ ledger, send, resolver, maxItems, deadlineAt: now() + maxTickMs, now });
      lastResult = Object.fromEntries(BUCKETS.map((k) => [k, out[k].length]));
      return { ok: true, ...out };
    } catch {
      lastResult = { error: "RELAY_TICK_FAILED" };
      return { ok: false, code: "RELAY_TICK_FAILED" };
    } finally {
      lastTickAt = new Date(now()).toISOString();
    }
  }

  function tick() {
    if (running) return Promise.resolve({ ok: false, code: "RELAY_TICK_IN_PROGRESS" });
    running = run().finally(() => { running = null; });
    return running;
  }

  function start() {
    if (!(intervalMs > 0) || timer) return timer !== null;
    timer = setInterval(() => { tick(); }, intervalMs);
    if (typeof timer.unref === "function") timer.unref();
    return true;
  }

  function stop() {
    if (timer) { clearInterval(timer); timer = null; }
  }

  function health() {
    const items = ledger.outbox();
    const q = items.filter((o) => o.quarantine);
    const oldest = q.length ? Math.min(...q.map((o) => Date.parse(o.created_at))) : null;
    return {
      enabled: timer !== null, running: running !== null, last_tick_at: lastTickAt, last_result: lastResult ? { ...lastResult } : null,
      uncertain_count: items.filter((o) => o.state === "uncertain").length,
      queued_count: items.filter((o) => o.state === "queued" && !o.quarantine).length,
      quarantined_count: q.length, oldest_quarantined_age_ms: oldest === null ? null : Math.max(0, now() - oldest),
    };
  }

  // Resolves once no tick is running (close() waits on it, bounded by the caller).
  const idle = () => (running ? running.then(() => {}) : Promise.resolve());

  return Object.freeze({ tick, start, stop, health, idle });
}

// transport.send record → relay contract. The relay key is the transport idempotency key, so a resend of
// the same item can never inject twice. Refusals before any inject are definite non-sends ("no"). The
// route's peer travels as `destination` (the same session name may exist on several hosts).
// Durable attempt key (Mac re-review TS3): the ledger counts an attempt only after a proven non-send
// (sent:"no"), so each such attempt gets its own request_id and is a new POST, never the transport's
// persisted refusal of the previous attempt. Attempt 0 keeps `relay:<key>`; intent/uncertain/sent items
// are never sent again, so an ambiguous or accepted attempt is never retried.
// Fail closed (#2026101110 U2): the transport injects into its LOCAL daemon only, so an item for another
// peer is refused before any inject (never delivered to a local same-name session). A real cross-host send
// needs a daemon-side exact remote forward (telepty#111).
export function transportSendPrimitive(send, { localPeer = "local" } = {}) {
  return async (item) => {
    if (item.peer_id !== localPeer) return { ok: false, sent: "no", code: "PEER_UNSUPPORTED" };
    const r = await send({
      target: item.session, text: item.text, request_id: item.attempt > 0 ? `relay:${item.key}:${item.attempt}` : `relay:${item.key}`, destination: { host: item.peer_id, session: item.session },
    });
    if (r && r.ok === true) {
      if (r.accepted === true && typeof r.inject_id === "string") return { ok: true, transport_id: r.inject_id };
      if (r.accepted === false) return { ok: false, sent: "yes", code: r.error_code || "SEND_REFUSED" };
      return { ok: false, sent: "unknown", code: typeof r.reason === "string" ? r.reason : "ACCEPTANCE_UNKNOWN" };
    }
    const e = (r && r.error) || {};
    const code = typeof e.code === "string" ? e.code : "SEND_FAILED";
    if (e.accepted === false && e.http_status != null) return { ok: false, sent: "yes", code };
    // REQUEST_IN_FLIGHT: a same-id send may still deliver; not a proven non-send, so never a new attempt key (B-1).
    if (e.accepted === "unknown" || code === "TRANSPORT_INTERNAL" || code === "REQUEST_IN_FLIGHT") return { ok: false, sent: "unknown", code };
    return { ok: false, sent: "no", code };
  };
}
