/**
 * R-side relay context (SPEC 2026-10-12 §1.2 R → F, §1.2.2; task #2026101110 U4). The relay context is
 * out-of-band (inject body, never the prompt) and carries no host name. R copies C and I verbatim and never
 * builds a final context with a null I: on I = null, or an inbound direct-final context, it sends none.
 */

export const RELAY_HOP_MAX = 4;

const HEX32_RE = /^[0-9a-f]{32}$/;
const INJECT_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const ORIGIN_KEYS = "correlation_id,leg,v";
const FINAL_KEYS = "correlation_id,final_session,hop,leg,origin_inject_id,v";

// The §1.2.2 variant ("origin" | "final" | "direct-final") of `ctx`, or null for anything else. `maxHop` lets the
// ledger hold an outgoing hop RELAY_HOP_MAX + 1 context until the send refuses it (RELAY_HOP_LIMIT).
export function relayContextVariant(ctx, { maxHop = RELAY_HOP_MAX } = {}) {
  if (ctx === null || typeof ctx !== "object" || Array.isArray(ctx) || ctx.v !== 2
      || typeof ctx.correlation_id !== "string" || !HEX32_RE.test(ctx.correlation_id)) return null;
  const keys = Object.keys(ctx).sort().join(",");
  if (ctx.leg === "origin") return keys === ORIGIN_KEYS ? "origin" : null;
  if (ctx.leg !== "final" || keys !== FINAL_KEYS || typeof ctx.final_session !== "string" || ctx.final_session.length < 1
      || ctx.final_session.length > 128 || !Number.isInteger(ctx.hop)) return null;
  if (typeof ctx.origin_inject_id === "string" && INJECT_ID_RE.test(ctx.origin_inject_id) && ctx.hop >= 1 && ctx.hop <= maxHop) return "final";
  if (ctx.origin_inject_id === null && ctx.hop === 0) return "direct-final";
  return null;
}

// The context R sends to F for its outbox destination `finalSession`. `inbound` is the context of R's leg-1
// inject (null under the interim lookup, §1.2(b): hop 0, C from the wire header); `originInjectId` is the I R's
// lookup found (null = ORIGIN_INJECT_AMBIGUOUS). Returns null when R must forward without relay_context.
export function nextRelayContext({ inbound = null, correlationId, originInjectId, finalSession }) {
  const variant = inbound === null ? null : relayContextVariant(inbound);
  if (inbound !== null && (variant === null || variant === "direct-final")) return null;
  if (variant === "final") {
    return { v: 2, leg: "final", correlation_id: inbound.correlation_id, origin_inject_id: inbound.origin_inject_id, final_session: finalSession, hop: inbound.hop + 1 };
  }
  if (typeof originInjectId !== "string") return null;
  return { v: 2, leg: "final", correlation_id: variant === "origin" ? inbound.correlation_id : correlationId, origin_inject_id: originInjectId, final_session: finalSession, hop: 1 };
}
