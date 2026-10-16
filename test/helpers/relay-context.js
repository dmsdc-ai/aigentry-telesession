/**
 * Shared relay-context validator (SPEC 2026-10-12 §1.2.2), used by every fake that accepts a `relay_context`
 * (fake-receipts.js seam, fake-telepty.js daemon + fake #111), so no fake passes a context through
 * unvalidated. Models the PROPOSED telepty#100 T-2 rule; it is not evidence that telepty implements it.
 *   role "deliver": the daemon that resolves the session locally (applies the final_session check);
 *   role "forward": a forwarding daemon (#111): shape, variants and mixed-form refusals, no final_session check.
 * Absent (undefined/null) → {ok:true, variant:null}.
 */

const HEX32_RE = /^[0-9a-f]{32}$/;
const INJECT_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const ORIGIN_KEYS = "correlation_id,leg,v";
const FINAL_KEYS = "correlation_id,final_session,hop,leg,origin_inject_id,v";
const INVALID = Object.freeze({ ok: false, code: "RELAY_CONTEXT_INVALID" });

export function validateRelayContext(ctx, { resolvedSid, role = "deliver" } = {}) {
  if (ctx === undefined || ctx === null) return { ok: true, variant: null };
  if (typeof ctx !== "object" || Array.isArray(ctx) || ctx.v !== 2 || typeof ctx.correlation_id !== "string" || !HEX32_RE.test(ctx.correlation_id)) return INVALID;
  const keys = Object.keys(ctx).sort().join(",");
  if (ctx.leg === "origin") return keys === ORIGIN_KEYS ? { ok: true, variant: "origin" } : INVALID;
  if (ctx.leg !== "final" || keys !== FINAL_KEYS) return INVALID;
  if (typeof ctx.final_session !== "string" || ctx.final_session.length < 1 || ctx.final_session.length > 128 || !Number.isInteger(ctx.hop)) return INVALID;
  let variant;
  if (typeof ctx.origin_inject_id === "string" && INJECT_ID_RE.test(ctx.origin_inject_id) && ctx.hop >= 1 && ctx.hop <= 4) variant = "final";
  else if (ctx.origin_inject_id === null && ctx.hop === 0) variant = "direct-final";
  else return INVALID;
  if (role === "deliver" && ctx.final_session !== resolvedSid) return INVALID;
  return { ok: true, variant };
}
