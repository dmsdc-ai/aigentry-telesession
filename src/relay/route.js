/**
 * Route resolution over a permitted peer table (SPEC 2026-10-11 §9). Every locator form a node may use
 * for a peer (address, machine name, …) maps to ONE canonical peer id; nothing is guessed (no DNS, no
 * fuzzy match). A form listed for two peers is ambiguous. Alias consistency across nodes is telepty
 * work (#105); this module only consumes the table it is given. Pure, no I/O.
 */

const PEER_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const LOCATOR_RE = /^[A-Za-z0-9._:\[\]-]{1,253}$/;
const SID_RE = /^[A-Za-z0-9._-]{1,128}$/;

export class RouteError extends Error {
  constructor(code) {
    super(code);
    this.name = "RouteError";
    this.code = code;
  }
}

const norm = (s) => s.toLowerCase();

export function createRouteResolver(peers) {
  if (!Array.isArray(peers)) throw new RouteError("ROUTE_TABLE_INVALID");
  const byForm = new Map();       // normalized form → Set(peer_id)
  const preferred = new Map();    // peer_id → first locator (the form used to send)
  for (const p of peers) {
    if (!p || typeof p.peer_id !== "string" || !PEER_RE.test(p.peer_id) || preferred.has(p.peer_id)
        || !Array.isArray(p.locators) || p.locators.length === 0
        || !p.locators.every((l) => typeof l === "string" && LOCATOR_RE.test(l))) {
      throw new RouteError("ROUTE_TABLE_INVALID");
    }
    preferred.set(p.peer_id, p.locators[0]);
    for (const form of [p.peer_id, ...p.locators]) {
      const k = norm(form);
      if (!byForm.has(k)) byForm.set(k, new Set());
      byForm.get(k).add(p.peer_id);
    }
  }

  function lookup(host) {
    if (typeof host !== "string") return { code: "ROUTE_INVALID" };
    const ids = byForm.get(norm(host));
    if (!ids) return { code: "ROUTE_UNRESOLVED" };
    if (ids.size > 1) return { code: "ROUTE_AMBIGUOUS" };
    return { peer_id: ids.values().next().value };
  }

  function canonical(host) {
    const r = lookup(host);
    return r.peer_id || null;
  }

  function resolve(endpoint) {
    const e = endpoint || {};
    if (typeof e.session !== "string" || !SID_RE.test(e.session)) return { ok: false, code: "ROUTE_INVALID" };
    const r = lookup(e.host);
    if (!r.peer_id) return { ok: false, code: r.code };
    return { ok: true, peer_id: r.peer_id, locator: preferred.get(r.peer_id), session: e.session };
  }

  function sameEndpoint(a, b) {
    if (!a || !b || typeof a.session !== "string" || a.session !== b.session) return false;
    const x = canonical(a.host);
    return x !== null && x === canonical(b.host);
  }

  return Object.freeze({ canonical, resolve, sameEndpoint });
}
