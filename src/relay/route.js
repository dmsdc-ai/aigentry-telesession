/**
 * Route resolution over a permitted peer table (SPEC 2026-10-11 §9). Every locator form a node may use
 * for a peer (address, machine name, …) maps to ONE canonical peer id; nothing is guessed (no DNS, no
 * fuzzy match). A form listed for two peers is ambiguous. Alias consistency across nodes is telepty
 * work (#105); this module only consumes the table it is given. Pure, no I/O.
 * SPEC 2026-10-12 §2.3: optional per-peer `receipt_keys: [{key_id, public_key_spki_b64}]` pin the final
 * daemon's receipt keys under this node's OWN peer id (no TOFU, never learned from a receipt or a hop).
 */

import { keyIdOf } from "./receipt-sig.js";

const PEER_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const LOCATOR_RE = /^[A-Za-z0-9._:\[\]-]{1,253}$/;
const SID_RE = /^[A-Za-z0-9._-]{1,128}$/;
const KEY_ID_RE = /^ed25519:[A-Za-z0-9_-]{43}$/;
const SPKI_B64_MAX = 128;
const RECEIPT_KEYS_MAX = 4;

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
  const pinned = new Map();       // peer_id → Map(key_id → public_key_spki_b64)
  const keyOwner = new Map();     // key_id → peer_id (one key_id under two peers is refused)
  for (const p of peers) {
    if (!p || typeof p.peer_id !== "string" || !PEER_RE.test(p.peer_id) || preferred.has(p.peer_id)
        || !Array.isArray(p.locators) || p.locators.length === 0
        || !p.locators.every((l) => typeof l === "string" && LOCATOR_RE.test(l))) {
      throw new RouteError("ROUTE_TABLE_INVALID");
    }
    preferred.set(p.peer_id, p.locators[0]);
    if (p.receipt_keys !== undefined) {
      if (!Array.isArray(p.receipt_keys) || p.receipt_keys.length > RECEIPT_KEYS_MAX) throw new RouteError("ROUTE_TABLE_INVALID");
      const keys = new Map();
      for (const k of p.receipt_keys) {
        if (!k || typeof k.key_id !== "string" || !KEY_ID_RE.test(k.key_id) || typeof k.public_key_spki_b64 !== "string"
            || k.public_key_spki_b64.length > SPKI_B64_MAX || keyIdOf(k.public_key_spki_b64) !== k.key_id || keyOwner.has(k.key_id)) {
          throw new RouteError("ROUTE_TABLE_INVALID");
        }
        keyOwner.set(k.key_id, p.peer_id);
        keys.set(k.key_id, k.public_key_spki_b64);
      }
      pinned.set(p.peer_id, keys);
    }
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

  // Keys pinned under this node's own name for `host` (any locator form); empty when none are pinned.
  function receiptKeys(host) {
    const id = canonical(host);
    return new Map(id !== null && pinned.has(id) ? pinned.get(id) : []);
  }

  function peerOfKey(keyId) {
    return keyOwner.get(keyId) ?? null;
  }

  return Object.freeze({ canonical, resolve, sameEndpoint, receiptKeys, peerOfKey });
}
