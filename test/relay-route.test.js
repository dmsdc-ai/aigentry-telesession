// Route-resolution interface (SPEC 2026-10-11 §9): a fake permitted-peer table with two differing
// locator forms for the same peer (address form vs machine-name form, telepty #105).

import { test } from "node:test";
import assert from "node:assert/strict";
import { createRouteResolver, RouteError } from "../src/relay/route.js";

const PEERS = [
  { peer_id: "peer-a", locators: ["10.0.0.1", "host-a"] },
  { peer_id: "peer-b", locators: ["10.0.0.2", "Host-B.example"] },
];

test("T8 two locator forms of one peer resolve to the same canonical peer; unknown form is unresolved", () => {
  const r = createRouteResolver(PEERS);
  assert.equal(r.canonical("10.0.0.1"), "peer-a");
  assert.equal(r.canonical("host-a"), "peer-a");
  assert.equal(r.canonical("HOST-A"), "peer-a", "host forms compare case-insensitively");
  assert.equal(r.canonical("peer-a"), "peer-a", "the canonical id resolves to itself");
  assert.equal(r.canonical("host-c"), null);

  assert.deepEqual(r.resolve({ host: "host-a", session: "s1" }), { ok: true, peer_id: "peer-a", locator: "10.0.0.1", session: "s1" });
  assert.deepEqual(r.resolve({ host: "10.0.0.1", session: "s1" }), { ok: true, peer_id: "peer-a", locator: "10.0.0.1", session: "s1" });
  assert.deepEqual(r.resolve({ host: "host-c", session: "s1" }), { ok: false, code: "ROUTE_UNRESOLVED" });

  assert.equal(r.sameEndpoint({ host: "10.0.0.1", session: "s1" }, { host: "host-a", session: "s1" }), true);
  assert.equal(r.sameEndpoint({ host: "10.0.0.1", session: "s1" }, { host: "host-a", session: "s2" }), false, "session is exact");
  assert.equal(r.sameEndpoint({ host: "10.0.0.1", session: "s1" }, { host: "10.0.0.2", session: "s1" }), false);
  assert.equal(r.sameEndpoint({ host: "host-c", session: "s1" }, { host: "host-c", session: "s1" }), false, "unknown form never matches");
});

test("a locator form listed for two peers is ambiguous; malformed tables are refused", () => {
  const r = createRouteResolver([
    { peer_id: "peer-a", locators: ["shared", "a"] },
    { peer_id: "peer-b", locators: ["shared", "b"] },
  ]);
  assert.equal(r.canonical("shared"), null);
  assert.deepEqual(r.resolve({ host: "shared", session: "s" }), { ok: false, code: "ROUTE_AMBIGUOUS" });
  assert.deepEqual(r.resolve({ host: "a", session: "" }), { ok: false, code: "ROUTE_INVALID" });
  assert.throws(() => createRouteResolver("x"), RouteError);
  assert.throws(() => createRouteResolver([{ peer_id: "p", locators: [] }]), RouteError);
  assert.throws(() => createRouteResolver([{ peer_id: "p", locators: ["x"] }, { peer_id: "p", locators: ["y"] }]), RouteError);
});
