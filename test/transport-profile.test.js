// Issue #16 — Telesession profile mode transport against the loopback fake daemon (rows S-T*). The fake
// emulates the RESPONSES of a Telepty `client-profile-scope-v1` daemon (test/helpers/fake-telepty.js). These
// rows prove CLIENT behaviour only — carrier, capability/caller verification, fail-closed mapping, health
// truth. They are NOT server-enforcement evidence; that is test/real-daemon-profile.test.js (S-R*) against a
// real Telepty build. Synthetic tpc1 tokens and temp dirs only.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { loadConfig, normalizeConfig, createTeleptyTransport } from "../src/index.js";
import { startFakeTelepty, PROFILE_SCOPE_CAPABILITY } from "./helpers/fake-telepty.js";

const POSIX = process.platform !== "win32";
const mkToken = (gen) => `tpc1.${gen}.${randomBytes(32).toString("base64url")}`;
const skip = !POSIX && "NOTRUN: profile mode is refused on win32 (CONFIG_PROFILE_PLATFORM_UNSUPPORTED)";

// Two profiles on one fake daemon; the Telesession profiles file points at the fake's origin.
async function setup(t, { fake: fakeOpts = {}, gens = { "asst-a": 3, "asst-b": 7 } } = {}) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "ts-profile-tr-")));
  const tokens = Object.fromEntries(Object.entries(gens).map(([n, g]) => [n, mkToken(g)]));
  const fake = await startFakeTelepty({
    targets: ["orchestrator", "worker-2"],
    clientProfiles: [
      { profile: "asst-a", inbox_prefix: "exa", targets: ["orchestrator"], generation: gens["asst-a"], token: tokens["asst-a"] },
      { profile: "asst-b", inbox_prefix: "exb", targets: ["orchestrator", "worker-2"], generation: gens["asst-b"], token: tokens["asst-b"] },
    ],
    ...fakeOpts,
  });
  const opened = [];
  t.after(async () => {
    for (const tr of opened) { try { await tr.close(); } catch { /* best effort */ } }
    await fake.close();
    try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
  });
  for (const d of ["keys", "state", "home", "cwd"]) fs.mkdirSync(path.join(root, d), { mode: 0o700 });
  const profiles = {};
  for (const [n, prefix, targets] of [["asst-a", "exa", ["orchestrator"]], ["asst-b", "exb", ["orchestrator", "worker-2"]]]) {
    const tf = path.join(root, "keys", `${n}.token`);
    fs.writeFileSync(tf, tokens[n], { mode: 0o600 });
    profiles[n] = { inbox_prefix: prefix, targets, state_dir: path.join(root, "state", n), token_file: tf };
  }
  const file = path.join(root, "profiles.json");
  fs.writeFileSync(file, JSON.stringify({ schema: "telesession.profiles/v1", telepty_url: fake.origin, profiles }), { mode: 0o600 });
  const seam = { homedir: path.join(root, "home"), cwd: path.join(root, "cwd") };
  const open = (name) => {
    const tr = createTeleptyTransport(loadConfig({ TELESESSION_PROFILE: name, TELESESSION_PROFILES_FILE: file }), seam);
    opened.push(tr);
    return tr;
  };
  return { root, fake, tokens, open };
}

// Every request this process sent in profile mode carried exactly the profile token, never the shared token.
function assertCarrier(fake, token) {
  assert.ok(fake.requests.length > 0);
  for (const r of fake.requests) {
    assert.equal(r.rootTokenSent, false, `${r.method} ${r.path} must not carry x-telepty-token`);
    assert.equal(r.clientToken, token, `${r.method} ${r.path} carries this profile's client token`);
  }
}

const nonMeta = (fake) => fake.requests.filter((r) => r.path !== "/api/meta");

test("S-T0 own ops: profile A creates its inbox in its namespace and injects to an allowed target with only x-telepty-client-token", { skip }, async (t) => {
  const s = await setup(t);
  const a = s.open("asst-a");
  const r = await a.send({ target: "orchestrator", text: "hello from A", request_id: "req-1" });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.match(s.fake.registrations[0].session_id, /^exa-i[0-9a-f]{32}$/);
  assert.equal(s.fake.injectsTo("orchestrator").length, 1);
  assertCarrier(s.fake, s.tokens["asst-a"]);
  // request_id replay: the earlier record, no second inject (no same-nonce retransmit).
  const again = await a.send({ target: "orchestrator", text: "hello from A", request_id: "req-1" });
  assert.equal(again.deduplicated, true);
  assert.equal(again.nonce, r.nonce);
  assert.equal(s.fake.injectsTo("orchestrator").length, 1);
  const closed = await a.close();
  assert.equal(closed.outcome, "deleted");
  assertCarrier(s.fake, s.tokens["asst-a"]);
});

test("S-T6 health.credential comes from the verified server caller (profile mode)", { skip }, async (t) => {
  const s = await setup(t);
  const h = await s.open("asst-b").health();
  assert.equal(h.ok, true);
  assert.deepEqual(h.credential, { mode: "client-profile", profile: "asst-b", server_enforced: true, shared_token_in_use: false, generation: 7 });
  assert.deepEqual(h.telepty.capabilities_missing, []);
  const text = JSON.stringify(h);
  for (const tok of Object.values(s.tokens)) assert.ok(!text.includes(tok), "no token in health");
  assert.ok(!text.includes(s.root), "no private path in health");
});

test("S-T6 health.credential in legacy shared-control mode is truthful (server caller or the shared token actually sent)", async (t) => {
  const fake = await startFakeTelepty({ targets: ["orchestrator"] });
  t.after(() => fake.close());
  const tr = createTeleptyTransport(normalizeConfig({ teleptyUrl: fake.origin, token: fake.token, targets: ["orchestrator"], inboxPrefix: "ts" }));
  t.after(() => tr.close());
  const h = await tr.health();
  assert.deepEqual(h.credential, { mode: "shared-control", profile: null, server_enforced: false, shared_token_in_use: true, generation: null });
  // Legacy carrier unchanged: the shared token, never a client token.
  assert.ok(fake.requests.every((r) => r.authorized && r.clientToken === null));
});

test("S-T4a real-daemon shape: daemon without profile scope answers 401 → PROFILE_CREDENTIAL_REJECTED, no register/inject, never the shared token", { skip }, async (t) => {
  const s = await setup(t, { fake: { profileScope: false } });
  const a = s.open("asst-a");
  const r = await a.send({ target: "orchestrator", text: "x" });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, "PROFILE_CREDENTIAL_REJECTED");
  const l = await a.listAllowedTargets();
  assert.equal(l.error && l.error.code, "PROFILE_CREDENTIAL_REJECTED");
  const h = await a.health();
  assert.equal(h.credential.server_enforced, null);
  assert.equal(h.credential.code, "PROFILE_CREDENTIAL_REJECTED");
  assert.equal(h.credential.shared_token_in_use, false);
  assert.deepEqual(nonMeta(s.fake), [], "nothing but /api/meta reached the daemon");
  assert.equal(s.fake.registrations.length, 0);
  assertCarrier(s.fake, s.tokens["asst-a"]);
});

test("S-T4b fake 200 without client-profile-scope-v1 → DAEMON_LACKS_CAPABILITY, no register/inject", { skip }, async (t) => {
  const s = await setup(t);
  s.fake.flags.omitProfileCapability = true;
  const a = s.open("asst-a");
  const r = await a.send({ target: "orchestrator", text: "x" });
  assert.equal(r.error.code, "DAEMON_LACKS_CAPABILITY");
  assert.deepEqual(r.error.missing, [PROFILE_SCOPE_CAPABILITY]);
  assert.deepEqual(nonMeta(s.fake), []);
  const h = await a.health();
  assert.equal(h.credential.server_enforced, false);
});

test("S-T5 capability present but caller not this profile's server enforcement → PROFILE_NOT_ENFORCED before any own op", { skip }, async (t) => {
  const variants = [
    { kind: "shared-control" }, { profile: "asst-b" }, { inbox_prefix: "exb" }, { targets: ["worker-2"] }, { targets: "orchestrator" },
    { generation: 4 }, { generation: "3" }, { enforcement: "none" }, { shared_token: true },
  ];
  for (const callerOverride of variants) {
    const s = await setup(t);
    s.fake.flags.callerOverride = callerOverride;
    const a = s.open("asst-a");
    const r = await a.send({ target: "orchestrator", text: "x" });
    assert.equal(r.error && r.error.code, "PROFILE_NOT_ENFORCED", JSON.stringify(callerOverride));
    const l = await a.listAllowedTargets();
    assert.equal(l.error && l.error.code, "PROFILE_NOT_ENFORCED");
    assert.deepEqual(nonMeta(s.fake), [], JSON.stringify(callerOverride));
    const h = await a.health();
    assert.equal(h.credential.server_enforced, false);
    assert.equal(h.credential.generation, null);
  }
});

test("registry 503 PROFILE_REGISTRY_UNAVAILABLE and 401 PROFILE_CREDENTIAL_INVALID pass through without fallback", { skip }, async (t) => {
  const s = await setup(t);
  s.fake.flags.registryUnavailable = true;
  const a = s.open("asst-a");
  assert.equal((await a.send({ target: "orchestrator", text: "x" })).error.code, "PROFILE_REGISTRY_UNAVAILABLE");
  assert.equal((await a.health()).credential.code, "PROFILE_REGISTRY_UNAVAILABLE");
  s.fake.flags.registryUnavailable = false;
  // Rotation on the server (new generation/verifier): the old token is rejected; the client never falls back.
  s.fake.flags.metaStatus = 401;
  assert.equal((await a.send({ target: "orchestrator", text: "y" })).error.code, "PROFILE_CREDENTIAL_REJECTED");
  assert.deepEqual(nonMeta(s.fake), []);
  assertCarrier(s.fake, s.tokens["asst-a"]);
});

test("a refused gate is re-checked: once the server proves the caller, the same process proceeds", { skip }, async (t) => {
  const s = await setup(t);
  s.fake.flags.callerOverride = { enforcement: "none" };
  const a = s.open("asst-a");
  assert.equal((await a.send({ target: "orchestrator", text: "x" })).error.code, "PROFILE_NOT_ENFORCED");
  s.fake.flags.callerOverride = null;
  const r = await a.send({ target: "orchestrator", text: "x2" });
  assert.equal(r.ok, true, JSON.stringify(r));
});

test("cross-profile (emulated server refusals): B's targets/namespace are not A's; A cannot be configured or verified into B", { skip }, async (t) => {
  const s = await setup(t);
  const b = s.open("asst-b");
  const okB = await b.send({ target: "worker-2", text: "B owns worker-2 grant" });
  assert.equal(okB.ok, true);
  const a = s.open("asst-a");
  // A's own config never names worker-2; a send there is refused locally (allowlist), nothing sent.
  const before = s.fake.requests.length;
  assert.equal((await a.send({ target: "worker-2", text: "x" })).error.code, "TARGET_NOT_ALLOWED");
  assert.equal(s.fake.requests.length, before);
  // A's listing never shows B's inbox (server filter, emulated).
  const listed = await a.listAllowedTargets();
  assert.deepEqual(listed.targets, [{ id: "orchestrator", present: true }]);
  // Raw calls with A's token against B's inbox id: refused by the (emulated) server gate.
  const bInbox = s.fake.registrations.find((x) => x.session_id.startsWith("exb-i")).session_id;
  const raw = async (method, p, body) => {
    const res = await fetch(s.fake.origin + p, { method, headers: { "x-telepty-client-token": s.tokens["asst-a"], ...(body ? { "content-type": "application/json" } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, body: await res.json() };
  };
  assert.equal((await raw("POST", `/api/sessions/${bInbox}/inject`, { prompt: "p", from: a.inboxId, reply_to: a.inboxId, exact_target: true })).status, 403);
  assert.equal((await raw("GET", `/api/injects?to=${bInbox}`)).status, 403);
  assert.equal((await raw("DELETE", `/api/sessions/${bInbox}?owned=true`)).status, 403);
  assert.equal((await raw("POST", "/api/sessions/register", { session_id: `exb-i${"0".repeat(32)}`, delivery_type: "aterm", delivery_endpoint: "http://127.0.0.1:1/x", create_only: true })).status, 403);
  // Mixed carrier: a profile token together with the shared token is ambiguous, never admin.
  const mixed = await fetch(`${s.fake.origin}/api/meta`, { headers: { "x-telepty-client-token": s.tokens["asst-a"], "x-telepty-token": s.fake.token } });
  assert.equal(mixed.status, 400);
  assert.ok(s.fake.sessions.has(bInbox), "B's inbox still exists");
});

test("S-T8 redirect from the daemon is refused; the Location listener receives nothing (no token leak)", { skip }, async (t) => {
  const hits = [];
  const sink = http.createServer((req, res) => { hits.push(req.headers); res.end("{}"); });
  await new Promise((r) => sink.listen({ host: "127.0.0.1", port: 0 }, r));
  const redirector = http.createServer((req, res) => {
    res.writeHead(307, { location: `http://127.0.0.1:${sink.address().port}${req.url}` });
    res.end();
  });
  await new Promise((r) => redirector.listen({ host: "127.0.0.1", port: 0 }, r));
  t.after(() => { sink.close(); redirector.close(); });
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "ts-profile-redir-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const d of ["keys", "state", "home", "cwd"]) fs.mkdirSync(path.join(root, d), { mode: 0o700 });
  const tf = path.join(root, "keys", "a.token");
  fs.writeFileSync(tf, mkToken(1), { mode: 0o600 });
  const file = path.join(root, "profiles.json");
  fs.writeFileSync(file, JSON.stringify({ schema: "telesession.profiles/v1", telepty_url: `http://127.0.0.1:${redirector.address().port}`,
    profiles: { "asst-a": { inbox_prefix: "exa", targets: ["orchestrator"], state_dir: path.join(root, "state", "a"), token_file: tf } } }), { mode: 0o600 });
  const tr = createTeleptyTransport(loadConfig({ TELESESSION_PROFILE: "asst-a", TELESESSION_PROFILES_FILE: file }), { homedir: path.join(root, "home"), cwd: path.join(root, "cwd") });
  t.after(() => tr.close());
  const r = await tr.send({ target: "orchestrator", text: "x" });
  assert.equal(r.error.code, "DAEMON_REDIRECT_REFUSED");
  assert.equal(hits.length, 0);
});
