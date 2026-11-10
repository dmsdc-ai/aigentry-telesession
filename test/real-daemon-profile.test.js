// Issue #16 — S-R* rows: two Telesession profiles against a REAL spawned Telepty with
// `client-profile-scope-v1` (contract564 §3 + review569 §3; Telepty ≥ 0.11.0). This is the only Telesession
// file that can show server enforcement. NOTRUN unless TELESESSION_TEST_TELEPTY_DIR (or ../telepty) is a
// Telepty source tree whose package.json version is ≥ 0.11.0 and that ships src/protocol/client-profiles.js.
// Native macOS and Linux only; win32 → NOTRUN (profile mode is refused there; refusal rows live elsewhere).
// Hermetic: temp HOME, synthetic tpc1 tokens, loopback daemon on port 0.
// RB1 (review698): TELESESSION_TEST_REQUIRE_PROFILE_DAEMON=1 (set by the supported-POSIX CI/release legs) turns a
// missing, too-old or capability-less Telepty into a FAILING row instead of a NOTRUN skip, so a skip can never be
// counted as the S-R1 release evidence. It has no effect on win32.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { loadConfig, createTeleptyTransport } from "../src/index.js";
import { observationUnavailableBody } from "./helpers/fake-telepty.js";
import { HAS_TELEPTY, TELEPTY_DIR, startAtermEndpoint, startTeleptyDaemon, registerAterm } from "./helpers.js";

function teleptyVersion() {
  try { return String(JSON.parse(fs.readFileSync(path.join(TELEPTY_DIR, "package.json"), "utf8")).version); } catch { return null; }
}
function teleptyVersionAtLeast(major, minor) {
  const m = /^(\d+)\.(\d+)\./.exec(String(teleptyVersion()));
  return Boolean(m) && (Number(m[1]) > major || (Number(m[1]) === major && Number(m[2]) >= minor));
}
const REQUIRE = process.env.TELESESSION_TEST_REQUIRE_PROFILE_DAEMON === "1";
const PROFILE_CAPABILITY = "client-profile-scope-v1";
const UNAVAILABLE = !HAS_TELEPTY ? `no Telepty source at ${TELEPTY_DIR}`
  : !fs.existsSync(path.join(TELEPTY_DIR, "src", "protocol", "client-profiles.js")) ? "Telepty source has no src/protocol/client-profiles.js"
    : !teleptyVersionAtLeast(0, 11) ? `Telepty ${teleptyVersion()} < 0.11.0 has no ${PROFILE_CAPABILITY}` : null;
const SKIP = process.platform === "win32" ? "NOTRUN: profile mode unsupported on native Windows"
  : UNAVAILABLE && !REQUIRE ? `NOTRUN: ${UNAVAILABLE}` : false;
// Under REQUIRE the row runs; an unavailable Telepty is a failure with its reason, never a pass.
function requireProfileDaemon() {
  if (UNAVAILABLE) assert.fail(`TELESESSION_TEST_REQUIRE_PROFILE_DAEMON=1 but ${UNAVAILABLE}`);
}
// The daemon itself must advertise the capability (wrong-capability source fails, it is not skipped).
async function assertProfileCapability(daemon) {
  const meta = await daemon.request("/api/meta");
  assert.equal(meta.status, 200);
  assert.ok(Array.isArray(meta.body.capabilities) && meta.body.capabilities.includes(PROFILE_CAPABILITY),
    `daemon ${meta.body.version} does not advertise ${PROFILE_CAPABILITY}`);
}
const iso = (ms) => new Date(ms).toISOString();
const grant = (profile, prefix, token, generation, notBefore) =>
  ({ profile, inbox_prefix: prefix, targets: ["orchestrator"], generation, token_verifier: verifier(token), not_before: notBefore });
// Atomic replace (new inode, nlink 1, mode 0600), as an operator edits the server file.
function writePrivateAtomic(file, text) {
  const tmp = `${file}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  fs.writeFileSync(tmp, text, { mode: 0o600, flag: "wx" });
  fs.chmodSync(tmp, 0o600);
  fs.renameSync(tmp, file);
}
const rawAs = (daemon, token) => async (method, p, body, extra = {}) => {
  const res = await fetch(daemon.origin + p, { method, redirect: "manual", headers: { "x-telepty-client-token": token, ...extra, ...(body ? { "content-type": "application/json" } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { json = null; }
  return { status: res.status, body: json };
};
// The server's foreign/unknown observation body; `capability` is the server's own object (not compared by value).
function assertUnavailableObservation(o, id) {
  assert.equal(o.status, 200);
  const { capability, ...rest } = o.body;
  const { capability: _fake, ...expected } = observationUnavailableBody(id);
  assert.deepEqual(rest, expected);
  assert.ok(capability && typeof capability === "object" && !Array.isArray(capability));
}

// ci733 defect A: GET /api/sessions also returns fields the server computes per read from `now` (readiness/handshake
// sampled_at, idleSeconds, healthStatus, healthReason, disconnectedSeconds, transport; server
// src/routes/session-inspection.js:186 and src/readiness.js:45), so two reads differ with no state change. Before/after
// comparisons use only this allow-list of stored session state, sorted by id. A field is kept only when present.
const STABLE_SESSION_FIELDS = ["id", "session_epoch", "type", "command", "cwd", "createdAt", "deliveryEndpoint", "delivery",
  "lastInjectReturn", "lastActivityAt", "lastConnectedAt", "lastDisconnectedAt", "active_clients", "ready", "owningPrincipal", "authorityAudit"];
const STABLE_HANDSHAKE_FIELDS = ["session_epoch", "owner_generation", "status", "reason"];
function stableSessions(body) {
  assert.ok(Array.isArray(body), "GET /api/sessions answers an array");
  const pick = (src, keys) => Object.fromEntries(keys.filter((k) => Object.hasOwn(src, k)).map((k) => [k, src[k]]));
  return body.map((s) => {
    const out = pick(s, STABLE_SESSION_FIELDS);
    if (s.handshake !== null && typeof s.handshake === "object") out.handshake = pick(s.handshake, STABLE_HANDSHAKE_FIELDS);
    return out;
  }).sort((x, y) => (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
}

const mkToken = (gen) => `tpc1.${gen}.${randomBytes(32).toString("base64url")}`;
const verifier = (token) => `sha256:${createHash("sha256").update(token, "utf8").digest("hex")}`;

test("S-R1 two profiles end to end on a real daemon: own create/inject/read/delete succeed, server-verified health, cross-profile four-op denial", { skip: SKIP, timeout: 60000 }, async (t) => {
  requireProfileDaemon();
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "ts-profile-real-")));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const d of ["keys", "state", "home", "cwd", "server"]) fs.mkdirSync(path.join(root, d), { mode: 0o700 });
  const tokens = { "asst-a": mkToken(1), "asst-b": mkToken(2) };
  const serverFile = path.join(root, "server", "client-profiles.json");
  fs.writeFileSync(serverFile, JSON.stringify({ schema: "telepty.client-profiles/v1", profiles: [
    { profile: "asst-a", inbox_prefix: "exa", targets: ["orchestrator"], generation: 1, token_verifier: verifier(tokens["asst-a"]), not_before: new Date(Date.now() - 60000).toISOString() },
    { profile: "asst-b", inbox_prefix: "exb", targets: ["orchestrator"], generation: 2, token_verifier: verifier(tokens["asst-b"]), not_before: new Date(Date.now() - 60000).toISOString() },
  ] }), { mode: 0o600 });
  const daemon = await startTeleptyDaemon({ orchestratorSids: "orchestrator", env: { TELEPTY_CLIENT_PROFILES_FILE: serverFile } });
  t.after(() => daemon.stop());
  await assertProfileCapability(daemon);
  const target = await startAtermEndpoint();
  t.after(() => target.close());
  const targetCred = await registerAterm(daemon, "orchestrator", target.endpoint);

  const profiles = {};
  for (const [n, prefix] of [["asst-a", "exa"], ["asst-b", "exb"]]) {
    const tf = path.join(root, "keys", `${n}.token`);
    fs.writeFileSync(tf, tokens[n], { mode: 0o600 });
    profiles[n] = { inbox_prefix: prefix, targets: ["orchestrator"], state_dir: path.join(root, "state", n), token_file: tf };
  }
  const file = path.join(root, "profiles.json");
  fs.writeFileSync(file, JSON.stringify({ schema: "telesession.profiles/v1", telepty_url: daemon.origin, profiles }), { mode: 0o600 });
  const seam = { homedir: path.join(root, "home"), cwd: path.join(root, "cwd") };
  const open = (n) => createTeleptyTransport(loadConfig({ TELESESSION_PROFILE: n, TELESESSION_PROFILES_FILE: file }), seam);
  const a = open("asst-a");
  t.after(() => a.close());
  const b = open("asst-b");
  t.after(() => b.close());

  // Health is server-derived.
  const ha = await a.health();
  assert.deepEqual(ha.credential, { mode: "client-profile", profile: "asst-a", server_enforced: true, shared_token_in_use: false, generation: 1 });

  // Own ops: create (lazy) + inject, then audit read through the transport.
  const sa = await a.send({ target: "orchestrator", text: "A own op" });
  assert.equal(sa.ok, true, JSON.stringify(sa));
  const sb = await b.send({ target: "orchestrator", text: "B own op" });
  assert.equal(sb.ok, true, JSON.stringify(sb));
  // N2 (review714): a distinguishable reply from the target, injected into A's inbox through the existing fixture route
  // (shared token + the target's own live bearer), is read from A's inbox by A; B can neither read it nor see it.
  const answerA = `REPLY ${sa.nonce} S-R1 answer for A ${randomBytes(8).toString("hex")}`;
  const delivered = await daemon.request(`/api/sessions/${encodeURIComponent(a.inboxId)}/inject`, {
    method: "POST", sessionToken: targetCred.bearer, body: { prompt: answerA, from: "orchestrator" },
  });
  assert.equal(delivered.status, 200, delivered.text);
  const ra = await a.readReply({ nonce: sa.nonce, wait_ms: 8000 });
  assert.equal(ra.ok, true, JSON.stringify(ra));
  assert.equal(ra.reply, "trusted", JSON.stringify(ra));
  assert.equal(ra.text, answerA, "A reads the actual payload from its own inbox");
  assert.equal(ra.verified_sender.sid, "orchestrator");
  const rbForeign = await b.readReply({ nonce: sa.nonce, wait_ms: 0 });
  assert.equal(rbForeign.ok, false);
  assert.equal(rbForeign.error.code, "NONCE_NOT_ISSUED");
  const rbOwn = await b.readReply({ nonce: sb.nonce, wait_ms: 0 });
  assert.equal(rbOwn.ok, true, JSON.stringify(rbOwn));
  assert.notEqual(rbOwn.reply, "trusted");
  for (const r of [rbForeign, rbOwn]) assert.ok(!JSON.stringify(r).includes(answerA), "B never receives A's reply");
  assert.equal((await rawAs(daemon, tokens["asst-b"])("GET", `/api/injects?to=${encodeURIComponent(a.inboxId)}`)).status, 403,
    "B cannot read A's inbox");

  // C4 exact audit (server A4): A's own audit read names only rows whose verified sender is A's live inbox.
  const asA = rawAs(daemon, tokens["asst-a"]);
  const audit = await asA("GET", `/api/injects?to=orchestrator&from=${encodeURIComponent(a.inboxId)}`);
  assert.equal(audit.status, 200, JSON.stringify(audit.body));
  assert.ok(Array.isArray(audit.body.injects) && audit.body.injects.length >= 1);
  for (const row of audit.body.injects) {
    assert.equal(row.to, "orchestrator");
    assert.equal(row.verified_sender_sid, a.inboxId, "only A's verified rows");
  }
  assert.ok(audit.body.injects.some((row) => row.inject_id === sa.inject_id), "A's inject is in A's audit");
  assert.ok(!audit.body.injects.some((row) => row.inject_id === sb.inject_id), "B's inject is not in A's audit");
  assert.equal((await asA("GET", `/api/injects?to=orchestrator&from=${encodeURIComponent(b.inboxId)}`)).status, 403, "A cannot read B's sender audit");

  // C4 observation ownership (server A3): own record visible; B's id and an unknown id get one identical body.
  const own = await asA("GET", `/api/inject-observations/${encodeURIComponent(sa.inject_id)}`);
  assert.equal(own.status, 200);
  assert.equal(own.body.inject_id, sa.inject_id);
  assert.notEqual(own.body.reason, "not_observed_by_daemon_epoch", "A observes its own inject");
  // N3: after both injects to the shared target, A's own observation names neither B's inject nor the active one.
  assert.ok(!JSON.stringify(own.body).includes(sb.inject_id), "no B inject id in A's observation");
  assert.ok(!JSON.stringify(own.body).includes("active_inject_id"), "no active_inject_id in A's observation");
  assertUnavailableObservation(await asA("GET", `/api/inject-observations/${encodeURIComponent(sb.inject_id)}`), sb.inject_id);
  const unknownId = "00000000-0000-4000-8000-000000000000";
  assertUnavailableObservation(await asA("GET", `/api/inject-observations/${unknownId}`), unknownId);

  // Cross-profile four-op negatives with A's credential on B's namespace (server boundary, raw requests).
  const raw = async (method, p, body, extra = {}) => {
    const res = await fetch(daemon.origin + p, { method, redirect: "manual", headers: { "x-telepty-client-token": tokens["asst-a"], ...extra, ...(body ? { "content-type": "application/json" } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
    return res.status;
  };
  const bInbox = b.inboxId;
  const sessionsBefore = await daemon.request("/api/sessions");
  assert.equal(await raw("POST", "/api/sessions/register", { session_id: `exb-i${"0".repeat(32)}`, delivery_type: "aterm", delivery_endpoint: `http://127.0.0.1:1/${"x".repeat(43)}`, create_only: true }), 403);
  assert.equal(await raw("GET", `/api/injects?to=${encodeURIComponent(bInbox)}`), 403);
  assert.equal(await raw("POST", `/api/sessions/${encodeURIComponent(bInbox)}/inject`, { prompt: "p", from: a.inboxId, reply_to: a.inboxId, exact_target: true }), 403);
  assert.equal(await raw("DELETE", `/api/sessions/${encodeURIComponent(bInbox)}?owned=true`), 403);
  assert.equal(await raw("GET", "/api/meta", undefined, { "x-telepty-token": daemon.token }), 400, "mixed carrier is CREDENTIAL_AMBIGUOUS");
  const sessionsAfter = await daemon.request("/api/sessions");
  // Negative controls (ci733): the projection still sees a changed epoch, a removed id and a changed lastInjectReturn,
  // and ignores only the per-read fields.
  const stableBefore = stableSessions(sessionsBefore.body);
  const mutated = (edit) => {
    const copy = structuredClone(sessionsBefore.body);
    edit(copy, copy.find((x) => x && x.id === "orchestrator"));
    return stableSessions(copy);
  };
  assert.notDeepEqual(mutated((_, o) => { o.session_epoch = `${o.session_epoch}-changed`; }), stableBefore, "an epoch change is seen");
  assert.notDeepEqual(mutated((c) => { c.splice(c.findIndex((x) => x && x.id === bInbox), 1); }), stableBefore, "a removed id is seen");
  assert.notDeepEqual(mutated((_, o) => { o.lastInjectReturn = { synthetic: "changed" }; }), stableBefore, "a lastInjectReturn change is seen");
  assert.deepEqual(mutated((_, o) => {
    o.idleSeconds = -1;
    if (o.handshake !== null && typeof o.handshake === "object") o.handshake = { ...o.handshake, sampled_at: "1970-01-01T00:00:00.000Z" };
  }), stableBefore, "per-read fields are not state");
  assert.deepEqual(stableSessions(sessionsAfter.body), stableBefore, "no session state changed by any denial");

  // C4 owned delete needs the live owner bearer: A's client token alone, or with a forged bearer, removes nothing.
  const aInbox = a.inboxId;
  const listedBefore = await daemon.request("/api/sessions");
  for (const extra of [{}, { "x-telepty-session-token": randomBytes(24).toString("hex") }]) {
    const del = await asA("DELETE", `/api/sessions/${encodeURIComponent(aInbox)}?owned=true`, undefined, extra);
    assert.ok(del.status >= 400, `owned delete without the live bearer refused (${del.status})`);
  }
  assert.deepEqual(stableSessions((await daemon.request("/api/sessions")).body), stableSessions(listedBefore.body), "no session removed without the bearer");

  // Own delete (with the live owned bearer) succeeds; B is unaffected.
  assert.equal((await a.close()).outcome, "deleted");
  const listedAfterDelete = await daemon.request("/api/sessions");
  assert.notDeepEqual(stableSessions(listedAfterDelete.body), stableSessions(listedBefore.body), "the authorized owned delete changes the projection");
  assert.ok(!listedAfterDelete.body.some((x) => x && x.id === aInbox), "A's inbox is gone");
  assert.equal((await b.health()).credential.server_enforced, true);
  assert.equal((await b.close()).outcome, "deleted");
});

// C4 credential rotation / generation on the real server (per-request digest reload): the old token is refused with
// no fallback and nothing is created; a client holding the rotated token is verified at the new generation.
test("S-R1b rotation on a real daemon: old generation PROFILE_CREDENTIAL_REJECTED, new token verified at generation 2", { skip: SKIP, timeout: 60000 }, async (t) => {
  requireProfileDaemon();
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "ts-profile-rot-")));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const d of ["keys", "state", "home", "cwd", "server"]) fs.mkdirSync(path.join(root, d), { mode: 0o700 });
  const notBefore = iso(Date.now() - 60000);
  const old = mkToken(1);
  const serverFile = path.join(root, "server", "client-profiles.json");
  writePrivateAtomic(serverFile, JSON.stringify({ schema: "telepty.client-profiles/v1", profiles: [grant("asst-a", "exa", old, 1, notBefore)] }));
  const daemon = await startTeleptyDaemon({ orchestratorSids: "orchestrator", env: { TELEPTY_CLIENT_PROFILES_FILE: serverFile } });
  t.after(() => daemon.stop());
  await assertProfileCapability(daemon);
  const target = await startAtermEndpoint();
  t.after(() => target.close());
  await registerAterm(daemon, "orchestrator", target.endpoint);
  const seam = { homedir: path.join(root, "home"), cwd: path.join(root, "cwd") };
  const openWith = (label, token) => {
    const tf = path.join(root, "keys", `${label}.token`);
    fs.writeFileSync(tf, token, { mode: 0o600 });
    const file = path.join(root, `profiles-${label}.json`);
    fs.writeFileSync(file, JSON.stringify({ schema: "telesession.profiles/v1", telepty_url: daemon.origin,
      profiles: { "asst-a": { inbox_prefix: "exa", targets: ["orchestrator"], state_dir: path.join(root, "state", label), token_file: tf } } }), { mode: 0o600 });
    return createTeleptyTransport(loadConfig({ TELESESSION_PROFILE: "asst-a", TELESESSION_PROFILES_FILE: file }), seam);
  };
  const a1 = openWith("g1", old);
  t.after(() => a1.close());
  assert.equal((await a1.health()).credential.generation, 1);
  assert.equal((await a1.send({ target: "orchestrator", text: "generation 1" })).ok, true);

  const rotated = mkToken(2);
  writePrivateAtomic(serverFile, JSON.stringify({ schema: "telepty.client-profiles/v1", profiles: [grant("asst-a", "exa", rotated, 2, notBefore)] }));
  const sessionsBefore = await daemon.request("/api/sessions");
  const h1 = await a1.health();
  assert.deepEqual(h1.credential, { mode: "client-profile", profile: "asst-a", server_enforced: null, shared_token_in_use: false, generation: null, code: "PROFILE_CREDENTIAL_REJECTED" });
  const r1 = await a1.send({ target: "orchestrator", text: "old generation" });
  assert.equal(r1.ok, false);
  assert.equal(r1.error.code, "PROFILE_CREDENTIAL_REJECTED");
  assert.deepEqual(stableSessions((await daemon.request("/api/sessions")).body), stableSessions(sessionsBefore.body), "the old token changed nothing");
  await a1.close();

  const a2 = openWith("g2", rotated);
  t.after(() => a2.close());
  const h2 = await a2.health();
  assert.deepEqual(h2.credential, { mode: "client-profile", profile: "asst-a", server_enforced: true, shared_token_in_use: false, generation: 2 });
  const s2 = await a2.send({ target: "orchestrator", text: "generation 2" });
  assert.equal(s2.ok, true, JSON.stringify(s2));
  assert.equal((await a2.close()).outcome, "deleted");
});

test("S-T4a on a real daemon with the feature off: PROFILE_CREDENTIAL_REJECTED, no register/inject", { skip: process.platform === "win32" ? "NOTRUN: win32" : !HAS_TELEPTY && !REQUIRE ? `NOTRUN: no Telepty source at ${TELEPTY_DIR}` : false, timeout: 60000 }, async (t) => {
  if (!HAS_TELEPTY) assert.fail(`TELESESSION_TEST_REQUIRE_PROFILE_DAEMON=1 but no Telepty source at ${TELEPTY_DIR}`);
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "ts-profile-off-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const d of ["keys", "state", "home", "cwd"]) fs.mkdirSync(path.join(root, d), { mode: 0o700 });
  const daemon = await startTeleptyDaemon({ orchestratorSids: "orchestrator" });
  t.after(() => daemon.stop());
  const tf = path.join(root, "keys", "a.token");
  fs.writeFileSync(tf, mkToken(1), { mode: 0o600 });
  const file = path.join(root, "profiles.json");
  fs.writeFileSync(file, JSON.stringify({ schema: "telesession.profiles/v1", telepty_url: daemon.origin,
    profiles: { "asst-a": { inbox_prefix: "exa", targets: ["orchestrator"], state_dir: path.join(root, "state", "a"), token_file: tf } } }), { mode: 0o600 });
  const tr = createTeleptyTransport(loadConfig({ TELESESSION_PROFILE: "asst-a", TELESESSION_PROFILES_FILE: file }), { homedir: path.join(root, "home"), cwd: path.join(root, "cwd") });
  t.after(() => tr.close());
  const before = await daemon.request("/api/sessions");
  const r = await tr.send({ target: "orchestrator", text: "x" });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, "PROFILE_CREDENTIAL_REJECTED");
  assert.deepEqual(stableSessions((await daemon.request("/api/sessions")).body), stableSessions(before.body), "nothing registered");
});
