// Issue #16 — S-R* rows: two Telesession profiles against a REAL spawned Telepty with
// `client-profile-scope-v1` (contract564 §3 + review569 §3; Telepty ≥ 0.11.0). This is the only Telesession
// file that can show server enforcement. NOTRUN unless TELESESSION_TEST_TELEPTY_DIR (or ../telepty) is a
// Telepty source tree whose package.json version is ≥ 0.11.0. Native macOS and Linux only; win32 → NOTRUN
// (profile mode is refused there). Hermetic: temp HOME, synthetic tpc1 tokens, loopback daemon on port 0.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { loadConfig, createTeleptyTransport } from "../src/index.js";
import { HAS_TELEPTY, TELEPTY_DIR, startAtermEndpoint, startTeleptyDaemon, registerAterm } from "./helpers.js";

function teleptyVersionAtLeast(major, minor) {
  try {
    const v = JSON.parse(fs.readFileSync(path.join(TELEPTY_DIR, "package.json"), "utf8")).version;
    const m = /^(\d+)\.(\d+)\./.exec(String(v));
    return Boolean(m) && (Number(m[1]) > major || (Number(m[1]) === major && Number(m[2]) >= minor));
  } catch { return false; }
}
const SKIP = process.platform === "win32" ? "NOTRUN: profile mode unsupported on native Windows"
  : !HAS_TELEPTY ? `NOTRUN: no Telepty source at ${TELEPTY_DIR}`
    : !teleptyVersionAtLeast(0, 11) ? "NOTRUN: Telepty < 0.11.0 has no client-profile-scope-v1" : false;

const mkToken = (gen) => `tpc1.${gen}.${randomBytes(32).toString("base64url")}`;
const verifier = (token) => `sha256:${createHash("sha256").update(token, "utf8").digest("hex")}`;

test("S-R1 two profiles end to end on a real daemon: own create/inject/read/delete succeed, server-verified health, cross-profile four-op denial", { skip: SKIP, timeout: 60000 }, async (t) => {
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
  const target = await startAtermEndpoint();
  t.after(() => target.close());
  await registerAterm(daemon, "orchestrator", target.endpoint);

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
  const b = open("asst-b");

  // Health is server-derived.
  const ha = await a.health();
  assert.deepEqual(ha.credential, { mode: "client-profile", profile: "asst-a", server_enforced: true, shared_token_in_use: false, generation: 1 });

  // Own ops: create (lazy) + inject, then audit read through the transport.
  const sa = await a.send({ target: "orchestrator", text: "A own op" });
  assert.equal(sa.ok, true, JSON.stringify(sa));
  const sb = await b.send({ target: "orchestrator", text: "B own op" });
  assert.equal(sb.ok, true, JSON.stringify(sb));
  const ra = await a.readReply({ nonce: sa.nonce, wait_ms: 0 });
  assert.equal(ra.ok, true, JSON.stringify(ra));

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
  assert.deepEqual(sessionsAfter.body, sessionsBefore.body, "no session state changed by any denial");

  // Own delete succeeds; B is unaffected.
  assert.equal((await a.close()).outcome, "deleted");
  assert.equal((await b.health()).credential.server_enforced, true);
  assert.equal((await b.close()).outcome, "deleted");
});

test("S-T4a on a real daemon with the feature off: PROFILE_CREDENTIAL_REJECTED, no register/inject", { skip: process.platform === "win32" ? "NOTRUN: win32" : !HAS_TELEPTY ? `NOTRUN: no Telepty source at ${TELEPTY_DIR}` : false, timeout: 60000 }, async (t) => {
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
  assert.deepEqual((await daemon.request("/api/sessions")).body, before.body, "nothing registered");
});
