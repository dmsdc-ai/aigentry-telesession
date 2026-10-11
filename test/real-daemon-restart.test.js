// RC5 (task 1215 S1 §1b) — telesession over the REAL candidate telepty daemon ACROSS a daemon restart.
//
// TV10 in transport-durable.test.js drives a fake (helpers/fake-telepty.js `restartDaemon()`), which
// ASSUMES wrapped targets keep id + epoch. This row measures it: the target is a real wrapped session —
// telepty's own `cli.js allow` bridge around telepty/test-support/restart-credential-child-1215.js —
// whose child keeps the bearer it got at spawn, and the daemon is really stopped and re-booted on the
// same HOME and port (helpers.js startRestartableTeleptyDaemon).
//
//   send (pre-restart) → target_epoch read from /api/inject-observations → SIGTERM + restart →
//   inbox absent → re-created create_only (409 never mutates) → target replies `REPLY <nonce>` with its
//   SPAWN-TIME bearer → readReply = trusted, verified epoch == the pre-restart target_epoch.
//
// The epoch is compared only with the value read earlier in this same run. Durable mode (stateDir) is
// required: only the durable transport notices an absent inbox in-process and re-creates it
// (transports/telepty.js noteInboxAbsent); memory-only mode would keep using the dropped inbox.
//
// The target id is `orchestrator` under telepty's DEFAULT peer-lane policy (AIGENTRY_ORCHESTRATOR_SIDS
// empty → built-in sids): the D → orchestrator → D route with no widened policy.
//
// No skip: a missing telepty tree or fixture child FAILS. Nothing here reads, prints or stores the
// target's bearer; the telesession inbox bearer stays inside the transport as in production.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { createTeleptyTransport, normalizeConfig, REQUIRED_CAPABILITIES } from "../src/index.js";
import { HAS_TELEPTY, TELEPTY_DIR, listSessionIds, startRestartableTeleptyDaemon, startTeleptyBridge, waitFor } from "./helpers.js";

const CHILD = path.join(TELEPTY_DIR, "test-support", "restart-credential-child-1215.js");
const TARGET = "orchestrator";
const CASE_TIMEOUT_MS = 180000;

// Diagnostics never carry credential material (daemon token, bearer- or verifier-shaped strings).
function redact(text, token) {
  let s = String(text == null ? "" : text);
  if (token) s = s.split(token).join("[daemon-token]");
  return s.replace(/[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{32,}/g, "[bearer-shaped]").replace(/\b[0-9a-f]{64}\b/g, "[hex64]");
}

// The durable store refuses a state dir under the real HOME/cwd/telepty paths; give it its own
// sandbox and point the store's path seams at it (same shape as helpers/fault-fs.js makeSandbox).
function makeStateSandbox() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "rc5-state-")));
  const home = path.join(root, "home");
  const project = path.join(root, "work", "project");
  fs.mkdirSync(path.join(home, ".local", "state"), { recursive: true, mode: 0o700 });
  fs.mkdirSync(project, { recursive: true, mode: 0o700 });
  return {
    stateDir: path.join(home, ".local", "state", "telesession"),
    seam: () => ({ homedir: home, cwd: project }),
    remove: () => { try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ } },
  };
}

test("RC5 telesession across a real daemon restart: wrapped target replies with its spawn-time bearer → trusted, verified epoch == pre-restart target_epoch, inbox re-created create_only", { timeout: CASE_TIMEOUT_MS }, async (t) => {
  assert.equal(HAS_TELEPTY, true, `RC5 needs the candidate telepty tree at ${TELEPTY_DIR} (a missing fixture is a FAIL, not a skip)`);
  assert.ok(fs.existsSync(CHILD), `RC5 fixture child missing at ${CHILD}`);
  assert.notEqual(process.platform, "win32", "RC5 is POSIX-only (node-pty bridge)");

  const sandbox = makeStateSandbox();
  let d = null;
  let bridge = null;
  let tr = null;
  t.after(async () => {
    if (tr) { try { await tr.close(); } catch { /* best effort */ } }
    if (bridge) await bridge.stop();
    if (d) await d.stop();
    sandbox.remove();
  });

  const context = () => redact([
    `bridge alive=${bridge ? bridge.isAlive() : "n/a"}`,
    `bridge log (tail):\n${bridge ? bridge.readLog().slice(-2000) : ""}`,
    `daemon log (tail):\n${d ? d.readLog().slice(-2500) : ""}`,
  ].join("\n"), d && d.token);
  const until = async (check, opts) => {
    try {
      return await waitFor(async () => { try { return await check(); } catch { return null; } }, opts);
    } catch (err) {
      throw new Error(`${err.message}\n${context()}`);
    }
  };
  const activeClients = async (sid) => {
    const r = await d.request(`/api/sessions/${encodeURIComponent(sid)}`);
    return r.status === 200 && r.body && typeof r.body.active_clients === "number" ? r.body.active_clients : 0;
  };
  // §1f gate on every boot, before anything else touches the daemon.
  const assertCandidate = async (label) => {
    const meta = await d.request("/api/meta");
    assert.equal(meta.status, 200, `${label}: /api/meta must answer`);
    const caps = Array.isArray(meta.body && meta.body.capabilities) ? meta.body.capabilities : [];
    assert.deepEqual(REQUIRED_CAPABILITIES.filter((c) => !caps.includes(c)), [],
      `${label}: STOP — the daemon lacks the candidate capabilities (baseline daemon.js?)`);
    assert.equal(meta.body.pid, d.pid(), `${label}: the daemon answering is not this fixture's own child`);
    return meta.body;
  };

  // ── Before the restart ──
  d = await startRestartableTeleptyDaemon({ orchestratorSids: "" });
  const meta1 = await assertCandidate("boot 1");

  bridge = startTeleptyBridge(d, { sid: TARGET, script: CHILD });
  await until(async () => (await activeClients(TARGET)) >= 1
    && /RC-CHILD-READY has_sid=true has_bearer=true bearer_shape=true/.test(bridge.readLog()),
  { timeoutMs: 30000, description: "the wrapped target owns its session and its child holds a spawn-time bearer" });

  tr = createTeleptyTransport(normalizeConfig({
    teleptyUrl: d.origin, token: d.token, targets: [TARGET], inboxPrefix: "rc5", stateDir: sandbox.stateDir,
  }), sandbox.seam());
  const s = await tr.send({ target: TARGET, text: "rc5 prompt before the restart" });
  assert.equal(s.ok, true, `send before restart: ${redact(JSON.stringify(s), d.token)}`);
  assert.equal(s.accepted, true);
  assert.equal(s.durability, "durable");
  assert.equal(s.target_epoch_known, true);
  const inboxId = tr.inboxId;
  assert.equal(s.reply_to, inboxId);

  const obs = await d.request(`/api/inject-observations/${encodeURIComponent(s.inject_id)}`);
  assert.equal(obs.status, 200);
  assert.equal(obs.body.inject_id, s.inject_id);
  assert.equal(obs.body.session_id, TARGET);
  const targetEpochBefore = obs.body.session_epoch;
  assert.equal(typeof targetEpochBefore, "string", "the observation names the target's epoch before the restart");
  assert.ok(targetEpochBefore.length > 0);

  // The candidate's exact routing, observed directly: an exact_target inject is echoed back.
  const exact = await d.request(`/api/sessions/${TARGET}/inject`, { method: "POST", body: { prompt: "rc5 exact-target probe", exact_target: true } });
  assert.equal(exact.status, 200, exact.text);
  assert.equal(exact.body.exact_target, true, "exact_target:true echoed by the candidate");
  assert.equal(exact.body.session_id, TARGET);

  await until(() => bridge.readLog().includes(`[telesession nonce=${s.nonce} reply-to=${inboxId}]`),
    { timeoutMs: 15000, description: "the telesession prompt reached the wrapped target's PTY" });
  assert.ok((await listSessionIds(d)).includes(inboxId), "the aterm inbox exists before the restart");

  // ── Restart: same HOME, same port, this fixture's own child only ──
  const exit = await d.restart({ signal: "SIGTERM" });
  assert.deepEqual(exit, { code: 0, signal: null }, "the first daemon exited through its SIGTERM handler");
  const meta2 = await assertCandidate("boot 2");
  assert.notEqual(meta2.pid, meta1.pid, "a different daemon process answers");
  assert.match(d.readLog(), new RegExp(`\\[PERSIST\\] Restored session ${TARGET} \\(awaiting reconnect\\)`),
    "the wrapped target was restored from sessions.json");

  const idsAfter = await listSessionIds(d);
  assert.ok(Array.isArray(idsAfter));
  const inboxAbsentAfterRestart = !idsAfter.includes(inboxId);
  assert.equal(inboxAbsentAfterRestart, true, "the aterm inbox is NOT restored by a restart");
  await until(async () => (await activeClients(TARGET)) >= 1,
    { timeoutMs: 45000, description: "the wrapped target reconnects to the restarted daemon" });

  // The next send notices the absent inbox and re-creates the SAME id with create_only.
  const s2 = await tr.send({ target: TARGET, text: "rc5 probe after the restart" });
  assert.equal(s2.ok, true, `send after restart: ${redact(JSON.stringify(s2), d.token)}`);
  assert.equal(s2.reply_to, inboxId, "same inbox id");
  assert.equal(s2.daemon_restart, "observed");
  assert.ok((await listSessionIds(d)).includes(inboxId), "the inbox was re-created");
  const log2 = d.readLog();
  assert.ok(log2.includes(`[REGISTER] Registered wrapped session ${inboxId} (epoch:`), "re-created as a FIRST registration");
  assert.ok(!log2.includes(`[REGISTER] Re-registered session ${inboxId}`), "not a legacy (mutating) re-register");

  // create_only conflict on the live inbox: 409, and the record is unchanged.
  const squat = await d.request("/api/sessions/register", {
    method: "POST",
    body: { session_id: inboxId, delivery_type: "aterm", delivery_endpoint: "http://127.0.0.1:9/rc5-squat", command: "rc5-squatter", create_only: true },
  });
  assert.equal(squat.status, 409);
  assert.equal(squat.body.code, "SESSION_EXISTS");
  const inboxRec = await d.request(`/api/sessions/${encodeURIComponent(inboxId)}`);
  assert.equal(inboxRec.body.command, "telesession-inbox", "409 never mutates the existing inbox");

  // ── The target replies with the bearer it was spawned with ──
  const tag = `rc5-${randomBytes(4).toString("hex")}`;
  const op = await d.request(`/api/sessions/${TARGET}/inject`, { method: "POST", body: { prompt: `RCREPLY ${inboxId} ${s.nonce} ${tag}` } });
  assert.equal(op.status, 200, op.text);
  await until(() => new RegExp(`RC-SENT ${tag} status=\\d+`).test(bridge.readLog()),
    { timeoutMs: 20000, description: "the target's child sent its reply" });
  assert.match(bridge.readLog(), new RegExp(`RC-SENT ${tag} status=200`), "the reply inject was accepted");

  const rr = await tr.readReply({ nonce: s.nonce, wait_ms: 30000 });
  assert.equal(rr.reply, "trusted", `readReply: ${redact(JSON.stringify(rr), d.token)}`);
  assert.equal(rr.text, `REPLY ${s.nonce} ${tag}`);
  assert.equal(rr.verified_sender.sid, TARGET);
  assert.equal(rr.reply_route, "interrupted", "the restart is reported on the reply route, not hidden");

  const audit = await d.request(`/api/injects?to=${encodeURIComponent(inboxId)}&limit=1000`);
  const row = audit.body.injects.find((x) => x.inject_id === rr.inject_id);
  assert.ok(row, "the trusted reply has its audit row");
  assert.equal(row.claimed_from, TARGET);
  assert.equal(row.verified_sender_sid, TARGET);
  assert.equal(row.spoof_suspected, false);
  const epochEqual = row.verified_sender_epoch === targetEpochBefore;
  assert.equal(epochEqual, true, "the reply's verified epoch equals the target_epoch read BEFORE the restart");

  t.diagnostic(`RC-SUMMARY ${JSON.stringify({
    case: "RC5", reply: rr.reply, verified_sid_match: rr.verified_sender.sid === TARGET, epoch_equal: epochEqual,
    spoof: row.spoof_suspected, daemon1_exit: exit, inbox_absent_after_restart: inboxAbsentAfterRestart,
    inbox_recreated_create_only: true, create_only_conflict_409_unchanged: true, exact_target_echo: exact.body.exact_target,
    daemon_restart: s2.daemon_restart, reply_route: rr.reply_route, wrapper_alive: bridge.isAlive(),
  })}`);
  assert.equal(bridge.isAlive(), true, "the wrapped target survived the restart");
});
