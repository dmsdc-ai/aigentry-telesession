// Issue #16 — Telesession profile mode configuration (received contract564 §4 + review569 F10; rows S-C*).
// Daemon-free and listener-free: synthetic profiles/token files in a private temp dir, real fs safety checks,
// real store locks. Synthetic `tpc1.` tokens only; no real credential, ~/.telepty or daemon is touched.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { ConfigError, loadConfig, normalizeConfig, resolveProfile, createTeleptyTransport } from "../src/index.js";
import { StoreError } from "../src/store.js";
import { registerMcpTools, TOOL_NAMES } from "../src/adapters/mcp.js";
import { buildChildEnv, buildSpawnPlan, CHILD_CONFIG_KEYS, TunnelChildError } from "../src/tunnel-child.js";

const URL_ = "http://127.0.0.1:41234";
const POSIX = process.platform !== "win32";
const mkToken = (gen = 1) => `tpc1.${gen}.${randomBytes(32).toString("base64url")}`;

function writePrivate(p, text) {
  fs.writeFileSync(p, text, { mode: 0o600 });
  fs.chmodSync(p, 0o600);
}

function profileSandbox(t, { gens = { "asst-a": 3, "asst-b": 7 } } = {}) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "ts-profile-cfg-")));
  t.after(() => { try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ } });
  const keys = path.join(root, "keys");
  const state = path.join(root, "state");
  fs.mkdirSync(keys, { mode: 0o700 });
  fs.mkdirSync(state, { mode: 0o700 });
  const tokens = {};
  for (const [n, g] of Object.entries(gens)) { tokens[n] = mkToken(g); writePrivate(path.join(keys, `${n}.token`), `${tokens[n]}\n`); }
  const profiles = {
    "asst-a": { inbox_prefix: "exa", targets: ["orchestrator"], state_dir: path.join(state, "asst-a"), token_file: path.join(keys, "asst-a.token") },
    "asst-b": { inbox_prefix: "exb", targets: ["orchestrator", "worker-2"], state_dir: path.join(state, "asst-b"), token_file: path.join(keys, "asst-b.token"), persist_inbox_credential: false },
  };
  const file = path.join(root, "profiles.json");
  const doc = (over = {}) => ({ schema: "telesession.profiles/v1", telepty_url: URL_, profiles, ...over });
  const write = (obj) => { writePrivate(file, typeof obj === "string" ? obj : JSON.stringify(obj)); return file; };
  write(doc());
  const env = (name, extra = {}) => ({ TELESESSION_PROFILES_FILE: file, TELESESSION_PROFILE: name, ...extra });
  const seam = { homedir: path.join(root, "home"), cwd: path.join(root, "cwd") };
  fs.mkdirSync(seam.homedir); fs.mkdirSync(seam.cwd);
  return { root, keys, state, tokens, profiles, file, doc, write, env, seam };
}

function refuses(fn, code, secrets = []) {
  let caught;
  try { fn(); } catch (err) { caught = err; }
  assert.ok(caught instanceof ConfigError, `expected ConfigError ${code}, got ${caught && (caught.code || caught)}`);
  assert.equal(caught.code, code);
  assert.equal(caught.message, code);
  for (const s of secrets) assert.ok(!String(caught.stack).includes(s), "no secret/path in error");
}

test("S-C0 two profiles resolve to their own prefix, targets, state dir, URL and tpc1 credential", { skip: !POSIX && "NOTRUN: profile mode is refused on win32" }, (t) => {
  const s = profileSandbox(t);
  const a = loadConfig(s.env("asst-a"));
  const b = loadConfig(s.env("asst-b"));
  assert.equal(a.profile, "asst-a");
  assert.equal(b.profile, "asst-b");
  assert.deepEqual([a.inboxPrefix, b.inboxPrefix], ["exa", "exb"]);
  assert.deepEqual([...a.targets], ["orchestrator"]);
  assert.deepEqual([...b.targets], ["orchestrator", "worker-2"]);
  assert.equal(a.stateDir, s.profiles["asst-a"].state_dir);
  assert.equal(b.stateDir, s.profiles["asst-b"].state_dir);
  assert.equal(a.teleptyOrigin, URL_);
  assert.equal(a.token, s.tokens["asst-a"]);
  assert.equal(b.token, s.tokens["asst-b"]);
  assert.equal(b.persistInboxCredential, false);
  for (const cfg of [a, b]) {
    const json = JSON.stringify(cfg);
    for (const tok of Object.values(s.tokens)) assert.ok(!json.includes(tok), "token never enumerable");
  }
});

test("S-C0 legacy env without a profile keeps the exact 0.2.x shape", () => {
  const cfg = loadConfig({ TELESESSION_TARGETS: "orch-1", TELESESSION_INBOX_PREFIX: "ts", TELESESSION_TELEPTY_URL: URL_, TELESESSION_TELEPTY_TOKEN: "abc" });
  assert.deepEqual(Object.keys(cfg).sort(), ["inboxPrefix", "targets", "teleptyOrigin"]);
  assert.equal(cfg.profile, null);
  assert.equal(resolveProfile({ TELESESSION_TARGETS: "x" }), null);
});

test("S-C1/S-C7 profile mode refuses every legacy credential/target/prefix/state/persist/URL key", { skip: !POSIX && "NOTRUN: win32" }, (t) => {
  const s = profileSandbox(t);
  const keys = ["TELESESSION_TELEPTY_TOKEN", "TELESESSION_TELEPTY_TOKEN_FILE", "TELESESSION_TARGETS", "TELESESSION_INBOX_PREFIX",
    "TELESESSION_STATE_DIR", "TELESESSION_PERSIST_INBOX_CREDENTIAL", "TELESESSION_TELEPTY_URL"];
  for (const k of keys) refuses(() => loadConfig(s.env("asst-a", { [k]: k.endsWith("URL") ? URL_ : "/x/y" })), "CONFIG_PROFILE_CONFLICT", [s.tokens["asst-a"]]);
  // The relay interval carries no credential or namespace: allowed.
  assert.equal(loadConfig(s.env("asst-a", { TELESESSION_RELAY_INTERVAL_MS: "5000" })).relayIntervalMs, 5000);
});

test("S-C7 telepty_url in the file must be raw loopback http (validated like TELESESSION_TELEPTY_URL)", { skip: !POSIX && "NOTRUN: win32" }, (t) => {
  const s = profileSandbox(t);
  for (const telepty_url of ["http://10.0.0.1:3848", "https://127.0.0.1:3848", "http://localhost:3848", "http://u:p@127.0.0.1:3848", "http://127.0.0.1"]) {
    s.write(s.doc({ telepty_url }));
    refuses(() => loadConfig(s.env("asst-a")), "CONFIG_URL_INVALID");
  }
});

test("S-C5 unknown, malformed and half-configured selections are refused before any token read", { skip: !POSIX && "NOTRUN: win32" }, (t) => {
  const s = profileSandbox(t);
  let reads = 0;
  const readPrivateFile = (p, code) => { if (p.endsWith(".token")) reads += 1; return fs.readFileSync(p, "utf8"); };
  const L = (env) => () => loadConfig(env, { readPrivateFile });
  refuses(L(s.env("asst-c")), "CONFIG_PROFILE_UNKNOWN");
  for (const bad of ["../asst-a", "a b", "x".repeat(65), "-lead", "Asst-A"]) refuses(L(s.env(bad)), "CONFIG_PROFILE_INVALID");
  refuses(L({ TELESESSION_PROFILE: "asst-a" }), "CONFIG_PROFILES_FILE_MISSING");
  refuses(L({ TELESESSION_PROFILES_FILE: s.file }), "CONFIG_PROFILE_MISSING");
  refuses(L(s.env("asst-a", { TELESESSION_PROFILES_FILE: "rel/profiles.json" })), "CONFIG_PROFILES_FILE_INVALID");
  refuses(L(s.env("asst-a", { TELESESSION_PROFILES_FILE: path.join(s.root, "absent.json") })), "CONFIG_PROFILES_FILE_INVALID");
  const good = s.profiles["asst-a"];
  const bad = [
    "not json", "[]", JSON.stringify({ ...s.doc(), schema: "telesession.profiles/v2" }), JSON.stringify({ schema: "telesession.profiles/v1", telepty_url: URL_ }),
    JSON.stringify(s.doc({ profiles: {} })), JSON.stringify(s.doc({ extra: 1 })),
    JSON.stringify(s.doc({ profiles: { "asst-a": { ...good, profile_override: "asst-b" } } })),
    JSON.stringify(s.doc({ profiles: { "asst-a": { ...good, token_file: "keys/a.token" } } })),
    JSON.stringify(s.doc({ profiles: { "asst-a": { ...good, state_dir: undefined } } })),
    JSON.stringify(s.doc({ profiles: { "asst-a": { ...good, targets: [] } } })),
    JSON.stringify(s.doc({ profiles: { "asst-a": { ...good, targets: Array.from({ length: 9 }, (_, i) => `t${i}`) } } })),
    JSON.stringify(s.doc({ profiles: { "asst-a": { ...good, inbox_prefix: "a-b" } } })),
    JSON.stringify(s.doc({ profiles: { "asst-a": { ...good, persist_inbox_credential: "1" } } })),
    JSON.stringify(s.doc({ profiles: { "bad name": good } })),
  ];
  for (const text of bad) {
    s.write(text);
    refuses(L(s.env("asst-a")), "CONFIG_PROFILES_INVALID");
  }
  assert.equal(reads, 0, "no token file was read for any refused configuration");
});

test("S-C2 token must be a bare tpc1 token; the shared {authToken} form and other text are refused", { skip: !POSIX && "NOTRUN: win32" }, (t) => {
  const s = profileSandbox(t);
  const tf = s.profiles["asst-a"].token_file;
  for (const text of [JSON.stringify({ authToken: mkToken(3) }), "plain-shared-token-0123456789", `tpc1.3.${"a".repeat(42)}`,
    `tpc1.x.${randomBytes(32).toString("base64url")}`, `${mkToken(3)} extra`, `${mkToken(3)}\n\n`, ""]) {
    writePrivate(tf, text);
    refuses(() => loadConfig(s.env("asst-a")), "CONFIG_PROFILE_TOKEN_INVALID");
  }
  writePrivate(tf, mkToken(3));
  assert.match(loadConfig(s.env("asst-a")).token, /^tpc1\.3\./);
  assert.throws(() => normalizeConfig({ teleptyUrl: URL_, token: "not-tpc1", targets: ["o"], inboxPrefix: "ts", stateDir: "/tmp/x", profile: "asst-a" }),
    (e) => e.code === "CONFIG_PROFILE_TOKEN_INVALID");
});

// review698 CF5: the token generation field matches the server's `tpc1\.[1-9][0-9]{0,15}\.` (generation >= 1).
test("S-C2b token generation starts at 1: generation 0, a leading zero and bad shapes are refused", { skip: !POSIX && "NOTRUN: win32" }, (t) => {
  const s = profileSandbox(t);
  const tf = s.profiles["asst-a"].token_file;
  const tail = randomBytes(32).toString("base64url");
  for (const text of [`tpc1.0.${tail}`, `tpc1.00.${tail}`, `tpc1.01.${tail}`, `tpc1.007.${tail}`, `tpc1.${"1".repeat(17)}.${tail}`,
    `tpc1.-1.${tail}`, `tpc1.+1.${tail}`, `tpc1.1e3.${tail}`, `tpc1..${tail}`, `tpc1.1.${tail}=`, `tpc1.1.${tail.slice(1)}`, `TPC1.1.${tail}`]) {
    writePrivate(tf, text);
    refuses(() => loadConfig(s.env("asst-a")), "CONFIG_PROFILE_TOKEN_INVALID");
    assert.throws(() => normalizeConfig({ teleptyUrl: URL_, token: text, targets: ["o"], inboxPrefix: "ts", stateDir: "/tmp/x", profile: "asst-a" }),
      (e) => e.code === "CONFIG_PROFILE_TOKEN_INVALID", text.slice(0, 12));
  }
  for (const gen of ["1", "9", "10", "1234567890123456"]) {
    writePrivate(tf, `tpc1.${gen}.${tail}`);
    assert.equal(loadConfig(s.env("asst-a")).token, `tpc1.${gen}.${tail}`, gen);
  }
});

test("S-C3 profiles file and token file: symlink, group/other mode, hardlink (nlink>1), oversize, non-regular are refused", { skip: !POSIX && "NOTRUN: win32" }, (t) => {
  const s = profileSandbox(t);
  const real = s.file;
  const ln = path.join(s.root, "profiles-link.json");
  fs.symlinkSync(real, ln);
  refuses(() => loadConfig(s.env("asst-a", { TELESESSION_PROFILES_FILE: ln })), "CONFIG_PROFILES_FILE_INVALID");
  fs.chmodSync(real, 0o640);
  refuses(() => loadConfig(s.env("asst-a")), "CONFIG_PROFILES_FILE_INVALID");
  fs.chmodSync(real, 0o600);
  const hard = path.join(s.root, "profiles-hard.json");
  fs.linkSync(real, hard);
  refuses(() => loadConfig(s.env("asst-a")), "CONFIG_PROFILES_FILE_INVALID");
  fs.unlinkSync(hard);
  refuses(() => loadConfig(s.env("asst-a", { TELESESSION_PROFILES_FILE: s.keys })), "CONFIG_PROFILES_FILE_INVALID");
  s.write(JSON.stringify(s.doc()) + " ".repeat(64 * 1024));
  refuses(() => loadConfig(s.env("asst-a")), "CONFIG_PROFILES_FILE_INVALID");
  s.write(s.doc());
  const tf = s.profiles["asst-a"].token_file;
  fs.chmodSync(tf, 0o644);
  refuses(() => loadConfig(s.env("asst-a")), "CONFIG_TOKEN_FILE_INVALID", [s.tokens["asst-a"]]);
  fs.chmodSync(tf, 0o600);
  const tlink = path.join(s.keys, "a-link.token");
  fs.symlinkSync(tf, tlink);
  s.write(s.doc({ profiles: { ...s.profiles, "asst-a": { ...s.profiles["asst-a"], token_file: tlink } } }));
  refuses(() => loadConfig(s.env("asst-a")), "CONFIG_TOKEN_FILE_INVALID");
  assert.equal(loadConfig(s.env("asst-b")).profile, "asst-b", "B's own safe file is unaffected by A's unsafe one");
});

test("S-C3 foreign-uid files are refused (needs root to chown; NOTRUN otherwise)", { skip: !(POSIX && process.geteuid && process.geteuid() === 0) && "NOTRUN: needs euid 0 to create a foreign-owned file" }, (t) => {
  const s = profileSandbox(t);
  fs.chownSync(s.file, 65534, 65534);
  refuses(() => loadConfig(s.env("asst-a")), "CONFIG_PROFILES_FILE_INVALID");
});

test("S-C4 state dirs equal, nested, symlinked or case-folded (darwin/win32) and prefix collisions are refused", { skip: !POSIX && "NOTRUN: win32" }, (t) => {
  const s = profileSandbox(t);
  const P = s.profiles;
  const with_ = (b) => s.write(s.doc({ profiles: { "asst-a": P["asst-a"], "asst-b": { ...P["asst-b"], ...b } } }));
  with_({ state_dir: P["asst-a"].state_dir });
  refuses(() => loadConfig(s.env("asst-b")), "CONFIG_PROFILE_STATE_ALIAS");
  refuses(() => loadConfig(s.env("asst-a")), "CONFIG_PROFILE_STATE_ALIAS");
  with_({ state_dir: path.join(P["asst-a"].state_dir, "ledger") });
  refuses(() => loadConfig(s.env("asst-b")), "CONFIG_PROFILE_STATE_ALIAS");
  with_({ state_dir: s.state });
  refuses(() => loadConfig(s.env("asst-b")), "CONFIG_PROFILE_STATE_ALIAS");
  fs.mkdirSync(P["asst-a"].state_dir, { mode: 0o700 });
  const ln = path.join(s.root, "state-link");
  fs.symlinkSync(s.state, ln);
  with_({ state_dir: path.join(ln, "asst-a") });
  refuses(() => loadConfig(s.env("asst-b")), "CONFIG_PROFILE_STATE_ALIAS");
  with_({ state_dir: path.join(ln, "asst-a", "sub") });
  refuses(() => loadConfig(s.env("asst-b")), "CONFIG_PROFILE_STATE_ALIAS");
  if (process.platform === "darwin") {
    with_({ state_dir: path.join(s.state, "ASST-A") });
    refuses(() => loadConfig(s.env("asst-b")), "CONFIG_PROFILE_STATE_ALIAS");
  }
  with_({ inbox_prefix: "EXA" });
  refuses(() => loadConfig(s.env("asst-b")), "CONFIG_PROFILE_CONFLICT");
});

test("S-C4 credential aliases (same path, symlink, inside a state dir) across profiles are refused", { skip: !POSIX && "NOTRUN: win32" }, (t) => {
  const s = profileSandbox(t);
  const P = s.profiles;
  const with_ = (b) => s.write(s.doc({ profiles: { "asst-a": P["asst-a"], "asst-b": { ...P["asst-b"], ...b } } }));
  with_({ token_file: P["asst-a"].token_file });
  refuses(() => loadConfig(s.env("asst-b")), "CONFIG_PROFILE_CREDENTIAL_ALIAS");
  const link = path.join(s.keys, "link-to-a");
  fs.symlinkSync(P["asst-a"].token_file, link);
  with_({ token_file: link });
  refuses(() => loadConfig(s.env("asst-b")), "CONFIG_PROFILE_CREDENTIAL_ALIAS");
  fs.mkdirSync(P["asst-a"].state_dir, { mode: 0o700 });
  const inState = path.join(P["asst-a"].state_dir, "b.token");
  writePrivate(inState, mkToken(7));
  with_({ token_file: inState });
  refuses(() => loadConfig(s.env("asst-b")), "CONFIG_PROFILE_CREDENTIAL_ALIAS");
  refuses(() => loadConfig(s.env("asst-a")), "CONFIG_PROFILE_CREDENTIAL_ALIAS");
});

test("targets intersect a non-empty AIGENTRY_ORCHESTRATOR_SIDS and never widen", { skip: !POSIX && "NOTRUN: win32" }, (t) => {
  const s = profileSandbox(t);
  assert.deepEqual([...loadConfig(s.env("asst-b", { AIGENTRY_ORCHESTRATOR_SIDS: "orchestrator,other" })).targets], ["orchestrator"]);
  refuses(() => loadConfig(s.env("asst-a", { AIGENTRY_ORCHESTRATOR_SIDS: "someone-else" })), "CONFIG_TARGETS_INVALID");
  assert.deepEqual([...loadConfig(s.env("asst-b", { AIGENTRY_ORCHESTRATOR_SIDS: "" })).targets], ["orchestrator", "worker-2"]);
});

test("W2 profile mode on win32 → CONFIG_PROFILE_PLATFORM_UNSUPPORTED before any file access", () => {
  refuses(() => resolveProfile({ TELESESSION_PROFILE: "asst-a", TELESESSION_PROFILES_FILE: "C:\\\\x\\\\p.json" }, { platform: "win32" }), "CONFIG_PROFILE_PLATFORM_UNSUPPORTED");
  assert.equal(resolveProfile({}, { platform: "win32" }), null, "legacy mode on win32 unchanged");
});

test("normalizeConfig: a profile needs its own state dir and a valid name; profile is enumerable only when set", () => {
  const base = { teleptyUrl: URL_, token: mkToken(1), targets: ["o"], inboxPrefix: "ts" };
  // A native absolute, normalized dir (lexical only; nothing is created), so the name check is the one reached on
  // every platform (CI730: POSIX "/tmp/x" is not normalized on win32 → CONFIG_STATE_DIR_INVALID first).
  const stateDir = path.resolve(os.tmpdir(), "ts-profile-cfg-synthetic");
  assert.throws(() => normalizeConfig({ ...base, profile: "asst-a" }), (e) => e.code === "CONFIG_STATE_DIR_REQUIRED");
  for (const profile of ["", "a b", 7, "x".repeat(65), "Upper"]) {
    assert.throws(() => normalizeConfig({ ...base, profile, stateDir }), (e) => e.code === "CONFIG_PROFILE_INVALID");
  }
  const cfg = normalizeConfig({ ...base, profile: "asst-a", stateDir });
  assert.equal(cfg.profile, "asst-a");
  assert.ok(Object.keys(cfg).includes("profile"));
  assert.equal(normalizeConfig({ ...base, token: "abc" }).profile, null);
});

test("no MCP tool accepts a profile/identity/credential override argument", () => {
  const tools = new Map();
  registerMcpTools({ registerTool: (name, def) => tools.set(name, def) }, {});
  assert.deepEqual([...tools.keys()].sort(), [...TOOL_NAMES].sort());
  for (const [name, def] of tools) {
    for (const key of ["profile", "inbox_prefix", "token_file", "state_dir", "client_token", "sender", "from"]) {
      assert.equal(def.inputSchema.safeParse({ [key]: "asst-b" }).success, false, `${name} refuses ${key}`);
    }
  }
});

test("S-C6 independent locks: profile A's crash-held lock (STORE_LOCKED) never blocks profile B", { skip: !POSIX && "NOTRUN: win32" }, async (t) => {
  const s = profileSandbox(t);
  const a1 = createTeleptyTransport(loadConfig(s.env("asst-a")), s.seam);   // never closed: models an abrupt crash
  assert.throws(() => createTeleptyTransport(loadConfig(s.env("asst-a")), s.seam), (e) => e instanceof StoreError && e.code === "STORE_LOCKED");
  const b = createTeleptyTransport(loadConfig(s.env("asst-b")), s.seam);
  assert.match(a1.inboxId, /^exa-i[0-9a-f]{32}$/);
  assert.match(b.inboxId, /^exb-i[0-9a-f]{32}$/);
  await b.close();
  assert.ok(!fs.existsSync(path.join(s.profiles["asst-b"].state_dir, "lock")), "B released its own lock");
  assert.ok(fs.existsSync(path.join(s.profiles["asst-a"].state_dir, "lock")), "A's crash lock untouched by B");
});

test("tunnel child forwards the profile selection; a token file or URL alongside it is refused before spawn", { skip: !POSIX && "NOTRUN: win32" }, (t) => {
  const s = profileSandbox(t);
  for (const k of ["TELESESSION_PROFILE", "TELESESSION_PROFILES_FILE", "AIGENTRY_ORCHESTRATOR_SIDS"]) assert.ok(CHILD_CONFIG_KEYS.includes(k), k);
  const child = buildChildEnv({ ...s.env("asst-a"), AIGENTRY_ORCHESTRATOR_SIDS: "orchestrator", OPENAI_API_KEY: "x" }, { platform: "linux" });
  assert.equal(child.TELESESSION_PROFILE, "asst-a");
  assert.equal(child.TELESESSION_PROFILES_FILE, s.file);
  assert.equal(child.OPENAI_API_KEY, undefined);
  assert.throws(() => buildChildEnv({ ...s.env("asst-a"), TELESESSION_TELEPTY_TOKEN_FILE: s.profiles["asst-a"].token_file }, { platform: "linux" }),
    (e) => e instanceof TunnelChildError && e.code === "TUNNEL_CHILD_PROFILE_CONFLICT");
  const plan = (env) => () => buildSpawnPlan({ argv: [], env, platform: process.platform, execPath: "/usr/bin/node", entryPath: "/opt/pkg/bin/telesession-mcp.js" });
  assert.throws(plan({ ...s.env("nope") }), (e) => e instanceof TunnelChildError && e.code === "CONFIG_PROFILE_UNKNOWN");
  assert.throws(plan({ ...s.env("asst-a"), TELESESSION_TELEPTY_URL: URL_ }), (e) => e instanceof TunnelChildError && e.code === "CONFIG_PROFILE_CONFLICT");
  assert.equal(plan({ ...s.env("asst-a") })().options.env.TELESESSION_PROFILE, "asst-a");
});
