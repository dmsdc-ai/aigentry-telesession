// telesession config — pure normalization + env/token-file loading. No network, no daemon.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ConfigError, loadConfig, normalizeConfig, createTeleptyTransport } from "../src/index.js";
import { freshToken } from "./helpers.js";

const GOOD = Object.freeze({ teleptyUrl: "http://127.0.0.1:41234", token: "tok-" + "a".repeat(20), targets: ["orch-1"], inboxPrefix: "ts" });

function refuses(fn, code, secret) {
  let caught;
  try { fn(); } catch (err) { caught = err; }
  assert.ok(caught instanceof ConfigError, `expected ConfigError ${code}, got ${caught}`);
  assert.equal(caught.code, code);
  assert.equal(caught.message, code, "message is the code only");
  if (secret) {
    assert.ok(!String(caught.stack).includes(secret), "secret never in error stack");
    assert.ok(!JSON.stringify(caught).includes(secret), "secret never in serialized error");
  }
}

test("normalizeConfig: frozen origin-only result, token non-enumerable", () => {
  const cfg = normalizeConfig({ ...GOOD, teleptyUrl: "http://127.0.0.1:41234/" });
  assert.equal(cfg.teleptyOrigin, "http://127.0.0.1:41234");
  assert.deepEqual([...cfg.targets], ["orch-1"]);
  assert.ok(Object.isFrozen(cfg) && Object.isFrozen(cfg.targets));
  assert.equal(cfg.token, GOOD.token);
  assert.deepEqual(Object.keys(cfg).sort(), ["inboxPrefix", "targets", "teleptyOrigin"]);
  assert.ok(!JSON.stringify(cfg).includes(GOOD.token));
  assert.equal(normalizeConfig({ ...GOOD, teleptyUrl: "http://[::1]:65535" }).teleptyOrigin, "http://[::1]:65535");
  assert.equal(normalizeConfig({ ...GOOD, teleptyUrl: "http://127.9.8.7:1" }).teleptyOrigin, "http://127.9.8.7:1");
});

test("normalizeConfig: URL must be raw loopback http with explicit port — refused, never stripped", () => {
  const bad = [
    "https://127.0.0.1:41234", "HTTP://127.0.0.1:41234", "http://localhost:41234", "http://127.0.0.1",
    "http://127.0.0.1:0", "http://127.0.0.1:01234", "http://127.0.0.1:65536", "http://127.0.0.1:80",
    "http://u:p@127.0.0.1:41234", "http://127.0.0.1:41234/api", "http://127.0.0.1:41234/?a=1",
    "http://127.0.0.1:41234/#f", "http://127.0.0.1:41234//", " http://127.0.0.1:41234", "http://127.0.0.1:41234\n",
    "http://127.0.0.256:41234", "http://127.1:41234", "http://0.0.0.0:41234", "http://10.0.0.1:41234",
    "http://[::ffff:127.0.0.1]:41234", "http://[::1]", "http://127.0.0.1:41234\u0000", "", null, 41234,
  ];
  for (const teleptyUrl of bad) refuses(() => normalizeConfig({ ...GOOD, teleptyUrl }), "CONFIG_URL_INVALID");
});

test("normalizeConfig: targets, prefix and token limits; documented check order", () => {
  const badTargets = [[], "orch-1", ["a", "a"], ["."], [".."], ["a/b"], ["a\u0000b"], ["a b"], ["x".repeat(129)], [7],
    Array.from({ length: 9 }, (_, i) => `t${i}`)];
  for (const targets of badTargets) refuses(() => normalizeConfig({ ...GOOD, targets }), "CONFIG_TARGETS_INVALID");
  assert.equal(normalizeConfig({ ...GOOD, targets: Array.from({ length: 8 }, (_, i) => `t${i}`) }).targets.length, 8);
  assert.equal(normalizeConfig({ ...GOOD, targets: ["x".repeat(128)] }).targets[0].length, 128);

  for (const inboxPrefix of ["", "a-b", "a b", "x".repeat(49), "a\u0000", 5]) {
    refuses(() => normalizeConfig({ ...GOOD, inboxPrefix }), "CONFIG_INBOX_PREFIX_INVALID");
  }
  const secret = freshToken();
  for (const token of ["", `${secret} x`, `${secret}\u0000`, `${secret}\n`, `é${secret}`, "x".repeat(4097), null]) {
    refuses(() => normalizeConfig({ ...GOOD, token }), "CONFIG_TOKEN_INVALID", typeof token === "string" && token ? secret : undefined);
  }
  // Order: targets → prefix → URL → token.
  refuses(() => normalizeConfig({ targets: [], inboxPrefix: "-", teleptyUrl: "x", token: "" }), "CONFIG_TARGETS_INVALID");
  refuses(() => normalizeConfig({ ...GOOD, inboxPrefix: "-", teleptyUrl: "x", token: "" }), "CONFIG_INBOX_PREFIX_INVALID");
  refuses(() => normalizeConfig({ ...GOOD, teleptyUrl: "x", token: "" }), "CONFIG_URL_INVALID");
});

test("loadConfig: TELESESSION_* only, exactly one token source, no implicit lookup", () => {
  const base = { TELESESSION_TARGETS: " orch-1, worker.2 \n w_3 ", TELESESSION_INBOX_PREFIX: "ts", TELESESSION_TELEPTY_URL: "http://127.0.0.1:41234" };
  const cfg = loadConfig({ ...base, TELESESSION_TELEPTY_TOKEN: "abc" });
  assert.deepEqual([...cfg.targets], ["orch-1", "worker.2", "w_3"]);
  assert.equal(cfg.token, "abc");

  refuses(() => loadConfig({ ...base, TELESESSION_TELEPTY_TOKEN: "abc", TELESESSION_TELEPTY_TOKEN_FILE: "/x" }), "CONFIG_TOKEN_SOURCE_CONFLICT");
  refuses(() => loadConfig({ ...base }), "CONFIG_TOKEN_MISSING");
  refuses(() => loadConfig({ ...base, TELESESSION_TELEPTY_TOKEN: "" }), "CONFIG_TOKEN_MISSING");
  // telepty's own variables and HOME are never consulted.
  refuses(() => loadConfig({ ...base, TELEPTY_AUTH_TOKEN: "abc", HOME: os.tmpdir() }), "CONFIG_TOKEN_MISSING");
  refuses(() => loadConfig({}), "CONFIG_TARGETS_INVALID");
  refuses(() => loadConfig({ ...base, TELESESSION_TARGETS: "a\u0000b", TELESESSION_TELEPTY_TOKEN: "abc" }), "CONFIG_TARGETS_INVALID");

  // targets/prefix/URL are validated before any token source is touched.
  let reads = 0;
  const readTokenFile = () => { reads += 1; return "abc"; };
  refuses(() => loadConfig({ ...base, TELESESSION_TELEPTY_URL: "http://localhost:1", TELESESSION_TELEPTY_TOKEN_FILE: "/t" }, { readTokenFile }), "CONFIG_URL_INVALID");
  refuses(() => loadConfig({ ...base, TELESESSION_INBOX_PREFIX: "a-b", TELESESSION_TELEPTY_TOKEN_FILE: "/t" }, { readTokenFile }), "CONFIG_INBOX_PREFIX_INVALID");
  assert.equal(reads, 0);
});

test("loadConfig: token file — absolute regular file ≤ 64 KiB; bare token or own authToken", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "telesession-config-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const base = { TELESESSION_TARGETS: "orch-1", TELESESSION_INBOX_PREFIX: "ts", TELESESSION_TELEPTY_URL: "http://127.0.0.1:41234" };
  const secret = freshToken();
  const write = (name, content) => { const p = path.join(dir, name); fs.writeFileSync(p, content); return p; };
  const load = (file) => loadConfig({ ...base, TELESESSION_TELEPTY_TOKEN_FILE: file });

  assert.equal(load(write("bare", `  ${secret}\n`)).token, secret);
  assert.equal(load(write("config.json", JSON.stringify({ authToken: secret, other: 1 }))).token, secret);

  refuses(() => load("relative/token"), "CONFIG_TOKEN_FILE_INVALID");
  refuses(() => load(path.join(dir, "missing")), "CONFIG_TOKEN_FILE_INVALID");
  refuses(() => load(dir), "CONFIG_TOKEN_FILE_INVALID");
  refuses(() => load(write("big", "a".repeat(64 * 1024 + 1))), "CONFIG_TOKEN_FILE_INVALID");
  refuses(() => load(write("noauth.json", JSON.stringify({ token: secret }))), "CONFIG_TOKEN_INVALID", secret);
  // Only content starting with "{" is parsed as JSON (contract §2); anything else is the literal token.
  assert.equal(load(write("arr.json", JSON.stringify([secret]))).token, `["${secret}"]`);
  refuses(() => load(write("num.json", JSON.stringify({ authToken: 5 }))), "CONFIG_TOKEN_INVALID");
  refuses(() => load(write("proto.json", `{"__proto__": {"authToken": "${secret}"}}`)), "CONFIG_TOKEN_INVALID", secret);
  refuses(() => load(write("broken.json", `{ "authToken": "${secret}"`)), "CONFIG_TOKEN_INVALID", secret);
  refuses(() => load(write("space", `${secret} ${secret}`)), "CONFIG_TOKEN_INVALID", secret);
});

test("createTeleptyTransport re-validates: a widened config is refused, a valid one makes no request until used", async () => {
  const cfg = normalizeConfig(GOOD);
  const widened = [
    { teleptyOrigin: "http://10.0.0.5:41234", token: cfg.token, targets: [...cfg.targets], inboxPrefix: "ts" },
    { teleptyOrigin: "http://127.0.0.1:41234", token: cfg.token, targets: ["orch-1", "a\u0000"], inboxPrefix: "ts" },
    { teleptyOrigin: "http://127.0.0.1:41234", token: "has space", targets: ["orch-1"], inboxPrefix: "ts" },
    { teleptyOrigin: "http://127.0.0.1:41234", targets: ["orch-1"], inboxPrefix: "ts" },
    null,
  ];
  for (const c of widened) assert.throws(() => createTeleptyTransport(c), (err) => err instanceof ConfigError);

  const tr = createTeleptyTransport(cfg);
  assert.match(tr.inboxId, /^ts-i[0-9a-f]{32}$/);
  assert.ok(!cfg.targets.includes(tr.inboxId));
  assert.ok(Object.isFrozen(tr));
  // close() before any send: nothing registered, nothing deleted, no network needed.
  assert.deepEqual(await tr.close(), { inbox_id: tr.inboxId, outcome: "not_created" });
  assert.equal(await tr.close(), await tr.close(), "close is idempotent");
});
