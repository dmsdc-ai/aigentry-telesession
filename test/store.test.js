// telesession durable store (src/store.js, L1) — independent tests against the FROZEN contract
// (IMPLEMENTATION-CONTRACT-R2.json apis.store + state_schema_v1, SPEC-R2 §3–§5, CONTROLLER-ADDENDA).
// Real filesystem only: no sockets, no HTTP, no telepty. Faults are targeted errno throws from a
// wrapper over the real fs passed through the documented openStore test seam. Crash = SIGKILL of a
// child process that holds the store through the real module.

import { describe, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  StoreError, STORE_SCHEMA, STORE_VERSION, STORE_LIMITS, openStore,
} from "../src/store.js";
import {
  createFaultFs, foreignLock, hex, inspectDir, makeInbox, makeRequest, makeSandbox, makeState, newInboxId,
  readJson, renamesOnto, requestKey, sha256, tmpIn, tmpLeftovers, writeLockFile, writeStateDir,
} from "./helpers/fault-fs.js";
import { startChildHost } from "./helpers/child-host.js";

const ORIGIN = "http://127.0.0.1:47999";
const PREFIX = "tsd";
const POSIX = process.platform !== "win32";
const POSIX_ONLY = POSIX ? false : "POSIX-only (native Windows has its own cases below)";
const STORE_SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "src", "store.js");

function sandbox(t, prefix) {
  const sb = makeSandbox(prefix);
  const opened = [];
  t.after(() => {
    for (const s of opened) { try { s.close(); } catch { /* already closed */ } }
    sb.remove();
  });
  sb.open = (opts = {}, seamExtra = {}) => {
    const s = openStore({
      dir: opts.dir ?? sb.stateDir, origin: opts.origin ?? ORIGIN, inboxPrefix: opts.inboxPrefix ?? PREFIX,
      persistCredential: opts.persistCredential ?? false, newInboxId: () => opts.inboxId ?? newInboxId(PREFIX),
      ...(opts.extra || {}),
    }, sb.seam(seamExtra));
    opened.push(s);
    return s;
  };
  return sb;
}

function refusal(fn, code) {
  let err = null;
  try { fn(); } catch (e) { err = e; }
  assert.ok(err, `expected StoreError ${code}, got no throw`);
  assert.ok(err instanceof StoreError, `expected StoreError, got ${err && err.name}: ${err && err.message}`);
  assert.equal(err.code, code);
  assert.equal(err.message, code, "message === code (no path, no detail)");
  return err;
}

const sender = (inboxId) => ({ id: inboxId, epoch: `epoch-${hex(4)}`, generation: 3 });
const fileBytes = (p) => fs.readFileSync(p);
const exists = (p) => { try { fs.lstatSync(p); return true; } catch { return false; } };
const lockPath = (dir) => path.join(dir, "lock");
const statePath = (dir) => path.join(dir, "state.json");
const filesOnly = (snap) => Object.fromEntries(Object.entries(snap).filter(([k]) => !k.endsWith("/")));
const regularFiles = (dir) => { try { return fs.readdirSync(dir).filter((n) => fs.lstatSync(path.join(dir, n)).isFile()); } catch { return []; } };

function assertNoPath(value, dir) {
  const s = JSON.stringify(value);
  assert.ok(!s.includes(dir), "result must not contain the state dir path");
  assert.ok(!s.includes(os.tmpdir()), "result must not contain a filesystem path");
}

describe("exports (frozen API)", () => {
  test("schema, version, limits and StoreError match the contract exactly", () => {
    assert.equal(STORE_SCHEMA, "telesession-state");
    assert.equal(STORE_VERSION, 1);
    assert.deepEqual({ ...STORE_LIMITS }, {
      requests: 1024, replies: 64, replyTextBytes: 65536, replyFileBytes: 98304, stateBytes: 1048576,
      retainMs: 86400000, gaps: 32, orphans: 16, boundInjectIds: 1024, retiredNonces: 256,
    });
    assert.ok(Object.isFrozen(STORE_LIMITS));
    assert.ok(new StoreError("STORE_LOCKED") instanceof Error);
  });

  test("no time-based lock authority exists in the source: no stale/heartbeat option, no timer", () => {
    const src = fs.readFileSync(STORE_SRC, "utf8");
    assert.doesNotMatch(src, /lockStaleMs|heartbeatMs/);
    assert.doesNotMatch(src, /\bsetInterval\s*\(/, "no heartbeat lease");
  });
});

describe("open / commit / graceful close-reopen (real fs)", () => {
  test("fresh open: leaf created 0700, lock {v,owner,pid,created_at} 0600, fresh frozen snapshot without secrets", { skip: POSIX_ONLY }, (t) => {
    const sb = sandbox(t);
    const id = newInboxId(PREFIX);
    assert.equal(exists(sb.stateDir), false);
    const s = sb.open({ inboxId: id });
    assert.equal(fs.statSync(sb.stateDir).mode & 0o777, 0o700);
    const lock = readJson(lockPath(sb.stateDir));
    assert.equal(lock.v, 1);
    assert.match(lock.owner, /^[0-9a-f]{32}$/);
    assert.equal(typeof lock.pid, "number");
    assert.ok(lock.created_at !== undefined);
    assert.equal(fs.statSync(lockPath(sb.stateDir)).mode & 0o777, 0o600);
    assert.deepEqual(s.info(), { mode: "durable", permissions: "verified", credential_persisted: false });
    assert.equal(s.lockState(), "held");
    const snap = s.snapshot();
    assert.equal(snap.schema, "telesession-state");
    assert.equal(snap.version, 1);
    assert.deepEqual({ ...snap.binding }, { origin: ORIGIN, inbox_prefix: PREFIX });
    assert.equal(snap.inbox.id, id);
    assert.equal(snap.inbox.phase, "none");
    assert.deepEqual(Object.keys(snap.requests), []);
    assert.throws(() => { snap.inbox.phase = "ready"; }, TypeError, "snapshot is deep-frozen");
    assert.throws(() => { snap.requests.x = 1; }, TypeError);
    assert.doesNotMatch(JSON.stringify(snap), /bearer|token/i);
  });

  test("commit: atomic 0600 state.json, generation +1, snapshot swap only on success, no tmp left", { skip: POSIX_ONLY }, (t) => {
    const sb = sandbox(t);
    const s = sb.open();
    const before = s.snapshot();
    const rec = makeRequest({ sender: sender(before.inbox.id) });
    const r = s.commit((d) => { d.requests[requestKey(rec)] = rec; });
    assert.deepEqual(r, { ok: true });
    const after = s.snapshot();
    assert.equal(after.generation, before.generation + 1);
    assert.deepEqual(Object.keys(after.requests), ["r:req-1"], "identity is the map key r:<request_id> (R3 §1)");
    assert.deepEqual(after.requests[requestKey(rec)], rec);
    assert.deepEqual(Object.keys(before.requests), [], "an older snapshot is a clone, never mutated");
    assert.equal(fs.statSync(statePath(sb.stateDir)).mode & 0o777, 0o600);
    assert.deepEqual(readJson(statePath(sb.stateDir)), JSON.parse(JSON.stringify(after)));
    assert.deepEqual(tmpLeftovers(sb.stateDir), []);
  });

  test("invalid mutations are refused with memory and disk unchanged; commit never throws", (t) => {
    const sb = sandbox(t);
    const s = sb.open();
    const id = s.snapshot().inbox.id;
    const good = makeRequest({ sender: sender(id) });
    assert.deepEqual(s.commit((d) => { d.requests[requestKey(good)] = good; }), { ok: true });
    const snap = s.snapshot();
    const bytes = fileBytes(statePath(sb.stateDir));
    const cases = {
      "unknown top key": (d) => { d.extra = 1; },
      "bearer smuggled into inbox": (d) => { d.inbox.bearer = "secret-bearer"; },
      "unknown request key": (d) => { d.requests[requestKey(good)].prompt = "text"; },
      "redundant key property (R3 §1)": (d) => { d.requests[requestKey(good)].key = requestKey(good); },
      "map key ≠ r:<request_id>": (d) => { const w = makeRequest({ request_id: "req-w", sender: sender(id) }); d.requests["r:req-x"] = w; },
      "n:<nonce> key for a request_id record": (d) => { const w = makeRequest({ request_id: "req-w", sender: sender(id) }); d.requests[`n:${w.nonce}`] = w; },
      "upper-case counter name (R3 §2)": (d) => { d.counters.EPERM = 1; },
      "upper-case quarantine name (R3 §2)": (d) => { d.requests[requestKey(good)].quarantined.DUPLICATE = 1; },
      "wrong type": (d) => { d.requests[requestKey(good)].body_len = "1"; },
      "bad state": (d) => { d.requests[requestKey(good)].state = "delivered"; },
      "bad phase": (d) => { d.inbox.phase = "alive"; },
      "duplicate nonce": (d) => {
        const dup = makeRequest({ request_id: "req-dup", sender: sender(id), nonce: good.nonce });
        d.requests[requestKey(dup)] = dup;
      },
      "requests > 1024": (d) => {
        for (let i = 0; i < 1024; i++) {
          const r = makeRequest({ request_id: `bulk-${i}`, sender: sender(id) });
          d.requests[requestKey(r)] = r;
        }
      },
    };
    for (const [name, mutate] of Object.entries(cases)) {
      let r;
      assert.doesNotThrow(() => { r = s.commit(mutate); }, name);
      assert.equal(r.ok, false, name);
      assert.equal(r.code, "STORE_INVALID_MUTATION", name);
      assert.deepEqual(s.snapshot(), snap, `${name}: memory unchanged`);
      assert.deepEqual(fileBytes(statePath(sb.stateDir)), bytes, `${name}: disk unchanged`);
    }
    let thrown;
    assert.doesNotThrow(() => { thrown = s.commit(() => { throw new Error("mutator bug"); }); });
    assert.equal(thrown.ok, false);
    assert.deepEqual(s.snapshot(), snap);
    assert.deepEqual(tmpLeftovers(sb.stateDir), []);
    const anon = makeRequest({ request_id: null, sender: sender(id) });
    assert.deepEqual(s.commit((d) => { d.requests[`n:${anon.nonce}`] = anon; }), { ok: true }, "request_id null → map key n:<nonce>");
  });

  test("graceful close releases the lock; reopen restores records, inbox id and generation", (t) => {
    const sb = sandbox(t);
    const s1 = sb.open();
    const id = s1.snapshot().inbox.id;
    const rec = makeRequest({ sender: sender(id), state: "accepted", inject_id: "00000000-0000-4000-8000-000000000001", target_epoch: "te-1" });
    assert.deepEqual(s1.commit((d) => { d.requests[requestKey(rec)] = rec; d.inbox.phase = "deleted"; }), { ok: true });
    const owner1 = readJson(lockPath(sb.stateDir)).owner;
    const snap1 = s1.snapshot();
    s1.close();
    assert.equal(exists(lockPath(sb.stateDir)), false);
    const s2 = sb.open({ inboxId: newInboxId(PREFIX) });     // a new id generator must NOT replace the stored id
    const snap2 = s2.snapshot();
    assert.equal(snap2.inbox.id, id);
    assert.equal(snap2.generation, snap1.generation);
    assert.deepEqual(snap2.requests[requestKey(rec)], rec);
    assert.notEqual(readJson(lockPath(sb.stateDir)).owner, owner1, "fresh owner per process/open");
  });

  // R3 §3: only store-created temp names are swept; unknown look-alikes are never touched.
  test("a stale .tmp is swept only after the lock is acquired", (t) => {
    const sb = sandbox(t);
    const s1 = sb.open();
    s1.commit((d) => { d.inbox.phase = "deleted"; });
    const nonce = hex(16);
    const text = `REPLY ${nonce} seed`;
    assert.deepEqual(s1.putReply({ nonce, sha256: sha256(text), text, received_at: new Date().toISOString() }), { ok: true });
    s1.close();
    const replies = path.join(sb.stateDir, "replies");
    const known = [
      path.join(sb.stateDir, `.state.json.${hex(8)}.tmp`),
      path.join(sb.stateDir, `.credential.json.${hex(8)}.tmp`),
      path.join(replies, `.${hex(16)}-${sha256(hex(4))}.json.${hex(8)}.tmp`),
    ];
    const unknown = [
      path.join(sb.stateDir, ".state.json.123.tmp"),
      path.join(sb.stateDir, `.state.json.${hex(8).toUpperCase()}.tmp`),
      path.join(sb.stateDir, `state.json.${hex(8)}.tmp`),
      path.join(sb.stateDir, `.other.json.${hex(8)}.tmp`),
      path.join(sb.stateDir, "notes.tmp"),
      path.join(replies, `.${hex(16)}.json.${hex(8)}.tmp`),
    ];
    for (const p of [...known, ...unknown]) fs.writeFileSync(p, "partial", { mode: 0o600 });
    writeLockFile(sb.stateDir, foreignLock());
    refusal(() => sb.open(), "STORE_LOCKED");
    for (const p of [...known, ...unknown]) assert.equal(exists(p), true, `no sweep without the lock: ${path.basename(p)}`);
    fs.unlinkSync(lockPath(sb.stateDir));                     // test setup: the operator removed it
    sb.open();
    for (const p of known) assert.equal(exists(p), false, `store-created temp swept after acquire: ${path.basename(p)}`);
    for (const p of unknown) assert.equal(exists(p), true, `unknown similar name preserved: ${path.basename(p)}`);
  });
});

describe("atomic write faults (fault-fs over the real fs)", () => {
  // The exact-path predicates below only bite if the sandbox speaks the store's (native realpath) path form.
  test("sandbox stateDir is the store's canonical path; the store's tmp writes match tmpIn(stateDir)", (t) => {
    const sb = sandbox(t);
    const ff = createFaultFs();
    const s = sb.open({}, { fs: ff.fs });
    assert.equal(fs.realpathSync.native(sb.stateDir), sb.stateDir);
    ff.resetCalls();
    assert.deepEqual(s.commit((d) => { d.counters.canon = 1; }), { ok: true });
    const pred = tmpIn(sb.stateDir);
    assert.ok(ff.calls.some((c) => c.op === "openSync" && pred(c)), "store opened its tmp under the sandbox stateDir");
  });

  const points = [
    { name: "open tmp", op: "openSync" },
    { name: "write tmp", op: ["writeSync", "writeFileSync"] },
    { name: "fsync tmp", op: "fsyncSync" },
    { name: "rename onto state.json", op: "renameSync", when: () => renamesOnto("state.json") },
  ];
  for (const errno of ["ENOSPC", "EIO"]) {
    for (const point of points) {
      test(`${errno} at ${point.name} → STORE_WRITE_FAILED{errno}, previous bytes + memory intact, no tmp`, (t) => {
        const sb = sandbox(t);
        const ff = createFaultFs();
        const s = sb.open({}, { fs: ff.fs });
        assert.deepEqual(s.commit((d) => { d.counters.seed = 1; }), { ok: true });
        const snap = s.snapshot();
        const bytes = fileBytes(statePath(sb.stateDir));
        const rule = ff.fail({ op: point.op, when: point.when ? point.when() : tmpIn(sb.stateDir), errno });
        const r = s.commit((d) => { d.counters.seed = 2; });
        assert.equal(rule.hits, 1, "the targeted call went through the fs seam");
        assert.deepEqual(r, { ok: false, code: "STORE_WRITE_FAILED", errno });
        assertNoPath(r, sb.stateDir);
        assert.deepEqual(fileBytes(statePath(sb.stateDir)), bytes);
        assert.deepEqual(s.snapshot(), snap);
        assert.deepEqual(tmpLeftovers(sb.stateDir), []);
        assert.deepEqual(s.commit((d) => { d.counters.seed = 3; }), { ok: true }, "next commit works once the fault is gone");
        assert.equal(s.snapshot().generation, snap.generation + 1);
      });
    }
  }

  test("directory fsync EPERM/EINVAL/EBADF/EISDIR is ignored (commit ok)", (t) => {
    const sb = sandbox(t);
    const ff = createFaultFs();
    const s = sb.open({}, { fs: ff.fs });
    for (const errno of ["EPERM", "EINVAL", "EBADF", "EISDIR"]) {
      const counter = `dir_fsync_${errno.toLowerCase()}`;   // R3 §2: lower-case reason code witnesses the commit
      const rule = ff.fail({ op: "fsyncSync", when: (ctx) => ctx.paths[0] === sb.stateDir, errno });
      const r = s.commit((d) => { d.counters[counter] = 1; });
      assert.equal(rule.hits, 1, `${errno}: directory fsync attempted`);
      assert.deepEqual(r, { ok: true }, errno);
      assert.equal(readJson(statePath(sb.stateDir)).counters[counter], 1);
    }
  });
});

describe("refuse start on bad state.json (bytes untouched, owned lock released)", () => {
  // `origin`/`prefix` = the binding the state was written under; the fixture is valid under it (R3 §4).
  function fixture(sb, mutate, { origin = ORIGIN, prefix = PREFIX } = {}) {
    const st = makeState({ origin, prefix, inbox: makeInbox({ prefix, phase: "deleted" }) });
    st.requests = {};
    const rec = makeRequest({ sender: sender(st.inbox.id) });
    st.requests[requestKey(rec)] = rec;
    return mutate(st, rec);
  }
  const cases = [
    ["truncated JSON", "STORE_CORRUPT", (sb) => ({ raw: JSON.stringify(fixture(sb, (s) => s)).slice(0, 40) })],
    ["version 2", "STORE_VERSION_UNSUPPORTED", (sb) => ({ state: fixture(sb, (s) => ({ ...s, version: 2 })) })],
    ["other schema", "STORE_CORRUPT", (sb) => ({ state: fixture(sb, (s) => ({ ...s, schema: "something-else" })) })],
    ["unknown top key", "STORE_CORRUPT", (sb) => ({ state: fixture(sb, (s) => ({ ...s, extra: true })) })],
    ["unknown request key", "STORE_CORRUPT", (sb) => ({ state: fixture(sb, (s, r) => { r.text = "prompt"; return s; }) })],
    ["wrong type", "STORE_CORRUPT", (sb) => ({ state: fixture(sb, (s) => ({ ...s, generation: "7" })) })],
    ["duplicate nonces", "STORE_CORRUPT", (sb) => ({
      state: fixture(sb, (s, r) => { const d = { ...r, request_id: "other" }; s.requests[requestKey(d)] = d; return s; }),
    })],
    ["1025 requests", "STORE_CORRUPT", (sb) => ({
      state: fixture(sb, (s) => {
        for (let i = 0; i < 1025; i++) { const r = makeRequest({ request_id: `b${i}`, sender: sender(s.inbox.id) }); s.requests[requestKey(r)] = r; }
        return s;
      }),
    })],
    ["> 1 MiB", "STORE_CORRUPT", (sb) => ({ raw: JSON.stringify(fixture(sb, (s) => s)) + " ".repeat(1048576) })],
    ["binding origin mismatch", "STORE_BINDING_MISMATCH", (sb) => ({
      state: fixture(sb, (s) => s, { origin: "http://127.0.0.1:47998" }),
    })],
    ["binding prefix mismatch", "STORE_BINDING_MISMATCH", (sb) => ({
      state: fixture(sb, (s) => s, { prefix: "other" }),
    })],
    ["inbox ids outside the stored prefix", "STORE_CORRUPT", (sb) => ({
      state: fixture(sb, (s) => ({ ...s, binding: { origin: ORIGIN, inbox_prefix: "other" } })),
    })],
  ];
  for (const [name, code, build] of cases) {
    test(`${name} → ${code}`, (t) => {
      const sb = sandbox(t);
      const { state, raw } = build(sb);
      writeStateDir(sb.stateDir, state, { raw });
      const before = filesOnly(inspectDir(sb.stateDir));
      refusal(() => sb.open(), code);
      assert.deepEqual(filesOnly(inspectDir(sb.stateDir)), before, "bytes, mode and mtime untouched; owned lock released");
    });
  }

  test("state.json that is a symlink, a hardlink (nlink 2) or a directory → STORE_CORRUPT, nothing touched", { skip: POSIX_ONLY }, (t) => {
    const sb = sandbox(t);
    const good = makeState({ origin: ORIGIN, prefix: PREFIX });
    const elsewhere = path.join(sb.root, "elsewhere.json");
    for (const variant of ["symlink", "hardlink", "directory"]) {
      fs.rmSync(sb.stateDir, { recursive: true, force: true });
      fs.mkdirSync(sb.stateDir, { mode: 0o700 });
      fs.writeFileSync(elsewhere, JSON.stringify(good), { mode: 0o600 });
      if (variant === "symlink") fs.symlinkSync(elsewhere, statePath(sb.stateDir));
      if (variant === "hardlink") fs.linkSync(elsewhere, statePath(sb.stateDir));
      if (variant === "directory") fs.mkdirSync(statePath(sb.stateDir), { mode: 0o700 });
      const before = inspectDir(sb.stateDir);
      const target = fileBytes(elsewhere);
      refusal(() => sb.open(), "STORE_CORRUPT");
      assert.deepEqual(inspectDir(sb.stateDir), before, variant);
      assert.deepEqual(fileBytes(elsewhere), target, `${variant}: link target untouched`);
      fs.rmSync(elsewhere, { force: true });
    }
  });
});

describe("state-dir predicate and permissions (SPEC-R2 §3; no repair)", () => {
  test("MUST ACCEPT private app state under home, with cwd=home and with cwd=project elsewhere", { skip: POSIX_ONLY }, (t) => {
    const sb = sandbox(t);
    const s1 = sb.open({}, { cwd: sb.home });
    s1.close();
    const s2 = sb.open({}, { cwd: sb.project });
    s2.close();
    const appSupport = path.join(sb.home, "Library", "Application Support", "telesession");
    fs.mkdirSync(path.dirname(appSupport), { recursive: true, mode: 0o700 });
    const s3 = sb.open({ dir: appSupport });
    assert.equal(s3.info().permissions, "verified");
  });

  // Leaves are pre-created 0700 (so no mkdir is needed) and must stay empty: no lock, no state, no tmp.
  const forbidden = [
    ["filesystem root", (sb) => path.parse(sb.root).root, {}],
    ["home exact", (sb) => sb.home, {}],
    ["cwd exact", (sb) => sb.project, {}],
    ["ancestor of home", (sb) => path.dirname(sb.home), {}],
    ["ancestor of project cwd", (sb) => path.dirname(sb.project), {}],
    ["inside project cwd", (sb) => path.join(sb.project, ".telesession"), {}],
    ["~/.telepty itself", (sb) => path.join(sb.home, ".telepty"), {}],
    ["~/.telepty/x", (sb) => path.join(sb.home, ".telepty", "x"), {}],
    ["~/.config/aigentry-telepty", (sb) => path.join(sb.home, ".config", "aigentry-telepty"), {}],
    ["~/.config/aigentry-telepty/x", (sb) => path.join(sb.home, ".config", "aigentry-telepty", "x"), {}],
    ["~/.aigentry/mailbox/x", (sb) => path.join(sb.home, ".aigentry", "mailbox", "x"), {}],
    ["~/.aigentry (ancestor of the mailbox)", (sb) => path.join(sb.home, ".aigentry"), {}],
    ["parent symlink resolving into ~/.telepty", (sb) => {
      fs.mkdirSync(path.join(sb.home, ".telepty"), { recursive: true, mode: 0o700 });
      const link = path.join(sb.home, ".local", "state", "via-link");
      fs.symlinkSync(path.join(sb.home, ".telepty"), link);
      return path.join(link, "x");
    }, {}],
  ];
  for (const [name, leafOf] of forbidden) {
    test(`STORE_PATH_FORBIDDEN: ${name}; nothing written, no chmod`, { skip: POSIX_ONLY }, (t) => {
      const sb = sandbox(t);
      const leaf = leafOf(sb);
      fs.mkdirSync(leaf, { recursive: true, mode: 0o700 });
      const real = fs.realpathSync(leaf);
      const isRoot = path.parse(real).root === real;
      const before = isRoot ? null : inspectDir(real);
      const ff = createFaultFs();
      refusal(() => sb.open({ dir: leaf }, { fs: ff.fs }), "STORE_PATH_FORBIDDEN");
      const writes = ff.mutatingCalls().filter((c) => !c.op.startsWith("mkdirSync"));
      assert.deepEqual(writes, [], "no write/chmod/chown/unlink/rename before a path refusal");
      if (!isRoot) assert.deepEqual(inspectDir(real), before);
    });
  }

  test("leaf symlink → STORE_PATH_FORBIDDEN; link and target untouched", { skip: POSIX_ONLY }, (t) => {
    const sb = sandbox(t);
    const target = path.join(sb.root, "real-state");
    fs.mkdirSync(target, { mode: 0o700 });
    fs.symlinkSync(target, sb.stateDir);
    refusal(() => sb.open(), "STORE_PATH_FORBIDDEN");
    assert.ok(fs.lstatSync(sb.stateDir).isSymbolicLink());
    assert.deepEqual(fs.readdirSync(target), []);
  });

  test("parent missing → STORE_PATH_FORBIDDEN, nothing created", (t) => {
    const sb = sandbox(t);
    const leaf = path.join(sb.home, ".local", "missing-parent", "telesession");
    refusal(() => sb.open({ dir: leaf }), "STORE_PATH_FORBIDDEN");
    assert.equal(exists(path.dirname(leaf)), false);
  });

  test("lexical recheck in openStore (defence in depth) → STORE_PATH_FORBIDDEN, nothing created", (t) => {
    const sb = sandbox(t);
    const base = path.join(sb.home, ".local", "state");
    const bad = [
      "relative/telesession",
      `${base}${path.sep}a${path.sep}..${path.sep}telesession`,
      `${base}${path.sep}telesession${path.sep}`,
      `${base}${path.sep}tele\u0000session`,
      `${base}${path.sep}tele\u0001session`,
      `${base}${path.sep}tele\u007fsession`,
      `${base}${path.sep}${"a".repeat(600)}`,
      "",
    ];
    const before = inspectDir(sb.root);
    for (const dir of bad) refusal(() => sb.open({ dir }), "STORE_PATH_FORBIDDEN");
    assert.deepEqual(inspectDir(sb.root), before);
  });

  for (const mode of [0o755, 0o750, 0o701, 0o707]) {
    test(`leaf mode ${mode.toString(8)} → STORE_PERMISSIONS_INVALID, mode not repaired, no files`, { skip: POSIX_ONLY }, (t) => {
      const sb = sandbox(t);
      fs.mkdirSync(sb.stateDir, { mode: 0o700 });
      fs.chmodSync(sb.stateDir, mode);
      const ff = createFaultFs();
      refusal(() => sb.open({}, { fs: ff.fs }), "STORE_PERMISSIONS_INVALID");
      assert.equal(fs.statSync(sb.stateDir).mode & 0o777, mode);
      assert.deepEqual(fs.readdirSync(sb.stateDir), []);
      assert.deepEqual(ff.mutatingCalls().filter((c) => !c.op.startsWith("mkdirSync")), []);
    });
  }

  test("leaf owned by another uid → STORE_PERMISSIONS_INVALID, no chown, no files", { skip: POSIX_ONLY }, (t) => {
    const sb = sandbox(t);
    fs.mkdirSync(sb.stateDir, { mode: 0o700 });
    const ff = createFaultFs();
    const rule = ff.mapResult({
      op: ["statSync", "lstatSync", "fstatSync"],
      when: (ctx) => ctx.paths[0] === sb.stateDir,
      map: (st) => { st.uid = typeof st.uid === "bigint" ? st.uid + 1n : st.uid + 1; return st; },
    });
    refusal(() => sb.open({}, { fs: ff.fs }), "STORE_PERMISSIONS_INVALID");
    assert.ok(rule.hits >= 1, "owner check read the leaf through the fs seam");
    assert.deepEqual(fs.readdirSync(sb.stateDir), []);
    assert.deepEqual(ff.mutatingCalls().filter((c) => !c.op.startsWith("mkdirSync")), []);
  });
});

describe("lock: strict single writer, no takeover (SPEC-R2 §5)", () => {
  test("second open while held → STORE_LOCKED; lock bytes/mtime unchanged; holder unaffected", (t) => {
    const sb = sandbox(t);
    const s1 = sb.open();
    const before = inspectDir(sb.stateDir);
    refusal(() => sb.open(), "STORE_LOCKED");
    assert.deepEqual(inspectDir(sb.stateDir), before);
    assert.equal(s1.lockState(), "held");
    assert.deepEqual(s1.commit((d) => { d.counters.after_contention = 1; }), { ok: true });
  });

  test("any existing lock file → STORE_LOCKED regardless of age, pid, content or clock; nothing touched", async (t) => {
    const sb = sandbox(t);
    const s0 = sb.open();
    s0.commit((d) => { d.inbox.phase = "deleted"; });
    s0.close();
    const dead = spawn(process.execPath, ["-e", ""], { stdio: "ignore" });
    const deadPid = await new Promise((r) => dead.once("exit", () => r(dead.pid)));
    const dayAgo = new Date(Date.now() - 86400000);
    const variants = [
      ["fresh foreign owner", foreignLock(), null],
      ["1-day-old", foreignLock({ created_at: dayAgo.toISOString() }), dayAgo],
      ["dead pid", foreignLock({ pid: deadPid }), null],
      ["this process's own pid", foreignLock({ pid: process.pid }), null],
      ["garbage pid", JSON.stringify({ v: 1, owner: hex(16), pid: "not-a-pid", created_at: "x" }), null],
      ["empty file", "", null],
      ["corrupt JSON", "{\"v\":1,\"own", null],
    ];
    const stray = path.join(sb.stateDir, ".state.json.9.tmp");
    for (const [name, content, mtime] of variants) {
      writeLockFile(sb.stateDir, content);
      if (mtime) fs.utimesSync(lockPath(sb.stateDir), mtime, mtime);
      fs.writeFileSync(stray, "x", { mode: 0o600 });
      for (const clock of [undefined, () => Date.now() + 365 * 86400000]) {
        const before = inspectDir(sb.stateDir);
        const ff = createFaultFs();
        refusal(() => sb.open({ extra: { lockStaleMs: 0, heartbeatMs: 1, takeover: true } },
          { fs: ff.fs, ...(clock ? { now: clock } : {}) }), "STORE_LOCKED");
        assert.deepEqual(inspectDir(sb.stateDir), before, `${name}: lock/state/tmp bytes and mtimes unchanged`);
        assert.deepEqual(ff.mutatingCalls().filter((c) => !c.op.startsWith("mkdirSync")), [],
          `${name}: no unlink/rename/write/chmod/utimes after EEXIST`);
      }
      fs.unlinkSync(lockPath(sb.stateDir));
    }
  });

  test("lock replaced under the holder → sticky STORE_LOCK_LOST for every write; close() leaves the foreign lock", { skip: POSIX_ONLY }, (t) => {
    const sb = sandbox(t);
    const ff = createFaultFs();
    const s = sb.open({ persistCredential: true }, { fs: ff.fs });
    assert.deepEqual(s.commit((d) => { d.counters.n = 1; }), { ok: true });
    const original = fs.readFileSync(lockPath(sb.stateDir), "utf8");
    const stateBytes = fileBytes(statePath(sb.stateDir));
    const foreign = foreignLock();
    fs.writeFileSync(lockPath(sb.stateDir), foreign);
    ff.resetCalls();
    assert.deepEqual(s.commit((d) => { d.counters.n = 2; }), { ok: false, code: "STORE_LOCK_LOST" });
    assert.equal(s.lockState(), "lost");
    const nonce = hex(16);
    const text = `REPLY ${nonce} hi`;
    assert.equal(s.putReply({ nonce, sha256: sha256(text), text, received_at: new Date().toISOString() }).code, "STORE_LOCK_LOST");
    assert.equal(s.writeCredential({ inbox_id: s.snapshot().inbox.id, epoch: "e", generation: 1, bearer: "b".repeat(32) }).code, "STORE_LOCK_LOST");
    assert.equal(s.clearCredential().code, "STORE_LOCK_LOST");
    fs.writeFileSync(lockPath(sb.stateDir), original);          // even our own bytes back: still lost (sticky)
    assert.deepEqual(s.commit((d) => { d.counters.n = 3; }), { ok: false, code: "STORE_LOCK_LOST" });
    fs.writeFileSync(lockPath(sb.stateDir), foreign);
    s.close();
    assert.equal(fs.readFileSync(lockPath(sb.stateDir), "utf8"), foreign, "foreign lock never unlinked");
    assert.deepEqual(fileBytes(statePath(sb.stateDir)), stateBytes);
    assert.equal(exists(path.join(sb.stateDir, "credential.json")), false);
    assert.equal(exists(path.join(sb.stateDir, "replies", `${nonce}-${sha256(text)}.json`)), false);
    const lockTouch = ff.callsTouching(lockPath(sb.stateDir)).filter((c) => /^(unlink|rename|rm|writeFile|truncate)/.test(c.op));
    assert.deepEqual(lockTouch, [], "no product unlink/rename/write of a foreign lock");
  });

  test("lock deleted under the holder → STORE_LOCK_LOST; close() creates and unlinks nothing", (t) => {
    const sb = sandbox(t);
    const s = sb.open();
    assert.deepEqual(s.commit((d) => { d.counters.n = 1; }), { ok: true });
    fs.unlinkSync(lockPath(sb.stateDir));
    assert.deepEqual(s.commit((d) => { d.counters.n = 2; }), { ok: false, code: "STORE_LOCK_LOST" });
    assert.equal(s.lockState(), "lost");
    s.close();
    assert.equal(exists(lockPath(sb.stateDir)), false);
    assert.equal(readJson(statePath(sb.stateDir)).counters.n, 1);
  });

  test("graceful close unlinks exactly the owner-matched lock once", (t) => {
    const sb = sandbox(t);
    const ff = createFaultFs();
    const s = sb.open({}, { fs: ff.fs });
    s.commit((d) => { d.counters.n = 1; });
    ff.resetCalls();
    s.close();
    const unlinks = ff.callsTouching(lockPath(sb.stateDir)).filter((c) => /^(unlink|rm|rename)/.test(c.op));
    assert.equal(unlinks.length, 1);
    assert.equal(unlinks[0].op, "unlinkSync");
    assert.equal(exists(lockPath(sb.stateDir)), false);
  });

  test("abrupt crash (SIGKILL of a store child) → lock stays, every restart STORE_LOCKED, durable record intact", async (t) => {
    const sb = sandbox(t);
    const inboxId = newInboxId(PREFIX);
    const rec = makeRequest({ request_id: "crash-1", sender: sender(inboxId) });
    const host = startChildHost("store-hold", {
      dir: sb.stateDir, origin: ORIGIN, inboxPrefix: PREFIX, inboxId, requests: [rec], seam: sb.seam(),
    }, { name: "store-hold-crash" });
    t.after(() => host.stop());
    const ready = await host.nextEvent((e) => e.event === "ready" || e.event === "error");
    assert.equal(ready.event, "ready", host.readLog());
    assert.deepEqual(ready.commit, { ok: true });
    const exit = await host.crash();
    assert.equal(exit && exit.signal, "SIGKILL");
    const lockBefore = inspectDir(sb.stateDir).lock;
    for (let i = 0; i < 2; i++) refusal(() => sb.open(), "STORE_LOCKED");
    assert.deepEqual(inspectDir(sb.stateDir).lock, lockBefore, "lock bytes and mtime unchanged by refusals");
    const onDisk = readJson(statePath(sb.stateDir));
    assert.equal(onDisk.requests[requestKey(rec)].state, "reserved");
    assert.equal(onDisk.requests[requestKey(rec)].payload_sha256, rec.payload_sha256);
    assert.equal(onDisk.requests[requestKey(rec)].sender_inbox_id, inboxId);
    assert.equal(onDisk.requests[requestKey(rec)].sender_inbox_epoch, rec.sender_inbox_epoch);
    assert.equal(onDisk.requests[requestKey(rec)].sender_inbox_generation, rec.sender_inbox_generation);
    // The future reviewed repair gate is simulated by a lock-free COPY; the store itself never unlocks.
    const copy = path.join(sb.home, ".local", "state", "telesession-copy");
    fs.mkdirSync(copy, { mode: 0o700 });
    fs.copyFileSync(statePath(sb.stateDir), statePath(copy));
    fs.chmodSync(statePath(copy), 0o600);
    const s = sb.open({ dir: copy });
    assert.deepEqual(s.snapshot().requests[requestKey(rec)], rec);
    assert.equal(s.snapshot().inbox.id, inboxId);
  });

  test("graceful stop of a store child (SIGTERM on POSIX / IPC stop on win32 → close) releases the lock; parent reopens", async (t) => {
    const sb = sandbox(t);
    const inboxId = newInboxId(PREFIX);
    const rec = makeRequest({ request_id: "graceful-1", sender: sender(inboxId) });
    const host = startChildHost("store-hold", {
      dir: sb.stateDir, origin: ORIGIN, inboxPrefix: PREFIX, inboxId, requests: [rec], seam: sb.seam(),
    }, { name: "store-hold-graceful" });
    t.after(() => host.stop());
    assert.equal((await host.nextEvent((e) => e.event === "ready" || e.event === "error")).event, "ready", host.readLog());
    await host.stop();
    assert.ok(host.events.some((e) => e.event === "closed"), host.readLog());
    assert.equal(exists(lockPath(sb.stateDir)), false);
    const s = sb.open();
    assert.deepEqual(s.snapshot().requests[requestKey(rec)], rec);
  });
});

describe("replies (replies/<nonce>-<sha256>.json)", () => {
  const mk = (body = "answer") => {
    const nonce = hex(16);
    const text = `REPLY ${nonce} ${body}`;
    return { nonce, text, sha256: sha256(text), received_at: new Date().toISOString() };
  };
  const replyFile = (dir, r) => path.join(dir, "replies", `${r.nonce}-${r.sha256}.json`);

  test("putReply → 0600 file; readReply survives close/reopen; deleteReply → REPLY_MISSING", { skip: POSIX_ONLY }, (t) => {
    const sb = sandbox(t);
    const s1 = sb.open();
    const r = mk();
    assert.deepEqual(s1.putReply(r), { ok: true });
    assert.equal(fs.statSync(replyFile(sb.stateDir, r)).mode & 0o777, 0o600);
    assert.equal(fs.statSync(path.join(sb.stateDir, "replies")).mode & 0o777, 0o700);
    s1.close();
    const s2 = sb.open();
    assert.deepEqual(s2.readReply({ nonce: r.nonce, sha256: r.sha256 }), { ok: true, text: r.text, received_at: r.received_at });
    s2.deleteReply({ nonce: r.nonce, sha256: r.sha256 });
    assert.equal(exists(replyFile(sb.stateDir, r)), false);
    assert.deepEqual(s2.readReply({ nonce: r.nonce, sha256: r.sha256 }), { ok: false, code: "REPLY_MISSING" });
  });

  test("putReply refuses a sha mismatch and text over 65536 bytes; nothing written", (t) => {
    const sb = sandbox(t);
    const s = sb.open();
    const r = mk();
    assert.equal(s.putReply({ ...r, sha256: sha256("other") }).ok, false);
    const big = { ...r, text: "a".repeat(65537) };
    big.sha256 = sha256(big.text);
    assert.equal(s.putReply(big).ok, false);
    const edge = { ...r, text: "a".repeat(65536) };
    edge.sha256 = sha256(edge.text);
    assert.deepEqual(s.putReply(edge), { ok: true }, "exactly 65536 bytes is allowed");
    assert.deepEqual(fs.readdirSync(path.join(sb.stateDir, "replies")), [`${edge.nonce}-${edge.sha256}.json`]);
  });

  test("tampered / symlinked / hardlinked / oversized reply file → REPLY_CORRUPT, text never returned", { skip: POSIX_ONLY }, (t) => {
    const sb = sandbox(t);
    const s = sb.open();
    const variants = {
      garbage: (f) => fs.writeFileSync(f, "\u0000not json"),
      "text altered (sha mismatch)": (f) => { const j = readJson(f); j.text = String(j.text) + "!"; fs.writeFileSync(f, JSON.stringify(j)); },
      symlink: (f) => { const o = f + ".orig"; fs.renameSync(f, path.join(sb.root, path.basename(o))); fs.symlinkSync(path.join(sb.root, path.basename(o)), f); },
      hardlink: (f) => fs.linkSync(f, path.join(sb.root, `hl-${path.basename(f)}`)),
      "> 96 KiB": (f) => { const j = readJson(f); fs.writeFileSync(f, JSON.stringify(j) + " ".repeat(98305)); },
    };
    for (const [name, damage] of Object.entries(variants)) {
      const r = mk(name);
      assert.deepEqual(s.putReply(r), { ok: true }, name);
      damage(replyFile(sb.stateDir, r));
      const out = s.readReply({ nonce: r.nonce, sha256: r.sha256 });
      assert.deepEqual(out, { ok: false, code: "REPLY_CORRUPT" }, name);
      assert.ok(!JSON.stringify(out).includes(r.text), name);
    }
  });

  test("quota: 64 reply files → 65th putReply STORE_FULL (no eviction); freeing one admits one", (t) => {
    const sb = sandbox(t);
    const s = sb.open();
    const all = [];
    for (let i = 0; i < 64; i++) { const r = mk(`n${i}`); all.push(r); assert.deepEqual(s.putReply(r), { ok: true }, `#${i}`); }
    const extra = mk("overflow");
    assert.deepEqual(s.putReply(extra), { ok: false, code: "STORE_FULL" });
    assert.equal(fs.readdirSync(path.join(sb.stateDir, "replies")).length, 64);
    for (const r of all) assert.equal(s.readReply({ nonce: r.nonce, sha256: r.sha256 }).ok, true, "nothing evicted");
    s.deleteReply({ nonce: all[0].nonce, sha256: all[0].sha256 });
    assert.deepEqual(s.putReply(extra), { ok: true });
  });

  test("ENOSPC while writing a reply → STORE_WRITE_FAILED{errno}, no file, no tmp", (t) => {
    const sb = sandbox(t);
    const ff = createFaultFs();
    const s = sb.open({}, { fs: ff.fs });
    const r = mk();
    const repliesDir = path.join(sb.stateDir, "replies");
    const replyWrite = (ctx) => ctx.paths.some((p) => path.dirname(p) === repliesDir || (path.dirname(p) === sb.stateDir && /\.tmp$/.test(p)));
    const rule = ff.fail({ op: ["writeSync", "writeFileSync", "fsyncSync"], when: replyWrite, errno: "ENOSPC" });
    const out = s.putReply(r);
    assert.equal(rule.hits, 1);
    assert.deepEqual(out, { ok: false, code: "STORE_WRITE_FAILED", errno: "ENOSPC" });
    assertNoPath(out, sb.stateDir);
    assert.deepEqual(exists(repliesDir) ? fs.readdirSync(repliesDir) : [], []);
    assert.deepEqual(tmpLeftovers(sb.stateDir), []);
    assert.deepEqual(s.readReply({ nonce: r.nonce, sha256: r.sha256 }), { ok: false, code: "REPLY_MISSING" });
  });
});

describe("inbox credential (POSIX only; never in state)", () => {
  const cred = (id) => ({ inbox_id: id, epoch: `epoch-${hex(4)}`, generation: 7, bearer: `bearer-${hex(24)}` });

  test("persistCredential=false: read null even if a file exists; write → STORE_CREDENTIAL_DISABLED", (t) => {
    const sb = sandbox(t);
    const s = sb.open();
    assert.equal(s.readCredential(), null);
    const out = s.writeCredential(cred(s.snapshot().inbox.id));
    assert.deepEqual(out, { ok: false, code: "STORE_CREDENTIAL_DISABLED" });
    assert.equal(exists(path.join(sb.stateDir, "credential.json")), false);
    fs.writeFileSync(path.join(sb.stateDir, "credential.json"), JSON.stringify(cred("x")), { mode: 0o600 });
    assert.equal(s.readCredential(), null);
    assert.equal(s.info().credential_persisted, false);
  });

  test("persistCredential=true: 0600 file, survives reopen, never in state.json/snapshot, clear is idempotent", { skip: POSIX_ONLY }, (t) => {
    const sb = sandbox(t);
    const s1 = sb.open({ persistCredential: true });
    const c = cred(s1.snapshot().inbox.id);
    assert.deepEqual(s1.writeCredential(c), { ok: true });
    s1.commit((d) => { d.inbox.phase = "ready"; d.inbox.epoch = c.epoch; d.inbox.generation = c.generation; });
    const file = path.join(sb.stateDir, "credential.json");
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    assert.deepEqual(s1.readCredential(), c);
    assert.equal(s1.info().credential_persisted, true);
    assert.ok(!fs.readFileSync(statePath(sb.stateDir), "utf8").includes(c.bearer));
    assert.ok(!JSON.stringify(s1.snapshot()).includes(c.bearer));
    s1.close();
    const s2 = sb.open({ persistCredential: true });
    assert.deepEqual(s2.readCredential(), c);
    assert.deepEqual(s2.clearCredential(), { ok: true });
    assert.equal(exists(file), false);
    assert.equal(s2.readCredential(), null);
    assert.deepEqual(s2.clearCredential(), { ok: true });
  });

  // Simulated through the documented `platform` seam on a POSIX host; does NOT satisfy TV20.
  // R3 §5: a POSIX path under a fake win32 platform is not a coherent Windows filesystem (the real
  // win32 lexical check refuses it first) and there is no fs seam that makes it one, so this case is
  // NOTRUN everywhere; the native Windows case below carries the requirement.
  test("simulated win32 (seam): credential persistence refused before any file; ordinary state 'unverified'", { skip: "NOTRUN: fake win32 platform over a POSIX path is incoherent (R3 §5); see native Windows case" }, (t) => {
    const sb = sandbox(t);
    fs.mkdirSync(sb.stateDir, { mode: 0o700 });
    refusal(() => sb.open({ persistCredential: true }, { platform: "win32" }), "STORE_CREDENTIAL_PLATFORM_UNSUPPORTED");
    assert.deepEqual(regularFiles(sb.stateDir), [], "no lock, state or credential file");
    const s = sb.open({ persistCredential: false }, { platform: "win32" });
    assert.equal(s.info().permissions, "unverified");
    assert.equal(s.info().credential_persisted, false);
  });

  test("native Windows: credential persistence refused, ordinary state 'unverified', EEXIST → STORE_LOCKED", { skip: process.platform === "win32" ? false : "NOTRUN: needs a native Windows runner (TV20)" }, (t) => {
    const sb = sandbox(t);
    refusal(() => sb.open({ persistCredential: true }), "STORE_CREDENTIAL_PLATFORM_UNSUPPORTED");
    assert.deepEqual(regularFiles(sb.stateDir), []);
    const s = sb.open();
    assert.equal(s.info().permissions, "unverified");
    refusal(() => sb.open(), "STORE_LOCKED");
    assert.deepEqual(s.commit((d) => { d.counters.win = 1; }), { ok: true });
  });
});
