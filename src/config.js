/**
 * telesession config — typed, normalized values from the host. No network, no defaults that widen
 * trust: the operator supplies the telepty URL, token, targets and inbox prefix.
 */

import fs from "node:fs";
import net from "node:net";
import path from "node:path";

const SID_RE = /^[A-Za-z0-9._-]{1,128}$/;
const PREFIX_RE = /^[A-Za-z0-9._]{1,48}$/;
// Checked on the RAW string before any parsing, so nothing (userinfo, path, query, fragment) is
// ever stripped into acceptance.
const RAW_URL_RE = /^http:\/\/(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[::1\]):([1-9]\d{0,4})\/?$/;
const TOKEN_RE = /^[\x21-\x7E]{1,4096}$/;
const TOKEN_FILE_MAX = 64 * 1024;
const MAX_TARGETS = 8;
const STATE_DIR_MAX = 512;
const RELAY_INTERVAL_MIN_MS = 1000;
const RELAY_INTERVAL_MAX_MS = 3600000;
// Issue #16 profile mode (Telepty `client-profile-scope-v1`, received contract564 §4 + review569 F10).
// Name rule = the server's profile rule, so a client name can always be matched by the server's `caller`.
const PROFILE_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const PROFILES_SCHEMA = "telesession.profiles/v1";
const PRIVATE_FILE_MAX = 64 * 1024;
// Profile credential: `tpc1.<generation>.<43 base64url>`; only the bare token is accepted.
export const PROFILE_TOKEN_RE = /^tpc1\.(0|[1-9]\d{0,15})\.[A-Za-z0-9_-]{43}$/;
const PROFILE_REQUIRED_KEYS = Object.freeze(["inbox_prefix", "state_dir", "targets", "token_file"]);
const PROFILE_OPTIONAL_KEYS = Object.freeze(["persist_inbox_credential"]);
// Legacy credential/target/prefix/state/persist/URL keys: in profile mode the profiles file is their only
// source (no mixing, no fallback). TELESESSION_RELAY_INTERVAL_MS carries no credential and stays allowed.
const PROFILE_EXCLUSIVE_ENV = Object.freeze([
  "TELESESSION_TARGETS", "TELESESSION_INBOX_PREFIX", "TELESESSION_TELEPTY_TOKEN", "TELESESSION_TELEPTY_TOKEN_FILE", "TELESESSION_STATE_DIR",
  "TELESESSION_PERSIST_INBOX_CREDENTIAL", "TELESESSION_TELEPTY_URL",
]);

export class ConfigError extends Error {
  constructor(code) {
    super(code);
    this.name = "ConfigError";
    this.code = code;
  }
}

function normalizeUrl(raw) {
  const m = typeof raw === "string" ? RAW_URL_RE.exec(raw) : null;
  if (!m) throw new ConfigError("CONFIG_URL_INVALID");
  const [, host, port] = m;
  if (host !== "[::1]" && !net.isIPv4(host)) throw new ConfigError("CONFIG_URL_INVALID");
  if (Number(port) > 65535) throw new ConfigError("CONFIG_URL_INVALID");
  let url;
  try { url = new URL(raw); } catch { throw new ConfigError("CONFIG_URL_INVALID"); }
  if (url.hostname !== host || url.port !== port || url.pathname !== "/") throw new ConfigError("CONFIG_URL_INVALID");
  return url.origin;
}

// Lexical only (no fs): the store re-checks the real path. Refused, never repaired.
function normalizeStateDir(raw) {
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== "string" || raw.length < 1 || raw.length > STATE_DIR_MAX || /[\u0000-\u001f\u007f]/.test(raw)
      || !path.isAbsolute(raw) || path.normalize(raw) !== raw || (raw.endsWith(path.sep) || raw.endsWith("/"))) {
    throw new ConfigError("CONFIG_STATE_DIR_INVALID");
  }
  if (process.platform === "win32" && (raw.startsWith("\\\\") || raw.startsWith("//") || /^[A-Za-z]:(?![\\/])/.test(raw))) {
    throw new ConfigError("CONFIG_STATE_DIR_INVALID");
  }
  return raw;
}

// Pure: typed inputs in, frozen normalized config out (or ConfigError). The token is a
// non-enumerable property so it never appears in JSON.stringify / Object.keys of the config.
// stateDir/persistInboxCredential are enumerable only when a state dir is set, so the memory-only
// config keeps exactly the 0.1.0 shape. relayIntervalMs (0 = relay runner off, the default) is
// enumerable only when enabled; enabling it needs a state dir (the ledger lives there).
// profile (issue #16): the host-selected assistant profile name, or null (legacy); enumerable only when
// set, and a profile always needs its own state dir (own store and lock).
export function normalizeConfig({ teleptyUrl, token, targets, inboxPrefix, stateDir, persistInboxCredential, relayIntervalMs, profile } = {}) {
  if (!Array.isArray(targets)) throw new ConfigError("CONFIG_TARGETS_INVALID");
  const unique = [...new Set(targets)];
  if (unique.length < 1 || unique.length > MAX_TARGETS || unique.length !== targets.length
      || !unique.every((t) => typeof t === "string" && SID_RE.test(t) && !/^\.+$/.test(t))) {
    throw new ConfigError("CONFIG_TARGETS_INVALID");
  }
  if (typeof inboxPrefix !== "string" || !PREFIX_RE.test(inboxPrefix)) throw new ConfigError("CONFIG_INBOX_PREFIX_INVALID");
  const teleptyOrigin = normalizeUrl(teleptyUrl);
  if (typeof token !== "string" || !TOKEN_RE.test(token)) throw new ConfigError("CONFIG_TOKEN_INVALID");
  const dir = normalizeStateDir(stateDir);
  if (persistInboxCredential !== undefined && typeof persistInboxCredential !== "boolean") throw new ConfigError("CONFIG_PERSIST_INVALID");
  const persist = persistInboxCredential === true;
  if (persist && dir === null) throw new ConfigError("CONFIG_STATE_DIR_REQUIRED");
  const relay = relayIntervalMs === undefined || relayIntervalMs === null ? 0 : relayIntervalMs;
  if (!(relay === 0 || (Number.isSafeInteger(relay) && relay >= RELAY_INTERVAL_MIN_MS && relay <= RELAY_INTERVAL_MAX_MS))) {
    throw new ConfigError("CONFIG_RELAY_INTERVAL_INVALID");
  }
  if (relay > 0 && dir === null) throw new ConfigError("CONFIG_STATE_DIR_REQUIRED");
  const prof = profile === undefined || profile === null ? null : profile;
  if (prof !== null && (typeof prof !== "string" || !PROFILE_NAME_RE.test(prof))) throw new ConfigError("CONFIG_PROFILE_INVALID");
  if (prof !== null && dir === null) throw new ConfigError("CONFIG_STATE_DIR_REQUIRED");
  if (prof !== null && !PROFILE_TOKEN_RE.test(token)) throw new ConfigError("CONFIG_PROFILE_TOKEN_INVALID");
  const cfg = { targets: Object.freeze(unique), inboxPrefix, teleptyOrigin };
  Object.defineProperty(cfg, "stateDir", { value: dir, enumerable: dir !== null });
  Object.defineProperty(cfg, "persistInboxCredential", { value: persist, enumerable: dir !== null });
  Object.defineProperty(cfg, "relayIntervalMs", { value: relay, enumerable: relay > 0 });
  Object.defineProperty(cfg, "profile", { value: prof, enumerable: prof !== null });
  Object.defineProperty(cfg, "token", { value: token, enumerable: false });
  return Object.freeze(cfg);
}

// Reads ONLY the operator-named file. A telepty config.json ({"authToken": "..."}) or a bare token.
function defaultReadTokenFile(filePath) {
  if (!path.isAbsolute(filePath)) throw new ConfigError("CONFIG_TOKEN_FILE_INVALID");
  let text;
  try {
    const st = fs.statSync(filePath);
    if (!st.isFile() || st.size > TOKEN_FILE_MAX) throw new ConfigError("CONFIG_TOKEN_FILE_INVALID");
    text = fs.readFileSync(filePath, "utf8");
  } catch (err) {
    if (err instanceof ConfigError) throw err;
    throw new ConfigError("CONFIG_TOKEN_FILE_INVALID");
  }
  if (text.length > TOKEN_FILE_MAX) throw new ConfigError("CONFIG_TOKEN_FILE_INVALID");
  return text;
}

function tokenFromFileText(text) {
  const trimmed = String(text).trim();
  if (!trimmed.startsWith("{")) return trimmed;
  let parsed;
  try { parsed = JSON.parse(trimmed); } catch { throw new ConfigError("CONFIG_TOKEN_INVALID"); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)
      || !Object.prototype.hasOwnProperty.call(parsed, "authToken") || typeof parsed.authToken !== "string") {
    throw new ConfigError("CONFIG_TOKEN_INVALID");
  }
  return parsed.authToken;
}

// ── Assistant profiles (issue #16) ──
// One operator-private JSON file, selected once at construction by TELESESSION_PROFILE (never a tool
// argument). Everything here runs before any token read, store, HTTP request, child or inbox. Other profiles'
// token files are stat'ed for alias checks, never read. Selection by env is configuration, not
// authentication: the credential boundary is the daemon's (`client-profile-scope-v1`), verified by the transport.

const envSet = (e, k) => typeof e[k] === "string" && e[k] !== "";
const isPlain = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

// Private regular file: lstat → open(O_RDONLY|O_NOFOLLOW) → fstat with equal dev/ino, regular, nlink 1,
// owned by the effective uid, no group/other bits, ≤ 64 KiB. POSIX only (profile mode refuses win32).
function defaultReadPrivateFile(filePath, code) {
  const C = fs.constants;
  let fd = null;
  try {
    const lst = fs.lstatSync(filePath);
    if (!lst.isFile()) throw new ConfigError(code);
    fd = fs.openSync(filePath, C.O_RDONLY | (typeof C.O_NOFOLLOW === "number" ? C.O_NOFOLLOW : 0));
    const st = fs.fstatSync(fd);
    const euid = typeof process.geteuid === "function" ? process.geteuid() : null;
    if (!st.isFile() || st.dev !== lst.dev || st.ino !== lst.ino || st.nlink !== 1 || euid === null || st.uid !== euid
        || (st.mode & 0o077) !== 0 || st.size > PRIVATE_FILE_MAX) {
      throw new ConfigError(code);
    }
    const buf = Buffer.alloc(PRIVATE_FILE_MAX + 1);
    let n = 0;
    for (;;) {
      const r = fs.readSync(fd, buf, n, buf.length - n, null);
      if (r === 0) break;
      n += r;
      if (n > PRIVATE_FILE_MAX) throw new ConfigError(code);
    }
    return buf.subarray(0, n).toString("utf8");
  } catch (err) {
    if (err instanceof ConfigError) throw err;
    throw new ConfigError(code);
  } finally {
    if (fd !== null) { try { fs.closeSync(fd); } catch { /* already closed */ } }
  }
}

// Absolute + normalized path, then the private-file reader; any non-ConfigError becomes `code`.
function readPrivate(readPrivateFile, filePath, code) {
  if (typeof filePath !== "string" || !path.isAbsolute(filePath) || path.normalize(filePath) !== filePath) throw new ConfigError(code);
  try { return readPrivateFile(filePath, code); } catch (err) {
    if (err instanceof ConfigError) throw err;
    throw new ConfigError(code);
  }
}

function parseProfiles(text) {
  let doc;
  try { doc = JSON.parse(text); } catch { throw new ConfigError("CONFIG_PROFILES_INVALID"); }
  if (!isPlain(doc) || Object.keys(doc).sort().join(",") !== "profiles,schema,telepty_url" || doc.schema !== PROFILES_SCHEMA
      || !isPlain(doc.profiles) || Object.keys(doc.profiles).length < 1) {
    throw new ConfigError("CONFIG_PROFILES_INVALID");
  }
  const out = new Map();
  for (const [name, p] of Object.entries(doc.profiles)) {
    const keys = isPlain(p) ? Object.keys(p) : null;
    if (!PROFILE_NAME_RE.test(name) || keys === null || !PROFILE_REQUIRED_KEYS.every((k) => keys.includes(k))
        || !keys.every((k) => PROFILE_REQUIRED_KEYS.includes(k) || PROFILE_OPTIONAL_KEYS.includes(k))
        || (p.persist_inbox_credential !== undefined && typeof p.persist_inbox_credential !== "boolean")) {
      throw new ConfigError("CONFIG_PROFILES_INVALID");
    }
    try {
      normalizeConfig({ teleptyUrl: "http://127.0.0.1:1", token: "x", targets: p.targets, inboxPrefix: p.inbox_prefix });
      if (normalizeStateDir(p.state_dir) === null || normalizeStateDir(p.token_file) === null) throw new ConfigError("CONFIG_PROFILES_INVALID");
    } catch {
      throw new ConfigError("CONFIG_PROFILES_INVALID");
    }
    out.set(name, {
      name, inboxPrefix: p.inbox_prefix, targets: [...p.targets], tokenFile: p.token_file, stateDir: p.state_dir,
      persistInboxCredential: p.persist_inbox_credential === true,
    });
  }
  return { teleptyUrl: normalizeUrl(doc.telepty_url), profiles: out };
}

const realpathOf = (p) => (typeof fs.realpathSync.native === "function" ? fs.realpathSync.native(p) : fs.realpathSync(p));

// realpath of the nearest existing ancestor + the not-yet-existing rest; dev:ino when the path exists.
function locate(p) {
  let head = p;
  const rest = [];
  for (;;) {
    try {
      const real = path.join(realpathOf(head), ...rest);
      let id = null;
      if (rest.length === 0) { try { const st = fs.statSync(p); id = `${st.dev}:${st.ino}`; } catch { id = null; } }
      return { real, id };
    } catch {
      const up = path.dirname(head);
      if (up === head) return { real: p, id: null };
      rest.unshift(path.basename(head));
      head = up;
    }
  }
}

const within = (child, parent) => {
  const rel = path.relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
};

// Over EVERY profile in the file: prefixes unique case-insensitively; state dirs pairwise distinct and not
// nested (lexical, realpath, dev:ino; case-insensitive on darwin/win32); token files not aliased to each other
// or placed inside any state dir. Observable aliases only: same-uid files stay readable by that user.
function checkProfileAliases(profiles, platform) {
  const fold = (p) => (platform === "win32" || platform === "darwin" ? p.toLowerCase() : p);
  const list = [...profiles.values()];
  const prefixes = new Set();
  for (const p of list) {
    const k = p.inboxPrefix.toLowerCase();
    if (prefixes.has(k)) throw new ConfigError("CONFIG_PROFILE_CONFLICT");
    prefixes.add(k);
  }
  const tok = list.map((p) => { const l = locate(p.tokenFile); return { lex: fold(p.tokenFile), real: fold(l.real), id: l.id }; });
  const st = list.map((p) => { const l = locate(p.stateDir); return { lex: fold(p.stateDir), real: fold(l.real), id: l.id }; });
  for (let i = 0; i < list.length; i += 1) {
    for (const d of st) {
      if (within(tok[i].lex, d.lex) || within(tok[i].real, d.real)) throw new ConfigError("CONFIG_PROFILE_CREDENTIAL_ALIAS");
    }
    for (let j = i + 1; j < list.length; j += 1) {
      const a = tok[i];
      const b = tok[j];
      if (a.lex === b.lex || a.real === b.real || (a.id !== null && a.id === b.id)) throw new ConfigError("CONFIG_PROFILE_CREDENTIAL_ALIAS");
      const x = st[i];
      const y = st[j];
      if (within(x.lex, y.lex) || within(y.lex, x.lex) || within(x.real, y.real) || within(y.real, x.real)
          || (x.id !== null && x.id === y.id)) {
        throw new ConfigError("CONFIG_PROFILE_STATE_ALIAS");
      }
    }
  }
}

/**
 * Profile selection from env without reading any token: null in legacy mode, else the validated selected
 * profile {name, inboxPrefix, targets, tokenFile, stateDir, persistInboxCredential, teleptyUrl}. Targets are
 * intersected with a non-empty AIGENTRY_ORCHESTRATOR_SIDS (never widened). Exported for the tunnel child.
 */
export function resolveProfile(env, { readPrivateFile = defaultReadPrivateFile, platform = process.platform } = {}) {
  const e = env || {};
  const hasName = envSet(e, "TELESESSION_PROFILE");
  const hasFile = envSet(e, "TELESESSION_PROFILES_FILE");
  if (!hasName && !hasFile) return null;
  if (!hasFile) throw new ConfigError("CONFIG_PROFILES_FILE_MISSING");
  if (!hasName) throw new ConfigError("CONFIG_PROFILE_MISSING");
  if (platform === "win32") throw new ConfigError("CONFIG_PROFILE_PLATFORM_UNSUPPORTED");
  if (!PROFILE_NAME_RE.test(e.TELESESSION_PROFILE)) throw new ConfigError("CONFIG_PROFILE_INVALID");
  if (PROFILE_EXCLUSIVE_ENV.some((k) => envSet(e, k))) throw new ConfigError("CONFIG_PROFILE_CONFLICT");
  const { teleptyUrl, profiles } = parseProfiles(readPrivate(readPrivateFile, e.TELESESSION_PROFILES_FILE, "CONFIG_PROFILES_FILE_INVALID"));
  const selected = profiles.get(e.TELESESSION_PROFILE);
  if (!selected) throw new ConfigError("CONFIG_PROFILE_UNKNOWN");
  checkProfileAliases(profiles, platform);
  let targets = selected.targets;
  if (envSet(e, "AIGENTRY_ORCHESTRATOR_SIDS")) {
    const allowed = new Set(e.AIGENTRY_ORCHESTRATOR_SIDS.split(/[\s,]+/).filter(Boolean));
    targets = targets.filter((t) => allowed.has(t));
  }
  return Object.freeze({ ...selected, teleptyUrl, targets: Object.freeze(targets) });
}

// TELESESSION_* env only. Exactly one token source; nothing is looked up implicitly.
export function loadConfig(env, { readTokenFile = defaultReadTokenFile, readPrivateFile = defaultReadPrivateFile, platform = process.platform } = {}) {
  const e = env || {};
  const profile = resolveProfile(e, { readPrivateFile, platform });
  if (profile !== null) return loadProfileConfig(e, profile, readPrivateFile);
  const targets = String(e.TELESESSION_TARGETS || "").split(/[\s,]+/).filter(Boolean);
  const inboxPrefix = String(e.TELESESSION_INBOX_PREFIX || "");
  const teleptyUrl = String(e.TELESESSION_TELEPTY_URL || "");
  // Validate targets/prefix/URL before touching any token source.
  normalizeConfig({ teleptyUrl, token: "x", targets, inboxPrefix });
  const hasToken = typeof e.TELESESSION_TELEPTY_TOKEN === "string" && e.TELESESSION_TELEPTY_TOKEN !== "";
  const hasFile = typeof e.TELESESSION_TELEPTY_TOKEN_FILE === "string" && e.TELESESSION_TELEPTY_TOKEN_FILE !== "";
  if (hasToken && hasFile) throw new ConfigError("CONFIG_TOKEN_SOURCE_CONFLICT");
  if (!hasToken && !hasFile) throw new ConfigError("CONFIG_TOKEN_MISSING");
  const token = hasToken ? e.TELESESSION_TELEPTY_TOKEN : tokenFromFileText(readTokenFile(e.TELESESSION_TELEPTY_TOKEN_FILE));
  const stateDir = typeof e.TELESESSION_STATE_DIR === "string" && e.TELESESSION_STATE_DIR !== "" ? e.TELESESSION_STATE_DIR : null;
  // An invalid value is passed through as-is so normalizeConfig refuses it at its place in the check order.
  const rawPersist = e.TELESESSION_PERSIST_INBOX_CREDENTIAL;
  const persistInboxCredential = rawPersist === undefined || rawPersist === "" || rawPersist === "0" ? false
    : rawPersist === "1" ? true : String(rawPersist);
  const rawRelay = e.TELESESSION_RELAY_INTERVAL_MS;
  const relayIntervalMs = rawRelay === undefined || rawRelay === "" ? 0 : /^\d{1,7}$/.test(String(rawRelay)) ? Number(rawRelay) : String(rawRelay);
  return normalizeConfig({ teleptyUrl, token, targets, inboxPrefix, stateDir, persistInboxCredential, relayIntervalMs });
}

function relayOption(e) {
  // An invalid value is passed through as-is so normalizeConfig refuses it at its place in the check order.
  const rawRelay = e.TELESESSION_RELAY_INTERVAL_MS;
  return rawRelay === undefined || rawRelay === "" ? 0 : /^\d{1,7}$/.test(String(rawRelay)) ? Number(rawRelay) : String(rawRelay);
}

// Profile mode: URL/prefix/targets/state/persistence/credential come from the profiles file only; the relay
// interval stays host env. Only the selected profile's token file is read, after every other check.
function loadProfileConfig(e, profile, readPrivateFile) {
  const base = { teleptyUrl: profile.teleptyUrl, targets: [...profile.targets], inboxPrefix: profile.inboxPrefix, stateDir: profile.stateDir };
  normalizeConfig({ ...base, token: "x" });
  const text = readPrivate(readPrivateFile, profile.tokenFile, "CONFIG_TOKEN_FILE_INVALID");
  const token = text.endsWith("\n") ? text.slice(0, -1) : text;
  if (!PROFILE_TOKEN_RE.test(token)) throw new ConfigError("CONFIG_PROFILE_TOKEN_INVALID");
  return normalizeConfig({
    ...base, token, profile: profile.name, persistInboxCredential: profile.persistInboxCredential, relayIntervalMs: relayOption(e),
  });
}
