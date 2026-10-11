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
// config keeps exactly the 0.1.0 shape.
export function normalizeConfig({ teleptyUrl, token, targets, inboxPrefix, stateDir, persistInboxCredential } = {}) {
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
  const cfg = { targets: Object.freeze(unique), inboxPrefix, teleptyOrigin };
  Object.defineProperty(cfg, "stateDir", { value: dir, enumerable: dir !== null });
  Object.defineProperty(cfg, "persistInboxCredential", { value: persist, enumerable: dir !== null });
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

// TELESESSION_* env only. Exactly one token source; nothing is looked up implicitly.
export function loadConfig(env, { readTokenFile = defaultReadTokenFile } = {}) {
  const e = env || {};
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
  return normalizeConfig({ teleptyUrl, token, targets, inboxPrefix, stateDir, persistInboxCredential });
}
