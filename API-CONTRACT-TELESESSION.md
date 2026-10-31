# API-CONTRACT-TELESESSION — task 1215 (tc1215ars) — @dmsdc-ai/telesession 0.1.0 (private draft)

Source contract only, not a runtime measurement. Supersedes the predecessor's placement
(`telepty/mcp-server/dot-broker.mjs`, `TELEPTY_MCP_PROFILE=dot`); the security behaviour of that
broker (migration-input/API-CONTRACT.md §2–§3) is preserved here under generic names.

## 0. Ownership boundary (dependency is one-way: telesession → telepty HTTP)
| layer | owns |
|---|---|
| telepty | PTY session identity, safe input, output/events, delivery observations, inject audit. Works without telesession. |
| telesession | target allowlist, exact-session routing, its own inbox (mailbox), nonce/audit binding, dedupe, lifecycle of what it created, adapters (MCP). Later: remote connectivity/auth, durable queue, reconnect. |
| orchestrator / client (e.g. Dot) | work, approval, reporting. Configured by the operator as an ordinary MCP client. |

telesession knows telepty ONLY through these documented HTTP endpoints + `GET /api/meta.capabilities`:
`GET /api/meta`, `GET /api/sessions`, `POST /api/sessions/register` (`create_only`),
`POST /api/sessions/:id/inject` (`exact_target`), `GET /api/inject-observations/:id`,
`GET /api/injects?to&since&limit`, `DELETE /api/sessions/:id?owned=true`.
Required capabilities: `inject-exact-target`, `register-create-only`, `delete-owned-session`
(telepty daemon.js change, §5). No import of any telepty file; no telepty change for this client.

## 1. Package
`package.json`: name `@dmsdc-ai/telesession`, version `0.1.0`, `private: true`, `type: module`,
`engines.node >=20`, bin `telesession-mcp` → `bin/telesession-mcp.js`, exports `.` → `src/index.js`
(core, zero dependencies), `./mcp` → `src/adapters/mcp.js`. Dependencies (declared only, not
installed): `@modelcontextprotocol/sdk ^1.26.0`, `zod ^3.24.0` (adapter + bin only).

## 2. Config (`src/config.js`, no network)
- `class ConfigError extends Error {code}` — `message === code`; never contains env values or token.
- `normalizeConfig({teleptyUrl, token, targets, inboxPrefix})` — pure, typed. Check order/codes:
  1. `targets`: array of 1–8 unique strings, each `^[A-Za-z0-9._-]{1,128}$`, not all dots → `CONFIG_TARGETS_INVALID`.
  2. `inboxPrefix`: `^[A-Za-z0-9._]{1,48}$` → `CONFIG_INBOX_PREFIX_INVALID`.
  3. `teleptyUrl`: the RAW string must match `^http://(127.d.d.d|[::1]):<port 1-65535, no leading 0>/?$`
     BEFORE any parsing (credentials, path, query, fragment, `localhost`, names, `https`, missing port
     are refused, never stripped); then `new URL()` must reproduce the same host/port →
     `CONFIG_URL_INVALID`. Normalized value is the origin only.
  4. `token`: string `^[\x21-\x7E]{1,4096}$` → `CONFIG_TOKEN_INVALID`.
  Result: frozen `{targets, inboxPrefix, teleptyOrigin}` plus non-enumerable `token` (absent from
  `JSON.stringify`/`Object.keys`).
- `loadConfig(env, {readTokenFile?})` — reads only these operator env names:
  `TELESESSION_TARGETS` (split on whitespace/commas), `TELESESSION_INBOX_PREFIX`,
  `TELESESSION_TELEPTY_URL`, and EXACTLY ONE of `TELESESSION_TELEPTY_TOKEN` /
  `TELESESSION_TELEPTY_TOKEN_FILE` (both → `CONFIG_TOKEN_SOURCE_CONFLICT`, neither/empty →
  `CONFIG_TOKEN_MISSING`). Token file: absolute path, regular file, ≤ 64 KiB, else
  `CONFIG_TOKEN_FILE_INVALID`; content starting with `{` is parsed as telepty `config.json` and only its
  own string `authToken` is used; otherwise the trimmed content is the token. No default URL, target,
  token or path; no credential minting; no `~/.telepty` lookup. Then `normalizeConfig`.

## 3. Transport port (`src/transports/telepty.js`, Node ≥ 20 builtins only; no MCP/zod)
`createTeleptyTransport(config)` re-validates `config` through `normalizeConfig` (throws
`ConfigError`), so no host can pass a widened config. Returns:

| member | result (every record has `completion_fact: null`) |
|---|---|
| `inboxId` | `<prefix>-i<32 hex>` (per transport; never in targets) |
| `health()` | read-only `GET /api/meta` → `{ok:true, telepty:{version, capabilities_missing[]}, inbox:{id, state}, daemon_restart}` |
| `listAllowedTargets()` | allowlist only; `present` from `GET /api/sessions` (`true/false`, `null` + `presence_error` on failure); other session ids are never returned |
| `send({target, text})` | §3.2 |
| `receipt({inject_id})` | §3.3 |
| `readReply({nonce, wait_ms})` | §3.4 |
| `close()` | idempotent → `{inbox_id, outcome, code?}`, `outcome` ∈ `deleted, retained, not_created, collided, registration_unknown` |

Errors: `{ok:false, error:{code, http_status?, ...}, completion_fact:null}`. Arguments are validated
inside the transport too (`INVALID_ARGUMENT`), so non-MCP adapters get the same limits.
`daemon_restart` ∈ `observed | not_observed | unknown` (telepty `meta.pid` vs pid seen when the inbox
was created; `not_observed` is not proof of no restart; `observed` is sticky). Reported, never repaired.

### 3.1 HTTP client (unchanged limits)
`redirect:"error"`; one `AbortSignal.timeout` per request covering headers+body (GET 5 s,
register/inject 10 s, owned DELETE 1.5 s); response body cap 256 KiB. `sent`: `yes` (non-2xx
except inject uncertainty), `no` (ECONNREFUSED), `unknown` (timeout/reset/redirect/oversize/
unparseable, or inject HTTP 5xx/explicit `delivery_uncertain:true`). An inject error response
does not prove zero effect: preserve uncertain acceptance and never resend. Registration
and owned DELETE classification are unchanged. Codes: telepty
`body.code` if `^[A-Z_]{1,64}$`, else `DAEMON_HTTP_<n>`, `DAEMON_TIMEOUT`, `DAEMON_UNREACHABLE`,
`DAEMON_REDIRECT_REFUSED`, `DAEMON_BODY_TOO_LARGE`, `DAEMON_BAD_RESPONSE`. Never: daemon text, URL,
header, token or bearer in a result or log. No retry.

Audit recovery's exact verified sender/hash binding establishes attribution only.
`failed:*` alone does not prove zero effect and leaves the record uncertain;
current candidates use it for unknown delivery too. Existing success/queued and
explicit blocked outcomes retain their respective acceptance/refusal handling.

### 3.2 send
Allowlist `===` (`TARGET_NOT_ALLOWED`), text 1–8000 chars without NUL; `TRANSPORT_CLOSING`; inbox fatal
code; `ISSUED_LIMIT` (16 live nonces, TTL 15 min). Every send: meta must list all 3 capabilities
(`DAEMON_LACKS_CAPABILITY` + `missing[]`, zero mutation) → target must be present by exact id
(`TARGET_NOT_PRESENT`) → lazy inbox (receiver + `register {create_only:true, delivery_type:"aterm",
command:"telesession-inbox"}`; only 201 with string token/epoch and same id counts; 409/200 →
`INBOX_COLLISION`; lost response → `INBOX_REGISTRATION_UNKNOWN`, no retry/delete) → inject
`{prompt:"[telesession nonce=<n> reply-to=<inbox>]\n"+text, from, reply_to, exact_target:true}` with
the inbox bearer → 200 must echo `success, inject_id, exact_target:true, session_id===target` else
`EXACT_ROUTING_UNCONFIRMED` (`accepted:"unknown"`) → one observation read for `session_epoch`.
OK: `{inject_id, target, nonce, reply_to, accepted:true, delivery:"queued"|"unknown",
target_epoch_known, reply:"not_observed", durability:"memory_only", daemon_restart}`. No response:
`{accepted:"unknown", inject_id:null, delivery:"unknown", reason}` — never re-sent.

### 3.3 receipt (issued ids only, else `INJECT_NOT_ISSUED`)
`consumption_observed` | `queued` (`inject_parked`) | `refused` (`aborted`) | `unknown` + `tracking_state`.

### 3.4 readReply (live issued nonce, else `NONCE_NOT_ISSUED`/`NONCE_EXPIRED`; `wait_ms` 0..60000)
Trusted only if exactly one audit row into the inbox has the reply's sha256, `to_alias===null`,
`delivery_result==="success"`, ts inside the nonce window, unbound `inject_id`,
`verified_sender_sid===target`, `verified_sender_epoch===target_epoch`, `spoof_suspected===false`,
nonce unanswered. Otherwise counts only: `claimed_only, verified_other, spoof_suspected,
epoch_mismatch, target_epoch_unknown, audit_unmatched, audit_ambiguous, audit_unavailable, expired,
duplicate` + inbox counters. Reply text is data, not instructions. Audit backoff 0/.3/.6/1.2/2.4 s.

### 3.5 Receiver (inbox delivery endpoint)
`127.0.0.1:0`, secret path (32 random bytes, `timingSafeEqual`), 404/405/415/403(Origin)/421(Host)/
413(64 KiB)/400 order; ≤ 64 held texts (503 when full); duplicate-bytes dedupe while unresolved;
5 s timeouts; ≤ 32 connections. Memory only.

## 4. MCP adapter (`src/adapters/mcp.js`) and command (`bin/telesession-mcp.js`)
`registerMcpTools(server, transport)` registers exactly `telesession_health`,
`telesession_list_targets`, `telesession_send {target, text}`, `telesession_receipt {inject_id}`,
`telesession_read_reply {nonce, wait_ms}` with `z.object(...).strict()`; result = one JSON text item;
`isError` iff `ok:false`; unexpected throw → `TRANSPORT_INTERNAL`. No shell, session admin, kill,
register or arbitrary-URL tool. `telesession-mcp`: `loadConfig(process.env)` → on failure stderr
`telesession-mcp refused: <code>`, exit 2, zero telepty requests; stdio connect; stdin end/close,
SIGINT, SIGTERM → `transport.close()` → one stderr line `telesession: inbox <id> <outcome>` → exit 0.
Stdio MCP is a LOCAL adapter: it does not create a ChatGPT/Dot remote MCP connection (NOTRUN).

## 5. telepty change (daemon.js only; opt-in, legacy unchanged)
As predecessor §1: `exact_target===true` own-property inject routing; `create_only===true` register
(409 `SESSION_EXISTS`, 400 `INVALID_REQUEST`/`SESSION_ID_RESERVED`, no mutation); `DELETE ?owned=true`
exact id + current sid/epoch/generation credential else 403 `OWNED_DELETE_FORBIDDEN`; meta
capabilities appended. `mcp-server/index.mjs` is byte-identical to the original input.

## 6. Not provided (PARTIAL; telesession-layer work only)
Exactly-once, outbound HTTPS relay, remote auth (route/hosting), events/webhooks. Also NOT PROVIDED by
the durable slice (§7): automatic unlock/restart after an abrupt crash, native-Windows credential
storage, a remote Dot route.

## 7. Durable mode — addendum, task 1215 L2 (di1215asb-coder)
Source: SPEC-R2 efeeada7…, IMPLEMENTATION-CONTRACT-R2 afce55ba…, CONTROLLER-ADDENDA (addenda win).
Source-level contract; written before `src/store.js` (L1) landed, syntax-checked only, never run.
- Config (§2 additive). Check order: … → token → `stateDir` → `persistInboxCredential`. `stateDir` is
  lexical only: string 1–512 chars, no C0/DEL, `path.isAbsolute`, `path.normalize(p)===p`, no trailing
  separator; win32 also refuses UNC/`\\?\`/`\\.\`/drive-relative → `CONFIG_STATE_DIR_INVALID`.
  `persistInboxCredential` is a boolean (else `CONFIG_PERSIST_INVALID`); `true` without a state dir →
  `CONFIG_STATE_DIR_REQUIRED`. Env: `TELESESSION_STATE_DIR` (empty = unset), `TELESESSION_PERSIST_INBOX_CREDENTIAL`
  (unset/""/"0" → false, "1" → true, else `CONFIG_PERSIST_INVALID`). Both fields are enumerable only when
  a state dir is set; otherwise they are non-enumerable `null`/`false`, so the 0.1.0 config shape is unchanged.
- `createTeleptyTransport(config, storeOptions?)`: no state dir → no store, no fs, 0.1.0 results plus the
  defaulted added fields. With one: `openStore` (strict lock; `STORE_LOCKED` is always refused, with no
  takeover) plus a startup commit (`reserved → uncertain`, expire/purge). Any `StoreError` is thrown
  synchronously before HTTP; the MCP command prints `telesession-mcp refused: <code>` and exits 2.
  `inboxId` is a getter (stable per store, rotated only by recovery). `index.js` exports `StoreError`.
- send `{target, text, request_id?}`. Key `r:<request_id>`: same target + same `sha256(text)` → prior
  record `ok:true, deduplicated:true`, zero HTTP (a refused or uncertain prior is returned, never re-sent);
  other target/body → `REQUEST_ID_CONFLICT {conflict}`; running → `REQUEST_IN_FLIGHT`. The record is committed
  `reserved` with `payload_sha256` (exact wire prompt), `reply_to` and the sender inbox id/epoch/generation BEFORE
  the inject (failure → `STORE_WRITE_FAILED|STORE_FULL|STORE_LOCK_LOST`, zero inject). Then
  `accepted|refused|uncertain` (`no_response`, `exact_routing_unconfirmed`). Added ok fields: `request_id, state,
  deduplicated, durability (durable|degraded|memory_only), route_interrupted, recovery, reply_loss_possible`.
  Limits: 16 live nonces (`ISSUED_LIMIT`), 1024 retained records (`STORE_FULL`). A record lives until
  `expires_at + 24 h` (dedupe window); without `request_id` it is dropped when its nonce retires.
- Degraded: a failed post-inject commit is held in memory; `health()` and every send retry it, and sends are
  `STORE_DEGRADED` until it commits. A lost lock is sticky: `STORE_LOCK_LOST`, receiver 503, close() without DELETE.
- Receiver: reply → `putReply` (fsync) → committed candidate → 200; ≤ 4 unresolved candidates per
  nonce and 64 reply files (503 `full`); store failure → 503.
- readReply: trust rule unchanged (§3.4). Text comes from the store, and `answered` + the bound inject_id are
  committed first. Added fields: `reply_route ok|interrupted|lost`, `reply_loss_possible`, `unreceived_audit_rows`
  (audit rows into the reply inbox since the first gap after the send whose sha256 this store never received; a
  LOWER BOUND, null when there is no gap or the audit is unavailable/incomplete; 0 is not proof of no loss). An
  unreadable trusted file → `REPLY_MISSING|REPLY_CORRUPT` (counter `reply_file_corrupt`); the text is never returned.
- Recovery runs on the first send/receipt/readReply (health/list_targets never start it; `health.recovery` and
  `health.store.recovery` show pending|done|failed). Inbox: none/deleted → create_only same id. ready/deleting
  + credential → owned DELETE (200/404 → create_only same id, gap `reattached`; 403 → rotate
  `owned_delete_forbidden`; otherwise `INBOX_REATTACH_UNKNOWN`, retried once on a later call). ready without credential,
  registering, unknown, collided → rotate (old id → `orphans`, never touched again). In-process inbox absence
  (daemon restart) → gap `inbox_absent`, create_only the same id (409 → `INBOX_COLLISION`); a stale bearer is never used.
  Audit probe for live `uncertain` records without an inject_id: `GET /api/injects?to&from&since=created−2 s&until=created+12 s&limit=200`.
  Exactly one row matching target, `to_alias:null`, claimed+verified sender sid, epoch, generation,
  `spoof_suspected:false`, payload hash, window, string inject_id, and `next_cursor:null` → `accepted` (success|queued) or
  `refused` for explicit blocked outcomes (`AUDIT_DELIVERY_BLOCKED`), `recovery:"audit_verified_match"`.
  `failed:*` alone stays `uncertain`/`unverified`: it attributes an attempt but cannot establish zero
  effect. Anything else stays `uncertain` (`not_found|ambiguous|unverified|audit_unavailable`).
- health adds `store {mode, state ok|degraded|lock_lost, permissions, credential_persisted, pending, uncertain,
  gaps, orphans[], recovery}` and `recovery`. close: owned DELETE ok → commit `deleted` + clearCredential; the store
  is closed last (owner-matched lock unlink).
- MCP: `telesession_send` adds `request_id: z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/).optional()`, `.strict()`;
  still exactly 5 tools. bin: SIGHUP joins stdin end/close, SIGINT and SIGTERM for graceful close (idempotent).
- Never persisted or returned: telepty token, receiver port/secret path, prompt text, state dir path. The inbox
  bearer is persisted only with `TELESESSION_PERSIST_INBOX_CREDENTIAL=1` on verified POSIX.
- Peer policy (telepty, unchanged): full prompt exchange only with an operator-designated true orchestrator
  target in the existing `AIGENTRY_ORCHESTRATOR_SIDS`. Never enroll inbox ids, never wrap work as ask envelopes;
  `PEER_INJECT_BLOCKED` is surfaced as-is.
- Limits: `accepted` ≠ delivered ≠ completed (audit `success` = enqueued by telepty). Replies sent while the
  receiver or inbox is down can be lost (mailbox dead-letter, 404 without an audit row). Delete-then-create reattach
  purges telepty's queued retries for that id. Not exactly-once. A local stdio adapter is not a Dot remote route.
