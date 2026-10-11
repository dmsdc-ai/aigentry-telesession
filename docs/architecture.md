# telesession architecture (0.1.0 draft)

## Boundary
| component | owns | must not |
|---|---|---|
| telepty | PTY session identity, safe input, output/events, delivery observations, inject audit log | depend on telesession; carry client-specific profiles/tools |
| telesession | target allowlist, exact-session routing, its own inbox (mailbox), nonce + audit binding, dedupe, lifecycle of what it created, adapters; later remote connectivity/auth, durable queue, reconnect | import telepty files or its auth module; start/stop/kill daemons; claim completion |
| orchestrator / clients (Dot, CLIs) | work, approval, reporting | — (they are operator-configured consumers) |

Dependency is one-way: telesession → telepty documented HTTP API. telepty runs without telesession.

## Modules
```
bin/telesession-mcp.js   host: env → config → transport → MCP stdio; process lifetime; stderr codes only
src/adapters/mcp.js      5 tools, strict zod schemas, maps records → MCP results (no state, no secrets)
src/index.js             core public API (no dependencies)
src/config.js            ConfigError, normalizeConfig (pure), loadConfig (TELESESSION_* env + explicit token file, optional state dir)
src/transports/telepty.js createTeleptyTransport → {inboxId, health, listAllowedTargets, send, receipt, readReply, close}
src/store.js             (L1 lane) openStore → strict-lock, fsync'd state.json + replies/ + optional credential.json
```
Another adapter (CLI, HTTP worker) calls the same transport API; no plugin framework. Remote routes
will be added at the telesession layer behind the same API.

## Durable slice (opt-in `TELESESSION_STATE_DIR`; SPEC-R2)
- One record model in both modes. Memory-only: mutations apply in process (0.1.0 lifetime, no fs).
  Durable: every mutation is a store commit; the in-memory view changes only after the commit succeeds.
- send: validate → allowlist → recovery → request_id dedupe + in-flight mark (synchronous) → limits → meta →
  sessions (target + inbox presence) → inbox → commit `reserved` {payload_sha256 of the exact wire prompt,
  reply_to, sender inbox id/epoch/generation} → inject → commit `accepted|refused|uncertain`. A failed
  post-inject commit is held in memory (`durability:"degraded"`, then `STORE_DEGRADED` until it commits).
- Receiver: a reply is fsynced to `replies/` and referenced by a committed record before the 200; a
  store failure or a lost lock answers 503 (telepty's mailbox retries, then dead-letters).
- Startup: `reserved → uncertain(process_restart)`. Then, on the first send/receipt/readReply: inbox
  reattach (owned DELETE with a persisted credential, then create_only of the same id) or rotation
  (old id → orphans, never touched again). Then an audit probe that accepts only exactly one row matching
  every persisted sender binding. Nothing is re-sent.
- Lock: strict exclusive file. No takeover by age/pid. After an abrupt crash every start is
  `STORE_LOCKED` until a separately reviewed repair exists (NOT PROVIDED).
- Gaps (`inbox_absent`, `process_restart`, `reattached`, `rotated`) mark pending requests
  `route_interrupted`/`reply_loss_possible`. `unreceived_audit_rows` is a lower bound, never proof.

## telepty HTTP surface used (documented: telepty docs/specs/2026-06-09-inject-audit-provenance.md, daemon capabilities)
| call | purpose |
|---|---|
| `GET /api/meta` | `capabilities` must include `inject-exact-target`, `register-create-only`, `delete-owned-session`; `pid` for restart observation |
| `GET /api/sessions` | exact target presence (only allowlisted ids are surfaced) |
| `POST /api/sessions/register` `{create_only:true, delivery_type:"aterm", delivery_endpoint}` | create own inbox, never touch an existing record (409) |
| `POST /api/sessions/:id/inject` `{exact_target:true, from, reply_to}` + inbox bearer | exact routing, no alias fallback; response must echo `exact_target`/`session_id` |
| `GET /api/inject-observations/:id` | target `session_epoch`; receipt mapping |
| `GET /api/injects?to=<inbox>&since&limit=200` | audit rows: `payload_sha256`, `verified_sender_sid/epoch`, `spoof_suspected`, `to_alias`, `delivery_result` |
| `GET /api/injects?to=<target>&from=<inbox>&since&until&limit=200` | durable startup probe of `uncertain` sends (`claimed_from`, `verified_sender_generation`, `next_cursor`) |
| `DELETE /api/sessions/:id?owned=true` + inbox bearer | delete only our own current instance (else 403) |

## Security invariants (preserved from the task-1215 broker)
- Config refused before any request; loopback-only URL validated on the raw string; token non-enumerable, never returned/logged.
- HTTP: no redirects, per-request timeouts (5/10/1.5 s), 256 KiB body cap, sanitized codes, no retry.
- Receiver: 127.0.0.1, random port + 256-bit secret path, Origin/Host checks, 64 KiB, 64 held texts (memory or `replies/`).
- State dir never holds the telepty token, receiver port/secret path or prompt text (hashes only). The inbox
  bearer is stored only on explicit opt-in on verified POSIX, and is refused on Windows.
- Peer policy is telepty's: only an operator-designated true orchestrator target (existing
  `AIGENTRY_ORCHESTRATOR_SIDS`) gets full prompt exchange. Never enroll inbox ids, never wrap work as
  ask envelopes; `PEER_INJECT_BLOCKED` is surfaced as-is.
- Trust = exactly one audit row with matching sha256, verified sender sid + epoch, no spoof, inside nonce window, unbound inject id.
- `completion_fact: null` everywhere; ambiguity (`accepted:"unknown"`, `audit_ambiguous`), expiry (`NONCE_EXPIRED`) and restart (`daemon_restart`) are reported, never smoothed over.

## Not provided yet (tracked, PARTIAL)
Automatic unlock/restart after an abrupt crash; native-Windows credential storage; exactly-once;
outbound HTTPS relay; remote auth route/hosting; events/webhooks. A stdio MCP server does not
establish a ChatGPT/Dot remote MCP connection; that path is NOTRUN.
